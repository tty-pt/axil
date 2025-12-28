#ifndef NDC_H
#define NDC_H
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET socket_t;
#else
#include <sys/select.h>
typedef int socket_t;
#endif


#define ENV_KEY_LEN 128
#define ENV_LEN (BUFSIZ * 2)
#define ENV_VALUE_LEN (ENV_LEN - ENV_KEY_LEN - 2)

enum descr_flags {
	DF_CONNECTED = 1,
	// RESERVED = 0x2,
	DF_WEBSOCKET = 4,
	DF_TO_CLOSE = 8,
	DF_ACCEPTED = 16,
	DF_AUTHENTICATED = 32,
	DF_RESERVED = 64,
	// RESERVED = 0x80,
};

enum ndc_srv_flags {
	NDC_WAKE = 1,
	NDC_SSL = 2,
	NDC_ROOT = 4,
	NDC_SSL_ONLY = 8,
	NDC_DETACH = 16,
};

enum ndc_req_flags {
	NDC_POST = 1,
};

typedef void ndc_handler_t(socket_t cfd, char *body);

struct ndc_config {
	char * chroot;
	unsigned flags, port, ssl_port;
	ndc_handler_t *default_handler;
};

typedef void ndc_cb_t(socket_t fd, int argc, char *argv[]);
typedef void (*cmd_cb_t)(socket_t cfd, char *buf, size_t len, int ofd);

struct cmd_slot {
	char *name;
	ndc_cb_t *cb;
	int flags;
};

enum cmd_flags {
	CF_NOAUTH = 1,
	CF_NOTRIM = 2,
};

extern long long ndc_tick;
extern struct ndc_config ndc_config;

void ndc_register(char *name, ndc_cb_t *cb, int flags);
int ndc_main(void);
void ndc_register_handler(char *path, ndc_handler_t handler);

/* define these */
extern void ndc_update(unsigned long long dt) __attribute__((weak));
extern void ndc_vim(socket_t fd, int argc, char *argv[]) __attribute__((weak));
extern int ndc_accept(socket_t fd) __attribute__((weak));
extern int ndc_connect(socket_t fd) __attribute__((weak));
extern void ndc_disconnect(socket_t fd) __attribute__((weak));
extern void ndc_command(socket_t fd, int argc, char *argv[]) __attribute__((weak)); /* will run on any command */
extern void ndc_flush(socket_t fd, int argc, char *argv[]) __attribute__((weak)); /* will run after any command */
extern char *ndc_auth_check(socket_t fd) __attribute__((weak));

/* write to descriptor (might not need) */
int ndc_write(socket_t fd, void *data, size_t len);
#define NDC_TWRITE(fd, msg) ndc_write(fd, msg, strlen(msg))
int ndc_dwritef(socket_t fd, const char *fmt, va_list va);
int ndc_writef(socket_t fd, const char *fmt, ...);
void ndc_wall(const char *msg);

ndc_cb_t do_GET, do_POST, do_sh;

void ndc_pty(socket_t fd, char * const args[]);

int ndc_flags(socket_t fd);
void ndc_close(socket_t fd);
void ndc_set_flags(socket_t fd, int flags);
int ndc_auth(socket_t fd, char *username);
unsigned ndc_env(socket_t fd);
void ndc_cert_add(char *str);
void ndc_certs_add(char *fname);

extern char ndc_execbuf[BUFSIZ * 64];

ssize_t ndc_mmap(char **mapped, char *file);
char *ndc_mmap_iter(char *start, size_t *pos);

void ndc_env_clear(socket_t fd);
int ndc_env_get(socket_t fd, char *target, char *key);
int ndc_env_put(socket_t fd, char *key, char *value);

void ndc_exec(socket_t cfd, char * const args[],
		cmd_cb_t callback, void *input,
		size_t input_len);
#endif
