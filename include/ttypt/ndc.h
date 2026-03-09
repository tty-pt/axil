#ifndef NDC_H
#define NDC_H
/**
 * @file ndc.h
 * @brief Public API for ndc.
 *
 * ndc provides an HTTP(S) + WebSocket(S) server with a terminal mux.
 * POSIX-only features (PTY, CGI, autoindex, passwd auth, mmap) are
 * no-ops on Windows.
 */

/** @defgroup ndc ndc API
 * @brief Core API and configuration types.
 * @{ */
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


/** Max key size for request environment. */
#define ENV_KEY_LEN 128
/** Maximum environment string size. */
#define ENV_LEN (BUFSIZ * 2)
/** Max value size for request environment. */
#define ENV_VALUE_LEN (ENV_LEN - ENV_KEY_LEN - 2)

/** Descriptor state flags. */
enum descr_flags {
	/** Connection established and accepted. */
	DF_CONNECTED = 1,
	// RESERVED = 0x2,
	/** WebSocket mode enabled. */
	DF_WEBSOCKET = 4,
	/** Marked to close after remaining output. */
	DF_TO_CLOSE = 8,
	/** Accepted socket (pre-WS). */
	DF_ACCEPTED = 16,
	/** Authenticated user. */
	DF_AUTHENTICATED = 32,
	DF_RESERVED = 64,
	// RESERVED = 0x80,
};

/** Server configuration flags. */
enum ndc_srv_flags {
	/** Wake on activity. */
	NDC_WAKE = 1,
	/** Enable TLS. */
	NDC_SSL = 2,
	/** Root multiplex mode. */
	NDC_ROOT = 4,
	/** Redirect HTTP to HTTPS when SSL enabled. */
	NDC_SSL_ONLY = 8,
	/** Detach into the background. */
	NDC_DETACH = 16,
};

/** Request flags used internally. */
enum ndc_req_flags {
	/** Request is POST. */
	NDC_POST = 1,
};

/** HTTP handler callback signature. */
typedef int ndc_handler_t(socket_t cfd, char *body);

/** Global server configuration.
 *
 * Fields include chroot path (POSIX-only), server flags, HTTP/HTTPS ports,
 * and an optional fallback handler.
 */
struct ndc_config {
	char * chroot;
	unsigned flags;
	unsigned port;
	unsigned ssl_port;
	ndc_handler_t *default_handler;
};

typedef void ndc_cb_t(socket_t fd, int argc, char *argv[]);
typedef void (*cmd_cb_t)(socket_t cfd, char *buf, size_t len, int ofd);

/** Command handler registration. */
struct cmd_slot {
	char *name;
	ndc_cb_t *cb;
	int flags;
};

/** Command flags. */
enum cmd_flags {
	/** Allow command without authentication. */
	CF_NOAUTH = 1,
	/** Do not trim trailing CR from input. */
	CF_NOTRIM = 2,
};

extern long long ndc_tick;
extern struct ndc_config ndc_config;

/** Register a command handler by name. */
void ndc_register(char *name, ndc_cb_t *cb, int flags);
/** Run the main server loop (blocks). */
int ndc_main(void);
/** Register an HTTP handler for a path (exact match or pattern).
 *  Patterns support :param syntax (e.g., "/items/:id" or "/a/:type/:id").
 *  Matched parameters are available via PATTERN_PARAM_<NAME> env vars.
 *  Example: "/items/:id" matches "/items/123", sets PATTERN_PARAM_ID="123"
 */
void ndc_register_handler(char *path, ndc_handler_t handler);

/* define these */
/** Periodic update hook. */
extern void ndc_update(unsigned long long dt) __attribute__((weak));
/** Called when a command is not found. */
extern void ndc_vim(socket_t fd, int argc, char *argv[]) __attribute__((weak));
/** Called on accept; return value is ignored. */
extern int ndc_accept(socket_t fd) __attribute__((weak));
/** Called on websocket connect; return non-zero to accept. */
extern int ndc_connect(socket_t fd) __attribute__((weak));
/** Called on disconnect. */
extern void ndc_disconnect(socket_t fd) __attribute__((weak));
/** Called before a registered command handler. */
extern void ndc_command(socket_t fd, int argc, char *argv[]) __attribute__((weak)); /* will run on any command */
/** Called after a registered command handler. */
extern void ndc_flush(socket_t fd, int argc, char *argv[]) __attribute__((weak)); /* will run after any command */
/** Return a username to authenticate the connection, or NULL. */
extern char *ndc_auth_check(socket_t fd) __attribute__((weak));

/* write to descriptor (might not need) */
/** Write raw bytes to a descriptor. Returns bytes written or -1. */
int ndc_write(socket_t fd, void *data, size_t len);
#define NDC_TWRITE(fd, msg) ndc_write(fd, msg, strlen(msg))
/** Write formatted data using a va_list. */
int ndc_dwritef(socket_t fd, const char *fmt, va_list va);
/** Write formatted data. */
int ndc_writef(socket_t fd, const char *fmt, ...);
/** Broadcast a message to all connected descriptors. */
void ndc_wall(const char *msg);

ndc_cb_t do_GET, do_POST, do_sh;

/** Spawn a PTY-backed command for fd (POSIX-only). */
void ndc_pty(socket_t fd, char * const args[]);

/** Get descriptor flags. */
int ndc_flags(socket_t fd);
/** Close a descriptor. */
void ndc_close(socket_t fd);
/** Set descriptor flags. */
void ndc_set_flags(socket_t fd, int flags);
/** Authenticate a user for fd; returns 0 on success, 1 on failure. */
int ndc_auth(socket_t fd, char *username);
/** Return internal env handle for fd (advanced use; stable but not recommended). */
unsigned ndc_env(socket_t fd);
/** Add a certificate mapping: domain:cert.pem:key.pem (POSIX-only). */
void ndc_cert_add(char *str);
/** Load certificate mappings from file (POSIX-only). */
void ndc_certs_add(char *fname);

/** Shared exec buffer (legacy). Prefer callbacks; symbol is stable. */
extern char ndc_execbuf[BUFSIZ * 64];

/** Map a file into memory (POSIX-only). */
ssize_t ndc_mmap(char **mapped, char *file);
/** Iterate mapped lines separated by '\n' (POSIX-only). */
char *ndc_mmap_iter(char *start, size_t *pos);

/** Clear request environment for fd. */
void ndc_env_clear(socket_t fd);
/** Get environment value by key; returns 0 on success. */
int ndc_env_get(socket_t fd, char *target, char *key);
/** Set environment key/value; returns 0 on success. */
int ndc_env_put(socket_t fd, char *key, char *value);

/** Get HTTP status text for a status code. Returns "Unknown" for invalid codes. */
const char *ndc_status_text(int code);

/** Add a response header. Call before ndc_head(). */
void ndc_header(socket_t fd, const char *key, const char *value);

/** Send HTTP status line and all accumulated headers. Call after ndc_header(). */
void ndc_head(socket_t fd, int code);

/** Send HTTP body and close the connection. Headers must be sent first via ndc_head(). */
void ndc_body(socket_t fd, const char *body);

/** Serve a static file with auto-detected MIME type. Closes fd on completion. */
void ndc_sendfile(socket_t fd, const char *path);

/** Execute a command and stream output via callback (POSIX-only).
 * Callback ofd is 1 for stdout, 0 for stderr.
 */
void ndc_exec(socket_t cfd, char * const args[],
		cmd_cb_t callback, void *input,
		size_t input_len);
/** @} */
#endif
