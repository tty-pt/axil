#ifndef NDC_H
#define NDC_H
/**
 * @file ndc.h
 * @brief Public API for ndc.
 *
 * ndc provides an HTTP(S) + WebSocket(S) server with a modular handler system.
 * POSIX-only features (PTY, autoindex, passwd auth, mmap) are
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
#include <ttypt/qsys.h>

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
	/** Part of a tunnel pair. */
	DF_TUNNEL = 64,
	/** Waiting for upstream websocket upgrade response. */
	DF_WS_WAITING = 128,
	DF_WS_PROXY_PENDING = 256,
	/** Externally-watched fd: skip client processing, dispatch via on_fd_tick. */
	DF_EXTERN = 512,
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
	/** Auto-authenticate all WebSocket connections (dev/testing only). */
	NDC_AUTOAUTH = 32,
};

/** Request flags used internally. */
enum ndc_req_flags {
	/** Request is POST. */
	NDC_POST = 1,
};

/** HTTP handler callback signature. */
typedef int ndc_handler_t(socket_t cfd, char *body);

/** WebSocket tunnel callback: connects to upstream and returns socket.
 *  NDC handles forwarding the HTTP upgrade request, reading the response,
 *  and establishing the tunnel.
 */
typedef socket_t ndc_ws_upstream_t(socket_t client_fd);

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
	size_t max_body_size; /* 0 = use NDC_DEFAULT_MAX_BODY_SIZE (10 MB) */
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
 *  Patterns support :param syntax (e.g., "/items/:id" or "/a/:type/:id"),
 *  terminal catch-alls via * (e.g., "/items/" followed by "*"), and optional trailing slash
 *  matching on path patterns.
 *  Matched parameters are available via PATTERN_PARAM_<NAME> env vars.
 *  Example: "/items/:id" matches "/items/123", sets PATTERN_PARAM_ID="123"
 */
void ndc_register_handler(char *path, ndc_handler_t handler);

/** Register a fallback HTTP handler.
 *  Fallback handlers run after static files, registered handlers, and
 *  ndc_config.default_handler have declined the request. Return non-zero
 *  when the request was handled. Returns 0 on success, -1 when the fallback
 *  table is full.
 */
int ndc_register_fallback_handler(ndc_handler_t handler);

/** Register a websocket handler for a path.
 *  When a websocket request arrives for this path, the handler is called
 *  with the client socket. The handler connects to the upstream and returns
 *  the upstream socket. NDC then forwards the HTTP upgrade, reads the response,
 *  and establishes a bidirectional tunnel.
 */
void ndc_ws_handler(char *path, ndc_ws_upstream_t handler);

/** Upgrade connection to websocket. Reads Sec-WebSocket-Key from the request
 *  environment, performs the handshake, and calls ndc_connect() on success.
 *  Modules should call this explicitly from their GET handler when
 *  HTTP_SEC_WEBSOCKET_KEY is present in the request environment. */
int ndc_ws_upgrade(socket_t fd);

/** Write data to websocket. */
int ndc_ws_write(socket_t fd, const void *data, size_t len);

/** Read data from websocket. Returns bytes read, 0 on close, -1 on error. */
ssize_t ndc_ws_read(socket_t fd, void *buf, size_t len);

/** Close websocket connection. */
int ndc_ws_close(socket_t fd);

/** Formatted write to websocket. */
int ndc_ws_printf(socket_t fd, const char *fmt, ...);

/* define these */
/** Periodic update hook. */
extern void ndc_update(unsigned long long dt) WEAK;
/** Called when a command is not found. */
extern void ndc_vim(socket_t fd, int argc, char *argv[]) WEAK;
/** Called on accept; return value is ignored. */
extern int ndc_accept(socket_t fd) WEAK;
/** Called after a WebSocket upgrade completes via ndc_ws_upgrade().
 *  Return non-zero to mark the connection as established (DF_CONNECTED). */
extern int ndc_connect(socket_t fd) WEAK;
/** Called on disconnect. */
extern void ndc_disconnect(socket_t fd) WEAK;
/** Called before a registered command handler. */
extern void ndc_command(socket_t fd, int argc, char *argv[]) WEAK; /* will run on any command */
/** Called after a registered command handler. */
extern void ndc_flush(socket_t fd, int argc, char *argv[]) WEAK; /* will run after any command */
/** Return a username to authenticate the connection, or NULL. */
extern char *ndc_auth_check(socket_t fd) WEAK;
/* TODO DESCRIBE */
extern void ndc_fd_tick(socket_t fd) WEAK;
extern int ndc_parse(
    socket_t fd,
    unsigned char * input,
    int nread) WEAK;

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

ndc_cb_t do_GET, do_POST;

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

/** Parse a URL-encoded form body (application/x-www-form-urlencoded) into an
 *  internal key/value store.  Call once per request before ndc_query_param().
 *  Subsequent calls replace the previous parse result.  Returns 0 on success,
 *  -1 on error. */
int ndc_query_parse(char *body);

/** Look up a key previously parsed by ndc_query_parse().  Copies the
 *  URL-decoded value into buf (at most buf_len-1 bytes, NUL-terminated).
 *  Returns the number of bytes written, or -1 if the key was not found. */
int ndc_query_param(const char *name, char *buf, size_t buf_len);

/** Get HTTP status text for a status code. Returns "Unknown" for invalid codes. */
const char *ndc_status_text(int code);

#ifndef _WIN32
#include <pwd.h>

/** Copy the authenticated user's passwd entry for fd into *out (POSIX-only).
 *  Returns 0 on success, -1 if fd is not authenticated. */
int ndc_get_pw(socket_t fd, struct passwd *out);

/** Add fd to the server's active (select) watch set as an externally-managed
 *  fd. Sets DF_EXTERN so the main loop dispatches it via on_fd_tick rather
 *  than treating it as a client connection (POSIX-only). */
void ndc_fd_watch(socket_t fd);

/** Remove fd from the server's active and read watch sets (POSIX-only). */
void ndc_fd_unwatch(socket_t fd);

/** Reset the cleanup flag in a forked child process (POSIX-only).
 *  Must be called immediately after fork() in the child. */
void ndc_fork_child_reset(void);

/** Send a raw TELNET command sequence over fd (POSIX-only). */
static inline void
ndc_send_telnet_cmd(socket_t fd, const unsigned char *command, size_t cmd_len)
{
	ndc_write(fd, (void *)command, cmd_len);
}

/** Build and send a TELNET command from a literal byte sequence. */
#define TELNET_CMD(fd, ...) do { \
	unsigned char _tc[] = { __VA_ARGS__ }; \
	ndc_send_telnet_cmd(fd, _tc, sizeof(_tc)); \
} while (0)

#endif /* !_WIN32 */

/** Add a response header. Call before ndc_respond(). */
void ndc_header_set(socket_t fd, const char *key, const char *value);

/** Get an incoming request header by its natural name (e.g. "Content-Type").
 *  Copies the value into buf (at most buf_len-1 bytes, NUL-terminated).
 *  Returns 0 on success, -1 if the header was not present in the request. */
int ndc_header_get(socket_t fd, const char *key, char *buf, size_t buf_len);

/** Send HTTP status, accumulated headers, body and close the connection.
 *  If body is NULL, only the status line and headers are sent and the
 *  connection is left open for streaming via ndc_write(). */
void ndc_respond(socket_t fd, int code, const char *body);

/** Send a plain-text response and close the connection.
 *  Returns 0 on 2xx status codes, 1 otherwise. */
static inline int
ndc_respond_plain(socket_t fd, int status, const char *msg)
{
	ndc_header_set(fd, "Content-Type", "text/plain");
	ndc_respond(fd, status, msg ? msg : "");
	return status / 100 != 2;
}

/** Send a 303 redirect and close the connection. Returns 0. */
static inline int
ndc_redirect(socket_t fd, const char *location)
{
	ndc_header_set(fd, "Location", (char *)location);
	ndc_respond(fd, 303, "");
	return 0;
}

/** Serve a static file with auto-detected MIME type. Closes fd on completion. */
void ndc_sendfile(socket_t fd, const char *path);

/** Execute a command and stream output via callback (POSIX-only).
 * Callback ofd is 1 for stdout, 0 for stderr.
 */
void ndc_exec(socket_t cfd, char * const args[],
		cmd_cb_t callback, void *input,
		size_t input_len);

/** Continue processing a command started with ndc_exec() (POSIX-only). */
int ndc_exec_loop(socket_t cfd);

void ndc_clear_active(socket_t cfd);

/** @} */
#endif
