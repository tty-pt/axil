#ifndef AXIL_INTERNAL_H
#define AXIL_INTERNAL_H

#include <stdio.h>
#include "../include/ttypt/axil.h"
#include "axil-platform.h"
#include "../include/iio.h"
#include "../include/ws.h"

#include <ttypt/xy.h>
#include <ttypt/corm.h>
#include <ttypt/stele.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#if !defined(_WIN32)
#include <sys/mman.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define WILL 251
#define WONT 252
#define DO 253
#define DONT 254
#define IAC 255
#define SB 250
#define TELOPT_ECHO 1
#define TELOPT_SGA 3
#define TELOPT_NAWS 31

#define OPOST 0000001
#define ONLCR 0000004
#define OCRNL 0000010

#define ICANON 0000002
#define ECHO 0000010
#define ECHOK 0000040
#define ECHOCTL 0001000
#define IGNCR 0000200
#define ICRNL 0000400
#define INLCR 0000100

#define TCSANOW 0
#else
#include <arpa/inet.h>
#include <fnmatch.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <termios.h>
#define INVALID_SOCKET -1
#endif

/* Sockets need closesocket() on Winsock; close() only works for CRT fds. */
#ifdef _WIN32
#define axil_sock_close(fd) closesocket(fd)
#else
#define axil_sock_close(fd) close(fd)
#endif


#define CERT_MASK 0x1F
#define MIME_MASK 0x3F
#define CMD_MASK 0x7F
#define HDLR_MASK 0x3F
#define FALLBACK_MAX 16
#define ENV_MASK 0xFF

#define CMD_ARGM 8

#define DESCR_ITER                                                             \
	for (register int di_i = 1; di_i < FD_SETSIZE; di_i++)                 \
		if (!FD_ISSET(di_i, &fds_read) ||                              \
		    !(descr_map[di_i].flags & DF_CONNECTED))                   \
			continue;                                              \
		else

#define FIRST_INPUT_SIZE (BUFSIZ * 2)
#define SELECT_TIMEOUT 10000
#define EXEC_TIMEOUT 1000
/* Per-descriptor bound on a partially received request head. A client that
 * never sends its blank line gets a 431 and its fd freed (descr_read) instead
 * of an unbounded stash. Generous next to what the header storage (ENV_VALUE_LEN)
 * can hold, so only a real slowloris or a bug trips it. */
#define MAX_REQUEST_HEAD (64 * 1024)

/* Body-read stall budget. A non-blocking socket may simply not have the rest of
 * a declared body yet, which is indistinguishable from a disconnect and used to
 * kill the request. EAGAIN is retried inline on the event loop, so the wait has
 * to be bounded: MAX_BODY_STALL_RETRIES * BODY_STALL_SLEEP_MS caps the cost to
 * 10 ms. Only stalls count against the budget -- counting every read would cap
 * the body at 20 * BUFSIZ (~160 KiB) and silently truncate anything bigger. A
 * handler that must not block at all wants axil_respond_defer() instead. */
#define MAX_BODY_STALL_RETRIES 20
#define BODY_STALL_SLEEP_MS    500


struct descr {
	SSL *cSSL;
	socket_t fd;
	int flags, pty, epid;
	char username[BUFSIZ];
	char *remaining;
	struct sockaddr_in addr;
	size_t remaining_size, remaining_len, remaining_off;
	time_t sor; // start of request
	int pipes[3], pipes_mask;
	cmd_cb_t callback;
	size_t total;
	unsigned char *head;
	size_t head_len, head_cap;
#ifndef _WIN32
	struct winsize wsz;
	struct termios tty;
	struct passwd pw;
	int pid;
#endif
	unsigned env_hd;
	char resp_headers[BUFSIZ];
	unsigned long long generation;
};

struct cmd {
	int fd;
	int argc;
	char *argv[CMD_ARGM];
};

struct popen {
	int in, out, pid;
};

typedef struct {
	char *crt;
	char *key;
	char *domain;
	SSL_CTX *ctx;
} cert_t;


#define AXIL_DEFAULT_MAX_BODY_SIZE (10UL * 1024UL * 1024UL)
#define AXIL_CROSS_ORIGIN_HEADERS                                              \
	"Cross-Origin-Opener-Policy: same-origin\r\n"                          \
	"Cross-Origin-Embedder-Policy: require-corp\r\n"                       \
	"Cross-Origin-Resource-Policy: same-origin\r\n"


#ifndef AXIL_HIDDEN
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
#define AXIL_HIDDEN __attribute__((visibility("hidden")))
#else
#define AXIL_HIDDEN
#endif
#endif

extern struct descr descr_map[FD_SETSIZE] AXIL_HIDDEN;
extern socket_t tunnel_pair[FD_SETSIZE] AXIL_HIDDEN;
extern fd_set fds_read, fds_active, fds_write, fds_wactive AXIL_HIDDEN;
extern struct timeval select_timeout, exec_timeout AXIL_HIDDEN;
extern int do_cleanup AXIL_HIDDEN;
extern int axil_srv_flags AXIL_HIDDEN;
extern struct io io[FD_SETSIZE];
extern struct axil_config axil_config;
extern socket_t srv_ssl_fd, srv_fd;
extern unsigned cmds_hd, cert_hd, mime_hd, hdlr_hd, ws_hd, query_db AXIL_HIDDEN;
extern char *domain_default AXIL_HIDDEN;
extern SSL_CTX *default_ssl_ctx AXIL_HIDDEN;
extern unsigned char *input AXIL_HIDDEN;
extern size_t input_size, input_len AXIL_HIDDEN;

axil_cb_t do_GET, do_POST, do_PUT, do_DELETE, do_HEAD, do_sh;

int axil_write_remaining(socket_t fd);
void axil_upstream_descr_init(socket_t fd) AXIL_HIDDEN;
void axil_raw_descr_reset(socket_t fd) AXIL_HIDDEN;
void axil_tunnel_close_raw(socket_t fd) AXIL_HIDDEN;
void axil_ws_tunnel(socket_t a, socket_t b) AXIL_HIDDEN;

void axil_ssl_drop(struct descr *d) AXIL_HIDDEN;
int ssl_accept(socket_t fd) AXIL_HIDDEN;
io_ssize_t axil_ssl_low_read(socket_t fd, void *to, io_size_t len, int flags) AXIL_HIDDEN;
io_ssize_t axil_ssl_lower_write(socket_t fd, void *from, io_size_t len, int flags) AXIL_HIDDEN;
int openssl_error_callback(const char *str, size_t len, void *u) AXIL_HIDDEN;
SSL_CTX *axil_ctx_new(char *crt, char *key);
void _axil_cert_add(char *domain, char *crt, char *key);

#endif /* AXIL_INTERNAL_H */
