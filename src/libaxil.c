#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1

#include <stdio.h>

#include "../include/ttypt/axil.h"
#include "../include/iio.h"
#include "axil-internal.h"

#include <ttypt/xy.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
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

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include "../include/ws.h"

#include <ttypt/qmap.h>
#include <ttypt/qsys.h>

#include "ws.c"

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

struct descr descr_map[FD_SETSIZE] AXIL_HIDDEN;

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

axil_cb_t do_GET, do_POST, do_PUT, do_DELETE, do_HEAD, do_sh;

static unsigned char *input;
static size_t input_size = FIRST_INPUT_SIZE, input_len = 0;

#define AXIL_DEFAULT_MAX_BODY_SIZE (10UL * 1024UL * 1024UL)
#define AXIL_CROSS_ORIGIN_HEADERS                                              \
	"Cross-Origin-Opener-Policy: same-origin\r\n"                          \
	"Cross-Origin-Embedder-Policy: require-corp\r\n"                       \
	"Cross-Origin-Resource-Policy: same-origin\r\n"

struct timeval select_timeout, exec_timeout;

struct io io[FD_SETSIZE];

struct axil_config axil_config;
socket_t srv_ssl_fd = -1, srv_fd = -1;

int axil_srv_flags = 0;
static unsigned cmds_hd;
fd_set fds_read, fds_active, fds_write, fds_wactive;
socket_t tunnel_pair[FD_SETSIZE];
long long dt, tack = 0;
SSL_CTX *default_ssl_ctx;
long long axil_tick;
int do_cleanup = 1;

char axil_execbuf[BUFSIZ * 64];

char *domain_default = NULL;
unsigned cert_hd, mime_hd, hdlr_hd, ws_hd;
static unsigned query_db;
static axil_handler_t *fallback_handlers[FALLBACK_MAX];
static size_t fallback_handlers_len;

static void axil_ws_tunnel(socket_t a, socket_t b);
int axil_write_remaining(socket_t fd);

static int header_name_eq(const char *line, size_t line_len, const char *name)
{
	size_t name_len = strlen(name);

	if (line_len != name_len)
		return 0;

	for (size_t i = 0; i < name_len; i++)
		if (tolower((unsigned char)line[i]) !=
		    tolower((unsigned char)name[i]))
			return 0;

	return 1;
}

static int axil_header_has(socket_t fd, const char *key)
{
	struct descr *d = &descr_map[fd];
	const char *line = d->resp_headers;

	while (*line) {
		const char *colon = strchr(line, ':');
		const char *end = strstr(line, "\r\n");

		if (!end)
			end = line + strlen(line);
		if (colon && colon < end &&
		    header_name_eq(line, (size_t)(colon - line), key))
			return 1;

		line = *end ? end + 2 : end;
	}

	return 0;
}

static void
axil_header_set_default(socket_t fd, const char *key, const char *value)
{
	if (!axil_header_has(fd, key))
		axil_header_set(fd, key, value);
}

static void axil_default_response_headers(socket_t fd)
{
	axil_header_set_default(
	        fd, "Cross-Origin-Opener-Policy", "same-origin");
	axil_header_set_default(
	        fd, "Cross-Origin-Embedder-Policy", "require-corp");
	axil_header_set_default(
	        fd, "Cross-Origin-Resource-Policy", "same-origin");
}

void axil_env_clear(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	if (d->env_hd)
		qmap_drop(d->env_hd);

	d->resp_headers[0] = '\0';
}

unsigned axil_env(socket_t fd)
{
	return descr_map[fd].env_hd;
}

void axil_header_set(socket_t fd, const char *key, const char *value)
{
	struct descr *d = &descr_map[fd];
	size_t len = strlen(d->resp_headers);
	snprintf(d->resp_headers + len, BUFSIZ - len, "%s: %s\r\n", key, value);
}

int axil_header_get(socket_t fd, const char *key, char *buf, size_t buf_len)
{
	char env_key[ENV_KEY_LEN];
	size_t i;

	memcpy(env_key, "HTTP_", 5);
	size_t prefix_len = 5;

	for (i = 0; key[i] && prefix_len + i < sizeof(env_key) - 1; i++) {
		char c = key[i];
		env_key[prefix_len + i] =
		        (c == '-') ? '_' : (char)toupper((unsigned char)c);
	}
	env_key[prefix_len + i] = '\0';

	struct descr *d = &descr_map[fd];
	const char *val = (const char *)qmap_get(d->env_hd, env_key);
	if (!val)
		return -1;

	size_t len = strlen(val);
	if (len >= buf_len)
		len = buf_len - 1;
	memcpy(buf, val, len);
	buf[len] = '\0';
	return 0;
}

void axil_respond(socket_t fd, int code, const char *body)
{
	struct descr *d = &descr_map[fd];
	axil_default_response_headers(fd);

	size_t body_len = (body && !(d->flags & DF_HEAD)) ? strlen(body) : 0;
	char hdr[4096];
	int hlen = snprintf(
	        hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\n%s\r\n", code,
	        axil_status_text(code), d->resp_headers);
	d->resp_headers[0] = '\0';

	if (hlen > 0) {
		if (body_len > 0 && (size_t)hlen + body_len <= 65536) {
			char combined[hlen + body_len];
			memcpy(combined, hdr, (size_t)hlen);
			memcpy(combined + hlen, body, body_len);
			axil_write(fd, combined, (size_t)hlen + body_len);
		} else {
			axil_write(fd, hdr, (size_t)hlen);
			if (body_len > 0)
				axil_write(fd, (void *)body, body_len);
		}
	}

	d->flags |= DF_TO_CLOSE;
	if (!d->remaining_len)
		axil_close(fd);
	else
		axil_write_remaining(fd);
}

static void axil_raw_descr_reset(socket_t fd);

static void axil_tunnel_close_raw(socket_t fd);

static void axil_ssl_drop(struct descr *d)
{
	if (!d->cSSL)
		return;
	SSL_free(d->cSSL);
	d->cSSL = NULL;
}

void axil_close(socket_t fd)
{
	if (fd == INVALID_SOCKET || fd >= FD_SETSIZE)
		return;

	struct descr *d = &descr_map[fd];

	/*
	 * Tunnel descriptors and pending WS proxy pairs must use unified pair
	 * teardown. Otherwise one side can survive with a stale tunnel_pair[]
	 * entry and later hit an unrelated connection that reuses the same fd
	 * number.
	 */
	if (d->flags & (DF_TUNNEL | DF_WS_PROXY_PENDING | DF_WS_WAITING)) {
		axil_tunnel_close_raw(fd);
		return;
	}

	if (d->remaining_size && d->remaining) {
		free(d->remaining);
		d->remaining = NULL;
	}
	d->remaining_size = 0;
	d->remaining_len = 0;
	d->remaining_off = 0;

	d->resp_headers[0] = '\0';

	if ((d->flags & DF_CONNECTED) && axil_disconnect)
		axil_disconnect(fd);

	if (d->flags & DF_WEBSOCKET)
		ws_close(fd);

	if (axil_platform && axil_platform->cleanup_descr)
		axil_platform->cleanup_descr(d);

	axil_ssl_drop(d);

	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_read);
	FD_CLR(fd, &fds_wactive);
	FD_CLR(fd, &fds_write);

	if (d->env_hd) {
		axil_env_clear(fd);
		qmap_close(d->env_hd);
		d->env_hd = 0;
	}

	shutdown(fd, 2);
	close(fd);

	tunnel_pair[fd] = INVALID_SOCKET;

	memset(d, 0, sizeof(struct descr));
	d->fd = -1;

	/* Shrink global input buffer if it grew excessively */
	if (input_size > FIRST_INPUT_SIZE * 4) {
		unsigned char *shrunk = realloc(input, FIRST_INPUT_SIZE);
		if (shrunk) {
			input = shrunk;
			input_size = FIRST_INPUT_SIZE;
		}
	}
}

static void cleanup(void)
{
	if (!do_cleanup)
		return;

	DESCR_ITER
	axil_close(di_i);
}

#if !defined(_WIN32)
static void sig_shutdown(int sig UNUSED)
{
	axil_srv_flags &= ~AXIL_WAKE;
}
#endif

static void setup_signals(void)
{
#if !defined(_WIN32)
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_shutdown;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	struct sigaction sa_pipe;
	memset(&sa_pipe, 0, sizeof(sa_pipe));
	sa_pipe.sa_handler = SIG_IGN;
	sigemptyset(&sa_pipe.sa_mask);
	sa_pipe.sa_flags = 0;

	sigaction(SIGPIPE, &sa_pipe, NULL);
#endif
	atexit(cleanup);
}

static int ssl_accept(socket_t fd)
{
	/* fprintf(stderr, "ssl_accept %d\n", fd); */
	struct descr *d = &descr_map[fd];
	int res = SSL_accept(d->cSSL);

	d->flags &= ~DF_ACCEPTED;

	if (res > 0) {
		d->flags |= DF_ACCEPTED;
		return 0;
	}

	int ssl_err = SSL_get_error(d->cSSL, res);
	if (errno == EAGAIN && ssl_err == SSL_ERROR_WANT_READ)
		return 0;

	ERR("SSL_accept %d %d %d %d %s\n", fd, res, ssl_err, errno,
	    ERR_error_string(ssl_err, NULL));

	unsigned long openssl_err;
	while ((openssl_err = ERR_get_error()) != 0) {
		char buf[256];
		ERR_error_string_n(openssl_err, buf, sizeof(buf));
		ERR("OpenSSL: %s\n", buf);
	}

	ERR_clear_error();
	axil_close(fd);
	return 1;
}

static io_ssize_t
axil_ssl_low_read(socket_t fd, void *to, io_size_t len, int flags UNUSED)
{
	return SSL_read(descr_map[fd].cSSL, to, len);
}

static void
cmd_new(int *argc_r, char *argv[CMD_ARGM], socket_t fd UNUSED, char *input,
        size_t len)
{
	register char *p = input;
	int argc = 0;

	p[len] = '\0';

	if (!*p || !isalnum(*p)) {
		argv[0] = "";
		*argc_r = argc;
		return;
	}

	argv[0] = p;
	argc++;

	for (p = input; *p && *p != '\r' && argc < CMD_ARGM; p++)
		if (isspace(*p)) {
			*p = '\0';
			argv[argc] = p + 1;
			argc++;
		}

	while (*p && *p != '\r')
		p++;

	for (int i = argc; i < CMD_ARGM; i++)
		argv[i] = "";

	argv[argc] = p + 2;

	*argc_r = argc;
}

static io_ssize_t
axil_ssl_lower_write(socket_t fd, void *from, io_size_t len, int flags UNUSED)
{
	struct descr *d = &descr_map[fd];
	if (!d->cSSL)
		return -1;
	return SSL_write(d->cSSL, from, len);
}

int axil_write_remaining(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	if (!d->remaining_len)
		return 0;

	int ret = dio->lower_write(
	        fd, d->remaining + d->remaining_off, d->remaining_len, 0);

	if (ret < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return -1;

		axil_close(fd);
		return -1;
	}

	if (ret == 0)
		return 0;

	d->remaining_off += ret;
	d->remaining_len -= ret;

	if (!d->remaining_len) {
		d->remaining_off = 0;
		if (d->flags & DF_TO_CLOSE)
			axil_close(fd);
	}

	return ret;
}

inline static void axil_rem_may_inc(socket_t fd, size_t len)
{
	struct descr *d = &descr_map[fd];

	size_t tail = d->remaining_size - (d->remaining_off + d->remaining_len);
	if (tail >= len)
		return;

	// compact
	if (d->remaining_off) {
		memmove(d->remaining, d->remaining + d->remaining_off,
		        d->remaining_len);
		d->remaining_off = 0;
		tail = d->remaining_size - d->remaining_len;
		if (tail >= len)
			return;
	}

	size_t need = d->remaining_off + d->remaining_len + len;
	size_t old_size = d->remaining_size;

	while (need >= d->remaining_size) {
		while (d->remaining_size < need)
			d->remaining_size *= 2;
		char *tmp = realloc(d->remaining, d->remaining_size);
		if (!tmp) {
			d->remaining_size = old_size;
			return;
		}
		d->remaining = tmp;
	}
}

static io_ssize_t
axil_low_write(socket_t fd, void *from, io_size_t len, int flags UNUSED)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	if (d->remaining_len) {
		axil_rem_may_inc(fd, len);
		memcpy(d->remaining + d->remaining_off + d->remaining_len, from,
		       len);
		d->remaining_len += len;
		axil_write_remaining(fd);
		return -1;
	}

	int ret = dio->lower_write(fd, from, len, flags);

	if (ret < 0 && errno == EAGAIN) {
		axil_rem_may_inc(fd, len);
		memcpy(d->remaining, from, len);
		d->remaining_off = 0;
		d->remaining_len = len;
		return -1;
	}

	if (ret >= 0 && (size_t)ret < len) {
		// partial send
		size_t left = len - ret;
		axil_rem_may_inc(fd, left);
		memcpy(d->remaining, (char *)from + ret, left);
		d->remaining_off = 0;
		d->remaining_len = left;
	}

	return ret;
}

int axil_env_put(socket_t fd, char *key, char *value)
{
	if (!value)
		return 1;
	struct descr *d = &descr_map[fd];
	qmap_put(d->env_hd, key, value);
	return 0;
}

static void descr_new(int ssl)
{
	struct sockaddr_in addr;
	socklen_t addr_len = (socklen_t)sizeof(addr);
	int fd = accept(
	        ssl ? srv_ssl_fd : srv_fd, (struct sockaddr *)&addr, &addr_len);
	struct descr *d;
	struct io *dio;

	if (fd <= 0)
		return;
	if (fd >= FD_SETSIZE) {
		close(fd);
		return;
	}

#ifdef TCP_NODELAY
	int nodelay = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#endif

	FD_SET(fd, &fds_active);

	d = &descr_map[fd];
	dio = &io[fd];
	memset(d, 0, sizeof(struct descr));
	memset(dio, 0, sizeof(struct io));
	d->addr = addr;
	d->fd = fd;
	d->flags = 0;
	d->remaining_size = BUFSIZ * 1024;
	d->remaining = malloc(d->remaining_size);
	if (!d->remaining) {
		close(fd);
		FD_CLR(fd, &fds_active);
		return;
	}
	d->epid = 0;
	d->env_hd = qmap_open(NULL, NULL, QM_STR, QM_STR, ENV_MASK, 0);
	d->pty = -1;

	dio->write = axil_low_write;

	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->addr.sin_addr, ipstr, sizeof(ipstr));
	axil_env_put(fd, "REMOTE_ADDR", ipstr);

	errno = 0;
	if (ssl) {
		d->cSSL = SSL_new(default_ssl_ctx);
		dio->read = dio->lower_read = axil_ssl_low_read;
		dio->lower_write = axil_ssl_lower_write;
		SSL_set_fd(d->cSSL, fd);
		if (ssl_accept(fd))
			return;
	} else {
		d->flags = DF_ACCEPTED;
		dio->read = dio->lower_read = (io_t)recv;
		dio->lower_write = (io_t)send;
	}
	if (axil_accept)
		axil_accept(fd);
}

static void axil_upstream_descr_init(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	memset(d, 0, sizeof(struct descr));
	memset(dio, 0, sizeof(struct io));

	d->fd = fd;
	d->flags = DF_ACCEPTED;
	d->remaining_size = BUFSIZ * 1024;
	d->remaining = malloc(d->remaining_size);
	if (!d->remaining) {
		close(fd);
		return;
	}
	d->epid = 0;
	d->env_hd = qmap_open(NULL, NULL, QM_STR, QM_STR, ENV_MASK, 0);
	d->pty = -1;

	dio->read = dio->lower_read = (io_t)recv;
	dio->lower_write = (io_t)send;
	dio->write = axil_low_write;
}

inline static ssize_t axil_read(socket_t fd)
{
	char buf[BUFSIZ];
	struct io *dio = &io[fd];
	input_len = 0;
	size_t ret;
	size_t rounds = 0;

	while (1)
		switch ((ret = dio->read(fd, buf, sizeof(buf), 0))) {
		case -1:
		case 0:
			return ret;
		default:
			if (input_len + ret >= input_size) {
				size_t old_size = input_size;
				input_size *= 2;
				input_size += ret;
				unsigned char *tmp = realloc(input, input_size);
				if (!tmp) {
					input_size = old_size;
					return -1;
				}
				input = tmp;
			}
			memcpy(input + input_len, buf, ret);
			input_len += ret;
			if (ret < sizeof(buf) || ++rounds > 64)
				return input_len;
		}
}

int axil_write(socket_t fd, void *data, size_t len)
{
	if (fd <= 0)
		return -1;
	struct io *dio = &io[fd];
	/* fprintf(stderr, "axil_write %d %lu %d\n", fd, len, d->flags); */
	int ret = dio->write(fd, data, len, 0);
	return ret;
}

int axil_dwritef(socket_t fd, const char *fmt, va_list args)
{
	static char buf[BUFSIZ];
	ssize_t len = vsnprintf(buf, sizeof(buf), fmt, args);
	if (len < 0 || (size_t)len >= sizeof(buf))
		len = sizeof(buf) - 1;
	return axil_write(fd, buf, len);
}

int axil_writef(socket_t fd, const char *fmt, ...)
{
	if (fd <= 0)
		return -1;
	va_list va;
	va_start(va, fmt);
	int ret = axil_dwritef(fd, fmt, va);
	va_end(va);
	return ret;
}

void axil_wall(const char *msg)
{
	DESCR_ITER AXIL_TWRITE(di_i, (char *)msg);
}

static inline void cmd_proc(socket_t fd, int argc, char *argv[])
{
	char *s;

	if (argc < 1)
		return;

	/* HTTP/2 prior-knowledge preface, not an HTTP/1.1 method. */
	if (argc >= 3 && !strcmp(argv[0], "PRI") && !strcmp(argv[1], "*") &&
	    !strncmp(argv[2], "HTTP/2", 6))
	{
		axil_close(fd);
		return;
	}

	s = argv[0];

	for (s = argv[0]; isalnum(*s); s++)
		;

	int found = 0;

	*s = '\0';
	const struct cmd_slot *cmd = qmap_get(cmds_hd, argv[0]);

	if (cmd != NULL)
		found = 1;

	struct descr *d = &descr_map[fd];

	if (!(d->flags & DF_AUTHENTICATED) &&
	    (!found || !(cmd->flags & CF_NOAUTH)))
		return;

	if ((!found && argc) || !(cmd->flags & CF_NOTRIM)) {
		// this looks buggy let's fix it, please
		/* fprintf(stderr, "??? %d %p, %d '%s'\n", argc, cmd_i, cmd_i -
		 * cmds_hd, argv[0]); */
		char *p = &argv[argc][-2];
		if (*p == '\r')
			*p = '\0';
		argv[argc] = "";
	}

	if (found) {
		if (axil_command)
			axil_command(fd, argc, argv);
		cmd->cb(fd, argc, argv);
	} else if (axil_vim)
		axil_vim(fd, argc, argv);
	if (axil_flush)
		axil_flush(fd, argc, argv);
}

static inline int cmd_parse(socket_t fd, char *cmd, size_t len)
{
	int argc;
	char *argv[CMD_ARGM];

	cmd_new(&argc, argv, fd, cmd, len);

#if 0
	fprintf(stderr, "CMD_PARSE %d %lu:\n", fd, len);
	for (int i = 0; i < argc; i++)
		fprintf(stderr, " A %s\n", argv[i]);
#endif

	if (!argc)
		return 0;

	cmd_proc(fd, argc, argv);

	if (argc != 3)
		return 0;

	return len;
}

static int descr_read(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	int ret;

	if (d->fd != fd)
		return 1;

	/* fprintf(stderr, "descr_read %d\n", fd); */

	if (!(d->flags & DF_ACCEPTED))
		return 0;

	ret = axil_read(fd);
	switch (ret) {
	case -1:
		if (errno == EAGAIN)
			return 0;

		return -1;
	/* case 0: return 0; */
	case 0:
		return -1;
	}

	/* fprintf(stderr, "descr_read %d %d %s\n", d->fd, ret, input); */

	if (axil_parse && axil_parse(fd, input, ret) < 0)
		return 0;

	return cmd_parse(fd, (char *)input, ret);
}

static inline void descr_proc_writes(void)
{
	for (register socket_t i = 0; i < FD_SETSIZE; i++) {
		struct descr *d = &descr_map[i];

		if (!(d->flags & DF_ACCEPTED) && d->cSSL)
			ssl_accept(i);

		if (!FD_ISSET(i, &fds_write) || i == srv_fd ||
		    i == srv_ssl_fd || (d->flags & DF_EXTERN))
			continue;

		if (d->remaining_len)
			axil_write_remaining(i);

		// i is not a pty fd!
		if (d->epid && axil_platform && axil_platform->exec_loop)
			axil_platform->exec_loop(i);
	}
}

static void axil_raw_descr_reset(socket_t fd)
{
	if (fd == INVALID_SOCKET || fd >= FD_SETSIZE)
		return;

	struct descr *d = &descr_map[fd];

	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_wactive);
	FD_CLR(fd, &fds_read);
	FD_CLR(fd, &fds_write);

	axil_ssl_drop(d);

	if (d->remaining_size && d->remaining) {
		free(d->remaining);
		d->remaining = NULL;
	}
	d->remaining_size = 0;
	d->remaining_len = 0;
	d->remaining_off = 0;

	d->resp_headers[0] = '\0';

	if (d->env_hd) {
		axil_env_clear(fd);
		qmap_close(d->env_hd);
		d->env_hd = 0;
	}

	shutdown(fd, 2);
	close(fd);

	tunnel_pair[fd] = INVALID_SOCKET;

	memset(&io[fd], 0, sizeof(struct io));
	memset(d, 0, sizeof(struct descr));
	d->fd = -1;
}

static void axil_tunnel_close_raw(socket_t fd)
{
	if (fd == INVALID_SOCKET || fd >= FD_SETSIZE)
		return;

	socket_t peer = tunnel_pair[fd];

	tunnel_pair[fd] = INVALID_SOCKET;
	if (peer != INVALID_SOCKET && peer < FD_SETSIZE && peer != fd)
		tunnel_pair[peer] = INVALID_SOCKET;

	axil_raw_descr_reset(fd);

	if (peer != INVALID_SOCKET && peer < FD_SETSIZE && peer != fd)
		axil_raw_descr_reset(peer);
}

void axil_clear_active(socket_t cfd)
{
	FD_CLR(cfd, &fds_active);
}

static inline void descr_proc_reads(void)
{
	for (register socket_t i = 0; i < FD_SETSIZE; i++) {
		if (!FD_ISSET(i, &fds_read))
			continue;

		if (i == srv_fd) {
			descr_new(0);
			continue;
		}
		if (i == srv_ssl_fd) {
			descr_new(1);
			continue;
		}

		struct descr *d = &descr_map[i];
		struct io *dio = &io[i];

		/* Descriptor might have been reset earlier in this same pass */
		if (d->fd != i)
			continue;

		/* Externally-watched fd: dispatch to module hook */
		if (d->flags & DF_EXTERN) {
			if (axil_fd_tick)
				axil_fd_tick(i);
			continue;
		}

		/* Waiting for upstream 101 */
		if (d->flags & DF_WS_WAITING) {
			char buf[4096];
			ssize_t n = dio->read(i, buf, sizeof(buf), 0);

			if (n <= 0) {
				axil_tunnel_close_raw(i);
				continue;
			}

			socket_t peer = tunnel_pair[i];
			if (peer == INVALID_SOCKET || peer == i ||
			    peer >= FD_SETSIZE || descr_map[peer].fd != peer ||
			    tunnel_pair[peer] != i ||
			    !(descr_map[peer].flags & DF_WS_PROXY_PENDING))
			{
				axil_tunnel_close_raw(i);
				continue;
			}

			struct io *pdio = &io[peer];

			if (n >= 12 && !strncmp(buf, "HTTP/1.1 101", 12)) {
				/* Forward 101 back to browser */
				pdio->write(peer, buf, n, 0);

				/* Only now enter raw tunnel mode */
				axil_ws_tunnel(peer, i);
			} else {
				/* Forward upstream failure response, then tear
				 * down */
				pdio->write(peer, buf, n, 0);
				axil_tunnel_close_raw(i);
			}
			continue;
		}

		/* Raw tunnel mode */
		if (d->flags & DF_TUNNEL) {
			char buf[4096];
			ssize_t n = dio->read(i, buf, sizeof(buf), 0);

			if (n <= 0) {
				axil_tunnel_close_raw(i);
				continue;
			}

			socket_t peer = tunnel_pair[i];
			if (peer == INVALID_SOCKET || peer == i ||
			    peer >= FD_SETSIZE || descr_map[peer].fd != peer)
			{
				axil_tunnel_close_raw(i);
				continue;
			}

			struct io *pdio = &io[peer];

			/*
			 * IMPORTANT:
			 * axil_low_write() may return -1 merely because it
			 * buffered the data. That is NOT a fatal tunnel error
			 * here.
			 */
			(void)pdio->write(peer, buf, n, 0);
			continue;
		}

		/* Normal axil path */
		if (!d->epid && descr_read(i) < 0)
			axil_close(i);
	}
}

static long long timestamp(void)
{
	struct timeval te;
	gettimeofday(&te, NULL); // get current time
	return te.tv_sec * 1000000LL + te.tv_usec;
}

static void axil_bind(socket_t *srv_fd_r, int ssl)
{
	socket_t srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	int opt;

	CBUG(srv_fd == INVALID_SOCKET, "socket\n");

	opt = 1;
	CBUG(setsockopt(
	             srv_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
	             sizeof(opt)),
	     "setsockopt SO_REUSEADDR\n");

	opt = 1;
	CBUG(setsockopt(
	             srv_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&opt,
	             sizeof(opt)),
	     "setsockopt SO_KEEPALIVE\n");

#ifdef _WIN32
	u_long mode = 1;
	ioctlsocket(srv_fd, FIONBIO, &mode);
#else
	CBUG(fcntl(srv_fd, F_SETFL, O_NONBLOCK) == -1,
	     "fcntl F_SETFL O_NONBLOCK\n");

	CBUG(fcntl(srv_fd, F_SETFD, FD_CLOEXEC) == -1,
	     "fcntl F_SETFL FD_CLOEXEC\n");
#endif

	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(ssl ? axil_config.ssl_port : axil_config.port);

	CBUG(bind(srv_fd, (struct sockaddr *)&server, sizeof(server)), "bind");

	descr_map[srv_fd].fd = srv_fd;

	listen(srv_fd, 32);

	FD_SET(srv_fd, &fds_active);

	*srv_fd_r = srv_fd;
}

static int axil_sni(SSL *ssl, int *ad UNUSED, void *arg UNUSED)
{
	const char *servername =
	        SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername)
		return SSL_TLSEXT_ERR_NOACK; // no SNI

	const cert_t *cert = qmap_get(cert_hd, servername);

	if (cert == NULL)
		return SSL_TLSEXT_ERR_NOACK;

	SSL_set_SSL_CTX(ssl, cert->ctx);

	return SSL_TLSEXT_ERR_OK;
}

/* Speak what we implement. Add h2 here when HTTP/2 exists. */
static int axil_alpn_select(
        SSL *ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *arg)
{
	const unsigned char *p;
	const unsigned char *end;
	unsigned int len;

	(void)ssl;
	(void)arg;
	p = in;
	end = in + inlen;
	while (p < end) {
		len = *p++;
		if (p + len > end)
			break;
		if (len == 8 && !memcmp(p, "http/1.1", 8)) {
			*out = p;
			*outlen = (unsigned char)len;
			return SSL_TLSEXT_ERR_OK;
		}
		p += len;
	}
	return SSL_TLSEXT_ERR_NOACK;
}

SSL_CTX *axil_ctx_new(char *crt, char *key)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	CBUG(!ctx, "SSL_CTX_new\n");

	SSL_CTX_set_alpn_select_cb(ctx, axil_alpn_select, NULL);

	CBUG(!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION),
	     "set_min_proto_version\n");

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	CBUG(!SSL_CTX_set_cipher_list(
	             ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4"),
	     "set_cipher_list\n");

	(void)SSL_CTX_set_ciphersuites(
	        ctx, "TLS_AES_256_GCM_SHA384:"
	             "TLS_AES_128_GCM_SHA256:"
	             "TLS_CHACHA20_POLY1305_SHA256");

	CBUG(!SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384"),
	     "set1_groups_list\n");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	SSL_CTX_set_ecdh_auto(ctx, 1);
#else
	FILE *fp = fopen("/etc/ssl/dhparam.pem", "r");
	CBUG(!fp, "open dhparam.pem\n");
	DH *dh = PEM_read_DHparams(fp, NULL, NULL, NULL);
	CBUG(!dh, "PEM_read_DHparams\n");
	SSL_CTX_set_tmp_dh(ctx, dh);
#endif

	CBUG(SSL_CTX_use_certificate_chain_file(ctx, crt) <= 0,
	     "use_certificate_chain_file\n");
	CBUG(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0,
	     "use_privatekey_file\n");
	CBUG(!SSL_CTX_check_private_key(ctx),
	     "private key does not match certificate\n");

	return ctx;
}

static int openssl_error_callback(const char *str, size_t len, void *u)
{
	(void)u;
	ERR("%.*s\n", (int)len, str);
	return 0;
}

void axil_register(char *name, axil_cb_t *cb, int flags)
{
	struct cmd_slot cmd = { .name = name, .cb = cb, .flags = flags };
	qmap_put(cmds_hd, name, &cmd);
}

static inline void mime_put(char *key, char *value)
{
	qmap_put(mime_hd, key, value);
}

#ifdef __APPLE__
extern int chroot(const char *path);
#endif

static void axil_init(void)
{
	axil_srv_flags |= axil_config.flags | AXIL_WAKE;

	if ((axil_srv_flags & AXIL_DETACH))
		qsyslog = qsys_syslog;

	if (axil_srv_flags & AXIL_SSL) {

		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();

		const cert_t *cert = qmap_get(cert_hd, domain_default);

		default_ssl_ctx = axil_ctx_new(cert->crt, cert->key);

		SSL_CTX_set_tlsext_servername_callback(
		        default_ssl_ctx, axil_sni);

		ERR_print_errors_cb(openssl_error_callback, NULL);
	}

	if (axil_platform && axil_platform->init_pre_bind)
		axil_platform->init_pre_bind();

	mime_put("html", "text/html; charset=utf-8");
	mime_put("txt", "text/plain; charset=utf-8");
	mime_put("css", "text/css");
	mime_put("js", "application/javascript");
	mime_put("wasm", "application/wasm");
	mime_put("jpeg", "image/jpeg");
	mime_put("jpg", "image/jpeg");
	mime_put("png", "image/png");
	mime_put("gif", "image/gif");
	mime_put("webp", "image/webp");
	mime_put("svg", "image/svg+xml");
	mime_put("pdf", "application/pdf");
	mime_put("mp3", "audio/mpeg");
	mime_put("ogg", "audio/ogg");
	mime_put("wav", "audio/wav");
	mime_put("json", "application/json");

	setup_signals();

	input = malloc(input_size);
	if (!input) {
		perror("malloc");
		exit(1);
	}

	if (axil_srv_flags & AXIL_SSL)
		axil_bind(&srv_ssl_fd, 1);

	axil_bind(&srv_fd, 0);

	exec_timeout.tv_sec = EXEC_TIMEOUT / 1000000;
	exec_timeout.tv_usec = EXEC_TIMEOUT % 1000000;
	select_timeout.tv_sec = SELECT_TIMEOUT / 1000000;
	select_timeout.tv_usec = SELECT_TIMEOUT % 1000000;

	if (axil_platform && axil_platform->init_post_bind)
		axil_platform->init_post_bind();
}

int axil_main(void)
{
	struct timeval timeout;

	axil_init();

	axil_tick = timestamp();

	while (axil_srv_flags & AXIL_WAKE) {
		long long last = axil_tick;
		axil_tick = timestamp();
		dt = axil_tick - last;

		if (axil_update)
			axil_update(dt);

		if (!(axil_srv_flags & AXIL_WAKE))
			break;

		for (register int i = 0; i < FD_SETSIZE; i++)
			if (descr_map[i].remaining_len)
				axil_write_remaining(i);

		memcpy(&timeout, &select_timeout, sizeof(timeout));

		fds_read = fds_active;
		fds_write = fds_wactive;
		int select_n = select(
		        FD_SETSIZE, &fds_read, &fds_write, NULL, &timeout);

		switch (select_n) {
		case -1:
			switch (errno) {
			case EAGAIN:
			case EINTR:
				continue;
			case EBADF:
				ERR("select: EBADF\n");
				continue;
			}

			ERR("select\n");
			return -1;

		case 0:
			continue;
		}

		descr_proc_writes();
		descr_proc_reads();
	}

	return 0;
}

static char *env_name(char *key)
{
	static char buf[ENV_KEY_LEN];
	char *b = buf;
	memcpy(b, "HTTP_", 5);
	b += 5;
	for (const char *s = key; *s && (size_t)(b - buf) < sizeof(buf) - 1; s++, b++) {
		if (*s == '-')
			*b = '_';
		else
			*b = (char)toupper((unsigned char)*s);
	}
	*b = '\0';
	return buf;
}

static inline void
headers_get(socket_t fd, size_t *body_start, char *next_lines)
{
	register char *s, *key, *value;

	for (s = next_lines, key = s, value = s; *s;)
		switch (*s) {
		case ':':
			if (value == key) {
				*s = '\0';
				value = (s += 2);
			} else
				s++;
			break;
		case '\r':
			*s = '\0';
			if (s != key) {
				if (s - key >= BUFSIZ)
					*(key + BUFSIZ - 1) = '\0';
				axil_env_put(fd, env_name(key), value);
				key = s += 2;
				value = key;
			} else
				*++s = '\0';

			break;
		default:
			s++;
			break;
		}

	*body_start = s - next_lines;
}

static int request_path_is_safe(const char *target)
{
	char current[BUFSIZ], decoded[BUFSIZ];
	size_t path_len = strcspn(target, "?");

	if (!path_len || path_len >= sizeof(current))
		return 0;
	memcpy(current, target, path_len);
	current[path_len] = '\0';

	for (;;) {
		size_t src = 0, dst = 0;
		int changed = 0;

		while (current[src]) {
			unsigned char c = (unsigned char)current[src++];
			if (c == '%') {
				int hi, lo;

				if (!current[src] || !current[src + 1] ||
				    !isxdigit((unsigned char)current[src]) ||
				    !isxdigit((unsigned char)current[src + 1]))
					return 0;
				hi = isdigit((unsigned char)current[src])
				             ? current[src] - '0'
				             : tolower((unsigned char)
				                               current[src]) -
				                       'a' + 10;
				lo = isdigit((unsigned char)current[src + 1])
				             ? current[src + 1] - '0'
				             : tolower((unsigned char)
				                               current[src +
				                                       1]) -
				                       'a' + 10;
				c = (unsigned char)((hi << 4) | lo);
				src += 2;
				changed = 1;
			}
			if (!c || c == '\\' || c < 0x20 || c == 0x7f)
				return 0;
			decoded[dst++] = (char)c;
		}
		decoded[dst] = '\0';

		for (char *segment = decoded, *p = decoded;; p++) {
			if (*p != '/' && *p)
				continue;
			if (p - segment == 2 && segment[0] == '.' &&
			    segment[1] == '.')
				return 0;
			if (!*p)
				break;
			segment = p + 1;
		}

		if (!changed)
			return decoded[0] == '/';
		memcpy(current, decoded, dst + 1);
	}
}

static char *env_sane(char *str)
{
	static char buf[BUFSIZ];
	char *b;
	for (b = buf;
	     b - buf - 1 < BUFSIZ &&
	     (((unsigned char)*str >= 0x80) || isalnum((unsigned char)*str) ||
	      *str == '/' || *str == '+' || *str == '%' || *str == '&' ||
	      *str == '_' || *str == '-' || *str == ' ' || *str == '=' ||
	      *str == ';' || *str == '.' || *str == '"');
	     str++, b++)
		*b = *str;
	*b = '\0';
	return buf;
}

int axil_env_get(socket_t fd, char *target, size_t dest_len, char *key)
{
	struct descr *d = &descr_map[fd];
	const void *skey = qmap_get(d->env_hd, key);

	if (!skey)
		return 1;

	strlcpy(target, skey, dest_len);
	return 0;
}

int axil_query_parse(char *body)
{
	if (!query_db)
		return -1;

	qmap_drop(query_db);

	if (!body || !*body)
		return 0;

	char *copy = strdup(body);
	if (!copy)
		return -1;

	char *saveptr;
	char *pair = strtok_r(copy, "&", &saveptr);

	while (pair) {
		char *eq = strchr(pair, '=');
		if (eq) {
			*eq = '\0';
			char *key = pair;
			char *value = eq + 1;
			size_t vlen = strlen(value);
			char *decoded = malloc(vlen + 1);
			if (decoded) {
				size_t j = 0;
				for (size_t i = 0; value[i] && j < vlen; i++) {
					if (value[i] == '+') {
						decoded[j++] = ' ';
					} else if (
					        value[i] == '%' &&
					        value[i + 1] && value[i + 2])
					{
						unsigned int c;
						sscanf(value + i + 1, "%2x",
						       &c);
						decoded[j++] = (char)c;
						i += 2;
					} else {
						decoded[j++] = value[i];
					}
				}
				decoded[j] = '\0';
				qmap_put(query_db, key, decoded);
				free(decoded);
			}
		}
		pair = strtok_r(NULL, "&", &saveptr);
	}

	free(copy);
	return 0;
}

int axil_query_param(const char *name, char *buf, size_t buf_len)
{
	if (!query_db || !buf || !buf_len)
		return -1;

	buf[0] = '\0';

	const char *val = (const char *)qmap_get(query_db, name);
	if (!val)
		return -1;

	size_t len = strlen(val);
	if (len >= buf_len)
		len = buf_len - 1;

	memcpy(buf, val, len);
	buf[len] = '\0';
	return (int)len;
}

int axil_param(socket_t fd, const char *name, char *buf, size_t buf_len)
{
	if (!name || !buf || !buf_len)
		return -1;

	int rc = axil_query_param(name, buf, buf_len);
	if (rc > 0 && buf[0] != '\0')
		return rc;

	if (fd > 0) {
		char env_key[128];
		size_t prefix_len = sizeof("PATTERN_PARAM_") - 1;
		memcpy(env_key, "PATTERN_PARAM_", prefix_len);
		size_t i = 0;
		for (; name[i] && prefix_len + i + 1 < sizeof(env_key); i++) {
			char c = name[i];
			if (c >= 'a' && c <= 'z')
				c -= 32;
			env_key[prefix_len + i] = c;
		}
		env_key[prefix_len + i] = '\0';
		if (axil_env_get(fd, buf, buf_len, env_key) == 0 && buf[0] != '\0')
			return (int)strlen(buf);

		/* Fall back to verbatim case pattern param if uppercase didn't match */
		snprintf(env_key, sizeof(env_key), "PATTERN_PARAM_%s", name);
		if (axil_env_get(fd, buf, buf_len, env_key) == 0 && buf[0] != '\0')
			return (int)strlen(buf);
	}

	return -1;
}

int axil_param_int(socket_t fd, const char *name, int default_val)
{
	char tmp[32];
	if (axil_param(fd, name, tmp, sizeof(tmp)) <= 0)
		return default_val;
	char *end = NULL;
	long val = strtol(tmp, &end, 10);
	if (end == tmp)
		return default_val;
	return (int)val;
}

static void
_env_prep(socket_t fd, char *document_uri, char *param, char *method)
{
	char req_content_type[BUFSIZ];

	if (axil_env_get(
	            fd, req_content_type, sizeof(req_content_type),
	            "HTTP_CONTENT_TYPE"))
		strncpy(req_content_type, "text/plain",
		        sizeof(req_content_type));

	axil_env_put(fd, "CONTENT_TYPE", env_sane(req_content_type));
	axil_env_put(fd, "DOCUMENT_URI", document_uri);
	axil_env_put(fd, "QUERY_STRING", env_sane(param));
	axil_env_put(fd, "REQUEST_METHOD", method);
	axil_env_put(
	        fd, "DOCUMENT_ROOT",
#ifdef _WIN32
	        0
#else
	        geteuid()
#endif
	                ? axil_config.chroot
	                : "");
	if (axil_platform && axil_platform->env_prep)
		axil_platform->env_prep(fd);
}

#if defined(_WIN32)
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtime)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)0)
#elif defined(__OpenBSD__)
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtim.tv_sec)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)(sbp)->st_mtim.tv_nsec)
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
        defined(__DragonFly__)
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtimespec.tv_sec)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)(sbp)->st_mtimespec.tv_nsec)
#else
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtim.tv_sec)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)(sbp)->st_mtim.tv_nsec)
#endif

#define AXIL_DEFAULT_CACHE_CONTROL "no-cache"

static void http_date(time_t t, char *out, size_t outlen)
{
	static time_t cached_time = 0;
	static char cached_date[64] = "";

	if (t != 0 && t == cached_time && cached_date[0]) {
		size_t len = strlen(cached_date);
		if (len >= outlen)
			len = outlen - 1;
		memcpy(out, cached_date, len);
		out[len] = '\0';
		return;
	}

	struct tm tm_buf;
	struct tm *tm_info = gmtime_r(&t, &tm_buf);
	if (tm_info) {
		strftime(out, outlen, "%a, %d %b %Y %H:%M:%S GMT", tm_info);
		if (outlen >= sizeof(cached_date)) {
			cached_time = t;
			strncpy(cached_date, out, sizeof(cached_date) - 1);
			cached_date[sizeof(cached_date) - 1] = '\0';
		}
	} else {
		out[0] = '\0';
	}
}

static void static_etag(const struct stat *sb, char *out, size_t outlen)
{
	snprintf(
	        out, outlen, "\"%llx-%llx-%lx-%llx\"",
	        (unsigned long long)sb->st_ino,
	        (unsigned long long)AXIL_ST_MTIME_SEC(sb),
	        (unsigned long)AXIL_ST_MTIME_NSEC(sb),
	        (unsigned long long)sb->st_size);
}

static int month_eq(const char *a, const char *b)
{
	int i;
	for (i = 0; i < 3; i++) {
		char ca = a[i], cb = b[i];
		if (ca >= 'A' && ca <= 'Z')
			ca = (char)(ca + ('a' - 'A'));
		if (cb >= 'A' && cb <= 'Z')
			cb = (char)(cb + ('a' - 'A'));
		if (ca != cb)
			return 0;
	}
	return 1;
}

static int month_number(const char *mon)
{
	static const char *const names[] = { "Jan", "Feb", "Mar", "Apr",
		                             "May", "Jun", "Jul", "Aug",
		                             "Sep", "Oct", "Nov", "Dec" };
	int i;
	for (i = 0; i < 12; i++)
		if (month_eq(mon, names[i]))
			return i;
	return -1;
}

static time_t tm_to_time_t_utc(const struct tm *t)
{
	long long y = (long long)t->tm_year + 1900;
	int m = t->tm_mon + 1;
	long long era;
	long long days;
	unsigned yoe, doy, doe;

	if (m <= 2)
		y--;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = (unsigned)(y - era * 400);
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + (unsigned)t->tm_mday - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	days = era * 146097 + (long long)doe - 719468;

	return (time_t)(days * 86400) + t->tm_hour * 3600 + t->tm_min * 60 +
	       t->tm_sec;
}

static int http_date_parse(const char *s, time_t *out)
{
	char wday[4], mon[4];
	int day, year, hh, mm, ss;
	int m;
	struct tm tm_info;

	if (!s || sscanf(s, "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d GMT", wday,
	                 &day, mon, &year, &hh, &mm, &ss) != 7)
		return -1;

	m = month_number(mon);
	if (m < 0)
		return -1;

	memset(&tm_info, 0, sizeof(tm_info));
	tm_info.tm_year = year - 1900;
	tm_info.tm_mon = m;
	tm_info.tm_mday = day;
	tm_info.tm_hour = hh;
	tm_info.tm_min = mm;
	tm_info.tm_sec = ss;

	*out = tm_to_time_t_utc(&tm_info);
	return 0;
}

static void static_validator_headers(
        const char *etag, const char *last_mod, const char *cache_ctl,
        char *out, size_t outlen)
{
	char etag_hdr[80] = "";
	char last_mod_hdr[100] = "";
	char cache_hdr[256] = "";

	if (etag && *etag)
		snprintf(etag_hdr, sizeof(etag_hdr), "ETag: %s\r\n", etag);
	if (last_mod && *last_mod)
		snprintf(
		        last_mod_hdr, sizeof(last_mod_hdr),
		        "Last-Modified: %s\r\n", last_mod);
	if (cache_ctl && *cache_ctl)
		snprintf(
		        cache_hdr, sizeof(cache_hdr), "Cache-Control: %s\r\n",
		        cache_ctl);

	snprintf(out, outlen, "%s%s%s", etag_hdr, last_mod_hdr, cache_hdr);
}

static void static_cache_control(const char *uri, char *out, size_t outlen)
{
	if (axil_platform && axil_platform->cache_policy &&
	    axil_platform->cache_policy(uri, out, outlen))
		return;
	snprintf(out, outlen, "%s", AXIL_DEFAULT_CACHE_CONTROL);
}

static inline int static_not_modified(
        socket_t fd, const char *etag, const char *last_mod,
        const char *cache_ctl)
{
	struct descr *d = &descr_map[fd];
	char vhdr[512];
	char date[100];

	http_date(time(NULL), date, sizeof(date));
	static_validator_headers(etag, last_mod, cache_ctl, vhdr, sizeof(vhdr));

	d->flags |= DF_TO_CLOSE;
	axil_writef(
	        fd,
	        "HTTP/1.1 304 Not Modified\r\n"
	        "Date: %s\r\n"
	        "Server: axil/0.0.1 (Unix)\r\n"
	        "%s" AXIL_CROSS_ORIGIN_HEADERS "\r\n",
	        date, vhdr);
	if (!d->remaining_len)
		axil_close(fd);
	return 1;
}

static void static_write(
        socket_t fd, char *status, const char *content_type, int want_fd,
        off_t total, const char *etag, const char *last_mod,
        const char *cache_ctl)
{
	struct descr *d = &descr_map[fd];
	char date[100];
	char vhdr[512];

	http_date(time(NULL), date, sizeof(date));
	static_validator_headers(etag, last_mod, cache_ctl, vhdr, sizeof(vhdr));

	char hdr[1024];
	int hlen = snprintf(
	        hdr, sizeof(hdr),
	        "HTTP/1.1 %s\r\n"
	        "Date: %s\r\n"
	        "Server: axil/0.0.1 (Unix)\r\n"
	        "Content-Length: %lu\r\n"
	        "Content-Type: %s\r\n"
	        "%s" AXIL_CROSS_ORIGIN_HEADERS "\r\n",
	        status, date, (unsigned long)total, content_type, vhdr);

	if (d->flags & DF_HEAD) {
		if (hlen > 0)
			axil_write(fd, hdr, (size_t)hlen);
		if (want_fd > 0)
			close(want_fd);
		goto end;
	}

	if (want_fd <= 0) {
		if (hlen > 0)
			axil_write(fd, hdr, (size_t)hlen);
		axil_writef(fd, "%s\r\n", status);
		goto end;
	}

	// static file: read into buffer and combine with headers if it fits in 64KB
	char b[BUFSIZ * 16];
	ssize_t first_len = read(want_fd, b, sizeof(b));
	if (first_len > 0) {
		if (hlen > 0 && (size_t)hlen + (size_t)first_len <= sizeof(b)) {
			char combined[sizeof(b) + sizeof(hdr)];
			memcpy(combined, hdr, (size_t)hlen);
			memcpy(combined + hlen, b, (size_t)first_len);
			axil_write(fd, combined, (size_t)hlen + (size_t)first_len);
		} else {
			if (hlen > 0)
				axil_write(fd, hdr, (size_t)hlen);
			axil_write(fd, b, (size_t)first_len);
		}

		ssize_t len;
		while ((len = read(want_fd, b, sizeof(b))) > 0)
			axil_write(fd, b, len);
	} else if (hlen > 0) {
		axil_write(fd, hdr, (size_t)hlen);
	}

	close(want_fd);

end:
	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		axil_close(fd);
}

/* RFC 7232 3.2: If-None-Match may be "*" or a comma-separated list of
 * entity-tags. Return 1 when the value matches the strong etag. */
static int static_etag_matches(const char *inm, const char *etag)
{
	const char *p, *q;
	size_t len;

	if (strcmp(inm, "*") == 0)
		return 1;

	p = inm;
	len = strlen(etag);
	while (*p) {
		while (*p == ' ' || *p == '\t' || *p == ',')
			p++;
		if (!*p)
			break;
		q = p;
		while (*q && *q != ',')
			q++;
		while (q > p && (q[-1] == ' ' || q[-1] == '\t'))
			q--;
		if ((size_t)(q - p) == len && strncmp(p, etag, len) == 0)
			return 1;
		p = q;
	}
	return 0;
}

static inline int
request_handle_static(socket_t fd, char *document_uri, struct stat *stat_buf)
{
	char buf[BUFSIZ];
	char etag[64];
	char last_mod[100];
	char cache_ctl[256];
	char inm[64] = { 0 };
	char ims[64] = { 0 };
	time_t ims_time;
	errno = 0;
	char *ext, *s;
	const char *content_type;

	if (document_uri[strlen(document_uri) - 1] == '/') {
		snprintf(buf, sizeof(buf), "%sindex.html", document_uri);
		document_uri = buf;
	}

	char *filename = NULL;
	if (axil_platform && axil_platform->static_allowed)
		filename =
		        axil_platform->static_allowed(document_uri, stat_buf);

	if (!filename)
		return 0;
	if (!S_ISREG(stat_buf->st_mode))
		return 0;

	ext = filename;
	for (s = ext; *s; s++)
		if (*s == '.')
			ext = s + 1;

	content_type = "application/octet-stream";
	if (ext) {
		const void *skey = qmap_get(mime_hd, ext);
		if (skey)
			content_type = skey;
	}

	static_etag(stat_buf, etag, sizeof(etag));
	http_date(stat_buf->st_mtime, last_mod, sizeof(last_mod));
	static_cache_control(document_uri, cache_ctl, sizeof(cache_ctl));

	/* RFC 7232 6: If-None-Match takes precedence over If-Modified-Since. */
	if (axil_header_get(fd, "If-None-Match", inm, sizeof(inm)) == 0) {
		if (static_etag_matches(inm, etag))
			return static_not_modified(
			        fd, etag, last_mod, cache_ctl);
	} else if (
	        axil_header_get(fd, "If-Modified-Since", ims, sizeof(ims)) ==
	                0 &&
	        http_date_parse(ims, &ims_time) == 0 &&
	        stat_buf->st_mtime <= ims_time)
	{
		return static_not_modified(fd, etag, last_mod, cache_ctl);
	}

	static_write(
	        fd, "200 OK", content_type, open(filename, O_RDONLY),
	        stat_buf->st_size, etag, last_mod, cache_ctl);

	return 1;
}

static inline int request_handle_redirect(socket_t fd, char *document_uri)
{
	struct descr *d = &descr_map[fd];

	if ((axil_srv_flags & AXIL_SSL_ONLY) && (axil_srv_flags & AXIL_SSL) &&
	    !d->cSSL)
	{
		char host[ENV_KEY_LEN] = { 0 };
		axil_env_get(fd, host, sizeof(host), "HTTP_HOST");
		char response[8285];
		d->flags |= DF_TO_CLOSE;

		snprintf(
		        response, sizeof(response),
		        "HTTP/1.1 301 Moved Permanently\r\n"
		        "Location: https://%s%s\r\n"
		        "Content-Length: 0\r\n"
		        "Connection: close\r\n"
		        "\r\n",
		        host, document_uri);
		axil_writef(fd, "%s", response);

		if (!d->remaining_len)
			axil_close(fd);

		return 1;
	}

	return 0;
}

// Generates and sends an HTML directory listing.
static inline void
request_handle_autoindex(socket_t fd, const char *uri_path, const char *fs_path)
{
	char body[BUFSIZ * 8]; // 8KB buffer for the HTML body
	char line[BUFSIZ * 2];
	size_t body_len = 0;
	DIR *dir;
	struct dirent *entry;

	memset(body, 0, sizeof(body));

	dir = opendir(fs_path);
	if (!dir) {
		static_write(
		        fd, "500 Internal Server Error", "text/plain", -1, 27,
		        "", "", "");
		return;
	}

	// Start building the HTML body
	body_len = snprintf(
	        body, sizeof(body),
	        "<!DOCTYPE html><html><head><title>Index of %s</title></head>"
	        "<body><h1>Index of %s</h1><hr><pre>",
	        uri_path, uri_path);

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(
		        line, sizeof(line), "<a href=\"./%s\">%s</a>\n",
		        entry->d_name, entry->d_name);

		// Append to body, checking buffer size
		if (body_len + strlen(line) < sizeof(body) - 20)
		{ // Keep some safety margin
			strcat(body, line);
			body_len += strlen(line);
		}
	}
	closedir(dir);

	strcat(body, "</pre><hr></body></html>");
	body_len += 26;

	// Write HTTP headers and the generated body
	time_t now = time(NULL);
	struct tm *tm_info = gmtime(&now);
	char date[100];
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tm_info);

	axil_writef(
	        fd,
	        "HTTP/1.1 200 OK\r\n"
	        "Date: %s\r\n"
	        "Server: axil/0.0.1 (Unix)\r\n"
	        "Content-Length: %lu\r\n"
	        "Content-Type: text/html\r\n"
	        "Connection: close\r\n" AXIL_CROSS_ORIGIN_HEADERS "\r\n",
	        date, body_len);
	axil_write(fd, body, body_len);

	struct descr *d = &descr_map[fd];
	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		axil_close(fd);
}

typedef struct {
	char env_key[256];
	char value[256];
} axil_pattern_param_t;

typedef struct {
	int matched;
	int literal_chars;
	int param_count;
	int wildcard_count;
	int param_used;
	axil_pattern_param_t params[16];
} axil_pattern_match_t;

static void
pattern_commit_params(socket_t fd, const axil_pattern_match_t *match)
{
	int i;

	for (i = 0; i < match->param_used; i++)
		axil_env_put(
		        fd, (char *)match->params[i].env_key,
		        (char *)match->params[i].value);
}

static int pattern_better_match(
        const axil_pattern_match_t *candidate, const axil_pattern_match_t *best)
{
	if (!best->matched)
		return 1;

	if (candidate->wildcard_count != best->wildcard_count)
		return candidate->wildcard_count < best->wildcard_count;

	if (candidate->literal_chars != best->literal_chars)
		return candidate->literal_chars > best->literal_chars;

	if (candidate->param_count != best->param_count)
		return candidate->param_count < best->param_count;

	return 0;
}

/* Match a URL pattern against a path.
 * Supports:
 *   - :param single-segment captures
 *   - terminal * catch-alls (e.g. "/sb/" followed by "*")
 *   - optional trailing slash on either the pattern or the path
 */
static int
pattern_match(const char *pat, const char *path, axil_pattern_match_t *m)
{
	memset(m, 0, sizeof(*m));

	for (;;) {
		/* skip redundant trailing slashes */
		while (*pat == '/' &&
		       (pat[1] == '/' || !pat[1] || pat[1] == '?'))
			pat++;

		while (*path == '/' &&
		       (path[1] == '/' || !path[1] || path[1] == '?'))
			path++;

		/* both done */
		if ((!*pat || *pat == '?') && (!*path || *path == '?')) {
			m->matched = 1;
			return 1;
		}

		/* one ended early */
		if (!*pat || !*path || *pat == '?' || *path == '?')
			return 0;

		/* wildcard */
		if (*pat == '*' &&
		    (!pat[1] || pat[1] == '?' ||
		     (pat[1] == '/' && (!pat[2] || pat[2] == '?'))))
		{
			m->wildcard_count++;
			m->matched = 1;
			return 1;
		}

		/* consume slash */
		if (*pat == '/' || *path == '/') {
			if (*pat != *path)
				return 0;
			pat++;
			path++;
			continue;
		}

		const char *ps = pat;
		const char *us = path;

		while (*pat && *pat != '/' && *pat != '?')
			pat++;

		while (*path && *path != '/' && *path != '?')
			path++;

		size_t plen = pat - ps;
		size_t ulen = path - us;

		/* parameter */
		if (*ps == ':') {
			if (!ulen)
				return 0;

			if (m->param_used >=
			    (int)(sizeof(m->params) / sizeof(m->params[0])))
				return 0;

			axil_pattern_param_t *pp = &m->params[m->param_used++];

			size_t k = snprintf(
			        pp->env_key, sizeof(pp->env_key),
			        "PATTERN_PARAM_");

			for (size_t i = 1;
			     i < plen && k + 1 < sizeof(pp->env_key); i++)
				pp->env_key[k++] =
				        toupper((unsigned char)ps[i]);

			pp->env_key[k] = 0;

			if (ulen >= sizeof(pp->value))
				return 0;

			memcpy(pp->value, us, ulen);
			pp->value[ulen] = 0;

			m->param_count++;
			continue;
		}

		/* literal */
		if (plen != ulen || memcmp(ps, us, plen))
			return 0;

		m->literal_chars += plen;
	}
}

/* Pattern matching for registered handlers
 * Supports :param syntax (e.g., "/chords/:id")
 * Sets PATTERN_PARAM_* env vars for matched parameters
 */
static axil_handler_t *axil_match_pattern(
        const char *path_with_method, const char *document_uri, socket_t fd)
{
	/* Iterate through all registered handlers */
	uint32_t cur = qmap_iter(hdlr_hd, NULL, 0);
	const void *pattern_key;
	const void *handler_ptr;
	axil_handler_t *best_handler = NULL;
	axil_pattern_match_t best_match;

	memset(&best_match, 0, sizeof(best_match));

	while (qmap_next(&pattern_key, &handler_ptr, cur)) {
		const char *pattern = (const char *)pattern_key;
		axil_pattern_match_t candidate;
		int matched = 0;

		/* Skip non-patterns (no special path syntax) */
		if (!strchr(pattern, ':') && !strchr(pattern, '*'))
			continue;

		memset(&candidate, 0, sizeof(candidate));
		if (pattern_match(pattern, path_with_method, &candidate))
			matched = 1;
		else if (pattern_match(pattern, document_uri, &candidate))
			matched = 1;

		if (matched && pattern_better_match(&candidate, &best_match)) {
			memcpy(&best_handler, handler_ptr,
			       sizeof(best_handler));
			best_match = candidate;
		}
	}

	qmap_fin(cur);

	if (!best_handler)
		return NULL;

	pattern_commit_params(fd, &best_match);
	return best_handler;
}

/* Ensures the full POST body is present in the global `input` buffer.
 * Returns 0 on success, -1 if the request was rejected (caller must return). */
static int
buffer_post_body(socket_t fd, int argc, char *argv[], size_t body_start)
{
	char clen_str[32] = { 0 };
	axil_env_get(fd, clen_str, sizeof(clen_str), "HTTP_CONTENT_LENGTH");
	if (!clen_str[0])
		return 0;

	size_t content_length = strtoul(clen_str, NULL, 10);
	size_t limit = axil_config.max_body_size ? axil_config.max_body_size
	                                         : AXIL_DEFAULT_MAX_BODY_SIZE;

	if (content_length > limit) {
		axil_header_set(fd, "Connection", "close");
		axil_set_flags(fd, DF_TO_CLOSE);
		axil_respond(fd, 413, "");
		return -1;
	}

	size_t headers_offset = (size_t)(argv[argc] - (char *)input);
	size_t needed = headers_offset + body_start + 1 + content_length;
	struct io *dio = &io[fd];

	while (input_len < needed) {
		char buf[BUFSIZ];
		ssize_t n = dio->read(fd, buf, sizeof(buf), 0);
		if (n <= 0) {
			/* Client disconnected or lied about Content-Length */
			axil_close(fd);
			return -1;
		}
		if (input_len + (size_t)n > input_size) {
			char *old_base = (char *)input;
			size_t old_size = input_size;
			input_size = (input_len + (size_t)n) * 2;
			input = realloc(input, input_size);
			if (!input) {
				input = (unsigned char *)old_base;
				input_size = old_size;
				axil_close(fd);
				return -1;
			}
			ptrdiff_t shift = (char *)input - old_base;
			for (int i = 0; i <= argc; i++)
				argv[i] += shift;
		}
		memcpy(input + input_len, buf, n);
		input_len += (size_t)n;
	}

	return 0;
}

static inline int request_handle_trailing_slash(socket_t fd, char *document_uri)
{
	struct stat stat_buf;
	int uri_len = strlen(document_uri);

	if (uri_len > 1 && document_uri[uri_len - 1] != '/') {
		char *fs_path = NULL;
		if (axil_platform && axil_platform->static_allowed)
			fs_path = axil_platform->static_allowed(
			        document_uri, &stat_buf);

		if (fs_path && S_ISDIR(stat_buf.st_mode)) {
			struct descr *d = &descr_map[fd];
			char host[ENV_KEY_LEN] = { 0 };
			axil_env_get(fd, host, sizeof(host), "HTTP_HOST");
			const char *scheme = d->cSSL ? "https" : "http";

			axil_writef(
			        fd,
			        "HTTP/1.1 301 Moved Permanently\r\n"
			        "Location: %s://%s%s/\r\n"
			        "Content-Length: 0\r\n"
			        "Connection: close\r\n"
			        "\r\n",
			        scheme, host, document_uri);

			d->flags |= DF_TO_CLOSE;
			if (!d->remaining_len)
				axil_close(fd);
			return 1;
		}
	}

	return 0;
}

static void request_handle(socket_t fd, int argc, char *argv[], int req_flags)
{
	char *method;
	struct descr *d = &descr_map[fd];
	size_t body_start;
	char document_uri[BUFSIZ], *param;
	struct stat stat_buf;

	if (req_flags & AXIL_POST)
		method = "POST";
	else if (req_flags & AXIL_PUT)
		method = "PUT";
	else if (req_flags & AXIL_DELETE)
		method = "DELETE";
	else if (req_flags & AXIL_HEAD) {
		method = "HEAD";
		d->flags |= DF_HEAD;
	} else
		method = "GET";

	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->addr.sin_addr, ipstr, sizeof(ipstr));
	WARN("%d (%s) %s %s\n", fd, ipstr, method, argv[1]);

	if (argc < 2 || !request_path_is_safe(argv[1])) {
		axil_close(fd);
		return;
	}

	size_t target_len = strlen(argv[1]);
	if (target_len >= sizeof(document_uri)) {
		axil_respond(fd, 414, "URI Too Long");
		axil_close(fd);
		return;
	}
	size_t decoded_len = axil_url_decode(
	        argv[1], target_len, document_uri, sizeof(document_uri));
	if (memchr(document_uri, '\0', decoded_len)) {
		axil_close(fd);
		return;
	}

	param = strchr(document_uri, '?');
	if (param)
		*param++ = '\0';
	else
		param = "";

	headers_get(fd, &body_start, argv[argc]);

	/* For requests with Content-Length (POST/PUT/DELETE), ensure full body is buffered.
	 * axil_read() may return after reading only the headers if the body
	 * arrives in a separate TCP segment. */
	if (req_flags & (AXIL_POST | AXIL_PUT | AXIL_DELETE)) {
		if (buffer_post_body(fd, argc, argv, body_start) < 0)
			return;
	}

	if (axil_platform && axil_platform->auth_try)
		axil_platform->auth_try(fd);

	if (request_handle_trailing_slash(fd, document_uri))
		return;

	/* Check for registered websocket handler before auto-detection */
	char path_with_method[16384];
	snprintf(
	        path_with_method, sizeof(path_with_method), "%s:%s", method,
	        document_uri);
	const void *ws_key = qmap_get(ws_hd, path_with_method);
	if (!ws_key)
		ws_key = qmap_get(ws_hd, document_uri);

	axil_ws_upstream_t *ws_handler = NULL;
	if (ws_key) {
		memcpy(&ws_handler, ws_key, sizeof(ws_handler));
	}

	/* Prepare environment for handlers */
	char *body = argv[argc] + body_start + 1;
	_env_prep(fd, document_uri, param, method);

	/* If websocket handler registered, call it */
	if (ws_handler) {
		socket_t upstream = ws_handler(fd);
		if (upstream != INVALID_SOCKET) {
#ifndef _WIN32
			fcntl(upstream, F_SETFL, O_NONBLOCK);
#endif

			char ws_key[128];
			if (axil_env_get(
			            fd, ws_key, sizeof(ws_key),
			            "HTTP_SEC_WEBSOCKET_KEY"))
			{
				fprintf(stderr,
				        "WS: no Sec-WebSocket-Key header\n");
				close(upstream);
			} else {
				char req_buf[2048];
				int len = snprintf(
				        req_buf, sizeof(req_buf),
				        "%s %s HTTP/1.1\r\n"
				        "Host: 127.0.0.1:3000\r\n"
				        "Upgrade: websocket\r\n"
				        "Connection: Upgrade\r\n"
				        "Sec-WebSocket-Key: %s\r\n"
				        "Sec-WebSocket-Version: 13\r\n"
				        "\r\n",
				        argv[0], argv[1], ws_key);

				if (len <= 0 || len >= (int)sizeof(req_buf)) {
					close(upstream);
					return;
				}

				if (upstream >= FD_SETSIZE) {
					close(upstream);
					return;
				}

				axil_upstream_descr_init(upstream);

				tunnel_pair[fd] = upstream;
				tunnel_pair[upstream] = fd;

				/* both ends belong to the same pending WS proxy
				 * pair */
				descr_map[fd].flags |= DF_WS_PROXY_PENDING;
				descr_map[upstream].flags |=
				        DF_WS_WAITING | DF_WS_PROXY_PENDING;

				FD_SET(upstream, &fds_active);

#ifdef MSG_NOSIGNAL
				ssize_t wr = send(
				        upstream, req_buf, len, MSG_NOSIGNAL);
#else
				ssize_t wr = write(upstream, req_buf, len);
#endif
				if (wr < 0 || wr < len) {
					axil_tunnel_close_raw(upstream);
				}
			}
		}
		return;
	}

	if (!(d->flags & DF_WEBSOCKET))
		d->flags |= DF_TO_CLOSE;

	if (request_handle_static(fd, document_uri, &stat_buf))
		return;

	char *autoindex_path = NULL;
	if (axil_platform && axil_platform->autoindex_allowed)
		autoindex_path = axil_platform->autoindex_allowed(
		        document_uri, &stat_buf);
	if (autoindex_path) {
		request_handle_autoindex(fd, document_uri, autoindex_path);
		return;
	}

	if (request_handle_redirect(fd, document_uri))
		return;

	/* Try HTTP handler match */
	const void *key = qmap_get(hdlr_hd, path_with_method);
	if (!key && (req_flags & AXIL_HEAD)) {
		char get_path[16384];
		snprintf(get_path, sizeof(get_path), "GET:%s", document_uri);
		key = qmap_get(hdlr_hd, get_path);
	}
	if (!key)
		key = qmap_get(hdlr_hd, document_uri);

	axil_handler_t *hdlr = NULL;
	if (key) {
		memcpy(&hdlr, key, sizeof(hdlr));
	} else {
		/* Try pattern matching */
		hdlr = axil_match_pattern(path_with_method, document_uri, fd);
		if (!hdlr && (req_flags & AXIL_HEAD)) {
			char get_path[16384];
			snprintf(get_path, sizeof(get_path), "GET:%s", document_uri);
			hdlr = axil_match_pattern(get_path, document_uri, fd);
		}
	}

	if (hdlr) {
		hdlr(fd, body);
		return;
	}

	if (axil_config.default_handler) {
		axil_config.default_handler(fd, body);
		return;
	}

	for (size_t i = 0; i < fallback_handlers_len; i++) {
		if (fallback_handlers[i](fd, body))
			return;
	}

	axil_respond(fd, 404, "404 Not Found\n");
}

void axil_register_handler(char *path, axil_handler_t handler)
{
	qmap_put(hdlr_hd, path, &handler);
}

int axil_register_fallback_handler(axil_handler_t handler)
{
	if (fallback_handlers_len >= FALLBACK_MAX)
		return -1;

	fallback_handlers[fallback_handlers_len++] = handler;
	return 0;
}

void axil_ws_handler(char *path, axil_ws_upstream_t handler)
{
	qmap_put(ws_hd, path, &handler);
}

int axil_ws_upgrade(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	char buf[ENV_VALUE_LEN];

	if (d->flags & DF_WEBSOCKET)
		return 0;

	if (axil_env_get(fd, buf, sizeof(buf), "HTTP_SEC_WEBSOCKET_KEY"))
		return -1;

	struct io *dio = &io[fd];
	if (ws_init(fd, buf))
		return -1;

	d->flags |= DF_WEBSOCKET;
	dio->read = ws_read;
	dio->write = ws_write;

	if (!axil_connect || axil_connect(fd))
		d->flags |= DF_CONNECTED;

	return 0;
}

int axil_ws_write(socket_t fd, const void *data, size_t len)
{
	return ws_write(fd, (void *)data, len, 0);
}

ssize_t axil_ws_read(socket_t fd, void *buf, size_t len)
{
	return ws_read(fd, buf, len, 0);
}

int axil_ws_close(socket_t fd)
{
	ws_close(fd);
	return 0;
}

int axil_ws_printf(socket_t fd, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int ret = ws_dprintf(fd, fmt, args);
	va_end(args);
	return ret;
}

static void axil_ws_tunnel(socket_t a, socket_t b)
{
	struct descr *da = &descr_map[a];
	struct descr *db = &descr_map[b];

#ifndef _WIN32
	fcntl(a, F_SETFL, O_NONBLOCK);
	fcntl(b, F_SETFL, O_NONBLOCK);
#endif

	FD_SET(a, &fds_active);
	FD_SET(b, &fds_active);

	da->flags &= ~(DF_WS_WAITING | DF_WS_PROXY_PENDING);
	db->flags &= ~(DF_WS_WAITING | DF_WS_PROXY_PENDING);

	da->flags |= DF_TUNNEL;
	db->flags |= DF_TUNNEL;

	tunnel_pair[a] = b;
	tunnel_pair[b] = a;
}

void do_GET(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, 0);
	qmap_drop(query_db);
}

void do_HEAD(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_HEAD);
	qmap_drop(query_db);
}

void do_POST(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_POST);
	qmap_drop(query_db);
}

void do_PUT(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_PUT);
	qmap_drop(query_db);
}

void do_DELETE(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_DELETE);
	qmap_drop(query_db);
}

int axil_flags(socket_t fd)
{
	return descr_map[fd].flags;
}

void axil_set_flags(socket_t fd, int flags)
{
	descr_map[fd].flags = flags;
}

#ifndef _WIN32
int axil_get_pw(socket_t fd, struct passwd *out)
{
	struct descr *d = &descr_map[fd];
	if (!(d->flags & DF_AUTHENTICATED))
		return -1;
	*out = d->pw;
	out->pw_name = d->pw.pw_name ? strdup(d->pw.pw_name) : NULL;
	out->pw_shell = d->pw.pw_shell ? strdup(d->pw.pw_shell) : NULL;
	out->pw_dir = d->pw.pw_dir ? strdup(d->pw.pw_dir) : NULL;
	return 0;
}

void axil_fd_watch(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	d->fd = fd;
	d->flags |= DF_EXTERN;
	FD_SET(fd, &fds_active);
}

void axil_fd_unwatch(socket_t fd)
{
	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_read);
}

void axil_fork_child_reset(void)
{
	do_cleanup = 0;
}
#endif

__attribute__((constructor)) static void axil_pre_init(void)
{
	memset(&axil_config, 0, sizeof(axil_config));
	axil_config.port = 80;
	axil_config.ssl_port = 443;

	for (int i = 0; i < FD_SETSIZE; i++)
		tunnel_pair[i] = INVALID_SOCKET;

	unsigned cert_type = qmap_reg(sizeof(cert_t));
	unsigned cmd_type = qmap_reg(sizeof(struct cmd_slot));
	unsigned hdlr_type = qmap_reg(sizeof(axil_handler_t *));
	unsigned ws_type = qmap_reg(sizeof(axil_ws_upstream_t *));

	query_db = qmap_open(NULL, NULL, QM_STR, QM_STR, 0xFF, 0);
	mime_hd = qmap_open(NULL, NULL, QM_STR, QM_STR, MIME_MASK, 0);
	cert_hd = qmap_open(NULL, NULL, QM_STR, cert_type, CERT_MASK, 0);
	hdlr_hd = qmap_open(NULL, NULL, QM_STR, hdlr_type, HDLR_MASK, 0);
	ws_hd = qmap_open(NULL, NULL, QM_STR, ws_type, HDLR_MASK, 0);
	cmds_hd = qmap_open(NULL, NULL, QM_STR, cmd_type, CMD_MASK, 0);

	/* Register default HTTP command handlers */
	/* These need to be in the library, not just the axil binary */
	axil_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("HEAD", do_HEAD, CF_NOAUTH | CF_NOTRIM);
	axil_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);
	axil_register("PUT", do_PUT, CF_NOAUTH | CF_NOTRIM);
	axil_register("DELETE", do_DELETE, CF_NOAUTH | CF_NOTRIM);
}

int axil_respond_file(socket_t fd, const char *path, const char *allowed_exts)
{
	char len_buf[32];
	const char *ext = NULL;
	const char *mime = NULL;
	FILE *fp;
	struct stat st;
	char *buf;
	const char *filename;

	if (!path || !path[0]) {
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}

	filename = strrchr(path, '/');
	filename = filename ? filename + 1 : path;

	ext = strrchr(filename, '.');
	if (!ext || !ext[1]) {
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}
	ext++; /* skip '.' */

	if (mime_hd) {
		const void *val = qmap_get(mime_hd, ext);
		if (val)
			mime = (const char *)val;
	}
	if (!mime)
		mime = "application/octet-stream";

	if (allowed_exts && allowed_exts[0]) {
		if (!strstr(allowed_exts, ext)) {
			axil_respond_plain(fd, 404, "Not found");
			return -1;
		}
	}

	fp = fopen(path, "rb");
	if (!fp) {
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}
	if (fstat(fileno(fp), &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size < 0)
	{
		fclose(fp);
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}

	if (st.st_size == 0) {
		fclose(fp);
		axil_header_set(fd, "Content-Type", mime);
		axil_header_set(fd, "Content-Length", "0");
		axil_respond(fd, 200, "");
		return 0;
	}

	buf = malloc((size_t)st.st_size);
	if (!buf) {
		fclose(fp);
		axil_respond_plain(fd, 500, "Internal server error");
		return -1;
	}
	if (fread(buf, 1, (size_t)st.st_size, fp) != (size_t)st.st_size) {
		fclose(fp);
		free(buf);
		axil_respond_plain(fd, 500, "Short read");
		return -1;
	}
	fclose(fp);

	snprintf(len_buf, sizeof(len_buf), "%ld", (long)st.st_size);
	axil_header_set(fd, "Content-Type", mime);
	axil_header_set(fd, "Content-Length", len_buf);
	axil_respond(fd, 200, NULL);
	if (!(descr_map[fd].flags & DF_HEAD))
		axil_write(fd, buf, (size_t)st.st_size);
	free(buf);
	return 0;
}

void _axil_cert_add(char *domain, char *crt, char *key)
{
	SSL_CTX *ssl_ctx = axil_ctx_new(crt, key);
	cert_t cert = {
		.crt = crt,
		.key = key,
		.domain = domain,
		.ctx = ssl_ctx,
	};

	unsigned id = qmap_put(cert_hd, domain, &cert);
	WARN("%u '%s' '%s' '%s'\n", id, domain, crt, key);
	if (!domain_default)
		domain_default = domain;
}
