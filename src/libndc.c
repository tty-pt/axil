#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1

#include <stdio.h>

#include "../include/ttypt/ndc.h"
#include "../include/iio.h"
#include "ndc-internal.h"

#include <ttypt/ndx.h>

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
#define	SB 250
#define TELOPT_ECHO 1
#define TELOPT_SGA 3
#define	TELOPT_NAWS 31

#define OPOST	0000001
#define ONLCR	0000004
#define OCRNL	0000010

#define ICANON	0000002
#define ECHO	0000010
#define ECHOK	0000040
#define ECHOCTL 0001000
#define IGNCR	0000200
#define ICRNL	0000400
#define INLCR	0000100

#define	TCSANOW		0
#else
#include <arpa/inet.h>
#include <fnmatch.h>
#include <grp.h>
#include <netinet/in.h>
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

#define DESCR_ITER \
	for (register int di_i = 1; di_i < FD_SETSIZE; di_i++) \
		if (!FD_ISSET(di_i, &fds_read) || !(descr_map[di_i].flags & DF_CONNECTED)) continue; \
		else


#define FIRST_INPUT_SIZE (BUFSIZ * 2)
#define SELECT_TIMEOUT 10000
#define EXEC_TIMEOUT 1000

struct descr descr_map[FD_SETSIZE];

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

ndc_cb_t do_GET, do_POST, do_sh;

static unsigned char *input;
static size_t input_size = FIRST_INPUT_SIZE, input_len = 0;

#define NDC_DEFAULT_MAX_BODY_SIZE (10UL * 1024UL * 1024UL)
#define NDC_CROSS_ORIGIN_HEADERS \
		"Cross-Origin-Opener-Policy: same-origin\r\n" \
		"Cross-Origin-Embedder-Policy: require-corp\r\n" \
		"Cross-Origin-Resource-Policy: same-origin\r\n"

struct timeval select_timeout, exec_timeout;

struct io io[FD_SETSIZE];

struct ndc_config ndc_config;
socket_t srv_ssl_fd = -1, srv_fd = -1;

int ndc_srv_flags = 0;
static unsigned cmds_hd;
fd_set fds_read, fds_active, fds_write, fds_wactive;
socket_t tunnel_pair[FD_SETSIZE];
long long dt, tack = 0;
SSL_CTX *default_ssl_ctx;
long long ndc_tick;
int do_cleanup = 1;

char ndc_execbuf[BUFSIZ * 64];

char *domain_default = NULL;
unsigned cert_hd, mime_hd, hdlr_hd, ws_hd;
static unsigned query_db;
static ndc_handler_t *fallback_handlers[FALLBACK_MAX];
static size_t fallback_handlers_len;

static void ndc_ws_tunnel(socket_t a, socket_t b);

static int
header_name_eq(const char *line, size_t line_len, const char *name)
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

static int
ndc_header_has(socket_t fd, const char *key)
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
ndc_header_set_default(socket_t fd, const char *key, const char *value)
{
	if (!ndc_header_has(fd, key))
		ndc_header_set(fd, key, value);
}

static void
ndc_default_response_headers(socket_t fd)
{
	ndc_header_set_default(fd, "Cross-Origin-Opener-Policy",
			"same-origin");
	ndc_header_set_default(fd, "Cross-Origin-Embedder-Policy",
			"require-corp");
	ndc_header_set_default(fd, "Cross-Origin-Resource-Policy",
			"same-origin");
}

void
ndc_env_clear(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	unsigned cur = qmap_iter(d->env_hd, NULL, 0);
	const void *key, *value;

	while (qmap_next(&key, &value, cur))
		qmap_del(d->env_hd, key);

	d->resp_headers[0] = '\0';
}

unsigned
ndc_env(socket_t fd)
{
	return descr_map[fd].env_hd;
}

void
ndc_header_set(socket_t fd, const char *key, const char *value)
{
	struct descr *d = &descr_map[fd];
	size_t len = strlen(d->resp_headers);
	snprintf(d->resp_headers + len, BUFSIZ - len, "%s: %s\r\n", key, value);
}

int
ndc_header_get(socket_t fd, const char *key, char *buf, size_t buf_len)
{
	char env_key[ENV_KEY_LEN];
	size_t i;

	snprintf(env_key, sizeof(env_key), "HTTP_");
	size_t prefix_len = strlen(env_key);

	for (i = 0; key[i] && prefix_len + i < sizeof(env_key) - 1; i++) {
		char c = key[i];
		env_key[prefix_len + i] = (c == '-') ? '_' : (char)toupper((unsigned char)c);
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

static void
ndc_head(socket_t fd, int code)
{
	struct descr *d = &descr_map[fd];
	/* Send status line */
	ndc_writef(fd, "HTTP/1.1 %d %s\r\n", code, ndc_status_text(code));
	ndc_default_response_headers(fd);
	/* Send accumulated headers */
	if (*d->resp_headers) {
		ndc_writef(fd, "%s", d->resp_headers);
	}
	/* Send final CRLF to end headers section */
	ndc_writef(fd, "\r\n");
	/* Clear buffer */
	d->resp_headers[0] = '\0';
}

static void
ndc_body(socket_t fd, const char *body)
{
	/* Just send body content - headers already sent by ndc_head() */
	if (body && *body)
		ndc_write(fd, (void *)body, strlen(body));
	ndc_close(fd);
}

void
ndc_respond(socket_t fd, int code, const char *body)
{
	ndc_head(fd, code);
	if (body != NULL)
		ndc_body(fd, body);
}


static void
ndc_raw_descr_reset(socket_t fd);

static void
ndc_tunnel_close_raw(socket_t fd);

void
ndc_close(socket_t fd)
{
	if (fd == INVALID_SOCKET || fd >= FD_SETSIZE)
		return;

	struct descr *d = &descr_map[fd];

	/*
	 * Tunnel descriptors and pending WS proxy pairs must use unified pair teardown.
	 * Otherwise one side can survive with a stale tunnel_pair[] entry and later hit
	 * an unrelated connection that reuses the same fd number.
	 */
	if (d->flags & (DF_TUNNEL | DF_WS_PROXY_PENDING | DF_WS_WAITING)) {
		ndc_tunnel_close_raw(fd);
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

	if ((d->flags & DF_CONNECTED) && ndc_disconnect)
		ndc_disconnect(fd);

	if (d->flags & DF_WEBSOCKET)
		ws_close(fd);

	if (ndc_platform && ndc_platform->cleanup_descr)
		ndc_platform->cleanup_descr(d);

	if (d->cSSL) {
		SSL_shutdown(d->cSSL);
		SSL_free(d->cSSL);
		d->cSSL = NULL;
	}

	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_read);
	FD_CLR(fd, &fds_wactive);
	FD_CLR(fd, &fds_write);

	if (d->env_hd) {
		ndc_env_clear(fd);
		qmap_close(d->env_hd);
		d->env_hd = 0;
	}

	shutdown(fd, 2);
	close(fd);

	tunnel_pair[fd] = INVALID_SOCKET;

	memset(d, 0, sizeof(struct descr));
	d->fd = -1;
}

static void
cleanup(void)
{
	if (!do_cleanup)
		return;

	DESCR_ITER
		ndc_close(di_i);
}

#if !defined(_WIN32)
static void sig_shutdown(int sig UNUSED)
{
    ndc_srv_flags &= ~NDC_WAKE;
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

static int
ssl_accept(socket_t fd)
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

	ERR("SSL_accept %d %d %d %d %s\n", fd, res,
			ssl_err, errno,
			ERR_error_string(ssl_err, NULL));

	unsigned long openssl_err;
	while ((openssl_err = ERR_get_error()) != 0) {
		char buf[256];
		ERR_error_string_n(openssl_err, buf, sizeof(buf));
		ERR("OpenSSL: %s\n", buf);
	}

	ERR_clear_error();
	ndc_close(fd);
	return 1;
}

static io_ssize_t
ndc_ssl_low_read(socket_t fd, void *to, io_size_t len, int flags UNUSED)
{
	return SSL_read(descr_map[fd].cSSL, to, len);
}

static void
cmd_new(int *argc_r, char *argv[CMD_ARGM],
		socket_t fd UNUSED, char *input, size_t len)
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

	for (p = input; *p && *p != '\r' && argc < CMD_ARGM; p++) if (isspace(*p)) {
		*p = '\0';
		argv[argc] = p + 1;
		argc ++;
	}

	while (*p && *p != '\r')
		p++;

	for (int i = argc; i < CMD_ARGM; i++)
		argv[i] = "";

	argv[argc] = p + 2;

	*argc_r = argc;
}

static io_ssize_t
ndc_ssl_lower_write(socket_t fd, void *from, io_size_t len, int flags UNUSED)
{
	struct descr *d = &descr_map[fd];
	if (!d->cSSL)
		return -1;
	return SSL_write(d->cSSL, from, len);
}

static int
ndc_write_remaining(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	if (!d->remaining_len)
		return 0;

	int ret = dio->lower_write(fd,
		d->remaining + d->remaining_off,
		d->remaining_len, 0);

	if (ret < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return -1;

		ndc_close(fd);
		return -1;
	}

	if (ret == 0)
		return 0;

	d->remaining_off += ret;
	d->remaining_len -= ret;

	if (!d->remaining_len) {
		d->remaining_off = 0;
		if (d->flags & DF_TO_CLOSE)
			ndc_close(fd);
	}

	return ret;
}

inline static void
ndc_rem_may_inc(socket_t fd, size_t len)
{
	struct descr *d = &descr_map[fd];

	size_t tail = d->remaining_size - (d->remaining_off + d->remaining_len);
	if (tail >= len) return;

	// compact
	if (d->remaining_off) {
		memmove(d->remaining,
				d->remaining + d->remaining_off,
				d->remaining_len);
		d->remaining_off = 0;
		tail = d->remaining_size - d->remaining_len;
		if (tail >= len) return;
	}

	size_t need = d->remaining_off + d->remaining_len + len;

	while (need >= d->remaining_size) {
		while (d->remaining_size < need)
			d->remaining_size *= 2;
		d->remaining = realloc(d->remaining, d->remaining_size);
	}
}

static io_ssize_t
ndc_low_write(socket_t fd, void *from, io_size_t len, int flags UNUSED)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	if (d->remaining_len) {
		ndc_rem_may_inc(fd, len);
		memcpy(d->remaining + d->remaining_off + d->remaining_len, from, len);
		d->remaining_len += len;
		ndc_write_remaining(fd);
		return -1;
	}

	int ret = dio->lower_write(fd, from, len, flags);

	if (ret < 0 && errno == EAGAIN) {
		ndc_rem_may_inc(fd, len);
		memcpy(d->remaining, from, len);
		d->remaining_off = 0;
		d->remaining_len = len;
		return -1;
	}

	if (ret >= 0 && (size_t) ret < len) {
		// partial send
		size_t left = len - ret;
		ndc_rem_may_inc(fd, left);
		memcpy(d->remaining, (char*) from + ret, left);
		d->remaining_off = 0;
		d->remaining_len = left;
	}

	return ret;
}

int
ndc_env_put(socket_t fd, char *key, char *value)
{
	if (!value)
		return 1;
	struct descr *d = &descr_map[fd];
	qmap_put(d->env_hd, key, value);
	return 0;
}

static void
descr_new(int ssl)
{
	struct sockaddr_in addr;
	socklen_t addr_len = (socklen_t)sizeof(addr);
	int fd = accept(ssl ? srv_ssl_fd : srv_fd, (struct sockaddr *) &addr, &addr_len);
	struct descr *d;
	struct io *dio;

	if (fd <= 0)
		return;

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
	d->epid = 0;
	d->env_hd = qmap_open(NULL, NULL, QM_STR, QM_STR, ENV_MASK, 0);
	d->pty = -1;

	dio->write = ndc_low_write;

	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->addr.sin_addr, ipstr, sizeof(ipstr));
	ndc_env_put(fd, "REMOTE_ADDR", ipstr);

	errno = 0;
	if (ssl) {
		d->cSSL = SSL_new(default_ssl_ctx);
		dio->read = dio->lower_read = ndc_ssl_low_read;
		dio->lower_write = ndc_ssl_lower_write;
		SSL_set_fd(d->cSSL, fd);
		if (ssl_accept(fd))
			return;
	} else {
		d->flags = DF_ACCEPTED;
		dio->read = dio->lower_read = (io_t) recv;
		dio->lower_write = (io_t) send;
	}
	if (ndc_accept)
		ndc_accept(fd);
}

static void
ndc_upstream_descr_init(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	memset(d, 0, sizeof(struct descr));
	memset(dio, 0, sizeof(struct io));

	d->fd = fd;
	d->flags = DF_ACCEPTED;
	d->remaining_size = BUFSIZ * 1024;
	d->remaining = malloc(d->remaining_size);
	d->epid = 0;
	d->env_hd = qmap_open(NULL, NULL, QM_STR, QM_STR, ENV_MASK, 0);
	d->pty = -1;

	dio->read = dio->lower_read = (io_t) recv;
	dio->lower_write = (io_t) send;
	dio->write = ndc_low_write;
}

inline static ssize_t
ndc_read(socket_t fd)
{
	char buf[BUFSIZ];
	struct io *dio = &io[fd];
	input_len = 0;
	size_t ret;

	while (1) switch ((ret = dio->read(fd, buf, sizeof(buf), 0))) {
	case -1:
	case 0: return ret;
	default:
		if (input_len + ret > input_size) {
			input_size *= 2;
			input_size += ret;
			input = realloc(input, input_size);
		}
		memcpy(input + input_len, buf, ret);
		input_len += ret;
		if (ret < sizeof(buf))
			return input_len;
	}
}

int
ndc_write(socket_t fd, void *data, size_t len)
{
	if (fd <= 0)
		return -1;
	struct io *dio = &io[fd];
	/* fprintf(stderr, "ndc_write %d %lu %d\n", fd, len, d->flags); */
	int ret = dio->write(fd, data, len, 0);
	return ret;
}

int
ndc_dwritef(socket_t fd, const char *fmt, va_list args)
{
	static char buf[BUFSIZ];
	ssize_t len = vsnprintf(buf, sizeof(buf), fmt, args);
	return ndc_write(fd, buf, len);
}

int
ndc_writef(socket_t fd, const char *fmt, ...)
{
	if (fd <= 0)
		return -1;
	va_list va;
	va_start(va, fmt);
	int ret = ndc_dwritef(fd, fmt, va);
	va_end(va);
	return ret;
}

void
ndc_wall(const char *msg)
{
	DESCR_ITER NDC_TWRITE(di_i, (char *) msg);
}

static inline void
cmd_proc(socket_t fd, int argc, char *argv[])
{
	if (argc < 1)
		return;

	char *s = argv[0];

	for (s = argv[0]; isalnum(*s); s++);

	int found = 0;

	*s = '\0';
	const struct cmd_slot *cmd
		= qmap_get(cmds_hd, argv[0]);

	if (cmd != NULL)
		found = 1;

	struct descr *d = &descr_map[fd];

	if (!(d->flags & DF_AUTHENTICATED)
			&& (!found || !(cmd->flags & CF_NOAUTH)))
		return;

	if ((!found && argc) || !(cmd->flags & CF_NOTRIM)) {
		// this looks buggy let's fix it, please
		/* fprintf(stderr, "??? %d %p, %d '%s'\n", argc, cmd_i, cmd_i - cmds_hd, argv[0]); */
		char *p = &argv[argc][-2];
		if (*p == '\r') *p = '\0';
		argv[argc] = "";
	}

	if (found) {
		if (ndc_command)
			ndc_command(fd, argc, argv);
		cmd->cb(fd, argc, argv);
	} else if (ndc_vim)
		ndc_vim(fd, argc, argv);
	if (ndc_flush)
		ndc_flush(fd, argc, argv);
}

static inline int
cmd_parse(socket_t fd, char *cmd, size_t len)
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


static int
descr_read(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	int ret;

	if (d->fd != fd)
		return 1;

	/* fprintf(stderr, "descr_read %d\n", fd); */

	if (!(d->flags & DF_ACCEPTED))
		return 0;

	ret = ndc_read(fd);
	switch (ret) {
	case -1:
		if (errno == EAGAIN)
			return 0;

		return -1;
	/* case 0: return 0; */
	case 0: return -1;
	}

	/* fprintf(stderr, "descr_read %d %d %s\n", d->fd, ret, input); */

  if (ndc_parse && ndc_parse(fd, input, ret) < 0)
    return 0;

	return cmd_parse(fd, (char *) input, ret);
}


static inline void
descr_proc_writes(void)
{
	for (register socket_t i = 0; i < FD_SETSIZE; i++) {
		struct descr *d = &descr_map[i];

		if (!(d->flags & DF_ACCEPTED) && d->cSSL)
			ssl_accept(i);

		if (!FD_ISSET(i, &fds_write)
				|| i == srv_fd
				|| i == srv_ssl_fd
				|| (d->flags & DF_EXTERN))
			continue;

		if (d->remaining_len)
			ndc_write_remaining(i);

		// i is not a pty fd!
		if (d->epid && ndc_platform && ndc_platform->exec_loop)
			ndc_platform->exec_loop(i);
	}
}

static void
ndc_raw_descr_reset(socket_t fd)
{
	if (fd == INVALID_SOCKET || fd >= FD_SETSIZE)
		return;

	struct descr *d = &descr_map[fd];

	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_wactive);
	FD_CLR(fd, &fds_read);
	FD_CLR(fd, &fds_write);

	if (d->cSSL) {
		SSL_shutdown(d->cSSL);
		SSL_free(d->cSSL);
		d->cSSL = NULL;
	}

	if (d->remaining_size && d->remaining) {
		free(d->remaining);
		d->remaining = NULL;
	}
	d->remaining_size = 0;
	d->remaining_len = 0;
	d->remaining_off = 0;

	d->resp_headers[0] = '\0';

	if (d->env_hd) {
		ndc_env_clear(fd);
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

static void
ndc_tunnel_close_raw(socket_t fd)
{
	if (fd == INVALID_SOCKET || fd >= FD_SETSIZE)
		return;

	socket_t peer = tunnel_pair[fd];

	tunnel_pair[fd] = INVALID_SOCKET;
	if (peer != INVALID_SOCKET && peer < FD_SETSIZE && peer != fd)
		tunnel_pair[peer] = INVALID_SOCKET;

	ndc_raw_descr_reset(fd);

	if (peer != INVALID_SOCKET && peer < FD_SETSIZE && peer != fd)
		ndc_raw_descr_reset(peer);
}

void ndc_clear_active(socket_t cfd)
{
  FD_CLR(cfd, &fds_active);
}

static inline void
descr_proc_reads(void)
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
      if (ndc_fd_tick)
        ndc_fd_tick(i);
			continue;
		}

		/* Waiting for upstream 101 */
		if (d->flags & DF_WS_WAITING) {
			char buf[4096];
			ssize_t n = dio->read(i, buf, sizeof(buf), 0);

			if (n <= 0) {
				ndc_tunnel_close_raw(i);
				continue;
			}

			socket_t peer = tunnel_pair[i];
			if (peer == INVALID_SOCKET || peer == i || peer >= FD_SETSIZE ||
					descr_map[peer].fd != peer ||
					tunnel_pair[peer] != i ||
					!(descr_map[peer].flags & DF_WS_PROXY_PENDING)) {
				ndc_tunnel_close_raw(i);
				continue;
			}

			struct io *pdio = &io[peer];

			if (n >= 12 && !strncmp(buf, "HTTP/1.1 101", 12)) {
				/* Forward 101 back to browser */
				pdio->write(peer, buf, n, 0);

				/* Only now enter raw tunnel mode */
				ndc_ws_tunnel(peer, i);
			} else {
				/* Forward upstream failure response, then tear down */
				pdio->write(peer, buf, n, 0);
				ndc_tunnel_close_raw(i);
			}
			continue;
		}

		/* Raw tunnel mode */
		if (d->flags & DF_TUNNEL) {
			char buf[4096];
			ssize_t n = dio->read(i, buf, sizeof(buf), 0);

			if (n <= 0) {
				ndc_tunnel_close_raw(i);
				continue;
			}

			socket_t peer = tunnel_pair[i];
			if (peer == INVALID_SOCKET || peer == i || peer >= FD_SETSIZE || descr_map[peer].fd != peer) {
				ndc_tunnel_close_raw(i);
				continue;
			}

			struct io *pdio = &io[peer];

			/*
			 * IMPORTANT:
			 * ndc_low_write() may return -1 merely because it buffered
			 * the data. That is NOT a fatal tunnel error here.
			 */
			(void) pdio->write(peer, buf, n, 0);
			continue;
		}

		/* Normal NDC path */
		if (!d->epid && descr_read(i) < 0)
			ndc_close(i);
	}
}

static long long
timestamp(void)
{
	struct timeval te;
	gettimeofday(&te, NULL); // get current time
	return te.tv_sec * 1000000LL + te.tv_usec;
}

static void
ndc_bind(socket_t *srv_fd_r, int ssl)
{
	socket_t srv_fd = socket(AF_INET, SOCK_STREAM, 0);
	int opt;

	CBUG(srv_fd == INVALID_SOCKET, "socket\n");

	opt = 1;
	CBUG(setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR,
			(char *) &opt, sizeof(opt)),
			"setsockopt SO_REUSEADDR\n");

	opt = 1;
	CBUG(setsockopt(srv_fd, SOL_SOCKET, SO_KEEPALIVE,
			(char *) &opt, sizeof(opt)),
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
	server.sin_port = htons(ssl
			? ndc_config.ssl_port
			: ndc_config.port);

	CBUG(bind(srv_fd, (struct sockaddr *) &server,
			sizeof(server)),
			"bind");

	descr_map[srv_fd].fd = srv_fd;

	listen(srv_fd, 32);

	FD_SET(srv_fd, &fds_active);

	*srv_fd_r = srv_fd;
}

static int
ndc_sni(SSL *ssl, int *ad UNUSED, void *arg UNUSED)
{
	const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername)
		return SSL_TLSEXT_ERR_NOACK; // no SNI

	const cert_t *cert = qmap_get(cert_hd, servername);

	if (cert == NULL)
		return SSL_TLSEXT_ERR_NOACK;

	SSL_set_SSL_CTX(ssl, cert->ctx);

	return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *
ndc_ctx_new(char *crt, char *key)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	CBUG(!ctx, "SSL_CTX_new\n");

	CBUG(!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION),
			"set_min_proto_version\n");

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	CBUG(!SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4"),
			"set_cipher_list\n");


	(void)SSL_CTX_set_ciphersuites(ctx,
			"TLS_AES_256_GCM_SHA384:"
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

static int
openssl_error_callback(const char *str, size_t len, void *u)
{
    (void)u;
    ERR("%.*s\n", (int) len, str);
    return 0;
}

void
ndc_register(char *name, ndc_cb_t *cb, int flags)
{
	struct cmd_slot cmd = { .name = name, .cb = cb, .flags = flags };
	qmap_put(cmds_hd, name, &cmd);
}


static inline void mime_put(char *key, char *value) {
	qmap_put(mime_hd, key, value);
}


#ifdef __APPLE__
extern int chroot(const char *path);
#endif

static void
ndc_init(void)
{
	ndc_srv_flags |= ndc_config.flags | NDC_WAKE;

	if ((ndc_srv_flags & NDC_DETACH))
		qsyslog = qsys_syslog;

	if (ndc_srv_flags & NDC_SSL) {

		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();

		const cert_t *cert
			= qmap_get(cert_hd, domain_default);

		default_ssl_ctx = ndc_ctx_new(cert->crt, cert->key);

		SSL_CTX_set_tlsext_servername_callback(default_ssl_ctx, ndc_sni);

		ERR_print_errors_cb(openssl_error_callback, NULL);
	}

	if (ndc_platform && ndc_platform->init_pre_bind)
		ndc_platform->init_pre_bind();

	mime_put("html", "text/html");
	mime_put("txt", "text/plain");
	mime_put("css", "text/css");
	mime_put("js", "application/javascript");
	mime_put("wasm", "application/wasm");

	setup_signals();

	input = malloc(input_size);

	if (ndc_srv_flags & NDC_SSL)
		ndc_bind(&srv_ssl_fd, 1);

	ndc_bind(&srv_fd, 0);

	exec_timeout.tv_sec = EXEC_TIMEOUT / 1000000;
	exec_timeout.tv_usec = EXEC_TIMEOUT % 1000000;
	select_timeout.tv_sec = SELECT_TIMEOUT / 1000000;
	select_timeout.tv_usec = SELECT_TIMEOUT % 1000000;

	if (ndc_platform && ndc_platform->init_post_bind)
		ndc_platform->init_post_bind();
}

int
ndc_main(void)
{
	struct timeval timeout;

	ndc_init();

	ndc_tick = timestamp();

	while (ndc_srv_flags & NDC_WAKE) {
		long long last = ndc_tick;
		ndc_tick = timestamp();
		dt = ndc_tick - last;

		if (ndc_update)
			ndc_update(dt);

		if (!(ndc_srv_flags & NDC_WAKE))
			break;

		for (register int i = 0; i < FD_SETSIZE; i++)
			if (descr_map[i].remaining_len)
				ndc_write_remaining(i);

		memcpy(&timeout, &select_timeout, sizeof(timeout));

		fds_read = fds_active;
		fds_write = fds_wactive;
		int select_n = select(FD_SETSIZE, &fds_read, &fds_write, NULL, &timeout);

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

static char *
env_name(char *key)
{
	static char buf[BUFSIZ];
	int i = 0;
	register char *b, *s;
	memset(buf, 0, BUFSIZ);
	strncpy(buf, "HTTP_", sizeof(buf));
	for (s = (char *) key, b = buf + 5; *s; s++, b++, i++)
		if (*s == '-')
			*b = '_';
		else
			*b = toupper(*s);
	return buf;
}

static inline void
headers_get(socket_t fd, size_t *body_start, char *next_lines)
{
	register char *s, *key, *value;

	for (s = next_lines, key = s, value = s; *s; ) switch (*s) {
		case ':':
			*s = '\0';
			value = (s += 2);
			break;
		case '\r':
			*s = '\0';
			if (s != key) {
				if (s - key >= BUFSIZ)
					*(key + BUFSIZ - 1) = '\0';
				ndc_env_put(fd, env_name(key), value);
				key = s += 2;
			} else
				*++s = '\0';

			break;
		default:
			s++;
			break;
	}

	*body_start = s - next_lines;	
}

static void
url_decode(char *str)
{
    char *src = str, *dst = str;

    while (*src) {
        if (*src == '%' && src[1] && src[2] && isxdigit(src[1]) && isxdigit(src[2])) {
            unsigned value;
            sscanf(src + 1, "%2x", &value);
            *dst++ = (char)value;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }

    *dst = '\0';
}

static char *
env_sane(char *str)
{
	static char buf[BUFSIZ];
	char *b;
	for (b = buf; b - buf - 1 < BUFSIZ && (isalnum(*str) || *str == '/' || *str == '+'
				|| *str == '%' || *str == '&' || *str == '_' || *str == '-'
				|| *str == ' ' || *str == '=' || *str == ';' || *str == '.'); str++, b++)
		*b = *str;
	*b = '\0';
	return buf;
}


int
ndc_env_get(socket_t fd, char *target, char *key)
{
	struct descr *d = &descr_map[fd];
	const void *skey = qmap_get(d->env_hd, key);

	if (!skey)
		return 1;

	strcpy(target, skey);
	return 0;
}

int
ndc_query_parse(char *body)
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
					} else if (value[i] == '%' && value[i+1] && value[i+2]) {
						unsigned int c;
						sscanf(value + i + 1, "%2x", &c);
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

int
ndc_query_param(const char *name, char *buf, size_t buf_len)
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

static void
_env_prep(socket_t fd, char *document_uri,
		char *param, char *method)
{
	char req_content_type[BUFSIZ];

	if (ndc_env_get(fd, req_content_type, "HTTP_CONTENT_TYPE"))
		strncpy(req_content_type, "text/plain", sizeof(req_content_type));

	ndc_env_put(fd, "CONTENT_TYPE", env_sane(req_content_type));
	ndc_env_put(fd, "DOCUMENT_URI", document_uri);
	ndc_env_put(fd, "QUERY_STRING", env_sane(param));
	ndc_env_put(fd, "REQUEST_METHOD", method);
	ndc_env_put(fd, "DOCUMENT_ROOT",
#ifdef _WIN32
		0
#else
		geteuid()
#endif
		? ndc_config.chroot : "");
	if (ndc_platform && ndc_platform->env_prep)
		ndc_platform->env_prep(fd);
}

static void
static_write(socket_t fd, char *status, const char *content_type,
		int want_fd, off_t total)
{
	struct descr *d = &descr_map[fd];
	time_t now = time(NULL);
	struct tm *tm_info = gmtime(&now);
	char date[100];

	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tm_info);
	ndc_writef(fd, "HTTP/1.1 %s\r\n"
			"Date: %s\r\n"
			"Server: ndc/0.0.1 (Unix)\r\n"
			"Content-Length: %lu\r\n"
			"Content-Type: %s\r\n"
			"Cache-Control: max-age=5184000\r\n"
			NDC_CROSS_ORIGIN_HEADERS
			"\r\n",
			status, date, total, content_type);


	if (want_fd <= 0) {
		ndc_writef(fd, "%s\r\n", status);
		goto end;
	}

	// static file
	ssize_t len;
	char b[BUFSIZ * 16];

	while ((len = read(want_fd, b, sizeof(b))) > 0)
		ndc_write(fd, b, len);

	close(want_fd);

end:	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		ndc_close(fd);
}

static inline int
request_handle_static(socket_t fd, char *document_uri,
		struct stat *stat_buf)
{
	char buf[BUFSIZ];
	errno = 0;
	char *ext, *s;
	const char *content_type;

	if (document_uri[strlen(document_uri) - 1] == '/')
	{
		snprintf(buf, sizeof(buf), "%sindex.html",
				document_uri);
		document_uri = buf;
	}

	char *filename = NULL;
	if (ndc_platform && ndc_platform->static_allowed)
		filename = ndc_platform->static_allowed(document_uri, stat_buf);

	if (!filename)
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

	static_write(fd, "200 OK", content_type,
			open(filename, O_RDONLY),
			stat_buf->st_size);

	return 1;
}


static inline int
request_handle_redirect(socket_t fd, char *document_uri)
{
	struct descr *d = &descr_map[fd];

	if ((ndc_srv_flags & NDC_SSL_ONLY)
			&& (ndc_srv_flags & NDC_SSL)
			&& !d->cSSL)
	{
		char host[ENV_KEY_LEN] = { 0 };
		ndc_env_get(fd, host, "HTTP_HOST");
		char response[8285];
		d->flags |= DF_TO_CLOSE;

		snprintf(response, sizeof(response),
				"HTTP/1.1 301 Moved Permanently\r\n"
				"Location: https://%s%s\r\n"
				"Content-Length: 0\r\n"
				"Connection: close\r\n"
				"\r\n", host, document_uri);
		ndc_writef(fd, "%s", response);

		if (!d->remaining_len)
			ndc_close(fd);

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
		static_write(fd, "500 Internal Server Error", "text/plain", -1, 27);
		return;
	}

	// Start building the HTML body
	body_len = snprintf(body, sizeof(body),
		"<!DOCTYPE html><html><head><title>Index of %s</title></head>"
		"<body><h1>Index of %s</h1><hr><pre>",
		uri_path, uri_path);

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(line, sizeof(line), "<a href=\"./%s\">%s</a>\n", entry->d_name, entry->d_name);

		// Append to body, checking buffer size
		if (body_len + strlen(line) < sizeof(body) - 20) { // Keep some safety margin
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

	ndc_writef(fd, "HTTP/1.1 200 OK\r\n"
			"Date: %s\r\n"
			"Server: ndc/0.0.1 (Unix)\r\n"
			"Content-Length: %lu\r\n"
			"Content-Type: text/html\r\n"
			"Connection: close\r\n"
			NDC_CROSS_ORIGIN_HEADERS
			"\r\n",
			date, body_len);
	ndc_write(fd, body, body_len);

	struct descr *d = &descr_map[fd];
	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		ndc_close(fd);
}

typedef struct {
	char env_key[256];
	char value[256];
} ndc_pattern_param_t;

typedef struct {
	int matched;
	int literal_chars;
	int param_count;
	int wildcard_count;
	int param_used;
	ndc_pattern_param_t params[16];
} ndc_pattern_match_t;

static int
pattern_is_end(const char *s)
{
	return *s == '\0' || *s == '?';
}

static int
pattern_is_terminal_wildcard(const char *start, const char *end)
{
	if ((end - start) != 1 || start[0] != '*')
		return 0;

	if (*end == '\0' || *end == '?')
		return 1;

	if (*end != '/')
		return 0;

	end++;
	return pattern_is_end(end);
}

static void
pattern_commit_params(socket_t fd, const ndc_pattern_match_t *match)
{
	int i;

	for (i = 0; i < match->param_used; i++)
		ndc_env_put(fd,
			(char *)match->params[i].env_key,
			(char *)match->params[i].value);
}

static int
pattern_better_match(const ndc_pattern_match_t *candidate,
	const ndc_pattern_match_t *best)
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
pattern_match(const char *pattern, const char *path, ndc_pattern_match_t *out)
{
	const char *p = pattern;
	const char *u = path;
	const char *p_path = strchr(pattern, '/');
	const char *u_path = strchr(path, '/');
	ndc_pattern_match_t match;

	memset(&match, 0, sizeof(match));

	if (!p_path)
		p_path = pattern + strlen(pattern);
	if (!u_path)
		u_path = path + strlen(path);

	if (p_path != pattern) {
		size_t p_prefix_len = (size_t)(p_path - pattern);
		size_t u_prefix_len = (size_t)(u_path - path);

		if (p_prefix_len != u_prefix_len ||
		    memcmp(pattern, path, p_prefix_len) != 0)
			return 0;

		match.literal_chars += (int)p_prefix_len;
		p = p_path;
		u = u_path;
	} else {
		u = u_path;
	}

	while (1) {
		const char *p_end;
		const char *u_end;
		size_t p_seg_len;
		size_t u_seg_len;

		while (*p == '/' && pattern_is_end(p + 1))
			p++;
		while (*u == '/' && pattern_is_end(u + 1))
			u++;

		if (pattern_is_end(p) && pattern_is_end(u)) {
			*out = match;
			out->matched = 1;
			return 1;
		}

		if (*p == '/' && *u == '/') {
			p++;
			u++;
			continue;
		}

		if (*p == '/' || *u == '/')
			return 0;

		if (pattern_is_end(p) || pattern_is_end(u))
			return 0;

		p_end = p;
		while (*p_end && *p_end != '/' && *p_end != '?')
			p_end++;
		u_end = u;
		while (*u_end && *u_end != '/' && *u_end != '?')
			u_end++;

		p_seg_len = (size_t)(p_end - p);
		u_seg_len = (size_t)(u_end - u);

		if (pattern_is_terminal_wildcard(p, p_end)) {
			match.wildcard_count++;
			*out = match;
			out->matched = 1;
			return 1;
		}

		if (p_seg_len > 1 && p[0] == ':') {
			char env_key[256];
			size_t key_pos;
			size_t i;

			if (u_seg_len == 0 || match.param_used >= (int)(sizeof(match.params) / sizeof(match.params[0])))
				return 0;

			key_pos = (size_t)snprintf(env_key, sizeof(env_key), "PATTERN_PARAM_");
			if (key_pos >= sizeof(env_key))
				return 0;

			for (i = 1; i < p_seg_len && key_pos + 1 < sizeof(env_key); i++)
				env_key[key_pos++] = (char)toupper((unsigned char)p[i]);
			if (i != p_seg_len || key_pos >= sizeof(env_key))
				return 0;
			env_key[key_pos] = '\0';

			if (u_seg_len >= sizeof(match.params[match.param_used].value))
				return 0;

			snprintf(match.params[match.param_used].env_key,
				sizeof(match.params[match.param_used].env_key),
				"%s", env_key);
			memcpy(match.params[match.param_used].value, u, u_seg_len);
			match.params[match.param_used].value[u_seg_len] = '\0';
			match.param_used++;
			match.param_count++;
		} else {
			if (p_seg_len != u_seg_len || memcmp(p, u, p_seg_len) != 0)
				return 0;
			match.literal_chars += (int)p_seg_len;
		}

		p = p_end;
		u = u_end;
	}
}

/* Pattern matching for registered handlers
 * Supports :param syntax (e.g., "/chords/:id")
 * Sets PATTERN_PARAM_* env vars for matched parameters
 */
static ndc_handler_t *
ndc_match_pattern(const char *path_with_method, const char *document_uri, socket_t fd)
{
	/* Iterate through all registered handlers */
	uint32_t cur = qmap_iter(hdlr_hd, NULL, 0);
	const void *pattern_key;
	const void *handler_ptr;
	ndc_handler_t *best_handler = NULL;
	ndc_pattern_match_t best_match;

	memset(&best_match, 0, sizeof(best_match));

	while (qmap_next(&pattern_key, &handler_ptr, cur)) {
		const char *pattern = (const char *)pattern_key;
		ndc_pattern_match_t candidate;
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
			memcpy(&best_handler, handler_ptr, sizeof(best_handler));
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
	char clen_str[32] = {0};
	ndc_env_get(fd, clen_str, "HTTP_CONTENT_LENGTH");
	if (!clen_str[0])
		return 0;

	size_t content_length = strtoul(clen_str, NULL, 10);
	size_t limit = ndc_config.max_body_size
		? ndc_config.max_body_size
		: NDC_DEFAULT_MAX_BODY_SIZE;

	if (content_length > limit) {
		ndc_header_set(fd, "Connection", "close");
		ndc_set_flags(fd, DF_TO_CLOSE);
		ndc_respond(fd, 413, "");
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
			ndc_close(fd);
			return -1;
		}
		if (input_len + (size_t)n > input_size) {
			char *old_base = (char *)input;
			input_size = (input_len + (size_t)n) * 2;
			input = realloc(input, input_size);
			ptrdiff_t shift = (char *)input - old_base;
			for (int i = 0; i <= argc; i++)
				argv[i] += shift;
		}
		memcpy(input + input_len, buf, n);
		input_len += (size_t)n;
	}

	return 0;
}

static inline int
request_handle_trailing_slash(socket_t fd, char *document_uri)
{
    struct stat stat_buf;
    int uri_len = strlen(document_uri);

    if (uri_len > 1 && document_uri[uri_len - 1] != '/') {
		char *fs_path = NULL;
		if (ndc_platform && ndc_platform->static_allowed)
			fs_path = ndc_platform->static_allowed(document_uri, &stat_buf);

	if (fs_path && S_ISDIR(stat_buf.st_mode)) {
		struct descr *d = &descr_map[fd];
		char host[ENV_KEY_LEN] = { 0 };
		ndc_env_get(fd, host, "HTTP_HOST");
		const char *scheme = d->cSSL ? "https" : "http";

		ndc_writef(fd, "HTTP/1.1 301 Moved Permanently\r\n"
				"Location: %s://%s%s/\r\n"
				"Content-Length: 0\r\n"
				"Connection: close\r\n"
				"\r\n", scheme, host, document_uri);

		d->flags |= DF_TO_CLOSE;
		if (!d->remaining_len)
			ndc_close(fd);
            return 1;
	}
    }

    return 0;
}

static void
request_handle(socket_t fd, int argc, char *argv[], int req_flags)
{
	char *method;
	struct descr *d = &descr_map[fd];
	size_t body_start;
	char document_uri[BUFSIZ], *param;
	struct stat stat_buf;

	if (req_flags & NDC_POST)
		method = "POST";
	else
		method = "GET";

	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->addr.sin_addr, ipstr, sizeof(ipstr));
	WARN("%d (%s) %s %s\n", fd, ipstr, method, argv[1]);

	if (argc < 2 || argv[1][0] != '/' || strstr(argv[1], "..")) {
		// you wish
		ndc_close(fd);
		return;
	}

	strncpy(document_uri, argv[1], sizeof(document_uri));
	url_decode(document_uri);

	param = strchr(document_uri, '?');
	if (param)
		*param ++ = '\0';
	else
		param = "";

	headers_get(fd, &body_start, argv[argc]);

	/* For POST with Content-Length, ensure the full body is buffered.
	 * ndc_read() may return after reading only the headers if the body
	 * arrives in a separate TCP segment. */
	if (req_flags & NDC_POST) {
		if (buffer_post_body(fd, argc, argv, body_start) < 0)
			return;
	}

	if (ndc_platform && ndc_platform->auth_try)
		ndc_platform->auth_try(fd);

	if (request_handle_trailing_slash(fd, document_uri))
		return;

	/* Check for registered websocket handler before auto-detection */
	char path_with_method[16384];
	snprintf(path_with_method, sizeof(path_with_method), "%s:%s", method, document_uri);
	const void *ws_key = qmap_get(ws_hd, path_with_method);
	if (!ws_key)
		ws_key = qmap_get(ws_hd, document_uri);

	ndc_ws_upstream_t *ws_handler = NULL;
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
			if (ndc_env_get(fd, ws_key, "HTTP_SEC_WEBSOCKET_KEY")) {
				fprintf(stderr, "WS: no Sec-WebSocket-Key header\n");
				close(upstream);
			} else {
				char req_buf[2048];
				int len = snprintf(req_buf, sizeof(req_buf),
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

				ndc_upstream_descr_init(upstream);

				tunnel_pair[fd] = upstream;
				tunnel_pair[upstream] = fd;

				/* both ends belong to the same pending WS proxy pair */
				descr_map[fd].flags |= DF_WS_PROXY_PENDING;
				descr_map[upstream].flags |= DF_WS_WAITING | DF_WS_PROXY_PENDING;

				FD_SET(upstream, &fds_active);

#ifdef MSG_NOSIGNAL
				ssize_t wr = send(upstream, req_buf, len, MSG_NOSIGNAL);
#else
				ssize_t wr = write(upstream, req_buf, len);
#endif
				if (wr < 0 || wr < len) {
					ndc_tunnel_close_raw(upstream);
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
	if (ndc_platform && ndc_platform->autoindex_allowed)
		autoindex_path = ndc_platform->autoindex_allowed(document_uri, &stat_buf);
	if (autoindex_path) {
		request_handle_autoindex(fd, document_uri, autoindex_path);
		return;
	}

	if (request_handle_redirect(fd, document_uri))
		return;

	/* Try HTTP handler match */
	const void *key = qmap_get(hdlr_hd, path_with_method);
	if (!key)
		key = qmap_get(hdlr_hd, document_uri);

	ndc_handler_t *hdlr = NULL;
	if (key) {
		memcpy(&hdlr, key, sizeof(hdlr));
	} else {
		/* Try pattern matching */
		hdlr = ndc_match_pattern(path_with_method, document_uri, fd);
	}

	if (hdlr) {
		hdlr(fd, body);
		return;
	}

	if (ndc_config.default_handler) {
		ndc_config.default_handler(fd, body);
		return;
	}

	for (size_t i = 0; i < fallback_handlers_len; i++) {
		if (fallback_handlers[i](fd, body))
			return;
	}

	ndc_respond(fd, 404, "404 Not Found\n");
}

void
ndc_register_handler(char *path, ndc_handler_t handler)
{
	qmap_put(hdlr_hd, path, &handler);
}

int
ndc_register_fallback_handler(ndc_handler_t handler)
{
	if (fallback_handlers_len >= FALLBACK_MAX)
		return -1;

	fallback_handlers[fallback_handlers_len++] = handler;
	return 0;
}

void
ndc_ws_handler(char *path, ndc_ws_upstream_t handler)
{
	qmap_put(ws_hd, path, &handler);
}

int
ndc_ws_upgrade(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	char buf[ENV_VALUE_LEN];

	if (d->flags & DF_WEBSOCKET)
		return 0;

	if (ndc_env_get(fd, buf, "HTTP_SEC_WEBSOCKET_KEY"))
		return -1;

	struct io *dio = &io[fd];
	if (ws_init(fd, buf))
		return -1;

	d->flags |= DF_WEBSOCKET;
	dio->read = ws_read;
	dio->write = ws_write;

	if (!ndc_connect || ndc_connect(fd))
		d->flags |= DF_CONNECTED;

	return 0;
}

int
ndc_ws_write(socket_t fd, const void *data, size_t len)
{
	return ws_write(fd, (void *)data, len, 0);
}

ssize_t
ndc_ws_read(socket_t fd, void *buf, size_t len)
{
	return ws_read(fd, buf, len, 0);
}

int
ndc_ws_close(socket_t fd)
{
	ws_close(fd);
	return 0;
}

int
ndc_ws_printf(socket_t fd, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int ret = ws_dprintf(fd, fmt, args);
	va_end(args);
	return ret;
}

static void
ndc_ws_tunnel(socket_t a, socket_t b)
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

void
do_GET(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, 0);
	qmap_drop(query_db);
}

void
do_POST(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, NDC_POST);
	qmap_drop(query_db);
}

int
ndc_flags(socket_t fd)
{
	return descr_map[fd].flags;
}

void
ndc_set_flags(socket_t fd, int flags)
{
	descr_map[fd].flags = flags;
}

#ifndef _WIN32
int
ndc_get_pw(socket_t fd, struct passwd *out)
{
	struct descr *d = &descr_map[fd];
	if (!(d->flags & DF_AUTHENTICATED))
		return -1;
	*out = d->pw;
	out->pw_name  = d->pw.pw_name  ? strdup(d->pw.pw_name)  : NULL;
	out->pw_shell = d->pw.pw_shell ? strdup(d->pw.pw_shell) : NULL;
	out->pw_dir   = d->pw.pw_dir   ? strdup(d->pw.pw_dir)   : NULL;
	return 0;
}

void
ndc_fd_watch(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	d->fd = fd;
	d->flags |= DF_EXTERN;
	FD_SET(fd, &fds_active);
}

void
ndc_fd_unwatch(socket_t fd)
{
	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_read);
}

void
ndc_fork_child_reset(void)
{
	do_cleanup = 0;
}
#endif


__attribute__((constructor)) static void
ndc_pre_init(void)
{
	memset(&ndc_config, 0, sizeof(ndc_config));
	ndc_config.port = 80;
	ndc_config.ssl_port = 443;

	for (int i = 0; i < FD_SETSIZE; i++)
		tunnel_pair[i] = INVALID_SOCKET;

	unsigned cert_type = qmap_reg(sizeof(cert_t));
	unsigned cmd_type = qmap_reg(sizeof(struct cmd_slot));
	unsigned hdlr_type = qmap_reg(sizeof(ndc_handler_t *));
	unsigned ws_type = qmap_reg(sizeof(ndc_ws_upstream_t *));

	query_db = qmap_open(NULL, NULL, QM_STR, QM_STR, 0xFF, 0);
	mime_hd = qmap_open(NULL, NULL, QM_STR, QM_STR, MIME_MASK, 0);
	cert_hd = qmap_open(NULL, NULL, QM_STR, cert_type, CERT_MASK, 0);
	hdlr_hd = qmap_open(NULL, NULL, QM_STR, hdlr_type, HDLR_MASK, 0);
	ws_hd = qmap_open(NULL, NULL, QM_STR, ws_type, HDLR_MASK, 0);
	cmds_hd = qmap_open(NULL, NULL, QM_STR, cmd_type, CMD_MASK, 0);

	/* Register default HTTP command handlers */
	/* These need to be in the library, not just the ndc binary */
	ndc_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);
}

void
_ndc_cert_add(char *domain, char *crt, char *key)
{
	SSL_CTX *ssl_ctx = ndc_ctx_new(crt, key);
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
