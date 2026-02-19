#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1

#include <stdio.h>

#include "../include/ttypt/ndc.h"
#include "../include/iio.h"
#include "ndc-internal.h"

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
#include <arpa/telnet.h>
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

static char cgi_index[] = "./index.sh";
struct timeval select_timeout, exec_timeout;

struct io io[FD_SETSIZE];

struct ndc_config ndc_config;
socket_t srv_ssl_fd = -1, srv_fd = -1;

int ndc_srv_flags = 0;
static unsigned cmds_hd;
fd_set fds_read, fds_active, fds_write, fds_wactive;
long long dt, tack = 0;
SSL_CTX *default_ssl_ctx;
long long ndc_tick;
int do_cleanup = 1;

char ndc_execbuf[BUFSIZ * 64];

char *domain_default = NULL;
unsigned cert_hd, mime_hd, hdlr_hd; 

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
ndc_header(socket_t fd, const char *key, const char *value)
{
	struct descr *d = &descr_map[fd];
	size_t len = strlen(d->resp_headers);
	snprintf(d->resp_headers + len, BUFSIZ - len, "%s: %s\r\n", key, value);
}

void
ndc_head(socket_t fd, int code)
{
	struct descr *d = &descr_map[fd];
	/* Send status line */
	ndc_writef(fd, "HTTP/1.1 %d %s\r\n", code, ndc_status_text(code));
	/* Send accumulated headers */
	if (*d->resp_headers) {
		ndc_writef(fd, "%s", d->resp_headers);
	}
	/* Send final CRLF to end headers section */
	ndc_writef(fd, "\r\n");
	/* Clear buffer */
	d->resp_headers[0] = '\0';
}

void
ndc_body(socket_t fd, const char *body)
{
	/* Just send body content - headers already sent by ndc_head() */
	if (body && *body)
		ndc_write(fd, (void *)body, strlen(body));
	ndc_close(fd);
}


void
ndc_close(socket_t fd)
{
	struct descr *d = &descr_map[fd];

	if (d->remaining_size)
		free(d->remaining);

	/* Clear buffer (should already be empty if API used correctly) */
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
	}

	shutdown(fd, 2);
	close(fd);
	FD_CLR(fd, &fds_active);
	FD_CLR(fd, &fds_read);
	FD_CLR(fd, &fds_wactive);
	FD_CLR(fd, &fds_write);
	ndc_env_clear(fd);
	qmap_close(d->env_hd);
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
    sa.sa_flags = 0;   // IMPORTANTE: sem SA_RESTART

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
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

	int ret = dio->lower_write(fd, d->remaining + d->remaining_off, d->remaining_len, 0);

	if (ret < 0 && errno == EAGAIN)
		return -1;

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

static inline void
pty_open(socket_t fd)
{
	TELNET_CMD(fd, IAC, WILL, TELOPT_ECHO);
	TELNET_CMD(fd, IAC, WONT, TELOPT_SGA);

	if (ndc_platform && ndc_platform->pty_open)
		ndc_platform->pty_open(fd);
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

	int i = 0;

	for (; i < ret && input[i] != IAC; i++);

	if (i == ret)
		i = 0;

	while (i < ret && input[i + 0] == IAC) if (input[i + 1] == SB && input[i + 2] == TELOPT_NAWS) {
		int skip = 9;
		if (ndc_platform && ndc_platform->handle_naws)
			skip = ndc_platform->handle_naws(fd, input + i);
		i += skip;
	} else if (input[i + 1] == DO && input[i + 2] == TELOPT_SGA) {
		/* this must change pty tty settings as well. Not just reply */
		/* TELNET_CMD(IAC, WONT, TELOPT_ECHO, IAC, WILL, TELOPT_SGA); */
		i += 3;
	} else if (input[i + 1] == DO) {
		/* TELNET_CMD(IAC, WILL, input[i + 2]); */
		i += 3;
	} else if (input[i + 1] == DONT) {
		/* TELNET_CMD(IAC, WONT, input[i + 2]); */
		i += 3;
	} else if (input[i + 1] == DO || input[i + 1] == DONT || input[i + 1] == WILL)
		i += 3;
	else
		i++;

	if (ndc_platform && ndc_platform->pty_write_input) {
		if (ndc_platform->pty_write_input(fd, input, i, ret))
			return 0;
	}

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
				|| d->pty == -2)
			continue;

		if (d->remaining_len)
			ndc_write_remaining(i);

		// i is not a pty fd!
		if (d->epid && ndc_platform && ndc_platform->exec_loop)
			ndc_platform->exec_loop(i);
	}
}

static inline void
descr_proc_reads(void)
{
	for (register socket_t i = 0; i < FD_SETSIZE; i++) {
		struct descr *d = &descr_map[i];

		if (!FD_ISSET(i, &fds_read))
			continue;

		if (i == srv_fd)
			descr_new(0);
		else if (i == srv_ssl_fd)
			descr_new(1);

		// i is a pty fd
		if (d->pty == -2 && ndc_platform && ndc_platform->pty_read) {
			if (ndc_platform->pty_read(d->fd) < 0)
				FD_CLR(i, &fds_active);
			continue;
		}

		// i is not a pty fd!
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
		descr_proc_writes();

		switch (select_n) {
		case -1:
			switch (errno) {
			case EAGAIN: /* return 0; */
			case EINTR:
			case EBADF: continue;
			}

			ERR("select\n");
			return -1;

		case 0: continue;
		}

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


void
do_GET_cb(int fd, char *buf, size_t len, int ofd)
{
	if (ofd == 1)
		ndc_write(fd, buf, len);
	else
		ERR("%s\n", buf);
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

static void
_env_prep(socket_t fd, char *document_uri,
		char *param, char *method)
{
	char req_content_type[BUFSIZ];

	if (ndc_env_get(fd, req_content_type, "HTTP_CONTENT_TYPE"))
		strncpy(req_content_type, "text/plain", sizeof(req_content_type));

	ndc_env_put(fd, "CONTENT_TYPE", env_sane(req_content_type));
	ndc_env_put(fd, "CONTENT_TYPE", env_sane(req_content_type));
	ndc_env_put(fd, "DOCUMENT_URI", document_uri);
	ndc_env_put(fd, "QUERY_STRING", env_sane(param));
	ndc_env_put(fd, "REQUEST_METHOD", method);
	ndc_env_put(fd, "SCRIPT_NAME", cgi_index + 1);
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
request_handle_websocket(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	char buf[ENV_VALUE_LEN];

	if (d->flags & DF_WEBSOCKET)
		return 0;

	if (ndc_env_get(fd, buf, "HTTP_SEC_WEBSOCKET_KEY"))
		return 0;

	struct io *dio = &io[fd];
	if (ws_init(fd, buf))
		return -1;

	d->flags |= DF_WEBSOCKET;
	dio->read = ws_read;
	dio->write = ws_write;
	TELNET_CMD(fd, IAC, DO, TELOPT_NAWS);
	if (!ndc_connect || ndc_connect(fd)) {
		d->flags |= DF_CONNECTED;
		pty_open(fd);
	}

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
		char host[ENV_KEY_LEN];
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
			"\r\n",
			date, body_len);
	ndc_write(fd, body, body_len);

	struct descr *d = &descr_map[fd];
	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		ndc_close(fd);
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
		char host[ENV_KEY_LEN];
		ndc_env_get(fd, host, "HTTP_HOST");

		ndc_writef(fd, "HTTP/1.1 301 Moved Permanently\r\n"
				"Location: https://%s%s/\r\n"
				"Content-Length: 0\r\n"
				"Connection: close\r\n"
				"\r\n", host, document_uri);

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

	if (ndc_platform && ndc_platform->auth_try)
		ndc_platform->auth_try(fd);

	if (request_handle_trailing_slash(fd, document_uri))
		return;

	if (!(d->flags & DF_WEBSOCKET)) {
		if (request_handle_websocket(fd))
			return;
		d->flags |= DF_TO_CLOSE;
	}

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

	char *body = argv[argc] + body_start + 1;

	_env_prep(fd, document_uri, param, method);

	char path_with_method[16384];
	snprintf(path_with_method, sizeof(path_with_method), "%s:%s", method, document_uri);
	const void *key = qmap_get(hdlr_hd, path_with_method);
	if (!key)
		key = qmap_get(hdlr_hd, document_uri);

	ndc_handler_t *hdlr = NULL;
	if (key)
		memcpy(&hdlr, key, sizeof(hdlr));

	if (hdlr) {
		hdlr(fd, body);
		return;
	}

	if (ndc_config.default_handler) {
		ndc_config.default_handler(fd, body);
		return;
	}

	if (ndc_platform && ndc_platform->request_handle_cgi)
		ndc_platform->request_handle_cgi(fd, &stat_buf, body);
}

void
ndc_register_handler(char *path, ndc_handler_t handler)
{
	qmap_put(hdlr_hd, path, &handler);
}

void
do_GET(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, 0);
}

void
do_POST(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, NDC_POST);
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


__attribute__((constructor)) static void
ndc_pre_init(void)
{
	memset(&ndc_config, 0, sizeof(ndc_config));
	ndc_config.port = 80;
	ndc_config.ssl_port = 443;

	unsigned cert_type = qmap_reg(sizeof(cert_t));
	unsigned cmd_type = qmap_reg(sizeof(struct cmd_slot));
	unsigned hdlr_type = qmap_reg(sizeof(ndc_handler_t *));

	mime_hd = qmap_open(NULL, NULL, QM_STR, QM_STR, MIME_MASK, 0);
	cert_hd = qmap_open(NULL, NULL, QM_STR, cert_type, CERT_MASK, 0);
	hdlr_hd = qmap_open(NULL, NULL, QM_STR, hdlr_type, HDLR_MASK, 0);
	cmds_hd = qmap_open(NULL, NULL, QM_STR, cmd_type, CMD_MASK, 0);
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
