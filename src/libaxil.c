#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1


#include "axil-internal.h"
#include "ws.c"

struct descr descr_map[FD_SETSIZE] AXIL_HIDDEN;

/* Source of per-connection generations for struct descr.generation. Never
 * reused or wrapped in practice: it is bumped once per accept, and an
 * unsigned long long at a million accepts a second still takes ~585k years. */
static unsigned long long conn_generation;


axil_cb_t do_GET, do_POST, do_PUT, do_DELETE, do_HEAD, do_sh;

unsigned char *input AXIL_HIDDEN;
size_t input_size = FIRST_INPUT_SIZE, input_len = 0;


struct timeval select_timeout, exec_timeout;

struct io io[FD_SETSIZE];

struct axil_config axil_config;
socket_t srv_ssl_fd = -1, srv_fd = -1;

int axil_srv_flags = 0;
unsigned cmds_hd AXIL_HIDDEN;
fd_set fds_read, fds_active, fds_write, fds_wactive;
socket_t tunnel_pair[FD_SETSIZE];
long long dt, tack = 0;
SSL_CTX *default_ssl_ctx;
long long axil_tick;
int do_cleanup = 1;

char axil_execbuf[BUFSIZ * 64];

char *domain_default = NULL;
unsigned cert_hd, mime_hd, hdlr_hd, ws_hd;
unsigned query_db AXIL_HIDDEN;

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

void axil_respond(socket_t fd, int code, const char *body)
{
	struct descr *d = &descr_map[fd];
	axil_default_response_headers(fd);

	size_t body_len = (body && !(d->flags & DF_HEAD)) ? strlen(body) : 0;

	/* Framing: without Content-Length the peer can only delimit the body
	 * by connection close, and over TLS that requires close_notify --
	 * without either, strict clients (OpenSSL 3.5+, current browsers)
	 * discard the response as truncated, taking Set-Cookie with it
	 * (observed live: a login 303 that neither logged in nor errored).
	 * 1xx/204/304 carry no body by definition, so no length is stated;
	 * anything else always closes (DF_TO_CLOSE below), hence the
	 * Connection header too. */
	axil_header_set_default(fd, "Connection", "close");
	if ((code < 100 || code >= 200) && code != 204 && code != 304) {
		char len_buf[32];
		snprintf(len_buf, sizeof(len_buf), "%lu",
		         (unsigned long)body_len);
		axil_header_set_default(fd, "Content-Length", len_buf);
	}

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

void *axil_respond_defer(socket_t fd, int code)
{
	struct descr *d;
	char hdr[4096];
	int hlen;

	if (fd <= 0 || fd >= FD_SETSIZE)
		return NULL;
	d = &descr_map[fd];
	if (d->flags & (DF_DEFERRED | DF_WEBSOCKET))
		return NULL;

	axil_default_response_headers(fd);
	axil_header_set_default(fd, "Connection", "close");

	hlen = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\n%s\r\n",
			code, axil_status_text(code), d->resp_headers);
	d->resp_headers[0] = '\0';

	if (hlen > 0)
		axil_write(fd, hdr, (size_t)hlen);

	d->flags |= DF_DEFERRED;
	return (void *)(intptr_t)fd;
}

void axil_respond_defer_finish(void *handle, const char *body)
{
	socket_t fd = (socket_t)(intptr_t)handle;
	struct descr *d;

	if (fd <= 0 || fd >= FD_SETSIZE)
		return;
	d = &descr_map[fd];
	if (!(d->flags & DF_DEFERRED))
		return;

	d->flags &= ~DF_DEFERRED;

	if (body)
		axil_write(fd, (void *)body, strlen(body));

	d->flags |= DF_TO_CLOSE;
	if (!d->remaining_len)
		axil_close(fd);
	else
		axil_write_remaining(fd);
}

void axil_respond_defer_done(void *handle)
{
	socket_t fd = (socket_t)(intptr_t)handle;
	struct descr *d;

	if (fd <= 0 || fd >= FD_SETSIZE)
		return;
	d = &descr_map[fd];
	if (!(d->flags & DF_DEFERRED))
		return;

	d->flags &= ~DF_DEFERRED;
	d->flags |= DF_TO_CLOSE;
	if (!d->remaining_len)
		axil_close(fd);
	else
		axil_write_remaining(fd);
}

void axil_respond_defer_abort(void *handle)
{
	socket_t fd = (socket_t)(intptr_t)handle;
	struct descr *d;

	if (fd <= 0 || fd >= FD_SETSIZE)
		return;
	d = &descr_map[fd];
	if (!(d->flags & DF_DEFERRED))
		return;

	d->flags &= ~DF_DEFERRED;
	axil_close(fd);
}


void axil_close(socket_t fd)
{
	if (fd == INVALID_SOCKET || fd >= FD_SETSIZE)
		return;
	/* Teardown is not idempotent at the syscall level: a real write error
	 * closes the fd from inside axil_low_write(), after which axil_respond(),
	 * axil_respond_defer_done(), axil_respond_defer_finish() and
	 * axil_write_remaining() all close again. The second pass would re-run
	 * axil_disconnect(), cleanup_descr(), shutdown() and close() against a
	 * dead number, and re-set DF_TO_CLOSE on the descriptor the first pass
	 * reset. If the kernel reissued the number in between -- it can, via the
	 * module hooks below -- that pass would close somebody else's fd.
	 * d->fd is -1 until descr_new() reuses the number, which is exactly the
	 * window this closes. */
	if (descr_map[fd].fd != fd)
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

	/* Unconditional. This used to be gated on DF_CONNECTED, which is only set
	 * by a WebSocket upgrade (axil_ws_upgrade) or axil_auth(), so every other
	 * descriptor -- including any connection a module had given a pty and a
	 * child shell to -- was torn down without ever reaching the hook. The
	 * kernel reuses fd numbers, so module state keyed by fd outlived its
	 * connection and landed on the next one. axil.h states this hook fires
	 * whenever a descriptor is torn down; this is that. SECURITY.md S5.4. */
	if (axil_disconnect)
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
		corm_close(d->env_hd);
		d->env_hd = 0;
	}

	shutdown(fd, 2);
	axil_sock_close(fd);

	tunnel_pair[fd] = INVALID_SOCKET;

	free(d->head);
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

/* Make room for `len` more bytes at the end of the write queue, growing the
 * buffer if it has to. Returns 0 on success, -1 if the buffer could not grow, in
 * which case the queue is left exactly as it was.
 *
 * The return value used to be void, so a realloc() that failed returned quietly
 * and every caller went on to memcpy() into a buffer that had not grown. That
 * was a heap overflow on the write path, and the bytes past the end were then
 * flushed to the peer (SECURITY.md finding 3). Callers must check, and must not
 * memcpy when this returns -1. */
inline static int axil_rem_may_inc(socket_t fd, size_t len)
{
	struct descr *d = &descr_map[fd];
	size_t need, old_size;

	size_t tail = d->remaining_size - (d->remaining_off + d->remaining_len);
	if (tail >= len)
		return 0;

	// compact
	if (d->remaining_off) {
		memmove(d->remaining, d->remaining + d->remaining_off,
		        d->remaining_len);
		d->remaining_off = 0;
		tail = d->remaining_size - d->remaining_len;
		if (tail >= len)
			return 0;
	}

	/* The queue never gets compacted again after this point, so there is no
	 * wrapped-around off. A size_t overflow here would leave `need` below
	 * remaining_size, skip the growth, and hand the caller a buffer smaller
	 * than the memcpy it is about to do. */
	if (len > SIZE_MAX - d->remaining_len) {
		errno = ENOMEM;
		return -1;
	}
	need = d->remaining_len + len;
	old_size = d->remaining_size;

	while (need >= d->remaining_size) {
		if (d->remaining_size > SIZE_MAX / 2) {
			/* Doubling would wrap to 0 and spin this loop forever. */
			d->remaining_size = need;
		} else {
			d->remaining_size *= 2;
		}

		char *tmp = realloc(d->remaining, d->remaining_size);
		if (!tmp) {
			d->remaining_size = old_size;
			errno = ENOMEM;
			return -1;
		}
		d->remaining = tmp;
	}

	return 0;
}

static io_ssize_t
axil_low_write(socket_t fd, void *from, io_size_t len, int flags UNUSED)
{
	struct descr *d = &descr_map[fd];
	struct io *dio = &io[fd];

	if (d->remaining_len) {
		/* The stream cannot survive a queue that will not grow: the bytes
		 * ahead of these are already promised to the peer, so there is no
		 * ordering left to preserve. Fail closed. */
		if (axil_rem_may_inc(fd, len) < 0) {
			axil_close(fd);
			return -1;
		}
		memcpy(d->remaining + d->remaining_off + d->remaining_len, from,
		       len);
		d->remaining_len += len;
		axil_write_remaining(fd);
		return -1;
	}

	int ret = dio->lower_write(fd, from, len, flags);

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			if (axil_rem_may_inc(fd, len) < 0) {
				axil_close(fd);
				return -1;
			}
			memcpy(d->remaining, from, len);
			d->remaining_off = 0;
			d->remaining_len = len;
			return -1;
		}

		/* A real write error. Returning left the fd in the descriptor table
		 * with a stream nobody would ever complete, so every later caller
		 * kept writing into it. Close instead: -1 from this function then
		 * means "queued" or "gone", and never "still open, still broken",
		 * which is what lets ws_write() report honestly (SECURITY.md S2.2).
		 * axil_close() also frees d->remaining, so nothing is left queued
		 * for a descriptor that no longer exists. */
		axil_close(fd);
		return -1;
	}

	if (ret >= 0 && (size_t)ret < len) {
		// partial send
		size_t left = len - ret;
		if (axil_rem_may_inc(fd, left) < 0) {
			axil_close(fd);
			return -1;
		}
		memcpy(d->remaining, (char *)from + ret, left);
		d->remaining_off = 0;
		d->remaining_len = left;
	}

	return ret;
}

static void descr_new(int ssl)
{
	struct sockaddr_in addr;
	socklen_t addr_len = (socklen_t)sizeof(addr);
	socket_t fd = accept(
	        ssl ? srv_ssl_fd : srv_fd, (struct sockaddr *)&addr, &addr_len);
	struct descr *d;
	struct io *dio;

	/* INVALID_SOCKET (~0) only survives "fd <= 0" once socket_t is the
	 * unsigned Windows SOCKET, so spell the sentinel out. */
	if (fd == INVALID_SOCKET || fd == 0)
		return;
	if (fd >= FD_SETSIZE) {
		axil_sock_close(fd);
		return;
	}

	/* Non-blocking, so the event loop can multiplex. Keep the existing
	 * flags, and use the winsock spelling where fcntl() is not fcntl(). */
#ifdef _WIN32
	u_long nonblock = 1;
	ioctlsocket(fd, FIONBIO, &nonblock);
#else
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl != -1)
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
#endif

#ifdef TCP_NODELAY
	int nodelay = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));
#endif

	FD_SET(fd, &fds_active);

	d = &descr_map[fd];
	dio = &io[fd];
	memset(d, 0, sizeof(struct descr));
	memset(dio, 0, sizeof(struct io));
	/* New identity for this slot. The memset above just zeroed it, and fd
	 * numbers are reused, so a module holding state keyed by fd from a previous
	 * connection cannot be told apart from this one by the number alone. */
	d->generation = ++conn_generation;
	/* frame_map is keyed by fd number and is not part of struct descr, so the
	 * memsets above do not touch it. A closed WebSocket that still held a
	 * partially received frame would otherwise leave frame_map[fd].data
	 * pointing at freed-or-not memory for the next connection to land on this
	 * fd number, and ws_read() reuses a non-NULL frame->data instead of
	 * allocating, so the new frame would be written into the old frame's
	 * buffer (SECURITY.md finding 7, S5.2). */
	ws_frame_reset(fd);
	d->addr = addr;
	d->fd = fd;
	d->flags = 0;
	d->remaining_size = BUFSIZ * 1024;
	d->remaining = malloc(d->remaining_size);
	if (!d->remaining) {
		axil_sock_close(fd);
		FD_CLR(fd, &fds_active);
		return;
	}
	d->epid = 0;
	d->env_hd = corm_open(NULL, NULL, CM_STR, CM_STR, ENV_MASK, 0);
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

void axil_upstream_descr_init(socket_t fd)
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
		axil_sock_close(fd);
		return;
	}
	d->epid = 0;
	d->env_hd = corm_open(NULL, NULL, CM_STR, CM_STR, ENV_MASK, 0);
	d->pty = -1;

	dio->read = dio->lower_read = (io_t)recv;
	dio->lower_write = (io_t)send;
	dio->write = axil_low_write;
}

/* Does the accumulated request contain a complete head, i.e. a blank line?
 * Returns the length of the buffer when it does, 0 when it does not. The method
 * is not inspected: a WebSocket frame or a tunnelled byte stream never reaches
 * this function, because descr_proc_reads() routes those descriptors by flag
 * first, and refusing to wait for the rest of an unrecognised method would
 * strand the connection (including axil_cmd_drop() for "PRI * HTTP/2.0"). */
static size_t head_complete(const unsigned char *buf, size_t len)
{
	size_t i;

	if (len < 4)
		return 0;

	/* Both CRLFCRLF and LFLF are accepted, as before. */
	for (i = 0; i < len; i++) {
		if (buf[i] != '\n')
			continue;
		if (i + 1 < len && buf[i + 1] == '\n')
			return len;
		if (i + 2 < len && buf[i + 1] == '\r' && buf[i + 2] == '\n')
			return len;
	}
	return 0;
}

/* Move a partially received head out of the shared input buffer and into the
 * descriptor so the next select() pass can resume from it. Returns 0 on
 * success. */
static int stash_head(struct descr *d, const unsigned char *buf, size_t len)
{
	unsigned char *tmp;
	size_t want;

	if (len > d->head_cap) {
		/* Grow geometrically, like axil_rem_may_inc(): a client dribbling
		 * a head in one-byte segments would otherwise realloc() on every
		 * select() pass. Clamp to MAX_REQUEST_HEAD so the doubling
		 * cannot overshoot the per-descriptor bound. */
		want = d->head_cap ? d->head_cap * 2 : len;
		if (want < len)
			want = len;
		if (want > MAX_REQUEST_HEAD)
			want = MAX_REQUEST_HEAD;
		tmp = realloc(d->head, want);
		if (!tmp)
			return -1;
		d->head = tmp;
		d->head_cap = want;
	}
	memcpy(d->head, buf, len);
	d->head_len = len;
	return 0;
}

inline static ssize_t axil_read(socket_t fd)
{
	char buf[BUFSIZ];
	struct io *dio = &io[fd];
	struct descr *d = &descr_map[fd];
	ssize_t rd;

	input_len = 0;

	/* Resume a head left over from an earlier select() pass. Dropped below
	 * once a complete head has been assembled. */
	if (d->head_len) {
		if (d->head_len >= input_size) {
			size_t old_size = input_size;
			unsigned char *tmp;

			input_size = d->head_len * 2 + 1;
			tmp = realloc(input, input_size);
			if (!tmp) {
				input_size = old_size;
				return -1;
			}
			input = tmp;
		}
		memcpy(input, d->head, d->head_len);
		input_len = d->head_len;
	}

	while (1) {
		rd = dio->read(fd, buf, sizeof(buf), 0);

		/* A WebSocket frame is already a whole message: ws_read() does its
		 * own reassembly, so appending a second frame would corrupt the
		 * request. A -1 means the frame is still incomplete and the
		 * descriptor must stay open for the rest to arrive. */
		if (d->flags & DF_WEBSOCKET) {
			d->head_len = 0;
			return rd;
		}

		if (rd < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				return -1;

			if (input_len > MAX_REQUEST_HEAD) {
				errno = EMSGSIZE;
				return -1;
			}
			/* Out of data mid-head. Report EAGAIN so the event loop keeps
			 * the descriptor and comes back when the rest arrives. */
			if (input_len > 0 && stash_head(d, input, input_len) == 0)
				errno = EAGAIN;
			return -1;
		}
		if (rd == 0) {
			/* EOF. A head that never got its blank line is not a request
			 * and must not be dispatched: cmd_new() walks to the
			 * terminator looking for '\r', finds the NUL instead, and
			 * points the body two bytes past it -- past anything a handler
			 * can measure, since axil_handler_t takes a bare char *.
			 * Returning 0 drops the buffer; descr_read()'s case 0 returns
			 * -1 and the caller closes. */
			d->head_len = 0;
			if (input_len > 0 && head_complete(input, input_len))
				return input_len;
			return 0;
		}

		/* Bound the head before growing, not after: input_size doubles on
		 * every overflowing read, so a client dribbling a head out without
		 * a terminator would drive the shared buffer well past
		 * MAX_REQUEST_HEAD before the 431 fired. */
		if (input_len + (size_t)rd > MAX_REQUEST_HEAD) {
			errno = EMSGSIZE;
			return -1;
		}

		if (input_len + (size_t)rd >= input_size) {
			size_t old_size = input_size;
			unsigned char *tmp;

			input_size *= 2;
			input_size += (size_t)rd + 1;
			tmp = realloc(input, input_size);
			if (!tmp) {
				input_size = old_size;
				return -1;
			}
			input = tmp;
		}
		memcpy(input + input_len, buf, (size_t)rd);
		input_len += (size_t)rd;
		input[input_len] = '\0';

		/* Accepted sockets are non-blocking (descr_new), so return as soon
		 * as the head is complete instead of sleeping in a poll loop for
		 * data that may never come. A request that arrives in one segment
		 * therefore costs exactly one read. */
		if (head_complete(input, input_len)) {
			d->head_len = 0;
			return input_len;
		}
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
	const struct cmd_slot *cmd = corm_get(cmds_hd, argv[0]);

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

/* Dispatch one WebSocket frame down the same path a raw request takes: a
 * module gets first refusal through axil_parse(), and whatever it leaves over
 * is a command line. Returns what descr_read() should return -- 0 to keep the
 * connection, -1 to close it. */
static int descr_read_ws(socket_t fd)
{
	ssize_t ret;

	/* Read into the same shared `input` the raw path assembles heads in.
	 * That buffer always has at least one spare byte -- axil_read() grows
	 * input_size past input_len, and axil_ws_read() refuses any frame
	 * larger than len - 1 -- so cmd_new()'s p[len] = '\0' lands in bounds.
	 *
	 * The payload is deliberately left unterminated. cmd_new() writes that
	 * byte itself as its first act, and a module taking first refusal is
	 * owed the frame's bytes exactly as they arrived, not clipped to a
	 * terminator axil invented. */
	ret = axil_ws_read(fd, input, input_size);
	if (ret < 0) {
		/* A frame still arriving is not an error: the descriptor stays
		 * open and select() comes back when the rest of it lands. */
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		/* A frame larger than input_size - 1 is refused rather than
		 * truncated, and a frame has no HTTP response to give it:
		 * axil_respond() drops replies for DF_WEBSOCKET anyway. Closing
		 * is the only way the peer learns, as in the raw path's EMSGSIZE
		 * branch in descr_read() below. */
		return -1;
	}
	if (ret == 0)
		return -1; /* EOF, as in `case 0:` below */

	/* Leave the shared buffer in the state the raw path would, for the POST
	 * body reader's offset arithmetic against `input`. */
	input_len = ret;

	if (axil_parse && axil_parse(fd, input, (int)ret) < 0)
		return 0;

	return cmd_parse(fd, (char *)input, (size_t)ret);
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

	/* While a deferred response is in flight, do not read into the global
	 * input buffer or dispatch another request on this socket. Drain/check
	 * only to detect client disconnect (EOF / error). */
	if (d->flags & DF_DEFERRED) {
		char discard[256];
		ssize_t n = io[fd].read(fd, discard, sizeof(discard), 0);
		if (n > 0)
			return 0;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 0;
		return -1;
	}

	/* A frame is handled before axil_read(), not after: on DF_WEBSOCKET that
	 * path assembles the frame in a buffer of its own and returns only the
	 * length, so the payload is already gone by the time we could look at it.
	 * Reading the frame here instead is what makes the length and the bytes
	 * come from one read -- with them paired, the hazard the old early return
	 * documented cannot occur. See SECURITY.md 1.1. */
	if (d->flags & DF_WEBSOCKET) {
		/* A module claimed this socket with axil_fd_watch(), which makes
		 * it the module's to read. The main loop keeps DF_EXTERN
		 * descriptors out of here entirely (they go to axil_fd_tick), so
		 * this is belt and braces -- but the ownership rule belongs next
		 * to the read that would otherwise take it. */
		if (d->flags & DF_EXTERN)
			return 0;

		return descr_read_ws(fd);
	}

	ret = axil_read(fd);
	switch (ret) {
	case -1:
		if (errno == EAGAIN)
			return 0;

		/* axil_read() caps a partial head instead of stashing forever.
		 * Answer here rather than in the read path: axil_respond()
		 * closes the fd, and a -1 from descr_read would make the caller
		 * close it a second time. */
		if (errno == EMSGSIZE) {
			/* A WebSocket frame has no HTTP response to give it: nobody is
			 * listening for one, and axil_respond() drops the reply for
			 * DF_WEBSOCKET anyway. Closing is the only way the peer learns
			 * the frame was refused. */
			if (d->flags & DF_WEBSOCKET)
				return -1;

			axil_respond_plain(fd, 431, "Request Header Fields Too Large");
			return 0;
		}

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

void axil_raw_descr_reset(socket_t fd)
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

	/* The memset() below would drop this pointer without freeing it. */
	if (d->head) {
		free(d->head);
		d->head = NULL;
	}
	d->head_len = 0;
	d->head_cap = 0;

	d->resp_headers[0] = '\0';

	if (d->env_hd) {
		axil_env_clear(fd);
		corm_close(d->env_hd);
		d->env_hd = 0;
	}

	shutdown(fd, 2);
	axil_sock_close(fd);

	tunnel_pair[fd] = INVALID_SOCKET;

	memset(&io[fd], 0, sizeof(struct io));
	memset(d, 0, sizeof(struct descr));
	d->fd = -1;
}

void axil_tunnel_close_raw(socket_t fd)
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

/* Classify the result of a read from a non-blocking descriptor:
 *  1 = data was read
 *  0 = end of stream, or a real error
 * -1 = would block, so nothing happened and we should try again later
 * Confusing EAGAIN with EOF closes healthy connections. */
static inline int read_result(ssize_t n)
{
	if (n > 0)
		return 1;
	if (n == 0)
		return 0;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return -1;
	return 0;
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
			int rr = read_result(n);

			/* Nothing available yet: stay in the set and try again when
			 * the socket becomes readable. Treating EAGAIN as EOF would
			 * tear down a perfectly healthy proxy. */
			if (rr < 0)
				continue;
			if (rr == 0) {
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

		/* WS proxy: the client is waiting for the upstream's 101, so its
		 * socket may already hold frames. Reading them here would parse
		 * them as an HTTP request. Leave them in the kernel buffer until
		 * axil_ws_tunnel() flips the pair to DF_TUNNEL, which clears
		 * DF_WS_PROXY_PENDING. */
		if (d->flags & DF_WS_PROXY_PENDING)
			continue;

		/* Raw tunnel mode */
		if (d->flags & DF_TUNNEL) {
			char buf[4096];
			ssize_t n = dio->read(i, buf, sizeof(buf), 0);
			int rr = read_result(n);

			if (rr < 0)
				continue;
			if (rr == 0) {
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

void axil_register(char *name, axil_cb_t *cb, int flags)
{
	struct cmd_slot cmd = { .name = name, .cb = cb, .flags = flags };
	corm_put(cmds_hd, name, &cmd);
}

static inline void mime_put(char *key, char *value)
{
	corm_put(mime_hd, key, value);
}

#ifdef __APPLE__
extern int chroot(const char *path);
#endif

static void axil_init(void)
{
	axil_srv_flags |= axil_config.flags | AXIL_WAKE;

	if ((axil_srv_flags & AXIL_DETACH))
		stllog_set(stl_syslog);

	if (axil_srv_flags & AXIL_SSL) {

		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();

		const cert_t *cert = corm_get(cert_hd, domain_default);
		default_ssl_ctx = cert->ctx;

		ERR_print_errors_cb(openssl_error_callback, NULL);
	}

	if (axil_platform && axil_platform->init_pre_bind)
		axil_platform->init_pre_bind();

	/* Post-chroot, pre-bind: init_pre_bind() is where -C did its chroot()
	 * and chdir("/"), and the first axil_bind() below is where the server
	 * becomes reachable. Content that resolves paths on disk belongs in this
	 * window -- after the filesystem view changed, before a request can beat
	 * it to the answer. */
	if (axil_post_chroot)
		axil_post_chroot();

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

int axil_flags(socket_t fd)
{
	return descr_map[fd].flags;
}

unsigned long long axil_generation(socket_t fd)
{
	return descr_map[fd].generation;
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

	unsigned cert_type = corm_reg(sizeof(cert_t));
	unsigned cmd_type = corm_reg(sizeof(struct cmd_slot));
	unsigned hdlr_type = corm_reg(sizeof(axil_handler_t *));
	unsigned ws_type = corm_reg(sizeof(axil_ws_upstream_t *));

	query_db = corm_open(NULL, NULL, CM_STR, CM_STR, 0xFF, 0);
	mime_hd = corm_open(NULL, NULL, CM_STR, CM_STR, MIME_MASK, 0);
	cert_hd = corm_open(NULL, NULL, CM_STR, cert_type, CERT_MASK, 0);
	hdlr_hd = corm_open(NULL, NULL, CM_STR, hdlr_type, HDLR_MASK, 0);
	ws_hd = corm_open(NULL, NULL, CM_STR, ws_type, HDLR_MASK, 0);
	cmds_hd = corm_open(NULL, NULL, CM_STR, cmd_type, CMD_MASK, 0);

	/* Register default HTTP command handlers */
	/* These need to be in the library, not just the axil binary */
	axil_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("HEAD", do_HEAD, CF_NOAUTH | CF_NOTRIM);
	axil_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);
	axil_register("PUT", do_PUT, CF_NOAUTH | CF_NOTRIM);
	axil_register("DELETE", do_DELETE, CF_NOAUTH | CF_NOTRIM);
}
