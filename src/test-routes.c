#include "../include/ttypt/axil.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _WIN32
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

static int
route_respond(socket_t fd, const char *body)
{
	char len_buf[32];

	snprintf(len_buf, sizeof(len_buf), "%zu", strlen(body));
	axil_header_set(fd, "Content-Type", "text/plain");
	axil_header_set(fd, "Content-Length", len_buf);
	axil_header_set(fd, "Connection", "close");
	axil_respond(fd, 200, body);
	return 0;
}

static int
route_song(socket_t fd, char *body)
{
	char id[ENV_VALUE_LEN] = {0};

	(void)body;
	axil_env_get(fd, id, sizeof(id), "PATTERN_PARAM_ID");
	return route_respond(fd, id);
}

static int
route_songbook_edit(socket_t fd, char *body)
{
	char id[ENV_VALUE_LEN] = {0};
	char resp[ENV_VALUE_LEN + 16];

	(void)body;
	axil_env_get(fd, id, sizeof(id), "PATTERN_PARAM_ID");
	snprintf(resp, sizeof(resp), "edit:%s", id);
	return route_respond(fd, resp);
}

static int
route_songbook_catchall(socket_t fd, char *body)
{
	(void)body;
	return route_respond(fd, "catchall");
}

static int
route_chords(socket_t fd, char *body)
{
	char id[ENV_VALUE_LEN] = {0};
	char resp[ENV_VALUE_LEN + 16];

	(void)body;
	axil_env_get(fd, id, sizeof(id), "PATTERN_PARAM_ID");
	snprintf(resp, sizeof(resp), "chords:%s", id);
	return route_respond(fd, resp);
}

/* T1 (P1-5): echoes X-Probe back. A request whose header terminator arrives in
 * a later TCP segment must still be parsed as one complete request. */
static int
route_echo_header(socket_t fd, char *body)
{
	char probe[ENV_VALUE_LEN] = {0};

	(void)body;
	if (axil_header_get(fd, "X-Probe", probe, sizeof(probe)) < 0)
		return route_respond(fd, "no-probe");
	return route_respond(fd, probe);
}

/* T3 (P0-3): echoes the request body verbatim, so a body delivered in a second
 * segment is observable. */
static int
route_echo_body(socket_t fd, char *body)
{
	if (!body)
		return route_respond(fd, "no-body");
	return route_respond(fd, body);
}

/* T8: reports the request length against Content-Length. buffer_post_body() used
 * to count every read against its retry budget and return 0 when the budget ran
 * out, so a body needing more than 20 reads was silently truncated. A body well
 * past that mark must arrive complete. */
/* T8: reports whether the body arrived complete, and how big it was declared.
 *
 * Deliberately does *not* use strlen(body). buffer_post_body() appends the body
 * to the shared `input` buffer and never writes a terminator after it, while
 * axil_handler_t hands the handler a bare `char *` with no length and axil
 * exposes no content-length accessor -- so strlen() is the only length a
 * handler can see, and it reports the previous request's leftover bytes too
 * (reproducible: a 10 KB body reads back as 16308 after a 300 KB one). It can
 * also run past the end of the allocation when the tail happens to be free of
 * NULs. Instead the client puts a per-run token in the last bytes of the body
 * and in X-Body-Tail, and this compares the two at the declared offset: that is
 * what "the body arrived whole" means, and stale buffer content cannot match a
 * fresh token. */
static int
route_echo_size(socket_t fd, char *body)
{
	char clen[32] = { 0 };
	char tail[64] = { 0 };
	char resp[160];
	size_t declared, tail_len;

	axil_env_get(fd, clen, sizeof(clen), "HTTP_CONTENT_LENGTH");
	if (axil_header_get(fd, "X-Body-Tail", tail, sizeof(tail)) < 0)
		return route_respond(fd, "no-tail-header");

	declared = strtoul(clen, NULL, 10);
	tail_len = strlen(tail);
	if (!body || tail_len < 8 || declared < tail_len) {
		snprintf(resp, sizeof(resp),
		         "declared=%lu tail=short\n", (unsigned long)declared);
		return route_respond(fd, resp);
	}
	snprintf(resp, sizeof(resp), "declared=%lu strlen=%lu tail=%s\n",
	         (unsigned long)declared,
	         (unsigned long)strlen(body),
	         memcmp(body + declared - tail_len, tail, tail_len) == 0 ?
	                 "ok" :
	                 "bad");
	return route_respond(fd, resp);
}

/* T8: proof that an unregistered method is dispatched at all. At HEAD
 * head_complete() only accepted GET/POST/HEAD/PUT/DELETE, so an OPTIONS request
 * was never parsed into a request: the descriptor just sat there. Registering an
 * OPTIONS callback is the cheapest observable signal -- cmd_proc() only reaches
 * it once the head has been assembled and the method recognised.
 *
 * axil_vim() cannot be used for this: cmd_proc() returns before it for any method
 * it has no slot for unless the descriptor is already authenticated
 * (libaxil.c:1006), and auth_try() only ever runs from request_handle() for a
 * registered method -- so an unknown method never reaches the hook at all. */
/* S6.5: the public axil_ws_* wrappers must bound-check fd against
 * FD_SETSIZE, which is the extent of frame_map[], ws_flags[], descr_map[] and
 * io[]. Every other public entry point in libaxil.c, axil_close() included,
 * already rejects a descriptor outside the range.
 *
 * This runs as its own process (-B) and never as a route handler: the failure
 * mode is a garbage function pointer from io[-1].lower_read, so from a route it
 * would take the event-loop server and every other test case down with it. In
 * its own process a crash is just a nonzero exit.
 *
 * FD_SETSIZE + 64 as well as FD_SETSIZE itself: the one-past-the-end index is
 * what a `>=` check misses, and it is the common shape of the bug. */
static int
fd_bounds_selfcheck(void)
{
	static const socket_t bad[] = { -1, FD_SETSIZE, FD_SETSIZE + 64 };
	char buf[8];
	size_t i;
	int failures = 0;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		socket_t fd = bad[i];
		ssize_t r;

		/* len must be non-zero: ws_read() rejects a zero-length destination
		 * with EMSGSIZE before it parses anything, and that check is not
		 * what is under test here. */
		errno = 0;
		r = axil_ws_read(fd, buf, sizeof(buf));
		if (r == -1 && errno == EBADF)
			printf("fdbounds read fd=%lld ret=-1 errno=EBADF\n", (long long)fd);
		else {
			printf("fdbounds read fd=%lld ret=%lld errno=%d (want -1/EBADF)\n",
			       (long long)fd, (long long)r, errno);
			failures++;
		}

		errno = 0;
		r = axil_ws_write(fd, "x", 1);
		if (r == -1 && errno == EBADF)
			printf("fdbounds write fd=%lld ret=-1 errno=EBADF\n", (long long)fd);
		else {
			printf("fdbounds write fd=%lld ret=%lld errno=%d (want -1/EBADF)\n",
			       (long long)fd, (long long)r, errno);
			failures++;
		}

		errno = 0;
		r = axil_ws_printf(fd, "x");
		if (r == -1 && errno == EBADF)
			printf("fdbounds printf fd=%lld ret=-1 errno=EBADF\n", (long long)fd);
		else {
			printf("fdbounds printf fd=%lld ret=%lld errno=%d (want -1/EBADF)\n",
			       (long long)fd, (long long)r, errno);
			failures++;
		}

		/* axil_ws_close() returns 0 on success, so EBADF has to come back
		 * as -1 here. */
		errno = 0;
		r = axil_ws_close(fd);
		if (r == -1 && errno == EBADF)
			printf("fdbounds close fd=%lld ret=-1 errno=EBADF\n", (long long)fd);
		else {
			printf("fdbounds close fd=%lld ret=%lld errno=%d (want -1/EBADF)\n",
			       (long long)fd, (long long)r, errno);
			failures++;
		}
	}

	return failures ? 1 : 0;
}

static char last_options[64];

static void
route_options(socket_t fd, int argc, char *argv[])
{
	(void)fd;
	snprintf(last_options, sizeof(last_options), "%s %s", argc > 0 ? argv[0] : "?",
	         argc > 1 ? argv[1] : "?");
}

static int
route_unknown_methods(socket_t fd, char *body)
{
	(void)body;
	return route_respond(fd, last_options[0] ? last_options : "none");
}

/* T6 (change 5 + P1-7): serves a known file through both public static-file
 * entry points, so truncated bodies and HEAD handling are both observable.
 * Set with -f; test.sh points it at a fixture with a known size. */
static char test_file[BUFSIZ] = "README.md";

static int
route_sendfile(socket_t fd, char *body)
{
	(void)body;
	axil_sendfile(fd, test_file);
	return 0;
}

static int
route_respond_file(socket_t fd, char *body)
{
	(void)body;
	axil_respond_file(fd, test_file, "txt");
	return 0;
}

/* T4/T5a/T5b: WebSocket echo endpoint.
 *
 * axil_ws_handler() wants an upstream socket and then proxies the upgrade to
 * it: the child below answers the forwarded HTTP upgrade with a real 101, and
 * after that axil_ws_tunnel() hands the two sockets to each other as raw
 * bytes. The child is therefore a *raw* echo server, and the test gets a
 * byte-exact round trip through the DF_WS_WAITING and DF_TUNNEL paths.
 *
 * Note what this does NOT cover: the frame layer. axil_ws_tunnel() installs no
 * io hooks, so ws_read()/ws_write() are never called on the relay, and both
 * endpoints speak raw bytes. Frame-level behaviour needs axil_ws_upgrade() and
 * axil_ws_read()/axil_ws_write() in a handler (see PLAN.md 5.2).
 *
 * axil forwards the 101 to the client verbatim (libaxil.c:1125) without
 * validating Sec-WebSocket-Accept, so the child has to compute a correct one:
 * the client checks it. */
#ifndef _WIN32
/* RFC 6455 handshake GUID */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static void
ws_upstream_child(int fd)
{
	char req[4096];
	char resp[512];
	char key[128] = { 0 };
	char concat[sizeof(key) + sizeof(WS_GUID)];
	unsigned char sha[SHA_DIGEST_LENGTH];
	unsigned char b64[4 * ((SHA_DIGEST_LENGTH + 2) / 3) + 1];
	size_t got = 0, i;
	ssize_t n;

	while (got < sizeof(req) - 1) {
		n = read(fd, req + got, sizeof(req) - 1 - got);
		if (n <= 0)
			_exit(0);
		got += (size_t)n;
		req[got] = '\0';
		if (strstr(req, "\r\n\r\n"))
			break;
	}

	/* extract Sec-WebSocket-Key without depending on strcasestr */
	for (i = 0; i + 1 < got; i++) {
		if (req[i] == '\n' && !strncmp(req + i + 1, "Sec-WebSocket-Key:", 18))
		{
			char *p = req + i + 1 + 18;
			size_t k = 0;
			while (*p == ' ' || *p == '\t')
				p++;
			while (*p && *p != '\r' && *p != '\n' &&
			       k < sizeof(key) - 1)
				key[k++] = *p++;
			key[k] = '\0';
			break;
		}
	}
	if (!key[0])
		_exit(0);

	/* RFC 6455: accept = base64(SHA1(key + GUID)) */
	snprintf(concat, sizeof(concat), "%s%s", key, WS_GUID);
	SHA1((const unsigned char *)concat, strlen(concat), sha);
	EVP_EncodeBlock(b64, sha, SHA_DIGEST_LENGTH);
	b64[4 * ((SHA_DIGEST_LENGTH + 2) / 3)] = '\0';

	n = snprintf(resp, sizeof(resp),
	             "HTTP/1.1 101 Switching Protocols\r\n"
	             "Upgrade: websocket\r\n"
	             "Connection: Upgrade\r\n"
	             "Sec-WebSocket-Accept: %s\r\n"
	             "\r\n",
	             (char *)b64);
	if (n <= 0 || write(fd, resp, n) != n)
		_exit(0);

	for (;;) {
		n = read(fd, req, sizeof(req));
		if (n <= 0)
			_exit(0);
		if (write(fd, req, n) != n)
			_exit(0);
	}
}

static socket_t
ws_echo_upstream(socket_t client_fd)
{
	int sv[2];
	pid_t pid;

	/* libaxil.c:65 defines INVALID_SOCKET privately, so spell the sentinel
	 * out: axil_ws_upstream_t reports failure as -1. */
	(void)client_fd;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
		return -1;

	pid = fork();
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}
	if (!pid) {
		close(sv[1]);
		ws_upstream_child(sv[0]);
		_exit(0);
	}

	close(sv[0]);
	return sv[1];
}
#endif /* !_WIN32: fork() + socketpair() + OpenSSL */

#ifndef _WIN32
/* S0/T9: WebSocket frame endpoints. See SECURITY.md S0.1.
 *
 * /ws-frames is the supported flow: axil_ws_upgrade() then axil_fd_watch(),
 * which sets DF_EXTERN so the main loop hands the fd to axil_fd_tick() instead
 * of treating it as an HTTP client connection. The tick hook reads a frame and
 * echoes the payload.
 *
 * /ws-unwatched deliberately stops after axil_ws_upgrade(), with no
 * axil_fd_watch() and therefore no DF_EXTERN. That leaves descr_read() in
 * charge, which is the path finding 1 lives on: before the S1 fix a frame is
 * re-parsed as an HTTP request and cmd_new() writes at input[frame_length].
 * The route exists so SECURITY.md S1.4 has a real one-re-break/one-failure
 * proof. It is not a pattern to copy -- see S1.3. */
#define T9_FRAME_BUF_SIZE (256 * 1024)
static char t9_frame_buf[T9_FRAME_BUF_SIZE];

/* S2: /ws-pair answers one request frame with TWO frames written back to back in
 * a single tick. The first is large enough to overflow the socket buffers, so
 * axil_low_write() parks most of it in the descriptor's write queue; the second
 * is one byte. That is the exact shape that makes a frame header written on the
 * raw socket land *before* the queued bytes of the frame ahead of it -- or, when
 * the socket is full, get dropped with EAGAIN and lose the frame entirely.
 * Both are finding 2, and both are fixed by queuing the header too. */
#define T9_PAIR_BIG (128 * 1024)
#define T9_PAIR_PATTERN "0123456789abcdef"
static char t9_pair_buf[T9_PAIR_BIG];

/* axil_fd_tick() is one hook for every watched fd, so the route that claimed the
 * fd records what the tick should do. Reset by whichever route claims the fd,
 * so a reused fd number cannot inherit the previous connection's mode. */
enum t9_mode { T9_ECHO, T9_PAIR, T9_PRINTF, T9_LEAK, T9_LEN0 };
static enum t9_mode t9_mode[FD_SETSIZE];
static int t9_leak_armed[FD_SETSIZE];
static int t9_len0_logged[FD_SETSIZE];

static int
route_ws_frames(socket_t fd, char *body)
{
	(void)body;
	t9_mode[fd] = T9_ECHO;
	if (axil_ws_upgrade(fd) < 0)
		return 1;
	axil_fd_watch(fd);
	return 0;
}

static int
route_ws_pair(socket_t fd, char *body)
{
	/* Shrink the send buffer so backpressure is reached with a frame small
	 * enough to keep the test quick. The kernel enforces its own minimum and
	 * doubles the request; exact numbers do not matter, only that the combined
	 * buffers are far below T9_PAIR_BIG. */
	int sndbuf = 4096;

	(void)body;
	t9_mode[fd] = T9_PAIR;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	if (axil_ws_upgrade(fd) < 0)
		return 1;
	axil_fd_watch(fd);
	return 0;
}

static int
route_ws_printf(socket_t fd, char *body)
{
	(void)body;
	t9_mode[fd] = T9_PRINTF;
	if (axil_ws_upgrade(fd) < 0)
		return 1;
	axil_fd_watch(fd);
	return 0;
}

/* S6.2: axil_ws_read() into a zero-length destination. The bounds check used
 * to be `if (data && len && pl + 1 > len)`, so len == 0 turned it off and the
 * payload was then written into a buffer the caller had said held nothing.
 * The destination is a real malloc(0) so ASan sees the overflow, and the
 * result is logged for the runner to check. */
static int
route_ws_len0(socket_t fd, char *body)
{
	(void)body;
	t9_mode[fd] = T9_LEN0;
	t9_len0_logged[fd] = 0;
	if (axil_ws_upgrade(fd) < 0)
		return 1;
	axil_fd_watch(fd);
	return 0;
}

static int
route_ws_unwatched(socket_t fd, char *body)
{
	(void)body;
	t9_mode[fd] = T9_ECHO;
	(void)axil_ws_upgrade(fd);
	return 0;
}

/* S5.4: read one partial frame, then close the connection from the *server*
 * side, which is the only transition that orphaned the frame payload. A client
 * disconnect does not leak: the next tick observes EOF in ws_fill(), and that
 * path calls ws_frame_reset. ws_close() must do the same, or frame->data stays
 * allocated and still pointed at by frame_map[fd] -- and since ws_read() mallocs
 * the payload as soon as the length is parsed, before any payload byte arrives,
 * N connections closed mid-frame retain N x WS_MAX_PAYLOAD for the life of the
 * process, unauthenticated and before any auth check.
 *
 * Two observables that do *not* work, so nobody retries them: this is a leak
 * rather than an fd-reuse overflow (ws_init() clears the frame on every new
 * connection, so a reused fd number is always clean), and LeakSanitizer stays
 * quiet because frame_map is a global, leaving a leaked block reachable at exit.
 * The observable is bytes held in large private mappings, which is what T9
 * measures. */
static int
route_ws_leak(socket_t fd, char *body)
{
	(void)body;
	t9_mode[fd] = T9_LEAK;
	t9_leak_armed[fd] = 0;
	if (axil_ws_upgrade(fd) < 0)
		return 1;
	axil_fd_watch(fd);
	return 0;
}

void
axil_fd_tick(socket_t fd)
{
	ssize_t n;

	/* The tick must not close on a tick *count*: descr_proc_reads() dispatches
	 * here for a readable fd, and the same select pass that dispatched the HTTP
	 * upgrade can still be reported readable with no frame data in it, so the
	 * first tick after axil_fd_watch() routinely runs before the client's frame
	 * has arrived. Counting ticks therefore closed the connection before
	 * anything was ever allocated, and the leak never reproduced.
	 *
	 * Instead the close is armed by a frame actually completing (a read that
	 * returns > 0, which only happens once real frame bytes were parsed) and
	 * then fires on the EAGAIN that leaves a larger frame half-read. */
	if (t9_mode[fd] == T9_LEAK) {
		n = axil_ws_read(fd, t9_frame_buf, sizeof(t9_frame_buf));
		if (n > 0) {
			t9_leak_armed[fd] = 1;
			(void)axil_ws_write(fd, t9_frame_buf, (size_t)n);
			return;
		}
		if (t9_leak_armed[fd] && errno == EAGAIN)
			axil_close(fd);
		return;
	}

	if (t9_mode[fd] == T9_LEN0) {
		void *zero = malloc(0);

		errno = 0;
		n = axil_ws_read(fd, zero, 0);
		/* Close on EOF. A dead socket stays readable, so leaving the
		 * descriptor watched here spins the tick and floods the log. */
		if (n == 0) {
			free(zero);
			axil_close(fd);
			return;
		}
		/* Once per connection: the return value is a property of the call,
		 * not of how many ticks it took to get there. */
		if (!t9_len0_logged[fd]) {
			t9_len0_logged[fd] = 1;
			fprintf(stderr, "len0 ret=%zd errno=%d\n", n, errno);
		}
		free(zero);
		return;
	}

	n = axil_ws_read(fd, t9_frame_buf, sizeof(t9_frame_buf));

	/* A 0 is the peer closing, or a close frame: a real app stops reading and
	 * drops the connection, and that is what makes a spurious EOF observable.
	 * axil_ws_read() used to report 0 for a read interrupted by a signal
	 * (finding 8), so an app following that pattern closed healthy
	 * connections whenever a SIGCHLD or timer fired.
	 *
	 * EPROTO is a frame the server has already refused, having sent a 1002
	 * close for it (finding 12). The connection is finished, and leaving it
	 * watched ticks forever on the unread remainder of the bad frame. */
	if (n < 0) {
		if (errno == EPROTO)
			axil_close(fd);
		return;
	}
	if (n == 0) {
		axil_close(fd);
		return;
	}

	if (t9_mode[fd] == T9_PAIR) {
		size_t i;

		for (i = 0; i < sizeof(t9_pair_buf); i++)
			t9_pair_buf[i] = T9_PAIR_PATTERN[i % 16];
		(void)axil_ws_write(fd, t9_pair_buf, sizeof(t9_pair_buf));
		(void)axil_ws_write(fd, "B", 1);
		return;
	}

	if (t9_mode[fd] == T9_PRINTF) {
		/* The request frame carries the size to print. axil_ws_printf()
		 * formats into a `static char buf[BUFSIZ]`, so a request above
		 * BUFSIZ-1 is what makes ws_dprintf() over-report and ws_write()
		 * read past the buffer (SECURITY.md finding 4, S4.3). */
		long want = atol(t9_frame_buf);
		size_t i;

		if (want < 1)
			want = 1;
		if (want > (long)sizeof(t9_pair_buf) - 1)
			want = (long)sizeof(t9_pair_buf) - 1;
		for (i = 0; i < (size_t)want; i++)
			t9_pair_buf[i] = T9_PAIR_PATTERN[i % 16];
		/* Terminate, or "%s" reads whatever the previous request left in the
		 * tail of this shared buffer. */
		t9_pair_buf[want] = '\0';
		(void)axil_ws_printf(fd, "%s", t9_pair_buf);
		return;
	}

	(void)axil_ws_write(fd, t9_frame_buf, (size_t)n);
}
#endif /* !_WIN32: axil_fd_watch() is POSIX-only */

int
main(int argc, char *argv[])
{
	int opt;

	axil_config.flags = 0;

	while ((opt = getopt(argc, argv, "p:f:B")) != -1) {
		switch (opt) {
		case 'p':
			axil_config.port = (unsigned)atoi(optarg);
			break;
		case 'f':
			snprintf(test_file, sizeof(test_file), "%s", optarg);
			break;
		case 'B':
			/* S6.5 descriptor bounds self-check; see fd_bounds_selfcheck(). */
			return fd_bounds_selfcheck();
		default:
			fprintf(stderr, "usage: %s -p <port> [-f <file>] [-B]\n", argv[0]);
			return 1;
		}
	}

#ifndef _WIN32
	axil_ws_handler("GET:/ws-echo", ws_echo_upstream);
	axil_register_handler("GET:/ws-frames", route_ws_frames);
	axil_register_handler("GET:/ws-leak", route_ws_leak);
	axil_register_handler("GET:/ws-pair", route_ws_pair);
	axil_register_handler("GET:/ws-printf", route_ws_printf);
	axil_register_handler("GET:/ws-unwatched", route_ws_unwatched);
	axil_register_handler("GET:/ws-len0", route_ws_len0);
#endif
	axil_register_handler("GET:/song/:id", route_song);
	axil_register_handler("GET:/sb/*", route_songbook_catchall);
	axil_register_handler("GET:/sb/:id/edit", route_songbook_edit);
	axil_register_handler("/chords/:id", route_chords);
	axil_register_handler("GET:/echo-header", route_echo_header);
	axil_register_handler("GET:/sendfile", route_sendfile);
	axil_register_handler("HEAD:/sendfile", route_sendfile);
	axil_register_handler("GET:/respond-file", route_respond_file);
	axil_register_handler("HEAD:/respond-file", route_respond_file);
	axil_register_handler("POST:/echo-body", route_echo_body);
	axil_register_handler("PUT:/echo-body", route_echo_body);
	axil_register_handler("DELETE:/echo-body", route_echo_body);
	axil_register_handler("POST:/echo-size", route_echo_size);
	axil_register_handler("GET:/unknown-methods", route_unknown_methods);
	axil_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);
	axil_register("PUT", do_PUT, CF_NOAUTH | CF_NOTRIM);
	axil_register("DELETE", do_DELETE, CF_NOAUTH | CF_NOTRIM);
	axil_register("OPTIONS", route_options, CF_NOAUTH | CF_NOTRIM);

#if defined(SIGPIPE)
	signal(SIGPIPE, SIG_IGN);
#endif

	return axil_main();
}
