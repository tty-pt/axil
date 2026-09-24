#include "../include/ttypt/axil.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *g_pending;
static const char *g_status_path;

static void
write_ready(void)
{
	FILE *f;

	if (!g_status_path)
		return;
	f = fopen(g_status_path, "a");
	if (f) {
		fputs("ready\n", f);
		fclose(f);
	}
}

static int
route_plain(socket_t fd, const char *body)
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
route_defer(socket_t fd, char *body)
{
	(void)body;
	axil_header_set(fd, "Content-Type", "text/plain");
	g_pending = axil_respond_defer(fd, 200);
	if (g_pending)
		write_ready();
	return 0;
}

static int
route_finish(socket_t fd, char *body)
{
	(void)body;
	if (g_pending) {
		axil_respond_defer_finish(g_pending, "deferred-ok");
		g_pending = NULL;
	}
	return route_plain(fd, "finished-ok");
}

static int
route_done(socket_t fd, char *body)
{
	(void)body;
	if (g_pending) {
		axil_respond_defer_done(g_pending);
		g_pending = NULL;
	}
	return route_plain(fd, "done-ok");
}

static int
route_abort(socket_t fd, char *body)
{
	(void)body;
	if (g_pending) {
		axil_respond_defer_abort(g_pending);
		g_pending = NULL;
	}
	return route_plain(fd, "aborted-ok");
}

static int
route_double(socket_t fd, char *body)
{
	(void)body;
	if (g_pending) {
		axil_respond_defer_finish(g_pending, "deferred-ok");
		axil_respond_defer_finish(g_pending, "deferred-ok");
		g_pending = NULL;
	}
	return route_plain(fd, "double-ok");
}

static int
route_ping(socket_t fd, char *body)
{
	(void)body;
	return route_plain(fd, "pong");
}

int
main(int argc, char *argv[])
{
	int opt;

	axil_config.flags = 0;

	while ((opt = getopt(argc, argv, "p:s:")) != -1) {
		switch (opt) {
		case 'p':
			axil_config.port = (unsigned)atoi(optarg);
			break;
		case 's':
			g_status_path = optarg;
			break;
		default:
			fprintf(stderr, "usage: %s -p <port> [-s <statusfile>]\n", argv[0]);
			return 1;
		}
	}

	axil_register_handler("GET:/defer", route_defer);
	axil_register_handler("GET:/finish", route_finish);
	axil_register_handler("GET:/done", route_done);
	axil_register_handler("GET:/abort", route_abort);
	axil_register_handler("GET:/double", route_double);
	axil_register_handler("GET:/ping", route_ping);
	axil_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);

#if defined(SIGPIPE)
	signal(SIGPIPE, SIG_IGN);
#endif

	return axil_main();
}