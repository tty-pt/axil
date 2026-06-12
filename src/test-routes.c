#include "../include/ttypt/axil.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	axil_env_get(fd, id, "PATTERN_PARAM_ID");
	return route_respond(fd, id);
}

static int
route_songbook_edit(socket_t fd, char *body)
{
	char id[ENV_VALUE_LEN] = {0};
	char resp[ENV_VALUE_LEN + 16];

	(void)body;
	axil_env_get(fd, id, "PATTERN_PARAM_ID");
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
	axil_env_get(fd, id, "PATTERN_PARAM_ID");
	snprintf(resp, sizeof(resp), "chords:%s", id);
	return route_respond(fd, resp);
}

int
main(int argc, char *argv[])
{
	int opt;

	axil_config.flags = 0;

	while ((opt = getopt(argc, argv, "p:")) != -1) {
		switch (opt) {
		case 'p':
			axil_config.port = (unsigned)atoi(optarg);
			break;
		default:
			fprintf(stderr, "usage: %s -p <port>\n", argv[0]);
			return 1;
		}
	}

	axil_register_handler("GET:/song/:id", route_song);
	axil_register_handler("GET:/sb/*", route_songbook_catchall);
	axil_register_handler("GET:/sb/:id/edit", route_songbook_edit);
	axil_register_handler("/chords/:id", route_chords);
	axil_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("PRI", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);

#if defined(SIGPIPE)
	signal(SIGPIPE, SIG_IGN);
#endif

	return axil_main();
}
