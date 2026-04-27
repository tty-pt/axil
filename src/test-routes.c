#include "../include/ttypt/ndc.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
route_respond(socket_t fd, const char *body)
{
	ndc_writef(fd, "HTTP/1.1 200 OK\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %zu\r\n"
			"Connection: close\r\n"
			"\r\n"
			"%s",
			strlen(body), body);
	return 0;
}

static int
route_song(socket_t fd, char *body)
{
	char id[ENV_VALUE_LEN] = {0};

	(void)body;
	ndc_env_get(fd, id, "PATTERN_PARAM_ID");
	return route_respond(fd, id);
}

static int
route_songbook_edit(socket_t fd, char *body)
{
	char id[ENV_VALUE_LEN] = {0};
	char resp[ENV_VALUE_LEN + 16];

	(void)body;
	ndc_env_get(fd, id, "PATTERN_PARAM_ID");
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
	ndc_env_get(fd, id, "PATTERN_PARAM_ID");
	snprintf(resp, sizeof(resp), "chords:%s", id);
	return route_respond(fd, resp);
}

int
main(int argc, char *argv[])
{
	int opt;

	ndc_config.flags = 0;

	while ((opt = getopt(argc, argv, "p:")) != -1) {
		switch (opt) {
		case 'p':
			ndc_config.port = (unsigned)atoi(optarg);
			break;
		default:
			fprintf(stderr, "usage: %s -p <port>\n", argv[0]);
			return 1;
		}
	}

	ndc_register_handler("GET:/song/:id", route_song);
	ndc_register_handler("GET:/sb/*", route_songbook_catchall);
	ndc_register_handler("GET:/sb/:id/edit", route_songbook_edit);
	ndc_register_handler("/chords/:id", route_chords);
	ndc_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("PRI", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);

#if defined(SIGPIPE)
	signal(SIGPIPE, SIG_IGN);
#endif

	return ndc_main();
}
