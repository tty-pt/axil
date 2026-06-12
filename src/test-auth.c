#include "../include/ttypt/axil.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
auth_handler(socket_t fd, char *body)
{
	(void)body;
	const char *resp;
	if (axil_flags(fd) & DF_AUTHENTICATED)
		resp = "auth ok\n";
	else
		resp = "auth none\n";

	axil_writef(fd, "HTTP/1.1 200 OK\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %zu\r\n"
			"Connection: close\r\n"
			"\r\n"
			"%s",
			strlen(resp), resp);
	return 0;
}

char *
axil_auth_check(socket_t fd)
{
	static char user[BUFSIZ];
	char cookie[ENV_VALUE_LEN], *eq;
	FILE *fp;

	if (axil_env_get(fd, cookie, "HTTP_COOKIE"))
		return NULL;

	eq = strchr(cookie, '=');
	if (!eq)
		return NULL;

	snprintf(user, sizeof(user), "./sessions/%s", eq + 1);
	fp = fopen(user, "r");

	if (!fp)
		return NULL;

	fscanf(fp, "%s", user);
	fclose(fp);

	return user;
}

int
main(int argc, char *argv[])
{
	int opt;

	axil_config.flags = 0;

	while ((opt = getopt(argc, argv, "p:C:")) != -1) {
		switch (opt) {
		case 'p':
			axil_config.port = (unsigned) atoi(optarg);
			break;
		case 'C':
			axil_config.chroot = optarg;
			break;
		default:
			fprintf(stderr, "usage: %s -p <port> -C <dir>\n", argv[0]);
			return 1;
		}
	}

	axil_config.default_handler = auth_handler;
	axil_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("PRI", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);

	#if defined(SIGPIPE)
		signal(SIGPIPE, SIG_IGN);
	#endif

	return axil_main();
}
