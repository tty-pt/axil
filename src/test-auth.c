#include "../include/ttypt/ndc.h"

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
	if (ndc_flags(fd) & DF_AUTHENTICATED)
		resp = "auth ok\n";
	else
		resp = "auth none\n";

	ndc_writef(fd, "HTTP/1.1 200 OK\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: %zu\r\n"
			"Connection: close\r\n"
			"\r\n"
			"%s",
			strlen(resp), resp);
	return 0;
}

char *
ndc_auth_check(socket_t fd)
{
	static char user[BUFSIZ];
	char cookie[ENV_VALUE_LEN], *eq;
	FILE *fp;

	if (ndc_env_get(fd, cookie, "HTTP_COOKIE"))
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

	ndc_config.flags = 0;

	while ((opt = getopt(argc, argv, "p:C:")) != -1) {
		switch (opt) {
		case 'p':
			ndc_config.port = (unsigned) atoi(optarg);
			break;
		case 'C':
			ndc_config.chroot = optarg;
			break;
		default:
			fprintf(stderr, "usage: %s -p <port> -C <dir>\n", argv[0]);
			return 1;
		}
	}

	ndc_config.default_handler = auth_handler;
	ndc_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("PRI", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);

	#if defined(SIGPIPE)
		signal(SIGPIPE, SIG_IGN);
	#endif

	return ndc_main();
}
