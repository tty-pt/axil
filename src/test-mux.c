#include "../include/ttypt/ndc.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
ndc_connect(socket_t fd)
{
	ndc_auth(fd, "test");
	return 1;
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

	signal(SIGPIPE, SIG_IGN);

	ndc_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("PRI", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);
	ndc_register("sh", do_sh, CF_NOAUTH | CF_NOTRIM);

	return ndc_main();
}
