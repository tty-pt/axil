#include "./../include/ttypt/ndc.h"

#include <unistd.h>
#include <signal.h>

#include <ttypt/qsys.h>
#include <ttypt/qmap.h>
#include <ttypt/ndx.h>

struct ndx_ctx ndx;

NDX_HOOK_DECL(const char *, get_session_user,
    const char *, token);

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET socket_t;
#else
#include <pwd.h>
#include <sys/select.h>
typedef int socket_t;
#endif

NDX_HOOK_DEF(int, on_ndc_exit, int, i);
NDX_HOOK_DEF(int, on_ndc_update, unsigned long long, dt);
NDX_HOOK_DEF(int, on_ndc_vim, socket_t, fd, int, argc, char **, argv);
NDX_HOOK_DEF(int, on_ndc_command, socket_t, fd, int, argc, char **, argv);
NDX_HOOK_DEF(int, on_ndc_connect, socket_t, fd);
NDX_HOOK_DEF(int, on_ndc_disconnect, socket_t, fd);
NDX_HOOK_DEF(int, on_ndc_tick, socket_t, fd);
NDX_HOOK_DEF(int, on_ndc_parse,
    socket_t, fd,
    unsigned char *, input,
    int, nread);

void exit_all(int i) {
	// close databases here
	on_ndc_exit(i);

	qsys_closelog();
#ifndef _WIN32
	sync();
#endif

	if (i)
		exit(i);
}

void
usage(char *prog) {
	fprintf(stderr, "Usage: %s [-Adr?] [-C PATH] [-u USER] [-k PATH] [-c PATH] [-p PORT] [-B BYTES] [-m MODS]\n", prog);
	fprintf(stderr, "    Options:\n");
	fprintf(stderr, "        -C PATH   changes directory to PATH before starting up.\n");
	fprintf(stderr, "        -u USER   login as USER before starting up.\n");
	fprintf(stderr, "        -k PATH   specify SSL certificate 'key' file\n");
	fprintf(stderr, "        -c PATH   specify SSL certificate 'crt' file\n");
	fprintf(stderr, "        -p PORT   specify server port\n");
	fprintf(stderr, "        -B BYTES  maximum POST body size in bytes (default: 10485760)\n");
	fprintf(stderr, "        -m MODS   colon-separated list of module paths to load\n");
	fprintf(stderr, "        -A        auto-authenticate all WebSocket connections\n");
	fprintf(stderr, "        -d        don't detach\n");
	fprintf(stderr, "        -r        root multiplex mode\n");
	fprintf(stderr, "        -?        display this message.\n");
}

int
main(int argc, char *argv[])
{
	register char c;
	char *mods = NULL;

	qsys_openlog("ndc");

	ndc_config.flags |= NDC_DETACH;

	while ((c = getopt(argc, argv, "?AdK:k:C:rp:s:B:m:"))
			!= -1) switch (c)
	{
		case 'A': ndc_config.flags |= NDC_AUTOAUTH; break;
		case 'd': ndc_config.flags &= ~NDC_DETACH; break;
		case 'p': ndc_config.port = atoi(optarg); break;
		case 'C': ndc_config.chroot = optarg; break;
		case 'K':
		case 'k': break;
		case 'r': ndc_config.flags |= NDC_ROOT; break;
		case 's': ndc_config.ssl_port = atoi(optarg);
			  break;
		case 'B': ndc_config.max_body_size = (size_t)strtoull(optarg, NULL, 10); break;
		case 'm': mods = optarg; break;
		default:
			  usage(*argv);
			  return 1;
	}

	optind = 1;

#ifndef _WIN32
	while ((c = getopt(argc, argv, "?AdK:k:C:rp:s:B:m:"))
			!= -1)
	{
		switch (c) {
		case 'K':
			ndc_certs_add(optarg);
			break;

		case 'k':
			ndc_cert_add(optarg);
			break;
			
		default: break;
		}
	}
#endif

	signal(SIGSEGV, exit_all);

	srand(getpid());

	if (ndc_config.chroot && chdir(ndc_config.chroot) != 0) {
		fprintf(stderr, "Failed to chdir to %s\n", ndc_config.chroot);
		return 1;
	}

	ndc_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("PRI", do_GET, CF_NOAUTH | CF_NOTRIM);
	ndc_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);

	ndx_init();

	if (mods) {
		char *p = mods, *sep;
		do {
			sep = strchr(p, ':');
			if (sep) *sep = '\0';
			ndx_load(p);
			if (sep) { *sep = ':'; p = sep + 1; }
		} while (sep);
	}

	ndc_main();

	// temporary
	exit_all(0);

	return 0;
}

char *ndc_auth_check(socket_t fd) {
	static char token[BUFSIZ];
	char cookie[ENV_VALUE_LEN], *p, *eq, *end;
	const char *username;

	if (ndc_env_get(fd, cookie, "HTTP_COOKIE"))
		return NULL;

	/* Find QSESSION=<token> among potentially multiple cookies */
	p = cookie;
	while (p && *p) {
		while (*p == ' ') p++;
		eq = strchr(p, '=');
		if (!eq) break;
		if (eq - p == 8 && strncmp(p, "QSESSION", 8) == 0) {
			eq++;
			end = strchr(eq, ';');
			if (end) {
				size_t len = (size_t)(end - eq);
				if (len >= sizeof(token)) len = sizeof(token) - 1;
				strncpy(token, eq, len);
				token[len] = '\0';
			} else {
				strncpy(token, eq, sizeof(token) - 1);
				token[sizeof(token) - 1] = '\0';
			}
			username = get_session_user(token);
			return username ? (char *)username : NULL;
		}
		p = strchr(eq, ';');
		if (p) p++;
	}

	return NULL;
}

void
ndc_update(unsigned long long dt)
{
	on_ndc_update(dt);
}

void ndc_vim(socket_t fd, int argc, char *argv[])
{
	if (!(ndc_flags(fd) & DF_AUTHENTICATED))
		return;

	on_ndc_vim(fd, argc, argv);
}

void ndc_command(socket_t fd, int argc, char *argv[])
{
	on_ndc_command(fd, argc, argv);
}

int ndc_connect(socket_t fd) {
	if (ndc_config.flags & NDC_AUTOAUTH) {
#ifndef _WIN32
		struct passwd *pw = getpwuid(geteuid());
		ndc_auth(fd, pw ? pw->pw_name : "root");
#else
		ndc_auth(fd, "root");
#endif
	}
	on_ndc_connect(fd);
	return !!(ndc_config.flags & NDC_AUTOAUTH);
}

void ndc_disconnect(socket_t fd) {
	if (!(ndc_flags(fd) & DF_AUTHENTICATED))
		return;

	on_ndc_disconnect(fd);
}

void ndc_fd_tick(socket_t fd) {
  on_ndc_tick(fd);
}

int ndc_parse(
    socket_t fd,
    unsigned char * input,
    int nread)
{
  return on_ndc_parse(fd, input, nread);
}
