#include "../include/ttypt/axil.h"
/* NOTE: <ttypt/xy-mod.h> must NOT be included here. It defines a macro
 * xy_load() bound to this TU's own never-filled module context; the harness is
 * a host binary, so it uses the real xy_load() from xy.h, exactly like the
 * axil binary's main() does. */
#include <ttypt/xy.h>
#include <ttypt/axil-xy.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _WIN32
#include <pwd.h>
#endif

/* T7 (change 4): counts disconnects so the shell test can assert that
 * axil_disconnect() is reachable. It used to be gated on DF_CONNECTED (and then
 * on DF_AUTHENTICATED in axil_disconnect()), so it never fired for an
 * unauthenticated request -- which meant a module that had attached a pty to one
 * could never clean it up, and its fd-keyed state outlived the connection.
 * SECURITY.md S5.4. Both gates are gone; the count now includes
 * unauthenticated requests, which is the point. */
static int disconnects;

/* Mirror of the axil binary's own forwarder (axil.c): libaxil fires this from
 * axil_init() between init_pre_bind() and the first bind, so a harness that
 * left it undefined would boot every -T module without the post-chroot content
 * load that production gets -- the suite would then be testing a module-less
 * boot and calling it green. Nothing to chroot under -T; the hook fires all
 * the same, which is exactly the point of mirroring it. */
int
axil_post_chroot(void)
{
	return on_axil_post_chroot();
}

void
axil_disconnect(socket_t fd)
{
	(void)fd;
	disconnects++;
	/* Production's axil_disconnect() dispatches this; without it a module's
	 * per-connection state (PTY masters, children) leaks and watched fds spin
	 * the loop. The count above stays first so the S5.4 regression still
	 * observes every teardown including unauthenticated ones. */
	on_axil_disconnect(fd);
}

/* Mirrors the axil binary's hooks so modules under test (-T) see the same
 * dispatch they get in production. Without these, libaxil's guarded calls
 * (`if (!axil_connect || ...)`, `if (axil_parse && ...)`) short-circuit and a
 * loaded module's on_axil_connect/on_axil_parse never run -- the upgrade
 * completes but no hook fires. The -A branch copies axil.c's autoauth,
 * including DF_AUTH_AUTO, so the flag behaviour under test is the real one. */
int
axil_connect(socket_t fd)
{
	if (axil_config.flags & AXIL_AUTOAUTH) {
#ifndef _WIN32
		struct passwd *pw = getpwuid(geteuid());
		axil_auth(fd, pw ? pw->pw_name : "root");
#else
		axil_auth(fd, "root");
#endif
		if (FD_VALID(fd))
			axil_set_flags(fd, axil_flags(fd) | DF_AUTH_AUTO);
	}
	on_axil_connect(fd);
	return !!(axil_config.flags & AXIL_AUTOAUTH);
}

int
axil_parse(socket_t fd, unsigned char *input, int nread)
{
	return on_axil_parse(fd, input, nread);
}

void
axil_fd_tick(socket_t fd)
{
	on_axil_tick(fd);
}

static int
route_respond_str(socket_t fd, const char *body)
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

/* T7 (change 4): the session file names a user with no passwd entry, so
 * axil_auth() takes the unknown-user path. axil_get_pw() hands back exactly
 * the passwd entry drop_priviledges() would use, so this observes the
 * privilege-drop target without needing root: drop_priviledges() skips
 * setuid()/setgid() entirely when euid != 0, so an exec('id -u') probe could
 * never catch a zeroed entry. */
#ifndef _WIN32
static int
auth_pw_handler(socket_t fd, char *body)
{
	struct passwd pw;
	char resp[64];

	(void)body;
	memset(&pw, 0, sizeof(pw));
	if (axil_get_pw(fd, &pw) < 0)
		return route_respond_str(fd, "no-pw");
	snprintf(resp, sizeof(resp), "pw_uid=%lu\n", (unsigned long)pw.pw_uid);
	return route_respond_str(fd, resp);
}

/* T7: the return value of axil_auth() for a name the system does not know must
 * be 1 (not 0), while the privilege target must be the server's own axil_pw
 * entry rather than a zeroed struct passwd (uid 0). This connection is
 * unauthenticated, so the auth_try() path has not run and d->pw is whatever
 * axil_auth() below leaves behind. */
static int
auth_unknown_handler(socket_t fd, char *body)
{
	struct passwd pw;
	char resp[96];
	int ret;

	(void)body;
	memset(&pw, 0, sizeof(pw));
	ret = axil_auth(fd, "no-such-user-axil-test");
	if (axil_get_pw(fd, &pw) < 0)
		snprintf(resp, sizeof(resp), "ret=%d no-pw\n", ret);
	else
		snprintf(resp, sizeof(resp), "ret=%d uid=%lu name=%s\n", ret,
		         (unsigned long)pw.pw_uid,
		         pw.pw_name ? pw.pw_name : "(null)");
	return route_respond_str(fd, resp);
}

/* T7 (S7.1/S7.2): a name at or past sizeof(d->username). d->username is
 * BUFSIZ (8192) bytes and axil_auth() used to strncpy() into it without
 * terminating, leaving both axil_env_put() and getpwnam() reading past the end
 * of the field into the adjacent struct descr members.
 *
 * The observable that discriminates is the *length* of what axil_env_put()
 * stored, not the privilege result. REMOTE_USER goes into d->env_hd, which is
 * corm_open(..., CM_STR, CM_STR, ...) (libaxil.c:803), so corm measures the
 * value with a plain strlen and stores exactly that many bytes; axil_env_get()
 * reads it back through qsys_strlcpy(). So a correctly terminated truncated name
 * reads back as exactly 8191, and the unterminated one reads back as 8192 or
 * more -- the over-read runs into d->remaining, which is NULL on a fresh
 * connection, so it normally stops right there.
 *
 * Note what this deliberately does NOT assert: getpwnam() returns NULL for
 * 8192 junk bytes just as it does for 8191, so ret= and uid= are the same
 * before and after the fix. They guard against the fix introducing a bad
 * outcome; they are not evidence of termination. env_len= is the evidence.
 *
 * Neither ASan nor valgrind can see this class of bug at all: the over-read
 * stays inside the descr_map[] allocation, and ASan only poisons redzones
 * around whole allocations. Hence a length assertion.
 *
 * The name is built here rather than fed through axil_auth_check() because that
 * helper does fscanf(fp, "%s", user) into a static BUFSIZ buffer -- an unbounded
 * %s, so a long session name would overflow the test harness before it ever
 * reached the code under test. */
static int
auth_longname_handler(socket_t fd, char *body)
{
	struct passwd pw;
	char name[BUFSIZ + 64];
	char env[BUFSIZ * 2];
	size_t sum = 0;
	size_t name_len, env_len, i;
	char resp[128];
	int ret;

	(void)body;

	/* A position-dependent pattern, not a uniform fill: a uniform 'A' would
	 * hide an off-by-one in either direction, since the checksum of the wrong
	 * 8191 bytes would still look plausible. */
	name_len = BUFSIZ + 32;
	for (i = 0; i < name_len; i++)
		name[i] = (char) ('a' + (i % 26));
	name[name_len] = '\0';

	memset(&pw, 0, sizeof(pw));
	ret = axil_auth(fd, name);

	/* axil_get_pw() reports what drop_priviledges() would use. The truncated
	 * name is not a real account, so this must be the server's own axil_pw
	 * entry and never uid 0. */
	if (axil_get_pw(fd, &pw) < 0)
		return route_respond_str(fd, "no-pw");

	env_len = 0;
	if (axil_env_get(fd, env, sizeof(env), "REMOTE_USER") == 0)
		env_len = strlen(env);
	for (i = 0; i < env_len; i++)
		sum = (sum + (unsigned char) env[i]) % 1000003u;

	/* Numbers only. Returning the 8191 bytes themselves would make the
	 * response size part of what is being tested. */
	snprintf(resp, sizeof(resp), "ret=%d uid=%lu env_len=%zu sum=%zu nlen=%zu\n",
	         ret, (unsigned long)pw.pw_uid, env_len, sum, name_len);
	return route_respond_str(fd, resp);
}

/* T7 (S7.1): the descriptor bound axil_auth() gained alongside the termination
 * fix. descr_map[] is [FD_SETSIZE] and the function indexed it with whatever it
 * was handed, so fd = -1 and fd = FD_SETSIZE both wrote outside the array.
 * Unlike the username over-read above, this one *is* out-of-array, so it is
 * inside a global redzone and ASan does see it.
 *
 * This was added while fixing the strncpy() line below it rather than being
 * asked for by a finding, and it changes a public contract by adding a return
 * value, so it gets a test of its own. */
static int
auth_badfd_handler(socket_t fd, char *body)
{
	char resp[96];
	int lo, hi;

	(void)body;

	lo = axil_auth(-1, "axil-test-badfd");
	hi = axil_auth(FD_SETSIZE, "axil-test-badfd");

	snprintf(resp, sizeof(resp), "lo=%d hi=%d errno=%d\n", lo, hi, errno);
	return route_respond_str(fd, resp);
}
#endif /* !_WIN32 */

/* T7 (change 4): reports the disconnect count, including for this connection.
 * Both the DF_CONNECTED and DF_AUTHENTICATED gates are gone (SECURITY.md S5.4),
 * so an unauthenticated request such as this one bumps it. That is exactly the
 * behaviour under test: a module may hold a pty on an unauthenticated terminal,
 * so teardown cannot be conditional on auth. */
static int
auth_disconnect_handler(socket_t fd, char *body)
{
	char resp[32];

	(void)body;
	snprintf(resp, sizeof(resp), "%d\n", disconnects);
	return route_respond_str(fd, resp);
}

/* Reports DF_AUTH_AUTO for this connection. -A authenticates every connection as
 * the server's own account, so the only way a downstream module can tell a
 * published identity from a proven one is this flag -- the name is identical, so
 * a name comparison cannot help. DF_AUTHENTICATED is reported too because -A
 * sets that as well: a module gating on it alone is the bug this route catches.
 *
 * The flags are only meaningful after a WebSocket upgrade, because that is where
 * axil_connect() runs the -A autoauth; a plain request never sees it. So the
 * route upgrades and answers inside the first frame. */
static int
auth_flags_handler(socket_t fd, char *body)
{
	char resp[64], key[ENV_VALUE_LEN];
	int flags = axil_flags(fd);

	(void)body;

	if (axil_env_get(fd, key, sizeof(key), "HTTP_SEC_WEBSOCKET_KEY") == 0) {
		if (axil_ws_upgrade(fd) < 0)
			return route_respond_str(fd, "upgrade-failed");
		flags = axil_flags(fd);
		axil_ws_printf(fd, "auto=%d auth=%d\n",
		    !!(flags & DF_AUTH_AUTO) ? 1 : 0,
		    !!(flags & DF_AUTHENTICATED) ? 1 : 0);
#ifndef _WIN32
		/* External watch is POSIX-only (axil.h); without it the upgraded
		 * socket stays with descr_read_ws(), which is safe for this route. */
		axil_fd_watch(fd);
#endif
		return 1;
	}

	snprintf(resp, sizeof(resp), "auto=%d auth=%d\n",
	    !!(flags & DF_AUTH_AUTO) ? 1 : 0,
	    !!(flags & DF_AUTHENTICATED) ? 1 : 0);
	return route_respond_str(fd, resp);
}

char *
axil_auth_check(socket_t fd)
{
	static char user[BUFSIZ];
	char cookie[ENV_VALUE_LEN], *eq;
	FILE *fp;

	if (axil_env_get(fd, cookie, sizeof(cookie), "HTTP_COOKIE"))
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

	while ((opt = getopt(argc, argv, "p:C:AT:")) != -1) {
		switch (opt) {
		case 'p':
			axil_config.port = (unsigned) atoi(optarg);
			break;
		case 'C':
			axil_config.chroot = optarg;
			break;
		case 'A':
			axil_config.flags |= AXIL_AUTOAUTH;
			break;
		case 'T':
			/* Load a module under test (e.g. axil-tty) so its routes run
			 * behind this harness's file-backed cookie auth. The module's
			 * xy_install() runs at load; auth_init() equivalents, if any,
			 * are the module's own business. Host-side xy_load(): it
			 * ensures the runtime itself. */
			if (xy_load(optarg) != 0) {
				fprintf(stderr, "test-auth: xy_load(%s) failed\n", optarg);
				return 1;
			}
			break;
		default:
			fprintf(stderr, "usage: %s -p <port> -C <dir> [-A] [-T module]\n", argv[0]);
			return 1;
		}
	}

	axil_config.default_handler = auth_handler;
#ifndef _WIN32
	axil_register_handler("GET:/pw", auth_pw_handler);
	axil_register_handler("GET:/auth-unknown", auth_unknown_handler);
	axil_register_handler("GET:/auth-longname", auth_longname_handler);
	axil_register_handler("GET:/auth-badfd", auth_badfd_handler);
#endif
	axil_register_handler("GET:/disconnects", auth_disconnect_handler);
	axil_register_handler("GET:/autoauth", auth_flags_handler);
	axil_register_handler("GET:/wsflags", auth_flags_handler);
	axil_register("GET", do_GET, CF_NOAUTH | CF_NOTRIM);
	axil_register("POST", do_POST, CF_NOAUTH | CF_NOTRIM);
	axil_register("PUT", do_PUT, CF_NOAUTH | CF_NOTRIM);
	axil_register("DELETE", do_DELETE, CF_NOAUTH | CF_NOTRIM);

	#if defined(SIGPIPE)
		signal(SIGPIPE, SIG_IGN);
	#endif

	return axil_main();
}
