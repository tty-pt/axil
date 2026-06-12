#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1

#include "axil-internal.h"

#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <pwd.h>
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include <util.h>
#else
#include <pty.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Explicit declarations for functions hidden by _XOPEN_SOURCE */
#ifdef __APPLE__
int chroot(const char *);
int daemon(int, int);
int setgroups(int, const gid_t *);
int initgroups(const char *, int);  /* macOS uses int for gid */
#endif

#ifdef __OpenBSD__
int chroot(const char *);
int daemon(int, int);
int setgroups(int, const gid_t *);
int initgroups(const char *, gid_t);  /* OpenBSD uses gid_t */
#endif

/* OpenBSD may not define ECHOCTL */
#ifndef ECHOCTL
#define ECHOCTL 0
#endif

#include "../include/ttypt/qsys.h"
#include "../include/ttypt/qmap.h"

static char *statics_mmap;
static size_t statics_len = 0;

static char *autoindex_mmap;
static size_t autoindex_len = 0;

static struct passwd axil_pw;

#define ENV_CAP 0xFF

int axil_exec_loop(int cfd);

static char **
axil_env_prep(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	char **env = malloc(ENV_CAP * sizeof(char *));
	unsigned cur;
	size_t count = 0;
	const void *key, *value;

	cur = qmap_iter(d->env_hd, NULL, 0);
	while (qmap_next(&key, &value, cur)) {
		char *envstr = malloc(ENV_LEN);
		env[count++] = envstr;
		snprintf(envstr, ENV_LEN, "%s=%s",
				(char *) key,
				(char *) value);
	}

	env[count] = NULL;

	return env;
}

static void
axil_pw_free(struct passwd *target)
{
	free(target->pw_name);
	free(target->pw_shell);
	free(target->pw_dir);
}

static void
axil_pw_copy(struct passwd *target, struct passwd *origin)
{
	*target = *origin;
	target->pw_name = strdup(origin->pw_name);
	target->pw_shell = strdup(origin->pw_shell);
	target->pw_dir = strdup(origin->pw_dir);
	target->pw_passwd = NULL;
}

ssize_t
axil_mmap(char **mapped, char *file)
{
	int fd = open(file, O_RDONLY);

	if (fd < 0)
		return 0;

	struct stat sb;
	if (fstat(fd, &sb) == -1) {
		close(fd);
		return 0;
	}

	size_t file_size = sb.st_size;
	if (!file_size) {
		close(fd);
		return 0;
	}

	*mapped = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);

	if (*mapped == MAP_FAILED)
		return 0;

	return file_size;
}

char *
axil_mmap_iter(char *start, size_t *pos_r)
{
	char *line = start + *pos_r;
	char *line_end = strchr(line, '\n');
	if (line_end)
		*line_end = '\0';
	*pos_r += strlen(line) + 1;
	return line;
}

static void
axil_platform_init_pre_bind(void)
{
	char euname[BUFSIZ] = "root";
	int euid = 0;

	strncpy(euname, getpwuid(geteuid())->pw_name, sizeof(euname));
	axil_pw_copy(&axil_pw, getpwnam(euname));

	euid = geteuid();
	if (euid && !axil_config.chroot)
		axil_config.chroot = ".";
	if (!axil_config.chroot) {
		WARN("Running from cwd\n");
	} else if (!geteuid()) {
		CBUG(chroot(axil_config.chroot), "chroot\n");
		CBUG(chdir("/"), "chdir\n");
	} else
		CBUG(chdir(axil_config.chroot),
				"axil_main chdir2\n");

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	statics_len = axil_mmap(&statics_mmap, "./serve.allow");
	autoindex_len = axil_mmap(&autoindex_mmap, "./serve.autoindex");
}

static void
axil_platform_init_post_bind(void)
{
	if ((axil_srv_flags & AXIL_DETACH) && daemon(1, 1) != 0)
		exit(EXIT_SUCCESS);
}

static void
axil_platform_cleanup_descr(struct descr *d)
{
	if (d->flags & DF_AUTHENTICATED)
		axil_pw_free(&d->pw);
}

static void
axil_platform_auth_try(socket_t fd)
{
	if (!axil_auth_check)
		return;
	char *user = axil_auth_check(fd);
	if (user)
		axil_auth(fd, user);
}

static void
axil_platform_env_prep(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	axil_env_put(fd, "DOCUMENT_ROOT", geteuid() ? axil_config.chroot : "");
	axil_env_put(fd, "HOME", d->pw.pw_dir);
}

static char *
axil_platform_static_allowed(const char *path, struct stat *stat_buf)
{
	static char output[BUFSIZ];
	char *rstart = statics_mmap, *start, *out = NULL;
	size_t pos = 0;
	if (!statics_mmap)
		return NULL;

	do {
		start = axil_mmap_iter(rstart, &pos);
		char *glob = strchr(start, ' ');
		if (!glob)
			break;
		if (fnmatch(glob + 1, path, 0) == 0) {
			register char aux = *glob,
				 *aster = strchr(glob + 1, '*');

			CBUG(!aster, "No asterisk on serve.allow\n");

			size_t offset = aster - 1 - glob;
			aux = *glob;
			*glob = '\0';
			size_t len = snprintf(output, sizeof(output), "./%s/%s", start, path + offset);
			*glob = aux;
			if (output[len - 1] != '/') {
				if (stat(output, stat_buf))
					continue;
				out = output;
				break;
			}
		}
	} while (pos < statics_len);

	return out;
}

static char *
axil_platform_autoindex_allowed(const char *uri, struct stat *stat_buf)
{
	static char fs_path[BUFSIZ];
	char *rstart, *start, *out = NULL;
	size_t pos;

	// 1. Find the real filesystem path using serve.allow mappings
	rstart = statics_mmap;
	pos = 0;
	if (!statics_mmap)
		return NULL;

	do {
		start = axil_mmap_iter(rstart, &pos);
		char *glob = strchr(start, ' ');
		if (!glob)
			break;
		if (fnmatch(glob + 1, uri, 0) == 0) {
			char aux = *glob;
			*glob = '\0';
			snprintf(fs_path, sizeof(fs_path), "./%s%s", start, uri);
			*glob = aux;

			// We found a mapping. Now check if it's a directory.
			if (stat(fs_path, stat_buf) == 0 && S_ISDIR(stat_buf->st_mode)) {
				// It's a valid directory. Now proceed to step 2.
				out = fs_path;
				break;
			}
		}
	} while (pos < statics_len);

	if (!out)
		return NULL; // No valid directory found for this URI

	// 2. Now check if the ORIGINAL URI is approved for auto-indexing
	rstart = autoindex_mmap;
	pos = 0;
	if (!autoindex_mmap)
		return NULL;

	do {
		start = axil_mmap_iter(rstart, &pos);
		if (fnmatch(start, uri, 0) == 0) {
			// Success! Return the real filesystem path.
			return out;
		}
	} while (pos < autoindex_len);

	// Not in the autoindex list
	return NULL;
}

int
axil_auth(socket_t fd, char *username)
{
	struct descr *d = &descr_map[fd];
	/* syserr(LOG_ERR, "axil_auth %d %s", fd, username); */
	strncpy(d->username, username, sizeof(d->username));
	d->flags |= DF_AUTHENTICATED;
	axil_env_put(fd, "REMOTE_USER", d->username);
	struct passwd *pw = getpwnam(d->username);
	if (!pw)
		return 1;
	axil_pw_copy(&d->pw, pw);
	return 0;
}

static struct passwd *
drop_priviledges(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	int euid = geteuid();

	struct passwd *pw = (d->flags & DF_AUTHENTICATED)
		? &d->pw : &axil_pw;

	if (!axil_config.chroot) {
		WARN("NOT_CHROOTED - running with %s\n", pw->pw_name);
		return pw;
	}

	if (euid != 0) {
		WARN("NOT_ROOT - skipping privilege drop for %s\n", pw->pw_name);
		return pw;
	}

	CBUG(!pw, "getpwnam\n");
	CBUG(setgroups(0, NULL), "setgroups\n");
	CBUG(initgroups(pw->pw_name, pw->pw_gid), "initgroups\n");
	CBUG(setgid(pw->pw_gid), "setgid\n");
	CBUG(setuid(pw->pw_uid), "setuid\n");

	return pw;
}

static inline int
popen2(socket_t cfd, char * const args[])
{
	struct descr *d = &descr_map[cfd];
	pid_t p = -1;
	int pipe_stdin[2], pipe_stdout[2], pipe_stderr[2];

	if (pipe(pipe_stdin) \
			|| pipe(pipe_stdout) \
			|| pipe(pipe_stderr) \
			|| (p = fork()) < 0)
		return p;

	if(p == 0) { /* child */
		drop_priviledges(cfd);
		do_cleanup = 0;
		close(pipe_stdin[1]);
		dup2(pipe_stdin[0], 0);
		close(pipe_stdout[0]);
		dup2(pipe_stdout[1], 1);
		close(pipe_stderr[0]);
		dup2(pipe_stderr[1], 2);
		setpgid(0, 0);

		char * const *env = axil_env_prep(cfd);
		execve(args[0], args, env);
		CBUG(1, "execve\n");
	}

	d->pipes[0] = pipe_stdin[1];
	d->pipes[1] = pipe_stdout[0];
	d->pipes[2] = pipe_stderr[0];
	close(pipe_stdin[0]);
	close(pipe_stdout[1]);
	close(pipe_stderr[1]);
	return p;
}

static inline
ssize_t cb_proc(socket_t fd, int pfd,
		cmd_cb_t callback)
{
	char axil_execbuf[BUFSIZ * 64];

	struct descr *d = &descr_map[fd];
	memset(axil_execbuf, 0, sizeof(axil_execbuf));
	ssize_t len;
	int ofd;

	*axil_execbuf = '\0';

	ofd = pfd == d->pipes[1];
	len = read(pfd, axil_execbuf, sizeof(axil_execbuf) - 1);
	if (len > 0) {
		axil_execbuf[len] = '\0';
		callback(fd, axil_execbuf, len, ofd);
	} else if (len < 0) {
		if (errno != EAGAIN)
			ERR("read\n");
		return -1;
	}

	// stop iteration if output receives 0
	return len;
}

int
axil_exec_loop(int cfd)
{
	struct descr *d = &descr_map[cfd];
	fd_set read_fds;
	int ready_fds, total_timeout = 40 /* should be a config option */, ret = 0;
	ssize_t len = 0;

	d->flags &= ~DF_TO_CLOSE;

	do {
		struct timeval timeout;
		memcpy(&timeout, &exec_timeout, sizeof(timeout));
		int pfd;
		time_t dt;

		if (!d->pipes_mask)
			break;

		dt = time(NULL) - d->sor;

		if (dt >= total_timeout) {
			axil_writef(cfd, "504 Gateway Timeout\r\n"
					"Content-Type: text/plain\r\n"
					"Content-Length: 26\r\n"
					"\r\n"
					"Code 504: Gateway Timeout\n");
			ERR("Timeout! %u\n", cfd);
			break;
		}

		FD_ZERO(&read_fds);
		if (d->pipes_mask & 1)
			FD_SET(d->pipes[1], &read_fds);
		if (d->pipes_mask & 2)
			FD_SET(d->pipes[2], &read_fds);

		ready_fds = select(d->pipes[1] + 1, &read_fds, NULL, NULL, &timeout);

		if (!ready_fds)
			return 1;

		if (ready_fds == -1) {
			ERR("select %d\n", errno);
			break;
		}

		if (FD_ISSET(d->pipes[1], &read_fds))
			pfd = d->pipes[1];
		else if (FD_ISSET(d->pipes[2], &read_fds))
			pfd = d->pipes[2];
		else
			continue;

		errno = 0;
		len = cb_proc(cfd, pfd, d->callback);

		if (len > 0) {
			d->total += len;
			return 1;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			FD_SET(cfd, &fds_active);
			FD_SET(cfd, &fds_read);
			return 1;
		}

		if (pfd == d->pipes[1]) {
			d->pipes_mask &= ~1;
			break;
		} else
			d->pipes_mask &= ~2;

	} while (d->pipes_mask);

	if (d->total == 0) {
		char axil_execbuf[BUFSIZ * 64];
		read(d->pipes[2], axil_execbuf, sizeof(axil_execbuf) - 1);
		ERR("%s\n", axil_execbuf);
		axil_writef(cfd, "500 Internal Server Error\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Length: %ld\r\n"
				"\r\n"
				"Code 500: Internal Server Error:\n%s\n", strlen(axil_execbuf) + 37, axil_execbuf);
		ret = -1;
	} else {
		len = cb_proc(cfd, d->pipes[2], d->callback);
	}

	close(d->pipes[1]);
	close(d->pipes[2]);
	kill(-d->epid, SIGKILL);
	waitpid(d->epid, NULL, 0);
	d->epid = 0;
	memset(d->pipes, 0, sizeof(d->pipes));
	FD_CLR(cfd, &fds_wactive);

	d->flags |= DF_TO_CLOSE;
	if (!d->remaining_len)
		axil_close(cfd);

	return ret;
}

void
axil_exec(int cfd, char * const args[],
		cmd_cb_t callback, void *input,
		size_t input_len)
{
	struct descr *d = &descr_map[cfd];
	int flags;

	d->epid = popen2(cfd, args); // should assert it doesn't equal 0
	d->pipes_mask = 3;

	flags = fcntl(d->pipes[1], F_GETFL, 0);
	fcntl(d->pipes[1], F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(d->pipes[2], F_GETFL, 0);
	fcntl(d->pipes[2], F_SETFL, flags | O_NONBLOCK);

	if (input)
		write(d->pipes[0], input, input_len);
	close(d->pipes[0]);

	d->sor = time(NULL);
	d->total = 0;
	d->callback = callback;
	FD_SET(cfd, &fds_wactive);
}

void
axil_cert_add(char *optarg)
{
	char *domain = optarg, *crt, *ioc;
	ioc = strchr(optarg, ':');
	CBUG(!ioc, "Invalid cert info\n");
	*ioc = '\0';
	crt = ioc + 1;
	ioc = strchr(crt, ':');
	CBUG(!ioc, "Invalid cert info\n");
	*ioc = '\0';
	_axil_cert_add(domain, crt, ioc + 1);
	axil_srv_flags |= AXIL_SSL;
}

void
axil_certs_add(char *certs_file)
{
	char *mapped;
	size_t file_size = axil_mmap(&mapped, certs_file);
	size_t pos = 0;

	do
		axil_cert_add(axil_mmap_iter(mapped, &pos));
	while (pos < file_size);
}

static const struct axil_platform_ops axil_posix_ops = {
	.init_pre_bind = axil_platform_init_pre_bind,
	.init_post_bind = axil_platform_init_post_bind,
	.cleanup_descr = axil_platform_cleanup_descr,
	.pty_open = NULL,
	.pty_read = NULL,
	.handle_naws = NULL,
	.pty_write_input = NULL,
	.auth_try = axil_platform_auth_try,
	.env_prep = axil_platform_env_prep,
	.static_allowed = axil_platform_static_allowed,
	.autoindex_allowed = axil_platform_autoindex_allowed,
	.exec_loop = axil_exec_loop,
};

extern unsigned mime_hd;

void
axil_sendfile(socket_t fd, const char *path)
{
	int file_fd = open(path, O_RDONLY);
	if (file_fd < 0) {
		axil_respond(fd, 404, "404 Not Found");
		return;
	}

	struct stat st;
	if (fstat(file_fd, &st) < 0) {
		close(file_fd);
		axil_respond(fd, 500, "500 Internal Server Error");
		return;
	}

	char *ext = strrchr(path, '.');
	const char *mime = ext ? (const char *)qmap_get(mime_hd, ext + 1) : NULL;
	if (!mime)
		mime = "application/octet-stream";

	char *mapped = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, file_fd, 0);
	close(file_fd);

	if (mapped == MAP_FAILED) {
		axil_respond(fd, 500, "500 Internal Server Error");
		return;
	}

	char len_buf[32];
	snprintf(len_buf, sizeof(len_buf), "%ld", (long)st.st_size);
	axil_header_set(fd, "Content-Type", mime);
	axil_header_set(fd, "Content-Length", len_buf);
	axil_respond(fd, 200, NULL);
        axil_write(fd, mapped, st.st_size);
        munmap(mapped, st.st_size);
        struct descr *d = &descr_map[fd];
        d->flags |= DF_TO_CLOSE;
        if (!d->remaining_len)
                axil_close(fd);
        else
                axil_write_remaining(fd);
}

const struct axil_platform_ops *axil_platform = &axil_posix_ops;
