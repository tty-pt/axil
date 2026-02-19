#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1

#include "ndc-internal.h"

#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <pwd.h>
#include <pty.h>
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

#include "../include/ttypt/qsys.h"
#include "../include/ttypt/qmap.h"

static char *statics_mmap;
static size_t statics_len = 0;

static char *autoindex_mmap;
static size_t autoindex_len = 0;

static struct passwd ndc_pw;
static char cgi_index[] = "./index.sh";

#define ENV_CAP 0xFF

int ndc_exec_loop(int cfd);

static char **
ndc_env_prep(socket_t fd)
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

void
pw_free(struct passwd *target)
{
	free(target->pw_name);
	free(target->pw_shell);
	free(target->pw_dir);
}

void
pw_copy(struct passwd *target, struct passwd *origin)
{
	*target = *origin;
	target->pw_name = strdup(origin->pw_name);
	target->pw_shell = strdup(origin->pw_shell);
	target->pw_dir = strdup(origin->pw_dir);
	target->pw_passwd = NULL;
}

ssize_t
ndc_mmap(char **mapped, char *file)
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
ndc_mmap_iter(char *start, size_t *pos_r)
{
	char *line = start + *pos_r;
	char *line_end = strchr(line, '\n');
	if (line_end)
		*line_end = '\0';
	*pos_r += strlen(line) + 1;
	return line;
}

static void
ndc_platform_init_pre_bind(void)
{
	char euname[BUFSIZ] = "root";
	int euid = 0;

	strncpy(euname, getpwuid(geteuid())->pw_name, sizeof(euname));
	pw_copy(&ndc_pw, getpwnam(euname));

	euid = geteuid();
	if (euid && !ndc_config.chroot)
		ndc_config.chroot = ".";
	if (!ndc_config.chroot) {
		WARN("Running from cwd\n");
	} else if (!geteuid()) {
		CBUG(chroot(ndc_config.chroot), "chroot\n");
		CBUG(chdir("/"), "chdir\n");
	} else
		CBUG(chdir(ndc_config.chroot),
				"ndc_main chdir2\n");

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	statics_len = ndc_mmap(&statics_mmap, "./serve.allow");
	autoindex_len = ndc_mmap(&autoindex_mmap, "./serve.autoindex");
}

static void
ndc_platform_init_post_bind(void)
{
	if ((ndc_srv_flags & NDC_DETACH) && daemon(1, 1) != 0)
		exit(EXIT_SUCCESS);
}

static void
ndc_platform_cleanup_descr(struct descr *d)
{
	if (d->flags & DF_AUTHENTICATED)
		pw_free(&d->pw);

	if (d->pty > 0) {
		if (d->pid > 0)
			kill(-d->pid, SIGKILL);
		d->pid = -1;
		FD_CLR(d->pty, &fds_active);
		FD_CLR(d->pty, &fds_read);
		descr_map[d->pty].pty = -1;
		close(d->pty);
		d->pty = -1;
	}
}

static void
ndc_tty_update(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	struct termios last = d->tty;

	if ((last.c_lflag & ECHO) != (d->tty.c_lflag & ECHO))
		TELNET_CMD(fd, IAC, d->tty.c_lflag & ECHO ? WILL : WONT, TELOPT_ECHO);

	if ((last.c_lflag & ICANON) != (d->tty.c_lflag & ICANON))
		TELNET_CMD(fd, IAC, d->tty.c_lflag & ICANON ? WONT : WILL, TELOPT_SGA);

	tcgetattr(d->pty, &d->tty);
	tcflush(d->pty, TCIFLUSH);
}

static void
ndc_platform_pty_open(socket_t fd)
{
	struct descr *d = &descr_map[fd];

	d->tty.c_lflag = ICANON | ECHO | ECHOK | ECHOCTL;
	d->tty.c_iflag = IGNCR;
	d->tty.c_iflag &= ~ICRNL;
	d->tty.c_iflag &= ~INLCR;
	d->tty.c_oflag |= OPOST | ONLCR;
	d->tty.c_oflag &= ~OCRNL;

	CBUG(fcntl(fd, F_SETFL, O_NONBLOCK) == -1,
			"pty_open fcntl F_SETFL O_NONBLOCK\n");

	d->pty = posix_openpt(O_RDWR | O_NOCTTY);

	/* fprintf(stderr, "pty_open %d %d\n", fd, d->pty); */

	CBUG(d->pty == -1, "pty_open posix_openpt\n");
	CBUG(grantpt(d->pty), "pty_open grantpt\n");
	CBUG(unlockpt(d->pty), "pty_open unlockpt\n");

	descr_map[d->pty].fd = fd;
	descr_map[d->pty].pty = -1;

	tcsetattr(d->pty, TCSANOW, &d->tty);
	ndc_tty_update(fd);

	if (d->wsz.ws_col || d->wsz.ws_row)
		ioctl(d->pty, TIOCSWINSZ, &d->wsz);
}

static int
ndc_platform_pty_read(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	static char buf[BUFSIZ * 4];
	int ret = -1, status;

	errno = 0;
	/* if (waitpid(d->pid, NULL, WNOHANG) > 0) { */
	/* 	if (errno == EAGAIN) */
	/* 		ret = 0; */
	/* 	else */
	/* 		goto close; */
	/* }; */

	memset(buf, 0, sizeof(buf));
	errno = 0;
	ret = read(d->pty, buf, sizeof(buf));

	switch (ret) {
		case 0:
			if (d->pid > 0 && waitpid(d->pid, &status, WNOHANG) == 0)
				return 0;
			break;
		case -1:
			if (errno == EAGAIN || errno == EIO)
				return 0;
			return -1;
		default:
			buf[ret] = '\0';
			ndc_write(fd, buf, ret);
			ndc_tty_update(fd);
			return ret;
	}

	if (d->pid > 0)
		kill(d->pid, SIGKILL);

	d->pid = -1;
	return ret;
}

static int
ndc_platform_handle_naws(socket_t fd, const unsigned char *input)
{
	struct descr *d = &descr_map[fd];
	unsigned char colsHighByte = input[3];
	unsigned char colsLowByte = input[4];
	unsigned char rowsHighByte = input[5];
	unsigned char rowsLowByte = input[6];

	memset(&d->wsz, 0, sizeof(d->wsz));
	d->wsz.ws_col = (colsHighByte << 8) | colsLowByte;
	d->wsz.ws_row = (rowsHighByte << 8) | rowsLowByte;

	if (d->pty > 0)
		ioctl(d->pty, TIOCSWINSZ, &d->wsz);

	return 9;
}

static int
ndc_platform_pty_write_input(socket_t fd, const unsigned char *input, size_t offset, size_t len)
{
	struct descr *d = &descr_map[fd];

	if (d->pid > 0 && offset < len) {
		write(d->pty, input + offset, len);
		return 1;
	}

	return 0;
}

static void
ndc_platform_auth_try(socket_t fd)
{
	if (!ndc_auth_check)
		return;
	char *user = ndc_auth_check(fd);
	if (user)
		ndc_auth(fd, user);
}

static void
ndc_platform_env_prep(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	ndc_env_put(fd, "DOCUMENT_ROOT", geteuid() ? ndc_config.chroot : "");
	ndc_env_put(fd, "HOME", d->pw.pw_dir);
}

static char *
ndc_platform_static_allowed(const char *path, struct stat *stat_buf)
{
	static char output[BUFSIZ];
	char *rstart = statics_mmap, *start, *out = NULL;
	size_t pos = 0;
	if (!statics_mmap)
		return NULL;

	do {
		start = ndc_mmap_iter(rstart, &pos);
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
ndc_platform_autoindex_allowed(const char *uri, struct stat *stat_buf)
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
		start = ndc_mmap_iter(rstart, &pos);
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
		start = ndc_mmap_iter(rstart, &pos);
		if (fnmatch(start, uri, 0) == 0) {
			// Success! Return the real filesystem path.
			return out;
		}
	} while (pos < autoindex_len);

	// Not in the autoindex list
	return NULL;
}

static void
ndc_platform_request_handle_cgi(socket_t fd, struct stat *stat_buf, char *body)
{
	if (stat(cgi_index, stat_buf) || access(cgi_index, X_OK)) {
		const char *body = "404 Not Found\n";
		ndc_writef(fd, "HTTP/1.1 404 Not Found\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Length: %zu\r\n"
				"\r\n"
				"%s",
				strlen(body), body);
		return;
	}

	char * args[2] = { cgi_index, NULL };
	ndc_writef(fd, "HTTP/1.1 ");

	ndc_exec(fd, args, do_GET_cb, body, strlen(body));

	ndc_exec_loop(fd);
}

int
ndc_auth(socket_t fd, char *username)
{
	struct descr *d = &descr_map[fd];
	/* syserr(LOG_ERR, "ndc_auth %d %s", fd, username); */
	strncpy(d->username, username, sizeof(d->username));
	d->flags |= DF_AUTHENTICATED;
	struct passwd *pw = getpwnam(d->username);
	if (!pw)
		return 1;
	pw_copy(&d->pw, pw);
	return 0;
}

static struct passwd *
drop_priviledges(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	int euid = geteuid();

	struct passwd *pw = (d->flags & DF_AUTHENTICATED)
		? &d->pw : &ndc_pw;

	if (!ndc_config.chroot) {
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

		char * const *env = ndc_env_prep(cfd);
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
	char ndc_execbuf[BUFSIZ * 64];

	struct descr *d = &descr_map[fd];
	memset(ndc_execbuf, 0, sizeof(ndc_execbuf));
	ssize_t len;
	int ofd;

	*ndc_execbuf = '\0';

	ofd = pfd == d->pipes[1];
	len = read(pfd, ndc_execbuf, sizeof(ndc_execbuf) - 1);
	if (len > 0) {
		ndc_execbuf[len] = '\0';
		callback(fd, ndc_execbuf, len, ofd);
	} else if (len < 0) {
		if (errno != EAGAIN)
			ERR("read\n");
		return -1;
	}

	// stop iteration if output receives 0
	return len;
}

int
ndc_exec_loop(int cfd)
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
			ndc_writef(cfd, "504 Gateway Timeout\r\n"
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
		char ndc_execbuf[BUFSIZ * 64];
		read(d->pipes[2], ndc_execbuf, sizeof(ndc_execbuf) - 1);
		ERR("%s\n", ndc_execbuf);
		ndc_writef(cfd, "500 Internal Server Error\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Length: %ld\r\n"
				"\r\n"
				"Code 500: Internal Server Error:\n%s\n", strlen(ndc_execbuf) + 37, ndc_execbuf);
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
		ndc_close(cfd);

	return ret;
}

void
ndc_exec(int cfd, char * const args[],
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

inline static int
command_pty(socket_t cfd, struct winsize *ws, char * const args[])
{
	struct descr *d = &descr_map[cfd];
	pid_t p;

	/* fprintf(stderr, "command_pty WILL EXEC %s\n", args[0]); */
	FD_SET(d->pty, &fds_active);
	descr_map[d->pty].pty = -2;

	p = fork();
	if(p == 0) { /* child */
		do_cleanup = 0;

		struct descr *d = &descr_map[cfd];
		CBUG(setsid() == -1, "setsid\n");

		CBUG(!(d->flags & DF_AUTHENTICATED),
				"NOT AUTHENTICATED\n");

		int slave_fd = open(ptsname(d->pty), O_RDWR);
		CBUG(slave_fd == -1,
				"open %d\n",
				errno);

		struct passwd *pw = drop_priviledges(cfd);

		int pflags = fcntl(slave_fd, F_GETFL, 0);
		CBUG(pflags == -1, "pflags -1\n");

		close(d->pty);

		CBUG(ioctl(slave_fd, TIOCSCTTY, NULL) == -1,
				"ioctl TIOCSCTTY\n");

		CBUG(ioctl(slave_fd, TIOCSWINSZ, ws) == -1,
				"ioctl TIOCSWINSZ\n");

		CBUG(fcntl(slave_fd, F_SETFD, FD_CLOEXEC) == -1,
				"fcntl srv_fd F_SETFL FD_CLOEXEC\n");

		CBUG(dup2(slave_fd, STDIN_FILENO) == -1,
				"dup2 STDIN\n");
		CBUG(dup2(slave_fd, STDOUT_FILENO) == -1,
				"dup2 STDOUT\n");
		CBUG(dup2(slave_fd, STDERR_FILENO) == -1,
				"dup2 STDERR\n");

		char *alt_args[] = { pw->pw_shell, NULL };
		char * const *real_args = args[0] ? args : alt_args;
		char home[BUFSIZ], user[BUFSIZ], shell[BUFSIZ];
		snprintf(home, sizeof(home), "HOME=%s", d->pw.pw_dir);
		snprintf(user, sizeof(user), "USER=%s", d->pw.pw_name);
		snprintf(shell, sizeof(shell), "SHELL=%s", d->pw.pw_shell);

		char * const env[] = {
			"PATH=/bin:/usr/bin:/usr/local/bin",
			"LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib",
			home,
			user,
			shell,
			NULL,
		};

		execve(real_args[0], real_args, env);
		CBUG(1, "execve\n");
	}

	return p;
}

void
ndc_pty(socket_t fd, char * const args[])
{
	struct descr *d = &descr_map[fd];

	/* fprintf(stderr, "ndc_pty %s %d pty %d SGA %d ECHO %d\n", */
	/* 		args[0], fd, d->pty, WONT, WILL); */

	d->pid = command_pty(fd, &d->wsz, args);
	FD_SET(d->pty, &fds_active);

	/* fprintf(stderr, "PTY master fd: %d\n", d->pty); */
}

void
do_sh(socket_t fd, int argc UNUSED, char *argv[] UNUSED)
{
	char *args[] = { NULL, NULL };
	ndc_pty(fd, args);
}

void
ndc_cert_add(char *optarg)
{
	char *domain = optarg, *crt, *ioc;
	ioc = strchr(optarg, ':');
	CBUG(!ioc, "Invalid cert info\n");
	*ioc = '\0';
	crt = ioc + 1;
	ioc = strchr(crt, ':');
	CBUG(!ioc, "Invalid cert info\n");
	*ioc = '\0';
	_ndc_cert_add(domain, crt, ioc + 1);
	ndc_srv_flags |= NDC_SSL;
}

void
ndc_certs_add(char *certs_file)
{
	char *mapped;
	size_t file_size = ndc_mmap(&mapped, certs_file);
	size_t pos = 0;

	do
		ndc_cert_add(ndc_mmap_iter(mapped, &pos));
	while (pos < file_size);
}

static const struct ndc_platform_ops ndc_posix_ops = {
	.init_pre_bind = ndc_platform_init_pre_bind,
	.init_post_bind = ndc_platform_init_post_bind,
	.cleanup_descr = ndc_platform_cleanup_descr,
	.pty_open = ndc_platform_pty_open,
	.pty_read = ndc_platform_pty_read,
	.handle_naws = ndc_platform_handle_naws,
	.pty_write_input = ndc_platform_pty_write_input,
	.auth_try = ndc_platform_auth_try,
	.env_prep = ndc_platform_env_prep,
	.static_allowed = ndc_platform_static_allowed,
	.autoindex_allowed = ndc_platform_autoindex_allowed,
	.request_handle_cgi = ndc_platform_request_handle_cgi,
	.exec_loop = ndc_exec_loop,
};

const struct ndc_platform_ops *ndc_platform = &ndc_posix_ops;
