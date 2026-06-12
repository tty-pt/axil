#include "axil-internal.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <ttypt/qmap.h>

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

	char len_buf[32];
	snprintf(len_buf, sizeof(len_buf), "%ld", (long)st.st_size);
	axil_header_set(fd, "Content-Type", mime);
	axil_header_set(fd, "Content-Length", len_buf);
	axil_respond(fd, 200, NULL);

	char buf[BUFSIZ];
	ssize_t read_len;
	while ((read_len = read(file_fd, buf, sizeof(buf))) > 0) {
		axil_write(fd, buf, (size_t)read_len);
	}

	close(file_fd);
	axil_close(fd);
}

ssize_t
axil_mmap(char **mapped, char *file)
{
	(void)file;
	if (mapped)
		*mapped = NULL;
	return 0;
}

char *
axil_mmap_iter(char *start, size_t *pos)
{
	(void)start;
	if (pos)
		*pos = 0;
	return NULL;
}

int
axil_auth(socket_t fd, char *username)
{
	(void)fd;
	(void)username;
	return 1;
}

void
axil_pty(socket_t fd, char * const args[])
{
	(void)fd;
	(void)args;
}

void
do_sh(socket_t fd, int argc, char *argv[])
{
	(void)fd;
	(void)argc;
	(void)argv;
}

void
axil_exec(socket_t cfd, char * const args[],
        cmd_cb_t callback, void *input,
        size_t input_len)
{
	(void)cfd;
	(void)args;
	(void)callback;
	(void)input;
	(void)input_len;
}

void
axil_cert_add(char *optarg)
{
	(void)optarg;
}

void
axil_certs_add(char *certs_file)
{
	(void)certs_file;
}

static void
axil_platform_init_pre_bind(void)
{
}

static void
axil_platform_init_post_bind(void)
{
}

static void
axil_platform_cleanup_descr(struct descr *d)
{
	(void)d;
}

static void
axil_platform_pty_open(socket_t fd)
{
	(void)fd;
}

static int
axil_platform_pty_read(socket_t fd)
{
	(void)fd;
	return 0;
}

static int
axil_platform_handle_naws(socket_t fd, const unsigned char *input)
{
	(void)fd;
	(void)input;
	return 9;
}

static int
axil_platform_pty_write_input(socket_t fd, const unsigned char *input, size_t offset, size_t len)
{
	(void)fd;
	(void)input;
	(void)offset;
	(void)len;
	return 0;
}

static void
axil_platform_auth_try(socket_t fd)
{
	(void)fd;
}

static void
axil_platform_env_prep(socket_t fd)
{
	(void)fd;
}

static char *
axil_platform_static_allowed(const char *path, struct stat *stat_buf)
{
	(void)path;
	(void)stat_buf;
	return NULL;
}

static char *
axil_platform_autoindex_allowed(const char *uri, struct stat *stat_buf)
{
	(void)uri;
	(void)stat_buf;
	return NULL;
}

static int
axil_platform_exec_loop(socket_t fd)
{
	(void)fd;
	return 0;
}

static const struct axil_platform_ops axil_win_ops = {
	.init_pre_bind = axil_platform_init_pre_bind,
	.init_post_bind = axil_platform_init_post_bind,
	.cleanup_descr = axil_platform_cleanup_descr,
	.pty_open = axil_platform_pty_open,
	.pty_read = axil_platform_pty_read,
	.handle_naws = axil_platform_handle_naws,
	.pty_write_input = axil_platform_pty_write_input,
	.auth_try = axil_platform_auth_try,
	.env_prep = axil_platform_env_prep,
	.static_allowed = axil_platform_static_allowed,
	.autoindex_allowed = axil_platform_autoindex_allowed,
	.exec_loop = axil_platform_exec_loop,
};

const struct axil_platform_ops *axil_platform = &axil_win_ops;
#endif
