#include "ndc-internal.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <ttypt/qmap.h>

extern unsigned mime_hd;

void
ndc_sendfile(socket_t fd, const char *path)
{
	int file_fd = open(path, O_RDONLY);
	if (file_fd < 0) {
		ndc_respond(fd, 404, "404 Not Found");
		return;
	}

	struct stat st;
	if (fstat(file_fd, &st) < 0) {
		close(file_fd);
		ndc_respond(fd, 500, "500 Internal Server Error");
		return;
	}

	char *ext = strrchr(path, '.');
	const char *mime = ext ? (const char *)qmap_get(mime_hd, ext + 1) : NULL;
	if (!mime)
		mime = "application/octet-stream";

	char len_buf[32];
	snprintf(len_buf, sizeof(len_buf), "%ld", (long)st.st_size);
	ndc_header_set(fd, "Content-Type", mime);
	ndc_header_set(fd, "Content-Length", len_buf);
	ndc_respond(fd, 200, NULL);

	char buf[BUFSIZ];
	ssize_t read_len;
	while ((read_len = read(file_fd, buf, sizeof(buf))) > 0) {
		ndc_write(fd, buf, (size_t)read_len);
	}

	close(file_fd);
	ndc_close(fd);
}

ssize_t
ndc_mmap(char **mapped, char *file)
{
	(void)file;
	if (mapped)
		*mapped = NULL;
	return 0;
}

char *
ndc_mmap_iter(char *start, size_t *pos)
{
	(void)start;
	if (pos)
		*pos = 0;
	return NULL;
}

int
ndc_auth(socket_t fd, char *username)
{
	(void)fd;
	(void)username;
	return 1;
}

void
ndc_pty(socket_t fd, char * const args[])
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
ndc_exec(socket_t cfd, char * const args[],
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
ndc_cert_add(char *optarg)
{
	(void)optarg;
}

void
ndc_certs_add(char *certs_file)
{
	(void)certs_file;
}

static void
ndc_platform_init_pre_bind(void)
{
}

static void
ndc_platform_init_post_bind(void)
{
}

static void
ndc_platform_cleanup_descr(struct descr *d)
{
	(void)d;
}

static void
ndc_platform_pty_open(socket_t fd)
{
	(void)fd;
}

static int
ndc_platform_pty_read(socket_t fd)
{
	(void)fd;
	return 0;
}

static int
ndc_platform_handle_naws(socket_t fd, const unsigned char *input)
{
	(void)fd;
	(void)input;
	return 9;
}

static int
ndc_platform_pty_write_input(socket_t fd, const unsigned char *input, size_t offset, size_t len)
{
	(void)fd;
	(void)input;
	(void)offset;
	(void)len;
	return 0;
}

static void
ndc_platform_auth_try(socket_t fd)
{
	(void)fd;
}

static void
ndc_platform_env_prep(socket_t fd)
{
	(void)fd;
}

static char *
ndc_platform_static_allowed(const char *path, struct stat *stat_buf)
{
	(void)path;
	(void)stat_buf;
	return NULL;
}

static char *
ndc_platform_autoindex_allowed(const char *uri, struct stat *stat_buf)
{
	(void)uri;
	(void)stat_buf;
	return NULL;
}

static int
ndc_platform_exec_loop(socket_t fd)
{
	(void)fd;
	return 0;
}

static const struct ndc_platform_ops ndc_win_ops = {
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
	.exec_loop = ndc_platform_exec_loop,
};

const struct ndc_platform_ops *ndc_platform = &ndc_win_ops;
#endif
