#ifndef NDC_PLATFORM_H
#define NDC_PLATFORM_H

#include <sys/stat.h>

#include "../include/ttypt/ndc.h"

struct descr;

struct ndc_platform_ops {
	void (*init_pre_bind)(void);
	void (*init_post_bind)(void);
	void (*cleanup_descr)(struct descr *d);
	void (*pty_open)(socket_t fd);
	int (*pty_read)(socket_t fd);
	int (*handle_naws)(socket_t fd, const unsigned char *input);
	int (*pty_write_input)(socket_t fd, const unsigned char *input, size_t offset, size_t len);
	void (*auth_try)(socket_t fd);
	void (*env_prep)(socket_t fd);
	char *(*static_allowed)(const char *path, struct stat *stat_buf);
	char *(*autoindex_allowed)(const char *uri, struct stat *stat_buf);
	void (*request_handle_cgi)(socket_t fd, struct stat *stat_buf, char *body);
	int (*exec_loop)(socket_t fd);
};

extern const struct ndc_platform_ops *ndc_platform;

#endif
