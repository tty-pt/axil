#ifndef WS_H
#define WS_H

#include <unistd.h>
#include <stdarg.h>

int ws_init(socket_t fd, char *buf);
void ws_close(socket_t fd);
io_ssize_t ws_read(socket_t fd, void *data, io_size_t len, int flags);
io_ssize_t ws_write(socket_t fd, void *data, io_size_t n, int flags);
int ws_dprintf(socket_t fd, const char *fmt, va_list ap);
int ws_printf(socket_t fd, const char *fmt, ...);

#endif
