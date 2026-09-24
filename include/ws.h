#ifndef WS_H
#define WS_H

/**
 * @file ws.h
 * @brief WebSocket framing on top of the axil I/O table.
 *
 * Handles handshake buffers, close, and framed read/write dispatch
 * through the io[fd] slots.
 */

#include <unistd.h>
#include <stdarg.h>

/**
 * @brief Initialize WebSocket framing on a descriptor.
 * @param[in] fd  Socket descriptor.
 * @param[in] buf Handshake buffer (consumed by the handshake).
 * @return 0 on success, -1 on failure.
 */
int ws_init(socket_t fd, char *buf);

/**
 * @brief Close a WebSocket session and tear down its framing state.
 * @param[in] fd Socket descriptor.
 */
void ws_close(socket_t fd);

/**
 * @brief Framed read hook installed into the I/O table.
 * @param[in] fd    Socket descriptor.
 * @param[in] data  Destination buffer.
 * @param[in] len   Requested byte count.
 * @param[in] flags Operation flags.
 * @return Bytes read, or -1 on error.
 */
io_ssize_t ws_read(socket_t fd, void *data, io_size_t len, int flags);

/**
 * @brief Framed write hook installed into the I/O table.
 * @param[in] fd    Socket descriptor.
 * @param[in] data  Source buffer.
 * @param[in] n     Byte count.
 * @param[in] flags Operation flags.
 * @return Bytes written, or -1 on error.
 */
io_ssize_t ws_write(socket_t fd, void *data, io_size_t n, int flags);

/**
 * @brief Write a formatted string over a WS frame (va_list form).
 * @param[in] fd  Socket descriptor.
 * @param[in] fmt Format string.
 * @param[in] ap  Argument list.
 * @return 0 on success, -1 on error.
 */
int ws_dprintf(socket_t fd, const char *fmt, va_list ap);

/**
 * @brief Write a formatted string over a WS frame.
 * @param[in] fd  Socket descriptor.
 * @param[in] fmt Format string.
 * @return 0 on success, -1 on error.
 */
int ws_printf(socket_t fd, const char *fmt, ...);

#endif
