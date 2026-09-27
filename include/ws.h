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
 * @param[in] len   Requested byte count. Must be at least 1 whenever `data` is
 *                  non-NULL: a zero-length destination is refused with -1 and
 *                  `errno` EMSGSIZE, since it is the one value that cannot
 *                  describe any buffer at all. `data == NULL` discards the
 *                  frame whatever `len` is. The frame's NUL terminator needs
 *                  one of these bytes, so a payload is only returned when it
 *                  fits in `len - 1`.
 * @param[in] flags Operation flags.
 * @return Bytes read (NUL-terminated), or -1 on error. A frame larger than
 *         `len - 1` is refused with -1 and `errno` set to EMSGSIZE rather than
 *         truncated — note the frame is read off the socket in full before the
 *         size is known, so a refused frame is consumed and cannot be retried.
 *         -1 with `errno` EAGAIN means the frame is still arriving and nothing
 *         was consumed.
 */
io_ssize_t ws_read(socket_t fd, void *data, io_size_t len, int flags);

/**
 * @brief Framed write hook installed into the I/O table.
 * @param[in] fd    Socket descriptor.
 * @param[in] data  Source buffer.
 * @param[in] n     Byte count.
 * @param[in] flags Operation flags.
 * @return The frame size, header included, once the frame is wholly written or
 *         queued for a non-blocking socket, or -1 if the connection failed. A
 *         non-negative result does not mean the bytes have left the socket: when
 *         the peer is slow the tail sits in the descriptor's write queue and is
 *         flushed by the event loop. The header goes through the same queue as
 *         the payload, so frames cannot interleave or be lost to EAGAIN.
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
