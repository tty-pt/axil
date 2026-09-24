#ifndef IIO_H
#define IIO_H

/**
 * @file iio.h
 * @brief I/O descriptor table abstraction for axil.
 *
 * Wraps read/write dispatch so a descriptor can carry extra protocol
 * state (e.g. WebSocket framing) beneath the socket fd.
 */

#include <stdio.h>

#ifdef _WIN32
/** @brief Plain integer type used for I/O sizes on Windows. */
typedef unsigned io_size_t;
/** @brief Signed integer type used for I/O sizes on Windows. */
typedef long io_ssize_t;
#else
/** @brief Unsigned I/O byte-size type. */
typedef size_t io_size_t;
/** @brief Signed I/O size type (result or error). */
typedef ssize_t io_ssize_t;
#endif

/**
 * @brief I/O operation hook performed on a descriptor.
 *
 * @param[in] fd    Socket descriptor.
 * @param[in] data  Buffer to read into or write from.
 * @param[in] len   Requested byte count.
 * @param[in] flags Operation flags.
 * @return Bytes transferred, or -1 on error.
 */
typedef io_ssize_t (*io_t)(socket_t fd, void *data, io_size_t len, int flags);

/**
 * @brief I/O dispatch table for one descriptor slot.
 */
struct io {
	/** Read hook for the active protocol. */
	io_t read;
	/** Write hook for the active protocol. */
	io_t write;
	/** Fallback read hook from the underlying transport. */
	io_t lower_read;
	/** Fallback write hook from the underlying transport. */
	io_t lower_write;
};

/** @brief Global I/O descriptor table (one entry per fd slot). */
extern struct io io[FD_SETSIZE];

#endif
