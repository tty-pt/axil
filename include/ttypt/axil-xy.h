#ifndef AXIL_XY_H
#define AXIL_XY_H

/**
 * @file axil-xy.h
 * @brief XY hook declarations for the axil event loop.
 *
 * Modules listen on these hooks to react to server lifecycle, command
 * input, and client connect/disconnect events.
 */

#include <ttypt/xy.h>

#ifdef _WIN32
#include <winsock2.h>
/** @brief Socket handle type on Windows. */
typedef SOCKET socket_t;
#else
#include <sys/select.h>
/** @brief Socket descriptor type. */
typedef int socket_t;
#endif

/** @brief Hook fired as the server is about to exit (i = exit code). */
XY_DECL(int, on_axil_exit, int, i);
/** @brief Hook fired each event-loop update (dt = millisecond delta). */
XY_DECL(int, on_axil_update, unsigned long long, dt);
/** @brief Hook fired for vim (-v) command input on a client fd. */
XY_DECL(int, on_axil_vim, socket_t, fd, int, argc, char **, argv);
/** @brief Hook fired for a command string from a client fd. */
XY_DECL(int, on_axil_command, socket_t, fd, int, argc, char **, argv);
/** @brief Hook fired when a client connects. */
XY_DECL(int, on_axil_connect, socket_t, fd);
/** @brief Hook fired when a client disconnects. */
XY_DECL(int, on_axil_disconnect, socket_t, fd);
/** @brief Hook fired on each periodic tick for a client fd. */
XY_DECL(int, on_axil_tick, socket_t, fd);
/** @brief Hook fired with raw parsed input bytes from a client fd. */
XY_DECL(int, on_axil_parse,
    socket_t, fd,
    unsigned char *, input,
    int, nread);

#endif
