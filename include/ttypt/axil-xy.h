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

/** @brief Hook fired once after startup's `-C` chroot/chdir, before any bind.
 *
 *  This is the point where the process's filesystem view has changed but no
 *  socket is listening yet, so a module that resolves paths at boot -- a
 *  content loader, say -- can load from inside the jail here and be finished
 *  before the first request is served. Hooks fired later (on_axil_update,
 *  on_axil_connect, ...) all run after bind, which is too late for that.
 *
 *  Zero implementors is a safe no-op; a second fire (a host that does not
 *  chroot has nothing to do) is the implementor's own to ignore. */
XY_DECL(int, on_axil_post_chroot, void);
/** @brief Hook fired as the server is about to exit (i = exit code). */
XY_DECL(int, on_axil_exit, int, i);
/** @brief Hook fired each event-loop update (dt = millisecond delta). */
XY_DECL(int, on_axil_update, unsigned long long, dt);
/** @brief Hook fired for vim (-v) command input on a client fd. */
XY_DECL(int, on_axil_vim, socket_t, fd, int, argc, char **, argv);
/** @brief Hook fired for a command string from a client fd. */
XY_DECL(int, on_axil_command, socket_t, fd, int, argc, char **, argv);
/** @brief Hook fired after every dispatched command (tail flush).
 *
 *  axil calls the executable's weak `axil_flush` bridge at the tail of
 *  cmd_proc(); that bridge dispatches here. A module that buffers output
 *  (e.g. a history+dedup typewriter buffer) drains it from this hook so the
 *  last reply is not left pending until the next, different write. */
XY_DECL(int, on_axil_flush, socket_t, fd, int, argc, char **, argv);
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
