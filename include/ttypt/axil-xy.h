#ifndef AXIL_XY_H
#define AXIL_XY_H

#include <ttypt/xy.h>

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET socket_t;
#else
#include <sys/select.h>
typedef int socket_t;
#endif

XY_DECL(int, on_axil_exit, int, i);
XY_DECL(int, on_axil_update, unsigned long long, dt);
XY_DECL(int, on_axil_vim, socket_t, fd, int, argc, char **, argv);
XY_DECL(int, on_axil_command, socket_t, fd, int, argc, char **, argv);
XY_DECL(int, on_axil_connect, socket_t, fd);
XY_DECL(int, on_axil_disconnect, socket_t, fd);
XY_DECL(int, on_axil_tick, socket_t, fd);
XY_DECL(int, on_axil_parse,
    socket_t, fd,
    unsigned char *, input,
    int, nread);

#endif
