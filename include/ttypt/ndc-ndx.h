#ifndef NDC_NDX_H
#define NDC_NDX_H

#include <ttypt/ndx.h>

#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET socket_t;
#else
#include <sys/select.h>
typedef int socket_t;
#endif

NDX_HOOK_DECL(int, on_ndc_exit, int, i);
NDX_HOOK_DECL(int, on_ndc_update, unsigned long long, dt);
NDX_HOOK_DECL(int, on_ndc_vim, socket_t, fd, int, argc, char **, argv);
NDX_HOOK_DECL(int, on_ndc_command, socket_t, fd, int, argc, char **, argv);
NDX_HOOK_DECL(int, on_ndc_connect, socket_t, fd);
NDX_HOOK_DECL(int, on_ndc_disconnect, socket_t, fd);
NDX_HOOK_DECL(int, on_ndc_tick, socket_t, fd);
NDX_HOOK_DECL(int, on_ndc_parse,
    socket_t, fd,
    unsigned char *, input,
    int, nread);

#endif
