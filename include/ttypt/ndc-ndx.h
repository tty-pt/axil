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

/* Forward declarations for init functions */
static void on_ndc_exit_init_id(void);
static void on_ndc_update_init_id(void);
static void on_ndc_vim_init_id(void);
static void on_ndc_command_init_id(void);
static void on_ndc_connect_init_id(void);
static void on_ndc_disconnect_init_id(void);

NDX_DECL(int, on_ndc_exit, int, i);
NDX_DECL(int, on_ndc_update, unsigned long long, dt);
NDX_DECL(int, on_ndc_vim, socket_t, fd, int, argc, char **, argv);
NDX_DECL(int, on_ndc_command, socket_t, fd, int, argc, char **, argv);
NDX_DECL(int, on_ndc_connect, socket_t, fd);
NDX_DECL(int, on_ndc_disconnect, socket_t, fd);

#endif
