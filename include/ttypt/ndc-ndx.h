#ifndef NDC_NDX_H
#define NDC_NDX_H

#include <ttypt/ndx.h>

/* Forward declarations for init functions */
static void on_ndc_init_init_id(void);
static void on_ndc_exit_init_id(void);
static void on_ndc_update_init_id(void);
static void on_ndc_vim_init_id(void);
static void on_ndc_command_init_id(void);
static void on_ndc_connect_init_id(void);
static void on_ndc_disconnect_init_id(void);

NDX_DECL(int, on_ndc_init, int, i);
NDX_DECL(int, on_ndc_exit, int, i);
NDX_DECL(int, on_ndc_update, unsigned long long, dt);
NDX_DECL(int, on_ndc_vim, int, fd, int, argc, char **, argv);
NDX_DECL(int, on_ndc_command, int, fd, int, argc, char **, argv);
NDX_DECL(int, on_ndc_connect, int, fd);
NDX_DECL(int, on_ndc_disconnect, int, fd);

#endif
