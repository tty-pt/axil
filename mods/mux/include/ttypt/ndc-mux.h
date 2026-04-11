#ifndef NDC_MUX_H
#define NDC_MUX_H

#include <ttypt/ndc.h>
#include <ttypt/ndx.h>

/** Open a PTY and exec argv on fd. argv[0]==NULL uses the user's login shell. */
NDX_DECL(int, ndc_mux_exec, socket_t, fd, char **, argv);

/** Open a PTY shell (login shell) on fd. */
NDX_DECL(int, ndc_mux_shell, socket_t, fd);

#endif
