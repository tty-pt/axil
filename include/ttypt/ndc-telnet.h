#ifndef NDC_TELNET_H
#define NDC_TELNET_H

/**
 * @file ndc-telnet.h
 * @brief NDX hook declarations for the telnet/PTY lifecycle.
 *
 * Include this wherever the telnet hooks need to be declared/called —
 * including libndc.c itself.  NDX_DECL generates call_*() wrappers without
 * registering a stub adapter, so the mux module's real implementations are
 * not shadowed.
 */

#include <ttypt/ndc.h>
#include <ttypt/ndx.h>

/** Called on WebSocket connect: send TELNET negotiations and open PTY. */
NDX_DECL(int, telnet_connected, socket_t, fd);

/** Called to parse TELNET escape sequences from input; returns byte offset. */
NDX_DECL(int, telnet_parse, socket_t, fd, unsigned char *, input, int, nread);

/** Called each event-loop tick when an externally-watched fd is readable. */
NDX_DECL(int, on_fd_tick, socket_t, fd);

/** Called on descriptor close: tear down any resources for fd. */
NDX_DECL(int, telnet_cleanup, socket_t, fd);

#endif
