#ifndef TTYPT_AXIL_WS_H
#define TTYPT_AXIL_WS_H

/*
 * axil-ws.h — Canonical client WebSocket streaming transport interface.
 * Implements two-level WASM import namespace "axil" and "tty".
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standard multiplexed channel IDs */
#define AXIL_WS_CH_TEXT   0  /* Plain text / ANSI TTY stream */
#define AXIL_WS_CH_BCP    1  /* Binary Client Protocol (#b) */
#define AXIL_WS_CH_RPC    2  /* Remote procedure / Bud UI patch stream */

/* Connection status codes */
#define AXIL_WS_DISCONNECTED 0
#define AXIL_WS_CONNECTING   1
#define AXIL_WS_CONNECTED    2
#define AXIL_WS_CLOSING      3

#ifdef __wasm__
__attribute__((import_module("axil"), import_name("ws_connect")))
void ws_connect(const char *url, size_t len);

__attribute__((import_module("axil"), import_name("ws_send")))
void ws_send(const void *buf, size_t len);

__attribute__((import_module("axil"), import_name("ws_send_channel")))
void ws_send_channel(uint8_t channel, const void *buf, size_t len);

__attribute__((import_module("axil"), import_name("ws_status")))
int ws_status(void);

__attribute__((import_module("axil"), import_name("ws_close")))
void ws_close(void);

__attribute__((import_module("tty"), import_name("term_write")))
void term_write(const char *buf, size_t len);
#else
static inline void ws_connect(const char *url, size_t len) { (void)url; (void)len; }
static inline void ws_send(const void *buf, size_t len) { (void)buf; (void)len; }
static inline void ws_send_channel(uint8_t channel, const void *buf, size_t len) { (void)channel; (void)buf; (void)len; }
static inline int  ws_status(void) { return AXIL_WS_CONNECTED; }
static inline void ws_close(void) {}
static inline void term_write(const char *buf, size_t len) { (void)buf; (void)len; }
#endif

#ifdef __cplusplus
}
#endif

#endif /* TTYPT_AXIL_WS_H */
