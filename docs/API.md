# axil — Complete API Reference

This document provides the exhaustive function reference, typedefs, server configuration flags, and hooks for `axil`. For a high-level overview, quickstart, and ecosystem context, see the [main README](../README.md).

## Library API

### Core Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_main()` | Start event loop (blocking) | Exit code |
| `axil_register(name, cb, flags)` | Register command handler | - |
| `axil_register_handler(path, handler)` | Register HTTP handler for exact path or pattern | - |
| `axil_register_fallback_handler(handler)` | Register fallback HTTP handler (runs after all others declined) | 0 on success, -1 if full |
| `axil_write(fd, data, len)` | Write raw bytes | Bytes written or -1 |
| `axil_writef(fd, fmt, ...)` | Write formatted data | Bytes written or -1 |
| `axil_dwritef(fd, fmt, va)` | Write formatted data with va_list | Bytes written or -1 |
| `axil_close(fd)` | Close connection | - |
| `axil_wall(msg)` | Broadcast message to all descriptors | - |

### HTTP Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_header_set(fd, key, val)` | Add response header (call before axil_respond) | - |
| `axil_header_get(fd, key, buf, len)` | Get incoming request header | 0 on success, -1 if absent |
| `axil_respond(fd, code, body)` | Send HTTP status, accumulated headers, optional body, and close when a body is provided | - |
| `axil_respond_plain(fd, status, msg)` | Send plain-text response with `Content-Type: text/plain` | 0 on 2xx |
| `axil_redirect(fd, location)` | Send a 303 redirect | 0 |
| `axil_sendfile(fd, path)` | Serve static file with auto MIME type | - |
| `axil_status_text(code)` | Get HTTP status text for code | Status string |

`axil_respond()`, `axil_sendfile()`, built-in static files, and autoindex responses include cross-origin isolation headers by default. Static `.wasm` files are served as `application/wasm`.

### WebSocket API

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_ws_handler(path, handler)` | Register WebSocket tunnel handler for a path | - |
| `axil_ws_upgrade(fd)` | Upgrade connection to WebSocket (handshake + connect hook) | 0 on success |
| `axil_fd_watch(fd)` | Required after `axil_ws_upgrade()`; routes frames to `axil_fd_tick()` | - |
| `axil_ws_write(fd, data, len)` | Write data to WebSocket | Frame size or -1 |
| `axil_ws_read(fd, buf, len)` | Read data from WebSocket | Bytes read, 0 on close, -1 on error |
| `axil_ws_close(fd)` | Close WebSocket connection | 0 on success |
| `axil_ws_printf(fd, fmt, ...)` | Formatted write to WebSocket | Written or -1 |

### Server Configuration

```c
struct axil_config {
    char *chroot;                     // chroot directory (POSIX)
    unsigned flags;                   // Server flags
    unsigned port;                    // HTTP listen port
    unsigned ssl_port;                // HTTPS listen port (POSIX)
    axil_handler_t *default_handler;  // Fallback HTTP handler
    size_t max_body_size;             // Max POST body size (0 = 10MB default)
};
```

#### Server Flags
- `AXIL_WAKE` — Wake on activity
- `AXIL_SSL` — Enable TLS/SSL
- `AXIL_ROOT` — Root multiplex mode
- `AXIL_SSL_ONLY` — Redirect HTTP to HTTPS
- `AXIL_DETACH` — Detach into background daemon mode
- `AXIL_AUTOAUTH` — Auto-authenticate all WebSocket connections (dev/testing)
