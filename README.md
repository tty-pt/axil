# axil
> HTTP(S) + WS(S) + extensible network daemon library

A cross-platform C library for building network daemons - HTTP servers, WebSocket servers, telnet-like services, or custom network applications.

From <a href="https://github.com/tty-pt/axileverdark">NeverDark</a> • Powers [tty.pt](https://tty.pt)

## What is axil?

**`libaxil`** - C library for building network daemons  
**`axil`** - Standalone server binary with HTTP/WS support

Build telnet-like servers, custom protocol handlers, HTTP APIs, WebSocket apps, or anything that needs persistent network connections with an event loop.

## Platform Support

| Platform | Status |
|----------|--------|
| Linux, macOS, BSD | ✅ Full support |
| Windows | ⚠️ HTTP/WS only (no PTY/privilege dropping) |

## Quick Start

```sh
# Run simple HTTP server
axil -d -p 8888

# With SSL (POSIX)
sudo axil -C . -K certs.txt -d
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-p PORT` | Specify HTTP server port |
| `-s PORT` | Specify HTTPS server port (POSIX) |
| `-C PATH` | Change directory to PATH before starting |
| `-K PATH` | Load SSL certificate mappings from file (POSIX) |
| `-k CERT` | Add single SSL certificate mapping (POSIX) |
| `-d` | Don't detach (run in foreground) |
| `-r` | Root multiplex mode |
| `-?` | Display help message |

### certs.txt Format (POSIX)
```txt
example.com:cert.pem:key.pem
```

## Building Custom Daemons

### Minimal Example

```c
#include <ttypt/axil.h>

int main(void) {
    axil_config.port = 8080;
    axil_register("GET", do_GET, CF_NOAUTH);
    return axil_main();  // Blocks, runs event loop
}
```

### Telnet-Style Server

```c
void cmd_echo(socket_t fd, int argc, char *argv[]) {
    for (int i = 0; i < argc; i++)
        axil_writef(fd, "%s ", argv[i]);
    axil_writef(fd, "\n");
}

int axil_connect(socket_t fd) {
    axil_writef(fd, "Welcome! Type 'echo hello'\n");
    return 1;  // Accept connection
}

int main(void) {
    axil_config.port = 2323;
    axil_register("echo", cmd_echo, CF_NOAUTH);
    return axil_main();
}
```

### Custom Protocol Handler

```c
void my_handler(socket_t fd, char *body) {
    // Handle raw data from client
    axil_write(fd, "RESPONSE", 8);
}

void axil_command(socket_t fd, int argc, char *argv[]) {
    // Called on every command
    log_command(argv[0]);
}

void axil_update(unsigned long long dt) {
    // Periodic tick (game loops, etc)
}
```

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

`axil_respond()`, `axil_sendfile()`, built-in static files, and autoindex responses
include cross-origin isolation headers by default:
`Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Embedder-Policy: require-corp`, and
`Cross-Origin-Resource-Policy: same-origin`. Static `.wasm` files are served as
`application/wasm`.

### Descriptor Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_flags(fd)` | Get descriptor flags | Flags bitmask |
| `axil_set_flags(fd, flags)` | Set descriptor flags | - |
| `axil_clear_active(fd)` | Clear fd from the active select set | - |

### Request Environment Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_env_get(fd, target, key)` | Get request environment value | 0 on success |
| `axil_env_put(fd, key, value)` | Set environment key/value | 0 on success |
| `axil_env_clear(fd)` | Clear request environment | - |
| `axil_env(fd)` | Get internal env handle (advanced) | Env handle |

### POSIX-Only Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_exec(fd, args[], cb, input, len)` | Execute command with callback | - |
| `axil_exec_loop(fd)` | Continue processing a command started with `axil_exec()` | - |
| `axil_auth(fd, username)` | Mark user as authenticated, drop privileges (POSIX) | 0 on success, 1 on failure |
| `axil_get_pw(fd, out)` | Copy authenticated user's passwd entry | 0 on success, -1 if not auth'd |
| `axil_cert_add(str)` | Add cert mapping: `domain:cert.pem:key.pem` | - |
| `axil_certs_add(fname)` | Load certificate mappings from file | - |
| `axil_mmap(mapped, file)` | Map file into memory | File size or -1 |
| `axil_mmap_iter(start, pos)` | Iterate mapped lines separated by `\n` | Next line or NULL |
| `axil_sendfile(fd, path)` | Serve static file (POSIX uses sendfile syscall) | - |
| `axil_fd_watch(fd)` | Add fd to select set as externally-managed (`DF_EXTERN`) | - |
| `axil_fd_unwatch(fd)` | Remove fd from active/read watch sets | - |
| `axil_fork_child_reset()` | Reset cleanup after `fork()` in child process | - |
| `axil_send_telnet_cmd(fd, cmd, len)` | Send raw TELNET command sequence | - |

### Built-in Command Handlers

| Handler | Description |
|---------|-------------|
| `do_GET` | HTTP GET request handler |
| `do_POST` | HTTP POST request handler |

### Hook Functions (Optional)

Define these weak symbol hooks to customize behavior:

| Hook | Description | Return Value |
|------|-------------|--------------|
| `axil_connect(socket_t fd)` | Accept/reject WebSocket connections | Non-zero to accept |
| `axil_disconnect(socket_t fd)` | Cleanup on disconnect | - |
| `axil_accept(socket_t fd)` | Called on socket accept | Ignored |
| `axil_command(socket_t fd, int argc, char *argv[])` | Before command execution | - |
| `axil_flush(socket_t fd, int argc, char *argv[])` | After command execution | - |
| `axil_vim(socket_t fd, int argc, char *argv[])` | Called when command not found | - |
| `axil_update(unsigned long long dt)` | Periodic updates (dt in microseconds) | - |
| `axil_auth_check(socket_t fd)` | Custom auth hook: validate credentials, return username. Default: session file lookup in `./sessions/` | Username string or NULL |
| `axil_fd_tick(socket_t fd)` | Tick for externally-watched fds (`DF_EXTERN`) | - |
| `axil_parse(socket_t fd, unsigned char *input, int nread)` | Called on raw input before command parsing | Return <0 to skip |

Example:

```c
int axil_connect(socket_t fd) {
    axil_writef(fd, "Welcome!\n");
    return 1;  // Accept connection
}

void axil_disconnect(socket_t fd) {
    // Cleanup resources
}

void axil_command(socket_t fd, int argc, char *argv[]) {
    // Log or validate commands
}

void axil_flush(socket_t fd, int argc, char *argv[]) {
    // Post-command processing
}

void axil_vim(socket_t fd, int argc, char *argv[]) {
    axil_writef(fd, "Unknown command: %s\n", argv[0]);
}

void axil_update(unsigned long long dt) {
    // Game loop, periodic tasks, etc.
}

char *axil_auth_check(socket_t fd) {
    // Check cookies, tokens, etc.
    // Return username or NULL
    return authenticated_user;
}
```

### WebSocket API

WebSocket tunnel handlers connect a client fd to an upstream server:

```c
socket_t my_upstream(socket_t client_fd) {
    // Connect to upstream WebSocket server
    socket_t up = connect_to_upstream("ws://example.com/ws");
    return up;  // axil will bridge client <-> upstream
}

void setup_ws(void) {
    axil_ws_handler("/ws", my_upstream);       // Register WS tunnel path
}

// Manual upgrade for non-tunnel use:
int fd = ...;
axil_ws_upgrade(fd);
axil_ws_write(fd, "hello", 5);
```

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_ws_handler(path, handler)` | Register WebSocket tunnel handler for a path | - |
| `axil_ws_upgrade(fd)` | Upgrade connection to WebSocket (handshake + connect hook) | 0 on success |
| `axil_ws_write(fd, data, len)` | Write data to WebSocket | Bytes written or -1 |
| `axil_ws_read(fd, buf, len)` | Read data from WebSocket | Bytes read, 0 on close, -1 on error |
| `axil_ws_close(fd)` | Close WebSocket connection | 0 on success |
| `axil_ws_printf(fd, fmt, ...)` | Formatted write to WebSocket | Written or -1 |

### Form Parsing

Parse `application/x-www-form-urlencoded` request bodies:

```c
char *body = "name=alice&age=30";
axil_query_parse(body);
char val[64];
axil_query_param("name", val, sizeof(val));  // val = "alice"
```

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_query_parse(body)` | Parse URL-encoded form body into internal store | 0 on success |
| `axil_query_param(name, buf, len)` | Look up parsed form value | Bytes written, or -1 if not found |

### Encoding Utilities

```c
char out[256];
axil_url_encode("hello world", out, sizeof(out));   // "hello%20world"
axil_json_escape("say \"hi\"", out, sizeof(out));    // "say \"hi\""
axil_slugify("Hello World", 11, out, sizeof(out));   // "hello-world"
```

| Function | Description | Return Value |
|----------|-------------|--------------|
| `axil_url_encode(in, out, outlen)` | Percent-encode a string | Bytes written or -1 |
| `axil_url_decode(src, src_len, out, out_len)` | Percent-decode a string | Bytes written |
| `axil_json_escape(in, out, outlen)` | JSON-escape a string | 0 on success |
| `axil_slugify(title, title_len, result, result_len)` | Convert title to filesystem-safe slug | 0 on success |

### XY Hooks

When built with libxylem support, modules may implement these hooks (declared in
`<ttypt/axil-xy.h>`):

| Hook | Signature | Description |
|------|-----------|-------------|
| `on_axil_exit` | `int on_axil_exit(int i)` | Called on exit / segfault. |
| `on_axil_update` | `int on_axil_update(unsigned long long dt)` | Periodic update tick. |
| `on_axil_vim` | `int on_axil_vim(socket_t fd, int argc, char **argv)` | Unknown command. |
| `on_axil_command` | `int on_axil_command(socket_t fd, int argc, char **argv)` | Before command execution. |
| `on_axil_connect` | `int on_axil_connect(socket_t fd)` | On WebSocket connect. |
| `on_axil_disconnect` | `int on_axil_disconnect(socket_t fd)` | On disconnect. |
| `on_axil_tick` | `int on_axil_tick(socket_t fd)` | Tick for externally-watched fds. |
| `on_axil_parse` | `int on_axil_parse(socket_t fd, unsigned char *input, int nread)` | Raw input parse hook. |

### Configuration

```c
struct axil_config {
    char *chroot;                    // chroot directory (POSIX)
    unsigned flags;                  // Server flags (see below)
    unsigned port;                   // HTTP listen port
    unsigned ssl_port;               // HTTPS listen port (POSIX)
    axil_handler_t *default_handler;  // Fallback HTTP handler
    size_t max_body_size;            // Max POST body size (0 = 10MB default)
};

// Example usage
axil_config.port = 8080;              // HTTP on port 8080
axil_config.ssl_port = 8443;          // HTTPS on port 8443 (POSIX)
axil_config.flags = AXIL_SSL;          // Enable TLS
axil_config.chroot = "/var/www";      // chroot directory (POSIX)
axil_config.default_handler = my_404; // Custom 404 handler
```

#### Server Flags

| Flag | Description |
|------|-------------|
| `AXIL_WAKE` | Wake on activity |
| `AXIL_SSL` | Enable TLS/SSL |
| `AXIL_ROOT` | Root multiplex mode |
| `AXIL_SSL_ONLY` | Redirect HTTP to HTTPS when SSL enabled |
| `AXIL_DETACH` | Detach into background (daemon mode) |
| `AXIL_AUTOAUTH` | Auto-authenticate all WebSocket connections (dev/testing) |

#### Request Flags

| Flag | Description |
|------|-------------|
| `AXIL_POST` | Request is a POST |

#### Command Flags

Use with `axil_register()`:

| Flag | Description |
|------|-------------|
| `CF_NOAUTH` | Allow command without authentication |
| `CF_NOTRIM` | Do not trim trailing CR from input |

#### Descriptor Flags

Access with `axil_flags()` and `axil_set_flags()`:

| Flag | Description |
|------|-------------|
| `DF_CONNECTED` | Connection established and accepted |
| `DF_WEBSOCKET` | WebSocket mode enabled |
| `DF_TO_CLOSE` | Marked to close after remaining output |
| `DF_ACCEPTED` | Accepted socket (pre-WebSocket) |
| `DF_AUTHENTICATED` | User authenticated |
| `DF_TUNNEL` | Part of a WebSocket tunnel pair |
| `DF_WS_WAITING` | Waiting for upstream WebSocket upgrade response |
| `DF_WS_PROXY_PENDING` | WebSocket proxy pending |
| `DF_EXTERN` | Externally-watched fd (dispatch via `axil_fd_tick`) |

## Typedefs

| Type | Signature | Description |
|------|-----------|-------------|
| `axil_handler_t` | `int (*)(socket_t cfd, char *body)` | HTTP handler callback. |
| `axil_ws_upstream_t` | `socket_t (*)(socket_t client_fd)` | WebSocket tunnel upstream callback. Returns upstream fd. |
| `axil_cb_t` | `void (*)(socket_t fd, int argc, char *argv[])` | Generic command callback. |
| `cmd_cb_t` | `void (*)(socket_t cfd, char *buf, size_t len, int ofd)` | Execution output callback (ofd=1 stdout, 0 stderr). |

## Macros

| Macro | Description |
|-------|-------------|
| `AXIL_TWRITE(fd, msg)` | Shorthand for `axil_write(fd, msg, strlen(msg))`. |
| `TELNET_CMD(fd, ...)` | Build and send a TELNET command from literal byte sequence (POSIX only). |
| `ENV_KEY_LEN` (128) | Max key size for request environment. |
| `ENV_LEN` (BUFSIZ*2) | Maximum environment string size. |
| `ENV_VALUE_LEN` (ENV_LEN - ENV_KEY_LEN - 2) | Max value size for request environment. |

## Global Symbols

| Symbol | Type | Description |
|--------|------|-------------|
| `axil_tick` | `long long` | Monotonic tick counter (microseconds). |
| `axil_execbuf` | `char[BUFSIZ*64]` | Shared execution buffer (legacy). |

## POSIX vs Windows

| Feature | POSIX | Windows |
|---------|-------|---------|
| HTTP/WebSocket | ✅ | ✅ |
| Custom commands | ✅ | ✅ |
| PTY/Terminal | External module | ❌ |
| CGI execution | External module | External module |
| Authentication (privilege dropping) | ✅ | ❌ |
| SSL certs | ✅ | ❌ |
| Process execution (`axil_exec`) | ✅ | ❌ |
| fd watching (`axil_fd_watch`) | ✅ | ❌ |
| `axil_get_pw` | ✅ | ❌ |
| Telnet commands (`TELNET_CMD`) | ✅ | ❌ |

Windows build provides core networking only.

## Static Files (POSIX)

Control access with `serve.allow` and `serve.autoindex` files.

CGI is provided by the separate `axil-cgi` module.

## Modules

`axil` loads dynamic modules with `-m`:

```sh
axil -d -p 8888 -m /path/to/libaxil-tty.so
axil -d -p 8888 -m /path/to/libaxil-cgi.so
```

Multiple modules can be loaded with a colon-separated list.

Sibling modules:

- `../axil-tty`: browser terminal / WebSocket PTY support (provides `axil_pty()`).
- `../axil-cgi`: CGI fallback support for executable `./index.sh`.

Modules can register HTTP handlers, fallback handlers, commands, and `libxylem`
hooks (see [XY Hooks](#xy-hooks) above).

- Man pages: `man axil` and `man axil.3`
- Full API: `include/ttypt/axil.h`
- Examples: `src/test.c`, `src/test-auth.c`

**Installation**: See [install docs](https://github.com/tty-pt/ci/blob/main/docs/install.md)  
**Entry points**: `src/axil.c` (native)
