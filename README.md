# ndc
> HTTP(S) + WS(S) + extensible network daemon library

A cross-platform C library for building network daemons - HTTP servers, WebSocket servers, telnet-like services, or custom network applications.

From <a href="https://github.com/tty-pt/neverdark">NeverDark</a> • Powers [tty.pt](https://tty.pt)

## What is ndc?

**`libndc`** - C library for building network daemons  
**`ndc`** - Standalone server binary with HTTP/WS support

Build telnet-like servers, custom protocol handlers, HTTP APIs, WebSocket apps, or anything that needs persistent network connections with an event loop.

## Platform Support

| Platform | Status |
|----------|--------|
| Linux, macOS, BSD | ✅ Full support |
| Windows | ⚠️ HTTP/WS only (no PTY/CGI/privilege dropping) |

## Quick Start

```sh
# Run simple HTTP server
ndc -d -p 8888

# With SSL (POSIX)
sudo ndc -C . -K certs.txt -d
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
#include <ttypt/ndc.h>

int main(void) {
    ndc_config.port = 8080;
    ndc_register("GET", do_GET, CF_NOAUTH);
    return ndc_main();  // Blocks, runs event loop
}
```

### Telnet-Style Server

```c
void cmd_echo(socket_t fd, int argc, char *argv[]) {
    for (int i = 0; i < argc; i++)
        ndc_writef(fd, "%s ", argv[i]);
    ndc_writef(fd, "\n");
}

int ndc_connect(socket_t fd) {
    ndc_writef(fd, "Welcome! Type 'echo hello'\n");
    return 1;  // Accept connection
}

int main(void) {
    ndc_config.port = 2323;
    ndc_register("echo", cmd_echo, CF_NOAUTH);
    return ndc_main();
}
```

### Custom Protocol Handler

```c
void my_handler(socket_t fd, char *body) {
    // Handle raw data from client
    ndc_write(fd, "RESPONSE", 8);
}

void ndc_command(socket_t fd, int argc, char *argv[]) {
    // Called on every command
    log_command(argv[0]);
}

void ndc_update(unsigned long long dt) {
    // Periodic tick (game loops, etc)
}
```

## Library API

### Core Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `ndc_main()` | Start event loop (blocking) | Exit code |
| `ndc_register(name, cb, flags)` | Register command handler | - |
| `ndc_register_handler(path, handler)` | Register HTTP handler for exact path or pattern | - |
| `ndc_write(fd, data, len)` | Write raw bytes | Bytes written or -1 |
| `ndc_writef(fd, fmt, ...)` | Write formatted data | Bytes written or -1 |
| `ndc_dwritef(fd, fmt, va)` | Write formatted data with va_list | Bytes written or -1 |
| `ndc_close(fd)` | Close connection | - |
| `ndc_wall(msg)` | Broadcast message to all descriptors | - |

### HTTP Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `ndc_header(fd, key, val)` | Add response header (call before ndc_head) | - |
| `ndc_head(fd, code)` | Send HTTP status and headers | - |
| `ndc_body(fd, body)` | Send body and close connection | - |
| `ndc_sendfile(fd, path)` | Serve static file with auto MIME type | - |
| `ndc_status_text(code)` | Get HTTP status text for code | Status string |

### Descriptor Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `ndc_flags(fd)` | Get descriptor flags | Flags bitmask |
| `ndc_set_flags(fd, flags)` | Set descriptor flags | - |

### Request Environment Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `ndc_env_get(fd, target, key)` | Get request environment value | 0 on success |
| `ndc_env_put(fd, key, value)` | Set environment key/value | 0 on success |
| `ndc_env_clear(fd)` | Clear request environment | - |
| `ndc_env(fd)` | Get internal env handle (advanced) | Env handle |

### POSIX-Only Functions

| Function | Description | Return Value |
|----------|-------------|--------------|
| `ndc_pty(fd, args[])` | Spawn PTY-backed command | - |
| `ndc_exec(fd, args[], cb, input, len)` | Execute command with callback | - |
| `ndc_auth(fd, username)` | Mark user as authenticated, drop privileges (POSIX) | 0 on success, 1 on failure |
| `ndc_cert_add(str)` | Add cert mapping: `domain:cert.pem:key.pem` | - |
| `ndc_certs_add(fname)` | Load certificate mappings from file | - |
| `ndc_mmap(mapped, file)` | Map file into memory | File size or -1 |
| `ndc_mmap_iter(start, pos)` | Iterate mapped lines separated by `\n` | Next line or NULL |
| `ndc_sendfile(fd, path)` | Serve static file (POSIX uses sendfile syscall) | - |

### Built-in Command Handlers

| Handler | Description |
|---------|-------------|
| `do_GET` | HTTP GET request handler |
| `do_POST` | HTTP POST request handler |

### Hook Functions (Optional)

Define these weak symbol hooks to customize behavior:

| Hook | Description | Return Value |
|------|-------------|--------------|
| `ndc_connect(socket_t fd)` | Accept/reject WebSocket connections | Non-zero to accept |
| `ndc_disconnect(socket_t fd)` | Cleanup on disconnect | - |
| `ndc_accept(socket_t fd)` | Called on socket accept | Ignored |
| `ndc_command(socket_t fd, int argc, char *argv[])` | Before command execution | - |
| `ndc_flush(socket_t fd, int argc, char *argv[])` | After command execution | - |
| `ndc_vim(socket_t fd, int argc, char *argv[])` | Called when command not found | - |
| `ndc_update(unsigned long long dt)` | Periodic updates (dt in milliseconds) | - |
| `ndc_auth_check(socket_t fd)` | Custom auth hook: validate credentials, return username. Default: session file lookup in `./sessions/` | Username string or NULL |

Example:

```c
int ndc_connect(socket_t fd) {
    ndc_writef(fd, "Welcome!\n");
    return 1;  // Accept connection
}

void ndc_disconnect(socket_t fd) {
    // Cleanup resources
}

void ndc_command(socket_t fd, int argc, char *argv[]) {
    // Log or validate commands
}

void ndc_flush(socket_t fd, int argc, char *argv[]) {
    // Post-command processing
}

void ndc_vim(socket_t fd, int argc, char *argv[]) {
    ndc_writef(fd, "Unknown command: %s\n", argv[0]);
}

void ndc_update(unsigned long long dt) {
    // Game loop, periodic tasks, etc.
}

char *ndc_auth_check(socket_t fd) {
    // Check cookies, tokens, etc.
    // Return username or NULL
    return authenticated_user;
}
```

### Configuration

```c
struct ndc_config {
    char *chroot;                    // chroot directory (POSIX)
    unsigned flags;                  // Server flags (see below)
    unsigned port;                   // HTTP listen port
    unsigned ssl_port;               // HTTPS listen port (POSIX)
    ndc_handler_t *default_handler;  // Fallback HTTP handler
};

// Example usage
ndc_config.port = 8080;              // HTTP on port 8080
ndc_config.ssl_port = 8443;          // HTTPS on port 8443 (POSIX)
ndc_config.flags = NDC_SSL;          // Enable TLS
ndc_config.chroot = "/var/www";      // chroot directory (POSIX)
ndc_config.default_handler = my_404; // Custom 404 handler
```

#### Server Flags

| Flag | Description |
|------|-------------|
| `NDC_WAKE` | Wake on activity |
| `NDC_SSL` | Enable TLS/SSL |
| `NDC_ROOT` | Root multiplex mode |
| `NDC_SSL_ONLY` | Redirect HTTP to HTTPS when SSL enabled |
| `NDC_DETACH` | Detach into background (daemon mode) |

#### Command Flags

Use with `ndc_register()`:

| Flag | Description |
|------|-------------|
| `CF_NOAUTH` | Allow command without authentication |
| `CF_NOTRIM` | Do not trim trailing CR from input |

#### Descriptor Flags

Access with `ndc_flags()` and `ndc_set_flags()`:

| Flag | Description |
|------|-------------|
| `DF_CONNECTED` | Connection established and accepted |
| `DF_WEBSOCKET` | WebSocket mode enabled |
| `DF_TO_CLOSE` | Marked to close after remaining output |
| `DF_ACCEPTED` | Accepted socket (pre-WebSocket) |
| `DF_AUTHENTICATED` | User authenticated |

## POSIX vs Windows

| Feature | POSIX | Windows |
|---------|-------|---------|
| HTTP/WebSocket | ✅ | ✅ |
| Custom commands | ✅ | ✅ |
| PTY/Terminal | ✅ | ❌ |
| CGI execution | ✅ | ❌ |
| Authentication (privilege dropping) | ✅ | ❌ |
| SSL certs | ✅ | ❌ |

Windows build provides core networking only.

## CGI & Static Files (POSIX)

Create `index.sh` for dynamic pages:

```sh
#!/bin/sh
# CGI scripts output status line without "HTTP/1.1" prefix
printf "200 OK\r\n"
printf "Content-Type: text/plain\r\n"
printf "\r\n"
printf "Hello world\n"
printf "REQUEST_METHOD=%s\n" "$REQUEST_METHOD"
printf "QUERY_STRING=%s\n" "$QUERY_STRING"
```

Control access with `serve.allow` and `serve.autoindex` files.

## Modules

For browser terminal / WebSocket PTY multiplexer support, see [libndc-mux](mods/mux/).

---

- Man pages: `man ndc` and `man ndc.3`
- Full API: `include/ttypt/ndc.h`
- Examples: `src/test.c`, `src/test-auth.c`

## Plugin System

Load dynamic modules with dependency resolution via `libndx`:

```c
// In your plugin module
const char *ndx_deps[] = { "dependency.so", NULL };

// In main application
ndx_load("plugin.so");  // Automatically loads dependencies
```

The binary automatically loads `core.so` at startup. Plugins can hook into lifecycle events (`ndc_update`, `ndc_connect`, etc.) to extend functionality.

---

**Installation**: See [install docs](https://github.com/tty-pt/ci/blob/main/docs/install.md)  
**Entry points**: `src/ndc.c` (native)
