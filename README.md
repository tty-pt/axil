<p align="center">
  <img src="assets/logo.png" alt="axil logo" width="220" />
</p>

# axil

[![C99](https://img.shields.io/badge/C-C99-555?logo=c)](#)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](#)
[![HTTP(S)+WS daemon](https://img.shields.io/badge/HTTP%28S%29%2BWS-daemon-4B8BBE)](#)
[![libxylem compatible](https://img.shields.io/badge/modules-libxylem-16A34A)](#)

> High-throughput, non-blocking HTTP(S), WebSocket, and PTY daemon in plain C with dynamic module loading and chroot jail isolation.

Axil is an ultra-fast, single-threaded POSIX network daemon engineered for minimal memory overhead and zero-copy performance. Rather than requiring complex async/await runtimes or heavy multi-megabyte frameworks, Axil handles thousands of concurrent HTTP and WebSocket connections through a clean event loop and modular `.so` plugin system.

---

## Why Axil? (The Unix Philosophy Web Server)

Building high-throughput network services in C often forces an unpleasant choice: microscopic toy libraries that crash under real concurrency, or massive multi-threaded frameworks with complex async/await state machines and hidden heap allocations.

`axil` takes a different path:
- **Zero Hidden Allocations**: A single-threaded, non-blocking POSIX event loop handling thousands of concurrent HTTP and WebSocket connections with minimal CPU cache thrashing and predictable memory use.
- **True Shared-Module Modularity (`-m`)**: Load REST APIs, authentication layers, terminal bridges, or game engines dynamically at startup without recompiling the daemon.
- **Production Hardening Out of the Box**: Chroot jail isolation (`-c`), privilege dropping (`-u www`), automatic `Content-Length` framing to prevent HTTP request smuggling, and instant teardown (S5.4) of abusive or malformed connections.

---

## Contents

- [Why Axil? (The Unix Philosophy Web Server)](#why-axil-the-unix-philosophy-web-server)
- [Modular Architecture (-m)](#modular-architecture--m)
- [CLI Options Reference](#cli-options-reference)
- [Quickstart: HTTP & WebSocket Server](#quickstart-http--websocket-server)
- [Core API Reference](#core-api-reference)
- [Production Hardening & Security (S5.4)](#production-hardening--security-s54)
- [Installation & Build](#installation--build)
- [License](#license)

---

## Modular Architecture (`-m`)

Axil is extensible through dynamic shared modules loaded at runtime via [libxylem](https://github.com/tty-pt/libxylem). When passed the `-m` flag, Axil dynamically resolves and mounts protocol handlers, REST endpoints, and interactive bridges:

```bash
# Load authentication, database REST connector, and browser terminal modules
axil -d -p 8080 -m libaxil-auth -m libaxil-hyle -m libaxil-tty
```

Standard ecosystem modules:
- **[axil-auth](https://github.com/tty-pt/axil-auth)**: User registration, bcrypt verification, session cookies, and terminal access gating.
- **[axil-hyle](https://github.com/tty-pt/axil-hyle)**: Schema-driven RESTful CRUD endpoints over Hyle datasets.
- **[axil-auren](https://github.com/tty-pt/auren)**: Local LLM inference, OpenAI-compatible completions, dense vector embeddings, and System One decision judging.
- **[axil-tty](https://github.com/tty-pt/axil-tty)**: WebSocket-to-PTY streaming bridge with Telnet NAWS negotiation.
- **[axil-nd](https://github.com/tty-pt/axil-nd)**: NeverDark MUCK engine running in-process over WebSocket/telnet.

---

## CLI Options Reference

| Option | Argument | Description |
| :--- | :--- | :--- |
| `-m` | `PATH` | Load a `.so` module (colon-separated list or repeatable) |
| `-p` | `PORT` | Listen port for HTTP/WS connections (default: `8080`) |
| `-d` | *none* | Run in foreground (debug mode; do not daemonize) |
| `-A` | *none* | Anonymous mode: auto-authenticate all requests (bypasses auth checks) |
| `-c` | `PATH` | Chroot jail directory before entering event loop |
| `-r` | `PATH` | Document root directory for static files |
| `-u` | `USER` | Drop privileges to specific user after binding sockets |
| `-g` | `GROUP` | Drop privileges to specific group after binding sockets |
| `-C` | `PATH` | Change working directory before server initialization |

---

## Quickstart: HTTP & WebSocket Server

Serve non-blocking HTTP endpoints and WebSocket streams in under 25 lines:

```c
#include <stdio.h>
#include <ttypt/axil.h>

static int handle_hello(socket_t fd, char *body) {
    (void)body;
    axil_respond_plain(fd, 200, "Hello from axil!\n");
    return 0;
}

static int handle_ws_echo(socket_t fd, char *body) {
    (void)body;
    if (axil_ws_upgrade(fd) == 0) {
        axil_ws_write(fd, "Connected to echo server\n", 25);
    }
    return 0;
}

int main(void) {
    axil_config.port = 8080;
    axil_register_handler("/api/hello", handle_hello);
    axil_register_handler("/ws/echo", handle_ws_echo);

    printf("Serving on http://localhost:8080/api/hello\n");
    return axil_main(); // Enters non-blocking event loop
}
```

Run standalone server from CLI:
```sh
axil -d -p 8080
```

---

## Core API Reference

| Function | Signature | Description |
| :--- | :--- | :--- |
| `axil_main` | `int axil_main(void)` | Enter non-blocking network event loop |
| `axil_register_handler` | `void axil_register_handler(path, cb)` | Map HTTP path or pattern to a handler callback |
| `axil_respond_plain` | `int axil_respond_plain(fd, code, msg)` | Send HTTP response with automatic `Content-Length` framing |
| `axil_respond_json` | `int axil_respond_json(fd, code, json)` | Send `application/json` payload with proper framing |
| `axil_ws_upgrade` | `int axil_ws_upgrade(fd)` | Perform RFC 6455 WebSocket handshake upgrade |
| `axil_ws_write` | `ssize_t axil_ws_write(fd, data, len)` | Write framed WebSocket text or binary payload |
| `axil_sendfile` | `void axil_sendfile(fd, path)` | Zero-copy static file transfer with MIME auto-detection |

👉 *For SSL certificates, PTY terminal tunneling, request environment maps, and the complete API reference, see [docs/API.md](docs/API.md).*

---

## Production Hardening & Security (S5.4)

* **Framed HTTP Responses**: Emits explicit `Content-Length` and `Connection: close` headers for strict response framing and connection lifecycle predictability.
* **Immediate Security Teardowns (S5.4)**: Unauthenticated or malformed requests on protected endpoints immediately tear down connection sockets, preventing state-exhaustion attacks.
* **Per-Connection Generation Tracking**: Detects stale socket file descriptors across asynchronous callbacks to eliminate socket reuse race conditions.
* **Chroot & Privilege Dropping**: Can bind privileged low ports (`80`, `443`), chroot into a minimal filesystem jail (`-c`), and drop to an unprivileged system user (`-u www`).
* **Isomorphic WASM Headers**: Pre-configures `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` so WASM `SharedArrayBuffer` runs securely in all modern browsers.

---

## Installation & Build

### Prebuilt Packages
Prebuilt packages are distributed on tty.pt for Linux (APT / Alpine / Arch / Fedora-RHEL), macOS (Homebrew), Windows (winget / MSYS2), and OpenBSD. Follow the [installation instructions](https://github.com/tty-pt/ci/blob/main/docs/install.md) and use **axil** as the package name.

### Build from Source
```sh
make                  # builds lib/libaxil.so + bin/axil
./test.sh             # run HTTP/WS integration test suite
sudo make install     # install headers and library to system
```

## License

BSD 2-Clause License. Copyright (c) 2023, tty-pt. See `LICENSE`.
