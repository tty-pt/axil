<p align="center">
  <img src="assets/logo.png" alt="axil logo" width="220" />
</p>

# axil

[![C99](https://img.shields.io/badge/C-C99-555?logo=c)](#)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](#)
[![HTTP(S)+WS daemon](https://img.shields.io/badge/HTTP%28S%29%2BWS-daemon-4B8BBE)](#)
[![libxylem compatible](https://img.shields.io/badge/modules-libxylem-16A34A)](#)

> High-throughput, non-blocking HTTP(S), WebSocket, and PTY daemon in plain C with dynamic module loading and chroot jail isolation. Canonical header is `<ttypt/axil.h>`.

---

## 1. Quickstart

### Launch Server from CLI
Start the daemon in foreground on port 8080 loading dynamic modules:

```bash
axil -d -p 8080 -m libaxil-auth -m libaxil-hyle
```

### Embed in Pure C
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

Compile and link:
```sh
cc my_server.c $(pkg-config --cflags --libs axil) -o my_server
```

---

## 2. CLI Options Reference

| Option | Argument | Description |
| :--- | :--- | :--- |
| `-m` | `PATH` | Load a `.so` module (colon-separated list or repeatable) |
| `-p` | `PORT` | Listen port for HTTP/WS connections (default: `8080`) |
| `-d` | *none* | Run in foreground (debug mode; do not daemonize) |
| `-A` | *none* | Anonymous mode: auto-authenticate all requests |
| `-c` | `PATH` | Chroot jail directory before entering event loop |
| `-r` | `PATH` | Document root directory for static files |
| `-u` | `USER` | Drop privileges to specific user after binding sockets |
| `-g` | `GROUP` | Drop privileges to specific group after binding sockets |
| `-C` | `PATH` | Change working directory before server initialization |

---

## 3. Core API Reference

| Function | Signature | Description |
| :--- | :--- | :--- |
| `axil_main` | `int axil_main(void)` | Enter non-blocking network event loop |
| `axil_register_handler` | `void axil_register_handler(path, cb)` | Map HTTP path or pattern to a handler callback |
| `axil_respond_plain` | `void axil_respond_plain(fd, status, body)` | Send HTTP response with `text/plain` |
| `axil_respond_json` | `void axil_respond_json(fd, status, json)` | Send HTTP response with `application/json` |
| `axil_ws_upgrade` | `int axil_ws_upgrade(socket_t fd)` | Perform WebSocket handshake upgrade |
| `axil_ws_write` | `int axil_ws_write(fd, data, len)` | Transmit binary/text frame to WebSocket client |

👉 *For the browser WebSocket transport, see the canonical [htdocs/axil-bridge.js](htdocs/axil-bridge.js).*

---

## 4. Production Hardening & Security

- **Chroot Jail Isolation**: Confines the process and worker threads to a designated scratch directory via `-c`.
- **Privilege Dropping**: Drops from `root` to an unprivileged user/group (`-u www -g www`) immediately after binding privileged ports (<1024).
- **Framing & Anti-Smuggling**: Automatic `Content-Length` enforcement and strict RFC 7230 request line parsing.

---

## 5. Installation & Build

### Prebuilt Packages
Prebuilt packages are distributed on tty.pt for Linux (APT / Alpine / Arch / Fedora-RHEL), macOS (Homebrew), Windows (winget / MSYS2), and OpenBSD. Follow the [installation instructions](https://github.com/tty-pt/ci/blob/main/docs/install.md) and use **axil** as the package name.

### Build from Source
```sh
make                  # builds bin/axil and lib/libaxil.so
make test             # run unit and integration test suite
sudo make install     # install binary, headers, and library to system
```

## License

BSD 2-Clause License. Copyright (c) 2025, tty-pt. See `LICENSE`.
