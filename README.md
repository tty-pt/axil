<p align="center">
  <img src="assets/logo.png" alt="axil logo" width="220" />
</p>

# axil

[![C99](https://img.shields.io/badge/C-C99-555?logo=c)](#)
[![BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](#)
[![HTTP(S)+WS daemon](https://img.shields.io/badge/HTTP%28S%29%2BWS-daemon-4B8BBE)](#)
[![libxylem compatible](https://img.shields.io/badge/modules-libxylem-16A34A)](#)

> Build high-throughput HTTP(S), WebSocket, and custom network daemons in plain C without async runtime bloat or heavy framework dependencies.

---

## Extensibility & Architecture

`axil` provides a modular, low-latency network daemon architecture:
- **Dynamic Extensions**: Dynamically loads `.so` protocol handlers, HTTP routes, and terminal extensions via [libxylem](https://github.com/tty-pt/libxylem).
- **Session State**: Uses [libcorm](https://github.com/tty-pt/libcorm) for fast, zero-overhead connection descriptor and session maps.
- **Isomorphic Frontends**: Serves static `.wasm` bundles with auto-configured cross-origin isolation headers for [libbud](https://github.com/tty-pt/libbud).

---

## Quickstart

A non-blocking HTTP and WebSocket service in 15 lines of pure C:

```c
#include <stdio.h>
#include <ttypt/axil.h>

static int handle_hello(socket_t fd, char *body) {
    (void)body;
    axil_respond_plain(fd, 200, "Hello from axil!\n");
    return 0;
}

int main(void) {
    axil_config.port = 8080;
    axil_register_handler("/api/hello", handle_hello);
    printf("Serving on http://localhost:8080/api/hello\n");
    return axil_main(); // Blocks, running event loop
}
```

Run standalone server from CLI:
```sh
axil -d -p 8080
```

---

## Core API (The Essential 20%)

| Function | Signature | Description |
| :--- | :--- | :--- |
| `axil_main` | `int axil_main(void)` | Enter the non-blocking network event loop |
| `axil_register_handler` | `void axil_register_handler(path, cb)` | Map HTTP path or pattern to a handler |
| `axil_respond_plain` | `int axil_respond_plain(fd, code, msg)` | Send HTTP status and text response |
| `axil_ws_upgrade` | `int axil_ws_upgrade(fd)` | Perform WebSocket handshake upgrade |
| `axil_ws_write` | `ssize_t axil_ws_write(fd, data, len)` | Write a framed WebSocket payload |
| `axil_sendfile` | `void axil_sendfile(fd, path)` | Zero-copy static file transfer with MIME auto-detection |

👉 *For SSL certificates, PTY terminal tunneling, request environment maps, and the complete API reference, see [docs/API.md](docs/API.md).*

---

## Design Philosophy: Constraints as Superpowers

* **Zero-Async Mental Model**: Instead of deep async/await state machines or promise allocations, `axil` uses clean, predictable POSIX event loop callbacks with zero hidden allocations.
* **Built-in Isolation Headers**: Pre-configures `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` automatically so WASM SharedArrayBuffers work out of the box.
* **Unix Philosophy**: Designed to run cleanly inside chroot jails with privilege dropping (`axil_auth`) and minimal system attack surfaces.

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
