<p align="center">
  <img src="https://raw.githubusercontent.com/tty-pt/axil/main/assets/logo.png" alt="@tty-pt/axil logo" width="220" />
</p>

# @tty-pt/axil

[![npm version](https://img.shields.io/npm/v/@tty-pt/axil.svg)](https://www.npmjs.com/package/@tty-pt/axil)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](https://github.com/tty-pt/axil/blob/main/LICENSE)
[![TypeScript Ready](https://img.shields.io/badge/TypeScript-Ready-3178C6?logo=typescript)](#)
[![WebAssembly](https://img.shields.io/badge/WebAssembly-Bridge-654FF0?logo=webassembly)](#)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)](#)

> Universal Node.js and Browser client and **N-API daemon host** for **`axil`** network transport, persistent WebSocket multiplexing, Xylem module hosting, and the WebAssembly transport bridge (`createAxilBridge`). Canonical C header: `<ttypt/axil.h>`.

📖 **Full C & Systems Documentation**: See the main [**axil GitHub README**](https://github.com/tty-pt/axil#readme) for the C event-driven HTTP/WebSocket daemon architecture, module hooks, and chroot security model.

---

## 1. Quickstart & Installation

```bash
npm install @tty-pt/axil
```

**Native OS Packages (`tty.pt`)**: Prebuilt native C packages (`axil`) for Linux (`apt`, `apk`, `pacman`, `dnf`), macOS (`brew`), Windows (`winget`, MSYS2), and OpenBSD (`pkg_add`) are available via the [**tty.pt package repositories**](https://github.com/tty-pt/ci/blob/main/docs/install.md).

### Launch the Native `axil` Daemon via CLI (`bin/axil.js`)
`@tty-pt/axil` bundles the native C `axil` server as a Node-API addon (`axil.node`) loaded with `RTLD_GLOBAL`. It automatically resolves `-m` module names across installed `@tty-pt/*` `prebuilds/<platform>-<arch>/` directories:

```bash
# Start axil-auren in the background on port 4242 (detaches cleanly)
npx axil -A -p 4242 -m axil-auren

# Run in foreground (-d)
npx axil -A -d -p 4242 -m axil-auren
```

### Connect with `AxilClient` (Browser & Node.js)

```javascript
import { AxilClient, createAxilBridge } from "@tty-pt/axil";

// 1. Connect a multiplexed WebSocket client
const client = new AxilClient({ url: "/ws" });

// 2. Subscribe to raw frames or specific multiplexed channels:
//    Channel 0: Text frames
//    Channel 1: Binary Chunk Protocol (#b)
//    Channel 2: Remote Procedure Call (#r)
client.subscribeChannel(1, (bytes) => {
  console.log("BCP frame bytes:", bytes.byteLength);
});

// 3. Send data over the persistent connection
client.send("hello");
```

---

## 2. JavaScript / TypeScript API Reference

### N-API Daemon Host & Module Resolution (Node.js)
- `runCli(args?: string[]): number`: Normalizes `-m` module paths and invokes the native C `axil_cli(argc, argv)` server entry point.
- `resolveModulePath(modSpec: string, searchBases?: string[]): string`: Resolves a module specifier (e.g. `"axil-auren"` or `"auren"`) to its absolute prebuilt shared library path inside `@tty-pt/*` `prebuilds/<platform>-<arch>/`.
- `normalizeCliArgs(args?: string[], searchBases?: string[]): string[]`: Rewrites `-m` arguments in a CLI array using `resolveModulePath`.

### Native String & HTTP Utilities (N-API with Pure-JS Fallback)
- `statusText(code: number): string`: Returns the standard HTTP reason phrase for a status code.
- `urlEncode(str: string): string`: Percent-encodes a string (`axil_urlencode`).
- `urlDecode(str: string): string`: Decodes a percent-encoded or `+`-encoded string (`axil_urldecode`).
- `jsonEscape(str: string): string`: Escapes a string for safe inclusion in a JSON string literal (`axil_json_escape`).
- `slugify(str: string): string`: Converts UTF-8 text into a lowercase ASCII URL/filename slug (`axil_slugify`).

### `AxilClient`
Persistent WebSocket multiplexer supporting text and binary protocol channels:
- `constructor(options?: { url?: string, autoConnect?: boolean })`: Creates a client and optionally opens a connection.
- `.connect(url?: string): void`: Opens (or reconnects) the underlying binary WebSocket.
- `.send(data: string | ArrayBuffer | Uint8Array): boolean`: Sends frame payload when open.
- `.sendChannel(channel: number, data: string | ArrayBuffer | Uint8Array): boolean`: Sends data on a multiplexed channel.
- `.subscribe(cb: (bytes: Uint8Array, isText: boolean) => void): () => void`: Subscribes to all incoming frames.
- `.subscribeChannel(channel: number, cb: (bytes: Uint8Array, isText: boolean) => void): () => void`: Subscribes to channel `0` (Text), `1` (`#b` BCP), or `2` (`#r` RPC).
- `.close(): void`: Closes the active WebSocket connection.

### `createAxilBridge` (`@tty-pt/axil/bridge`)
Registers WebAssembly host transport imports on a Stele `CapabilityRegistry` or WASM environment so isomorphic C modules can open, send, and receive over `axil` channels directly.

---

## 3. C Development Headers & Native Integration

```makefile
CFLAGS += -I./node_modules/@tty-pt/axil/include
LDLIBS += -laxil
```

---

## License

BSD-2-Clause — Copyright (c) 2026, Paulo Quirino <quirinpa@gmail.com>. See [LICENSE](https://github.com/tty-pt/axil/blob/main/LICENSE).
