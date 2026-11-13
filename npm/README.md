<p align="center">
  <img src="../assets/logo.png" alt="@tty-pt/axil logo" width="220" />
</p>

# @tty-pt/axil

[![npm version](https://img.shields.io/badge/npm-v1.8.0-CB3837?logo=npm)](#)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue)](../LICENSE)
[![TypeScript Ready](https://img.shields.io/badge/TypeScript-Ready-3178C6?logo=typescript)](#)
[![WebAssembly](https://img.shields.io/badge/WebAssembly-Bridge-654FF0?logo=webassembly)](#)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success)](#)

> Universal Node.js and Browser client for **`axil`** network transport, persistent WebSocket multiplexing, and the WebAssembly transport bridge (`createAxilBridge`).

---

## 1. Quickstart

```bash
npm install @tty-pt/axil
```

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

## 3. Running Tests

```bash
npm test
```

## License

BSD-2-Clause — Author: Paulo Quirino
