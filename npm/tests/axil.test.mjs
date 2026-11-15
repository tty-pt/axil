import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  AxilClient,
  createAxilBridge,
  getNativeAxil,
  statusText,
  urlEncode,
  urlDecode,
  jsonEscape,
  slugify,
  normalizeCliArgs,
} from "../dist/index.js";
import { createAxilBridge as createAxilBridgeDirect } from "../dist/bridge.js";

// Mock WebSocket
class MockWebSocket {
  static OPEN = 1;
  constructor(url, protocols) {
    this.url = url;
    this.protocols = protocols;
    this.readyState = MockWebSocket.OPEN;
    this.sent = [];
    setTimeout(() => {
      if (this.onopen) this.onopen({});
    }, 5);
  }

  send(data) {
    this.sent.push(data);
  }

  close() {
    this.readyState = 3;
    if (this.onclose) this.onclose({});
  }

  // Helper for test to simulate incoming message
  emitMessage(data) {
    if (this.onmessage) this.onmessage({ data });
  }
}

globalThis.WebSocket = MockWebSocket;

test("createAxilBridge creates capability bridge and imports", () => {
  assert.equal(typeof createAxilBridge, "function");
  assert.equal(typeof createAxilBridgeDirect, "function");

  const mockExports = {
    memory: new WebAssembly.Memory({ initial: 1 })
  };
  const bridge = createAxilBridge(null, () => mockExports);
  assert.ok(bridge);
  assert.equal(typeof bridge.mount, "function");
  assert.equal(typeof bridge.destroy, "function");
  assert.equal(typeof bridge.makeImports, "function");

  const imports = bridge.makeImports();
  assert.equal(typeof imports.ws_connect, "function");
  assert.equal(typeof imports.ws_send, "function");
  assert.equal(typeof imports.axil_ws_send, "function");
  assert.equal(typeof imports.ws_send_channel, "function");
  assert.equal(typeof imports.ws_status, "function");
  assert.equal(typeof imports.ws_close, "function");

  assert.equal(imports.ws_status(), 0);
  bridge.destroy();
});

test("AxilClient connecting, multiplexing channel subscriptions, and sending", async () => {
  const client = new AxilClient({ autoConnect: false });
  assert.equal(client.status, 0);

  client.connect("ws://localhost:8080/ws");
  assert.equal(client.status, 1);

  // Wait for onopen
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.equal(client.status, 2);

  const rawReceived = [];
  const bcpReceived = [];
  const textReceived = [];

  const unsubRaw = client.subscribe((bytes, isText) => {
    rawReceived.push({ bytes, isText });
  });

  const unsubBcp = client.subscribeChannel(1, (bytes, isText) => {
    bcpReceived.push({ bytes, isText });
  });

  const unsubText = client.subscribeChannel(0, (bytes, isText) => {
    textReceived.push({ bytes, isText });
  });

  // 1. Text message
  client.socket.emitMessage("Hello server");
  assert.equal(rawReceived.length, 1);
  assert.equal(textReceived.length, 1);
  assert.equal(bcpReceived.length, 0);
  assert.equal(new TextDecoder().decode(textReceived[0].bytes), "Hello server");

  // 2. Binary message on Channel 1 (BCP '#b' magic: 0x23, 0x62)
  const bcpMsg = new Uint8Array([0x23, 0x62, 0x01, 0x02]);
  client.socket.emitMessage(bcpMsg.buffer);
  assert.equal(rawReceived.length, 2);
  assert.equal(bcpReceived.length, 1);
  assert.deepEqual(Array.from(bcpReceived[0].bytes), [0x23, 0x62, 0x01, 0x02]);

  // 3. Client send
  const ok = client.send("outbound message");
  assert.equal(ok, true);
  assert.equal(client.socket.sent.length, 1);
  assert.equal(client.socket.sent[0], "outbound message");

  // 4. Cleanup
  unsubRaw();
  unsubBcp();
  unsubText();
  client.close();
  assert.equal(client.status, 0);
});

test("N-API native bindings and CLI helpers", () => {
  const native = getNativeAxil();
  assert.ok(native, "expected native axil.node binding to load");
  assert.equal(statusText(200), "OK");
  assert.equal(statusText(404), "Not Found");
  assert.equal(urlEncode("hello world!"), "hello%20world%21");
  assert.equal(urlDecode("hello+world%21"), "hello world!");
  assert.equal(jsonEscape('a"b\nc'), 'a\\"b\\nc');
  assert.equal(slugify("Hello World!"), "hello_world");

  const args = normalizeCliArgs(["-A", "-p", "4242", "-m", "libaxil-auren"]);
  assert.equal(args[0], "-A");
  assert.equal(args[1], "-p");
  assert.equal(args[2], "4242");
  assert.equal(args[3], "-m");
  assert.ok(args[4].includes("libaxil-auren"));

  const here = dirname(fileURLToPath(import.meta.url));
  const binPath = join(here, "..", "bin", "axil.js");
  const helpRes = spawnSync(process.execPath, [binPath, "-?"], { encoding: "utf8" });
  assert.equal(helpRes.status, 1);
  assert.ok(helpRes.stderr.includes("Usage: axil"));
});

test("bin/axil.js launches a detached HTTP daemon and serves requests", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const binPath = join(here, "..", "bin", "axil.js");
  const port = 19100 + (process.pid % 500);

  // Launch in detached mode (no -d) — should return immediately with status 0
  const launchRes = spawnSync(process.execPath, [binPath, "-p", String(port)], {
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(launchRes.status, 0);

  try {
    let status = 0;
    for (let i = 0; i < 25; i++) {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/`);
        status = res.status;
        await res.text();
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    assert.equal(status, 404, "expected detached axil daemon to answer HTTP 404 on /");
  } finally {
    spawnSync("pkill", ["-f", `${binPath} -d -p ${port}`]);
  }
});


