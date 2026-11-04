import test from "node:test";
import assert from "node:assert/strict";
import { AxilClient, createAxilBridge } from "../dist/index.js";
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
