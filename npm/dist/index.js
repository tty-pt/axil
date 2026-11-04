import { createAxilBridge } from "./bridge.js";

export class AxilClient {
  constructor(options = {}) {
    this.url = options.url || null;
    this.socket = null;
    this.status = 0; // 0: CLOSED, 1: CONNECTING, 2: OPEN, 3: CLOSING
    this._subscribers = new Set();
    this._channelSubscribers = new Map([
      [0, new Set()], // Channel 0: Text
      [1, new Set()], // Channel 1: BCP (#b)
      [2, new Set()]  // Channel 2: RPC (#r)
    ]);
    if (this.url && options.autoConnect !== false) {
      this.connect(this.url);
    }
  }

  connect(url) {
    if (url) this.url = url;
    if (!this.url) return;

    if (this.socket) {
      try { this.socket.close(); } catch (_) {}
      this.socket = null;
    }

    const WebSocketClass = typeof WebSocket !== 'undefined' ? WebSocket : globalThis.WebSocket;
    if (!WebSocketClass) {
      throw new Error('WebSocket is not available in the current environment');
    }

    this.status = 1; // CONNECTING
    let target = this.url;
    if (target.startsWith('/') && typeof window !== 'undefined' && window.location) {
      target = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${target}`;
    }

    const sock = new WebSocketClass(target, ['binary']);
    sock.binaryType = 'arraybuffer';
    this.socket = sock;

    sock.onopen = (evt) => {
      if (this.socket !== sock) return;
      this.status = 2; // OPEN
      if (typeof this.onOpen === 'function') this.onOpen(evt);
    };

    sock.onmessage = (evt) => {
      if (this.socket !== sock) return;

      let bytes;
      let isText = false;
      if (typeof evt.data === 'string') {
        bytes = new TextEncoder().encode(evt.data);
        isText = true;
      } else {
        bytes = new Uint8Array(evt.data);
      }

      let channel = 0;
      if (!isText && bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x62) {
        channel = 1;
      } else if (!isText && bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x72) {
        channel = 2;
      }

      for (const cb of this._subscribers) {
        try { cb(bytes, isText); } catch (_) {}
      }

      const chanSubs = this._channelSubscribers.get(channel);
      if (chanSubs) {
        for (const cb of chanSubs) {
          try { cb(bytes, isText); } catch (_) {}
        }
      }
    };

    sock.onclose = (evt) => {
      if (this.socket !== sock) return;
      this.status = 0; // CLOSED
      this.socket = null;
      if (typeof this.onClose === 'function') this.onClose(evt);
    };

    sock.onerror = (err) => {
      if (typeof this.onError === 'function') this.onError(err);
    };
  }

  send(data) {
    const readyState = this.socket ? this.socket.readyState : null;
    const openState = typeof WebSocket !== 'undefined' ? WebSocket.OPEN : 1;
    if (this.socket && readyState === openState) {
      this.socket.send(data);
      return true;
    }
    return false;
  }

  sendChannel(channel, data) {
    return this.send(data);
  }

  subscribe(cb) {
    this._subscribers.add(cb);
    return () => this._subscribers.delete(cb);
  }

  subscribeChannel(channel, cb) {
    let set = this._channelSubscribers.get(channel);
    if (!set) {
      set = new Set();
      this._channelSubscribers.set(channel, set);
    }
    set.add(cb);
    return () => set.delete(cb);
  }

  close() {
    if (this.socket) {
      try { this.socket.close(); } catch (_) {}
      this.socket = null;
    }
    this.status = 0;
  }
}

export { createAxilBridge } from "./bridge.js";
