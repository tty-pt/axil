import { createAxilBridge } from "./bridge.js";
import { loadNativeAddon, getPlatformPrebuildKeys } from "@tty-pt/stele";

const nativeBinding = loadNativeAddon(import.meta.url, "axil");

export function getNativeAxil() {
  return nativeBinding;
}

/**
 * Strip shared-library extension (.so / .dylib / .dll) so xy_load() receives a stem path.
 * @param {string} p
 * @returns {string}
 */
function stripLibExt(p) {
  return p.replace(/\.(?:so|dylib|dll)$/i, "");
}

/**
 * Check whether `<stem>.so`, `<stem>.dylib`, or `<stem>.dll` exists on disk.
 * @param {string} stem
 * @param {typeof import("node:fs")} fs
 * @returns {boolean}
 */
function hasModuleBinary(stem, fs) {
  return (
    fs.existsSync(`${stem}.so`) ||
    fs.existsSync(`${stem}.dylib`) ||
    fs.existsSync(`${stem}.dll`)
  );
}

/**
 * Resolve a single module specifier or colon-separated `-m` module list
 * (e.g. `"libaxil-auren"`, `"auren"`, or `"/path/to/libaxil-auren"`) across
 * local files, installed `@tty-pt/*` prebuild directories, and sibling checkouts.
 *
 * @param {string} modSpec
 * @param {string} [callerImportMetaUrl]
 * @returns {string}
 */
export function resolveModulePath(modSpec, callerImportMetaUrl = import.meta.url) {
  if (!modSpec || typeof process === "undefined" || !process.versions?.node) {
    return modSpec;
  }
  const getModule = globalThis.process?.getBuiltinModule;
  if (!getModule) return modSpec;
  const fs = getModule("fs");
  const path = getModule("path");
  const url = getModule("url");
  const req = getModule("module").createRequire(callerImportMetaUrl);
  const callerDir = path.dirname(url.fileURLToPath(callerImportMetaUrl));
  const keys = getPlatformPrebuildKeys();

  const resolveSingle = (entry) => {
    if (!entry) return entry;
    const stem = stripLibExt(entry);
    if (hasModuleBinary(stem, fs)) {
      return path.resolve(stem);
    }

    const base = path.basename(stem);
    const shortName = base.replace(/^lib/, "").replace(/^axil-/, "");
    const libNames = Array.from(
      new Set([`libaxil-${shortName}`, base, `lib${shortName}`])
    );
    const pkgCandidates = Array.from(
      new Set([`@tty-pt/axil-${shortName}`, `@tty-pt/${shortName}`])
    );

    const searchDirs = [];
    const addDir = (d) => {
      if (d && !searchDirs.includes(d)) searchDirs.push(d);
    };

    for (const pkg of pkgCandidates) {
      try {
        const pkgJson = req.resolve(`${pkg}/package.json`);
        const pkgRoot = path.dirname(pkgJson);
        for (const k of keys) addDir(path.join(pkgRoot, "prebuilds", k));
        addDir(path.join(pkgRoot, "build", "Release"));
        addDir(path.resolve(pkgRoot, "..", "lib"));
      } catch {}
    }

    for (const sub of [`axil-${shortName}`, shortName]) {
      const siblingPkg = path.resolve(callerDir, "..", "..", sub);
      for (const k of keys) addDir(path.join(siblingPkg, "prebuilds", k));
      addDir(path.join(siblingPkg, "build", "Release"));
      addDir(path.resolve(callerDir, "..", "..", sub, "lib"));
      addDir(path.resolve(callerDir, "..", "..", `lib${sub}`, "lib"));
    }

    const cwd = process.cwd();
    for (const sub of [`axil-${shortName}`, shortName]) {
      for (const k of keys) {
        addDir(path.join(cwd, "node_modules", "@tty-pt", sub, "prebuilds", k));
      }
      addDir(path.join(cwd, "external", `axil-${shortName}`, "lib"));
      addDir(path.join(cwd, "..", `axil-${shortName}`, "lib"));
    }
    addDir(path.join(cwd, "lib"));

    for (const libName of libNames) {
      for (const dir of searchDirs) {
        const cand = path.join(dir, libName);
        if (hasModuleBinary(cand, fs)) {
          return cand;
        }
      }
    }

    return stem;
  };

  if (process.platform === "win32") {
    return resolveSingle(modSpec);
  }
  return modSpec
    .split(":")
    .map((part) => resolveSingle(part))
    .join(":");
}

/**
 * Normalize an `axil` CLI argument array, resolving `-m` module paths.
 *
 * @param {string[]} args
 * @param {string} [callerImportMetaUrl]
 * @returns {string[]}
 */
export function normalizeCliArgs(args = [], callerImportMetaUrl = import.meta.url) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const arg = String(args[i]);
    if (arg === "-m" && i + 1 < args.length) {
      out.push("-m", resolveModulePath(String(args[++i]), callerImportMetaUrl));
    } else if (arg.startsWith("-m") && arg.length > 2) {
      out.push("-m", resolveModulePath(arg.slice(2), callerImportMetaUrl));
    } else {
      out.push(arg);
    }
  }
  return out;
}

/**
 * Run the native `axil` CLI entrypoint synchronously in the current process.
 *
 * @param {string[]} args
 * @returns {number}
 */
export function runCli(args = []) {
  if (!nativeBinding || typeof nativeBinding.cli !== "function") {
    throw new Error("@tty-pt/axil native addon is not available on this platform");
  }
  const normalized = normalizeCliArgs(args);
  return nativeBinding.cli(normalized);
}

export function statusText(code) {
  if (nativeBinding && typeof nativeBinding.statusText === "function") {
    return nativeBinding.statusText(Number(code));
  }
  const map = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
  };
  return map[Number(code)] || "Unknown";
}

export function urlEncode(input) {
  const str = String(input ?? "");
  if (nativeBinding && typeof nativeBinding.urlEncode === "function") {
    return nativeBinding.urlEncode(str);
  }
  return encodeURIComponent(str);
}

export function urlDecode(input) {
  const str = String(input ?? "");
  if (nativeBinding && typeof nativeBinding.urlDecode === "function") {
    return nativeBinding.urlDecode(str);
  }
  return decodeURIComponent(str.replace(/\+/g, " "));
}

export function jsonEscape(input) {
  const str = String(input ?? "");
  if (nativeBinding && typeof nativeBinding.jsonEscape === "function") {
    return nativeBinding.jsonEscape(str);
  }
  return JSON.stringify(str).slice(1, -1);
}

export function slugify(input) {
  const str = String(input ?? "");
  if (nativeBinding && typeof nativeBinding.slugify === "function") {
    return nativeBinding.slugify(str);
  }
  const s = str
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_-]/g, "");
  return s || "item";
}

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
