/*
 * bridge.js — Browser WebAssembly bridge for axil network transport.
 * Provides the "axil" and "axil-ws" capability module with single persistent socket multiplexing.
 */

function readWasmStr(memory, ptr, len) {
	if (!memory || !ptr || len <= 0) return '';
	return new TextDecoder().decode(new Uint8Array(memory.buffer, ptr, len));
}

function getExport(exports, names) {
	if (!exports) return null;
	for (const name of names) {
		if (typeof exports[name] === 'function') return exports[name];
	}
	return null;
}

function ensureAxilWsBus(globalScope) {
	const loc = (typeof window !== 'undefined' && window.location)
		? window.location
		: (globalScope.__stele_location || globalScope.location || null);
	const hostKey = (loc && loc.host) ? loc.host : 'default';

	globalScope.__axil_ws_instances = globalScope.__axil_ws_instances || {};
	if (!globalScope.__axil_ws_instances[hostKey]) {
		globalScope.__axil_ws_instances[hostKey] = {
			socket: null,
			status: 0, // 0: CLOSED, 1: CONNECTING, 2: OPEN, 3: CLOSING
			subscribers: new Set(),
			channelSubscribers: new Map([
				[0, new Set()],
				[1, new Set()],
				[2, new Set()]
			]),
			backlog: [],
			send(data) {
				if (this.socket && this.socket.readyState === (typeof WebSocket !== 'undefined' ? WebSocket.OPEN : 1)) {
					this.socket.send(data);
					return true;
				}
				if (typeof globalScope.__stele_ws_send === 'function') {
					return globalScope.__stele_ws_send(data);
				}
				return false;
			},
			deliverStream0(bytes, isText) {
				const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
				if (this.subscribers.size === 0) {
					this.backlog.push({ bytes: u8, isText: !!isText });
					if (this.backlog.length > 50) this.backlog.shift();
				} else {
					for (const sub of this.subscribers) {
						try { sub(u8, !!isText); } catch (_) {}
					}
				}
				const chanSubs = this.channelSubscribers?.get(0);
				if (chanSubs) {
					for (const sub of chanSubs) {
						try { sub(u8, !!isText); } catch (_) {}
					}
				}
			},
			subscribe(cb) {
				this.subscribers.add(cb);
				if (this.backlog.length > 0) {
					const pending = this.backlog.splice(0, this.backlog.length);
					for (const item of pending) {
						try { cb(item.bytes, item.isText); } catch (_) {}
					}
				}
				return () => this.subscribers.delete(cb);
			},
			subscribeChannel(chan, cb) {
				let set = this.channelSubscribers.get(chan);
				if (!set) {
					set = new Set();
					this.channelSubscribers.set(chan, set);
				}
				set.add(cb);
				return () => set.delete(cb);
			}
		};
	}
	globalScope.__axil_ws = globalScope.__axil_ws_instances[hostKey];
	return globalScope.__axil_ws;
}

export function createAxilBridge(root, getWasm) {
	let reconnectTimer = null;
	let reconnectDelay = 1000;
	let lastUrl = null;
	let explicitClose = false;
	let lastAckSeq = 0;
	let pendingUrl = null;
	let isMounted = false;

	const globalScope = typeof window !== 'undefined' ? window : globalThis;
	const loc = (typeof window !== 'undefined' && window.location)
		? window.location
		: (globalScope.__stele_location || globalScope.location || null);
	const bus = ensureAxilWsBus(globalScope);

	function resolveWsUrl(url) {
		if (!url || !url.startsWith('/')) return url;
		if (typeof window !== 'undefined' && window.location && window.location.host) {
			return `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${url}`;
		}
		if (globalScope.__stele_origin) {
			return `${globalScope.__stele_origin.replace(/^http/, 'ws')}${url}`;
		}
		if (loc && loc.host) {
			return `${loc.protocol === 'https:' ? 'wss:' : 'ws:'}//${loc.host}${url}`;
		}
		return url;
	}

	function connect(url) {
		if (!url) return;
		if (!isMounted) {
			pendingUrl = url;
			return;
		}
		lastUrl = url;
		explicitClose = false;

		if (bus.socket) {
			try { bus.socket.close(); } catch (_) {}
			bus.socket = null;
		}

		bus.status = 1; // CONNECTING
		const target = resolveWsUrl(url);

		const WebSocketClass = typeof WebSocket !== 'undefined' ? WebSocket : globalThis.WebSocket;
		if (!WebSocketClass) return;

		const sock = new WebSocketClass(target, ['binary']);
		sock.binaryType = 'arraybuffer';
		bus.socket = sock;

		sock.onopen = () => {
			if (bus.socket !== sock) return;
			bus.status = 2; // OPEN
			reconnectDelay = 1000;
			if (lastAckSeq > 0) {
				try {
					sock.send(new TextEncoder().encode(`ack:${lastAckSeq}\n`));
				} catch (_) {}
			}
			if (typeof globalScope.__stele_worker_post === 'function') {
				globalScope.__stele_worker_post({ type: 'stele:ws_status', status: 2 });
			}
			const wasm = typeof getWasm === 'function' ? getWasm() : null;
			const fn = getExport(wasm, ['wasm_ws_on_open']);
			if (fn) {
				globalScope.__stele_begin_turn?.();
				try {
					fn();
				} finally {
					globalScope.__stele_flush_turn?.();
				}
			}
		};

		sock.onmessage = (evt) => {
			if (bus.socket !== sock) return;

			let bytes;
			let isText = false;
			if (typeof evt.data === 'string') {
				bytes = new TextEncoder().encode(evt.data);
				isText = true;
			} else {
				bytes = new Uint8Array(evt.data);
			}

			let channel = 0; // 0: Text, 1: BCP, 2: RPC
			if (!isText && bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x62) {
				lastAckSeq++;
				channel = 1;
			} else if (!isText && bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x72) {
				channel = 2;
			}

			// Notify raw bus subscribers
			if (bus.subscribers.size === 0) {
				bus.backlog.push({ bytes, isText });
				if (bus.backlog.length > 50) bus.backlog.shift();
			} else {
				for (const sub of bus.subscribers) {
					try { sub(bytes, isText); } catch (_) {}
				}
			}

			// Notify channel subscribers
			const chanSubs = bus.channelSubscribers?.get(channel);
			if (chanSubs) {
				for (const sub of chanSubs) {
					try { sub(bytes, isText); } catch (_) {}
				}
			}

			// When running inside a Web Worker, forward Stream 0 (ANSI text / Telnet IAC)
			// to the Main Thread so xterm.js subscribers on window.__axil_ws receive it.
			if (channel === 0 && typeof globalScope.__stele_worker_post === 'function') {
				globalScope.__stele_worker_post({
					type: 'stele:ws_stream0',
					bytes: new Uint8Array(bytes),
					isText
				});
			}

			const wasm = typeof getWasm === 'function' ? getWasm() : null;
			if (!wasm || !wasm.memory) return;

			const onMsg = getExport(wasm, ['wasm_ws_on_message']);
			const onChan = getExport(wasm, ['wasm_ws_on_channel']);
			const malloc = getExport(wasm, ['malloc']);
			const free = getExport(wasm, ['free']);

			if ((onMsg || onChan) && malloc && free) {
				globalScope.__stele_begin_turn?.();
				try {
					const ptr = malloc(bytes.length);
					if (ptr) {
						new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);
						if (onChan) {
							onChan(channel, ptr, bytes.length);
						} else if (onMsg) {
							onMsg(ptr, bytes.length);
						}
						free(ptr);
					}
				} finally {
					globalScope.__stele_flush_turn?.();
				}
			}
		};

		sock.onclose = (evt) => {
			if (bus.socket !== sock) return;
			bus.status = 0; // CLOSED
			bus.socket = null;
			if (typeof globalScope.__stele_worker_post === 'function') {
				globalScope.__stele_worker_post({ type: 'stele:ws_status', status: 0 });
			}

			const wasm = typeof getWasm === 'function' ? getWasm() : null;
			const fn = getExport(wasm, ['wasm_ws_on_close']);
			if (fn) {
				globalScope.__stele_begin_turn?.();
				try {
					fn(evt.code || 0);
				} finally {
					globalScope.__stele_flush_turn?.();
				}
			}

			if (!explicitClose && lastUrl) {
				clearTimeout(reconnectTimer);
				reconnectTimer = setTimeout(() => {
					reconnectDelay = Math.min(reconnectDelay * 2, 16000);
					connect(lastUrl);
				}, reconnectDelay);
			}
		};

		sock.onerror = () => {
			if (bus.socket === sock) {
				try { sock.close(); } catch (_) {}
			}
		};
	}

	return {
		mount() {
			isMounted = true;
			if (pendingUrl) {
				const url = pendingUrl;
				pendingUrl = null;
				connect(url);
			}
		},
		destroy() {
			isMounted = false;
			pendingUrl = null;
			explicitClose = true;
			clearTimeout(reconnectTimer);
			if (bus.socket) {
				try { bus.socket.close(); } catch (_) {}
				bus.socket = null;
			}
			bus.status = 0;
		},
		makeImports() {
			const sendFn = (buf_ptr, buf_len) => {
				const exports = typeof getWasm === 'function' ? getWasm() : null;
				if (!exports || !exports.memory || !buf_ptr || buf_len <= 0) return;
				const bytes = new Uint8Array(exports.memory.buffer, buf_ptr, buf_len);
				let isText = true;
				for (let i = 0; i < bytes.length; i++) {
					const b = bytes[i];
					if ((b < 32 && b !== 9 && b !== 10 && b !== 13) || b > 126) {
						isText = false;
						break;
					}
				}
				if (isText) {
					const text = new TextDecoder().decode(bytes);
					bus.send(text);
				} else {
					bus.send(bytes.slice());
				}
			};

			return {
				ws_connect(url_ptr, url_len) {
					const exports = typeof getWasm === 'function' ? getWasm() : null;
					if (!exports || !exports.memory) return;
					const url = readWasmStr(exports.memory, url_ptr, url_len);
					connect(url);
				},
				ws_send: sendFn,
				axil_ws_send: sendFn,
				ws_send_channel(channel, buf_ptr, buf_len) {
					const exports = typeof getWasm === 'function' ? getWasm() : null;
					if (!exports || !exports.memory) return;
					const bytes = new Uint8Array(exports.memory.buffer, buf_ptr, buf_len);
					bus.send(bytes.slice());
				},
				ws_status() {
					return bus.status;
				},
				ws_close() {
					explicitClose = true;
					clearTimeout(reconnectTimer);
					if (bus.socket) {
						try { bus.socket.close(); } catch (_) {}
						bus.socket = null;
					}
					bus.status = 0;
				}
			};
		}
	};
}

const _axilGlobal = typeof window !== 'undefined' ? window : globalThis;
ensureAxilWsBus(_axilGlobal);
_axilGlobal.__wasm_capability_registry = _axilGlobal.__wasm_capability_registry || {};
const _axilFactory = (root, getWasm) => createAxilBridge(root, getWasm);
_axilGlobal.__wasm_capability_registry.axil = _axilFactory;
_axilGlobal.__wasm_capability_registry['axil-ws'] = _axilFactory;
if (typeof _axilGlobal.registerWasmCapability === 'function') {
	_axilGlobal.registerWasmCapability('axil', _axilFactory);
	_axilGlobal.registerWasmCapability('axil-ws', _axilFactory);
}
