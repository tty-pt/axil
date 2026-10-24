/*
 * axil-bridge.js — Canonical browser WebAssembly bridge for axil network transport.
 * Provides the "axil" WASM capability module with single persistent socket multiplexing.
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

export function createAxilBridge(root, getWasm) {
	let reconnectTimer = null;
	let reconnectDelay = 1000;
	let lastUrl = null;
	let explicitClose = false;
	let lastAckSeq = 0;
	let pendingUrl = null;
	let isMounted = false;

	const hostKey = (typeof window !== 'undefined' && window.location) ? window.location.host : 'default';
	if (typeof window !== 'undefined') {
		window.__axil_ws_instances = window.__axil_ws_instances || {};
		if (!window.__axil_ws_instances[hostKey]) {
			window.__axil_ws_instances[hostKey] = {
				socket: null,
				status: 0, // 0: CLOSED, 1: CONNECTING, 2: OPEN, 3: CLOSING
				subscribers: new Set(),
				backlog: [],
				send(data) {
					if (this.socket && this.socket.readyState === WebSocket.OPEN) {
						this.socket.send(data);
						return true;
					}
					return false;
				},
				subscribe(cb) {
					this.subscribers.add(cb);
					if (this.backlog.length > 0) {
						for (const item of this.backlog) {
							try { cb(item.bytes, item.isText); } catch (_) {}
						}
					}
					return () => this.subscribers.delete(cb);
				}
			};
		}
		window.__axil_ws = window.__axil_ws_instances[hostKey];
	}

	const bus = (typeof window !== 'undefined' && window.__axil_ws_instances) ? window.__axil_ws_instances[hostKey] : window.__axil_ws;

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
		const target = url.startsWith('/')
			? `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${url}`
			: url;

		const sock = new WebSocket(target, ['binary']);
		sock.binaryType = 'arraybuffer';
		bus.socket = sock;

		sock.onopen = () => {
			if (bus.socket !== sock) return;
			bus.status = 2; // OPEN
			reconnectDelay = 1000;
			if (lastAckSeq > 0) {
				// Reconnection delta catchup request with last acknowledged BCP sequence
				try {
					sock.send(new TextEncoder().encode(`ack:${lastAckSeq}\n`));
				} catch (_) {}
			}
			const fn = getExport(getWasm(), ['wasm_ws_on_open']);
			if (fn) fn();
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

			if (!isText && bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x62) {
				lastAckSeq++;
			}

			// Notify raw bus subscribers (e.g. terminal or inspect tools)
			if (bus.subscribers.size === 0) {
				bus.backlog.push({ bytes, isText });
				if (bus.backlog.length > 50) bus.backlog.shift();
			} else {
				for (const sub of bus.subscribers) {
					try { sub(bytes, isText); } catch (_) {}
				}
			}

			const wasm = getWasm();
			if (!wasm || !wasm.memory) return;

			const onMsg = getExport(wasm, ['wasm_ws_on_message']);
			const onChan = getExport(wasm, ['wasm_ws_on_channel']);
			const malloc = getExport(wasm, ['malloc']);
			const free = getExport(wasm, ['free']);

			if ((onMsg || onChan) && malloc && free) {
				const ptr = malloc(bytes.length);
				if (ptr) {
					new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);

					if (onChan) {
						let channel = 0; // 0: Text, 1: BCP, 2: RPC
						if (!isText && bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x62) {
							channel = 1; // Magic '#b'
						}
						onChan(channel, ptr, bytes.length);
					} else if (onMsg) {
						onMsg(ptr, bytes.length);
					}

					free(ptr);
				}
			}
		};

		sock.onclose = (evt) => {
			if (bus.socket !== sock) return;
			bus.status = 0; // CLOSED
			bus.socket = null;

			const fn = getExport(getWasm(), ['wasm_ws_on_close']);
			if (fn) fn(evt.code || 0);

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
			return {
				ws_connect(url_ptr, url_len) {
					const exports = getWasm();
					if (!exports || !exports.memory) return;
					const url = readWasmStr(exports.memory, url_ptr, url_len);
					connect(url);
				},
				ws_send(buf_ptr, buf_len) {
					const exports = getWasm();
					if (!exports || !exports.memory || !buf_ptr || buf_len <= 0) return;
					const bytes = new Uint8Array(exports.memory.buffer, buf_ptr, buf_len);
					bus.send(bytes);
				},
				ws_send_channel(channel, buf_ptr, buf_len) {
					const exports = getWasm();
					if (!exports || !exports.memory) return;
					if (channel === 0) {
						// Raw text channel
						const bytes = new Uint8Array(exports.memory.buffer, buf_ptr, buf_len);
						bus.send(bytes);
					} else {
						// Framed binary channel
						const bytes = new Uint8Array(exports.memory.buffer, buf_ptr, buf_len);
						bus.send(bytes);
					}
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

if (typeof window !== 'undefined') {
	window.__wasm_capability_registry = window.__wasm_capability_registry || {};
	const axilFactory = (root, getWasm) => createAxilBridge(root, getWasm);
	window.__wasm_capability_registry.axil = axilFactory;
	window.__wasm_capability_registry['axil-ws'] = axilFactory;
}
