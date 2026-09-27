#!/usr/bin/env python3
import base64
import os
import socket
import sys
import time
import hashlib


def recv_exact(sock, size):
	buf = b""
	while len(buf) < size:
		chunk = sock.recv(size - len(buf))
		if not chunk:
			return None
		buf += chunk
	return buf


def recv_http_response(sock):
	data = b""
	while b"\r\n\r\n" not in data:
		chunk = sock.recv(4096)
		if not chunk:
			break
		data += chunk
	if b"\r\n\r\n" not in data:
		return data, b""
	idx = data.find(b"\r\n\r\n") + 4
	return data[:idx], data[idx:]


class BufferedSocket:
	def __init__(self, sock, buf=b""):
		self.sock = sock
		self.buf = buf

	def recv(self, size):
		if self.buf:
			out = self.buf[:size]
			self.buf = self.buf[size:]
			return out
			
		return self.sock.recv(size)


def recv_frame(sock):
	head = recv_exact(sock, 2)
	if not head:
		return None
	fin = (head[0] & 0x80) != 0
	opcode = head[0] & 0x0F
	masked = (head[1] & 0x80) != 0
	length = head[1] & 0x7F
	if length == 126:
		raw = recv_exact(sock, 2)
		if not raw:
			return None
		length = int.from_bytes(raw, "big")
	elif length == 127:
		raw = recv_exact(sock, 8)
		if not raw:
			return None
		length = int.from_bytes(raw, "big")
	mask_key = b""
	if masked:
		mask_key = recv_exact(sock, 4)
		if not mask_key:
			return None
	payload = recv_exact(sock, length)
	if payload is None:
		return None
	if masked:
		payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
	return fin, opcode, payload


def send_frame(sock, payload, opcode=0x2):
	if isinstance(payload, str):
		payload = payload.encode("utf-8")
	mask_key = os.urandom(4)
	length = len(payload)
	head = bytearray()
	head.append(0x80 | (opcode & 0x0F))
	if length < 126:
		head.append(0x80 | length)
	elif length < (1 << 16):
		head.append(0x80 | 126)
		head.extend(length.to_bytes(2, "big"))
	else:
		head.append(0x80 | 127)
		head.extend(length.to_bytes(8, "big"))
	masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
	sock.sendall(bytes(head) + mask_key + masked)


def build_frame(payload, opcode=0x2):
	"""Return (header, mask_key, masked_payload) so a test can dribble the
	bytes out in separate segments."""
	if isinstance(payload, str):
		payload = payload.encode("utf-8")
	mask_key = os.urandom(4)
	length = len(payload)
	head = bytearray()
	head.append(0x80 | (opcode & 0x0F))
	if length < 126:
		head.append(0x80 | length)
	elif length < (1 << 16):
		head.append(0x80 | 126)
		head.extend(length.to_bytes(2, "big"))
	else:
		head.append(0x80 | 127)
		head.extend(length.to_bytes(8, "big"))
	masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
	return bytes(head), mask_key, masked


def ws_handshake(sock, port, path="/"):
	"""Perform the opening handshake on an already-connected socket. Returns the
	accept header value the server sent."""
	key = base64.b64encode(os.urandom(16)).decode("ascii")
	accept = base64.b64encode(
		hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
	).decode("ascii")
	req = (
		"GET %s HTTP/1.1\r\n"
		"Host: 127.0.0.1:%d\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"\r\n"
	) % (path, port, key)
	sock.sendall(req.encode("ascii"))
	resp, extra = recv_http_response(sock)
	if b"101" not in resp.split(b"\r\n", 1)[0]:
		raise RuntimeError("handshake failed: %r" % resp[:120])
	got = None
	for line in resp.decode("iso-8859-1", errors="ignore").split("\r\n")[1:]:
		if not line:
			break
		if ":" not in line:
			continue
		name, value = line.split(":", 1)
		if name.strip().lower() == "sec-websocket-accept":
			got = value.strip()
			break
	if got != accept:
		raise RuntimeError("accept mismatch: %r != %r" % (got, accept))
	return BufferedSocket(sock, extra), extra


def ws_connect(port, path="/ws-echo", timeout=5):
	sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
	sock.settimeout(timeout)
	bsock, _extra = ws_handshake(sock, port, path)
	return sock, bsock


def expect_echo(sock, payload, label):
	"""Read one echoed frame and require its payload to equal `payload`."""
	try:
		frame = recv_frame(sock)
	except socket.timeout:
		print("FAIL %s: timed out waiting for echo" % label)
		return False
	if not frame:
		print("FAIL %s: connection closed instead of echoing" % label)
		return False
	_fin, opcode, got = frame
	if opcode == 0x8:
		print("FAIL %s: server sent close frame" % label)
		return False
	if got != payload:
		print(
			"FAIL %s: echo mismatch (want %d bytes, got %d bytes%s)"
			% (label, len(payload), len(got),
			   ", first bytes differ" if len(got) == len(payload) else "")
		)
		return False
	print("PASS %s (%d bytes round-tripped)" % (label, len(payload)))
	return True


def test_split(port):
	"""T4 (P0-2, P0-4): a client that dribbles a request out over several TCP
	segments must still be handled as one request, and the upgrade response
	must survive the relay intact.

	This exercises the raw byte relay behind /ws-echo, i.e. DF_WS_WAITING and
	DF_TUNNEL -- axil forwards every byte untouched, so the payload comes back
	whatever framing the client used. It does NOT exercise axil's own frame
	layer: axil_ws_tunnel() installs no io hooks, so ws_read()/ws_write() are
	never called and no 126/127 length is decoded by axil. The 300- and
	70000-byte payloads are here to move real volume through the relay, not to
	cover the extended-length encodings (see PLAN.md 5.2)."""
	ok = True
	for size, form in ((300, "126"), (70000, "127")):
		sock, bsock = ws_connect(port)
		payload = bytes((i * 7 + 13) & 0xFF for i in range(size))
		head, mask, masked = build_frame(payload)
		# 1 byte, then the rest of the header plus part of the mask and
		# payload, then the remainder: every field is split mid-value.
		sock.sendall(head[:1])
		time.sleep(0.05)
		sock.sendall(head[1:] + mask + masked[:10])
		time.sleep(0.05)
		sock.sendall(masked[10:])
		ok = expect_echo(bsock, payload, "T4 split frame, %d-byte payload (%s form)" % (size, form)) and ok
		# the connection must still be usable afterwards
		follow = b"still-alive"
		send_frame(sock, follow)
		ok = expect_echo(bsock, follow, "T4 follow-up frame after %s-form split" % form) and ok
		sock.close()
	return ok


def test_large(port):
	"""T5a (P0-1, and the ws_write mirror of P0-2): a 100 KiB payload must
	survive the relay intact, without truncation at BUFSIZ or the 16 KiB input
	buffer.

	Again this is the raw byte relay, not axil's frame writer: a short write
	anywhere in the tunnel path would show up here, but ws_write()'s own
	length encoding is not what is under test (PLAN.md 5.2)."""
	sock, bsock = ws_connect(port, timeout=15)
	size = 100 * 1024
	payload = bytes((i * 31 + 7) & 0xFF for i in range(size))
	send_frame(sock, payload)
	ok = expect_echo(bsock, payload, "T5a 100 KiB frame round-trip")
	sock.close()
	return ok



def test_slowloris(port, count=20):
	"""T2 (P1-5): a client that sends a partial request head and then stalls
	must not block the single-threaded server.

	The synchronization is load-bearing: each stalled descriptor only stalls the
	event loop once, because after axil_read() drains it the descriptor is no
	longer readable. If the clients dribble in over time they land in different
	select() passes and the test can pass against the buggy code."""
	stalled = []
	for _ in range(count):
		s = socket.create_connection(("127.0.0.1", port), timeout=5)
		stalled.append(s)
	# every connection is now established; release all the partial heads at
	# once so they become readable in the same pass
	for s in stalled:
		s.sendall(b"GET / HTTP/1.1\r\n")
	# measure a normal request issued while all of them are stalled
	start = time.time()
	try:
		probe = socket.create_connection(("127.0.0.1", port), timeout=3)
		probe.settimeout(3)
		probe.sendall(
			b"GET /song/probe HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
		)
		data = b""
		while b"\r\n\r\n" not in data:
			chunk = probe.recv(4096)
			if not chunk:
				break
			data += chunk
		elapsed = time.time() - start
		probe.close()
	except OSError as exc:
		elapsed = time.time() - start
		print("FAIL T2 slowloris: probe failed after %.2fs (%s)" % (elapsed, exc))
		for s in stalled:
			s.close()
		return False
	for s in stalled:
		s.close()
	if b"200" not in data.split(b"\r\n", 1)[0]:
		print("FAIL T2 slowloris: probe did not get a response (%.2fs)" % elapsed)
		return False
	if elapsed > 0.2:
		print(
			"FAIL T2 slowloris: %d stalled clients delayed a normal request by "
			"%.2fs (want < 0.2s)" % (count, elapsed)
		)
		return False
	print("PASS T2 slowloris: %d stalled clients, probe answered in %.3fs" % (count, elapsed))
	return True


def main():
	if len(sys.argv) < 2:
		print("usage: test-ws.py <port> [--pty] [--split] [--large] [--slowloris]")
		return 2
	port = int(sys.argv[1])
	args = sys.argv[2:]
	use_pty = "--pty" in args

	# frame-layer regression tests, each on its own connection
	frame_tests = [
		("--split", test_split),
		("--large", test_large),
	]
	ran = False
	failed = 0
	for flag, fn in frame_tests:
		if flag in args:
			ran = True
			try:
				if not fn(port):
					failed += 1
			except Exception as exc:  # noqa: BLE001 - report and keep going
				print("FAIL %s: %s" % (flag, exc))
				failed += 1
	if "--slowloris" in args:
		ran = True
		if not test_slowloris(port):
			failed += 1
	if ran:
		print("ws-frame: %d failed" % failed if failed else "ws-frame ok")
		return 1 if failed else 0

	key_raw = os.urandom(16)
	key = base64.b64encode(key_raw).decode("ascii")
	accept = base64.b64encode(
		hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
	).decode("ascii")

	sock = socket.create_connection(("127.0.0.1", port), timeout=2)
	sock.settimeout(2)

	req = (
		"GET / HTTP/1.1\r\n"
		"Host: 127.0.0.1:%d\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"\r\n"
	) % (port, key)
	sock.sendall(req.encode("ascii"))
	resp, extra = recv_http_response(sock)
	if b"101" not in resp.split(b"\r\n", 1)[0]:
		print("handshake failed")
		return 1
	headers = resp.decode("iso-8859-1", errors="ignore").split("\r\n")
	accept_line = None
	for line in headers[1:]:
		if not line:
			break
		if ":" not in line:
			continue
		name, value = line.split(":", 1)
		if name.strip().lower() == "sec-websocket-accept":
			accept_line = value.strip()
			break
	if accept_line != accept:
		print("accept mismatch")
		return 1

	expected = [b"\xff\xfd\x1f", b"\xff\xfb\x01", b"\xff\xfc\x03"]
	found = [False, False, False]
	carry = b""
	deadline = time.time() + 2.5
	bsock = BufferedSocket(sock, extra)
	while time.time() < deadline and not all(found):
		try:
			frame = recv_frame(bsock)
		except socket.timeout:
			break
		if not frame:
			break
		_, opcode, payload = frame
		if opcode == 0x8:
			break
		data = carry + payload
		for i, exp in enumerate(expected):
			if exp in data:
				found[i] = True
			carry = data[-2:]

	if not all(found):
		print("telnet negotiation missing")
		return 1

	if use_pty:
		send_frame(sock, "sh\n", opcode=0x2)
		time.sleep(0.2)
		send_frame(sock, "echo AXIL_TEST\n", opcode=0x2)
		deadline = time.time() + 3.0
		seen = False
		buf = b""
		while time.time() < deadline:
			try:
				frame = recv_frame(bsock)
			except socket.timeout:
				break
			if not frame:
				break
			_, opcode, payload = frame
			if opcode == 0x8:
				break
			buf += payload
			if b"AXIL_TEST" in buf:
				seen = True
				break
		if not seen:
			print("pty output missing")
			return 1

	print("ws-mux ok")
	return 0


if __name__ == "__main__":
	sys.exit(main())
