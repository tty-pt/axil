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


def main():
	if len(sys.argv) < 2:
		print("usage: test-ws.py <port> [--pty]")
		return 2
	port = int(sys.argv[1])
	use_pty = "--pty" in sys.argv[2:]
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
