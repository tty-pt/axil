#!/usr/bin/env python3
"""Send an HTTP request in two segments and print the response.

The request is cut after SPLIT_AT bytes, a delay passes, and the remainder is
sent. axil accepts sockets in non-blocking mode, so a request whose CRLFCRLF
terminator has not arrived must be held and resumed, not dispatched truncated.

usage:
  test-split.py PORT GET  /echo-header '' 37 0.05 'X-Probe: split-ok\r\n'
  test-split.py PORT POST /echo-body  hello-body

  test-split.py --big-head PORT [PAD_LINES]
  test-split.py --slow-body PORT [PATH] [TOTAL] [HEAD_GAP] [GAP] [PIECES]

--big-head sends a head that never terminates (no CRLFCRLF) and then *holds the
connection open*, printing whatever the server answers. A head over
MAX_REQUEST_HEAD must come back as 431. This mode exists because the shell+nc
version of the probe is not reproducible: nc loses the reply whenever the server
closes while the rest of the request is still queued in its receive buffer (the
kernel answers RST, which discards the response), and the timing of that race
cannot be pinned down from a shell loop. Holding the connection open here keeps
the 431 from being lost to that RST, and keeps the request in axil_read()'s
"head still growing" state, where MAX_REQUEST_HEAD is what ends it.

--slow-body POSTs TOTAL bytes in PIECES pieces, pausing HEAD_GAP seconds before
the body and GAP seconds between pieces. The pauses are what make the test
meaningful: buffer_post_body() runs on a non-blocking socket, so a body already
sitting in the socket buffer never exercises the EAGAIN path at all. Sending one
big body with curl therefore passes even with the pre-fix code, which treated a
short read exactly like a disconnect.

Keep the pauses short. The retry budget counts *server-side read attempts*, not
client pauses: the server sleeps 500 us per EAGAIN, so a 2 ms client gap costs it
~4 stalls and nine such gaps overrun the 20-stall budget. A 1 ms gap in front of
the body plus 4 sub-millisecond ones costs well under 10 stalls, and the pre-fix
code still dies on the first one.

--ws-ctl PORT PATH [PLEN] [OPCODE] sends one control frame (ping by default)
declaring PLEN bytes of payload and requires a 1002 close.
--ws-echo PORT PATH [N] [--split] [--close] [--unmask] [--send-only] is the
WebSocket frame client (SECURITY.md S0.2). It does the RFC 6455 handshake,
verifies Sec-WebSocket-Accept, sends N bytes as a real masked frame, and reads
the reply frame back. Flags:
  --split       send header and payload as two TCP segments with a pause, so
                ws_fill() has to loop and reassemble
  --close       send a close frame (opcode 8) instead of data. Requires the
                echo AND that no second frame follows it (S6.7: one Close per
                connection, or a browser fails with "Close received after close")
  --unmask      clear the MASK bit, which a server must reject (S6.3)
  --send-only   do not wait for a reply frame; just report that the frame went
                out. Needed for /ws-unwatched, where the server is *expected* to
                stay silent, and where a crash is the signal instead of a reply.

--ws-pair PORT PATH [BIG] is the ordering client (SECURITY.md S2). It sends one
frame and requires two frames back -- BIG bytes of "0123456789abcdef" then the
single byte "B" -- intact, in that order. The server writes both in one tick and
the first overflows its socket buffers, so this is the case where a frame header
sent on the raw socket instead of through the write queue either jumps the queue
or is lost to EAGAIN (finding 2). Prints frames=<sizes> and ws=ok|BAD(...).

--ws-leak PORT PATH [ITERS] [DECLARED] is the S5.4 memory client. Each of ITERS
connections sends a small complete frame, which the server echoes, then a
127-form header declaring DECLARED bytes (8 MiB by default) with a little payload
and no end, then one more byte that makes the server close the connection with
the frame half-read. It requires the echo on every connection and the server-side
close on every connection, and prints armed, closed and ws=ok|BAD(...). It only
creates the condition: the retained payload is asserted from a valgrind log by
proof.sh, because the leak is not reliably observable from outside the server.
See ws_leak() for the three in-process observables that do not work.

Output is key=value lines for the shell to assert on: handshake, accept, sent,
recv, echo, ws. The payload deliberately contains NUL bytes and a per-run tail
token, so an echo compared with strlen() instead of the frame length is caught.
"""
import base64
import hashlib
import os
import socket
import struct
import sys
import time


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_OP_CONT = 0x0
WS_OP_TEXT = 0x1
WS_OP_BIN = 0x2
WS_OP_CLOSE = 0x8
WS_OP_PING = 0x9
WS_OP_PONG = 0xA


def _ws_payload(n):
    """Deterministic, non-repeating bytes with a per-run tail token.

    Includes NULs on purpose: the server must echo `axil_ws_read`'s return
    value, not strlen() of the buffer, or the round trip comes back short.
    """
    tail = f"axil{os.getpid()}{int(time.time() * 1000) % 100000:05d}".encode()
    if n <= len(tail):
        return tail[:n]
    head = bytes((i * 7 + 11) % 256 for i in range(n - len(tail)))
    return head + tail


def _ws_frame(opcode, payload, fin=True, mask=True):
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(payload)
    # The MASK bit lives in the second header byte. It was never set here: the
    # key was prepended and the payload XORed, but the length byte carried no
    # 0x80, so every "masked" frame this client sent was a protocol violation
    # (RFC 6455 5.1). Two server bugs hid it -- the key was read
    # unconditionally, and the MASK bit was never tested -- and S6.3 closed both,
    # which turned the whole T9 suite red at once.
    m = 0x80 if mask else 0
    if n < 126:
        hdr = struct.pack("!BB", b0, n | m)
    elif n < (1 << 16):
        hdr = struct.pack("!BBH", b0, 126 | m, n)
    else:
        hdr = struct.pack("!BBQ", b0, 127 | m, n)
    if not mask:
        return hdr + payload
    key = os.urandom(4)
    return hdr + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


class WsConn:
    """Minimal client: a read buffer for handshake leftovers plus frame reads."""

    def __init__(self, sock):
        self.sock = sock
        self.leftover = b""

    def _exact(self, n):
        while len(self.leftover) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(f"closed: wanted {n} bytes, have {len(self.leftover)}")
            self.leftover += chunk
        out, self.leftover = self.leftover[:n], self.leftover[n:]
        return out

    def handshake(self, port, path):
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(
            (f"GET {path} HTTP/1.1\r\n"
             f"Host: 127.0.0.1:{port}\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\n"
             "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        while b"\r\n\r\n" not in self.leftover:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("closed during handshake")
            self.leftover += chunk
        head, self.leftover = self.leftover.split(b"\r\n\r\n", 1)
        head = head.decode("utf-8", "replace")
        status = head.split("\r\n", 1)[0]
        code = status.split()[1] if len(status.split()) > 1 else "000"
        expect = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        got = ""
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith("sec-websocket-accept:"):
                got = line.split(":", 1)[1].strip()
        return code, ("ok" if got == expect else f"BAD({got!r})")

    def read_frame(self):
        b0, b1 = self._exact(2)
        fin, opcode, masked = bool(b0 & 0x80), b0 & 0x0F, bool(b1 & 0x80)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._exact(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self._exact(8))[0]
        key = self._exact(4) if masked else None
        payload = self._exact(n) if n else b""
        if key:
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        return fin, opcode, masked, payload


def _print_ws(out):
    for k in ("handshake", "accept", "sent", "recv", "close", "second", "echo", "ws"):
        if k in out:
            print(f"{k}={out[k]}")


def ws_echo(port, path, size, do_split, do_close, do_unmask, send_only):
    if do_close:
        payload, opcode = struct.pack("!H", 1000), WS_OP_CLOSE
    else:
        payload, opcode = _ws_payload(size), WS_OP_BIN
    frame = _ws_frame(opcode, payload, mask=not do_unmask)

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10)
    out = {}
    try:
        conn = WsConn(sock)
        code, accept = conn.handshake(port, path)
        out["handshake"] = code
        out["accept"] = accept
        if code != "101" or accept != "ok":
            _print_ws(out)
            return 1

        if do_split:
            # Cut inside the header so ws_fill() sees a partial frame.
            cut = 2
            sock.sendall(frame[:cut])
            time.sleep(0.05)
            sock.sendall(frame[cut:])
        else:
            sock.sendall(frame)
        out["sent"] = (f"op:{opcode} len:{len(payload)} "
                       f"fin:1 masked:{0 if do_unmask else 1}")

        if send_only:
            # No reply is expected; a clean send is all we can observe. Linger
            # so the server's next select() pass still has a live connection:
            # exiting at once can close the socket before the tick, and the
            # server then reads EOF instead of the frame (S6.2).
            time.sleep(0.4)
            out["ws"] = "sent"
        elif do_close:
            # S6.6: RFC 6455 5.5.1 requires a close frame *back* when a peer
            # receives one, before the connection goes away. ws_read() used to
            # swallow it -- reset, return 0, nothing written -- so the client
            # waited out its own close timeout for a reply that never came.
            #
            # This branch used to accept a close echo, a clean EOF *or* silence
            # and then set ws=ok unconditionally, which made the `16:--close`
            # entry in both runners a check that could not fail: it passed
            # against the unfixed server. Silence and EOF are exactly the
            # pre-fix behaviour, so both are failures now, and only a close
            # carrying 1000 passes.
            try:
                fin, op, masked, body = conn.read_frame()
                out["recv"] = (f"op:{op} len:{len(body)} "
                               f"fin:{int(fin)} masked:{int(masked)}")
                if op == WS_OP_CLOSE and len(body) == 2:
                    status = struct.unpack("!H", body)[0]
                    out["close"] = f"{status}"
                    out["ws"] = "ok" if status == 1000 else f"BAD(code:{status})"
                else:
                    out["close"] = "none"
                    out["ws"] = f"BAD(op:{op} len:{len(body)})"
            except (socket.timeout, TimeoutError):
                out["close"] = "silent"
                out["ws"] = "BAD(silent)"
            except EOFError:
                out["close"] = "eof"
                out["ws"] = "BAD(eof-without-close-echo)"

            # S6.7: exactly one Close frame. The echo in ws_read() and the
            # teardown in axil_close()/axil_ws_close() are separate calls on the
            # same fd, so the server used to send the close twice; a browser
            # reports the second as "Close received after close" and fails the
            # socket. Once the echo has been read the peer must send nothing
            # more: a second frame fails, EOF -- or the read timing out with the
            # connection still open -- is correct.
            if str(out.get("close", "")).isdigit():
                sock.settimeout(1.0)
                try:
                    _fin2, op2, _masked2, body2 = conn.read_frame()
                    out["second"] = (f"close:{struct.unpack('!H', body2)[0]}"
                                     if op2 == WS_OP_CLOSE and len(body2) == 2
                                     else f"op:{op2}")
                    out["ws"] = f"BAD(second-frame:{out['second']})"
                except (socket.timeout, TimeoutError):
                    out["second"] = "none"
                except EOFError:
                    out["second"] = "none"
        elif do_unmask:
            # S6.3: an unmasked client frame is a protocol error. The 4-byte
            # mask key used to be read before the MASK bit was tested, so the
            # server consumed 4 payload bytes as a key and then waited forever
            # for 4 more: the tick never progressed, nothing was reclaimed, and
            # the client saw silence until its own timeout. The server must
            # answer with a close carrying 1002 instead. Silence here is the
            # pre-fix behaviour, so a timeout is a failure, not a pass.
            try:
                fin, op, masked, body = conn.read_frame()
                out["recv"] = (f"op:{op} len:{len(body)} "
                               f"fin:{int(fin)} masked:{int(masked)}")
                if op == WS_OP_CLOSE and len(body) == 2:
                    code = struct.unpack("!H", body)[0]
                    out["close"] = f"{code}"
                    out["ws"] = "ok" if code == 1002 else f"BAD(code:{code})"
                else:
                    out["ws"] = f"BAD(op:{op})"
            except (socket.timeout, TimeoutError):
                out["close"] = "silent"
                out["ws"] = "BAD(silent)"
            except EOFError:
                out["close"] = "eof"
                out["ws"] = "BAD(eof-without-1002)"
        else:
            fin, op, masked, body = conn.read_frame()
            out["recv"] = f"op:{op} len:{len(body)} fin:{int(fin)} masked:{int(masked)}"
            out["echo"] = "ok" if body == payload else "BAD"
            out["ws"] = "ok" if (op == WS_OP_BIN and body == payload) else "BAD"
    finally:
        sock.close()

    _print_ws(out)
    return 0 if out.get("ws") in ("ok", "sent") else 1


def ws_ctl(port, path, plen, opcode):
    """S6.4: a control frame must declare at most 125 bytes of payload.

    RFC 6455 5.5 fixes that limit precisely because a control frame is never
    fragmented: allowing a long one would let a peer interleave a "control"
    frame inside a fragmented message. The old parser imposed no limit at all,
    so a ping declaring 200 bytes was read as an ordinary data frame, unmasked,
    handed to the caller as application data and echoed back.

    The point of the assertion is what the server does *instead*. Pre-fix, the
    first frame to arrive is a 200-byte echo. Post-fix it must be a close
    carrying 1002, so reading a single frame and requiring the close is enough to
    distinguish the two -- an echo that arrived first fails on the opcode.

    `plen` 126 and 127 are the interesting values, not 200: they are the two
    length forms a control frame is forbidden to use, and they are also what a
    *close* frame used to slip through, since the opcode 8 branch returned
    before the extended length was read.
    """
    payload = b"C" * plen
    frame = _ws_frame(opcode, payload)

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10)
    out = {}
    try:
        conn = WsConn(sock)
        code, accept = conn.handshake(port, path)
        out["handshake"] = code
        out["accept"] = accept
        if code != "101" or accept != "ok":
            _print_ws(out)
            return 1

        sock.sendall(frame)
        out["sent"] = f"op:{opcode} len:{plen} control:1"

        try:
            fin, op, masked, body = conn.read_frame()
            out["recv"] = (f"op:{op} len:{len(body)} "
                           f"fin:{int(fin)} masked:{int(masked)}")
            if op == WS_OP_CLOSE and len(body) == 2:
                status = struct.unpack("!H", body)[0]
                out["close"] = f"{status}"
                out["ws"] = "ok" if status == 1002 else f"BAD(code:{status})"
            elif op == opcode and len(body) == plen:
                # The pre-fix behaviour: the oversized control frame was
                # accepted as data and echoed back.
                out["close"] = "none"
                out["ws"] = f"BAD(echoed {len(body)}B as op:{op})"
            else:
                out["close"] = "none"
                out["ws"] = f"BAD(op:{op} len:{len(body)})"
        except (socket.timeout, TimeoutError):
            out["close"] = "silent"
            out["ws"] = "BAD(silent)"
        except EOFError:
            out["close"] = "eof"
            out["ws"] = "BAD(eof-without-1002)"
    finally:
        sock.close()

    _print_ws(out)
    return 0 if out.get("ws") == "ok" else 1


def ws_pair(port, path, big):
    """S2: require two frames back, intact and in order, from one request.

    The server answers with a `big`-byte frame and then a 1-byte frame, both in
    one tick. Anything less than both frames arriving means a frame was lost;
    anything out of order or misparsed means the stream desynchronised. Reading
    in small chunks with a pause keeps the write queue draining in stages, which
    is the state the ordering violation lives in.
    """
    want_big = (b"0123456789abcdef" * (big // 16 + 1))[:big]

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    sock.settimeout(10)
    out = {}
    try:
        conn = WsConn(sock)
        code, accept = conn.handshake(port, path)
        out["handshake"] = code
        out["accept"] = accept
        if code != "101" or accept != "ok":
            _print_ws(out)
            return 1

        sock.sendall(_ws_frame(WS_OP_BIN, b"go", mask=True))
        out["sent"] = "op:2 len:2"

        # Keep the receive window small so the server's queue drains gradually
        # rather than in one gulp.
        frames = []
        try:
            while len(frames) < 2:
                frames.append(conn.read_frame()[3])
                time.sleep(0.02)
        except (socket.timeout, TimeoutError):
            out["timeout"] = f"after {len(frames)} frame(s)"
        except EOFError:
            out["eof"] = f"after {len(frames)} frame(s)"

        out["frames"] = ",".join(str(len(f)) for f in frames)
        # Check frame 1 first: if the header of frame 2 jumped the queue, frame 1
        # is already corrupt, and "lost frame" would hide that.
        if not frames:
            out["ws"] = "BAD(no frame)"
        elif frames[0] != want_big:
            out["ws"] = f"BAD(frame1 {len(frames[0])}B != {big}B)"
        elif len(frames) < 2:
            out["ws"] = "BAD(lost frame2)"
        elif frames[1] != b"B":
            out["ws"] = f"BAD(frame2 {frames[1]!r})"
        else:
            out["ws"] = "ok"
    finally:
        sock.close()

    _print_ws(out)
    for k in ("frames", "timeout", "eof", "ws"):
        if k in out:
            print(f"{k}={out[k]}")
    return 0 if out.get("ws") == "ok" else 1


def ws_printf(port, path, want, bufsiz):
    """S4.3: a printf larger than the internal BUFSIZ buffer.

    The server formats `want` bytes through axil_ws_printf(), whose destination
    is a `static char buf[BUFSIZ]`. Two things must hold: the frame must carry at
    most BUFSIZ-1 bytes (clamping, not trusting vsnprintf's would-be length,
    which is finding 4), and the frame must have FIN set (ws_dprintf used `&`
    where it meant `|`, so every printf emitted a continuation frame --
    finding 10). Content is checked byte for byte, so a read past the buffer
    cannot pass by accident.
    """
    pattern = b"0123456789abcdef"
    sent = str(want).encode()
    expect_len = min(want, bufsiz - 1)
    expect = (pattern * (expect_len // 16 + 1))[:expect_len]

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10)
    out = {}
    try:
        conn = WsConn(sock)
        code, accept = conn.handshake(port, path)
        out["handshake"] = code
        out["accept"] = accept
        if code != "101" or accept != "ok":
            _print_ws(out)
            return 1

        sock.sendall(_ws_frame(WS_OP_BIN, sent, mask=True))
        out["sent"] = f"op:{WS_OP_BIN} len:{len(sent)}"

        fin, op, masked, body = conn.read_frame()
        out["recv"] = f"op:{op} len:{len(body)} fin:{int(fin)} masked:{int(masked)}"
        out["want_len"] = expect_len
        if len(body) != expect_len:
            out["ws"] = f"BAD(len {len(body)} != {expect_len})"
        elif not fin:
            out["ws"] = "BAD(fin=0, continuation frame)"
        elif body != expect:
            out["ws"] = "BAD(content)"
        else:
            out["ws"] = "ok"
    finally:
        sock.close()

    _print_ws(out)
    for k in ("recv", "want_len", "ws"):
        if k in out:
            print(f"{k}={out[k]}")
    return 0 if out.get("ws") == "ok" else 1


def _drain(sock):
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def slow_body(port, path, total, head_gap, gap, pieces):
    # The last bytes of the body are a per-run token, also sent as X-Body-Tail.
    # The server compares the two at the declared offset, which is the only
    # reliable completeness check: the body pointer is not NUL-terminated, so
    # strlen() on it also counts the previous request's leftovers.
    tail = f"axil{os.getpid()}{int(time.time() * 1000) % 100000:05d}".encode()
    total = max(total, len(tail) + 16)
    body = b"B" * (total - len(tail)) + tail
    head = (
        f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"X-Body-Tail: {tail.decode()}\r\n"
        f"Content-Length: {total}\r\nConnection: close\r\n\r\n"
    ).encode()

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10)
    try:
        sock.sendall(head)
        # The gap in front of the body is the one that matters: the server
        # dispatches as soon as the head is complete, so it is already waiting
        # on an empty buffer here.
        time.sleep(head_gap)
        step = max(1, total // max(1, pieces))
        for off in range(0, total, step):
            sock.sendall(body[off:off + step])
            if off + step < total:
                time.sleep(gap)
        out = _drain(sock)
    finally:
        sock.close()

    sys.stdout.write(out.decode("utf-8", "replace"))
    return 0


def big_head(port, pad_lines):
    head = "GET /echo-header HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    for i in range(pad_lines):
        head += f"X-Pad-{i:04d}: {'a' * 36}\r\n"
    raw = head.encode()
    assert b"\r\n\r\n" not in raw

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(5)
    chunks = []
    try:
        sock.sendall(raw)
        # No terminator: whatever comes back is the server's decision about the
        # partial head, not a dispatch triggered by our own close.
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            break
    finally:
        sock.close()

    sys.stdout.write(b"".join(chunks).decode("utf-8", "replace"))
    return 0


def ws_leak(port, path, iters, declared):
    """S5.4: park a frame payload, then abandon it with a server-side close.

    This client only *creates the condition*; the runner asserts the leak from a
    valgrind log, because the condition is not reliably observable from outside
    the server. Three attempts at an in-process observable were wrong:

    * LeakSanitizer cannot see it. frame_map is a global, so a retained
      frame->data is still *reachable* at exit, and LSan reports unreachable
      blocks only. The plan's "ASan's leak check must stay quiet" passes against
      the unfixed code, which is worse than no proof.
    * Counting large mappings in /proc/PID/maps under-reports: the kernel merges
      adjacent anonymous VMAs, so three retained payloads showed up as one
      region, and a per-fd reuse pattern hides it entirely (below).
    * VmRSS cannot see it either: a declared-but-unwritten 64 MiB malloc is
      untouched mmap space. Making the server dirty the payload means racing its
      tick, and the tick closes as soon as it sees EAGAIN, so most of the payload
      is never read. Measured 3 MiB resident where 16 MiB was expected.

    valgrind reports "still reachable" and is not fooled by any of that.

    Per connection: a small complete frame, which the server echoes, then a
    127-form header declaring DECLARED bytes plus a little payload. The echo is
    the synchronisation point -- it proves the server parsed a frame, which is
    what arms /ws-leak's close -- and the trailing byte sent afterwards is the
    readable event that makes the armed tick close the connection with the big
    frame still incomplete. That server-side close is the only transition that
    orphaned frame->data: a client disconnect instead makes the next tick
    observe EOF, and ws_read()'s eof path already reset the frame.

    All ITERS connections run to completion one at a time, which is fine here
    precisely because the retained payload is self-limiting -- ws_init() has
    always called ws_frame_reset(), so a later connection reusing that fd number
    frees the previous payload. Only valgrind sees the leak before that reuse.
    """
    out = {"declared": declared, "iter": iters}

    for i in range(iters):
        sock = socket.create_connection(("127.0.0.1", port), timeout=15)
        sock.settimeout(15)
        try:
            conn = WsConn(sock)
            code, accept = conn.handshake(port, path)
            if code != "101" or accept != "ok":
                out["ws"] = "BAD(handshake %s/%s)" % (code, accept)
                _print_ws(out)
                return 1

            warm = b"warmup"
            key = b"\x01\x02\x03\x04"
            chunk = os.urandom(4096)
            masked = bytes(b ^ key[j % 4] for j, b in enumerate(chunk))
            # One write: the complete frame, then the incomplete 127-form
            # header, then a little of its payload. The server reads the first
            # frame, echoes it and arms; the rest is left half-read.
            sock.sendall(_ws_frame(WS_OP_BIN, warm, mask=True) +
                         struct.pack("!BBQ", 0x80 | WS_OP_BIN, 127, declared) +
                         key + masked)

            fin, op, got_mask, body = conn.read_frame()
            if body != warm:
                out["ws"] = "BAD(warmup echo %r)" % (body,)
                _print_ws(out)
                return 1
            out["armed"] = i + 1

            # The readable event that makes the armed tick close. The frame is
            # still incomplete, so this never completes it.
            sock.sendall(b"\x00")
            sock.settimeout(5)
            try:
                while True:
                    if not conn.sock.recv(4096):
                        break
            except socket.timeout:
                out["ws"] = "BAD(conn %d not closed by the server)" % (i + 1)
                _print_ws(out)
                return 1
            except OSError:
                pass  # RST after the server closed: the close still happened
        finally:
            sock.close()

    out["closed"] = iters
    out["ws"] = "ok"
    _print_ws(out)
    for k in ("declared", "iter", "armed", "closed", "ws"):
        if k in out:
            print("%s=%s" % (k, out[k]))
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--ws-leak":
        port = int(sys.argv[2])
        path = sys.argv[3] if len(sys.argv) > 3 else "/ws-leak"
        pid = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        iters = int(sys.argv[5]) if len(sys.argv) > 5 else 3
        declared = int(sys.argv[6]) if len(sys.argv) > 6 else (8 * 1024 * 1024)
        return ws_leak(port, path, iters, declared)

    if len(sys.argv) > 1 and sys.argv[1] == "--ws-echo":
        port = int(sys.argv[2])
        path = sys.argv[3] if len(sys.argv) > 3 else "/ws-frames"
        rest = sys.argv[4:]
        # The first bare number is the payload size; the rest are flags.
        size = next((int(a) for a in rest if not a.startswith("-")), 16)
        flags = {a for a in rest if a.startswith("-")}
        return ws_echo(port, path, size, "--split" in flags, "--close" in flags,
                       "--unmask" in flags, "--send-only" in flags)

    if len(sys.argv) > 1 and sys.argv[1] == "--ws-ctl":
        port = int(sys.argv[2])
        path = sys.argv[3] if len(sys.argv) > 3 else "/ws-frames"
        plen = int(sys.argv[4]) if len(sys.argv) > 4 else 200
        opcode = int(sys.argv[5]) if len(sys.argv) > 5 else WS_OP_PING
        return ws_ctl(port, path, plen, opcode)

    if len(sys.argv) > 1 and sys.argv[1] == "--ws-pair":
        port = int(sys.argv[2])
        path = sys.argv[3] if len(sys.argv) > 3 else "/ws-pair"
        big = int(sys.argv[4]) if len(sys.argv) > 4 else 131072
        return ws_pair(port, path, big)

    if len(sys.argv) > 1 and sys.argv[1] == "--ws-printf":
        port = int(sys.argv[2])
        path = sys.argv[3] if len(sys.argv) > 3 else "/ws-printf"
        want = int(sys.argv[4]) if len(sys.argv) > 4 else 20000
        bufsiz = int(sys.argv[5]) if len(sys.argv) > 5 else 8192
        return ws_printf(port, path, want, bufsiz)

    if len(sys.argv) > 1 and sys.argv[1] == "--big-head":
        port = int(sys.argv[2])
        pad = int(sys.argv[3]) if len(sys.argv) > 3 else 1600
        return big_head(port, pad)

    if len(sys.argv) > 1 and sys.argv[1] == "--slow-body":
        port = int(sys.argv[2])
        path = sys.argv[3] if len(sys.argv) > 3 else "/echo-size"
        total = int(sys.argv[4]) if len(sys.argv) > 4 else 65536
        head_gap = float(sys.argv[5]) if len(sys.argv) > 5 else 0.001
        gap = float(sys.argv[6]) if len(sys.argv) > 6 else 0.0005
        pieces = int(sys.argv[7]) if len(sys.argv) > 7 else 4
        return slow_body(port, path, total, head_gap, gap, pieces)

    port = int(sys.argv[1])
    method = sys.argv[2]
    path = sys.argv[3]
    body = sys.argv[4] if len(sys.argv) > 4 else ""
    split_at = int(sys.argv[5]) if len(sys.argv) > 5 else 7
    delay = float(sys.argv[6]) if len(sys.argv) > 6 else 0.05
    extra = sys.argv[7] if len(sys.argv) > 7 else ""

    head = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    if extra:
        head += extra
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    head += "Connection: close\r\n\r\n"
    raw = head.encode() + body.encode()

    if split_at < 1 or split_at >= len(raw):
        sys.stderr.write("split_at out of range\n")
        return 2

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(10)
    try:
        sock.sendall(raw[:split_at])
        time.sleep(delay)
        sock.sendall(raw[split_at:])

        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()

    sys.stdout.write(b"".join(chunks).decode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
