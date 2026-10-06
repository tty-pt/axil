## 1.5.0

- **Teardown is ungated: an unauthenticated connection is now cleaned up.**
  `axil_disconnect()` no longer requires `DF_AUTHENTICATED` and `axil_close()`
  no longer requires `DF_CONNECTED`. The two gates contradicted the documented
  contract ("fires whenever a descriptor is torn down") and their net effect
  was unauthenticated RCE as the server user: a connection that owned a PTY but
  was never authenticated — a raw telnet terminal, a non-upgraded `/tty` — was
  never cleaned up, so its PTY, live child and `mux_state` entry outlived it,
  the kernel recycled the fd number onto an unrelated request, and
  `axil_tty_input()` wrote that request's bytes straight into the leaked
  shell's PTY (the HTTP headers-as-commands symptom in SECURITY.md S5.4).
  Every hook now self-gates on the descriptors it does not own, which is what
  the header contract already required of them. The old leak mechanics are
  kept as a regression: an AUTHENTICATED PTY connection killed abruptly must
  still leave no live child, no PTY master, and clean HTTP on recycled fds.
- **Per-connection generation: `axil_generation()`.** `struct descr` grows a
  monotonic generation bumped on every accept, so fd-keyed module state can
  reject stale entries. axil-tty's `mux_state` and NAWS entry carry it and
  `mux_get()`/`mux_wsz_get()` refuse a mismatch — even a leaked entry is inert
  on a recycled descriptor, which closes the whole class rather than the one
  instance above.
- **`DF_AUTH_AUTO` (flag 4096): `-A` publishes an identity, it does not prove
  one.** `AXIL_AUTOAUTH` authenticates every connection as the server's own
  account, so under `-A` a name comparison cannot tell an asserted identity
  from a published one. The flag is set only by `AXIL_AUTOAUTH` (so it cannot
  survive descriptor reuse), `drop_priviledges()` refuses to spawn a child
  under it — a child would otherwise run as the operator while the request
  proved nothing — and any downstream authorization that trusts `REMOTE_USER`
  must refuse a descriptor carrying it (SECURITY.md S5.8).
- **`FD_VALID(fd)` before any `[FD_SETSIZE]` table.** One macro, checked
  before the first index rather than after the frame has already been touched,
  covering `descr_map`, `io`, `frame_map` and `ws_flags`; on Windows
  `socket_t` is the unsigned `SOCKET`, so `>= 0` would be a tautology and
  `INVALID_SOCKET` (~0) is rejected by the `< FD_SETSIZE` half. Accept now
  spells the sentinel out (`fd == INVALID_SOCKET || fd == 0`) instead of the
  `fd <= 0` test that never fires for an unsigned ~0, and every teardown path
  closes with `axil_sock_close()` (`closesocket()` on Winsock) instead of
  `close()` on a CRT fd.
- **Tests**: `test-auth`, `test.sh` and `test-ws.py` gain the teardown,
  recycled-fd, `DF_AUTH_AUTO` and `FD_VALID` assertions; `SECURITY.md` records
  S5.4 and S5.5.

## [1.4.0]

- **Renamed `libndc` → `axil`**: the `ndc_*` API and `include/ttypt/ndc.h` became `axil_*` / `include/ttypt/axil.h` (`ndc.pc` → `axil.pc`, lib renamed accordingly). XY hooks are now `axil_*` (`on_axil_exit`, `on_axil_vim`, `on_axil_command`, `on_axil_connect`, `on_axil_disconnect`, `on_axil_tick`, `on_axil_parse` in `include/ttypt/axil-xy.h`).
- **Unified request-parameter API**: `axil_req_param(fd, body, name, buf, len)` plus `_int`/`_bool` variants read a parameter from a URL-encoded form body or the query string in a single call (handles quoted values); `axil_param`/`axil_param_int`/`axil_param_bool` cover the query-string path, with support for special characters in the URL.
- **PUT, DELETE and HEAD support**: new `AXIL_PUT` / `AXIL_DELETE` / `AXIL_HEAD` request flags, `do_PUT`/`do_DELETE`/`do_HEAD` handlers, and `DF_HEAD` to suppress the response body.
- **Encoding helpers**: `axil_url_encode` / `axil_url_decode` (percent-encoding, `%XX` and `+`), `axil_json_escape`, and `axil_slugify` for URL/filesystem-safe slugs.
- **Static-file serving**: `axil_respond_file` / `axil_sendfile` with auto-detected MIME type, ETag validator headers derived from the file stat, and an mmap-backed `cache.allow` caching policy (OpenBSD-compatible).
- **Response conveniences**: `axil_respond_plain`/`axil_respond_json`/`axil_respond_json_ok`/`axil_respond_no_content`, `axil_redirect` (303).
- **Deferred responses**: `axil_respond_defer(fd, code)` sends status + headers now; the body is completed later from the event loop via `axil_respond_defer_finish`/`_done`/`_abort` (streaming and long-poll style responses).
- **Performance**: optimised header conversion, cached HTTP date strings, `TCP_NODELAY`, single-write responses.
- **Hardening**: audit fixes, expanded test suite, OpenBSD (`iconv`) build fix, `bmake` compatibility, and the `libqmap` → `libcorm` rename in the build.
- **TLS & HTTP/2 hardening**: teardown no longer calls `SSL_shutdown` (no `close_notify` on a dead peer); the HTTP/2 prior-knowledge preface (`PRI * HTTP/2.0`) is dropped, not treated as a GET; ALPN advertises `http/1.1` only (not a protocol freeze — add `h2` when HTTP/2 exists).

## [v1.4.1] - 2026-09-27

- **Non-blocking I/O correctness**: accepted sockets are non-blocking, but several paths still assumed a blocking read. A request head split across TCP segments is now held in per-descriptor state and resumed when the rest arrives, instead of being dispatched truncated and losing headers (`usleep()` is gone from the request path); `EAGAIN` is no longer confused with end-of-stream in the WebSocket proxy wait, the raw tunnel, or POST-body buffering, all three of which used to drop a healthy connection.
- **WebSocket frame layer**: payloads are heap-allocated to the length the frame declares rather than overflowing a fixed `BUFSIZ` buffer into neighbouring connections' state; extended 16/32/64-bit lengths are byte-swapped in both directions (the 64-bit write path used `htonl`, so a 2^33 frame encoded as length 0); a frame split across reads resumes instead of being discarded; peer-declared lengths are capped at 64 MB; `ws_write()` sends the header and payload separately instead of sizing a stack VLA from the caller's length; `frame_map` shrank from 8.4 MB to under 100 KB.
- **Request head**: any blank-line-terminated head is parsed instead of only GET/POST/HEAD/PUT/DELETE, so a registered `OPTIONS` (or any other) handler runs again; a head that grows past 64 KiB without a terminator is answered with `431 Request Header Fields Too Large` and the descriptor is freed, instead of being stashed on the connection indefinitely.
- **POST body**: buffering retries `EAGAIN` on the non-blocking socket (20 attempts, 500 us apart) instead of treating a short read as a disconnect, and only *stalls* count against that budget, so a body larger than 20 reads arrives whole instead of being silently truncated.
- **Handler body**: the body handed to an `axil_handler_t` is NUL-terminated at the declared `Content-Length`, at the end of the body rather than the end of the last read. `axil_handler_t` passes only a `char *` and axil exposes no content-length accessor, so `strlen(body)` was the only length a handler could get — and it returned the length of whatever the previous request had left in the shared buffer, or ran past the allocation when the tail held no NUL. A request without a `Content-Length` gets an empty body.
- **TLS accept**: `ssl_accept()` retries `SSL_ERROR_WANT_WRITE` as well as `SSL_ERROR_WANT_READ`; sockets are made non-blocking with the platform's own call (`ioctlsocket`/`ioctl`/`fcntl`) and without clobbering existing status flags.
- **WebSocket writes**: `ws_write()` sends the frame payload through `axil_low_write()`, so a partially written payload is buffered and retried like every other write.
- **Tests**: `proof.sh` reports T1-T8 individually (19 checks) and both runners refuse to run against a port another process already owns, kill every server they started on the way out, and check request bodies against a per-run token *and* the length a handler sees.
- **Static files**: `axil_respond_file()` now queues its body between `axil_respond_defer()` and `axil_respond_defer_done()` like `axil_sendfile()`, so it delivers the whole file instead of headers promising `Content-Length` with a 0-byte body.
- **Auth**: an unknown user now inherits the `axil_pw` identity deliberately rather than being resolved to uid 0, and `axil_disconnect()` fires for authenticated connections.
- **Docs**: `axil_auth()` returns 0 for a name the system knows and 1 for an unknown one. That return is **advisory** — nothing in-tree enforces it, since the platform auth hook returns `void` — so a caller wanting to reject an unknown name must check for itself. The unknown-user fallback to the `axil_pw` identity, the 8191-byte truncation of over-long names, and the `EBADF` descriptor bound are documented.
- **Security**: `axil_auth()` no longer leaves its `username` field unterminated when given a name at or past `BUFSIZ`; the over-read into adjacent descriptor state (including the `remaining` pointer) is gone. `axil_ws_read`/`write`/`printf`/`close` and `axil_auth` now reject descriptors outside `[0, FD_SETSIZE)`.

## [v1.1.0] - 2026-04-18

- **Breaking:** `ndc_handler_t` return type changed from `void` to `int`.
- **Breaking:** `on_ndc_init` XY hook removed.
- **Breaking:** XY hooks `on_ndc_vim`, `on_ndc_command`, `on_ndc_connect`, `on_ndc_disconnect`: `fd` parameter type changed from `int` to `socket_t`.
- **Breaking:** `DF_RESERVED = 64` renamed to `DF_TUNNEL = 64`.
- **Breaking:** `ndc_header(fd, key, value)` renamed to `ndc_header_set(fd, key, value)`.
- **Breaking:** `ndc_head(fd, code)` and `ndc_body(fd, body)` replaced by `ndc_respond(fd, code, body)`. Passing `NULL` body sends only the status line and headers, leaving the connection open for streaming.
- **Breaking:** `do_sh` removed from exported `ndc_cb_t` symbols.
- **Breaking:** `ndc_pty()` removed from public API.
- **New:** `ndc_ws_upstream_t` typedef and `ndc_ws_handler()` for registering WebSocket tunnel handlers.
- **New:** `ndc_ws_upgrade()`, `ndc_ws_write()`, `ndc_ws_read()`, `ndc_ws_close()`, `ndc_ws_printf()` — WebSocket I/O API.
- **New:** `ndc_header_get(fd, key, buf, buf_len)` — read an incoming request header by name.
- **New:** `ndc_query_parse(body)` / `ndc_query_param(name, buf, buf_len)` — URL-encoded form body parsing.
- **New:** `ndc_respond(fd, code, body)` — send HTTP status, accumulated headers, and optional body.
- **New:** `ndc_sendfile(fd, path)` — serve a static file with auto-detected MIME type.
- **New:** `ndc_status_text(code)` — get HTTP status text for a code.
- **New:** `ndc_config.max_body_size` field (0 = default 10 MB); configurable via `-B` CLI flag.
- **New:** `AXIL_AUTOAUTH = 32` server flag — auto-authenticate all WebSocket connections (dev/testing only).
- **New:** `DF_EXTERN = 512`, `DF_WS_WAITING = 128`, `DF_WS_PROXY_PENDING = 256` descriptor flags.
- **New weak hooks:** `ndc_fd_tick(fd)`, `ndc_parse(fd, input, nread)`.
- **New XY hooks:** `on_ndc_tick`, `on_ndc_parse`.
- **New (POSIX-only):** `ndc_fd_watch()`, `ndc_fd_unwatch()`, `ndc_fork_child_reset()`, `ndc_get_pw()`, `ndc_send_telnet_cmd()` / `TELNET_CMD()` macro.
- **New:** `ndc_clear_active()`.
- **New:** `ndc_register_handler()` now supports `:param` path patterns (e.g. `/items/:id`), exposing matched segments as `PATTERN_PARAM_<NAME>` environment variables.
- **Breaking:** Public headers moved to `ttypt/` subdirectory (e.g. `#include <ttypt/axil.h>`).
- **New:** Plugin modules can declare dependencies via `xy_deps[]` for the libxylem loader.
