## 1.4.0

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
