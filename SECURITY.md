# axil SECURITY.md — numbered findings

The S-series numbers below continue the external audit series already cited in
the tree (`S0.1` … `S7.2`). Findings S5.4 and S5.5 are recorded here because the
code cites them; earlier entries in the series live with the audit, not here.

## S5.4 — fd-keyed PTY state + doubly-gated disconnect hook → unauthenticated RCE

**Status:** fixed (Layers 1–3 below), regression-covered by `axil-nd/test.sh` §S5.4.

A PTY and its spawned `sh` live in axil-tty's `struct mux_state`, keyed by raw
file-descriptor number in a process-global map (`mux_get()`,
`external/axil-tty/src/libaxil-tty.c`). The teardown hook was gated twice:

- `axil_close()` called `axil_disconnect()` only for `DF_CONNECTED`
  (`src/libaxil.c`), which is set solely by a WebSocket upgrade or `axil_auth()`;
- `axil_disconnect()` itself returned early without `DF_AUTHENTICATED (`src/axil.c`).

A connection that owned a PTY but was never authenticated — a raw telnet
terminal, a non-upgraded `/tty` request — was therefore never cleaned up: PTY,
live child, and map entry all outlived it. The kernel then recycled the
descriptor number to an unrelated request (normally a site HTTP request), and
`axil_tty_input()` wrote that request into the leaked shell's PTY and returned
`-1` so axil skipped dispatching it. Observed wire symptoms: the client's own
request echoed back, every `\r\n` doubled to `\r\n\r\n` (ICRNL then ONLCR),
`\x1b[?2004l`, a shell prompt, and `command not found` — the shell executing
HTTP headers as commands, i.e. command execution as the server user to whoever
wins descriptor allocation.

Both gates contradicted the documented contract (`include/ttypt/axil.h`:
"fires whenever a descriptor is torn down").

**Fix, in order:**

1. **Layer 1 (the fix):** both gates removed. Every hook implementation already
   self-gates for descriptors it does not own, which is what the header contract
   requires of them.
2. **Layer 2 (closes the class):** `struct descr.generation`, bumped per accept
   (`src/axil-internal.h`, `src/libaxil.c`), exposed as `axil_generation()`
   (`include/ttypt/axil.h`). `mux_state` and the NAWS entry carry it;
   `mux_get()`/`mux_wsz_get()` refuse a mismatch, so even a leaked entry is
   inert on a recycled fd.
3. **Layer 3 (fail loud):** `axil_tty_input()` logs PTY handover under
   `AXIL_TTY_TRACE` instead of doing it silently.

A residual is deliberately left open: axil never `waitpid()`s a PTY child (the
single `waitpid()` in the tree covers command exec), so a correctly-killed shell
lingers as a zombie — PID-table pressure, not a security issue, since a zombie
holds no PTY and no descriptors.

## S5.5 — telnet option processing applied to HTTP request bytes

**Status:** fixed, regression-covered by `axil-nd/test.sh` §S5.5 and the site
`song-add-invalid-utf8` e2e.

Every read chunk passes through `on_axil_parse` before dispatch, and
`axil_tty_input()` scanned the *whole* chunk — head plus body — for `0xFF`.
A body byte of `0xFF` (legal in e.g. a multipart title) was read as IAC, the
"consume `i` bytes" return made nd slide the request head off the front of the
input, and the RAW check then answered the POST with the telnet banner. The
client saw `ff fc 01 … "Connect with: connect <name>"` where an HTTP status
belonged ("invalid HTTP version parsed").

**Fix:** a chunk that opens with an HTTP request line passes through untouched
— no IAC scan, no slide, no RAW classification (`on_axil_parse` in
`external/axil-nd/src/libaxil-nd.c`; same gate for non-WebSocket connections in
axil-tty's own `on_axil_parse`). WebSocket frame payloads are exempt in axil-tty
because shell bytes ride frames and must still reach the PTY. Segmented bodies
never reach the hooks at all (`buffer_post_body()` reads them directly), so the
single-chunk case was the whole bug.
