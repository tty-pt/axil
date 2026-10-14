# axil SECURITY.md — numbered findings

The S-series numbers below continue the external audit series already cited in
the tree (`S0.1` … `S7.2`). Findings S5.4 and S5.5 are recorded here because the
code cites them; earlier entries in the series live with the audit, not here.

## S5.4 — fd-keyed PTY state + doubly-gated disconnect hook → unauthenticated RCE

**Status:** fixed (Layers 1–3 below). Re-scoped: an unauthenticated terminal no
longer spawns a shell at all — it is refused before the PTY is born
(S5.6–S5.8) — so the original shape (spawn-then-check-cleanup on an anonymous
connection) cannot exist any more. What the regression still covers, in
`axil-nd/test.sh` §S5.4 and `axil-tty/test.sh`:
- the new property: an unauthenticated `/tty` yields no PTY, no child, no
  output — only a refusal line, a close, and a log entry;
- the retained regression: an AUTHENTICATED PTY connection, killed abruptly,
  still cleans up (no live child, no PTY master), and recycled fds still serve
  clean HTTP.

The leak mechanics below are unchanged history: they describe what the old
code did, and why the teardown must stay ungated even though nothing
unauthenticated can hold a PTY any more.

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

## S5.6 — `axil_get_pw` substitutes the server's identity for strangers

**Status:** fixed in axil-tty (identity resolved fresh per request, never from
`axil_get_pw`); guarded in axil core (`drop_priviledges` refuses `-A`).

`axil_auth()` (`src/axil-posix.c`) marks every connection `DF_AUTHENTICATED` —
even for a name `getpwnam()` does not know, in which case it copies the
server's own entry over the descriptor — and `axil_get_pw()` hands that entry
back for any *un*authenticated descriptor. Three places in axil-tty treated the
substitution as the caller's identity: `drop_priviledges()` fell back to the
server-user entry, the PTY child re-queried it and fell back again, and an
empty `pw_shell` became `"/bin/sh"`. No-shell accounts (`/bin/false`, empty)
were inexpressible: every path led to a real shell as the server user.

The substitution itself stays (it is documented in `axil.h`, and genuinely
unauthenticated callers such as proxy upstreams have no other identity). What
changed is who may consult it: terminal spawning resolves the identity itself
— `-A` flag clear, `REMOTE_USER` set, `getpwnam()` hit, real shell — and
anything else is refused before any allocation. Axil core's second
`drop_priviledges` (same file, reached from `popen2()`) refuses a
`-A`-published identity for the same reason rather than running a child under
a published name.

## S5.7 — `do_man` path traversal and flag injection

**Status:** fixed, regression-covered by `axil-nd/test.sh` (traversal,
`--pager=`, `-K` all refused).

`do_man()` (`external/axil-nd/src/world.c`, shared by `man` and `help`) passed
its topic into two `execve` argument vectors: interpolated into
`man/<topic>.10` for `man -l` (which preprocesses through `cat`: an
arbitrary-file read bounded only by the `.10` suffix), and, when that file was
absent, as a bare positional to `man` (a leading dash made it a flag: `-K`,
`--pager=`). Topics containing `/` or `..` or beginning with `-` are now
refused before any spawn — legitimate topics are bare command names.

## S5.8 — `-A` publishes the operator's identity to every connection

**Status:** contained by provenance flag `DF_AUTH_AUTO`, regression-covered by
`external/axil/test.sh` (set under `-A` after upgrade, clear otherwise,
pre-existing flag bits preserved) and the refusal suites.

Under `AXIL_AUTOAUTH`, `axil_connect()` authenticates every WebSocket upgrade
as the server's own account. `DF_AUTHENTICATED` alone therefore cannot
distinguish a proven identity from a published one — and neither can a name
comparison, because the published name literally IS the operator's own passwd
name. `DF_AUTH_AUTO` (`include/ttypt/axil.h`) marks descriptors whose identity
came from `-A`; it is set in the library upgrade path (so library-linked hosts
get it too, not just the axil binary's weak `axil_connect`), preserved across
the assigning `axil_set_flags()`, and cleared on accept with everything else
so it cannot survive fd reuse. Terminal spawning refuses it with its own
message; it is never merely one factor among others.
