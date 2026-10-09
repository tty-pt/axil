#!/bin/sh
# Per-test proof runner: exercises T1/T2/T3/T4/T5a/T6/T8 (routes) and T7 (auth)
# and prints a PASS/FAIL line for each, instead of exiting on the first failure
# like test.sh does. Build the tree first, then: sh proof.sh
set -u
export LD_LIBRARY_PATH=./lib:${LD_LIBRARY_PATH:-}

testroutes=./bin/test-routes
testauth=./bin/test-auth
port=${1:-$((19000 + $$ % 500))}

pass=0
fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }

need_nc=0
need_py=0
command -v python3 >/dev/null 2>&1 || need_py=1
command -v nc >/dev/null 2>&1 || need_nc=1

# /ws-echo is POSIX-only: test-routes.c guards its fork()/socketpair()/OpenSSL
# upstream child with #ifndef _WIN32.
case "$(uname -s)" in
MinGW* | MSYS* | MINGW* | Windows* | CYGWIN*) ws_posix=0 ;;
*) ws_posix=1 ;;
esac

fetch_header_value() {
	curl -sS -i --max-time 5 "http://127.0.0.1:$1$2" | tr -d '\r' |
		grep -i "^$3:" | sed 's/^[^:]*: *//' | head -n1
}

# ------------------------------------------------- server lifetime / ports ---
# A server left behind by an earlier run keeps its port, and its config dir has
# usually been deleted. A later run that picks the same port cannot bind, exits,
# and every request is then answered by the *stale* server as a 404 — which
# reads as a wall of unrelated failures. So: never leak a server, pick a port
# that is actually free, and require a per-run marker from the process we just
# started before running a single assertion.
sfdir=
auth_dir=
route_pid=
auth_pid=

cleanup() {
	[ -n "$route_pid" ] && kill "$route_pid" >/dev/null 2>&1
	[ -n "$auth_pid" ] && kill "$auth_pid" >/dev/null 2>&1
	[ -n "$sfdir" ] && rm -rf "$sfdir"
	[ -n "$auth_dir" ] && rm -rf "$auth_dir"
	return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

port_busy() {
	if [ $need_nc -eq 0 ]; then
		nc -z 127.0.0.1 "$1" >/dev/null 2>&1
	elif command -v ss >/dev/null 2>&1; then
		ss -ltn 2>/dev/null | grep -q ":$1[[:space:]]"
	else
		return 1 # cannot tell; rely on the marker check below
	fi
}

# wait_marker <port> <path> <header-line> <expect-substring>
# True once a response containing <expect-substring> comes back. The header
# value is per-run, so a server left over from an earlier run cannot satisfy the
# check: its config dir is gone, so it has neither our fixture nor our session.
wait_marker() {
	_mport=$1; _mpath=$2; _mhdr=$3; _mexp=$4
	_tries=60
	while [ $_tries -gt 0 ]; do
		if curl -sS --max-time 2 -H "$_mhdr" \
			"http://127.0.0.1:$_mport$_mpath" 2>/dev/null | grep -qF "$_mexp"
		then
			return 0
		fi
		_tries=$((_tries - 1)); sleep 0.1
	done
	return 1
}

# start_server <path> <header-line> <expect> <base-port> <cmd> [extra args]
# sets $srv_port / $srv_pid, or exits if no port in base..base+19 works.
# Server output goes to $srv_log when that is set, and to /dev/null otherwise;
# T9 needs the log to count request dispatches.
start_server() {
	_mpath=$1; _mhdr=$2; _mexp=$3; _base=$4; _cmd=$5; shift 5
	_n=0
	while [ $_n -lt 20 ]; do
		_srv_port=$((_base + _n))
		port_busy "$_srv_port" && { _n=$((_n + 1)); continue; }
		$_cmd -p "$_srv_port" "$@" >"${srv_log:-/dev/null}" 2>&1 &
		_srv_pid=$!
		if wait_marker "$_srv_port" "$_mpath" "$_mhdr" "$_mexp"; then
			srv_port=$_srv_port; srv_pid=$_srv_pid
			return 0
		fi
		kill "$_srv_pid" >/dev/null 2>&1
		_n=$((_n + 1))
	done
	echo "FATAL: $_cmd never answered its marker on $_mpath in ports $_base..$((_base + _n - 1))" >&2
	exit 1
}

# ---------------------------------------------------------------- routes ----
# axil_respond_file() requires the path to carry an extension, so the shared
# fixture is named fixture.txt.
sfdir=$(mktemp -d)
sf="$sfdir/fixture.txt"
head -c 65536 /dev/zero | tr '\0' 'A' >"$sf"
sf_size=$(wc -c <"$sf" | tr -d ' ')

# T9 counts "request_handle:" lines for /ws-unwatched in the server log, so the
# routes server keeps one.
srv_log=$sfdir/routes.log
start_server /echo-header "X-Probe: proof-$$-$port" "proof-$$-$port" "$port" "$testroutes" -f "$sf"
route_port=$srv_port
route_pid=$srv_pid
srv_log=

echo "routes (port $route_port):"

# T1 (P1-5): request head split across TCP segments
if [ $need_py -eq 0 ]; then
	out=$(python3 ./test-split.py "$route_port" GET /echo-header "" 37 0.05 'X-Probe: split-ok\r\n')
	echo "$out" | grep -qF "split-ok" && ok "T1  segmented request head" || bad "T1  segmented request head ($(echo "$out" | tail -1))"
else
	echo "  SKIP  T1  (python3 missing)"
fi

# T3 (P0-3): complete head, body in a second segment
if [ $need_py -eq 0 ]; then
	out=$(python3 ./test-split.py "$route_port" POST /echo-body "hello-body")
	echo "$out" | grep -qF "hello-body" && ok "T3  segmented request body" || bad "T3  segmented request body (got: $(echo "$out" | tail -1))"
else
	echo "  SKIP  T3  (python3 missing)"
fi

# T2 (P1-5) / T4 / T5a (P0-1, P0-2): stalled clients must not block the event
# loop, and the WebSocket relay must carry a split request and a 100 KiB payload
# intact. See test-ws.py: /ws-echo is a raw byte relay, so these cover the
# tunnel, not axil's frame layer.
if [ $need_py -eq 0 ] && [ "$ws_posix" = 1 ]; then
	for ws_flag in --slowloris --split --large; do
		if out=$(python3 ./test-ws.py "$route_port" "$ws_flag" 2>&1); then
			ok "T2/T4/T5a  ws $ws_flag"
		else
			bad "T2/T4/T5a  ws $ws_flag ($(echo "$out" | tail -1))"
		fi
	done
else
	echo "  SKIP  T2/T4/T5a  (python3 missing or non-POSIX)"
fi

# T6 (change 5 + P1-7): both static-file entry points deliver the whole file
for r in /sendfile /respond-file; do
	cl=$(fetch_header_value "$route_port" "$r" Content-Length)
	got=$(curl -sS --max-time 5 "http://127.0.0.1:$route_port$r" | wc -c | tr -d ' ')
	if [ "$cl" = "$sf_size" ] && [ "$got" = "$sf_size" ]; then
		ok "T6  body $r ($got bytes)"
	else
		bad "T6  body $r (Content-Length=$cl got=$got want=$sf_size)"
	fi
	hcl=$(curl -sS -i --max-time 5 -I "http://127.0.0.1:$route_port$r" | tr -d '\r' |
		grep -i "^content-length:" | sed 's/^[^:]*: *//')
	# count only what follows the header terminator; curl -I echoes the
	# headers themselves, so measuring total output would be meaningless
	hbody=$(curl -sS -i --max-time 5 -I "http://127.0.0.1:$route_port$r" |
		sed -n '/^\r\{0,1\}$/,$p' | sed '1d' | wc -c | tr -d ' ')
	if [ "$hcl" = "$sf_size" ] && [ "$hbody" = "0" ]; then
		ok "T6  HEAD $r (no body, Content-Length ok)"
	else
		bad "T6  HEAD $r (Content-Length=$hcl bodybytes=$hbody want=$sf_size/0)"
	fi
done

# T8: a request whose head exceeds MAX_REQUEST_HEAD must be answered with 431
# instead of stashing forever, and a body past the old 20-read budget must
# arrive complete.
if [ $need_py -eq 0 ]; then
	# ~73 KB of pad: just over the 64 KiB cap, no CRLFCRLF, connection held
	# open. See test-split.py --big-head for why this is not done with nc.
	head_reply=$(python3 ./test-split.py --big-head "$route_port" 1600 2>&1 | head -n1)
	if echo "$head_reply" | grep -qF "431"; then
		ok "T8  oversized request head rejected (431)"
	else
		bad "T8  oversized request head not rejected ($head_reply)"
	fi
else
	echo "  SKIP  T8  head cap (python3 missing)"
fi

# The last bytes of the body are a per-run token that is also sent as
# X-Body-Tail, so "arrived complete" is checked at the declared offset instead of
# with strlen (the body is not NUL-terminated -- see route_echo_size).
big_size=$((300 * 1024))
big_tok=$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')
head -c "$((big_size - ${#big_tok}))" /dev/zero | tr '\0' 'B' >"$sfdir/big.bin"
printf '%s' "$big_tok" >>"$sfdir/big.bin"
big=$(curl -sS --max-time 20 -H "X-Body-Tail: $big_tok" \
	--data-binary "@$sfdir/big.bin" \
	"http://127.0.0.1:$route_port/echo-size" 2>/dev/null | tr -d '\r')
if [ "$big" = "declared=$big_size strlen=$big_size tail=ok" ]; then
	ok "T8  300 KB POST body complete"
else
	bad "T8  300 KB POST body (got: $big)"
fi

# T8 (2.1): the same body, but delivered in pieces with a pause in front of each
# one. curl streams fast enough that buffer_post_body() never sees EAGAIN, so
# the test above also passes with the pre-fix code, which treated a short read
# exactly like a disconnect. The pauses force the stall path: fatal on the first
# one without the fix, and ~5 stalls with it (budget: 20).
if [ $need_py -eq 0 ]; then
	stalled=$(python3 ./test-split.py --slow-body "$route_port" /echo-size 65536 0.001 0.0005 4 2>&1 |
		tr -d '\r')
	# test-split.py prints the whole response, headers included.
	case "$stalled" in
	*"declared=65536 strlen=65536 tail=ok"*) ok "T8  stalled POST body survives EAGAIN (65536 bytes)" ;;
	*) bad "T8  stalled POST body lost (got: $(echo "$stalled" | tail -n1))" ;;
	esac
else
	echo "  SKIP  T8  stalled body (python3 missing)"
fi

# T8: an unregistered method must still be dispatched. At HEAD
# head_complete() only accepted GET/POST/HEAD/PUT/DELETE, so an OPTIONS request
# was never parsed and the registered OPTIONS callback never ran.
#
# The probe must run while the sending socket is still open: axil_read() also
# dispatches a partial head when the client closes, so checking after nc exits
# would pass even with the whitelist back.
if [ $need_nc -eq 0 ]; then
	{
		printf 'OPTIONS /song/x HTTP/1.1\r\nHost: h\r\n\r\n'
		sleep 3
	} | nc -w 3 127.0.0.1 "$route_port" >/dev/null 2>&1 &
	opt_pid=$!
	tries=20
	got=none
	while [ $tries -gt 0 ]; do
		got=$(curl -sS --max-time 5 "http://127.0.0.1:$route_port/unknown-methods" 2>/dev/null | tr -d '\r')
		[ "$got" = "OPTIONS /song/x" ] && break
		tries=$((tries - 1)); sleep 0.1
	done
	wait "$opt_pid" >/dev/null 2>&1 || true
	if [ "$got" = "OPTIONS /song/x" ]; then
		ok "T8  unregistered method dispatched (OPTIONS)"
	else
		bad "T8  unregistered method not dispatched (got: $got)"
	fi
else
	echo "  SKIP  T8  unknown method (nc missing)"
fi

# T9 (SECURITY.md S0.3): the WebSocket *frame* layer, which nothing else here
# reaches. test-ws.py drives /ws-echo, which is a raw byte relay -- its child
# speaks raw bytes, so ws_read()/ws_write() are never called and the frames are
# never parsed. These cases go through axil_ws_upgrade() + axil_fd_watch() and
# therefore exercise ws_fill/ws_read/ws_write for real.
if [ $need_py -eq 0 ] && [ "$ws_posix" = 1 ]; then
	# Byte-exact echo, including NUL bytes in the payload: the server must
	# echo axil_ws_read()'s return value, not strlen() of the buffer.
	for t9_case in "16:" "20000:" "20000:--split" "16:--close"; do
		t9_n=${t9_case%%:*}
		t9_flag=${t9_case#*:}
		if out=$(python3 ./test-split.py --ws-echo "$route_port" /ws-frames \
			"$t9_n" $t9_flag 2>&1) && echo "$out" | grep -q "^ws=ok$"
		then
			ok "T9  ws frame echo ${t9_n}B ${t9_flag:-plain}"
		else
			bad "T9  ws frame echo ${t9_n}B ${t9_flag:-plain} ($(echo "$out" | tail -n1))"
		fi
	done

	# T9/S6.7: exactly one Close frame for a client-initiated close. The echo
	# is ws_read()'s; a second (from axil_close()) makes a browser fail with
	# "Close received after close".
	if out=$(python3 ./test-split.py --ws-echo "$route_port" /ws-frames 16 \
		--close 2>&1) && echo "$out" | grep -q "^second=none$"
	then
		ok "T9  ws close sends exactly one frame"
	else
		bad "T9  ws close sends exactly one frame ($(echo "$out" | tail -n1))"
	fi

	# T9/S1.4: on the unwatched path the upgrade request must be dispatched
	# exactly once, no matter how many frames arrive. Before the S1 fix every
	# frame re-parses the stale request and dispatches it again, so the count
	# tracks the frame count. A dispatch count, not an ASan report: there is
	# no memory error to catch (SECURITY.md 1.1).
	#
	# The pattern deliberately omits the slash after GET: the upgrade logs as
	# "GET /ws-unwatched" and each replay logs as "GET ws-unwatche" with the
	# parse truncated at the frame length, so matching the slash would count
	# the upgrades only and the replays would go unnoticed.
	unwatched_dispatches() {
		# grep -c prints 0 *and* exits 1 when nothing matches, so the count
		# has to come from stdout with the status discarded -- "|| echo 0"
		# would append a second line and break the arithmetic.
		_c=$(grep -c 'request_handle:.*ws-unwatche' "$sfdir/routes.log" 2>/dev/null || :)
		echo "${_c:-0}"
	}
	tries=30
	before=0
	while [ $tries -gt 0 ]; do
		before=$(unwatched_dispatches)
		[ "${before:-0}" -gt 0 ] 2>/dev/null && break
		tries=$((tries - 1)); sleep 0.1
	done
	for _i in 1 2 3; do
		python3 ./test-split.py --ws-echo "$route_port" /ws-unwatched 16 \
			--send-only >/dev/null 2>&1 || true
	done
	tries=30
	after=$before
	while [ $tries -gt 0 ]; do
		after=$(unwatched_dispatches)
		[ "${after:-0}" -ge $((before + 3)) ] 2>/dev/null && break
		tries=$((tries - 1)); sleep 0.1
	done
	# Each frame is its own connection, so 3 frames mean 3 upgrades; the count
	# must be exactly 3, not 3 upgrades plus 3 replays.
	if [ "${after:-0}" = "3" ]; then
		ok "T9  ws frames do not re-dispatch the upgrade request ($after for 3 frames)"
	else
		bad "T9  ws frames re-dispatched the upgrade request ($after dispatches for 3 frames, want 3)"
	fi

	# T9/S2.4: two frames written back to back in one tick, the first too big
	# for the socket buffers. A header sent on the raw socket instead of
	# through the write queue either overtakes the queued payload of the frame
	# ahead of it or is lost to EAGAIN; either way this client does not get two
	# intact frames in order.
	if out=$(python3 ./test-split.py --ws-pair "$route_port" /ws-pair \
		131072 2>&1) && echo "$out" | grep -q "^ws=ok$"
	then
		ok "T9  ws two frames per tick arrive in order"
	else
		bad "T9  ws frame header/payload interleaved or lost ($(echo "$out" | grep '^ws=' | tail -n1))"
	fi

	# T9/S4.3: a printf larger than the internal BUFSIZ buffer. vsnprintf's
	# would-be length used to be handed straight to ws_write(), framing and
	# sending ~12 KiB of process memory past a `static char buf[BUFSIZ]`
	# (finding 4). The client checks the frame length is clamped *and* that
	# FIN is set, since ws_dprintf's `WS_BINARY & WS_FIN` emitted a
	# continuation frame (finding 10).
	if out=$(python3 ./test-split.py --ws-printf "$route_port" /ws-printf \
		20000 2>&1) && echo "$out" | grep -q "^ws=ok$"
	then
		ok "T9  ws printf clamped to BUFSIZ with FIN set"
	else
		bad "T9  ws printf leaked or mis-framed ($(echo "$out" | grep '^ws=' | tail -n1))"
	fi

	# T9/S6.2: a zero-length destination is a caller error, not a way to switch
	# off the bounds check. `if (data && len && pl + 1 > len)` meant len == 0
	# skipped the check and then wrote pl + 1 bytes into a buffer the caller had
	# said held nothing; /ws-len0 passes a real malloc(0) so the pre-fix build
	# is a heap-buffer-overflow under ASan, and the result is logged for the
	# fixed build to be read back here.
	python3 ./test-split.py --ws-echo "$route_port" /ws-len0 16 --send-only \
		>/dev/null 2>&1 || true
	tries=30
	while [ $tries -gt 0 ]; do
		grep -q '^len0 ret=' "$sfdir/routes.log" 2>/dev/null && break
		tries=$((tries - 1)); sleep 0.2
	done
	len0=$(sed -n 's/^len0 \(ret=[^ ]* errno=[0-9]*\).*/\1/p' "$sfdir/routes.log" 2>/dev/null | head -n1)
	case "$len0" in
	"ret=-1 errno=90")
		ok "T9  ws_read refuses a zero-length destination (EMSGSIZE)"
		;;
	"")
		bad "T9  ws_read zero-length destination (no result logged)"
		;;
	*)
		bad "T9  ws_read zero-length destination ($len0, want ret=-1 errno=90)"
		;;
	esac

	# T9/S6.3: a client frame with the MASK bit clear is a protocol error
	# (RFC 6455 5.1). The 4-byte key was read unconditionally and the bit was
	# never tested, so an unmasked frame ate 4 payload bytes as its key and
	# then waited for 4 more that never arrive: EAGAIN forever, the tick never
	# progressed, and with no idle reaper the fd was never reclaimed. The server
	# must answer with a close carrying 1002. Silence *is* the pre-fix
	# behaviour, so the client's own timeout is a failure, not a pass.
	# No dedicated server: no process-wide state is involved, unlike S6.1.
	if out=$(timeout 30 python3 ./test-split.py --ws-echo "$route_port" \
		/ws-frames 16 --unmask 2>&1) && echo "$out" | grep -q "^ws=ok$" &&
	   echo "$out" | grep -q "^close=1002$"
	then
		ok "T9  ws client frame with the MASK bit clear is refused with 1002"
	else
		bad "T9  ws unmasked client frame (want ws=ok close=1002, got $(echo "$out" | grep -E '^(ws|close)=' | tr '\n' ' '))"
	fi

	# T9/S6.5: the public axil_ws_* wrappers must bound-check the descriptor.
	# They indexed frame_map[], ws_flags[], descr_map[] and io[] -- all
	# [FD_SETSIZE] -- with whatever they were handed, while every other public
	# entry point, axil_close() included, rejects one outside the range. A stale
	# descriptor or the -1 from a failed accept read and wrote out of bounds.
	#
	# Run as its own process on purpose. Pre-fix this segfaults on the first
	# call, dereferencing io[-1].lower_read -- a garbage function pointer -- and
	# from a route handler that would take the whole server down and turn one
	# missing guard into a red board with no clue which check failed. Isolated,
	# a crash is just a nonzero exit and the other cases still run.
	if LD_LIBRARY_PATH=./lib $testroutes -B >"$sfdir/fdbounds.log" 2>&1; then
		ok "T9  axil_ws_* reject a descriptor outside [0, FD_SETSIZE)"
	else
		bad "T9  axil_ws_* descriptor bounds (exit $?: $(tr '\n' ';' <"$sfdir/fdbounds.log" | cut -c1-160))"
	fi

	# T9/S6.4: a control frame must declare at most 125 bytes of payload
	# (RFC 6455 5.5) -- precisely because it is never fragmented, so it cannot
	# be split across reads. Both values below are ones a control frame may not
	# use, and the client distinguishes the two behaviours by what arrives
	# *first*: an echo of the payload, or a 1002 close.
	#   pl=200 op=9  -- a ping that simply declares too much.
	#   pl=126 op=8  -- the 2-byte extended length form, which is the case that
	#     also desynchronised: the opcode 8 branch returned before the extended
	#     length was read, so those 2 bytes stayed unread and the next frame read
	#     them as a header. Here the client sees the 1008 that axil_close()
	#     sends at teardown, not the 1002 a protocol error warrants.
	for s64 in "200 9 ping" "126 8 close"; do
		set -- $s64
		s64_pl=$1; s64_op=$2; s64_name=$3
		if out=$(timeout 30 python3 ./test-split.py --ws-ctl "$route_port" \
			/ws-frames "$s64_pl" "$s64_op" 2>&1) && echo "$out" | grep -q "^ws=ok$" &&
		   echo "$out" | grep -q "^close=1002$"
		then
			ok "T9  ws control frame over 125 bytes refused ($s64_name pl=$s64_pl, 1002)"
		else
			bad "T9  ws control frame over 125 bytes ($s64_name pl=$s64_pl: want ws=ok close=1002, got $(echo "$out" | grep -E '^(ws|close|recv)=' | tr '\n' ' '))"
		fi
	done

	# T9/S6.1: a read interrupted by a signal reports EINTR, which is neither a
	# closed peer nor a protocol error. axil_ws_read() used to pass it on as a
	# 0, indistinguishable from the peer closing, so an app that stops reading
	# on 0 dropped healthy connections whenever a SIGCHLD or a timer fired.
	# The dedicated server injects one EINTR mid-payload; with the retry in
	# ws_fill() the frame completes and is echoed, and without it the server
	# tears the connection down mid-frame and the echo never arrives.
	# A dedicated server because AXIL_TEST_WS_EINTR is process-wide and would
	# fire on every other T9 case sharing it.
	eintr_port=$((route_port + 4))
	eintr_pid=
	LD_LIBRARY_PATH=./lib AXIL_TEST_WS_EINTR=1 \
		$testroutes -p "$eintr_port" >"$sfdir/eintr.routes.log" 2>&1 &
	eintr_pid=$!
	tries=60
	while [ $tries -gt 0 ]; do
		curl -sS --max-time 2 "http://127.0.0.1:$eintr_port/health" \
			>/dev/null 2>&1 && break
		tries=$((tries - 1)); sleep 0.2
	done
	if out=$(timeout 30 python3 ./test-split.py --ws-echo "$eintr_port" \
		/ws-frames 20000 --split 2>&1) && echo "$out" | grep -q "^ws=ok$"
	then
		ok "T9  ws read interrupted by a signal is retried, not EOF"
	else
		bad "T9  ws read interrupted by a signal ($(echo "$out" | tail -n1))"
	fi
	kill "$eintr_pid" >/dev/null 2>&1
	wait "$eintr_pid" >/dev/null 2>&1 || true

	# T9/S5.4: a frame payload abandoned by a server-side close, i.e.
	# frame_map[fd].data never freed at teardown, so the last connection's
	# payload is still allocated at exit. The observable has to be valgrind's
	# "still reachable", for three separate reasons -- all three were tried
	# first and all three passed against the unfixed code:
	#   * LeakSanitizer cannot see it: frame_map is a global, so the block is
	#     still reachable at exit and LSan reports unreachable blocks only.
	#   * /proc/PID/maps under-reports: the kernel merges adjacent anonymous
	#     VMAs, so one retained payload looked like a single region.
	#   * VmRSS cannot see it: an unwritten 64 MiB malloc is untouched mmap
	#     space, and making the server dirty the payload means racing the tick
	#     that closes the connection.
	# A dedicated server, because valgrind slows it enough that reusing the
	# shared one would change the timing of every other T9 case.
	leak_port=$((route_port + 3))
	vg_log="$sfdir/valgrind-s5.log"
	leak_pid=
	# valgrind cannot run an ASan-instrumented binary: the sanitizer runtime
	# refuses to initialise under it and the server never comes up. Detect the
	# instrumentation instead of letting that look like a failed assertion.
	leak_asan=0
	if command -v nm >/dev/null 2>&1 &&
		nm "$testroutes" 2>/dev/null | grep -q "__asan_init"
	then
		leak_asan=1
	fi
	if [ "$leak_asan" = 1 ]; then
		echo "  SKIP  T9  ws abandoned frame payload (ASan build: valgrind cannot run it)"
	elif command -v valgrind >/dev/null 2>&1; then
		valgrind --leak-check=full --show-leak-kinds=all \
			--log-file="$vg_log" $testroutes -p "$leak_port" \
			>"$sfdir/valgrind-s5.routes.log" 2>&1 &
		leak_pid=$!
		tries=60
		while [ $tries -gt 0 ]; do
			curl -sS --max-time 2 "http://127.0.0.1:$leak_port/health" \
				>/dev/null 2>&1 && break
			tries=$((tries - 1)); sleep 0.2
		done
		if out=$(python3 ./test-split.py --ws-leak "$leak_port" /ws-leak 4 \
			2>&1) && echo "$out" | grep -q "^ws=ok$"
		then
			# SIGTERM: valgrind still reports leaks on a normal exit signal.
			kill "$leak_pid" >/dev/null 2>&1
			wait "$leak_pid" >/dev/null 2>&1 || true
			leak_pid=
			# Threshold is 1 MiB against a 16 KB baseline and an 8 MiB leak,
			# so neither side is close to the line.
			reachable=$(sed -n 's/.*still reachable: \([0-9,]*\) bytes.*/\1/p' \
				"$vg_log" 2>/dev/null | tr -d , | head -n1)
			if [ -z "$reachable" ]; then
				bad "T9  ws abandoned frame payload freed (no valgrind leak summary)"
			elif [ "$reachable" -gt 1048576 ]; then
				bad "T9  ws abandoned frame payload retained ($reachable bytes still reachable)"
			else
				ok "T9  ws abandoned frame payload freed ($reachable bytes still reachable)"
			fi
		else
			bad "T9  ws leak setup ($(echo "$out" | tail -n1))"
			[ -n "$leak_pid" ] && kill "$leak_pid" >/dev/null 2>&1
			leak_pid=
		fi
	else
		echo "  SKIP  T9  ws abandoned frame payload (valgrind missing)"
	fi

	# The server must still be serving after all of that.
	if curl -sS --max-time 5 -H "X-Probe: proof-$$-$port" \
		"http://127.0.0.1:$route_port/echo-header" 2>/dev/null |
		grep -qF "proof-$$-$port"
	then
		ok "T9  server still healthy after frame traffic"
	else
		bad "T9  server unhealthy after frame traffic"
	fi
else
	echo "  SKIP  T9  (python3 missing or non-POSIX)"
fi

kill "$route_pid" >/dev/null 2>&1 || true
route_pid=

# ------------------------------------------------------------------ auth ----
auth_dir=$(mktemp -d)
mkdir -p "$auth_dir/sessions"
printf "tester\n" >"$auth_dir/sessions/abc"
# /pw answers with "pw_uid=..." for a valid session, so a per-run session name is
# the marker: a stale test-auth from another run has no such session.
session="proof-$$"
printf "tester\n" >"$auth_dir/sessions/$session"
start_server /pw "Cookie: session=$session" "pw_uid=" "$((route_port + 1))" "$testauth" -C "$auth_dir"
auth_port=$srv_port
auth_pid=$srv_pid

echo "auth (port $auth_port):"

# The counter is process-global and start_server's marker already authenticated
# one connection, so compare deltas against a baseline taken here instead of
# assuming 0.
dc() { curl -sS --max-time 5 "http://127.0.0.1:$auth_port/disconnects" | tr -d '[:space:]'; }
base=$(dc)
curl -sS --max-time 5 "http://127.0.0.1:$auth_port/" | grep -qF "auth none" &&
	ok "T7  unauthenticated request" || bad "T7  unauthenticated request"
after=$(dc)
[ "$after" = "$base" ] && ok "T7  unauthenticated does not fire axil_disconnect" ||
	bad "T7  unauthenticated fired axil_disconnect ($base -> $after, want unchanged)"

curl -sS --max-time 5 -H "Cookie: session=$session" "http://127.0.0.1:$auth_port/" | grep -qF "auth ok" &&
	ok "T7  authenticated request" || bad "T7  authenticated request"

uid=$(curl -sS --max-time 5 -H "Cookie: session=$session" "http://127.0.0.1:$auth_port/pw" |
	sed -n 's/^pw_uid=\([0-9]*\).*$/\1/p')
if [ -z "$uid" ]; then
	bad "T7  unknown-user pw_uid (no value reported)"
elif [ "$uid" = "0" ]; then
	bad "T7  unknown-user pw_uid (resolved to uid 0)"
else
	ok "T7  unknown-user pw_uid ($uid != 0)"
fi

# T7: axil_auth() must report an unknown name instead of claiming success, and
# still leave a non-zero privilege target behind.
unknown=$(curl -sS --max-time 5 "http://127.0.0.1:$auth_port/auth-unknown" | tr -d '\r')
unknown_ret=$(echo "$unknown" | sed -n 's/.*ret=\([0-9]*\).*/\1/p')
unknown_uid=$(echo "$unknown" | sed -n 's/.*uid=\([0-9]*\).*/\1/p')
if [ "$unknown_ret" != "1" ]; then
	bad "T7  axil_auth() return for unknown name (ret=$unknown_ret, want 1)"
elif [ -z "$unknown_uid" ] || [ "$unknown_uid" = "0" ]; then
	bad "T7  axil_auth() unknown-name privilege target (uid=$unknown_uid, want non-zero)"
else
	ok "T7  axil_auth() reports unknown name (ret=1, uid=$unknown_uid != 0)"
fi

# T7 (S7.1/S7.2): a name past sizeof(d->username) must leave d->username
# terminated. env_len is the discriminator -- REMOTE_USER is stored in a CM_STR
# corm map, so what comes back is exactly what strlen() measured on the field.
# Fixed: 8191. Pre-fix: 8192 or more, the over-read running into d->remaining.
# Neither ASan nor valgrind can see this (the read stays inside the descr_map[]
# allocation), which is why it is asserted as a length.
#
# ret= and uid= are a guard, NOT evidence: getpwnam() returns NULL for 8192 junk
# bytes just as for 8191, and both builds measure ret=1 uid=1000. sum= is the
# checksum of the first 8191 pattern bytes, so an off-by-one in the truncation
# is caught too.
long=$(curl -sS --max-time 5 "http://127.0.0.1:$auth_port/auth-longname" | tr -d '\r')
long_len=$(echo "$long" | sed -n 's/.*env_len=\([0-9]*\).*/\1/p')
long_sum=$(echo "$long" | sed -n 's/.*sum=\([0-9]*\).*/\1/p')
long_ret=$(echo "$long" | sed -n 's/.*ret=\([0-9]*\).*/\1/p')
long_uid=$(echo "$long" | sed -n 's/.*uid=\([0-9]*\).*/\1/p')
if [ -z "$long_len" ]; then
	bad "T7  axil_auth() long username (no env_len reported: $long)"
elif [ "$long_len" != "8191" ]; then
	bad "T7  axil_auth() left d->username unterminated (env_len=$long_len, want 8191)"
elif [ "$long_sum" != "896902" ]; then
	bad "T7  axil_auth() truncated to the wrong bytes (sum=$long_sum, want 896902)"
elif [ "$long_ret" != "1" ]; then
	bad "T7  axil_auth() return for a truncated name (ret=$long_ret, want 1)"
elif [ -z "$long_uid" ] || [ "$long_uid" = "0" ]; then
	bad "T7  axil_auth() truncated name changed privileges (uid=$long_uid, want non-zero)"
else
	ok "T7  axil_auth() terminates a 8224-byte name (env_len=$long_len, uid=$long_uid != 0)"
fi

# T7 (S7.1): the descriptor bound added alongside the termination fix. Out of
# array, so unlike the case above ASan does see it; -1 and EBADF both.
badfd=$(curl -sS --max-time 5 "http://127.0.0.1:$auth_port/auth-badfd" | tr -d '\r')
badfd_lo=$(echo "$badfd" | sed -n 's/.*lo=\(-*[0-9]*\).*/\1/p')
badfd_hi=$(echo "$badfd" | sed -n 's/.*hi=\(-*[0-9]*\).*/\1/p')
badfd_err=$(echo "$badfd" | sed -n 's/.*errno=\([0-9]*\).*/\1/p')
if [ "$badfd_lo" != "-1" ] || [ "$badfd_hi" != "-1" ]; then
	bad "T7  axil_auth() descriptor bound (lo=$badfd_lo hi=$badfd_hi, want -1/-1)"
elif [ "$badfd_err" != "9" ]; then
	bad "T7  axil_auth() descriptor bound errno ($badfd_err, want 9/EBADF)"
else
	ok "T7  axil_auth() rejects out-of-range fd (lo=-1 hi=-1 EBADF)"
fi

tries=50; after=0
while [ $tries -gt 0 ]; do
	after=$(curl -sS --max-time 5 "http://127.0.0.1:$auth_port/disconnects" | tr -d '[:space:]')
	[ "$after" -ge 1 ] 2>/dev/null && break
	tries=$((tries-1)); sleep 0.1
done
[ "$after" -ge 1 ] 2>/dev/null && ok "T7  authenticated fires axil_disconnect ($after)" ||
	bad "T7  authenticated never fired axil_disconnect"

kill "$auth_pid" >/dev/null 2>&1 || true
rm -rf "$sfdir"

echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
