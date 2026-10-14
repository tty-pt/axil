#!/bin/sh -e
# `set -e` is repeated in the body, not just the shebang, because `make test`
# and the documented gate both run `sh ./test.sh`, and `sh script` ignores the
# shebang's options. Without this an assert_contains() failure printed "Test
# FAILED!" and the script still exited 0, so the suite could not fail.
set -e

testbin=./bin/test
axil=./bin/axil
testauth=./bin/test-auth
testroutes=./bin/test-routes
testdefer=./bin/test-defer

case "$(uname -s)" in
	Darwin)
		export DYLD_LIBRARY_PATH=./lib:${DYLD_LIBRARY_PATH}
		;;
	*)
		export LD_LIBRARY_PATH=./lib:${LD_LIBRARY_PATH}
		;;
esac

assert() {
	file=snap/$1.txt
	shift
	echo $@ >&2
	if "$@" | diff $file -; then
		return 0;
	else
		echo Test FAILED! $file != $@ >&2
		return 1
	fi
}

wait_for_port() {
	port=$1
	tries=50
	while [ $tries -gt 0 ]; do
		if command -v curl >/dev/null 2>&1; then
			curl -sS --max-time 1 "http://127.0.0.1:$port/" >/dev/null 2>&1 && return 0
		else
			nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && return 0
		fi
		tries=$((tries - 1))
		sleep 0.1
	done
	return 1
}

# Every server this script starts is killed on the way out, including on a failed
# assertion (sh -e) or an interrupt. A leaked server keeps its port, and its
# config dir is normally deleted with it, so the next run either cannot bind or
# -- worse -- is answered by the stale process, which turns one real regression
# into a screenful of unrelated 404s.
servers_started=""
dirs_created=""
cleanup() {
	for _p in $servers_started; do
		kill "$_p" >/dev/null 2>&1 || true
	done
	for _d in $dirs_created; do
		rm -rf "$_d"
	done
	return 0
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

note_server() { servers_started="$servers_started $1"; }
note_dir() { dirs_created="$dirs_created $1"; }

# port_busy <port>: true if something is already listening.
port_busy() {
	if command -v nc >/dev/null 2>&1; then
		nc -z 127.0.0.1 "$1" >/dev/null 2>&1 && return 0
		return 1
	fi
	if command -v ss >/dev/null 2>&1; then
		ss -ltn 2>/dev/null | grep -q ":$1[[:space:]]" && return 0
		return 1
	fi
	# curl cannot tell "refused" from "answered", so assume free and let the
	# marker check in the caller sort it out.
	return 1
}

# free_port <preferred>: the preferred port, or the next free one above it.
free_port() {
	_p=$1
	_n=0
	while [ $_n -lt 20 ]; do
		port_busy "$_p" || { echo "$_p"; return 0; }
		_p=$((_p + 1)); _n=$((_n + 1))
	done
	echo "$1"
}

wait_for_port_tcp() {
	port=$1
	tries=50
	if ! command -v nc >/dev/null 2>&1; then
		wait_for_port "$port"
		return $?
	fi
	while [ $tries -gt 0 ]; do
		nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && return 0
		tries=$((tries - 1))
		sleep 0.1
	done
	return 1
}

fetch_root() {
	port=$1
	if command -v curl >/dev/null 2>&1; then
		curl -sS --max-time 2 "http://127.0.0.1:$port/__axil_test_missing__"
		return $?
	fi

	if ! command -v nc >/dev/null 2>&1; then
		echo "curl or nc required" >&2
		return 1
	fi

	printf "GET /__axil_test_missing__ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" |
		nc 127.0.0.1 "$port" | sed -n '/^\r\{0,1\}$/,$p' | sed '1d'
}

fetch_status() {
	port=$1
	path=$2
	if command -v curl >/dev/null 2>&1; then
		curl -sS -i --max-time 2 "http://127.0.0.1:$port$path" | sed -n '1p' | tr -d '\r'
		return $?
	fi

	if ! command -v nc >/dev/null 2>&1; then
		echo "curl or nc required" >&2
		return 1
	fi

	printf "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" "$path" |
		nc 127.0.0.1 "$port" | sed -n '1p' | tr -d '\r'
}

fetch_headers() {
	port=$1
	path=$2
	if command -v curl >/dev/null 2>&1; then
		curl -sS -i --max-time 2 "http://127.0.0.1:$port$path" |
			sed -n '/^\r\{0,1\}$/q;p' | tr -d '\r'
		return $?
	fi

	if ! command -v nc >/dev/null 2>&1; then
		echo "curl or nc required" >&2
		return 1
	fi

	printf "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" "$path" |
		nc 127.0.0.1 "$port" | sed -n '/^\r\{0,1\}$/q;p' | tr -d '\r'
}

fetch_body() {
	port=$1
	path=$2
	if command -v curl >/dev/null 2>&1; then
		curl -sS --max-time 2 "http://127.0.0.1:$port$path" | tr -d '\r'
		return $?
	fi

	if ! command -v nc >/dev/null 2>&1; then
		echo "curl or nc required" >&2
		return 1
	fi

	printf "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" "$path" |
		nc 127.0.0.1 "$port" | sed -n '/^\r\{0,1\}$/,$p' | sed '1d' | tr -d '\r'
}

fetch_header_value() {
	port=$1
	path=$2
	header=$3
	if command -v curl >/dev/null 2>&1; then
		curl -sS -i --max-time 2 "http://127.0.0.1:$port$path" |
			tr -d '\r' | grep -i "^$header:" |
			sed 's/^[^:]*: *//' | head -n1
		return $?
	fi
	echo "curl required" >&2
	return 1
}

fetch_status_hdr() {
	port=$1
	path=$2
	shift 2
	if command -v curl >/dev/null 2>&1; then
		curl -sS -i --max-time 2 "$@" "http://127.0.0.1:$port$path" |
			sed -n '1p' | tr -d '\r'
		return $?
	fi
	echo "curl required" >&2
	return 1
}

assert_contains() {
	label=$1
	needle=$2
	shift 2
	# `set -e` must not fire on the command under test. A nonzero exit is
	# precisely what this function exists to report, and letting it propagate
	# aborts the script on the assignment below, one line after the call, with
	# no diagnostic printed at all.
	#
	# The command's own output goes to the diagnostic too, because "missing
	# 'ws=ok'" on its own does not say what the client actually printed -- and
	# for the WebSocket cases that output is the entire result.
	output=$("$@" 2>&1) && status=0 || status=$?
	echo "$output" | grep -F "$needle" >/dev/null 2>&1 && return 0
	echo "Test FAILED! $label missing '$needle' (exit $status)" >&2
	echo "$output" | sed 's/^/    | /' >&2
	return 1
}

assert_not_exported() {
	sym=$1
	if ! command -v nm >/dev/null 2>&1; then
		echo "Skipping export check: nm not found" >&2
		return 0
	fi
	nm -D lib/libaxil.so | grep -F " $sym" >/dev/null 2>&1 && {
		echo "Test FAILED! symbol exported: $sym" >&2
		return 1
	}
	return 0
}

raw_request() {
	port=$1
	request=$2
	if ! command -v nc >/dev/null 2>&1; then
		echo "nc required" >&2
		return 1
	fi
	printf "%s" "$request" | nc -w 1 127.0.0.1 "$port"
}

# send a request as two TCP segments separated by a delay, so the server has to
# reassemble it. Used by the P1-5 and P0-3 tests.
split_request() {
	port=$1
	first=$2
	second=$3
	delay=${4:-0.05}
	if ! command -v nc >/dev/null 2>&1; then
		echo "nc required" >&2
		return 1
	fi
	{ printf "%s" "$first"; sleep "$delay"; printf "%s" "$second"; } |
		nc -w 2 127.0.0.1 "$port"
}

$testbin | diff expects.txt -
assert usage sh -c "$axil -? 2>&1"
assert_not_exported axil_platform
assert_not_exported descr_map

if ! command -v curl >/dev/null 2>&1 && ! command -v nc >/dev/null 2>&1; then
	echo "Skipping HTTP tests: curl or nc not found" >&2
	exit 0
fi

port=$((18000 + $$ % 1000))
$axil -d -p "$port" >/dev/null 2>&1 &
axil_pid=$!
note_server "$axil_pid"

if wait_for_port "$port"; then
	assert http-404 fetch_root "$port"
	if command -v nc >/dev/null 2>&1; then
		bad=$(raw_request "$port" "GET /../secret HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
		if [ -n "$bad" ]; then
			echo "Test FAILED! expected empty response for bad path" >&2
			exit 1
		fi
		malformed=$(raw_request "$port" "BADREQUEST\r\n\r\n")
		if [ -n "$malformed" ]; then
			echo "Test FAILED! expected empty response for malformed request" >&2
			exit 1
		fi
		preface=$(raw_request "$port" "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		if [ -n "$preface" ]; then
			echo "Test FAILED! expected empty response for HTTP/2 preface" >&2
			exit 1
		fi
		kill -0 "$axil_pid" >/dev/null 2>&1 || {
			echo "Test FAILED! server died after HTTP/2 preface" >&2
			exit 1
		}
		assert http-404 fetch_root "$port"
	fi
else
	echo "axil failed to listen on $port" >&2
	kill "$axil_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$axil_pid" >/dev/null 2>&1 || true

auth_dir=$(mktemp -d)
note_dir "$auth_dir"
mkdir -p "$auth_dir/sessions"
printf "tester\n" >"$auth_dir/sessions/abc"
auth_port=$(free_port $((port + 10)))
$testauth -p "$auth_port" -C "$auth_dir" >/dev/null 2>&1 &
auth_pid=$!
note_server "$auth_pid"

if wait_for_port_tcp "$auth_port"; then
	if command -v curl >/dev/null 2>&1; then
		# T7 (change 4): axil_disconnect() must fire for an *unauthenticated*
		# request. It used to be gated on DF_CONNECTED and then on
		# DF_AUTHENTICATED, so it fired for neither -- which meant a module that
		# had attached a pty and a child shell to a raw terminal could never
		# clean it up, and its fd-keyed state outlived the connection and landed
		# on the next one (SECURITY.md S5.4). Poll rather than sample once: the
		# count is read while this request is still open, so the bump for the
		# previous connection has to have landed already.
		assert_contains auth-none "auth none" sh -c "curl -sS --max-time 2 http://127.0.0.1:$auth_port/"
		tries=50
		before=0
		while [ $tries -gt 0 ]; do
			before=$(curl -sS --max-time 2 "http://127.0.0.1:$auth_port/disconnects" | tr -d '[:space:]')
			[ "$before" -ge 1 ] 2>/dev/null && break
			tries=$((tries - 1))
			sleep 0.1
		done
		[ "$before" -ge 1 ] 2>/dev/null || {
			echo "Test FAILED! auth-disconnect: hook never fired for an unauthenticated request ($before)" >&2
			exit 1
		}

		assert_contains auth-ok "auth ok" sh -c "curl -sS --max-time 2 -H 'Cookie: session=abc' http://127.0.0.1:$auth_port/"

		# T7 (change 4): the session names a user with no passwd entry, so
		# axil_auth() takes the unknown-user path. axil_get_pw() returns the
		# entry drop_priviledges() would use; at HEAD it was left zeroed, so
		# this reads back uid 0.
		uid=$(curl -sS --max-time 2 -H 'Cookie: session=abc' \
			"http://127.0.0.1:$auth_port/pw" | sed -n 's/^pw_uid=\([0-9]*\).*$/\1/p')
		[ -n "$uid" ] || {
			echo "Test FAILED! auth-pw: no pw_uid reported" >&2
			exit 1
		}
		[ "$uid" != "0" ] || {
			echo "Test FAILED! auth-pw: unknown user resolved to uid 0" >&2
			exit 1
		}

		# T7 (change 4): axil_auth() must report an unknown name instead of
		# claiming success, while the privilege target must not be uid 0.
		unknown=$(curl -sS --max-time 2 "http://127.0.0.1:$auth_port/auth-unknown" | tr -d '\r')
		echo "$unknown" | grep -F "ret=1" >/dev/null 2>&1 || {
			echo "Test FAILED! auth-unknown: axil_auth() did not report the unknown name ($unknown)" >&2
			exit 1
		}
		echo "$unknown" | sed -n 's/.*uid=\([0-9]*\).*/\1/p' | grep -v '^0$' >/dev/null 2>&1 || {
			echo "Test FAILED! auth-unknown: unknown user resolved to uid 0 ($unknown)" >&2
			exit 1
		}

		# T7 (S7.1/S7.2): a name past sizeof(d->username) must leave
		# d->username terminated. env_len is the discriminator: REMOTE_USER is
		# stored in a CM_STR corm map, so the read-back length is exactly what
		# strlen() measured on the field. Fixed: 8191. Pre-fix: 8192 or more.
		# ASan and valgrind are both blind here (the over-read stays inside the
		# descr_map[] allocation), so it is asserted as a length. ret=/uid= are
		# a guard only -- both builds measure ret=1 uid=1000 -- and sum= pins the
		# first 8191 pattern bytes so a wrong-offset truncation is caught.
		long=$(curl -sS --max-time 2 "http://127.0.0.1:$auth_port/auth-longname" | tr -d '\r')
		echo "$long" | grep -F "env_len=8191" >/dev/null 2>&1 || {
			echo "Test FAILED! auth-longname: d->username left unterminated ($long)" >&2
			exit 1
		}
		echo "$long" | grep -F "sum=896902" >/dev/null 2>&1 || {
			echo "Test FAILED! auth-longname: truncated to the wrong bytes ($long)" >&2
			exit 1
		}
		echo "$long" | sed -n 's/.*ret=\([0-9]*\).*/\1/p' | grep -F 1 >/dev/null 2>&1 || {
			echo "Test FAILED! auth-longname: axil_auth() did not report the truncated name as unknown ($long)" >&2
			exit 1
		}
		echo "$long" | sed -n 's/.*uid=\([0-9]*\).*/\1/p' | grep -v '^0$' >/dev/null 2>&1 || {
			echo "Test FAILED! auth-longname: truncated name changed privileges ($long)" >&2
			exit 1
		}

		# T7 (S7.1): the descriptor bound added alongside the termination fix.
		# Out of array, so unlike the case above ASan does see it.
		badfd=$(curl -sS --max-time 2 "http://127.0.0.1:$auth_port/auth-badfd" | tr -d '\r')
		echo "$badfd" | grep -F "lo=-1 hi=-1 errno=9" >/dev/null 2>&1 || {
			echo "Test FAILED! auth-badfd: axil_auth() accepted an out-of-range fd ($badfd)" >&2
			exit 1
		}

		tries=50
		after=0
		while [ $tries -gt 0 ]; do
			after=$(curl -sS --max-time 2 "http://127.0.0.1:$auth_port/disconnects" | tr -d '[:space:]')
			[ "$after" -ge 1 ] 2>/dev/null && break
			tries=$((tries - 1))
			sleep 0.1
		done
		[ "$after" -ge 1 ] 2>/dev/null || {
			echo "Test FAILED! auth-disconnect: hook never fired for an authenticated request" >&2
			exit 1
		}

		# Without -A there is no published identity, so DF_AUTH_AUTO must be
		# clear even though axil_auth_check() may still have resolved a cookie.
		# Observed after an upgrade, which is where -A would act.
		off=$(python3 ./test-ws.py "$auth_port" --flags | sed -n 's/^wsflags //p')
		case "$off" in
		*"auto=0"*)
			;;
		*)
			echo "Test FAILED! auth-autoauth-off: expected DF_AUTH_AUTO clear without -A, got '$off'" >&2
			exit 1
			;;
		esac
	else
		echo "Skipping auth HTTP checks: curl not found" >&2
	fi
else
	echo "test-auth failed to listen on $auth_port" >&2
	kill "$auth_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$auth_pid" >/dev/null 2>&1 || true

# With -A every connection is authenticated as the server's own account. Both
# DF_AUTHENTICATED and DF_AUTH_AUTO must be set, and the pre-existing bits must
# survive: axil_set_flags() assigns rather than ors, so dropping the or would
# clear DF_CONNECTED and remove the descriptor from iteration.
if command -v python3 >/dev/null 2>&1; then
	autoauth_port=$(free_port $((port + 12)))
	$testauth -p "$autoauth_port" -C "$auth_dir" -A >/dev/null 2>&1 &
	autoauth_pid=$!
	note_server "$autoauth_pid"

	if wait_for_port_tcp "$autoauth_port"; then
		on=$(python3 ./test-ws.py "$autoauth_port" --flags | sed -n 's/^wsflags //p')
		case "$on" in
		*"auto=1"*"auth=1"*) ;;
		*)
			echo "Test FAILED! auth-autoauth-on: expected DF_AUTH_AUTO and DF_AUTHENTICATED set under -A, got '$on'" >&2
			exit 1
			;;
		esac

		# The descriptor must still be dispatched, i.e. DF_CONNECTED survived
		# the flag write rather than being cleared by the assignment.
		after=$(curl -sS --max-time 2 "http://127.0.0.1:$autoauth_port/disconnects" | tr -d '[:space:]')
		[ "${after:-0}" -ge 1 ] 2>/dev/null || {
			echo "Test FAILED! auth-autoauth-conn: request was not dispatched (DF_CONNECTED lost), disconnects='$after'" >&2
			exit 1
		}
	else
		echo "test-auth -A failed to listen on $autoauth_port" >&2
		kill "$autoauth_pid" >/dev/null 2>&1 || true
		exit 1
	fi

	kill "$autoauth_pid" >/dev/null 2>&1 || true
else
	echo "Skipping -A auth checks: python3 not found" >&2
fi

route_port=$(free_port $((port + 15)))
route_dir=$(mktemp -d)
note_dir "$route_dir"
# axil_respond_file() derives the MIME type from the extension and 404s when
# there is none, so the fixture must end in .txt for both routes to serve it.
sendfile_fixture=$route_dir/fixture.txt
head -c 65536 /dev/zero | tr '\0' 'A' >"$sendfile_fixture"
sendfile_size=$(wc -c <"$sendfile_fixture" | tr -d ' ')
# T9 counts "request_handle:" lines for /ws-unwatched, so the routes server
# keeps a log instead of discarding its output.
$testroutes -p "$route_port" -f "$sendfile_fixture" >"$route_dir/routes.log" 2>&1 &
route_pid=$!
note_server "$route_pid"

if wait_for_port_tcp "$route_port"; then
	if command -v curl >/dev/null 2>&1; then
		assert_contains route-song "amazing_grace" sh -c "curl -sS --max-time 2 http://127.0.0.1:$route_port/song/amazing_grace/"
		assert_contains route-edit "edit:test-book" sh -c "curl -sS --max-time 2 'http://127.0.0.1:$route_port/sb/test-book/edit?foo=bar'"
		assert_contains route-catchall "catchall" sh -c "curl -sS --max-time 2 http://127.0.0.1:$route_port/sb/test-book/delete"
		assert_contains route-chords "chords:amazing_grace" sh -c "curl -sS --max-time 2 http://127.0.0.1:$route_port/chords/amazing_grace"
		assert_contains respond-coop "Cross-Origin-Opener-Policy: same-origin" fetch_headers "$route_port" "/song/amazing_grace/"
		assert_contains respond-coep "Cross-Origin-Embedder-Policy: require-corp" fetch_headers "$route_port" "/song/amazing_grace/"
		assert_contains respond-corp "Cross-Origin-Resource-Policy: same-origin" fetch_headers "$route_port" "/song/amazing_grace/"

		# T1 (P1-5): the header terminator arrives in a second segment, so
		# the request is only complete after reassembly. At HEAD the head was
		# dispatched on the first short read and the probe header was lost.
		# python3 gives finer control; split_request() is the nc fallback so
		# the test does not skip on a box without it.
		if command -v python3 >/dev/null 2>&1; then
			split=$(python3 ./test-split.py "$route_port" GET /echo-header \
				"" 37 0.05 'X-Probe: split-ok\r\n')
			echo "$split" | grep -F "split-ok" >/dev/null 2>&1 || {
				echo "Test FAILED! route-split-head: segmented request head not reassembled" >&2
				echo "got: $split" >&2
				exit 1
			}

			# T3 (P0-3): complete head, body in a second segment. At HEAD
			# buffer_post_body() saw EAGAIN on a non-blocking socket and
			# closed the connection.
			split=$(python3 ./test-split.py "$route_port" POST /echo-body \
				"hello-body")
			echo "$split" | grep -F "hello-body" >/dev/null 2>&1 || {
				echo "Test FAILED! route-split-body: segmented request body dropped" >&2
				echo "got: $split" >&2
				exit 1
			}
		elif command -v nc >/dev/null 2>&1; then
			split=$(split_request "$route_port" \
				'GET /echo-header HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Probe: split-' \
				'ok\r\nConnection: close\r\n\r\n')
			echo "$split" | grep -F "split-ok" >/dev/null 2>&1 || {
				echo "Test FAILED! route-split-head: segmented request head not reassembled" >&2
				echo "got: $split" >&2
				exit 1
			}
			split=$(split_request "$route_port" \
				'POST /echo-body HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\n' \
				'hello-body')
			echo "$split" | grep -F "hello-body" >/dev/null 2>&1 || {
				echo "Test FAILED! route-split-body: segmented request body dropped" >&2
				echo "got: $split" >&2
				exit 1
			}
		else
			echo "Skipping segmented request tests: python3 or nc not found" >&2
		fi

		# T8: a body larger than one BUFSIZ-served read has to arrive whole.
		#
		# Completeness is checked against a per-run token in the last bytes of
		# the body, not with strlen: buffer_post_body() appends the body to the
		# shared `input` buffer without writing a terminator, so strlen() also
		# counts the previous request's leftovers (a 10 KB body reads back as
		# 16308 after a 300 KB one) and can run past the allocation. See
		# route_echo_size in test-routes.c.
		big_size=$((300 * 1024))
		big_tok=$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')
		head -c "$((big_size - ${#big_tok}))" /dev/zero | tr '\0' 'B' \
			>"$route_dir/big.bin"
		printf '%s' "$big_tok" >>"$route_dir/big.bin"
		big=$(curl -sS --max-time 20 -H "X-Body-Tail: $big_tok" \
			--data-binary "@$route_dir/big.bin" \
			"http://127.0.0.1:$route_port/echo-size" | tr -d '\r')
		[ "$big" = "declared=$big_size strlen=$big_size tail=ok" ] || {
			echo "Test FAILED! route-big-body: $big" >&2
			exit 1
		}

		# T8 (2.1): the same, but the body arrives in pieces with a pause in
		# front of it. curl streams fast enough that buffer_post_body() never
		# sees EAGAIN, so the check above also passes with the pre-fix code,
		# which treated a short read exactly like a disconnect. The pause is
		# what forces the stall path.
		if command -v python3 >/dev/null 2>&1; then
			stalled=$(python3 ./test-split.py --slow-body "$route_port" \
				/echo-size 65536 0.001 0.0005 4 2>&1)
			case "$stalled" in
			*"declared=65536 strlen=65536 tail=ok"*) ;;
			*)
				echo "Test FAILED! route-stalled-body: $(echo "$stalled" | tail -n1)" >&2
				exit 1
				;;
			esac
		fi

		# T8 (1.4): a head over MAX_REQUEST_HEAD must be refused with 431
		# instead of being stashed forever. python3-only: the equivalent
		# shell+nc loop drops the reply whenever the server closes while the
		# rest of the request is still queued, which is not reproducible.
		if command -v python3 >/dev/null 2>&1; then
			cap=$(python3 ./test-split.py --big-head "$route_port" 1600 2>&1 |
				head -n1)
			echo "$cap" | grep -qF "431" || {
				echo "Test FAILED! route-head-cap: no 431 ('$cap')" >&2
				exit 1
			}
		fi

		# T8: an unregistered method must still reach cmd_proc(). At HEAD
		# head_complete() only accepted GET/POST/HEAD/PUT/DELETE, so OPTIONS
		# was never parsed and the registered OPTIONS callback never ran.
		#
		# The probe has to run while the sending socket is still open:
		# axil_read() also dispatches a partial head when the client closes
		# (its rd == 0 branch), so checking after nc exits would pass even
		# with the whitelist back.
		if command -v nc >/dev/null 2>&1; then
			{
				printf 'OPTIONS /song/x HTTP/1.1\r\nHost: h\r\n\r\n'
				sleep 3
			} | nc -w 3 127.0.0.1 "$route_port" >/dev/null 2>&1 &
			opt_pid=$!
			note_server "$opt_pid"
			tries=20
			got=none
			while [ $tries -gt 0 ]; do
				got=$(fetch_body "$route_port" "/unknown-methods" | tr -d '\r')
				[ "$got" = "OPTIONS /song/x" ] && break
				tries=$((tries - 1))
				sleep 0.1
			done
			wait "$opt_pid" >/dev/null 2>&1 || true
			[ "$got" = "OPTIONS /song/x" ] || {
				echo "Test FAILED! route-unknown-method: OPTIONS not dispatched (got '$got')" >&2
				exit 1
			}
		fi

		# T2/T4/T5a (P0-2, P1-5): the event loop under stalled clients and
		# the WebSocket byte relay. python3-only, and /ws-echo is POSIX-only
		# (fork + socketpair + OpenSSL in test-routes.c).
		case "$(uname -s)" in
		MinGW* | MSYS* | MINGW* | Windows* | CYGWIN*) ws_posix=0 ;;
		*) ws_posix=1 ;;
		esac
		if [ "$ws_posix" = 1 ] && command -v python3 >/dev/null 2>&1; then
			for ws_flag in --slowloris --split --large; do
				python3 ./test-ws.py "$route_port" "$ws_flag" || {
					echo "Test FAILED! route-ws $ws_flag" >&2
					exit 1
				}
			done
		else
			echo "Skipping WebSocket tests: python3 or POSIX-only route missing" >&2
		fi

		# T6 (change 5 + P1-7): both public static-file entry points must
		# deliver the whole file. At HEAD axil_respond_file() armed
		# DF_TO_CLOSE and closed before the body was written.
		for sf_route in /sendfile /respond-file; do
			cl=$(fetch_header_value "$route_port" "$sf_route" "Content-Length")
			[ "$cl" = "$sendfile_size" ] || {
				echo "Test FAILED! static-len$sf_route: Content-Length $cl != $sendfile_size" >&2
				exit 1
			}
			got=$(curl -sS --max-time 5 "http://127.0.0.1:$route_port$sf_route" | wc -c | tr -d ' ')
			[ "$got" = "$sendfile_size" ] || {
				echo "Test FAILED! static-body$sf_route: got $got bytes, want $sendfile_size" >&2
				exit 1
			}
			head_cl=$(curl -sS --max-time 5 -I \
				"http://127.0.0.1:$route_port$sf_route" |
				tr -d '\r' | grep -i "^content-length:" |
				sed 's/^[^:]*: *//')
			[ "$head_cl" = "$sendfile_size" ] || {
				echo "Test FAILED! static-head$sf_route: HEAD Content-Length '$head_cl' != $sendfile_size" >&2
				exit 1
			}
			# A HEAD response must carry the headers and no body at all.
			# Count only what follows the blank line, not the headers.
			head_body=$(curl -sS --max-time 5 -I \
				"http://127.0.0.1:$route_port$sf_route" |
				sed '1,/^.$/d' | wc -c | tr -d ' ')
			[ "$head_body" = "0" ] || {
				echo "Test FAILED! static-head$sf_route: HEAD returned a $head_body byte body" >&2
				exit 1
			}
		done

		# T9 (SECURITY.md S0.3): the WebSocket *frame* layer, which the
		# /ws-echo relay above never reaches -- its child speaks raw bytes,
		# so ws_read()/ws_write() are not called. These go through
		# axil_ws_upgrade() + axil_fd_watch() for real.
		if [ "$ws_posix" = 1 ] && command -v python3 >/dev/null 2>&1; then
			for t9_case in "16:" "20000:" "20000:--split" "16:--close"; do
				t9_n=${t9_case%%:*}
				t9_flag=${t9_case#*:}
				# shellcheck disable=SC2086 # empty t9_flag must expand to nothing
				assert_contains "ws-frame-echo-${t9_n}${t9_flag:-plain}" "ws=ok" \
					sh -c "python3 ./test-split.py --ws-echo $route_port /ws-frames $t9_n $t9_flag"
			done

			# T9/S6.7: exactly one Close frame for a client-initiated close.
			# ws_read() echoes one and axil_close() then sent a second, which
			# a browser rejects as "Close received after close". The `16:--close`
			# case above already fails if a second frame follows the echo; this
			# names the property.
			assert_contains ws-frame-close-once "second=none" \
				sh -c "python3 ./test-split.py --ws-echo $route_port /ws-frames 16 --close"

			# T9/S1.4: the upgrade request must be dispatched exactly once per
			# connection, not once per frame. The pattern omits the slash after
			# GET because the replay is logged truncated ("GET ws-unwatche"),
			# so matching the slash would count upgrades only.
			tries=30
			before=0
			while [ $tries -gt 0 ]; do
				before=$(grep -c 'request_handle:.*ws-unwatche' "$route_dir/routes.log" 2>/dev/null || :)
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
				after=$(grep -c 'request_handle:.*ws-unwatche' "$route_dir/routes.log" 2>/dev/null || :)
				[ "${after:-0}" -ge $((before + 3)) ] 2>/dev/null && break
				tries=$((tries - 1)); sleep 0.1
			done
			[ "${after:-0}" = "3" ] || {
				echo "Test FAILED! ws-no-redispatch: $after dispatches for 3 frames, want 3" >&2
				exit 1
			}

			# T9/S2.4: two frames written back to back in one tick, the first
			# too big for the socket buffers. A header sent on the raw socket
			# instead of through the write queue either overtakes the queued
			# payload ahead of it or is lost to EAGAIN, and this client then
			# does not get two intact frames in order.
			assert_contains ws-frame-pair-order "ws=ok" \
				sh -c "python3 ./test-split.py --ws-pair $route_port /ws-pair 131072"

			# T9/S4.3: a printf larger than the internal BUFSIZ buffer must
			# clamp instead of sending ~12 KiB of process memory past a
			# static buffer, and must set FIN (finding 10 used `&`).
			assert_contains ws-printf-clamped "ws=ok" \
				sh -c "python3 ./test-split.py --ws-printf $route_port /ws-printf 20000"

			# T9/S6.2: a zero-length destination is a caller error, not a
			# way to switch off the bounds check. `if (data && len && pl + 1
			# > len)` meant len == 0 skipped the check and then wrote
			# pl + 1 bytes into a buffer the caller had said held nothing;
			# /ws-len0 passes a real malloc(0), so the pre-fix build is a
			# heap-buffer-overflow of 17 bytes under ASan.
			python3 ./test-split.py --ws-echo "$route_port" /ws-len0 16 \
				--send-only >/dev/null 2>&1 || true
			tries=30
			while [ $tries -gt 0 ]; do
				grep -q '^len0 ret=' "$route_dir/routes.log" 2>/dev/null && break
				tries=$((tries - 1)); sleep 0.1
			done
			len0=$(sed -n 's/^len0 \(ret=[^ ]* errno=[0-9]*\).*/\1/p' \
				"$route_dir/routes.log" 2>/dev/null | head -n1)
			[ "$len0" = "ret=-1 errno=90" ] || {
				echo "Test FAILED! ws-read-zero-len: got '${len0:-no result}', want 'ret=-1 errno=90'" >&2
				exit 1
			}
			echo "PASS ws-read-zero-len (EMSGSIZE)"

			# T9/S6.3: a client frame with the MASK bit clear is a protocol
			# error (RFC 6455 5.1). The 4-byte key was read unconditionally and
			# the bit was never tested, so an unmasked frame ate 4 payload bytes
			# as its key and then waited for 4 more that never arrive: EAGAIN
			# forever, the tick never progressed, and with no idle reaper the fd
			# was never reclaimed. The server must answer with a close carrying
			# 1002. Silence *is* the pre-fix behaviour, so the client's own
			# timeout is a failure, not a pass. No dedicated server needed.
			unmask=$(timeout 30 python3 ./test-split.py --ws-echo "$route_port" \
				/ws-frames 16 --unmask 2>&1 || true)
			echo "$unmask" | grep -q '^ws=ok$' &&
				echo "$unmask" | grep -q '^close=1002$' || {
				echo "Test FAILED! ws-unmask: want ws=ok and close=1002, got '$(echo "$unmask" | grep -E '^(ws|close)=' | tr '\n' ' ')'" >&2
				exit 1
			}
			echo "PASS ws-unmask (MASK bit clear refused with 1002)"

			# T9/S6.5: the public axil_ws_* wrappers must bound-check the
			# descriptor. They indexed frame_map[], ws_flags[], descr_map[]
			# and io[] -- all [FD_SETSIZE] -- with whatever they were
			# handed, while every other public entry point, axil_close()
			# included, rejects one outside the range. Run as its own
			# process: pre-fix this segfaults on io[-1].lower_read, and from
			# a route that would take the whole server down.
			if LD_LIBRARY_PATH=./lib $testroutes -B \
				>"$route_dir/fdbounds.log" 2>&1; then
				echo "PASS ws-fd-bounds (axil_ws_* reject fd outside [0, FD_SETSIZE))"
			else
				echo "Test FAILED! ws-fd-bounds: axil_ws_* accepted an out-of-range descriptor: $(tr '\n' ';' <"$route_dir/fdbounds.log" | cut -c1-200)" >&2
				exit 1
			fi

			# T9/S6.4: a control frame must declare at most 125 bytes of
			# payload (RFC 6455 5.5) -- precisely because it is never
			# fragmented. The old parser imposed no limit, so a 200-byte ping
			# was read as an ordinary data frame, unmasked, handed to the
			# caller as application data and echoed back. pl=126 op=8 is the
			# 2-byte extended length form, which also desynchronised: the
			# opcode 8 branch returned before the extended length was read.
			for s64 in "200 9 ping" "126 8 close"; do
				set -- $s64
				s64_pl=$1; s64_op=$2; s64_name=$3
				ctl=$(timeout 30 python3 ./test-split.py --ws-ctl \
					"$route_port" /ws-frames "$s64_pl" "$s64_op" 2>&1 || true)
				echo "$ctl" | grep -q '^ws=ok$' &&
					echo "$ctl" | grep -q '^close=1002$' || {
					echo "Test FAILED! ws-ctl-$s64_name: want ws=ok and close=1002, got '$(echo "$ctl" | grep -E '^(ws|close|recv)=' | tr '\n' ' ')'" >&2
					exit 1
				}
				echo "PASS ws-ctl-$s64_name (control frame pl=$s64_pl refused with 1002)"
			done

			# T9/S6.1: a read interrupted by a signal reports EINTR, which is
			# neither a closed peer nor a protocol error. Passing it on as a 0
			# is indistinguishable from the peer closing, so an app that stops
			# reading on 0 drops healthy connections whenever a SIGCHLD or a
			# timer fires. The dedicated server injects one EINTR mid-payload:
			# with the retry in ws_fill() the frame completes and is echoed,
			# without it the connection is torn down mid-frame and the echo
			# never arrives.
			# A dedicated server because AXIL_TEST_WS_EINTR is process-wide and
			# would fire on every other T9 case sharing it.
			eintr_port=$((route_port + 4))
			LD_LIBRARY_PATH=./lib AXIL_TEST_WS_EINTR=1 \
				./bin/test-routes -p "$eintr_port" \
				>"$route_dir/eintr.routes.log" 2>&1 &
			eintr_pid=$!
			tries=60
			while [ $tries -gt 0 ]; do
				curl -sS --max-time 2 "http://127.0.0.1:$eintr_port/health" \
					>/dev/null 2>&1 && break
				tries=$((tries - 1)); sleep 0.2
			done
			assert_contains ws-eintr-retried "ws=ok" \
				sh -c "timeout 30 python3 ./test-split.py --ws-echo $eintr_port /ws-frames 20000 --split"
			kill "$eintr_pid" >/dev/null 2>&1
			wait "$eintr_pid" >/dev/null 2>&1 || true

			# T9/S5.4: a frame payload abandoned by a server-side close must be
			# freed at teardown. Asserted from a valgrind log on a dedicated
			# server, because the leak is invisible to every cheaper
			# observable: frame_map is a global, so LeakSanitizer classifies
			# the block as still reachable and stays quiet; the kernel merges
			# adjacent VMAs, so /proc/PID/maps under-reports it; and an
			# unwritten payload is untouched mmap space that moves no RSS.
			# All three were tried against the unfixed code and all three
			# passed. Measured: 16 KB baseline, 8.4 MB with the payload
			# retained, so the 1 MiB threshold is not near either side.
			leak_port=$((route_port + 3))
			vg_log="$route_dir/valgrind-s5.log"
			# valgrind cannot run an ASan-instrumented binary: the sanitizer
			# runtime refuses to initialise under it and the server never comes
			# up. Detect the instrumentation instead of letting that look like a
			# failed assertion.
			leak_asan=0
			if command -v nm >/dev/null 2>&1 &&
				nm ./bin/test-routes 2>/dev/null | grep -q "__asan_init"
			then
				leak_asan=1
			fi
			if [ "$leak_asan" = 1 ]; then
				echo "Skipping ws-frame-freed-on-teardown: ASan build, valgrind cannot run it" >&2
			elif command -v valgrind >/dev/null 2>&1; then
				valgrind --leak-check=full --show-leak-kinds=all \
					--log-file="$vg_log" ./bin/test-routes -p "$leak_port" \
					>"$route_dir/valgrind-s5.routes.log" 2>&1 &
				leak_pid=$!
				tries=60
				while [ $tries -gt 0 ]; do
					curl -sS --max-time 2 "http://127.0.0.1:$leak_port/health" \
						>/dev/null 2>&1 && break
					tries=$((tries - 1)); sleep 0.2
				done
				if ! python3 ./test-split.py --ws-leak "$leak_port" /ws-leak 4 \
					>/dev/null 2>&1
				then
					echo "Test FAILED! ws-leak-setup: server did not park and close" >&2
					kill "$leak_pid" >/dev/null 2>&1
					exit 1
				fi
				kill "$leak_pid" >/dev/null 2>&1
				wait "$leak_pid" >/dev/null 2>&1 || true
				reachable=$(sed -n 's/.*still reachable: \([0-9,]*\) bytes.*/\1/p' \
					"$vg_log" 2>/dev/null | tr -d , | head -n1)
				[ -n "$reachable" ] && [ "$reachable" -le 1048576 ] || {
					echo "Test FAILED! ws-frame-freed-on-teardown: ${reachable:-no summary} bytes still reachable, want <= 1048576" >&2
					exit 1
				}
				echo "PASS ws-frame-freed-on-teardown ($reachable bytes still reachable)"
			else
				echo "Skipping ws-frame-freed-on-teardown: valgrind not found" >&2
			fi

			assert_contains ws-server-healthy "no-probe" \
				sh -c "curl -sS --max-time 5 http://127.0.0.1:$route_port/echo-header"
		fi
	else
		echo "Skipping route matcher checks: curl not found" >&2
	fi
else
	echo "test-routes failed to listen on $route_port" >&2
	kill "$route_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$route_pid" >/dev/null 2>&1 || true
rm -rf "$route_dir"

defer_dir=$(mktemp -d)
note_dir "$defer_dir"
defer_status="$defer_dir/ready"
defer_port=$(free_port $((port + 25)))
$testdefer -p "$defer_port" -s "$defer_status" >/dev/null 2>&1 &
defer_pid=$!
note_server "$defer_pid"

if wait_for_port_tcp "$defer_port"; then
	if command -v curl >/dev/null 2>&1; then
		# defer -> finish delivers the deferred body
		rm -f "$defer_status"
		curl -sS --max-time 10 -o "$defer_dir/a.txt" "http://127.0.0.1:$defer_port/defer" &
		curl_pid=$!
		note_server "$curl_pid"
		tries=50
		while [ $tries -gt 0 ]; do
			[ -f "$defer_status" ] && break
			tries=$((tries - 1))
			sleep 0.1
		done
		[ -f "$defer_status" ] || { echo "defer never became ready" >&2; exit 1; }
		fin=$(curl -sS --max-time 5 "http://127.0.0.1:$defer_port/finish")
		[ "$fin" = "finished-ok" ] || { echo "finish route reply wrong: $fin" >&2; exit 1; }
		wait "$curl_pid" >/dev/null 2>&1 || true
		grep -F "deferred-ok" "$defer_dir/a.txt" >/dev/null 2>&1 ||
			{ echo "deferred body missing after finish" >&2; exit 1; }

		# defer -> abort closes without a body
		rm -f "$defer_status" "$defer_dir/b.txt"
		curl -sS --max-time 10 -o "$defer_dir/b.txt" "http://127.0.0.1:$defer_port/defer" &
		curl_pid=$!
		note_server "$curl_pid"
		tries=50
		while [ $tries -gt 0 ]; do
			[ -f "$defer_status" ] && break
			tries=$((tries - 1))
			sleep 0.1
		done
		[ -f "$defer_status" ] || { echo "defer never became ready (abort)" >&2; exit 1; }
		curl -sS --max-time 5 "http://127.0.0.1:$defer_port/abort" >/dev/null
		wait "$curl_pid" >/dev/null 2>&1 || true
		[ ! -s "$defer_dir/b.txt" ] ||
			{ echo "aborted deferred request got a body" >&2; exit 1; }

		# client disconnect before finish must leave the server safe
		rm -f "$defer_status"
		curl -sS --max-time 1 -o /dev/null "http://127.0.0.1:$defer_port/defer" 2>/dev/null &
		curl_pid=$!
		note_server "$curl_pid"
		tries=50
		while [ $tries -gt 0 ]; do
			[ -f "$defer_status" ] && break
			tries=$((tries - 1))
			sleep 0.1
		done
		[ -f "$defer_status" ] || { echo "defer never became ready (stale)" >&2; exit 1; }
		wait "$curl_pid" >/dev/null 2>&1 || true
		sleep 1
		fin=$(curl -sS --max-time 5 "http://127.0.0.1:$defer_port/finish")
		[ "$fin" = "finished-ok" ] || { echo "finish after stale handle wrong: $fin" >&2; exit 1; }
		assert_contains defer-stale-alive "pong" fetch_body "$defer_port" "/ping"

		# double-finish idempotency
		rm -f "$defer_status" "$defer_dir/c.txt"
		curl -sS --max-time 10 -o "$defer_dir/c.txt" "http://127.0.0.1:$defer_port/defer" &
		curl_pid=$!
		note_server "$curl_pid"
		tries=50
		while [ $tries -gt 0 ]; do
			[ -f "$defer_status" ] && break
			tries=$((tries - 1))
			sleep 0.1
		done
		[ -f "$defer_status" ] || { echo "defer never became ready (double)" >&2; exit 1; }
		curl -sS --max-time 5 "http://127.0.0.1:$defer_port/double" >/dev/null
		wait "$curl_pid" >/dev/null 2>&1 || true
		grep -F "deferred-ok" "$defer_dir/c.txt" >/dev/null 2>&1 ||
			{ echo "double-finish lost first body" >&2; exit 1; }
		assert_contains defer-double-alive "pong" fetch_body "$defer_port" "/ping"
	else
		echo "Skipping defer HTTP checks: curl not found" >&2
	fi
else
	echo "test-defer failed to listen on $defer_port" >&2
	kill "$defer_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$defer_pid" >/dev/null 2>&1 || true

static_dir=$(mktemp -d)
note_dir "$static_dir"
mkdir -p "$static_dir/public"
printf "<!doctype html><title>static</title>\n" >"$static_dir/public/index.html"
printf "\0asm\1\0\0\0" >"$static_dir/public/app.wasm"
printf "outside static root\n" >"$static_dir/secret.txt"
ln -s ../secret.txt "$static_dir/public/escape.txt"
printf "public /*\n" >"$static_dir/serve.allow"
static_port=$(free_port $((port + 18)))
$axil -d -p "$static_port" -C "$static_dir" >/dev/null 2>&1 &
static_pid=$!
note_server "$static_pid"

if wait_for_port_tcp "$static_port"; then
	assert_contains static-coop "Cross-Origin-Opener-Policy: same-origin" fetch_headers "$static_port" "/index.html"
	assert_contains static-coep "Cross-Origin-Embedder-Policy: require-corp" fetch_headers "$static_port" "/index.html"
	assert_contains static-corp "Cross-Origin-Resource-Policy: same-origin" fetch_headers "$static_port" "/index.html"
	assert_contains wasm-type "Content-Type: application/wasm" fetch_headers "$static_port" "/app.wasm"
	assert_contains wasm-coep "Cross-Origin-Embedder-Policy: require-corp" fetch_headers "$static_port" "/app.wasm"
	if command -v curl >/dev/null 2>&1; then
		for traversal in \
			'/%2e%2e/secret.txt' \
			'/%2E%2E%2fsecret.txt' \
			'/%252e%252e/secret.txt' \
			'/safe%2f..%2fsecret.txt' \
			'/%2e%2e%5csecret.txt' \
			'/%2e%2/secret.txt'
		do
			body=$(curl --path-as-is -sS --max-time 2 \
				"http://127.0.0.1:$static_port$traversal" 2>/dev/null || true)
			[ "$body" != "outside static root" ] || {
				echo "traversal served secret: $traversal" >&2
				exit 1
			}
		done
		body=$(curl --path-as-is -sS --max-time 2 \
			"http://127.0.0.1:$static_port/escape.txt" 2>/dev/null || true)
		[ "$body" != "outside static root" ] || {
			echo "static symlink escaped configured root" >&2
			exit 1
		}
		assert_contains cache-default "Cache-Control: no-cache" fetch_headers "$static_port" "/index.html"
		assert_contains cache-etag "ETag:" fetch_headers "$static_port" "/index.html"
		assert_contains cache-lmod "Last-Modified:" fetch_headers "$static_port" "/index.html"
		etag=$(fetch_header_value "$static_port" "/index.html" "ETag")
		lmod=$(fetch_header_value "$static_port" "/index.html" "Last-Modified")
		[ -n "$etag" ] || { echo "static ETag value missing" >&2; exit 1; }
		[ -n "$lmod" ] || { echo "static Last-Modified value missing" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" -H "If-None-Match: $etag")
		echo "$status" | grep -F "304 Not Modified" >/dev/null 2>&1 ||
			{ echo "If-None-Match did not yield 304" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" -H "If-Modified-Since: $lmod")
		echo "$status" | grep -F "304 Not Modified" >/dev/null 2>&1 ||
			{ echo "If-Modified-Since did not yield 304" >&2; exit 1; }
		future_lmod=$(LC_ALL=C date -u -d "now + 1 hour" +"%a, %d %b %Y %H:%M:%S GMT" 2>/dev/null ||
			echo "Sat, 15 Aug 2036 12:00:00 GMT")
		status=$(fetch_status_hdr "$static_port" "/index.html" -H "If-Modified-Since: $future_lmod")
		echo "$status" | grep -F "304 Not Modified" >/dev/null 2>&1 ||
			{ echo "If-Modified-Since future date did not yield 304" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" -H "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT")
		echo "$status" | grep -F "200 OK" >/dev/null 2>&1 ||
			{ echo "If-Modified-Since past date did not yield 200" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" \
			-H "If-None-Match: \"bogus-etag\"" -H "If-Modified-Since: $lmod")
		echo "$status" | grep -F "200 OK" >/dev/null 2>&1 ||
			{ echo "If-None-Match did not take precedence over If-Modified-Since" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" -H "If-None-Match: *")
		echo "$status" | grep -F "304 Not Modified" >/dev/null 2>&1 ||
			{ echo "If-None-Match * did not yield 304" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" \
			-H "If-None-Match: \"nope\", $etag")
		echo "$status" | grep -F "304 Not Modified" >/dev/null 2>&1 ||
			{ echo "If-None-Match list with matching tag did not yield 304" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" \
			-H "If-None-Match: \"aaa\", \"bbb\"")
		echo "$status" | grep -F "200 OK" >/dev/null 2>&1 ||
			{ echo "If-None-Match list without match did not yield 200" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" \
			-H "If-Modified-Since: not-a-date")
		echo "$status" | grep -F "200 OK" >/dev/null 2>&1 ||
			{ echo "unparseable If-Modified-Since did not yield 200" >&2; exit 1; }
		empty_304=$(curl -sS --max-time 2 -H "If-None-Match: $etag" \
			"http://127.0.0.1:$static_port/index.html")
		[ -z "$empty_304" ] ||
			{ echo "304 Not Modified carried a body" >&2; exit 1; }
		cl_304=$(curl -sS -i --max-time 2 -H "If-None-Match: $etag" \
			"http://127.0.0.1:$static_port/index.html" | tr -d '\r' |
			grep -i "^Content-Length:" || true)
		[ -z "$cl_304" ] ||
			{ echo "304 Not Modified sent Content-Length" >&2; exit 1; }
		coep_304=$(curl -sS -i --max-time 2 -H "If-None-Match: $etag" \
			"http://127.0.0.1:$static_port/index.html" | tr -d '\r' |
			grep -i "Cross-Origin-Embedder-Policy: require-corp" || true)
		[ -n "$coep_304" ] ||
			{ echo "304 Not Modified missing COEP" >&2; exit 1; }
		coop_304=$(curl -sS -i --max-time 2 -H "If-None-Match: $etag" \
			"http://127.0.0.1:$static_port/index.html" | tr -d '\r' |
			grep -i "Cross-Origin-Opener-Policy: same-origin" || true)
		[ -n "$coop_304" ] ||
			{ echo "304 Not Modified missing COOP" >&2; exit 1; }
		date_304=$(curl -sS -i --max-time 2 -H "If-None-Match: $etag" \
			"http://127.0.0.1:$static_port/index.html" | tr -d '\r' |
			grep -i "^Date:" || true)
		[ -n "$date_304" ] ||
			{ echo "304 Not Modified missing Date" >&2; exit 1; }
		server_304=$(curl -sS -i --max-time 2 -H "If-None-Match: $etag" \
			"http://127.0.0.1:$static_port/index.html" | tr -d '\r' |
			grep -i "^Server:" || true)
		[ -n "$server_304" ] ||
			{ echo "304 Not Modified missing Server" >&2; exit 1; }
		sleep 1
		printf "<!-- stale-check -->\n" >> "$static_dir/public/index.html"
		status=$(fetch_status_hdr "$static_port" "/index.html" -H "If-None-Match: $etag")
		echo "$status" | grep -F "200 OK" >/dev/null 2>&1 ||
			{ echo "stale If-None-Match did not yield 200" >&2; exit 1; }
		status=$(fetch_status_hdr "$static_port" "/index.html" -H "If-Modified-Since: $lmod")
		echo "$status" | grep -F "200 OK" >/dev/null 2>&1 ||
			{ echo "stale If-Modified-Since did not yield 200" >&2; exit 1; }
		new_etag=$(fetch_header_value "$static_port" "/index.html" "ETag")
		[ "$new_etag" != "$etag" ] ||
			{ echo "ETag did not change after file edit" >&2; exit 1; }
		body=$(curl -sS --max-time 2 "http://127.0.0.1:$static_port/index.html")
		echo "$body" | grep -F "stale-check" >/dev/null 2>&1 ||
			{ echo "stale body not served" >&2; exit 1; }
	else
		echo "Skipping cache validator tests: curl not found" >&2
	fi
else
	echo "static axil failed to listen on $static_port" >&2
	kill "$static_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$static_pid" >/dev/null 2>&1 || true

cache_dir=$(mktemp -d)
note_dir "$cache_dir"
mkdir -p "$cache_dir/public"
printf "body{color:red}\n" >"$cache_dir/public/data.css"
printf "body{color:blue}\n" >"$cache_dir/public/other.css"
printf "body{color:yellow}\n" >"$cache_dir/public/crlf.txt"
printf "<!doctype html><title>c</title>\n" >"$cache_dir/public/index.html"
printf "public /*\n" >"$cache_dir/serve.allow"
printf '# cache rules\n*.css public, max-age=86400\n/crlf.txt public, max-age=60\r\n\n/index.html public, max-age=31536000, immutable\n/index.html no-store\n' \
	>"$cache_dir/cache.allow"
cache_port=$(free_port $((port + 22)))
$axil -d -p "$cache_port" -C "$cache_dir" >/dev/null 2>&1 &
cache_pid=$!
note_server "$cache_pid"

if wait_for_port_tcp "$cache_port"; then
	if command -v curl >/dev/null 2>&1; then
		ctl=$(fetch_header_value "$cache_port" "/data.css" "Cache-Control")
		echo "$ctl" | grep -F "public, max-age=86400" >/dev/null 2>&1 ||
			{ echo "cache.allow *.css policy not applied" >&2; exit 1; }
		ctl=$(fetch_header_value "$cache_port" "/other.css" "Cache-Control")
		echo "$ctl" | grep -F "public, max-age=86400" >/dev/null 2>&1 ||
			{ echo "cache.allow *.css glob did not match /other.css" >&2; exit 1; }
		crlf_raw=$(curl -sS -i --max-time 2 "http://127.0.0.1:$cache_port/crlf.txt")
		echo "$crlf_raw" | grep -F "Cache-Control: public, max-age=60" >/dev/null 2>&1 ||
			{ echo "cache.allow CRLF-terminated rule not applied" >&2; exit 1; }
		doubled=$(printf 'public, max-age=60\r\r')
		echo "$crlf_raw" | grep -F "$doubled" >/dev/null 2>&1 &&
			{ echo "cache.allow CRLF not stripped from directive" >&2; exit 1; }
		ctl=$(fetch_header_value "$cache_port" "/index.html" "Cache-Control")
		echo "$ctl" | grep -F "public, max-age=31536000, immutable" >/dev/null 2>&1 ||
			{ echo "cache.allow first-match-wins broken" >&2; exit 1; }
		ctl=$(fetch_header_value "$cache_port" "/index.html" "Cache-Control")
		echo "$ctl" | grep -F "no-store" >/dev/null 2>&1 &&
			{ echo "cache.allow later rule won over first" >&2; exit 1; }
		printf "body{color:green}\n" >"$cache_dir/public/plain.txt"
		ctl=$(fetch_header_value "$cache_port" "/plain.txt" "Cache-Control")
		echo "$ctl" | grep -F "no-cache" >/dev/null 2>&1 ||
			{ echo "cache.allow default not no-cache" >&2; exit 1; }
	else
		echo "Skipping cache.allow tests: curl not found" >&2
	fi
else
	echo "cache axil failed to listen on $cache_port" >&2
	kill "$cache_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$cache_pid" >/dev/null 2>&1 || true

ai_dir=$(mktemp -d)
note_dir "$ai_dir"
cp tests/fixtures/autoindex/serve.allow "$ai_dir/serve.allow"
cp tests/fixtures/autoindex/serve.autoindex "$ai_dir/serve.autoindex"
cp -R tests/fixtures/autoindex/data "$ai_dir/data"
ai_port=$(free_port $((port + 30)))
$axil -d -p "$ai_port" -C "$ai_dir" >/dev/null 2>&1 &
ai_pid=$!
note_server "$ai_pid"

if wait_for_port_tcp "$ai_port"; then
	if command -v curl >/dev/null 2>&1; then
		assert http-200 fetch_status "$ai_port" "/"
		abody=$(curl -sS --max-time 2 "http://127.0.0.1:$ai_port/")
		echo "$abody" | grep -F "alpha.txt" >/dev/null 2>&1 || { echo "autoindex alpha missing" >&2; exit 1; }
		echo "$abody" | grep -F "beta.txt" >/dev/null 2>&1 || { echo "autoindex beta missing" >&2; exit 1; }
	else
		echo "Skipping autoindex tests: curl not found" >&2
	fi
else
	echo "autoindex axil failed to listen on $ai_port" >&2
	kill "$ai_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$ai_pid" >/dev/null 2>&1 || true

if command -v openssl >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
	tls_dir=$(mktemp -d)
	note_dir "$tls_dir"
	openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" \
		-keyout "$tls_dir/key.pem" -out "$tls_dir/cert.pem" -days 1 >/dev/null 2>&1
	printf "localhost:%s:%s\n" "$tls_dir/cert.pem" "$tls_dir/key.pem" >"$tls_dir/certs.txt"
	ssl_port=$(free_port $((port + 40)))
	http_port=$(free_port $((port + 41)))
	$axil -d -p "$http_port" -s "$ssl_port" -K "$tls_dir/certs.txt" >/dev/null 2>&1 &
	ssl_pid=$!
	note_server "$ssl_pid"

	if wait_for_port_tcp "$http_port"; then
		shead=$(curl -k -sS -i --max-time 2 "https://127.0.0.1:$ssl_port/" | sed -n '1p' | tr -d '\r')
		echo "$shead" | grep -F "HTTP/1.1" >/dev/null 2>&1 || { echo "TLS status missing" >&2; exit 1; }
		alpn=$(echo | openssl s_client -alpn h2,http/1.1 -connect "127.0.0.1:$ssl_port" \
			-servername localhost 2>/dev/null | grep -F "ALPN protocol:" | tr -d '\r')
		echo "$alpn" | grep -F "http/1.1" >/dev/null 2>&1 || {
			echo "ALPN did not select http/1.1: $alpn" >&2
			exit 1
		}
		echo "$alpn" | grep -F "h2" >/dev/null 2>&1 && {
			echo "ALPN selected h2: $alpn" >&2
			exit 1
		}
		if command -v nc >/dev/null 2>&1; then
			printf 'x' | nc -w 1 127.0.0.1 "$ssl_port" >/dev/null 2>&1 || true
		fi
		shead=$(curl -k -sS -i --max-time 2 "https://127.0.0.1:$ssl_port/" | sed -n '1p' | tr -d '\r')
		echo "$shead" | grep -F "HTTP/1.1" >/dev/null 2>&1 || {
			echo "TLS request after abort failed" >&2
			exit 1
		}
	else
		echo "tls axil failed to listen on $http_port" >&2
		kill "$ssl_pid" >/dev/null 2>&1 || true
		exit 1
	fi

	kill "$ssl_pid" >/dev/null 2>&1 || true
else
	echo "Skipping TLS tests: openssl or curl not found" >&2
fi
