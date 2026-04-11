#!/usr/bin/env bash
set -e

case "$(uname -s)" in
	Darwin) export DYLD_LIBRARY_PATH=./lib:${DYLD_LIBRARY_PATH} ;;
	*)      export LD_LIBRARY_PATH=./lib:${LD_LIBRARY_PATH} ;;
esac

port=$((20000 + RANDOM % 8000))
tmpout=$(mktemp)
trap 'rm -f "$tmpout"; kill "$mux_pid" 2>/dev/null; wait "$mux_pid" 2>/dev/null || true' EXIT

./bin/ndc -d -A -p "$port" -m ./mods/mux/libndc-mux >/dev/null 2>&1 &
mux_pid=$!

# WS key and expected accept
key=$(head -c 16 /dev/urandom | base64 | tr -d '\n')
accept=$(printf '%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11' "$key" \
	| openssl dgst -sha1 -binary | base64)

ws_request=$(printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n' \
	"$port" "$key")

# Poll until server responds with 101 (proves port open AND module loaded)
tries=50
resp=""
while [ $tries -gt 0 ]; do
	resp=$(printf '%s' "$ws_request" | nc -w1 127.0.0.1 "$port" 2>/dev/null | head -1 | tr -d '\r')
	[ "$resp" = "HTTP/1.1 101 Switching Protocols" ] && break
	tries=$((tries - 1))
	sleep 0.1
done
[ $tries -eq 0 ] && { echo "FAIL: ndc did not become ready" >&2; exit 1; }

# Now open the real connection
exec 3<>/dev/tcp/127.0.0.1/$port
printf '%s' "$ws_request" >&3

# Read HTTP response headers
resp=""
while IFS= read -r -t3 line <&3; do
	line="${line%$'\r'}"
	resp="$resp
$line"
	[ -z "$line" ] && break
done

echo "$resp" | grep -qF "101" \
	|| { echo "FAIL: no 101 in response" >&2; exit 1; }

got_accept=$(echo "$resp" | grep -i "sec-websocket-accept" \
	| sed 's/.*: *//' | tr -d '\r\n ')
[ "$got_accept" = "$accept" ] \
	|| { echo "FAIL: accept mismatch: got '$got_accept' want '$accept'" >&2; exit 1; }

# Collect WS frames for 1.5s
cat <&3 >"$tmpout" &
cat_pid=$!
sleep 0.05
kill $cat_pid 2>/dev/null || true
wait $cat_pid 2>/dev/null || true

hex=$(xxd -p "$tmpout" | tr -d '\n')
echo "$hex" | grep -qiF "fffd1f" || { echo "FAIL: IAC DO NAWS missing"   >&2; exit 1; }
echo "$hex" | grep -qiF "fffb01" || { echo "FAIL: IAC WILL ECHO missing" >&2; exit 1; }
echo "$hex" | grep -qiF "fffc03" || { echo "FAIL: IAC WONT SGA missing"  >&2; exit 1; }

# Send PTY commands (mask key = 00 00 00 00 → payload unchanged)
printf '\x82\x83\x00\x00\x00\x00sh\n' >&3
printf '\x82\x8e\x00\x00\x00\x00echo NDC_TEST\n' >&3

# Collect PTY output for 3s
: >"$tmpout"
cat <&3 >"$tmpout" &
cat_pid=$!
sleep 0.2
kill $cat_pid 2>/dev/null || true
wait $cat_pid 2>/dev/null || true

hex2=$(xxd -p "$tmpout" | tr -d '\n')
ndc_test_hex=$(printf 'NDC_TEST' | xxd -p | tr -d '\n')
echo "$hex2" | grep -qiF "$ndc_test_hex" \
	|| { echo "FAIL: PTY output NDC_TEST not seen" >&2; exit 1; }

echo "ws-mux ok"
