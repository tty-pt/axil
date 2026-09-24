#!/bin/sh -e

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
	output=$("$@")
	echo "$output" | grep -F "$needle" >/dev/null 2>&1 && return 0
	echo "Test FAILED! $label missing '$needle'" >&2
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
mkdir -p "$auth_dir/sessions"
printf "tester\n" >"$auth_dir/sessions/abc"
auth_port=$((port + 10))
$testauth -p "$auth_port" -C "$auth_dir" >/dev/null 2>&1 &
auth_pid=$!

if wait_for_port_tcp "$auth_port"; then
	if command -v curl >/dev/null 2>&1; then
		assert_contains auth-none "auth none" sh -c "curl -sS --max-time 2 http://127.0.0.1:$auth_port/"
		assert_contains auth-ok "auth ok" sh -c "curl -sS --max-time 2 -H 'Cookie: session=abc' http://127.0.0.1:$auth_port/"
	else
		echo "Skipping auth HTTP checks: curl not found" >&2
	fi
else
	echo "test-auth failed to listen on $auth_port" >&2
	kill "$auth_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$auth_pid" >/dev/null 2>&1 || true

route_port=$((port + 15))
$testroutes -p "$route_port" >/dev/null 2>&1 &
route_pid=$!

if wait_for_port_tcp "$route_port"; then
	if command -v curl >/dev/null 2>&1; then
		assert_contains route-song "amazing_grace" sh -c "curl -sS --max-time 2 http://127.0.0.1:$route_port/song/amazing_grace/"
		assert_contains route-edit "edit:test-book" sh -c "curl -sS --max-time 2 'http://127.0.0.1:$route_port/sb/test-book/edit?foo=bar'"
		assert_contains route-catchall "catchall" sh -c "curl -sS --max-time 2 http://127.0.0.1:$route_port/sb/test-book/delete"
		assert_contains route-chords "chords:amazing_grace" sh -c "curl -sS --max-time 2 http://127.0.0.1:$route_port/chords/amazing_grace"
		assert_contains respond-coop "Cross-Origin-Opener-Policy: same-origin" fetch_headers "$route_port" "/song/amazing_grace/"
		assert_contains respond-coep "Cross-Origin-Embedder-Policy: require-corp" fetch_headers "$route_port" "/song/amazing_grace/"
		assert_contains respond-corp "Cross-Origin-Resource-Policy: same-origin" fetch_headers "$route_port" "/song/amazing_grace/"
	else
		echo "Skipping route matcher checks: curl not found" >&2
	fi
else
	echo "test-routes failed to listen on $route_port" >&2
	kill "$route_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$route_pid" >/dev/null 2>&1 || true

defer_dir=$(mktemp -d)
defer_status="$defer_dir/ready"
defer_port=$((port + 25))
$testdefer -p "$defer_port" -s "$defer_status" >/dev/null 2>&1 &
defer_pid=$!

if wait_for_port_tcp "$defer_port"; then
	if command -v curl >/dev/null 2>&1; then
		# defer -> finish delivers the deferred body
		rm -f "$defer_status"
		curl -sS --max-time 10 -o "$defer_dir/a.txt" "http://127.0.0.1:$defer_port/defer" &
		curl_pid=$!
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
mkdir -p "$static_dir/public"
printf "<!doctype html><title>static</title>\n" >"$static_dir/public/index.html"
printf "\0asm\1\0\0\0" >"$static_dir/public/app.wasm"
printf "outside static root\n" >"$static_dir/secret.txt"
ln -s ../secret.txt "$static_dir/public/escape.txt"
printf "public /*\n" >"$static_dir/serve.allow"
static_port=$((port + 18))
$axil -p "$static_port" -C "$static_dir" >/dev/null 2>&1 &
static_pid=$!

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
mkdir -p "$cache_dir/public"
printf "body{color:red}\n" >"$cache_dir/public/data.css"
printf "body{color:blue}\n" >"$cache_dir/public/other.css"
printf "body{color:yellow}\n" >"$cache_dir/public/crlf.txt"
printf "<!doctype html><title>c</title>\n" >"$cache_dir/public/index.html"
printf "public /*\n" >"$cache_dir/serve.allow"
printf '# cache rules\n*.css public, max-age=86400\n/crlf.txt public, max-age=60\r\n\n/index.html public, max-age=31536000, immutable\n/index.html no-store\n' \
	>"$cache_dir/cache.allow"
cache_port=$((port + 22))
$axil -p "$cache_port" -C "$cache_dir" >/dev/null 2>&1 &
cache_pid=$!

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
cp tests/fixtures/autoindex/serve.allow "$ai_dir/serve.allow"
cp tests/fixtures/autoindex/serve.autoindex "$ai_dir/serve.autoindex"
cp -R tests/fixtures/autoindex/data "$ai_dir/data"
ai_port=$((port + 30))
$axil -p "$ai_port" -C "$ai_dir" >/dev/null 2>&1 &
ai_pid=$!

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
	openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" \
		-keyout "$tls_dir/key.pem" -out "$tls_dir/cert.pem" -days 1 >/dev/null 2>&1
	printf "localhost:%s:%s\n" "$tls_dir/cert.pem" "$tls_dir/key.pem" >"$tls_dir/certs.txt"
	ssl_port=$((port + 40))
	http_port=$((port + 41))
	$axil -d -p "$http_port" -s "$ssl_port" -K "$tls_dir/certs.txt" >/dev/null 2>&1 &
	ssl_pid=$!

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
