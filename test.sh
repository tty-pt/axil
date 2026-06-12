#!/bin/sh -e

testbin=./bin/test
axil=./bin/axil
testauth=./bin/test-auth
testroutes=./bin/test-routes

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

static_dir=$(mktemp -d)
mkdir -p "$static_dir/public"
printf "<!doctype html><title>static</title>\n" >"$static_dir/public/index.html"
printf "\0asm\1\0\0\0" >"$static_dir/public/app.wasm"
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
else
	echo "static axil failed to listen on $static_port" >&2
	kill "$static_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$static_pid" >/dev/null 2>&1 || true

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
	else
		echo "tls axil failed to listen on $http_port" >&2
		kill "$ssl_pid" >/dev/null 2>&1 || true
		exit 1
	fi

	kill "$ssl_pid" >/dev/null 2>&1 || true
else
	echo "Skipping TLS tests: openssl or curl not found" >&2
fi
