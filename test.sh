#!/bin/sh -e

testbin=./bin/test
ndc=./bin/ndc
testmux=./bin/test-mux
testauth=./bin/test-auth

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
		curl -sS --max-time 2 "http://127.0.0.1:$port/__ndc_test_missing__"
		return $?
	fi

	if ! command -v nc >/dev/null 2>&1; then
		echo "curl or nc required" >&2
		return 1
	fi

	printf "GET /__ndc_test_missing__ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" |
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
	nm -D lib/libndc.so | grep -F " $sym" >/dev/null 2>&1 && {
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
assert usage sh -c "$ndc -? 2>&1"
assert_not_exported ndc_platform
assert_not_exported descr_map

if ! command -v curl >/dev/null 2>&1 && ! command -v nc >/dev/null 2>&1; then
	echo "Skipping HTTP tests: curl or nc not found" >&2
	exit 0
fi

port=$((18000 + $$ % 1000))
$ndc -d -p "$port" >/dev/null 2>&1 &
ndc_pid=$!

if wait_for_port "$port"; then
	assert http-404 fetch_root "$port"
	assert http-200 fetch_status "$port" "/"
	assert http-css-200 fetch_status "$port" "/ndc.css"
	assert http-js-200 fetch_status "$port" "/ndc.js"
	assert_contains root-title "<title>NDC Terminal</title>" fetch_body "$port" "/"
	assert_contains css-marker ".xterm" fetch_body "$port" "/ndc.css"
	assert_contains js-marker "window.ttyNdc" fetch_body "$port" "/ndc.js"
	if command -v curl >/dev/null 2>&1; then
		pids=""
		for i in 1 2 3 4 5; do
			curl -sS --connect-timeout 1 --max-time 2 -o /dev/null "http://127.0.0.1:$port/ndc.css" &
			pids="$pids $!"
		done
		for pid in $pids; do
			wait "$pid"
		done
	fi
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
	echo "ndc failed to listen on $port" >&2
	kill "$ndc_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$ndc_pid" >/dev/null 2>&1 || true

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

cgi_dir=$(mktemp -d)
cp tests/fixtures/cgi/index.sh "$cgi_dir/index.sh"
chmod +x "$cgi_dir/index.sh"
cgi_port=$((port + 20))
$testmux -p "$cgi_port" -C "$cgi_dir" >/dev/null 2>&1 &
cgi_pid=$!

if wait_for_port_tcp "$cgi_port"; then
	if command -v nc >/dev/null 2>&1; then
		resp=$(raw_request "$cgi_port" "GET /?foo=bar HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
		head=$(echo "$resp" | sed -n '1p' | tr -d '\r')
		body=$(echo "$resp" | sed -n '/^\r\{0,1\}$/,$p' | sed '1d' | tr -d '\r')
		echo "$head" | grep -F "HTTP/1.1 200" >/dev/null 2>&1 || { echo "CGI status missing" >&2; exit 1; }
		echo "$body" | grep -F "Hello CGI" >/dev/null 2>&1 || { echo "CGI response missing" >&2; exit 1; }
		echo "$body" | grep -F "QUERY_STRING=foo=bar" >/dev/null 2>&1 || { echo "CGI QUERY_STRING missing" >&2; exit 1; }
	else
		echo "Skipping CGI tests: nc not found" >&2
	fi
else
	echo "cgi ndc failed to listen on $cgi_port" >&2
	kill "$cgi_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$cgi_pid" >/dev/null 2>&1 || true

ai_dir=$(mktemp -d)
cp tests/fixtures/autoindex/serve.allow "$ai_dir/serve.allow"
cp tests/fixtures/autoindex/serve.autoindex "$ai_dir/serve.autoindex"
cp -R tests/fixtures/autoindex/data "$ai_dir/data"
ai_port=$((port + 30))
$testmux -p "$ai_port" -C "$ai_dir" >/dev/null 2>&1 &
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
	echo "autoindex ndc failed to listen on $ai_port" >&2
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
	$ndc -d -p "$http_port" -s "$ssl_port" -K "$tls_dir/certs.txt" >/dev/null 2>&1 &
	ssl_pid=$!

	if wait_for_port_tcp "$http_port"; then
		shead=$(curl -k -sS -i --max-time 2 "https://127.0.0.1:$ssl_port/" | sed -n '1p' | tr -d '\r')
		sbody=$(curl -k -sS --max-time 2 "https://127.0.0.1:$ssl_port/")
		echo "$shead" | grep -F "HTTP/1.1 200" >/dev/null 2>&1 || { echo "TLS status missing" >&2; exit 1; }
		echo "$sbody" | grep -F "<title>NDC Terminal</title>" >/dev/null 2>&1 || { echo "TLS body missing" >&2; exit 1; }
	else
		echo "tls ndc failed to listen on $http_port" >&2
		kill "$ssl_pid" >/dev/null 2>&1 || true
		exit 1
	fi

	kill "$ssl_pid" >/dev/null 2>&1 || true
else
	echo "Skipping TLS tests: openssl or curl not found" >&2
fi

ws_port=$((port + 1))
$testmux -p "$ws_port" >/dev/null 2>&1 &
ws_pid=$!

if wait_for_port_tcp "$ws_port"; then
	if command -v python3 >/dev/null 2>&1; then
		python3 ./test-ws.py "$ws_port" --pty
	else
		echo "Skipping WS mux test: python3 not found" >&2
	fi
else
	echo "test-mux failed to listen on $ws_port" >&2
	kill "$ws_pid" >/dev/null 2>&1 || true
	exit 1
fi

kill "$ws_pid" >/dev/null 2>&1 || true
