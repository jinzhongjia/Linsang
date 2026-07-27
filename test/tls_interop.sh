#!/bin/sh
set -eu

server=$1
command -v openssl >/dev/null
command -v curl >/dev/null

work=$(mktemp -d "${TMPDIR:-/tmp}/linsang-tls-interop.XXXXXX")
pid=
cleanup() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout "$work/rsa-key.pem" -out "$work/rsa-cert.pem" \
    >"$work/rsa-generate.log" 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 1 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout "$work/ecdsa-key.pem" -out "$work/ecdsa-cert.pem" \
    >"$work/ecdsa-generate.log" 2>&1

start_server() {
    cert=$1
    key=$2
    port_file=$work/port
    server_log=$work/server.log
    : >"$port_file"
    : >"$server_log"
    "$server" "$cert" "$key" >"$port_file" 2>"$server_log" &
    pid=$!

    attempts=0
    while [ ! -s "$port_file" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" || true
            pid=
            sed -n '1,120p' "$server_log" >&2
            return 1
        fi
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 200 ]; then
            sed -n '1,120p' "$server_log" >&2
            return 1
        fi
        sleep 0.05
    done
    port=$(sed -n '1p' "$port_file")
}

finish_server() {
    wait "$pid"
    pid=
}

run_curl() {
    version=$1
    cert=$2
    key=$3
    start_server "$cert" "$key"
    if [ "$version" = 1.2 ]; then
        tls_args="--tlsv1.2 --tls-max 1.2"
    else
        tls_args="--tlsv1.3 --tls-max 1.3"
    fi
    if ! body=$(curl --silent --show-error --fail --insecure --http1.1 \
        --noproxy '*' --resolve "localhost:$port:127.0.0.1" \
        --connect-timeout 5 --max-time 10 $tls_args \
        "https://localhost:$port/"); then
        printf 'curl TLS %s failed with certificate %s\n' "$version" "$cert" >&2
        sed -n '1,120p' "$server_log" >&2
        return 1
    fi
    [ "$body" = "interop ok" ]
    finish_server
}

run_openssl() {
    version=$1
    cert=$2
    key=$3
    start_server "$cert" "$key"
    if [ "$version" = 1.2 ]; then
        tls_arg=-tls1_2
    else
        tls_arg=-tls1_3
    fi
    response=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' |
        openssl s_client -quiet -ign_eof "$tls_arg" \
            -connect "127.0.0.1:$port" -servername localhost 2>"$work/s_client.log")
    printf '%s' "$response" | grep -q "interop ok"
    finish_server
}

for kind in rsa ecdsa; do
    cert=$work/$kind-cert.pem
    key=$work/$kind-key.pem
    run_curl 1.2 "$cert" "$key"
    run_curl 1.3 "$cert" "$key"
    run_openssl 1.2 "$cert" "$key"
    run_openssl 1.3 "$cert" "$key"
done

printf '%s\n' "TLS interop: RSA/ECDSA x TLS 1.2/1.3 x curl/OpenSSL OK"
