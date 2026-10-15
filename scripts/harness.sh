#!/usr/bin/env bash
# Local test harness for onion-gate. No tor needed: the circuit_proxy example
# plays tor's part, and curl's --haproxy-protocol plays it for the checks.
#
#   scripts/harness.sh check          automated checks on a fresh stack (CI runs this)
#   scripts/harness.sh up             test backend + gate + circuit proxies, for a browser
#   scripts/harness.sh pass COOKIE    checks behind the gate, against a stack from `up`,
#                                     with a pass cookie value copied from the browser
#   scripts/harness.sh pass COOKIE --spend
#                                     ...then spends the pass's request budget (revokes it)
#
# Needs bash, curl >= 8.2 (for --haproxy-clientip) and cargo. See docs/TESTING.md.
# Environment: HARNESS_RELEASE=1 builds and runs the release profile (default:
# debug); BACKEND_PORT, GATE_PORT, BROWSER_PORT override the ports of `up`/`pass`.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
if [ "${HARNESS_RELEASE:-0}" = 1 ]; then
    PROFILE_FLAG=--release
    BIN=$TARGET/release
else
    PROFILE_FLAG=
    BIN=$TARGET/debug
fi

BACKEND_PORT=${BACKEND_PORT:-13000}
GATE_PORT=${GATE_PORT:-18088}
BROWSER_PORT=${BROWSER_PORT:-18080}
# `check` runs its own stack on other ports, so it never touches one from `up`.
CHECK_BACKEND_PORT=13001
CHECK_GATE_PORT=18089

PIDS=""
PASSED=0
FAILED=0

cleanup() {
    for p in $PIDS; do
        kill "$p" 2>/dev/null || true
    done
    for p in $PIDS; do
        wait "$p" 2>/dev/null || true
    done
    PIDS=""
}
trap cleanup EXIT
trap 'exit 130' INT TERM

die() {
    echo "harness: $*" >&2
    exit 1
}

need_curl() {
    command -v curl >/dev/null || die "curl not found"
    curl --help all 2>/dev/null | grep -q -- --haproxy-clientip ||
        die "curl $(curl --version | head -n1 | cut -d' ' -f2) has no --haproxy-clientip (needs curl >= 8.2)"
}

build() {
    (cd "$ROOT" && cargo build --locked --offline $PROFILE_FLAG --bin onion-gate --example test_backend --example circuit_proxy)
}

# Starts a program in the background and remembers it for cleanup.
spawn() {
    "$@" &
    PIDS="$PIDS $!"
}

# Waits until something listens on 127.0.0.1:$1.
wait_port() {
    i=0
    while ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || die "nothing is listening on 127.0.0.1:$1"
        sleep 0.1
    done
}

start_stack() { # backend_port gate_port
    spawn "$BIN/examples/test_backend" "$1"
    wait_port "$1"
    spawn "$BIN/onion-gate" "$2" --proxy-protocol "--upstream=127.0.0.1:$1"
    wait_port "$2"
}

# The IPv4 address whose 32 bits are circuit $1 (the gate reads a TCP4 PROXY
# source address as the circuit identifier).
circuit_ip() {
    c=$1
    echo "$((c >> 24 & 255)).$((c >> 16 & 255)).$((c >> 8 & 255)).$((c & 255))"
}

# gate PORT CIRCUIT [curl args...]: one request through the gate as that circuit.
gate() {
    port=$1
    circuit=$2
    shift 2
    curl -sS --max-time 20 --haproxy-protocol --haproxy-clientip "$(circuit_ip "$circuit")" "$@" \
        "http://127.0.0.1:$port${URL_PATH:-/}"
}

ok() {
    PASSED=$((PASSED + 1))
    echo "ok    $1"
}

bad() {
    FAILED=$((FAILED + 1))
    echo "FAIL  $1" >&2
}

# expect DESCRIPTION CONDITION...: runs the condition (a command), ok if it succeeds.
expect() {
    desc=$1
    shift
    if "$@"; then ok "$desc"; else bad "$desc"; fi
}

has() { printf '%s' "$1" | grep -qF -- "$2"; }
lacks() { ! printf '%s' "$1" | grep -qiF -- "$2"; }
status_is() { [ "$(printf '%s' "$1" | head -n1 | tr -d '\r' | cut -d' ' -f2)" = "$2" ]; }

summary() {
    echo
    echo "$PASSED passed, $FAILED failed"
    [ "$FAILED" -eq 0 ]
}

# ---------------------------------------------------------------- check

cmd_check() {
    need_curl
    build
    G=$CHECK_GATE_PORT
    start_stack "$CHECK_BACKEND_PORT" "$G"
    CHALLENGE="Click the broken circle."
    BACKEND_MARK="the gate let you through"

    # 1. Without a pass every path is the challenge, and nothing of the backend shows.
    for p in / /echo "/does-not-exist?x=1"; do
        r=$(URL_PATH=$p gate "$G" 1 -i)
        expect "no pass: $p is the challenge (200)" status_is "$r" 200
        expect "no pass: $p shows the challenge" has "$r" "$CHALLENGE"
        expect "no pass: $p shows nothing of the backend" lacks "$r" "$BACKEND_MARK"
    done

    # 2. Security headers on the challenge page.
    r=$(gate "$G" 2 -i)
    expect "challenge: Cache-Control: no-store" has "$r" "Cache-Control: no-store"
    expect "challenge: Content-Security-Policy default-src 'none'" has "$r" "Content-Security-Policy: default-src 'none'"
    expect "challenge: Connection: close" has "$r" "Connection: close"
    expect "challenge: no JavaScript" lacks "$r" "<script"

    # 3. HEAD gets the headers and no body.
    r=$(gate "$G" 2 -I)
    expect "HEAD: 200" status_is "$r" 200
    expect "HEAD: no body" lacks "$r" "$CHALLENGE"

    # 4. The gate's own namespace.
    r=$(URL_PATH=/__gate/nope gate "$G" 3 -i)
    expect "/__gate/nope: 404" status_is "$r" 404
    r=$(URL_PATH=/__gate/verify gate "$G" 3 -i)
    expect "GET /__gate/verify: 405" status_is "$r" 405
    expect "GET /__gate/verify: Allow: POST" has "$r" "Allow: POST"

    # 5. A bogus token, a wrong click and a replayed token all get the same
    #    generic failure with a new image (no oracle).
    FAIL_MSG="Wrong or expired. Try this new image."
    r=$(URL_PATH=/__gate/verify gate "$G" 4 -i --data "t=00&c.x=1&c.y=1")
    expect "bogus token: generic failure" has "$r" "$FAIL_MSG"
    page=$(gate "$G" 4)
    tok=$(printf '%s' "$page" | sed -n 's/.*name="t" value="\([0-9a-f]*\)".*/\1/p')
    expect "challenge carries a 32-hex token" [ "${#tok}" -eq 32 ]
    # (0, 0) is in the frame: no ring comes within 10 px of the border.
    r=$(URL_PATH=/__gate/verify gate "$G" 4 -i --data "t=$tok&c.x=0&c.y=0")
    expect "wrong click: generic failure" has "$r" "$FAIL_MSG"
    expect "wrong click: no pass issued" lacks "$r" "Set-Cookie: onion_gate_pass="
    r=$(URL_PATH=/__gate/verify gate "$G" 4 -i --data "t=$tok&c.x=150&c.y=150")
    expect "replayed token: same generic failure" has "$r" "$FAIL_MSG"
    expect "replayed token: no pass issued" lacks "$r" "Set-Cookie: onion_gate_pass="

    # 6. A malformed or unknown pass is refused and cleared.
    for cookie in "onion_gate_pass=forged" "onion_gate_pass=0123456789abcdef0123456789abcdef"; do
        r=$(gate "$G" 5 -i -H "Cookie: $cookie")
        expect "pass '${cookie#*=}': challenge" has "$r" "$CHALLENGE"
        expect "pass '${cookie#*=}': cookie cleared" has "$r" "Max-Age=0"
    done

    # 7. Without the PROXY line the connection is closed with no answer.
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$G/" || true)
    expect "no PROXY line: closed without a response" [ "$code" = 000 ]

    # 8. Challenge permits per circuit: 10 in a burst, then 429. Another circuit
    #    is unaffected. (One permit comes back every 6 s, so allow one extra.)
    codes=""
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        codes="$codes $(gate "$G" 10 -o /dev/null -w '%{http_code}')"
    done
    first10=$(echo "$codes" | cut -d' ' -f2-11)
    expect "circuit 10: first 10 challenges served ($codes)" [ "$first10" = "200 200 200 200 200 200 200 200 200 200" ]
    expect "circuit 10: then 429" [ "$(echo "$codes" | awk '{print $NF}')" = 429 ]
    r=$(gate "$G" 10 -i)
    expect "429 carries Retry-After" has "$r" "Retry-After: 60"
    r=$(gate "$G" 11 -o /dev/null -w '%{http_code}')
    expect "circuit 11 still served" [ "$r" = 200 ]

    # 9. Connections per circuit: 8 held open, the 9th is refused with 429.
    line="PROXY TCP4 $(circuit_ip 20) 127.0.0.1 40000 $G"
    exec 3<>"/dev/tcp/127.0.0.1/$G" 4<>"/dev/tcp/127.0.0.1/$G" 5<>"/dev/tcp/127.0.0.1/$G" \
        6<>"/dev/tcp/127.0.0.1/$G" 7<>"/dev/tcp/127.0.0.1/$G" 8<>"/dev/tcp/127.0.0.1/$G" \
        9<>"/dev/tcp/127.0.0.1/$G" 10<>"/dev/tcp/127.0.0.1/$G"
    for fd in 3 4 5 6 7 8 9 10; do
        printf '%s\r\n' "$line" >&"$fd"
    done
    sleep 0.5
    r=$(gate "$G" 20 -o /dev/null -w '%{http_code}')
    expect "circuit 20: 9th simultaneous connection gets 429" [ "$r" = 429 ]
    exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 10>&-
    sleep 0.5
    r=$(gate "$G" 20 -o /dev/null -w '%{http_code}')
    expect "circuit 20: served again once they close" [ "$r" = 200 ]

    # 10. The binary refuses a non-loopback or self-pointing upstream and bad flags.
    set +e
    "$BIN/onion-gate" 18090 --upstream=10.0.0.1:80 >/dev/null 2>&1
    expect "non-loopback upstream refused" [ $? -ne 0 ]
    "$BIN/onion-gate" 18090 --upstream=127.0.0.1:18090 >/dev/null 2>&1
    expect "upstream on the gate's own port refused" [ $? -ne 0 ]
    "$BIN/onion-gate" --upstream=127.0.0.1:1 --bogus >/dev/null 2>&1
    expect "unknown flag: exit 2" [ $? -eq 2 ]
    set -e

    summary
}

# ---------------------------------------------------------------- up

cmd_up() {
    build
    start_stack "$BACKEND_PORT" "$GATE_PORT"
    spawn "$BIN/examples/circuit_proxy" "$BROWSER_PORT" "$GATE_PORT" --circuit=1
    spawn "$BIN/examples/circuit_proxy" "$((BROWSER_PORT + 1))" "$GATE_PORT" --circuit=2
    wait_port "$BROWSER_PORT"
    wait_port "$((BROWSER_PORT + 1))"
    cat <<EOF

Stack is up (Ctrl-C stops it):
  test backend      http://127.0.0.1:$BACKEND_PORT/   (direct, no gate: for comparison only)
  onion-gate        127.0.0.1:$GATE_PORT              (--proxy-protocol: browsers cannot talk to it directly)
  visitor, circuit 1  http://127.0.0.1:$BROWSER_PORT/
  visitor, circuit 2  http://127.0.0.1:$((BROWSER_PORT + 1))/

Open a visitor URL in a browser with JavaScript disabled, pass the CAPTCHA, then
copy the value of the onion_gate_pass cookie and run, in another terminal:
  scripts/harness.sh pass <value>
EOF
    wait
}

# ---------------------------------------------------------------- pass

cmd_pass() {
    [ $# -ge 1 ] || die "usage: harness.sh pass COOKIE [--spend]"
    need_curl
    P=$1
    spend=${2:-}
    G=$GATE_PORT
    wait_port "$G"
    C=1 # the circuit of the browser's proxy: the same visitor
    jar="Cookie: onion_gate_pass=$P"

    r=$(gate "$G" $C -i -H "$jar")
    has "$r" "the gate let you through" || die "the pass was not accepted (expired, revoked, or the stack was restarted?)"
    ok "pass: / reaches the backend"

    r=$(URL_PATH=/echo gate "$G" $C -H "Cookie: a=1; onion_gate_pass=$P; b=2" \
        -H "X-Forwarded-For: 192.0.2.1" -H "X-Forwarded-Host: evil.example" -H "Forwarded: for=192.0.2.1" \
        -H "X-Real-IP: 192.0.2.1" -H "True-Client-IP: 192.0.2.1" -H "X_Forwarded_For: 192.0.2.1" \
        -H "Proxy: http://192.0.2.1/")
    expect "backend does not see the pass cookie" lacks "$r" "onion_gate_pass="
    expect "backend does not see the pass value" lacks "$r" "$P"
    expect "backend sees the other cookies" has "$r" "Cookie: a=1; b=2"
    for h in "x-forwarded-for:" "x-forwarded-host:" "forwarded:" "x-real-ip:" "true-client-ip:" "x_forwarded_for:" "proxy:"; do
        expect "backend does not see '$h'" lacks "$r" "$h"
    done
    expect "backend sees Connection: close" has "$r" "Connection: close"

    r=$(URL_PATH=/echo gate "$G" $C -H "$jar" --data-binary "hello=world&x=%C3%BC")
    expect "POST body reaches the backend intact" has "$r" "20 body bytes:"
    expect "POST body content" has "$r" "hello=world&amp;x=%C3%BC"

    r=$(URL_PATH=/chunked gate "$G" $C -H "$jar")
    expect "chunked response relayed" has "$r" "chunk 10 of 10"

    n=$(URL_PATH="/big?kib=1024" gate "$G" $C -H "$jar" -o /dev/null -w '%{size_download}')
    expect "1 MiB response relayed whole ($n bytes)" [ "$n" = 1048576 ]
    r=$(URL_PATH="/big?kib=9000" gate "$G" $C -H "$jar" -o /dev/null -w '%{http_code}')
    expect "response over the 8 MiB cap: 502" [ "$r" = 502 ]

    r=$(URL_PATH=/redirect gate "$G" $C -H "$jar" -i)
    expect "backend redirect relayed (302)" status_is "$r" 302
    expect "backend redirect keeps Location" has "$r" "Location: /"

    r=$(URL_PATH=/__gate/nope gate "$G" $C -H "$jar" -i)
    expect "/__gate/ is never forwarded, even with a pass" status_is "$r" 404

    if [ "$spend" = --spend ]; then
        # 60 requests in a burst, 1 more per second: 70 quick ones exhaust it.
        last=""
        for _ in $(seq 1 70); do
            last=$(gate "$G" $C -H "$jar" -i)
            has "$last" "Please verify again" && break
        done
        expect "spent budget: pass revoked with a challenge" has "$last" "Please verify again"
        expect "spent budget: cookie cleared" has "$last" "Max-Age=0"
        r=$(gate "$G" $C -H "$jar")
        expect "revoked pass stays revoked" has "$r" "Click the broken circle."
    fi

    summary
}

case "${1:-}" in
    check) cmd_check ;;
    up) cmd_up ;;
    pass) shift; cmd_pass "$@" ;;
    *) sed -n '2,15p' "$0" >&2; exit 2 ;;
esac
