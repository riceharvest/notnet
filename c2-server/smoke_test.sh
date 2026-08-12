#!/usr/bin/env bash
# c2-server smoke test — real notnet binary against the real C2, end-to-end.
#  HTTP channel: inventory, targeted + untargeted command delivery/exec,
#                payload serving, wrong-secret rejection, connection stays up
#  WS channel:   inventory + targeted command exec over WebSocket
#  IRC channel:  inventory + targeted command exec over IRC (legacy)
set -euo pipefail
cd "$(dirname "$0")"

PORT_HTTP=18080
PORT_PAY=18443
PORT_CON=18090
PORT_WS=18081
PORT_IRC=16667
SECRET=smokesecret
WORK=/tmp/c2smoke-test
C2LOG="$WORK/c2.log"

cleanup() {
  docker rm -f c2smoke-bot >/dev/null 2>&1 || true
  [ -n "${C2_PID:-}" ] && kill "$C2_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$WORK"; mkdir -p "$WORK/queue" "$WORK/payload"
cp ../notnet "$WORK/payload/notnet"

run_bot() {  # $1 = conf file, $2 = bot tag (for log grep)
  docker rm -f c2smoke-bot >/dev/null 2>&1 || true
  docker run --rm -d --name c2smoke-bot --network host \
    -v "$1":/etc/notnet.conf:ro notnet-sim-bot >/dev/null
  # wait for the bot's first heartbeat in the C2 log (tag appears in both
  # the HTTP "tag=X" form and the WS/IRC JSON form)
  for i in $(seq 1 25); do
    grep -q "$2" "$C2LOG" && return 0
    sleep 1
  done
  echo "FAIL: bot $2 never heartbeated"
  exit 1
}

wait_exec() {  # $1 = allowlist command name, $2 = bot tag
  for i in $(seq 1 25); do
    docker logs c2smoke-bot 2>&1 | grep -q "CMD: exec: allowlist hit: $1" && return 0
    sleep 1
  done
  echo "FAIL: exec $1 not executed"
  exit 1
}

python3 c2.py --secret "$SECRET" \
  --http-port $PORT_HTTP --payload-port $PORT_PAY --console-port $PORT_CON \
  --ws-port $PORT_WS --irc-port $PORT_IRC --irc-nick mockirc --irc-channel '#notnet' \
  --queue-dir "$WORK/queue" --payload-dir "$WORK/payload" --db "$WORK/c2.db" \
  > "$C2LOG" 2>&1 &
C2_PID=$!
sleep 2

API="http://127.0.0.1:$PORT_CON"
fail=0

# ── HTTP channel ───────────────────────────────────────────────────────
cat > "$WORK/notnet.conf.http" <<EOF
http_server=127.0.0.1
http_port=$PORT_HTTP
http_path=/api/v1/bot
ws_enabled=0
irc_enabled=0
c2_secret=$SECRET
heartbeat_interval=2
scan_interval=1
persist_enabled=0
bot_tag=smoke-http-1
EOF
run_bot "$WORK/notnet.conf.http" smoke-http-1

echo "[1/7] HTTP: inventory"
./c2ctl --api "$API" bots | grep -q "smoke-http-1" || { echo "FAIL: no http bot"; fail=1; }

echo "[2/7] HTTP: targeted command delivered + executed"
./c2ctl --api "$API" queue --target smoke-http-1 exec hostname
wait_exec hostname smoke-http-1 || fail=1

echo "[3/7] HTTP: untargeted command delivered"
./c2ctl --api "$API" queue exec date
wait_exec date smoke-http-1 || fail=1

echo "[4/7] HTTP: payload serving"
code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT_PAY/bot/notnet")
[ "$code" = "200" ] || { echo "FAIL: payload http $code"; fail=1; }

echo "[5/7] HTTP: wrong secret rejected"
curl -s -X POST "http://127.0.0.1:$PORT_HTTP/api/v1/bot" \
  -d '{"cmd":"status","hostname":"evil","secret":"wrong","tag":"evil-1"}' >/dev/null
sleep 2
grep -q "AUTH-FAIL.*evil" "$C2LOG" || { echo "FAIL: no AUTH-FAIL logged"; fail=1; }

echo "[6/7] HTTP: bot stays connected (no autonomous spread)"
docker logs c2smoke-bot 2>&1 | grep -q "Local spread cycle started" \
  && { echo "FAIL: bot went autonomous (connection dropped)"; fail=1; }

# ── WS channel ─────────────────────────────────────────────────────────
cat > "$WORK/notnet.conf.ws" <<EOF
http_enabled=0
ws_server=127.0.0.1
ws_port=$PORT_WS
ws_path=/ws/v1/bot
ws_enabled=1
irc_enabled=0
c2_secret=$SECRET
heartbeat_interval=2
scan_interval=1
persist_enabled=0
bot_tag=smoke-ws-1
EOF
run_bot "$WORK/notnet.conf.ws" smoke-ws-1

echo "[7/7] WS: inventory + targeted command exec"
./c2ctl --api "$API" bots | grep -q "smoke-ws-1" || { echo "FAIL: no ws bot"; fail=1; }
./c2ctl --api "$API" bots | grep "smoke-ws-1" | grep -q "ws" || { echo "FAIL: ws channel not recorded"; fail=1; }
./c2ctl --api "$API" queue --target smoke-ws-1 exec hostname
wait_exec hostname smoke-ws-1 || fail=1

# ── IRC channel (legacy) ───────────────────────────────────────────────
cat > "$WORK/notnet.conf.irc" <<EOF
http_enabled=0
ws_enabled=0
irc_enabled=1
irc_server=127.0.0.1
irc_port=$PORT_IRC
irc_channel=#notnet
irc_auth_nicks=mockirc
c2_secret=$SECRET
heartbeat_interval=2
scan_interval=1
persist_enabled=0
bot_tag=smoke-irc-1
EOF
run_bot "$WORK/notnet.conf.irc" smoke-irc-1

echo "[8/7] IRC: inventory + targeted command"
./c2ctl --api "$API" bots | grep -q "smoke-irc-1" || { echo "FAIL: no irc bot"; fail=1; }
./c2ctl --api "$API" bots | grep "smoke-irc-1" | grep -q "irc" || { echo "FAIL: irc channel not recorded"; fail=1; }
./c2ctl --api "$API" queue --target smoke-irc-1 exec hostname
wait_exec hostname smoke-irc-1 || fail=1

# ── Global kill broadcast (killall) ────────────────────────────────────
echo "[9/7] killall: broadcast kill reaches the connected bot"
./c2ctl --api "$API" killall
# The bot's kill response arrives at the C2 ("wiping state"). The bot
# container is --rm'd on exit, so the C2 log is the reliable evidence.
for i in $(seq 1 25); do
  grep -q "wiping state" "$C2LOG" && break
  sleep 1
done
grep -q "wiping state" "$C2LOG" \
  || { echo "FAIL: bot did not process broadcast kill"; fail=1; }

if [ "$fail" = "0" ]; then
  echo "C2 SMOKE (http+ws+irc+killall): PASS"
  exit 0
else
  echo "C2 SMOKE: FAIL"
  exit 1
fi
