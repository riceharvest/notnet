#!/usr/bin/env bash
# notnet sim runner — up -> driver -> down
# Usage: ./tests/sim/run-sim.sh [--scenario all|c2-drive|autonomous|resilience|monetization|defence] [--posture lax|standard|hardened] [--keep]
set -euo pipefail

cd "$(dirname "$0")"

SCENARIO="all"
POSTURE="lax"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --scenario) SCENARIO="${2:-all}"; shift 2 ;;
    --posture) POSTURE="${2:-lax}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) shift ;;
  esac
done

export SIM_POSTURE="$POSTURE"

echo "═══════════════════════════════════════════════════════"
echo "  notnet sim — scenario=$SCENARIO posture=$POSTURE"
echo "═══════════════════════════════════════════════════════"

# 0. Build images (bot compiles notnet in-container, validating the build)
echo "[1/6] Building images..."
docker compose -f docker-compose.sim.yml build bot ids-monitor 2>&1 | tail -3
docker build -f Dockerfile.device -t notnet-sim-device ../.. 2>&1 | tail -2

# 1. Generate fleet + payload artifacts
echo "[2/6] Generating fleet + payload..."
python3 gen_fleet.py
mkdir -p payload evidence queue cowrie reports
# payload: real binary + source bundle (for compile-fallback test)
cp ../../notnet payload/notnet 2>/dev/null || echo "WARN: no notnet binary at repo root (run make)"
if [ -f ../../dist/notnet-src.tar ]; then
  cp ../../dist/notnet-src.tar payload/notnet-src.tar
else
  echo "WARN: no dist/notnet-src.tar (run make dist-src for compile-fallback tests)"
fi

# 2. Clean state
rm -f evidence/*.log queue/*.json
: > evidence/.keep

# 3. Boot stack
echo "[3/6] Booting stack..."
docker compose -f docker-compose.sim.yml -f docker-compose.fleet.yml up -d --remove-orphans --force-recreate 2>&1 | tail -5

# 4. Wait for services to be ready
echo "[4/6] Waiting for services..."
sleep 8
docker compose -f docker-compose.sim.yml -f docker-compose.fleet.yml ps --format 'table {{.Name}}\t{{.Status}}' | head -45

# 5. Run driver
echo "[5/6] Running driver (scenario=$SCENARIO posture=$POSTURE)..."
set +e
python3 run_sim.py --scenario "$SCENARIO" --posture "$POSTURE"
DRIVER_RC=$?
set -e

# 6. Teardown
if [ "$KEEP" -eq 1 ]; then
  echo "[6/6] --keep: leaving stack up"
else
  echo "[6/6] Tearing down..."
  docker compose -f docker-compose.sim.yml -f docker-compose.fleet.yml down -v 2>&1 | tail -2
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DRIVER RC=$DRIVER_RC"
echo "  REPORT: tests/sim/reports/parity-*.md"
echo "═══════════════════════════════════════════════════════"
exit $DRIVER_RC
