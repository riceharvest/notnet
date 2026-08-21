#!/usr/bin/env bash
# notnet sim runner — up -> driver -> down
# Usage: ./tests/sim/run-sim.sh [--scenario all|c2-drive|autonomous|resilience|monetization|defence|remaining-parity] [--posture lax|standard|hardened] [--profile <name>] [--keep]
#   --profile <name>  (#153) expands a named defensive profile to its posture:
#       legacy-unpatched  -> posture lax     (legacy tier: default creds, unpatched CVEs)
#       patched-firmware   -> posture standard (modern tier: CVEs patched, SMB1 off)
#       edr-on            -> posture hardened  (modern tier + Wazuh/Sysmon/osquery, #150)
#       credential-hygiene -> posture standard (modern tier: key-only SSH, no default creds)
#       segmented         -> posture hardened  (legacy tier isolated from office/dmz)
set -euo pipefail

cd "$(dirname "$0")"

SCENARIO="all"
POSTURE="lax"
PROFILE=""
KEEP=0
C2_MODE="mock"
while [ $# -gt 0 ]; do
  case "$1" in
    --scenario) SCENARIO="${2:-all}"; shift 2 ;;
    --posture) POSTURE="${2:-lax}"; shift 2 ;;
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --c2) C2_MODE="${2:-real}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) shift ;;
  esac
done

# Expand a named profile (#153) to its posture. The mapping mirrors
# defence/posture.yaml `profiles:`. Keep the two in sync.
if [ -n "$PROFILE" ]; then
  case "$PROFILE" in
    legacy-unpatched)  POSTURE="lax" ;;
    patched-firmware)  POSTURE="standard" ;;
    edr-on)            POSTURE="hardened" ;;
    credential-hygiene) POSTURE="standard" ;;
    segmented)         POSTURE="hardened" ;;
    *) echo "ERROR: unknown --profile '$PROFILE' (see defence/posture.yaml)"; exit 1 ;;
  esac
  echo "PROFILE: $PROFILE -> posture=$POSTURE"
  export SIM_PROFILE="$PROFILE"
fi

export SIM_POSTURE="$POSTURE"
export SUDO_PW="${SUDO_PW:-}"

# The driver (run_sim.py) runs on the HOST (step 5), not in a container, so it
# must point at the host-side evidence/queue/reports dirs — not /evidence (which
# only exists inside the sim containers that bind-mount ./evidence). Without this,
# EVIDENCE falls back to /evidence, the seed writes in scenario_telemetry silently
# fail, and the honeytoken/telemetry assertions can't see host-written artifacts.
export SIM_EVIDENCE="$PWD/evidence"
export SIM_QUEUE_DIR="$PWD/queue"
export SIM_REPORTS="$PWD/reports"

# --c2 real merges docker-compose.realc2.yml so the fleet talks to the real
# c2-server instead of the Python mocks (same hostnames/IPs).
C2_OVERRIDE=""
if [ "$C2_MODE" = "real" ]; then
  C2_OVERRIDE="-f docker-compose.realc2.yml"
  export SIM_C2_REAL=1
  echo "C2: REAL (c2-server) — mocks replaced"
fi
COMPOSE_BASE="docker compose -f docker-compose.sim.yml $C2_OVERRIDE"

echo "═══════════════════════════════════════════════════════"
echo "  notnet sim — scenario=$SCENARIO posture=$POSTURE"
echo "═══════════════════════════════════════════════════════"

# 0. Build images (bot compiles notnet in-container, validating the build)
echo "[1/6] Building images..."
docker compose -f docker-compose.sim.yml build bot ids-monitor 2>&1 | tail -3
docker build -f Dockerfile.device -t notnet-sim-device ../.. 2>&1 | tail -2
# notnet-sim-realsvc (#123): Tier-1 real-service devices reference this image.
# gen_fleet.py emits containers for it, so a fresh runner without the cached
# image fails at `up` with "pull access denied" — build it here like the rest.
docker build -f Dockerfile.realsvc -t notnet-sim-realsvc . 2>&1 | tail -2

# 1. Generate fleet + payload artifacts
echo "[2/6] Generating fleet + payload..."
python3 gen_fleet.py
mkdir -p payload evidence queue cowrie reports
# Cowrie runs as a non-root uid (999) and writes its jsonlog to /evidence; the
# host bind-mounted dir is owned by the invoking user, so open it up so the
# honeypot containers can write their capture there.
chmod 777 evidence 2>/dev/null || true
cp ../../notnet payload/notnet 2>/dev/null || echo "WARN: no notnet binary at repo root (run make)"
if [ -f ../../dist/notnet-src.tar ]; then
  cp ../../dist/notnet-src.tar payload/notnet-src.tar
else
  echo "WARN: no dist/notnet-src.tar (run make dist-src for compile-fallback tests)"
fi

# 2. Clean state
rm -f evidence/*.log queue/*.json
: > evidence/.keep
mkdir -p state

# 2b. Host firewall (L3 enforcement of the posture — DOCKER-USER chain)
echo "[2b] Host firewall (posture=$POSTURE)..."
FW_PID=""
if command -v sudo >/dev/null 2>&1; then
  SUDO_PW="${SUDO_PW:-}"
  if [ -n "$SUDO_PW" ]; then
    echo "$SUDO_PW" | sudo -S -v 2>/dev/null
  fi
  if sudo -n true 2>/dev/null; then
    if [ -n "$SUDO_PW" ]; then
      echo "$SUDO_PW" | sudo -S bash defence/host_firewall.sh install --posture="$POSTURE" --ips="${SIM_IPS:-0}" 2>&1 | tail -4
    else
      sudo -n bash defence/host_firewall.sh install --posture="$POSTURE" --ips="${SIM_IPS:-0}" 2>&1 | tail -4
    fi
    # IPS blacklist watcher (only needed when IPS is on)
    if [ "${SIM_IPS:-0}" = "1" ] || [ "$POSTURE" = "hardened" ]; then
      # </dev/null so the watcher never holds our stdout pipe open (teardown
      # would hang waiting for the pipe to close); redirect output to a file.
      if [ -n "$SUDO_PW" ]; then
        echo "$SUDO_PW" | sudo -S bash defence/host_firewall.sh watch --evidence="$PWD/evidence" </dev/null >> evidence/host_firewall.log 2>&1 &
      else
        sudo -n bash defence/host_firewall.sh watch --evidence="$PWD/evidence" </dev/null >> evidence/host_firewall.log 2>&1 &
      fi
      FW_PID=$!
    fi
  else
    echo "WARN: no passwordless sudo — host firewall SKIPPED (network posture not enforced)"
  fi
else
  echo "WARN: sudo not found — host firewall SKIPPED"
fi

# 3. Boot stack
echo "[3/6] Booting stack..."
$COMPOSE_BASE -f docker-compose.fleet.yml up -d --remove-orphans --force-recreate 2>&1 | tail -5

# 4. Wait for services to be ready
echo "[4/6] Waiting for services..."
sleep 8
# No `| head` here — under `set -euo pipefail` a slow `ps` on a cold fleet
# (55+ containers still starting) gets SIGPIPE when head closes the pipe
# early, and the whole script dies with 255 before the driver runs.
$COMPOSE_BASE -f docker-compose.fleet.yml ps --format 'table {{.Name}}\t{{.Status}}'

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
  if [ -n "$FW_PID" ]; then kill "$FW_PID" 2>/dev/null || true; fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    if [ -n "${SUDO_PW:-}" ]; then
      echo "$SUDO_PW" | sudo -S bash defence/host_firewall.sh remove 2>&1 | tail -1
    else
      sudo -n bash defence/host_firewall.sh remove 2>&1 | tail -1
    fi
  fi
  $COMPOSE_BASE -f docker-compose.fleet.yml down -v 2>&1 | tail -2
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  DRIVER RC=$DRIVER_RC"
echo "  REPORT: tests/sim/reports/parity-*.md"
echo "═══════════════════════════════════════════════════════"
exit $DRIVER_RC
