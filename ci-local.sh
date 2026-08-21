#!/usr/bin/env bash
# Local CI for notnet — runs the same gates as the (billing-blocked)
# GitHub Actions without spending anything on runners.
#
# Usage:
#   ./ci-local.sh          quick: build gates + c2-drive smoke + TLS smoke
#   ./ci-local.sh --full   full: everything incl. the 21-check regressions
#   ./ci-local.sh --push   full + git push (safe to use as a pre-push hook)
#
# Exit code: number of failed gates (0 = all green).
set -u
cd "$(dirname "$0")"
FAILS=0
PASS="[PASS]"
FAIL="[FAIL]"

gate() { # gate <name> <cmd...>
    local name="$1"; shift
    local log="/tmp/ci-local-$(echo "$name" | tr ' ' '_').log"
    echo "── $name"
    if "$@" >"$log" 2>&1; then
        echo "   $PASS $name"
    else
        echo "   $FAIL $name (see $log)"
        FAILS=$((FAILS+1))
    fi
}

echo "=== notnet local CI ($(date -u +%H:%M)) ==="

# 1. static build, zero warnings
gate "make (static, zero warnings)" bash -c 'make clean >/dev/null 2>&1 && ! make 2>&1 | grep -E "warning|error" && test -x notnet'

# 2. TLS build, zero warnings
gate "make TLS=1 (zero warnings)" bash -c 'make clean >/dev/null 2>&1 && ! make TLS=1 2>&1 | grep -E "warning|error" && test -x notnet'

# 3. TLS smoke (real binary, pinned cert, handshake, data path, fail-closed)
gate "TLS build + smoke" ./c2-server/tls_smoke.sh

# 4. c2-drive smoke against the mock C2 (9 checks)
gate "sim c2-drive (mock C2)" bash -c "cd tests/sim && SUDO_PW='${SUDO_PW:-}' ./run-sim.sh --scenario c2-drive --posture lax >/dev/null 2>&1"

# 5. socks5_client fork guard (#194): canonical copy lives in tests/sim/c2/
gate "socks5_client drift guard" bash -c 'if [ -f c2-server/socks5_client.py ]; then
    echo "stray c2-server/socks5_client.py — canonical copy is tests/sim/c2/socks5_client.py (see issue #194)"
    diff -u tests/sim/c2/socks5_client.py c2-server/socks5_client.py
    exit 1
fi'

# 6. global killswitch (#130): armed build self-destructs at boot, inert control runs
gate "killswitch (armed + inert)" ./tests/run-tests.sh killswitch

if [ "${1:-}" = "--full" ] || [ "${1:-}" = "--push" ]; then
    # 7. full regression — all scenarios, mock C2 (21 checks)
    gate "sim full regression (all, mock)" bash -c "cd tests/sim && SUDO_PW='${SUDO_PW:-}' ./run-sim.sh --scenario all --posture standard >/dev/null 2>&1"
    # 8. full suite against the real C2 (21 checks)
    gate "sim full suite (all, real C2)" bash -c "cd tests/sim && SUDO_PW='${SUDO_PW:-}' ./run-sim.sh --scenario all --posture standard --c2 real >/dev/null 2>&1"
fi

# restore the default build artifact
make clean >/dev/null 2>&1; make >/dev/null 2>&1

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "LOCAL CI GREEN (0 failed)"
else
    echo "LOCAL CI RED ($FAILS failed)"
fi

if [ "${1:-}" = "--push" ] && [ "$FAILS" -eq 0 ]; then
    git push origin main
fi
exit "$FAILS"
