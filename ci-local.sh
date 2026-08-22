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
gate "sim c2-drive (mock C2)" bash -c "cd tests/sim && ./run-sim.sh --scenario c2-drive --posture lax >/dev/null 2>&1"

# 5. socks5_client fork guard (#194): canonical copy lives in tests/sim/c2/
gate "socks5_client drift guard" bash -c 'if [ -f c2-server/socks5_client.py ]; then
    echo "stray c2-server/socks5_client.py — canonical copy is tests/sim/c2/socks5_client.py (see issue #194)"
    diff -u tests/sim/c2/socks5_client.py c2-server/socks5_client.py
    exit 1
fi'

# 6. global killswitch (#130): armed build self-destructs at boot, inert control runs
gate "killswitch (armed + inert)" ./tests/run-tests.sh killswitch

# ── detections-ci.yml parity (#246) ──
# 7. detection-as-code: schema + source-drift + replay
gate "detections validate --strict" python3 detections/validate.py --strict

# 8. STIX 2.1 intel: bundle build + drift check (schema needs stix2 installed;
#    build_intel.py falls back to a structural check — same semantics as CI)
gate "intel build + drift check" bash -c 'python3 intel/build_intel.py >/dev/null && python3 intel/build_intel.py --check'

# 9. guardrails (#154): disclosure docs, inert killswitch default, attest tool
gate "guardrails (#154)" bash -c 'grep -q "Responsible Use & Disclosure" README.md \
    && grep -q SECURITY.md README.md \
    && test -f SECURITY.md \
    && grep -qi "Responsible disclosure" SECURITY.md \
    && grep -q "KILLSWITCH_DOMAIN_DEFAULT   \"killswitch.invalid\"" include/config.h \
    && test -f attest.py \
    && python3 attest.py --help >/dev/null'

# ── sim.yml host-runnable parity (#246) ──
# 10. dist-src completeness + compile gate (#138 / #133)
gate "dist-src verify (compile gate)" ./c2-server/verify_dist_src.sh

# 11. mesh command-signer trust gate (#139): MESH_ED25519 build + host test.
#     Links src/*.o so the test binary matches the Makefile-built one (#241).
gate "mesh trust gate (MESH_ED25519)" bash -c 'make clean >/dev/null 2>&1 \
    && make MESH_ED25519=1 >/dev/null 2>&1 \
    && gcc -DTLS_ENABLED -DMESH_ED25519 -I include -o /tmp/mesh_test tests/host/mesh_test.c src/*.o -lssl -lcrypto -lpthread \
    && /tmp/mesh_test'

if [ "${1:-}" = "--full" ] || [ "${1:-}" = "--push" ]; then
    # 7. full regression — all scenarios, mock C2 (21 checks)
    gate "sim full regression (all, mock)" bash -c "cd tests/sim && ./run-sim.sh --scenario all --posture standard >/dev/null 2>&1"
    # 8. full suite against the real C2 (21 checks)
    gate "sim full suite (all, real C2)" bash -c "cd tests/sim && ./run-sim.sh --scenario all --posture standard --c2 real >/dev/null 2>&1"
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
    # Push HEAD's actual branch, not a hardcoded ref (#247): only main is
    # allowed through; from any other branch, refuse rather than silently
    # publishing a stale local main.
    branch="$(git symbolic-ref --quiet --short HEAD || true)"
    if [ "$branch" = "main" ]; then
        git push origin HEAD:main
    else
        echo "REFUSING to push: --push only publishes main; current branch is '${branch:-DETACHED}'" >&2
        FAILS=$((FAILS+1))
    fi
fi
exit "$FAILS"
