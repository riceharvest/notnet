#!/usr/bin/env bash
# notnet Docker test runner
# Usage: ./tests/run-tests.sh [no-net|mock-c2|all]

set -e

COMPOSE="docker compose -f docker-compose.test.yml"
TEST_NAME="${1:-all}"

run_scenario() {
    local name="$1"
    local compose_service="$2"
    local timeout="$3"

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
    output=$($COMPOSE run --rm --timeout "$timeout" "$compose_service" 2>&1 &
        BOT_PID=$!
        sleep "$timeout"
        kill $BOT_PID 2>/dev/null || true
        wait $BOT_PID 2>/dev/null || true
    )

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

case "$TEST_NAME" in
    no-net)
        run_scenario "No-Network (init + loop + shutdown)" "bot-no-net" 20
        ;;
    mock-c2)
        run_scenario "Mock C2 (IRC + HTTP)" "bot-mock-c2" 30
        ;;
    all)
        run_scenario "No-Network (init + loop + shutdown)" "bot-no-net" 20
        echo ""
        echo "───────────────────────────────────────────────────────"
        echo ""
        run_scenario "Mock C2 (IRC + HTTP)" "bot-mock-c2" 30
        ;;
    *)
        echo "Usage: $0 [no-net|mock-c2|all]"
        echo ""
        echo "  no-net   - Test bot with no networking (init, loop, shutdown)"
        echo "  mock-c2  - Test bot with mock IRC + HTTP C2 servers"
        echo "  all      - Run both scenarios"
        exit 1
        ;;
esac
