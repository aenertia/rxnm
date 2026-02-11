#!/bin/bash
# ==============================================================================
# RXNM PHASE 4.2 PERFORMANCE REGRESSION CHECK
# Measures Latency: Legacy vs Agent with statistical pass/fail
# Target: Agent < 5ms avg on embedded hardware
# ==============================================================================

# Setup
LIB_DIR="./lib"
BIN_DIR="./bin"
AGENT_BIN="$BIN_DIR/rxnm-agent"
ITERATIONS=50  # Increased for statistical significance

# Source Legacy
export RXNM_LIB_DIR="$LIB_DIR"
source "$LIB_DIR/rxnm-constants.sh"
source "$LIB_DIR/rxnm-utils.sh"
source "$LIB_DIR/rxnm-system.sh"
source "$LIB_DIR/rxnm-diagnostics.sh"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; }
warn() { echo -e "${YELLOW}⚠ WARN:${NC} $1"; }

# Helper for nanosecond timing
get_time() {
    date +%s%N
}

if [ ! -x "$AGENT_BIN" ]; then
    fail "Agent binary not found at $AGENT_BIN. Run 'make tiny'."
    exit 1
fi

echo "--- Benchmarking (n=$ITERATIONS) ---"

# 1. Benchmark Legacy (Warmup run first)
action_status_legacy > /dev/null

echo "Measuring Legacy Shell..."
total_legacy=0
for ((i=1; i<=ITERATIONS; i++)); do
    start=$(get_time)
    action_status_legacy > /dev/null
    end=$(get_time)
    diff=$((end - start))
    total_legacy=$((total_legacy + diff))
    # echo -n "."
done
avg_legacy_ns=$((total_legacy / ITERATIONS))
avg_legacy=$((avg_legacy_ns / 1000000))
echo ""
echo "Legacy Avg: ${avg_legacy} ms ($avg_legacy_ns ns)"

# 2. Benchmark Agent (Warmup run first)
"$AGENT_BIN" --dump > /dev/null

echo "Measuring Native Agent..."
total_agent=0
for ((i=1; i<=ITERATIONS; i++)); do
    start=$(get_time)
    "$AGENT_BIN" --dump > /dev/null
    end=$(get_time)
    diff=$((end - start))
    total_agent=$((total_agent + diff))
    # echo -n "."
done
avg_agent_ns=$((total_agent / ITERATIONS))
avg_agent=$((avg_agent_ns / 1000000))
echo ""
echo "Agent Avg:  ${avg_agent} ms ($avg_agent_ns ns)"

# 3. Results & Regression Logic
echo "-----------------------------------"
if [ "$avg_agent" -eq 0 ]; then avg_agent=1; fi
speedup=$((avg_legacy / avg_agent))

echo "RESULTS:"
echo "Legacy: ${avg_legacy}ms"
echo "Agent:  ${avg_agent}ms"
echo "Speedup: ${speedup}x FASTER"

# Thresholds (Simulated Hardware Targets)
# RK3326 Target: < 5ms
# SG2002 Target: < 15ms
TARGET_MS=5

if [ "$avg_agent" -lt "$TARGET_MS" ]; then
    pass "Performance meets RK3326 target (<${TARGET_MS}ms)"
elif [ "$avg_agent" -lt 15 ]; then
    warn "Performance OK for SG2002 (<15ms) but missed RK3326 target."
else
    fail "Performance REGRESSION detected (>15ms)."
    exit 1
fi

echo "-----------------------------------"
exit 0
