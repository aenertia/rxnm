#!/bin/bash
# ==============================================================================
# RXNM PHASE 3 PERFORMANCE BENCHMARK
# Measures Latency: Legacy vs Agent
# ==============================================================================

# Setup
LIB_DIR="./lib"
BIN_DIR="./bin"
AGENT_BIN="$BIN_DIR/rxnm-agent"
ITERATIONS=10

# Source Legacy
export RXNM_LIB_DIR="$LIB_DIR"
source "$LIB_DIR/rxnm-constants.sh"
source "$LIB_DIR/rxnm-utils.sh"
# FIX: Source system module
source "$LIB_DIR/rxnm-system.sh"
source "$LIB_DIR/rxnm-diagnostics.sh"

# Helper for nanosecond timing
get_time() {
    date +%s%N
}

echo "--- Benchmarking (n=$ITERATIONS) ---"

# 1. Benchmark Legacy
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
avg_legacy=$((total_legacy / ITERATIONS / 1000000)) # to ms
echo ""
echo "Legacy Avg: ${avg_legacy} ms"

# 2. Benchmark Agent
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
avg_agent=$((total_agent / ITERATIONS / 1000000)) # to ms
echo ""
echo "Agent Avg:  ${avg_agent} ms"

# 3. Results
echo "-----------------------------------"
if [ "$avg_agent" -eq 0 ]; then avg_agent=1; fi # Prevent div/0 for sub-1ms
speedup=$((avg_legacy / avg_agent))

echo "RESULTS:"
echo "Legacy: ${avg_legacy}ms"
echo "Agent:  ${avg_agent}ms"
echo "Speedup: ${speedup}x FASTER"

if [ "$avg_agent" -lt 5 ]; then
    echo "✓ SUCCESS: Target latency (<5ms) achieved."
else
    echo "⚠ WARNING: Latency target missed ($avg_agent ms)."
fi
echo "-----------------------------------"
