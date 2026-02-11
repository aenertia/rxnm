#!/bin/bash
# ==============================================================================
# RXNM PHASE 2 CORE AGENT TESTS
# Validates Netlink Data Collection
# ==============================================================================

AGENT_BIN="./bin/rxnm-agent"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; exit 1; }

echo "--- RXNM Phase 2 Agent Tests ---"

# 1. Build Agent
echo "Ensuring build..."
make tiny >/dev/null || fail "Build failed"

# 2. Run Dump
echo "Running --dump..."
output=$("$AGENT_BIN" --dump)
exit_code=$?

if [ $exit_code -ne 0 ]; then
    fail "Agent crashed or returned non-zero"
fi

# 3. Validate JSON Structure
if echo "$output" | grep -q '"interfaces": {'; then
    pass "JSON structure valid (found interfaces object)"
else
    fail "JSON invalid: $output"
fi

# 4. Check for Loopback (lo)
# Netlink should always find 'lo'
if echo "$output" | grep -q '"name": "lo"'; then
    pass "Found loopback interface (Netlink working)"
else
    fail "Netlink failed to find 'lo'. Permissions issue?"
fi

# 5. Check for IP Address (if any interface has one)
# This is heuristic, passed if we see an "ip" field or if ip addr show is empty
if ip addr show | grep -q "inet "; then
    if echo "$output" | grep -q '"ip":'; then
        pass "IP address reporting verified"
    else
        # Dump output for debug
        echo "$output"
        fail "System has IP, but Agent didn't report it"
    fi
else
    echo "Skipping IP check (no system IPs found)"
fi

echo "--- All Phase 2 Tests Passed ---"
exit 0
