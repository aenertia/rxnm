#!/bin/bash
# ==============================================================================
# RXNM PHASE 6 QUERY INTERFACE TESTS
# Validates --get functionality
# ==============================================================================

AGENT_BIN="./bin/rxnm-agent"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; exit 1; }

if [ ! -x "$AGENT_BIN" ]; then
    fail "Agent binary not found"
fi

echo "--- RXNM Agent Query Tests ---"

# 1. Test Hostname Query
echo "Querying hostname..."
host_val=$("$AGENT_BIN" --get hostname)
if [ -n "$host_val" ]; then
    pass "Hostname retrieved: $host_val"
else
    fail "Hostname query returned empty"
fi

# 2. Test Interface Query (Loopback)
echo "Querying interfaces.lo.state..."
lo_state=$("$AGENT_BIN" --get interfaces.lo.state)
if [ "$lo_state" == "routable" ] || [ "$lo_state" == "unknown" ]; then
    pass "Loopback state retrieved: $lo_state"
else
    fail "Loopback state unexpected: '$lo_state'"
fi

# 3. Test Invalid Key (Should be empty)
echo "Querying invalid key..."
bad_val=$("$AGENT_BIN" --get interfaces.nonexistent.ip)
if [ -z "$bad_val" ]; then
    pass "Invalid key returned empty string (Correct)"
else
    fail "Invalid key returned data: '$bad_val'"
fi

echo "--- All Query Tests Passed ---"
exit 0
