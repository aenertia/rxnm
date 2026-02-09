#!/bin/bash
# ==============================================================================
# RXNM PHASE 1 FOUNDATION TESTS
# Validates Agent-Shell Consistency & Binary Characteristics
# ==============================================================================

AGENT_BIN="./bin/rxnm-agent"
CONSTANTS_SH="lib/rxnm-constants.sh"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
YELLOW='\033[0;33m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}ℹ INFO:${NC} $1"; }

echo "--- RXNM Agent Foundation Tests ---"

# 1. Check Binary Existence
if [ ! -x "$AGENT_BIN" ]; then
    fail "Agent binary not found at $AGENT_BIN"
fi
pass "Agent binary exists"

# 2. Binary Analysis (Size & Linking)
filesize=$(stat -c%s "$AGENT_BIN")
info "Binary Size: ${filesize} bytes"

if command -v file >/dev/null; then
    filetype=$(file "$AGENT_BIN")
    if [[ "$filetype" == *"statically linked"* ]]; then
        pass "Binary is statically linked (Portable)"
        if [ "$filesize" -lt 100000 ]; then
            pass "Binary size is optimal (<100KB)"
        else
            info "Binary size >100KB. Consider using musl-gcc or 'make tiny'."
        fi
    else
        info "Binary is dynamically linked. (Use 'make tiny' for extremis targets)"
    fi
else
    info "Skipping 'file' check (utility not installed). Ensure static linking manually."
fi

# 3. Test Time Consistency
sh_time=$(date +%s)
agent_time=$("$AGENT_BIN" --time)
diff=$((sh_time - agent_time))
diff=${diff#-} # Abs

if [ "$diff" -le 1 ]; then
    pass "Time sync check (Delta: ${diff}s)"
else
    fail "Time divergent! Shell: $sh_time, Agent: $agent_time"
fi

# 4. Test Low Power Detection Consistency
source "$CONSTANTS_SH"
agent_lp=$("$AGENT_BIN" --is-low-power)

if [ "$IS_LOW_POWER" == "$agent_lp" ]; then
    pass "Low Power Detection Logic ($agent_lp)"
else
    fail "Logic Mismatch. Shell: $IS_LOW_POWER, Agent: $agent_lp"
fi

# 5. Test Health JSON
health_json=$("$AGENT_BIN" --health)
if echo "$health_json" | grep -q "\"success\": true"; then
    pass "Health Check JSON valid"
else
    fail "Health Check JSON invalid: $health_json"
fi

echo "--- All Foundation Tests Passed ---"
exit 0
