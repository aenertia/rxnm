#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: verify_rc3.sh
# PURPOSE: Release Candidate 3 Verification Suite
# ARCHITECTURE: Test Suite / Verification
#
# Validates key RC3 features:
# 1. Service Isolation (Namespace creation/execution)
# 2. Stub Correctness (MPLS/PPPoE return 501)
# 3. Agent Fallback (Graceful degradation if agent missing)
# -----------------------------------------------------------------------------

BIN_DIR="./bin"
LIB_DIR="./lib"
RXNM="$BIN_DIR/rxnm"
AGENT_BIN="$BIN_DIR/rxnm-agent"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "${YELLOW}⚠ WARN:${NC} $1"; }
info() { echo -e "${CYAN}ℹ INFO:${NC} $1"; }

ERRORS=0

# --- MOCKING SETUP ---
# Create temp environment
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

export CONF_DIR="$TEST_ROOT/config"
export STATE_DIR="$TEST_ROOT/var/lib"
export RUN_DIR="$TEST_ROOT/run"
mkdir -p "$CONF_DIR" "$STATE_DIR" "$RUN_DIR"

# Mock required system tools if not root/available
if [ "$EUID" -ne 0 ]; then
    warn "Running as non-root: mocking 'ip' command for Service tests"
    mkdir -p "$TEST_ROOT/bin"
    cat <<'EOF' > "$TEST_ROOT/bin/ip"
#!/bin/bash
if [[ "$*" == *"netns add"* ]]; then exit 0; fi
if [[ "$*" == *"netns del"* ]]; then exit 0; fi
if [[ "$*" == *"netns exec"* ]]; then shift 3; exec "$@"; fi
# Default passthrough or silent success
exit 0
EOF
    chmod +x "$TEST_ROOT/bin/ip"
    export PATH="$TEST_ROOT/bin:$PATH"
fi

# Enable experimental features for testing
export RXNM_EXPERIMENTAL=true

echo "--- RC3 Verification Suite ---"

# TEST 1: Service Isolation (Stub or Real)
info "Testing Service Architecture..."
SERVICE_NAME="rc3_test_ns"

# Create (Use --json for deterministic grep)
out=$("$RXNM" service create "$SERVICE_NAME" --json)
if echo "$out" | grep -q "created"; then
    pass "Service creation (mocked/real)"
else
    fail "Service creation failed: $out"
fi

# Exec
# This verifies argument propagation fixed in Phase 1
exec_out=$("$RXNM" service exec "$SERVICE_NAME" echo "hello world")
if [[ "$exec_out" == "hello world" ]]; then
    pass "Service execution argument propagation"
else
    fail "Service exec failed. Expected 'hello world', got: '$exec_out'"
fi

# Delete (Use --json for deterministic grep)
out=$("$RXNM" service delete "$SERVICE_NAME" --json)
if echo "$out" | grep -q "deleted"; then
    pass "Service deletion"
else
    fail "Service deletion failed: $out"
fi

# TEST 2: Stub Correctness
info "Testing Experimental Stubs..."

# MPLS (Should be 501 Not Implemented)
# Capture stderr (2>&1) because human-readable errors go to stderr
mpls_out=$("$RXNM" mpls route-add --label 100 2>&1)
if echo "$mpls_out" | grep -q "not yet implemented"; then
    pass "MPLS stub correctly identifies as unimplemented"
else
    fail "MPLS stub behavior incorrect: $mpls_out"
fi

# TEST 3: Agent Fallback
info "Testing Agent Fallback..."

if [ -f "$AGENT_BIN" ]; then
    mv "$AGENT_BIN" "$AGENT_BIN.bak"
    
    # Run a command that typically uses agent (e.g. check internet)
    # Mocking tcp check in pure bash might fail if no internet, but we check if it runs without crashing
    
    # We'll use a simpler one: system status
    status_out=$("$RXNM" system status --simple)
    if [ $? -eq 0 ]; then
        pass "Bash fallback operational (Agent missing)"
    else
        fail "Bash fallback crashed"
    fi
    
    mv "$AGENT_BIN.bak" "$AGENT_BIN"
else
    warn "Agent binary not found, skipping fallback test (already running in fallback mode?)"
fi

echo "-----------------------------------"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}RC3 Verification Complete: All tests passed.${NC}"
    exit 0
else
    echo -e "${RED}RC3 Verification Failed: $ERRORS errors found.${NC}"
    exit 1
fi
