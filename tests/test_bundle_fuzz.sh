#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: tests/test_bundle_fuzz.sh
# PURPOSE: CLI Fuzzing & Regression Testing for the ROCKNIX Bundle
# ARCHITECTURE: Test Suite
#
# Tests the generated single-file artifact `build/rxnm` to ensure:
# 1. Amalgamation didn't introduce syntax/parsing errors.
# 2. Pruned enterprise features correctly fail cleanly (no "command not found").
# -----------------------------------------------------------------------------

RXNM="./build/rxnm"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "${YELLOW}⚠ WARN:${NC} $1"; }
info() { echo -e "${CYAN}ℹ INFO:${NC} $1"; }

if [ ! -x "$RXNM" ]; then
    fail "Bundle binary not found at $RXNM. Run 'make rocknix-release' first."
    exit 1
fi

# --- ISOLATION ENVIRONMENT ---
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

export CONF_DIR="$TEST_ROOT/config"
export STATE_DIR="$TEST_ROOT/var/lib"
export RUN_DIR="$TEST_ROOT/run"
export EPHEMERAL_NET_DIR="$TEST_ROOT/run/systemd/network"
export PERSISTENT_NET_DIR="$TEST_ROOT/config/network"
# Force tiny DBus timeout for mocks
export RXNM_DBUS_TIMEOUT_MS=100 

mkdir -p "$CONF_DIR" "$STATE_DIR" "$RUN_DIR" "$EPHEMERAL_NET_DIR" "$PERSISTENT_NET_DIR"

# --- MOCKING INFRASTRUCTURE ---
MOCK_DIR="$TEST_ROOT/bin"
mkdir -p "$MOCK_DIR"

setup_mocks() {
    cat <<'EOF' > "$MOCK_DIR/systemctl"
#!/bin/bash
if [[ "$1" == "is-active" ]]; then exit 0; fi
exit 0
EOF
    chmod +x "$MOCK_DIR/systemctl"

    cat <<'EOF' > "$MOCK_DIR/busctl"
#!/bin/bash
echo '{"data": {}}'
exit 0
EOF
    chmod +x "$MOCK_DIR/busctl"

    cat <<'EOF' > "$MOCK_DIR/networkctl"
#!/bin/bash
if [[ "$*" == *"json"* ]]; then echo '[]'; else echo "IDX LINK TYPE OPERATIONAL"; fi
exit 0
EOF
    chmod +x "$MOCK_DIR/networkctl"

    cat <<'EOF' > "$MOCK_DIR/iwctl"
#!/bin/bash
exit 0
EOF
    chmod +x "$MOCK_DIR/iwctl"

    cat <<'EOF' > "$MOCK_DIR/ip"
#!/bin/bash
echo '[]'
exit 0
EOF
    chmod +x "$MOCK_DIR/ip"

    export PATH="$MOCK_DIR:$PATH"
}

setup_mocks

# --- FUZZER LOGIC ---

ERRORS=0
TOTAL=0

# Define test vectors
# Format: "CMD_ARGS"
VALID_VECTORS=(
    "system status"
    "system status --simple"
    "system check internet"
    "system nullify status"
    "interface list"
    "interface wlan0 show"
    "interface wlan0 set dhcp"
    "wifi status"
    "wifi list"
    "vpn wireguard list"
    "bluetooth scan"
    "--version"
    "--help"
)

# Features that should be explicitly rejected by the bundle as 'Unknown command'
PRUNED_VECTORS=(
    "service list"
    "mpls route-list"
    "tunnel list"
    "bridge create br0"
    "vlan create vlan10"
    "vrf list"
    "ha bfd-list"
)

echo "--- Starting ROCKNIX Bundle Fuzzing ---"

run_fuzz() {
    local args="$1"
    local expect_pruned="$2"
    local description="rxnm $args"
    TOTAL=$((TOTAL+1))
    
    local out_file
    out_file=$(mktemp)
    
    # Run with timeout to prevent hangs
    timeout 2s "$RXNM" $args > "$out_file" 2>&1
    local ret=$?
    
    local out_content
    out_content=$(cat "$out_file")
    rm -f "$out_file"
    
    # Check 1: Timeout
    if [ $ret -eq 124 ]; then
        fail "$description (Timed out)"
        return
    fi
    
    # Check 2: Fatal Bash Errors (The Core Goal)
    # We look for "No such file" to ensure indented `source` lines were properly stripped.
    if echo "$out_content" | grep -qiE "command not found|syntax error|unbound variable|Bad substitution|No such file or directory"; then
        fail "$description (Script Error detected in bundle)"
        echo "    Output: $out_content"
        return
    fi
    
    # Check 3: Pruned Validation
    if [ "$expect_pruned" == "true" ]; then
        if echo "$out_content" | grep -q "Unknown command or category"; then
            pass "$description (Correctly rejected pruned category)"
        else
            fail "$description (Failed to cleanly reject pruned category)"
            echo "    Output: $out_content"
        fi
        return
    fi
    
    pass "$description (Exit: $ret)"
}

for vector in "${VALID_VECTORS[@]}"; do
    run_fuzz "$vector" "false"
done

for vector in "${PRUNED_VECTORS[@]}"; do
    run_fuzz "$vector" "true"
done

echo "-----------------------------------"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}Bundle Fuzzing Complete: $TOTAL tests passed.${NC}"
    exit 0
else
    echo -e "${RED}Bundle Fuzzing Failed: $ERRORS errors found.${NC}"
    exit 1
fi
