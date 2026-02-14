#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: test_cli_fuzz.sh
# PURPOSE: CLI Fuzzing & Regression Testing with Environment Mocking
# ARCHITECTURE: Test Suite
#
# Iterates through permutations of categories, actions, and flags to detect:
# 1. Missing dependencies (command not found)
# 2. Bash syntax errors
# 3. Unhandled argument combinations
#
# FEATURES:
# - Auto-Mocks systemd-networkd/iwd tools if missing (for Distrobox/CI)
# - Validates exit codes and stderr purity
# - ISOLATION: Runs in temporary directories to prevent filesystem writes
# -----------------------------------------------------------------------------

BIN_DIR="./bin"
RXNM="$BIN_DIR/rxnm"

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
    fail "RXNM binary not found at $RXNM"
    exit 1
fi

# --- ISOLATION ENVIRONMENT ---
# Create temp directories to override RXNM global paths
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

export CONF_DIR="$TEST_ROOT/config"
export STATE_DIR="$TEST_ROOT/var/lib"
export RUN_DIR="$TEST_ROOT/run"
export EPHEMERAL_NET_DIR="$TEST_ROOT/run/systemd/network"
export PERSISTENT_NET_DIR="$TEST_ROOT/config/network"

mkdir -p "$CONF_DIR" "$STATE_DIR" "$RUN_DIR" "$EPHEMERAL_NET_DIR" "$PERSISTENT_NET_DIR"

info "Test Root: $TEST_ROOT"

# --- MOCKING INFRASTRUCTURE ---
MOCK_DIR="$TEST_ROOT/bin"
mkdir -p "$MOCK_DIR"

setup_mocks() {
    info "Injecting mocks..."
    
    # 1. Mock systemctl (Always report services as active to trigger logic paths)
    cat <<'EOF' > "$MOCK_DIR/systemctl"
#!/bin/bash
if [[ "$1" == "is-active" ]]; then
    for arg in "${@:2}"; do echo "active"; done
    exit 0
fi
exit 0
EOF
    chmod +x "$MOCK_DIR/systemctl"

    # 2. Mock busctl (Return empty valid JSON for IWD queries)
    cat <<'EOF' > "$MOCK_DIR/busctl"
#!/bin/bash
if [[ "$*" == *"GetManagedObjects"* ]]; then echo '{"data": {}}'; exit 0; fi
if [[ "$*" == *"get-property"* ]]; then echo '{"data": "false"}'; exit 0; fi
exit 0
EOF
    chmod +x "$MOCK_DIR/busctl"

    # 3. Mock networkctl (Return empty valid JSON list)
    cat <<'EOF' > "$MOCK_DIR/networkctl"
#!/bin/bash
if [[ "$*" == *"json"* ]]; then echo '[]'; else echo "IDX LINK TYPE OPERATIONAL"; fi
exit 0
EOF
    chmod +x "$MOCK_DIR/networkctl"

    # 4. Mock iwctl (Silent success)
    cat <<'EOF' > "$MOCK_DIR/iwctl"
#!/bin/bash
exit 0
EOF
    chmod +x "$MOCK_DIR/iwctl"

    # 5. Mock ip (Basic output)
    cat <<'EOF' > "$MOCK_DIR/ip"
#!/bin/bash
if [[ "$*" == *"-j"* ]]; then echo '[]'; else if [ -x /usr/bin/ip ]; then /usr/bin/ip "$@"; else echo ""; fi; fi
exit 0
EOF
    chmod +x "$MOCK_DIR/ip"

    export PATH="$MOCK_DIR:$PATH"
}

# Auto-detect need for mocks
if ! command -v iwd >/dev/null 2>&1 || ! command -v networkctl >/dev/null 2>&1 || [ "${RXNM_TEST_MOCKS:-0}" -eq 1 ]; then
    setup_mocks
    
    # CRITICAL: Reduce agent DBus timeout for mock environment
    # This prevents the 5-second retry loop when the DBus socket is missing
    # in Distrobox/Container environments.
    export RXNM_DBUS_TIMEOUT_MS=100
    info "Reduced DBus timeout to 100ms for testing."
fi

# --- FUZZER LOGIC ---

ERRORS=0
TOTAL=0

# Define test vectors
# Format: "CMD_ARGS"
TEST_VECTORS=(
    # Category: Interface
    "interface list"
    "interface show"
    "interface wlan0 show"
    "interface eth0 list"
    "interface list --json"
    "interface list --simple"
    "interface wlan0 show --get ip"
    "interface wlan0 set hardware --speed 1000" # Dry run check
    
    # Category: System
    "system status"
    "system status --simple"
    "system check internet"
    "system proxy set --http 1.2.3.4" # Should verify interface lib loaded
    
    # Category: Bridge/Bond/Virt (Virtuals often miss deps)
    "bridge list"
    "bond list"
    "vlan list"
    "vrf list"
    "bridge create br_fuzz_test"
    # Added --yes to bypass confirmation hang
    "bridge delete br_fuzz_test --yes"
    
    # Category: WiFi
    "wifi status"
    "wifi list"
    "wifi networks"
    "wifi scan"
    
    # Category: Profile
    "profile list"
    
    # Global Flags
    "--version"
    "--help"
    "interface --help"
    
    # Edge Cases
    "interface invalid_action"
    "interface wlan0 --get invalid.key"
)

echo "--- Starting CLI Fuzzing ---"

run_fuzz() {
    local args="$1"
    local description="rxnm $args"
    TOTAL=$((TOTAL+1))
    
    local stderr_file
    stderr_file=$(mktemp)
    
    # Run with timeout to prevent hangs
    timeout 2s "$RXNM" $args >/dev/null 2> "$stderr_file"
    local ret=$?
    
    local stderr_content
    stderr_content=$(cat "$stderr_file")
    rm -f "$stderr_file"
    
    # Check 1: Timeout
    if [ $ret -eq 124 ]; then
        fail "$description (Timed out)"
        return
    fi
    
    # Check 2: Bash Errors (The Core Goal)
    if echo "$stderr_content" | grep -qE "command not found|syntax error|unbound variable|Bad substitution"; then
        fail "$description (Script Error detected)"
        echo "    Output: $stderr_content"
        return
    fi
    
    # Check 3: Logic (Loose check)
    if [[ "$args" == *"list"* ]] || [[ "$args" == *"status"* ]]; then
        if [ $ret -ne 0 ] && [[ "$args" != *"invalid"* ]]; then
            warn "$description returned $ret (Expected 0 with mocks)"
        else
            pass "$description"
        fi
    else
        pass "$description (Exit: $ret)"
    fi
}

for vector in "${TEST_VECTORS[@]}"; do
    run_fuzz "$vector"
done

echo "-----------------------------------"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}Fuzzing Complete: $TOTAL tests passed.${NC}"
    exit 0
else
    echo -e "${RED}Fuzzing Failed: $ERRORS errors found.${NC}"
    exit 1
fi
