#!/bin/bash
# ==============================================================================
# RXNM PHASE 5 CONSISTENCY VALIDATION
# Compares Agent Output vs Legacy Shell Output (Extended for WiFi)
# ==============================================================================

# Setup Environment
LIB_DIR="./lib"
BIN_DIR="./bin"
TEST_AGENT_BIN="$BIN_DIR/rxnm-agent"

# Source Legacy Logic
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

log_pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
log_fail() { echo -e "${RED}✗ FAIL:${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠ WARN:${NC} $1"; }

if [ ! -x "$TEST_AGENT_BIN" ]; then
    echo "Agent binary not found at $TEST_AGENT_BIN. Run 'make tiny' first."
    exit 1
fi

echo "--- Generating Data ---"

# 1. Capture Legacy Output
echo "Running Legacy Shell Logic..."
json_legacy=$(action_status_legacy)

# 2. Capture Agent Output
echo "Running Native Agent..."
json_agent=$("$TEST_AGENT_BIN" --dump)

# 3. Validation Logic using JQ
echo "--- Comparing Results ---"

# Compare Interface Lists
ifaces_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r '.interfaces | keys | sort | .[]')
ifaces_agent=$(echo "$json_agent" | "$JQ_BIN" -r '.interfaces | keys | sort | .[]')

if [ "$ifaces_legacy" == "$ifaces_agent" ]; then
    log_pass "Interface list matches exactly"
else
    log_fail "Interface mismatch!"
fi

# Deep Dive: Per-Interface IP/Gateway Checks
for iface in $ifaces_agent; do
    # Extract IPs
    ip_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].ip // empty")
    ip_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].ip // empty")
    
    if [ -n "$ip_legacy" ] && [[ "$ip_agent" == "$ip_legacy"* ]]; then
        log_pass "[$iface] IP Match: $ip_legacy vs $ip_agent"
    elif [ -z "$ip_legacy" ] && [ -z "$ip_agent" ]; then
        log_pass "[$iface] IP Match: (Both empty)"
    else
        log_warn "[$iface] IP Divergence: Legacy='$ip_legacy', Agent='$ip_agent'"
    fi

    # Check Gateway
    gw_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].gateway // empty")
    gw_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].gateway // empty")
    
    if [ "$gw_legacy" == "$gw_agent" ]; then
        log_pass "[$iface] Gateway Match: ${gw_agent:-none}"
    else
        log_fail "[$iface] Gateway Mismatch: Legacy='$gw_legacy', Agent='$gw_agent'"
    fi
done

# Issue 5.1: Check WiFi fields for wireless interfaces
echo "--- Checking WiFi Metadata Consistency ---"
for iface in $ifaces_agent; do
    is_wifi_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi // \"null\"")
    is_wifi_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi // \"null\"")
    
    if [ "$is_wifi_agent" != "null" ] || [ "$is_wifi_legacy" != "null" ]; then
        ssid_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.ssid // empty")
        ssid_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.ssid // empty")
        
        if [ "$ssid_agent" = "$ssid_legacy" ]; then
            log_pass "[$iface] WiFi SSID match: '${ssid_agent:-none}'"
        else
            log_fail "[$iface] WiFi SSID mismatch: agent='$ssid_agent', legacy='$ssid_legacy'"
        fi
        
        bssid_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.bssid // empty")
        bssid_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.bssid // empty")
        
        if [ "$bssid_agent" = "$bssid_legacy" ]; then
            log_pass "[$iface] WiFi BSSID match: '${bssid_agent:-none}'"
        else
            # Divergence is expected if using different collection methods, but should be minimal
            log_warn "[$iface] WiFi BSSID divergence: agent='$bssid_agent', legacy='$bssid_legacy'"
        fi

        freq_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.frequency // empty")
        freq_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.frequency // empty")

        if [ "$freq_agent" = "$freq_legacy" ]; then
            log_pass "[$iface] WiFi Frequency match: ${freq_agent:-none} MHz"
        else
            log_warn "[$iface] WiFi Frequency divergence: agent='$freq_agent', legacy='$freq_legacy'"
        fi
    fi
done

# 4. JSON Validity Check
if echo "$json_agent" | "$JQ_BIN" . >/dev/null 2>&1; then
    log_pass "Agent JSON is valid"
else
    log_fail "Agent produced invalid JSON"
fi

echo "--- Consistency Check Complete ---"
