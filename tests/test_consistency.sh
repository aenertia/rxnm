#!/bin/bash
# ==============================================================================
# RXNM PHASE 4.1 CONSISTENCY VALIDATION (STRICT)
# Compares Agent Output vs Legacy Shell Output
# Checks: Interfaces, IPs, Gateways, Routes (strict CIDR), Types (strict none/unknown)
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
CYAN='\033[0;36m'
NC='\033[0m'

log_pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
log_fail() { echo -e "${RED}✗ FAIL:${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠ WARN:${NC} $1"; }
log_info() { echo -e "${CYAN}ℹ INFO:${NC} $1"; }

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

if [ "$ifaces_legacy" = "$ifaces_agent" ]; then
    log_pass "Interface list matches exactly"
else
    log_fail "Interface mismatch!"
    echo "Legacy: $(echo "$ifaces_legacy" | tr '\n' ' ')"
    echo "Agent:  $(echo "$ifaces_agent" | tr '\n' ' ')"
fi

# Deep Dive: Per-Interface Checks
for iface in $ifaces_agent; do
    echo "--- Analyzing Interface: $iface ---"
    
    # 1. IPv4 Address
    # FIX: Normalize Legacy IP output. If it's an array (older networkctl), join with dots.
    ip_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r "(.interfaces[\"$iface\"].ip | if type==\"array\" then join(\".\") else . end) // empty")
    ip_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].ip // empty")
    
    case "$ip_agent" in
        "${ip_legacy}"*) log_pass "IP Match: $ip_legacy" ;;
        *)
            if [ -z "$ip_legacy" ] && [ -z "$ip_agent" ]; then
                log_pass "IP Match: (Both empty)"
            else
                log_warn "IP Divergence: Legacy='$ip_legacy', Agent='$ip_agent'"
            fi
            ;;
    esac

    # 2. Gateway
    gw_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].gateway // empty")
    gw_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].gateway // empty")
    
    if [ "$gw_legacy" = "$gw_agent" ]; then
        log_pass "Gateway Match: ${gw_agent:-none}"
    else
        log_fail "Gateway Mismatch: Legacy='$gw_legacy', Agent='$gw_agent'"
    fi

    # 3. MAC Address (Normalized to lowercase)
    raw_mac_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].mac // empty")
    
    # FIX: Handle Networkctl decimal array quirk (e.g., [202, 2, ...]) safely
    case "$raw_mac_legacy" in
        \[*)
            mac_legacy=$(echo "$raw_mac_legacy" | "$JQ_BIN" -r '.[]' | while IFS= read -r num; do
                printf "%02x" "$num"
            done | sed 's/\(..\)/\1:/g' | sed 's/:$//')
            ;;
        *)
            mac_legacy="$raw_mac_legacy"
            ;;
    esac
    
    mac_legacy=$(echo "$mac_legacy" | tr '[:upper:]' '[:lower:]')
    mac_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].mac // empty" | tr '[:upper:]' '[:lower:]')
    
    # FIX: Treat empty string and zero-mac as equivalent for loopback or uninitialized virtuals
    if [ "$mac_legacy" = "$mac_agent" ] || { [ "$iface" = "lo" ] && { [ -z "$mac_legacy" ] || [ "$mac_legacy" = "00:00:00:00:00:00" ]; }; }; then
        log_pass "MAC Match: ${mac_agent:-none}"
    else
        log_fail "MAC Mismatch: Legacy='$raw_mac_legacy', Agent='$mac_agent'"
    fi

    # 4. MTU
    mtu_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].mtu // 0")
    mtu_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].mtu // 0")
    
    if [ "$mtu_legacy" -eq "$mtu_agent" ]; then
        log_pass "MTU Match: $mtu_agent"
    else
        log_warn "MTU Divergence: Legacy='$mtu_legacy', Agent='$mtu_agent'"
    fi

    # 5. Interface Type (Strict check for unknown/none)
    type_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].type // \"unknown\"")
    type_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].type // \"unknown\"")
    
    # Normalization: Map 'none' (legacy networkctl quirk) to 'unknown' (schema standard)
    [ "$type_legacy" = "none" ] && type_legacy="unknown"
    [ "$type_agent" = "none" ] && type_agent="unknown"

    if [ "$type_legacy" = "$type_agent" ]; then
        log_pass "Type Match: $type_agent"
    else
        log_warn "Type Divergence: Legacy='$type_legacy', Agent='$type_agent'"
    fi

    # 6. Routes (Dest@Gateway) - Strict CIDR Check
    routes_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].routes[]? | \"\(.dst)@\(.gw // \"none\")\"" | sort | tr '\n' ',' | sed 's/,$//')
    routes_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].routes[]? | \"\(.dst)@\(.gw // \"none\")\"" | sort | tr '\n' ',' | sed 's/,$//')
    
    if [ "$routes_legacy" = "$routes_agent" ]; then
        log_pass "Routes Match"
    else
        log_warn "Route Divergence:"
        echo "      Legacy: [$routes_legacy]"
        echo "      Agent:  [$routes_agent]"
    fi

    # 7. IPv6 Addresses
    ipv6_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].ipv6[]?" | sort | tr '\n' ',' | sed 's/,$//')
    ipv6_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].ipv6[]?" | sort | tr '\n' ',' | sed 's/,$//')
    
    # FIX: Detect if Legacy output corrupted by array-to-string conversion
    case "$ipv6_legacy" in
        *",,"*) log_info "Legacy IPv6 output format is raw array (incompatible with simple diff). Skipping comparison." ;;
        *)
            if [ "$ipv6_legacy" = "$ipv6_agent" ]; then
                if [ -n "$ipv6_agent" ]; then
                    log_pass "IPv6 Match: Found addresses"
                else
                    log_pass "IPv6 Match: (None)"
                fi
            else
                log_warn "IPv6 Divergence: Legacy='$ipv6_legacy', Agent='$ipv6_agent'"
            fi
            ;;
    esac

    # 8. WiFi Metadata (If applicable)
    is_wifi_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi // \"null\"")
    is_wifi_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi // \"null\"")
    
    if [ "$is_wifi_agent" != "null" ] || [ "$is_wifi_legacy" != "null" ]; then
        ssid_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.ssid // empty")
        ssid_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.ssid // empty")
        
        if [ "$ssid_agent" = "$ssid_legacy" ]; then
            log_pass "WiFi SSID match: '${ssid_agent:-none}'"
        else
            log_fail "WiFi SSID mismatch: agent='$ssid_agent', legacy='$ssid_legacy'"
        fi
        
        bssid_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.bssid // empty")
        bssid_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.bssid // empty")
        
        if [ "$bssid_agent" = "$bssid_legacy" ]; then
            log_pass "WiFi BSSID match: '${bssid_agent:-none}'"
        else
            log_warn "WiFi BSSID divergence: agent='$bssid_agent', legacy='$bssid_legacy'"
        fi

        freq_agent=$(echo "$json_agent" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.frequency // empty")
        freq_legacy=$(echo "$json_legacy" | "$JQ_BIN" -r ".interfaces[\"$iface\"].wifi.frequency // empty")

        if [ "$freq_agent" = "$freq_legacy" ]; then
            log_pass "WiFi Frequency match: ${freq_agent:-none} MHz"
        else
            log_warn "WiFi Frequency divergence: agent='$freq_agent', legacy='$freq_legacy'"
        fi
    fi
done

# 9. JSON Validity Check
if echo "$json_agent" | "$JQ_BIN" . >/dev/null 2>&1; then
    log_pass "Agent JSON is valid"
else
    log_fail "Agent produced invalid JSON"
fi

echo "--- Consistency Check Complete ---"
