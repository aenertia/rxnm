# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-config-schema.sh
# PURPOSE: Declarative State Validation
# ARCHITECTURE: Logic / Schema
#
# Defines valid configuration states and their requirements/constraints.
# Implements "Fail-Fast" logic to prevent invalid configurations from reaching
# the execution layer.
# -----------------------------------------------------------------------------

declare -A CONFIG_STATE_SCHEMA

# --- Schema Definitions ---
# Format: "key" → "requires:dependency|excludes:conflict|allows:feature"

# WiFi Modes
CONFIG_STATE_SCHEMA["wifi:ap"]="requires:iwd,wireless_iface|excludes:wifi:station,wifi:adhoc,wifi:p2p|allows:net:nat,net:dhcp_server,net:ipv6_pd"
CONFIG_STATE_SCHEMA["wifi:station"]="requires:iwd,wireless_iface|excludes:wifi:ap,wifi:adhoc|allows:net:dhcp_client,net:static"
CONFIG_STATE_SCHEMA["wifi:adhoc"]="requires:iwd,wireless_iface|excludes:wifi:ap,wifi:station|allows:net:static"
CONFIG_STATE_SCHEMA["wifi:p2p"]="requires:iwd,wireless_iface|excludes:wifi:ap|allows:net:static,net:dhcp_server"

# Network Features
CONFIG_STATE_SCHEMA["net:nat"]="requires:firewall_tool|excludes:iface:bridge_member|requires:net:static_or_gateway"
CONFIG_STATE_SCHEMA["net:dhcp_server"]="requires:net:static_or_gateway"
CONFIG_STATE_SCHEMA["iface:bridge_member"]="excludes:net:dhcp_client,net:static,net:nat"

# --- Helper Functions ---

# Description: Checks if a specific requirement is met by the system.
_check_requirement() {
    local req="$1"
    local context_iface="$2"

    case "$req" in
        iwd)
            if ! is_service_active "iwd"; then
                json_error "Service requirement failed: iwd is not active" "1" "Enable iwd via systemctl"
                return 1
            fi
            ;;
        wireless_iface)
            # Rough check: if context_iface is provided, check if it is wifi
            if [ -n "$context_iface" ]; then
                if [ ! -d "/sys/class/net/$context_iface/wireless" ] && [ ! -d "/sys/class/net/$context_iface/phy80211" ]; then
                    # Allow override if it looks like a virtual wifi interface (e.g. uap0)
                    if [[ "$context_iface" != uap* ]] && [[ "$context_iface" != wlan* ]] && [[ "$context_iface" != mlan* ]]; then
                         json_error "Interface '$context_iface' does not appear to be wireless" "1"
                         return 1
                    fi
                fi
            fi
            ;;
        firewall_tool)
            # Relies on detection from rxnm-constants or system check
            local tool=""
            if command -v iptables >/dev/null; then tool="iptables"; fi
            if command -v nft >/dev/null; then tool="nft"; fi
            if [ -z "$tool" ]; then
                json_error "NAT requested but no firewall tool (iptables/nft) found" "1"
                return 1
            fi
            ;;
        net:static_or_gateway)
            # This is a logical check usually validated by arg parsing, strictly satisfied here
            return 0
            ;;
        *)
            # Unknown requirement, warn but pass
            log_debug "Unknown schema requirement: $req"
            ;;
    esac
    return 0
}

# Description: Parses arguments to build a descriptor of the intended state.
# Arguments: Category, Action, Arguments...
build_config_descriptor() {
    local category="$1"
    local action="$2"
    shift 2
    local args=("$@")
    
    local states=()
    local iface=""

    # 1. Base Category/Action mapping
    case "$category" in
        wifi)
            case "$action" in
                connect) states+=("wifi:station") ;;
                ap)
                    # Safe array expansion for set -u
                    local subcmd="${args[0]:-}"
                    if [ "$subcmd" == "start" ]; then
                        states+=("wifi:ap")
                        # Check for NAT/Share
                        for arg in "${args[@]:-}"; do
                            if [[ "$arg" == "--share" ]]; then states+=("net:nat" "net:dhcp_server"); fi
                            if [[ "$arg" == "--interface" ]]; then
                                # Next arg is interface
                                local idx=0
                                for a in "${args[@]:-}"; do if [[ "$a" == "--interface" ]]; then iface="${args[$((idx+1))]:-}"; break; fi; ((idx++)); done
                            fi
                        done
                    fi
                    ;;
                p2p) states+=("wifi:p2p") ;;
            esac
            ;;
        interface)
            # Extract target interface if present
            # Safe array expansion for set -u
            local arg0="${args[0]:-}"
            if [[ -n "$arg0" ]] && [[ "$arg0" != -* ]]; then iface="$arg0"; fi
            
            case "$action" in
                set)
                    local subcmd=""
                    for arg in "${args[@]:-}"; do if [[ "$arg" != -* ]] && [ -z "$subcmd" ] && [ "$arg" != "$iface" ]; then subcmd="$arg"; fi; done
                    
                    if [ "$subcmd" == "dhcp" ]; then states+=("net:dhcp_client"); fi
                    if [ "$subcmd" == "static" ]; then states+=("net:static"); fi
                    ;;
            esac
            ;;
    esac

    # Return JSON-ish string for validation: "iface:wlan0|states:wifi:ap,net:nat"
    local state_str
    state_str=$(IFS=,; echo "${states[*]}")
    echo "iface:${iface}|states:${state_str}"
}

# Description: Validates the descriptor against the schema.
# Arguments: Descriptor String
validate_config_state() {
    local descriptor="$1"
    local iface_field="${descriptor%%|*}"
    local state_field="${descriptor#*|}"
    
    local iface="${iface_field#iface:}"
    local states_str="${state_field#states:}"
    
    # Split states
    IFS=',' read -ra STATES <<< "$states_str"
    
    for state in "${STATES[@]}"; do
        [ -z "$state" ] && continue
        
        local rules="${CONFIG_STATE_SCHEMA[$state]}"
        if [ -z "$rules" ]; then continue; fi
        
        # Parse Rules: requires:A,B|excludes:C|allows:D
        IFS='|' read -ra RULE_GROUPS <<< "$rules"
        for group in "${RULE_GROUPS[@]}"; do
            local type="${group%%:*}"
            local list="${group#*:}"
            IFS=',' read -ra ITEMS <<< "$list"
            
            case "$type" in
                requires)
                    for req in "${ITEMS[@]}"; do
                        if ! _check_requirement "$req" "$iface"; then return 1; fi
                    done
                    ;;
                excludes)
                    # Check if any excluded state is currently active on the interface?
                    # For now, we assume this is a 'intent' validation.
                    # Complex state conflict checking (e.g. is it ALREADY a bridge member) 
                    # requires querying current state, which we do via sysfs/networkd.
                    for excl in "${ITEMS[@]}"; do
                        if [[ "$excl" == "iface:bridge_member" ]]; then
                            if [ -n "$iface" ] && [ -e "/sys/class/net/$iface/brport" ]; then
                                json_error "Conflict: Interface '$iface' is a bridge member. Cannot apply '$state'." "1"
                                return 1
                            fi
                        fi
                    done
                    ;;
            esac
        done
    done
    
    return 0
}

# Description: Basic JSON structure validation for stdin input.
# Arguments: $1 = JSON String
validate_json_input() {
    local json="$1"
    if [ -z "$json" ]; then
        json_error "Empty input received on stdin" "1"
        return 1
    fi
    
    # Check for basic JSON validity using jq if available
    if command -v "$JQ_BIN" >/dev/null; then
        if ! echo "$json" | "$JQ_BIN" . >/dev/null 2>&1; then
            json_error "Invalid JSON format" "1" "Ensure JSON is well-formed"
            return 1
        fi
        
        # Check required field: category
        local cat
        cat=$(echo "$json" | "$JQ_BIN" -r '.category // empty')
        if [ -z "$cat" ]; then
            json_error "Missing required field: category" "1"
            return 1
        fi
    fi
    return 0
}
