# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-config-schema.sh
# PURPOSE: Declarative State Validation
# ARCHITECTURE: Logic / Schema
#
# Defines valid configuration states and their requirements/constraints.
# Refactored for 100% POSIX compliance to ensure intent validation works
# even in strict Ash/Dash environments without Bash associative arrays.
# -----------------------------------------------------------------------------

# --- Schema Definitions ---
# Format: "requires:dependency|excludes:conflict|allows:feature"
_get_schema_rules() {
    case "$1" in
        "wifi:ap") echo "requires:iwd,wireless_iface|excludes:wifi:station,wifi:adhoc,wifi:p2p|allows:net:nat,net:dhcp_server,net:ipv6_pd" ;;
        "wifi:station") echo "requires:iwd,wireless_iface|excludes:wifi:ap,wifi:adhoc|allows:net:dhcp_client,net:static" ;;
        "wifi:adhoc") echo "requires:iwd,wireless_iface|excludes:wifi:ap,wifi:station|allows:net:static" ;;
        "wifi:p2p") echo "requires:iwd,wireless_iface|excludes:wifi:ap|allows:net:static,net:dhcp_server" ;;
        "net:nat") echo "requires:firewall_tool|excludes:iface:bridge_member|requires:net:static_or_gateway" ;;
        "net:dhcp_server") echo "requires:net:static_or_gateway" ;;
        "iface:bridge_member") echo "excludes:net:dhcp_client,net:static,net:nat" ;;
        *) echo "" ;;
    esac
}

# --- Helper Functions ---

# Description: Checks if a specific requirement is met by the system.
_check_requirement() {
    local req="$1"
    local context_iface="$2"
    local context_states="$3"

    case "$req" in
        iwd)
            if ! is_service_active "iwd"; then
                json_error "Service requirement failed: iwd is not active" "1" "Enable iwd via systemctl"
                return 1
            fi
            ;;
        wireless_iface)
            if [ -n "$context_iface" ]; then
                if [ ! -d "/sys/class/net/$context_iface/wireless" ] && [ ! -d "/sys/class/net/$context_iface/phy80211" ]; then
                    # Allow override if it looks like a virtual wifi interface (e.g. uap0)
                    case "$context_iface" in
                        uap*|wlan*|mlan*) ;;
                        *)
                             json_error "Interface '$context_iface' does not appear to be wireless" "1"
                             return 1
                             ;;
                    esac
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
            # Validates that the requested configuration includes a static IP or implies a gateway (like AP mode)
            case ",${context_states}," in
                *,net:static,*|*,wifi:ap,*)
                    return 0
                    ;;
                *)
                    json_error "Requirement failed: This feature requires a Static IP or Gateway mode." "1" "Configure a static IP or use AP mode."
                    return 1
                    ;;
            esac
            ;;
        *)
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
    
    local states=""
    local iface=""

    # 1. Base Category/Action mapping
    case "$category" in
        wifi)
            case "$action" in
                connect) states="wifi:station" ;;
                ap)
                    local subcmd="${1:-}"
                    if [ "$subcmd" = "start" ]; then
                        states="wifi:ap"
                        local prev=""
                        for arg in "$@"; do
                            if [ "$arg" = "--share" ]; then states="${states:+${states},}net:nat,net:dhcp_server"; fi
                            if [ "$prev" = "--interface" ]; then iface="$arg"; fi
                            prev="$arg"
                        done
                    fi
                    ;;
                p2p) states="wifi:p2p" ;;
            esac
            ;;
        interface)
            local arg0="${1:-}"
            if [ -n "$arg0" ] && case "$arg0" in -*) false;; *) true;; esac; then
                iface="$arg0"
            fi
            
            case "$action" in
                set)
                    local subcmd=""
                    for arg in "$@"; do
                        if case "$arg" in -*) false;; *) true;; esac && [ -z "$subcmd" ] && [ "$arg" != "$iface" ]; then
                            subcmd="$arg"
                        fi
                    done
                    
                    if [ "$subcmd" = "dhcp" ]; then states="${states:+${states},}net:dhcp_client"; fi
                    if [ "$subcmd" = "static" ]; then states="${states:+${states},}net:static"; fi
                    ;;
            esac
            ;;
    esac

    # Return JSON-ish string for validation: "iface:wlan0|states:wifi:ap,net:nat"
    echo "iface:${iface}|states:${states}"
}

# Description: Validates the descriptor against the schema.
# Arguments: Descriptor String
validate_config_state() {
    local descriptor="$1"
    local iface_field="${descriptor%%|*}"
    local state_field="${descriptor#*|}"
    
    local iface="${iface_field#iface:}"
    local states_str="${state_field#states:}"
    
    set -f
    local _old_ifs="$IFS"
    IFS=","
    for state in $states_str; do
        [ -z "$state" ] && continue
        
        local rules
        rules=$(_get_schema_rules "$state")
        [ -z "$rules" ] && continue
        
        IFS="|"
        for group in $rules; do
            [ -z "$group" ] && continue
            local type="${group%%:*}"
            local list="${group#*:}"
            
            IFS=","
            for item in $list; do
                [ -z "$item" ] && continue
                
                case "$type" in
                    requires)
                        if ! _check_requirement "$item" "$iface" "$states_str"; then
                            IFS="$_old_ifs"; set +f; return 1
                        fi
                        ;;
                    excludes)
                        if [ "$item" = "iface:bridge_member" ]; then
                            if [ -n "$iface" ] && [ -e "/sys/class/net/$iface/brport" ]; then
                                json_error "Conflict: Interface '$iface' is a bridge member. Cannot apply '$state'." "1"
                                IFS="$_old_ifs"; set +f; return 1
                            fi
                        fi
                        ;;
                esac
            done
            IFS="|"
        done
        IFS=","
    done
    IFS="$_old_ifs"
    set +f
    
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
    
    if command -v "$JQ_BIN" >/dev/null; then
        if ! printf '%s' "$json" | "$JQ_BIN" . >/dev/null 2>&1; then
            json_error "Invalid JSON format" "1" "Ensure JSON is well-formed"
            return 1
        fi
        
        local cat
        cat=$(printf '%s' "$json" | "$JQ_BIN" -r '.category // empty')
        if [ -z "$cat" ]; then
            json_error "Missing required field: category" "1"
            return 1
        fi
    fi
    return 0
}
