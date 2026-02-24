# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-templates.sh
# PURPOSE: Systemd Networkd Template Management & Conflict Resolution
# ARCHITECTURE: Logic / Templates
#
# Handles the detection and masking of vendor-supplied network templates that
# might conflict with RXNM's runtime configurations.
# Refactored for strict POSIX compatibility (dash/ash/busybox).
# -----------------------------------------------------------------------------

# Cache for template metadata to avoid re-parsing on every call
# MAX_CACHE_SIZE prevents memory bloat in long-lived sessions (e.g. roaming daemon)
_TEMPLATE_CACHE_COUNT=0
_MAX_TEMPLATE_CACHE=50

if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
    eval 'declare -A TEMPLATE_CACHE'
fi

# Description: Parses a .network file to extract key matching/config data.
# Note: Key extraction is aligned with networkd-match-gperf and networkd-network-gperf.
# Arguments: $1 = File Path
# Returns: JSON string with metadata
parse_template_metadata() {
    local file="$1"
    if [ ! -f "$file" ]; then echo "{}"; return; fi

    # Use grep to quickly extract relevant lines without cat
    # Aligned with systemd networkd gperf stanzas: [Match] and [Network]
    local match_name
    match_name=$(grep -E "^Name=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local match_type
    match_type=$(grep -E "^Type=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local wlan_type
    wlan_type=$(grep -E "^WLANInterfaceType=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local ssid
    ssid=$(grep -E "^SSID=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local ip_masq
    ip_masq=$(grep -E "^IPMasquerade=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local dhcp
    dhcp=$(grep -E "^DHCP=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')

    # Construct simple JSON object
    local meta
    if [ "${RXNM_HAS_JQ:-false}" = "true" ]; then
        meta=$("$JQ_BIN" -n \
            --arg name "$match_name" \
            --arg type "$match_type" \
            --arg wlan "$wlan_type" \
            --arg ssid "$ssid" \
            --arg masq "$ip_masq" \
            --arg dhcp "$dhcp" \
            '{name: $name, type: $type, wlan_type: $wlan, ssid: $ssid, masquerade: $masq, dhcp: $dhcp}')
    else
        # POSIX string fallback when JQ is missing
        local s_name; s_name=$(printf '%s' "$match_name" | sed 's/"/\\"/g')
        local s_type; s_type=$(printf '%s' "$match_type" | sed 's/"/\\"/g')
        local s_wlan; s_wlan=$(printf '%s' "$wlan_type" | sed 's/"/\\"/g')
        local s_ssid; s_ssid=$(printf '%s' "$ssid" | sed 's/"/\\"/g')
        local s_masq; s_masq=$(printf '%s' "$ip_masq" | sed 's/"/\\"/g')
        local s_dhcp; s_dhcp=$(printf '%s' "$dhcp" | sed 's/"/\\"/g')
        meta=$(printf '{"name":"%s","type":"%s","wlan_type":"%s","ssid":"%s","masquerade":"%s","dhcp":"%s"}' \
            "$s_name" "$s_type" "$s_wlan" "$s_ssid" "$s_masq" "$s_dhcp")
    fi
        
    # Populates the cache with a size guard to protect low-RAM handhelds
    if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ] && [ -n "$file" ]; then
        if [ "$_TEMPLATE_CACHE_COUNT" -lt "$_MAX_TEMPLATE_CACHE" ]; then
            eval 'TEMPLATE_CACHE["'"$file"'"]="'"$(printf '%s' "$meta" | tr '\n' '\035')"'"'
            _TEMPLATE_CACHE_COUNT=$((_TEMPLATE_CACHE_COUNT + 1))
        fi
    fi
    
    echo "$meta"
}

# Description: Identifies templates that conflict with a specific intent.
# Arguments: $1 = Interface Name, $2 = Intent JSON (e.g. {role: "ap"})
build_template_conflict_map() {
    local iface="$1"
    local intent_role="$2" # e.g. "ap", "station", "p2p"
    
    local conflict_list=""
    local search_paths="/usr/lib/systemd/network /etc/systemd/network"
    
    for path in $search_paths; do
        [ ! -d "$path" ] && continue
        
        for f in "$path"/*.network; do
            [ ! -f "$f" ] && continue
            local fname="${f##*/}"
            
            # --- FAST-PATH 1: PROTECT NON-WIRELESS LINKS (USB/Ethernet) ---
            # Handhelds use USB Gadget or Ethernet for ROM transfers.
            # We skip evaluation if the file isn't explicitly a wireless template.
            # Checked against validated networkd gperf Match/Network keys.
            if ! grep -qE "Type=wlan|WLANInterfaceType=|SSID=|Name=.*(wlan|mlan|p2p)" "$f" 2>/dev/null; then
                continue
            fi

            # --- FAST-PATH 2: NAME PATTERN MISMATCH ---
            local is_match="false"
            if grep -qFx "Name=$iface" "$f" 2>/dev/null; then
                is_match="true"
            else
                case "$iface" in
                    wlan*) grep -qF "wlan*" "$f" 2>/dev/null && is_match="true" ;;
                    mlan*) grep -qF "mlan*" "$f" 2>/dev/null && is_match="true" ;;
                    p2p*)  grep -qF "p2p*" "$f" 2>/dev/null && is_match="true" ;;
                esac
            fi
            
            [ "$is_match" = "false" ] && continue
            
            # Metadata Analysis
            local meta=""
            if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
                eval 'meta="${TEMPLATE_CACHE['"\"$f\""']:-}"'
                [ -n "$meta" ] && meta=$(printf '%s' "$meta" | tr '\035' '\n')
            fi
            [ -z "$meta" ] && meta=$(parse_template_metadata "$f")
            
            local wlan_type=""
            if [ "${RXNM_HAS_JQ:-false}" = "true" ]; then
                wlan_type=$(echo "$meta" | "$JQ_BIN" -r '.wlan_type')
            else
                wlan_type=$(printf '%s' "$meta" | grep -o '"wlan_type":"[^"]*"' | sed 's/"wlan_type":"\([^"]*\)"/\1/')
            fi
            
            # Conflict logic (Optimized for Handhelds):
            local is_conflict="false"
            
            if [ "$intent_role" = "ap" ]; then
                # Intent: Start AP. 
                # Conflict: Anything explicitly set as Station mode.
                # Templates with wlan_type=null/empty (generic DHCP) are ignored if they 
                # aren't explicitly marked as Type=wlan (protected via Fast-path 1).
                if [ "$wlan_type" = "station" ]; then
                    is_conflict="true"
                fi
            elif [ "$intent_role" = "station" ]; then
                # Intent: Return to Client mode.
                # Conflict: Any template explicitly forcing AP or Peer roles.
                if [ "$wlan_type" = "ap" ] || [ "${wlan_type#p2p-go}" != "$wlan_type" ]; then
                    is_conflict="true"
                fi
            fi
            
            if [ "$is_conflict" = "true" ]; then
                conflict_list="${conflict_list}${fname} "
            fi
        done
    done
    
    echo "$conflict_list"
}

# Description: Masks a system template in the ephemeral runtime directory.
mask_system_template() {
    local fname="$1"
    [ -z "$fname" ] && return
    
    local link_target="${EPHEMERAL_NET_DIR}/${fname}"
    if [ -L "$link_target" ]; then
        [ "$(readlink "$link_target")" = "/dev/null" ] && return
    fi
    
    log_info "Masking conflicting template: $fname"
    ln -sf /dev/null "$link_target"
}

# Description: Unmasks a system template.
unmask_system_template() {
    local fname="$1"
    [ -z "$fname" ] && return
    
    local link_target="${EPHEMERAL_NET_DIR}/${fname}"
    if [ -L "$link_target" ]; then
        if [ "$(readlink "$link_target")" = "/dev/null" ]; then
            log_info "Unmasking template: $fname"
            rm -f "$link_target"
        fi
    fi
}
