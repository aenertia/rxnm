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
# Hidden from POSIX parser via eval
if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
    eval 'declare -A TEMPLATE_CACHE'
fi

# Description: Parses a .network file to extract key matching/config data.
# Arguments: $1 = File Path
# Returns: JSON string with metadata
parse_template_metadata() {
    local file="$1"
    if [ ! -f "$file" ]; then echo "{}"; return; fi

    # Use grep to quickly extract relevant lines without cat
    local match_name
    match_name=$(grep -E "^Name=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local match_type
    match_type=$(grep -E "^Type=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local wlan_type
    wlan_type=$(grep -E "^WLANInterfaceType=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local desc
    desc=$(grep -E "^Description=" "$file" | head -n1 | cut -d= -f2)
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
            --arg desc "$desc" \
            --arg masq "$ip_masq" \
            --arg dhcp "$dhcp" \
            '{name: $name, type: $type, wlan_type: $wlan, description: $desc, masquerade: $masq, dhcp: $dhcp}')
    else
        # POSIX string fallback when JQ is missing
        local s_name; s_name=$(printf '%s' "$match_name" | sed 's/"/\\"/g')
        local s_type; s_type=$(printf '%s' "$match_type" | sed 's/"/\\"/g')
        local s_wlan; s_wlan=$(printf '%s' "$wlan_type" | sed 's/"/\\"/g')
        local s_desc; s_desc=$(printf '%s' "$desc" | sed 's/"/\\"/g')
        local s_masq; s_masq=$(printf '%s' "$ip_masq" | sed 's/"/\\"/g')
        local s_dhcp; s_dhcp=$(printf '%s' "$dhcp" | sed 's/"/\\"/g')
        meta=$(printf '{"name":"%s","type":"%s","wlan_type":"%s","description":"%s","masquerade":"%s","dhcp":"%s"}' \
            "$s_name" "$s_type" "$s_wlan" "$s_desc" "$s_masq" "$s_dhcp")
    fi
        
    # Actually populate the cache
    if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ] && [ -n "$file" ]; then
        # Store as a compact single-line value; the cache key is the file path
        eval 'TEMPLATE_CACHE["'"$file"'"]="'"$(printf '%s' "$meta" | tr '\n' '\035')"'"'
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
        
        # Iterate files using POSIX globbing
        for f in "$path"/*.network; do
            [ ! -f "$f" ] && continue
            local fname="${f##*/}"
            
            # Parse metadata
            local meta=""
            if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
                eval 'meta="${TEMPLATE_CACHE['"\"$f\""']:-}"'
                # Restore newlines if cached
                [ -n "$meta" ] && meta=$(printf '%s' "$meta" | tr '\035' '\n')
            fi
            [ -z "$meta" ] && meta=$(parse_template_metadata "$f")
            
            local match_pattern
            if [ "${RXNM_HAS_JQ:-false}" = "true" ]; then
                match_pattern=$(echo "$meta" | "$JQ_BIN" -r '.name')
                wlan_type=$(echo "$meta" | "$JQ_BIN" -r '.wlan_type')
            else
                match_pattern=$(printf '%s' "$meta" | grep -o '"name":"[^"]*"' | sed 's/"name":"\([^"]*\)"/\1/')
                wlan_type=$(printf '%s' "$meta" | grep -o '"wlan_type":"[^"]*"' | sed 's/"wlan_type":"\([^"]*\)"/\1/')
            fi
            
            # Pattern matching via case for POSIX compatibility
            # shellcheck disable=SC2254
            # We intentionally leave $match_pattern unquoted because systemd
            # templates use glob patterns (e.g. wlan*) in the Name= field.
            case "$iface" in
                $match_pattern)
                    # Conflict logic:
                    local is_conflict="false"
                    
                    if [ "$intent_role" = "ap" ]; then
                        # If we want AP, anything station-like is a conflict
                        if [ "$wlan_type" = "station" ] || [ "$wlan_type" = "null" ] || [ -z "$wlan_type" ]; then
                            # Assume default is station if not specified for wlan type
                            is_conflict="true"
                        fi
                    elif [ "$intent_role" = "station" ]; then
                        # If we want Station, anything AP-like is a conflict
                        if [ "$wlan_type" = "ap" ] || [ "${wlan_type#p2p}" != "$wlan_type" ]; then
                            is_conflict="true"
                        fi
                    fi
                    
                    if [ "$is_conflict" = "true" ]; then
                        conflict_list="${conflict_list}${fname} "
                    fi
                    ;;
            esac
        done
    done
    
    echo "$conflict_list"
}

# Description: Masks a system template in the ephemeral runtime directory.
# Arguments: $1 = Filename (e.g. 80-wifi-station.network)
mask_system_template() {
    local fname="$1"
    [ -z "$fname" ] && return
    
    local link_target="${EPHEMERAL_NET_DIR}/${fname}"
    
    # Check if already masked
    if [ -L "$link_target" ]; then
        local target
        target=$(readlink "$link_target")
        if [ "$target" = "/dev/null" ]; then
            return
        fi
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
        local target
        target=$(readlink "$link_target")
        if [ "$target" = "/dev/null" ]; then
            log_info "Unmasking template: $fname"
            rm -f "$link_target"
        fi
    fi
}
