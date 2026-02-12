# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-templates.sh
# PURPOSE: Systemd Networkd Template Management & Conflict Resolution
# ARCHITECTURE: Logic / Templates
#
# Handles the detection and masking of vendor-supplied network templates that
# might conflict with RXNM's runtime configurations.
# -----------------------------------------------------------------------------

# Cache for template metadata to avoid re-parsing on every call
declare -A TEMPLATE_CACHE

# Description: Parses a .network file to extract key matching/config data.
# Arguments: $1 = File Path
# Returns: JSON string with metadata
parse_template_metadata() {
    local file="$1"
    if [ ! -f "$file" ]; then echo "{}"; return; fi

    # Use grep to quickly extract relevant lines without cat
    # Note: We look for the first occurrence. Networkd allows sections, 
    # but usually Match is at the top.
    local match_name=$(grep -E "^Name=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local match_type=$(grep -E "^Type=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local wlan_type=$(grep -E "^WLANInterfaceType=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local desc=$(grep -E "^Description=" "$file" | head -n1 | cut -d= -f2)
    local ip_masq=$(grep -E "^IPMasquerade=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')
    local dhcp=$(grep -E "^DHCP=" "$file" | head -n1 | cut -d= -f2 | tr -d ' "')

    # Construct simple JSON object
    "$JQ_BIN" -n \
        --arg name "$match_name" \
        --arg type "$match_type" \
        --arg wlan "$wlan_type" \
        --arg desc "$desc" \
        --arg masq "$ip_masq" \
        --arg dhcp "$dhcp" \
        '{name: $name, type: $type, wlan_type: $wlan, description: $desc, masquerade: $masq, dhcp: $dhcp}'
}

# Description: Identifies templates that conflict with a specific intent.
# Arguments: $1 = Interface Name, $2 = Intent JSON (e.g. {role: "ap"})
build_template_conflict_map() {
    local iface="$1"
    local intent_role="$2" # e.g. "ap", "station", "p2p"
    
    local conflict_list=()
    local search_paths=("/usr/lib/systemd/network" "/etc/systemd/network")
    
    for path in "${search_paths[@]}"; do
        [ ! -d "$path" ] && continue
        
        # Iterate files
        for f in "$path"/*.network; do
            [ ! -f "$f" ] && continue
            local fname=$(basename "$f")
            
            # Parse metadata
            local meta=$(parse_template_metadata "$f")
            local match_pattern=$(echo "$meta" | "$JQ_BIN" -r '.name')
            local wlan_type=$(echo "$meta" | "$JQ_BIN" -r '.wlan_type')
            
            # Check if template matches our interface via glob pattern
            # Note: This checks if the interface name fits the pattern in the file
            if [[ "$iface" == $match_pattern ]]; then
                # Conflict logic:
                local is_conflict="false"
                
                if [ "$intent_role" == "ap" ]; then
                    # If we want AP, anything station-like is a conflict
                    if [[ "$wlan_type" == "station" ]] || [[ "$wlan_type" == "null" ]] || [[ -z "$wlan_type" ]]; then
                        # Assume default is station if not specified for wlan type
                        is_conflict="true"
                    fi
                elif [ "$intent_role" == "station" ]; then
                    # If we want Station, anything AP-like is a conflict
                    if [[ "$wlan_type" == "ap" ]] || [[ "$wlan_type" == "p2p"* ]]; then
                        is_conflict="true"
                    fi
                fi
                
                if [ "$is_conflict" == "true" ]; then
                    conflict_list+=("$fname")
                fi
            fi
        done
    done
    
    echo "${conflict_list[@]}"
}

# Description: Masks a system template in the ephemeral runtime directory.
# Arguments: $1 = Filename (e.g. 80-wifi-station.network)
mask_system_template() {
    local fname="$1"
    [ -z "$fname" ] && return
    
    local link_target="${EPHEMERAL_NET_DIR}/${fname}"
    
    # Check if already masked
    if [ -L "$link_target" ] && [ "$(readlink "$link_target")" == "/dev/null" ]; then
        return
    fi
    
    log_info "Masking conflicting template: $fname"
    ln -sf /dev/null "$link_target"
}

# Description: Unmasks a system template.
unmask_system_template() {
    local fname="$1"
    [ -z "$fname" ] && return
    
    local link_target="${EPHEMERAL_NET_DIR}/${fname}"
    
    if [ -L "$link_target" ] && [ "$(readlink "$link_target")" == "/dev/null" ]; then
        log_info "Unmasking template: $fname"
        rm -f "$link_target"
    fi
}

# Description: Initialize cache (Placeholder for future optimization)
init_template_cache() {
    :
}
