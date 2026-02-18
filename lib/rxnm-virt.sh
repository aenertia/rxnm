# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-virt.sh
# PURPOSE: Advanced Virtual Interface Management
# ARCHITECTURE: Logic / Virtualization
#
# Handles creation of complex software-defined networking interfaces:
# VRF, VLAN, Bonds, MacVLAN, IPVLAN, and Veth pairs.
# -----------------------------------------------------------------------------

# --- Internal Tasks ---

_task_create_vrf() {
    local name="$1"
    local table="$2"
    ensure_dirs
    
    # Netdev definition
    local netdev_file="${STORAGE_NET_DIR}/60-vrf-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=vrf\n[VRF]\nTable=${table}\n"
    secure_write "$netdev_file" "$netdev_content" "644"
    
    # Config definition (VRF needs to be up to work)
    local network_file="${STORAGE_NET_DIR}/75-config-${name}.network"
    local content="[Match]\nName=${name}\n[Network]\nIPForwarding=yes\n"
    secure_write "$network_file" "$content" "644"
    
    reload_networkd
}

_task_set_vrf_member() {
    local iface="$1"
    local vrf="$2"
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local content
    
    # 1.0.0 Refactor: Use named parameters
    content=$(build_network_config \
        --match-name "$iface" \
        --dhcp "no" \
        --description "VRF Member" \
        --mdns "no" \
        --llmnr "no" \
        --vrf "$vrf")
        
    secure_write "$cfg_file" "$content" "644"
    reconfigure_iface "$iface"
    reconfigure_iface "$vrf"
}

_task_create_macvlan() {
    local name="$1"
    local parent="$2"
    local mode="${3:-bridge}"
    ensure_dirs
    
    local netdev_file="${STORAGE_NET_DIR}/60-macvlan-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=macvlan\n[MACVLAN]\nMode=${mode}\n"
    secure_write "$netdev_file" "$netdev_content" "644"
    
    # Update parent to acknowledge child (Critical for networkd)
    local parent_cfg="${STORAGE_NET_DIR}/75-config-${parent}.network"
    
    if [ -f "$parent_cfg" ]; then
        if [ -x "$RXNM_AGENT_BIN" ]; then
            "$RXNM_AGENT_BIN" --append-config "$parent_cfg" --line "MACVLAN=${name}"
        else
            if ! grep -q "MACVLAN=${name}" "$parent_cfg"; then
                # Fallback: Correctly handle appending to [Network] section
                if grep -q "\[Network\]" "$parent_cfg"; then
                    # Section exists, just append property
                    printf "MACVLAN=%s\n" "$name" >> "$parent_cfg"
                else
                    # Section missing, append header and property
                    printf "\n[Network]\nMACVLAN=%s\n" "$name" >> "$parent_cfg"
                fi
            fi
        fi
    else
        # Create minimal parent config if none exists
        local content
        # 1.0.0 Refactor: Use named parameters
        content=$(build_network_config \
            --match-name "$parent" \
            --dhcp "yes" \
            --description "Parent for MACVLAN ${name}" \
            --mdns "yes" \
            --llmnr "yes")
            
        content="${content/\[Network\]/[Network]\nMACVLAN=${name}}"
        secure_write "$parent_cfg" "$content" "644"
    fi
    
    reload_networkd
}

_task_create_ipvlan() {
    local name="$1"
    local parent="$2"
    local mode="${3:-L2}"
    ensure_dirs
    
    local netdev_file="${STORAGE_NET_DIR}/60-ipvlan-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=ipvlan\n[IPVLAN]\nMode=${mode}\n"
    secure_write "$netdev_file" "$netdev_content" "644"
    
    # Update parent logic (similar to MacVLAN)
    local parent_cfg="${STORAGE_NET_DIR}/75-config-${parent}.network"
    
    if [ -f "$parent_cfg" ]; then
        if [ -x "$RXNM_AGENT_BIN" ]; then
            "$RXNM_AGENT_BIN" --append-config "$parent_cfg" --line "IPVLAN=${name}"
        else
            if ! grep -q "IPVLAN=${name}" "$parent_cfg"; then
                 if grep -q "\[Network\]" "$parent_cfg"; then
                    printf "IPVLAN=%s\n" "$name" >> "$parent_cfg"
                 else
                    printf "\n[Network]\nIPVLAN=%s\n" "$name" >> "$parent_cfg"
                 fi
            fi
        fi
    else
        local content
        # 1.0.0 Refactor: Use named parameters
        content=$(build_network_config \
            --match-name "$parent" \
            --dhcp "yes" \
            --description "Parent for IPVLAN ${name}" \
            --mdns "yes" \
            --llmnr "yes")
            
        content="${content/\[Network\]/[Network]\nIPVLAN=${name}}"
        secure_write "$parent_cfg" "$content" "644"
    fi
    
    reload_networkd
}

_task_create_veth() {
    local name="$1"
    local peer="$2"
    ensure_dirs
    local netdev_file="${STORAGE_NET_DIR}/60-veth-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=veth\n[Peer]\nName=${peer}\n"
    secure_write "$netdev_file" "$netdev_content" "644"
    
    # Give them link-local configs by default
    local net_name="${STORAGE_NET_DIR}/75-config-${name}.network"
    local net_peer="${STORAGE_NET_DIR}/75-config-${peer}.network"
    secure_write "$net_name" "[Match]\nName=${name}\n[Network]\nLinkLocalAddressing=yes\n" "644"
    secure_write "$net_peer" "[Match]\nName=${peer}\n[Network]\nLinkLocalAddressing=yes\n" "644"
    
    reload_networkd
}

_task_create_bond() {
    local name="$1"
    local mode="${2:-active-backup}"
    ensure_dirs
    
    local netdev_file="${STORAGE_NET_DIR}/60-bond-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=bond\n[Bond]\nMode=${mode}\nMIIMonitorSec=100ms\n"
    
    if [ "$mode" == "802.3ad" ]; then
        netdev_content+="LACPTransmitRate=fast\nTransmitHashPolicy=layer2+3\n"
    fi
    secure_write "$netdev_file" "$netdev_content" "644"
    
    local network_file="${STORAGE_NET_DIR}/75-config-${name}.network"
    local content
    # 1.0.0 Refactor: Use named parameters
    content=$(build_network_config \
        --match-name "$name" \
        --dhcp "yes" \
        --description "Bond Interface ($mode)" \
        --mdns "yes" \
        --llmnr "yes")
        
    secure_write "$network_file" "$content" "644"
    reload_networkd
}

_task_set_bond_slave() {
    local iface="$1"
    local bond="$2"
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local content
    
    # 1.0.0 Refactor: Use named parameters
    content=$(build_network_config \
        --match-name "$iface" \
        --dhcp "no" \
        --description "Bond Slave" \
        --bond "$bond" \
        --mdns "no" \
        --llmnr "no")
        
    secure_write "$cfg_file" "$content" "644"
    reconfigure_iface "$iface"
    reconfigure_iface "$bond"
}

_task_create_vlan() {
    local parent="$1"
    local name="$2"
    local id="$3"
    ensure_dirs
    
    local netdev_file="${STORAGE_NET_DIR}/60-vlan-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=vlan\n[VLAN]\nId=${id}\n"
    secure_write "$netdev_file" "$netdev_content" "644"
    
    # Update parent to acknowledge VLAN
    local parent_cfg="${STORAGE_NET_DIR}/75-config-${parent}.network"
    if [ -f "$parent_cfg" ]; then
        if [ -x "$RXNM_AGENT_BIN" ]; then
            "$RXNM_AGENT_BIN" --append-config "$parent_cfg" --line "VLAN=${name}"
        else
            if ! grep -q "VLAN=${name}" "$parent_cfg"; then
                if grep -q "\[Network\]" "$parent_cfg"; then
                    printf "VLAN=%s\n" "$name" >> "$parent_cfg"
                else
                    printf "\n[Network]\nVLAN=%s\n" "$name" >> "$parent_cfg"
                fi
            fi
        fi
    else
        # Create minimal parent config if none exists
        local content
        # 1.0.0 Refactor: Use named parameters
        content=$(build_network_config \
            --match-name "$parent" \
            --dhcp "yes" \
            --description "Parent for VLAN ${name}" \
            --vlan "$name" \
            --mdns "yes" \
            --llmnr "yes")
            
        secure_write "$parent_cfg" "$content" "644"
    fi
}

# --- Public Actions ---

action_create_vrf() {
    local name="$1"
    local table="$2"
    ! validate_interface_name "$name" && { json_error "Invalid VRF name"; return 1; }
    [ -z "$table" ] && { json_error "Routing table ID required for VRF"; return 1; }
    if ! validate_integer "$table"; then json_error "Table ID must be a number"; return 1; fi
    
    _task_create_vrf "$name" "$table"
    json_success '{"type": "vrf", "iface": "'"$name"'", "table": '"$table"'}'
}

action_set_vrf_member() {
    local iface="$1"; local vrf="$2"
    ! validate_interface_name "$iface" && { json_error "Invalid interface"; return 1; }
    ! validate_interface_name "$vrf" && { json_error "Invalid VRF name"; return 1; }
    
    with_iface_lock "$iface" _task_set_vrf_member "$iface" "$vrf"
    json_success '{"action": "set_vrf_member", "iface": "'"$iface"'", "vrf": "'"$vrf"'"}'
}

action_create_macvlan() {
    local name="$1"; local parent="$2"; local mode="${3:-bridge}"
    ! validate_interface_name "$name" && { json_error "Invalid name"; return 1; }
    ! validate_interface_name "$parent" && { json_error "Invalid parent"; return 1; }
    
    with_iface_lock "$parent" _task_create_macvlan "$name" "$parent" "$mode"
    json_success '{"type": "macvlan", "iface": "'"$name"'", "parent": "'"$parent"'", "mode": "'"$mode"'"}'
}

action_create_ipvlan() {
    local name="$1"; local parent="$2"; local mode="${3:-L2}"
    ! validate_interface_name "$name" && { json_error "Invalid name"; return 1; }
    ! validate_interface_name "$parent" && { json_error "Invalid parent"; return 1; }
    
    with_iface_lock "$parent" _task_create_ipvlan "$name" "$parent" "$mode"
    json_success '{"type": "ipvlan", "iface": "'"$name"'", "parent": "'"$parent"'", "mode": "'"$mode"'"}'
}

action_create_veth() {
    local name="$1"; local peer="$2"
    ! validate_interface_name "$name" && { json_error "Invalid name"; return 1; }
    ! validate_interface_name "$peer" && { json_error "Invalid peer"; return 1; }
    
    _task_create_veth "$name" "$peer"
    json_success '{"type": "veth", "iface": "'"$name"'", "peer": "'"$peer"'"}'
}

action_create_bond() {
    local name="$1"
    local mode="$2"
    ! validate_interface_name "$name" && { json_error "Invalid bond name"; return 1; }
    
    _task_create_bond "$name" "$mode"
    json_success '{"type": "bond", "iface": "'"$name"'", "mode": "'"${mode:-active-backup}"'"}'
}

action_set_bond_slave() {
    local iface="$1"; local bond="$2"
    [ -z "$iface" ] || [ -z "$bond" ] && { json_error "Interface and Bond required"; return 1; }
    ! validate_interface_name "$iface" && { json_error "Invalid interface"; return 1; }
    
    with_iface_lock "$iface" _task_set_bond_slave "$iface" "$bond"
    json_success '{"action": "set_bond_slave", "iface": "'"$iface"'", "bond": "'"$bond"'"}'
}

action_create_vlan() {
    local parent="$1"; local name="$2"; local id="$3"
    ! validate_interface_name "$name" && { json_error "Invalid vlan name"; return 1; }
    ! validate_vlan_id "$id" && { json_error "Invalid VLAN ID (1-4094)"; return 1; }
    
    with_iface_lock "$parent" _task_create_vlan "$parent" "$name" "$id"
    reload_networkd
    json_success '{"type": "vlan", "iface": "'"$name"'", "id": '"$id"'}'
}
