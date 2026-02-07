# ==============================================================================
# VIRTUAL & CONTAINER INTERFACES (VRF, MACVLAN, IPVLAN, VETH, BOND, VLAN)
# ==============================================================================

# --- TASKS ---

_task_create_vrf() {
    local name="$1"
    local table="$2"
    
    ensure_dirs
    local netdev_file="${STORAGE_NET_DIR}/60-vrf-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=vrf\n[VRF]\nTable=${table}\n"
    
    secure_write "$netdev_file" "$netdev_content" "644"
    
    # VRF interface itself needs to be up to function
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
    # Arguments: iface ssid dhcp desc addr gw dns bridge vlan domains mac routes mdns llmnr bond metric vrf
    local content
    content=$(build_network_config "$iface" "" "no" "VRF Member" "" "" "" "" "" "" "" "" "no" "no" "" "" "$vrf")
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
    
    # Bind to parent network file with specific lock to prevent race conditions
    local parent_cfg="${STORAGE_NET_DIR}/75-config-${parent}.network"
    local lock_file="${RUN_DIR}/${parent}.cfg.lock"
    local lock_fd
    
    exec {lock_fd}>"$lock_file" || { log_error "Cannot open lock file"; return 1; }
    if ! flock -w 5 "$lock_fd"; then log_error "Timeout waiting for config lock"; exec {lock_fd}>&-; return 1; fi

    if [ -f "$parent_cfg" ]; then
        if ! grep -q "MACVLAN=${name}" "$parent_cfg"; then
            # Safe Read-Modify-Write
            local current_content
            current_content=$(cat "$parent_cfg")
            if [[ "$current_content" == *"[Network]"* ]]; then
                 local new_content
                 new_content=$(echo "$current_content" | sed "/\[Network\]/a MACVLAN=${name}")
                 secure_write "$parent_cfg" "$new_content" "644"
            else
                 # Append block
                 printf "\n[Network]\nMACVLAN=%s\n" "$name" >> "$parent_cfg"
            fi
        fi
    else
        local content
        content=$(build_network_config "$parent" "" "yes" "Parent for MACVLAN ${name}" "" "" "" "" "" "" "" "" "yes" "yes")
        # Inject MACVLAN directive
        content="${content/\[Network\]/[Network]\nMACVLAN=${name}}"
        secure_write "$parent_cfg" "$content" "644"
    fi
    
    flock -u "$lock_fd"
    exec {lock_fd}>&-
    
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
    
    # Bind to parent network file with specific lock
    local parent_cfg="${STORAGE_NET_DIR}/75-config-${parent}.network"
    local lock_file="${RUN_DIR}/${parent}.cfg.lock"
    local lock_fd
    
    exec {lock_fd}>"$lock_file" || { log_error "Cannot open lock file"; return 1; }
    if ! flock -w 5 "$lock_fd"; then log_error "Timeout waiting for config lock"; exec {lock_fd}>&-; return 1; fi

    if [ -f "$parent_cfg" ]; then
        if ! grep -q "IPVLAN=${name}" "$parent_cfg"; then
            local current_content
            current_content=$(cat "$parent_cfg")
            if [[ "$current_content" == *"[Network]"* ]]; then
                 local new_content
                 new_content=$(echo "$current_content" | sed "/\[Network\]/a IPVLAN=${name}")
                 secure_write "$parent_cfg" "$new_content" "644"
            else
                 printf "\n[Network]\nIPVLAN=%s\n" "$name" >> "$parent_cfg"
            fi
        fi
    else
        local content
        content=$(build_network_config "$parent" "" "yes" "Parent for IPVLAN ${name}" "" "" "" "" "" "" "" "" "yes" "yes")
        content="${content/\[Network\]/[Network]\nIPVLAN=${name}}"
        secure_write "$parent_cfg" "$content" "644"
    fi
    
    flock -u "$lock_fd"
    exec {lock_fd}>&-
    
    reload_networkd
}

_task_create_veth() {
    local name="$1"
    local peer="$2"
    
    ensure_dirs
    local netdev_file="${STORAGE_NET_DIR}/60-veth-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=veth\n[Peer]\nName=${peer}\n"
    
    secure_write "$netdev_file" "$netdev_content" "644"
    
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
    content=$(build_network_config "$name" "" "yes" "Bond Interface ($mode)" "" "" "" "" "" "" "" "" "yes" "yes")
    secure_write "$network_file" "$content" "644"
    
    reload_networkd
}

_task_set_bond_slave() {
    local iface="$1"
    local bond="$2"
    
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local content
    content=$(build_network_config "$iface" "" "no" "Bond Slave" "" "" "" "" "" "" "" "" "no" "no" "$bond")
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
    
    local parent_cfg="${STORAGE_NET_DIR}/75-config-${parent}.network"
    if [ -f "$parent_cfg" ]; then
        if ! grep -q "VLAN=${name}" "$parent_cfg"; then
            local current_content
            current_content=$(cat "$parent_cfg")
             if [[ "$current_content" == *"[Network]"* ]]; then
                 local new_content
                 new_content=$(echo "$current_content" | sed "/\[Network\]/a VLAN=${name}")
                 secure_write "$parent_cfg" "$new_content" "644"
            else
                printf "\n[Network]\nVLAN=%s\n" "$name" >> "$parent_cfg"
            fi
        fi
    else
        local content
        # Fix: Arguments order (VLAN is $9, not $8)
        content=$(build_network_config "$parent" "" "yes" "Parent for VLAN ${name}" "" "" "" "" "$name" "" "" "" "yes" "yes")
        secure_write "$parent_cfg" "$content" "644"
    fi
}

# --- ACTIONS ---

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
    
    # We use a dedicated config lock in the task, but we still lock the interface operations
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
