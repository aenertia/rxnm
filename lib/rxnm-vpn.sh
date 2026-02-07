# ==============================================================================
# VPN INTERFACES (WireGuard, TUN, TAP)
# ==============================================================================

# --- TASKS ---

_task_connect_wireguard() {
    local name="$1"
    local priv="$2"
    local peer="$3"
    local endp="$4"
    local ips="$5"
    local addr="$6"
    local dns="$7"
    
    ensure_dirs
    local netdev_file="${STORAGE_NET_DIR}/90-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=wireguard\n\n[WireGuard]\nPrivateKey=${priv}\n"
    
    local network_file="${STORAGE_NET_DIR}/90-${name}.network"
    local network_content="[Match]\nName=${name}\n\n[Network]\nAddress=${addr}\n"
    
    [ -n "$dns" ] && network_content+="DNS=${dns}\n"
    
    network_content+="\n[WireGuardPeer]\nPublicKey=${peer}\nEndpoint=${endp}\n"
    [ -z "$ips" ] && ips="0.0.0.0/0"
    network_content+="AllowedIPs=${ips}\nPersistentKeepalive=25\n"

    secure_write "$netdev_file" "$netdev_content" "600"
    secure_write "$network_file" "$network_content" "644"
    
    reload_networkd
}

_task_create_tuntap() {
    local name="$1"
    local kind="$2" # tun or tap
    local user="$3"
    local group="$4"
    
    ensure_dirs
    local netdev_file="${STORAGE_NET_DIR}/60-${kind}-${name}.netdev"
    local netdev_content="[NetDev]\nName=${name}\nKind=${kind}\n\n[${kind^}]\n"
    
    [ -n "$user" ] && netdev_content+="User=${user}\n"
    [ -n "$group" ] && netdev_content+="Group=${group}\n"
    
    # Enable packet info by default for better compatibility with some daemons
    netdev_content+="PacketInfo=yes\n"

    secure_write "$netdev_file" "$netdev_content" "644"
    
    # Ensure networkd manages the link status even if IP is handled externally
    local network_file="${STORAGE_NET_DIR}/75-config-${name}.network"
    # Basic config to keep it up. Users can use 'rxnm interface set ...' to add IPs later.
    local content="[Match]\nName=${name}\n\n[Network]\nLinkLocalAddressing=no\nKeepConfiguration=yes\n"
    secure_write "$network_file" "$content" "644"
    
    reload_networkd
}

# --- ACTIONS ---

action_connect_wireguard() {
    local name="$1"; local priv="$2"; local peer="$3"; local endp="$4"; local ips="$5"; local addr="$6"; local dns="$7"
    
    ! validate_interface_name "$name" && { json_error "Invalid interface name"; return 1; }
    
    [ -z "$name" ] || [ -z "$priv" ] || [ -z "$peer" ] || [ -z "$endp" ] || [ -z "$addr" ] && \
        { json_error "Missing WireGuard args"; return 1; }

    with_iface_lock "$name" _task_connect_wireguard "$name" "$priv" "$peer" "$endp" "$ips" "$addr" "$dns"

    json_success '{"type": "wireguard", "iface": "'"$name"'"}'
}

action_create_tun() {
    local name="$1"; local user="$2"; local group="$3"
    ! validate_interface_name "$name" && { json_error "Invalid interface name"; return 1; }
    
    _task_create_tuntap "$name" "tun" "$user" "$group"
    json_success '{"type": "tun", "iface": "'"$name"'", "user": "'"${user:-root}"'", "group": "'"${group:-root}"'"}'
}

action_create_tap() {
    local name="$1"; local user="$2"; local group="$3"
    ! validate_interface_name "$name" && { json_error "Invalid interface name"; return 1; }
    
    _task_create_tuntap "$name" "tap" "$user" "$group"
    json_success '{"type": "tap", "iface": "'"$name"'", "user": "'"${user:-root}"'", "group": "'"${group:-root}"'"}'
}
