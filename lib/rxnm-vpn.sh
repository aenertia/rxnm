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
    local netdev_content
    netdev_content=$(printf '[NetDev]\nName=%s\nKind=wireguard\n\n[WireGuard]\nPrivateKey=%s\n' "$name" "$priv")

    local network_file="${STORAGE_NET_DIR}/90-${name}.network"
    local network_content
    network_content=$(printf '[Match]\nName=%s\n\n[Network]\nAddress=%s\n' "$name" "$addr")

    [ -n "$dns" ] && network_content=$(printf '%s\nDNS=%s' "$network_content" "$dns")

    [ -z "$ips" ] && ips="0.0.0.0/0"
    network_content=$(printf '%s\n\n[WireGuardPeer]\nPublicKey=%s\nEndpoint=%s\nAllowedIPs=%s\nPersistentKeepalive=25\n' "$network_content" "$peer" "$endp" "$ips")

    # Prevent credential leak in logs
    { set +x; } 2>/dev/null
    secure_write "$netdev_file" "$netdev_content" "600"
    # Harden WireGuard network config permissions (contains peer keys/endpoints)
    secure_write "$network_file" "$network_content" "600"
    set -x 2>/dev/null
    
    reload_networkd
}

_task_create_tuntap() {
    local name="$1"
    local kind="$2" # tun or tap
    local user="$3"
    local group="$4"
    
    ensure_dirs
    local netdev_file="${STORAGE_NET_DIR}/60-${kind}-${name}.netdev"
    # To uppercase kind: using awk since ${var^} is Bash
    local kind_upper
    kind_upper=$(echo "$kind" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')
    local netdev_content
    netdev_content=$(printf '[NetDev]\nName=%s\nKind=%s\n\n[%s]\n' "$name" "$kind" "$kind_upper")

    [ -n "$user" ] && netdev_content=$(printf '%sUser=%s\n' "$netdev_content" "$user")
    [ -n "$group" ] && netdev_content=$(printf '%sGroup=%s\n' "$netdev_content" "$group")

    # Enable packet info by default for better compatibility with some daemons
    netdev_content=$(printf '%sPacketInfo=yes\n' "$netdev_content")

    secure_write "$netdev_file" "$netdev_content" "644"

    # Ensure networkd manages the link status even if IP is handled externally
    local network_file="${STORAGE_NET_DIR}/75-config-${name}.network"
    local content
    content=$(printf '[Match]\nName=%s\n\n[Network]\nLinkLocalAddressing=no\nKeepConfiguration=yes\n' "$name")
    secure_write "$network_file" "$content" "644"
    
    reload_networkd
}

_task_delete_vpn() {
    local name="$1"
    local found="false"
    
    # Remove WireGuard files
    if [ -f "${STORAGE_NET_DIR}/90-${name}.netdev" ]; then
        rm -f "${STORAGE_NET_DIR}/90-${name}.netdev"
        found="true"
    fi
    if [ -f "${STORAGE_NET_DIR}/90-${name}.network" ]; then
        rm -f "${STORAGE_NET_DIR}/90-${name}.network"
        found="true"
    fi
    
    # Remove Tun/Tap files
    # POSIX loop
    for kind in tun tap; do
        if [ -f "${STORAGE_NET_DIR}/60-${kind}-${name}.netdev" ]; then
            rm -f "${STORAGE_NET_DIR}/60-${kind}-${name}.netdev"
            found="true"
        fi
    done
    
    # Cleanup generic configs
    if [ -f "${STORAGE_NET_DIR}/75-config-${name}.network" ]; then
        rm -f "${STORAGE_NET_DIR}/75-config-${name}.network"
    fi
    
    if [ "$found" = "true" ]; then
        reload_networkd
    else
        return 1
    fi
}

# --- ACTIONS ---

action_connect_wireguard() {
    local name="$1"; local priv="$2"; local peer="$3"; local endp="$4"; local ips="$5"; local addr="$6"; local dns="$7"
    
    ! validate_interface_name "$name" && { json_error "Invalid interface name"; return 1; }
    
    if [ -z "$name" ] || [ -z "$priv" ] || [ -z "$peer" ] || [ -z "$endp" ] || [ -z "$addr" ]; then
        json_error "Missing WireGuard args"
        return 1
    fi

    with_iface_lock "$name" _task_connect_wireguard "$name" "$priv" "$peer" "$endp" "$ips" "$addr" "$dns"

    json_success '{"type": "wireguard", "iface": "'"$name"'", "status": "connected"}'
}

action_disconnect_wireguard() {
    local name="$1"
    ! validate_interface_name "$name" && { json_error "Invalid interface name"; return 1; }
    
    # WireGuard in this context is stateless config, so disconnect = delete config
    confirm_action "Disconnect and remove VPN interface '$name'?" "$FORCE_ACTION"
    
    if with_iface_lock "$name" _task_delete_vpn "$name"; then
        json_success '{"action": "disconnected", "iface": "'"$name"'"}'
    else
        json_error "VPN interface configuration not found"
    fi
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

action_delete_vpn() {
    local name="$1"
    ! validate_interface_name "$name" && { json_error "Invalid interface name"; return 1; }
    
    confirm_action "Delete VPN interface '$name'?" "$FORCE_ACTION"
    
    if with_iface_lock "$name" _task_delete_vpn "$name"; then
        json_success '{"action": "deleted", "iface": "'"$name"'"}'
    else
        json_error "VPN interface configuration not found"
    fi
}
