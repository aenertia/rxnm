# ==============================================================================
# INTERFACE CONFIGURATION (VLAN, Bridge, WireGuard, Static, DHCP, Bonding)
# ==============================================================================

# --- TASKS ---

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
            if grep -q "\[Network\]" "$parent_cfg"; then
                sed -i "/\[Network\]/a VLAN=${name}" "$parent_cfg"
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

_task_set_member() {
    local iface="$1"
    local bridge="$2"
    
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local content
    content=$(build_network_config "$iface" "" "no" "Bridge Member" "" "" "" "$bridge" "" "" "" "" "no" "no")
    secure_write "$cfg_file" "$content" "644"
    reconfigure_iface "$iface"
    reconfigure_iface "$bridge"
}

_task_set_dhcp() {
    local iface="$1"
    local ssid="$2"
    local dns="$3"
    local domains="$4"
    local routes="$5"
    local mdns="$6"
    local llmnr="$7"
    
    rm -f "${STORAGE_NET_DIR}/75-static-${iface}.network" 2>/dev/null
    
    # Fix: Always ensure a file is written to satisfy persistence/test checks
    ensure_dirs
    set_network_cfg "$iface" "yes" "" "" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr"
    reconfigure_iface "$iface"
}

_task_set_static() {
    local iface="$1"
    local ip="$2"
    local gw="$3"
    local dns="$4"
    local ssid="$5"
    local domains="$6"
    local routes="$7"
    local mdns="$8"
    local llmnr="$9"
    
    ensure_dirs
    set_network_cfg "$iface" "no" "$ip" "$gw" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr"
    reconfigure_iface "$iface"
}

_task_set_link() {
    local iface="$1"
    local ipv4="$2"
    local ipv6="$3"
    
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local ll="yes"; local ra="yes"; local dhcp="yes"
    [[ "$ipv4" == "off" ]] && { dhcp="ipv6"; ll="ipv6"; }
    [[ "$ipv6" == "off" ]] && { dhcp="ipv4"; ra="no"; ll="ipv4"; }
    [[ "$ipv4" == "off" ]] && [[ "$ipv6" == "off" ]] && { dhcp="no"; ll="no"; ra="no"; }
    
    local content="[Match]\nName=${iface}\n\n[Network]\nDescription=Link Toggles\nDHCP=${dhcp}\nLinkLocalAddressing=${ll}\nIPv6AcceptRA=${ra}\n"
    secure_write "$cfg_file" "$content" "644"
    reconfigure_iface "$iface"
}

_task_set_proxy() {
    local iface="$1"
    local http="$2"
    local https="$3"
    local noproxy="$4"
    
    local target_file="$STORAGE_PROXY_GLOBAL"
    if [ -n "$iface" ]; then
        target_file="${STORAGE_NET_DIR}/proxy-${iface}.conf"
    fi
    
    if [ -z "$http" ] && [ -z "$https" ] && [ -z "$noproxy" ]; then
        [ -f "$target_file" ] && rm -f "$target_file"
    else
        local content="# Proxy Configuration\n"
        [ -n "$http" ] && content+="http_proxy=\"$http\"\nHTTP_PROXY=\"$http\"\n"
        [ -n "$https" ] && content+="https_proxy=\"$https\"\nHTTPS_PROXY=\"$https\"\n"
        [ -n "$noproxy" ] && content+="no_proxy=\"$noproxy\"\nNO_PROXY=\"$noproxy\"\n"
        secure_write "$target_file" "$content" "600"
    fi
}

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

set_network_cfg() {
    local iface=$1 dhcp=$2 ip=$3 gw=$4 dns=$5 ssid=$6 domains=$7 routes=$8 mdns=$9 llmnr=${10}
    local safe_ssid=""
    [ -n "$ssid" ] && safe_ssid=$(sanitize_ssid "$ssid")
    
    local cfg
    cfg=$(build_network_config "$iface" "$ssid" "$dhcp" "User Config" "$ip" "$gw" "$dns" "" "" "$domains" "" "$routes" "$mdns" "$llmnr")
    
    local filename="${STORAGE_NET_DIR}/75-config-${iface}"
    if [ -n "$safe_ssid" ]; then
        filename="${filename}-${safe_ssid}.network"
    else
        filename="${filename}.network"
    fi
    
    secure_write "$filename" "$cfg" 644
}

# --- ACTIONS ---

action_create_bridge() {
    local name="$1"
    ! validate_interface_name "$name" && { json_error "Invalid bridge name"; return 1; }
    
    ensure_dirs
    local netdev_file="${STORAGE_NET_DIR}/60-bridge-${name}.netdev"
    local content="[NetDev]\nName=${name}\nKind=bridge\n[Bridge]\nSTP=no\nMulticastSnooping=yes\n"
    
    secure_write "$netdev_file" "$content" "644"
    reload_networkd
    json_success '{"type": "bridge", "iface": "'"$name"'"}'
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
    
    with_iface_lock "$parent" _task_create_vlan "$parent" "$name" "$id"
    
    reload_networkd
    json_success '{"type": "vlan", "iface": "'"$name"'"}'
}

action_set_member() {
    local iface="$1"; local bridge="$2"
    ! validate_interface_name "$iface" && { json_error "Invalid interface"; return 1; }
    
    with_iface_lock "$iface" _task_set_member "$iface" "$bridge"
    json_success '{"action": "set_member", "iface": "'"$iface"'", "bridge": "'"$bridge"'"}'
}

action_delete_netdev() {
    local name="$1"
    ! validate_interface_name "$name" && { json_error "Invalid name"; return 1; }
    
    local found="false"
    for f in "${STORAGE_NET_DIR}/60-bridge-${name}.netdev" \
             "${STORAGE_NET_DIR}/60-vlan-${name}.netdev" \
             "${STORAGE_NET_DIR}/60-bond-${name}.netdev"; do
        if [ -f "$f" ]; then rm -f "$f"; found="true"; fi
    done
    
    if [ "$found" == "true" ]; then
        reload_networkd
        json_success '{"deleted": "'"$name"'"}'
    else
        json_error "Device configuration not found"
    fi
}

action_set_dhcp() {
    local iface="$1"; local ssid="$2"; local dns="$3"; local domains="$4"; local routes="$5"
    local mdns="${6:-yes}"; local llmnr="${7:-yes}"

    [ -z "$iface" ] && { log_error "Interface required"; return 1; }
    
    if [ -n "$dns" ] || [ -n "$domains" ] || [ -n "$routes" ]; then
        [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
        [ -n "$routes" ] && ! validate_routes "$routes" && { json_error "Invalid routes"; return 1; }
    fi

    with_iface_lock "$iface" _task_set_dhcp "$iface" "$ssid" "$dns" "$domains" "$routes" "$mdns" "$llmnr"
    json_success '{"mode": "dhcp", "iface": "'"$iface"'"}'
}

action_set_static() {
    local iface="$1"; local ip="$2"; local gw="$3"; local dns="$4"; local ssid="$5"; local domains="$6"; local routes="$7"
    local mdns="${8:-yes}"; local llmnr="${9:-yes}"

    [ -z "$iface" ] || [ -z "$ip" ] && { log_error "Interface and IP required"; return 1; }
    
    ! validate_ip "$ip" && { json_error "Invalid IP"; return 1; }
    [ -n "$gw" ] && ! validate_ip "$gw" && { json_error "Invalid Gateway"; return 1; }
    [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
    
    [[ "$ip" != *"/"* ]] && ip="${ip}/24"

    with_iface_lock "$iface" _task_set_static "$iface" "$ip" "$gw" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr"
        
    json_success '{"mode": "static", "iface": "'"$iface"'"}'
}

action_set_link() {
    local iface="$1"; local ipv4="$2"; local ipv6="$3"
    [ -z "$iface" ] && return 1
    
    with_iface_lock "$iface" _task_set_link "$iface" "$ipv4" "$ipv6"
        
    json_success '{"config": "updated", "iface": "'"$iface"'"}'
}

action_set_proxy() {
    local iface="$1"; local http="$2"; local https="$3"; local noproxy="$4"
    
    # Fix: Lock by interface or global
    with_iface_lock "${iface:-global_proxy}" _task_set_proxy "$iface" "$http" "$https" "$noproxy"
        
    json_success '{"action": "set_proxy"}'
}

action_connect_wireguard() {
    local name="$1"; local priv="$2"; local peer="$3"; local endp="$4"; local ips="$5"; local addr="$6"; local dns="$7"
    
    ! validate_interface_name "$name" && { json_error "Invalid interface name"; return 1; }
    
    [ -z "$name" ] || [ -z "$priv" ] || [ -z "$peer" ] || [ -z "$endp" ] || [ -z "$addr" ] && \
        { json_error "Missing WireGuard args"; return 1; }

    with_iface_lock "$name" _task_connect_wireguard "$name" "$priv" "$peer" "$endp" "$ips" "$addr" "$dns"

    json_success '{"type": "wireguard", "iface": "'"$name"'"}'
}
