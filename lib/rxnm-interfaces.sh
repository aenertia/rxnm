# ==============================================================================
# INTERFACE CONFIGURATION (Bridge, Static, DHCP)
# ==============================================================================

# --- TASKS ---

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
    local metric="$8"
    
    rm -f "${STORAGE_NET_DIR}/75-static-${iface}.network" 2>/dev/null
    
    # Fix: Always ensure a file is written to satisfy persistence/test checks
    ensure_dirs
    set_network_cfg "$iface" "yes" "" "" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr" "$metric"
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
    local mdns="${8:-yes}"; local llmnr="${9:-yes}"; local metric="${10}"

    [ -z "$iface" ] || [ -z "$ip" ] && { log_error "Interface and IP required"; return 1; }
    
    # Handle Multiple IPs (Aliases) by iterating through comma-separated list
    local final_ips=""
    local IFS=','
    read -ra ADDR_LIST <<< "$ip"
    for addr in "${ADDR_LIST[@]}"; do
        # Trim spaces
        addr="${addr// /}"
        [ -z "$addr" ] && continue
        
        # Default CIDR /24 if missing
        if [[ "$addr" != *"/"* ]]; then addr="${addr}/24"; fi
        
        # Validate individual IP (CIDR aware)
        if ! validate_ip "$addr"; then
             return 1
        fi
        
        if [ -z "$final_ips" ]; then final_ips="$addr"; else final_ips="$final_ips,$addr"; fi
    done
    unset IFS

    [ -n "$gw" ] && ! validate_ip "$gw" && { json_error "Invalid Gateway"; return 1; }
    [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
    
    # Sane Default Metrics
    if [ -z "$metric" ]; then
        if [[ "$iface" == wlan* ]] || [[ "$iface" == wlp* ]] || [[ "$iface" == uap* ]]; then
             metric="600"
        elif [[ "$iface" == eth* ]] || [[ "$iface" == en* ]]; then
             metric="100"
        fi
    fi

    with_iface_lock "$iface" _task_set_static "$iface" "$final_ips" "$gw" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr" "$metric"
        
    json_success '{"mode": "static", "iface": "'"$iface"'", "ip": "'"$final_ips"'", "metric": "'"$metric"'"}'
}

_task_set_link() {
    local iface="$1"; local ipv4="$2"; local ipv6="$3"
    
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

set_network_cfg() {
    local iface=$1 dhcp=$2 ip=$3 gw=$4 dns=$5 ssid=$6 domains=$7 routes=$8 mdns=$9 llmnr=${10} metric=${11} vrf=${12}
    local safe_ssid=""
    [ -n "$ssid" ] && safe_ssid=$(sanitize_ssid "$ssid")
    
    local cfg
    cfg=$(build_network_config "$iface" "$ssid" "$dhcp" "User Config" "$ip" "$gw" "$dns" "" "" "$domains" "" "$routes" "$mdns" "$llmnr" "" "$metric" "$vrf")
    
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

action_set_member() {
    local iface="$1"; local bridge="$2"
    ! validate_interface_name "$iface" && { json_error "Invalid interface"; return 1; }
    
    with_iface_lock "$iface" _task_set_member "$iface" "$bridge"
    json_success '{"action": "set_member", "iface": "'"$iface"'", "bridge": "'"$bridge"'"}'
}

action_delete_netdev() {
    local name="$1"
    ! validate_interface_name "$name" && { json_error "Invalid name"; return 1; }
    
    confirm_action "Delete virtual interface '$name'?" "$FORCE_ACTION"
    
    local found="false"
    # Identify device kind and remove .netdev
    for f in "${STORAGE_NET_DIR}"/60-*-"${name}.netdev"; do
        if [ -f "$f" ]; then rm -f "$f"; found="true"; fi
    done
    
    # Also remove associated .network files for this interface
    for f in "${STORAGE_NET_DIR}"/*-"${name}.network"; do
         if [ -f "$f" ]; then rm -f "$f"; found="true"; fi
    done
    
    if [ "$found" == "true" ]; then
        reload_networkd
        json_success '{"deleted": "'"$name"'"}'
    else
        json_error "Device configuration not found for '$name'"
    fi
}

action_set_dhcp() {
    local iface="$1"; local ssid="$2"; local dns="$3"; local domains="$4"; local routes="$5"
    local mdns="${6:-yes}"; local llmnr="${7:-yes}"; local metric="$8"

    [ -z "$iface" ] && { log_error "Interface required"; return 1; }
    
    if [ -n "$dns" ] || [ -n "$domains" ] || [ -n "$routes" ]; then
        [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
        [ -n "$routes" ] && ! validate_routes "$routes" && { json_error "Invalid routes"; return 1; }
    fi
    
    # Sane Default Metrics for Handhelds:
    # Prefer Ethernet (100) over WiFi (600)
    if [ -z "$metric" ]; then
        if [[ "$iface" == wlan* ]] || [[ "$iface" == wlp* ]] || [[ "$iface" == uap* ]]; then
             metric="600"
        elif [[ "$iface" == eth* ]] || [[ "$iface" == en* ]]; then
             metric="100"
        fi
    fi

    with_iface_lock "$iface" _task_set_dhcp "$iface" "$ssid" "$dns" "$domains" "$routes" "$mdns" "$llmnr" "$metric"
    json_success '{"mode": "dhcp", "iface": "'"$iface"'", "metric": "'"$metric"'"}'
}

action_set_static() {
    local iface="$1"; local ip="$2"; local gw="$3"; local dns="$4"; local ssid="$5"; local domains="$6"; local routes="$7"
    local mdns="${8:-yes}"; local llmnr="${9:-yes}"; local metric="${10}"

    [ -z "$iface" ] || [ -z "$ip" ] && { log_error "Interface and IP required"; return 1; }
    
    # Handle Multiple IPs (Aliases) by iterating through comma-separated list
    local final_ips=""
    local IFS=','
    read -ra ADDR_LIST <<< "$ip"
    for addr in "${ADDR_LIST[@]}"; do
        # Trim spaces
        addr="${addr// /}"
        [ -z "$addr" ] && continue
        
        # Default CIDR /24 if missing
        if [[ "$addr" != *"/"* ]]; then addr="${addr}/24"; fi
        
        # Validate individual IP (CIDR aware)
        if ! validate_ip "$addr"; then
             return 1
        fi
        
        if [ -z "$final_ips" ]; then final_ips="$addr"; else final_ips="$final_ips,$addr"; fi
    done
    unset IFS

    [ -n "$gw" ] && ! validate_ip "$gw" && { json_error "Invalid Gateway"; return 1; }
    [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
    
    # Sane Default Metrics
    if [ -z "$metric" ]; then
        if [[ "$iface" == wlan* ]] || [[ "$iface" == wlp* ]] || [[ "$iface" == uap* ]]; then
             metric="600"
        elif [[ "$iface" == eth* ]] || [[ "$iface" == en* ]]; then
             metric="100"
        fi
    fi

    with_iface_lock "$iface" _task_set_static "$iface" "$final_ips" "$gw" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr" "$metric"
        
    json_success '{"mode": "static", "iface": "'"$iface"'", "ip": "'"$final_ips"'", "metric": "'"$metric"'"}'
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
