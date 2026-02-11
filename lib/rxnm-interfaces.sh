# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-interfaces.sh
# PURPOSE: Standard Interface Operations
# ARCHITECTURE: Logic / Interfaces
#
# Handles high-level interface commands: set dhcp, set static, set hardware,
# hotplug events, and proxy settings.
# -----------------------------------------------------------------------------

# --- Internal Tasks (Executed with Locks) ---

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
    local mtu="$9"
    local mac="${10}"
    local ipv6_priv="${11}"
    local dhcp_id="${12}"
    local ipv6_pd="${13}"
    
    # Clean up static config if it exists
    rm -f "${STORAGE_NET_DIR}/75-static-${iface}.network" 2>/dev/null
    
    ensure_dirs
    set_network_cfg "$iface" "yes" "" "" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr" "$metric" "" "$mtu" "$mac" "$ipv6_priv" "$dhcp_id" "$ipv6_pd"
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
    local metric="${10}"
    local mtu="${11}"
    local mac="${12}"
    local ipv6_priv="${13}"
    local dhcp_id="${14}"
    
    # Remove conflicting dynamic configs
    rm -f "${STORAGE_NET_DIR}/75-config-${iface}.network" 2>/dev/null
    rm -f "${STORAGE_NET_DIR}/75-config-${iface}-"*.network 2>/dev/null
    
    ensure_dirs
    local content
    content=$(build_network_config "$iface" "$ssid" "no" "Static Configuration" "$ip" "$gw" "$dns" "" "" "$domains" "" "$routes" "$mdns" "$llmnr" "" "$metric" "" "$mtu" "$mac" "$ipv6_priv" "$dhcp_id")
    local filename="${STORAGE_NET_DIR}/75-static-${iface}.network"
    secure_write "$filename" "$content" "644"
    reconfigure_iface "$iface"
}

_task_set_link() {
    local iface="$1"; local ipv4="$2"; local ipv6="$3"
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    
    # Determine flags
    local ll="yes"; local ra="yes"; local dhcp="yes"
    [[ "$ipv4" == "off" ]] && { dhcp="ipv6"; ll="ipv6"; }
    [[ "$ipv6" == "off" ]] && { dhcp="ipv4"; ra="no"; ll="ipv4"; }
    [[ "$ipv4" == "off" ]] && [[ "$ipv6" == "off" ]] && { dhcp="no"; ll="no"; ra="no"; }
    
    local content="[Match]\nName=${iface}\n\n[Network]\nDescription=Link Toggles\nDHCP=${dhcp}\nLinkLocalAddressing=${ll}\nIPv6AcceptRA=${ra}\n"
    secure_write "$cfg_file" "$content" "644"
    reconfigure_iface "$iface"
}

_task_set_hardware() {
    local iface="$1"
    local speed="$2"
    local duplex="$3"
    local autoneg="$4"
    local wol="$5"
    local mac_policy="$6"
    local name_policy="$7"
    local mac_addr="$8"
    ensure_dirs
    
    local link_file="${STORAGE_NET_DIR}/10-rxnm-${iface}.link"
    local content
    content=$(build_device_link_config "$iface" "$speed" "$duplex" "$autoneg" "$wol" "$mac_policy" "$name_policy" "$mac_addr")
    secure_write "$link_file" "$content" "644"
    
    # Hardware changes usually require re-triggering udev
    if command -v udevadm >/dev/null; then
        udevadm control --reload
        udevadm trigger --verbose --type=devices --action=change --subsystem-match=net --sysname-match="$iface" >/dev/null 2>&1
    else
        log_warn "udevadm not found. Link settings may require reboot to apply."
    fi
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
        # Clearing proxy
        [ -f "$target_file" ] && rm -f "$target_file"
    else
        local content="# Proxy Configuration\n"
        [ -n "$http" ] && content+="http_proxy=\"$http\"\nHTTP_PROXY=\"$http\"\n"
        [ -n "$https" ] && content+="https_proxy=\"$https\"\nHTTPS_PROXY=\"$https\"\n"
        [ -n "$noproxy" ] && content+="no_proxy=\"$noproxy\"\nNO_PROXY=\"$noproxy\"\n"
        secure_write "$target_file" "$content" "600"
    fi
}

# Helper wrapper for standard config generation
set_network_cfg() {
    local iface=$1 dhcp=$2 ip=$3 gw=$4 dns=$5 ssid=$6 domains=$7 routes=$8 mdns=$9 llmnr=${10} metric=${11} vrf=${12} mtu=${13} mac=${14} ipv6_priv=${15} dhcp_id=${16} ipv6_pd=${17}
    
    local safe_ssid=""
    [ -n "$ssid" ] && safe_ssid=$(sanitize_ssid "$ssid")
    
    local cfg
    cfg=$(build_network_config "$iface" "$ssid" "$dhcp" "User Config" "$ip" "$gw" "$dns" "" "" "$domains" "" "$routes" "$mdns" "$llmnr" "" "$metric" "$vrf" "$mtu" "$mac" "$ipv6_priv" "$dhcp_id" "$ipv6_pd")
    
    local filename="${STORAGE_NET_DIR}/75-config-${iface}"
    if [ -n "$safe_ssid" ]; then
        filename="${filename}-${safe_ssid}.network"
    else
        filename="${filename}.network"
    fi
    secure_write "$filename" "$cfg" 644
}

# --- Public Actions ---

action_hotplug() {
    local iface="$1"
    [ -z "$iface" ] && return 1
    
    local is_usb_gadget=false
    if [[ "$iface" == "usb"* ]] || [[ "$iface" == "rndis"* ]]; then
        is_usb_gadget=true
    fi
    
    # If networkd is dead, fall back to standalone/busybox mode
    if ! is_service_active "systemd-networkd"; then
        log_warn "Network daemon inactive during hotplug of $iface."
        if [ "$is_usb_gadget" = true ]; then
            if type configure_standalone_gadget &>/dev/null; then
                configure_standalone_gadget "$iface"
            else
                log_warn "Rescue gadget helper not found."
            fi
        else
            if type configure_standalone_client &>/dev/null; then
                configure_standalone_client "$iface"
            else
                log_warn "Rescue client helper not found."
            fi
        fi
        json_success '{"action": "hotplug", "mode": "rescue", "iface": "'"$iface"'"}'
        return 0
    fi
    
    # Standard Mode
    reconfigure_iface "$iface"
    json_success '{"action": "hotplug", "mode": "standard", "iface": "'"$iface"'"}'
}

# Bridge creation logic (Simple)
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
    # Clean up all related files
    for f in "${STORAGE_NET_DIR}"/60-*-"${name}.netdev"; do
        if [ -f "$f" ]; then rm -f "$f"; found="true"; fi
    done
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
    local mdns="${6:-yes}"; local llmnr="${7:-yes}"; local metric="$8"; local mtu="$9"; local mac="${10}"
    local ipv6_priv="${11}"; local dhcp_id="${12}"; local ipv6_pd="${13}"
    
    [ -z "$iface" ] && { log_error "Interface required"; return 1; }
    
    # Validation
    if [ -n "$dns" ] || [ -n "$domains" ] || [ -n "$routes" ]; then
        [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
        [ -n "$routes" ] && ! validate_routes "$routes" && { json_error "Invalid routes"; return 1; }
    fi
    [ -n "$mac" ] && ! validate_mac "$mac" && { json_error "Invalid MAC"; return 1; }
    [ -n "$mtu" ] && ! validate_mtu "$mtu" && { json_error "Invalid MTU"; return 1; }
    
    # Default Metrics
    if [ -z "$metric" ]; then
        if [[ "$iface" == wlan* ]] || [[ "$iface" == wlp* ]] || [[ "$iface" == uap* ]]; then
             metric="600" # WiFi default
        elif [[ "$iface" == eth* ]] || [[ "$iface" == en* ]]; then
             metric="100" # Wired default
        fi
    fi
    
    with_iface_lock "$iface" _task_set_dhcp "$iface" "$ssid" "$dns" "$domains" "$routes" "$mdns" "$llmnr" "$metric" "$mtu" "$mac" "$ipv6_priv" "$dhcp_id" "$ipv6_pd"
    json_success '{"mode": "dhcp", "iface": "'"$iface"'", "metric": "'"$metric"'", "mac": "'"${mac:-default}"'", "mtu": "'"${mtu:-default}"'", "ipv6_privacy": "'"${ipv6_priv:-default}"'", "dhcp_id": "'"${dhcp_id:-default}"'", "ipv6_pd": "'"${ipv6_pd:-default}"'"}'
}

action_set_static() {
    local iface="$1"; local ip="$2"; local gw="$3"; local dns="$4"; local ssid="$5"; local domains="$6"; local routes="$7"
    local mdns="${8:-yes}"; local llmnr="${9:-yes}"; local metric="${10}"; local mtu="${11}"; local mac="${12}"
    local ipv6_priv="${13}"; local dhcp_id="${14}"
    
    [ -z "$iface" ] || [ -z "$ip" ] && { log_error "Interface and IP required"; return 1; }
    
    # Validate and clean IPs
    local final_ips=""
    local IFS=','
    read -ra ADDR_LIST <<< "$ip"
    for addr in "${ADDR_LIST[@]}"; do
        addr="${addr// /}"
        [ -z "$addr" ] && continue
        if [[ "$addr" != *"/"* ]]; then addr="${addr}/24"; fi
        if ! validate_ip "$addr"; then return 1; fi
        if [ -z "$final_ips" ]; then final_ips="$addr"; else final_ips="$final_ips,$addr"; fi
    done
    unset IFS
    
    [ -n "$gw" ] && ! validate_ip "$gw" && { json_error "Invalid Gateway"; return 1; }
    [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
    
    if [ -z "$metric" ]; then
        if [[ "$iface" == wlan* ]] || [[ "$iface" == wlp* ]] || [[ "$iface" == uap* ]]; then
             metric="600"
        elif [[ "$iface" == eth* ]] || [[ "$iface" == en* ]]; then
             metric="100"
        fi
    fi
    
    with_iface_lock "$iface" _task_set_static "$iface" "$ip" "$gw" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr" "$metric" "$mtu" "$mac" "$ipv6_priv" "$dhcp_id"
    json_success '{"mode": "static", "iface": "'"$iface"'", "ip": "'"$final_ips"'", "metric": "'"$metric"'", "mac": "'"${mac:-default}"'", "mtu": "'"${mtu:-default}"'", "ipv6_privacy": "'"${ipv6_priv:-default}"'", "dhcp_id": "'"${dhcp_id:-default}"'"}'
}

action_set_hardware() {
    local iface="$1"; local speed="$2"; local duplex="$3"; local autoneg="$4"
    local wol="$5"; local mac_policy="$6"; local name_policy="$7"; local mac_addr="$8"
    
    [ -z "$iface" ] && { json_error "Interface required"; return 1; }
    
    if [ -n "$speed" ] && ! validate_link_speed "$speed"; then return 1; fi
    if [ -n "$duplex" ] && ! validate_duplex "$duplex"; then return 1; fi
    if [ -n "$autoneg" ] && ! validate_autoneg "$autoneg"; then return 1; fi
    if [ -n "$mac_addr" ] && ! validate_mac "$mac_addr"; then return 1; fi
    
    with_iface_lock "$iface" _task_set_hardware "$iface" "$speed" "$duplex" "$autoneg" "$wol" "$mac_policy" "$name_policy" "$mac_addr"
    json_success '{"action": "set_hardware", "iface": "'"$iface"'"}'
}

action_set_link() {
    local iface="$1"; local ipv4="$2"; local ipv6="$3"
    [ -z "$iface" ] && return 1
    with_iface_lock "$iface" _task_set_link "$iface" "$ipv4" "$ipv6"
    json_success '{"config": "updated", "iface": "'"$iface"'"}'
}

action_set_proxy() {
    local iface="$1"; local http="$2"; local https="$3"; local noproxy="$4"
    with_iface_lock "${iface:-global_proxy}" _task_set_proxy "$iface" "$http" "$https" "$noproxy"
    json_success '{"action": "set_proxy"}'
}
