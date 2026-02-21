# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-interfaces.sh
# PURPOSE: Standard Interface Operations
# ARCHITECTURE: Logic / Interfaces
# -----------------------------------------------------------------------------

_task_set_member() {
    local iface="$1" bridge="$2"
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local content
    content=$(build_network_config --match-name "$iface" --dhcp "no" --description "Bridge Member" --bridge "$bridge" --mdns "no" --llmnr "no")
    secure_write "$cfg_file" "$content" "644"
    reconfigure_iface "$iface"
    reconfigure_iface "$bridge"
}

_task_set_dhcp() {
    local iface="" ssid="" dns="" domains="" routes=""
    local mdns="yes" llmnr="yes" metric="" mtu="" mac=""
    local ipv6_priv="" dhcp_id="" ipv6_pd="yes"
    
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --iface)     iface="$2";     shift 2 ;;
            --ssid)      ssid="$2";      shift 2 ;;
            --dns)       dns="$2";       shift 2 ;;
            --domains)   domains="$2";   shift 2 ;;
            --routes)    routes="$2";    shift 2 ;;
            --mdns)      mdns="$2";      shift 2 ;;
            --llmnr)     llmnr="$2";     shift 2 ;;
            --metric)    metric="$2";    shift 2 ;;
            --mtu)       mtu="$2";       shift 2 ;;
            --mac)       mac="$2";       shift 2 ;;
            --ipv6-priv) ipv6_priv="$2"; shift 2 ;;
            --dhcp-id)   dhcp_id="$2";   shift 2 ;;
            --ipv6-pd)   ipv6_pd="$2";   shift 2 ;;
            *) shift ;;
        esac
    done

    rm -f "${STORAGE_NET_DIR}/75-static-${iface}.network" 2>/dev/null
    ensure_dirs
    set_network_cfg "$iface" "yes" "" "" "$dns" "$ssid" "$domains" "$routes" "$mdns" "$llmnr" "$metric" "" "$mtu" "$mac" "$ipv6_priv" "$dhcp_id" "$ipv6_pd"
    reconfigure_iface "$iface"
}

_task_set_static() {
    local iface="" ip="" gw="" dns="" ssid="" domains="" routes=""
    local mdns="yes" llmnr="yes" metric="" mtu="" mac=""
    local ipv6_priv="" dhcp_id="" ipv6_pd="yes"
    
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --iface)     iface="$2";     shift 2 ;;
            --ip)        ip="$2";        shift 2 ;;
            --gw)        gw="$2";        shift 2 ;;
            --dns)       dns="$2";       shift 2 ;;
            --ssid)      ssid="$2";      shift 2 ;;
            --domains)   domains="$2";   shift 2 ;;
            --routes)    routes="$2";    shift 2 ;;
            --mdns)      mdns="$2";      shift 2 ;;
            --llmnr)     llmnr="$2";     shift 2 ;;
            --metric)    metric="$2";    shift 2 ;;
            --mtu)       mtu="$2";       shift 2 ;;
            --mac)       mac="$2";       shift 2 ;;
            --ipv6-priv) ipv6_priv="$2"; shift 2 ;;
            --dhcp-id)   dhcp_id="$2";   shift 2 ;;
            --ipv6-pd)   ipv6_pd="$2";   shift 2 ;;
            *) shift ;;
        esac
    done
    
    rm -f "${STORAGE_NET_DIR}/75-config-${iface}.network" 2>/dev/null
    rm -f "${STORAGE_NET_DIR}/75-config-${iface}-"*.network 2>/dev/null
    ensure_dirs
    local content
    content=$(build_network_config --match-name "$iface" --match-ssid "$ssid" --dhcp "no" --description "Static Configuration" --address "$ip" --gateway "$gw" --dns "$dns" --domains "$domains" --routes "$routes" --mdns "$mdns" --llmnr "$llmnr" --metric "$metric" --mtu "$mtu" --mac-addr "$mac" --ipv6-privacy "$ipv6_priv" --dhcp-client-id "$dhcp_id")
    secure_write "${STORAGE_NET_DIR}/75-static-${iface}.network" "$content" "644"
    reconfigure_iface "$iface"
}

_task_set_link() {
    local iface="$1" ipv4="$2" ipv6="$3"
    ensure_dirs
    local cfg_file="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local ll="yes" ra="yes" dhcp="yes"
    [ "$ipv4" = "off" ] && { dhcp="ipv6"; ll="ipv6"; }
    [ "$ipv6" = "off" ] && { [ "$ipv4" = "off" ] && dhcp="no" || dhcp="ipv4"; ra="no"; [ "$ipv4" = "off" ] && ll="no" || ll="ipv4"; }
    local content="[Match]\nName=${iface}\n\n[Network]\nDescription=Link Toggles\nDHCP=${dhcp}\nLinkLocalAddressing=${ll}\nIPv6AcceptRA=${ra}\n"
    secure_write "$cfg_file" "$content" "644"
    reconfigure_iface "$iface"
}

_task_set_hardware() {
    local iface="$1" speed="$2" duplex="$3" autoneg="$4" wol="$5" mac_policy="$6" name_policy="$7" mac_addr="$8"
    ensure_dirs
    local content
    content=$(build_device_link_config "$iface" "$speed" "$duplex" "$autoneg" "$wol" "$mac_policy" "$name_policy" "$mac_addr")
    secure_write "${STORAGE_NET_DIR}/10-rxnm-${iface}.link" "$content" "644"
    if command -v udevadm >/dev/null; then udevadm control --reload; udevadm trigger --verbose --type=devices --action=change --subsystem-match=net --sysname-match="$iface" >/dev/null 2>&1; fi
}

_task_set_proxy() {
    local iface="$1" http="$2" https="$3" noproxy="$4"
    
    [ -n "$http" ]  && ! validate_proxy_url "$http"  && { json_error "Invalid HTTP proxy URL";  return 1; }
    [ -n "$https" ] && ! validate_proxy_url "$https" && { json_error "Invalid HTTPS proxy URL"; return 1; }
    
    local target_file="${iface:+${STORAGE_NET_DIR}/proxy-${iface}.conf}"
    target_file="${target_file:-$STORAGE_PROXY_GLOBAL}"
    if [ -z "$http" ] && [ -z "$https" ] && [ -z "$noproxy" ]; then [ -f "$target_file" ] && rm -f "$target_file"; else
        local content="# Proxy Configuration\n"
        [ -n "$http" ] && content="${content}http_proxy=\"$http\"\nHTTP_PROXY=\"$http\"\n"
        [ -n "$https" ] && content="${content}https_proxy=\"$https\"\nHTTPS_PROXY=\"$https\"\n"
        [ -n "$noproxy" ] && content="${content}no_proxy=\"$noproxy\"\nNO_PROXY=\"$noproxy\"\n"
        secure_write "$target_file" "$content" "600"
    fi
}

set_network_cfg() {
    local iface=$1 dhcp=$2 ip=$3 gw=$4 dns=$5 ssid=$6 domains=$7 routes=$8 mdns=$9 llmnr=${10} metric=${11} vrf=${12} mtu=${13} mac=${14} ipv6_priv=${15} dhcp_id=${16} ipv6_pd=${17}
    local safe_ssid="${ssid:+$(sanitize_ssid "$ssid")}"
    local cfg
    cfg=$(build_network_config --match-name "$iface" --match-ssid "$ssid" --dhcp "$dhcp" --description "User Config" --address "$ip" --gateway "$gw" --dns "$dns" --domains "$domains" --routes "$routes" --mdns "$mdns" --llmnr "$llmnr" --metric "$metric" --vrf "$vrf" --mtu "$mtu" --mac-addr "$mac" --ipv6-privacy "$ipv6_priv" --dhcp-client-id "$dhcp_id" --ipv6-pd "$ipv6_pd")
    local filename="${STORAGE_NET_DIR}/75-config-${iface}${safe_ssid:+-${safe_ssid}}.network"
    secure_write "$filename" "$cfg" 644
}

# --- Actions ---

action_hotplug() {
    local iface="$1"
    [ -z "$iface" ] && return 1
    case "$iface" in usb*|rndis*)
        if ! is_service_active "systemd-networkd"; then
            if type configure_standalone_gadget >/dev/null 2>&1; then configure_standalone_gadget "$iface"; fi
            json_success '{"action": "hotplug", "mode": "rescue", "iface": "'"$iface"'"}'
            return 0
        fi
    ;; *)
        if ! is_service_active "systemd-networkd"; then
            if type configure_standalone_client >/dev/null 2>&1; then configure_standalone_client "$iface"; fi
            json_success '{"action": "hotplug", "mode": "rescue", "iface": "'"$iface"'"}'
            return 0
        fi
    ;; esac
    reconfigure_iface "$iface"
    json_success '{"action": "hotplug", "mode": "standard", "iface": "'"$iface"'"}'
}

action_create_bridge() {
    local name="$1"
    ! validate_interface_name "$name" && { json_error "Invalid bridge name"; return 1; }
    ensure_dirs
    secure_write "${STORAGE_NET_DIR}/60-bridge-${name}.netdev" "[NetDev]\nName=${name}\nKind=bridge\n[Bridge]\nSTP=no\nMulticastSnooping=yes\n" "644"
    reload_networkd
    json_success '{"type": "bridge", "iface": "'"$name"'"}'
}

action_set_member() {
    local iface="$1" bridge="$2"
    ! validate_interface_name "$iface" && { json_error "Invalid interface"; return 1; }
    with_iface_lock "$iface" _task_set_member "$iface" "$bridge"
    json_success '{"action": "set_member", "iface": "'"$iface"'", "bridge": "'"$bridge"'"}'
}

action_delete_netdev() {
    local name="$1"
    ! validate_interface_name "$name" && { json_error "Invalid name"; return 1; }
    confirm_action "Delete virtual interface '$name'?" "$FORCE_ACTION"
    local found="false"
    for f in "${STORAGE_NET_DIR}"/60-*-"${name}.netdev" "${STORAGE_NET_DIR}"/*-"${name}.network"; do
        if [ -f "$f" ]; then rm -f "$f"; found="true"; fi
    done
    if [ "$found" = "true" ]; then reload_networkd; json_success '{"deleted": "'"$name"'"}'
    else json_error "Device configuration not found for '$name'"; fi
}

action_set_dhcp() {
    local iface="$1" ssid="$2" dns="$3" domains="$4" routes="$5" mdns="${6:-yes}" llmnr="${7:-yes}" metric="$8" mtu="$9" mac="${10}" ipv6_priv="${11}" dhcp_id="${12}" ipv6_pd="${13}"
    [ -z "$iface" ] && return 1
    [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
    [ -n "$routes" ] && ! validate_routes "$routes" && { json_error "Invalid routes"; return 1; }
    [ -n "$mac" ] && ! validate_mac "$mac" && { json_error "Invalid MAC"; return 1; }
    [ -n "$mtu" ] && ! validate_mtu "$mtu" && { json_error "Invalid MTU"; return 1; }
    if [ -z "$metric" ]; then case "$iface" in wlan*|wlp*|uap*) metric="600" ;; eth*|en*) metric="100" ;; esac; fi
    
    with_iface_lock "$iface" _task_set_dhcp \
        --iface "$iface" --ssid "$ssid" --dns "$dns" --domains "$domains" --routes "$routes" \
        --mdns "$mdns" --llmnr "$llmnr" --metric "$metric" --mtu "$mtu" --mac "$mac" \
        --ipv6-priv "$ipv6_priv" --dhcp-id "$dhcp_id" --ipv6-pd "$ipv6_pd"
        
    json_success '{"mode": "dhcp", "iface": "'"$iface"'"}'
}

action_set_static() {
    local iface="$1" ip="$2" gw="$3" dns="$4" ssid="$5" domains="$6" routes="$7" mdns="${8:-yes}" llmnr="${9:-yes}" metric="${10}" mtu="${11}" mac="${12}" ipv6_priv="${13}" dhcp_id="${14}"
    [ -z "$iface" ] || [ -z "$ip" ] && return 1
    
    local final_ips=""
    set -f
    local _old_ifs="$IFS"
    IFS=","
    for addr in $ip; do
        addr=$(echo "$addr" | tr -d ' ')
        [ -z "$addr" ] && continue
        
        # Only apply default /24 to bare IPv4 addresses, leave IPv6 alone
        case "$addr" in 
            *:*) ;; # IPv6: Do not append /24
            */*) ;; # Already has CIDR
            *) addr="${addr}/24" ;; 
        esac
        
        if ! validate_ip "$addr"; then IFS="$_old_ifs"; set +f; return 1; fi
        final_ips="${final_ips:+$final_ips,}$addr"
    done
    IFS="$_old_ifs"
    set +f
    
    [ -n "$gw" ] && ! validate_ip "$gw" && { json_error "Invalid Gateway"; return 1; }
    [ -n "$dns" ] && ! validate_dns "$dns" && { json_error "Invalid DNS"; return 1; }
    if [ -z "$metric" ]; then case "$iface" in wlan*|wlp*|uap*) metric="600" ;; eth*|en*) metric="100" ;; esac; fi
    
    with_iface_lock "$iface" _task_set_static \
        --iface "$iface" --ip "$final_ips" --gw "$gw" --dns "$dns" --ssid "$ssid" \
        --domains "$domains" --routes "$routes" --mdns "$mdns" --llmnr "$llmnr" \
        --metric "$metric" --mtu "$mtu" --mac "$mac" --ipv6-priv "$ipv6_priv" --dhcp-id "$dhcp_id"
        
    json_success '{"mode": "static", "iface": "'"$iface"'", "ip": "'"$final_ips"'"}'
}

action_set_hardware() {
    local iface="$1" speed="$2" duplex="$3" autoneg="$4" wol="$5" mac_policy="$6" name_policy="$7" mac_addr="$8"
    [ -z "$iface" ] && return 1
    if [ -n "$speed" ] && ! validate_link_speed "$speed"; then return 1; fi
    if [ -n "$duplex" ] && ! validate_duplex "$duplex"; then return 1; fi
    if [ -n "$autoneg" ] && ! validate_autoneg "$autoneg"; then return 1; fi
    if [ -n "$mac_addr" ] && ! validate_mac "$mac_addr"; then return 1; fi
    with_iface_lock "$iface" _task_set_hardware "$iface" "$speed" "$duplex" "$autoneg" "$wol" "$mac_policy" "$name_policy" "$mac_addr"
    json_success '{"action": "set_hardware", "iface": "'"$iface"'"}'
}

action_set_link() {
    local iface="$1" ipv4="$2" ipv6="$3"
    [ -z "$iface" ] && return 1
    with_iface_lock "$iface" _task_set_link "$iface" "$ipv4" "$ipv6"
    json_success '{"action": "set_link", "iface": "'"$iface"'"}'
}

action_set_proxy() {
    local iface="$1" http="$2" https="$3" noproxy="$4"
    with_iface_lock "${iface:-global_proxy}" _task_set_proxy "$iface" "$http" "$https" "$noproxy"
    json_success '{"action": "set_proxy"}'
}
