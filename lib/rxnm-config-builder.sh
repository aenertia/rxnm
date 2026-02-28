# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-config-builder.sh
# PURPOSE: Configuration Templating Engine (Aligned with systemd 255.8)
# ARCHITECTURE: Logic / Templating
# -----------------------------------------------------------------------------

_get_system_template_val() {
    local fname="$1"
    local key="$2"
    local f="/usr/lib/systemd/network/$fname"
    [ -f "$f" ] || return
    
    while IFS= read -r line; do
        case "$line" in
            "${key}="*)
                local val="${line#*=}"
                val="${val%%#*}"
                val="$(echo "$val" | tr -d '[:space:]')"
                echo "$val"
                return
                ;;
        esac
    done < "$f"
}

_ini_safe() {
    printf '%s' "$1" | tr -d '\000-\037\177'
}

build_network_config() {
    local match_iface=""
    local match_ssid=""
    local ssid_match_only="false"
    local dhcp="yes"
    local desc=""
    local addresses=""
    local gateway=""
    local dns_servers=""
    local bridge=""
    local vlan=""
    local domains=""
    local mac_policy=""
    local routes=""
    local mdns="yes"
    local llmnr="yes"
    local bond=""
    local metric=""
    local vrf=""
    local mtu=""
    local mac_addr=""
    local ipv6_privacy=""
    local dhcp_client_id=""
    local ipv6_pd="yes"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --match-name) match_iface="$2"; shift 2 ;;
            --match-ssid) match_ssid="$2"; shift 2 ;;
            --ssid-match-only) ssid_match_only="true"; shift ;;
            --dhcp) dhcp="$2"; shift 2 ;;
            --description) desc="$2"; shift 2 ;;
            --address) addresses="$2"; shift 2 ;;
            --gateway) gateway="$2"; shift 2 ;;
            --dns) dns_servers="$2"; shift 2 ;;
            --bridge) bridge="$2"; shift 2 ;;
            --vlan) vlan="$2"; shift 2 ;;
            --domains) domains="$2"; shift 2 ;;
            --mac-policy) mac_policy="$2"; shift 2 ;;
            --routes) routes="$2"; shift 2 ;;
            --mdns) mdns="$2"; shift 2 ;;
            --llmnr) llmnr="$2"; shift 2 ;;
            --bond) bond="$2"; shift 2 ;;
            --metric) metric="$2"; shift 2 ;;
            --vrf) vrf="$2"; shift 2 ;;
            --mtu) mtu="$2"; shift 2 ;;
            --mac-addr) mac_addr="$2"; shift 2 ;;
            --ipv6-privacy) ipv6_privacy="$2"; shift 2 ;;
            --dhcp-client-id) dhcp_client_id="$2"; shift 2 ;;
            --ipv6-pd) ipv6_pd="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [ "$mdns" = "yes" ] && command -v is_avahi_running >/dev/null 2>&1 && is_avahi_running; then
        mdns="no"
    fi

    local safe_match_iface; safe_match_iface=$(_ini_safe "${match_iface}")
    local safe_match_ssid; safe_match_ssid=$(_ini_safe "${match_ssid}")
    local safe_desc; safe_desc=$(_ini_safe "${desc}")
    local safe_mac_addr; safe_mac_addr=$(_ini_safe "${mac_addr}")

    printf "[Match]\n"
    [ -n "$safe_match_iface" ] && printf "Name=%s\n" "${safe_match_iface}"
    [ -n "$safe_match_ssid" ] && printf "SSID=%s\n" "${safe_match_ssid}"
    
    case "$safe_match_iface" in
        wlan*|mlan*|uap*) printf "Type=wlan\n" ;;
    esac
    
    [ "$ssid_match_only" = "true" ] && return

    if [ -n "$mac_policy" ] || [ -n "$mtu" ] || [ -n "$safe_mac_addr" ]; then
        printf "\n[Link]\n"
        [ -n "$mac_policy" ] && printf "MACAddressPolicy=%s\n" "${mac_policy}"
        [ -n "$safe_mac_addr" ] && printf "MACAddress=%s\n" "${safe_mac_addr}"
        [ -n "$mtu" ] && printf "MTUBytes=%s\n" "${mtu}"
    fi

    printf "\n[Network]\n"
    [ -n "$safe_desc" ] && printf "Description=%s\n" "${safe_desc}"
    [ -n "$dhcp" ] && printf "DHCP=%s\n" "${dhcp}"
    
    [ -n "$bridge" ] && printf "Bridge=%s\n" "${bridge}"
    [ -n "$bond" ] && printf "Bond=%s\n" "${bond}"
    [ -n "$vrf" ] && printf "VRF=%s\n" "${vrf}"
    [ -n "$vlan" ] && printf "VLAN=%s\n" "${vlan}"
    
    printf "MulticastDNS=%s\nLLMNR=%s\n" "${mdns}" "${llmnr}"
    printf "LinkLocalAddressing=yes\nIPv6AcceptRA=yes\nConfigureWithoutCarrier=yes\n"
    # shellcheck disable=SC2059
    printf "${RXNM_NETWORKD_KEY_IPFORWARD}\n"

    if [ -n "$ipv6_privacy" ]; then
        printf "IPv6PrivacyExtensions=%s\n" "${ipv6_privacy}"
    fi

    if [ -n "$addresses" ]; then
        set -f
        local _old_ifs="$IFS"
        IFS=","
        for addr in $addresses; do
            addr=$(printf '%s' "$addr" | tr -d ' ')
            [ -z "$addr" ] && continue
            printf "Address=%s\n" "$addr"
        done
        IFS="$_old_ifs"
        set +f
    fi
    
    if [ -n "$gateway" ]; then
        printf "Gateway=%s\n" "${gateway}"
    fi
    
    if [ -n "$dns_servers" ]; then
        set -f
        local _old_ifs="$IFS"
        IFS=","
        for d in $dns_servers; do
            d=$(printf '%s' "$d" | tr -d ' ')
            [ -z "$d" ] && continue
            printf "DNS=%s\n" "$d"
        done
        IFS="$_old_ifs"
        set +f
    fi
    
    if [ -n "$domains" ]; then
        set -f
        local _old_ifs="$IFS"
        IFS=","
        for d in $domains; do
            d=$(printf '%s' "$d" | tr -d ' ')
            [ -z "$d" ] && continue
            local safe_d; safe_d=$(_ini_safe "$d")
            printf "Domains=%s\n" "${safe_d}"
        done
        IFS="$_old_ifs"
        set +f
    fi
    
    if [ "$dhcp" != "no" ] || [ -n "$dhcp_client_id" ]; then
         printf "\n[DHCPv4]\n"
         if [ -n "$dhcp_client_id" ]; then
             local safe_dhcp_id; safe_dhcp_id=$(_ini_safe "${dhcp_client_id}")
             printf "ClientIdentifier=%s\n" "${safe_dhcp_id}"
         fi
         [ "$dhcp" != "no" ] && [ -n "$metric" ] && printf "RouteMetric=%s\n" "${metric}"
    fi
    
    if [ "$ipv6_pd" = "no" ]; then
        printf "\n[DHCPv6]\nUseDelegatedPrefix=no\n"
    fi

    if [ -n "$routes" ]; then
        set -f
        local _old_ifs="$IFS"
        IFS=","
        for r in $routes; do
            r=$(printf '%s' "$r" | tr -d ' ')
            [ -z "$r" ] && continue
            local r_dest="" r_gw="" r_metric=""
            r_dest=$(echo "$r" | cut -d'@' -f1)
            r_gw=$(echo "$r" | cut -d'@' -f2 -s)
            r_metric=$(echo "$r" | cut -d'@' -f3 -s)
            
            [ -z "$r_dest" ] && r_dest="$r"
            
            printf "\n[Route]\nDestination=%s\n" "${r_dest}"
            [ -n "$r_gw" ] && printf "Gateway=%s\n" "${r_gw}"
            if [ -n "$r_metric" ]; then 
                printf "Metric=%s\n" "${r_metric}"
            elif [ -n "$metric" ] && [ "$dhcp" = "no" ]; then 
                printf "Metric=%s\n" "${metric}"
            fi
        done
        IFS="$_old_ifs"
        set +f
    fi
}

build_device_link_config() {
    local iface="$1" speed="$2" duplex="$3" autoneg="$4" wol="$5" mac_policy="$6" name_policy="$7" mac_addr="$8"
    
    local safe_iface; safe_iface=$(_ini_safe "$iface")
    local safe_mac_addr; safe_mac_addr=$(_ini_safe "$mac_addr")
    
    printf "[Match]\nOriginalName=%s\n" "${safe_iface}"
    printf "\n[Link]\nDescription=RXNM Hardware Config\n"
    
    [ -n "$speed" ] && printf "BitsPerSecond=%sM\n" "${speed}"
    [ -n "$duplex" ] && printf "Duplex=%s\n" "${duplex}"
    [ -n "$autoneg" ] && printf "AutoNegotiation=%s\n" "${autoneg}"
    [ -n "$wol" ] && printf "WakeOnLan=%s\n" "${wol}"
    [ -n "$mac_policy" ] && printf "MACAddressPolicy=%s\n" "${mac_policy}"
    [ -n "$name_policy" ] && printf "NamePolicy=%s\n" "${name_policy}"
    [ -n "$safe_mac_addr" ] && printf "MACAddress=%s\n" "${safe_mac_addr}"
}

build_gateway_config() {
    local iface="$1" ip="$2" share="$3" desc="$4" mdns="${5:-yes}" llmnr="${6:-yes}" ipv6_pd="${7:-yes}"
    
    if [ "$mdns" = "yes" ] && command -v is_avahi_running >/dev/null 2>&1 && is_avahi_running; then mdns="no"; fi
    
    if [ -z "$ip" ]; then
        local detected_ip=""
        case "$iface" in
            usb*|rndis*) detected_ip=$(_get_system_template_val "70-usb-gadget.network" "Address") ;;
            wlan*) [ "$share" = "true" ] && detected_ip=$(_get_system_template_val "70-wifi-ap-share.network" "Address") ;;
        esac
        
        if [ -n "$detected_ip" ]; then ip="$detected_ip"
        else
            if [ "$share" = "true" ]; then ip="${DEFAULT_GW_V4:-192.168.212.1/24}"
            else
                 case "$iface" in
                    usb*|rndis*) ip="192.168.213.1/24" ;;
                    *) ip="169.254.1.1/16" ;;
                 esac
            fi
        fi
    fi
    
    local safe_iface; safe_iface=$(_ini_safe "$iface")
    local safe_desc; safe_desc=$(_ini_safe "$desc")
    
    printf "[Match]\nName=%s\n" "${safe_iface}"
    case "$safe_iface" in
        wlan*) printf "Type=wlan\n" ;;
    esac

    printf "\n[Network]\nDescription=%s\n" "${safe_desc}"
    printf "MulticastDNS=%s\nLLMNR=%s\n" "${mdns}" "${llmnr}"
    [ -n "$ip" ] && printf "Address=%s\n" "${ip}"
    printf "LinkLocalAddressing=yes\nConfigureWithoutCarrier=yes\n"
    
    if [ "$share" = "true" ]; then
        # v255.8 Compliant Forwarding (NAT is handled externally by rxnm-system)
        # shellcheck disable=SC2059
        printf "${RXNM_NETWORKD_KEY_IPFORWARD}\nIPv6SendRA=yes\n"
        if [ "$ipv6_pd" != "no" ]; then printf "DHCPPrefixDelegation=yes\n"; fi
        
        printf "Address=fd00:cafe:feed::a7ca:de/64\n"
        
        printf "DHCPServer=yes\n\n[DHCPServer]\nPoolOffset=100\nEmitDNS=yes\nEmitRouter=yes\n"
        # shellcheck disable=SC2059
        printf "[IPv6SendRA]\nManaged=no\n${RXNM_NETWORKD_KEY_RA_OTHER}=no\n"
    else
        printf "Address=fd00:cafe:feed::a7ca:de/64\n"
        printf "IPv6AcceptRA=no\nDHCPServer=yes\n\n[DHCPServer]\nEmitDNS=yes\nEmitRouter=no\n"
    fi
}
