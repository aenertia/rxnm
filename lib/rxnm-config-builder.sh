# ==============================================================================
# NETWORK CONFIGURATION BUILDERS
# ==============================================================================

# Helper to peek at system templates to ensure consistency
_get_system_template_val() {
    local fname="$1"
    local key="$2"
    local f="/usr/lib/systemd/network/$fname"
    if [ -f "$f" ]; then
         grep "^${key}=" "$f" | sed 's/#.*//' | cut -d= -f2- | tr -d '[:space:]' | head -n1
    fi
}

# Generic Client/Station Config Builder (WAN/Upstream)
build_network_config() {
    local match_iface="$1"
    local match_ssid="$2"
    local dhcp="${3:-yes}"
    local desc="$4"
    local addresses="$5"
    local gateway="$6"
    local dns_servers="$7"
    local bridge="$8"
    local vlan="$9"
    local domains="${10}"
    local mac_policy="${11}"
    local routes="${12}"
    local mdns="${13:-yes}"
    local llmnr="${14:-yes}"
    local bond="${15:-}"
    local metric="${16:-}"
    local vrf="${17:-}"
    local mtu="${18:-}"
    local mac_addr="${19:-}"
    local ipv6_privacy="${20:-}"
    local dhcp_client_id="${21:-}"
    local ipv6_pd="${22:-yes}"

    # Intelligent conflict avoidance:
    if [ "$mdns" == "yes" ] && is_avahi_running; then
        mdns="no"
    fi

    local config="[Match]\nName=${match_iface}\n"
    [ -n "$match_ssid" ] && config+="SSID=${match_ssid}\n"
    
    if [ -n "$mac_policy" ] || [ -n "$mtu" ] || [ -n "$mac_addr" ]; then
        config+="\n[Link]\n"
        [ -n "$mac_policy" ] && config+="MACAddressPolicy=${mac_policy}\n"
        [ -n "$mac_addr" ] && config+="MACAddress=${mac_addr}\n"
        [ -n "$mtu" ] && config+="MTUBytes=${mtu}\n"
    fi
    
    config+="\n[Network]\n"
    [ -n "$desc" ] && config+="Description=${desc}\n"
    [ -n "$dhcp" ] && config+="DHCP=${dhcp}\n"
    [ -n "$bridge" ] && config+="Bridge=${bridge}\n"
    [ -n "$bond" ] && config+="Bond=${bond}\n"
    [ -n "$vrf" ] && config+="VRF=${vrf}\n"
    [ -n "$vlan" ] && config+="VLAN=${vlan}\n"
    [ -n "$metric" ] && config+="RouteMetric=${metric}\n"
    
    config+="MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    
    # Issue 6.4: Change default IPMasquerade to 'no' for client configs (Security Hardening)
    config+="LinkLocalAddressing=yes\nIPv6AcceptRA=yes\nIPMasquerade=no\n"
    
    if [ -n "$ipv6_privacy" ]; then
        config+="IPv6PrivacyExtensions=${ipv6_privacy}\n"
    fi

    if [ -n "$addresses" ]; then
        IFS=',' read -ra ADDRS <<< "$addresses"
        for addr in "${ADDRS[@]}"; do config+="Address=${addr}\n"; done
    fi
    
    if [ -n "$gateway" ]; then
        config+="Gateway=${gateway}\n"
    fi

    if [ -n "$dns_servers" ]; then
        IFS=',' read -ra DNS <<< "$dns_servers"
        for d in "${DNS[@]}"; do config+="DNS=${d}\n"; done
    fi
    
    if [ -n "$domains" ]; then
        IFS=',' read -ra DOMS <<< "$domains"
        for d in "${DOMS[@]}"; do config+="Domains=${d}\n"; done
    fi
    
    if [ -n "$dhcp_client_id" ]; then
         config+="\n[DHCPv4]\nClientIdentifier=${dhcp_client_id}\n"
    fi
    
    if [ "$ipv6_pd" == "no" ]; then
        config+="\n[DHCPv6]\nUseDelegatedPrefix=no\n"
    fi
    
    if [ -n "$routes" ]; then
        IFS=',' read -ra RTS <<< "$routes"
        for r in "${RTS[@]}"; do
            local r_dest="" r_gw="" r_metric=""
            IFS='@' read -r r_dest r_gw r_metric <<< "$r"
            config+="\n[Route]\nDestination=${r_dest}\n"
            [ -n "$r_gw" ] && config+="Gateway=${r_gw}\n"
            if [ -n "$r_metric" ]; then config+="Metric=${r_metric}\n"; elif [ -n "$metric" ]; then config+="Metric=${metric}\n"; fi
        done
    fi

    printf "%b" "$config"
}

# Device Link Configuration (.link file generation)
build_device_link_config() {
    local iface="$1" speed="$2" duplex="$3" autoneg="$4" wol="$5" mac_policy="$6" name_policy="$7" mac_addr="$8"
    local config="[Match]\nOriginalName=${iface}\n"
    config+="\n[Link]\nDescription=RXNM Hardware Config\n"
    [ -n "$speed" ] && config+="BitsPerSecond=${speed}M\n"
    [ -n "$duplex" ] && config+="Duplex=${duplex}\n"
    [ -n "$autoneg" ] && config+="AutoNegotiation=${autoneg}\n"
    [ -n "$wol" ] && config+="WakeOnLan=${wol}\n"
    [ -n "$mac_policy" ] && config+="MACAddressPolicy=${mac_policy}\n"
    [ -n "$name_policy" ] && config+="NamePolicy=${name_policy}\n"
    [ -n "$mac_addr" ] && config+="MACAddress=${mac_addr}\n"
    printf "%b" "$config"
}

# Gateway/Host/Sharing Config Builder (LAN/Downstream)
build_gateway_config() {
    local iface="$1" ip="$2" share="$3" desc="$4" mdns="${5:-yes}" llmnr="${6:-yes}" ipv6_pd="${7:-yes}"
    if [ "$mdns" == "yes" ] && is_avahi_running; then mdns="no"; fi

    if [ -z "$ip" ]; then
        local detected_ip=""
        if [[ "$iface" == usb* ]] || [[ "$iface" == rndis* ]]; then
             detected_ip=$(_get_system_template_val "70-usb-gadget.network" "Address")
             [ -z "$detected_ip" ] && detected_ip=$(_get_system_template_val "70-br-usb-host.network" "Address")
        elif [[ "$iface" == wlan* ]] && [ "$share" == "true" ]; then
             detected_ip=$(_get_system_template_val "70-wifi-ap.network" "Address")
        fi
        if [ -n "$detected_ip" ]; then ip="$detected_ip"
        else
            if [ "$share" == "true" ]; then ip="${DEFAULT_GW_V4:-192.168.212.1/24}"
            else
                 if [[ "$iface" == usb* ]] || [[ "$iface" == rndis* ]]; then ip="169.254.10.2/24"
                 else ip="169.254.1.1/16" ; fi
            fi
        fi
    fi

    local config="[Match]\nName=${iface}\n\n[Network]\nDescription=${desc}\n"
    config+="MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    [ -n "$ip" ] && config+="Address=${ip}\n"
    config+="LinkLocalAddressing=yes\n"
    
    if [ "$share" == "true" ]; then
        config+="IPForwarding=yes\nIPv6SendRA=yes\n"
        if [ "$ipv6_pd" != "no" ]; then config+="DHCPPrefixDelegation=yes\n"; fi
        config+="Address=fd00:cafe:feed::a7ca:de/64\n"
        config+="DHCPServer=yes\n\n[DHCPServer]\nPoolOffset=100\nEmitDNS=yes\n"
        config+="[IPv6SendRA]\nManaged=no\nOtherConfig=no\n"
    else
        config+="IPv6AcceptRA=no\nDHCPServer=yes\n\n[DHCPServer]\nEmitDNS=yes\nEmitRouter=no\n"
    fi
    printf "%b" "$config"
}
