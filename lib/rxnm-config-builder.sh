# ==============================================================================
# NETWORK CONFIGURATION BUILDERS
# ==============================================================================

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

    # Intelligent conflict avoidance:
    if [ "$mdns" == "yes" ] && is_avahi_running; then
        mdns="no"
    fi

    local config="[Match]\nName=${match_iface}\n"
    [ -n "$match_ssid" ] && config+="SSID=${match_ssid}\n"
    
    if [ -n "$mac_policy" ]; then
        config+="\n[Link]\nMACAddressPolicy=${mac_policy}\n"
    fi
    
    config+="\n[Network]\n"
    [ -n "$desc" ] && config+="Description=${desc}\n"
    [ -n "$dhcp" ] && config+="DHCP=${dhcp}\n"
    [ -n "$bridge" ] && config+="Bridge=${bridge}\n"
    [ -n "$bond" ] && config+="Bond=${bond}\n"
    [ -n "$vrf" ] && config+="VRF=${vrf}\n"
    [ -n "$vlan" ] && config+="VLAN=${vlan}\n"
    
    # Metric setting (applies to DHCP and static routes in [Network] context)
    [ -n "$metric" ] && config+="RouteMetric=${metric}\n"
    
    # mDNS and LLMNR controls
    config+="MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    
    # Fix: IPMasquerade=yes is deprecated. Use "ipv4" to satisfy systemd-networkd warnings.
    # RFC Compliance: LinkLocalAddressing=yes enables both IPv4LL (169.254/16) and IPv6LL (fe80::/10)
    config+="LinkLocalAddressing=yes\nIPv6AcceptRA=yes\nIPMasquerade=ipv4\n"

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
    
    if [ -n "$routes" ]; then
        IFS=',' read -ra RTS <<< "$routes"
        for r in "${RTS[@]}"; do
            if [[ "$r" == *":"* ]]; then
                local dest="${r%%:*}"
                local rgw="${r#*:}"
                config+="\n[Route]\nDestination=${dest}\nGateway=${rgw}\n"
                [ -n "$metric" ] && config+="Metric=${metric}\n"
            else
                config+="\n[Route]\nDestination=${r}\n"
                [ -n "$metric" ] && config+="Metric=${metric}\n"
            fi
        done
    fi

    printf "%b" "$config"
}

# Gateway/Host/Sharing Config Builder (LAN/Downstream)
build_gateway_config() {
    local iface="$1"
    local ip="$2"
    local share="$3"
    local desc="$4"
    local mdns="${5:-yes}"
    local llmnr="${6:-yes}"
    
    if [ "$mdns" == "yes" ] && is_avahi_running; then
        mdns="no"
    fi

    # Auto-IP Strategy
    if [ -z "$ip" ]; then
        if [ "$share" == "true" ]; then
             # Use configured default or fall back to original RXNM default (192.168.212.1/24)
             # This avoids common conflicts (0.1, 1.1, 8.1, 42.1, 100.1, 254.1)
             ip="${DEFAULT_GW_V4:-192.168.212.1/24}"
        else
             # Local/No-Share: Link Local strategy
             if [[ "$iface" == usb* ]] || [[ "$iface" == rndis* ]]; then
                 # RFC 3927: Avoid 169.254.0.0/24 and 169.254.255.0/24
                 ip="169.254.10.2/24"
             else
                 ip="169.254.1.1/16" 
             fi
        fi
    fi

    local config="[Match]\nName=${iface}\n\n[Network]\nDescription=${desc}\n"
    config+="MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    
    [ -n "$ip" ] && config+="Address=${ip}\n"
    
    # Ensure IPv6 Link Local is ALWAYS enabled (RFC Compliance)
    config+="LinkLocalAddressing=yes\n"
    
    if [ "$share" == "true" ]; then
        # --- SHARING ENABLED (Gateway/Router) ---
        config+="IPForwarding=yes\n"
        config+="IPv6SendRA=yes\nDHCPPrefixDelegation=yes\n"
        
        # Add a stable ULA Address for isolated IPv6 connectivity (RFC 4193)
        # This ensures local IPv6 reachability even without upstream PD
        # Suffix "arcade" in hexspeak: a7ca:de
        config+="Address=fd00:cafe:feed::a7ca:de/64\n"
        
        config+="DHCPServer=yes\n\n[DHCPServer]\nPoolOffset=100\nEmitDNS=yes\n"
        config+="[IPv6SendRA]\nManaged=no\nOtherConfig=no\n"
    else
        # --- SHARING DISABLED (Local/Link-Local) ---
        config+="IPv6AcceptRA=no\n" # We are not a client on this isolated link
        config+="DHCPServer=yes\n\n[DHCPServer]\n"
        config+="EmitDNS=yes\n"
        config+="EmitRouter=no\n"
    fi
    
    printf "%b" "$config"
}
