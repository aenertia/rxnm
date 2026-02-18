# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-config-builder.sh
# PURPOSE: Configuration Templating Engine
# ARCHITECTURE: Logic / Templating
#
# Generates valid systemd-networkd configuration files (.network, .link).
# This file is PURE logic (no side effects, no writes, just string generation).
# -----------------------------------------------------------------------------

# Helper: Reads values from existing system templates if needed
_get_system_template_val() {
    local fname="$1"
    local key="$2"
    local f="/usr/lib/systemd/network/$fname"
    [ -f "$f" ] || return
    while read -r line; do
        if [[ "$line" == "${key}="* ]]; then
             local val="${line#*=}"
             val="${val%%#*}" # Strip comments
             val="${val//[[:space:]]/}" # Strip whitespace
             echo "$val"
             return
        fi
    done < "$f"
}

# Description: Generates the content for a .network file
# Arguments: Named flags (e.g. --match-name eth0 --dhcp yes)
# Refactored for RXNM 1.0.0 to replace positional arguments
build_network_config() {
    # Defaults
    local match_iface=""
    local match_ssid=""
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

    # Argument Parsing
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --match-name) match_iface="$2"; shift 2 ;;
            --match-ssid) match_ssid="$2"; shift 2 ;;
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
            *) 
                # Ignore unknown flags to allow future extension without breaking callers
                shift 
                ;;
        esac
    done

    # Conflict resolution: If Avahi is running, disable networkd's mdns
    if [ "$mdns" == "yes" ] && type is_avahi_running &>/dev/null && is_avahi_running; then
        mdns="no"
    fi

    # [Match] Section
    local config="[Match]\nName=${match_iface}\n"
    [ -n "$match_ssid" ] && config+="SSID=${match_ssid}\n"
    
    # [Link] Section (Configuration applied at link up)
    if [ -n "$mac_policy" ] || [ -n "$mtu" ] || [ -n "$mac_addr" ]; then
        config+="\n[Link]\n"
        [ -n "$mac_policy" ] && config+="MACAddressPolicy=${mac_policy}\n"
        [ -n "$mac_addr" ] && config+="MACAddress=${mac_addr}\n"
        [ -n "$mtu" ] && config+="MTUBytes=${mtu}\n"
    fi

    # [Network] Section (Core settings)
    config+="\n[Network]\n"
    [ -n "$desc" ] && config+="Description=${desc}\n"
    [ -n "$dhcp" ] && config+="DHCP=${dhcp}\n"
    
    # Virtual Memberships
    [ -n "$bridge" ] && config+="Bridge=${bridge}\n"
    [ -n "$bond" ] && config+="Bond=${bond}\n"
    [ -n "$vrf" ] && config+="VRF=${vrf}\n"
    [ -n "$vlan" ] && config+="VLAN=${vlan}\n"
    
    config+="MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    # ConfigureWithoutCarrier helps with virtual/flaky links
    config+="LinkLocalAddressing=yes\nIPv6AcceptRA=yes\nConfigureWithoutCarrier=yes\n"
    
    if [ -n "$ipv6_privacy" ]; then
        config+="IPv6PrivacyExtensions=${ipv6_privacy}\n"
    fi

    # Static Addresses
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
    
    # DHCP Client Options
    if [ "$dhcp" != "no" ] || [ -n "$dhcp_client_id" ]; then
         config+="\n[DHCPv4]\n"
         [ -n "$dhcp_client_id" ] && config+="ClientIdentifier=${dhcp_client_id}\n"
         # Fix: Apply metric to DHCP routes if DHCP is enabled (Valid in DHCPv4 section)
         [ "$dhcp" != "no" ] && [ -n "$metric" ] && config+="RouteMetric=${metric}\n"
    fi
    
    if [ "$ipv6_pd" == "no" ]; then
        config+="\n[DHCPv6]\nUseDelegatedPrefix=no\n"
    fi

    # Static Routes
    if [ -n "$routes" ]; then
        IFS=',' read -ra RTS <<< "$routes"
        for r in "${RTS[@]}"; do
            local r_dest="" r_gw="" r_metric=""
            IFS='@' read -r r_dest r_gw r_metric <<< "$r"
            config+="\n[Route]\nDestination=${r_dest}\n"
            [ -n "$r_gw" ] && config+="Gateway=${r_gw}\n"
            if [ -n "$r_metric" ]; then 
                config+="Metric=${r_metric}\n"
            elif [ -n "$metric" ] && [ "$dhcp" == "no" ]; then 
                # Explicitly inherit base metric for manual static routes
                config+="Metric=${metric}\n"
            fi
        done
    fi

    printf "%b" "$config"
}

# Description: Generates content for a .link file (Hardware/Udev level)
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

# Description: Generates config for AP/Host modes
build_gateway_config() {
    local iface="$1" ip="$2" share="$3" desc="$4" mdns="${5:-yes}" llmnr="${6:-yes}" ipv6_pd="${7:-yes}"
    
    if [ "$mdns" == "yes" ] && type is_avahi_running &>/dev/null && is_avahi_running; then mdns="no"; fi
    
    # Auto-detect IP if missing (useful for usb gadgets)
    if [ -z "$ip" ]; then
        local detected_ip=""
        # REFACTOR: Removed check for legacy bridge template
        if [[ "$iface" == usb* ]] || [[ "$iface" == rndis* ]]; then
             detected_ip=$(_get_system_template_val "70-usb-gadget.network" "Address")
        elif [[ "$iface" == wlan* ]] && [ "$share" == "true" ]; then
             detected_ip=$(_get_system_template_val "71-wifi-ap.network" "Address")
        fi
        
        if [ -n "$detected_ip" ]; then ip="$detected_ip"
        else
            if [ "$share" == "true" ]; then ip="${DEFAULT_GW_V4:-192.168.212.1/24}"
            else
                 # Default for gadgets match templates (High RFC1918)
                 if [[ "$iface" == usb* ]] || [[ "$iface" == rndis* ]]; then ip="192.168.213.1/24"
                 else ip="169.254.1.1/16" ; fi
            fi
        fi
    fi
    
    local config="[Match]\nName=${iface}\n\n[Network]\nDescription=${desc}\n"
    config+="MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    [ -n "$ip" ] && config+="Address=${ip}\n"
    config+="LinkLocalAddressing=yes\nConfigureWithoutCarrier=yes\n"
    
    if [ "$share" == "true" ]; then
        # Router Mode: Forwarding + RA
        config+="IPForwarding=yes\nIPv6SendRA=yes\n"
        if [ "$ipv6_pd" != "no" ]; then config+="DHCPPrefixDelegation=yes\n"; fi
        
        # Local ULA for IPv6
        config+="Address=fd00:cafe:feed::a7ca:de/64\n"
        
        config+="DHCPServer=yes\n\n[DHCPServer]\nPoolOffset=100\nEmitDNS=yes\n"
        config+="[IPv6SendRA]\nManaged=no\nOtherConfig=no\n"
    else
        # Local Mode: No Forwarding
        config+="IPv6AcceptRA=no\nDHCPServer=yes\n\n[DHCPServer]\nEmitDNS=yes\nEmitRouter=no\n"
    fi
    
    printf "%b" "$config"
}
