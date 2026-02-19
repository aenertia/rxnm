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
    
    # POSIX read loop
    while IFS= read -r line; do
        case "$line" in
            "${key}="*)
                local val="${line#*=}"
                val="${val%%#*}" # Strip comments
                # Strip whitespace (POSIX compatible)
                val="$(echo "$val" | tr -d '[:space:]')"
                echo "$val"
                return
                ;;
        esac
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
    while [ "$#" -gt 0 ]; do
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
    # Check type exists first to avoid 'not found' errors in some shells
    if [ "$mdns" = "yes" ] && command -v is_avahi_running >/dev/null 2>&1 && is_avahi_running; then
        mdns="no"
    fi

    # [Match] Section
    local config="[Match]\nName=${match_iface}\n"
    [ -n "$match_ssid" ] && config="${config}SSID=${match_ssid}\n"
    
    # [Link] Section (Configuration applied at link up)
    if [ -n "$mac_policy" ] || [ -n "$mtu" ] || [ -n "$mac_addr" ]; then
        config="${config}\n[Link]\n"
        [ -n "$mac_policy" ] && config="${config}MACAddressPolicy=${mac_policy}\n"
        [ -n "$mac_addr" ] && config="${config}MACAddress=${mac_addr}\n"
        [ -n "$mtu" ] && config="${config}MTUBytes=${mtu}\n"
    fi

    # [Network] Section (Core settings)
    config="${config}\n[Network]\n"
    [ -n "$desc" ] && config="${config}Description=${desc}\n"
    [ -n "$dhcp" ] && config="${config}DHCP=${dhcp}\n"
    
    # Virtual Memberships
    [ -n "$bridge" ] && config="${config}Bridge=${bridge}\n"
    [ -n "$bond" ] && config="${config}Bond=${bond}\n"
    [ -n "$vrf" ] && config="${config}VRF=${vrf}\n"
    [ -n "$vlan" ] && config="${config}VLAN=${vlan}\n"
    
    config="${config}MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    # ConfigureWithoutCarrier helps with virtual/flaky links
    config="${config}LinkLocalAddressing=yes\nIPv6AcceptRA=yes\nConfigureWithoutCarrier=yes\n"
    
    if [ -n "$ipv6_privacy" ]; then
        config="${config}IPv6PrivacyExtensions=${ipv6_privacy}\n"
    fi

    # Static Addresses - POSIX array emulation
    if [ -n "$addresses" ]; then
        # Save IFS
        old_ifs="$IFS"
        IFS=','
        # Word splitting expansion
        set -- $addresses
        IFS="$old_ifs"
        for addr do
            config="${config}Address=${addr}\n"
        done
    fi
    
    if [ -n "$gateway" ]; then
        config="${config}Gateway=${gateway}\n"
    fi
    
    if [ -n "$dns_servers" ]; then
        old_ifs="$IFS"
        IFS=','
        set -- $dns_servers
        IFS="$old_ifs"
        for d do
            config="${config}DNS=${d}\n"
        done
    fi
    
    if [ -n "$domains" ]; then
        old_ifs="$IFS"
        IFS=','
        set -- $domains
        IFS="$old_ifs"
        for d do
            config="${config}Domains=${d}\n"
        done
    fi
    
    # DHCP Client Options
    if [ "$dhcp" != "no" ] || [ -n "$dhcp_client_id" ]; then
         config="${config}\n[DHCPv4]\n"
         [ -n "$dhcp_client_id" ] && config="${config}ClientIdentifier=${dhcp_client_id}\n"
         # Fix: Apply metric to DHCP routes if DHCP is enabled (Valid in DHCPv4 section)
         [ "$dhcp" != "no" ] && [ -n "$metric" ] && config="${config}RouteMetric=${metric}\n"
    fi
    
    if [ "$ipv6_pd" = "no" ]; then
        config="${config}\n[DHCPv6]\nUseDelegatedPrefix=no\n"
    fi

    # Static Routes
    if [ -n "$routes" ]; then
        old_ifs="$IFS"
        IFS=','
        set -- $routes
        IFS="$old_ifs"
        
        for r do
            local r_dest="" r_gw="" r_metric=""
            # POSIX split on @ using cut (safer than read)
            r_dest=$(echo "$r" | cut -d'@' -f1)
            r_gw=$(echo "$r" | cut -d'@' -f2 -s) # -s to only output if delimiter found
            r_metric=$(echo "$r" | cut -d'@' -f3 -s)
            
            # If no @ found, dest is the whole string
            [ -z "$r_dest" ] && r_dest="$r"
            
            config="${config}\n[Route]\nDestination=${r_dest}\n"
            [ -n "$r_gw" ] && config="${config}Gateway=${r_gw}\n"
            if [ -n "$r_metric" ]; then 
                config="${config}Metric=${r_metric}\n"
            elif [ -n "$metric" ] && [ "$dhcp" = "no" ]; then 
                # Explicitly inherit base metric for manual static routes
                config="${config}Metric=${metric}\n"
            fi
        done
    fi

    printf "%b" "$config"
}

# Description: Generates content for a .link file (Hardware/Udev level)
build_device_link_config() {
    local iface="$1" speed="$2" duplex="$3" autoneg="$4" wol="$5" mac_policy="$6" name_policy="$7" mac_addr="$8"
    
    local config="[Match]\nOriginalName=${iface}\n"
    config="${config}\n[Link]\nDescription=RXNM Hardware Config\n"
    
    [ -n "$speed" ] && config="${config}BitsPerSecond=${speed}M\n"
    [ -n "$duplex" ] && config="${config}Duplex=${duplex}\n"
    [ -n "$autoneg" ] && config="${config}AutoNegotiation=${autoneg}\n"
    [ -n "$wol" ] && config="${config}WakeOnLan=${wol}\n"
    [ -n "$mac_policy" ] && config="${config}MACAddressPolicy=${mac_policy}\n"
    [ -n "$name_policy" ] && config="${config}NamePolicy=${name_policy}\n"
    [ -n "$mac_addr" ] && config="${config}MACAddress=${mac_addr}\n"
    
    printf "%b" "$config"
}

# Description: Generates config for AP/Host modes
build_gateway_config() {
    local iface="$1" ip="$2" share="$3" desc="$4" mdns="${5:-yes}" llmnr="${6:-yes}" ipv6_pd="${7:-yes}"
    
    if [ "$mdns" = "yes" ] && command -v is_avahi_running >/dev/null 2>&1 && is_avahi_running; then mdns="no"; fi
    
    # Auto-detect IP if missing (useful for usb gadgets)
    if [ -z "$ip" ]; then
        local detected_ip=""
        # REFACTOR: Removed check for legacy bridge template
        # Use case instead of [[ == ]]
        case "$iface" in
            usb*|rndis*)
                 detected_ip=$(_get_system_template_val "70-usb-gadget.network" "Address")
                 ;;
            wlan*)
                 if [ "$share" = "true" ]; then
                     detected_ip=$(_get_system_template_val "71-wifi-ap.network" "Address")
                 fi
                 ;;
        esac
        
        if [ -n "$detected_ip" ]; then ip="$detected_ip"
        else
            if [ "$share" = "true" ]; then ip="${DEFAULT_GW_V4:-192.168.212.1/24}"
            else
                 # Default for gadgets match templates (High RFC1918)
                 case "$iface" in
                    usb*|rndis*) ip="192.168.213.1/24" ;;
                    *) ip="169.254.1.1/16" ;;
                 esac
            fi
        fi
    fi
    
    local config="[Match]\nName=${iface}\n\n[Network]\nDescription=${desc}\n"
    config="${config}MulticastDNS=${mdns}\nLLMNR=${llmnr}\n"
    [ -n "$ip" ] && config="${config}Address=${ip}\n"
    config="${config}LinkLocalAddressing=yes\nConfigureWithoutCarrier=yes\n"
    
    if [ "$share" = "true" ]; then
        # Router Mode: Forwarding + RA
        config="${config}IPForwarding=yes\nIPv6SendRA=yes\n"
        if [ "$ipv6_pd" != "no" ]; then config="${config}DHCPPrefixDelegation=yes\n"; fi
        
        # Local ULA for IPv6
        config="${config}Address=fd00:cafe:feed::a7ca:de/64\n"
        
        config="${config}DHCPServer=yes\n\n[DHCPServer]\nPoolOffset=100\nEmitDNS=yes\n"
        config="${config}[IPv6SendRA]\nManaged=no\nOtherConfig=no\n"
    else
        # Local Mode: No Forwarding
        config="${config}IPv6AcceptRA=no\nDHCPServer=yes\n\n[DHCPServer]\nEmitDNS=yes\nEmitRouter=no\n"
    fi
    
    printf "%b" "$config"
}
