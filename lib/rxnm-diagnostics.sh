# ==============================================================================
# REFINED STATUS & DIAGNOSTICS
# ==============================================================================

# Optimized action_check_portal to minimize outbound traffic and latency.
# Logic: Fast-check first -> Portal check only on failure -> Sequential fallback.
action_check_portal() {
    local iface="$1"
    local primary_url="http://connectivitycheck.gstatic.com/generate_204"
    local fallback_urls=(
        "http://nmcheck.gnome.org/check_network_status.txt"
        "http://detectportal.firefox.com/success.txt"
    )
    
    # 1. TIER 1: FAST CHECK (Primary URL, No Redirects)
    # We use -L- but start with a check that expects a 204.
    local curl_base_opts=(-s -o /dev/null --max-time 3)
    [ -n "$iface" ] && curl_base_opts+=(--interface "$iface")

    # Quick probe: Is the internet just "working"?
    if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
        json_success '{"portal_detected": false, "status": "online", "method": "fast_path"}'
        return 0
    fi

    # 2. TIER 2: PORTAL DETECTION (Follow Redirects)
    # Only run if the fast path failed. We check the primary URL again with redirect tracking.
    # The -L flag effectively "visits" the portal page, which for some simple gateways
    # is enough to authorize the session ("View to connect").
    local portal_opts=("${curl_base_opts[@]}" -L -w "%{http_code}:%{url_effective}")
    local result
    result=$(curl "${portal_opts[@]}" "$primary_url" 2>/dev/null || echo "000:$primary_url")
    
    local code="${result%%:*}"
    local effective_url="${result#*:}"

    # CASE A: Late Success (Tier 1 failed, but Tier 2 got the 204)
    # This happens if the redirect chain eventually leads back to the success page.
    if [[ "$code" == "204" ]] && [[ "$effective_url" == "$primary_url" ]]; then
        json_success '{"portal_detected": false, "status": "online", "method": "tier2_check"}'
        return 0
    fi

    # CASE B: Redirect Detected (Standard Portal) OR DNS Hijack (Code != 204)
    if [[ "$effective_url" != "$primary_url" ]] || [[ "$code" != "204" && "$code" != "000" ]]; then
        
        # --- POST-INTERACTION VERIFICATION ---
        # We just visited the portal page via curl -L. For simple "click-through" or 
        # "view-through" portals, this might have been enough to authorize the MAC.
        # We try the fast check ONE more time to see if we are now online.
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
             json_success "{\"portal_detected\": true, \"auto_ack\": true, \"status\": \"online\", \"target\": \"$effective_url\", \"note\": \"authorized_by_probe\"}"
             return 0
        fi

        # If still not 204, we are truly locked behind the portal.
        local hijack_flag="false"
        if [[ "$effective_url" == "$primary_url" ]]; then hijack_flag="true"; fi

        json_success "{\"portal_detected\": true, \"auto_ack\": false, \"status\": \"portal_locked\", \"target\": \"$effective_url\", \"http_code\": \"$code\", \"hijacked\": $hijack_flag}"
        return 0
    fi

    # 3. TIER 3: SEQUENTIAL FALLBACK (Avoid Regional Outages)
    # If the primary check failed entirely (000/Timeout), try secondary hosts one-by-one.
    for fallback in "${fallback_urls[@]}"; do
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$fallback" 2>/dev/null | grep -qE "200|204"; then
            json_success "{\"portal_detected\": false, \"status\": \"online\", \"method\": \"fallback\", \"host\": \"$fallback\"}"
            return 0
        fi
    done

    # If everything failed
    json_success '{"portal_detected": false, "status": "offline"}'
}

action_check_internet() {
    local curl_fmt="%{http_code}:%{time_total}"
    local target="http://clients3.google.com/generate_204"
    local v4="false" v6="false"
    local out4="" out6=""
    
    if ip -4 route show default | grep -q default; then
        out4=$(curl -4 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000:0")
        [[ "${out4%%:*}" == "204" ]] && v4="true"
    fi

    if ip -6 route show default | grep -q default; then
        out6=$(curl -6 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000:0")
        [[ "${out6%%:*}" == "204" ]] && v6="true"
    fi
    
    local connected="false"
    [[ "$v4" == "true" || "$v6" == "true" ]] && connected="true"
    
    json_success '{"ipv4": '"$v4"', "ipv6": '"$v6"', "connected": '"$connected"'}'
}

action_status() {
    local filter_iface="${1:-}"
    [ -f "$STORAGE_COUNTRY_FILE" ] && iw reg set "$(cat "$STORAGE_COUNTRY_FILE")" 2>/dev/null || true
    
    local hostname="ROCKNIX"
    if [ -f /etc/hostname ]; then
        read -r hostname < /etc/hostname || true
    fi

    declare -A WIFI_SSID_MAP
    if is_service_active "iwd"; then
        local bus_data
        bus_data=$(busctl call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null || echo "")
        
        if [ -n "$bus_data" ]; then
            while read -r dev_name ssid; do
                [ -n "$dev_name" ] && WIFI_SSID_MAP["$dev_name"]="$ssid"
            done < <(echo "$bus_data" | jq -r '
                .data[] | to_entries[] | select(.value["net.connman.iwd.Network"] != null) 
                | select(.value["net.connman.iwd.Network"].Connected.data == true)
                | .value as $net 
                | ($net["net.connman.iwd.Network"].Device.data) as $dev_path
                | .data[0][$dev_path]["net.connman.iwd.Device"].Name.data + " " + $net["net.connman.iwd.Network"].Name.data
            ' 2>/dev/null || true)
        fi
    fi

    declare -A IP_MAP
    declare -A IPV6_MAP
    while read -r _ iface_name family ip_addr _; do
        if [[ "$family" == "inet" ]]; then
             IP_MAP["$iface_name"]="${ip_addr%/*}"
        elif [[ "$family" == "inet6" ]]; then
             IPV6_MAP["$iface_name"]="${IPV6_MAP[$iface_name]:-}${ip_addr%/*},"
        fi
    done < <(ip -o addr show 2>/dev/null || true)

    declare -A GW_MAP
    while read -r _ _ gw_addr _ gw_dev _ ; do
        if [ -n "$gw_dev" ]; then
            GW_MAP["$gw_dev"]="$gw_addr"
        fi
    done < <(ip -4 route show default 2>/dev/null || true)

    local global_proxy_json
    global_proxy_json=$(get_proxy_json "$STORAGE_PROXY_GLOBAL")
    
    local -a json_objects=()
    local ifaces=(/sys/class/net/*)
    for iface_path in "${ifaces[@]}"; do
        local iface=${iface_path##*/}
        [[ "$iface" == "lo" || "$iface" == "sit0" || "$iface" == "*" ]] && continue
        
        # Performance optimization: skip processing if we are filtering for a specific interface
        if [ -n "$filter_iface" ] && [ "$iface" != "$filter_iface" ]; then
            continue
        fi

        local ip="${IP_MAP[$iface]:-}"
        local ipv6_csv="${IPV6_MAP[$iface]:-}"
        local gw="${GW_MAP[$iface]:-}"
        local mac=""
        if [ -f "$iface_path/address" ]; then
            read -r mac < "$iface_path/address" || mac=""
        fi
        
        local connected="false"; [ -n "$ip" ] || [ -n "$ipv6_csv" ] && connected="true"
        
        local type="ethernet"
        case "$iface" in
            wlan*|wlp*) type="wifi" ;;
            br*) [ -d "$iface_path/bridge" ] && type="bridge" || type="ethernet" ;;
            wg*) type="vpn" ;;
            usb*|rndis*) type="gadget" ;;
            bnep*) type="bluetooth_pan" ;;
            tun*|tap*) type="tun" ;;
            *)
                if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
                    type="wifi"
                elif [ -d "$iface_path/bridge" ]; then
                    type="bridge"
                else
                    type="ethernet"
                fi
                ;;
        esac
        
        local ssid=""
        local channel=""
        local frequency=""
        if [ "$type" == "wifi" ]; then
             ssid="${WIFI_SSID_MAP[$iface]:-}"
             if command -v iw >/dev/null; then
                 local iw_info
                 iw_info=$(iw dev "$iface" info 2>/dev/null || true)
                 if [[ "$iw_info" =~ channel\ ([0-9]+)\ \(([0-9]+)\ MHz\) ]]; then
                     channel="${BASH_REMATCH[1]}"
                     frequency="${BASH_REMATCH[2]}"
                 fi
             fi
             if [ -z "$ssid" ] && is_service_active "iwd"; then
                 local ap_output
                 ap_output=$(iwctl ap "$iface" show 2>/dev/null || echo "")
                 if grep -q "Started" <<< "$ap_output"; then
                     type="wifi_ap"
                     ssid=$(awk '/Started/{print $2}' <<< "$ap_output")
                 fi
             fi
        fi

        local cfg_mode="dhcp"
        if [ -f "${STORAGE_NET_DIR}/75-config-${iface}.network" ]; then 
            if grep -q "Address=" "${STORAGE_NET_DIR}/75-config-${iface}.network"; then cfg_mode="static"; fi
        fi
        
        local iface_proxy_json="null"
        if [ -f "${STORAGE_NET_DIR}/proxy-${iface}.conf" ]; then
            iface_proxy_json=$(get_proxy_json "${STORAGE_NET_DIR}/proxy-${iface}.conf")
        fi
        
        local ipv6_json="[]"
        if [ -n "$ipv6_csv" ]; then
            ipv6_csv="${ipv6_csv%,}"
            ipv6_json=$(jq -n -R 'split(",")' <<< "$ipv6_csv")
        fi

        local json_obj
        json_obj=$(jq -n \
            --arg name "$iface" \
            --arg type "$type" \
            --arg ip "$ip" \
            --argjson ipv6 "$ipv6_json" \
            --arg mac "$mac" \
            --argjson connected "$connected" \
            --arg ssid "$ssid" \
            --arg channel "$channel" \
            --arg freq "$frequency" \
            --arg gw "$gw" \
            --arg config "$cfg_mode" \
            --argjson proxy "$iface_proxy_json" \
            '{name: $name, type: $type, ip: $ip, ipv6: $ipv6, mac: $mac, connected: $connected, ssid: (if $ssid=="" then null else $ssid end), channel: (if $channel=="" then null else $channel end), frequency: (if $freq=="" then null else $freq end), gateway: $gw, config: $config, proxy: $proxy}')
            
        json_objects+=("$json_obj")
    done
    
    local json_ifaces_array="[]"
    if [ ${#json_objects[@]} -gt 0 ]; then
        json_ifaces_array=$(printf '%s\n' "${json_objects[@]}" | jq -s '.')
    fi
    
    jq -n \
        --arg hn "$hostname" \
        --arg filter "$filter_iface" \
        --argjson gp "$global_proxy_json" \
        --argjson ifs "$json_ifaces_array" \
        '{
            success: true, 
            hostname: $hn, 
            global_proxy: $gp, 
            interfaces: (
                if ($ifs != null and ($ifs | length) > 0) then 
                    ($ifs | map({(.name): .}) | add // {}) 
                else {} end
            )
        }'
}

action_help() {
    cat <<EOF
ROCKNIX Network Manager
Usage: rocknix-network-manager [COMMAND] [OPTIONS]
Short: rxnm [COMMAND] [OPTIONS]

Core Commands:
  status                    Show current network status (JSON output)
  scan                      Scan for WiFi networks
  connect                   Connect to a WiFi network
  disconnect                Disconnect/Forget current WiFi connection
  check-internet            Check internet connectivity (IPv4/IPv6)
  check-portal              Check for captive portal and attempt simple auto-ack
  wps                       Start WiFi Protected Setup (Push Button)
  forget                    Forget a known WiFi network and remove configs

Configuration:
  set-dhcp                  Set interface to DHCP mode (enables mDNS/LLMNR)
  set-static                Set interface to Static IP (enables mDNS/LLMNR)
  set-country               Set WiFi regulatory domain (Country Code)
  set-proxy                 Set global or interface proxy
  set-link                  Toggle IPv4/IPv6 link local protocols

Hotspot & Tethering:
  host                      Start WiFi Access Point (AP) or Ad-Hoc mode
  client                    Revert WiFi interface to Client/Station mode
  pan-net                   Manage Bluetooth PAN (Tethering)

Virtual Devices:
  create-bridge             Create a network bridge
  create-bond               Create a network bond
  create-vlan               Create a VLAN interface
  connect-wireguard         Create a WireGuard client interface
  set-member                Add interface to a bridge
  set-bond-slave            Add interface to a bond
  delete-link               Delete a virtual interface

Profiles:
  profile save              Save current interface config as a named profile
  profile load              Load a named profile
  profile list              List available profiles

Options:
  --interface <iface>       Target interface (e.g., wlan0, eth0)
  --ssid <ssid>             SSID for connection or AP
  --password <pass>         WiFi passphrase (Legacy, use --password-stdin preferred)
  --password-stdin          Read password from standard input
  --password-file <file>    Read password from a specific file
  --ip <ip/cidr>            Static IP address (e.g., 192.168.1.10/24)
  --gateway <ip>            Gateway IP
  --dns <ip,ip>             Comma-separated DNS servers
  --hidden                  Connect to hidden network
  --share                   Enable NAT/Masquerading (for 'host' or 'pan-net')
  --mdns <yes/no>           Enable MulticastDNS (default: yes)
  --llmnr <yes/no>          Enable LLMNR (default: yes)
  --bond <name>             Target bond interface (e.g., bond0)
  
  # WireGuard Options
  --private-key <key>       WireGuard Private Key
  --peer-key <key>          WireGuard Peer Public Key
  --endpoint <ip:port>      WireGuard Endpoint
  --allowed-ips <cidrs>     Allowed IPs (default: 0.0.0.0/0)
EOF
}
