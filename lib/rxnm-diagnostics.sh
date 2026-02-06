# ==============================================================================
# STATUS & DIAGNOSTICS
# ==============================================================================

action_check_portal() {
    local iface="$1"
    local url="http://connectivitycheck.gstatic.com/generate_204"
    local curl_opts=(-s -o /dev/null -w "%{http_code}" --max-time 5)
    
    if [ -n "$iface" ]; then
        curl_opts+=(--interface "$iface")
    fi
    
    local http_code
    http_code=$(curl "${curl_opts[@]}" "$url" 2>/dev/null || echo "000")
    
    if [ "$http_code" == "204" ]; then
        json_success '{"portal_detected": false, "status": "online"}'
    elif [ "$http_code" == "000" ]; then
        json_success '{"portal_detected": false, "status": "offline"}'
    else
        # Auto-Ack Attempt
        local ack_attempt="failed"
        if curl -L "${curl_opts[@]}" "$url" >/dev/null 2>&1; then
             http_code=$(curl "${curl_opts[@]}" "$url" 2>/dev/null || echo "000")
             if [ "$http_code" == "204" ]; then
                 ack_attempt="success"
             fi
        fi
        
        if [ "$ack_attempt" == "success" ]; then
             json_success '{"portal_detected": true, "auto_ack": true, "status": "online"}'
        else
             json_success '{"portal_detected": true, "auto_ack": false, "status": "portal_locked", "http_code": "'"$http_code"'"}'
        fi
    fi
}

action_check_internet() {
    local curl_fmt="%{http_code}:%{time_total}"
    local target="http://clients3.google.com/generate_204"
    local v4=false v6=false
    
    if ip -4 route show default | grep -q default; then
        local out
        out=$(curl -4 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || true)
        [[ "${out%%:*}" == "204" ]] && v4=true
    fi

    if ip -6 route show default | grep -q default; then
        local out
        out=$(curl -6 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || true)
        [[ "${out%%:*}" == "204" ]] && v6=true
    fi
    
    json_success '{"ipv4": '"$v4"', "ipv6": '"$v6"', "connected": '"$(($v4 || $v6 ? "true" : "false"))"'}'
}

action_status() {
    [ -f "$STORAGE_COUNTRY_FILE" ] && iw reg set "$(cat "$STORAGE_COUNTRY_FILE")" 2>/dev/null
    
    local hostname="ROCKNIX"
    [ -f /etc/hostname ] && read -r hostname < /etc/hostname

    # Use global cached IWD state
    declare -A WIFI_SSID_MAP
    if [ "$IWD_ACTIVE" = true ]; then
        local bus_data
        bus_data=$(busctl call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
        
        while read -r dev_name ssid; do
            [ -n "$dev_name" ] && WIFI_SSID_MAP["$dev_name"]="$ssid"
        done < <(echo "$bus_data" | jq -r '
            .data[] | to_entries[] | select(.value["net.connman.iwd.Network"] != null) 
            | select(.value["net.connman.iwd.Network"].Connected.data == true)
            | .value as $net 
            | ($net["net.connman.iwd.Network"].Device.data) as $dev_path
            | .data[0][$dev_path]["net.connman.iwd.Device"].Name.data + " " + $net["net.connman.iwd.Network"].Name.data
        ' 2>/dev/null)
    fi

    declare -A IP_MAP
    # Optimization: Use readarray and read directly into vars to avoid subshells in loop
    readarray -t ip_lines < <(ip -o -4 addr show)
    for line in "${ip_lines[@]}"; do
        # Format: 2: wlan0    inet 192.168.1.1/24 ...
        read -r _ iface_name _ ip_addr _ <<< "$line"
        IP_MAP["$iface_name"]="${ip_addr%/*}"
    done

    declare -A GW_MAP
    # Optimization: Bash array split with read for faster parsing
    readarray -t gw_lines < <(ip -4 route show default)
    for line in "${gw_lines[@]}"; do
        # Format: default via 192.168.1.1 dev eth0 proto dhcp ...
        read -r _ _ gw_addr _ gw_dev _ <<< "$line"
        GW_MAP["$gw_dev"]="$gw_addr"
    done

    local global_proxy_json=$(get_proxy_json "$STORAGE_PROXY_GLOBAL")
    local -a json_ifaces=()

    # Optimization: Iterate glob directly to avoid spawning subshell ls/find
    for iface_path in /sys/class/net/*; do
        local iface=${iface_path##*/}
        [[ "$iface" == "lo" || "$iface" == "sit0" ]] && continue
        
        local ip="${IP_MAP[$iface]:-}"
        local gw="${GW_MAP[$iface]:-}"
        
        # Optimization: Batch sysfs reads in one subshell
        local mac=""
        read -r mac < "$iface_path/address" 2>/dev/null || mac=""
        
        local connected="false"; [ -n "$ip" ] && connected="true"
        local type="ethernet"

        # Optimization: Heuristic type detection (fast path)
        case "$iface" in
            wlan*|wlp*)
                type="wifi" ;;
            br*)
                [ -d "$iface_path/bridge" ] && type="bridge" || type="ethernet" ;;
            wg*)
                type="vpn" ;;
            usb*|rndis*)
                type="gadget" ;;
            bnep*)
                type="bluetooth_pan" ;;
            tun*|tap*)
                type="tun" ;;
            *)
                # Slow path: check filesystem
                if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
                    type="wifi"
                elif [ -d "$iface_path/bridge" ]; then
                    type="bridge"
                elif [ -f "$iface_path/tun_flags" ]; then
                    type="tun"
                else
                    type="ethernet"
                fi
                ;;
        esac
        
        local ssid=""
        if [ "$type" == "wifi" ]; then
             ssid="${WIFI_SSID_MAP[$iface]:-}"
             if [ -z "$ssid" ]; then
                 # Optimization: Avoid double call to iwctl
                 if [ "$IWD_ACTIVE" = true ]; then
                     local ap_output
                     ap_output=$(iwctl ap "$iface" show 2>/dev/null)
                     if grep -q "Started" <<< "$ap_output"; then
                         type="wifi_ap"
                         ssid=$(awk '/Started/{print $2}' <<< "$ap_output")
                     fi
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
        
        local safe_ssid="null"
        if [ -n "$ssid" ]; then
            # Optimization: Bash parameter expansion for escaping
            safe_ssid="\"${ssid//\"/\\\"}\""
        fi
        
        # Optimization: Accumulate array items instead of string concatenation
        json_ifaces+=("\"$iface\":{\"type\":\"$type\",\"ip\":\"$ip\",\"mac\":\"$mac\",\"connected\":$connected,\"ssid\":$safe_ssid,\"gateway\":\"$gw\",\"config\":\"$cfg_mode\",\"proxy\":$iface_proxy_json}")
    done
    
    # Optimization: Join array at end
    local json_ifaces_str
    json_ifaces_str=$(IFS=,; echo "${json_ifaces[*]}")
    
    echo "{\"hostname\":\"$hostname\",\"global_proxy\":$global_proxy_json,\"interfaces\":{$json_ifaces_str}}" | jq .
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
  --password <pass>         WiFi passphrase or AP password
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

Examples:
  # Scan WiFi
  rxnm scan --interface wlan0

  # Connect with WPS (Push Button)
  rxnm wps --interface wlan0

  # Create Bond (Active-Backup)
  rxnm create-bond --name bond0 --mode active-backup
  rxnm set-bond-slave --interface eth0 --bond bond0

  # Connect to WireGuard
  rxnm connect-wireguard --name wg0 --address 10.100.0.2/24 \\
    --private-key "S3cret..." --peer-key "PubK3y..." --endpoint "vpn.example.com:51820"

EOF
}
