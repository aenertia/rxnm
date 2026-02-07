# ==============================================================================
# REFINED STATUS & DIAGNOSTICS
# ==============================================================================

# Optimized action_check_portal to minimize outbound traffic and latency.
action_check_portal() {
    local iface="$1"
    local primary_url="http://connectivitycheck.gstatic.com/generate_204"
    local fallback_urls=(
        "http://nmcheck.gnome.org/check_network_status.txt"
        "http://detectportal.firefox.com/success.txt"
    )
    
    # 1. TIER 1: FAST CHECK (Primary URL, No Redirects)
    local curl_base_opts=(-s -o /dev/null --max-time 3)
    [ -n "$iface" ] && curl_base_opts+=(--interface "$iface")

    # Quick probe: Is the internet just "working"?
    if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
        json_success '{"portal_detected": false, "status": "online", "method": "fast_path"}'
        return 0
    fi

    # 2. TIER 2: PORTAL DETECTION (Follow Redirects)
    local portal_opts=("${curl_base_opts[@]}" -L -w "%{http_code}:%{url_effective}")
    local result
    result=$(curl "${portal_opts[@]}" "$primary_url" 2>/dev/null || echo "000:$primary_url")
    
    local code="${result%%:*}"
    local effective_url="${result#*:}"

    if [[ "$code" == "204" ]] && [[ "$effective_url" == "$primary_url" ]]; then
        json_success '{"portal_detected": false, "status": "online", "method": "tier2_check"}'
        return 0
    fi

    if [[ "$effective_url" != "$primary_url" ]] || [[ "$code" != "204" && "$code" != "000" ]]; then
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
             json_success "{\"portal_detected\": true, \"auto_ack\": true, \"status\": \"online\", \"target\": \"$effective_url\", \"note\": \"authorized_by_probe\"}"
             return 0
        fi
        local hijack_flag="false"
        if [[ "$effective_url" == "$primary_url" ]]; then hijack_flag="true"; fi
        json_success "{\"portal_detected\": true, \"auto_ack\": false, \"status\": \"portal_locked\", \"target\": \"$effective_url\", \"http_code\": \"$code\", \"hijacked\": $hijack_flag}"
        return 0
    fi

    # 3. TIER 3: SEQUENTIAL FALLBACK
    for fallback in "${fallback_urls[@]}"; do
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$fallback" 2>/dev/null | grep -qE "200|204"; then
            json_success "{\"portal_detected\": false, "status": "online", "method": "fallback", "host": "$fallback"}"
            return 0
        fi
    done

    json_success '{"portal_detected": false, "status": "offline"}'
}

action_check_internet() {
    # 0. TIER 0: NETWORKCTL STATUS (FASTEST)
    if command -v networkctl >/dev/null; then
         local operstate
         operstate=$(networkctl status 2>/dev/null | grep "Overall State" | awk '{print $3}')
         case "$operstate" in
            off|no-carrier|dormant|carrier)
                json_success '{"ipv4": false, "ipv6": false, "connected": false, "reason": "local_link_down", "state": "'"$operstate"'"}'
                return 0
                ;;
            routable|online)
                ;;
         esac
    fi

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

# Estimate Signal Quality from RSSI
get_signal_quality() {
    local rssi="$1"
    [ -z "$rssi" ] && echo "unknown" && return
    
    # -30 dBm = excellent, -67 dBm = good, -70 dBm = fair, -80 dBm = poor
    if [ "$rssi" -gt -50 ]; then echo "excellent";
    elif [ "$rssi" -gt -67 ]; then echo "good";
    elif [ "$rssi" -gt -70 ]; then echo "fair";
    else echo "poor"; fi
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

    # Optimization: Batch WiFi Info
    declare -A WIFI_CHANNEL_MAP
    declare -A WIFI_FREQ_MAP
    declare -A WIFI_RSSI_MAP
    if command -v iw >/dev/null 2>&1; then
        # Parse 'iw dev' output once
        while read -r iface_name chan freq; do
            WIFI_CHANNEL_MAP["$iface_name"]="$chan"
            WIFI_FREQ_MAP["$iface_name"]="$freq"
        done < <(iw dev 2>/dev/null | awk '
            /Interface/ {iface=$2}
            /channel/ {print iface, $2, $4; iface=""}
        ')
        
        # Parse station dump for RSSI (one call per iface is unavoidable if connected, but we can skip unrelated)
    fi

    declare -A IP_MAP
    declare -A IPV6_MAP
    
    # Optimization: Filter IP check if specific interface requested
    local ip_cmd_args=(-o addr show)
    [ -n "$filter_iface" ] && ip_cmd_args+=(dev "$filter_iface")
    
    while read -r _ iface_name family ip_addr _; do
        if [[ "$family" == "inet" ]]; then
             IP_MAP["$iface_name"]="${ip_addr%/*}"
        elif [[ "$family" == "inet6" ]]; then
             IPV6_MAP["$iface_name"]+="${IPV6_MAP[$iface_name]:+,}${ip_addr%/*}"
        fi
    done < <(ip "${ip_cmd_args[@]}" 2>/dev/null || true)

    declare -A GW_MAP
    while read -r _ _ gw_addr _ gw_dev _ ; do
        if [ -n "$gw_dev" ]; then
            GW_MAP["$gw_dev"]="$gw_addr"
        fi
    done < <(ip -4 route show default 2>/dev/null || true)

    # Detect Bridge members with safe globbing (no ls)
    declare -A BRIDGE_MEMBERS
    for br in /sys/class/net/*/bridge; do
        [ -e "$br" ] || continue
        local br_iface
        br_iface=$(basename "$(dirname "$br")")
        local members_list=""
        for m in "$br/../brif/"*; do
            [ -e "$m" ] || continue
            members_list+="${members_list:+,}$(basename "$m")"
        done
        if [ -n "$members_list" ]; then
            BRIDGE_MEMBERS["$br_iface"]="$members_list"
        fi
    done

    local global_proxy_json
    global_proxy_json=$(get_proxy_json "$STORAGE_PROXY_GLOBAL")
    
    # Memory Optimization: Use array instead of string concatenation
    local iface_json_array=()
    
    local ifaces=(/sys/class/net/*)
    for iface_path in "${ifaces[@]}"; do
        local iface=${iface_path##*/}
        [[ "$iface" == "lo" || "$iface" == "sit0" || "$iface" == "*" ]] && continue
        
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
        
        # Optimized Sysfs Type Detection
        local type="unknown"
        if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
            type="wifi"
        elif [ -d "$iface_path/bridge" ]; then
            type="bridge"
        elif [ -d "$iface_path/bonding" ]; then
            type="bond"
        elif [ -f "$iface_path/tun_flags" ]; then
            type="tun"
        elif [ -d "$iface_path/device" ]; then
            type="ethernet"
        else
            # Fast heuristics
            case "$iface" in
                wg*) type="wireguard" ;;
                tailscale*|wt*) type="tailscale" ;;
                zt*) type="zerotier" ;;
                veth*) type="veth" ;;
                *) type="virtual" ;;
            esac
        fi
        
        local ssid=""
        local channel=""
        local frequency=""
        local quality="unknown"
        local rssi=""
        
        if [ "$type" == "wifi" ]; then
             ssid="${WIFI_SSID_MAP[$iface]:-}"
             
             # Use batched info
             if [ -n "$ssid" ] || [ "$connected" == "true" ]; then
                 channel="${WIFI_CHANNEL_MAP[$iface]:-}"
                 frequency="${WIFI_FREQ_MAP[$iface]:-}"
                 
                 # Get RSSI only if connected (requires live query)
                 if command -v iw >/dev/null; then
                     rssi=$(iw dev "$iface" station dump 2>/dev/null | awk '/signal:/{print $2}' | head -1)
                     quality=$(get_signal_quality "$rssi")
                 fi
             fi
             
             # Fallback AP check (Optimized: Check file first)
             if [ -z "$ssid" ] && [ -f "${STORAGE_NET_DIR}/70-wifi-host-${iface}.network" ]; then
                 if is_service_active "iwd"; then
                     # Use busctl directly (faster than iwctl wrapper)
                     local ap_status
                     ap_status=$(busctl get-property net.connman.iwd "/net/connman/iwd/${iface}" \
                               net.connman.iwd.AccessPoint Started 2>/dev/null | awk '{print $2}')
                     
                     if [ "$ap_status" == "true" ]; then
                         type="wifi_ap"
                         # Get SSID from config file to avoid another DBus call
                         ssid=$(grep "^SSID=" "${STORAGE_NET_DIR}/70-wifi-host-${iface}.network" | cut -d= -f2)
                     fi
                 fi
             fi
        elif [ "$type" == "bridge" ]; then
            ssid="Members: ${BRIDGE_MEMBERS[$iface]:-none}"
        fi

        local cfg_mode="dhcp"
        if [[ "$type" == "tailscale" || "$type" == "zerotier" ]]; then
            cfg_mode="managed_external"
        elif [ -f "${STORAGE_NET_DIR}/75-config-${iface}.network" ]; then 
            if grep -q "Address=" "${STORAGE_NET_DIR}/75-config-${iface}.network"; then cfg_mode="static"; fi
        fi
        
        local iface_proxy_json="null"
        if [ -f "${STORAGE_NET_DIR}/proxy-${iface}.conf" ]; then
            iface_proxy_json=$(get_proxy_json "${STORAGE_NET_DIR}/proxy-${iface}.conf")
        fi
        
        # Build JSON fragment using pure bash to avoid forks
        local ipv6_json="[]"
        if [ -n "$ipv6_csv" ]; then
             # Safely build array by iterating and escaping each address
             local ipv6_arr=()
             local escaped_addrs=""
             IFS=',' read -ra ipv6_arr <<< "$ipv6_csv"
             for addr in "${ipv6_arr[@]}"; do
                 [ -z "$addr" ] && continue
                 local esc_addr
                 esc_addr=$(json_escape "$addr")
                 if [ -z "$escaped_addrs" ]; then
                     escaped_addrs="\"$esc_addr\""
                 else
                     escaped_addrs="$escaped_addrs,\"$esc_addr\""
                 fi
             done
             [ -n "$escaped_addrs" ] && ipv6_json="[$escaped_addrs]"
        fi
        
        local members="${BRIDGE_MEMBERS[$iface]:-}"
        
        # Safe escaping without sed
        local safe_ssid
        safe_ssid=$(json_escape "$ssid")
        local safe_members
        safe_members=$(json_escape "$members")
        local safe_name
        safe_name=$(json_escape "$iface")
        
        # Manually constructing JSON string
        local obj="{"
        obj+="\"name\": \"$safe_name\","
        obj+="\"type\": \"$type\","
        obj+="\"ip\": \"$ip\","
        obj+="\"ipv6\": $ipv6_json,"
        obj+="\"mac\": \"$mac\","
        obj+="\"connected\": $connected,"
        
        # Safe Null handling without subshells. Empty SSID = null unless we suspect hidden.
        local val_ssid="null"
        if [ -n "$safe_ssid" ]; then
            val_ssid="\"$safe_ssid\""
        elif [ "$type" == "wifi" ] && [ "$connected" == "true" ]; then
            # Connected but hidden/empty SSID
            val_ssid="\"\""
        fi
        obj+="\"ssid\": $val_ssid,"
        
        local val_chan="null"
        [ -n "$channel" ] && val_chan="\"$channel\""
        obj+="\"channel\": $val_chan,"

        local val_freq="null"
        [ -n "$frequency" ] && val_freq="\"$frequency\""
        obj+="\"frequency\": $val_freq,"
        
        obj+="\"signal_quality\": \"$quality\","
        [ -n "$rssi" ] && obj+="\"rssi\": \"$rssi\","
        
        obj+="\"gateway\": \"$gw\","
        obj+="\"config\": \"$cfg_mode\","
        obj+="\"proxy\": $iface_proxy_json,"
        
        local val_memb="null"
        [ -n "$safe_members" ] && val_memb="\"$safe_members\""
        obj+="\"members\": $val_memb"
        
        obj+="}"
        
        # Add to array
        iface_json_array+=("$obj")
    done
    
    # Join array with jq (single allocation, reliable)
    # If array is empty, default to []
    local json_ifaces_array="[]"
    if [ ${#iface_json_array[@]} -gt 0 ]; then
        json_ifaces_array=$(printf '%s\n' "${iface_json_array[@]}" | jq -s '.')
    fi
    
    # Final assembly using ONE jq call to ensure validity and pretty print if needed
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
