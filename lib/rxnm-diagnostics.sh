# ==============================================================================
# REFINED STATUS & DIAGNOSTICS (HYBRID ARCHITECTURE)
# ==============================================================================

CACHE_FILE="${RUN_DIR}/status.json"
CACHE_TTL=5

# Issue 3.4: Consolidate Agent Bin
AGENT_BIN="${RXNM_AGENT_BIN}"

# Helper: Extract WiFi State directly from Kernel (Robust Fallback)
# Used as the final fallback if IWD, NM, and WPA all fail.
_get_wifi_fallback_json() {
    local json_items=""
    # Check if 'iw' tool is available
    if type -P iw >/dev/null 2>&1; then
        for iface_path in /sys/class/net/*; do
            [ -e "$iface_path" ] || continue
            local ifname=$(basename "$iface_path")
            local is_wifi=false
            
            # Check sysfs indicators (Standard Linux)
            if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
                is_wifi=true
            # Fallback: Check naming convention (Container/Agent Parity)
            # This catches cases where sysfs wireless attributes aren't passed through
            elif [[ "$ifname" == wl* ]]; then
                is_wifi=true
            fi
            
            if [ "$is_wifi" == "true" ]; then
                # Parse link status from kernel (Force C locale)
                local link_out
                link_out=$(LC_ALL=C iw dev "$ifname" link 2>/dev/null)
                
                # Skip if not connected or command failed
                if [[ -z "$link_out" ]] || [[ "$link_out" == *"Not connected"* ]]; then continue; fi
                
                # Robust parsing
                # SSID: Use sed to preserve spaces correctly
                local ssid=$(echo "$link_out" | sed -n 's/^[[:space:]]*SSID: //p')
                # Freq: Use awk to cast to int (removes .0 divergence)
                local freq=$(echo "$link_out" | awk '/freq:/ {print int($2)}')
                # RSSI: Extract just the number
                local rssi=$(echo "$link_out" | awk '/signal:/ {print $2}')
                # BSSID is typically on the first line: "Connected to xx:xx... (on wlan0)"
                local bssid=$(echo "$link_out" | awk '/Connected to/ {print $3}' | tr '[:upper:]' '[:lower:]')
                
                if [ -n "$ssid" ]; then
                    # Sanitize JSON string (escape quotes and backslashes)
                    ssid="${ssid//\\/\\\\}"
                    ssid="${ssid//\"/\\\"}"
                    [ -n "$json_items" ] && json_items="$json_items,"
                    # Construct JSON object fragment
                    json_items="$json_items \"$ifname\": { \"ssid\": \"$ssid\", \"frequency\": ${freq:-0}, \"rssi\": ${rssi:--100}, \"bssid\": \"${bssid:-null}\", \"state\": \"connected\" }"
                fi
            fi
        done
    fi
    echo "{ $json_items }"
}

action_status_legacy() {
    local filter_iface="${1:-}"

    local hostname="ROCKNIX"
    [ -f /etc/hostname ] && read -r hostname < /etc/hostname

    local net_json="[]"
    # Use type -P to avoid noisy aliases in some distros
    if type -P networkctl >/dev/null 2>&1; then
        net_json=$(timeout 3s networkctl status --all --json=short 2>/dev/null || timeout 3s networkctl list --json=short 2>/dev/null || echo "[]")
    fi

    # 1. Primary WiFi Source: DBus (IWD)
    local iwd_json="{}"
    if is_service_active "iwd"; then
        # Issue 3.1: Fix JQ path for busctl output
        iwd_json=$(busctl --timeout=3s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null | "$JQ_BIN" -r '.data // {}' || echo "{}")
    fi

    # 2. Standalone WiFi Fallback (Multi-stack: NM -> WPA -> IW)
    # Essential for containers (Distrobox) or non-IWD systems.
    local legacy_wifi_json="{}"
    
    # Only probe fallbacks if IWD returned nothing useful
    if [[ "$iwd_json" == "{}" ]]; then
        
        # A. Probe NetworkManager (nmcli)
        if type -P nmcli >/dev/null 2>&1; then
            local nm_out; nm_out=$(nmcli -t -f active,device,ssid,bssid,freq,signal dev wifi list 2>/dev/null | grep "^yes" | head -n1 || true)
            if [[ -n "$nm_out" ]]; then
                IFS=':' read -r _ dev ssid bssid freq sig <<< "$nm_out"
                # Map score (0-100) to approximate dBm (-100 to -50)
                local updated_json
                updated_json=$(echo "$legacy_wifi_json" | "$JQ_BIN" --arg dev "$dev" --arg ssid "$ssid" --arg bssid "$bssid" --arg freq "$freq" --arg sig "$sig" \
                    '. + {($dev): {ssid: $ssid, bssid: $bssid, frequency: ($freq | split(" ") | .[0] | tonumber // 0), rssi: (($sig | tonumber / 2) - 100)}}' 2>/dev/null)
                # Atomic update: Only replace if jq succeeded
                if [ -n "$updated_json" ]; then legacy_wifi_json="$updated_json"; fi
            fi
        fi

        # B. Probe wpa_supplicant (wpa_cli) - if NM found nothing
        if [[ "$legacy_wifi_json" == "{}" ]] && type -P wpa_cli >/dev/null 2>&1; then
             for iface_path in /sys/class/net/*; do
                 [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ] || continue
                 local ifname=$(basename "$iface_path")
                 local wpa_out; wpa_out=$(wpa_cli -i "$ifname" status 2>/dev/null || true)
                 if echo "$wpa_out" | grep -q "wpa_state=COMPLETED"; then
                     local ssid; ssid=$(echo "$wpa_out" | sed -n 's/^ssid=\(.*\)/\1/p')
                     local bssid; bssid=$(echo "$wpa_out" | sed -n 's/^bssid=\(.*\)/\1/p')
                     local freq; freq=$(echo "$wpa_out" | sed -n 's/^freq=\(.*\)/\1/p')
                     local sig="-100"
                     local sig_poll; sig_poll=$(wpa_cli -i "$ifname" signal_poll 2>/dev/null || true)
                     sig=$(echo "$sig_poll" | sed -n 's/^RSSI=\(.*\)/\1/p')
                     [ -z "$sig" ] && sig="-100"
                     
                     local updated_json
                     updated_json=$(echo "$legacy_wifi_json" | "$JQ_BIN" --arg ifname "$ifname" --arg ssid "$ssid" --arg bssid "$bssid" --arg freq "$freq" --arg sig "$sig" \
                        '. + {($ifname): {ssid: $ssid, bssid: $bssid, frequency: ($freq | tonumber // 0), rssi: ($sig | tonumber // -100)}}' 2>/dev/null)
                     if [ -n "$updated_json" ]; then legacy_wifi_json="$updated_json"; fi
                     break # Stop after first connected iface found
                 fi
             done
        fi

        # C. Fallback to generic kernel tools (iw) - if NM/WPA found nothing
        if [[ "$legacy_wifi_json" == "{}" ]]; then
            legacy_wifi_json=$(_get_wifi_fallback_json)
        fi
    fi

    local global_proxy_json
    global_proxy_json=$(get_proxy_json "$STORAGE_PROXY_GLOBAL")

    local routes_json="[]"
    if ip -j route show >/dev/null 2>&1; then
        routes_json=$( { ip -j route show; ip -j -6 route show; } 2>/dev/null | "$JQ_BIN" -s 'add // []' )
    fi

    local ip_json="[]"
    if type -P ip >/dev/null 2>&1; then
        ip_json=$(ip -j -s addr show 2>/dev/null || echo "[]")
    fi
    
    local speed_json="{}"
    local speed_data=""
    for iface_dir in /sys/class/net/*; do
        if [ -e "$iface_dir/speed" ]; then
            local ifname=$(basename "$iface_dir")
            local s_val=$(cat "$iface_dir/speed" 2>/dev/null || echo -1)
            if [ "$s_val" -gt 0 ] 2>/dev/null; then
                if [ -z "$speed_data" ]; then 
                    speed_data="\"$ifname\": $s_val"
                else
                    speed_data="$speed_data, \"$ifname\": $s_val"
                fi
            fi
        fi
    done
    speed_json="{ $speed_data }"

    # SAFEGUARDS: Ensure no empty strings passed to --argjson
    [ -z "$net_json" ] && net_json="[]"
    [ -z "$iwd_json" ] && iwd_json="{}"
    [ -z "$legacy_wifi_json" ] && legacy_wifi_json="{}"
    [ -z "$routes_json" ] && routes_json="[]"
    [ -z "$ip_json" ] && ip_json="[]"
    [ -z "$speed_json" ] && speed_json="{}"
    [ -z "$global_proxy_json" ] && global_proxy_json="null"

    local json_output
    json_output=$("$JQ_BIN" -n \
        --arg hn "$hostname" \
        --arg filter "$filter_iface" \
        --argjson gp "$global_proxy_json" \
        --argjson net "$net_json" \
        --argjson iwd "$iwd_json" \
        --argjson legacy_wifi "$legacy_wifi_json" \
        --argjson routes "$routes_json" \
        --argjson ip "$ip_json" \
        --argjson speeds "$speed_json" \
        '
        ($iwd | if . == {} or . == null then {} else . end) as $safe_iwd |
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Device"]?)) |
         map({key: .key, value: .value["net.connman.iwd.Device"].Name.data}) | from_entries) as $dev_paths |
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.AccessPoint"]?)) |
         map({key: .key, value: .value["net.connman.iwd.AccessPoint"]}) | from_entries
        ) as $access_points |
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Station"]?)) |
         map({
            iface: $dev_paths[.key], 
            rssi: (.value["net.connman.iwd.Station"].SignalStrength.data // -100),
            state: .value["net.connman.iwd.Station"].State.data,
            bssid_path: .value["net.connman.iwd.Station"].ConnectedBss.data
         }) |
         map(select(.iface != null)) |
         map({
            (.iface): {
                rssi: .rssi, 
                state: .state,
                bssid: (if .bssid_path then ($access_points[.bssid_path].HardwareAddress.data) else null end),
                frequency: (if .bssid_path then ($access_points[.bssid_path].Frequency.data) else null end)
            }
         }) | add
        ) as $wifi_station_info |
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Network"]? and .value["net.connman.iwd.Network"].Connected.data == true)) |
         map({
            iface: $dev_paths[.value["net.connman.iwd.Network"].Device.data],
            ssid: .value["net.connman.iwd.Network"].Name.data
         }) |
         map(select(.iface != null)) |
         map({(.iface): {ssid: .ssid}}) | add
        ) as $wifi_network_info |
        
        # Merge DBus info with Legacy Fallback (NM/WPA/IW)
        # Fallback takes precedence only if DBus returned nothing for that interface
        (($wifi_network_info // {}) * ($wifi_station_info // {})) as $dbus_wifi |
        ($legacy_wifi + ($dbus_wifi // {})) as $full_wifi |
        
        (($routes // []) | group_by(.dev) | map({key: .[0].dev, value: .}) | from_entries) as $route_map |
        (($net | objects | .Interfaces) // ($net | arrays) // []) as $sysd_net |
        ($ip | map({key: .ifname, value: (.stats64 // .stats)}) | from_entries) as $ip_stats |

        (if ($sysd_net | length) > 0 then $sysd_net else 
            ($ip | map({
                Name: .ifname,
                # Hybrid Type Detection: Trust name convention (wl*) even if link_type is ether
                Type: (if .link_type=="wlan" or (.ifname | startswith("wl")) or (.ifname | startswith("mlan")) then "wlan" elif .link_type=="ether" then "ethernet" else .link_type end),
                Addresses: (.addr_info | map({
                    Family: (if .family=="inet" then 2 else 10 end),
                    Address: ((.local // .address) + "/" + (.prefixlen|tostring)),
                    Scope: .scope
                })),
                HardwareAddress: .address,
                MTU: .mtu,
                OperationalState: (.operstate | ascii_downcase | if . == "up" then "routable" else . end)
            }))
        end) as $normalized_net |
        
        {
            success: true,
            hostname: $hn,
            global_proxy: $gp,
            interfaces: ($normalized_net | map(
                select($filter == "" or .Name == $filter) |
                ($route_map[.Name] // []) as $iface_routes |
                ($iface_routes | map(select(.dst == "default")) | .[0]) as $def_route |
                ($ip_stats[.Name] // {}) as $my_stats |
                {
                    (.Name): {
                        name: .Name,
                        type: .Type,
                        state: .OperationalState,
                        ip: (if .Addresses then (.Addresses | map(select(.Family==2 and .Scope!="host")) | .[0].Address) else null end),
                        ipv6: (if .Addresses then (.Addresses | map(select(.Family==10 and .Scope!="host")) | map(.Address)) else [] end),
                        mac: (.HardwareAddress),
                        mtu: (.MTU),
                        connected: (.OperationalState == "routable" or .OperationalState == "enslaved" or .OperationalState == "online" or .OperationalState == "up"),
                        
                        # Use the merged WiFi object (DBus + Legacy)
                        wifi: (if .Type == "wlan" then ($full_wifi[.Name] // null) else null end),
                        
                        gateway: (.Gateway // $def_route.gateway // null),
                        metric: ($def_route.metric // null),
                        speed: ($speeds[.Name] // null),
                        routes: ($iface_routes | map({
                            dst: .dst,
                            gw: .gateway,
                            metric: .metric
                        })),
                        stats: {
                            rx_bytes: ($my_stats.rx.bytes // 0),
                            tx_bytes: ($my_stats.tx.bytes // 0)
                        }
                    }
                }
            ) | add)
        }
        '
    )
    
    echo "$json_output"
}

action_check_internet_legacy() {
    if type -P networkctl >/dev/null 2>&1; then
         local operstate
         operstate=$(timeout 2s networkctl status 2>/dev/null | grep "Overall State" | awk '{print $3}')
         case "$operstate" in
            off|no-carrier|dormant|carrier)
                "$JQ_BIN" -n --arg state "$operstate" \
                    '{ipv4: false, ipv6: false, connected: false, reason: "local_link_down", state: $state}' \
                    | json_success
                return 0
                ;;
         esac
    fi

    local curl_fmt="%{http_code}"
    local target="http://clients3.google.com/generate_204"
    
    local t_v4; t_v4=$(mktemp)
    local t_v6; t_v6=$(mktemp)
    
    (
        if ip -4 route show default | grep -q default; then
            local code
            code=$(curl -4 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
            if [[ "$code" == "204" ]]; then echo "true"; else echo "false"; fi
        else echo "false"; fi
    ) > "$t_v4" & 
    
    (
        if ip -6 route show default | grep -q default; then
            local code
            code=$(curl -6 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
            if [[ "$code" == "204" ]]; then echo "true"; else echo "false"; fi
        else echo "false"; fi
    ) > "$t_v6" &
    
    wait
    local v4; v4=$(cat "$t_v4")
    local v6; v6=$(cat "$t_v6")
    rm -f "$t_v4" "$t_v6"
    
    local connected="false"
    [[ "$v4" == "true" || "$v6" == "true" ]] && connected="true"
    
    "$JQ_BIN" -n --argjson v4 "$v4" --argjson v6 "$v6" --argjson connected "$connected" \
        '{ipv4: $v4, ipv6: $v6, connected: $connected}' \
        | json_success
}

action_status() {
    local filter_iface="${1:-}"

    if [ -f "$CACHE_FILE" ]; then
        local now file_time age
        now=$(date +%s)
        file_time=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0)
        age=$((now - file_time))
        
        if [ "$age" -lt "$CACHE_TTL" ]; then
            cat "$CACHE_FILE"
            return 0
        fi
    fi

    local json_output=""

    if [ -x "$AGENT_BIN" ]; then
        if output=$("$AGENT_BIN" --dump 2>/dev/null) && [[ "$output" == \{* ]]; then
            if [ -n "$filter_iface" ]; then
                json_output=$("$JQ_BIN" --arg f "$filter_iface" '.interfaces |= with_entries(select(.key == $f))' <<< "$output")
            else
                json_output="$output"
            fi
        fi
    fi

    if [ -z "$json_output" ]; then
        json_output=$(action_status_legacy "$filter_iface")
    fi

    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
    echo "$json_output" > "$CACHE_FILE"
    
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        echo "$json_output"
    else
        json_success "$json_output"
    fi
}

action_check_internet() {
    if [ -x "$AGENT_BIN" ]; then
        if output=$("$AGENT_BIN" --check-internet 2>/dev/null) && [[ "$output" == \{* ]]; then
            echo "$output"
            return 0
        fi
    fi
    action_check_internet_legacy
}

action_check_portal() {
    local iface="$1"
    local primary_url="http://connectivitycheck.gstatic.com/generate_204"
    local fallback_urls=("http://nmcheck.gnome.org/check_network_status.txt" "http://detectportal.firefox.com/success.txt")
    
    local curl_base_opts=(-s -o /dev/null --max-time 3)
    [ -n "$iface" ] && curl_base_opts+=(--interface "$iface")

    if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
        "$JQ_BIN" -n '{portal_detected: false, status: "online", method: "fast_path"}' | json_success
        return 0
    fi

    local portal_opts=("${curl_base_opts[@]}" -L -w "%{http_code}:%{url_effective}")
    local result; result=$(curl "${portal_opts[@]}" "$primary_url" 2>/dev/null || echo "000:$primary_url")
    local code="${result%%:*}"; local effective_url="${result#*:}"

    if [[ "$code" == "204" ]] && [[ "$effective_url" == "$primary_url" ]]; then
        "$JQ_BIN" -n '{portal_detected: false, status: "online", method: "tier2_check"}' | json_success
        return 0
    fi

    if [[ "$effective_url" != "$primary_url" ]] || [[ "$code" != "204" && "$code" != "000" ]]; then
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
             "$JQ_BIN" -n --arg url "$effective_url" '{portal_detected: true, auto_ack: true, status: "online", target: $url, note: "authorized_by_probe"}' | json_success
             return 0
        fi
        local hijack_flag="false"; if [[ "$effective_url" == "$primary_url" ]]; then hijack_flag="true"; fi
        "$JQ_BIN" -n --arg url "$effective_url" --arg code "$code" --argjson hijacked "$hijack_flag" \
            '{portal_detected: true, auto_ack: false, status: "portal_locked", target: $url, http_code: $code, hijacked: $hijacked}' | json_success
        return 0
    fi

    for fallback in "${fallback_urls[@]}"; do
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$fallback" 2>/dev/null | grep -qE "200|204"; then
            "$JQ_BIN" -n --arg url "$fallback" '{portal_detected: false, status: "online", method: "fallback", host: $url}' | json_success
            return 0
        fi
    done
    "$JQ_BIN" -n '{portal_detected: false, status: "offline"}' | json_success
}
