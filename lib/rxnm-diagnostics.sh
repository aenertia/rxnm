# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-diagnostics.sh
# PURPOSE: Status Aggregation & Connectivity Checks
# ARCHITECTURE: Logic / Diagnostics
#
# Aggregates state from multiple sources (Netlink, IWD, Networkd) into a single
# JSON object. Handles the "Legacy Path" if the C Agent is unavailable.
# Refactored for strict POSIX compatibility.
# -----------------------------------------------------------------------------

CACHE_FILE="${RUN_DIR}/status.json"
CACHE_TTL=5
AGENT_BIN="${RXNM_AGENT_BIN}"

# Description: Generates a JSON representation of WiFi state using standard tools (iw).
_get_wifi_fallback_json() {
    local json_items=""
    if command -v iw >/dev/null 2>&1; then
        for iface_path in /sys/class/net/*; do
            [ -e "$iface_path" ] || continue
            local ifname="${iface_path##*/}"
            local is_wifi=false
            
            if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
                is_wifi=true
            else
                case "$ifname" in wl*) is_wifi=true ;; esac
            fi
            
            if [ "$is_wifi" = "true" ]; then
                local link_out
                link_out=$(LC_ALL=C iw dev "$ifname" link 2>/dev/null)
                case "$link_out" in *"Not connected"*|"") continue ;; esac
                
                local ssid
                ssid=$(echo "$link_out" | sed -n 's/^[[:space:]]*SSID: //p')
                local freq
                freq=$(echo "$link_out" | awk '/freq:/ {print int($2)}')
                local rssi
                rssi=$(echo "$link_out" | awk '/signal:/ {print $2}')
                local bssid
                bssid=$(echo "$link_out" | awk '/Connected to/ {print $3}' | tr '[:upper:]' '[:lower:]')
                local bssid_val="null"
                if [ -n "$bssid" ]; then bssid_val="\"$bssid\""; fi
                
                if [ -n "$ssid" ]; then
                    # JSON escaping
                    ssid=$(echo "$ssid" | sed 's/\\/\\\\/g; s/"/\\"/g')
                    if [ -n "$json_items" ]; then json_items="$json_items,"; fi
                    json_items="$json_items \"$ifname\": { \"ssid\": \"$ssid\", \"frequency\": ${freq:-0}, \"rssi\": ${rssi:--100}, \"bssid\": $bssid_val, \"state\": \"connected\" }"
                fi
            fi
        done
    fi
    echo "{ $json_items }"
}

action_status_legacy() {
    # Guard: JQ is required for legacy status aggregation
    if [ "$RXNM_HAS_JQ" != "true" ]; then
        if [ -x "$AGENT_BIN" ]; then
            "$AGENT_BIN" --dump 2>/dev/null || printf '{"success":false,"error":"agent failed and jq missing"}\n'
        else
            printf '{"success":false,"error":"jq unavailable and agent missing"}\n'
        fi
        return
    fi

    local filter_iface="${1:-}"
    local hostname="ROCKNIX"
    if [ -f /etc/hostname ]; then read -r hostname < /etc/hostname || true; fi
    
    local net_json="[]"
    if command -v networkctl >/dev/null 2>&1; then
        net_json=$(timeout 3s networkctl status --all --json=short 2>/dev/null || timeout 3s networkctl list --json=short 2>/dev/null || echo "[]")
    fi
    
    local iwd_json="{}"
    if is_service_active "iwd"; then
        iwd_json=$(busctl --timeout=3s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null | "$JQ_BIN" -r '.data // {}' || echo "{}")
    fi
    
    local legacy_wifi_json="{}"
    if [ "$iwd_json" = "{}" ]; then
        # On low-power/POSIX-compat targets the agent is mandatory.
        # If we reach here without IWD data, iw-based fallback won't help.
        # Path A (Bash, any hardware) always uses the fallback.
        if [ "${IS_LOW_POWER:-false}" != "true" ] || \
           [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
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
    if command -v ip >/dev/null 2>&1; then
        ip_json=$(ip -j -s addr show 2>/dev/null || echo "[]")
    fi
    
    local speed_data=""
    for iface_dir in /sys/class/net/*; do
        if [ -e "$iface_dir/speed" ]; then
            local ifname="${iface_dir##*/}"
            local s_val
            s_val=$(cat "$iface_dir/speed" 2>/dev/null || echo -1)
            if [ "$s_val" -gt 0 ] 2>/dev/null; then
                if [ -z "$speed_data" ]; then speed_data="\"$ifname\": $s_val"; else speed_data="$speed_data, \"$ifname\": $s_val"; fi
            fi
        fi
    done
    local speed_json="{ $speed_data }"
    
    # Normalize inputs
    [ -z "$net_json" ] && net_json="[]"
    [ -z "$iwd_json" ] && iwd_json="{}"
    [ -z "$legacy_wifi_json" ] && legacy_wifi_json="{}"
    [ -z "$routes_json" ] && routes_json="[]"
    [ -z "$ip_json" ] && ip_json="[]"
    [ -z "$global_proxy_json" ] && global_proxy_json="null"
    
    # Final Merge
    "$JQ_BIN" -n \
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
        def normalize_type($name; $raw_type):
            if $raw_type == "wlan" or ($name | startswith("wl")) or ($name | startswith("mlan")) then "wifi"
            elif $raw_type == "wireguard" or ($name | startswith("wg")) then "wireguard"
            elif $raw_type == "bridge" or ($name | startswith("br")) then "bridge"
            elif $raw_type == "bond" or ($name | startswith("bond")) then "bond"
            elif $raw_type == "ether" or $raw_type == "ethernet" then "ethernet"
            else $raw_type end;
            
        ($iwd | if . == {} or . == null then {} else . end) as $safe_iwd |
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Device"]?)) | map({key: .key, value: .value["net.connman.iwd.Device"].Name.data}) | from_entries) as $dev_paths |
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.AccessPoint"]?)) | map({key: .key, value: .value["net.connman.iwd.AccessPoint"]}) | from_entries) as $access_points |
        
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Station"]?)) | map({
            iface: $dev_paths[.key],
            rssi: (.value["net.connman.iwd.Station"].SignalStrength.data // -100),
            state: .value["net.connman.iwd.Station"].State.data,
            bssid_path: .value["net.connman.iwd.Station"].ConnectedBss.data
         }) | map(select(.iface != null)) | map({
            (.iface): {
                rssi: .rssi,
                state: .state,
                bssid: (if .bssid_path then ($access_points[.bssid_path].HardwareAddress.data) else null end),
                frequency: (if .bssid_path then ($access_points[.bssid_path].Frequency.data) else null end)
            }
         }) | add) as $wifi_station_info |
        
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Network"]? and .value["net.connman.iwd.Network"].Connected.data == true)) | map({
            iface: $dev_paths[.value["net.connman.iwd.Network"].Device.data],
            ssid: .value["net.connman.iwd.Network"].Name.data
         }) | map(select(.iface != null)) | map({(.iface): {ssid: .ssid}}) | add) as $wifi_network_info |
        
        (($wifi_network_info // {}) * ($wifi_station_info // {})) as $dbus_wifi |
        ($legacy_wifi + ($dbus_wifi // {})) as $full_wifi |
        
        (($routes // []) | group_by(.dev) | map({key: .[0].dev, value: .}) | from_entries) as $route_map |
        
        (($net | objects | .Interfaces) // ($net | arrays) // []) as $sysd_net |
        
        ($ip | map({key: .ifname, value: (.stats64 // .stats)}) | from_entries) as $ip_stats |
        
        (if ($sysd_net | length) > 0 then $sysd_net else
            ($ip | map({
                Name: .ifname,
                Type: normalize_type((.ifname // ""); .link_type),
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
                normalize_type((.Name // ""); .Type) as $normalized_type |
                {
                    (.Name): {
                        name: .Name,
                        type: $normalized_type,
                        state: .OperationalState,
                        ip: (if .Addresses then (.Addresses | map(select(.Family==2 and .Scope!="host")) | .[0].Address) else null end),
                        ipv6: (if .Addresses then (.Addresses | map(select(.Family==10 and .Scope!="host")) | map(.Address)) else [] end),
                        mac: (.HardwareAddress),
                        mtu: (.MTU),
                        connected: (.OperationalState == "routable" or .OperationalState == "enslaved" or .OperationalState == "online" or .OperationalState == "up"),
                        wifi: (if $normalized_type == "wifi" then ($full_wifi[.Name] // null) else null end),
                        gateway: (.Gateway // $def_route.gateway // null),
                        metric: ($def_route.metric // null),
                        speed: ($speeds[.Name] // null),
                        routes: ($iface_routes | map({ dst: .dst, gw: .gateway, metric: .metric })),
                        stats: { rx_bytes: ($my_stats.rx.bytes // 0), tx_bytes: ($my_stats.tx.bytes // 0) }
                    }
                }
            ) | add)
        }
        '
}

action_check_internet_legacy() {
    local curl_fmt="%{http_code}"
    local target="http://clients3.google.com/generate_204"
    local t_v4; t_v4=$(mktemp)
    local t_v6; t_v6=$(mktemp)
    
    (
        if ip -4 route show default | grep -q default; then
            local code
            code=$(curl -4 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
            if [ "$code" = "204" ]; then echo "true"; else echo "false"; fi
        else echo "false"; fi
    ) > "$t_v4" &
    (
        if ip -6 route show default | grep -q default; then
            local code
            code=$(curl -6 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
            if [ "$code" = "204" ]; then echo "true"; else echo "false"; fi
        else echo "false"; fi
    ) > "$t_v6" &
    
    wait
    local v4; v4=$(cat "$t_v4")
    local v6; v6=$(cat "$t_v6")
    rm -f "$t_v4" "$t_v6"
    
    local connected="false"
    if [ "$v4" = "true" ] || [ "$v6" = "true" ]; then connected="true"; fi
    
    "$JQ_BIN" -n --argjson v4 "$v4" --argjson v6 "$v6" --argjson connected "$connected" \
        '{ipv4: $v4, ipv6: $v6, connected: $connected}' | json_success
}

action_status() {
    local filter_iface="${1:-}"
    
    # 1. Serve Cache if valid
    if [ -z "$filter_iface" ] && [ -f "$CACHE_FILE" ]; then
        local now file_time age
        now=$(date +%s)
        if stat -c %Y "$CACHE_FILE" >/dev/null 2>&1; then file_time=$(stat -c %Y "$CACHE_FILE"); else file_time=0; fi
        age=$((now - file_time))
        if [ "$age" -lt "$CACHE_TTL" ]; then cat "$CACHE_FILE"; return 0; fi
    fi
    
    # 2. Try Accelerator
    local json_output=""
    if [ -x "$AGENT_BIN" ]; then
        local output
        if output=$("$AGENT_BIN" --dump 2>/dev/null); then
            case "$output" in
                '{'*)
                    if [ -n "$filter_iface" ] && [ "$RXNM_HAS_JQ" = "true" ]; then
                        # Use pipe instead of Bash here-string for POSIX compliance
                        json_output=$(echo "$output" | "$JQ_BIN" --arg f "$filter_iface" '.interfaces |= with_entries(select(.key == $f))')
                    else
                        json_output="$output"
                    fi
                    ;;
            esac
        fi
    fi
    
    # 3. Fallback
    if [ -z "$json_output" ]; then
        json_output=$(action_status_legacy "$filter_iface") || json_output="{}"
    fi
    
    # 4. Cache
    if [ -z "$filter_iface" ] && [ -n "$json_output" ] && [ "$json_output" != "{}" ]; then
        if [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR" 2>/dev/null; then
            echo "$json_output" > "$CACHE_FILE" 2>/dev/null || true
        fi
    fi
    
    if [ "${RXNM_FORMAT:-human}" = "json" ]; then
        echo "$json_output"
    else
        json_success "$json_output"
    fi
}

action_check_internet() {
    if [ -x "$AGENT_BIN" ]; then
        local output
        if output=$("$AGENT_BIN" --check-internet 2>/dev/null); then
            case "$output" in '{'*) echo "$output"; return 0 ;; esac
        fi
    fi
    
    if [ "$RXNM_HAS_JQ" = "true" ]; then
        action_check_internet_legacy
    else
        printf '{"success": false, "error": "Cannot check internet (no agent, no jq)"}\n'
    fi
}

action_check_portal() {
    local iface="$1"
    local primary_url="http://connectivitycheck.gstatic.com/generate_204"
    local fallback_urls="http://nmcheck.gnome.org/check_network_status.txt http://detectportal.firefox.com/success.txt"
    
    local curl_opts="-s -o /dev/null --max-time 3"
    local iface_opt=""
    if [ -n "$iface" ]; then iface_opt="--interface $iface"; fi
    
    # shellcheck disable=SC2086
    if curl $curl_opts $iface_opt -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
        if [ "$RXNM_HAS_JQ" = "true" ]; then
            "$JQ_BIN" -n '{portal_detected: false, status: "online", method: "fast_path"}' | json_success
        else
            printf '{"success": true, "portal_detected": false, "status": "online", "method": "fast_path"}\n'
        fi
        return 0
    fi
    
    # shellcheck disable=SC2086
    local result
    result=$(curl $curl_opts $iface_opt -L -w "%{http_code}:%{url_effective}" "$primary_url" 2>/dev/null || echo "000:$primary_url")
    local code="${result%%:*}"
    local effective_url="${result#*:}"
    
    if [ "$code" = "204" ] && [ "$effective_url" = "$primary_url" ]; then
        if [ "$RXNM_HAS_JQ" = "true" ]; then
            "$JQ_BIN" -n '{portal_detected: false, status: "online", method: "tier2_check"}' | json_success
        else
            printf '{"success": true, "portal_detected": false, "status": "online", "method": "tier2_check"}\n'
        fi
        return 0
    fi
    
    if [ "$effective_url" != "$primary_url" ] || { [ "$code" != "204" ] && [ "$code" != "000" ]; }; then
        local hijack_flag="false"
        if [ "$effective_url" = "$primary_url" ]; then hijack_flag="true"; fi
        
        if [ "$RXNM_HAS_JQ" = "true" ]; then
            "$JQ_BIN" -n --arg url "$effective_url" --arg code "$code" --argjson hijacked "$hijack_flag" \
                '{portal_detected: true, auto_ack: false, status: "portal_locked", target: $url, http_code: $code, hijacked: $hijacked}' | json_success
        else
             printf '{"success": true, "portal_detected": true, "status": "portal_locked", "target": "%s"}\n' "$effective_url"
        fi
        return 0
    fi
    
    # POSIX safe iteration
    for fallback in $fallback_urls; do
        # shellcheck disable=SC2086
        if curl $curl_opts $iface_opt -w "%{http_code}" "$fallback" 2>/dev/null | grep -qE "200|204"; then
            if [ "$RXNM_HAS_JQ" = "true" ]; then
                "$JQ_BIN" -n --arg url "$fallback" '{portal_detected: false, status: "online", method: "fallback", host: $url}' | json_success
            else
                printf '{"success": true, "portal_detected": false, "status": "online", "method": "fallback"}\n'
            fi
            return 0
        fi
    done
    
    if [ "$RXNM_HAS_JQ" = "true" ]; then
        "$JQ_BIN" -n '{portal_detected: false, status: "offline"}' | json_success
    else
        printf '{"success": true, "portal_detected": false, "status": "offline"}\n'
    fi
}
