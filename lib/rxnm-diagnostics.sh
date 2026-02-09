# ==============================================================================
# REFINED STATUS & DIAGNOSTICS (OPTIMIZED FOR RK3326/ARM)
# ==============================================================================

# --- CACHING CONSTANTS ---
CACHE_FILE="${RUN_DIR}/status.json"
CACHE_TTL=5 # Seconds

# Agent Path
AGENT_BIN="${RXNM_LIB_DIR}/../../bin/rxnm-agent"
if [ ! -x "$AGENT_BIN" ]; then
    # Fallback for installed system path
    AGENT_BIN="/usr/bin/rxnm-agent"
fi

# -----------------------------------------------------------------------------
# LEGACY STATUS ENGINE (Preserved Verbatim for Fallback)
# -----------------------------------------------------------------------------
action_status_legacy() {
    local filter_iface="${1:-}"

    # READ-THROUGH CACHE (Battery Saver) logic is handled in the wrapper
    
    # 2. DATA COLLECTION (The "Two-Fork" Strategy)
    local hostname="ROCKNIX"
    [ -f /etc/hostname ] && read -r hostname < /etc/hostname

    # Source A: Systemd Networkd
    local net_json="[]"
    if command -v networkctl >/dev/null; then
        net_json=$(timeout 3s networkctl status --all --json=short 2>/dev/null || timeout 3s networkctl list --json=short 2>/dev/null || echo "[]")
    fi

    # Source B: IWD
    local iwd_json="{}"
    if is_service_active "iwd"; then
        iwd_json=$(busctl --timeout=3s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null | "$JQ_BIN" -r '.data[0] // {}' || echo "{}")
    fi

    # Source C: Global Proxy
    local global_proxy_json
    global_proxy_json=$(get_proxy_json "$STORAGE_PROXY_GLOBAL")

    # 3. MERGE & MAP
    local json_output
    json_output=$("$JQ_BIN" -n \
        --arg hn "$hostname" \
        --arg filter "$filter_iface" \
        --argjson gp "$global_proxy_json" \
        --argjson net "$net_json" \
        --argjson iwd "$iwd_json" \
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
                bssid: (if .bssid_path then ($access_points[.bssid_path].HardwareAddress.data) else null end)
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
        (($wifi_network_info // {}) * ($wifi_station_info // {})) as $full_wifi |
        ($net | if .Interfaces then .Interfaces else . end) as $normalized_net |
        {
            success: true,
            hostname: $hn,
            global_proxy: $gp,
            interfaces: ($normalized_net | map(
                select($filter == "" or .Name == $filter) |
                {
                    (.Name): {
                        name: .Name,
                        type: .Type,
                        state: .OperationalState,
                        ip: (if .Addresses then (.Addresses | map(select(.Family==2)) | .[0].Address) else null end),
                        ipv6: (if .Addresses then (.Addresses | map(select(.Family==10)) | map(.Address)) else [] end),
                        gateway: (.Gateway), 
                        mac: (.HardwareAddress),
                        mtu: (.MTU),
                        connected: (.OperationalState == "routable" or .OperationalState == "enslaved" or .OperationalState == "online"),
                        wifi: (if .Type == "wlan" then ($full_wifi[.Name] // null) else null end)
                    }
                }
            ) | add)
        }
        '
    )
    
    echo "$json_output"
}

# -----------------------------------------------------------------------------
# HYBRID DISPATCHER (Priority: Cache > Agent > Legacy)
# -----------------------------------------------------------------------------
action_status() {
    local filter_iface="${1:-}"

    # 1. READ-THROUGH CACHE (Common for both paths)
    if [ -f "$CACHE_FILE" ]; then
        local now file_time age
        now=$(printf '%(%s)T' -1) 2>/dev/null || now=$(date +%s)
        file_time=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0)
        age=$((now - file_time))
        
        if [ "$age" -lt "$CACHE_TTL" ]; then
            cat "$CACHE_FILE"
            return 0
        fi
    fi

    local json_output=""

    # 2. FASTPATH: Native Agent
    if [ -x "$AGENT_BIN" ]; then
        # Try agent dump. If it succeeds (exit 0) and outputs valid json ('{'), use it.
        if output=$("$AGENT_BIN" --dump 2>/dev/null) && [[ "$output" == \{* ]]; then
            json_output="$output"
        fi
    fi

    # 3. COLDPATH: Fallback to Shell Logic
    if [ -z "$json_output" ]; then
        log_debug "Agent unavailable or failed. Using legacy status."
        json_output=$(action_status_legacy "$filter_iface")
    fi

    # 4. SAVE CACHE & OUTPUT
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
    echo "$json_output" > "$CACHE_FILE"
    
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        echo "$json_output"
    else
        json_success "$json_output"
    fi
}

# -----------------------------------------------------------------------------
# DIAGNOSTIC TOOLS (Untouched in Phase 2)
# -----------------------------------------------------------------------------

action_check_portal() {
    # ... existing code ...
    local iface="$1"
    local primary_url="http://connectivitycheck.gstatic.com/generate_204"
    local fallback_urls=(
        "http://nmcheck.gnome.org/check_network_status.txt"
        "http://detectportal.firefox.com/success.txt"
    )
    local curl_base_opts=(-s -o /dev/null --max-time 3)
    [ -n "$iface" ] && curl_base_opts+=(--interface "$iface")

    if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
        "$JQ_BIN" -n '{portal_detected: false, status: "online", method: "fast_path"}' | json_success
        return 0
    fi

    local portal_opts=("${curl_base_opts[@]}" -L -w "%{http_code}:%{url_effective}")
    local result
    result=$(curl "${portal_opts[@]}" "$primary_url" 2>/dev/null || echo "000:$primary_url")
    
    local code="${result%%:*}"
    local effective_url="${result#*:}"

    if [[ "$code" == "204" ]] && [[ "$effective_url" == "$primary_url" ]]; then
        "$JQ_BIN" -n '{portal_detected: false, status: "online", method: "tier2_check"}' | json_success
        return 0
    fi

    if [[ "$effective_url" != "$primary_url" ]] || [[ "$code" != "204" && "$code" != "000" ]]; then
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
             "$JQ_BIN" -n --arg url "$effective_url" \
                 '{portal_detected: true, auto_ack: true, status: "online", target: $url, note: "authorized_by_probe"}' \
                 | json_success
             return 0
        fi
        local hijack_flag="false"
        if [[ "$effective_url" == "$primary_url" ]]; then hijack_flag="true"; fi
        "$JQ_BIN" -n --arg url "$effective_url" --arg code "$code" --argjson hijacked "$hijack_flag" \
            '{portal_detected: true, auto_ack: false, status: "portal_locked", target: $url, http_code: $code, hijacked: $hijacked}' \
            | json_success
        return 0
    fi

    for fallback in "${fallback_urls[@]}"; do
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$fallback" 2>/dev/null | grep -qE "200|204"; then
            "$JQ_BIN" -n --arg url "$fallback" \
                '{portal_detected: false, status: "online", method: "fallback", host: $url}' \
                | json_success
            return 0
        fi
    done
    "$JQ_BIN" -n '{portal_detected: false, status: "offline"}' | json_success
}

action_check_internet() {
    # ... existing code ...
    if command -v networkctl >/dev/null; then
         local operstate
         operstate=$(timeout 2s networkctl status 2>/dev/null | grep "Overall State" | awk '{print $3}')
         case "$operstate" in
            off|no-carrier|dormant|carrier)
                "$JQ_BIN" -n --arg state "$operstate" \
                    '{ipv4: false, ipv6: false, connected: false, reason: "local_link_down", state: $state}' \
                    | json_success
                return 0
                ;;
            routable|online)
                ;;
         esac
    fi

    local curl_fmt="%{http_code}"
    local target="http://clients3.google.com/generate_204"
    local t_v4; t_v4=$(mktemp)
    local t_v6; t_v6=$(mktemp)
    local pid_v4=0; local pid_v6=0
    
    (
        if ip -4 route show default | grep -q default; then
            local code
            code=$(curl -4 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
            if [[ "$code" == "204" ]]; then echo "true"; else echo "false"; fi
        else echo "false"; fi
    ) > "$t_v4" & pid_v4=$!
    
    (
        if ip -6 route show default | grep -q default; then
            local code
            code=$(curl -6 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
            if [[ "$code" == "204" ]]; then echo "true"; else echo "false"; fi
        else echo "false"; fi
    ) > "$t_v6" & pid_v6=$!
    
    wait $pid_v4 $pid_v6
    local v4; v4=$(cat "$t_v4")
    local v6; v6=$(cat "$t_v6")
    rm -f "$t_v4" "$t_v6"
    local connected="false"
    [[ "$v4" == "true" || "$v6" == "true" ]] && connected="true"
    "$JQ_BIN" -n --argjson v4 "$v4" --argjson v6 "$v6" --argjson connected "$connected" \
        '{ipv4: $v4, ipv6: $v6, connected: $connected}' \
        | json_success
}
