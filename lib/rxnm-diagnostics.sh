# ==============================================================================
# REFINED STATUS & DIAGNOSTICS (OPTIMIZED FOR RK3326/ARM)
# ==============================================================================

# --- CACHING CONSTANTS ---
CACHE_FILE="${RUN_DIR}/status.json"
CACHE_TTL=5 # Seconds

# Optimized action_check_portal using JQ for safe JSON generation
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
        jq -n '{portal_detected: false, status: "online", method: "fast_path"}' | json_success
        return 0
    fi

    # 2. TIER 2: PORTAL DETECTION (Follow Redirects)
    local portal_opts=("${curl_base_opts[@]}" -L -w "%{http_code}:%{url_effective}")
    local result
    result=$(curl "${portal_opts[@]}" "$primary_url" 2>/dev/null || echo "000:$primary_url")
    
    local code="${result%%:*}"
    local effective_url="${result#*:}"

    if [[ "$code" == "204" ]] && [[ "$effective_url" == "$primary_url" ]]; then
        jq -n '{portal_detected: false, status: "online", method: "tier2_check"}' | json_success
        return 0
    fi

    if [[ "$effective_url" != "$primary_url" ]] || [[ "$code" != "204" && "$code" != "000" ]]; then
        # Check if we were redirected but can still reach the target (weird transparent proxy cases)
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$primary_url" 2>/dev/null | grep -q "204"; then
             jq -n --arg url "$effective_url" \
                 '{portal_detected: true, auto_ack: true, status: "online", target: $url, note: "authorized_by_probe"}' \
                 | json_success
             return 0
        fi
        
        local hijack_flag="false"
        if [[ "$effective_url" == "$primary_url" ]]; then hijack_flag="true"; fi
        
        jq -n --arg url "$effective_url" --arg code "$code" --argjson hijacked "$hijack_flag" \
            '{portal_detected: true, auto_ack: false, status: "portal_locked", target: $url, http_code: $code, hijacked: $hijacked}' \
            | json_success
        return 0
    fi

    # 3. TIER 3: SEQUENTIAL FALLBACK
    for fallback in "${fallback_urls[@]}"; do
        if curl "${curl_base_opts[@]}" -w "%{http_code}" "$fallback" 2>/dev/null | grep -qE "200|204"; then
            jq -n --arg url "$fallback" \
                '{portal_detected: false, status: "online", method: "fallback", host: $url}' \
                | json_success
            return 0
        fi
    done

    jq -n '{portal_detected: false, status: "offline"}' | json_success
}

action_check_internet() {
    # 0. TIER 0: NETWORKCTL STATUS (FASTEST)
    if command -v networkctl >/dev/null; then
         local operstate
         operstate=$(networkctl status 2>/dev/null | grep "Overall State" | awk '{print $3}')
         case "$operstate" in
            off|no-carrier|dormant|carrier)
                jq -n --arg state "$operstate" \
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
    local v4="false" v6="false"
    
    # Use native JSON output where possible
    if ip -4 route show default | grep -q default; then
        local code4
        code4=$(curl -4 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
        [[ "$code4" == "204" ]] && v4="true"
    fi

    if ip -6 route show default | grep -q default; then
        local code6
        code6=$(curl -6 -s -o /dev/null -w "$curl_fmt" -m "$CURL_TIMEOUT" "$target" 2>/dev/null || echo "000")
        [[ "$code6" == "204" ]] && v6="true"
    fi
    
    local connected="false"
    [[ "$v4" == "true" || "$v6" == "true" ]] && connected="true"
    
    jq -n --argjson v4 "$v4" --argjson v6 "$v6" --argjson connected "$connected" \
        '{ipv4: $v4, ipv6: $v6, connected: $connected}' \
        | json_success
}

# --- STATUS ENGINE ---

action_status() {
    local filter_iface="${1:-}"

    # 1. READ-THROUGH CACHE (Battery Saver)
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

    # 2. DATA COLLECTION (The "Two-Fork" Strategy)
    local hostname="ROCKNIX"
    [ -f /etc/hostname ] && read -r hostname < /etc/hostname

    # Source A: Systemd Networkd (Layer 3)
    # Ensure net_json is a valid JSON array even on failure
    # systemd v252+ supports --json=short which is ideal.
    local net_json="[]"
    if command -v networkctl >/dev/null; then
        net_json=$(networkctl status --all --json=short 2>/dev/null || networkctl list --json=short 2>/dev/null || echo "[]")
    fi

    # Source B: IWD (Layer 2 - WiFi)
    # Ensure iwd_json is a valid JSON object even on failure
    # busctl --json=short returns { "type": "...", "data": [ { ... } ] }
    local iwd_json="{}"
    if is_service_active "iwd"; then
        # busctl json output for GetManagedObjects typically returns { "type": "...", "data": [...] }
        # We need the inner data which is the dictionary of objects.
        # Use || echo "{}" to prevent jq parse errors on empty output
        iwd_json=$(busctl call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null | jq -r '.data[0] // {}' || echo "{}")
    fi

    # Source C: Global Proxy
    local global_proxy_json
    global_proxy_json=$(get_proxy_json "$STORAGE_PROXY_GLOBAL")

    # 3. MERGE & MAP (Using JQ for speed - O(1) Fork)
    local json_output
    json_output=$(jq -n \
        --arg hn "$hostname" \
        --arg filter "$filter_iface" \
        --argjson gp "$global_proxy_json" \
        --argjson net "$net_json" \
        --argjson iwd "$iwd_json" \
        '
        # --- JQ Logic Start ---
        
        # Safe unpacking of IWD data (handle empty objects/nulls)
        ($iwd | if . == {} or . == null then {} else . end) as $safe_iwd |

        # Step 1: Process IWD Data
        
        # A. Map Device Object Paths to Interface Names (e.g. { "/net/connman/iwd/0": "wlan0" })
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Device"]?)) |
         map({key: .key, value: .value["net.connman.iwd.Device"].Name.data}) | from_entries) as $dev_paths |

        # B. Map Access Point Objects (for BSSID lookup - AccessPoints are at /net/connman/iwd/0/5 etc. )
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.AccessPoint"]?)) |
         map({key: .key, value: .value["net.connman.iwd.AccessPoint"]}) | from_entries
        ) as $access_points |

        # C. Find Station Info (RSSI/State/BSSID) for each interface
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Station"]?)) |
         map({
            iface: $dev_paths[.key], 
            rssi: (.value["net.connman.iwd.Station"].SignalStrength.data // -100),
            state: .value["net.connman.iwd.Station"].State.data,
            # BSSID Lookup: Station.ConnectedBss -> AccessPoint.HardwareAddress
            bssid_path: .value["net.connman.iwd.Station"].ConnectedBss.data
         }) |
         # Filter out instances where interface mapping failed
         map(select(.iface != null)) |
         map({
            (.iface): {
                rssi: .rssi, 
                state: .state,
                bssid: (if .bssid_path then ($access_points[.bssid_path].HardwareAddress.data) else null end)
            }
         }) | add
        ) as $wifi_station_info |

        # D. Find Connected Networks (SSID info)
        ($safe_iwd | to_entries | map(select(.value["net.connman.iwd.Network"]? and .value["net.connman.iwd.Network"].Connected.data == true)) |
         map({
            iface: $dev_paths[.value["net.connman.iwd.Network"].Device.data],
            ssid: .value["net.connman.iwd.Network"].Name.data
         }) |
         map(select(.iface != null)) |
         map({(.iface): {ssid: .ssid}}) | add
        ) as $wifi_network_info |

        # Merge WiFi info (defaults to empty object if null)
        (($wifi_network_info // {}) * ($wifi_station_info // {})) as $full_wifi |

        # Step 2: Process Systemd Network Data and Merge
        
        {
            success: true,
            hostname: $hn,
            global_proxy: $gp,
            interfaces: ($net | map(
                select($filter == "" or .Name == $filter) |
                {
                    (.Name): {
                        name: .Name,
                        type: .Type,
                        state: .OperationalState,
                        # Handle IP address parsing from networkctl JSON output
                        ip: (if .Addresses then (.Addresses | map(select(.Family==2)) | .[0].Address) else null end),
                        ipv6: (if .Addresses then (.Addresses | map(select(.Family==10)) | map(.Address)) else [] end),
                        gateway: (.Gateway), 
                        mac: (.HardwareAddress),
                        mtu: (.MTU),
                        connected: (.OperationalState == "routable" or .OperationalState == "enslaved" or .OperationalState == "online"),
                        # Merge the pre-calculated WiFi info based on Interface Name
                        wifi: (if .Type == "wlan" then ($full_wifi[.Name] // null) else null end)
                    }
                }
            ) | add)
        }
        '
    )

    # 4. SAVE CACHE & OUTPUT
    # Ensure run dir exists (it should, but safety first)
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
    echo "$json_output" > "$CACHE_FILE"
    
    # Check if we should pretty print human output
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        echo "$json_output"
    else
        # Re-use rxnm-utils.sh pretty printer
        json_success "$json_output"
    fi
}
