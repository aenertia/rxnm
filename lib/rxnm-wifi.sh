# ==============================================================================
# WIFI ACTIONS & HELPERS
# ==============================================================================

# Optimization: Cache WiFi interface detection
: "${WIFI_IFACE_CACHE:=}"
: "${WIFI_IFACE_CACHE_TIME:=0}"

get_wifi_iface() {
    local preferred="${1:-}"
    if [ -n "$preferred" ]; then echo "$preferred"; return; fi
    
    local now
    now=$(date +%s)
    local cache_ttl=30
    
    if [ -n "$WIFI_IFACE_CACHE" ] && [ $((now - WIFI_IFACE_CACHE_TIME)) -lt $cache_ttl ]; then
        if [ -d "/sys/class/net/$WIFI_IFACE_CACHE" ]; then
            echo "$WIFI_IFACE_CACHE"
            return 0
        fi
    fi
    
    local best_iface=""
    local interfaces=(/sys/class/net/*)
    for iface in "${interfaces[@]}"; do
        [ ! -e "$iface" ] && continue
        if [ -d "$iface/wireless" ] || [ -d "$iface/phy80211" ]; then
            local ifname
            ifname=$(basename "$iface")
            if [ -z "$best_iface" ]; then
                best_iface="$ifname"
            fi
            local operstate
            read -r operstate < "$iface/operstate" 2>/dev/null || operstate="unknown"
            if [[ "$operstate" != "down" ]]; then
                best_iface="$ifname"
                break
            fi
        fi
    done
    
    if [ -n "$best_iface" ]; then
        WIFI_IFACE_CACHE="$best_iface"
        WIFI_IFACE_CACHE_TIME=$now
        echo "$best_iface"
        return 0
    fi
    return 1
}

# --- TASKS ---

_task_host_mode() {
    local iface="$1"
    local ip="$2"
    local use_share="$3"
    local mode="$4"
    local ssid="$5"
    local pass="$6"
    local channel="$7"
    
    ensure_dirs
    local host_file="${STORAGE_NET_DIR}/70-wifi-host-${iface}.network"
    local content
    content=$(build_gateway_config "$iface" "$ip" "$use_share" "WiFi Host Mode ($mode)" "yes" "yes")
    secure_write "$host_file" "$content" "644"
    
    reload_networkd
    tune_network_stack "host"
    if [ "$use_share" == "true" ]; then enable_nat_masquerade "$iface"; else disable_nat_masquerade; fi
    
    if ! is_service_active "iwd"; then echo "IWD not running" >&2; exit 1; fi

    iwctl station "$iface" disconnect >/dev/null 2>&1 || true
    
    local ap_conf="${STATE_DIR}/iwd/ap/${ssid}.ap"
    mkdir -p "${STATE_DIR}/iwd/ap"
    
    # Fix: Allow open AP
    local ap_data="[General]\nChannel=${channel:-1}\n"
    if [ -n "$pass" ]; then
        ap_data+="[Security]\nPassphrase=${pass}\n"
    fi
    
    if [ "$mode" != "adhoc" ]; then
         secure_write "$ap_conf" "$ap_data" "600"
    fi
    
    case "$mode" in
        adhoc)
             if [ -n "$pass" ]; then
                printf "%s" "$pass" | iwctl ad-hoc "$iface" start "$ssid" --stdin 2>&1
             else
                iwctl ad-hoc "$iface" start "$ssid" 2>&1
             fi
             ;;
        ap|*)
             iwctl ap "$iface" start-profile "$ssid" 2>&1
             ;;
    esac
}

_task_client_mode() {
    local iface="$1"
    rm -f "${STORAGE_NET_DIR}/70-wifi-host-${iface}.network"
    rm -f "${STORAGE_NET_DIR}/70-share-${iface}.network"
    rm -f "$STORAGE_HOST_NET_FILE"
    reload_networkd
    reconfigure_iface "$iface"
    disable_nat_masquerade
    if [ -d "/sys/class/net/$iface/wireless" ] || [ -d "/sys/class/net/$iface/phy80211" ]; then
        if is_service_active "iwd"; then
            iwctl ap "$iface" stop >/dev/null 2>&1 || true
            # Fix: Disconnect
            iwctl station "$iface" disconnect >/dev/null 2>&1 || true
            iwctl station "$iface" scan >/dev/null 2>&1 || true
        fi
    fi
}

_task_save_wifi_creds() {
    local ssid="$1"
    local pass="$2"
    ensure_dirs
    secure_write "${STATE_DIR}/iwd/${ssid}.psk" "[Security]\nPassphrase=${pass}\n" "600"
}

_task_set_country() {
    local code="$1"
    ensure_dirs
    if iw reg set "$code" 2>/dev/null; then
        echo "$code" > "$STORAGE_COUNTRY_FILE"
    else
        return 1
    fi
}

# --- ACTIONS ---

action_wps() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi

    if ! is_service_active "iwd"; then
        json_error "IWD service not running"
        return 0
    fi

    if iwctl station "$iface" wsc start >/dev/null 2>&1; then
        json_success '{"message": "WPS started. Press button on router.", "iface": "'"$iface"'"}'
    else
        json_error "Failed to start WPS. Ensure interface is in station mode."
    fi
    return 0
}

action_forget() {
    local ssid="$1"
    [ -z "$ssid" ] && { json_error "SSID required"; return 0; }

    # Fix: Wrap in lock
    local iface
    iface=$(get_wifi_iface || echo "global_wifi")
    
    with_iface_lock "$iface" _task_forget "$ssid"
}

_task_forget() {
    local ssid="$1"
    if is_service_active "iwd"; then
        iwctl known-networks "$ssid" forget >/dev/null 2>&1 || true
    fi
    
    local safe_ssid=$(sanitize_ssid "$ssid")
    local removed_count=0
    local config_files=("${STORAGE_NET_DIR}"/75-config-*-"${safe_ssid}".network)
    for f in "${config_files[@]}"; do
        if [ -f "$f" ]; then
            rm -f "$f"
            removed_count=$((removed_count + 1))
        fi
    done
    if [ $removed_count -gt 0 ]; then reload_networkd; fi
    json_success '{"action": "forget", "ssid": "'"$ssid"'", "removed_configs": '"$removed_count"'}'
    return 0
}

action_scan() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then
        json_error "No WiFi interface found"
        return 0
    fi

    if ! is_service_active "iwd"; then
        json_error "IWD service not running"
        return 0
    fi

    local objects_json
    if ! objects_json=$(busctl call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        json_error "Failed to query IWD"
        return 0
    fi

    local device_path
    device_path=$(echo "$objects_json" | jq -r --arg iface "$iface" '.data[] | to_entries[] | select(.value["net.connman.iwd.Device"].Name.data == $iface) | .key')
    
    [ -z "$device_path" ] && { json_error "Interface not managed by IWD"; return 0; }
    
    busctl call net.connman.iwd "$device_path" net.connman.iwd.Station Scan >/dev/null 2>&1 || true
    
    local sleep_sec
    if (( SCAN_POLL_MS < 1000 )); then
        sleep_sec="0.${SCAN_POLL_MS}"
    else
        sleep_sec=$((SCAN_POLL_MS / 1000))
    fi
    
    local max_polls=$((SCAN_TIMEOUT * 1000 / SCAN_POLL_MS))
    for ((i=1; i<=max_polls; i++)); do
        local scanning
        scanning=$(busctl get-property net.connman.iwd "$device_path" net.connman.iwd.Station Scanning --json=short 2>/dev/null | jq -r '.data')
        [ "$scanning" != "true" ] && break
        sleep "$sleep_sec"
    done
    
    objects_json=$(busctl call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    
    echo "$objects_json" | jq -r --arg dev "$device_path" '
        [
            .data[] | to_entries[] | 
            select(.value["net.connman.iwd.Network"] != null) |
            select(.value["net.connman.iwd.Network"].Device.data == $dev) |
            {
                ssid: .value["net.connman.iwd.Network"].Name.data,
                security: .value["net.connman.iwd.Network"].Type.data,
                connected: (.value["net.connman.iwd.Network"].Connected.data == true),
                known: (if .value["net.connman.iwd.Network"].KnownNetwork.data then true else false end),
                signal: (.value["net.connman.iwd.Network"].SignalStrength.data // -10000),
                strength_pct: (
                    (.value["net.connman.iwd.Network"].SignalStrength.data // -10000) as $sig |
                    (($sig / 100) + 100) * 2 |
                    if . > 100 then 100 elif . < 0 then 0 else . end | floor
                )
            }
        ] | unique_by(.ssid) | sort_by(-.signal)
    '
    return 0
}

action_connect() {
    local ssid="$1"; local pass="$2"; local iface="$3"; local hidden="$4"
    [ -n "$ssid" ] || return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi

    # Fix: Handle password for open network or hidden
    if [ -z "${pass:-}" ] && [ -t 0 ] && [[ "$hidden" != "true" ]]; then 
        # Optional: prompt or read
        :
    fi

    if [ -n "$pass" ] && [ "$EPHEMERAL_CREDS" != "true" ]; then
        with_iface_lock "$iface" _task_save_wifi_creds "$ssid" "$pass"
    fi
    
    if ! is_service_active "iwd"; then
        json_error "IWD service not running"
        return 0
    fi

    local cmd="connect"
    [[ "$hidden" == "true" ]] && cmd="connect-hidden"
    
    local attempts=0
    local max_attempts=3
    local out=""
    local pass_file=""
    
    if [ -n "$pass" ]; then
        pass_file=$(mktemp)
        chmod 600 "$pass_file"
        printf "%s" "$pass" > "$pass_file"
    fi
    
    while [ $attempts -lt $max_attempts ]; do
        if [ "$EPHEMERAL_CREDS" == "true" ] && [ -n "${pass:-}" ]; then
             out=$(cat "$pass_file" | iwctl station "$iface" "$cmd" "$ssid" --stdin 2>&1 || true)
        else
             out=$(iwctl station "$iface" "$cmd" "$ssid" 2>&1 || true)
        fi
        if [[ -z "$out" ]]; then
            audit_log "WIFI_CONNECT" "Connected to $ssid"
            json_success '{"connected": true}'
            [ -n "$pass_file" ] && rm -f "$pass_file"
            return 0
        fi
        case "$out" in
            *"Not found"*|*"No such network"*) break ;;
            *"Authentication failed"*) break ;;
            *"Operation already in progress"*) sleep 2 ;;
        esac
        attempts=$((attempts+1))
        sleep 1
    done
    [ -n "$pass_file" ] && rm -f "$pass_file"
    json_error "Failed to connect: $out"
    return 0
}

# Fix: Explicit disconnect action
action_disconnect() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if is_service_active "iwd"; then
        iwctl station "$iface" disconnect >/dev/null 2>&1
        json_success '{"action": "disconnected", "iface": "'"$iface"'"}'
    else
        json_error "IWD not running"
    fi
}

action_host() {
    local ssid="$1"; local pass="$2"; local mode="${3:-ap}"; local share="$4"; local ip="$5"; local iface="$6"; local channel="$7"
    [ -z "$ssid" ] && return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    
    if [ -n "$pass" ] && ! validate_passphrase "$pass"; then json_error "Invalid passphrase"; return 0; fi
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi

    local use_share="false"
    [ "$mode" == "ap" ] && use_share="true"
    [ -n "$share" ] && use_share="$share"

    with_iface_lock "$iface" _task_host_mode "$iface" "$ip" "$use_share" "$mode" "$ssid" "$pass" "$channel"
    json_success '{"status": "host_started"}'
    return 0
}

action_client() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    with_iface_lock "$iface" _task_client_mode "$iface"
    json_success '{"mode": "client", "iface": "'"$iface"'"}'
    return 0
}

action_set_country() {
    local code="$1"
    ! validate_country "$code" && { json_error "Invalid country"; return 0; }
    if with_iface_lock "global_country" _task_set_country "$code"; then
        json_success '{"country": "'"$code"'"}'
    else
        json_error "Failed to set country"
    fi
    return 0
}
