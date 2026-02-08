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
    # Bash 4.2+ optimization: Avoid fork to 'date'
    now=$(printf '%(%s)T' -1) 2>/dev/null || now=$(date +%s)
    local cache_ttl=30
    
    if [ -n "$WIFI_IFACE_CACHE" ] && [ $((now - WIFI_IFACE_CACHE_TIME)) -lt $cache_ttl ]; then
        if [ -d "/sys/class/net/$WIFI_IFACE_CACHE" ]; then
            echo "$WIFI_IFACE_CACHE"
            return 0
        fi
    fi
    
    local best_iface=""
    local first_iface=""
    local interfaces=(/sys/class/net/*)
    for iface in "${interfaces[@]}"; do
        [ ! -e "$iface" ] && continue
        if [ -d "$iface/wireless" ] || [ -d "$iface/phy80211" ]; then
            local ifname
            ifname=$(basename "$iface")
            
            # Track first found as fallback (even if down)
            [ -z "$first_iface" ] && first_iface="$ifname"
            
            local operstate
            read -r operstate < "$iface/operstate" 2>/dev/null || operstate="unknown"
            # Prioritize an interface that is already UP
            if [[ "$operstate" != "down" ]]; then
                best_iface="$ifname"
                break
            fi
        fi
    done
    
    # Fallback to first found if all are down
    if [ -z "$best_iface" ]; then best_iface="$first_iface"; fi
    
    if [ -n "$best_iface" ]; then
        WIFI_IFACE_CACHE="$best_iface"
        WIFI_IFACE_CACHE_TIME=$now
        echo "$best_iface"
        return 0
    fi
    return 1
}

# Stability Helper for RK3326/H700 (Realtek/Broadcom)
# OPTIMIZED: Only calls external tools if sysfs indicates a problem
ensure_interface_active() {
    local iface="$1"
    local needs_wake=0

    # 1. Check Link State (Fast - Sysfs)
    if [ -e "/sys/class/net/$iface/flags" ]; then
        local flags
        read -r flags < "/sys/class/net/$iface/flags"
        # Check if UP bit (0x1) is NOT set
        if (( !(flags & 1) )); then
            needs_wake=1
        fi
    fi

    # 2. Check RFKill State (Fast - Sysfs iteration)
    # Only check if we assume we are UP, to catch Soft Blocks
    if [ "$needs_wake" -eq 0 ]; then
        for rdir in /sys/class/rfkill/rfkill*; do
            [ -e "$rdir/type" ] || continue
            local rtype
            read -r rtype < "$rdir/type" 2>/dev/null || rtype=""
            if [ "$rtype" == "wlan" ]; then
                local soft
                read -r soft < "$rdir/soft" 2>/dev/null || soft=0
                if [ "$soft" -eq 1 ]; then
                    needs_wake=1
                    break
                fi
            fi
        done
    fi

    # 3. Action (Only if needed)
    if [ "$needs_wake" -eq 1 ]; then
        if command -v rfkill >/dev/null; then
            rfkill unblock wifi 2>/dev/null || true
        fi
        
        if [ -e "/sys/class/net/$iface/flags" ]; then
             read -r flags < "/sys/class/net/$iface/flags"
             if (( !(flags & 1) )); then
                ip link set "$iface" up 2>/dev/null || true
                sleep 0.5
             fi
        fi
    fi
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
    local ipv6_pd="${8:-yes}"
    
    ensure_interface_active "$iface"

    ensure_dirs
    local host_file="${STORAGE_NET_DIR}/70-wifi-host-${iface}.network"
    local content
    content=$(build_gateway_config "$iface" "$ip" "$use_share" "WiFi Host Mode ($mode)" "yes" "yes" "$ipv6_pd")
    secure_write "$host_file" "$content" "644"
    
    reload_networkd
    tune_network_stack "host"
    if [ "$use_share" == "true" ]; then enable_nat_masquerade "$iface"; else disable_nat_masquerade; fi
    
    if [ "${RXNM_TEST_MODE:-0}" -ne 1 ] && ! is_service_active "iwd"; then 
        echo "IWD not running" >&2; exit 1
    fi

    timeout 5s iwctl station "$iface" disconnect >/dev/null 2>&1 || true
    
    local ap_conf="${STATE_DIR}/iwd/ap/${ssid}.ap"
    mkdir -p "${STATE_DIR}/iwd/ap"
    
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
                printf "%s" "$pass" | timeout 10s iwctl ad-hoc "$iface" start "$ssid" --stdin 2>&1
             else
                timeout 10s iwctl ad-hoc "$iface" start "$ssid" 2>&1
             fi
             ;;
        ap|*)
             timeout 10s iwctl ap "$iface" start-profile "$ssid" 2>&1
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
            timeout 5s iwctl ap "$iface" stop >/dev/null 2>&1 || true
            timeout 5s iwctl station "$iface" disconnect >/dev/null 2>&1 || true
            # Fire and forget scan to wake interface
            timeout 5s iwctl station "$iface" scan >/dev/null 2>&1 || true
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

_task_forget() {
    local ssid="$1"
    if is_service_active "iwd"; then
        timeout 5s iwctl known-networks "$ssid" forget >/dev/null 2>&1 || true
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
}

# --- P2P TASKS ---

_task_p2p_scan() {
    # Find P2P Device
    local objects_json=""
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        if ! is_service_active "iwd"; then echo "IWD not running" >&2; return 1; fi
        echo "Failed to query IWD DBus" >&2
        return 1
    fi
    
    local p2p_dev_path
    p2p_dev_path=$(echo "$objects_json" | "$JQ_BIN" -r '.data | to_entries[] | select(.value["net.connman.iwd.p2p.Device"] != null) | .key' | head -n1)
    
    [ -z "$p2p_dev_path" ] && { echo "No P2P-capable device found" >&2; return 1; }
    
    # Request Discovery with builtin Timeout
    busctl --timeout=5s call net.connman.iwd "$p2p_dev_path" net.connman.iwd.p2p.Device RequestDiscovery >/dev/null 2>&1
    
    local sleep_sec
    if (( SCAN_POLL_MS < 1000 )); then sleep_sec="0.${SCAN_POLL_MS}"; else sleep_sec=$((SCAN_POLL_MS / 1000)); fi
    local max_polls=$((SCAN_TIMEOUT * 1000 / SCAN_POLL_MS))

    for ((i=1; i<=max_polls; i++)); do
        sleep "$sleep_sec"
    done
    sleep 0.5
    
    objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    
    local peers
    peers=$(echo "$objects_json" | "$JQ_BIN" -r '
        [
            .data | to_entries[] | 
            select(.value["net.connman.iwd.p2p.Peer"] != null) |
            {
                name: .value["net.connman.iwd.p2p.Peer"].Name.data,
                mac: .value["net.connman.iwd.p2p.Peer"].DeviceAddress.data,
                category: .value["net.connman.iwd.p2p.Peer"].PrimaryDeviceType.data,
                connected: (.value["net.connman.iwd.p2p.Peer"].Connected.data == true)
            }
        ] | sort_by(.name)
    ')
    
    echo "{\"peers\": $peers}"
}

_task_p2p_connect() {
    local peer_name="$1"
    
    local objects_json
    objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    
    local peer_path
    peer_path=$(echo "$objects_json" | "$JQ_BIN" -r --arg name "$peer_name" '.data | to_entries[] | select(.value["net.connman.iwd.p2p.Peer"].Name.data == $name) | .key')
    
    [ -z "$peer_path" ] && { echo "Peer '$peer_name' not found" >&2; return 1; }
    
    # Trigger Connect with builtin Timeout
    # Note: Standard IWD Connect() negotiation includes WSC (WPS) handling if needed.
    if busctl --timeout=15s call net.connman.iwd "$peer_path" net.connman.iwd.p2p.Peer Connect >/dev/null 2>&1; then
        echo "OK"
        return 0
    else
        echo "P2P Connection Failed" >&2
        return 1
    fi
}

_task_p2p_status() {
    # Combine IWD info and Networkd state
    local objects_json
    objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    
    local net_json="[]"
    if command -v networkctl >/dev/null; then
        net_json=$(timeout 2s networkctl list --json=short 2>/dev/null || echo "[]")
    fi
    
    # Merge logic
    echo "$objects_json" | "$JQ_BIN" -n --argjson net "$net_json" --argjson iwd "$(cat)" '
        # Find Connected P2P Peers
        ($iwd.data | to_entries[] | select(.value["net.connman.iwd.p2p.Peer"] != null) | 
         select(.value["net.connman.iwd.p2p.Peer"].Connected.data == true) |
         {name: .value["net.connman.iwd.p2p.Peer"].Name.data, mac: .value["net.connman.iwd.p2p.Peer"].DeviceAddress.data}
        ) as $peers |
        
        # Check Networkd for P2P-GO interfaces
        ($net | map(select(.Type == "wlan" or .Name | startswith("p2p"))) | 
         map({name: .Name, type: .Type, state: .OperationalState})
        ) as $ifaces |
        
        {
            success: true,
            peers: [$peers],
            interfaces: $ifaces,
            is_go: ($ifaces | any(.name | startswith("p2p") and .state == "routable"))
        }
    '
}

# --- DPP TASKS ---

_task_dpp_enroll() {
    local iface="$1"
    local uri="$2"
    ensure_interface_active "$iface"
    timeout 10s iwctl station "$iface" dpp-start "$uri" >/dev/null 2>&1
}

_task_dpp_stop() {
    local iface="$1"
    timeout 5s iwctl station "$iface" dpp-stop >/dev/null 2>&1
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

    # Mitigate dormant interface before WPS
    ensure_interface_active "$iface"

    if timeout 5s iwctl station "$iface" wsc start >/dev/null 2>&1; then
        json_success '{"message": "WPS started. Press button on router.", "iface": "'"$iface"'"}'
    else
        json_error "Failed to start WPS. Ensure interface is in station mode."
    fi
    return 0
}

action_forget() {
    local ssid="$1"
    [ -z "$ssid" ] && { json_error "SSID required"; return 0; }

    local iface
    iface=$(get_wifi_iface || echo "global_wifi")
    
    with_iface_lock "$iface" _task_forget "$ssid"
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

    ensure_interface_active "$iface"

    local objects_json=""
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        json_error "Failed to query IWD via DBus"
        return 0
    fi
    
    if [ -z "$objects_json" ]; then
        json_error "IWD returned empty data"
        return 0
    fi

    local device_path
    device_path=$(echo "$objects_json" | "$JQ_BIN" -r --arg iface "$iface" '.data[] | to_entries[] | select(.value["net.connman.iwd.Device"].Name.data == $iface) | .key')
    
    [ -z "$device_path" ] && { json_error "Interface not managed by IWD"; return 0; }
    
    busctl --timeout=2s call net.connman.iwd "$device_path" net.connman.iwd.Station Scan >/dev/null 2>&1 || true
    
    local sleep_sec
    if (( SCAN_POLL_MS < 1000 )); then
        sleep_sec="0.${SCAN_POLL_MS}"
    else
        sleep_sec=$((SCAN_POLL_MS / 1000))
    fi
    
    local max_polls=$((SCAN_TIMEOUT * 1000 / SCAN_POLL_MS))
    
    for ((i=1; i<=max_polls; i++)); do
        local scanning
        # Use builtin timeout for property check
        scanning=$(busctl --timeout=1s get-property net.connman.iwd "$device_path" net.connman.iwd.Station Scanning --json=short 2>/dev/null | "$JQ_BIN" -r '.data')
        [ "$scanning" != "true" ] && break
        sleep "$sleep_sec"
    done
    
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        json_error "Failed to fetch scan results"
        return 0
    fi
    
    local result
    # REMEDIATION: JSON Schema Non-Compliance
    # Implemented scaled signal strength mapping:
    #   -90 dBm -> 0%
    #   -30 dBm -> 100%
    #   Calculation: (dBm - (-90)) * 100 / (-30 - (-90)) = (dBm + 90) * 100 / 60
    #   Clamped strictly between 0 and 100.
    result=$(echo "$objects_json" | "$JQ_BIN" -r --arg dev "$device_path" '
        [
            .data[] | to_entries[] | 
            select(.value["net.connman.iwd.Network"] != null) |
            select(.value["net.connman.iwd.Network"].Device.data == $dev) |
            {
                ssid: .value["net.connman.iwd.Network"].Name.data,
                security: .value["net.connman.iwd.Network"].Type.data,
                connected: (.value["net.connman.iwd.Network"].Connected.data == true),
                known: (if .value["net.connman.iwd.Network"].KnownNetwork.data then true else false end),
                signal: (.value["net.connman.iwd.Network"].SignalStrength.data // -100),
                strength_pct: (
                    (.value["net.connman.iwd.Network"].SignalStrength.data // -100) as $sig |
                    (($sig + 90) * 100 / 60) |
                    if . > 100 then 100 elif . < 0 then 0 else . end | floor
                )
            }
        ] | unique_by(.ssid) | sort_by(-.signal)
    ')
    
    json_success "{\"results\": $result}"
    return 0
}

action_list_known_networks() {
    if ! is_service_active "iwd"; then
        json_error "IWD service not running"
        return 0
    fi

    local objects_json=""
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        json_error "Failed to query IWD"
        return 0
    fi
    
    if [ -z "$objects_json" ]; then
         json_success '{"networks": []}'
         return 0
    fi

    local networks
    networks=$(echo "$objects_json" | "$JQ_BIN" -r '
        [
            .data[] | to_entries[] |
            select(.value["net.connman.iwd.KnownNetwork"] != null) |
            {
                ssid: .value["net.connman.iwd.KnownNetwork"].Name.data,
                security: .value["net.connman.iwd.KnownNetwork"].Type.data,
                hidden: (.value["net.connman.iwd.KnownNetwork"].Hidden.data == true),
                last_connected: (.value["net.connman.iwd.KnownNetwork"].LastConnectedTime.data // "Never")
            }
        ] | sort_by(.ssid)
    ')

    json_success "{\"networks\": $networks}"
    return 0
}

action_connect() {
    local ssid="$1"; local pass="$2"; local iface="$3"; local hidden="$4"
    [ -n "$ssid" ] || return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi

    if [ -z "${pass:-}" ] && [ -t 0 ] && [[ "$hidden" != "true" ]]; then 
        read -r -p "Passphrase for $ssid: " pass
    fi

    if [ -n "$pass" ] && [ "${EPHEMERAL_CREDS:-false}" != "true" ]; then
        with_iface_lock "$iface" _task_save_wifi_creds "$ssid" "$pass"
    fi
    
    if ! is_service_active "iwd"; then
        json_error "IWD service not running"
        return 0
    fi
    
    ensure_interface_active "$iface"

    local cmd="connect"
    [[ "$hidden" == "true" ]] && cmd="connect-hidden"
    
    local attempts=0
    local max_attempts=3
    local retry_delay=2
    local out=""
    local pass_file=""
    
    if [ -n "$pass" ]; then
        pass_file=$(mktemp)
        chmod 600 "$pass_file"
        printf "%s" "$pass" > "$pass_file"
    fi
    
    log_info "Connecting to $ssid on $iface..."
    while [ $attempts -lt $max_attempts ]; do
        if [ "${EPHEMERAL_CREDS:-false}" == "true" ] && [ -n "${pass:-}" ]; then
             out=$(cat "$pass_file" | timeout 15s iwctl station "$iface" "$cmd" "$ssid" --stdin 2>&1 || true)
        else
             out=$(timeout 15s iwctl station "$iface" "$cmd" "$ssid" 2>&1 || true)
        fi
        
        if [[ -z "$out" ]]; then
            local config_exists="false"
            
            # Check for config in EPHEMERAL (RAM/Active) OR PERSISTENT (Disk/Saved) layers.
            # If a user has a static IP config saved in persistent storage, we shouldn't overwrite it
            # with default DHCP just because it hasn't been loaded into RAM yet.
            
            if [ -f "${STORAGE_NET_DIR}/75-config-${iface}.network" ] || \
               [ -f "${STORAGE_NET_DIR}/75-static-${iface}.network" ]; then
                config_exists="true"
            elif [ -f "${PERSISTENT_NET_DIR}/75-config-${iface}.network" ] || \
                 [ -f "${PERSISTENT_NET_DIR}/75-static-${iface}.network" ]; then
                config_exists="true"
            fi
            
            if [ "$config_exists" == "false" ]; then
                 log_info "No network configuration found for $iface. Applying default DHCP."
                 if type _task_set_dhcp &>/dev/null; then
                     with_iface_lock "$iface" _task_set_dhcp "$iface" "" "" "" "" "yes" "yes" ""
                     
                     # REMEDIATION: The "Link-Local" Logic Bug
                     # Explicitly force a reconfigure/reload of networkd to ensure the newly created
                     # ephemeral configuration is picked up immediately. This guards against
                     # race conditions where networkd hasn't noticed the file creation event yet.
                     # Constraint: Check if networkd is actually running (we might be early boot)
                     if command -v networkctl >/dev/null; then
                         if is_service_active "systemd-networkd"; then
                             timeout 5s networkctl reconfigure "$iface" >/dev/null 2>&1 || \
                             timeout 5s networkctl reload >/dev/null 2>&1
                         fi
                     fi
                 else
                     log_warn "Cannot apply default DHCP: Interface library not loaded."
                 fi
            fi

            audit_log "WIFI_CONNECT" "Connected to $ssid"
            json_success '{"connected": true, "ssid": "'"$ssid"'", "iface": "'"$iface"'"}'
            [ -n "$pass_file" ] && rm -f "$pass_file"
            return 0
        fi
        
        if echo "$out" | grep -qi "passphrase\|password\|not correct"; then
             [ -n "$pass_file" ] && rm -f "$pass_file"
             json_error "Authentication failed - check password"
             return 0
        elif echo "$out" | grep -qi "not found\|no network"; then
             [ -n "$pass_file" ] && rm -f "$pass_file"
             json_error "Network '$ssid' not found"
             return 0
        elif echo "$out" | grep -qi "already in progress"; then
             log_warn "Connection in progress, waiting..."
             sleep 3
        else
             log_warn "Connection failed (attempt $((attempts+1))/$max_attempts): $out"
             sleep $((retry_delay * (attempts + 1)))
        fi
        
        attempts=$((attempts+1))
    done
    [ -n "$pass_file" ] && rm -f "$pass_file"
    json_error "Failed to connect: $out"
    return 0
}

action_disconnect() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if is_service_active "iwd"; then
        timeout 5s iwctl station "$iface" disconnect >/dev/null 2>&1
        json_success '{"action": "disconnected", "iface": "'"$iface"'"}'
    else
        json_error "IWD not running"
    fi
}

action_host() {
    local ssid="$1"; local pass="$2"; local mode="${3:-ap}"; local share="$4"; local ip="$5"; local iface="$6"; local channel="$7"; local ipv6_pd="${8:-yes}"
    [ -z "$ssid" ] && return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    
    if [ -n "$pass" ] && ! validate_passphrase "$pass"; then json_error "Invalid passphrase"; return 0; fi
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi

    local use_share="false"
    [ "$mode" == "ap" ] && use_share="true"
    [ -n "$share" ] && use_share="$share"

    with_iface_lock "$iface" _task_host_mode "$iface" "$ip" "$use_share" "$mode" "$ssid" "$pass" "$channel" "$ipv6_pd"
    json_success '{"status": "host_started", "ssid": "'"$ssid"'", "mode": "'"$mode"'", "open": '"$( [ -z "$pass" ] && echo true || echo false )"', "ipv6_pd": "'"$ipv6_pd"'"}'
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

action_p2p_scan() {
    local iface="${1:-global_p2p}"
    # Use global lock to prevent conflict with Station scans
    local output
    if output=$(with_iface_lock "global_wifi" _task_p2p_scan); then
        json_success "$output"
    else
        json_error "P2P Scan failed"
    fi
}

action_p2p_connect() {
    local peer_name="$1"
    [ -z "$peer_name" ] && { json_error "Peer name required"; return 0; }

    local result
    if result=$(with_iface_lock "global_wifi" _task_p2p_connect "$peer_name"); then
        json_success '{"action": "p2p_connect", "peer": "'"$peer_name"'", "status": "negotiating"}'
    else
        json_error "Failed to initiate P2P connection"
    fi
}

action_p2p_disconnect() {
    # Subshell logic to cleanly count disconnected peers
    local disconnect_logic='
    objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    connected_peers=$(echo "$objects_json" | "$JQ_BIN" -r ".data | to_entries[] | select(.value[\"net.connman.iwd.p2p.Peer\"].Connected.data == true) | .key")
    count=0
    for peer in $connected_peers; do
        busctl --timeout=2s call net.connman.iwd "$peer" net.connman.iwd.p2p.Peer Disconnect >/dev/null 2>&1
        count=$((count + 1))
    done
    echo $count
    '
    
    _task_p2p_disconnect_internal() {
        eval "$disconnect_logic"
    }
    
    local count
    count=$(with_iface_lock "global_wifi" _task_p2p_disconnect_internal)
    json_success '{"action": "p2p_disconnect", "count": '"${count:-0}"'}'
}

action_p2p_status() {
    local output
    if output=$(with_iface_lock "global_wifi" _task_p2p_status); then
        echo "$output"
    else
        json_error "Failed to retrieve P2P status"
    fi
}

action_dpp_enroll() {
    local iface="$1"
    local uri="$2"
    
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    [ -z "$iface" ] && { json_error "No WiFi interface found"; return 0; }
    [ -z "$uri" ] && { json_error "DPP URI string required"; return 0; }
    
    if ! command -v iwctl >/dev/null; then json_error "iwctl required for DPP"; return 0; fi
    
    log_info "Starting DPP enrollment on $iface..."
    
    if with_iface_lock "$iface" _task_dpp_enroll "$iface" "$uri"; then
        json_success '{"action": "dpp_enroll", "status": "started", "iface": "'"$iface"'"}'
    else
        json_error "Failed to start DPP enrollment"
    fi
}

action_dpp_stop() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    [ -z "$iface" ] && { json_error "No WiFi interface found"; return 0; }
    
    with_iface_lock "$iface" _task_dpp_stop "$iface"
    json_success '{"action": "dpp_stop", "status": "stopped", "iface": "'"$iface"'"}'
}
