# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-wifi.sh
# PURPOSE: Wireless Interface Management & IWD Abstraction
# ARCHITECTURE: Logic / Wireless
# -----------------------------------------------------------------------------

# Cache variables to avoid repeated sysfs lookups
: "${WIFI_IFACE_CACHE:=}"
: "${WIFI_IFACE_CACHE_TIME:=0}"

# Description: Auto-detects the primary wireless interface.
get_wifi_iface() {
    local preferred="${1:-}"
    if [ -n "$preferred" ]; then echo "$preferred"; return; fi
    
    local now
    now=$(printf '%(%s)T' -1) 2>/dev/null || now=$(date +%s)
    local cache_ttl=30
    
    # Check cache validity
    if [ -n "$WIFI_IFACE_CACHE" ] && [ $((now - WIFI_IFACE_CACHE_TIME)) -lt $cache_ttl ]; then
        if [ -d "/sys/class/net/$WIFI_IFACE_CACHE" ]; then
            echo "$WIFI_IFACE_CACHE"
            return 0
        fi
    fi
    
    local best_iface=""
    local first_iface=""
    
    # POSIX safe iteration over network interfaces
    for iface_path in /sys/class/net/*; do
        [ ! -e "$iface_path" ] && continue
        
        # Detect if wireless
        if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
            local ifname="${iface_path##*/}"
            [ -z "$first_iface" ] && first_iface="$ifname"
            
            # Prefer UP interfaces
            local operstate
            read -r operstate < "$iface_path/operstate" 2>/dev/null || operstate="unknown"
            if [ "$operstate" != "down" ]; then
                best_iface="$ifname"
                break
            fi
        fi
    done
    
    if [ -z "$best_iface" ]; then best_iface="$first_iface"; fi
    
    if [ -n "$best_iface" ]; then
        WIFI_IFACE_CACHE="$best_iface"
        WIFI_IFACE_CACHE_TIME=$now
        echo "$best_iface"
        return 0
    fi
    return 1
}

ensure_interface_active() {
    local iface="$1"
    local needs_wake=0
    
    # Check Administrative State (IFF_UP flag)
    if [ -e "/sys/class/net/$iface/flags" ]; then
        local flags
        read -r flags < "/sys/class/net/$iface/flags"
        # Bitwise logic for POSIX
        if [ "$((flags & 1))" -eq 0 ]; then
            needs_wake=1
        fi
    fi
    
    # Check RFKill State
    if [ "$needs_wake" -eq 0 ]; then
        for rdir in /sys/class/rfkill/rfkill*; do
            [ -e "$rdir/type" ] || continue
            local rtype
            read -r rtype < "$rdir/type" 2>/dev/null || rtype=""
            if [ "$rtype" = "wlan" ]; then
                local soft
                read -r soft < "$rdir/soft" 2>/dev/null || soft=0
                if [ "$soft" -eq 1 ]; then
                    needs_wake=1
                    break
                fi
            fi
        done
    fi
    
    if [ "$needs_wake" -eq 1 ]; then
        if command -v rfkill >/dev/null; then
            rfkill unblock wifi 2>/dev/null || true
        fi
        if [ -e "/sys/class/net/$iface/flags" ]; then
             read -r flags < "/sys/class/net/$iface/flags"
             if [ "$((flags & 1))" -eq 0 ]; then
                ip link set "$iface" up 2>/dev/null || true
                sleep 0.5
             fi
        fi
    fi
}

# --- Host Mode Tasks (AP/AdHoc) ---

_task_host_mode() {
    local iface="$1" ip="$2" use_share="$3" mode="$4" ssid="$5" pass="$6" channel="$7" ipv6_pd="${8:-yes}"
    
    ensure_interface_active "$iface"
    ensure_dirs
    
    # Mask conflicting templates (Batch 3)
    if type build_template_conflict_map >/dev/null 2>&1; then
        local conflicts
        conflicts=$(build_template_conflict_map "$iface" "ap")
        for t in $conflicts; do mask_system_template "$t"; done
    fi
    
    local host_file="${STORAGE_NET_DIR}/70-wifi-host-${iface}.network"
    local content
    content=$(build_gateway_config "$iface" "$ip" "$use_share" "WiFi Host Mode ($mode)" "yes" "yes" "$ipv6_pd")
    secure_write "$host_file" "$content" "644"
    
    reload_networkd
    if is_service_active "systemd-networkd"; then
        timeout 5s networkctl reconfigure "$iface" >/dev/null 2>&1
    fi
    
    tune_network_stack "host"
    if [ "$use_share" = "true" ]; then enable_nat_masquerade "$iface"; else disable_nat_masquerade; fi
    
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
         { set +x; } 2>/dev/null
         secure_write "$ap_conf" "$ap_data" "600"
         set -x 2>/dev/null
    fi
    
    case "$mode" in
        adhoc)
             if [ -n "$pass" ]; then
                { set +x; } 2>/dev/null
                printf "%s" "$pass" | timeout 10s iwctl ad-hoc "$iface" start "$ssid" --stdin 2>&1
                set -x 2>/dev/null
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
    
    if type build_template_conflict_map >/dev/null 2>&1; then
        local conflicts
        conflicts=$(build_template_conflict_map "$iface" "ap")
        for t in $conflicts; do unmask_system_template "$t"; done
    fi
    
    reload_networkd
    reconfigure_iface "$iface"
    disable_nat_masquerade
    
    if [ -d "/sys/class/net/$iface/wireless" ] || [ -d "/sys/class/net/$iface/phy80211" ]; then
        if is_service_active "iwd"; then
            timeout 5s iwctl ap "$iface" stop >/dev/null 2>&1 || true
            timeout 5s iwctl station "$iface" disconnect >/dev/null 2>&1 || true
            timeout 5s iwctl station "$iface" scan >/dev/null 2>&1 || true
        fi
    fi
}

_task_save_wifi_creds() {
    local ssid="$1" pass="$2"
    ensure_dirs
    { set +x; } 2>/dev/null
    secure_write "${STATE_DIR}/iwd/${ssid}.psk" "[Security]\nPassphrase=${pass}\n" "600"
    set -x 2>/dev/null
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
    
    local safe_ssid
    safe_ssid=$(sanitize_ssid "$ssid")
    local removed_count=0
    
    # POSIX safe glob cleanup
    for f in "${STORAGE_NET_DIR}"/75-config-*-"${safe_ssid}".network; do
        if [ -f "$f" ]; then
            rm -f "$f"
            removed_count=$((removed_count + 1))
        fi
    done
    
    if [ "$removed_count" -gt 0 ]; then reload_networkd; fi
    json_success '{"action": "forget", "ssid": "'"$ssid"'", "removed_configs": '"$removed_count"'}'
}

# --- P2P (WiFi Direct) Tasks ---

_task_p2p_scan() {
    local objects_json=""
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        if ! is_service_active "iwd"; then echo "IWD not running" >&2; return 1; fi
        echo "Failed to query IWD DBus" >&2
        return 1
    fi
    
    local p2p_dev_path
    p2p_dev_path=$(echo "$objects_json" | "$JQ_BIN" -r '.data | to_entries[] | select(.value["net.connman.iwd.p2p.Device"] != null) | .key' | head -n1)
    
    [ -z "$p2p_dev_path" ] && { echo "No P2P-capable device found" >&2; return 1; }
    
    busctl --timeout=5s call net.connman.iwd "$p2p_dev_path" net.connman.iwd.p2p.Device RequestDiscovery >/dev/null 2>&1
    
    local sleep_sec
    if [ "$SCAN_POLL_MS" -lt 1000 ]; then sleep_sec="0.${SCAN_POLL_MS}"; else sleep_sec=$((SCAN_POLL_MS / 1000)); fi
    local max_polls=$((SCAN_TIMEOUT * 1000 / SCAN_POLL_MS))
    
    local i=1
    while [ "$i" -le "$max_polls" ]; do
        sleep "$sleep_sec"
        i=$((i + 1))
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
    
    if busctl --timeout=15s call net.connman.iwd "$peer_path" net.connman.iwd.p2p.Peer Connect >/dev/null 2>&1; then
        echo "OK"
        return 0
    else
        echo "P2P Connection Failed" >&2
        return 1
    fi
}

_task_p2p_disconnect() {
    local objects_json
    objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
                   
    local connected_peer
    connected_peer=$(echo "$objects_json" | "$JQ_BIN" -r '
        .data | to_entries[] |
        select(.value["net.connman.iwd.p2p.Peer"] != null) |
        select(.value["net.connman.iwd.p2p.Peer"].Connected.data == true) |
        .key
    ')
    
    if [ -z "$connected_peer" ]; then
        echo "No P2P connection active"
        return 1
    fi
    
    if busctl --timeout=10s call net.connman.iwd "$connected_peer" net.connman.iwd.p2p.Peer Disconnect >/dev/null 2>&1; then
        echo "OK"
        return 0
    else
        echo "Disconnect failed"
        return 1
    fi
}

_task_p2p_status() {
    local objects_json
    objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    
    local net_json="[]"
    if command -v networkctl >/dev/null; then
        net_json=$(timeout 2s networkctl list --json=short 2>/dev/null || echo "[]")
    fi
    
    "$JQ_BIN" -n --argjson net "$net_json" --argjson iwd "$objects_json" '
        ($iwd.data | to_entries[] | select(.value["net.connman.iwd.p2p.Peer"] != null) |
         select(.value["net.connman.iwd.p2p.Peer"].Connected.data == true) |
         {name: .value["net.connman.iwd.p2p.Peer"].Name.data, mac: .value["net.connman.iwd.p2p.Peer"].DeviceAddress.data}
        ) as $peers |
        
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

_task_dpp_enroll() {
    local iface="$1" uri="$2"
    ensure_interface_active "$iface"
    timeout 10s iwctl station "$iface" dpp-start "$uri" >/dev/null 2>&1
}

_task_dpp_stop() {
    local iface="$1"
    timeout 5s iwctl station "$iface" dpp-stop >/dev/null 2>&1
}

# --- Public Actions ---

action_wps() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    
    if ! is_service_active "iwd"; then
        json_error "IWD service not running"
        return 0
    fi
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
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    
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
    device_path=$(echo "$objects_json" | "$JQ_BIN" -r --arg iface "$iface" '.data | to_entries[] | select(.value["net.connman.iwd.Device"].Name.data == $iface) | .key')
    
    [ -z "$device_path" ] && { json_error "Interface not managed by IWD"; return 0; }
    
    busctl --timeout=2s call net.connman.iwd "$device_path" net.connman.iwd.Station Scan >/dev/null 2>&1 || true
    
    local sleep_sec
    if [ "$SCAN_POLL_MS" -lt 1000 ]; then sleep_sec="0.${SCAN_POLL_MS}"; else sleep_sec=$((SCAN_POLL_MS / 1000)); fi
    local max_polls=$((SCAN_TIMEOUT * 1000 / SCAN_POLL_MS))
    
    local i=1
    while [ "$i" -le "$max_polls" ]; do
        local scanning
        scanning=$(busctl --timeout=1s get-property net.connman.iwd "$device_path" net.connman.iwd.Station Scanning --json=short 2>/dev/null | "$JQ_BIN" -r '.data')
        [ "$scanning" != "true" ] && break
        sleep "$sleep_sec"
        i=$((i + 1))
    done
    
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        json_error "Failed to fetch scan results"
        return 0
    fi
    
    local result
    result=$(echo "$objects_json" | "$JQ_BIN" -r --arg dev "$device_path" '
        ([
                .data | to_entries[] |
                select(.value["net.connman.iwd.AccessPoint"] != null) |
                select(.value["net.connman.iwd.AccessPoint"].Device.data == $dev) |
                {
                    network: .value["net.connman.iwd.AccessPoint"].Network.data,
                    bssid: .value["net.connman.iwd.AccessPoint"].HardwareAddress.data,
                    signal: (.value["net.connman.iwd.AccessPoint"].SignalStrength.data // -100),
                    freq: .value["net.connman.iwd.AccessPoint"].Frequency.data
                }
            ] | group_by(.network) | map({key: .[0].network, value: .}) | from_entries
        ) as $ap_map |
        
        [
            .data | to_entries[] |
            select(.value["net.connman.iwd.Network"] != null) |
            select(.value["net.connman.iwd.Network"].Device.data == $dev) |
            {
                ssid: .value["net.connman.iwd.Network"].Name.data,
                security: .value["net.connman.iwd.Network"].Type.data,
                connected: (.value["net.connman.iwd.Network"].Connected.data == true),
                known: (if .value["net.connman.iwd.Network"].KnownNetwork.data then true else false end),
                signal: (.value["net.connman.iwd.Network"].SignalStrength.data // -100),
                bssids: ($ap_map[.key] // [])
            }
        ] |
        map(. + {
            strength_pct: (
                (.signal) as $sig |
                (($sig + 90) * 100 / 60) |
                if . > 100 then 100 elif . < 0 then 0 else . end | floor
            )
        }) |
        unique_by(.ssid) | sort_by(-.signal)
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
            .data | to_entries[] |
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
    local ssid="$1" pass="$2" iface="$3" hidden="$4"
    
    [ -n "$ssid" ] || return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi
    
    if [ -z "${pass:-}" ] && [ -t 0 ] && [ "$hidden" != "true" ]; then
        printf 'Passphrase for %s: ' "$ssid"
        stty -echo; read -r pass; stty echo; echo
    fi
    
    if [ -n "$pass" ] && [ "${EPHEMERAL_CREDS:-false}" != "true" ]; then
        with_iface_lock "$iface" _task_save_wifi_creds "$ssid" "$pass"
    fi
    
    if ! is_service_active "iwd"; then
        json_error "IWD service not running"
        return 0
    fi
    
    ensure_interface_active "$iface"
    log_info "Connecting to $ssid on $iface..."
    
    if is_service_active "systemd-networkd"; then
        timeout 5s networkctl reconfigure "$iface" >/dev/null 2>&1
    fi
    
    if [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --connect "$ssid" --iface "$iface" >/dev/null; then
             audit_log "WIFI_CONNECT" "Connected to $ssid via Agent"
             json_success '{"connected": true, "ssid": "'"$ssid"'", "iface": "'"$iface"'", "method": "agent"}'
             return 0
        fi
        log_debug "Agent connect failed, falling back to iwctl..."
    fi
    
    local cmd="connect"
    [ "$hidden" = "true" ] && cmd="connect-hidden"
    
    local attempts=0
    local max_attempts=3
    local out=""
    
    while [ "$attempts" -lt "$max_attempts" ]; do
        if [ "${EPHEMERAL_CREDS:-false}" = "true" ] && [ -n "${pass:-}" ]; then
             { set +x; } 2>/dev/null
             out=$(printf "%s" "$pass" | timeout 15s iwctl station "$iface" "$cmd" "$ssid" --stdin 2>&1 || true)
             set -x 2>/dev/null
        else
             out=$(timeout 15s iwctl station "$iface" "$cmd" "$ssid" 2>&1 || true)
        fi
        
        if [ -z "$out" ]; then
            local config_exists="false"
            if [ -f "${STORAGE_NET_DIR}/75-config-${iface}.network" ] || [ -f "${STORAGE_NET_DIR}/75-static-${iface}.network" ]; then
                config_exists="true"
            elif [ -f "${PERSISTENT_NET_DIR}/75-config-${iface}.network" ] || [ -f "${PERSISTENT_NET_DIR}/75-static-${iface}.network" ]; then
                config_exists="true"
            fi
            
            if [ "$config_exists" = "false" ]; then
                 log_info "No network configuration found for $iface. Applying default DHCP."
                 if type _task_set_dhcp >/dev/null 2>&1; then
                     with_iface_lock "$iface" _task_set_dhcp "$iface" "" "" "" "" "yes" "yes" ""
                     if is_service_active "systemd-networkd"; then
                         timeout 5s networkctl reconfigure "$iface" >/dev/null 2>&1 || timeout 5s networkctl reload >/dev/null 2>&1
                     else
                         log_warn "networkd missing or inactive. Triggering Rescue Mode (udhcpc)."
                         if type configure_standalone_client >/dev/null 2>&1; then configure_standalone_client "$iface"; fi
                     fi
                 fi
            fi
            
            audit_log "WIFI_CONNECT" "Connected to $ssid via iwctl"
            json_success '{"connected": true, "ssid": "'"$ssid"'", "iface": "'"$iface"'"}'
            return 0
        fi
        
        if echo "$out" | grep -qi "passphrase\|password\|not correct"; then
             json_error "Authentication failed - check password"; return 0
        elif echo "$out" | grep -qi "not found\|no network"; then
             json_error "Network '$ssid' not found"; return 0
        elif echo "$out" | grep -qi "already in progress"; then
             sleep 3
        else
             sleep $((2 * (attempts + 1)))
        fi
        attempts=$((attempts + 1))
    done
    
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
    local ssid="$1" pass="$2" mode="${3:-ap}" share="$4" ip="$5" iface="$6" channel="$7" ipv6_pd="${8:-yes}"
    [ -z "$ssid" ] && return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    
    if [ -n "$pass" ] && ! validate_passphrase "$pass"; then json_error "Invalid passphrase"; return 0; fi
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi
    
    local use_share="false"
    [ "$mode" = "ap" ] && use_share="true"
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
    local output
    if output=$(with_iface_lock "global_wifi" _task_p2p_scan); then json_success "$output"; else json_error "P2P Scan failed"; fi
}

action_p2p_connect() {
    local peer_name="$1"
    [ -z "$peer_name" ] && { json_error "Peer name required"; return 0; }
    if with_iface_lock "global_wifi" _task_p2p_connect "$peer_name"; then
        json_success '{"action": "p2p_connect", "peer": "'"$peer_name"'", "status": "negotiating"}'
    else
        json_error "Failed to initiate P2P connection"
    fi
}

action_p2p_disconnect() {
    local iface="${1:-global_wifi}"
    if with_iface_lock "$iface" _task_p2p_disconnect; then json_success '{"action": "p2p_disconnect", "status": "ok"}'; else json_error "Failed to disconnect P2P peer"; fi
}

action_p2p_status() {
    local output
    if output=$(with_iface_lock "global_wifi" _task_p2p_status); then echo "$output"; else json_error "Failed to retrieve P2P status"; fi
}

action_dpp_enroll() {
    local iface="$1" uri="$2"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    [ -z "$iface" ] && { json_error "No WiFi interface found"; return 0; }
    [ -z "$uri" ] && { json_error "DPP URI string required"; return 0; }
    if ! command -v iwctl >/dev/null; then json_error "iwctl required for DPP"; return 0; fi
    if with_iface_lock "$iface" _task_dpp_enroll "$iface" "$uri"; then
        json_success '{"action": "dpp_enroll", "status": "started", "iface": "'"$iface"'"}'
    else
        json_error "Failed to start DPP enrollment"
    fi
}

action_dpp_stop() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    with_iface_lock "$iface" _task_dpp_stop "$iface"
    json_success '{"action": "dpp_stop", "status": "stopped", "iface": "'"$iface"'"}'
}
