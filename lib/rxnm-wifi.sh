# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-wifi.sh
# PURPOSE: Wireless Interface Management & IWD Abstraction
# ARCHITECTURE: Logic / Wireless
# -----------------------------------------------------------------------------

: "${WIFI_IFACE_CACHE:=}"
: "${WIFI_IFACE_CACHE_TIME:=0}"

get_wifi_iface() {
    local now
    now=$(printf '%(%s)T' -1 2>/dev/null) || now=$(date +%s)
    local cache_ttl=30
    
    if [ -n "$WIFI_IFACE_CACHE" ] && [ $((now - WIFI_IFACE_CACHE_TIME)) -lt $cache_ttl ]; then
        if [ -d "/sys/class/net/$WIFI_IFACE_CACHE" ]; then
            echo "$WIFI_IFACE_CACHE"
            return 0
        fi
    fi
    
    local best_iface=""
    local first_iface=""
    
    for iface_path in /sys/class/net/*; do
        [ ! -e "$iface_path" ] && continue
        if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
            local ifname="${iface_path##*/}"
            [ -z "$first_iface" ] && first_iface="$ifname"
            
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
    
    if [ -e "/sys/class/net/$iface/flags" ]; then
        local flags
        read -r flags < "/sys/class/net/$iface/flags"
        if [ "$((flags & 1))" -eq 0 ]; then
            needs_wake=1
        fi
    fi
    
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

_poll_hw_mode() {
    local iface="$1"
    local expected="$2"
    local timeout="${WIFI_MODE_SETTLE_SECS:-2}"
    local start; start=$(date +%s)
    
    while true; do
        local current; current=$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
        if [ "$current" = "$expected" ]; then
            log_debug "Hardware $iface settled into mode: $expected"
            return 0
        fi
        
        local now; now=$(date +%s)
        if [ $((now - start)) -ge "$timeout" ]; then
            log_warn "Hardware $iface failed to settle into mode $expected within ${timeout}s"
            return 1
        fi
        sleep 0.2
    done
}

_task_host_mode() {
    local iface="$1" ip="$2" use_share="$3" mode="$4" ssid="$5" pass="$6" channel="$7" ipv6_pd="${8:-yes}"
    
    ensure_interface_active "$iface"
    ensure_dirs
    
    if [ "${RXNM_TEST_MODE:-0}" -ne 1 ] && ! is_service_active "iwd"; then
        echo "IWD not running" >&2; exit 1
    fi
    
    timeout 5s iwctl station "$iface" disconnect >/dev/null 2>&1 || true
    
    local iw_mode="AP"
    [ "$mode" = "adhoc" ] && iw_mode="IBSS"
    
    if [ "$mode" = "adhoc" ]; then
        timeout 5s iwctl device "$iface" set-property Mode ad-hoc >/dev/null 2>&1 || true
    else
        timeout 5s iwctl device "$iface" set-property Mode ap >/dev/null 2>&1 || true
    fi
    
    _poll_hw_mode "$iface" "$iw_mode"
    
    if type build_template_conflict_map >/dev/null 2>&1; then
        local conflicts; conflicts=$(build_template_conflict_map "$iface" "ap")
        for t in $conflicts; do mask_system_template "$t"; done
    fi
    
    local host_file="${STORAGE_NET_DIR}/65-wifi-host-${iface}.network"
    local content; content=$(build_gateway_config "$iface" "$ip" "$use_share" "WiFi Host Mode ($mode)" "yes" "yes" "$ipv6_pd")
    secure_write "$host_file" "$content" "644"
    
    reload_networkd
    reconfigure_iface "$iface"
    
    tune_network_stack "host"
    
    # Restore the NAT dependency to the bash layer (RXNM Handles NAT, not networkd)
    if [ "$use_share" = "true" ]; then enable_nat_masquerade "$iface"; else disable_nat_masquerade; fi
    
    local ap_conf="${STATE_DIR}/iwd/ap/${ssid}.ap"
    mkdir -p "${STATE_DIR}/iwd/ap"
    
    local ap_data
    ap_data=$(printf '[General]\nChannel=%s\n' "${channel:-1}")
    if [ -n "$pass" ]; then ap_data=$(printf '%s\n[Security]\nPassphrase=%s\n' "$ap_data" "$pass"); fi
    
    if [ "$mode" != "adhoc" ]; then
         local was_x=0; if case $- in *x*) true;; *) false;; esac; then was_x=1; set +x; fi
         secure_write "$ap_conf" "$ap_data" "600"
         if [ "$was_x" -eq 1 ]; then set -x; fi
    fi
    
    case "$mode" in
        adhoc)
             if [ -n "$pass" ]; then
                local was_x=0; if case $- in *x*) true;; *) false;; esac; then was_x=1; set +x; fi
                printf "%s" "$pass" | timeout 10s iwctl ad-hoc "$iface" start "$ssid" --stdin 2>&1
                if [ "$was_x" -eq 1 ]; then set -x; fi
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
    
    if [ -d "/sys/class/net/$iface/wireless" ] || [ -d "/sys/class/net/$iface/phy80211" ]; then
        if is_service_active "iwd"; then
            timeout 5s iwctl ap "$iface" stop >/dev/null 2>&1 || true
            timeout 5s iwctl ad-hoc "$iface" stop >/dev/null 2>&1 || true
            timeout 5s iwctl device "$iface" set-property Mode station >/dev/null 2>&1 || true
            _poll_hw_mode "$iface" "managed"
            timeout 5s iwctl station "$iface" disconnect >/dev/null 2>&1 || true
            timeout 5s iwctl station "$iface" scan >/dev/null 2>&1 || true
        fi
    fi
    
    rm -f "${STORAGE_NET_DIR}/65-wifi-host-${iface}.network"
    rm -f "${STORAGE_NET_DIR}/70-wifi-host-${iface}.network"
    rm -f "${STORAGE_NET_DIR}/70-share-${iface}.network"
    rm -f "$STORAGE_HOST_NET_FILE"
    
    if type build_template_conflict_map >/dev/null 2>&1; then
        local conflicts; conflicts=$(build_template_conflict_map "$iface" "ap")
        for t in $conflicts; do unmask_system_template "$t"; done
    fi
    
    reload_networkd
    reconfigure_iface "$iface"
    disable_nat_masquerade
}

_task_save_wifi_creds() {
    local ssid="$1" pass="$2"
    ensure_dirs
    local safe_ssid; safe_ssid=$(iwd_encode_ssid "$ssid")
    local was_x=0; if case $- in *x*) true;; *) false;; esac; then was_x=1; set +x; fi
    local psk_data
    psk_data=$(printf '[Security]\nPassphrase=%s\n' "$pass")
    secure_write "${STATE_DIR}/iwd/${safe_ssid}.psk" "$psk_data" "600"
    if [ "$was_x" -eq 1 ]; then set -x; fi
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
    local removed_count=0
    for f in "${STORAGE_NET_DIR}"/75-config-*.network; do
        if [ -f "$f" ]; then
            if grep -qFx "SSID=${ssid}" "$f" 2>/dev/null; then
                rm -f "$f"
                removed_count=$((removed_count + 1))
            fi
        fi
    done
    local json_safe_ssid; json_safe_ssid=$(json_escape "$ssid")
    if [ "$removed_count" -gt 0 ]; then reload_networkd; fi
    json_success '{"action": "forget", "ssid": "'"$json_safe_ssid"'", "removed_configs": '"$removed_count"'}'
}

_task_p2p_scan() {
    # P2P operations require busctl + jq (Bash path). POSIX path delegates to agent.
    if [ "$RXNM_HAS_JQ" != "true" ] || ! command -v busctl >/dev/null 2>&1; then
        echo "P2P scan requires jq and busctl" >&2; return 1
    fi

    local objects_json=""
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then
        if ! is_service_active "iwd"; then echo "IWD not running" >&2; return 1; fi
        echo "Failed to query IWD DBus" >&2
        return 1
    fi
    local p2p_dev_path; p2p_dev_path=$(echo "$objects_json" | "$JQ_BIN" -r '.data[0] | to_entries[] | select(.value["net.connman.iwd.p2p.Device"] != null) | .key' | head -n1)
    [ -z "$p2p_dev_path" ] && { echo "No P2P-capable device found" >&2; return 1; }
    
    busctl --timeout=5s call net.connman.iwd "$p2p_dev_path" net.connman.iwd.p2p.Device RequestDiscovery >/dev/null 2>&1
    
    local sleep_sec
    if ! is_integer "$SCAN_POLL_MS"; then SCAN_POLL_MS=100; fi
    if ! is_integer "$SCAN_TIMEOUT"; then SCAN_TIMEOUT=4; fi
    if [ "$SCAN_POLL_MS" -lt 1000 ]; then sleep_sec="0.${SCAN_POLL_MS}"; else sleep_sec=$((SCAN_POLL_MS / 1000)); fi
    local max_polls=$((SCAN_TIMEOUT * 1000 / SCAN_POLL_MS))
    
    local i=1; while [ "$i" -le "$max_polls" ]; do sleep "$sleep_sec"; i=$((i + 1)); done; sleep 0.5
    
    objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    local peers
    peers=$(echo "$objects_json" | "$JQ_BIN" -r '
        [ .data[0] | to_entries[] | select(.value["net.connman.iwd.p2p.Peer"] != null) |
            { name: .value["net.connman.iwd.p2p.Peer"].Name.data, mac: .value["net.connman.iwd.p2p.Peer"].DeviceAddress.data,
              category: .value["net.connman.iwd.p2p.Peer"].PrimaryDeviceType.data, connected: (.value["net.connman.iwd.p2p.Peer"].Connected.data == true)
            }
        ] | sort_by(.name)
    ')
    echo "{\"peers\": $peers}"
}

_task_p2p_connect() {
    local peer_name="$1"
    local objects_json; objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    local peer_path
    # shellcheck disable=SC2016
    peer_path=$(echo "$objects_json" | "$JQ_BIN" -r --arg name "$peer_name" '.data[0] | to_entries[] | select(.value["net.connman.iwd.p2p.Peer"].Name.data == $name) | .key')
    [ -z "$peer_path" ] && { echo "Peer '$peer_name' not found" >&2; return 1; }
    if busctl --timeout=15s call net.connman.iwd "$peer_path" net.connman.iwd.p2p.Peer Connect >/dev/null 2>&1; then echo "OK"; return 0; else echo "P2P Connection Failed" >&2; return 1; fi
}

_task_p2p_disconnect() {
    local objects_json; objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    local connected_peer; connected_peer=$(echo "$objects_json" | "$JQ_BIN" -r '.data[0] | to_entries[] | select(.value["net.connman.iwd.p2p.Peer"] != null) | select(.value["net.connman.iwd.p2p.Peer"].Connected.data == true) | .key')
    if [ -z "$connected_peer" ]; then echo "No P2P connection active"; return 1; fi
    if busctl --timeout=10s call net.connman.iwd "$connected_peer" net.connman.iwd.p2p.Peer Disconnect >/dev/null 2>&1; then echo "OK"; return 0; else echo "Disconnect failed"; return 1; fi
}

_task_p2p_status() {
    local objects_json; objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    local net_json="[]"
    if command -v networkctl >/dev/null; then net_json=$(timeout 2s networkctl list --json=short 2>/dev/null || echo "[]"); fi
    # shellcheck disable=SC2016
    "$JQ_BIN" -n --argjson net "$net_json" --argjson iwd "$objects_json" '
        ($iwd.data[0] | to_entries[] | select(.value["net.connman.iwd.p2p.Peer"] != null) | select(.value["net.connman.iwd.p2p.Peer"].Connected.data == true) | {name: .value["net.connman.iwd.p2p.Peer"].Name.data, mac: .value["net.connman.iwd.p2p.Peer"].DeviceAddress.data}) as $peers |
        ($net | map(select(.Type == "wlan" or .Name | startswith("p2p"))) | map({name: .Name, type: .Type, state: .OperationalState})) as $ifaces |
        { success: true, peers: [$peers], interfaces: $ifaces, is_go: ($ifaces | any(.name | startswith("p2p") and .state == "routable")) }'
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

action_wps() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    if ! is_service_active "iwd"; then json_error "IWD service not running"; return 0; fi
    ensure_interface_active "$iface"
    if timeout 5s iwctl station "$iface" wsc start >/dev/null 2>&1; then json_success '{"message": "WPS started.", "iface": "'"$iface"'"}'
    else json_error "Failed to start WPS. Ensure interface is in station mode."; fi
    return 0
}

action_forget() {
    local ssid="$1"
    [ -z "$ssid" ] && { json_error "SSID required"; return 0; }
    local iface; iface=$(get_wifi_iface || echo "global_wifi")
    with_iface_lock "$iface" _task_forget "$ssid"
    return 0
}

action_scan() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    if ! is_service_active "iwd"; then json_error "IWD service not running"; return 0; fi
    ensure_interface_active "$iface"

    # POSIX guard: busctl + jq required for scan. On BusyBox/ash, fall back to agent --dump.
    if [ "$RXNM_HAS_JQ" != "true" ] || ! command -v busctl >/dev/null 2>&1; then
        if [ -x "$RXNM_AGENT_BIN" ]; then
            local agent_out
            if agent_out=$("$RXNM_AGENT_BIN" --dump 2>/dev/null); then
                json_success "$agent_out"
                return 0
            fi
        fi
        json_error "WiFi scan requires jq and busctl, or rxnm-agent"
        return 0
    fi

    local objects_json=""
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then json_error "Failed to query IWD via DBus"; return 0; fi
    if [ -z "$objects_json" ]; then json_error "IWD returned empty data"; return 0; fi

    local device_path
    # shellcheck disable=SC2016
    device_path=$(echo "$objects_json" | "$JQ_BIN" -r --arg iface "$iface" '.data[0] | to_entries[] | select(.value["net.connman.iwd.Device"].Name.data == $iface) | .key')
    [ -z "$device_path" ] && { json_error "Interface not managed by IWD"; return 0; }
    
    busctl --timeout=2s call net.connman.iwd "$device_path" net.connman.iwd.Station Scan >/dev/null 2>&1 || true
    
    local sleep_sec
    if ! is_integer "$SCAN_POLL_MS"; then SCAN_POLL_MS=100; fi
    if ! is_integer "$SCAN_TIMEOUT"; then SCAN_TIMEOUT=4; fi
    if [ "$SCAN_POLL_MS" -lt 1000 ]; then sleep_sec="0.${SCAN_POLL_MS}"; else sleep_sec=$((SCAN_POLL_MS / 1000)); fi
    local max_polls=$((SCAN_TIMEOUT * 1000 / SCAN_POLL_MS))
    
    local i=1; while [ "$i" -le "$max_polls" ]; do
        local scanning; scanning=$(busctl --timeout=1s get-property net.connman.iwd "$device_path" net.connman.iwd.Station Scanning --json=short 2>/dev/null | "$JQ_BIN" -r '.data')
        [ "$scanning" != "true" ] && break
        sleep "$sleep_sec"; i=$((i + 1))
    done
    
    if ! objects_json=$(busctl --timeout=2s call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null); then json_error "Failed to fetch scan results"; return 0; fi
    
    # strength_pct formula maps signal [-90, -30] dBm to 0-100% percentage
    local result
    # shellcheck disable=SC2016
    result=$(echo "$objects_json" | "$JQ_BIN" -r --arg dev "$device_path" '
        ([ .data[0] | to_entries[] | select(.value["net.connman.iwd.AccessPoint"] != null) | select(.value["net.connman.iwd.AccessPoint"].Device.data == $dev) | { network: .value["net.connman.iwd.AccessPoint"].Network.data, bssid: .value["net.connman.iwd.AccessPoint"].HardwareAddress.data, signal: (.value["net.connman.iwd.AccessPoint"].SignalStrength.data // -100), freq: .value["net.connman.iwd.AccessPoint"].Frequency.data } ] | group_by(.network) | map({key: .[0].network, value: .}) | from_entries ) as $ap_map |
        [ .data[0] | to_entries[] | select(.value["net.connman.iwd.Network"] != null) | select(.value["net.connman.iwd.Network"].Device.data == $dev) | { ssid: .value["net.connman.iwd.Network"].Name.data, security: .value["net.connman.iwd.Network"].Type.data, connected: (.value["net.connman.iwd.Network"].Connected.data == true), known: (if .value["net.connman.iwd.Network"].KnownNetwork.data then true else false end), signal: (.value["net.connman.iwd.Network"].SignalStrength.data // -100), bssids: ($ap_map[.key] // []) } ] |
        map(. + { strength_pct: ( (.signal) as $sig | (($sig + 90) * 100 / 60) | if . > 100 then 100 elif . < 0 then 0 else . end | floor ) }) | unique_by(.ssid) | sort_by(-.signal) ')
    
    json_success "{\"results\": $result}"
    return 0
}

_list_networks_posix() {
    local result="[" first="true"
    for f in /var/lib/iwd/*.psk /var/lib/iwd/*.8021x /var/lib/iwd/*.open; do
        [ -f "$f" ] || continue
        local fname="${f##*/}"
        local ssid="${fname%.*}"
        local sec="${fname##*.}"
        [ "$first" = "true" ] && first="false" || result="${result},"
        local safe_ssid; safe_ssid=$(json_escape "$ssid")
        local safe_sec; safe_sec=$(json_escape "$sec")
        result="${result}{\"ssid\":\"${safe_ssid}\",\"security\":\"${safe_sec}\"}"
    done
    json_success '{"networks":'"${result}]"'}'
}

action_list_known_networks() {
    if ! is_service_active "iwd"; then json_error "IWD service not running"; return 0; fi
    if [ -x "$RXNM_AGENT_BIN" ]; then
        local output
        if output=$("$RXNM_AGENT_BIN" --list-networks 2>/dev/null); then json_success "$output"; return 0; fi
    fi
    if [ "${RXNM_FORMAT:-human}" = "json" ]; then _list_networks_posix; return 0; fi
    iwctl known-networks list 2>/dev/null
    return 0
}

_ensure_wifi_netconfig() {
    local iface="$1"
    local found="false"
    for f in "${STORAGE_NET_DIR}/75-config-${iface}.network" "${STORAGE_NET_DIR}/75-static-${iface}.network" "${PERSISTENT_NET_DIR}/75-config-${iface}.network" "${PERSISTENT_NET_DIR}/75-static-${iface}.network"; do
        if [ -s "$f" ]; then found="true"; break; fi
    done
    if [ "$found" = "false" ]; then
        log_info "No network config for $iface; applying default DHCP."
        if type _task_set_dhcp >/dev/null 2>&1; then
            with_iface_lock "$iface" _task_set_dhcp --iface "$iface" --mdns yes --llmnr yes
            if is_service_active "systemd-networkd"; then timeout 5s networkctl reconfigure "$iface" >/dev/null 2>&1 || true
            else type configure_standalone_client >/dev/null 2>&1 && configure_standalone_client "$iface"; fi
        fi
    fi
}

action_connect() {
    local ssid="$1" pass="$2" iface="$3" hidden="$4"
    [ -n "$ssid" ] || return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if [ -z "$iface" ]; then json_error "No WiFi interface found"; return 0; fi
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi
    
    if [ -z "${pass:-}" ] && [ -t 0 ] && [ "$hidden" != "true" ]; then
        printf 'Passphrase for %s: ' "$ssid"
        _restore_tty() { stty echo 2>/dev/null; }
        trap '_restore_tty' INT TERM HUP
        stty -echo
        read -r pass
        _restore_tty
        trap - INT TERM HUP
        echo
    fi
    
    if [ -n "$pass" ]; then if ! validate_passphrase "$pass"; then return 0; fi; fi
    [ -n "$pass" ] && [ "${EPHEMERAL_CREDS:-false}" != "true" ] && with_iface_lock "$iface" _task_save_wifi_creds "$ssid" "$pass"
    if ! is_service_active "iwd"; then json_error "IWD service not running"; return 0; fi
    
    ensure_interface_active "$iface"
    log_info "Connecting to $ssid on $iface..."
    local safe_ssid; safe_ssid=$(json_escape "$ssid")
    
    if [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --connect "$ssid" --iface "$iface" >/dev/null; then
             audit_log "WIFI_CONNECT" "Connected to $ssid via Agent"
             json_success '{"connected": true, "ssid": "'"$safe_ssid"'", "iface": "'"$iface"'", "method": "agent"}'
             return 0
        fi
    fi
    
    local cmd="connect"
    [ "$hidden" = "true" ] && cmd="connect-hidden"
    _ensure_wifi_netconfig "$iface"
    
    local attempts=0
    while [ "$attempts" -lt 3 ]; do
        local skip_cmd="false"
        local conn_state; conn_state=$(iwctl station "$iface" show 2>/dev/null | grep -i "State" | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')
        case "$conn_state" in connecting|authenticating) skip_cmd="true" ;; esac

        if [ "$skip_cmd" = "false" ]; then
            if [ "${EPHEMERAL_CREDS:-false}" = "true" ] && [ -n "${pass:-}" ]; then
                 local was_x=0; if case $- in *x*) true;; *) false;; esac; then was_x=1; set +x; fi
                 printf "%s" "$pass" | timeout 15s iwctl station "$iface" "$cmd" "$ssid" --stdin >/dev/null 2>&1 || true
                 if [ "$was_x" -eq 1 ]; then set -x; fi
            else
                 timeout 15s iwctl station "$iface" "$cmd" "$ssid" >/dev/null 2>&1 || true
            fi
        fi
        
        sleep 2
        conn_state=$(iwctl station "$iface" show 2>/dev/null | grep -i "State" | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')
        case "$conn_state" in
            connected)
                reconfigure_iface "$iface"
                audit_log "WIFI_CONNECT" "Connected to $ssid via iwctl"
                json_success '{"connected":true,"ssid":"'"$safe_ssid"'","iface":"'"$iface"'"}'
                return 0
                ;;
            disconnected)
                json_error "Authentication failed - check passphrase or network range"
                return 0
                ;;
            connecting|authenticating) attempts=$((attempts + 1)); continue ;;
            *"not found"*|*"no network"*) json_error "Network '$ssid' not found"; return 0 ;;
        esac
        attempts=$((attempts + 1))
        sleep $((attempts * 2))
    done
    json_error "Failed to connect to $ssid"
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
    local iface="$1" ip="$2" share="$3" mode="${4:-ap}" ssid="$5" pass="$6" channel="$7" ipv6_pd="${8:-yes}"
    [ -z "$ssid" ] && return 0
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    if ! is_service_active "iwd"; then json_error "IWD service not running"; return 1; fi
    if [ -n "$pass" ] && ! validate_passphrase "$pass"; then json_error "Invalid passphrase"; return 0; fi
    if ! validate_ssid "$ssid"; then json_error "Invalid SSID"; return 0; fi
    
    local use_share="false"
    [ "$mode" = "ap" ] && use_share="true"
    [ -n "$share" ] && [ "$share" = "true" ] && use_share="true"
    
    local safe_ssid; safe_ssid=$(json_escape "$ssid")
    if ! with_iface_lock "$iface" _task_host_mode "$iface" "$ip" "$use_share" "$mode" "$ssid" "$pass" "$channel" "$ipv6_pd"; then
        json_error "Failed to start Hotspot mode"
        return 1
    fi
    json_success '{"status": "host_started", "ssid": "'"$safe_ssid"'", "mode": "'"$mode"'", "open": '"$( [ -z "$pass" ] && echo true || echo false )"', "ipv6_pd": "'"$ipv6_pd"'"}'
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
    if with_iface_lock "global_country" _task_set_country "$code"; then json_success '{"country": "'"$code"'"}'; else json_error "Failed to set country"; fi
    return 0
}

action_p2p_scan() {
    local output
    if output=$(with_iface_lock "global_wifi" _task_p2p_scan); then json_success "$output"; else json_error "P2P Scan failed"; fi
}

action_p2p_connect() {
    local peer_name="$1"
    [ -z "$peer_name" ] && { json_error "Peer name required"; return 0; }
    local safe_peer; safe_peer=$(json_escape "$peer_name")
    if with_iface_lock "global_wifi" _task_p2p_connect "$peer_name"; then json_success '{"action": "p2p_connect", "peer": "'"$safe_peer"'", "status": "negotiating"}'; else json_error "Failed to initiate P2P connection"; fi
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
    if with_iface_lock "$iface" _task_dpp_enroll "$iface" "$uri"; then json_success '{"action": "dpp_enroll", "status": "started", "iface": "'"$iface"'"}'
    else json_error "Failed to start DPP enrollment"; fi
}

action_dpp_stop() {
    local iface="$1"
    [ -z "$iface" ] && iface=$(get_wifi_iface || echo "")
    with_iface_lock "$iface" _task_dpp_stop "$iface"
    json_success '{"action": "dpp_stop", "status": "stopped", "iface": "'"$iface"'"}'
}
