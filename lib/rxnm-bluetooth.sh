# ==============================================================================
# BLUETOOTH PAN ACTIONS
# ==============================================================================

_task_pan_net() {
    local cmd="$1"
    local pin="$2"
    local name="$3"
    local custom_ip="$4"
    local mode="${5:-client}"
    local share="$6"
    
    case "$cmd" in
        enable)
            [ -n "$pin" ] && secure_write "$STORAGE_BT_PIN_FILE" "$pin" "600"
            if [ -n "$name" ] && command -v bluetoothctl >/dev/null; then
                validate_bluetooth_name "$name" && bluetoothctl system-alias "$name" >/dev/null 2>&1
            fi

            if [ "$mode" == "host" ] || [ "$mode" == "nap" ]; then
                local is_share="true"
                [ "$share" == "false" ] && is_share="false"
                local content
                content=$(build_gateway_config "bnep*" "$custom_ip" "$is_share" "Bluetooth PAN Host (NAP)" "yes" "yes")
                secure_write "$STORAGE_PAN_NET_FILE" "$content" "644"
                tune_network_stack "host"
                [ "$is_share" == "true" ] && enable_nat_masquerade "bnep+" 
            else
                local content
                content=$(build_network_config "bnep*" "" "yes" "Bluetooth PAN Client (PANU)" "" "" "" "" "" "" "" "" "yes" "yes")
                secure_write "$STORAGE_PAN_NET_FILE" "$content" "644"
                tune_network_stack "client"
                # Fix: Don't disable global NAT just because BT is client
                # disable_nat_masquerade
            fi
            reload_networkd
            ;;
        disable)
            rm -f "$STORAGE_PAN_NET_FILE"
            reload_networkd
            tune_network_stack "client"
            disable_nat_masquerade
            ;;
    esac
}

# --- ACTIONS ---

action_pan_net() {
    local cmd="$1"; local pin="$2"; local name="$3"; local custom_ip="$4"; local mode="$5"; local share="$6"
    check_paths
    
    with_iface_lock "pan_net" _task_pan_net "$cmd" "$pin" "$name" "$custom_ip" "$mode" "$share"
        
    if [ "$cmd" == "enable" ]; then
        json_success '{"status": "enabled", "mode": "'"$mode"'"}'
    else
        json_success '{"status": "disabled"}'
    fi
}

action_bt_scan() {
    if ! command -v bluetoothctl >/dev/null; then
        json_error "bluetoothctl not found"
        return 1
    fi
    
    # Process Safety: Trap interrupts to kill background scan
    local scan_pid=""
    cleanup_scan() {
        if [ -n "$scan_pid" ]; then
            kill "$scan_pid" 2>/dev/null
        fi
        bluetoothctl scan off >/dev/null 2>&1
    }
    trap cleanup_scan EXIT INT TERM

    # Start scan in background
    bluetoothctl scan on >/dev/null 2>&1 &
    scan_pid=$!
    
    # Wait for discovery (blocking on purpose, but safe now)
    sleep 4
    
    cleanup_scan
    trap - EXIT INT TERM # Clear trap
    
    local devices
    devices=$(bluetoothctl devices | awk '{$1=""; print $0}' | sed 's/^ //')
    
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        # Parse into JSON array
        local json="[]"
        if [ -n "$devices" ]; then
             json=$(echo "$devices" | jq -R -s -c 'split("\n")[:-1] | map(split(" ") | {mac: .[0], name: .[1:][]|join(" ")})')
        fi
        json_success "{\"devices\": $json}"
    else
        echo "Bluetooth Devices:"
        echo "$devices"
    fi
}

action_bt_pair() {
    local mac="$1"
    if ! [[ "$mac" =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        json_error "Invalid MAC address"
        return 1
    fi
    
    confirm_action "Pair with device $mac?" "$FORCE_ACTION"
    
    if bluetoothctl pair "$mac"; then
        bluetoothctl trust "$mac"
        json_success '{"action": "paired", "mac": "'"$mac"'"}'
    else
        json_error "Pairing failed"
    fi
}

action_bt_unpair() {
    local mac="$1"
    if bluetoothctl remove "$mac"; then
        json_success '{"action": "unpaired", "mac": "'"$mac"'"}'
    else
        json_error "Unpair failed"
    fi
}
