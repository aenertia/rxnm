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
                disable_nat_masquerade
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
