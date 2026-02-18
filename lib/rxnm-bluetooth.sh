# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-bluetooth.sh
# PURPOSE: Bluetooth Networking (PAN/NAP) & Device Management
# ARCHITECTURE: Logic / Bluetooth
#
# Manages Bluetooth adapters, pairing, and specifically the PAN (Personal Area Network)
# profiles for tethering (Client) and sharing (Host/NAP).
# -----------------------------------------------------------------------------

# --- DBus Helpers ---

_get_dbus_adapters() {
    busctl --timeout=2s call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null \
    | "$JQ_BIN" -r '.data | to_entries[] | select(.value["org.bluez.Adapter1"] != null) | .key'
}

_get_dbus_device_path() {
    local mac="$1"
    busctl --timeout=2s call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null \
    | "$JQ_BIN" -r --arg mac "$mac" '.data | to_entries[] | select(.value["org.bluez.Device1"].Address.data == $mac) | .key' | head -n1
}

_get_adapter_for_device() {
    local dev_path="$1"
    busctl --timeout=2s get-property org.bluez "$dev_path" org.bluez.Device1 Adapter --json=short 2>/dev/null | "$JQ_BIN" -r '.data'
}

ensure_bluetooth_power() {
    local blocked=0
    
    # Check RFKill
    for rdir in /sys/class/rfkill/rfkill*; do
        [ -e "$rdir/type" ] || continue
        read -r rtype < "$rdir/type" 2>/dev/null || rtype=""
        if [ "$rtype" == "bluetooth" ]; then
             read -r soft < "$rdir/soft" 2>/dev/null || soft=0
             if [ "$soft" -eq 1 ]; then blocked=1; break; fi
        fi
    done
    
    if [ "$blocked" -eq 1 ] && command -v rfkill >/dev/null; then
        rfkill unblock bluetooth 2>/dev/null || true
    fi
    
    # Power on adapters via DBus
    local adapters
    adapters=$(_get_dbus_adapters)
    
    if [ -z "$adapters" ]; then
        # Fallback to legacy tool if DBus empty (sometimes works)
        timeout 2s bluetoothctl power on >/dev/null 2>&1
        return
    fi
    
    for adapter in $adapters; do
         busctl --timeout=2s set-property org.bluez "$adapter" org.bluez.Adapter1 Powered b true >/dev/null 2>&1
    done
    sleep 0.5
}

# --- PAN Tasks ---

_task_pan_net() {
    local cmd="$1"
    local pin="$2"
    local name="$3"
    local custom_ip="$4"
    local mode="${5:-client}"
    local share="$6"
    
    ensure_bluetooth_power
    
    case "$cmd" in
        enable)
            # Set PIN if provided (Simple pairing)
            [ -n "$pin" ] && secure_write "$STORAGE_BT_PIN_FILE" "$pin" "600"
            
            # Set Alias if provided
            if [ -n "$name" ]; then
                validate_bluetooth_name "$name"
                local adapters=$(_get_dbus_adapters)
                for adapter in $adapters; do
                    busctl --timeout=2s set-property org.bluez "$adapter" org.bluez.Adapter1 Alias s "$name" >/dev/null 2>&1
                done
            fi
            
            if [ "$mode" == "host" ] || [ "$mode" == "nap" ]; then
                # Host/NAP Mode (Sharing internet)
                local is_share="true"
                [ "$share" == "false" ] && is_share="false"
                
                local content
                # Create gateway config for bnep* interfaces
                content=$(build_gateway_config "bnep*" "$custom_ip" "$is_share" "Bluetooth PAN Host (NAP)" "yes" "yes" "yes")
                secure_write "$STORAGE_PAN_NET_FILE" "$content" "644"
                
                tune_network_stack "host"
                [ "$is_share" == "true" ] && enable_nat_masquerade "bnep+"
            else
                # Client Mode (Tethering from phone)
                local content
                # 1.0.0 Refactor: Use named parameters
                content=$(build_network_config \
                    --match-name "bnep*" \
                    --dhcp "yes" \
                    --description "Bluetooth PAN Client (PANU)" \
                    --mdns "yes" \
                    --llmnr "yes")
                    
                secure_write "$STORAGE_PAN_NET_FILE" "$content" "644"
                
                tune_network_stack "client"
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

# --- Public Actions ---

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
    local timeout_sec="${1:-4}"
    
    if ! command -v busctl >/dev/null; then
        json_error "busctl required for DBus operations"
        return 1
    fi
    ensure_bluetooth_power
    
    local adapters
    adapters=$(_get_dbus_adapters)
    
    if [ -z "$adapters" ]; then
        json_error "No Bluetooth adapters found"
        return 1
    fi
    
    # Start Discovery on all adapters
    for adapter in $adapters; do
        busctl --timeout=5s call org.bluez "$adapter" org.bluez.Adapter1 StartDiscovery >/dev/null 2>&1
    done
    
    # Configurable scan duration (default 4s)
    sleep "$timeout_sec"
    
    # Stop Discovery
    for adapter in $adapters; do
        busctl --timeout=2s call org.bluez "$adapter" org.bluez.Adapter1 StopDiscovery >/dev/null 2>&1
    done
    
    # Parse results
    local objects_json
    objects_json=$(busctl --timeout=2s call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    
    local devices
    devices=$(echo "$objects_json" | "$JQ_BIN" -r '
        [
            .data | to_entries[] |
            select(.value["org.bluez.Device1"] != null) |
            {
                mac: .value["org.bluez.Device1"].Address.data,
                name: (.value["org.bluez.Device1"].Name.data // .value["org.bluez.Device1"].Alias.data // "Unknown"),
                rssi: (.value["org.bluez.Device1"].RSSI.data // -100),
                connected: (.value["org.bluez.Device1"].Connected.data == true),
                paired: (.value["org.bluez.Device1"].Paired.data == true),
                adapter: (.value["org.bluez.Device1"].Adapter.data)
            }
        ] | sort_by(-.rssi)
    ')
    
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        json_success "{\"devices\": $devices}"
    else
        echo "Bluetooth Devices:"
        echo "$devices" | "$JQ_BIN" -r '.[] | "\(.mac)  \(.name)  \(.rssi)dBm"'
    fi
}

action_bt_pair() {
    local mac="$1"
    if ! [[ "$mac" =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        json_error "Invalid MAC address"
        return 1
    fi
    ensure_bluetooth_power
    
    confirm_action "Pair with device $mac?" "$FORCE_ACTION"
    
    # Initiate pair
    if ! timeout 20s bluetoothctl pair "$mac"; then
        json_error "Failed to initiate pairing with $mac"
        return 1
    fi
    
    # Check if trust/pair succeeded via DBus (Retry loop for robustness)
    local dev_path
    dev_path=$(_get_dbus_device_path "$mac")
    
    local retries=5
    local success=false
    
    for ((i=0; i<retries; i++)); do
        if [ -z "$dev_path" ]; then
            dev_path=$(_get_dbus_device_path "$mac")
        fi
        
        if [ -n "$dev_path" ]; then
            local paired
            paired=$(busctl --timeout=2s get-property org.bluez "$dev_path" org.bluez.Device1 Paired --json=short 2>/dev/null | "$JQ_BIN" -r '.data')
            
            if [ "$paired" == "true" ]; then
                success=true
                break
            fi
        fi
        sleep 1
    done
    
    if [ "$success" == "true" ]; then
        timeout 5s bluetoothctl trust "$mac" >/dev/null 2>&1
        json_success '{"action": "paired", "mac": "'"$mac"'"}'
        return 0
    fi
    
    json_error "Pairing sequence finished but device not marked as Paired"
    return 1
}

action_bt_unpair() {
    local mac="$1"
    
    local dev_path
    dev_path=$(_get_dbus_device_path "$mac")
    
    if [ -z "$dev_path" ]; then
        json_error "Device $mac not found"
        return 1
    fi
    
    local adapter_path
    adapter_path=$(_get_adapter_for_device "$dev_path")
    
    if [ -z "$adapter_path" ]; then
        json_error "Could not determine adapter for device"
        return 1
    fi
    
    if busctl --timeout=5s call org.bluez "$adapter_path" org.bluez.Adapter1 RemoveDevice o "$dev_path" >/dev/null 2>&1; then
        json_success '{"action": "unpaired", "mac": "'"$mac"'"}'
    else
        json_error "Unpair failed (DBus call error)"
        return 1
    fi
}
