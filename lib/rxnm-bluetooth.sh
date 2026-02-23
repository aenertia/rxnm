# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-bluetooth.sh
# PURPOSE: Bluetooth Management (BlueZ 5 via DBus/bluetoothctl)
# ARCHITECTURE: Logic / Bluetooth
# -----------------------------------------------------------------------------

# Internal Helper: Get list of adapter object paths from BlueZ
_get_dbus_adapters() {
    if [ "$RXNM_HAS_JQ" = "true" ]; then
        # Query ObjectManager for objects implementing the Adapter1 interface
        busctl --timeout=2s call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null | \
        "$JQ_BIN" -r '.data[0] | to_entries[] | select(.value["org.bluez.Adapter1"] != null) | .key' 2>/dev/null || echo ""
    fi
}

# Description: Ensures Bluetooth is unblocked via rfkill and powered on via BlueZ
ensure_bluetooth_power() {
    # 1. Check RFKill
    local blocked=0
    for rdir in /sys/class/rfkill/rfkill*; do
        [ -e "$rdir/type" ] || continue
        local rtype; read -r rtype < "$rdir/type" 2>/dev/null || rtype=""
        if [ "$rtype" = "bluetooth" ]; then
            local soft; read -r soft < "$rdir/soft" 2>/dev/null || soft=0
            [ "$soft" -eq 1 ] && blocked=1
        fi
    done

    if [ "$blocked" -eq 1 ]; then
        log_info "Unblocking Bluetooth via rfkill..."
        if command -v rfkill >/dev/null; then
            rfkill unblock bluetooth 2>/dev/null || true
            sleep 0.5
        fi
    fi

    # 2. Check DBus connectivity and Power State
    if ! is_service_active "bluetooth" && ! pgrep bluetoothd >/dev/null; then
        return 1
    fi

    local adapters; adapters=$(_get_dbus_adapters)
    if [ -z "$adapters" ]; then
        # If no adapters seen via DBus, bluetoothctl is likely to fail/abort
        log_debug "No Bluetooth adapters found via DBus ObjectManager"
        return 1
    fi

    # Check if any adapter is powered
    local powered="false"
    for adapter in $adapters; do
        local p; p=$(busctl get-property org.bluez "$adapter" org.bluez.Adapter1 Powered --json=short 2>/dev/null | "$JQ_BIN" -r '.data' || echo "false")
        if [ "$p" = "true" ]; then powered="true"; break; fi
    done

    if [ "$powered" = "false" ]; then
        log_info "Powering on Bluetooth adapter..."
        # Use first available adapter
        local first; first=$(echo "$adapters" | head -n1)
        busctl set-property org.bluez "$first" org.bluez.Adapter1 Powered b true 2>/dev/null || \
        timeout 2s bluetoothctl power on >/dev/null 2>&1 || return 1
        sleep 0.5
    fi

    return 0
}

action_bt_scan() {
    local timeout_sec=5
    
    if ! ensure_bluetooth_power; then
        json_error "Bluetooth hardware not found or service unreachable" "1" "Ensure BlueZ is running and adapters are visible in D-Bus"
        return 0
    fi

    log_info "Scanning for Bluetooth devices (Event-driven, up to ${timeout_sec}s)..."
    
    # Start discovery in background via busctl (low latency)
    local adapters; adapters=$(_get_dbus_adapters)
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 StartDiscovery >/dev/null 2>&1 || true
    done

    # Event-driven early exit architecture.
    # Allow 1.5s for initial discovery burst of cached/nearby devices.
    sleep 1.5
    
    # Monitor DBus for *new* device additions. If a new device appears,
    # `head -n 1` consumes the signal and exits, terminating the timeout early.
    # This prevents the socket from blocking unnecessarily if devices are found quickly.
    timeout 3.5s busctl monitor org.bluez --match "type='signal',interface='org.freedesktop.DBus.ObjectManager',member='InterfacesAdded'" | head -n 1 >/dev/null 2>&1 || true

    # Stop discovery
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 StopDiscovery >/dev/null 2>&1 || true
    done

    # Collect results
    local objects
    objects=$(busctl call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)
    
    if [ -z "$objects" ] || [ "$RXNM_HAS_JQ" != "true" ]; then
        json_error "Failed to retrieve scan results from BlueZ"
        return 0
    fi

    local devices
    devices=$(echo "$objects" | "$JQ_BIN" -r '
        [
            .data[0] | to_entries[] | 
            select(.value["org.bluez.Device1"] != null) |
            {
                mac: .value["org.bluez.Device1"].Address.data,
                name: (.value["org.bluez.Device1"].Name.data // .value["org.bluez.Device1"].Alias.data // "Unknown"),
                rssi: (.value["org.bluez.Device1"].RSSI.data // -100),
                connected: (.value["org.bluez.Device1"].Connected.data == true),
                paired: (.value["org.bluez.Device1"].Paired.data == true),
                adapter: .value["org.bluez.Device1"].Adapter.data
            }
        ] | sort_by(.rssi) | reverse
    ')

    json_success "{\"devices\": $devices}"
}

action_bt_pair() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }
    
    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    # Dynamically resolve adapter path instead of hardcoding hci0
    local adapters; adapters=$(_get_dbus_adapters)
    local adapter; adapter=$(echo "$adapters" | head -n1)
    [ -z "$adapter" ] && { json_error "No Bluetooth adapter found"; return 0; }
    
    # Extract hciX from object path
    local hci_name; hci_name="${adapter##*/}"
    local path; path="/org/bluez/${hci_name}/dev_$(echo "$mac" | tr ':' '_')"
    
    log_info "Attempting to pair with $mac..."
    if busctl call org.bluez "$path" org.bluez.Device1 Pair --timeout=30s >/dev/null 2>&1; then
        busctl set-property org.bluez "$path" org.bluez.Device1 Trusted b true 2>/dev/null || true
        json_success '{"action": "pair", "mac": "'"$mac"'", "status": "paired"}'
    else
        # Fallback to bluetoothctl for complex PIN handling if needed
        if timeout 30s bluetoothctl pair "$mac" >/dev/null 2>&1; then
            json_success '{"action": "pair", "mac": "'"$mac"'", "status": "paired", "method": "fallback"}'
        else
            json_error "Pairing failed. Ensure device is in pairing mode."
        fi
    fi
}

action_bt_unpair() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }
    
    # Dynamically resolve adapter path instead of hardcoding hci0
    local adapters; adapters=$(_get_dbus_adapters)
    local adapter; adapter=$(echo "$adapters" | head -n1)
    [ -z "$adapter" ] && { json_error "No Bluetooth adapter found"; return 0; }
    
    local hci_name; hci_name="${adapter##*/}"
    local path; path="/org/bluez/${hci_name}/dev_$(echo "$mac" | tr ':' '_')"
    
    if busctl call org.bluez "$adapter" org.bluez.Adapter1 RemoveDevice o "$path" >/dev/null 2>&1; then
        json_success '{"action": "unpair", "mac": "'"$mac"'", "status": "removed"}'
    else
        if bluetoothctl remove "$mac" >/dev/null 2>&1; then
            json_success '{"action": "unpair", "mac": "'"$mac"'", "status": "removed", "method": "fallback"}'
        else
            json_error "Failed to remove device $mac"
        fi
    fi
}

action_pan_net() {
    local cmd="$1"   # enable/disable
    local iface="$2"
    local addr="$3"
    local ip="$4"
    local mode="${5:-client}"
    local share="${6:-false}"

    if [ "$cmd" = "disable" ]; then
        rm -f "${STORAGE_NET_DIR}/70-bt-pan.network"
        reload_networkd
        json_success '{"action": "pan", "status": "disabled"}'
        return 0
    fi

    # PAN Client Mode logic
    if [ "$mode" = "client" ]; then
        log_info "Configuring BT-PAN Client..."
        local content
        content=$(build_network_config \
            --match-name "bnep*" \
            --dhcp "yes" \
            --description "Bluetooth PAN Client" \
            --mdns "yes")
        secure_write "${STORAGE_NET_DIR}/70-bt-pan.network" "$content" "644"
        reload_networkd
        json_success '{"action": "pan", "mode": "client", "status": "configured"}'
    else
        json_error "BT-PAN Host mode not fully implemented in this version"
    fi
}
