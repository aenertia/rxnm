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
                icon: (.value["org.bluez.Device1"].Icon.data // "unknown"),
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

action_bt_connect() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }

    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    local adapters; adapters=$(_get_dbus_adapters)
    local adapter; adapter=$(echo "$adapters" | head -n1)
    [ -z "$adapter" ] && { json_error "No Bluetooth adapter found"; return 0; }

    local hci_name; hci_name="${adapter##*/}"
    local path; path="/org/bluez/${hci_name}/dev_$(echo "$mac" | tr ':' '_')"

    log_info "Connecting to $mac..."
    if busctl call org.bluez "$path" org.bluez.Device1 Connect --timeout=30s >/dev/null 2>&1; then
        json_success '{"action": "connect", "mac": "'"$mac"'", "status": "connected"}'
    else
        if timeout 30s bluetoothctl connect "$mac" >/dev/null 2>&1; then
            json_success '{"action": "connect", "mac": "'"$mac"'", "status": "connected", "method": "fallback"}'
        else
            json_error "Connect failed for $mac"
        fi
    fi
}

action_bt_disconnect() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }

    local adapters; adapters=$(_get_dbus_adapters)
    local adapter; adapter=$(echo "$adapters" | head -n1)
    [ -z "$adapter" ] && { json_error "No Bluetooth adapter found"; return 0; }

    local hci_name; hci_name="${adapter##*/}"
    local path; path="/org/bluez/${hci_name}/dev_$(echo "$mac" | tr ':' '_')"

    if busctl call org.bluez "$path" org.bluez.Device1 Disconnect --timeout=5s >/dev/null 2>&1; then
        json_success '{"action": "disconnect", "mac": "'"$mac"'", "status": "disconnected"}'
    else
        if timeout 5s bluetoothctl disconnect "$mac" >/dev/null 2>&1; then
            json_success '{"action": "disconnect", "mac": "'"$mac"'", "status": "disconnected", "method": "fallback"}'
        else
            json_error "Disconnect failed for $mac"
        fi
    fi
}

action_bt_list() {
    if [ "$RXNM_HAS_JQ" != "true" ]; then
        json_error "jq required for bluetooth list"
        return 0
    fi

    local objects
    objects=$(busctl call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null)

    if [ -z "$objects" ]; then
        json_success '{"devices": []}'
        return 0
    fi

    local devices
    devices=$(echo "$objects" | "$JQ_BIN" -r '
        [
            .data[0] | to_entries[] |
            select(.value["org.bluez.Device1"] != null) |
            select(.value["org.bluez.Device1"].Paired.data == true) |
            {
                mac: .value["org.bluez.Device1"].Address.data,
                name: (.value["org.bluez.Device1"].Name.data // .value["org.bluez.Device1"].Alias.data // "Unknown"),
                icon: (.value["org.bluez.Device1"].Icon.data // "unknown"),
                connected: (.value["org.bluez.Device1"].Connected.data == true),
                paired: true,
                adapter: .value["org.bluez.Device1"].Adapter.data
            }
        ] | sort_by(.name)
    ')

    json_success "{\"devices\": $devices}"
}

action_bt_enable() {
    log_info "Enabling Bluetooth..."
    if command -v rfkill >/dev/null; then
        rfkill unblock bluetooth 2>/dev/null || true
    fi
    if command -v systemctl >/dev/null && ! is_service_active "bluetooth"; then
        systemctl start bluetooth 2>/dev/null || {
            json_error "Failed to start bluetooth.service"
            return 0
        }
        sleep 1
    fi
    ensure_bluetooth_power || { json_error "Bluetooth hardware not available"; return 0; }
    json_success '{"action": "enable", "status": "enabled"}'
}

action_bt_disable() {
    log_info "Disabling Bluetooth..."
    if command -v rfkill >/dev/null; then
        rfkill block bluetooth 2>/dev/null || true
    fi
    json_success '{"action": "disable", "status": "disabled"}'
}

# Auto-pair: scan for first matching device, pair+trust+connect, then exit.
# Options: --filter input (match Icon=input-*), --mac XX:XX (specific device),
#          --timeout N (default 30s)
action_bt_auto_pair() {
    local filter="" mac="" timeout_sec=30

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --filter) filter="${2:-}"; shift 2 ;;
            --mac) mac="${2:-}"; shift 2 ;;
            --timeout) timeout_sec="${2:-30}"; shift 2 ;;
            *) shift ;;
        esac
    done

    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    # Register temporary agent for passkey auto-accept
    local agent_pid=""
    if command -v bluetoothctl >/dev/null; then
        (echo "agent NoInputNoOutput"; echo "default-agent"; sleep "$timeout_sec") | bluetoothctl >/dev/null 2>&1 &
        agent_pid=$!
        sleep 0.5
    fi

    # Start discovery
    local adapters; adapters=$(_get_dbus_adapters)
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 StartDiscovery >/dev/null 2>&1 || true
    done

    log_info "Auto-pair: scanning (filter=${filter:-any}, timeout=${timeout_sec}s)..."

    local elapsed=0 paired_mac="" paired_name=""
    while [ "$elapsed" -lt "$timeout_sec" ]; do
        sleep 1
        elapsed=$((elapsed + 1))

        # Query all devices
        local objects
        objects=$(busctl call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null) || continue
        [ "$RXNM_HAS_JQ" = "true" ] || continue

        # Find first unpaired device matching filter
        local match
        match=$(echo "$objects" | "$JQ_BIN" -r --arg filter "$filter" --arg mac "$mac" '
            .data[0] | to_entries[] |
            select(.value["org.bluez.Device1"] != null) |
            select(.value["org.bluez.Device1"].Paired.data != true) |
            {
                path: .key,
                mac: .value["org.bluez.Device1"].Address.data,
                name: (.value["org.bluez.Device1"].Name.data // .value["org.bluez.Device1"].Alias.data // "Unknown"),
                icon: (.value["org.bluez.Device1"].Icon.data // "unknown"),
                rssi: (.value["org.bluez.Device1"].RSSI.data // -100)
            } |
            select(
                ($mac != "" and .mac == $mac) or
                ($filter == "input" and (.icon | startswith("input"))) or
                ($filter == "" and $mac == "")
            )
        ' 2>/dev/null | head -n1)

        [ -z "$match" ] && continue

        paired_mac=$(echo "$match" | "$JQ_BIN" -r '.mac')
        paired_name=$(echo "$match" | "$JQ_BIN" -r '.name')
        local dev_path
        dev_path=$(echo "$match" | "$JQ_BIN" -r '.path')

        log_info "Found device: $paired_name ($paired_mac), pairing..."

        # Trust + Pair + Connect
        busctl set-property org.bluez "$dev_path" org.bluez.Device1 Trusted b true 2>/dev/null || true
        if busctl call org.bluez "$dev_path" org.bluez.Device1 Pair --timeout=15s >/dev/null 2>&1; then
            log_info "Paired with $paired_name, connecting..."
            busctl call org.bluez "$dev_path" org.bluez.Device1 Connect --timeout=15s >/dev/null 2>&1 || true
        else
            # Fallback
            timeout 15s bluetoothctl pair "$paired_mac" >/dev/null 2>&1 || true
            timeout 10s bluetoothctl connect "$paired_mac" >/dev/null 2>&1 || true
        fi
        break
    done

    # Cleanup
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 StopDiscovery >/dev/null 2>&1 || true
    done
    [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null

    if [ -n "$paired_mac" ]; then
        json_success '{"status": "paired", "device": {"mac": "'"$paired_mac"'", "name": "'"$paired_name"'"}}'
    else
        json_success '{"status": "timeout", "message": "No matching device found within '"$timeout_sec"'s"}'
    fi
}

# Live-scan: stream discovered devices as JSON-per-line to stdout.
# Runs until killed or --timeout expires.
action_bt_live_scan() {
    local timeout_sec=60

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --timeout) timeout_sec="${2:-60}"; shift 2 ;;
            *) shift ;;
        esac
    done

    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    local adapters; adapters=$(_get_dbus_adapters)
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 StartDiscovery >/dev/null 2>&1 || true
    done

    local prev_macs_file=$(mktemp)
    > "$prev_macs_file"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout_sec" ]; do
        sleep 1
        elapsed=$((elapsed + 1))

        local objects
        objects=$(busctl call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null) || continue
        [ "$RXNM_HAS_JQ" = "true" ] || continue

        # Get current device set
        local current_macs_file=$(mktemp)
        echo "$objects" | "$JQ_BIN" -r '
            .data[0] | to_entries[] |
            select(.value["org.bluez.Device1"] != null) |
            {
                mac: .value["org.bluez.Device1"].Address.data,
                name: (.value["org.bluez.Device1"].Name.data // .value["org.bluez.Device1"].Alias.data // "Unknown"),
                icon: (.value["org.bluez.Device1"].Icon.data // "unknown"),
                rssi: (.value["org.bluez.Device1"].RSSI.data // -100),
                paired: (.value["org.bluez.Device1"].Paired.data == true),
                connected: (.value["org.bluez.Device1"].Connected.data == true)
            } | @json
        ' 2>/dev/null > "$current_macs_file"

        # Emit added events (new MACs not in prev)
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local this_mac
            this_mac=$(echo "$line" | "$JQ_BIN" -r '.mac' 2>/dev/null)
            if ! grep -q "\"$this_mac\"" "$prev_macs_file" 2>/dev/null; then
                echo "{\"event\":\"added\",$(echo "$line" | sed 's/^{//')}"
            fi
        done < "$current_macs_file"

        # Emit removed events (MACs in prev but not current)
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local old_mac
            old_mac=$(echo "$line" | "$JQ_BIN" -r '.mac' 2>/dev/null)
            if ! grep -q "\"$old_mac\"" "$current_macs_file" 2>/dev/null; then
                echo "{\"event\":\"removed\",\"mac\":\"$old_mac\"}"
            fi
        done < "$prev_macs_file"

        cp "$current_macs_file" "$prev_macs_file"
        rm -f "$current_macs_file"
    done
    rm -f "$prev_macs_file"

    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 StopDiscovery >/dev/null 2>&1 || true
    done
}

action_bt_save() {
    local backup="/storage/roms/backups/bluetooth.tar"
    if [ -d /storage/.config/bluetooth ]; then
        mkdir -p "$(dirname "$backup")"
        tar cf "$backup" -C /storage/.config bluetooth 2>/dev/null
        json_success '{"action": "save", "status": "saved", "path": "'"$backup"'"}'
    else
        json_success '{"action": "save", "status": "nothing_to_save"}'
    fi
}

action_bt_restore() {
    local backup="/storage/roms/backups/bluetooth.tar"
    if [ -f "$backup" ]; then
        mkdir -p /storage/.config/bluetooth
        tar xf "$backup" -C /storage/.config 2>/dev/null
        if command -v systemctl >/dev/null; then
            systemctl restart bluetooth 2>/dev/null || true
        fi
        json_success '{"action": "restore", "status": "restored"}'
    else
        json_success '{"action": "restore", "status": "no_backup"}'
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
