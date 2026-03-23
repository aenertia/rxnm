# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-bluetooth.sh
# PURPOSE: Bluetooth Management (BlueZ 5 via DBus/bluetoothctl)
# ARCHITECTURE: Logic / Bluetooth
# -----------------------------------------------------------------------------

# Map BlueZ Icon to ES menu icon name
# BlueZ: input-gaming, input-keyboard, audio-headphones, computer, phone, etc.
# ES expects: joystick, keyboard, mouse, audio, unknown
_bt_icon_map='
  if startswith("input-gam") or startswith("input-joy") then "joystick"
  elif startswith("input-key") then "keyboard"
  elif startswith("input-mouse") or startswith("input-tablet") then "mouse"
  elif startswith("audio") then "audio"
  else "unknown"
  end
'

# Internal Helper: Get list of adapter object paths from BlueZ
# NOTE: busctl GetManagedObjects --json=short is broken on systemd 255 for
# complex types (a{oa{sa{sv}}}). Use hciconfig + sysfs as fallback.
_get_dbus_adapters() {
    # Try busctl first (works on newer systemd)
    if [ "$RXNM_HAS_JQ" = "true" ]; then
        local result
        result=$(busctl --timeout=2s call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null | \
            "$JQ_BIN" -r '.data[0] | to_entries[] | select(.value["org.bluez.Adapter1"] != null) | .key' 2>/dev/null)
        if [ -n "$result" ]; then
            echo "$result"
            return
        fi
    fi
    # Fallback: enumerate from sysfs
    for hci in /sys/class/bluetooth/hci*; do
        [ -d "$hci" ] && echo "/org/bluez/$(basename "$hci")"
    done
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

    # 2. Check BlueZ is running
    if ! pgrep -x bluetoothd >/dev/null 2>&1; then
        if command -v systemctl >/dev/null && ! systemctl is-active --quiet bluetooth 2>/dev/null; then
            return 1
        fi
    fi

    # 3. Check adapter exists
    if [ ! -d /sys/class/bluetooth/hci0 ]; then
        log_debug "No Bluetooth adapter found in sysfs"
        return 1
    fi

    # 4. Ensure powered on
    local powered
    powered=$(bluetoothctl show 2>/dev/null | grep "Powered:" | awk '{print $2}')
    if [ "$powered" != "yes" ]; then
        log_info "Powering on Bluetooth adapter..."
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
    
    # Start dual-transport discovery (BR/EDR + LE) via busctl
    local adapters; adapters=$(_get_dbus_adapters)
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 SetDiscoveryFilter 'a{sv}' 1 Transport s auto >/dev/null 2>&1 || true
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
                icon: ((.value["org.bluez.Device1"].Icon.data // "unknown") | '"${_bt_icon_map}"'),
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
                icon: ((.value["org.bluez.Device1"].Icon.data // "unknown") | '"${_bt_icon_map}"'),
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

    # bluetoothctl scan in background (dual transport BR/EDR + LE)
    # Poll bluetoothctl devices + info for results (busctl --json=short is
    # broken on systemd 255 for complex ObjectManager responses)
    bluetoothctl --timeout "$timeout_sec" scan on >/dev/null 2>&1 &
    local scan_pid=$!
    trap "kill $scan_pid 2>/dev/null" EXIT

    local seen_file=$(mktemp)
    > "$seen_file"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout_sec" ] && kill -0 "$scan_pid" 2>/dev/null; do
        sleep 2
        elapsed=$((elapsed + 2))

        # Get device list snapshot (filter strictly for "Device XX:XX" lines)
        local devfile=$(mktemp)
        bluetoothctl devices 2>/dev/null | grep -E '^Device [0-9A-Fa-f]{2}:' > "$devfile" || true

        while read -r _ mac name; do
            [ -z "$mac" ] && continue
            grep -q "$mac" "$seen_file" 2>/dev/null && continue
            echo "$mac" >> "$seen_file"

            local info icon="unknown" paired="false" connected="false"
            info=$(bluetoothctl info "$mac" 2>/dev/null)
            local raw_icon
            raw_icon=$(echo "$info" | sed -n 's/.*Icon: *//p' | head -1)
            if [ -n "$raw_icon" ]; then
                case "$raw_icon" in
                    input-gam*|input-joy*) icon="joystick" ;;
                    input-key*)            icon="keyboard" ;;
                    input-mouse*|input-tab*) icon="mouse" ;;
                    audio*)                icon="audio" ;;
                    *)                     icon="unknown" ;;
                esac
            fi
            echo "$info" | grep -q "Paired: yes" && paired="true"
            echo "$info" | grep -q "Connected: yes" && connected="true"

            printf '{"event":"added","mac":"%s","name":"%s","icon":"%s","paired":%s,"connected":%s}\n' \
                "$mac" "$name" "$icon" "$paired" "$connected"
        done < "$devfile"
        rm -f "$devfile"
    done
    rm -f "$seen_file"
    kill "$scan_pid" 2>/dev/null
    wait "$scan_pid" 2>/dev/null
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
