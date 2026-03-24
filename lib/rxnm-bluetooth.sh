# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wiramu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-bluetooth.sh
# PURPOSE: Bluetooth Management (BlueZ 5 via D-Bus / bluetoothctl fallback)
# ARCHITECTURE: Logic / Bluetooth
#
# Primary path: busctl --json=short (systemd 260+, structured JSON)
# Fallback path: bluetoothctl text parsing (POSIX compat, pre-260)
# Scan strategy: adaptive — probe LE capability, fall back to BR/EDR
# -----------------------------------------------------------------------------

# shellcheck disable=SC3043 # Target shells (Ash/Dash) support 'local'

# --- Adapter Quirk Detection ---

# Cached scan mode: "on" (dual), "bredr" (classic-only), "le" (LE-only)
# Probed once per session via _bt_detect_scan_mode().
_BT_SCAN_MODE=""

# Description: Probe adapter LE scan capability. RTL8821CS on kernel 7.0
# returns I/O error on LE scan params. Cached in _BT_SCAN_MODE.
# Returns: "on" | "bredr"
_bt_detect_scan_mode() {
    if [ -n "$_BT_SCAN_MODE" ]; then
        printf '%s' "$_BT_SCAN_MODE"
        return
    fi
    # Probe: attempt LE scan for 1 second
    if timeout 2s hcitool lescan --duplicates >/dev/null 2>&1; then
        _BT_SCAN_MODE="on"
    else
        log_debug "LE scan unavailable (hcitool lescan failed), using BR/EDR"
        _BT_SCAN_MODE="bredr"
    fi
    printf '%s' "$_BT_SCAN_MODE"
}

# Description: Start bluetoothctl scan with adaptive transport mode.
# Uses interactive pipe — ensures power+pairable are set first, then scans.
# Devices are ONLY visible to bluetoothctl sessions that started the scan,
# so this must run in the SAME session as device enumeration.
# Usage: _bt_scan <timeout_seconds>
_bt_scan() {
    local timeout="${1:-10}"
    local mode
    mode=$(_bt_detect_scan_mode)
    (printf 'power on\n'; sleep 0.5;
     printf 'pairable on\nagent NoInputNoOutput\ndefault-agent\n'; sleep 0.5;
     printf 'scan %s\n' "$mode"; sleep "$timeout";
     printf 'scan off\nquit\n') \
        | bluetoothctl >/dev/null 2>&1
}

# Description: Combined scan + collect in a single bluetoothctl session.
# Returns device list from the "devices" command within the same session
# that started discovery — required because BlueZ scopes discoveries per-client.
# Usage: _bt_scan_and_list <timeout_seconds>
# Outputs: lines of "Device XX:XX:XX:XX:XX:XX Name"
_bt_scan_and_list() {
    local timeout="${1:-10}"
    local mode
    mode=$(_bt_detect_scan_mode)
    local outfile
    outfile=$(mktemp) || return 1

    (printf 'power on\n'; sleep 0.5;
     printf 'pairable on\nagent NoInputNoOutput\ndefault-agent\n'; sleep 0.5;
     printf 'scan %s\n' "$mode"; sleep "$timeout";
     printf 'devices\n'; sleep 0.5;
     printf 'scan off\nquit\n') \
        | bluetoothctl 2>/dev/null | grep -E '^\s*Device [0-9A-Fa-f]{2}:' | sed 's/^[[:space:]]*//' > "$outfile"

    cat "$outfile"
    rm -f "$outfile"
}

# --- Icon Mapping ---

# Internal Helper: Map BlueZ Icon string to ES menu icon name
# BlueZ: input-gaming, input-keyboard, audio-headphones, computer, phone, etc.
# ES expects: joystick, keyboard, mouse, audio, unknown
_bt_map_icon() {
    case "${1:-unknown}" in
        input-gam*|input-joy*) printf '%s' "joystick" ;;
        input-key*)            printf '%s' "keyboard" ;;
        input-mouse*|input-tab*) printf '%s' "mouse" ;;
        audio*)                printf '%s' "audio" ;;
        *)                     printf '%s' "unknown" ;;
    esac
}

# --- D-Bus Helpers (busctl primary, bluetoothctl fallback) ---

# Internal Helper: Extract a string field from busctl --json=short output
# Usage: _bt_json_str <json> <field_name>
# Handles: "FieldName":{"type":"s","data":"value"}
_bt_json_str() {
    printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*{[^}]*"data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# Internal Helper: Extract a boolean field from busctl --json=short output
# Usage: _bt_json_bool <json> <field_name>
# Handles: "FieldName":{"type":"b","data":true}
_bt_json_bool() {
    printf '%s' "$1" | grep -q '"'"$2"'"[^}]*"data"[[:space:]]*:[[:space:]]*true' && printf 'true' || printf 'false'
}

# Internal Helper: Extract an integer field from busctl --json=short output
# Usage: _bt_json_int <json> <field_name> <default>
_bt_json_int() {
    local val
    val=$(printf '%s' "$1" | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*{[^}]*"data"[[:space:]]*:[[:space:]]*\(-\{0,1\}[0-9]*\).*/\1/p' | head -1)
    printf '%s' "${val:-${3:-0}}"
}

# Internal Helper: Get list of adapter object paths from BlueZ
# busctl primary (no jq needed), sysfs POSIX fallback
_get_dbus_adapters() {
    local result
    result=$(busctl --json=short --timeout=2s call org.bluez / \
        org.freedesktop.DBus.ObjectManager GetManagedObjects 2>/dev/null)
    if [ -n "$result" ]; then
        # Shell-native extraction: adapter paths near "org.bluez.Adapter1"
        printf '%s' "$result" | grep -o '"/org/bluez/hci[0-9]*"' | tr -d '"'
        return 0
    fi
    # POSIX fallback: sysfs enumeration
    local found=0
    for hci in /sys/class/bluetooth/hci*; do
        if [ -d "$hci" ]; then
            printf '/org/bluez/%s\n' "$(basename "$hci")"
            found=1
        fi
    done
    [ "$found" -eq 0 ] && return 1
    return 0
}

# Internal Helper: Query device properties, emit JSON fragment.
# busctl primary path, bluetoothctl fallback.
# Usage: _bt_query_device <MAC> <NAME>
# Outputs: {"mac":"...","name":"...","icon":"...","rssi":-100,"paired":false,"connected":false}
_bt_query_device() {
    local mac="$1" name="$2"
    local dev_path="/org/bluez/hci0/dev_$(printf '%s' "$mac" | tr ':' '_')"

    # busctl primary: get all Device1 properties as JSON
    local props
    props=$(busctl --json=short call org.bluez "$dev_path" \
        org.freedesktop.DBus.Properties GetAll s org.bluez.Device1 2>/dev/null) || true

    if [ -n "$props" ]; then
        local icon raw_icon paired connected rssi safe_name
        raw_icon=$(_bt_json_str "$props" "Icon")
        icon=$(_bt_map_icon "$raw_icon")
        paired=$(_bt_json_bool "$props" "Paired")
        connected=$(_bt_json_bool "$props" "Connected")
        rssi=$(_bt_json_int "$props" "RSSI" "-100")

        # Prefer Name, fall back to Alias, then caller-supplied name
        local dbus_name
        dbus_name=$(_bt_json_str "$props" "Name")
        [ -z "$dbus_name" ] && dbus_name=$(_bt_json_str "$props" "Alias")
        [ -n "$dbus_name" ] && name="$dbus_name"

        safe_name=$(printf '%s' "$name" | sed 's/\\/\\\\/g; s/"/\\"/g')
        printf '{"mac":"%s","name":"%s","icon":"%s","rssi":%s,"paired":%s,"connected":%s}' \
            "$mac" "$safe_name" "$icon" "$rssi" "$paired" "$connected"
        return
    fi

    # POSIX fallback: bluetoothctl info
    _bt_query_device_ctl "$mac" "$name"
}

# POSIX fallback: query device via bluetoothctl text parsing
_bt_query_device_ctl() {
    local mac="$1" name="$2"
    local info icon="unknown" paired="false" connected="false" rssi="-100"

    info=$(bluetoothctl info "$mac" 2>/dev/null) || true

    if [ -n "$info" ]; then
        local raw_icon
        raw_icon=$(printf '%s' "$info" | sed -n 's/^[[:space:]]*Icon: *//p' | head -1)
        [ -n "$raw_icon" ] && icon=$(_bt_map_icon "$raw_icon")

        printf '%s' "$info" | grep -q "Paired: yes" && paired="true"
        printf '%s' "$info" | grep -q "Connected: yes" && connected="true"

        local rssi_val
        rssi_val=$(printf '%s' "$info" | sed -n 's/^[[:space:]]*RSSI: *\([-0-9]*\).*/\1/p' | head -1)
        [ -n "$rssi_val" ] && rssi="$rssi_val"
    fi

    local safe_name
    safe_name=$(printf '%s' "$name" | sed 's/\\/\\\\/g; s/"/\\"/g')

    printf '{"mac":"%s","name":"%s","icon":"%s","rssi":%s,"paired":%s,"connected":%s}' \
        "$mac" "$safe_name" "$icon" "$rssi" "$paired" "$connected"
}

# Internal Helper: Start dual-transport discovery via adapter D-Bus
_bt_start_discovery() {
    local adapters
    adapters=$(_get_dbus_adapters) || return 1
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 \
            SetDiscoveryFilter 'a{sv}' 1 Transport s auto \
            >/dev/null 2>&1 || true
        busctl call org.bluez "$adapter" org.bluez.Adapter1 \
            StartDiscovery >/dev/null 2>&1 || true
    done
}

# Internal Helper: Stop discovery on all adapters
_bt_stop_discovery() {
    local adapters
    adapters=$(_get_dbus_adapters 2>/dev/null) || return 0
    for adapter in $adapters; do
        busctl call org.bluez "$adapter" org.bluez.Adapter1 \
            StopDiscovery >/dev/null 2>&1 || true
    done
}

# Internal Helper: Collect device list, build JSON array.
# Args: [Paired] — pass "Paired" to filter paired-only
# Outputs: JSON array string: [{"mac":...}, ...]
_bt_collect_devices() {
    local filter="${1:-}"

    # busctl primary: GetManagedObjects for all devices at once
    local managed
    managed=$(busctl --json=short call org.bluez / \
        org.freedesktop.DBus.ObjectManager GetManagedObjects 2>/dev/null) || true

    if [ -n "$managed" ]; then
        _bt_collect_devices_dbus "$managed" "$filter"
        return
    fi

    # POSIX fallback: bluetoothctl enumeration
    _bt_collect_devices_ctl "$filter"
}

# busctl path: parse GetManagedObjects JSON for Device1 entries
_bt_collect_devices_dbus() {
    local json="$1" filter="$2"
    local result="[" first="true"

    # Extract all dev_ paths from the JSON
    local paths
    paths=$(printf '%s' "$json" | grep -o '"/org/bluez/hci[0-9]*/dev_[^"]*"' | tr -d '"')

    for devpath in $paths; do
        # Extract the MAC from path: dev_AA_BB_CC_DD_EE_FF -> AA:BB:CC:DD:EE:FF
        local mac_underscored="${devpath##*/dev_}"
        local mac
        mac=$(printf '%s' "$mac_underscored" | tr '_' ':')

        # Get device properties via busctl (individual call, more reliable than
        # parsing the monster GetManagedObjects JSON per-device)
        local props
        props=$(busctl --json=short call org.bluez "$devpath" \
            org.freedesktop.DBus.Properties GetAll s org.bluez.Device1 2>/dev/null) || continue

        # Filter: paired-only
        if [ "$filter" = "Paired" ]; then
            local is_paired
            is_paired=$(_bt_json_bool "$props" "Paired")
            [ "$is_paired" != "true" ] && continue
        fi

        local name raw_icon icon paired connected rssi safe_name
        name=$(_bt_json_str "$props" "Name")
        [ -z "$name" ] && name=$(_bt_json_str "$props" "Alias")
        [ -z "$name" ] && name="$mac"
        raw_icon=$(_bt_json_str "$props" "Icon")
        icon=$(_bt_map_icon "$raw_icon")
        paired=$(_bt_json_bool "$props" "Paired")
        connected=$(_bt_json_bool "$props" "Connected")
        rssi=$(_bt_json_int "$props" "RSSI" "-100")
        safe_name=$(printf '%s' "$name" | sed 's/\\/\\\\/g; s/"/\\"/g')

        if [ "$first" = "true" ]; then
            first="false"
        else
            result="${result},"
        fi
        result="${result}{\"mac\":\"${mac}\",\"name\":\"${safe_name}\",\"icon\":\"${icon}\",\"rssi\":${rssi},\"paired\":${paired},\"connected\":${connected}}"
    done

    printf '%s]' "$result"
}

# POSIX fallback: bluetoothctl device enumeration
_bt_collect_devices_ctl() {
    local filter="${1:-}"
    local result="[" first="true"
    local devfile
    devfile=$(mktemp) || { printf '[]'; return; }

    if [ -n "$filter" ]; then
        bluetoothctl devices "$filter" 2>/dev/null | grep -E '^Device [0-9A-Fa-f]{2}:' > "$devfile" || true
    else
        bluetoothctl devices 2>/dev/null | grep -E '^Device [0-9A-Fa-f]{2}:' > "$devfile" || true
    fi

    while IFS=' ' read -r _ mac name; do
        [ -z "$mac" ] && continue
        local dev_json
        dev_json=$(_bt_query_device_ctl "$mac" "$name")
        if [ "$first" = "true" ]; then
            first="false"
        else
            result="${result},"
        fi
        result="${result}${dev_json}"
    done < "$devfile"
    rm -f "$devfile"

    printf '%s]' "$result"
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

    # 4. Ensure powered on — busctl primary, bluetoothctl fallback
    local powered
    powered=$(busctl --json=short get-property org.bluez /org/bluez/hci0 \
        org.bluez.Adapter1 Powered 2>/dev/null) || true

    if [ -n "$powered" ]; then
        if printf '%s' "$powered" | grep -q '"data":true'; then
            return 0
        fi
        log_info "Powering on Bluetooth adapter..."
        busctl set-property org.bluez /org/bluez/hci0 \
            org.bluez.Adapter1 Powered b true >/dev/null 2>&1 || \
            timeout 2s bluetoothctl power on >/dev/null 2>&1 || return 1
    else
        # POSIX fallback
        local ctl_powered
        ctl_powered=$(bluetoothctl show 2>/dev/null | sed -n 's/^[[:space:]]*Powered: *//p' | head -1)
        if [ "$ctl_powered" != "yes" ]; then
            log_info "Powering on Bluetooth adapter..."
            timeout 2s bluetoothctl power on >/dev/null 2>&1 || return 1
        fi
    fi

    sleep 0.5
    return 0
}

# --- Public Actions ---

action_bt_scan() {
    local timeout_sec=10

    if ! ensure_bluetooth_power; then
        json_error "Bluetooth hardware not found or service unreachable" "1" \
            "Ensure BlueZ is running and adapters are visible"
        return 0
    fi

    log_info "Scanning for Bluetooth devices (${timeout_sec}s)..."

    # Combined scan+list in single bluetoothctl session (BlueZ scopes per-client)
    local devfile result="[" first="true"
    devfile=$(mktemp) || { json_success '{"devices": []}'; return 0; }
    _bt_scan_and_list "$timeout_sec" > "$devfile"

    while IFS=' ' read -r _ mac name; do
        [ -z "$mac" ] && continue
        local dev_json
        dev_json=$(_bt_query_device "$mac" "$name")
        if [ "$first" = "true" ]; then first="false"; else result="${result},"; fi
        result="${result}${dev_json}"
    done < "$devfile"
    rm -f "$devfile"

    json_success "{\"devices\": ${result}]}"
}

action_bt_list() {
    local devices
    devices=$(_bt_collect_devices "Paired")
    json_success "{\"devices\": ${devices}}"
}

action_bt_pair() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }

    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    # Register temporary agent for passkey auto-accept (NoInputNoOutput)
    local agent_pid=""
    # shellcheck disable=SC2016
    (printf 'agent NoInputNoOutput\ndefault-agent\n'; sleep 35) \
        | bluetoothctl >/dev/null 2>&1 &
    agent_pid=$!
    sleep 0.5

    log_info "Attempting to pair with $mac..."

    # Start brief scan to re-discover device (devices drop from cache quickly)
    _bt_scan 5 &
    local scan_pid=$!
    sleep 3

    # Trust + Pair via bluetoothctl (reliable, handles all PIN modes)
    local paired="false"
    timeout 5s bluetoothctl trust "$mac" >/dev/null 2>&1 || true
    if timeout 30s bluetoothctl pair "$mac" >/dev/null 2>&1; then
        paired="true"
        timeout 10s bluetoothctl connect "$mac" >/dev/null 2>&1 || true
    fi

    kill "$scan_pid" 2>/dev/null
    wait "$scan_pid" 2>/dev/null

    # Cleanup agent
    kill "$agent_pid" 2>/dev/null
    wait "$agent_pid" 2>/dev/null

    if [ "$paired" = "true" ]; then
        json_success '{"action":"pair","mac":"'"$mac"'","status":"paired"}'
    else
        json_error "Pairing failed. Ensure device is in pairing mode."
    fi
}

action_bt_unpair() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }

    local adapters adapter hci_name path
    adapters=$(_get_dbus_adapters)
    adapter=$(printf '%s' "$adapters" | head -n1)
    [ -z "$adapter" ] && { json_error "No Bluetooth adapter found"; return 0; }
    hci_name="${adapter##*/}"
    path="/org/bluez/${hci_name}/dev_$(printf '%s' "$mac" | tr ':' '_')"

    if busctl call org.bluez "$adapter" org.bluez.Adapter1 RemoveDevice o "$path" \
        >/dev/null 2>&1; then
        json_success '{"action":"unpair","mac":"'"$mac"'","status":"removed"}'
    else
        if bluetoothctl remove "$mac" >/dev/null 2>&1; then
            json_success '{"action":"unpair","mac":"'"$mac"'","status":"removed","method":"fallback"}'
        else
            json_error "Failed to remove device $mac"
        fi
    fi
}

action_bt_connect() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }

    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    local adapters adapter hci_name path
    adapters=$(_get_dbus_adapters)
    adapter=$(printf '%s' "$adapters" | head -n1)
    [ -z "$adapter" ] && { json_error "No Bluetooth adapter found"; return 0; }
    hci_name="${adapter##*/}"
    path="/org/bluez/${hci_name}/dev_$(printf '%s' "$mac" | tr ':' '_')"

    log_info "Connecting to $mac..."
    if busctl call org.bluez "$path" org.bluez.Device1 Connect \
        --timeout=30s >/dev/null 2>&1; then
        json_success '{"action":"connect","mac":"'"$mac"'","status":"connected"}'
    else
        if timeout 30s bluetoothctl connect "$mac" >/dev/null 2>&1; then
            json_success '{"action":"connect","mac":"'"$mac"'","status":"connected","method":"fallback"}'
        else
            json_error "Connect failed for $mac"
        fi
    fi
}

action_bt_disconnect() {
    local mac="$1"
    [ -z "$mac" ] && { json_error "MAC address required"; return 0; }

    local adapters adapter hci_name path
    adapters=$(_get_dbus_adapters)
    adapter=$(printf '%s' "$adapters" | head -n1)
    [ -z "$adapter" ] && { json_error "No Bluetooth adapter found"; return 0; }
    hci_name="${adapter##*/}"
    path="/org/bluez/${hci_name}/dev_$(printf '%s' "$mac" | tr ':' '_')"

    if busctl call org.bluez "$path" org.bluez.Device1 Disconnect \
        --timeout=5s >/dev/null 2>&1; then
        json_success '{"action":"disconnect","mac":"'"$mac"'","status":"disconnected"}'
    else
        if timeout 5s bluetoothctl disconnect "$mac" >/dev/null 2>&1; then
            json_success '{"action":"disconnect","mac":"'"$mac"'","status":"disconnected","method":"fallback"}'
        else
            json_error "Disconnect failed for $mac"
        fi
    fi
}

action_bt_enable() {
    log_info "Enabling Bluetooth..."
    if command -v rfkill >/dev/null; then
        rfkill unblock bluetooth 2>/dev/null || true
    fi
    if command -v systemctl >/dev/null; then
        systemctl start bluetooth 2>/dev/null || {
            json_error "Failed to start bluetooth.service"
            return 0
        }
        sleep 1
    fi
    ensure_bluetooth_power || { json_error "Bluetooth hardware not available"; return 0; }
    json_success '{"action":"enable","status":"enabled"}'
}

action_bt_disable() {
    log_info "Disabling Bluetooth..."
    if command -v rfkill >/dev/null; then
        rfkill block bluetooth 2>/dev/null || true
    fi
    json_success '{"action":"disable","status":"disabled"}'
}

# Auto-pair: scan for first matching device, pair+trust+connect, then exit.
# Options: --filter input (match Icon=input-*), --mac XX:XX:... (specific),
#          --timeout N (default 30s)
action_bt_auto_pair() {
    local filter="" target_mac="" timeout_sec=30

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --filter)  filter="${2:-}"; shift 2 ;;
            --mac)     target_mac="${2:-}"; shift 2 ;;
            --timeout) timeout_sec="${2:-30}"; shift 2 ;;
            *) shift ;;
        esac
    done

    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    # Register temporary agent for passkey auto-accept
    local agent_pid=""
    if command -v bluetoothctl >/dev/null; then
        # shellcheck disable=SC2016
        (printf 'agent NoInputNoOutput\ndefault-agent\n'; sleep "$timeout_sec") \
            | bluetoothctl >/dev/null 2>&1 &
        agent_pid=$!
        sleep 0.5
    fi

    # Adaptive scan
    _bt_scan "$timeout_sec" &
    local scan_pid=$!

    log_info "Auto-pair: scanning (filter=${filter:-any}, timeout=${timeout_sec}s)..."

    local elapsed=0 paired_mac="" paired_name=""
    while [ "$elapsed" -lt "$timeout_sec" ]; do
        sleep 2
        elapsed=$((elapsed + 2))

        local devfile
        devfile=$(mktemp) || continue
        bluetoothctl devices 2>/dev/null | grep -E '^Device [0-9A-Fa-f]{2}:' > "$devfile" || true

        while IFS=' ' read -r _ mac name; do
            [ -z "$mac" ] && continue

            # Check if already paired — skip
            local dev_info
            dev_info=$(bluetoothctl info "$mac" 2>/dev/null) || continue
            printf '%s' "$dev_info" | grep -q "Paired: yes" && continue

            # Filter matching
            if [ -n "$target_mac" ]; then
                [ "$mac" != "$target_mac" ] && continue
            elif [ "$filter" = "input" ]; then
                local raw_icon
                raw_icon=$(printf '%s' "$dev_info" | sed -n 's/^[[:space:]]*Icon: *//p' | head -1)
                case "${raw_icon:-}" in
                    input-*) ;;
                    *) continue ;;
                esac
            fi

            paired_mac="$mac"
            paired_name="$name"
            break
        done < "$devfile"
        rm -f "$devfile"

        [ -n "$paired_mac" ] || continue

        log_info "Found device: $paired_name ($paired_mac), pairing..."

        # Trust + Pair + Connect
        timeout 5s bluetoothctl trust "$paired_mac" >/dev/null 2>&1 || true
        if timeout 15s bluetoothctl pair "$paired_mac" >/dev/null 2>&1; then
            log_info "Paired with $paired_name, connecting..."
            timeout 15s bluetoothctl connect "$paired_mac" >/dev/null 2>&1 || true
        fi
        break
    done

    # Cleanup
    kill "$scan_pid" 2>/dev/null
    wait "$scan_pid" 2>/dev/null
    [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null

    if [ -n "$paired_mac" ]; then
        json_success '{"status":"paired","device":{"mac":"'"$paired_mac"'","name":"'"$paired_name"'"}}'
    else
        json_success '{"status":"timeout","message":"No matching device found within '"$timeout_sec"'s"}'
    fi
}

# Live-scan: stream discovered devices as JSON-per-line to stdout.
# Each line: {"event":"added","mac":"...","name":"...","icon":"...","paired":...,"connected":...}
# Runs until killed or --timeout expires.
# NOTE: outputs raw JSON lines (not wrapped in json_success) for streaming.
action_bt_live_scan() {
    local timeout_sec=60

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --timeout) timeout_sec="${2:-60}"; shift 2 ;;
            *) shift ;;
        esac
    done

    ensure_bluetooth_power || { json_error "Bluetooth not available"; return 0; }

    local mode
    mode=$(_bt_detect_scan_mode)

    local seen_file scan_output
    seen_file=$(mktemp) || return 1
    scan_output=$(mktemp) || { rm -f "$seen_file"; return 1; }
    : > "$seen_file"

    # Start interactive bluetoothctl session that scans continuously.
    # We pipe commands in stages and read its stdout for [NEW] Device lines.
    (printf 'power on\n'; sleep 0.5;
     printf 'pairable on\nagent NoInputNoOutput\ndefault-agent\n'; sleep 0.5;
     printf 'scan %s\n' "$mode"; sleep "$timeout_sec";
     printf 'scan off\nquit\n') \
        | bluetoothctl 2>/dev/null > "$scan_output" &
    local scan_pid=$!

    # Cleanup trap
    # shellcheck disable=SC2064
    trap "kill $scan_pid 2>/dev/null; rm -f '$seen_file' '$scan_output'" EXIT INT TERM

    local elapsed=0
    while [ "$elapsed" -lt "$timeout_sec" ] && kill -0 "$scan_pid" 2>/dev/null; do
        sleep 2
        elapsed=$((elapsed + 2))

        # Extract [NEW] Device lines from bluetoothctl output
        local devfile
        devfile=$(mktemp) || continue
        grep -oE 'Device [0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2} .*' \
            "$scan_output" 2>/dev/null | sort -u > "$devfile" || true

        while IFS=' ' read -r _ mac name; do
            [ -z "$mac" ] && continue
            grep -q "$mac" "$seen_file" 2>/dev/null && continue
            printf '%s\n' "$mac" >> "$seen_file"

            local dev_json
            dev_json=$(_bt_query_device "$mac" "$name")
            local body="${dev_json%\}}"
            printf '%s,"event":"added"}\n' "$body"
        done < "$devfile"
        rm -f "$devfile"
    done

    # Cleanup handled by trap
}

action_bt_save() {
    local backup="/storage/roms/backups/bluetooth.tar"
    if [ -d /storage/.config/bluetooth ]; then
        mkdir -p "$(dirname "$backup")"
        tar cf "$backup" -C /storage/.config bluetooth 2>/dev/null
        json_success '{"action":"save","status":"saved","path":"'"$backup"'"}'
    else
        json_success '{"action":"save","status":"nothing_to_save"}'
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
        json_success '{"action":"restore","status":"restored"}'
    else
        json_success '{"action":"restore","status":"no_backup"}'
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
        json_success '{"action":"pan","status":"disabled"}'
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
        json_success '{"action":"pan","mode":"client","status":"configured"}'
    else
        json_error "BT-PAN Host mode not fully implemented in this version"
    fi
}
