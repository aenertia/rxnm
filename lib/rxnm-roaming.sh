# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-roaming.sh
# PURPOSE: Opportunistic Roaming & Profile Steering Engine
# ARCHITECTURE: Logic / Roaming
#
# Implements a passive/active monitor that:
# 1. Observes signal strength (RSSI)
# 2. Maps BSSIDs to GPS/Location contexts (conceptually) via Profile mapping
# 3. Triggers "Nudge" scans to force IWD to roam when signal degrades
# 4. Swaps RXNM Profiles (VPNs/Proxies) based on connected SSID/Gateway
# -----------------------------------------------------------------------------

# Internal State Tracking
LAST_SCAN_TIME=0
LAST_MATCH_VAL=""
CURRENT_PROFILE=""
NUDGE_COUNT=0
LAST_NUDGE_BSSID=""

# Map Storage (Session-based in RAM)
ROAM_MAP_FILE="${RUN_DIR:-/run/rocknix}/roaming_map.json"

log_roam() {
    if [ -t 2 ]; then
        echo "[ROAM] $1" >&2
    else
        echo "[ROAM] $1"
    fi
}

# Load user configuration overrides
load_roaming_config() {
    : "${ROAM_STRATEGY:=passive}"        # passive (events) or active (polling)
    : "${RXNM_FEATURE_STEERING:=true}"   # Band/AP steering
    : "${RXNM_FEATURE_PROFILES:=true}"   # Profile switching
    : "${RXNM_FEATURE_MAP:=true}"        # BSSID Mapping
    : "${ROAM_THRESHOLD_KICK:=-75}"      # dBm to trigger scan
    : "${ROAM_THRESHOLD_SEEK:=-65}"      # dBm to seek 5GHz/6GHz
    : "${SCAN_COOLDOWN_PANIC:=10}"       # Seconds between panic scans
    : "${SCAN_COOLDOWN_SEEK:=120}"       # Seconds between optimization scans
    : "${BAND_5G_MIN:=5000}"             # MHz
    : "${BAND_6G_MIN:=5900}"             # MHz
    : "${MAX_NUDGE_BACKOFF:=3600}"       # Max linear backoff
    
    local conf_file="${CONF_DIR}/rxnm-roaming.conf"
    if [ -f "$conf_file" ]; then
        log_roam "Loading configuration from $conf_file"
        source "$conf_file"
    fi
}

# Update the known BSSID map with latest scan results
update_roaming_map() {
    local iface="$1"
    [ "${RXNM_FEATURE_MAP:-true}" != "true" ] && return
    
    with_iface_lock "roam_map" _task_update_map "$iface"
}

_task_update_map() {
    local iface="$1"
    local scan_json
    # Fetch latest scan results (cached by IWD usually)
    scan_json=$(rxnm wifi scan --interface "$iface" --format json 2>/dev/null || echo "{}")
    
    if [[ "$scan_json" == *"results"* ]]; then
        local now; now=$(date +%s)
        local current_map="{}"
        [ -f "$ROAM_MAP_FILE" ] && current_map=$(cat "$ROAM_MAP_FILE")
        
        # Merge new scan data into map
        "$JQ_BIN" -n --argjson map "$current_map" --argjson scan "$scan_json" --arg now "$now" '
            ($scan.results | map(
                (.bssids // []) | map({
                    key: .bssid,
                    value: {
                        ssid: .ssid,
                        freq: .freq,
                        rssi: .signal,
                        last_seen: ($now | tonumber)
                    }
                })
            ) | flatten | from_entries) as $new_data |
            $map * $new_data
        ' > "$ROAM_MAP_FILE"
    fi
}

# Main Logic Evaluation Loop
evaluate_roaming_state() {
    local iface="$1"
    local is_oneshot="${2:-false}"
    
    local rssi="" ssid="" freq="" gateway="" bssid=""
    
    # 1. Fetch Core Context (Hybrid Fastpath)
    # Use Agent if available for atomic fetch, else fallback to iwctl/ip
    if [ -x "$RXNM_AGENT_BIN" ]; then
        local tsv_data
        tsv_data=$("$RXNM_AGENT_BIN" --dump 2>/dev/null | \
            "$JQ_BIN" -r ".interfaces[\"$iface\"] | \"\(.wifi.rssi // -100)\t\(.wifi.ssid // \"\")\t\(.wifi.frequency // 0)\t\(.gateway // \"\")\t\(.wifi.bssid // \"\")\"")
            
        if [ -n "$tsv_data" ]; then
            IFS=$'\t' read -r rssi ssid freq gateway bssid <<< "$tsv_data"
        fi
    else
        local status
        status=$(iwctl station "$iface" show 2>/dev/null)
        if [ -n "$status" ]; then
            ssid=$(echo "$status" | grep "Connected network" | awk '{print $3}')
            rssi=$(echo "$status" | grep "RSSI" | awk '{print $2}')
            freq=$(echo "$status" | grep "Frequency" | awk '{print $2}')
        fi
        gateway=$(ip -4 route show dev "$iface" | grep default | awk '{print $3}' | head -n1)
    fi
    
    # 2. Reset Backoff on Roam Event
    if [ "$is_oneshot" == "false" ] && [ -n "$bssid" ] && [ "$bssid" != "$LAST_NUDGE_BSSID" ] && [ -n "$LAST_NUDGE_BSSID" ]; then
        log_roam "Roam detected ($LAST_NUDGE_BSSID -> $bssid). Resetting backoff."
        NUDGE_COUNT=0
        LAST_NUDGE_BSSID=""
    fi
    
    # 3. Evaluate
    local connected=0
    if [ -n "$ssid" ] && [ -n "$rssi" ] && [ "$rssi" -ne -100 ]; then connected=1; fi
    if [ -n "$gateway" ]; then connected=1; fi
    
    if [ "$connected" -eq 1 ]; then
        # Profile Switching Logic
        if [ "${RXNM_FEATURE_PROFILES:-true}" == "true" ]; then
            _logic_profile_switch "$iface" "$ssid" "$bssid" "$gateway"
        fi
        
        # Steering Logic
        if [ "$is_oneshot" == "false" ] && [ -n "$ssid" ] && [ "${RXNM_FEATURE_STEERING:-true}" == "true" ]; then
            _logic_signal_steering "$iface" "$ssid" "$rssi" "$freq" "$bssid"
        fi
        return 0
    else
        # Disconnected state cleanup
        if [ "$is_oneshot" == "false" ] && [ -n "$LAST_MATCH_VAL" ]; then
            log_roam "Disconnected."
            LAST_MATCH_VAL=""
            NUDGE_COUNT=0
        fi
        return 1
    fi
}

_logic_profile_switch() {
    local iface="$1" ssid="$2" bssid="$3" gw="$4"
    local target_profile="" match_val=""
    
    # 1. Explicit Mapping via Environment/Config
    if [ -n "${RXNM_PROFILE_MAP:-}" ]; then
        for mapping in $RXNM_PROFILE_MAP; do
            # Format: ssid:MySSID:WorkProfile OR gw:10.0.0.1:HomeProfile
            local colons="${mapping//[^:]}"
            local type="" val="" prof=""
            
            if [ "${#colons}" -eq 2 ]; then
                IFS=':' read -r type val prof <<< "$mapping"
            else
                type="ssid"; IFS=':' read -r val prof <<< "$mapping"
            fi
            
            case "$type" in
                ssid)  [ "$val" == "$ssid" ] && target_profile="$prof" ;;
                bssid) [[ "${bssid,,}" == "${val,,}" ]] && target_profile="$prof" ;;
                gw)    [ "$val" == "$gw" ] && target_profile="$prof" ;;
            esac
            
            [ -n "$target_profile" ] && { match_val="${type}=${val}"; break; }
        done
    fi
    
    # 2. Implicit Mapping (Profile name == SSID)
    if [ -z "$target_profile" ] && [ -n "$ssid" ]; then
        local profile_path="${STORAGE_PROFILES_DIR}/global/${ssid}"
        [ -d "$profile_path" ] && { target_profile="$ssid"; match_val="ssid=${ssid}"; }
    fi
    
    # 3. Apply if changed
    [ "$match_val" == "$LAST_MATCH_VAL" ] && return
    LAST_MATCH_VAL="$match_val"
    
    if [ -n "$target_profile" ] && [ "$CURRENT_PROFILE" != "$target_profile" ]; then
        log_roam "Location match: '$match_val'. Applying profile: $target_profile"
        if type action_profile &>/dev/null; then
            action_profile "load" "$target_profile" >/dev/null
            CURRENT_PROFILE="$target_profile"
        fi
    fi
}

_logic_signal_steering() {
    local iface="$1" ssid="$2" rssi="$3" freq="$4" bssid="$5"
    
    [ -z "$rssi" ] || [ "$rssi" -eq -100 ] && return
    
    local now; now=$(date +%s)
    local time_since_scan=$((now - LAST_SCAN_TIME))
    local scan_needed=0
    local scan_reason=""
    
    # Linear Backoff
    local dynamic_cooldown=$(( SCAN_COOLDOWN_SEEK * (1 + NUDGE_COUNT) ))
    [ "$dynamic_cooldown" -gt "${MAX_NUDGE_BACKOFF:-3600}" ] && dynamic_cooldown="${MAX_NUDGE_BACKOFF:-3600}"
    
    # Check Map for better options
    local map_has_better=false
    if [ -f "$ROAM_MAP_FILE" ] && [ "${RXNM_FEATURE_MAP:-true}" == "true" ]; then
        map_has_better=$(cat "$ROAM_MAP_FILE" | "$JQ_BIN" -r --arg ssid "$ssid" --arg current_sig "$rssi" '
            to_entries | map(select(.value.ssid == $ssid and (.value.rssi | tonumber) > ($current_sig | tonumber + 12))) | length > 0
        ')
    fi
    
    # Condition A: Signal Critical (Panic)
    if [ "$rssi" -lt "$ROAM_THRESHOLD_KICK" ]; then
        if [ "$time_since_scan" -ge "$SCAN_COOLDOWN_PANIC" ]; then
            scan_needed=1
            scan_reason="Critical signal ($rssi dBm)"
        fi
    fi
    
    # Condition B: Optimization (Band Seek or Better AP known)
    if [ "$scan_needed" -eq 0 ]; then
        # If on 2.4GHz but signal is strong, check for 5GHz/6GHz
        if { [ "$freq" -lt "$BAND_5G_MIN" ] && [ "$freq" -gt 0 ] && [ "$rssi" -gt "$ROAM_THRESHOLD_SEEK" ]; } || [ "$map_has_better" == "true" ]; then
            if [ "$time_since_scan" -ge "$dynamic_cooldown" ]; then
                scan_needed=1
                [ "$map_has_better" == "true" ] && scan_reason="Map nudge (Stronger AP known)" || scan_reason="Band seek nudge"
            fi
        fi
    fi
    
    if [ "$scan_needed" -eq 1 ]; then
        log_roam "$scan_reason. Nudging iwd (Backoff: $NUDGE_COUNT, Next check in ${dynamic_cooldown}s)..."
        
        # Trigger scan via IWD (This updates IWD's internal candidate list and triggers roam)
        if command -v iwctl >/dev/null; then
            iwctl station "$iface" scan >/dev/null 2>&1
            
            LAST_SCAN_TIME="$now"
            LAST_NUDGE_BSSID="$bssid"
            ((NUDGE_COUNT++))
            
            # Update our map in background
            update_roaming_map "$iface" &
        fi
    fi
}

run_passive_monitor() {
    local iface="$1"
    log_roam "Mode: Passive (Event Driven)"
    
    if [ -x "$RXNM_AGENT_BIN" ]; then
        # Use native C agent for monitoring
        exec "$RXNM_AGENT_BIN" --monitor-roam "$iface" "${ROAM_THRESHOLD_KICK:--75}"
        return
    fi
    
    if ! command -v busctl >/dev/null; then run_active_monitor "$iface"; return; fi
    
    # Initial check
    evaluate_roaming_state "$iface" "false"
    
    # Block on DBus signal changes (Zero CPU usage)
    busctl monitor net.connman.iwd --match "member='PropertiesChanged',interface='net.connman.iwd.Station'" | \
    while read -r line; do
        if [[ "$line" == *"SignalStrength"* ]] || [[ "$line" == *"ConnectedNetwork"* ]]; then
            evaluate_roaming_state "$iface" "false"
        fi
    done
}

run_active_monitor() {
    local iface="$1"
    log_roam "Mode: Active (Adaptive Polling)"
    local sleep_time=5
    
    while true; do
        if evaluate_roaming_state "$iface" "false"; then
            # Connected: Adaptive sleep based on signal
            local r
            if [ -x "$RXNM_AGENT_BIN" ]; then r=$("$RXNM_AGENT_BIN" --get "interfaces.${iface}.wifi.rssi"); else r=$(iwctl station "$iface" show | grep "RSSI" | awk '{print $2}'); fi
            
            if [ -n "$r" ] && [ "$r" -gt -60 ]; then sleep_time=20; 
            elif [ -n "$r" ] && [ "$r" -gt -70 ]; then sleep_time=10; 
            else sleep_time=5; fi
        else
            sleep_time=5
        fi
        sleep "$sleep_time"
    done
}

action_wifi_roaming_trigger() {
    local iface="$1"
    if [ -z "$iface" ]; then
        iface=$(get_wifi_iface 2>/dev/null)
    fi
    
    if [ -z "$iface" ]; then
        log_roam "ERROR: Could not detect WiFi interface. Specify via --interface."
        exit 1
    fi
    
    load_roaming_config
    log_roam "Opportunistic Trigger: Checking location context for $iface..."
    if evaluate_roaming_state "$iface" "true"; then
        log_roam "Context evaluation complete."
    else
        log_roam "No active connection or context match found."
    fi
}

action_wifi_roaming_monitor() {
    local iface="$1"
    # L-4 Fix: Remove default to wlan0 fallback to prevent monitoring wrong interface
    if [ -z "$iface" ]; then
        iface=$(get_wifi_iface 2>/dev/null)
    fi
    
    if [ -z "$iface" ]; then
         log_roam "ERROR: Could not detect WiFi interface. Ensure IWD is running or specify interface."
         exit 1
    fi
    
    : "${STORAGE_PROFILES_DIR:=${CONF_DIR}/network/profiles}"
    
    load_roaming_config
    rm -f "$ROAM_MAP_FILE"
    
    log_roam "Starting Roaming Monitor on $iface"
    log_roam "  Features: Steering=${RXNM_FEATURE_STEERING}, Map=${RXNM_FEATURE_MAP}, Profiles=${RXNM_FEATURE_PROFILES}"
    
    update_roaming_map "$iface"
    
    if [ "$ROAM_STRATEGY" == "active" ]; then
        run_active_monitor "$iface"
    else
        run_passive_monitor "$iface"
    fi
}
