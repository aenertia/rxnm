# ==============================================================================
# RXNM ROAMING ENGINE (DUAL-PATH: PASSIVE EVENT VS ACTIVE POLL)
# Now with Session-based BSSID Mapping & One-Shot Triggering
# ==============================================================================

# State Tracking
LAST_SCAN_TIME=0
LAST_MATCH_VAL=""
CURRENT_PROFILE=""

# Nudge Backoff Tracking
NUDGE_COUNT=0
LAST_NUDGE_BSSID=""

# Map Storage (Session-based in RAM)
ROAM_MAP_FILE="${RUN_DIR:-/run/rocknix}/roaming_map.json"

# Logger
log_roam() {
    if [ -t 2 ]; then
        echo "[ROAM] $1" >&2
    else
        echo "[ROAM] $1"
    fi
}

# --- CONFIGURATION ---

load_roaming_config() {
    # 1. Establish Defaults
    : "${ROAM_STRATEGY:=passive}"        # passive (event-driven) or active (polling)
    : "${RXNM_FEATURE_STEERING:=true}"   # Enable signal-based scanning/steering
    : "${RXNM_FEATURE_PROFILES:=true}"   # Enable location-aware profile switching
    : "${RXNM_FEATURE_MAP:=true}"        # Build a session map of BSSIDs/Channels
    : "${ROAM_THRESHOLD_KICK:=-75}"      # dBm: Force scan if below
    : "${ROAM_THRESHOLD_SEEK:=-65}"      # dBm: Look for better bands if above
    : "${SCAN_COOLDOWN_PANIC:=10}"       # Seconds between panic scans
    : "${SCAN_COOLDOWN_SEEK:=120}"       # Base seconds between seek scans
    : "${BAND_5G_MIN:=5000}"             # Minimum MHz for 5GHz
    : "${BAND_6G_MIN:=5900}"             # Minimum MHz for 6GHz
    : "${MAX_NUDGE_BACKOFF:=3600}"       # Maximum wait (1 hour) for redundant nudges

    # 2. Load Config Override
    local conf_file="${CONF_DIR}/rxnm-roaming.conf"
    if [ -f "$conf_file" ]; then
        log_roam "Loading configuration from $conf_file"
        source "$conf_file"
    fi
}

# --- MAP ENGINE ---

update_roaming_map() {
    local iface="$1"
    [ "${RXNM_FEATURE_MAP:-true}" != "true" ] && return
    
    # We use a lock to ensure map updates don't collide if triggered rapidly
    with_iface_lock "roam_map" _task_update_map "$iface"
}

_task_update_map() {
    local iface="$1"
    local scan_json
    scan_json=$(rxnm wifi scan --interface "$iface" --format json 2>/dev/null || echo "{}")
    
    if [[ "$scan_json" == *"results"* ]]; then
        local now; now=$(date +%s)
        local current_map="{}"
        [ -f "$ROAM_MAP_FILE" ] && current_map=$(cat "$ROAM_MAP_FILE")
        
        echo "$scan_json" | "$JQ_BIN" -n --argjson map "$current_map" --argjson scan "$(cat)" --arg now "$now" '
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

# --- DECISION ENGINE (SHARED) ---

# Core logic: evaluating context to decide on Profile Switch or Scan Nudge
evaluate_roaming_state() {
    local iface="$1"
    local is_oneshot="${2:-false}"
    local rssi="" ssid="" freq="" gateway="" bssid=""
    
    # 1. Fetch Core Context (Hybrid Fastpath)
    if [ -x "$RXNM_AGENT_BIN" ]; then
        local tsv_data
        # We fetch the gateway even for WiFi to allow wired-location awareness
        tsv_data=$("$RXNM_AGENT_BIN" --dump 2>/dev/null | \
            "$JQ_BIN" -r ".interfaces[\"$iface\"] | \"\(.wifi.rssi // -100)\t\(.wifi.ssid // \"\")\t\(.wifi.frequency // 0)\t\(.gateway // \"\")\t\(.wifi.bssid // \"\")\"")
        
        if [ -n "$tsv_data" ]; then
            IFS=$'\t' read -r rssi ssid freq gateway bssid <<< "$tsv_data"
        fi
    else
        # Legacy Fallback
        local status
        status=$(iwctl station "$iface" show 2>/dev/null)
        if [ -n "$status" ]; then
            ssid=$(echo "$status" | grep "Connected network" | awk '{print $3}')
            rssi=$(echo "$status" | grep "RSSI" | awk '{print $2}')
            freq=$(echo "$status" | grep "Frequency" | awk '{print $2}')
        fi
        gateway=$(ip -4 route show dev "$iface" | grep default | awk '{print $3}' | head -n1)
    fi

    # 2. Backoff Reset Logic: If BSSID changed since last nudge, reset penalty
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
        # Path 1: Profile Switching (Works in Monitor AND One-shot)
        if [ "${RXNM_FEATURE_PROFILES:-true}" == "true" ]; then
            _logic_profile_switch "$iface" "$ssid" "$bssid" "$gateway"
        fi
        
        # Path 2: Signal Steering (Only makes sense in Monitor mode)
        if [ "$is_oneshot" == "false" ] && [ -n "$ssid" ] && [ "${RXNM_FEATURE_STEERING:-true}" == "true" ]; then
            _logic_signal_steering "$iface" "$ssid" "$rssi" "$freq" "$bssid"
        fi
        
        return 0 
    else
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

    # 1. Explicit Mapping
    if [ -n "${RXNM_PROFILE_MAP:-}" ]; then
        for mapping in $RXNM_PROFILE_MAP; do
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

    # 2. Implicit Mapping
    if [ -z "$target_profile" ] && [ -n "$ssid" ]; then
        local profile_path="${STORAGE_PROFILES_DIR}/global/${ssid}"
        [ -d "$profile_path" ] && { target_profile="$ssid"; match_val="ssid=${ssid}"; }
    fi
    
    # Check if we are already in this state
    [ "$match_val" == "$LAST_MATCH_VAL" ] && return
    LAST_MATCH_VAL="$match_val"
    
    # 3. Apply
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

    local dynamic_cooldown=$(( SCAN_COOLDOWN_SEEK * (1 + NUDGE_COUNT) ))
    [ "$dynamic_cooldown" -gt "${MAX_NUDGE_BACKOFF:-3600}" ] && dynamic_cooldown="${MAX_NUDGE_BACKOFF:-3600}"

    local map_has_better=false
    if [ -f "$ROAM_MAP_FILE" ] && [ "${RXNM_FEATURE_MAP:-true}" == "true" ]; then
        map_has_better=$(cat "$ROAM_MAP_FILE" | "$JQ_BIN" -r --arg ssid "$ssid" --arg current_sig "$rssi" '
            to_entries | map(select(.value.ssid == $ssid and (.value.rssi | tonumber) > ($current_sig | tonumber + 12))) | length > 0
        ')
    fi

    if [ "$rssi" -lt "$ROAM_THRESHOLD_KICK" ]; then
        if [ "$time_since_scan" -ge "$SCAN_COOLDOWN_PANIC" ]; then
            scan_needed=1
            scan_reason="Critical signal ($rssi dBm)"
        fi
    fi

    if [ "$scan_needed" -eq 0 ]; then
        if { [ "$freq" -lt "$BAND_5G_MIN" ] && [ "$freq" -gt 0 ] && [ "$rssi" -gt "$ROAM_THRESHOLD_SEEK" ]; } || [ "$map_has_better" == "true" ]; then
            if [ "$time_since_scan" -ge "$dynamic_cooldown" ]; then
                scan_needed=1
                [ "$map_has_better" == "true" ] && scan_reason="Map nudge (Stronger AP known)" || scan_reason="Band seek nudge"
            fi
        fi
    fi

    if [ "$scan_needed" -eq 1 ]; then
        log_roam "$scan_reason. Nudging iwd (Backoff: $NUDGE_COUNT, Next check in ${dynamic_cooldown}s)..."
        if command -v iwctl >/dev/null; then
            iwctl station "$iface" scan >/dev/null 2>&1
            LAST_SCAN_TIME="$now"
            LAST_NUDGE_BSSID="$bssid"
            ((NUDGE_COUNT++))
            update_roaming_map "$iface" &
        fi
    fi
}

# --- MONITORING STRATEGIES ---

run_passive_monitor() {
    local iface="$1"
    log_roam "Mode: Passive (Event Driven)"
    if ! command -v busctl >/dev/null; then run_active_monitor "$iface"; return; fi

    evaluate_roaming_state "$iface" "false"

    # Phase 3 Refactor: Direct pipe consumption without grep for lower latency/overhead
    # Matches specifically on net.connman.iwd.Station to avoid noise
    busctl monitor net.connman.iwd --match "member='PropertiesChanged',interface='net.connman.iwd.Station'" | \
    while read -r line; do
        # Lightweight substring check in bash (faster than forking grep)
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
            local r
            if [ -x "$RXNM_AGENT_BIN" ]; then r=$("$RXNM_AGENT_BIN" --get "interfaces.${iface}.wifi.rssi"); else r=$(iwctl station "$iface" show | grep "RSSI" | awk '{print $2}'); fi
            if [ -n "$r" ] && [ "$r" -gt -60 ]; then sleep_time=20; elif [ -n "$r" ] && [ "$r" -gt -70 ]; then sleep_time=10; else sleep_time=5; fi
        else
            sleep_time=5
        fi
        sleep "$sleep_time"
    done
}

# --- ACTIONS ---

# One-shot trigger for opportunistic profile switching
action_wifi_roaming_trigger() {
    local iface="${1:-wlan0}"
    load_roaming_config
    
    log_roam "Opportunistic Trigger: Checking location context for $iface..."
    if evaluate_roaming_state "$iface" "true"; then
        log_roam "Context evaluation complete."
    else
        log_roam "No active connection or context match found."
    fi
}

action_wifi_roaming_monitor() {
    local iface="${1:-wlan0}"
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
