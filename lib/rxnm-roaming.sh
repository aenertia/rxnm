# ==============================================================================
# RXNM ROAMING ENGINE (DUAL-PATH: PASSIVE EVENT VS ACTIVE POLL)
# ==============================================================================

# State Tracking
LAST_SCAN_TIME=0
LAST_MATCH_VAL=""
CURRENT_PROFILE=""

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
    : "${ROAM_THRESHOLD_KICK:=-75}"      # dBm: Force scan if below
    : "${ROAM_THRESHOLD_SEEK:=-65}"      # dBm: Look for better bands if above
    : "${SCAN_COOLDOWN_PANIC:=10}"       # Seconds between panic scans
    : "${SCAN_COOLDOWN_SEEK:=120}"       # Seconds between band-steering seek scans
    : "${BAND_5G_MIN:=5000}"             # Minimum MHz for 5GHz
    : "${BAND_6G_MIN:=5900}"             # Minimum MHz for 6GHz
    : "${RXNM_PROFILE_MAP:=}"            # Explicit mappings "Type:Value:Profile" or "SSID:Profile"

    # 2. Load Config Override
    local conf_file="${CONF_DIR}/rxnm-roaming.conf"
    if [ -f "$conf_file" ]; then
        log_roam "Loading configuration from $conf_file"
        source "$conf_file"
    fi
}

# --- DECISION ENGINE (SHARED) ---

# Core logic: evaluating context to decide on Profile Switch or Scan Nudge
evaluate_roaming_state() {
    local iface="$1"
    
    local rssi=""
    local ssid=""
    local freq=""
    local gateway=""
    local bssid=""
    local gwmac=""
    
    # 1. Fetch Core Context (Hybrid Fastpath)
    if [ -x "$RXNM_AGENT_BIN" ]; then
        local tsv_data
        # Extract WiFi data AND Gateway IP in one pass
        tsv_data=$("$RXNM_AGENT_BIN" --dump 2>/dev/null | \
            "$JQ_BIN" -r ".interfaces[\"$iface\"] | \"\(.wifi.rssi // -100)\t\(.wifi.ssid // \"\")\t\(.wifi.frequency // 0)\t\(.gateway // \"\")\"")
        
        if [ -n "$tsv_data" ]; then
            IFS=$'\t' read -r rssi ssid freq gateway <<< "$tsv_data"
        fi
    else
        # Legacy Fallback (iwctl parsing)
        local status
        status=$(iwctl station "$iface" show 2>/dev/null)
        if [ -n "$status" ]; then
            ssid=$(echo "$status" | grep "Connected network" | awk '{print $3}')
            rssi=$(echo "$status" | grep "RSSI" | awk '{print $2}')
            freq=$(echo "$status" | grep "Frequency" | awk '{print $2}')
        fi
        # Fetch gateway via ip route
        gateway=$(ip -4 route show dev "$iface" | grep default | awk '{print $3}' | head -n1)
    fi

    # 2. Enrich Extended Context (Shell Tools)
    # These are slower, so only fetch if we have a basic connection
    if [ -n "$ssid" ] || [ -n "$gateway" ]; then
        # Fetch BSSID (WiFi only)
        if [ -n "$ssid" ] && command -v iw >/dev/null; then
            bssid=$(iw dev "$iface" link 2>/dev/null | awk '/connected to/ {print $3}')
        fi
        
        # Fetch Gateway MAC (Wired/WiFi)
        if [ -n "$gateway" ] && command -v ip >/dev/null; then
            gwmac=$(ip neigh show dev "$iface" | grep "^$gateway " | awk '{print $3}')
        fi
    fi

    # 3. Evaluate
    # Proceed if we have EITHER a valid WiFi connection OR a Wired Gateway
    local connected=0
    if [ -n "$ssid" ] && [ -n "$rssi" ] && [ "$rssi" -ne -100 ]; then connected=1; fi
    if [ -n "$gateway" ]; then connected=1; fi

    if [ "$connected" -eq 1 ]; then
        if [ "${RXNM_FEATURE_PROFILES:-true}" == "true" ]; then
            _logic_profile_switch "$iface" "$ssid" "$bssid" "$gateway" "$gwmac"
        fi
        
        # Steering is WiFi specific
        if [ -n "$ssid" ] && [ "${RXNM_FEATURE_STEERING:-true}" == "true" ]; then
            _logic_signal_steering "$iface" "$rssi" "$freq"
        fi
        
        return 0 # Connected
    else
        # Reset state if disconnected
        if [ -n "$LAST_MATCH_VAL" ]; then
            log_roam "Disconnected."
            LAST_MATCH_VAL=""
        fi
        return 1 # Disconnected
    fi
}

_logic_profile_switch() {
    local iface="$1"
    local ssid="$2"
    local bssid="$3"
    local gw="$4"
    local gwmac="$5"
    
    local target_profile=""
    local match_val=""

    # 1. Explicit Mapping (Profile Map)
    # Supports: "SSID:Profile" (Legacy) OR "Type:Value:Profile" (Advanced)
    if [ -n "${RXNM_PROFILE_MAP:-}" ]; then
        for mapping in $RXNM_PROFILE_MAP; do
            # Count colons to determine format
            local colons="${mapping//[^:]}"
            
            local type=""
            local val=""
            local prof=""
            
            if [ "${#colons}" -eq 2 ]; then
                # Format: Type:Value:Profile
                IFS=':' read -r type val prof <<< "$mapping"
            else
                # Format: SSID:Profile (Default)
                type="ssid"
                IFS=':' read -r val prof <<< "$mapping"
            fi
            
            # Check match based on type
            case "$type" in
                ssid)  [ -n "$ssid" ] && [ "$val" == "$ssid" ] && target_profile="$prof" ;;
                bssid) [ -n "$bssid" ] && [[ "${bssid,,}" == "${val,,}" ]] && target_profile="$prof" ;;
                gw)    [ -n "$gw" ] && [ "$val" == "$gw" ] && target_profile="$prof" ;;
                gwmac) [ -n "$gwmac" ] && [[ "${gwmac,,}" == "${val,,}" ]] && target_profile="$prof" ;;
            esac
            
            if [ -n "$target_profile" ]; then
                match_val="${type}=${val}"
                log_roam "Location match (Map): '$match_val' -> '$target_profile'"
                break
            fi
        done
    fi

    # 2. Implicit Mapping (Directory Existence) - SSID Only
    if [ -z "$target_profile" ] && [ -n "$ssid" ]; then
        local profile_path="${STORAGE_PROFILES_DIR}/global/${ssid}"
        if [ -d "$profile_path" ]; then
            target_profile="$ssid"
            match_val="ssid=${ssid}"
            log_roam "Location match (Auto): '$ssid' profile found"
        fi
    fi
    
    # Debounce based on the matched value (not just SSID, to allow switching between wired nets)
    if [ "$match_val" == "$LAST_MATCH_VAL" ]; then return; fi
    LAST_MATCH_VAL="$match_val"
    
    # 3. Apply
    if [ -n "$target_profile" ]; then
        if [ "$CURRENT_PROFILE" != "$target_profile" ]; then
            log_roam "Activating profile: $target_profile"
            if type action_profile &>/dev/null; then
                action_profile "load" "$target_profile" >/dev/null
                CURRENT_PROFILE="$target_profile"
            fi
        fi
    fi
}

_logic_signal_steering() {
    local iface="$1"
    local rssi="$2"
    local freq="$3"
    
    # Sanity check: RSSI must be valid number
    if [ -z "$rssi" ] || [ "$rssi" -eq -100 ]; then return; fi

    local now
    now=$(printf '%(%s)T' -1) 2>/dev/null || now=$(date +%s)
    local time_since_scan=$((now - LAST_SCAN_TIME))
    local scan_needed=0
    local scan_reason=""

    # A. Panic Check
    if [ "$rssi" -lt "$ROAM_THRESHOLD_KICK" ]; then
        if [ "$time_since_scan" -ge "$SCAN_COOLDOWN_PANIC" ]; then
            scan_needed=1
            scan_reason="Critical signal ($rssi dBm < $ROAM_THRESHOLD_KICK dBm)"
        fi
    fi

    # B. Band Seeking
    if [ "$scan_needed" -eq 0 ] && [ "$freq" -lt "$BAND_5G_MIN" ] && [ "$freq" -gt 0 ]; then
        if [ "$rssi" -gt "$ROAM_THRESHOLD_SEEK" ]; then
            if [ "$time_since_scan" -ge "$SCAN_COOLDOWN_SEEK" ]; then
                scan_needed=1
                scan_reason="Band seek (On 2.4GHz @ $rssi dBm)"
            fi
        fi
    fi

    if [ "$scan_needed" -eq 1 ]; then
        log_roam "$scan_reason. Nudging scan..."
        if command -v iwctl >/dev/null; then
            iwctl station "$iface" scan >/dev/null 2>&1
        fi
        LAST_SCAN_TIME="$now"
    fi
}

# --- STRATEGY A: PASSIVE MONITOR (Battery Optimal) ---
# Listens for IWD DBus events. Zero CPU usage when idle.
run_passive_monitor() {
    local iface="$1"
    log_roam "Mode: Passive (Event Driven)"
    
    if ! command -v busctl >/dev/null; then
        log_roam "Error: busctl not found. Falling back to active polling."
        run_active_monitor "$iface"
        return
    fi

    # Perform initial check on startup
    evaluate_roaming_state "$iface"

    # Listen for Property Changes
    # We filter for SignalStrength (RSSI change) or ConnectedNetwork (SSID change)
    busctl monitor net.connman.iwd --match "member='PropertiesChanged'" | \
    grep --line-buffered -E "SignalStrength|ConnectedNetwork" | \
    while read -r line; do
        # On ANY relevant event, we trigger a full state evaluation.
        evaluate_roaming_state "$iface"
    done
}

# --- STRATEGY B: ACTIVE POLLING (Aggressive) ---
# Polls on a fixed/adaptive interval. Guaranteed checking regardless of daemon events.
run_active_monitor() {
    local iface="$1"
    log_roam "Mode: Active (Adaptive Polling)"
    
    local sleep_time=5
    
    while true; do
        if evaluate_roaming_state "$iface"; then
            # We are connected. Optimize sleep based on signal.
            if [ -x "$RXNM_AGENT_BIN" ]; then
                 local rssi
                 rssi=$("$RXNM_AGENT_BIN" --get "interfaces.${iface}.wifi.rssi")
                 if [ -n "$rssi" ] && [ "$rssi" -gt -60 ]; then
                     sleep_time=20
                 elif [ -n "$rssi" ] && [ "$rssi" -gt -70 ]; then
                     sleep_time=10
                 else
                     sleep_time=5
                 fi
            else
                 # Legacy Fallback: Full functional adaptive polling without agent
                 if command -v iwctl >/dev/null; then
                     local rssi_leg
                     rssi_leg=$(iwctl station "$iface" show 2>/dev/null | grep "RSSI" | awk '{print $2}')
                     if [ -n "$rssi_leg" ] && [ "$rssi_leg" -gt -60 ]; then
                         sleep_time=20
                     elif [ -n "$rssi_leg" ] && [ "$rssi_leg" -gt -70 ]; then
                         sleep_time=10
                     else
                         sleep_time=5
                     fi
                 else
                     sleep_time=10
                 fi
            fi
        else
            # Disconnected
            sleep_time=5
        fi
        sleep "$sleep_time"
    done
}

# --- ENTRYPOINT ---

action_wifi_roaming_monitor() {
    local iface="${1:-wlan0}"
    
    # Initialize
    : "${STORAGE_PROFILES_DIR:=${CONF_DIR}/network/profiles}"
    load_roaming_config
    
    log_roam "Starting Roaming Monitor on $iface"
    log_roam "  Features: Steering=${RXNM_FEATURE_STEERING:-true}, Profiles=${RXNM_FEATURE_PROFILES:-true}"
    log_roam "  Kick: <${ROAM_THRESHOLD_KICK}dBm | Seek: >${ROAM_THRESHOLD_SEEK}dBm"
    if [ -n "$RXNM_PROFILE_MAP" ]; then
        log_roam "  Profiles: Mapped ($(echo "$RXNM_PROFILE_MAP" | wc -w) entries)"
    fi

    if [ "$ROAM_STRATEGY" == "active" ]; then
        run_active_monitor "$iface"
    else
        run_passive_monitor "$iface"
    fi
}
