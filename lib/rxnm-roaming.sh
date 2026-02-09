# ==============================================================================
# RXNM ROAMING ENGINE (DAWN-Lite)
# Opportunistic roaming and profile management based on IWD telemetry.
# ==============================================================================

# --- TUNABLES (DAWN-Style) ---
# Kick: If RSSI drops below this, force a scan/roam evaluation
: "${ROAM_THRESHOLD_KICK:=-75}" # dBm
# Hysteresis: Candidate AP must be this much better to trigger roam
: "${ROAM_HYSTERESIS:=10}" # dB
# Scan Interval: Don't nudge more than once every X seconds
: "${SCAN_COOLDOWN:=30}"

# State Tracking
LAST_SCAN_TIME=0

log_roam() {
    echo "[ROAM] $1" | logger -t rxnm-roaming
    [ -n "${RXNM_DEBUG:-}" ] && echo "[ROAM] $1" >&2
}

# --- LOGIC ENGINE ---

evaluate_signal() {
    local rssi_raw="$1"
    # Convert uint16 (sometimes IWD reports raw) or int16 to signed integer
    local rssi
    if [ "$rssi_raw" -lt -1000 ]; then
        rssi=$((rssi_raw / 100))
    else
        rssi="$rssi_raw"
    fi

    # 1. CHECK KICK THRESHOLD
    if [ "$rssi" -lt "$ROAM_THRESHOLD_KICK" ]; then
        local now
        # Bash 4.2+ optimization
        now=$(printf '%(%s)T' -1) 2>/dev/null || now=$(date +%s)
        local time_diff=$((now - LAST_SCAN_TIME))
        
        if [ "$time_diff" -ge "$SCAN_COOLDOWN" ]; then
            log_roam "Signal degraded ($rssi dBm < $ROAM_THRESHOLD_KICK dBm). Nudging scan..."
            # Nudge IWD to look around. 
            if command -v iwctl >/dev/null; then
                iwctl station wlan0 scan >/dev/null 2>&1
            fi
            LAST_SCAN_TIME="$now"
        fi
    fi
}

action_wifi_roaming_monitor() {
    if ! command -v busctl >/dev/null; then
        log_error "busctl not found. Roaming monitor requires systemd/dbus."
        return 1
    fi

    log_roam "Starting RXNM Roaming Monitor (Threshold: ${ROAM_THRESHOLD_KICK}dBm)..."
    
    busctl monitor net.connman.iwd --match "member='PropertiesChanged'" | \
    grep --line-buffered "SignalStrength" | \
    while read -r line; do
        # Extract the number (last field typically)
        local val
        val=$(echo "$line" | grep -oE '\-?[0-9]+$')
        
        if [ -n "$val" ]; then
            evaluate_signal "$val"
        fi
    done
}
