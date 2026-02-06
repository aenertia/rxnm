# ==============================================================================
# VALIDATION & HELPER FUNCTIONS
# ==============================================================================

cleanup() {
    # Remove temporary files safely
    local temp_files=("${STORAGE_NET_DIR}"/*.XXXXXX)
    if [ ${#temp_files[@]} -gt 0 ]; then
        rm -f "${temp_files[@]}" 2>/dev/null
    fi
    # Remove PID file if we own the lock
    if [ -f "$GLOBAL_PID_FILE" ]; then
        local pid
        pid=$(cat "$GLOBAL_PID_FILE" 2>/dev/null || echo "")
        if [ "$pid" == "$$" ]; then
            rm -f "$GLOBAL_PID_FILE" "$GLOBAL_LOCK_FILE" 2>/dev/null
        fi
    fi
}

# --- LOCKING MECHANISM ---

acquire_global_lock() {
    local timeout="${1:-5}"
    
    exec 200>"$GLOBAL_LOCK_FILE"
    if ! flock -n 200; then
        if [ -f "$GLOBAL_PID_FILE" ]; then
            local old_pid
            old_pid=$(cat "$GLOBAL_PID_FILE" 2>/dev/null || echo "")
            if [ -n "$old_pid" ] && ! kill -0 "$old_pid" 2>/dev/null; then
                log_warn "Removing stale lock (PID $old_pid)"
                rm -f "$GLOBAL_LOCK_FILE" "$GLOBAL_PID_FILE"
                exec 200>"$GLOBAL_LOCK_FILE"
                if ! flock -n 200; then
                    log_error "Failed to acquire lock even after cleanup"
                    return 1
                fi
            else
                log_error "Another instance is running (PID $old_pid)"
                return 1
            fi
        else
            log_error "Another instance is running (Lock held)"
            return 1
        fi
    fi
    
    echo $$ > "$GLOBAL_PID_FILE"
    trap cleanup EXIT INT TERM
    return 0
}

acquire_iface_lock() {
    local iface="$1"
    local timeout="${2:-10}"
    local lock_file="${RUN_DIR}/${iface}.lock"
    
    exec {lock_fd}>"$lock_file" || return 1
    
    if ! flock -w "$timeout" "$lock_fd"; then
        log_error "Failed to acquire lock for $iface after ${timeout}s"
        exec {lock_fd}>&-
        return 1
    fi
}

with_iface_lock() {
    local iface="$1"; shift
    # FIX: Do not declare lock_fd as local here, as it is set in acquire_iface_lock
    acquire_iface_lock "$iface" || return 1
    
    # Execute command
    "$@"
    local ret=$?
    
    # Release and Close FD to prevent leaks
    flock -u "$lock_fd"
    eval "exec $lock_fd>&-"
    return $ret
}

# --- LOGGING ---

log_debug() {
    [ "$LOG_LEVEL" -ge "$LOG_LEVEL_DEBUG" ] && echo "[DEBUG] $*" >&2
}

log_info() {
    [ "$LOG_LEVEL" -ge "$LOG_LEVEL_INFO" ] && echo "[INFO] $*" >&2 || logger -t rocknix-network "$*"
}

log_warn() {
    [ "$LOG_LEVEL" -ge "$LOG_LEVEL_WARN" ] && echo "[WARN] $*" >&2
    logger -t rocknix-network "WARN: $*"
}

log_error() {
    echo "[ERROR] $*" >&2
    logger -t rocknix-network "ERROR [${FUNCNAME[1]:-main}]: $*"
}

cli_error() {
    local msg="$1"
    echo "Error: $msg" >&2
    exit 1
}

audit_log() {
    local event="$1"
    local details="$2"
    logger -t rocknix-network-audit -p auth.notice "$event: $details"
}

json_success() {
    # Fix: Explicitly check for unset/empty to avoid shell brace expansion bugs
    local data="$1"
    if [ -z "$data" ]; then data="{}"; fi
    jq -n --argjson data "$data" '{success:true} + $data'
}

json_error() {
    local msg="$1"
    local code="${2:-1}"
    jq -n --arg msg "$msg" --arg code "$code" \
        '{success:false, error:$msg, exit_code:($code|tonumber)}'
    return 0 
}

# --- VALIDATION ---

sanitize_ssid() {
    local ssid="$1"
    if [ ${#ssid} -gt 32 ]; then
        log_error "SSID too long (max 32 bytes)"
        return 1
    fi
    local safe
    safe=$(printf '%s' "$ssid" | tr -cd '[:alnum:]_-')
    [ -z "$safe" ] && safe="_unnamed_"
    echo "$safe"
}

validate_ssid() {
    local ssid="$1"
    local len=${#ssid}
    if (( len < 1 || len > 32 )); then
        log_error "Invalid SSID length: $len"
        return 1
    fi
    if [[ "$ssid" =~ [\$\`\\\!\;] ]]; then
        log_error "SSID contains forbidden characters"
        return 1
    fi
    return 0
}

validate_interface_name() {
    local iface="$1"
    if [[ ! "$iface" =~ ^[a-zA-Z0-9_:.-]{1,15}$ ]]; then
        log_error "Invalid interface name: $iface"
        return 1
    fi
    return 0
}

validate_passphrase() {
    local pass="$1"
    local len=${#pass}
    # Fix: Allow length 0 for open networks
    [ "$len" -eq 0 ] && return 0
    if [ "$len" -lt 8 ] || [ "$len" -gt 63 ]; then return 1; fi
    return 0
}

validate_bluetooth_name() {
    local name="$1"
    local len=${#name}
    if [ "$len" -gt 248 ]; then return 1; fi
    if [[ "$name" =~ [[:cntrl:]] ]]; then return 1; fi
    return 0
}

validate_channel() {
    local ch="$1"
    if [[ ! "$ch" =~ ^[0-9]+$ ]]; then return 1; fi
    if [ "$ch" -lt "$MIN_CHANNEL" ] || [ "$ch" -gt "$WIFI_CHANNEL_MAX" ]; then return 1; fi
    return 0
}

validate_ip() {
    local ip="$1"
    local clean_ip="${ip%/*}"
    if command -v ip >/dev/null; then
        if ip route get "$clean_ip" >/dev/null 2>&1; then
            return 0
        fi
        if [[ "$clean_ip" =~ : ]] && [[ "$clean_ip" =~ ^[0-9a-fA-F:]+$ ]]; then
            return 0
        fi
        if [[ "$clean_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return 0
        fi
        return 1
    else
        if [[ "$clean_ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; then
            return 0
        fi
        if [[ "$clean_ip" =~ : ]]; then
            return 0
        fi
        return 1
    fi
}

validate_routes() {
    local routes="$1"
    IFS=',' read -ra RTS <<< "$routes"
    for r in "${RTS[@]}"; do
        local dest="${r%%:*}"
        local rgw=""
        if [[ "$r" == *":"* ]]; then
            rgw="${r#*:}"
        fi
        # Fix: Allow 0.0.0.0/0 for manual routing overrides
        if ! validate_ip "$dest"; then return 1; fi
        if [ -n "$rgw" ]; then
            if ! validate_ip "$rgw"; then return 1; fi
        fi
    done
    return 0
}

validate_dns() {
    local dns_list="$1"
    IFS=',' read -ra SERVERS <<< "$dns_list"
    for server in "${SERVERS[@]}"; do
        if ! validate_ip "$server"; then
            return 1
        fi
    done
    return 0
}

validate_proxy_url() {
    local url="$1"
    if [[ "$url" =~ ^(http|https|socks4|socks5)://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then return 0; fi
    if [[ "$url" =~ ^([0-9.]+):([0-9]+)$ ]]; then
        local ip="${BASH_REMATCH[1]}"
        local port="${BASH_REMATCH[2]}"
        if validate_ip "$ip"; then
             if [ "$port" -le 65535 ]; then return 0; fi
        fi
    fi
    return 1
}

validate_country() {
    local code="$1"
    if [[ ! "$code" =~ ^[A-Z]{2}$ ]]; then return 1; fi
    return 0
}

get_proxy_json() {
    local file="$1"
    if [ -f "$file" ]; then
        local http="" https="" noproxy=""
        while IFS='=' read -r key value; do
            value="${value//\"/}"
            value="${value//\'/}"
            case "$key" in
                http_proxy|export\ http_proxy) http="$value" ;;
                https_proxy|export\ https_proxy) https="$value" ;;
                no_proxy|export\ no_proxy) noproxy="$value" ;;
            esac
        done < "$file"
        [ -n "$http" ] && ! validate_proxy_url "$http" && http=""
        [ -n "$https" ] && ! validate_proxy_url "$https" && https=""
        jq -n --arg h "$http" --arg s "$https" --arg n "$noproxy" \
            '{http: (if $h!="" then $h else null end), https: (if $s!="" then $s else null end), noproxy: (if $n!="" then $n else null end)}'
    else
        echo "null"
    fi
}
