# ==============================================================================
# VALIDATION & HELPER FUNCTIONS
# ==============================================================================

# --- CACHING & OPTIMIZATION HELPERS ---
declare -A _sysfs_cache

# Optimization: Batch read sysfs attributes to reduce forks/IO overhead
# Returns: operstate:address:mtu
get_iface_sysfs() {
    local iface=$1
    [ -n "${_sysfs_cache[$iface]}" ] && echo "${_sysfs_cache[$iface]}" && return
    
    local data=""
    if [ -d "/sys/class/net/$iface" ]; then
        # Read multiple attributes in one fork using paste
        data=$(paste -d: /sys/class/net/$iface/operstate /sys/class/net/$iface/address /sys/class/net/$iface/mtu 2>/dev/null)
    fi
    _sysfs_cache[$iface]="$data"
    echo "$data"
}

cleanup() {
    # Remove temporary files safely
    local temp_files=("${STORAGE_NET_DIR}"/*.XXXXXX)
    if [ ${#temp_files[@]} -gt 0 ]; then
        rm -f "${temp_files[@]}" 2>/dev/null
    fi
    
    # Remove PID file if we own the global lock
    if [ -f "$GLOBAL_PID_FILE" ]; then
        local pid
        pid=$(cat "$GLOBAL_PID_FILE" 2>/dev/null || echo "")
        if [ "$pid" == "$$" ]; then
            rm -f "$GLOBAL_PID_FILE" "$GLOBAL_LOCK_FILE" 2>/dev/null
        fi
    fi

    # Clean any interface locks owned by this PID
    if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
        # Check if fuser is available, otherwise just try to clean known locks
        if command -v fuser >/dev/null; then
            find "$RUN_DIR" -name "*.lock" -type f 2>/dev/null | while read -r lock; do
                if [ -f "$lock" ]; then
                    local lock_pid
                    lock_pid=$(fuser "$lock" 2>/dev/null | awk '{print $1}')
                    # If no process holds it, or we hold it, remove it
                    if [ -z "$lock_pid" ] || [ "$lock_pid" == "$$" ]; then
                        rm -f "$lock" 2>/dev/null
                    fi
                fi
            done
        fi
    fi
    
    if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
        rm -rf "$TMPDIR" 2>/dev/null
    fi
}

# --- LOCKING MECHANISM ---

acquire_global_lock() {
    local timeout="${1:-5}"
    
    # Ensure RUN_DIR exists before locking
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"

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

# Fixed: Local scoping of lock_fd to prevent leaks
with_iface_lock() {
    local iface="$1"; shift
    local timeout="${TIMEOUT:-10}"
    local lock_file="${RUN_DIR}/${iface}.lock"
    local lock_fd
    
    # Ensure RUN_DIR exists before locking
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"

    # Open FD in local scope
    exec {lock_fd}>"$lock_file" || {
        log_error "Failed to open lock file for $iface"
        return 1
    }
    
    if ! flock -w "$timeout" "$lock_fd"; then
        log_error "Failed to acquire lock for $iface after ${timeout}s"
        exec {lock_fd}>&-
        return 1
    fi
    
    # Execute command
    local ret=0
    "$@" || ret=$?
    
    # Release and Close FD
    flock -u "$lock_fd"
    exec {lock_fd}>&-
    return $ret
}

# --- LOGGING & OUTPUT ---

log_debug() {
    [ "$LOG_LEVEL" -ge "$LOG_LEVEL_DEBUG" ] && echo "[DEBUG] $*" >&2
}

log_info() {
    [ "$LOG_LEVEL" -ge "$LOG_LEVEL_INFO" ] && echo "[INFO] $*" >&2
}

log_warn() {
    [ "$LOG_LEVEL" -ge "$LOG_LEVEL_WARN" ] && echo "[WARN] $*" >&2
}

log_error() {
    echo "[ERROR] $*" >&2
}

cli_error() {
    local msg="$1"
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        json_error "$msg"
    else
        echo "Error: $msg" >&2
    fi
    exit 1
}

audit_log() {
    local event="$1"
    local details="$2"
    logger -t rocknix-network-audit -p auth.notice "$event: $details"
}

# --- OUTPUT FORMATTING ---

print_table() {
    local json_input="$1"
    local columns="$2" # "KEY:Header,KEY2:Header2"
    
    local jq_query="["
    local header_row=""
    
    IFS=',' read -ra COLS <<< "$columns"
    for col in "${COLS[@]}"; do
        local key="${col%%:*}"
        local hdr="${col#*:}"
        jq_query+=" .${key} // \"-\","
        header_row+="${hdr}\t"
    done
    jq_query="${jq_query%,}] | @tsv"
    
    # Generate Tab-Separated Values
    local tsv_data
    tsv_data=$(echo -e "${header_row}"; echo "$json_input" | "$JQ_BIN" -r ".[]? | $jq_query" 2>/dev/null)
    if [ -z "$tsv_data" ] && [ "${RXNM_FORMAT:-human}" != "json" ]; then
        # Handle single object case if array filter failed
        tsv_data=$(echo -e "${header_row}"; echo "$json_input" | "$JQ_BIN" -r "$jq_query" 2>/dev/null)
    fi

    # Formatting: Use column if available, else awk for embedded fallback
    if command -v column >/dev/null; then
        echo "$tsv_data" | column -t -s $'\t'
    else
        echo "$tsv_data" | awk -F'\t' '{
            for(i=1;i<=NF;i++) {
                if(length($i) > max[i]) max[i] = length($i)
            }
            lines[NR] = $0
        }
        END {
            for(i=1;i<=NR;i++) {
                split(lines[i], fields, "\t")
                for(j=1;j<=NF;j++) {
                    printf "%-" (max[j]+2) "s", fields[j]
                }
                printf "\n"
            }
        }'
    fi
}

json_success() {
    local data
    # Check if data is piped or passed as argument
    if [ -p /dev/stdin ]; then
        data=$(cat)
    else
        data="${1:-}"
    fi
    
    if [ -z "$data" ]; then data="{}"; fi
    
    # If data is already a JSON object string, merge directly
    local full_json
    full_json=$("$JQ_BIN" -n --argjson data "$data" '{success:true} + $data')
    
    case "${RXNM_FORMAT:-human}" in
        json)
            echo "$full_json"
            ;;
        table)
            # OPTIMIZATION: Determine content type in one pass to avoid multiple JQ forks
            local type_detect
            type_detect=$(echo "$full_json" | "$JQ_BIN" -r '
                if .results then "results" 
                elif .networks then "networks" 
                elif .interfaces then "interfaces" 
                elif .profiles then "profiles" 
                elif .devices then "devices" 
                else "unknown" end')

            case "$type_detect" in
                results)
                    print_table "$(echo "$full_json" | "$JQ_BIN" '.results')" "ssid:SSID,strength_pct:SIGNAL(%),security:SECURITY,connected:CONNECTED,channel:CH"
                    ;;
                networks)
                    print_table "$(echo "$full_json" | "$JQ_BIN" '.networks')" "ssid:SSID,security:SECURITY,last_connected:LAST_SEEN,hidden:HIDDEN"
                    ;;
                interfaces)
                    local arr_data
                    arr_data=$(echo "$full_json" | "$JQ_BIN" '[.interfaces[]]')
                    print_table "$arr_data" "name:NAME,type:TYPE,connected:STATE,ip:IP_ADDRESS,ssid:SSID/DETAILS"
                    ;;
                profiles)
                    # Check profile structure (array of strings or objects)
                    if echo "$full_json" | "$JQ_BIN" -e '.profiles[0] | type == "string"' >/dev/null 2>&1; then
                         echo "$full_json" | "$JQ_BIN" -r '.profiles[]' | sed '1iPROFILE_NAME'
                    else
                         print_table "$(echo "$full_json" | "$JQ_BIN" '.profiles')" "name:NAME,iface:INTERFACE"
                    fi
                    ;;
                devices)
                    print_table "$(echo "$full_json" | "$JQ_BIN" '.devices')" "mac:MAC_ADDRESS,name:DEVICE_NAME"
                    ;;
                *)
                    # Fallback to Key-Value
                    echo "$full_json" | "$JQ_BIN" -r 'del(.success) | to_entries | .[] | "\(.key): \(.value)"'
                    ;;
            esac
            ;;
        *)
            # Human readable pretty print (Default)
            # OPTIMIZATION: Check for keys in one pass to reduce JQ calls
            local key_detect
            key_detect=$(echo "$full_json" | "$JQ_BIN" -r '
                if .message then "message"
                elif .action then "action"
                elif .connected == true then "connected"
                elif .results then "results"
                elif .networks then "networks"
                elif .interfaces then "interfaces"
                else "unknown" end')
            
            case "$key_detect" in
                message)
                    echo "$full_json" | "$JQ_BIN" -r '.message'
                    ;;
                action)
                    local action_str
                    action_str=$(echo "$full_json" | "$JQ_BIN" -r '"✓ Success: " + .action + " performed on " + (.iface // .ssid // .name // "system")')
                    echo "$action_str"
                    ;;
                connected)
                    local ssid
                    ssid=$(echo "$full_json" | "$JQ_BIN" -r '.ssid')
                    echo "✓ Successfully connected to $ssid."
                    ;;
                results)
                     print_table "$(echo "$full_json" | "$JQ_BIN" '.results')" "ssid:SSID,strength_pct:SIG,security:SEC,connected:CONN"
                     ;;
                networks)
                     print_table "$(echo "$full_json" | "$JQ_BIN" '.networks')" "ssid:SSID,security:SEC,last_connected:LAST_SEEN"
                     ;;
                interfaces)
                     echo "--- Network Status ---"
                     echo "$full_json" | "$JQ_BIN" -r '.interfaces[] | "Interface: \(.name)\n  Type: \(.type)\n  State: \(if .connected then "UP" else "DOWN" end)\n  IP: \(.ip // "-")\n  Details: \(.ssid // .members // "-")\n"'
                     ;;
                *)
                    echo "$full_json" | "$JQ_BIN" -r 'del(.success) | to_entries | .[] | "\(.key): \(.value)"'
                    ;;
            esac
            ;;
    esac
}

json_error() {
    local msg="$1"
    local code="${2:-1}"
    local hint="${3:-}"
    
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        "$JQ_BIN" -n --arg msg "$msg" --arg code "$code" --arg hint "$hint" \
            '{success:false, error:$msg, hint:(if $hint=="" then null else $hint end), exit_code:($code|tonumber)}'
    else
        echo "✗ Error: $msg" >&2
        [ -n "$hint" ] && echo "  hint: $hint" >&2
    fi
    return 0
}

# --- INTERACTIVE HELPERS ---

confirm_action() {
    local msg="$1"
    local force="${2:-false}"
    
    if [ "$force" == "true" ]; then return 0; fi
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then return 0; fi 
    
    if [ ! -t 0 ]; then
        log_error "Destructive action requires confirmation or --yes flag."
        return 1
    fi
    
    read -p "⚠ $msg [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
    return 0
}

auto_select_interface() {
    local type="$1" # wifi, ethernet, etc
    local count=0
    local candidate=""
    
    local ifaces=(/sys/class/net/*)
    for iface_path in "${ifaces[@]}"; do
        local ifname=$(basename "$iface_path")
        if [[ "$type" == "wifi" ]]; then
            if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
                candidate="$ifname"
                count=$((count + 1))
            fi
        fi
    done
    
    if [ $count -eq 1 ]; then
        echo "$candidate"
        return 0
    fi
    return 1
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

# OPTIMIZED: Pure Bash implementation avoids JQ fork overhead
json_escape() {
    local s="$1"
    # Escape backslashes and quotes
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    # Escape control characters
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"
    
    # Note: For very complex UTF-8/Control character handling, this simple
    # replacement might be insufficient. If strict correctness is required
    # over raw speed for arbitrary inputs, uncomment the JQ fallback:
    
    # if [[ "$s" =~ [^[:print:]] ]]; then
    #    printf '%s' "$s" | "$JQ_BIN" -R . | sed 's/^"//;s/"$//'
    #    return
    # fi
    
    printf '%s' "$s"
}

validate_ssid() {
    local ssid="$1"
    local len=${#ssid}
    if (( len < 1 || len > 32 )); then
        json_error "Invalid SSID length: $len" "1" "SSID must be 1-32 chars"
        return 1
    fi
    if [[ "$ssid" =~ [\$\`\\\!\;] ]]; then
        json_error "SSID contains forbidden characters" "1" "Avoid shell special chars"
        return 1
    fi
    return 0
}

validate_interface_name() {
    local iface="$1"
    if [[ ! "$iface" =~ ^[a-zA-Z0-9_:.-]{1,15}$ ]]; then
        json_error "Invalid interface name: $iface" "1" "Must be alphanumeric, max 15 chars"
        return 1
    fi
    return 0
}

validate_passphrase() {
    local pass="$1"
    local len=${#pass}
    [ "$len" -eq 0 ] && return 0
    if [ "$len" -lt 8 ] || [ "$len" -gt 63 ]; then 
        json_error "Invalid passphrase length ($len)" "1" "WPA2 requires 8-63 characters"
        return 1
    fi
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

validate_integer() {
    local val="$1"
    if [[ "$val" =~ ^[0-9]+$ ]]; then return 0; fi
    return 1
}

validate_vlan_id() {
    local id="$1"
    if ! validate_integer "$id"; then return 1; fi
    if [ "$id" -lt 1 ] || [ "$id" -gt 4094 ]; then return 1; fi
    return 0
}

validate_ip() {
    local ip="$1"
    local clean_ip="${ip%/*}"
    if [[ ! "$ip" =~ ^[0-9a-fA-F:.]+(/[0-9]+)?$ ]]; then
        json_error "Invalid IP syntax: $ip" "1" "Expected format: x.x.x.x/CIDR or x:x::x/CIDR"
        return 1
    fi
    if command -v ip >/dev/null; then
        if ! ip route get "$clean_ip" >/dev/null 2>&1; then
             json_error "Invalid IP address: $clean_ip" "1"
             return 1
        fi
    fi
    return 0
}

validate_routes() {
    local routes="$1"
    IFS=',' read -ra RTS <<< "$routes"
    for r in "${RTS[@]}"; do
        # Supports: dest  OR  dest@gateway  OR  dest@gateway@metric
        # Use @ separator to be IPv6 safe
        local dest=""
        local rgw=""
        local rmet=""
        
        # Split by @
        IFS='@' read -r dest rgw rmet <<< "$r"
        
        if [ -z "$dest" ]; then return 1; fi
        if ! validate_ip "$dest"; then return 1; fi
        if [ -n "$rgw" ]; then
            if ! validate_ip "$rgw"; then return 1; fi
        fi
        if [ -n "$rmet" ]; then
            if ! validate_integer "$rmet"; then return 1; fi
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
    if [[ ! "$code" =~ ^[A-Z]{2}$ ]]; then 
        json_error "Invalid country code: $code" "1" "Use ISO 3166-1 alpha-2 format (e.g., US, JP, DE)"
        return 1
    fi
    return 0
}

validate_mac() {
    local mac="$1"
    if [[ "$mac" =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then return 0; fi
    json_error "Invalid MAC address format" "1" "Expected XX:XX:XX:XX:XX:XX"
    return 1
}

validate_mtu() {
    local mtu="$1"
    if [[ "$mtu" =~ ^[0-9]+$ ]] && [ "$mtu" -ge 68 ] && [ "$mtu" -le 65535 ]; then return 0; fi
    json_error "Invalid MTU" "1" "Must be integer between 68 and 65535"
    return 1
}

validate_link_speed() {
    local spd="$1"
    # Accept integers (Mbps) like 10, 100, 1000, 2500, 10000
    if [[ "$spd" =~ ^[0-9]+$ ]] && [ "$spd" -ge 10 ]; then return 0; fi
    json_error "Invalid link speed: $spd" "1" "Must be integer (Mbps)"
    return 1
}

validate_duplex() {
    local dup="$1"
    if [[ "$dup" =~ ^(half|full)$ ]]; then return 0; fi
    json_error "Invalid duplex mode: $dup" "1" "Must be 'half' or 'full'"
    return 1
}

validate_autoneg() {
    local auto="$1"
    if [[ "$auto" =~ ^(yes|no)$ ]]; then return 0; fi
    json_error "Invalid autonegotiation: $auto" "1" "Must be 'yes' or 'no'"
    return 1
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
        "$JQ_BIN" -n --arg h "$http" --arg s "$https" --arg n "$noproxy" \
            '{http: (if $h!="" then $h else null end), https: (if $s!="" then $s else null end), noproxy: (if $n!="" then $n else null end)}'
    else
        echo "null"
    fi
}
