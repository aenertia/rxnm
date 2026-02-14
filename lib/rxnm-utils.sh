# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-utils.sh
# PURPOSE: Standard Library for RXNM
# ARCHITECTURE: Foundation / Utility
#
# Contains reusable functions for I/O, locking, validation, and JSON formatting.
# -----------------------------------------------------------------------------

# --- System Utils ---

# Description: Caches sysfs reads to reduce I/O overhead in tight loops.
# Arguments: $1 = Interface Name
# Returns: String containing operstate:address:mtu
declare -A _sysfs_cache
get_iface_sysfs() {
    local iface=$1
    [ -n "${_sysfs_cache[$iface]}" ] && echo "${_sysfs_cache[$iface]}" && return
    local data=""
    if [ -d "/sys/class/net/$iface" ]; then
        data=$(paste -d: /sys/class/net/$iface/operstate /sys/class/net/$iface/address /sys/class/net/$iface/mtu 2>/dev/null)
    fi
    _sysfs_cache[$iface]="$data"
    echo "$data"
}

# Description: Cleans up temporary files and stale locks on exit.
cleanup() {
    local temp_files=("${STORAGE_NET_DIR}"/*.XXXXXX)
    if [ ${#temp_files[@]} -gt 0 ]; then
        rm -f "${temp_files[@]}" 2>/dev/null
    fi
    # Release global lock if owned by this process
    if [ -f "$GLOBAL_PID_FILE" ]; then
        local pid
        pid=$(cat "$GLOBAL_PID_FILE" 2>/dev/null || echo "")
        if [ "$pid" == "$$" ]; then
            rm -f "$GLOBAL_PID_FILE" "$GLOBAL_LOCK_FILE" 2>/dev/null
        fi
    fi
    # Attempt to clean up stale sub-locks in RUN_DIR
    if [ -n "$RUN_DIR" ] && [ -d "$RUN_DIR" ]; then
        if command -v fuser >/dev/null; then
            find "$RUN_DIR" -name "*.lock" -type f 2>/dev/null | while read -r lock; do
                if [ -f "$lock" ]; then
                    local lock_pid
                    lock_pid=$(fuser "$lock" 2>/dev/null | awk '{print $1}')
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

# --- Locking Mechanisms ---

# Description: Executes a command with xtrace disabled to prevent credential leakage in logs.
# Arguments: Command and arguments...
secure_exec() {
    local was_x=0
    # Check if xtrace is currently enabled
    if [[ $- == *x* ]]; then was_x=1; set +x; fi
    
    # Execute the command
    "$@"
    local ret=$?
    
    # Restore xtrace if it was enabled
    if [ $was_x -eq 1 ]; then set -x; fi
    return $ret
}

# Description: Acquires the global singleton lock for the RXNM process.
# Arguments: $1 = Timeout (seconds)
# Returns: 0 on success, 1 on failure.
acquire_global_lock() {
    local timeout="${1:-5}"
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
    exec 200>"$GLOBAL_LOCK_FILE"
    
    if ! flock -n 200; then
        # Lock exists, check if stale
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

# Description: Acquires a fine-grained lock for a specific interface.
# Arguments: $1 = Interface Name, $2... = Command to execute
# Returns: Exit code of the executed command.
with_iface_lock() {
    local iface="$1"; shift
    local timeout="${TIMEOUT:-10}"
    local lock_file="${RUN_DIR}/${iface}.lock"
    local lock_fd
    
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
    
    # Open lock file descriptor
    exec {lock_fd}>"$lock_file" || {
        log_error "Failed to open lock file for $iface"
        return 1
    }
    
    # Attempt to acquire lock with timeout
    if ! flock -w "$timeout" "$lock_fd"; then
        log_error "Failed to acquire lock for $iface after ${timeout}s"
        exec {lock_fd}>&-
        return 1
    fi
    
    # Execute the protected command
    local ret=0
    "$@" || ret=$?
    
    # Release and close
    flock -u "$lock_fd"
    exec {lock_fd}>&-
    return $ret
}

# --- Logging ---

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
    if [ "${RXNM_FORMAT:-human}" != "json" ]; then
         echo "Try 'rxnm --help' for usage information." >&2
    fi
}

# Description: Exits the script with an error message formatted correctly for the requested output mode.
# Arguments: $1 = Message
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

# --- Output Formatting (JSON/Table) ---

# Description: Prints a TSV-based table from JSON input using awk/column.
# Arguments: $1 = JSON Input, $2 = Column Definition (key:HEADER,key:HEADER)
print_table() {
    local json_input="$1"
    local columns="$2"
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
    
    local tsv_data
    tsv_data=$(echo -e "${header_row}"; echo "$json_input" | "$JQ_BIN" -r ".[]? | $jq_query" 2>/dev/null)
    
    # Fallback if first query empty
    if [ -z "$tsv_data" ] && [ "${RXNM_FORMAT:-human}" != "json" ]; then
        tsv_data=$(echo -e "${header_row}"; echo "$json_input" | "$JQ_BIN" -r "$jq_query" 2>/dev/null)
    fi
    
    if command -v column >/dev/null; then
        echo "$tsv_data" | column -t -s $'\t'
    else
        # BusyBox awk fallback for alignment
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

# Description: Outputs success data in the requested format (JSON, Table, or Human).
# Arguments: $1 = JSON payload (string)
json_success() {
    local data
    if [ -p /dev/stdin ]; then
        data=$(cat)
    else
        data="${1:-}"
    fi
    if [ -z "$data" ]; then data="{}"; fi
    
    local api_ver="${RXNM_API_VERSION:-1.0}"
    
    # REFINED: Inject api_version into every success response
    local full_json
    full_json=$("$JQ_BIN" -n --argjson data "$data" --arg ver "$api_ver" '{success:true, api_version:$ver} + $data')
    
    case "${RXNM_FORMAT:-human}" in
        json)
            echo "$full_json"
            ;;
        simple)
            if [ -n "${RXNM_GET_KEY:-}" ]; then
                # Use jq to extract specific path
                local query="${RXNM_GET_KEY}"
                
                # If the key provided doesn't look like a path, try direct top-level access
                if [[ "$query" != .* ]]; then query=".${query}"; fi
                
                local val
                val=$(echo "$full_json" | "$JQ_BIN" -r "$query // empty")
                
                # If extraction failed but user looked for typical interface props, search inside interfaces map
                if [ -z "$val" ]; then
                     val=$(echo "$full_json" | "$JQ_BIN" -r ".interfaces[]? | $query // empty" | head -n1)
                fi
                
                echo "$val"
            else
                # Heuristic fallback for --simple without --get
                # Returns IP (v4), SSID, Status or Message if found
                # Prioritizes clean single-line output for scripting (IP only)
                echo "$full_json" | "$JQ_BIN" -r '
                    if .interfaces and (.interfaces | length == 1) then
                        (.interfaces | to_entries[0].value | (.ip // .ipv4[0] // .state))
                    elif .ip and .ip != null then .ip
                    elif .ssid and .ssid != null then .ssid
                    elif .status and .status != null then .status
                    elif .result and .result != null then .result
                    elif .message then .message
                    else "OK" end
                '
            fi
            ;;
        table)
            # Detect data type to format table correctly
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
                    echo "$full_json" | "$JQ_BIN" -r 'del(.success, .api_version) | to_entries | .[] | "\(.key): \(.value)"'
                    ;;
            esac
            ;;
        *)
            # Human readable output logic
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
                     # Force output of IPv6 and Routes if available
                     # Uses string interpolation to ensure fields are printed even if empty/null
                     echo "$full_json" | "$JQ_BIN" -r '.interfaces[] | "Interface: \(.name)\n  Type: \(.type)\n  State: \(if .connected then "UP" else "DOWN" end)\n  IP: \(.ip // "-")\n  IPv6: \((.ipv6 // []) | join(", "))\n  Routes: \((.routes // []) | map(.dst + " via " + (.gw // "on-link")) | join(", "))\n  Details: \(.ssid // .members // "-")\n"'
                     ;;
                *)
                    echo "$full_json" | "$JQ_BIN" -r 'del(.success, .api_version) | to_entries | .[] | "\(.key): \(.value)"'
                    ;;
            esac
            ;;
    esac
}

# Description: Outputs error data in the requested format.
# Arguments: $1 = Message, $2 = Exit Code (optional), $3 = Hint (optional)
json_error() {
    local msg="$1"
    local code="${2:-1}"
    local hint="${3:-}"
    local api_ver="${RXNM_API_VERSION:-1.0}"
    
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then
        "$JQ_BIN" -n --arg msg "$msg" --arg code "$code" --arg hint "$hint" --arg ver "$api_ver" \
            '{success:false, api_version:$ver, error:$msg, hint:(if $hint=="" then null else $hint end), exit_code:($code|tonumber)}'
    else
        echo "✗ Error: $msg" >&2
        [ -n "$hint" ] && echo "  hint: $hint" >&2
    fi
    return 0
}

# Description: Prompts user for confirmation unless forced.
# Arguments: $1 = Message, $2 = Force Flag (true/false)
confirm_action() {
    local msg="$1"
    local force="${2:-false}"
    
    if [ "$force" == "true" ]; then return 0; fi
    if [ "${RXNM_FORMAT:-human}" == "json" ]; then return 0; fi # Implicit yes in JSON mode
    
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

# --- Utilities ---

auto_select_interface() {
    local type="$1"
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

sanitize_ssid() {
    # Preserves UTF-8, Emojis, and Spaces for readability in filenames.
    # Only replaces the directory separator '/' with underscore '_' to ensure filesystem safety.
    # Note: Bash variable replacement ${var//\//_} handles UTF-8 correctly on modern Linux systems.
    # Example: "Café 🚀/5G" -> "Café 🚀_5G"
    printf '%s\n' "${1//\//_}"
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\b'/\\b}"
    s="${s//$'\f'/\\f}"
    printf '%s' "$s"
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

# Description: Writes content to a file safely and atomically.
# Uses the C agent if available, otherwise falls back to mktemp/mv.
# Arguments: $1 = Destination, $2 = Content, $3 = Octal Permissions
secure_write() {
    local dest="$1"
    local content="$2"
    local perms="${3:-644}"
    
    # Security: Prevent writing outside allowed RXNM directories
    if [[ "$dest" != "${EPHEMERAL_NET_DIR}/"* ]] && \
       [[ "$dest" != "${PERSISTENT_NET_DIR}/"* ]] && \
       [[ "$dest" != "${STATE_DIR}/"* ]] && \
       [[ "$dest" != "${CONF_DIR}/"* ]] && \
       [[ "$dest" != "${RUN_DIR}/"* ]]; then
         log_error "Illegal file write attempted: $dest"
         return 1
    fi
    
    [ -d "$(dirname "$dest")" ] || mkdir -p "$(dirname "$dest")"
    
    # Accelerator Path: Use Native Agent if available (Atomic/Idempotent)
    if [ -x "${RXNM_AGENT_BIN}" ]; then
        if printf "%b" "$content" | "${RXNM_AGENT_BIN}" --atomic-write "$dest" --perm "$perms" 2>/dev/null; then
            return 0
        fi
    fi
    
    # Fallback Path: Shell implementation
    local tmp
    # Fix: Force umask 077 for the temp file creation to prevent race condition window
    tmp=$(umask 077 && mktemp "${dest}.XXXXXX") || return 1
    
    printf "%b" "$content" > "$tmp" || { rm -f "$tmp"; return 1; }
    
    # Apply requested permissions (only if wider than 600 needed)
    if [ "$perms" != "600" ]; then chmod "$perms" "$tmp"; fi
    
    sync
    mv "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}

# --- Validation Functions ---

validate_ssid() {
    local ssid="$1"
    local len=${#ssid}
    if (( len < 1 || len > 32 )); then
        json_error "Invalid SSID length: $len" "1" "SSID must be 1-32 chars"
        return 1
    fi
    # Removed character restriction check to allow for UTF-8/Emoji/Special Chars
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
