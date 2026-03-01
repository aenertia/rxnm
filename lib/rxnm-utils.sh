# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# shellcheck disable=SC3043 # Target shells (Ash/Dash) support 'local'

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
# Optimization: Restored Bash Associative Arrays (Hidden from POSIX parser via eval)
if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
    eval 'declare -A _sysfs_cache'
fi

get_iface_sysfs() {
    local iface="$1"
    local data=""
    
    # Fast Path: Bash Cache (eval-guarded)
    if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
        eval 'data="${_sysfs_cache['"$iface"']:-}"'
        if [ -n "$data" ]; then
             echo "$data"
             return
        fi
    fi
    
    if [ -d "/sys/class/net/$iface" ]; then
        if [ -r "/sys/class/net/$iface/operstate" ] && [ -r "/sys/class/net/$iface/address" ] && [ -r "/sys/class/net/$iface/mtu" ]; then
             data=$(paste -d: "/sys/class/net/$iface/operstate" "/sys/class/net/$iface/address" "/sys/class/net/$iface/mtu" 2>/dev/null)
        fi
    fi
    
    # Store in Cache (Bash only, eval-guarded)
    if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ] && [ -n "$data" ]; then
        eval '_sysfs_cache['"$iface"']="$data"'
    fi
    
    echo "$data"
}

clear_sysfs_cache() {
    if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
        eval '_sysfs_cache=()'
    fi
}

# Description: Cleans up temporary files and stale locks on exit.
cleanup() {
    exec 8>&- 2>/dev/null   # Release global lock FD (RXNM_FD_GLOBAL_LOCK)
    
    # POSIX compliant cleanup using find instead of array globs
    if [ -n "${STORAGE_NET_DIR:-}" ] && [ -d "$STORAGE_NET_DIR" ]; then
        find "$STORAGE_NET_DIR" -maxdepth 1 -name "*.XXXXXX" -exec rm -f {} + 2>/dev/null
    fi
    
    # Release global lock if owned by this process
    if [ -f "${GLOBAL_PID_FILE:-}" ]; then
        local pid
        pid=$(cat "$GLOBAL_PID_FILE" 2>/dev/null || echo "")
        if [ "$pid" = "$$" ]; then
            rm -f "$GLOBAL_PID_FILE" "$GLOBAL_LOCK_FILE" 2>/dev/null
        fi
    fi
    
    # Attempt to clean up stale sub-locks in RUN_DIR
    _try_remove_stale_lock() {
        local lock="$1"
        [ -f "$lock" ] || return
        
        #  Use FD-based flock in a subshell for universal BusyBox compatibility
        # and to avoid TOCTOU races by holding the lock while unlinking.
        (
            if exec 9>>"$lock" && flock -n 9; then
                rm -f "$lock"
            fi
        ) 2>/dev/null
    }

    if [ -n "${RUN_DIR:-}" ] && [ -d "$RUN_DIR" ]; then
        find "$RUN_DIR" -name "*.lock" -type f 2>/dev/null | while IFS= read -r lf; do
            _try_remove_stale_lock "$lf"
        done
    fi
    if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ]; then
        rm -rf "$TMPDIR" 2>/dev/null
    fi
}

# --- Locking Mechanisms ---

# Description: Executes a command with xtrace disabled to prevent credential leakage in logs.
# Arguments: Command and arguments...
secure_exec() {
    local was_x=0
    # Check if xtrace is currently enabled
    if case $- in *x*) true;; *) false;; esac; then was_x=1; set +x; fi
    
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
    # shellcheck disable=SC2034
    local timeout="${1:-5}"
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
    
    # FD 8 reserved for global lock — see RXNM_FD_GLOBAL_LOCK in rxnm-constants.sh.
    exec 8>"$GLOBAL_LOCK_FILE"
    
    if ! flock -w "$timeout" 8; then
        # Lock exists, check if stale
        if [ -f "$GLOBAL_PID_FILE" ]; then
            local old_pid
            old_pid=$(cat "$GLOBAL_PID_FILE" 2>/dev/null || echo "")
            if [ -n "$old_pid" ] && ! kill -0 "$old_pid" 2>/dev/null; then
                log_warn "Removing stale lock (PID $old_pid)"
                rm -f "$GLOBAL_LOCK_FILE" "$GLOBAL_PID_FILE"
                exec 8>"$GLOBAL_LOCK_FILE"
                if ! flock -w 2 8; then
                    log_error "Lock race on stale-lock cleanup — concurrent instance won"
                    exec 8>&-
                    return 1
                fi
            else
                log_error "Another instance is running (PID ${old_pid:-unknown})"
                exec 8>&-
                return 1
            fi
        else
            log_error "Another instance is running (no PID file)"
            exec 8>&-
            return 1
        fi
    fi
    echo "$$" > "$GLOBAL_PID_FILE"
    trap cleanup EXIT INT TERM
    return 0
}

# Description: Acquires a fine-grained lock for a specific interface.
# Arguments: $1 = Interface Name, $2... = Command to execute
# Returns: Exit code of the executed command.
with_iface_lock() {
    local _wi_iface="$1"
    shift
    local _wi_timeout="${TIMEOUT:-10}"
    local _wi_lock_file="${RUN_DIR}/${_wi_iface}.lock"
    
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
    
    # Check if we already hold this lock (e.g., nested calls within the SAME process)
    if [ "${_RXNM_ACTIVE_LOCK:-}" = "$_wi_iface" ]; then
        "$@"
        return $?
    fi
    
    # Dynamically allocate FDs to prevent lock clobbering when 
    # concurrent backgrounded RXNM tasks run within the same parent shell.
    # NOTE: This counter persists across sourced invocations in long-running 
    # parent shells. It safely wraps at 200, which may reuse FDs in extreme cases.
    : "${_RXNM_FD_COUNTER:=10}"
    
    # Export the counter so subshells don't reset to 10 and clobber parent FDs.
    export _RXNM_FD_COUNTER
    local _wi_fd="$_RXNM_FD_COUNTER"
    _RXNM_FD_COUNTER=$((_RXNM_FD_COUNTER + 1))
    
    # Reset bounds safely within POSIX spec to prevent max fd limits
    if [ "$_RXNM_FD_COUNTER" -gt 200 ]; then _RXNM_FD_COUNTER=10; fi
    
    eval "exec ${_wi_fd}>\"$_wi_lock_file\""
    
    if ! flock -w "$_wi_timeout" "$_wi_fd"; then
        log_error "Failed to acquire lock for $_wi_iface after ${_wi_timeout}s"
        eval "exec ${_wi_fd}>&-"
        return 1
    fi
    
    local _prev_lock="${_RXNM_ACTIVE_LOCK:-}"
    _RXNM_ACTIVE_LOCK="$_wi_iface"
    
    # Execute protected command
    "$@"
    local _wi_ret=$?
    
    _RXNM_ACTIVE_LOCK="$_prev_lock"
    
    # Release and close
    eval "exec ${_wi_fd}>&-"
    return $_wi_ret
}

# --- Logging ---

log_debug() {
    if [ "${LOG_LEVEL:-2}" -ge "$LOG_LEVEL_DEBUG" ]; then
        echo "[DEBUG] $*" >&2
    fi
    return 0
}
log_info() {
    if [ "${LOG_LEVEL:-2}" -ge "$LOG_LEVEL_INFO" ]; then
        echo "[INFO] $*" >&2
    fi
    return 0
}
log_warn() {
    if [ "${LOG_LEVEL:-2}" -ge "$LOG_LEVEL_WARN" ]; then
        echo "[WARN] $*" >&2
    fi
    return 0
}
log_error() {
    echo "[ERROR] $*" >&2
    if [ "${RXNM_FORMAT:-human}" != "json" ]; then
         echo "Try 'rxnm --help' for usage information." >&2
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Function: rxnm_json_get
# Description: Extracts a single top-level key from a flat JSON object.
# -----------------------------------------------------------------------------
rxnm_json_get() {
    local _json="$1"
    local _key="$2"
    local val=""

    if [ "${RXNM_HAS_JQ:-false}" = "true" ]; then
        # shellcheck disable=SC2016
        printf '%s' "$_json" | "$JQ_BIN" -r ".${_key} // empty"
        return
    fi

    # String: "key":"value"
    val=$(printf '%s' "$_json" | \
        grep -o '"'"$_key"'"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        sed 's/.*:[[:space:]]*"\([^"]*\)".*/\1/' | head -n1)
    [ -n "$val" ] && { printf '%s\n' "$val"; return 0; }
    
    # Number: "key":123 or "key":-1.5
    val=$(printf '%s' "$_json" | \
        grep -o '"'"$_key"'"[[:space:]]*:[[:space:]]*-\?[0-9][0-9.]*' | \
        sed 's/.*:[[:space:]]*//' | head -n1)
    [ -n "$val" ] && { printf '%s\n' "$val"; return 0; }
    
    # Boolean: "key":true|false
    val=$(printf '%s' "$_json" | \
        grep -o '"'"$_key"'"[[:space:]]*:[[:space:]]*\(true\|false\)' | \
        sed 's/.*:[[:space:]]*//' | head -n1)
    printf '%s\n' "${val:-}"
}

# -----------------------------------------------------------------------------
# Function: rxnm_match
# Description: POSIX regex matcher wrapper
# -----------------------------------------------------------------------------
rxnm_match() {
    local _str="$1"
    local _pat="$2"
    local _grep_ret

    if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
        # Path A: Bash native ERE — no subprocess
        # Hide [[ =~ ]] from POSIX parsers via eval
        eval '[[ "$_str" =~ $_pat ]]'
        return
    fi

    # Path B: grep -qE is universally available (BusyBox, musl, glibc).
    # Try it first to avoid burning an agent invocation on pattern matching.
    if printf '%s' "$_str" | grep -qE "$_pat" 2>/dev/null; then
        return 0
    else
        _grep_ret=$?
        [ "$_grep_ret" -eq 1 ] && return 1   # Clean no-match from grep — trust it
    fi

    # grep returned 2 (bad pattern) or failed — fall back to agent regex
    if [ -x "${RXNM_AGENT_BIN:-}" ]; then
        "$RXNM_AGENT_BIN" --match "$_str" "$_pat"
        return
    fi

    # No agent, bad grep pattern: conservatively return 1 (no-match)
    return 1
}

cli_error() {
    local msg="$1"
    if [ "${RXNM_FORMAT:-human}" = "json" ]; then
        json_error "$msg"
    else
        echo "Error: $msg" >&2
    fi
    exit 1
}

audit_log() {
    local event="$1"
    local details="$2"
    logger -t rxnm-audit -p auth.notice "$event: $details" || true
}

# --- Output Formatting ---

# Description: Outputs success data in the requested format (JSON, Table, or Human).
# Arguments: $1 = JSON payload (string)
json_success() {
    local data="${1:-}"
    
    if [ -z "$data" ] && [ -p /dev/stdin ]; then
        data=$(cat)
    fi
    if [ -z "$data" ]; then data="{}"; fi
    
    local api_ver="${RXNM_API_VERSION:-1.0}"
    
    # Corrected: Use POSIX fallback if JQ missing
    local full_json
    if [ "${RXNM_HAS_JQ:-false}" = "true" ]; then
        # shellcheck disable=SC2016
        full_json=$("$JQ_BIN" -n --argjson data "$data" --arg ver "$api_ver" '{success:true, api_version:$ver} + $data')
    else
        if [ "$data" = "{}" ]; then
             full_json=$(printf '{"success": true, "api_version": "%s"}' "$api_ver")
        else
             # Primitive merge: safely trim braces before structure merge
             local body="${data#\{}"
             body="${body%\}}"
             full_json=$(printf '{"success": true, "api_version": "%s", %s}' "$api_ver" "$body")
        fi
    fi
    
    case "${RXNM_FORMAT:-human}" in
        json)
            echo "$full_json"
            ;;
        simple)
            if [ -n "${RXNM_GET_KEY:-}" ]; then
                rxnm_json_get "$full_json" "$RXNM_GET_KEY"
            else
                # Very rough heuristic without JQ
                echo "OK"
            fi
            ;;
        *)
            echo "$full_json"
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
    
    if [ "${RXNM_FORMAT:-human}" = "json" ]; then
        if [ "${RXNM_HAS_JQ:-false}" = "true" ]; then
            # shellcheck disable=SC2016
            "$JQ_BIN" -n --arg msg "$msg" --arg code "$code" --arg hint "$hint" --arg ver "$api_ver" \
                '{success:false, api_version:$ver, error:$msg, hint:(if $hint=="" then null else $hint end), exit_code:($code|tonumber)}'
        else
            printf '{"success": false, "api_version": "%s", "error": "%s", "exit_code": %s}\n' "$api_ver" "$msg" "$code"
        fi
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
    
    if [ "$force" = "true" ]; then return 0; fi
    if [ "${RXNM_FORMAT:-human}" = "json" ]; then return 0; fi # Implicit yes in JSON mode
    
    if ! [ -t 0 ]; then
        log_error "Destructive action requires confirmation or --yes flag."
        return 1
    fi
    
    printf '⚠ %s [y/N] ' "$msg"
    read -r REPLY
    case "$REPLY" in
        [Yy]*) ;;
        *) echo "Cancelled."; exit 0 ;;
    esac
    return 0
}

# --- Utilities ---

auto_select_interface() {
    local type="$1"
    local count=0
    local candidate=""
    local ifaces
    # POSIX safe expansion of glob
    set -- /sys/class/net/*
    ifaces="$*"
    
    for iface_path in $ifaces; do
        if [ ! -e "$iface_path" ]; then continue; fi
        local ifname
        ifname=$(basename "$iface_path")
        if [ "$type" = "wifi" ]; then
            if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ]; then
                candidate="$ifname"
                count=$((count + 1))
            fi
        fi
    done
    if [ "$count" -eq 1 ]; then
        echo "$candidate"
        return 0
    fi
    return 1
}

sanitize_ssid() {
    printf '%s' "$1" | sed 's/[^a-zA-Z0-9_.-]/_/g'
}

# Description: Encodes SSID to strictly match IWD's hex-encoding parity scheme.
# Replaces non-alphanumeric characters with '=XX' to prevent Path Traversal.
iwd_encode_ssid() {
    local ssid="$1"
    if [ -x "${RXNM_AGENT_BIN:-}" ]; then
        if "$RXNM_AGENT_BIN" --encode-ssid "$ssid" 2>/dev/null; then
            return 0
        fi
    fi
    
    if [ "${RXNM_SHELL_IS_BASH:-false}" = "true" ]; then
        eval '
        local encoded=""
        local i c hex
        for (( i=0; i<${#ssid}; i++ )); do
            c="${ssid:$i:1}"
            case "$c" in
                [a-zA-Z0-9_.-]) encoded="${encoded}${c}" ;;
                *) 
                    hex=$(printf "%02x" "'\''$c")
                    encoded="${encoded}=${hex}" 
                    ;;
            esac
        done
        echo "$encoded"
        '
    else
        # POSIX Fallback (Lossy, but prevents crash if agent is missing on dash)
        printf '%s' "$ssid" | sed 's/[^a-zA-Z0-9_.-]/_/g'
    fi
}

json_escape() {
    local s="$1"
    # 1. Append newline for POSIX sed safety to prevent dropping string on strict BSD/GNU seds.
    # 2. Replace all newlines with spaces to ensure single-line JSON format.
    # 3. Escape backslashes, double quotes, and literal tabs.
    local escaped
    escaped=$(printf '%s\n' "$s" | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g')
    # 4. Strip the trailing space that was converted from the appended newline.
    printf '%s' "${escaped% }"
}

get_proxy_json() {
    local file="$1"
    if [ -f "$file" ]; then
        local http="" https="" noproxy=""
        while read -r line; do
            [ -z "$line" ] && continue
            
            # Robustly parse config without truncating embedded '=' signs
            local key="${line%%=*}"
            local value="${line#*=}"
            value=$(echo "$value" | tr -d "\"'")
            
            case "$key" in
                http_proxy|'export http_proxy') http="$value" ;;
                https_proxy|'export https_proxy') https="$value" ;;
                no_proxy|'export no_proxy') noproxy="$value" ;;
            esac
        done < "$file"
        
        if [ -n "$http" ] && ! validate_proxy_url "$http"; then http=""; fi
        if [ -n "$https" ] && ! validate_proxy_url "$https"; then https=""; fi
        
        if [ "${RXNM_HAS_JQ:-false}" = "true" ]; then
            # shellcheck disable=SC2016
            "$JQ_BIN" -n --arg h "$http" --arg s "$https" --arg n "$noproxy" \
                '{http: (if $h!="" then $h else null end), https: (if $s!="" then $s else null end), noproxy: (if $n!="" then $n else null end)}'
        else
            printf '{"http": "%s", "https": "%s", "noproxy": "%s"}' "$http" "$https" "$noproxy"
        fi
    else
        echo "null"
    fi
}

secure_write() {
    local dest="$1"
    local content="$2"
    local perms="${3:-644}"
    
    case "$dest" in
       "${EPHEMERAL_NET_DIR}/"*) ;;
       "${PERSISTENT_NET_DIR}/"*) ;;
       "${STATE_DIR}/"*) ;;
       "${CONF_DIR}/"*) ;;
       "${RUN_DIR}/"*) ;;
       *)
         log_error "Illegal file write attempted: $dest"
         return 1
         ;;
    esac
    
    local dir
    dir=$(dirname "$dest")
    [ -d "$dir" ] || mkdir -p "$dir"
    
    if [ -x "${RXNM_AGENT_BIN:-}" ]; then
        if printf "%s" "$content" | "${RXNM_AGENT_BIN}" --atomic-write "$dest" --perm "$perms" 2>/dev/null; then
            return 0
        fi
    fi
    
    local tmp
    tmp=$(umask 077 && mktemp "${dest}.XXXXXX") || return 1
    
    printf "%s" "$content" > "$tmp" || { rm -f "$tmp"; return 1; }
    if [ "$perms" != "600" ]; then chmod "$perms" "$tmp"; fi
    sync
    mv "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}

validate_ssid() {
    local ssid="$1"
    local len=${#ssid}
    if [ "$len" -lt 1 ] || [ "$len" -gt 32 ]; then
        json_error "Invalid SSID length: $len" "1" "SSID must be 1-32 chars"
        return 1
    fi
    return 0
}

validate_interface_name() {
    local iface="$1"
    if ! rxnm_match "$iface" '^[a-zA-Z0-9_:.-]{1,15}$'; then
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
    if rxnm_match "$name" '[[:cntrl:]]'; then return 1; fi
    return 0
}

validate_channel() {
    local ch="$1"
    if ! rxnm_match "$ch" '^[0-9]+$'; then return 1; fi
    if [ "$ch" -lt "${MIN_CHANNEL:-1}" ] || [ "$ch" -gt "${WIFI_CHANNEL_MAX:-177}" ]; then return 1; fi
    return 0
}

validate_integer() {
    local val="$1"
    rxnm_match "$val" '^[0-9]+$'
}

# Description: Lightweight integer check (POSIX case-based, no subprocess).
# Accepts negative integers. Used by roaming/scan poll loops.
is_integer() { case "$1" in ''|*[!0-9-]*) return 1;; esac; return 0; }

validate_vlan_id() {
    local id="$1"
    if ! validate_integer "$id"; then return 1; fi
    if [ "$id" -lt 1 ] || [ "$id" -gt 4094 ]; then return 1; fi
    return 0
}

validate_ip() {
    local ip="$1"
    
    # Structural check
    if ! rxnm_match "$ip" '^[0-9a-fA-F:.]+(/[0-9]{1,3})?$'; then
        json_error "Invalid IP syntax: $ip" "1" "Expected format: x.x.x.x/CIDR or x:x::x/CIDR"
        return 1
    fi
    
    local addr="${ip%/*}"
    local prefix="${ip##*/}"
    
    # Strict Semantic Validation for IPv4 Octets and IPv6 CIDR Lengths
    if case "$addr" in *:*) false;; *) true;; esac; then
        # IPv4
        if ! rxnm_match "$addr" '^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'; then
            return 1
        fi
        if [ "$prefix" != "$ip" ] && [ "$prefix" -gt 32 ] 2>/dev/null; then
            return 1
        fi
    else
        # IPv6
        if [ "$prefix" != "$ip" ] && [ "$prefix" -gt 128 ] 2>/dev/null; then
            json_error "Invalid IPv6 CIDR: prefix > 128" "1"
            return 1
        fi
    fi
    return 0
}

# _validate_ip_csv <comma-separated-ip-list>
# Returns 0 if every entry passes validate_ip, 1 on first failure.
_validate_ip_csv() {
    local _list="$1"
    set -f
    local _old_ifs="$IFS"
    IFS=","
    for _item in $_list; do
        _item=$(printf '%s' "$_item" | tr -d ' \t')
        [ -z "$_item" ] && continue
        if ! validate_ip "$_item"; then IFS="$_old_ifs"; set +f; return 1; fi
    done
    IFS="$_old_ifs"
    set +f
    return 0
}

validate_routes() {
    local routes="$1"
    set -f
    local _old_ifs="$IFS"
    IFS=","
    for r in $routes; do
        local dest=""
        local rgw=""
        local rmet=""
        
        dest="${r%%@*}"
        local rest="${r#*@}"
        if [ "$rest" = "$r" ]; then rest=""; fi
        
        if [ -n "$rest" ]; then
            rgw="${rest%%@*}"
            rmet="${rest#*@}"
            if [ "$rmet" = "$rest" ]; then rmet=""; fi
        fi
        
        if [ -z "$dest" ]; then IFS="$_old_ifs"; set +f; return 1; fi
        if ! validate_ip "$dest"; then IFS="$_old_ifs"; set +f; return 1; fi
        if [ -n "$rgw" ]; then
            if ! validate_ip "$rgw"; then IFS="$_old_ifs"; set +f; return 1; fi
        fi
        if [ -n "$rmet" ]; then
            if ! validate_integer "$rmet"; then IFS="$_old_ifs"; set +f; return 1; fi
        fi
    done
    IFS="$_old_ifs"
    set +f
    return 0
}

validate_dns() { _validate_ip_csv "$1"; }

validate_proxy_url() {
    local url="$1"
    case "$url" in
        *"$(printf '\n')"*|*"$(printf '\r')"*) return 1 ;;
    esac
    if rxnm_match "$url" '^(http|https|socks4|socks5)://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$'; then
        return 0
    fi
    if rxnm_match "$url" '^[0-9.]+:[0-9]+$'; then
        local ip="${url%%:*}"
        local port="${url##*:}"
        if validate_ip "$ip" && [ "$port" -le 65535 ]; then
            return 0
        fi
    fi
    return 1
}

validate_country() {
    local code="$1"
    if ! rxnm_match "$code" '^[A-Z]{2}$'; then
        json_error "Invalid country code: $code" "1" "Use ISO 3166-1 alpha-2 format (e.g., US, JP, DE)"
        return 1
    fi
    return 0
}

validate_mac() {
    local mac="$1"
    if ! rxnm_match "$mac" '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'; then
        json_error "Invalid MAC address format" "1" "Expected XX:XX:XX:XX:XX:XX"
        return 1
    fi
    return 0
}

validate_mtu() {
    local mtu="$1"
    if ! rxnm_match "$mtu" '^[0-9]+$' || [ "$mtu" -lt 68 ] || [ "$mtu" -gt 65535 ]; then
        json_error "Invalid MTU" "1" "Must be integer between 68 and 65535"
        return 1
    fi
    return 0
}

validate_link_speed() {
    local spd="$1"
    if ! rxnm_match "$spd" '^[0-9]+$' || [ "$spd" -lt 10 ]; then
        json_error "Invalid link speed: $spd" "1" "Must be integer (Mbps)"
        return 1
    fi
    return 0
}

validate_duplex() {
    local dup="$1"
    if ! rxnm_match "$dup" '^(half|full)$'; then
        json_error "Invalid duplex mode: $dup" "1" "Must be 'half' or 'full'"
        return 1
    fi
    return 0
}

validate_autoneg() {
    local auto="$1"
    if ! rxnm_match "$auto" '^(yes|no)$'; then
        json_error "Invalid autonegotiation: $auto" "1" "Must be 'yes' or 'no'"
        return 1
    fi
    return 0
}
