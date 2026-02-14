# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-routes.sh
# PURPOSE: Advanced Routing Table Management
# ARCHITECTURE: SOA / Routes
#
# Implements direct manipulation of the kernel routing tables.
# Bridges the gap between interface-centric configs and service-oriented
# routing requirements (multi-path, policy routing, source-routing).
# -----------------------------------------------------------------------------

action_route_dispatch() {
    local action="$1"
    shift
    
    case "$action" in
        list|show) action_route_list "$@" ;;
        add|del|delete|replace|change|append) 
            [ "$action" == "delete" ] && action="del"
            action_route_modify "$action" "$@" 
            ;;
        get) action_route_get "$@" ;;
        flush) action_route_flush "$@" ;;
        *) json_error "Unknown route action: $action" "1" "Try: list, add, del, get, flush" ;;
    esac
}

action_route_list() {
    local table=""
    local family=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --table) table="$2"; shift 2 ;;
            --v4) family="-4"; shift ;;
            --v6) family="-6"; shift ;;
            *) shift ;;
        esac
    done
    
    # Acceleration: Use agent if available and requesting table dump
    if [ -x "$RXNM_AGENT_BIN" ]; then
        local t_id="${table:-254}" # Default to main (254)
        local out
        if out=$("$RXNM_AGENT_BIN" --route-dump "$t_id" 2>/dev/null); then
            echo "$out"
            return 0
        fi
    fi
    
    # Fallback to iproute2
    local cmd_v4=("ip" "-j" "-4" "route" "show")
    local cmd_v6=("ip" "-j" "-6" "route" "show")
    
    if [ -n "$table" ]; then
        cmd_v4+=("table" "$table")
        cmd_v6+=("table" "$table")
    fi
    
    local routes_v4="[]"
    local routes_v6="[]"
    
    if [ "$family" != "-6" ]; then
        routes_v4=$("${cmd_v4[@]}" 2>/dev/null || echo "[]")
    fi
    if [ "$family" != "-4" ]; then
        routes_v6=$("${cmd_v6[@]}" 2>/dev/null || echo "[]")
    fi
    
    # Merge and output
    "$JQ_BIN" -n --argjson v4 "$routes_v4" --argjson v6 "$routes_v6" \
        '{success: true, routes: ($v4 + $v6)}'
}

action_route_modify() {
    local op="$1"
    shift
    
    local dest=""
    local gw=""
    local iface=""
    local metric=""
    local table=""
    local src=""
    local scope=""
    local proto=""
    local type=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --destination|--dst) dest="$2"; shift 2 ;;
            --gateway|--gw) gw="$2"; shift 2 ;;
            --interface|--dev) iface="$2"; shift 2 ;;
            --metric) metric="$2"; shift 2 ;;
            --table) table="$2"; shift 2 ;;
            --source|--src) src="$2"; shift 2 ;;
            --scope) scope="$2"; shift 2 ;;
            --protocol|--proto) proto="$2"; shift 2 ;;
            --type) type="$2"; shift 2 ;;
            *) 
                # Allow positional destination if first arg
                if [ -z "$dest" ] && [[ "$1" != --* ]]; then dest="$1"; shift; else shift; fi
                ;;
        esac
    done
    
    [ -z "$dest" ] && { json_error "Destination required (e.g. 10.0.0.0/24 or default)"; return 1; }
    
    # Construct ip route command
    local cmd=("ip" "route" "$op" "$dest")
    
    [ -n "$gw" ] && cmd+=("via" "$gw")
    [ -n "$iface" ] && cmd+=("dev" "$iface")
    [ -n "$metric" ] && cmd+=("metric" "$metric")
    [ -n "$table" ] && cmd+=("table" "$table")
    [ -n "$src" ] && cmd+=("src" "$src")
    [ -n "$scope" ] && cmd+=("scope" "$scope")
    [ -n "$proto" ] && cmd+=("proto" "$proto")
    [ -n "$type" ] && cmd+=("type" "$type")
    
    if "${cmd[@]}"; then
        json_success '{"action": "route_'"$op"'", "destination": "'"$dest"'", "status": "ok"}'
    else
        # Capture stderr for error message
        local err
        err=$("${cmd[@]}" 2>&1)
        json_error "Failed to $op route: $err"
    fi
}

action_route_get() {
    local target="$1"
    shift # Shift target
    
    # Handle flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --destination|--dst) target="$2"; shift 2 ;;
            *) if [ -z "$target" ]; then target="$1"; fi; shift ;;
        esac
    done
    
    [ -z "$target" ] && { json_error "Target address required"; return 1; }
    
    local result
    result=$(ip -j route get "$target" 2>/dev/null)
    
    if [ -n "$result" ] && [ "$result" != "[]" ]; then
        echo "$result" | "$JQ_BIN" '{success: true, route: .[0]}'
    else
        json_error "No route found to $target"
    fi
}

action_route_flush() {
    local target="$1" # e.g., table ID, or cache
    shift
    local table=""
    
    # Parse args to be safe
    if [[ "$target" == "cache" ]]; then
        ip route flush cache
        json_success '{"action": "route_flush", "target": "cache"}'
        return 0
    fi
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --table) table="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    
    if [ -n "$table" ]; then
        if ip route flush table "$table"; then
            json_success '{"action": "route_flush", "table": "'"$table"'"}'
        else
            json_error "Failed to flush table $table"
        fi
    else
        json_error "Specify target to flush (e.g. 'rxnm route flush cache' or 'rxnm route flush --table 100')"
    fi
}
