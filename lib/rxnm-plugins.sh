# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-plugins.sh
# PURPOSE: Plugin Discovery & Execution
# ARCHITECTURE: Logic / Plugins
#
# Allows extending RXNM without modifying core code.
# Refactored for POSIX compatibility (no Bash arrays).
# -----------------------------------------------------------------------------

# Space-separated string for POSIX compatibility
PLUGIN_SEARCH_PATHS="${CONF_DIR}/network/plugins /usr/lib/rocknix-network-manager/plugins"

# Description: Finds a plugin executable by name.
# Arguments: $1 = Plugin Name
find_plugin() {
    local name="$1"
    [ -z "$name" ] && return 1
    
    # Iterate over space-separated string
    for path in $PLUGIN_SEARCH_PATHS; do
        [ ! -d "$path" ] && continue
        
        # Check for binary file
        if [ -f "$path/$name" ] && [ -x "$path/$name" ]; then
            echo "$path/$name"
            return 0
        fi
        
        # Check for directory with run script (AppDir style)
        if [ -d "$path/$name" ] && [ -f "$path/$name/run" ] && [ -x "$path/$name/run" ]; then
            echo "$path/$name/run"
            return 0
        fi
    done
    return 1
}

list_plugins() {
    local _p_list=""
    
    for path in $PLUGIN_SEARCH_PATHS; do
        [ ! -d "$path" ] && continue
        
        # POSIX compliant glob iteration
        for f in "$path"/*; do
            [ ! -e "$f" ] && continue
            
            local p_name="${f##*/}"
            if [ -f "$f" ] && [ -x "$f" ]; then
                _p_list="${_p_list}${p_name} "
            elif [ -d "$f" ] && [ -x "$f/run" ]; then
                _p_list="${_p_list}${p_name} "
            fi
        done
    done
    
    if [ -n "$_p_list" ]; then
        # Use word-splitting to feed list to sort (POSIX safe)
        # shellcheck disable=SC2086
        printf '%s\n' $_p_list | sort -u
    fi
}

exec_plugin() {
    local plugin_path="$1"
    shift
    
    # Export Context for Plugin
    export RXNM_LIB_DIR="${LIB_DIR}"
    export RXNM_VERSION="${RXNM_VERSION}"
    export RXNM_FORMAT="${RXNM_FORMAT:-human}"
    export RXNM_DEBUG="${RXNM_DEBUG:-}"
    
    local timeout_sec=10
    
    if timeout "$timeout_sec" "$plugin_path" "$@"; then
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
             if [ "${RXNM_FORMAT:-human}" = "json" ]; then
                echo "{\"success\": false, \"error\": \"Plugin execution timed out\", \"plugin\": \"$plugin_path\"}"
            else
                echo "Error: Plugin timed out." >&2
            fi
        else
             if [ "${RXNM_FORMAT:-human}" = "json" ]; then
                echo "{\"success\": false, \"error\": \"Plugin exited with error code $exit_code\", \"plugin\": \"$plugin_path\"}"
            else
                echo "Error: Plugin failed (exit code $exit_code)." >&2
            fi
        fi
        return $exit_code
    fi
}
