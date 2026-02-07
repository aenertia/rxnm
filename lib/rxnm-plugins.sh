# ==============================================================================
# RXNM PLUGIN & HELPER DISCOVERY
# ==============================================================================

PLUGIN_SEARCH_PATHS=(
    "${CONF_DIR}/network/plugins"
    "/usr/lib/rocknix-network-manager/plugins"
)

# Find a plugin executable by name (category)
# Search order:
# 1. User config dir (.config/network/plugins)
# 2. System dir (/usr/lib/...)
#
# supports file structure:
# - plugins/tailscale       (executable script)
# - plugins/tailscale/run   (executable inside dir)
find_plugin() {
    local name="$1"
    [ -z "$name" ] && return 1
    
    for path in "${PLUGIN_SEARCH_PATHS[@]}"; do
        [ ! -d "$path" ] && continue
        
        # Check for direct script
        if [ -f "$path/$name" ] && [ -x "$path/$name" ]; then
            echo "$path/$name"
            return 0
        fi
        
        # Check for directory bundle
        if [ -d "$path/$name" ] && [ -f "$path/$name/run" ] && [ -x "$path/$name/run" ]; then
            echo "$path/$name/run"
            return 0
        fi
    done
    return 1
}

# List all available plugins for help text
list_plugins() {
    local plugins=()
    for path in "${PLUGIN_SEARCH_PATHS[@]}"; do
        [ ! -d "$path" ] && continue
        
        # Safe iteration
        local found_files=("$path"/*)
        for f in "${found_files[@]}"; do
            [ ! -e "$f" ] && continue
            local name=$(basename "$f")
            
            if [ -f "$f" ] && [ -x "$f" ]; then
                plugins+=("$name")
            elif [ -d "$f" ] && [ -x "$f/run" ]; then
                plugins+=("$name")
            fi
        done
    done
    
    # Return unique sorted list
    if [ ${#plugins[@]} -gt 0 ]; then
        printf "%s\n" "${plugins[@]}" | sort -u
    fi
}

# Execute plugin with context
exec_plugin() {
    local plugin_path="$1"
    shift
    
    # Export the runtime environment so plugins can source libraries easily
    export RXNM_LIB_DIR="${LIB_DIR}"
    export RXNM_VERSION="1.0" # Should match package version
    
    # Pass down global flags that might have been set
    export RXNM_FORMAT="${RXNM_FORMAT:-human}"
    export RXNM_DEBUG="${RXNM_DEBUG:-}"
    
    exec "$plugin_path" "$@"
}
