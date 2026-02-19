# ==============================================================================
# RXNM PUBLIC API FOR EXTERNAL HELPERS/PLUGINS
# Source this file in your script to gain RXNM capabilities.
# ==============================================================================

# Ensure we know where we are
if [ -z "${RXNM_LIB_DIR:-}" ]; then
    # Derivation
    _rxnm_api_src="$0"
    if [ -L "$_rxnm_api_src" ]; then
        # Simple readlink if available, otherwise assume current dir structure
        if command -v readlink >/dev/null; then
            _rxnm_api_src="$(readlink -f "$_rxnm_api_src")"
        fi
    fi
    RXNM_LIB_DIR="$(cd -P "$(dirname "$_rxnm_api_src")" >/dev/null 2>&1 && pwd)"
    
    if [ ! -f "${RXNM_LIB_DIR}/rxnm-constants.sh" ]; then
        RXNM_LIB_DIR="/usr/lib/rocknix-network-manager/lib"
    fi
fi

if [ ! -d "$RXNM_LIB_DIR" ]; then
    echo "Error: RXNM libraries not found at $RXNM_LIB_DIR" >&2
    exit 1
fi

# Load Core Modules
. "${RXNM_LIB_DIR}/rxnm-constants.sh"
. "${RXNM_LIB_DIR}/rxnm-utils.sh"
# Fix Issue 3.3: Use RXNM_LIB_DIR consistently
. "${RXNM_LIB_DIR}/rxnm-system.sh"

# If the caller script didn't set format, inherit or default
: "${RXNM_FORMAT:=human}"

# Helper to standardise initialization in external scripts
rxnm_init() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --json)  export RXNM_FORMAT="json" ;;
            --debug) export RXNM_DEBUG=1; set -x ;;
            *)       printf '%s\n' "$1" ;;
        esac
        shift
    done
}

rxnm_get_schema() {
    local schema_path="${RXNM_LIB_DIR}/../api-schema.json"
    if [ -f "$schema_path" ]; then
        cat "$schema_path"
    else
        echo '{"error": "Schema file not found", "path": "'"$schema_path"'"}'
    fi
}

export RXNM_LIB_DIR
export RXNM_FORMAT
export CONF_DIR
export STATE_DIR
```cat
