# ==============================================================================
# RXNM PUBLIC API FOR EXTERNAL HELPERS/PLUGINS
# Source this file in your script to gain RXNM capabilities.
# ==============================================================================

# Ensure we know where we are
if [ -z "${RXNM_LIB_DIR:-}" ]; then
    # REMEDIATION: Path Hardcoding
    # Attempt to derive LIB_DIR relative to this script location if not exported by wrapper
    SOURCE="${BASH_SOURCE[0]}"
    while [ -h "$SOURCE" ]; do
      DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
      SOURCE="$(readlink "$SOURCE")"
      [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
    done
    RXNM_LIB_DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
    
    # Validation
    if [ ! -f "${RXNM_LIB_DIR}/rxnm-constants.sh" ]; then
        # Fallback to standard install path only if relative resolution fails
        RXNM_LIB_DIR="/usr/lib/rocknix-network-manager/lib"
    fi
fi

if [ ! -d "$RXNM_LIB_DIR" ]; then
    echo "Error: RXNM libraries not found at $RXNM_LIB_DIR" >&2
    exit 1
fi

# Load Core Modules
source "${RXNM_LIB_DIR}/rxnm-constants.sh"
source "${RXNM_LIB_DIR}/rxnm-utils.sh"
source "${LIB_DIR}/rxnm-system.sh" # Load system utils (fixes circular dep in action_setup)

# If the caller script didn't set format, inherit or default
: "${RXNM_FORMAT:=human}"

# Helper to standardise initialization in external scripts
rxnm_init() {
    # Parse standard flags if passed
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json) export RXNM_FORMAT="json"; shift ;;
            --debug) export RXNM_DEBUG=1; set -x; shift ;;
            *) args+=("$1"); shift ;;
        esac
    done
    # Return remaining args to caller
    echo "${args[@]}"
}

# Access the API Schema
# Usage: rxnm_get_schema > schema.json
rxnm_get_schema() {
    local schema_path="${RXNM_LIB_DIR}/../api-schema.json"
    if [ -f "$schema_path" ]; then
        cat "$schema_path"
    else
        # Fallback minimal schema if file missing
        echo '{"error": "Schema file not found", "path": "'"$schema_path"'"}'
    fi
}

# Export common variables for ease of use
export RXNM_LIB_DIR
export RXNM_FORMAT
export CONF_DIR
export STATE_DIR
