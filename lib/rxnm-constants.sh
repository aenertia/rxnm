# ==============================================================================
# CONFIGURATION, PATHS & CONSTANTS
# ==============================================================================

# System Identity
: "${RXNM_VERSION:=1.0.0}"
: "${DEFAULT_HOSTNAME:=ROCKNIX}"

# Connectivity Probes (TCP L4)
: "${RXNM_PROBE_TARGETS_V4:=1.1.1.1:80 8.8.8.8:443}"
: "${RXNM_PROBE_TARGETS_V6:=[2606:4700:4700::1111]:80 [2001:4860:4860::8888]:443}"

# Default Paths
: "${CONF_DIR:=/storage/.config}"
: "${STATE_DIR:=/var/lib}"
: "${ETC_NET_DIR:=/etc/systemd/network}"
: "${RUN_DIR:=/run/rocknix}"

# Ephemeral Configuration
: "${EPHEMERAL_NET_DIR:=/run/systemd/network}"

# Logging Levels
export LOG_LEVEL_ERROR=0
export LOG_LEVEL_WARN=1
export LOG_LEVEL_INFO=2
export LOG_LEVEL_DEBUG=3
: "${LOG_LEVEL:=$LOG_LEVEL_INFO}"

# Agent Path Discovery
if [ -z "${RXNM_AGENT_BIN:-}" ]; then
    if [ -n "${RXNM_LIB_DIR:-}" ]; then
        RXNM_AGENT_BIN="${RXNM_LIB_DIR}/../bin/rxnm-agent"
    else
        if [ -f "/usr/lib/rocknix-network-manager/bin/rxnm-agent" ]; then
            RXNM_AGENT_BIN="/usr/lib/rocknix-network-manager/bin/rxnm-agent"
        else
            RXNM_AGENT_BIN="rxnm-agent"
        fi
    fi
fi

# Optimization 3.5: Cache IS_LOW_POWER result to avoid fork-per-source
IS_LOW_POWER=false
_LP_CACHE="${RUN_DIR}/.is_low_power"

if [ -f "$_LP_CACHE" ]; then
    [ "$(cat "$_LP_CACHE")" == "true" ] && IS_LOW_POWER=true
else
    # HYBRID DISPATCH: Hardware Detection
    if [ -x "$RXNM_AGENT_BIN" ]; then
        _lp=$("$RXNM_AGENT_BIN" --is-low-power 2>/dev/null || echo "false")
        [ "$_lp" == "true" ] && IS_LOW_POWER=true
    else
        # Coldpath: Legacy Grep
        if grep -qEi "RK3326|RK3566|RK3128|RK3036|RK3288|H700|H616|H3|H5|H6|A64|A133|A33|sunxi|BCM2835|BCM2836|BCM2837|ATM7051|S905|S805|Meson|X1830|JZ4770|riscv|sun20iw1p1|JH7110|JH7100|Atom|Celeron|Pentium|Geode|MIPS32|MIPS64|avr|xtensa|tensilica|loongson|loongarch" /proc/cpuinfo 2>/dev/null; then
            IS_LOW_POWER=true
        fi
    fi
    # Store in cache if RUN_DIR is writable
    [ -d "$RUN_DIR" ] && echo "$IS_LOW_POWER" > "$_LP_CACHE" 2>/dev/null || true
fi

# Optimization: Cache Firewall Tool Detection
FW_TOOL=""
if [ -n "${FORCE_FW_TOOL:-}" ]; then
    FW_TOOL="$FORCE_FW_TOOL"
elif command -v iptables >/dev/null; then
    FW_TOOL="iptables"
elif command -v nft >/dev/null; then
    FW_TOOL="nft"
else
    FW_TOOL="none"
fi

# Adaptive Timeouts
if [ "$IS_LOW_POWER" = true ]; then
    : "${CURL_TIMEOUT:=5}"
    : "${SCAN_TIMEOUT:=10}"
    SCAN_POLL_MS=200
else
    : "${CURL_TIMEOUT:=2}"
    : "${SCAN_TIMEOUT:=4}"
    SCAN_POLL_MS=100
fi

# WiFi & Network Constants
: "${MIN_CHANNEL:=1}"
: "${WIFI_CHANNEL_MAX:=177}"
: "${MIN_VLAN_ID:=1}"
: "${MAX_VLAN_ID:=4094}"
: "${DEFAULT_GW_V4:=192.168.212.1/24}"

# Derived Paths
PERSISTENT_NET_DIR="${CONF_DIR}/network"
STORAGE_NET_DIR="${EPHEMERAL_NET_DIR}"
STORAGE_PROFILES_DIR="${PERSISTENT_NET_DIR}/profiles"
STORAGE_WIFI_DIR="${PERSISTENT_NET_DIR}/wifi"
STORAGE_RESOLVED_DIR="${CONF_DIR}/resolved.conf.d"
STORAGE_RESOLVED_FILE="${STORAGE_RESOLVED_DIR}/global-dns.conf"
STORAGE_COUNTRY_FILE="${STORAGE_WIFI_DIR}/country"
STORAGE_PROXY_GLOBAL="${CONF_DIR}/proxy.conf"
STORAGE_HOST_NET_FILE="${PERSISTENT_NET_DIR}/70-wifi-host.network"
STORAGE_PAN_NET_FILE="${PERSISTENT_NET_DIR}/70-bluetooth-pan.network"
STORAGE_BT_PIN_FILE="${PERSISTENT_NET_DIR}/bluetooth.pin"

# Locking
GLOBAL_LOCK_FILE="${RUN_DIR}/network.lock"
GLOBAL_PID_FILE="${RUN_DIR}/network.pid"

# --- JSON PROCESSOR DETECTION ---
if command -v jaq >/dev/null; then
    if jaq --help 2>&1 | grep -q "\--argjson"; then export JQ_BIN="jaq"; else export JQ_BIN="jq"; fi
elif command -v gojq >/dev/null; then export JQ_BIN="gojq";
else export JQ_BIN="jq"; fi

# --- GLOBAL SERVICE STATE CACHE ---
declare -A SERVICE_STATE_CACHE
declare -A SERVICE_STATE_TS
