# ==============================================================================
# CONFIGURATION, PATHS & CONSTANTS
# ==============================================================================

# Default Paths (Override via Environment Variables)
: "${CONF_DIR:=/storage/.config}"
: "${STATE_DIR:=/var/lib}"
: "${ETC_NET_DIR:=/etc/systemd/network}"
: "${RUN_DIR:=/run/rocknix}"

# Optimization: Cache CPU capability check
IS_LOW_POWER=false
if grep -qi "RK3326\|RK3566" /proc/cpuinfo 2>/dev/null; then
    IS_LOW_POWER=true
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
STORAGE_NET_DIR="${CONF_DIR}/network"
STORAGE_PROFILES_DIR="${STORAGE_NET_DIR}/profiles"
STORAGE_WIFI_DIR="${STORAGE_NET_DIR}/wifi"
STORAGE_RESOLVED_DIR="${CONF_DIR}/resolved.conf.d"
STORAGE_RESOLVED_FILE="${STORAGE_RESOLVED_DIR}/global-dns.conf"
STORAGE_COUNTRY_FILE="${STORAGE_WIFI_DIR}/country"
STORAGE_PROXY_GLOBAL="${CONF_DIR}/proxy.conf"
STORAGE_HOST_NET_FILE="${STORAGE_NET_DIR}/70-wifi-host.network"
STORAGE_PAN_NET_FILE="${STORAGE_NET_DIR}/70-bluetooth-pan.network"
STORAGE_BT_PIN_FILE="${STORAGE_NET_DIR}/bluetooth.pin"

# --- GLOBAL SERVICE STATE CACHE ---
# Initialized in system.sh
IWD_ACTIVE=false
NETWORKD_ACTIVE=false
AVAHI_ACTIVE=false
