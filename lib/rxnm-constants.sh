# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-constants.sh
# PURPOSE: Single Source of Truth (SSoT) for RXNM Configuration
# ARCHITECTURE: Foundation / Configuration
# -----------------------------------------------------------------------------

# --- Identity & Defaults ---
: "${RXNM_VERSION:=1.1.0}"
: "${RXNM_API_VERSION:=1.1}"
: "${DEFAULT_HOSTNAME:=ROCKNIX}"

# Feature Flags
: "${RXNM_EXPERIMENTAL:=false}"

# --- Patience Variables (Handheld Optimized) ---
# RK3326 and RK3566 SoCs using SDIO Realtek/Broadcom chips are notoriously slow 
# at firmware state transitions. We wait longer than standard Linux desktops.
: "${WIFI_MODE_SETTLE_SECS:=2}"
: "${CURL_TIMEOUT:=5}"
: "${SCAN_TIMEOUT:=10}"

# Connectivity Probes
: "${RXNM_PROBE_TARGETS_V4:=13.107.4.52:80 8.8.8.8:80}"
: "${RXNM_PROBE_TARGETS_V6:=[2620:1ec:c11::200]:80 [2001:4860:4860::8888]:80}"

# --- Directory Structure ---
: "${CONF_DIR:=/storage/.config}"
: "${STATE_DIR:=/var/lib}"
: "${ETC_NET_DIR:=/etc/systemd/network}"
: "${RUN_DIR:=/run/rocknix}"
: "${EPHEMERAL_NET_DIR:=/run/systemd/network}"

# --- Logging Levels ---
export LOG_LEVEL_ERROR=0
export LOG_LEVEL_WARN=1
export LOG_LEVEL_INFO=2
export LOG_LEVEL_DEBUG=3
: "${LOG_LEVEL:=$LOG_LEVEL_INFO}"

# --- Agent Binary Resolution ---
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

# --- Hardware Capability Detection ---
IS_LOW_POWER=false
_LP_CACHE="${RUN_DIR}/.is_low_power"
if [ -f "$_LP_CACHE" ]; then
    [ "$(cat "$_LP_CACHE")" = "true" ] && IS_LOW_POWER=true
else
    if [ -x "$RXNM_AGENT_BIN" ]; then
        _lp=$("$RXNM_AGENT_BIN" --is-low-power 2>/dev/null || echo "false")
        [ "$_lp" = "true" ] && IS_LOW_POWER=true
    else
        if grep -qEi "RK3326|RK3566|RK3128|H700|sunxi|Meson" /proc/cpuinfo 2>/dev/null; then
            IS_LOW_POWER=true
        fi
    fi
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR" 2>/dev/null
    echo "$IS_LOW_POWER" > "$_LP_CACHE" 2>/dev/null
fi

# --- Firewall Tool Detection ---
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

# --- Performance Tuning Constants ---
if [ "$IS_LOW_POWER" = true ]; then
    SCAN_POLL_MS=200
else
    SCAN_POLL_MS=100
fi

: "${IWD_DBUS_MAX_KB:=512}"

# --- systemd-networkd Version-Aware Config Keys ---
# IPForward= was deprecated in systemd 256, replaced by IPv4Forwarding=/IPv6Forwarding=.
# Detect the running networkd version and emit the correct key for dynamic configs.
# Shipped .network templates use IPForward= (works on all versions, deprecated warning on 256+).
if [ -z "${RXNM_NETWORKD_KEY_IPFORWARD:-}" ]; then
    _sd_ver=""
    if command -v networkctl >/dev/null 2>&1; then
        _sd_ver=$(networkctl --version 2>/dev/null | awk '/^systemd / {print $2; exit}')
    fi
    _sd_ver="${_sd_ver:-255}"
    if [ "$_sd_ver" -ge 256 ] 2>/dev/null; then
        RXNM_NETWORKD_KEY_IPFORWARD="IPv4Forwarding=yes\nIPv6Forwarding=yes"
    else
        RXNM_NETWORKD_KEY_IPFORWARD="IPForward=yes"
    fi
fi
# OtherInformation= is correct for all systemd versions (OtherConfig was never valid)
: "${RXNM_NETWORKD_KEY_RA_OTHER:=OtherInformation}"

# --- FD Reservations ---
RXNM_FD_GLOBAL_LOCK=8
RXNM_FD_IFACE_LOCK=9
export RXNM_FD_GLOBAL_LOCK RXNM_FD_IFACE_LOCK

# --- Storage Paths ---
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
GLOBAL_LOCK_FILE="${RUN_DIR}/network.lock"
GLOBAL_PID_FILE="${RUN_DIR}/network.pid"
NULLIFY_STATE_FILE="${RUN_DIR}/nullify.state"
ROAM_MAP_FILE="${RUN_DIR}/roaming-bssid-map.json"

if command -v jaq >/dev/null; then
    if jaq --help 2>&1 | grep -q "\--argjson"; then export JQ_BIN="jaq"; else export JQ_BIN="jq"; fi
elif command -v gojq >/dev/null; then
    if gojq --help 2>&1 | grep -q "\--argjson"; then export JQ_BIN="gojq"; else export JQ_BIN="jq"; fi
else export JQ_BIN="jq"; fi

RXNM_SHELL_IS_BASH=false
[ -n "${BASH_VERSION:-}" ] && RXNM_SHELL_IS_BASH=true
export RXNM_SHELL_IS_BASH

RXNM_HAS_JQ=false
command -v "${JQ_BIN:-jq}" >/dev/null 2>&1 && RXNM_HAS_JQ=true
export RXNM_HAS_JQ
