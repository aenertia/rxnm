# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-constants.sh
# PURPOSE: Single Source of Truth (SSoT) for RXNM Configuration
# ARCHITECTURE: Foundation / Configuration
#
# This file defines the static configuration, directory paths, and hardware
# capabilities detection logic. It is sourced by every other component.
#
# CRITICAL: This file is parsed by scripts/sync-constants.sh to generate
# the C header (src/rxnm_generated.h) for the Agent. Variable definitions
# must adhere to standard KEY=VAL syntax to ensure the parser works correctly.
# -----------------------------------------------------------------------------

# --- Identity & Defaults ---
: "${RXNM_VERSION:=1.1.0}"
: "${RXNM_API_VERSION:=1.1}"
: "${DEFAULT_HOSTNAME:=ROCKNIX}"

# Feature Flags
# Set to 'true' to enable SOA/Experimental features (Service, Tunnel, MPLS)
: "${RXNM_EXPERIMENTAL:=false}"

# Connectivity Probes (Used for Internet Checks)
# Target 1: Microsoft NCSI (Anycast, highly available, not a DNS resolver)
# Target 2: Google Public DNS on Port 80 (Avoids Port 443 DoH blocking/DPI)
# Format: "IP:PORT IP:PORT"
: "${RXNM_PROBE_TARGETS_V4:=13.107.4.52:80 8.8.8.8:80}"
: "${RXNM_PROBE_TARGETS_V6:=[2620:1ec:c11::200]:80 [2001:4860:4860::8888]:80}"

# --- Directory Structure ---
# These paths define the layout of the ephemeral and persistent state.
: "${CONF_DIR:=/storage/.config}"
: "${STATE_DIR:=/var/lib}"
: "${ETC_NET_DIR:=/etc/systemd/network}"
: "${RUN_DIR:=/run/rocknix}"

# The ephemeral directory is where systemd-networkd reads runtime configs.
# In RXNM, we write here by default to avoid flash wear.
: "${EPHEMERAL_NET_DIR:=/run/systemd/network}"

# --- Logging Levels ---
export LOG_LEVEL_ERROR=0
export LOG_LEVEL_WARN=1
export LOG_LEVEL_INFO=2
export LOG_LEVEL_DEBUG=3
: "${LOG_LEVEL:=$LOG_LEVEL_INFO}"

# --- Agent Binary Resolution ---
# Locates the hardware accelerator binary.
if [ -z "${RXNM_AGENT_BIN:-}" ]; then
    if [ -n "${RXNM_LIB_DIR:-}" ]; then
        # Development mode: relative to lib dir
        RXNM_AGENT_BIN="${RXNM_LIB_DIR}/../bin/rxnm-agent"
    else
        # Production mode: system install path
        if [ -f "/usr/lib/rocknix-network-manager/bin/rxnm-agent" ]; then
            RXNM_AGENT_BIN="/usr/lib/rocknix-network-manager/bin/rxnm-agent"
        else
            RXNM_AGENT_BIN="rxnm-agent"
        fi
    fi
fi

# --- Hardware Capability Detection ---
# Detects Low Power SoCs (RK3326, Allwinner, etc.) to adjust timeouts.
IS_LOW_POWER=false
_LP_CACHE="${RUN_DIR}/.is_low_power"

if [ -f "$_LP_CACHE" ]; then
    # Fast path: Read from runtime cache
    if [ "$(cat "$_LP_CACHE")" = "true" ]; then IS_LOW_POWER=true; fi
else
    # Slow path: Detection logic
    if [ -x "$RXNM_AGENT_BIN" ]; then
        # Prefer Agent detection if available
        _lp=$("$RXNM_AGENT_BIN" --is-low-power 2>/dev/null || echo "false")
        if [ "$_lp" = "true" ]; then IS_LOW_POWER=true; fi
    else
        # Fallback: Grep cpuinfo for known low-power chipsets
        # This list includes Rockchip, Allwinner, Broadcom, Amlogic, and MIPS variants common in handhelds.
        if grep -qEi "RK3326|RK3566|RK3128|RK3036|RK3288|H700|H616|H3|H5|H6|A64|A133|A33|sunxi|BCM2835|BCM2836|BCM2837|ATM7051|S905|S805|Meson|X1830|JZ4770|riscv|sun20iw1p1|JH7110|JH7100|Atom|Celeron|Pentium|Geode|MIPS32|MIPS64|avr|xtensa|tensilica|loongson|loongarch" /proc/cpuinfo 2>/dev/null; then
            IS_LOW_POWER=true
        fi
    fi
    # Cache the result to avoid repeated greps
    if [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR" 2>/dev/null; then
         echo "$IS_LOW_POWER" > "$_LP_CACHE" 2>/dev/null || log_debug "Failed to write low-power cache to $_LP_CACHE"
    fi
fi

# --- Firewall Tool Detection ---
# Determines which backend to use for NAT/Masquerading.
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
# Adjust timeouts based on hardware class.
if [ "$IS_LOW_POWER" = true ]; then
    : "${CURL_TIMEOUT:=5}"
    : "${SCAN_TIMEOUT:=10}"
    SCAN_POLL_MS=200
else
    : "${CURL_TIMEOUT:=2}"
    : "${SCAN_TIMEOUT:=4}"
    SCAN_POLL_MS=100
fi

# Maximum bytes accepted from IWD GetManagedObjects DBus response.
# 512KB covers ~1000 BSSIDs with full metadata. Tune up for dense
# enterprise environments; tune down for very memory-constrained targets.
: "${IWD_DBUS_MAX_KB:=512}"

# --- FD Reservations ---
# POSIX only guarantees exec N>file works for single-digit N (0-9).
# These constants document the reservation; do not use FD 8 or 9 elsewhere.
RXNM_FD_GLOBAL_LOCK=8    # acquire_global_lock — singleton process lock
RXNM_FD_IFACE_LOCK=9     # with_iface_lock — per-interface serialisation (Legacy/Fallback, dynamically allocated now)
export RXNM_FD_GLOBAL_LOCK RXNM_FD_IFACE_LOCK

# --- Logic Constants ---
: "${MIN_CHANNEL:=1}"
: "${WIFI_CHANNEL_MAX:=177}"
: "${MIN_VLAN_ID:=1}"
: "${MAX_VLAN_ID:=4094}"
: "${DEFAULT_GW_V4:=192.168.212.1/24}" # Default subnet for AP/Share modes

# --- Storage Paths (Detailed) ---
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
GLOBAL_LOCK_FILE="${RUN_DIR}/network.lock"
GLOBAL_PID_FILE="${RUN_DIR}/network.pid"
# v1.1.0: State caching for robust nullify restoration
NULLIFY_STATE_FILE="${RUN_DIR}/nullify.state"
# C-3 FIX: Define roaming map file globally to prevent set -eu crash in roaming module
ROAM_MAP_FILE="${RUN_DIR}/roaming-bssid-map.json"

# --- JSON Processor Detection ---
# Detects the fastest available JSON processor (jaq > gojq > jq).
if command -v jaq >/dev/null; then
    # Ensure jaq supports --argjson (some older versions do not)
    if jaq --help 2>&1 | grep -q "\--argjson"; then export JQ_BIN="jaq"; else export JQ_BIN="jq"; fi
elif command -v gojq >/dev/null; then
    if gojq --help 2>&1 | grep -q "\--argjson"; then export JQ_BIN="gojq"; else export JQ_BIN="jq"; fi
else export JQ_BIN="jq"; fi

# --- Shell Capability Flags ---
# Detected once at startup; used by guard wrappers in rxnm-utils.sh.
# These are exported so sourced libraries see them without re-detection.
RXNM_SHELL_IS_BASH=false
[ -n "${BASH_VERSION:-}" ] && RXNM_SHELL_IS_BASH=true
export RXNM_SHELL_IS_BASH

RXNM_HAS_JQ=false
command -v "${JQ_BIN:-jq}" >/dev/null 2>&1 && RXNM_HAS_JQ=true
export RXNM_HAS_JQ

# --- State Caches ---
# NOTE: Bash associative arrays (declare -A) are guarded to avoid syntax errors in sh.
# rxnm-system.sh handles the constrained path via flat variables.
if [ "${RXNM_SHELL_IS_BASH}" = "true" ]; then
    declare -A SERVICE_STATE_CACHE
    declare -A SERVICE_STATE_TS
fi
