# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# shellcheck disable=SC3043 # Target shells (Ash/Dash) support 'local'

# -----------------------------------------------------------------------------
# FILE: rxnm-system.sh
# PURPOSE: System-Level Operations & Service Management
# ARCHITECTURE: Logic / System
#
# Handles initialization, service state caching (to reduce systemctl calls),
# firewall/NAT abstraction, and kernel network stack tuning.
# -----------------------------------------------------------------------------

# --- Service State Caching ---
# Optimization: Calling 'systemctl is-active' is slow (fork + IPC).
# We cache the state for 2 seconds to speed up bulk operations.
# POSIX Compatible: Uses flat variables to mimic associative array behavior.

_SVC_CACHE_IWD=""
_SVC_CACHE_NETWORKD=""
_SVC_CACHE_RESOLVED=""
_SVC_CACHE_AVAHI=""
_SVC_TS_IWD=0
_SVC_TS_NETWORKD=0
_SVC_TS_RESOLVED=0
_SVC_TS_AVAHI=0

# --- Service State Cache ---
# This cache (flat variables, POSIX-safe) provides a 2-second TTL for
# systemctl is-active queries. It is the BASH PATH mechanism for reducing
# fork overhead when multiple actions within a single invocation check
# service state (e.g. action_setup calls cache_service_states once, then
# is_service_active is called several times for iwd, networkd, resolved).
#
# RELATIONSHIP TO AGENT:
# On PATH B (compat/agent-mandatory), 'rxnm-agent --dump' provides service
# state in one Netlink+DBus pass — the agent is called first by action_status
# and the cache is not exercised. The cache remains essential for PATH A
# operations that don't go through action_status (e.g. action_setup,
# tune_network_stack, action_reload).
#
# DO NOT REMOVE this cache. The agent-available path optimisation in
# action_status/action_reload does not cover all callers of is_service_active.
cache_service_states() {
    local now
    now=$(printf '%(%s)T' -1 2>/dev/null || date +%s)
    
    # Bulk query to minimize fork overhead
    local states
    states=$(timeout 2s systemctl is-active iwd systemd-networkd systemd-resolved avahi-daemon 2>/dev/null || echo "inactive
inactive
inactive
inactive")
    
    # Read into flat vars (POSIX safe)
    # The order matches the systemctl call args above
    _SVC_CACHE_IWD=$(echo "$states" | sed -n '1p')
    _SVC_CACHE_NETWORKD=$(echo "$states" | sed -n '2p')
    _SVC_CACHE_RESOLVED=$(echo "$states" | sed -n '3p')
    _SVC_CACHE_AVAHI=$(echo "$states" | sed -n '4p')
    
    _SVC_TS_IWD=$now
    _SVC_TS_NETWORKD=$now
    _SVC_TS_RESOLVED=$now
    _SVC_TS_AVAHI=$now
}

# Description: Checks if a service is active, using cache if fresh (<2s).
# Arguments: $1 = Service Name
is_service_active() {
    local svc="$1"
    local now
    now=$(printf '%(%s)T' -1 2>/dev/null || date +%s)
    local last_check=0
    local cached_state=""
    
    # Map service to cache var
    case "$svc" in
        iwd) last_check=$_SVC_TS_IWD; cached_state=$_SVC_CACHE_IWD ;;
        systemd-networkd) last_check=$_SVC_TS_NETWORKD; cached_state=$_SVC_CACHE_NETWORKD ;;
        systemd-resolved) last_check=$_SVC_TS_RESOLVED; cached_state=$_SVC_CACHE_RESOLVED ;;
        avahi-daemon) last_check=$_SVC_TS_AVAHI; cached_state=$_SVC_CACHE_AVAHI ;;
        *) 
            # Non-cached service: check directly
            systemctl is-active --quiet "$svc"
            return $?
            ;;
    esac
    
    local age=$((now - last_check))
    
    if [ "$age" -gt 2 ]; then
        cached_state=$(timeout 1s systemctl is-active "$svc" 2>/dev/null || echo "inactive")
        # Update cache
        case "$svc" in
            iwd) _SVC_CACHE_IWD="$cached_state"; _SVC_TS_IWD=$now ;;
            systemd-networkd) _SVC_CACHE_NETWORKD="$cached_state"; _SVC_TS_NETWORKD=$now ;;
            systemd-resolved) _SVC_CACHE_RESOLVED="$cached_state"; _SVC_TS_RESOLVED=$now ;;
            avahi-daemon) _SVC_CACHE_AVAHI="$cached_state"; _SVC_TS_AVAHI=$now ;;
        esac
    fi
    
    [ "$cached_state" = "active" ]
}

is_avahi_running() {
    is_service_active "avahi-daemon"
}

# --- Rescue Mode Utilities ---
# Used when systemd-networkd fails or is missing.

configure_standalone_client() {
    local iface="$1"
    log_warn "Entering Rescue Mode: Configuring $iface as standalone client"
    ip link set "$iface" up
    # Kill any existing udhcpc for this interface to avoid conflict
    pkill -f "udhcpc -i $iface" 2>/dev/null
    udhcpc -i "$iface" -b -s /usr/share/udhcpc/default.script
}

configure_standalone_gadget() {
    local iface="$1"
    local ip="169.254.10.2"
    log_warn "Entering Rescue Mode: Configuring $iface as standalone gadget"
    ip link set "$iface" up
    ip addr add "${ip}/24" dev "$iface" 2>/dev/null
    
    # Generate temporary busybox dhcpd config
    local conf="/tmp/udhcpd.${iface}.conf"
    # Use printf for safety instead of heredoc in potentially quirky shells
    printf 'start 169.254.10.10\nend 169.254.10.20\ninterface %s\noption subnet 255.255.255.0\noption router %s\noption dns %s\n' "$iface" "$ip" "$ip" > "$conf"

    pkill -f "udhcpd $conf" 2>/dev/null
    udhcpd "$conf"
}

# --- Lifecycle Actions ---

# NOTE: init_template_cache() was a no-op removed in v1.1.0-rc1.
# If template conflict pre-scanning is implemented in a future version,
# add a build_template_conflict_map warmup call here with a TTL cache.
action_setup() {
    log_info "Initializing Network Manager..."
    ensure_dirs
    check_paths
    cache_service_states
    
    # Ensure systemd-networkd has access to runtime configs
    [ -d /run/systemd/netif ] && chown -R systemd-network:systemd-network /run/systemd/netif 2>/dev/null
    
    # Boot Profile Logic
    # 1. Load profiles if available
    # 2. Sync persistent config to runtime
    if command -v action_profile >/dev/null; then
        action_profile "boot"
    else
        # If sourcing order failed, try to source profiles manually
        if [ -n "${RXNM_LIB_DIR:-}" ] && [ -f "${RXNM_LIB_DIR}/rxnm-profiles.sh" ]; then
             . "${RXNM_LIB_DIR}/rxnm-profiles.sh"
             action_profile "boot"
        fi
    fi
    
    # Apply Hosts file overrides
    if [ -f "${CONF_DIR}/hosts.conf" ]; then
        cp "${CONF_DIR}/hosts.conf" "${RUN_DIR}/hosts"
    else
        rm -f "${RUN_DIR}/hosts"
    fi
    
    fix_permissions
    tune_network_stack "client"
    
    # RFKill Unblock Logic
    local needs_unblock=0
    for rdir in /sys/class/rfkill/rfkill*; do
        if [ -e "$rdir/soft" ]; then 
            read -r s < "$rdir/soft"
            if [ "$s" -eq 1 ]; then needs_unblock=1; break; fi
        fi
    done
    if [ "$needs_unblock" -eq 1 ] && command -v rfkill >/dev/null; then
         rfkill unblock all 2>/dev/null || true
    fi
    
    log_info "Setup complete."
}

action_reload() {
    ensure_dirs
    fix_permissions
    cache_service_states
    reload_networkd
}

action_stop() {
    # Stop wireless daemon to save power/interfere less
    timeout 5s systemctl stop iwd 2>/dev/null || true
    log_info "Wireless services stopped."
}

# --- File Management Helpers ---

ensure_dirs() {
    [ -d "$EPHEMERAL_NET_DIR" ] || mkdir -p "$EPHEMERAL_NET_DIR"
    [ -d "$PERSISTENT_NET_DIR" ] || mkdir -p "$PERSISTENT_NET_DIR"
    [ -d "${STATE_DIR}/iwd" ] || mkdir -p "${STATE_DIR}/iwd"
    [ -d "${STORAGE_PROFILES_DIR}" ] || mkdir -p "${STORAGE_PROFILES_DIR}"
    [ -d "${STORAGE_RESOLVED_DIR}" ] || mkdir -p "${STORAGE_RESOLVED_DIR}"
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
}

check_paths() {
    # Warn if /etc/systemd/network is not a symlink to our run/ target (Common misconfig)
    if [ ! -L "$ETC_NET_DIR" ] && [ "$ETC_NET_DIR" != "$EPHEMERAL_NET_DIR" ]; then
        log_warn "$ETC_NET_DIR is not pointing to $EPHEMERAL_NET_DIR. Configuration may be ignored."
    fi
}

fix_permissions() {
    # Networkd is picky about permissions
    if [ -d "$EPHEMERAL_NET_DIR" ]; then
        find "$EPHEMERAL_NET_DIR" -type f \( -name '*.netdev' -o -name '*.network' -o -name '*.link' \) -exec chmod 644 {} + 2>/dev/null
    fi
    # IWD secrets must be 600
    if [ -d "${STATE_DIR}/iwd" ]; then
        find "${STATE_DIR}/iwd" -type f \( -name '*.psk' -o -name '*.8021x' \) -exec chmod 600 {} + 2>/dev/null
    fi
}

# Description: Triggers a reload of systemd-networkd.
# Note: Prioritizes Agent (DBus direct) over networkctl (CLI) for speed.
reload_networkd() {
    fix_permissions
    
    # Accelerator Path
    if [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --reload >/dev/null 2>&1; then
            # Clear status cache on reload
            [ -n "$RUN_DIR" ] && rm -f "$RUN_DIR/status.json" 2>/dev/null
            return 0
        fi
        log_warn "Agent DBus reload failed, falling back to system tools."
    fi
    
    # Legacy Path
    if is_service_active "systemd-networkd"; then
        timeout 5s networkctl reload 2>/dev/null || log_warn "networkctl reload timed out"
    fi
    [ -n "$RUN_DIR" ] && rm -f "$RUN_DIR/status.json" 2>/dev/null
}

reconfigure_iface() {
    local iface="$1"
    fix_permissions
    if is_service_active "systemd-networkd"; then
        if [ -n "$iface" ]; then
            timeout 5s networkctl reconfigure "$iface" 2>/dev/null || networkctl reload
        else
            timeout 5s networkctl reload
        fi
    fi
    [ -n "$RUN_DIR" ] && rm -f "$RUN_DIR/status.json" 2>/dev/null
}

# --- Kernel Tuning ---

tune_network_stack() {
    local profile="$1" # 'host' or 'client'
    
    # Accelerator Path
    if [ -x "${RXNM_AGENT_BIN}" ]; then
        if "${RXNM_AGENT_BIN}" --tune "$profile" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    # Legacy Path: Manual sysctl
    sysctl -w net.netfilter.nf_conntrack_max=16384 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_keepalive_time=300 >/dev/null 2>&1 || true
    
    if [ -d /proc/sys/net/bridge ]; then
        sysctl -w net.bridge.bridge-nf-call-iptables=0 \
                  net.bridge.bridge-nf-call-ip6tables=0 \
                  net.bridge.bridge-nf-call-arptables=0 >/dev/null 2>&1 || true
    fi
    
    if [ "$profile" = "host" ]; then
        # Enable forwarding for AP/Tethering
        sysctl -w net.ipv4.ip_forward=1 \
                  net.ipv4.conf.all.rp_filter=1 \
                  net.ipv6.conf.all.forwarding=1 \
                  net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1 || true
    else
        sysctl -w net.ipv4.ip_forward=1 \
                  net.ipv4.conf.all.rp_filter=1 \
                  net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    fi
}

# --- Firewall Abstraction (NAT) ---

detect_firewall_tool() {
    echo "$FW_TOOL"
}

enable_nat_masquerade() {
    local lan_iface="$1"
    [ -z "$lan_iface" ] && return 1
    
    local fw_tool
    fw_tool=$(detect_firewall_tool)
    
    if [ "$fw_tool" = "none" ]; then
        log_warn "NAT requested but no firewall tool found."
        return 0
    fi
    
    # Auto-detect WAN interface (Default Route)
    local wan_iface
    wan_iface=$(ip -4 route show default 2>/dev/null | awk '$1=="default" {print $5; exit}')
    [ -z "$wan_iface" ] && wan_iface=$(ip -6 route show default 2>/dev/null | awk '$1=="default" {print $5; exit}')
    
    if [ -z "$wan_iface" ] || [ "$lan_iface" = "$wan_iface" ]; then return 0; fi
    
    log_info "Enabling NAT: LAN($lan_iface) -> WAN($wan_iface) using $fw_tool"
    local T="timeout 2s"
    
    if [ "$fw_tool" = "iptables" ]; then
        # 1. Masquerade Outbound
        $T iptables -t nat -C POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE 2>/dev/null || \
        $T iptables -t nat -A POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE
        
        # 2. Forwarding LAN -> WAN
        $T iptables -C FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        $T iptables -A FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT
        
        # 3. Forwarding WAN -> LAN (Established)
        $T iptables -C FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        $T iptables -A FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT
        
        # 4. MSS Clamping
        $T iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        $T iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu
        
    elif [ "$fw_tool" = "nft" ]; then
        # NFTables boilerplate
        $T nft add table ip rocknix_nat 2>/dev/null
        $T nft add chain ip rocknix_nat postrouting "{ type nat hook postrouting priority 100 ; }" 2>/dev/null
        $T nft flush chain ip rocknix_nat postrouting
        $T nft add rule ip rocknix_nat postrouting oifname "$wan_iface" masquerade
        
        $T nft add table ip rocknix_filter 2>/dev/null
        $T nft add chain ip rocknix_filter forward "{ type filter hook forward priority 0 ; }" 2>/dev/null
        $T nft flush chain ip rocknix_filter forward
        $T nft add rule ip rocknix_filter forward iifname "$lan_iface" oifname "$wan_iface" accept
        $T nft add rule ip rocknix_filter forward iifname "$wan_iface" oifname "$lan_iface" ct state established,related accept
    fi
}

disable_nat_masquerade() {
    local fw_tool; fw_tool=$(detect_firewall_tool)
    local T="timeout 2s"
    
    if [ "$fw_tool" = "iptables" ]; then
        # Clean up rules marked with our comment
        for table in nat filter mangle; do
            local rules; rules=$(iptables-save -t "$table" 2>/dev/null | grep -- '--comment "rocknix"' || true)
            # shellcheck disable=SC2086
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                # Basic parsing to extract rule for deletion
                # remove leading '-A '
                local rule="${line#-A * }"
                local chain
                # Extract chain from line: -A CHAIN ...
                chain=$(echo "$line" | awk '{print $2}')
                
                # Delete it
                $T iptables -t "$table" -D "$chain" $rule 2>/dev/null || true
            done <<EOF
$rules
EOF
        done
    elif [ "$fw_tool" = "nft" ]; then
        $T nft delete table ip rocknix_nat 2>/dev/null
        $T nft delete table ip rocknix_filter 2>/dev/null
    fi
}
