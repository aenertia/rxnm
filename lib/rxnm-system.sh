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

_SVC_CACHE_IWD=""
_SVC_CACHE_NETWORKD=""
_SVC_CACHE_RESOLVED=""
_SVC_CACHE_AVAHI=""
_SVC_TS_IWD=0
_SVC_TS_NETWORKD=0
_SVC_TS_RESOLVED=0
_SVC_TS_AVAHI=0

cache_service_states() {
    local now
    now=$(printf '%(%s)T' -1 2>/dev/null || date +%s)
    local t_dir="${RUN_DIR}/.svc_cache_tmp"
    mkdir -p "$t_dir"
    
    (timeout 1s systemctl is-active iwd 2>/dev/null || echo "inactive") > "$t_dir/iwd" &
    (timeout 1s systemctl is-active systemd-networkd 2>/dev/null || echo "inactive") > "$t_dir/net" &
    (timeout 1s systemctl is-active systemd-resolved 2>/dev/null || echo "inactive") > "$t_dir/res" &
    (timeout 1s systemctl is-active avahi-daemon 2>/dev/null || echo "inactive") > "$t_dir/avahi" &
    
    wait
    
    _SVC_CACHE_IWD=$(cat "$t_dir/iwd" 2>/dev/null || echo "inactive")
    _SVC_CACHE_NETWORKD=$(cat "$t_dir/net" 2>/dev/null || echo "inactive")
    _SVC_CACHE_RESOLVED=$(cat "$t_dir/res" 2>/dev/null || echo "inactive")
    _SVC_CACHE_AVAHI=$(cat "$t_dir/avahi" 2>/dev/null || echo "inactive")
    
    _SVC_TS_IWD=$now
    _SVC_TS_NETWORKD=$now
    _SVC_TS_RESOLVED=$now
    _SVC_TS_AVAHI=$now
}

is_service_active() {
    local svc="$1"
    local now
    now=$(printf '%(%s)T' -1 2>/dev/null || date +%s)
    local last_check=0
    local cached_state=""
    
    case "$svc" in
        iwd) last_check=$_SVC_TS_IWD; cached_state=$_SVC_CACHE_IWD ;;
        systemd-networkd) last_check=$_SVC_TS_NETWORKD; cached_state=$_SVC_CACHE_NETWORKD ;;
        systemd-resolved) last_check=$_SVC_TS_RESOLVED; cached_state=$_SVC_CACHE_RESOLVED ;;
        avahi-daemon) last_check=$_SVC_TS_AVAHI; cached_state=$_SVC_CACHE_AVAHI ;;
        *) 
            systemctl is-active --quiet "$svc"
            return $?
            ;;
    esac
    
    local age=$((now - last_check))
    
    if [ "$age" -gt 2 ]; then
        cached_state=$(timeout 1s systemctl is-active "$svc" 2>/dev/null || echo "inactive")
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

configure_standalone_client() {
    local iface="$1"
    log_warn "Entering Rescue Mode: Configuring $iface as standalone client"
    ip link set "$iface" up
    pkill -f "udhcpc -i $iface" 2>/dev/null
    udhcpc -i "$iface" -b -s /usr/share/udhcpc/default.script
}

configure_standalone_gadget() {
    local iface="$1"
    local ip="169.254.10.2"
    log_warn "Entering Rescue Mode: Configuring $iface as standalone gadget"
    ip link set "$iface" up
    ip addr add "${ip}/24" dev "$iface" 2>/dev/null
    
    local conf="${RUN_DIR}/udhcpd.${iface}.conf"
    printf 'start 169.254.10.10\nend 169.254.10.20\ninterface %s\noption subnet 255.255.255.0\noption router %s\noption dns %s\n' "$iface" "$ip" "$ip" > "$conf"

    pkill -f "udhcpd $conf" 2>/dev/null
    udhcpd "$conf"
}

action_setup() {
    log_info "Initializing Network Manager..."
    ensure_dirs
    check_paths
    cache_service_states
    
    [ -d /run/systemd/netif ] && chown -R systemd-network:systemd-network /run/systemd/netif 2>/dev/null
    
    if command -v action_profile >/dev/null; then
        action_profile "boot"
    else
        if [ -n "${RXNM_LIB_DIR:-}" ] && [ -f "${RXNM_LIB_DIR}/rxnm-profiles.sh" ]; then
             # shellcheck disable=SC1091
             . "${RXNM_LIB_DIR}/rxnm-profiles.sh"
             action_profile "boot"
        fi
    fi
    
    if [ -f "${CONF_DIR}/hosts.conf" ]; then
        cp "${CONF_DIR}/hosts.conf" "${RUN_DIR}/hosts"
    else
        rm -f "${RUN_DIR}/hosts"
    fi
    
    fix_permissions
    tune_network_stack "client"
    
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
    timeout 5s systemctl stop iwd 2>/dev/null || true
    log_info "Wireless services stopped."
}

ensure_dirs() {
    [ -d "$EPHEMERAL_NET_DIR" ] || mkdir -p "$EPHEMERAL_NET_DIR"
    [ -d "$PERSISTENT_NET_DIR" ] || mkdir -p "$PERSISTENT_NET_DIR"
    [ -d "${STATE_DIR}/iwd" ] || mkdir -p "${STATE_DIR}/iwd"
    [ -d "${STORAGE_PROFILES_DIR}" ] || mkdir -p "${STORAGE_PROFILES_DIR}"
    [ -d "${STORAGE_RESOLVED_DIR}" ] || mkdir -p "${STORAGE_RESOLVED_DIR}"
    [ -d "$RUN_DIR" ] || mkdir -p "$RUN_DIR"
}

check_paths() {
    if [ ! -L "$ETC_NET_DIR" ] && [ "$ETC_NET_DIR" != "$EPHEMERAL_NET_DIR" ]; then
        log_warn "$ETC_NET_DIR is not pointing to $EPHEMERAL_NET_DIR. Configuration may be ignored."
    fi
}

fix_permissions() {
    if [ -d "$EPHEMERAL_NET_DIR" ]; then
        find "$EPHEMERAL_NET_DIR" -type f \( -name '*.netdev' -o -name '*.network' -o -name '*.link' \) -exec chmod 644 {} + 2>/dev/null
    fi
    if [ -d "${STATE_DIR}/iwd" ]; then
        find "${STATE_DIR}/iwd" -type f \( -name '*.psk' -o -name '*.8021x' \) -exec chmod 600 {} + 2>/dev/null
    fi
}

reload_networkd() {
    fix_permissions
    
    if [ "${RXNM_FORCE_NETWORKCTL:-false}" != "true" ] && [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --reload >/dev/null 2>&1; then
            [ -n "$RUN_DIR" ] && rm -f "$RUN_DIR/status.json" 2>/dev/null
            return 0
        fi
        log_warn "Agent DBus reload failed, falling back to system tools."
    fi
    
    if is_service_active "systemd-networkd"; then
        timeout 5s networkctl reload 2>/dev/null || log_warn "networkctl reload timed out"
    fi
    [ -n "$RUN_DIR" ] && rm -f "$RUN_DIR/status.json" 2>/dev/null
}

reconfigure_iface() {
    local iface="$1"
    fix_permissions
    
    local reloaded="false"
    if [ "${RXNM_FORCE_NETWORKCTL:-false}" != "true" ] && [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --reload >/dev/null 2>&1; then
            reloaded="true"
        fi
    fi
    
    if [ "$reloaded" = "false" ] && is_service_active "systemd-networkd"; then
        timeout 5s networkctl reload 2>/dev/null || true
    fi
    
    if is_service_active "systemd-networkd" && [ -n "$iface" ]; then
        timeout 5s networkctl reconfigure "$iface" >/dev/null 2>&1 || true
    fi
    
    [ -n "$RUN_DIR" ] && rm -f "$RUN_DIR/status.json" 2>/dev/null
}

tune_network_stack() {
    local profile="$1"
    
    if [ -x "${RXNM_AGENT_BIN}" ]; then
        if "${RXNM_AGENT_BIN}" --tune "$profile" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    sysctl -w net.netfilter.nf_conntrack_max=16384 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_keepalive_time=300 >/dev/null 2>&1 || true
    
    if [ -d /proc/sys/net/bridge ]; then
        sysctl -w net.bridge.bridge-nf-call-iptables=0 \
                  net.bridge.bridge-nf-call-ip6tables=0 \
                  net.bridge.bridge-nf-call-arptables=0 >/dev/null 2>&1 || true
    fi
    
    if [ "$profile" = "host" ]; then
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

action_system_ipv6() {
    local action="$1"
    
    local sysctl_dir="/etc/sysctl.d"
    if [ ! -w "/etc/sysctl.d" ]; then
        sysctl_dir="/run/sysctl.d"
        mkdir -p "$sysctl_dir" 2>/dev/null || true
    fi
    local conf_file="${sysctl_dir}/99-rxnm-ipv6.conf"

    if [ "$action" = "disable" ]; then
        log_info "Tearing down IPv6 stack globally (Sysctl)..."
        
        sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
        
        for iface in /sys/class/net/*; do
            local iname
            iname=$(basename "$iface")
            [ "$iname" = "lo" ] && continue
            sysctl -w "net.ipv6.conf.${iname}.disable_ipv6=1" >/dev/null 2>&1 || true
        done
        
        printf "net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n" > "$conf_file" 2>/dev/null || true
        
        json_success '{"action": "ipv6", "status": "disabled", "note": "IPv6 addresses and routes flushed."}'
        
    elif [ "$action" = "enable" ]; then
        log_info "Restoring IPv6 stack globally..."
        
        rm -f "$conf_file" 2>/dev/null || true
        
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
        
        for iface in /sys/class/net/*; do
            local iname
            iname=$(basename "$iface")
            [ "$iname" = "lo" ] && continue
            sysctl -w "net.ipv6.conf.${iname}.disable_ipv6=0" >/dev/null 2>&1 || true
        done
        
        json_success '{"action": "ipv6", "status": "enabled"}'
        
    else
        local status="enabled"
        local val
        val=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
        if [ "$val" -eq 1 ]; then status="disabled"; fi
        json_success '{"action": "ipv6", "status": "'"$status"'"}'
    fi
}

action_system_ipv4() {
    local action="$1"
    
    local sysctl_dir="/etc/sysctl.d"
    if [ ! -w "/etc/sysctl.d" ]; then
        sysctl_dir="/run/sysctl.d"
        mkdir -p "$sysctl_dir" 2>/dev/null || true
    fi
    local conf_file="${sysctl_dir}/99-rxnm-ipv4-silence.conf"

    if [ "$action" = "disable" ]; then
        log_info "Silencing IPv4 globally (IGMP/Broadcast tuning)..."
        
        sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.arp_ignore=1 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.arp_announce=2 >/dev/null 2>&1 || true
        
        printf "net.ipv4.icmp_echo_ignore_broadcasts=1\nnet.ipv4.conf.all.arp_ignore=1\nnet.ipv4.conf.all.arp_announce=2\n" > "$conf_file" 2>/dev/null || true
        
        json_success '{"action": "ipv4", "status": "silenced", "note": "IPv4 cannot be fully disabled. Broadcasts and aggressive ARP announcements have been silenced."}'
        
    elif [ "$action" = "enable" ]; then
        log_info "Restoring IPv4 global broadcast behavior..."
        
        rm -f "$conf_file" 2>/dev/null || true
        
        sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.arp_ignore=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv4.conf.all.arp_announce=0 >/dev/null 2>&1 || true
        
        json_success '{"action": "ipv4", "status": "enabled"}'
        
    else
        local status="enabled"
        local val
        val=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "0")
        if [ "$val" -eq 1 ]; then status="silenced"; fi
        json_success '{"action": "ipv4", "status": "'"$status"'"}'
    fi
}

# --- Firewall Abstraction (NAT) ---
# Decoupled from systemd-networkd to guarantee operation in Rescue/Initramfs environments.

detect_firewall_tool() {
    # shellcheck disable=SC2153
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
    
    if [ "$fw_tool" = "iptables" ]; then
        timeout 2s iptables -t nat -C POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE 2>/dev/null || \
        timeout 2s iptables -t nat -A POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE
        
        timeout 2s iptables -C FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        timeout 2s iptables -A FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT
        
        timeout 2s iptables -C FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        timeout 2s iptables -A FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT
        
        timeout 2s iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        timeout 2s iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu
        
    elif [ "$fw_tool" = "nft" ]; then
        timeout 2s nft add table ip rocknix_nat 2>/dev/null
        timeout 2s nft add chain ip rocknix_nat postrouting "{ type nat hook postrouting priority 100 ; }" 2>/dev/null
        timeout 2s nft flush chain ip rocknix_nat postrouting
        timeout 2s nft add rule ip rocknix_nat postrouting oifname "$wan_iface" masquerade
        
        timeout 2s nft add table ip rocknix_filter 2>/dev/null
        timeout 2s nft add chain ip rocknix_filter forward "{ type filter hook forward priority 0 ; }" 2>/dev/null
        timeout 2s nft flush chain ip rocknix_filter forward
        timeout 2s nft add rule ip rocknix_filter forward iifname "$lan_iface" oifname "$wan_iface" accept
        timeout 2s nft add rule ip rocknix_filter forward iifname "$wan_iface" oifname "$lan_iface" ct state established,related accept
    fi
}

disable_nat_masquerade() {
    local fw_tool; fw_tool=$(detect_firewall_tool)
    
    if [ "$fw_tool" = "iptables" ]; then
        for table in nat filter mangle; do
            local rules; rules=$(iptables-save -t "$table" 2>/dev/null | grep -- '--comment "rocknix"' || true)
            if [ -n "$rules" ]; then
                printf '%s\n' "$rules" | sed "s/^-A /timeout 2s iptables -t $table -D /" | sh
            fi
        done
    elif [ "$fw_tool" = "nft" ]; then
        timeout 2s nft delete table ip rocknix_nat 2>/dev/null
        timeout 2s nft delete table ip rocknix_filter 2>/dev/null
    fi
}
