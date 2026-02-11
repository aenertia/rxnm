# ==============================================================================
# SYSTEM OPERATIONS & FIREWALL
# ==============================================================================

# --- SERVICE STATE MANAGEMENT ---
cache_service_states() {
    local now
    now=$(printf '%(%s)T' -1) 2>/dev/null || now=$(date +%s)
    
    # Phase 3 Refactor: Added systemd-resolved to batch check
    local services=("iwd" "systemd-networkd" "systemd-resolved" "avahi-daemon")
    local states
    states=$(timeout 2s systemctl is-active "${services[@]}" 2>/dev/null || echo "inactive")
    
    local i=0
    while IFS= read -r state; do
        local svc="${services[$i]}"
        SERVICE_STATE_CACHE["$svc"]="$state"
        SERVICE_STATE_TS["$svc"]=$now
        ((++i))
    done <<< "$states"
    
    [ "${SERVICE_STATE_CACHE["iwd"]}" == "active" ] && IWD_ACTIVE=true || IWD_ACTIVE=false
    [ "${SERVICE_STATE_CACHE["systemd-networkd"]}" == "active" ] && NETWORKD_ACTIVE=true || NETWORKD_ACTIVE=false
    [ "${SERVICE_STATE_CACHE["systemd-resolved"]}" == "active" ] && RESOLVED_ACTIVE=true || RESOLVED_ACTIVE=false
    [ "${SERVICE_STATE_CACHE["avahi-daemon"]}" == "active" ] && AVAHI_ACTIVE=true || AVAHI_ACTIVE=false
}

is_service_active() {
    local svc="$1"
    local now
    now=$(printf '%(%s)T' -1) 2>/dev/null || now=$(date +%s)
    local last_check="${SERVICE_STATE_TS["$svc"]:-0}"
    local age=$((now - last_check))
    
    if [ $age -gt 2 ]; then
        local state
        state=$(timeout 1s systemctl is-active "$svc" 2>/dev/null || echo "inactive")
        SERVICE_STATE_CACHE["$svc"]="$state"
        SERVICE_STATE_TS["$svc"]=$now
    fi
    
    [[ "${SERVICE_STATE_CACHE["$svc"]}" == "active" ]]
}

is_avahi_running() {
    is_service_active "avahi-daemon"
}

# --- RESCUE MODE HELPERS (Phase 8) ---

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
    
    local conf="/tmp/udhcpd.${iface}.conf"
    cat <<EOF > "$conf"
start 169.254.10.10
end 169.254.10.20
interface $iface
option subnet 255.255.255.0
option router $ip
option dns $ip
EOF
    pkill -f "udhcpd $conf" 2>/dev/null
    udhcpd "$conf"
}

# --- LIFECYCLE ACTIONS ---
action_setup() {
    log_info "Initializing Network Manager..."
    ensure_dirs
    check_paths
    
    cache_service_states
    
    [ -d /run/systemd/netif ] && chown -R systemd-network:systemd-network /run/systemd/netif 2>/dev/null

    if type action_profile &>/dev/null; then
        action_profile "boot"
    else
        if [ -n "${RXNM_LIB_DIR:-}" ] && [ -f "${RXNM_LIB_DIR}/rxnm-profiles.sh" ]; then
             source "${RXNM_LIB_DIR}/rxnm-profiles.sh"
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
        [ -e "$rdir/soft" ] && { read -r s < "$rdir/soft"; [ "$s" -eq 1 ] && needs_unblock=1 && break; }
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

# --- FILE OPERATIONS ---
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
        log_warn "$ETC_NET_DIR is not pointing to $EPHEMERAL_NET_DIR."
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
    
    if [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --reload >/dev/null 2>&1; then
            [ -n "$RUN_DIR" ] && rm -f "$RUN_DIR/status.json" 2>/dev/null
            return 0
        fi
    fi
    
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

secure_write() {
    local dest="$1"
    local content="$2"
    local perms="${3:-644}"
    
    if [[ "$dest" != "${EPHEMERAL_NET_DIR}/"* ]] && \
       [[ "$dest" != "${PERSISTENT_NET_DIR}/"* ]] && \
       [[ "$dest" != "${STATE_DIR}/"* ]] && \
       [[ "$dest" != "${CONF_DIR}/"* ]] && \
       [[ "$dest" != "${RUN_DIR}/"* ]]; then
         log_error "Illegal file write attempted: $dest"
         return 1
    fi
    
    [ -d "$(dirname "$dest")" ] || mkdir -p "$(dirname "$dest")"
    
    # Phase 2 Refactor: Use Native Agent if available (Atomic/Idempotent)
    if [ -x "${RXNM_AGENT_BIN}" ]; then
        if printf "%b" "$content" | "${RXNM_AGENT_BIN}" --atomic-write "$dest" "$perms" 2>/dev/null; then
            return 0
        fi
        # Fallback if agent write fails
    fi
    
    local tmp
    tmp=$(mktemp "${dest}.XXXXXX") || return 1
    printf "%b" "$content" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod "$perms" "$tmp"
    sync
    mv "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}

tune_network_stack() {
    local profile="$1"
    
    # Phase 1 Refactor: Use native agent for sysctl tuning if available
    if [ -x "${RXNM_AGENT_BIN}" ]; then
        if "${RXNM_AGENT_BIN}" --tune "$profile" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    # Legacy Fallback
    sysctl -w net.netfilter.nf_conntrack_max=16384 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_keepalive_time=300 >/dev/null 2>&1 || true

    if [ -d /proc/sys/net/bridge ]; then
        sysctl -w net.bridge.bridge-nf-call-iptables=0 \
                  net.bridge.bridge-nf-call-ip6tables=0 \
                  net.bridge.bridge-nf-call-arptables=0 >/dev/null 2>&1 || true
    fi

    if [ "$profile" == "host" ]; then
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

# --- FIREWALL MANAGEMENT ---

detect_firewall_tool() {
    echo "$FW_TOOL"
}

enable_nat_masquerade() {
    local lan_iface="$1"
    [ -z "$lan_iface" ] && return 1

    local fw_tool
    fw_tool=$(detect_firewall_tool)
    
    if [ "$fw_tool" == "none" ]; then
        log_warn "NAT requested but no firewall tool found."
        return 0
    fi
    
    local wan_iface
    wan_iface=$(ip -4 route show default 2>/dev/null | awk '$1=="default" {print $5; exit}')
    [ -z "$wan_iface" ] && wan_iface=$(ip -6 route show default 2>/dev/null | awk '$1=="default" {print $5; exit}')

    if [ -z "$wan_iface" ] || [ "$lan_iface" == "$wan_iface" ]; then return 0; fi
    
    log_info "Enabling NAT: LAN($lan_iface) -> WAN($wan_iface) using $fw_tool"
    local T="timeout 2s"

    if [ "$fw_tool" == "iptables" ]; then
        $T iptables -t nat -C POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE 2>/dev/null || \
        $T iptables -t nat -A POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE
        
        $T iptables -C FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        $T iptables -A FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT
        
        $T iptables -C FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        $T iptables -A FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT

        $T iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        $T iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu
    elif [ "$fw_tool" == "nft" ]; then
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
    if [ "$fw_tool" == "iptables" ]; then
        for table in nat filter mangle; do
            local rules; rules=$(iptables-save -t "$table" 2>/dev/null | grep -- '--comment "rocknix"' || true)
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                read -r _ chain rest <<< "$line"
                local rule="${line#-A $chain }"
                $T iptables -t "$table" -D "$chain" $rule 2>/dev/null || true
            done <<< "$rules"
        done
    elif [ "$fw_tool" == "nft" ]; then
        $T nft delete table ip rocknix_nat 2>/dev/null
        $T nft delete table ip rocknix_filter 2>/dev/null
    fi
}
