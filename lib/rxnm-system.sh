# ==============================================================================
# SYSTEM OPERATIONS & FIREWALL
# ==============================================================================

# --- SERVICE STATE MANAGEMENT ---
cache_service_states() {
    # Initialize cache with timestamps
    local now
    now=$(date +%s)
    
    local services=("iwd" "systemd-networkd" "avahi-daemon")
    local states
    states=$(systemctl is-active "${services[@]}" 2>/dev/null)
    
    local i=0
    while IFS= read -r state; do
        local svc="${services[$i]}"
        SERVICE_STATE_CACHE["$svc"]="$state"
        SERVICE_STATE_TS["$svc"]=$now
        # CRITICAL FIX: Use pre-increment (++i). 
        # Post-increment (i++) returns 0 (failure) when i=0, killing the script under set -e.
        ((++i))
    done <<< "$states"
    
    [ "${SERVICE_STATE_CACHE["iwd"]}" == "active" ] && IWD_ACTIVE=true || IWD_ACTIVE=false
    [ "${SERVICE_STATE_CACHE["systemd-networkd"]}" == "active" ] && NETWORKD_ACTIVE=true || NETWORKD_ACTIVE=false
    [ "${SERVICE_STATE_CACHE["avahi-daemon"]}" == "active" ] && AVAHI_ACTIVE=true || AVAHI_ACTIVE=false
}

is_service_active() {
    local svc="$1"
    local now
    now=$(date +%s)
    local last_check="${SERVICE_STATE_TS["$svc"]:-0}"
    local age=$((now - last_check))
    
    # Cache TTL: 2 seconds
    if [ $age -gt 2 ]; then
        local state
        state=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
        SERVICE_STATE_CACHE["$svc"]="$state"
        SERVICE_STATE_TS["$svc"]=$now
    fi
    
    [[ "${SERVICE_STATE_CACHE["$svc"]}" == "active" ]]
}

is_avahi_running() {
    is_service_active "avahi-daemon"
}

# --- LIFECYCLE ACTIONS ---
action_setup() {
    log_info "Initializing Network Manager..."
    ensure_dirs
    check_paths
    
    cache_service_states
    
    [ -d /run/systemd/netif ] && chown -R systemd-network:systemd-network /run/systemd/netif 2>/dev/null

    # Optimization: Batch copy wireless profiles
    if [ -d "$STORAGE_WIFI_DIR" ]; then
        local psk_files=("${STORAGE_WIFI_DIR}"/*.psk)
        [ ${#psk_files[@]} -gt 0 ] && cp "${psk_files[@]}" "${STATE_DIR}/iwd/" 2>/dev/null
    fi

    if [ -f "${CONF_DIR}/hosts.conf" ]; then
        cp "${CONF_DIR}/hosts.conf" "${RUN_DIR}/hosts"
    else
        rm -f "${RUN_DIR}/hosts"
    fi

    fix_permissions
    tune_network_stack "client"
    rfkill unblock all 2>/dev/null
    log_info "Setup complete."
}

action_reload() {
    ensure_dirs
    fix_permissions
    cache_service_states
    reload_networkd
}

action_stop() {
    systemctl stop iwd 2>/dev/null
    log_info "Wireless services stopped."
}

# --- FILE OPERATIONS ---
ensure_dirs() {
    [ -d "$STORAGE_NET_DIR" ] || mkdir -p "$STORAGE_NET_DIR"
    [ -d "${STATE_DIR}/iwd" ] || mkdir -p "${STATE_DIR}/iwd"
    [ -d "${STORAGE_PROFILES_DIR}" ] || mkdir -p "${STORAGE_PROFILES_DIR}"
    [ -d "${STORAGE_RESOLVED_DIR}" ] || mkdir -p "${STORAGE_RESOLVED_DIR}"
}

check_paths() {
    if [ ! -L "$ETC_NET_DIR" ] && [ "$ETC_NET_DIR" != "$STORAGE_NET_DIR" ]; then
        if [ "$(stat -c %i "$ETC_NET_DIR")" != "$(stat -c %i "$STORAGE_NET_DIR" 2>/dev/null)" ]; then
            log_warn "$ETC_NET_DIR does not point to $STORAGE_NET_DIR. Persistence may fail."
        fi
    fi
}

fix_permissions() {
    if [ -d "$STORAGE_NET_DIR" ]; then
        find "$STORAGE_NET_DIR" -type f \( -name '*.netdev' -o -name '*.network' \) -exec chmod 644 {} + 2>/dev/null
    fi
    if [ -d "${STATE_DIR}/iwd" ]; then
        find "${STATE_DIR}/iwd" -type f \( -name '*.psk' -o -name '*.8021x' \) -exec chmod 600 {} + 2>/dev/null
    fi
}

reload_networkd() {
    fix_permissions
    if is_service_active "systemd-networkd"; then
        networkctl reload
    fi
}

reconfigure_iface() {
    local iface="$1"
    fix_permissions
    if is_service_active "systemd-networkd"; then
        if [ -n "$iface" ]; then
            networkctl reconfigure "$iface" 2>/dev/null || networkctl reload
        else
            networkctl reload
        fi
    fi
}

secure_write() {
    local dest="$1"
    local content="$2"
    local perms="${3:-644}"
    
    # Hardened path check
    if [[ "$dest" != "${STORAGE_NET_DIR}/"* ]] && \
       [[ "$dest" != "${STATE_DIR}/"* ]] && \
       [[ "$dest" != "${CONF_DIR}/"* ]]; then
         log_error "Illegal file write attempted: $dest"
         return 1
    fi
    
    # Use mktemp for atomicity
    local tmp
    tmp=$(mktemp "${dest}.XXXXXX") || return 1
    
    printf "%b" "$content" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod "$perms" "$tmp"
    
    sync
    mv "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}

tune_network_stack() {
    local profile="$1"
    
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
                  net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1
    else
        sysctl -w net.ipv4.ip_forward=1 \
                  net.ipv4.conf.all.rp_filter=1 \
                  net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
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
        log_warn "NAT requested but no firewall tool (iptables/nft) found."
        return 0
    fi
    
    local wan_iface
    wan_iface=$(ip -4 route show default 2>/dev/null | awk '$1=="default" {print $5; exit}')
    
    if [ -z "$wan_iface" ]; then
        wan_iface=$(ip -6 route show default 2>/dev/null | awk '$1=="default" {print $5; exit}')
    fi

    if [ -z "$wan_iface" ] || [ "$lan_iface" == "$wan_iface" ]; then
        return 0
    fi
    
    log_info "Enabling NAT: LAN($lan_iface) -> WAN($wan_iface) using $fw_tool"

    if [ "$fw_tool" == "iptables" ]; then
        iptables -t nat -C POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE
        
        iptables -C FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT
        
        iptables -C FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT

        iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "rocknix" -j TCPMSS --clamp-mss-to-pmtu
        
        if command -v ip6tables >/dev/null && ip6tables -t nat -L >/dev/null 2>&1; then
            ip6tables -t nat -C POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE 2>/dev/null || \
            ip6tables -t nat -A POSTROUTING -o "$wan_iface" -m comment --comment "rocknix" -j MASQUERADE
            
            ip6tables -C FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
            ip6tables -A FORWARD -i "$lan_iface" -o "$wan_iface" -m comment --comment "rocknix" -j ACCEPT
            
            ip6tables -C FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT 2>/dev/null || \
            ip6tables -A FORWARD -i "$wan_iface" -o "$lan_iface" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "rocknix" -j ACCEPT
        fi
        
    elif [ "$fw_tool" == "nft" ]; then
        nft add table ip rocknix_nat 2>/dev/null
        nft add chain ip rocknix_nat postrouting "{ type nat hook postrouting priority 100 ; }" 2>/dev/null
        nft add rule ip rocknix_nat postrouting oifname "$wan_iface" masquerade
        
        nft add table ip rocknix_filter 2>/dev/null
        nft add chain ip rocknix_filter forward "{ type filter hook forward priority 0 ; }" 2>/dev/null
        nft add rule ip rocknix_filter forward iifname "$lan_iface" oifname "$wan_iface" accept
        nft add rule ip rocknix_filter forward iifname "$wan_iface" oifname "$lan_iface" ct state established,related accept
        nft add rule ip rocknix_filter forward tcp flags syn tcp option maxseg size set rt mtu
    fi
}

disable_nat_masquerade() {
    local fw_tool
    fw_tool=$(detect_firewall_tool)
    
    if [ "$fw_tool" == "iptables" ]; then
        for table in nat filter mangle; do
            local rules
            rules=$(iptables-save -t "$table" | grep -- '--comment "rocknix"')
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                read -r _ chain rest <<< "$line"
                local rule="${line#-A $chain }"
                iptables -t "$table" -D "$chain" $rule 2>/dev/null || true
            done <<< "$rules"
        done
        
        if command -v ip6tables >/dev/null && ip6tables -t nat -L >/dev/null 2>&1; then
             for table in nat filter mangle; do
                local rules
                rules=$(ip6tables-save -t "$table" | grep -- '--comment "rocknix"')
                while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    read -r _ chain rest <<< "$line"
                    local rule="${line#-A $chain }"
                    ip6tables -t "$table" -D "$chain" $rule 2>/dev/null || true
                done <<< "$rules"
            done
        fi
        
    elif [ "$fw_tool" == "nft" ]; then
        nft delete table ip rocknix_nat 2>/dev/null
        nft delete table ip rocknix_filter 2>/dev/null
        nft delete table ip6 rocknix_nat6 2>/dev/null
        nft delete table ip6 rocknix_filter6 2>/dev/null
    fi
}
