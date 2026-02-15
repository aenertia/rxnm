# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-nullify.sh
# PURPOSE: Zero-Stack Nullification Mode
# ARCHITECTURE: Logic / Nullify
#
# Implements complete network stack teardown for offline gaming/resource saving.
# -----------------------------------------------------------------------------

_nullify_sysctl_enable() {
    sysctl -w net.ipv4.conf.all.disable_ipv4=1 2>/dev/null || true
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
    sysctl -w net.ipv4.neigh.default.gc_thresh1=0 2>/dev/null || true
    sysctl -w net.ipv4.neigh.default.gc_thresh2=0 2>/dev/null || true
    sysctl -w net.ipv4.neigh.default.gc_thresh3=0 2>/dev/null || true
    sysctl -w net.core.rmem_default=4096 2>/dev/null || true
    sysctl -w net.core.wmem_default=4096 2>/dev/null || true
    sysctl -w net.ipv4.tcp_congestion_control=reno 2>/dev/null || true
    sysctl -w net.core.default_qdisc=pfifo_fast 2>/dev/null || true
    sysctl -w net.ipv4.tcp_timestamps=0 2>/dev/null || true
    sysctl -w net.ipv4.tcp_sack=0 2>/dev/null || true
    sysctl -w net.core.netdev_max_backlog=1 2>/dev/null || true
    sysctl -w net.core.bpf_jit_enable=0 2>/dev/null || true
}

_nullify_sysctl_disable() {
    sysctl -w net.ipv4.conf.all.disable_ipv4=0 2>/dev/null || true
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
    sysctl -w net.core.rmem_default=212992 2>/dev/null || true
    sysctl -w net.core.wmem_default=212992 2>/dev/null || true
    sysctl -w net.core.default_qdisc=fq_codel 2>/dev/null || true
    sysctl -w net.core.bpf_jit_enable=1 2>/dev/null || true
}

_nullify_bus_unbind() {
    for bus in pci sdio; do
        local dev_dir="/sys/bus/$bus/devices"
        if [ -d "$dev_dir" ]; then
            for dev in "$dev_dir"/*; do
                [ -e "$dev" ] || continue
                local is_net=0
                if [ -d "$dev/net" ]; then
                    is_net=1
                elif [ -f "$dev/class" ]; then
                    local class_val
                    read -r class_val < "$dev/class"
                    if [[ "$class_val" == 0x02* ]]; then
                        is_net=1
                    fi
                fi
                if [ "$is_net" -eq 1 ]; then
                    local dev_name
                    dev_name=$(basename "$dev")
                    if [ -e "$dev/driver/unbind" ]; then
                        echo "$dev_name" > "$dev/driver/unbind" 2>/dev/null || true
                    fi
                fi
            done
        fi
    done
}

_nullify_namespace_lockdown() {
    ip netns add null_ns 2>/dev/null || true
    for iface in /sys/class/net/*; do
        [ -e "$iface" ] || continue
        local name
        name=$(basename "$iface")
        if [ "$name" != "lo" ] && [ "$name" != "bonding_masters" ]; then
            ip link set "$name" netns null_ns 2>/dev/null || true
        fi
    done
    ip -n null_ns link set dev lo down 2>/dev/null || true
}

_nullify_namespace_restore() {
    if ip netns list 2>/dev/null | grep -q null_ns; then
        ip -n null_ns link show | awk -F': ' '/^[0-9]+:/ {print $2}' | while read -r name; do
            local clean_name="${name%%@*}"
            [ -n "$clean_name" ] && ip -n null_ns link set "$clean_name" netns 1 2>/dev/null || true
        done
        ip netns delete null_ns 2>/dev/null || true
    fi
}

_nullify_services_mask() {
    local state_file="/run/rocknix/nullify-pre-state.txt"
    > "$state_file"
    for svc in $NULLIFY_SERVICES; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "$svc:active" >> "$state_file"
        elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            echo "$svc:enabled" >> "$state_file"
        fi
        systemctl mask --now "$svc" 2>/dev/null || true
    done
}

_nullify_services_unmask() {
    local state_file="/run/rocknix/nullify-pre-state.txt"
    for svc in $NULLIFY_SERVICES; do
        systemctl unmask "$svc" 2>/dev/null || true
    done
    
    if [ -f "$state_file" ]; then
        while IFS=: read -r svc state; do
            if [ "$state" == "active" ]; then
                systemctl start "$svc" 2>/dev/null || true
            fi
        done < "$state_file"
        rm -f "$state_file"
    fi
}

_nullify_modules_purge() {
    mkdir -p /run/modprobe.d
    local conf="/run/modprobe.d/rxnm-null.conf"
    > "$conf"
    for mod in $NULLIFY_MODULES; do
        echo "blacklist $mod" >> "$conf"
        modprobe -rv "$mod" 2>/dev/null || true
    done
}

_nullify_modules_restore() {
    rm -f /run/modprobe.d/rxnm-null.conf
}

_nullify_dry_run() {
    local cmd="$1"
    echo "Dry-Run Mode: Nullify $cmd"
    echo ""
    if [ "$cmd" == "enable" ]; then
        echo "Would mask services:"
        for svc in $NULLIFY_SERVICES; do
            echo "  $svc"
        done
        echo ""
        echo "Would unbind devices:"
        for bus in pci sdio; do
            local dev_dir="/sys/bus/$bus/devices"
            if [ -d "$dev_dir" ]; then
                for dev in "$dev_dir"/*; do
                    [ -e "$dev" ] || continue
                    local is_net=0
                    if [ -d "$dev/net" ]; then
                        is_net=1
                    elif [ -f "$dev/class" ]; then
                        local class_val
                        read -r class_val < "$dev/class" 2>/dev/null || class_val=""
                        if [[ "$class_val" == 0x02* ]]; then
                            is_net=1
                        fi
                    fi
                    if [ "$is_net" -eq 1 ]; then
                        local dev_name
                        dev_name=$(basename "$dev")
                        local driver="unknown"
                        [ -L "$dev/driver" ] && driver=$(basename $(readlink "$dev/driver"))
                        echo "  $dev ($driver)"
                    fi
                done
            fi
        done
        echo ""
        echo "Would disable sysctls:"
        echo "  net.ipv4.conf.all.disable_ipv4 -> 1"
        echo "  net.ipv6.conf.all.disable_ipv6 -> 1"
    elif [ "$cmd" == "disable" ]; then
        echo "Would unmask services:"
        for svc in $NULLIFY_SERVICES; do
            echo "  $svc"
        done
        echo ""
        echo "Would enable sysctls:"
        echo "  net.ipv4.conf.all.disable_ipv4 -> 0"
        echo "  net.ipv6.conf.all.disable_ipv6 -> 0"
        echo "  net.core.default_qdisc -> fq_codel"
        echo "  net.core.bpf_jit_enable -> 1"
    fi
}

action_system_nullify() {
    local cmd="$1"
    local dry_run="$2"
    
    # --- EXPERIMENTAL FEATURE GUARD ---
    if [ "${RXNM_EXPERIMENTAL:-false}" != "true" ]; then
        json_error "Feature 'nullify' is experimental. Set RXNM_EXPERIMENTAL=true to enable." "501" \
            "This feature is destructive and experimental. See 'rxnm api capabilities' for status."
        exit 1
    fi

    if [ "$dry_run" == "--dry-run" ]; then
        _nullify_dry_run "$cmd"
        return 0
    fi
    
    if [ "$cmd" == "enable" ]; then
        if [ "$FORCE_ACTION" != "true" ]; then
            echo "!!! DANGER: NULLIFY MODE WILL DESTROY ALL NETWORK FUNCTIONALITY !!!" >&2
            echo "This action is NON-DETERMINISTIC and will break system stability." >&2
            echo "Wireless, Bluetooth, Ethernet, and all remote management (SSH/SMB)" >&2
            echo "will be PERMANENTLY DISABLED for this session." >&2
            echo "MANDATORY: This action requires the --yes flag to proceed." >&2
            exit 1
        fi
        
        log_info "Executing Nullify Mode (Enable)..."
        
        if [ -x "$RXNM_AGENT_BIN" ]; then
            "$RXNM_AGENT_BIN" --nullify enable
        else
            _nullify_sysctl_enable
            _nullify_bus_unbind
        fi
        
        _nullify_namespace_lockdown
        _nullify_services_mask
        _nullify_modules_purge
        
        json_success '{"action": "nullify", "status": "enabled"}'
        
    elif [ "$cmd" == "disable" ]; then
        echo "!!! WARNING: RESTORING NETWORK STACK AFTER NULLIFICATION IS EXPERIMENTAL !!!" >&2
        echo "While RXNM will attempt to unmask services and restore the IP stack," >&2
        echo "hardware bus unbinding and module purging often require a REBOOT to" >&2
        echo "fully recover functionality." >&2
        
        if [ "$FORCE_ACTION" != "true" ] && [ "${RXNM_FORMAT:-human}" != "json" ]; then
            read -p "⚠ Proceed with restore? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Cancelled."
                exit 0
            fi
        fi
        
        log_info "Executing Nullify Mode (Disable)..."
        
        _nullify_services_unmask
        _nullify_modules_restore
        _nullify_namespace_restore
        
        if [ -x "$RXNM_AGENT_BIN" ]; then
            "$RXNM_AGENT_BIN" --nullify disable
        else
            _nullify_sysctl_disable
        fi
        
        json_success '{"action": "nullify", "status": "disabled"}'
    else
        json_error "Invalid nullify command. Use 'enable' or 'disable'."
        exit 1
    fi
}
