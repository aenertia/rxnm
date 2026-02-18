# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-nullify.sh
# PURPOSE: Zero-Stack Nullification Mode
# ARCHITECTURE: Logic / Nullify
#
# Implements network stack teardown for offline gaming/resource saving.
# v1.1.0 Update: Prioritizes eBPF/XDP hardware offload.
#                Replaces destructive unbinding with robust state caching.
# -----------------------------------------------------------------------------

# List of sysctls to manage during fallback mode (Bash First)
NULLIFY_SYSCTLS=(
    "net.ipv4.conf.all.disable_ipv4"
    "net.ipv6.conf.all.disable_ipv6"
    "net.ipv4.neigh.default.gc_thresh1"
    "net.ipv4.neigh.default.gc_thresh2"
    "net.ipv4.neigh.default.gc_thresh3"
    "net.core.rmem_default"
    "net.core.wmem_default"
    "net.ipv4.tcp_congestion_control"
    "net.core.default_qdisc"
    "net.ipv4.tcp_timestamps"
    "net.ipv4.tcp_sack"
    "net.core.netdev_max_backlog"
    "net.core.bpf_jit_enable"
)

# Description: Saves current state of sysctls to file.
# Protects against overwriting an existing state file (double-enable).
_nullify_save_state() {
    if [ -f "$NULLIFY_STATE_FILE" ]; then
        log_debug "State file exists, skipping save to preserve original state."
        return
    fi

    mkdir -p "$(dirname "$NULLIFY_STATE_FILE")"
    : > "$NULLIFY_STATE_FILE"
    
    log_debug "Saving sysctl state to $NULLIFY_STATE_FILE..."
    for key in "${NULLIFY_SYSCTLS[@]}"; do
        if val=$(sysctl -n "$key" 2>/dev/null); then
            echo "SYSCTL:${key}=${val}" >> "$NULLIFY_STATE_FILE"
        fi
    done
    sync
}

# Description: Restores state from file.
_nullify_restore_state() {
    if [ ! -f "$NULLIFY_STATE_FILE" ]; then
        log_warn "Nullify state file not found. Skipping sysctl restore."
        return
    fi
    
    log_info "Restoring system tunables from cache..."
    
    while IFS= read -r line; do
        if [[ "$line" == SYSCTL:* ]]; then
            local content="${line#SYSCTL:}"
            local key="${content%%=*}"
            local val="${content#*=}"
            sysctl -w "$key=$val" >/dev/null 2>&1 || true
        fi
    done < "$NULLIFY_STATE_FILE"
    
    # Clean up state file after successful restore
    rm -f "$NULLIFY_STATE_FILE"
}

# Description: Applies aggressive power-saving sysctls (Fallback logic)
_nullify_sysctl_enable() {
    # 1. Save original values first
    _nullify_save_state
    
    # 2. Apply silence
    sysctl -w net.ipv4.conf.all.disable_ipv4=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    # Zero out GC thresholds to drop neighbor table entries aggressively
    sysctl -w net.ipv4.neigh.default.gc_thresh1=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.neigh.default.gc_thresh2=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.neigh.default.gc_thresh3=0 >/dev/null 2>&1 || true
    # Minimize buffers
    sysctl -w net.core.rmem_default=4096 >/dev/null 2>&1 || true
    sysctl -w net.core.wmem_default=4096 >/dev/null 2>&1 || true
    # Simplify TCP stack
    sysctl -w net.ipv4.tcp_congestion_control=reno >/dev/null 2>&1 || true
    sysctl -w net.core.default_qdisc=pfifo_fast >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_sack=0 >/dev/null 2>&1 || true
    # Drop queue depth
    sysctl -w net.core.netdev_max_backlog=1 >/dev/null 2>&1 || true
    # Disable BPF JIT to save memory/security surface during lockdown
    sysctl -w net.core.bpf_jit_enable=0 >/dev/null 2>&1 || true
}

_apply_xdp_to_all() {
    local action="$1" # enable|disable
    
    if [ ! -x "$RXNM_AGENT_BIN" ]; then
        # This function returns failure if it can't run, prompting fallback
        return 1
    fi
    
    local success_count=0
    
    # Iterate physical interfaces
    for iface_path in /sys/class/net/*; do
        local iface
        iface=$(basename "$iface_path")
        
        # Skip loopback
        [ "$iface" == "lo" ] && continue
        
        # Apply only to physical devices (Wireless or Ethernet)
        if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ] || \
           [ -d "$iface_path/device" ]; then
            
            log_debug "Applying XDP $action to $iface..."
            if "$RXNM_AGENT_BIN" --nullify-xdp "$iface" "$action" 2>/dev/null; then
                success_count=$((success_count + 1))
            else
                log_warn "Failed to apply XDP to $iface (Driver may not support it)"
            fi
        fi
    done
    
    if [ "$success_count" -eq 0 ]; then return 1; fi
    return 0
}

action_system_nullify() {
    local cmd="${1:-}"
    shift
    
    local dry_run="false"
    local specific_iface=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) dry_run="true"; shift ;;
            --interface) specific_iface="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    
    # Feature promoted to Unguarded Beta in 1.1.0 (Guard removed)

    if [ "$dry_run" == "true" ]; then
        echo "Dry-Run: Nullify $cmd"
        [ -n "$specific_iface" ] && echo "Target: Interface $specific_iface (XDP Only)" || echo "Target: Global System"
        echo "State File: $NULLIFY_STATE_FILE"
        return 0
    fi
    
    if [ "$cmd" == "enable" ]; then
        if [ "$FORCE_ACTION" != "true" ]; then
            echo "!!! DANGER: NULLIFY MODE WILL SILENCE NETWORK TRAFFIC !!!" >&2
            echo "Confirm with --yes" >&2
            exit 1
        fi
        
        if [ -n "$specific_iface" ]; then
            log_info "Nullifying specific interface: $specific_iface (XDP Drop)"
            if [ -x "$RXNM_AGENT_BIN" ]; then
                "$RXNM_AGENT_BIN" --nullify-xdp "$specific_iface" "enable"
                json_success '{"action": "nullify_iface", "iface": "'"$specific_iface"'", "status": "enabled"}'
            else
                json_error "Agent binary required for interface-specific nullify"
                exit 1
            fi
            return 0
        fi
        
        log_info "Executing Global Nullify..."
        
        # Strategy: Prefer XDP (Hardware Offload). Fallback to Sysctl (Kernel Drop).
        local mode="xdp"
        
        if ! _apply_xdp_to_all "enable"; then
            log_warn "XDP application failed or Agent missing. Falling back to Sysctl."
            _nullify_sysctl_enable
            mode="sysctl (fallback)"
        fi
        
        # Note: We NO LONGER mask services or unbind drivers (Legacy behavior scrapped).
        # This keeps the system responsive, just network-silent.
        
        json_success '{"action": "nullify", "status": "enabled", "mode": "'"$mode"'"}'
        
    elif [ "$cmd" == "disable" ]; then
        if [ -n "$specific_iface" ]; then
            log_info "Restoring interface: $specific_iface"
            if [ -x "$RXNM_AGENT_BIN" ]; then
                "$RXNM_AGENT_BIN" --nullify-xdp "$specific_iface" "disable"
                json_success '{"action": "nullify_iface", "iface": "'"$specific_iface"'", "status": "disabled"}'
            fi
            return 0
        fi
        
        log_info "Restoring Global Network..."
        
        # Attempt to disable XDP on all interfaces
        _apply_xdp_to_all "disable"
        
        # Restore sysctls if they were modified (State file determines this)
        _nullify_restore_state
        
        json_success '{"action": "nullify", "status": "disabled"}'
    else
        json_error "Invalid nullify command. Use 'enable' or 'disable'."
        exit 1
    fi
}
