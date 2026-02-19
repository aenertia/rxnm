# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-nullify.sh
# PURPOSE: Zero-Stack Nullification Mode
# ARCHITECTURE: Logic / Nullify
#
# Implements network stack teardown for offline gaming/resource saving.
# v1.1.0 Update: Prioritizes eBPF/XDP hardware offload.
#                Legacy destructive behaviors (unbind/masking) removed.
# -----------------------------------------------------------------------------

_apply_xdp_to_all() {
    local action="$1" # enable|disable
    
    if [ ! -x "$RXNM_AGENT_BIN" ]; then
        # Cannot apply XDP without agent binary
        return 1
    fi
    
    local success_count=0
    
    # Iterate physical interfaces
    for iface_path in /sys/class/net/*; do
        local iface
        iface=$(basename "$iface_path")
        
        # Skip loopback
        [ "$iface" = "lo" ] && continue
        
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
    
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dry-run) dry_run="true"; shift ;;
            --interface) specific_iface="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    
    # Feature promoted to Unguarded Beta in 1.1.0 (Guard removed)

    if [ "$dry_run" = "true" ]; then
        echo "Dry-Run: Nullify $cmd"
        [ -n "$specific_iface" ] && echo "Target: Interface $specific_iface (XDP Only)" || echo "Target: Global System (XDP)"
        return 0
    fi
    
    if [ "$cmd" = "enable" ]; then
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
        
        # Strategy: XDP Only (Hardware/Kernel Offload)
        # Legacy Sysctl/Unbind fallbacks have been removed per architectural decision.
        
        if _apply_xdp_to_all "enable"; then
            json_success '{"action": "nullify", "status": "enabled", "mode": "xdp"}'
        else
            json_error "Failed to enable XDP on any interface (Agent missing or Kernel unsupported)"
            exit 1
        fi
        
    elif [ "$cmd" = "disable" ]; then
        if [ -n "$specific_iface" ]; then
            log_info "Restoring interface: $specific_iface"
            if [ -x "$RXNM_AGENT_BIN" ]; then
                "$RXNM_AGENT_BIN" --nullify-xdp "$specific_iface" "disable"
                json_success '{"action": "nullify_iface", "iface": "'"$specific_iface"'", "status": "disabled"}'
            else
                json_error "Agent binary required for restore"
                exit 1
            fi
            return 0
        fi
        
        log_info "Restoring Global Network..."
        
        # Attempt to disable XDP on all interfaces
        if _apply_xdp_to_all "disable"; then
            json_success '{"action": "nullify", "status": "disabled"}'
        else
            # Even if it fails (e.g. nothing was enabled), we report success to not block boot scripts
            log_warn "XDP disable reported no changes"
            json_success '{"action": "nullify", "status": "disabled", "note": "no_changes"}'
        fi
    else
        json_error "Invalid nullify command. Use 'enable' or 'disable'."
        exit 1
    fi
}
