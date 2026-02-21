# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-nullify.sh
# PURPOSE: Zero-Stack Nullification Mode
# ARCHITECTURE: Logic / Nullify
#
# Implements network stack teardown for offline gaming/resource saving.
# v1.1.0 Update: Prioritizes eBPF/XDP hardware offload, WoWLAN, and BT HCI.
# -----------------------------------------------------------------------------

NULLIFY_STATE_DIR="${RUN_DIR}/nullify_state"

_set_nullify_state() {
    local state="$1"
    local file="$2"
    mkdir -p "$(dirname "$file")"
    if echo "$state" > "${file}.tmp" 2>/dev/null; then
        mv -f "${file}.tmp" "$file" 2>/dev/null || true
    fi
}

# --- STATE TRACKING ---

_save_bt_state() {
    mkdir -p "$NULLIFY_STATE_DIR"
    local state="down"
    if command -v hciconfig >/dev/null 2>&1; then
        if hciconfig | grep -q "UP RUNNING"; then state="up"; fi
    fi
    echo "$state" > "${NULLIFY_STATE_DIR}/bt.state"
}

_restore_bt_state() {
    local state="down"
    [ -f "${NULLIFY_STATE_DIR}/bt.state" ] && read -r state < "${NULLIFY_STATE_DIR}/bt.state"
    if [ "$state" = "up" ]; then
        for hci in /sys/class/bluetooth/hci*; do
            [ -e "$hci" ] || continue
            timeout 2s hciconfig "${hci##*/}" up >/dev/null 2>&1 || true
        done
    fi
}

_save_wifi_state() {
    local iface="$1"
    mkdir -p "$NULLIFY_STATE_DIR"
    local ssid=""
    if command -v iwctl >/dev/null 2>&1; then
        ssid=$(iwctl station "$iface" show 2>/dev/null | awk '/Connected network/{$1=$2=""; sub(/^ +/, ""); print}')
    fi
    if [ -n "$ssid" ]; then
        echo "$ssid" > "${NULLIFY_STATE_DIR}/wifi_${iface}.ssid"
    else
        rm -f "${NULLIFY_STATE_DIR}/wifi_${iface}.ssid"
    fi
}

_restore_wifi_state() {
    local iface="$1"
    if [ -f "${NULLIFY_STATE_DIR}/wifi_${iface}.ssid" ]; then
        local ssid
        read -r ssid < "${NULLIFY_STATE_DIR}/wifi_${iface}.ssid"
        if [ -n "$ssid" ]; then
            # Run in background to prevent blocking sleep hooks
            (
                # Use standard /bin/sh sequence to avoid missing bash in extreme environs
                # Loop variable '_' suppresses ShellCheck SC2034 (unused variable)
                for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
                    if systemctl is-active --quiet iwd; then break; fi
                    sleep 0.5
                done
                if [ -d "/sys/class/net/${iface}" ]; then
                    timeout 15s iwctl station "$iface" connect -- "$ssid" >/dev/null 2>&1 || true
                fi
            ) &
        fi
        rm -f "${NULLIFY_STATE_DIR}/wifi_${iface}.ssid"
    fi
}

# --- HARDWARE LAYERS ---

_apply_wowlan() {
    local iface="$1"
    local action="$2"
    
    if ! command -v iw >/dev/null 2>&1; then return 1; fi
    
    local phy_path="/sys/class/net/$iface/phy80211"
    if [ ! -L "$phy_path" ] && [ ! -d "$phy_path" ]; then return 1; fi
    
    local phy
    phy=$(basename "$(readlink "$phy_path")" 2>/dev/null || echo "")
    [ -z "$phy" ] && return 1
    
    if [ "$action" = "enable" ]; then
        timeout 1s iw phy "$phy" wowlan enable disconnect magic-packet >/dev/null 2>&1
    else
        timeout 1s iw phy "$phy" wowlan disable >/dev/null 2>&1
    fi
    return $?
}

_apply_bluetooth_nullify() {
    local action="$1"
    local specific_iface="${2:-}"
    
    if ! command -v hciconfig >/dev/null 2>&1; then return 1; fi
    
    local success=1
    for hci in /sys/class/bluetooth/hci*; do
        [ -e "$hci" ] || continue
        local hname="${hci##*/}"
        
        if [ -n "$specific_iface" ] && [ "$specific_iface" != "$hname" ]; then
            continue
        fi
        
        if [ "$action" = "enable" ]; then
            timeout 2s hciconfig "$hname" down >/dev/null 2>&1 && success=0
        else
            timeout 2s hciconfig "$hname" up >/dev/null 2>&1 && success=0
        fi
    done
    return $success
}

# --- TASK ABSTRACTIONS FOR LOCKING ---

_task_nullify_iface() {
    local iface="$1"
    local action="$2"
    local do_wowlan="$3"
    local do_xdp="$4"
    local do_bt="$5"
    local do_soft_wol="$6"
    local modes=""
    
    local agent_action="$action"
    if [ "$action" = "enable" ] && [ "$do_soft_wol" = "yes" ]; then
        agent_action="enable-swol"
    fi

    case "$iface" in
        hci[0-9]*)
            if [ "$action" = "enable" ]; then _save_bt_state; fi
            if [ "$do_bt" = "yes" ]; then
                if _apply_bluetooth_nullify "$action" "$iface"; then
                    modes="bt"
                fi
            fi
            if [ "$action" = "disable" ]; then _restore_bt_state; fi
            ;;
        *)
            if [ "$action" = "enable" ]; then _save_wifi_state "$iface"; fi
            
            # 1. Non-deterministic firmware layer (Fast Fail-through)
            if [ "$do_wowlan" = "yes" ]; then
                if _apply_wowlan "$iface" "$action"; then
                    modes="wowlan"
                fi
            fi

            # 2. Deterministic Host layer (eBPF)
            if [ "$do_xdp" = "yes" ]; then
                if [ ! -x "$RXNM_AGENT_BIN" ]; then
                    return 1
                fi
                log_debug "Applying XDP $agent_action to $iface..."
                local xdp_out
                if xdp_out=$("$RXNM_AGENT_BIN" --nullify-xdp "$iface" "$agent_action" 2>&1); then
                    modes="${modes:+$modes,}xdp"
                    [ "$do_soft_wol" = "yes" ] && modes="${modes}-swol"
                else
                    log_warn "XDP attach failed on $iface: $xdp_out"
                fi
            fi
            
            if [ "$action" = "disable" ]; then _restore_wifi_state "$iface"; fi
            ;;
    esac
    
    if [ -z "$modes" ]; then
        modes="none"
        if [ "$action" = "enable" ]; then
             return 1 # Fail fast if no mechanisms could be successfully enabled
        fi
    fi

    _set_nullify_state "${action}d" "${RUN_DIR}/nullify_${iface}.state"
    
    # Emit applied modes to stdout for JSON capture
    printf '%s\n' "$modes"
    return 0
}

_task_nullify_global() {
    local action="$1"
    local do_wowlan="$2"
    local do_xdp="$3"
    local do_bt="$4"
    local do_soft_wol="$5"
    local modes=""
    local xdp_success_count=0
    local wowlan_success_count=0
    
    local agent_action="$action"
    if [ "$action" = "enable" ] && [ "$do_soft_wol" = "yes" ]; then
        agent_action="enable-swol"
    fi
    
    # 1. Bluetooth Air-Gap (Fast Fail-through)
    if [ "$do_bt" = "yes" ]; then
        if [ "$action" = "enable" ]; then _save_bt_state; fi
        if _apply_bluetooth_nullify "$action"; then
            modes="bt"
        fi
        if [ "$action" = "disable" ]; then _restore_bt_state; fi
    fi
    
    # Iterate physical interfaces
    for iface_path in /sys/class/net/*; do
        [ ! -e "$iface_path" ] && continue
        local iface
        iface=$(basename "$iface_path")
        
        # Skip loopback
        [ "$iface" = "lo" ] && continue
        
        # Apply to physical devices (Wireless, Ethernet, USB Gadgets)
        if [ -d "$iface_path/wireless" ] || [ -d "$iface_path/phy80211" ] || \
           [ -d "$iface_path/device" ] || \
           case "$iface" in usb*|rndis*) true ;; *) false ;; esac; then
            
            if [ "$action" = "enable" ]; then _save_wifi_state "$iface"; fi
            
            # LAYER 1: Attempt WoWLAN programming first
            if [ "$do_wowlan" = "yes" ]; then
                if _apply_wowlan "$iface" "$action"; then
                    wowlan_success_count=$((wowlan_success_count + 1))
                fi
            fi

            # LAYER 2: XDP eBPF
            if [ "$do_xdp" = "yes" ]; then
                log_debug "Applying XDP $agent_action to $iface..."
                local xdp_out
                if [ -x "$RXNM_AGENT_BIN" ] && xdp_out=$("$RXNM_AGENT_BIN" --nullify-xdp "$iface" "$agent_action" 2>&1); then
                    xdp_success_count=$((xdp_success_count + 1))
                else
                    log_warn "Failed to apply XDP to $iface: $xdp_out"
                fi
            fi
            
            if [ "$action" = "disable" ]; then _restore_wifi_state "$iface"; fi
        fi
    done
    
    if [ "$wowlan_success_count" -gt 0 ]; then
        modes="${modes:+$modes,}wowlan"
    fi
    
    if [ "$xdp_success_count" -gt 0 ]; then
        modes="${modes:+$modes,}xdp"
        [ "$do_soft_wol" = "yes" ] && modes="${modes}-swol"
    fi
    
    _set_nullify_state "${action}d" "$NULLIFY_STATE_FILE"
    
    if [ -z "$modes" ]; then
        modes="none"
    fi
    
    printf '%s\n' "$modes"
    
    # If XDP was requested but completely failed on all interfaces, return failure
    if [ "$do_xdp" = "yes" ] && [ "$xdp_success_count" -eq 0 ] && [ "$action" = "enable" ]; then
        if [ "$wowlan_success_count" -eq 0 ] && [ "$modes" != "bt" ]; then
            return 1
        fi
    fi
    return 0
}

action_system_nullify() {
    local cmd="status"
    if [ "$#" -gt 0 ]; then
        case "$1" in
            enable|--enable) cmd="enable"; shift ;;
            disable|--disable) cmd="disable"; shift ;;
            status|--status) cmd="status"; shift ;;
        esac
    fi
    
    local dry_run="false"
    local specific_iface=""
    local opt_wowlan="yes"
    local opt_bt="yes"
    local opt_xdp="yes"
    local opt_swol="no"
    
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dry-run) dry_run="true"; shift ;;
            --interface) specific_iface="${2:-}"; shift; [ "$#" -gt 0 ] && shift ;;
            --wowlan) opt_wowlan="${2:-yes}"; shift; [ "$#" -gt 0 ] && shift ;;
            --soft-wol) opt_swol="${2:-no}"; shift; [ "$#" -gt 0 ] && shift ;;
            --bt) opt_bt="${2:-yes}"; shift; [ "$#" -gt 0 ] && shift ;;
            --xdp) opt_xdp="${2:-yes}"; shift; [ "$#" -gt 0 ] && shift ;;
            *) shift ;;
        esac
    done
    
    if [ "$dry_run" = "true" ]; then
        echo "Dry-Run: Nullify $cmd"
        [ -n "$specific_iface" ] && echo "Target: Interface $specific_iface (WoWLAN: $opt_wowlan, XDP: $opt_xdp, Soft-WoL: $opt_swol, BT: $opt_bt)" || echo "Target: Global System (WoWLAN: $opt_wowlan, XDP: $opt_xdp, Soft-WoL: $opt_swol, BT: $opt_bt)"
        return 0
    fi
    
    if [ "$cmd" = "enable" ]; then
        if [ -n "$specific_iface" ]; then
            log_info "Nullifying specific interface: $specific_iface"
            
            local modes
            # SAFEGUARD: Use FD 9 Interface Lock
            if modes=$(with_iface_lock "$specific_iface" _task_nullify_iface "$specific_iface" "enable" "$opt_wowlan" "$opt_xdp" "$opt_bt" "$opt_swol"); then
                json_success '{"action": "nullify_iface", "iface": "'"$specific_iface"'", "status": "enabled", "mode": "'"$modes"'"}'
            else
                json_error "Failed to enable nullify on $specific_iface (Mechanisms failed/rejected)"
                exit 1
            fi
            return 0
        fi
        
        log_info "Executing Global Nullify (Defense in Depth)..."
        
        # SAFEGUARD: Use FD 8 Global Lock (Timeout 5s)
        acquire_global_lock 5 || { json_error "Failed to acquire global lock for nullify"; exit 1; }
        
        local modes
        if modes=$(_task_nullify_global "enable" "$opt_wowlan" "$opt_xdp" "$opt_bt" "$opt_swol"); then
            json_success '{"action": "nullify", "status": "enabled", "mode": "'"$modes"'"}'
        else
            json_error "Failed to fully enable global nullify (XDP not supported?)" "1" "mode_applied: $modes"
            exit 1
        fi
        
    elif [ "$cmd" = "disable" ]; then
        if [ -n "$specific_iface" ]; then
            log_info "Restoring interface: $specific_iface"
            
            local modes
            # SAFEGUARD: Use FD 9 Interface Lock
            if modes=$(with_iface_lock "$specific_iface" _task_nullify_iface "$specific_iface" "disable" "$opt_wowlan" "$opt_xdp" "$opt_bt" "$opt_swol"); then
                json_success '{"action": "nullify_iface", "iface": "'"$specific_iface"'", "status": "disabled", "mode": "'"$modes"'"}'
            else
                json_error "Failed to disable nullify on $specific_iface (Agent missing?)"
                exit 1
            fi
            return 0
        fi
        
        log_info "Restoring Global Network..."
        
        # SAFEGUARD: Use FD 8 Global Lock (Timeout 5s)
        acquire_global_lock 5 || { json_error "Failed to acquire global lock for restore"; exit 1; }
        
        local modes
        if modes=$(_task_nullify_global "disable" "$opt_wowlan" "$opt_xdp" "$opt_bt" "$opt_swol"); then
            json_success '{"action": "nullify", "status": "disabled", "mode": "'"$modes"'"}'
        else
            json_success '{"action": "nullify", "status": "disabled", "note": "partial_restore", "mode": "'"$modes"'"}'
        fi
        
    elif [ "$cmd" = "status" ]; then
        if [ -n "$specific_iface" ]; then
            local istate="disabled"
            if [ -f "${RUN_DIR}/nullify_${specific_iface}.state" ]; then
                istate=$(cat "${RUN_DIR}/nullify_${specific_iface}.state" 2>/dev/null || echo "disabled")
            fi
            json_success '{"action": "nullify_iface", "iface": "'"$specific_iface"'", "status": "'"$istate"'"}'
            return 0
        fi
        
        local state="disabled"
        if [ -f "$NULLIFY_STATE_FILE" ]; then
            state=$(cat "$NULLIFY_STATE_FILE" 2>/dev/null || echo "disabled")
        fi
        json_success '{"action": "nullify", "status": "'"$state"'"}'
        
    else
        json_error "Invalid nullify command. Use 'enable', 'disable', or 'status'."
        exit 1
    fi
}
