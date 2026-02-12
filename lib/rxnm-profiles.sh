# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-profiles.sh
# PURPOSE: Persistence & Profile Management
# ARCHITECTURE: Logic / Profiles
#
# Saves and loads network configurations.
# Two modes:
# 1. Global Profile (Snapshot of entire system state)
# 2. Interface Profile (Snapshot of single interface config)
# -----------------------------------------------------------------------------

_sync_active_configs() {
    local src_dir="$1"
    local dest_dir="$2"
    
    local devs=("${src_dir}"/*.netdev)
    if [ ${#devs[@]} -gt 0 ] && [ -e "${devs[0]}" ]; then
        cp "${devs[@]}" "${dest_dir}/" 2>/dev/null
    fi
    local nets=("${src_dir}"/*.network)
    if [ ${#nets[@]} -gt 0 ] && [ -e "${nets[0]}" ]; then
        cp "${nets[@]}" "${dest_dir}/" 2>/dev/null
    fi
    local links=("${src_dir}"/*.link)
    if [ ${#links[@]} -gt 0 ] && [ -e "${links[0]}" ]; then
        cp "${links[@]}" "${dest_dir}/" 2>/dev/null
    fi
    local proxies=("${src_dir}"/proxy-*.conf)
    if [ ${#proxies[@]} -gt 0 ] && [ -e "${proxies[0]}" ]; then
        cp "${proxies[@]}" "${dest_dir}/" 2>/dev/null
    fi
}

_task_profile_save_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    local iwd_dir="${STATE_DIR}/iwd"
    
    rm -rf "$profile_dir"
    mkdir -p "$profile_dir"
    
    # Save Networkd state
    _sync_active_configs "${EPHEMERAL_NET_DIR}" "${profile_dir}"
    
    # Save System state
    [ -f "${STORAGE_PROXY_GLOBAL}" ] && cp "${STORAGE_PROXY_GLOBAL}" "$profile_dir/proxy.conf"
    [ -f "${STORAGE_COUNTRY_FILE}" ] && cp "${STORAGE_COUNTRY_FILE}" "$profile_dir/country"
    
    # Save Resolved state
    if [ -d "${STORAGE_RESOLVED_DIR}" ]; then
        mkdir -p "$profile_dir/resolved.conf.d"
        local res_confs=("${STORAGE_RESOLVED_DIR}"/*.conf)
        [ ${#res_confs[@]} -gt 0 ] && [ -e "${res_confs[0]}" ] && cp "${res_confs[@]}" "$profile_dir/resolved.conf.d/"
    fi
    
    # Save IWD state (Wifi creds)
    if [ -d "$iwd_dir" ]; then
        mkdir -p "$profile_dir/wifi"
        local psks=("${iwd_dir}"/*.psk)
        [ ${#psks[@]} -gt 0 ] && [ -e "${psks[0]}" ] && cp "${psks[@]}" "$profile_dir/wifi/"
        local eaps=("${iwd_dir}"/*.8021x)
        [ ${#eaps[@]} -gt 0 ] && [ -e "${eaps[0]}" ] && cp "${eaps[@]}" "$profile_dir/wifi/"
    fi
    
    return 0
}

_task_profile_load_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    local iwd_dir="${STATE_DIR}/iwd"
    
    # Transactional Loading Strategy:
    # 1. Create staging directory
    # 2. Populate staging
    # 3. Verify
    # 4. Atomic Swap (move into place)
    
    local staging_dir="${RUN_DIR}/profile_staging_$$"
    rm -rf "$staging_dir"
    mkdir -p "$staging_dir"
    
    # 2. Populate Staging
    _sync_active_configs "${profile_dir}" "${staging_dir}"
    
    # Verify basic integrity (check if we copied anything, or if empty profile is intentional)
    # For "default" empty profile, it might be empty, so loose check.
    
    # 4. Atomic Commit
    # Clean current ephemeral dir
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.link" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
    
    # Move from staging to ephemeral
    # Note: Since they are likely on the same tmpfs (/run), mv is atomic for individual files.
    # We move contents of staging into destination.
    if [ -d "$staging_dir" ]; then
        find "$staging_dir" -maxdepth 1 -type f -exec mv -f {} "${EPHEMERAL_NET_DIR}/" \;
        rm -rf "$staging_dir"
    fi
    
    # Handle System files (Non-networkd)
    if [ -f "$profile_dir/proxy.conf" ]; then cp "$profile_dir/proxy.conf" "${STORAGE_PROXY_GLOBAL}"; fi
    
    if [ -f "$profile_dir/country" ]; then
        cp "$profile_dir/country" "${STORAGE_COUNTRY_FILE}"
        local code; read -r code < "${STORAGE_COUNTRY_FILE}"
        if command -v iw >/dev/null; then [ -n "$code" ] && iw reg set "$code" 2>/dev/null || true; fi
    fi
    
    # Restore IWD (Direct copy as IWD watches this dir)
    if [ -d "$profile_dir/wifi" ]; then
        mkdir -p "$iwd_dir"
        local psks=("${profile_dir}/wifi"/*.psk)
        [ ${#psks[@]} -gt 0 ] && [ -e "${psks[0]}" ] && cp "${psks[@]}" "$iwd_dir/"
        local eaps=("${profile_dir}/wifi"/*.8021x)
        [ ${#eaps[@]} -gt 0 ] && [ -e "${eaps[0]}" ] && cp "${eaps[@]}" "$iwd_dir/"
        
        # Permissions fix
        chmod 600 "$iwd_dir"/*.psk 2>/dev/null || true
        chmod 600 "$iwd_dir"/*.8021x 2>/dev/null || true
    fi
    
    reload_networkd
}

action_profile() {
    local cmd="$1"; local name="$2"; local iface="$3"; local file_path="$4"
    
    if [[ "$cmd" == "save" || "$cmd" == "load" ]] && [ -z "$name" ]; then
        name="default"
    fi
    ensure_dirs
    
    # GLOBAL PROFILE SCOPE
    if [ -z "$iface" ]; then
        local global_dir="${STORAGE_PROFILES_DIR}/global"
        mkdir -p "$global_dir"
        
        case "$cmd" in
            save)
                confirm_action "Overwrite existing global profile '$name'?" "$FORCE_ACTION"
                _task_profile_save_global "$name"
                json_success '{"action": "saved_global", "name": "'"$name"'"}'
                ;;
            load)
                if [ "$name" == "default" ] && [ ! -d "$global_dir/default" ]; then
                     # If loading default but it doesn't exist, reset to empty slate
                     confirm_action "Reset active configuration to system defaults?" "$FORCE_ACTION"
                     find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
                     find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
                     find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.link" -delete
                     reload_networkd
                     json_success '{"action": "loaded_default", "note": "ephemeral_wiped"}'
                     return 0
                fi
                [ ! -d "$global_dir/$name" ] && { json_error "Profile not found: $name"; return 1; }
                
                confirm_action "Load global profile '$name' into RAM?" "$FORCE_ACTION"
                _task_profile_load_global "$name"
                json_success '{"action": "loaded_global", "name": "'"$name"'"}'
                ;;
            list)
                local files=()
                for f in "$global_dir"/*; do [ -d "$f" ] && files+=("$(basename "$f")") ; done
                [ ! -d "$global_dir/default" ] && files+=("default (system)")
                
                local json_list="[]"
                if [ ${#files[@]} -gt 0 ]; then
                    json_list=$(printf '%s\n' "${files[@]}" | sort -u | "$JQ_BIN" -R . | "$JQ_BIN" -s .)
                fi
                json_success '{"profiles": '"$json_list"', "scope": "global"}'
                ;;
            boot)
                # Boot logic: Wipes ephemeral, then loads 'default' if it exists
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.link" -delete
                
                if [ -d "$global_dir/default" ]; then
                    log_info "Boot: Loading persistent 'default' profile into RAM..."
                    _sync_active_configs "$global_dir/default" "${EPHEMERAL_NET_DIR}"
                fi
                
                # Overlay persistent manual configs (not in a profile)
                log_info "Boot: Syncing manual overrides from root config..."
                _sync_active_configs "${PERSISTENT_NET_DIR}" "${EPHEMERAL_NET_DIR}"
                log_info "Boot: RAM Active State initialized."
                ;;
        esac
        return 0
    fi
    
    # INTERFACE PROFILE SCOPE (Single Iface)
    local profile_iface_dir="${STORAGE_PROFILES_DIR}/${iface}"
    mkdir -p "$profile_iface_dir"
    
    local active_cfg="${EPHEMERAL_NET_DIR}/75-config-${iface}.network"
    local active_link="${EPHEMERAL_NET_DIR}/10-rxnm-${iface}.link"
    local active_proxy="${EPHEMERAL_NET_DIR}/proxy-${iface}.conf"
    
    local profile_path="${profile_iface_dir}/${name}.network"
    local profile_link="${profile_iface_dir}/${name}.link"
    local profile_proxy="${profile_iface_dir}/${name}.proxy.conf"
    
    case "$cmd" in
        save)
            if [ ! -f "$active_cfg" ] && [ ! -f "$active_link" ]; then
                 json_error "No active config to save for $iface"; return 1
            fi
            [ -f "$active_cfg" ] && cp "$active_cfg" "$profile_path"
            [ -f "$active_link" ] && cp "$active_link" "$profile_link"
            [ -f "$active_proxy" ] && cp "$active_proxy" "$profile_proxy"
            json_success '{"action": "saved", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        load)
            if [ ! -f "$profile_path" ] && [ ! -f "$profile_link" ]; then
                 json_error "Profile not found"; return 1
            fi
            [ -f "$profile_path" ] && cp "$profile_path" "$active_cfg"
            [ -f "$profile_link" ] && cp "$profile_link" "$active_link"
            if [ -f "$profile_proxy" ]; then cp "$profile_proxy" "$active_proxy"; else rm -f "$active_proxy"; fi
            reconfigure_iface "$iface"
            json_success '{"action": "loaded", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        list)
            local clean_files=()
            for f in "${profile_iface_dir}"/*.network "${profile_iface_dir}"/*.link; do
                [ -e "$f" ] && clean_files+=("$(basename "$f" | sed 's/\.network$//;s/\.link$//')")
            done
            local json_list="[]"
            if [ ${#clean_files[@]} -gt 0 ]; then
                local unique_files
                unique_files=$(printf '%s\n' "${clean_files[@]}" | sort -u | "$JQ_BIN" -R . | "$JQ_BIN" -s .)
                json_list="$unique_files"
            fi
            json_success '{"profiles": '"$json_list"', "scope": "'"$iface"'"}'
            ;;
        delete)
            [ -f "$profile_path" ] && rm -f "$profile_path"
            [ -f "$profile_link" ] && rm -f "$profile_link"
            [ -f "$profile_proxy" ] && rm -f "$profile_proxy"
            json_success '{"action": "deleted", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
    esac
}
