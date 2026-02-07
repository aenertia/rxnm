# ==============================================================================
# PROFILE MANAGEMENT (EPHEMERAL AWARE & PRECEDENCE LOGIC)
# ==============================================================================

# --- ARCHITECTURE NOTES: RAM OVERLAY ---
# 1. Level 0: System/Immutable: /usr/lib/systemd/network/
# 2. Level 1: User/Persistent Profile: /storage/.../profiles/global/default/ (Saved state)
# 3. Level 2: User/Persistent Root: /storage/.config/network/*.network (Manual overrides)
# 4. Active:  Ephemeral/Active: /run/systemd/network/ (RAM session)

_task_profile_save_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    local iwd_dir="${STATE_DIR}/iwd"
    
    rm -rf "$profile_dir"
    mkdir -p "$profile_dir"
    
    # 1. Save NetworkD and Virtual Device files from RAM
    local nets=("${EPHEMERAL_NET_DIR}"/*.network)
    [ ${#nets[@]} -gt 0 ] && cp "${nets[@]}" "$profile_dir/" 2>/dev/null
    
    local devs=("${EPHEMERAL_NET_DIR}"/*.netdev)
    [ ${#devs[@]} -gt 0 ] && cp "${devs[@]}" "$profile_dir/" 2>/dev/null
    
    # 2. Save Per-Interface Proxy Configs from RAM
    local interface_proxies=("${EPHEMERAL_NET_DIR}"/proxy-*.conf)
    [ ${#interface_proxies[@]} -gt 0 ] && cp "${interface_proxies[@]}" "$profile_dir/" 2>/dev/null
    
    # 3. Save Global Auxiliary configs (Persistent -> Profile Snapshot)
    [ -f "${STORAGE_PROXY_GLOBAL}" ] && cp "${STORAGE_PROXY_GLOBAL}" "$profile_dir/proxy.conf"
    [ -f "${STORAGE_COUNTRY_FILE}" ] && cp "${STORAGE_COUNTRY_FILE}" "$profile_dir/country"
    
    # 4. Save Resolved overrides
    if [ -d "${STORAGE_RESOLVED_DIR}" ]; then
        mkdir -p "$profile_dir/resolved.conf.d"
        local res_confs=("${STORAGE_RESOLVED_DIR}"/*.conf)
        [ ${#res_confs[@]} -gt 0 ] && cp "${res_confs[@]}" "$profile_dir/resolved.conf.d/" 2>/dev/null
    fi

    # 5. WiFi Credentials (Snapshot current IWD state)
    if [ -d "$iwd_dir" ]; then
        mkdir -p "$profile_dir/wifi"
        local psks=("${iwd_dir}"/*.psk)
        [ ${#psks[@]} -gt 0 ] && cp "${psks[@]}" "$profile_dir/wifi/" 2>/dev/null
        
        local eaps=("${iwd_dir}"/*.8021x)
        [ ${#eaps[@]} -gt 0 ] && cp "${eaps[@]}" "$profile_dir/wifi/" 2>/dev/null
    fi
    return 0
}

_task_profile_load_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    local iwd_dir="${STATE_DIR}/iwd"
    
    # 1. Wipe current Ephemeral session (RAM)
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
    
    # 2. Restore Network Configs & Per-Interface Proxies from Profile to RAM
    local nets=("${profile_dir}"/*.network)
    [ ${#nets[@]} -gt 0 ] && cp "${nets[@]}" "${EPHEMERAL_NET_DIR}/" 2>/dev/null
    
    local devs=("${profile_dir}"/*.netdev)
    [ ${#devs[@]} -gt 0 ] && cp "${devs[@]}" "${EPHEMERAL_NET_DIR}/" 2>/dev/null

    local interface_proxies=("${profile_dir}"/proxy-*.conf)
    [ ${#interface_proxies[@]} -gt 0 ] && cp "${interface_proxies[@]}" "${EPHEMERAL_NET_DIR}/" 2>/dev/null
    
    # 3. Restore Global Persistents (Disk)
    if [ -f "$profile_dir/proxy.conf" ]; then cp "$profile_dir/proxy.conf" "${STORAGE_PROXY_GLOBAL}"; fi
    if [ -f "$profile_dir/country" ]; then 
        cp "$profile_dir/country" "${STORAGE_COUNTRY_FILE}"
        local code; read -r code < "${STORAGE_COUNTRY_FILE}"
        if command -v iw >/dev/null; then [ -n "$code" ] && iw reg set "$code" 2>/dev/null || true; fi
    fi
    
    # 4. Restore WiFi Credentials to IWD system dir (Disk)
    if [ -d "$profile_dir/wifi" ]; then
        mkdir -p "$iwd_dir"
        local psks=("${profile_dir}/wifi"/*.psk)
        [ ${#psks[@]} -gt 0 ] && cp "${psks[@]}" "$iwd_dir/" 2>/dev/null
        
        local eaps=("${profile_dir}/wifi"/*.8021x)
        [ ${#eaps[@]} -gt 0 ] && cp "${eaps[@]}" "$iwd_dir/" 2>/dev/null
        
        chmod 600 "$iwd_dir"/*.psk 2>/dev/null || true
        chmod 600 "$iwd_dir"/*.8021x 2>/dev/null || true
    fi
    
    reload_networkd
}

# --- MAIN ACTION ---

action_profile() {
    local cmd="$1"; local name="$2"; local iface="$3"; local file_path="$4"
    
    # INFERRED PRECEDENCE: If no name provided for save/load, assume 'default'
    if [[ "$cmd" == "save" || "$cmd" == "load" ]] && [ -z "$name" ]; then
        name="default"
    fi

    ensure_dirs
    
    # --- GLOBAL PROFILE (No Interface Specified) ---
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
                # Implicit "Default" / Reset handling
                if [ "$name" == "default" ] && [ ! -d "$global_dir/default" ]; then
                     confirm_action "Reset active configuration to system defaults?" "$FORCE_ACTION"
                     find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
                     find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
                     find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
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
                [ ${#files[@]} -gt 0 ] && json_list=$(printf '%s\n' "${files[@]}" | jq -R . | jq -s .)
                json_success '{"profiles": '"$json_list"', "scope": "global"}'
                ;;
            delete)
                [ -z "$name" ] && { json_error "Profile name required for deletion"; return 1; }
                [ -d "$global_dir/$name" ] && rm -rf "$global_dir/$name" && json_success '{"action": "deleted", "name": "'"$name"'"}' || json_error "Profile not found"
                ;;
            export)
                [ -z "$name" ] && { json_error "Profile name required"; return 1; }
                [ ! -d "$global_dir/$name" ] && { json_error "Profile '$name' does not exist"; return 1; }
                local out_file="${file_path:-${name}.tar.gz}"
                tar -czf "$out_file" -C "$global_dir" "$name"
                json_success '{"action": "exported", "profile": "'"$name"'", "file": "'"$out_file"'"}'
                ;;
            import)
                 [ -z "$file_path" ] && { json_error "File path required"; return 1; }
                 [ ! -f "$file_path" ] && { json_error "File not found: $file_path"; return 1; }
                 confirm_action "Import profile from '$file_path'?" "$FORCE_ACTION"
                 mkdir -p "$global_dir"
                 tar -xzf "$file_path" -C "$global_dir"
                 json_success '{"action": "imported", "file": "'"$file_path"'"}'
                 ;;
            boot)
                # SYSTEM STARTUP HOOK: Precedence Logic
                # 1. Clean RAM state
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
                
                # 2. First Pass: Sync User Profile (Profile Default -> RAM)
                # This establishes the last known RXNM-managed state.
                if [ -d "$global_dir/default" ]; then
                    log_info "Boot: Loading persistent 'default' profile into RAM..."
                    local profile_nets=("$global_dir/default"/*.network)
                    [ ${#profile_nets[@]} -gt 0 ] && cp "${profile_nets[@]}" "${EPHEMERAL_NET_DIR}/" 2>/dev/null
                    local profile_devs=("$global_dir/default"/*.netdev)
                    [ ${#profile_devs[@]} -gt 0 ] && cp "${profile_devs[@]}" "${EPHEMERAL_NET_DIR}/" 2>/dev/null
                fi

                # 3. Second Pass (Highest Priority): Sync Manually Dropped Files (Persistent Root -> RAM)
                # Manual files ALWAYS overwrite profile files if there is a name collision.
                log_info "Boot: Syncing manual overrides from root config..."
                local manual_nets=("${PERSISTENT_NET_DIR}"/*.network)
                [ ${#manual_nets[@]} -gt 0 ] && cp "${manual_nets[@]}" "${EPHEMERAL_NET_DIR}/" 2>/dev/null
                local manual_devs=("${PERSISTENT_NET_DIR}"/*.netdev)
                [ ${#manual_devs[@]} -gt 0 ] && cp "${manual_devs[@]}" "${EPHEMERAL_NET_DIR}/" 2>/dev/null
                
                log_info "Boot: RAM Active State initialized."
                ;;
        esac
        return 0
    fi

    # --- INTERFACE SPECIFIC PROFILE ---
    local profile_iface_dir="${STORAGE_PROFILES_DIR}/${iface}"
    mkdir -p "$profile_iface_dir"
    local active_cfg="${EPHEMERAL_NET_DIR}/75-config-${iface}.network"
    local active_proxy="${EPHEMERAL_NET_DIR}/proxy-${iface}.conf"
    local profile_path="${profile_iface_dir}/${name}.network"
    local profile_proxy="${profile_iface_dir}/${name}.proxy.conf"

    case "$cmd" in
        save)
            [ ! -f "$active_cfg" ] && { json_error "No active config to save for $iface"; return 1; }
            cp "$active_cfg" "$profile_path"
            [ -f "$active_proxy" ] && cp "$active_proxy" "$profile_proxy"
            json_success '{"action": "saved", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        load)
            [ ! -f "$profile_path" ] && { json_error "Profile not found"; return 1; }
            cp "$profile_path" "$active_cfg"
            if [ -f "$profile_proxy" ]; then cp "$profile_proxy" "$active_proxy"; else rm -f "$active_proxy"; fi
            reconfigure_iface "$iface"
            json_success '{"action": "loaded", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        list)
            local clean_files=()
            for f in "${profile_iface_dir}"/*.network; do [ -e "$f" ] && clean_files+=("$(basename "$f" .network)"); done
            local json_list="[]"
            [ ${#clean_files[@]} -gt 0 ] && json_list=$(printf '%s\n' "${clean_files[@]}" | jq -R . | jq -s .)
            json_success '{"profiles": '"$json_list"', "scope": "'"$iface"'"}'
            ;;
        delete)
            [ -f "$profile_path" ] && rm -f "$profile_path"
            [ -f "$profile_proxy" ] && rm -f "$profile_proxy"
            json_success '{"action": "deleted", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
    esac
}
