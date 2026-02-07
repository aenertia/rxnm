# ==============================================================================
# PROFILE MANAGEMENT
# ==============================================================================

# --- ARCHITECTURE NOTES: OVERLAY & INHERITANCE ---
# RXNM relies on systemd-networkd's native path precedence for "Inheritance":
# 1. System/Immutable: /usr/lib/systemd/network/ (Read-only defaults)
# 2. User/Override:    $STORAGE_NET_DIR/         (Read-write active state)
#
# - The "Default Profile" is simply the current state of $STORAGE_NET_DIR.
# - Modifications (set-ip, etc) write higher-priority files (75-*) here, 
#   effectively masking the system defaults (80-*) for that specific interface.
# - "Loading Default" (if not saved) clears $STORAGE_NET_DIR, removing all 
#   masks and reverting the system to the Immutable state.

# --- GLOBAL PROFILE HELPERS ---

_task_profile_save_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    local iwd_dir="${STATE_DIR}/iwd"
    
    # Clean previous save of same name if exists
    rm -rf "$profile_dir"
    mkdir -p "$profile_dir"
    
    # 1. Save NetworkD files
    # Use array expansion with nullglob (inherited from main) to safely handle empty sets
    local nets=("${STORAGE_NET_DIR}"/*.network)
    [ ${#nets[@]} -gt 0 ] && cp "${nets[@]}" "$profile_dir/" 2>/dev/null
    
    local devs=("${STORAGE_NET_DIR}"/*.netdev)
    [ ${#devs[@]} -gt 0 ] && cp "${devs[@]}" "$profile_dir/" 2>/dev/null
    
    # 2. Save Proxy Configs
    local proxies=("${STORAGE_NET_DIR}"/proxy-*.conf)
    [ ${#proxies[@]} -gt 0 ] && cp "${proxies[@]}" "$profile_dir/" 2>/dev/null
    
    [ -f "${STORAGE_PROXY_GLOBAL}" ] && cp "${STORAGE_PROXY_GLOBAL}" "$profile_dir/proxy.conf"
    
    # 3. Save WiFi Country
    [ -f "${STORAGE_COUNTRY_FILE}" ] && cp "${STORAGE_COUNTRY_FILE}" "$profile_dir/country"
    
    # 4. Save DNS/Resolved specific overrides if any
    if [ -d "${STORAGE_RESOLVED_DIR}" ]; then
        mkdir -p "$profile_dir/resolved.conf.d"
        local res_confs=("${STORAGE_RESOLVED_DIR}"/*.conf)
        [ ${#res_confs[@]} -gt 0 ] && cp "${res_confs[@]}" "$profile_dir/resolved.conf.d/" 2>/dev/null
    fi

    # 5. Save WiFi Credentials (IWD)
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
    
    # 1. Wipe current active configuration (Strict State Switch)
    find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
    find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
    find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
    rm -f "${STORAGE_PROXY_GLOBAL}"
    
    # 2. Wipe active WiFi credentials
    if [ -d "$iwd_dir" ]; then
        find "$iwd_dir" -maxdepth 1 -type f -name "*.psk" -delete
        find "$iwd_dir" -maxdepth 1 -type f -name "*.8021x" -delete
    fi
    
    # 3. Restore Network Configs from Profile
    local nets=("${profile_dir}"/*.network)
    [ ${#nets[@]} -gt 0 ] && cp "${nets[@]}" "${STORAGE_NET_DIR}/" 2>/dev/null
    
    local devs=("${profile_dir}"/*.netdev)
    [ ${#devs[@]} -gt 0 ] && cp "${devs[@]}" "${STORAGE_NET_DIR}/" 2>/dev/null
    
    local proxies=("${profile_dir}"/proxy-*.conf)
    [ ${#proxies[@]} -gt 0 ] && cp "${proxies[@]}" "${STORAGE_NET_DIR}/" 2>/dev/null
    
    if [ -f "$profile_dir/proxy.conf" ]; then
        cp "$profile_dir/proxy.conf" "${STORAGE_PROXY_GLOBAL}"
    fi
    
    if [ -f "$profile_dir/country" ]; then
        cp "$profile_dir/country" "${STORAGE_COUNTRY_FILE}"
        local code
        read -r code < "${STORAGE_COUNTRY_FILE}"
        if command -v iw >/dev/null; then iw reg set "$code" 2>/dev/null || true; fi
    fi
    
    if [ -d "$profile_dir/resolved.conf.d" ]; then
        find "${STORAGE_RESOLVED_DIR}" -maxdepth 1 -type f -name "*.conf" -delete 2>/dev/null
        local res_confs=("${profile_dir}/resolved.conf.d"/*.conf)
        [ ${#res_confs[@]} -gt 0 ] && cp "${res_confs[@]}" "${STORAGE_RESOLVED_DIR}/" 2>/dev/null
    fi

    # 4. Restore WiFi Credentials
    if [ -d "$profile_dir/wifi" ]; then
        mkdir -p "$iwd_dir"
        local psks=("${profile_dir}/wifi"/*.psk)
        [ ${#psks[@]} -gt 0 ] && cp "${psks[@]}" "$iwd_dir/" 2>/dev/null
        
        local eaps=("${profile_dir}/wifi"/*.8021x)
        [ ${#eaps[@]} -gt 0 ] && cp "${eaps[@]}" "$iwd_dir/" 2>/dev/null
        
        chmod 600 "$iwd_dir"/*.psk 2>/dev/null || true
        chmod 600 "$iwd_dir"/*.8021x 2>/dev/null || true
    fi
    
    # 5. Apply
    reload_networkd
    if command -v systemctl >/dev/null; then
        systemctl try-reload-or-restart systemd-resolved 2>/dev/null || true
    fi
}

# --- MAIN ACTION ---

action_profile() {
    local cmd="$1"; local name="$2"; local iface="$3"; local file_path="$4"
    
    ensure_dirs
    
    # --- GLOBAL PROFILE (No Interface Specified) ---
    if [ -z "$iface" ]; then
        local global_dir="${STORAGE_PROFILES_DIR}/global"
        mkdir -p "$global_dir"
        
        case "$cmd" in
            save)
                [ -z "$name" ] && { json_error "Profile name required"; return 1; }
                confirm_action "Overwrite existing global profile '$name'?" "$FORCE_ACTION"
                _task_profile_save_global "$name"
                json_success '{"action": "saved_global", "name": "'"$name"'"}'
                ;;
            load)
                [ -z "$name" ] && { json_error "Profile name required"; return 1; }
                
                # Implicit "Default" / Reset handling
                if [ "$name" == "default" ] && [ ! -d "$global_dir/default" ]; then
                     confirm_action "Reset network configuration to system defaults?" "$FORCE_ACTION"
                     # Wipe settings only
                     find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
                     find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
                     find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
                     rm -f "${STORAGE_PROXY_GLOBAL}"
                     # Clean resolved
                     find "${STORAGE_RESOLVED_DIR}" -maxdepth 1 -type f -name "*.conf" -delete 2>/dev/null
                     
                     reload_networkd
                     json_success '{"action": "loaded_default", "note": "reset_config_kept_wifi"}'
                     return 0
                fi

                [ ! -d "$global_dir/$name" ] && { json_error "Profile not found: $name"; return 1; }
                confirm_action "Load global profile '$name' (will overwrite current config)?" "$FORCE_ACTION"
                _task_profile_load_global "$name"
                json_success '{"action": "loaded_global", "name": "'"$name"'"}'
                ;;
            list)
                local files=()
                for f in "$global_dir"/*; do
                    [ -d "$f" ] && files+=("$(basename "$f")")
                done
                if [ ! -d "$global_dir/default" ]; then
                    files+=("default (system)")
                fi
                
                local json_list="[]"
                if [ ${#files[@]} -gt 0 ]; then
                    json_list=$(printf '%s\n' "${files[@]}" | jq -R . | jq -s .)
                fi
                json_success '{"profiles": '"$json_list"', "scope": "global"}'
                ;;
            delete)
                [ -z "$name" ] && { json_error "Profile name required"; return 1; }
                if [ -d "$global_dir/$name" ]; then
                    confirm_action "Delete global profile '$name'?" "$FORCE_ACTION"
                    rm -rf "$global_dir/$name"
                    json_success '{"action": "deleted", "name": "'"$name"'"}'
                else
                    json_error "Profile not found"
                fi
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
        esac
        return 0
    fi

    # --- INTERFACE SPECIFIC PROFILE ---
    local profile_iface_dir="${STORAGE_PROFILES_DIR}/${iface}"
    mkdir -p "$profile_iface_dir"
    local active_cfg="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local profile_path="${profile_iface_dir}/${name}.network"

    case "$cmd" in
        save)
            [ -z "$name" ] && return 1
            [ ! -f "$active_cfg" ] && { json_error "No active config to save for $iface"; return 1; }
            cp "$active_cfg" "$profile_path"
            json_success '{"action": "saved", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        load)
            [ ! -f "$profile_path" ] && { json_error "Profile not found"; return 1; }
            confirm_action "Load profile '$name' on interface '$iface'?" "$FORCE_ACTION"
            cp "$profile_path" "$active_cfg"
            reconfigure_iface "$iface"
            json_success '{"action": "loaded", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        list)
            local files=("${profile_iface_dir}"/*.network)
            local clean_files=()
            if [ ${#files[@]} -gt 0 ] && [ -e "${files[0]}" ]; then
                 for f in "${files[@]}"; do
                    clean_files+=("$(basename "$f" .network)")
                 done
            fi
            
            local json_list="[]"
            if [ ${#clean_files[@]} -gt 0 ]; then
                json_list=$(printf '%s\n' "${clean_files[@]}" | jq -R . | jq -s .)
            fi
            json_success '{"profiles": '"$json_list"', "scope": "'"$iface"'"}'
            ;;
        delete)
             [ -f "$profile_path" ] && rm -f "$profile_path"
            json_success '{"action": "deleted", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
    esac
}
