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
    # We explicitly only backup files managed by RXNM or standard systemd-networkd extensions
    cp "${STORAGE_NET_DIR}"/*.network "$profile_dir/" 2>/dev/null
    cp "${STORAGE_NET_DIR}"/*.netdev "$profile_dir/" 2>/dev/null
    
    # 2. Save Proxy Configs
    cp "${STORAGE_NET_DIR}"/proxy-*.conf "$profile_dir/" 2>/dev/null
    [ -f "${STORAGE_PROXY_GLOBAL}" ] && cp "${STORAGE_PROXY_GLOBAL}" "$profile_dir/proxy.conf"
    
    # 3. Save WiFi Country
    [ -f "${STORAGE_COUNTRY_FILE}" ] && cp "${STORAGE_COUNTRY_FILE}" "$profile_dir/country"
    
    # 4. Save DNS/Resolved specific overrides if any
    if [ -d "${STORAGE_RESOLVED_DIR}" ]; then
        mkdir -p "$profile_dir/resolved.conf.d"
        cp "${STORAGE_RESOLVED_DIR}"/*.conf "$profile_dir/resolved.conf.d/" 2>/dev/null
    fi

    # 5. Save WiFi Credentials (IWD)
    # We backup known networks so the profile contains the keys required to connect.
    if [ -d "$iwd_dir" ]; then
        mkdir -p "$profile_dir/wifi"
        # Copy PSK (Personal) and 8021x (Enterprise) creds
        cp "$iwd_dir"/*.psk "$profile_dir/wifi/" 2>/dev/null
        cp "$iwd_dir"/*.8021x "$profile_dir/wifi/" 2>/dev/null
    fi

    return 0
}

_task_profile_load_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    local iwd_dir="${STATE_DIR}/iwd"
    
    # 1. Wipe current active configuration (Strict State Switch)
    # This removes the "User Overlay", briefly exposing System Defaults before the new profile is copied in.
    find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
    find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
    find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
    rm -f "${STORAGE_PROXY_GLOBAL}"
    
    # 2. Wipe active WiFi credentials
    # Profiles are strict snapshots. If I load "Work", I don't necessarily want "Home" keys active.
    if [ -d "$iwd_dir" ]; then
        find "$iwd_dir" -maxdepth 1 -type f -name "*.psk" -delete
        find "$iwd_dir" -maxdepth 1 -type f -name "*.8021x" -delete
    fi
    
    # 3. Restore Network Configs from Profile
    cp "$profile_dir"/*.network "${STORAGE_NET_DIR}/" 2>/dev/null
    cp "$profile_dir"/*.netdev "${STORAGE_NET_DIR}/" 2>/dev/null
    cp "$profile_dir"/proxy-*.conf "${STORAGE_NET_DIR}/" 2>/dev/null
    
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
        # Clean existing resolved confs
        find "${STORAGE_RESOLVED_DIR}" -maxdepth 1 -type f -name "*.conf" -delete 2>/dev/null
        cp "$profile_dir/resolved.conf.d"/*.conf "${STORAGE_RESOLVED_DIR}/" 2>/dev/null
    fi

    # 4. Restore WiFi Credentials
    if [ -d "$profile_dir/wifi" ]; then
        mkdir -p "$iwd_dir"
        cp "$profile_dir/wifi"/*.psk "$iwd_dir/" 2>/dev/null
        cp "$profile_dir/wifi"/*.8021x "$iwd_dir/" 2>/dev/null
        # Important: Restore secure permissions
        chmod 600 "$iwd_dir"/*.psk 2>/dev/null
        chmod 600 "$iwd_dir"/*.8021x 2>/dev/null
    fi
    
    # 5. Apply
    reload_networkd
    if command -v systemctl >/dev/null; then
        systemctl try-reload-or-restart systemd-resolved 2>/dev/null || true
    fi
    # IWD automatically detects new files, no restart needed typically, 
    # but strictly speaking, if we deleted connected creds, it might disconnect.
}

# --- MAIN ACTION ---

action_profile() {
    local cmd="$1"; local name="$2"; local iface="$3"
    
    ensure_dirs
    
    # --- GLOBAL PROFILE (No Interface Specified) ---
    if [ -z "$iface" ]; then
        local global_dir="${STORAGE_PROFILES_DIR}/global"
        mkdir -p "$global_dir"
        
        case "$cmd" in
            save)
                [ -z "$name" ] && { json_error "Profile name required"; return 1; }
                _task_profile_save_global "$name"
                json_success '{"action": "saved_global", "name": "'"$name"'"}'
                ;;
            load)
                [ -z "$name" ] && { json_error "Profile name required"; return 1; }
                
                # Implicit "Default" / Reset handling
                # If user loads "default" and it doesn't exist as a folder, we treat it as a factory reset.
                if [ "$name" == "default" ] && [ ! -d "$global_dir/default" ]; then
                     # Wipe settings only
                     find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
                     find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
                     find "${STORAGE_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
                     rm -f "${STORAGE_PROXY_GLOBAL}"
                     # Clean resolved
                     find "${STORAGE_RESOLVED_DIR}" -maxdepth 1 -type f -name "*.conf" -delete 2>/dev/null
                     
                     # NOTE: We do NOT wipe WiFi credentials on a "default" reset. 
                     # Users usually want to reset bad IP/DNS configs, not lose all passwords.
                     
                     reload_networkd
                     json_success '{"action": "loaded_default", "note": "reset_config_kept_wifi"}'
                     return 0
                fi

                [ ! -d "$global_dir/$name" ] && { json_error "Profile not found"; return 1; }
                
                _task_profile_load_global "$name"
                json_success '{"action": "loaded_global", "name": "'"$name"'"}'
                ;;
            list)
                local files=()
                for f in "$global_dir"/*; do
                    [ -d "$f" ] && files+=("$(basename "$f")")
                done
                # Add "default" as a virtual option if it doesn't exist explicitly
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
                [ -z "$name" ] && return 1
                if [ -d "$global_dir/$name" ]; then
                    rm -rf "$global_dir/$name"
                    json_success '{"action": "deleted", "name": "'"$name"'"}'
                else
                    json_error "Profile not found"
                fi
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
            # Helper for single load
            cp "$profile_path" "$active_cfg"
            reconfigure_iface "$iface"
            json_success '{"action": "loaded", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        list)
            local files=()
            for f in "$profile_iface_dir"/*.network; do
                [ -e "$f" ] && files+=("$(basename "$f" .network)")
            done
            local json_list="[]"
            if [ ${#files[@]} -gt 0 ]; then
                json_list=$(printf '%s\n' "${files[@]}" | jq -R . | jq -s .)
            fi
            json_success '{"profiles": '"$json_list"', "scope": "'"$iface"'"}'
            ;;
        delete)
            rm -f "$profile_path"
            json_success '{"action": "deleted", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
    esac
}
