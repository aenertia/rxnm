# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-profiles.sh
# PURPOSE: Persistence & Profile Management
# ARCHITECTURE: Logic / Profiles
#
# Saves and loads network configurations. Refactored for POSIX compliance.
# -----------------------------------------------------------------------------

_sync_active_configs() {
    local src_dir="$1" dest_dir="$2"
    
    # POSIX safe glob iteration and copy
    for ext in netdev network link conf; do
        # Use simple globbing check
        # shellcheck disable=SC2044
        for f in "${src_dir}"/*."${ext}"; do
            if [ -e "$f" ]; then
                cp "${src_dir}"/*."${ext}" "${dest_dir}/" 2>/dev/null
                break
            fi
        done
    done
}

_task_profile_save_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    
    # H-5 FIX: Validate the directory prefix to prevent rm -rf /global/* if $STORAGE_PROFILES_DIR is empty
    case "$profile_dir" in
        "${STORAGE_PROFILES_DIR}/"*) ;;
        *) 
            log_error "Safety Guard: Invalid profile directory path '$profile_dir'"
            return 1 
            ;;
    esac
    
    local iwd_dir="${STATE_DIR}/iwd"
    
    rm -rf "${profile_dir:?}/"
    mkdir -p "$profile_dir"
    
    _sync_active_configs "${EPHEMERAL_NET_DIR}" "${profile_dir}"
    
    [ -f "${STORAGE_PROXY_GLOBAL}" ] && cp "${STORAGE_PROXY_GLOBAL}" "$profile_dir/proxy.conf"
    [ -f "${STORAGE_COUNTRY_FILE}" ] && cp "${STORAGE_COUNTRY_FILE}" "$profile_dir/country"
    
    if [ -d "${STORAGE_RESOLVED_DIR}" ]; then
        mkdir -p "$profile_dir/resolved.conf.d"
        for f in "${STORAGE_RESOLVED_DIR}"/*.conf; do
            [ -e "$f" ] && cp "$f" "$profile_dir/resolved.conf.d/"
        done
    fi
    
    if [ -d "$iwd_dir" ]; then
        mkdir -p "$profile_dir/wifi"
        for f in "${iwd_dir}"/*.psk "${iwd_dir}"/*.8021x; do
            [ -e "$f" ] && cp "$f" "$profile_dir/wifi/"
        done
    fi
    
    return 0
}

_task_profile_load_global() {
    local name="$1"
    local profile_dir="${STORAGE_PROFILES_DIR}/global/${name}"
    local iwd_dir="${STATE_DIR}/iwd"
    
    # PROACTIVE FIX: Secure temporary directories instead of predictable PID ($$) paths
    local staging_dir
    staging_dir=$(umask 077 && mktemp -d "${RUN_DIR}/profile_staging_XXXXXX") || return 1
    
    _sync_active_configs "${profile_dir}" "${staging_dir}"
    
    # H-4 FIX: Verify staging successfully populated BEFORE wiping the live network configuration.
    # Prevents total network loss if out of space or profile is empty.
    local has_files="false"
    for f in "$staging_dir"/*; do
        if [ -e "$f" ]; then has_files="true"; break; fi
    done
    
    if [ "$has_files" = "false" ] && [ "$name" != "default" ]; then
        rm -rf "$staging_dir"
        log_error "Profile is empty or sync failed. Aborted to prevent network loss."
        return 1
    fi
    
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.link" -delete
    find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "proxy-*.conf" -delete
    
    if [ -d "$staging_dir" ]; then
        # POSIX safe move content
        for f in "$staging_dir"/*; do
            [ -e "$f" ] && mv -f "$f" "${EPHEMERAL_NET_DIR}/"
        done
        rm -rf "$staging_dir"
    fi
    
    [ -f "$profile_dir/proxy.conf" ] && cp "$profile_dir/proxy.conf" "${STORAGE_PROXY_GLOBAL}"
    
    if [ -f "$profile_dir/country" ]; then
        cp "$profile_dir/country" "${STORAGE_COUNTRY_FILE}"
        local code; read -r code < "${STORAGE_COUNTRY_FILE}"
        if command -v iw >/dev/null; then [ -n "$code" ] && iw reg set "$code" 2>/dev/null || true; fi
    fi
    
    if [ -d "$profile_dir/wifi" ]; then
        mkdir -p "$iwd_dir"
        for f in "${profile_dir}/wifi"/*.psk "${profile_dir}/wifi"/*.8021x; do
            if [ -e "$f" ]; then
                cp "$f" "$iwd_dir/"
                chmod 600 "$iwd_dir/${f##*/}" 2>/dev/null || true
            fi
        done
    fi
    
    reload_networkd
}

action_profile() {
    local cmd="${1:-}" name="${2:-}" iface="${3:-}"
    
    if [ "$cmd" = "save" ] || [ "$cmd" = "load" ]; then
        [ -z "$name" ] && name="default"
    fi
    ensure_dirs
    
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
                if [ "$name" = "default" ] && [ ! -d "$global_dir/default" ]; then
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
                local _pnames=""
                for f in "$global_dir"/*; do
                    [ -d "$f" ] && _pnames="${_pnames}${f##*/} "
                done
                [ ! -d "$global_dir/default" ] && _pnames="${_pnames}default "
                
                local json_list="[]"
                if [ -n "$_pnames" ]; then
                    # shellcheck disable=SC2086
                    json_list=$(printf '%s\n' $_pnames | sort -u | "$JQ_BIN" -R . | "$JQ_BIN" -s .)
                fi
                json_success '{"profiles": '"$json_list"', "scope": "global"}'
                ;;
            boot)
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.network" -delete
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.netdev" -delete
                find "${EPHEMERAL_NET_DIR}" -maxdepth 1 -type f -name "*.link" -delete
                
                if [ -d "$global_dir/default" ]; then
                    _sync_active_configs "$global_dir/default" "${EPHEMERAL_NET_DIR}"
                fi
                _sync_active_configs "${PERSISTENT_NET_DIR}" "${EPHEMERAL_NET_DIR}"
                ;;
        esac
        return 0
    fi
    
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
            if [ ! -f "$active_cfg" ] && [ ! -f "$active_link" ]; then json_error "No active config to save for $iface"; return 1; fi
            [ -f "$active_cfg" ] && cp "$active_cfg" "$profile_path"
            [ -f "$active_link" ] && cp "$active_link" "$profile_link"
            [ -f "$active_proxy" ] && cp "$active_proxy" "$profile_proxy"
            json_success '{"action": "saved", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        load)
            if [ ! -f "$profile_path" ] && [ ! -f "$profile_link" ]; then json_error "Profile not found"; return 1; fi
            [ -f "$profile_path" ] && cp "$profile_path" "$active_cfg"
            [ -f "$profile_link" ] && cp "$profile_link" "$active_link"
            if [ -f "$profile_proxy" ]; then cp "$profile_proxy" "$active_proxy"; else rm -f "$active_proxy"; fi
            reconfigure_iface "$iface"
            json_success '{"action": "loaded", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
        list)
            local _cf=""
            for f in "${profile_iface_dir}"/*.network "${profile_iface_dir}"/*.link; do
                [ -e "$f" ] && _cf="${_cf}${f##*/} "
            done
            local json_list="[]"
            if [ -n "$_cf" ]; then
                # shellcheck disable=SC2086
                json_list=$(printf '%s\n' $_cf | sed 's/\.network//;s/\.link//' | sort -u | "$JQ_BIN" -R . | "$JQ_BIN" -s .)
            fi
            json_success '{"profiles": '"$json_list"', "scope": "'"$iface"'"}'
            ;;
        delete)
            rm -f "$profile_path" "$profile_link" "$profile_proxy"
            json_success '{"action": "deleted", "name": "'"$name"'", "iface": "'"$iface"'"}'
            ;;
    esac
}
