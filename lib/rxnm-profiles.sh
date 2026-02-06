# ==============================================================================
# PROFILE MANAGEMENT
# ==============================================================================

_task_profile_load() {
    local iface="$1"
    local profile_path="$2"
    local active_cfg="$3"
    
    cp "$profile_path" "$active_cfg"
    reconfigure_iface "$iface"
}

action_profile() {
    local cmd="$1"; local name="$2"; local iface="$3"
    [ -z "$iface" ] && { json_error "Interface required"; return 1; }
    
    ensure_dirs
    local profile_iface_dir="${STORAGE_PROFILES_DIR}/${iface}"
    mkdir -p "$profile_iface_dir"
    
    local active_cfg="${STORAGE_NET_DIR}/75-config-${iface}.network"
    local profile_path="${profile_iface_dir}/${name}.network"

    case "$cmd" in
        save)
            [ -z "$name" ] && return 1
            [ ! -f "$active_cfg" ] && { json_error "No active config to save"; return 1; }
            cp "$active_cfg" "$profile_path"
            json_success '{"action": "saved", "name": "'"$name"'"}'
            ;;
        load)
            [ ! -f "$profile_path" ] && { json_error "Profile not found"; return 1; }
            with_iface_lock "$iface" _task_profile_load "$iface" "$profile_path" "$active_cfg"
            json_success '{"action": "loaded", "name": "'"$name"'"}'
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
            json_success '{"profiles": '"$json_list"'}'
            ;;
        delete)
            rm -f "$profile_path"
            json_success '{"action": "deleted", "name": "'"$name"'"}'
            ;;
    esac
}
