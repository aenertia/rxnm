# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-service.sh
# PURPOSE: Network Namespace Service Management (Experimental)
# ARCHITECTURE: SOA / Service
#
# Implements "Service" abstractions using Linux Network Namespaces.
# Used for isolating interfaces, creating VRF-lite topologies, and 
# testing virtual networks.
# -----------------------------------------------------------------------------

_check_service_prereqs() {
    if [ "${RXNM_EXPERIMENTAL:-false}" != "true" ]; then
        json_error "Service management is experimental. Set RXNM_EXPERIMENTAL=true to enable." "501" \
            "This feature is under active development. See 'rxnm api capabilities' for status."
        exit 1
    fi
}

action_service_create() {
    local name="$1"
    _check_service_prereqs
    [ -z "$name" ] && { json_error "Service name required"; exit 1; }
    
    # Try accelerated creation first (avoids fork overhead of ip netns add)
    if [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --ns-create "$name"; then
            # Bring up loopback (still requires iproute2 inside namespace context)
            if command -v ip >/dev/null; then
                ip netns exec "$name" ip link set lo up 2>/dev/null
            fi
            json_success '{"action": "service_create", "name": "'"$name"'", "status": "created"}'
            return 0
        fi
    fi
    
    # Fallback
    if command -v ip >/dev/null; then
        if ip netns add "$name"; then
            ip netns exec "$name" ip link set lo up
            json_success '{"action": "service_create", "name": "'"$name"'", "status": "created"}'
        else
            json_error "Failed to create service namespace '$name'"
        fi
    else
        json_error "Native agent failed and 'ip' command not found."
    fi
}

action_service_delete() {
    local name="$1"
    _check_service_prereqs
    [ -z "$name" ] && { json_error "Service name required"; exit 1; }
    
    if [ -x "$RXNM_AGENT_BIN" ]; then
        if "$RXNM_AGENT_BIN" --ns-delete "$name"; then
            json_success '{"action": "service_delete", "name": "'"$name"'", "status": "deleted"}'
            return 0
        fi
    fi
    
    if command -v ip >/dev/null; then
        if ip netns del "$name"; then
            json_success '{"action": "service_delete", "name": "'"$name"'", "status": "deleted"}'
        else
            json_error "Failed to delete service namespace '$name'"
        fi
    else
        json_error "Native agent failed and 'ip' command not found."
    fi
}

action_service_list() {
    _check_service_prereqs
    
    if [ -x "$RXNM_AGENT_BIN" ]; then
        local out
        if out=$("$RXNM_AGENT_BIN" --ns-list); then
            # Inject success key into agent output
            echo "$out" | "$JQ_BIN" '. + {success: true}'
            return 0
        fi
    fi
    
    if command -v ip >/dev/null; then
        local ns_list
        ns_list=$(ip netns list | awk '{print $1}')
        local json_arr="[]"
        if [ -n "$ns_list" ]; then
            json_arr=$(echo "$ns_list" | "$JQ_BIN" -R . | "$JQ_BIN" -s .)
        fi
        json_success "{\"services\": $json_arr}"
    else
        json_error "Cannot list services: Agent and iproute2 missing."
    fi
}

action_service_attach() {
    local service="$1"
    local iface="$2"
    _check_service_prereqs
    [ -z "$service" ] && { json_error "Service name required"; exit 1; }
    [ -z "$iface" ] && { json_error "Interface required"; exit 1; }
    
    # Check if interface exists in current namespace
    if [ ! -d "/sys/class/net/$iface" ]; then
        json_error "Interface '$iface' not found in current namespace"
        exit 1
    fi
    
    if command -v ip >/dev/null; then
        if ip link set "$iface" netns "$service"; then
            json_success '{"action": "service_attach", "service": "'"$service"'", "interface": "'"$iface"'"}'
        else
            json_error "Failed to attach interface to service"
        fi
    else
        json_error "iproute2 required for interface migration"
    fi
}

action_service_detach() {
    local service="$1"
    local iface="$2"
    _check_service_prereqs
    [ -z "$service" ] && { json_error "Service name required"; exit 1; }
    [ -z "$iface" ] && { json_error "Interface required"; exit 1; }
    
    if command -v ip >/dev/null; then
        if ip netns exec "$service" ip link set "$iface" netns 1; then
            json_success '{"action": "service_detach", "service": "'"$service"'", "interface": "'"$iface"'"}'
        else
            json_error "Failed to detach interface from service"
        fi
    else
        json_error "iproute2 required for interface migration"
    fi
}

action_service_exec() {
    local service="$1"
    shift
    local cmd="$@"
    _check_service_prereqs
    
    [ -z "$service" ] && { json_error "Service name required"; exit 1; }
    [ -z "$cmd" ] && { json_error "Command required"; exit 1; }
    
    if command -v ip >/dev/null; then
        ip netns exec "$service" $cmd
    else
        json_error "iproute2 required for exec"
    fi
}
