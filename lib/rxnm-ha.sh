# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-ha.sh
# PURPOSE: High Availability (BFD/VRRP) (Stub)
# ARCHITECTURE: SOA / HA
# -----------------------------------------------------------------------------

action_ha_dispatch() {
    if [ "${RXNM_EXPERIMENTAL:-false}" != "true" ]; then
        json_error "Feature 'ha' is experimental/planned. Set RXNM_EXPERIMENTAL=true to enable." "501" \
            "This feature is planned for v1.1. See 'rxnm api capabilities' for status."
        exit 1
    fi
    json_error "HA management not yet implemented." "501"
}
