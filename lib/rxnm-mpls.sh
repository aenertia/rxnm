# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-mpls.sh
# PURPOSE: MPLS Label Switching (Stub)
# ARCHITECTURE: SOA / MPLS
# -----------------------------------------------------------------------------

action_mpls_dispatch() {
    if [ "${RXNM_EXPERIMENTAL:-false}" != "true" ]; then
        json_error "Feature 'mpls' is experimental/planned. Set RXNM_EXPERIMENTAL=true to enable." "501" \
            "This feature is planned for v1.1. See 'rxnm api capabilities' for status."
        exit 1
    fi
    json_error "MPLS management not yet implemented." "501"
}
