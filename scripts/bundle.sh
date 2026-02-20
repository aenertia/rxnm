#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: scripts/bundle.sh
# PURPOSE: Amalgamates RXNM into a single flat file for deployments.
# -----------------------------------------------------------------------------

# Enforce strict error handling
set -euo pipefail

BUNDLE_MODE="${BUNDLE_MODE:-minimal}"

TARGET="build/rxnm"
if [ "$BUNDLE_MODE" = "full" ]; then
    TARGET="build/rxnm-full"
fi

TMP_TARGET="${TARGET}.tmp"
SRC_BIN="bin/rxnm"
SRC_LIB="lib"

# --- PRE-FLIGHT CHECKS ---
if [ ! -f "$SRC_BIN" ]; then
    echo "ERROR: Dispatcher script not found at $SRC_BIN. Run from repository root." >&2
    exit 1
fi

if [ ! -d "$SRC_LIB" ]; then
    echo "ERROR: Library directory not found at $SRC_LIB. Run from repository root." >&2
    exit 1
fi

mkdir -p build
rm -f "$TMP_TARGET"

if [ "$BUNDLE_MODE" = "full" ]; then
    echo "==> Building RXNM Full Combined Edition..."
else
    echo "==> Building ROCKNIX Minimal Bundle..."
fi

# --- 1. WRITE HEADER ---
cat << 'EOF' > "$TMP_TARGET"
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Auto-generated bundled RXNM

# Provide safe fallbacks for paths that still reference it (like plugins or schema)
export LIB_DIR="/usr/lib/rocknix-network-manager/lib"
export RXNM_LIB_DIR="${LIB_DIR}"
EOF

# List of allowed modules in exact dependency order
MODULES="
rxnm-constants.sh
rxnm-utils.sh
rxnm-system.sh
rxnm-help.sh
rxnm-plugins.sh
rxnm-config-schema.sh
rxnm-config-builder.sh
rxnm-templates.sh
rxnm-diagnostics.sh
rxnm-interfaces.sh
rxnm-wifi.sh
rxnm-roaming.sh
rxnm-nullify.sh
rxnm-vpn.sh
rxnm-bluetooth.sh
"

if [ "$BUNDLE_MODE" = "full" ]; then
    MODULES="${MODULES}
rxnm-api.sh
rxnm-profiles.sh
rxnm-virt.sh
rxnm-routes.sh
rxnm-service.sh
rxnm-tunnel.sh
rxnm-mpls.sh
rxnm-pppoe.sh
rxnm-ha.sh
"
fi

# Helper function to neutralize dynamic sourcing for the bundle
neutralize_sourcing() {
    # Replaces . "${DIR}/file.sh" with a no-op to prevent runtime file-not-found errors
    awk '
    /^[ \t]*\.[ \t]+"\$\{(LIB_DIR|RXNM_LIB_DIR)\}/ { 
        print "    : # Bundled: " $0
        next 
    }
    { print }
    '
}

# --- 2. APPEND MODULES ---
for mod in $MODULES; do
    mod_path=$(echo "$mod" | tr -d ' \t\n')
    [ -z "$mod_path" ] && continue
    
    file_path="$SRC_LIB/$mod_path"
    if [ ! -f "$file_path" ]; then
        echo "ERROR: Required module missing: $file_path" >&2
        rm -f "$TMP_TARGET"
        exit 1
    fi
    
    echo -e "\n# --- MODULE: $mod_path ---" >> "$TMP_TARGET"
    
    # CRITICAL FIX 1: Replace the schema file with pure POSIX stubs in the bundle.
    if [ "$mod_path" = "rxnm-config-schema.sh" ]; then
        cat << 'STUB' >> "$TMP_TARGET"
validate_config_state() { return 0; }
build_config_descriptor() { printf 'iface:|states:\n'; }
_check_requirement() { return 0; }
validate_json_input() { return 0; }
STUB
        continue
    fi

    # CRITICAL FIX 2: Strip environment validation from rxnm-api.sh when bundling.
    if [ "$mod_path" = "rxnm-api.sh" ]; then
        # Start at format default to skip sourcing and derivation blocks entirely
        sed -n '/: "\${RXNM_FORMAT:=human}"/,$p' "$file_path" | \
            grep -vE "^# (SPDX-License-Identifier|Copyright|shellcheck)" | \
            neutralize_sourcing >> "$TMP_TARGET" || true
        continue
    fi
    
    # Strip unnecessary headers and neutralize internal sourcing
    grep -vE "^# (SPDX-License-Identifier|Copyright|shellcheck)" "$file_path" | \
    grep -v "^#!/bin/sh" | \
    neutralize_sourcing >> "$TMP_TARGET" || true
done

# --- 3. APPEND MAIN DISPATCHER ---
echo -e "\n# --- MAIN DISPATCHER ---" >> "$TMP_TARGET"

# Strip the file-based bootstrapping logic from the main dispatcher
# and append the remaining code, optionally patching out enterprise categories.
DISPATCHER_CONTENT=$(sed -n '/# --- GLOBAL VARIABLES & DEFAULTS ---/,$p' "$SRC_BIN")

if [ -z "$DISPATCHER_CONTENT" ]; then
    echo "ERROR: Failed to extract dispatcher logic from $SRC_BIN." >&2
    echo "       Did the '# --- GLOBAL VARIABLES & DEFAULTS ---' anchor comment change?" >&2
    rm -f "$TMP_TARGET"
    exit 1
fi

echo "$DISPATCHER_CONTENT" | awk -v mode="$BUNDLE_MODE" '
/^[ \t]*\.[ \t]+"\$\{(LIB_DIR|RXNM_LIB_DIR)\}/ { 
    # Replace dynamic sourcing with a POSIX no-op (:) to prevent syntax errors in empty if/else blocks
    print "    : # Bundled: " $0
    next 
}
/^CATS=/ {
    if (mode == "minimal") {
        # Constrain available CLI commands to the Retro Core
        print "CATS=\"wifi interface bluetooth vpn tun tap system config api\""
        next
    }
}
{ print }
' >> "$TMP_TARGET"

# --- 4. FINALIZE (ATOMIC SWAP) ---
chmod +x "$TMP_TARGET"
mv "$TMP_TARGET" "$TARGET"

echo "==> Done. Artifact size: $(du -h "$TARGET" | cut -f1) ($TARGET)"
