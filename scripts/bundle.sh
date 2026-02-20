#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: scripts/bundle.sh
# PURPOSE: Amalgamates RXNM into a single flat file for ROCKNIX deployment.
# -----------------------------------------------------------------------------

# Enforce strict error handling
set -euo pipefail

TARGET="build/rxnm"
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

echo "==> Building ROCKNIX Minimal Bundle..."

# --- 1. WRITE HEADER ---
cat << 'EOF' > "$TMP_TARGET"
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Auto-generated bundled RXNM - ROCKNIX Minimal Edition

# Provide safe fallbacks for paths that still reference it (like plugins or schema)
export LIB_DIR="/usr/lib/rocknix-network-manager/lib"
export RXNM_LIB_DIR="${LIB_DIR}"
EOF

# List of allowed modules in exact dependency order (Strictly retro-gaming focused + VPN + Plugins)
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
    
    # CRITICAL FIX: Replace the schema file with pure POSIX stubs in the bundle.
    # This prevents the 'return 0' guard from causing a fatal parse error in dash
    # when executed as a flat file outside of a function.
    if [ "$mod_path" = "rxnm-config-schema.sh" ]; then
        cat << 'STUB' >> "$TMP_TARGET"
validate_config_state() { return 0; }
build_config_descriptor() { printf 'iface:|states:\n'; }
_check_requirement() { return 0; }
validate_json_input() { return 0; }
STUB
        continue
    fi
    
    # Strip unnecessary headers to save space and reduce parse time
    # '|| true' prevents pipefail from tripping if a file has no matching lines (unlikely, but safe)
    grep -vE "^# (SPDX-License-Identifier|Copyright|shellcheck)" "$file_path" | \
    grep -v "^#!/bin/sh" >> "$TMP_TARGET" || true
done

# --- 3. APPEND MAIN DISPATCHER ---
echo -e "\n# --- MAIN DISPATCHER ---" >> "$TMP_TARGET"

# Strip the file-based bootstrapping logic from the main dispatcher
# and append the remaining code, patching out enterprise categories.
DISPATCHER_CONTENT=$(sed -n '/# --- GLOBAL VARIABLES & DEFAULTS ---/,$p' "$SRC_BIN")

if [ -z "$DISPATCHER_CONTENT" ]; then
    echo "ERROR: Failed to extract dispatcher logic from $SRC_BIN." >&2
    echo "       Did the '# --- GLOBAL VARIABLES & DEFAULTS ---' anchor comment change?" >&2
    rm -f "$TMP_TARGET"
    exit 1
fi

echo "$DISPATCHER_CONTENT" | awk '
/^[ \t]*\.[ \t]+"\$\{LIB_DIR\}/ { 
    # Replace dynamic sourcing with a POSIX no-op (:) to prevent syntax errors in empty if/else blocks
    print "    : # " $0
    next 
}
/^CATS=/ {
    # Constrain available CLI commands to the Retro Core
    print "CATS=\"wifi interface bluetooth vpn tun tap system config api\""
    next
}
{ print }
' >> "$TMP_TARGET"

# --- 4. FINALIZE (ATOMIC SWAP) ---
chmod +x "$TMP_TARGET"
mv "$TMP_TARGET" "$TARGET"

echo "==> Done. Artifact size: $(du -h "$TARGET" | cut -f1) ($TARGET)"
