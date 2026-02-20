#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: scripts/bundle.sh
# PURPOSE: Amalgamates RXNM into a single flat file for ROCKNIX deployment.
# -----------------------------------------------------------------------------

set -e

TARGET="build/rxnm"
mkdir -p build

echo "==> Building ROCKNIX Minimal Bundle at $TARGET..."

echo "#!/bin/sh" > "$TARGET"
echo "# SPDX-License-Identifier: GPL-2.0-or-later" >> "$TARGET"
echo "# Auto-generated bundled RXNM - ROCKNIX Minimal Edition" >> "$TARGET"
echo "" >> "$TARGET"

# Provide safe fallbacks for paths that still reference it (like plugins or schema)
echo "export LIB_DIR=\"/usr/lib/rocknix-network-manager/lib\"" >> "$TARGET"
echo "export RXNM_LIB_DIR=\"\${LIB_DIR}\"" >> "$TARGET"

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

for mod in $MODULES; do
    mod_path=$(echo "$mod" | tr -d ' \t\n')
    [ -z "$mod_path" ] && continue
    
    echo "" >> "$TARGET"
    echo "# --- MODULE: $mod_path ---" >> "$TARGET"
    
    # Strip unnecessary headers to save space and reduce parse time
    grep -v "^# SPDX-License-Identifier" "lib/$mod_path" | \
    grep -v "^# Copyright" | \
    grep -v "^#!/bin/sh" | \
    grep -v "^# shellcheck" >> "$TARGET"
done

echo "" >> "$TARGET"
echo "# --- MAIN DISPATCHER ---" >> "$TARGET"

# Strip the file-based bootstrapping logic from the main dispatcher
# and append the remaining code, patching out enterprise categories.
sed -n '/# --- GLOBAL VARIABLES & DEFAULTS ---/,$p' bin/rocknix-network-manager | \
awk '
/^\. "\$\{LIB_DIR\}/ { next } # Skip dynamic sourcing (functions are now inline)
/^CATS=/ {
    # Constrain available CLI commands to the Retro Core
    print "CATS=\"wifi interface bluetooth vpn tun tap system config api\""
    next
}
{ print }
' >> "$TARGET"

chmod +x "$TARGET"
echo "==> Done. Artifact size: $(du -h "$TARGET" | cut -f1)"
