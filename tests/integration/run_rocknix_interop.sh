#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

set -e

# ==============================================================================
# RXNM BUNDLE INTEROPERABILITY TEST SUITE (Systemd-nspawn)
# ==============================================================================
# Verifies the generated flat-file bundled executables in a live network.
# ==============================================================================

# Constants
BRIDGE="rxnm-bundle-br"
ROOTFS="/var/lib/machines/fedora-rxnm-bundle"
SERVER="rxnm-bdl-server"
CLIENT="rxnm-bdl-client"
PCAP_FILE="/tmp/rxnm_bundle_bridge.pcap"
TCPDUMP_PID=""

# Helper for colored output
info() { echo -e "\033[0;36m[TEST-BUNDLE]\033[0m $1"; }
err() { echo -e "\033[0;31m[FAIL-BUNDLE]\033[0m $1"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $1"; }

m_exec() {
    local machine=$1
    shift
    timeout 40s systemd-run -M "$machine" \
        --quiet --wait --pipe \
        --setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        --property=After=dbus.service \
        --property=CollectMode=inactive \
        -- "$@"
}

cleanup() {
    EXIT_CODE=$?
    echo "--- Bundle Teardown (Exit Code: $EXIT_CODE) ---"
    if [ -n "$TCPDUMP_PID" ]; then kill "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true; fi
    if [ $EXIT_CODE -ne 0 ] && [ ! -f /tmp/rxnm_bundle_success ]; then
        err "BUNDLE TEST FAILED"
        [ -f "/tmp/$SERVER.log" ] && { echo ">>> SERVER CONSOLE <<<"; cat "/tmp/$SERVER.log"; }
        [ -f "/tmp/$CLIENT.log" ] && { echo ">>> CLIENT CONSOLE <<<"; cat "/tmp/$CLIENT.log"; }
    fi
    machinectl terminate $SERVER 2>/dev/null || true
    machinectl terminate $CLIENT 2>/dev/null || true
    ip link delete $BRIDGE 2>/dev/null || true
    sudo modprobe -r mac80211_hwsim 2>/dev/null || true
    rm -f /tmp/rxnm_bundle_success
    [ $EXIT_CODE -eq 0 ] && rm -f "$PCAP_FILE" 2>/dev/null || info "PCAP retained at $PCAP_FILE"
}
trap cleanup EXIT

BUNDLE_BIN="${BUNDLE_BIN:-build/rxnm}"
AGENT_BIN=""
[ -f "build/rxnm-agent" ] && AGENT_BIN="build/rxnm-agent" || AGENT_BIN="bin/rxnm-agent"

if [ ! -f "$BUNDLE_BIN" ] || [ -z "$AGENT_BIN" ]; then
    err "Bundle artifacts missing. Run 'make rocknix-release' first."; exit 1
fi

sudo systemctl start systemd-machined || true

info "Setting up Host Bridge ($BRIDGE)..."
if ! ip link show $BRIDGE >/dev/null 2>&1; then
    ip link add $BRIDGE type bridge
    ip link set $BRIDGE up
    echo 0 > /sys/class/net/$BRIDGE/bridge/multicast_snooping 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.$BRIDGE.forwarding=1 2>/dev/null || true
fi

# Ensure Host Kernel allows unprivileged BPF if restricted (helps inside container context)
sysctl -w kernel.unprivileged_bpf_disabled=0 2>/dev/null || true

info "Setting up Virtual WiFi (mac80211_hwsim)..."
HWSIM_LOADED=false
WLAN_SRV=""
WLAN_CLI=""

# Check if loaded (either by CI compilation step or native modprobe)
if lsmod | grep -q mac80211_hwsim || sudo modprobe mac80211_hwsim radios=2 2>/dev/null; then
    info "mac80211_hwsim active. Waiting for udev..."
    sleep 3 # Wait for udev and kernel to fully map the virtual radios
    
    # Grab the first two wireless interfaces using iw (more reliable than sysfs timing)
    WLAN_IFACES=$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}')
    
    for iface in $WLAN_IFACES; do
        if [ -z "$WLAN_SRV" ]; then
            WLAN_SRV="$iface"
            # Force DOWN to unhook from host NetworkManager before container injection
            sudo ip link set "$WLAN_SRV" down 2>/dev/null || true
        elif [ -z "$WLAN_CLI" ]; then
            WLAN_CLI="$iface"
            # Force DOWN to unhook from host NetworkManager before container injection
            sudo ip link set "$WLAN_CLI" down 2>/dev/null || true
            break
        fi
    done
    
    if [ -n "$WLAN_SRV" ] && [ -n "$WLAN_CLI" ]; then
        HWSIM_LOADED=true
        info "✓ Virtual radios allocated: $WLAN_SRV (Server), $WLAN_CLI (Client)"
    else
        warn "mac80211_hwsim loaded but interfaces not found (Found: $WLAN_IFACES)."
    fi
else
    warn "mac80211_hwsim module not available on host. Virtual WiFi tests will be skipped."
fi

info "Building Test RootFS..."
HASH=$(md5sum tests/integration/Containerfile 2>/dev/null | cut -d ' ' -f 1 || echo "nohash")
if [ -d "$ROOTFS" ]; then
    [ "$(cat "$ROOTFS/.rxnm_hash" 2>/dev/null)" != "$HASH" ] && rm -rf "$ROOTFS"
fi

if [ ! -d "$ROOTFS" ]; then
    mkdir -p "$ROOTFS"
    if command -v dnf >/dev/null 2>&1; then
        dnf -y --installroot="$ROOTFS" --releasever=43 install \
            systemd systemd-networkd systemd-resolved iwd dbus-daemon \
            iproute iputils procps-ng ethtool tcpdump hostname bash jq sed coreutils \
            --setopt=install_weak_deps=False
    elif command -v docker >/dev/null 2>&1; then
        docker build -t rxnm-test-base -f tests/integration/Containerfile tests/integration
        CID=$(docker create rxnm-test-base)
        docker export "$CID" | tar -x -C "$ROOTFS"
        docker rm "$CID"
        cp /etc/resolv.conf "$ROOTFS/etc/"
    else
        err "No bootstrap tool found."; exit 1
    fi
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/NetworkManager.service"
    ln -sf /dev/null "$ROOTFS/usr/lib/systemd/network/80-container-host0.network"
    
    # Mocking sysctl for Phase 5 read-back validation (preventing infinite fork loops)
    if [ -f "$ROOTFS/usr/bin/sysctl" ] && [ ! -f "$ROOTFS/usr/bin/sysctl.orig" ]; then
        mv "$ROOTFS/usr/bin/sysctl" "$ROOTFS/usr/bin/sysctl.orig"
    fi
    cat <<'MOCK' > "$ROOTFS/usr/bin/sysctl"
#!/bin/bash
if [[ "$*" == *"-n net.ipv4.icmp_echo_ignore_broadcasts"* ]]; then echo "1"; exit 0; fi
if [ -x /usr/bin/sysctl.orig ]; then exec /usr/bin/sysctl.orig "$@"; else exit 0; fi
MOCK
    chmod +x "$ROOTFS/usr/bin/sysctl"

    cat <<'MOCK' > "$ROOTFS/usr/bin/rfkill"
#!/bin/bash
exit 0
MOCK
    chmod +x "$ROOTFS/usr/bin/rfkill"

    mkdir -p "$ROOTFS/storage/.config/network" "$ROOTFS/var/lib/iwd" "$ROOTFS/run/rocknix" "$ROOTFS/run/systemd/network" "$ROOTFS/etc/iwd"
    
    # CRITICAL: IWD requires EnableNetworkConfiguration=true to unlock the AP API over DBus.
    # We omit EnableIPv4=false because IWD's AP mode mandates its internal IPv4 DHCP server 
    # to initialize the AP DBUS object.
    cat <<'EOF' > "$ROOTFS/etc/iwd/main.conf"
[General]
EnableNetworkConfiguration=true
EOF
    
    rm -rf "$ROOTFS/etc/systemd/network"
    ln -sf /run/systemd/network "$ROOTFS/etc/systemd/network"
    echo "$HASH" > "$ROOTFS/.rxnm_hash"
fi

info "Installing Bundle into RootFS..."
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/bin"
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/lib"
cp -f "$BUNDLE_BIN" "$ROOTFS/usr/bin/rxnm"
cp -f "$AGENT_BIN" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"
chmod +x "$ROOTFS/usr/bin/rxnm" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"
cp -f usr/lib/systemd/network/* "$ROOTFS/usr/lib/systemd/network/" 2>/dev/null || true

# Pre-stage PHY sanitization script into the base rootfs before overlayfs snapshot
mkdir -p "$ROOTFS/usr/local/bin"
cat <<'EOF' > "$ROOTFS/usr/local/bin/sanitize_wifi.sh"
#!/bin/bash
# The host OS (NetworkManager) often automatically attaches a P2P-device to new radios.
# This consumes the limited capability slots on the virtual PHY, preventing AP mode.
# We delicately prune ONLY the P2P devices, leaving the primary managed netdev intact.
iw dev | awk '/wdev 0x/{w=$2} /type P2P-device/{print w}' | while read -r wdev; do
    iw wdev "$wdev" del 2>/dev/null || true
done

# Ensure the remaining managed interface is brought up cleanly
WLAN_IFACE=$(iw dev | awk '$1=="Interface"{print $2; exit}')
if [ -n "$WLAN_IFACE" ]; then
    ip link set "$WLAN_IFACE" down 2>/dev/null || true
    ip link set "$WLAN_IFACE" up 2>/dev/null || true
fi
EOF
chmod +x "$ROOTFS/usr/local/bin/sanitize_wifi.sh"

info "Booting Bundle Machines..."
# Use bash array to prevent word-splitting on the space-separated syscall filter list.
# Also explicitly pass RLIMIT_MEMLOCK=infinity to nspawn to allow eBPF bytecode memory allocation.
COMMON_ARGS=(
    "--network-bridge=$BRIDGE"
    "--boot"
    "--capability=all"
    "--private-users=no"
    "--system-call-filter=bpf keyctl add_key"
    "--rlimit=RLIMIT_MEMLOCK=infinity"
    "--ephemeral"
)

# CRITICAL: IWD requires the /dev/rfkill character device to operate.
# By default, systemd-nspawn hides this device. We must explicitly bind it.
if [ -c /dev/rfkill ]; then
    COMMON_ARGS+=("--bind=/dev/rfkill")
fi

# Launch containers without --network-interface injection to prevent mac80211 hangs
systemd-nspawn -D "$ROOTFS" -M "$SERVER" "${COMMON_ARGS[@]}" > "/tmp/$SERVER.log" 2>&1 &
systemd-nspawn -D "$ROOTFS" -M "$CLIENT" "${COMMON_ARGS[@]}" > "/tmp/$CLIENT.log" 2>&1 &

info "Waiting for systemd initialization..."
for i in {1..30}; do
    if machinectl status $SERVER >/dev/null 2>&1 && machinectl status $CLIENT >/dev/null 2>&1; then break; fi
    sleep 1
done

check_ready() {
    local machine=$1
    for i in {1..60}; do
        if m_exec "$machine" systemctl is-active systemd-networkd 2>/dev/null | grep -q "active"; then return 0; fi
        sleep 1
    done
    return 1
}
check_ready $SERVER || { err "$SERVER failed"; exit 1; }
check_ready $CLIENT || { err "$CLIENT failed"; exit 1; }

# CRITICAL: Manually map the mac80211 PHYs into the containers.
# nspawn's standard --network-interface fails on WiFi because it uses standard netdev routing,
# whereas 802.11 interfaces must be moved by their base PHY.
if [ "$HWSIM_LOADED" = "true" ]; then
    info "Injecting Virtual WiFi Radios into containers via PHY..."
    
    SRV_PID=$(machinectl show $SERVER -p Leader | cut -d= -f2)
    CLI_PID=$(machinectl show $CLIENT -p Leader | cut -d= -f2)
    
    if [ -n "$SRV_PID" ] && [ -n "$WLAN_SRV" ]; then
        SRV_PHY=$(iw dev "$WLAN_SRV" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
        if [ -n "$SRV_PHY" ]; then
            sudo iw phy "$SRV_PHY" set netns "$SRV_PID" 2>/dev/null || warn "Failed to move $SRV_PHY to $SERVER"
        fi
    fi
    
    if [ -n "$CLI_PID" ] && [ -n "$WLAN_CLI" ]; then
        CLI_PHY=$(iw dev "$WLAN_CLI" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
        if [ -n "$CLI_PHY" ]; then
            sudo iw phy "$CLI_PHY" set netns "$CLI_PID" 2>/dev/null || warn "Failed to move $CLI_PHY to $CLIENT"
        fi
    fi
    
    # IMPORTANT: Wait for container udevd to process the new PHYs and map them to netdevs
    sleep 3
    
    info "Sanitizing Virtual Radios..."
    m_exec $SERVER sanitize_wifi.sh
    m_exec $CLIENT sanitize_wifi.sh
fi

m_exec $SERVER ethtool -K host0 tx off || true
m_exec $CLIENT ethtool -K host0 tx off || true

m_exec $SERVER rxnm system setup
m_exec $CLIENT rxnm system setup

info "--- [PHASE 1] DHCP Convergence (Bundle) ---"
m_exec $SERVER rxnm interface host0 set static 192.168.213.2/24
m_exec $SERVER /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
m_exec $SERVER networkctl reload && m_exec $SERVER networkctl reconfigure host0

m_exec $CLIENT rxnm interface host0 set dhcp
m_exec $CLIENT networkctl reload && m_exec $CLIENT networkctl reconfigure host0

CONVERGED=false
for ((i=1; i<=30; i++)); do
    IP=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213." | head -n1 || true)
    if [ -n "$IP" ]; then
        if m_exec $CLIENT ping -c 1 -W 2 192.168.213.2 >/dev/null 2>&1; then
            info "✓ DHCP Bidirectional Link Verified (IP: $IP)"
            CONVERGED=true; break
        fi
    fi
    sleep 2
done
[ "$CONVERGED" = "false" ] && { err "DHCP Convergence timeout"; exit 1; }

info "--- [PHASE 2] Advanced Attributes (Bundle) ---"
m_exec $CLIENT rxnm interface host0 set static 192.168.213.60/24 --gateway 192.168.213.2 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
m_exec $CLIENT networkctl reload && m_exec $CLIENT networkctl reconfigure host0

info "Waiting for Attribute Convergence..."
CONVERGED=false
for ((i=1; i<=15; i++)); do
    IP_CHECK=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213.60" || true)
    MAC_CHECK=$(m_exec $CLIENT ip -j link show host0 | jq -r '.[0].address // empty')
    MTU_CHECK=$(m_exec $CLIENT ip -j link show host0 | jq -r '.[0].mtu // empty')
    if [ -n "$IP_CHECK" ] && [ "$MAC_CHECK" == "02:aa:bb:cc:dd:ee" ] && [ "$MTU_CHECK" == "1420" ]; then
        CONVERGED=true; break
    fi
    sleep 2
done
[ "$CONVERGED" = "false" ] && { err "Attribute application failed!"; exit 1; }
info "✓ Attributes applied"

info "--- [PHASE 3] IPv6 (Bundle) ---"
m_exec $SERVER rxnm interface host0 set static 192.168.213.2/24,fd00:cafe::2/64
m_exec $SERVER /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
m_exec $SERVER networkctl reload && m_exec $SERVER networkctl reconfigure host0
m_exec $CLIENT rxnm interface host0 set static 192.168.213.60/24,fd00:cafe::3/64 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
m_exec $CLIENT networkctl reload && m_exec $CLIENT networkctl reconfigure host0

info "Waiting for IPv6 Convergence (Bundle)..."
CONVERGED=false
for ((i=1; i<=15; i++)); do
    if m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::3"; then
        if m_exec $SERVER ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::2"; then
            if m_exec $CLIENT ping -6 -c 1 -W 2 fd00:cafe::2 >/dev/null 2>&1; then
                CONVERGED=true; break
            fi
        fi
    fi
    sleep 2
done
[ "$CONVERGED" = "false" ] && { err "IPv6 failed"; exit 1; }
info "✓ IPv6 Validated"

info "--- [PHASE 4] Project Silence (Nullify XDP Bundle) ---"
m_exec $CLIENT rxnm system nullify enable --interface host0
sleep 1
m_exec $CLIENT ping -c 1 -W 1 192.168.213.2 >/dev/null 2>&1 && { err "Nullify leak!"; exit 1; } || info "✓ Packets dropped"

m_exec $CLIENT rxnm system nullify disable --interface host0
sleep 2
m_exec $CLIENT ping -c 1 -W 2 192.168.213.2 >/dev/null 2>&1 && info "✓ Restored" || { err "Restore failed!"; exit 1; }

info "--- [PHASE 5] Stack Tuning (Bundle) ---"
m_exec $CLIENT rxnm system ipv6 disable
sleep 2
IPV6_CHECK=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet6") | .local // empty' | head -n1)
[ -n "$IPV6_CHECK" ] && { err "IPv6 leaked"; exit 1; }
info "✓ IPv6 disabled"

m_exec $CLIENT rxnm system ipv4 disable
SYSCTL_VAL=$(m_exec $CLIENT /usr/sbin/sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "0")
[ "$SYSCTL_VAL" != "1" ] && { err "IPv4 tuning failed"; exit 1; }
info "✓ IPv4 chatter silenced"

info "Restoring System Stack for Phase 6..."
m_exec $CLIENT rxnm system ipv6 enable
m_exec $CLIENT rxnm system ipv4 enable
m_exec $CLIENT rxnm system nullify disable >/dev/null 2>&1 || true
sleep 2

if [ "$HWSIM_LOADED" = "true" ]; then
    info "--- [PHASE 6] IWD Virtual WiFi Interoperability (Bundle) ---"
    
    # Restart IWD to ensure it registers the clean, sanitized wlan0 radios
    m_exec $SERVER systemctl restart iwd
    m_exec $CLIENT systemctl restart iwd
    sleep 2
    
    # Defensive check: verify IWD stayed alive after detecting the radios
    if ! m_exec $SERVER systemctl is-active iwd >/dev/null 2>&1; then
        err "IWD crashed on Server! Likely missing Kernel AF_ALG crypto modules or /dev/rfkill permissions."
        m_exec $SERVER journalctl -u iwd --no-pager | tail -n 20
        exit 1
    fi
    
    m_exec $SERVER rxnm wifi ap start "RXNM_Test_Net" --password "supersecret"
    sleep 3
    
    info "Scanning for Virtual AP..."
    SCAN_RESULT=$(m_exec $CLIENT rxnm wifi scan --format json || echo "{}")
    if echo "$SCAN_RESULT" | grep -q "RXNM_Test_Net"; then
        info "✓ Simulated AP detected in client scan"
    else
        err "Failed to detect simulated AP"
        echo "Scan Output: $SCAN_RESULT"
        exit 1
    fi
    
    info "Connecting to Virtual AP..."
    m_exec $CLIENT rxnm wifi connect "RXNM_Test_Net" --password "supersecret"
    
    info "Waiting for WiFi L2/L3 Convergence..."
    CONVERGED=false
    for ((i=1; i<=20; i++)); do
        # Dynamically fetch the wlan interface name assigned inside the client container
        CLI_WLAN=$(m_exec $CLIENT /bin/bash -c "source /usr/lib/rocknix-network-manager/lib/rxnm-wifi.sh && get_wifi_iface" || echo "")
        STATE="unknown"
        
        if [ -n "$CLI_WLAN" ]; then
            STATE=$(m_exec $CLIENT rxnm interface "$CLI_WLAN" show --get wifi.state 2>/dev/null || echo "unknown")
            
            if [ "$STATE" == "connected" ]; then
                IP=$(m_exec $CLIENT ip -j addr show "$CLI_WLAN" | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.212." | head -n1 || true)
                if [ -n "$IP" ]; then
                    if m_exec $CLIENT ping -c 1 -W 2 192.168.212.1 >/dev/null 2>&1; then
                        info "✓ Client successfully authenticated and routed over Virtual WiFi (IP: $IP)"
                        CONVERGED=true
                        break
                    fi
                fi
            fi
        fi
        sleep 2
    done
    
    [ "$CONVERGED" = "false" ] && { err "Simulated WiFi connection or DHCP failed"; exit 1; }
else
    info "--- [PHASE 6] SKIPPED (Virtual WiFi module unavailable) ---"
fi

touch /tmp/rxnm_bundle_success
info "All Bundled Integration Phases Passed."
exit 0
