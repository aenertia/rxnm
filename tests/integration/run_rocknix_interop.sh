#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

set -e

# ==============================================================================
# RXNM ROCKNIX BUNDLE INTEROPERABILITY TEST SUITE (Systemd-nspawn)
# ==============================================================================
# Specifically tests the 'build/rxnm' flat-file bundled executable to ensure
# the amalgamation process didn't break core logic, and verifies that enterprise
# features were correctly stripped out.
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
    
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    
    if [ $EXIT_CODE -ne 0 ] && [ ! -f /tmp/rxnm_bundle_success ]; then
        err "BUNDLE TEST FAILED - DUMPING LOGS"
        [ -f "/tmp/$SERVER.log" ] && { echo ">>> SERVER CONSOLE <<<"; cat "/tmp/$SERVER.log"; }
        [ -f "/tmp/$CLIENT.log" ] && { echo ">>> CLIENT CONSOLE <<<"; cat "/tmp/$CLIENT.log"; }
    fi

    machinectl terminate $SERVER 2>/dev/null || true
    machinectl terminate $CLIENT 2>/dev/null || true
    
    ip link delete $BRIDGE 2>/dev/null || true
    rm -f /tmp/rxnm_bundle_success
    rm -f "$PCAP_FILE" 2>/dev/null
}
trap cleanup EXIT

# Pre-flight check
if [ ! -f "build/rxnm" ] || [ ! -f "build/rxnm-agent" ]; then
    err "Bundle artifacts not found. Run 'make rocknix-release' first."
    exit 1
fi

sudo systemctl start systemd-machined || true

info "Setting up Host Bridge ($BRIDGE)..."
if ! ip link show $BRIDGE >/dev/null 2>&1; then
    ip link add $BRIDGE type bridge
    ip link set $BRIDGE up
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    sysctl -w net.ipv6.conf.$BRIDGE.disable_ipv6=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.$BRIDGE.forwarding=1 2>/dev/null || true
fi

info "Building Test RootFS..."
if [ ! -d "$ROOTFS" ]; then
    mkdir -p "$ROOTFS"
    
    if command -v dnf >/dev/null 2>&1; then
        dnf -y --installroot="$ROOTFS" --releasever=43 install \
            systemd systemd-networkd systemd-resolved iwd dbus-daemon \
            iproute iputils procps-ng NetworkManager firewalld \
            ethtool tcpdump hostname bash jq sed coreutils \
            --setopt=install_weak_deps=False
    elif command -v docker >/dev/null 2>&1; then
        # FIXED: Added docker fallback back in for Ubuntu CI runners
        info "Using Docker to bootstrap Fedora rootfs..."
        docker build -t rxnm-test-base -f tests/integration/Containerfile tests/integration
        CID=$(docker create rxnm-test-base)
        docker export "$CID" | tar -x -C "$ROOTFS"
        docker rm "$CID"
        cp /etc/resolv.conf "$ROOTFS/etc/"
    else
        err "DNF or Docker required for host bootstrap."
        exit 1
    fi
        
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/NetworkManager.service"
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/firewalld.service"
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/systemd-update-utmp.service"
    ln -sf /dev/null "$ROOTFS/usr/lib/systemd/network/80-container-host0.network"
    
    mkdir -p "$ROOTFS/etc/systemd/system/multi-user.target.wants"
    ln -sf /usr/lib/systemd/system/systemd-networkd.service "$ROOTFS/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
    ln -sf /usr/lib/systemd/system/systemd-resolved.service "$ROOTFS/etc/systemd/system/multi-user.target.wants/systemd-resolved.service"
    
    # Mocking hooks
    cat <<'MOCK' > "$ROOTFS/usr/bin/sysctl"
#!/bin/bash
exit 0
MOCK
    chmod +x "$ROOTFS/usr/bin/sysctl"
    cp "$ROOTFS/usr/bin/sysctl" "$ROOTFS/usr/bin/rfkill"

    mkdir -p "$ROOTFS/storage/.config/network" "$ROOTFS/var/lib/iwd" "$ROOTFS/run/rocknix" "$ROOTFS/run/systemd/network"
    rm -rf "$ROOTFS/etc/systemd/network"
    ln -sf /run/systemd/network "$ROOTFS/etc/systemd/network"
fi

info "Installing ROCKNIX Bundle into RootFS..."
# Crucial Difference: We only install the single bundled file and the agent
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/bin"
mkdir -p "$ROOTFS/usr/bin"
cp -f build/rxnm "$ROOTFS/usr/bin/rxnm"
cp -f build/rxnm-agent "$ROOTFS/usr/lib/rocknix-network-manager/bin/"
chmod +x "$ROOTFS/usr/bin/rxnm" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"

mkdir -p "$ROOTFS/usr/lib/systemd/network"
cp -f usr/lib/systemd/network/* "$ROOTFS/usr/lib/systemd/network/"

info "Booting Bundle Machines..."
COMMON_ARGS="--network-bridge=$BRIDGE --boot --capability=all --private-users=no --system-call-filter=add_key:keyctl:bpf --ephemeral"
systemd-nspawn -D "$ROOTFS" -M $SERVER $COMMON_ARGS > /tmp/$SERVER.log 2>&1 &
systemd-nspawn -D "$ROOTFS" -M $CLIENT $COMMON_ARGS > /tmp/$CLIENT.log 2>&1 &

info "Waiting for systemd initialization..."
for i in {1..30}; do
    if machinectl status $SERVER >/dev/null 2>&1 && machinectl status $CLIENT >/dev/null 2>&1; then break; fi
    sleep 1
done

check_ready() {
    local machine=$1
    info "Waiting for $machine readiness..."
    for i in {1..60}; do
        if m_exec "$machine" systemctl is-active systemd-networkd 2>/dev/null | grep -q "active"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if ! check_ready $SERVER; then err "$SERVER failed"; exit 1; fi
if ! check_ready $CLIENT; then err "$CLIENT failed"; exit 1; fi

m_exec $SERVER ethtool -K host0 tx off || true
m_exec $CLIENT ethtool -K host0 tx off || true

info "Testing Feature Pruning (Negative Test)..."
# In the bundle, 'service' or 'mpls' should throw an 'Unknown command' error, not the standard 501 Not Implemented
# because they were stripped from the CATS variable.
PRUNE_TEST=$(m_exec $SERVER rxnm service list 2>&1 || true)
if echo "$PRUNE_TEST" | grep -q "Unknown command"; then
    info "✓ Verified 'service' module is correctly stripped from bundle."
else
    err "Pruning test failed. Output: $PRUNE_TEST"
    exit 1
fi

info "Initializing Bundled RXNM..."
m_exec $SERVER rxnm system setup
m_exec $CLIENT rxnm system setup

info "Applying Configurations..."
m_exec $SERVER rxnm interface host0 set static 192.168.213.2/24
m_exec $SERVER /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
m_exec $SERVER networkctl reload
m_exec $SERVER networkctl reconfigure host0

m_exec $CLIENT rxnm interface host0 set dhcp
m_exec $CLIENT networkctl reload
m_exec $CLIENT networkctl reconfigure host0

info "Waiting for DHCP Convergence via Bundle..."
for ((i=1; i<=30; i++)); do
    IP=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[] | select(.family=="inet") | .local // empty')
    
    if [[ "$IP" == "192.168.213."* ]]; then
        info "✓ IP Acquired: $IP"
        if m_exec $CLIENT ping -c 1 192.168.213.2 >/dev/null; then
            info "✓ Bidirectional Link Verified using Bundled Script"
            touch /tmp/rxnm_bundle_success
            exit 0
        fi
    fi
    sleep 2
done

err "Convergence timeout."
exit 1
