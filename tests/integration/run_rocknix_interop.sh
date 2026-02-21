#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

set -e

# ==============================================================================
# RXNM BUNDLE INTEROPERABILITY TEST SUITE (Systemd-nspawn)
# ==============================================================================
# Specifically tests the generated flat-file bundled executables to ensure
# the amalgamation process didn't break core logic, and verifies that enterprise
# features were correctly stripped out (or retained in the full bundle).
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
    
    if [ $EXIT_CODE -eq 0 ]; then
        rm -f "$PCAP_FILE" 2>/dev/null
    else
        info "Test failed: PCAP retained at $PCAP_FILE for forensics."
    fi
}
trap cleanup EXIT

BUNDLE_BIN="${BUNDLE_BIN:-build/rxnm}"

# Pre-flight check
# Resilient check: check both build/ and bin/ for the agent
AGENT_BIN=""
if [ -f "build/rxnm-agent" ]; then
    AGENT_BIN="build/rxnm-agent"
elif [ -f "bin/rxnm-agent" ]; then
    AGENT_BIN="bin/rxnm-agent"
fi

if [ ! -f "$BUNDLE_BIN" ] || [ -z "$AGENT_BIN" ]; then
    err "Bundle artifacts not found ($BUNDLE_BIN). Run 'make rocknix-release' or 'make combined-full' first."
    exit 1
fi

sudo systemctl start systemd-machined || true

info "Setting up Host Bridge ($BRIDGE)..."
if ! ip link show $BRIDGE >/dev/null 2>&1; then
    ip link add $BRIDGE type bridge
    ip link set $BRIDGE up
    # CRITICAL: Disable multicast snooping to prevent IPv6 Neighbor Discovery drop failures
    echo 0 > /sys/class/net/$BRIDGE/bridge/multicast_snooping 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    sysctl -w net.ipv6.conf.$BRIDGE.disable_ipv6=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.$BRIDGE.forwarding=1 2>/dev/null || true
fi

info "Building Test RootFS..."
HASH=$(md5sum tests/integration/Containerfile 2>/dev/null | cut -d ' ' -f 1 || echo "nohash")
if [ -d "$ROOTFS" ]; then
    if [ ! -f "$ROOTFS/.rxnm_hash" ] || [ "$(cat "$ROOTFS/.rxnm_hash" 2>/dev/null)" != "$HASH" ]; then
        info "RootFS cache invalid or stale. Rebuilding..."
        rm -rf "$ROOTFS"
    fi
fi

if [ ! -d "$ROOTFS" ]; then
    mkdir -p "$ROOTFS"
    
    # Robust bootstrap tool detection
    BOOTSTRAP_TOOL=""
    if command -v dnf >/dev/null 2>&1; then BOOTSTRAP_TOOL="dnf";
    elif command -v docker >/dev/null 2>&1; then BOOTSTRAP_TOOL="docker";
    elif [ -x /usr/bin/dnf ]; then BOOTSTRAP_TOOL="/usr/bin/dnf";
    elif [ -x /usr/bin/docker ]; then BOOTSTRAP_TOOL="/usr/bin/docker";
    fi

    if [ "$BOOTSTRAP_TOOL" = "dnf" ] || [ "$BOOTSTRAP_TOOL" = "/usr/bin/dnf" ]; then
        "$BOOTSTRAP_TOOL" -y --installroot="$ROOTFS" --releasever=43 install \
            systemd systemd-networkd systemd-resolved iwd dbus-daemon \
            iproute iputils procps-ng NetworkManager firewalld \
            ethtool tcpdump hostname bash jq sed coreutils \
            --setopt=install_weak_deps=False
    elif [ "$BOOTSTRAP_TOOL" = "docker" ] || [ "$BOOTSTRAP_TOOL" = "/usr/bin/docker" ]; then
        info "Using Docker to bootstrap Fedora rootfs..."
        "$BOOTSTRAP_TOOL" build -t rxnm-test-base -f tests/integration/Containerfile tests/integration
        CID=$("$BOOTSTRAP_TOOL" create rxnm-test-base)
        "$BOOTSTRAP_TOOL" export "$CID" | tar -x -C "$ROOTFS"
        "$BOOTSTRAP_TOOL" rm "$CID"
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
if [ -x /usr/sbin/sysctl ]; then /usr/sbin/sysctl "$@"; else exit 0; fi
MOCK
    chmod +x "$ROOTFS/usr/bin/sysctl"
    cp "$ROOTFS/usr/bin/sysctl" "$ROOTFS/usr/bin/rfkill"

    mkdir -p "$ROOTFS/storage/.config/network" "$ROOTFS/var/lib/iwd" "$ROOTFS/run/rocknix" "$ROOTFS/run/systemd/network"
    rm -rf "$ROOTFS/etc/systemd/network"
    ln -sf /run/systemd/network "$ROOTFS/etc/systemd/network"
    
    echo "$HASH" > "$ROOTFS/.rxnm_hash"
fi

info "Installing Bundle into RootFS..."
# Crucial Difference: We only install the single bundled file and the agent
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/bin"
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/lib" # Fix: Satisfy rxnm-api directory checks in full bundle
mkdir -p "$ROOTFS/usr/bin"
cp -f "$BUNDLE_BIN" "$ROOTFS/usr/bin/rxnm"
cp -f "$AGENT_BIN" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"
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

info "Testing Feature Pruning (Negative/Positive Test)..."
PRUNE_TEST=$(m_exec $SERVER rxnm service list 2>&1 || true)
if [[ "$BUNDLE_BIN" == *"rxnm-full"* ]]; then
    if echo "$PRUNE_TEST" | grep -q "Unknown command"; then
        err "Full bundle incorrectly pruned 'service' module. Output: $PRUNE_TEST"
        exit 1
    else
        info "✓ Verified 'service' module is present in full bundle."
    fi
else
    if echo "$PRUNE_TEST" | grep -q "Unknown command"; then
        info "✓ Verified 'service' module is correctly stripped from bundle."
    else
        err "Pruning test failed. Output: $PRUNE_TEST"
        exit 1
    fi
fi

info "Initializing Bundled RXNM..."
m_exec $SERVER rxnm system setup
m_exec $CLIENT rxnm system setup

info "--- [PHASE 1] DHCP Convergence (Bundled Script) ---"
m_exec $SERVER rxnm interface host0 set static 192.168.213.2/24
m_exec $SERVER /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
m_exec $SERVER networkctl reload
m_exec $SERVER networkctl reconfigure host0

m_exec $CLIENT rxnm interface host0 set dhcp
m_exec $CLIENT networkctl reload
m_exec $CLIENT networkctl reconfigure host0

CONVERGED=false
for ((i=1; i<=30; i++)); do
    IP=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213." | head -n1 || true)
    
    if [ -n "$IP" ]; then
        if m_exec $CLIENT ping -c 1 -W 2 192.168.213.2 >/dev/null 2>&1; then
            info "✓ DHCP Bidirectional Link Verified using Bundled Script (IP: $IP)"
            CONVERGED=true
            break
        fi
    fi
    sleep 2
done
if [ "$CONVERGED" = "false" ]; then err "DHCP Convergence timeout"; exit 1; fi

info "--- [PHASE 2] Advanced Interface Attributes ---"
m_exec $CLIENT rxnm interface host0 set static 192.168.213.60/24 --gateway 192.168.213.2 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
m_exec $CLIENT networkctl reload
m_exec $CLIENT networkctl reconfigure host0

info "Waiting for Attribute Convergence..."
CONVERGED=false
for ((i=1; i<=15; i++)); do
    IP_CHECK=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213.60" || true)
    MAC_CHECK=$(m_exec $CLIENT ip -j link show host0 | jq -r '.[0].address // empty')
    MTU_CHECK=$(m_exec $CLIENT ip -j link show host0 | jq -r '.[0].mtu // empty')

    if [ -n "$IP_CHECK" ] && [ "$MAC_CHECK" == "02:aa:bb:cc:dd:ee" ] && [ "$MTU_CHECK" == "1420" ]; then
        CONVERGED=true
        break
    fi
    sleep 2
done

if [ "$CONVERGED" = "false" ]; then
    IP_DUMP=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | tr '\n' ' ')
    err "Attribute application failed! IPs:[$IP_DUMP] MAC:$MAC_CHECK MTU:$MTU_CHECK"
    exit 1
fi
info "✓ Attributes applied successfully (Static IP, MTU 1420, Spoofed MAC)"

info "--- [PHASE 3] IPv6 Connectivity ---"
m_exec $SERVER rxnm interface host0 set static 192.168.213.2/24,fd00:cafe::2/64
m_exec $SERVER /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
m_exec $SERVER networkctl reload && m_exec $SERVER networkctl reconfigure host0

m_exec $CLIENT rxnm interface host0 set static 192.168.213.60/24,fd00:cafe::3/64 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
m_exec $CLIENT networkctl reload && m_exec $CLIENT networkctl reconfigure host0

info "Waiting for IPv6 Convergence..."
CONVERGED=false
for ((i=1; i<=15; i++)); do
    if m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::3"; then
        if m_exec $SERVER ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::2"; then
            CONVERGED=true
            break
        fi
    fi
    sleep 2
done
if [ "$CONVERGED" = "false" ]; then err "IPv6 Convergence timeout"; exit 1; fi

if m_exec $CLIENT ping -6 -c 1 -W 2 fd00:cafe::2 >/dev/null 2>&1; then
    info "✓ IPv6 Ping Successful (Dual-Stack Active)"
else
    err "IPv6 Ping Failed"
    exit 1
fi

info "--- [PHASE 4] Project Silence (Nullify XDP) ---"
info "Engaging Nullify on Client..."
m_exec $CLIENT rxnm system nullify enable
sleep 1

# Ping should FAIL immediately
if m_exec $CLIENT ping -c 1 -W 1 192.168.213.2 >/dev/null 2>&1; then
    err "Nullify failed! Traffic was successfully routed when it should have been dropped."
    exit 1
else
    info "✓ Traffic successfully dropped (XDP Drop Filter Active)"
fi

info "Restoring Network..."
m_exec $CLIENT rxnm system nullify disable
sleep 2

# Ping should SUCCEED again
if m_exec $CLIENT ping -c 1 -W 2 192.168.213.2 >/dev/null 2>&1; then
    info "✓ Network restored successfully (XDP Filter Removed)"
else
    err "Network restoration failed! XDP filter may be stuck."
    exit 1
fi

info "--- [PHASE 5] System Stack Tuning ---"
info "Disabling IPv6 Stack globally..."
m_exec $CLIENT rxnm system ipv6 disable
sleep 2

IPV6_CHECK=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet6") | .local // empty' | head -n1)
if [ -n "$IPV6_CHECK" ]; then
    err "IPv6 addresses still present after global disable! ($IPV6_CHECK)"
    exit 1
else
    info "✓ IPv6 flushed successfully from kernel structures"
fi

info "Silencing IPv4 Broadcasts..."
m_exec $CLIENT rxnm system ipv4 disable
SYSCTL_VAL=$(m_exec $CLIENT /usr/sbin/sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "0")
if [ "$SYSCTL_VAL" != "1" ]; then
    err "IPv4 sysctl tuning failed!"
    exit 1
else
    info "✓ IPv4 broadcast/ARP chatter silenced"
fi

touch /tmp/rxnm_bundle_success
info "All Bundled Integration Phases Passed."
exit 0
