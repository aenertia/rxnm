#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

set -e

# ==============================================================================
# RXNM LIVE INTEROPERABILITY TEST SUITE (Systemd-nspawn)
# ==============================================================================
# Uses systemd-nspawn "machines" connected via a native Linux bridge.
# Bootstraps Fedora rootfs via Docker if host DNF is missing.
#
# HARNESS DESIGN:
# - Host: Creates unmanaged bridge 'rxnm-br'
# - Server (rxnm-server): Static IP 192.168.213.1, DHCP Server enabled
# - Client (rxnm-client): DHCP Client -> Static Dual Stack -> Nullify Tests
# ==============================================================================

# Constants
BRIDGE="rxnm-br"
ROOTFS="/var/lib/machines/fedora-rxnm"
SERVER="rxnm-server"
CLIENT="rxnm-client"
PCAP_FILE="/tmp/rxnm_bridge.pcap"
TCPDUMP_PID=""

# Helper for colored output
info() { echo -e "\033[0;36m[TEST]\033[0m $1"; }
err() { echo -e "\033[0;31m[FAIL]\033[0m $1"; }

# CI-friendly execution helper
m_exec() {
    local machine=$1
    shift
    # --setenv is critical to avoid Exit 203 (command not found) in transient units
    # --wait --pipe ensures we get output and wait for completion
    timeout 40s systemd-run -M "$machine" \
        --quiet --wait --pipe \
        --setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        --property=After=dbus.service \
        --property=CollectMode=inactive \
        -- "$@"
}

cleanup() {
    EXIT_CODE=$?
    echo "--- Teardown (Exit Code: $EXIT_CODE) ---"
    
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    
    if [ $EXIT_CODE -ne 0 ] && [ ! -f /tmp/rxnm_success ]; then
        err "TEST FAILED - DUMPING LOGS"
        
        echo ">>> NETWORK TRAFFIC (TCPDUMP) <<<"
        if [ -f "$PCAP_FILE" ] && command -v tcpdump >/dev/null; then
            tcpdump -n -e -vv -r "$PCAP_FILE" || echo "Error parsing pcap"
        fi
        
        [ -f "/tmp/$SERVER.log" ] && { echo ">>> SERVER CONSOLE <<<"; cat "/tmp/$SERVER.log"; }
        [ -f "/tmp/$CLIENT.log" ] && { echo ">>> CLIENT CONSOLE <<<"; cat "/tmp/$CLIENT.log"; }

        echo ">>> SERVER JOURNAL <<<"
        journalctl -M $SERVER -u systemd-networkd -n 100 --no-pager || true
        
        echo ">>> CLIENT JOURNAL <<<"
        journalctl -M $CLIENT -u systemd-networkd -n 100 --no-pager || true
        
        echo ">>> FINAL STATUS CHECK <<<"
        m_exec $SERVER ip addr show host0 || true
        m_exec $CLIENT ip addr show host0 || true
    fi

    machinectl terminate $SERVER 2>/dev/null || true
    machinectl terminate $CLIENT 2>/dev/null || true
    
    ip link delete $BRIDGE 2>/dev/null || true
    rm -f /tmp/rxnm_success
    
    if [ $EXIT_CODE -eq 0 ]; then
        rm -f "$PCAP_FILE" 2>/dev/null
    else
        info "Test failed: PCAP retained at $PCAP_FILE for forensics."
    fi
}
trap cleanup EXIT

sudo systemctl start systemd-machined || true

info "Setting up Host Bridge..."
if ! ip link show $BRIDGE >/dev/null 2>&1; then
    ip link add $BRIDGE type bridge
    ip link set $BRIDGE up
    # CRITICAL: Disable multicast snooping to prevent IPv6 Neighbor Discovery drop failures in isolated bridges
    echo 0 > /sys/class/net/$BRIDGE/bridge/multicast_snooping 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    sysctl -w net.ipv4.conf.$BRIDGE.forwarding=1 2>/dev/null || true
fi

if command -v tcpdump >/dev/null; then
    info "Starting packet capture on $BRIDGE..."
    tcpdump -U -i "$BRIDGE" -w "$PCAP_FILE" -s 0 >/dev/null 2>&1 &
    TCPDUMP_PID=$!
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
        err "No bootstrap tool found (dnf/docker)."
        exit 1
    fi
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/NetworkManager.service"
    ln -sf /dev/null "$ROOTFS/usr/lib/systemd/network/80-container-host0.network"
    
    # Mocking sysctl for Phase 5 read-back validation
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

info "Installing RXNM into RootFS..."
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/bin"
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/lib"
cp -f bin/rxnm-agent "$ROOTFS/usr/lib/rocknix-network-manager/bin/"
cp -f lib/*.sh "$ROOTFS/usr/lib/rocknix-network-manager/lib/"
cp -f bin/rxnm "$ROOTFS/usr/bin/rxnm"
chmod +x "$ROOTFS/usr/bin/rxnm" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"
mkdir -p "$ROOTFS/usr/lib/systemd/network"
cp -f usr/lib/systemd/network/* "$ROOTFS/usr/lib/systemd/network/"

info "Booting Machines..."
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
    for i in {1..60}; do
        if m_exec "$machine" systemctl is-active systemd-networkd 2>/dev/null | grep -q "active"; then return 0; fi
        sleep 1
    done
    return 1
}
check_ready $SERVER || { err "$SERVER failed"; exit 1; }
check_ready $CLIENT || { err "$CLIENT failed"; exit 1; }

m_exec $SERVER ethtool -K host0 tx off || true
m_exec $CLIENT ethtool -K host0 tx off || true

m_exec $SERVER rxnm system setup
m_exec $CLIENT rxnm system setup

info "--- [PHASE 1] DHCP Convergence ---"
m_exec $SERVER rxnm interface host0 set static 192.168.213.1/24
m_exec $SERVER /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
m_exec $SERVER networkctl reload && m_exec $SERVER networkctl reconfigure host0

m_exec $CLIENT rxnm interface host0 set dhcp
m_exec $CLIENT networkctl reload && m_exec $CLIENT networkctl reconfigure host0

CONVERGED=false
for ((i=1; i<=30; i++)); do
    IP=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213." | head -n1 || true)
    if [ -n "$IP" ]; then
        if m_exec $CLIENT ping -c 1 -W 2 192.168.213.1 >/dev/null 2>&1; then
            info "✓ DHCP Link Verified (IP: $IP)"
            CONVERGED=true; break
        fi
    fi
    sleep 2
done
[ "$CONVERGED" = "false" ] && { err "DHCP Convergence timeout"; exit 1; }

info "--- [PHASE 2] Advanced Interface Attributes ---"
m_exec $CLIENT rxnm interface host0 set static 192.168.213.50/24 --gateway 192.168.213.1 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
m_exec $CLIENT networkctl reload && m_exec $CLIENT networkctl reconfigure host0

info "Waiting for Attribute Convergence..."
CONVERGED=false
for ((i=1; i<=15; i++)); do
    IP_CHECK=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213.50" || true)
    MAC_CHECK=$(m_exec $CLIENT ip -j link show host0 | jq -r '.[0].address // empty')
    MTU_CHECK=$(m_exec $CLIENT ip -j link show host0 | jq -r '.[0].mtu // empty')
    if [ -n "$IP_CHECK" ] && [ "$MAC_CHECK" == "02:aa:bb:cc:dd:ee" ] && [ "$MTU_CHECK" == "1420" ]; then
        CONVERGED=true; break
    fi
    sleep 2
done
[ "$CONVERGED" = "false" ] && { err "Attribute application failed! IPs:$(m_exec $CLIENT ip addr show host0) MAC:$MAC_CHECK MTU:$MTU_CHECK"; exit 1; }
info "✓ Attributes applied successfully"

info "--- [PHASE 3] IPv6 Connectivity ---"
m_exec $SERVER rxnm interface host0 set static 192.168.213.1/24,fd00:cafe::1/64
m_exec $SERVER /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
m_exec $SERVER networkctl reload && m_exec $SERVER networkctl reconfigure host0

m_exec $CLIENT rxnm interface host0 set static 192.168.213.50/24,fd00:cafe::2/64 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
m_exec $CLIENT networkctl reload && m_exec $CLIENT networkctl reconfigure host0

info "Waiting for IPv6 Convergence (DAD/NDP)..."
CONVERGED=false
for ((i=1; i<=15; i++)); do
    if m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::2"; then
        if m_exec $SERVER ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::1"; then
            if m_exec $CLIENT ping -6 -c 1 -W 2 fd00:cafe::1 >/dev/null 2>&1; then
                CONVERGED=true; break
            fi
        fi
    fi
    sleep 2
done
[ "$CONVERGED" = "false" ] && { err "IPv6 Convergence failed (NDP/DAD timeout)"; exit 1; }
info "✓ IPv6 Ping Successful"

info "--- [PHASE 4] Project Silence (Nullify XDP) ---"
info "Engaging Nullify on host0..."
m_exec $CLIENT rxnm system nullify enable --interface host0
sleep 1
if m_exec $CLIENT ping -c 1 -W 1 192.168.213.1 >/dev/null 2>&1; then
    err "Nullify failed! Traffic leaked through."; exit 1
else
    info "✓ Traffic successfully dropped"
fi

info "Restoring Network..."
m_exec $CLIENT rxnm system nullify disable --interface host0
sleep 2
if m_exec $CLIENT ping -c 1 -W 2 192.168.213.1 >/dev/null 2>&1; then
    info "✓ Network restored"
else
    err "Network restoration failed!"; exit 1
fi

info "--- [PHASE 5] System Stack Tuning ---"
m_exec $CLIENT rxnm system ipv6 disable
sleep 2
IPV6_CHECK=$(m_exec $CLIENT ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet6") | .local // empty' | head -n1)
[ -n "$IPV6_CHECK" ] && { err "IPv6 leaked: $IPV6_CHECK"; exit 1; }
info "✓ IPv6 stack disabled"

m_exec $CLIENT rxnm system ipv4 disable
SYSCTL_VAL=$(m_exec $CLIENT /usr/sbin/sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "0")
[ "$SYSCTL_VAL" != "1" ] && { err "IPv4 tuning failed"; exit 1; }
info "✓ IPv4 broadcast chatter silenced"

touch /tmp/rxnm_success
info "All Integration Phases Passed."
exit 0
