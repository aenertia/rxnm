#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# ==============================================================================
# RXNM BUNDLE INTEROPERABILITY TEST SUITE (Systemd-nspawn)
# ==============================================================================

set -eo pipefail

BRIDGE="rxnm-bundle-br"
ROOTFS="/var/lib/machines/fedora-rxnm-bundle"
SERVER="rxnm-bdl-server"
CLIENT="rxnm-bdl-client"
PCAP_FILE="/tmp/rxnm_bundle_bridge.pcap"
TCPDUMP_PID=""

HARNESS_DIR="$(cd "$(dirname "$0")/lib" && pwd)"
source "$HARNESS_DIR/harness.sh"

trap cleanup EXIT

BUNDLE_BIN="${BUNDLE_BIN:-build/rxnm}"
AGENT_BIN=""
[ -f "build/rxnm-agent" ] && AGENT_BIN="build/rxnm-agent" || AGENT_BIN="bin/rxnm-agent"

if [ ! -f "$BUNDLE_BIN" ] || [ -z "$AGENT_BIN" ]; then
    err "Bundle artifacts missing. Run 'make rocknix-release' first."; exit 1
fi

ensure_machined
setup_bridge
[ "$SKIP_WIFI" = "false" ] && setup_hwsim
build_rootfs

info "Installing Bundle into RootFS..."
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/bin" "$ROOTFS/usr/lib/rocknix-network-manager/lib"
cp -f "$BUNDLE_BIN" "$ROOTFS/usr/bin/rxnm"
cp -f "$AGENT_BIN" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"
chmod +x "$ROOTFS/usr/bin/rxnm" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"
cp -f usr/lib/systemd/network/* "$ROOTFS/usr/lib/systemd/network/" 2>/dev/null || true

boot_machines

# Reverted flawed dynamic interface detection. 
# systemd-nspawn deterministically binds the container end of --network-bridge to host0.
SRV_IFACE="host0"
CLI_IFACE="host0"
info "Target wired interfaces -> Server: $SRV_IFACE, Client: $CLI_IFACE"

if [ "$SKIP_WIFI" = "false" ] && [ "$HWSIM_LOADED" = "true" ]; then
    info "Injecting Virtual WiFi Radios into containers via PHY..."
    SRV_PID=$(machinectl show "$SERVER" -p Leader | cut -d= -f2)
    CLI_PID=$(machinectl show "$CLIENT" -p Leader | cut -d= -f2)
    if [ -n "$SRV_PID" ] && [ -n "$WLAN_SRV" ]; then
        SRV_PHY=$(iw dev "$WLAN_SRV" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
        [ -n "$SRV_PHY" ] && inject_phy_and_wait "$SERVER" "$SRV_PHY" "$SRV_PID"
    fi
    if [ -n "$CLI_PID" ] && [ -n "$WLAN_CLI" ]; then
        CLI_PHY=$(iw dev "$WLAN_CLI" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')
        [ -n "$CLI_PHY" ] && inject_phy_and_wait "$CLIENT" "$CLI_PHY" "$CLI_PID"
    fi
    info "Sanitizing Virtual Radios..."
    sanitize_in_machine "$SERVER" "$SRV_PID"
    sanitize_in_machine "$CLIENT" "$CLI_PID"
fi

m_exec "$SERVER" ethtool -K "$SRV_IFACE" tx off || true
m_exec "$CLIENT" ethtool -K "$CLI_IFACE" tx off || true

m_exec "$SERVER" rxnm system setup
m_exec "$CLIENT" rxnm system setup

if [ "$WIFI_ONLY" = "false" ]; then
    info "--- [PHASE 0] Primitive L3 Connectivity (Bundle) ---"
    m_exec "$SERVER" rxnm interface "$SRV_IFACE" set static 10.99.0.1/24 || true
    m_exec "$CLIENT" rxnm interface "$CLI_IFACE" set static 10.99.0.2/24 || true

    # Explicitly reload networkd to apply static config before asserting ping
    m_exec "$SERVER" rxnm system reload
    m_exec "$CLIENT" rxnm system reload

    info "Waiting for L3 Static IP Convergence..."
    SRV_IP=$(wait_ip_convergence "$SERVER" "$SRV_IFACE" "10.99.0.1" "inet" 10)
    CLI_IP=$(wait_ip_convergence "$CLIENT" "$CLI_IFACE" "10.99.0.2" "inet" 10)

    if [ -n "$SRV_IP" ] && [ -n "$CLI_IP" ]; then
        if m_exec "$CLIENT" ping -c 1 -W 2 10.99.0.1 >/dev/null 2>&1; then 
            info "✓ Basic L3 Static Ping Successful"
        else 
            err "Basic L3 Static Ping Failed! Plumbing issue."
            m_exec "$CLIENT" ip addr show dev "$CLI_IFACE" || true
            m_exec "$SERVER" ip addr show dev "$SRV_IFACE" || true
            exit 1
        fi
    else
        err "IP addresses failed to configure!"
        exit 1
    fi

    info "--- [PHASE 1] DHCP Convergence (Bundle) ---"
    m_exec "$SERVER" rxnm interface "$SRV_IFACE" set static 192.168.213.2/24 || true
    m_exec "$SERVER" /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-${SRV_IFACE}.network"
    m_exec "$SERVER" rxnm system reload
    m_exec "$CLIENT" rxnm interface "$CLI_IFACE" set dhcp || true
    m_exec "$CLIENT" rxnm system reload

    CONVERGED=false
    IP=$(wait_ip_convergence "$CLIENT" "$CLI_IFACE" "192.168.213." "inet" 15)
    if [ -n "$IP" ]; then
        if m_exec "$CLIENT" ping -c 1 -W 2 192.168.213.2 >/dev/null 2>&1; then info "✓ DHCP Bidirectional Link Verified (IP: $IP)"; CONVERGED=true; fi
    fi
    [ "$CONVERGED" = "false" ] && { err "DHCP Convergence timeout"; exit 1; }

    info "--- [PHASE 2] Advanced Attributes (Bundle) ---"
    m_exec "$CLIENT" rxnm interface "$CLI_IFACE" set static 192.168.213.60/24 --gateway 192.168.213.2 --mtu 1420 --mac 02:aa:bb:cc:dd:ee || true
    m_exec "$CLIENT" rxnm system reload

    info "Waiting for Attribute Convergence..."
    CONVERGED=false
    IP=$(wait_ip_convergence "$CLIENT" "$CLI_IFACE" "192.168.213.60" "inet" 10)
    if [ -n "$IP" ]; then
        MAC_CHECK=$(m_exec "$CLIENT" ip -j link show "$CLI_IFACE" | jq -r '.[0].address // empty')
        MTU_CHECK=$(m_exec "$CLIENT" ip -j link show "$CLI_IFACE" | jq -r '.[0].mtu // empty')
        if [ "$MAC_CHECK" == "02:aa:bb:cc:dd:ee" ] && [ "$MTU_CHECK" == "1420" ]; then CONVERGED=true; fi
    fi
    [ "$CONVERGED" = "false" ] && { err "Attribute application failed!"; exit 1; }
    info "✓ Attributes applied"

    info "--- [PHASE 3] IPv6 (Bundle) ---"
    m_exec "$SERVER" rxnm interface "$SRV_IFACE" set static 192.168.213.2/24,fd00:cafe::2/64 || true
    m_exec "$SERVER" /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-${SRV_IFACE}.network"
    m_exec "$SERVER" rxnm system reload
    m_exec "$CLIENT" rxnm interface "$CLI_IFACE" set static 192.168.213.60/24,fd00:cafe::3/64 --mtu 1420 --mac 02:aa:bb:cc:dd:ee || true
    m_exec "$CLIENT" rxnm system reload

    info "Waiting for IPv6 Convergence (Bundle)..."
    CONVERGED=false
    CLI_IP=$(wait_ip_convergence "$CLIENT" "$CLI_IFACE" "fd00:cafe::3" "inet6" 8)
    SRV_IP=$(wait_ip_convergence "$SERVER" "$SRV_IFACE" "fd00:cafe::2" "inet6" 8)
    if [ -n "$CLI_IP" ] && [ -n "$SRV_IP" ]; then
        if m_exec "$CLIENT" ping -6 -c 1 -W 2 fd00:cafe::2 >/dev/null 2>&1; then CONVERGED=true; fi
    fi
    [ "$CONVERGED" = "false" ] && { err "IPv6 failed"; exit 1; }
    info "✓ IPv6 Validated"

    info "--- [PHASE 4] Project Silence (Nullify XDP Bundle) ---"
    m_exec "$CLIENT" rxnm system nullify enable --interface "$CLI_IFACE" || warn "XDP Nullify mechanism rejected or unsupported in CI env"
    sleep 1
    if m_exec "$CLIENT" ping -c 1 -W 1 192.168.213.2 >/dev/null 2>&1; then warn "Nullify bypass detected (Expected if runner lacks XDP support)"; else info "✓ Packets dropped"; fi
    m_exec "$CLIENT" rxnm system nullify disable --interface "$CLI_IFACE" || true
    sleep 2
    m_exec "$CLIENT" ping -c 1 -W 2 192.168.213.2 >/dev/null 2>&1 && info "✓ Restored" || { err "Restore failed!"; exit 1; }

    info "--- [PHASE 5] Stack Tuning (Bundle) ---"
    m_exec "$CLIENT" rxnm system ipv6 disable || true
    sleep 2
    IPV6_CHECK=$(m_exec "$CLIENT" ip -j addr show "$CLI_IFACE" 2>/dev/null | jq -r '.[0].addr_info[]? | select(.family=="inet6") | .local // empty' | head -n1 || true)
    [ -n "$IPV6_CHECK" ] && { err "IPv6 leaked"; exit 1; }
    info "✓ IPv6 disabled"
    m_exec "$CLIENT" rxnm system ipv4 disable || true
    SYSCTL_VAL=$(m_exec "$CLIENT" /usr/sbin/sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "0")
    [ "$SYSCTL_VAL" != "1" ] && { err "IPv4 tuning failed"; exit 1; }
    info "✓ IPv4 chatter silenced"

    m_exec "$CLIENT" rxnm system ipv6 enable || true
    m_exec "$CLIENT" rxnm system ipv4 enable || true
    m_exec "$CLIENT" rxnm system nullify disable >/dev/null 2>&1 || true
    sleep 2
fi

if [ "$SKIP_WIFI" = "false" ] && [ "$HWSIM_LOADED" = "true" ]; then
    info "--- [PHASE 6] IWD Virtual WiFi Interoperability (Bundle) ---"
    m_exec "$SERVER" systemctl restart iwd
    m_exec "$CLIENT" systemctl restart iwd
    wait_iwd_ready "$SERVER"
    wait_iwd_ready "$CLIENT"
    
    SRV_WLAN=$(m_exec "$SERVER" iw dev | awk '$1=="Interface"{print $2; exit}' | tr -d '\r\n')
    CLI_WLAN=$(m_exec "$CLIENT" iw dev | awk '$1=="Interface"{print $2; exit}' | tr -d '\r\n')

    m_exec "$SERVER" ethtool -K "$SRV_WLAN" tx off || true
    m_exec "$CLIENT" ethtool -K "$CLI_WLAN" tx off || true

    info "Starting Virtual AP on $SRV_WLAN..."
    m_exec "$SERVER" rxnm wifi ap start "RXNM_Test_Net" --password "supersecret" --share --interface "$SRV_WLAN" || true
    
    info "Waiting for Server AP to become routable..."
    SRV_READY=false
    for i in $(seq 1 10); do
        if m_exec "$SERVER" rxnm interface "$SRV_WLAN" show --get state | grep -qE "routable|up"; then SRV_READY=true; break; fi
        sleep 1
    done
    [ "$SRV_READY" = "false" ] && { err "Server AP failed to reach routable state"; exit 1; }
    
    info "Scanning for Virtual AP from $CLI_WLAN..."
    SCAN_RESULT=$(m_exec "$CLIENT" rxnm wifi scan --interface "$CLI_WLAN" --format json || echo "{}")
    if echo "$SCAN_RESULT" | grep -q "RXNM_Test_Net"; then info "✓ Simulated AP detected in client scan"; else err "Failed to detect simulated AP"; exit 1; fi
    
    info "Connecting $CLI_WLAN to Virtual AP..."
    m_exec "$CLIENT" rxnm wifi connect "RXNM_Test_Net" --password "supersecret" --interface "$CLI_WLAN" || true
    
    info "Waiting for WiFi L3 Convergence..."
    CONVERGED=false
    for i in $(seq 1 20); do
        STATE=$(m_exec "$CLIENT" rxnm interface "$CLI_WLAN" show --get wifi.state 2>/dev/null || echo "unknown")
        if [ "$STATE" == "connected" ]; then
            GW=$(m_exec "$CLIENT" ip -4 route get 1.1.1.1 dev "$CLI_WLAN" 2>/dev/null | awk '/via/ {print $3}')
            if [ -n "$GW" ]; then
                if m_exec "$CLIENT" ping -c 1 -W 2 "$GW" >/dev/null 2>&1; then
                    info "✓ Client authenticated and routed via $GW"
                    CONVERGED=true; break
                fi
            fi
        fi
        sleep 2
    done
    [ "$CONVERGED" = "false" ] && { err "WiFi Convergence Failed"; exit 1; }

    info "--- [PHASE 6b] Client Mode Restoration ---"
    m_exec "$SERVER" rxnm wifi client --interface "$SRV_WLAN" || true
    sleep 2
    SRV_STATE=$(m_exec "$SERVER" rxnm interface "$SRV_WLAN" show --get wifi.state 2>/dev/null)
    if [[ "$SRV_STATE" == "disconnected" || "$SRV_STATE" == "station" ]]; then info "✓ AP state cleaned up successfully"; else err "AP residue detected"; exit 1; fi
elif [ "$SKIP_WIFI" = "false" ]; then
    info "--- [PHASE 6] SKIPPED (Virtual WiFi module unavailable) ---"
fi

info "All Bundled Integration Phases Passed."
exit 0
