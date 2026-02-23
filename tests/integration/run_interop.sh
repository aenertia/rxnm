#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# ==============================================================================
# RXNM LIVE INTEROPERABILITY TEST SUITE (Systemd-nspawn)
# ==============================================================================

set -eo pipefail

# Constants
BRIDGE="rxnm-br"
ROOTFS="/var/lib/machines/fedora-rxnm"
SERVER="rxnm-server"
CLIENT="rxnm-client"
PCAP_FILE="/tmp/rxnm_bridge.pcap"
WIFI_PCAP_FILE="/tmp/rxnm_wifi.pcap"
TCPDUMP_PID=""
WIFI_TCPDUMP_PID=""

HARNESS_DIR="$(cd "$(dirname "$0")/lib" && pwd)"
source "$HARNESS_DIR/harness.sh"

trap cleanup EXIT

sudo systemctl start systemd-machined || true

setup_bridge
[ "$SKIP_WIFI" = "false" ] && setup_hwsim
build_rootfs

info "Installing RXNM into RootFS..."
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/bin"
mkdir -p "$ROOTFS/usr/lib/rocknix-network-manager/lib"
cp -f bin/rxnm-agent "$ROOTFS/usr/lib/rocknix-network-manager/bin/"
cp -f lib/*.sh "$ROOTFS/usr/lib/rocknix-network-manager/lib/"
cp -f bin/rxnm "$ROOTFS/usr/bin/rxnm"
chmod +x "$ROOTFS/usr/bin/rxnm" "$ROOTFS/usr/lib/rocknix-network-manager/bin/rxnm-agent"
mkdir -p "$ROOTFS/usr/lib/systemd/network"
cp -f usr/lib/systemd/network/* "$ROOTFS/usr/lib/systemd/network/"

boot_machines

# CRITICAL: Manually map the mac80211 PHYs into the containers.
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

m_exec "$SERVER" ethtool -K host0 tx off || true
m_exec "$CLIENT" ethtool -K host0 tx off || true

m_exec "$SERVER" rxnm system setup
m_exec "$CLIENT" rxnm system setup

if [ "$WIFI_ONLY" = "false" ]; then
    info "--- [PHASE 1] DHCP Convergence ---"
    m_exec "$SERVER" rxnm interface host0 set static 192.168.213.1/24
    m_exec "$SERVER" /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
    m_exec "$SERVER" networkctl reload && m_exec "$SERVER" networkctl reconfigure host0

    m_exec "$CLIENT" rxnm interface host0 set dhcp
    m_exec "$CLIENT" networkctl reload && m_exec "$CLIENT" networkctl reconfigure host0

    CONVERGED=false
    for i in $(seq 1 30); do
        IP=$(m_exec "$CLIENT" ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213." | head -n1 || true)
        if [ -n "$IP" ]; then
            if m_exec "$CLIENT" ping -c 1 -W 2 192.168.213.1 >/dev/null 2>&1; then
                info "✓ DHCP Link Verified (IP: $IP)"
                CONVERGED=true; break
            fi
        fi
        sleep 2
    done
    [ "$CONVERGED" = "false" ] && { err "DHCP Convergence timeout"; exit 1; }

    info "--- [PHASE 2] Advanced Interface Attributes ---"
    m_exec "$CLIENT" rxnm interface host0 set static 192.168.213.50/24 --gateway 192.168.213.1 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
    m_exec "$CLIENT" networkctl reload && m_exec "$CLIENT" networkctl reconfigure host0

    info "Waiting for Attribute Convergence..."
    CONVERGED=false
    for i in $(seq 1 15); do
        IP_CHECK=$(m_exec "$CLIENT" ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | grep "192.168.213.50" || true)
        MAC_CHECK=$(m_exec "$CLIENT" ip -j link show host0 | jq -r '.[0].address // empty')
        MTU_CHECK=$(m_exec "$CLIENT" ip -j link show host0 | jq -r '.[0].mtu // empty')
        if [ -n "$IP_CHECK" ] && [ "$MAC_CHECK" == "02:aa:bb:cc:dd:ee" ] && [ "$MTU_CHECK" == "1420" ]; then
            CONVERGED=true; break
        fi
        sleep 2
    done
    [ "$CONVERGED" = "false" ] && { err "Attribute application failed!"; exit 1; }
    info "✓ Attributes applied successfully"

    info "--- [PHASE 3] IPv6 Connectivity ---"
    m_exec "$SERVER" rxnm interface host0 set static 192.168.213.1/24,fd00:cafe::1/64
    m_exec "$SERVER" /bin/bash -c "printf '\nDHCPServer=yes\n\n[DHCPServer]\nPoolOffset=10\nPoolSize=50\nEmitDNS=yes\n' >> /run/systemd/network/75-static-host0.network"
    m_exec "$SERVER" networkctl reload && m_exec "$SERVER" networkctl reconfigure host0

    m_exec "$CLIENT" rxnm interface host0 set static 192.168.213.50/24,fd00:cafe::2/64 --mtu 1420 --mac 02:aa:bb:cc:dd:ee
    m_exec "$CLIENT" networkctl reload && m_exec "$CLIENT" networkctl reconfigure host0

    info "Waiting for IPv6 Convergence (DAD/NDP)..."
    CONVERGED=false
    for i in $(seq 1 15); do
        if m_exec "$CLIENT" ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::2"; then
            if m_exec "$SERVER" ip -j addr show host0 | jq -r '.[0].addr_info[]? | .local // empty' | grep -q "fd00:cafe::1"; then
                if m_exec "$CLIENT" ping -6 -c 1 -W 2 fd00:cafe::1 >/dev/null 2>&1; then
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
    m_exec "$CLIENT" rxnm system nullify enable --interface host0
    sleep 1
    if m_exec "$CLIENT" ping -c 1 -W 1 192.168.213.1 >/dev/null 2>&1; then
        err "Nullify failed! Traffic leaked through."; exit 1
    else
        info "✓ Traffic successfully dropped"
    fi

    info "Restoring Network..."
    m_exec "$CLIENT" rxnm system nullify disable --interface host0
    sleep 2
    if m_exec "$CLIENT" ping -c 1 -W 2 192.168.213.1 >/dev/null 2>&1; then
        info "✓ Network restored"
    else
        err "Network restoration failed!"; exit 1
    fi

    info "--- [PHASE 5] System Stack Tuning ---"
    m_exec "$CLIENT" rxnm system ipv6 disable
    sleep 2
    IPV6_CHECK=$(m_exec "$CLIENT" ip -j addr show host0 | jq -r '.[0].addr_info[]? | select(.family=="inet6") | .local // empty' | head -n1)
    [ -n "$IPV6_CHECK" ] && { err "IPv6 leaked: $IPV6_CHECK"; exit 1; }
    info "✓ IPv6 stack disabled"

    m_exec "$CLIENT" rxnm system ipv4 disable
    SYSCTL_VAL=$(m_exec "$CLIENT" /usr/sbin/sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null || echo "0")
    [ "$SYSCTL_VAL" != "1" ] && { err "IPv4 tuning failed"; exit 1; }
    info "✓ IPv4 broadcast chatter silenced"

    info "Restoring System Stack for Phase 6..."
    m_exec "$CLIENT" rxnm system ipv6 enable
    m_exec "$CLIENT" rxnm system ipv4 enable
    m_exec "$CLIENT" rxnm system nullify disable >/dev/null 2>&1 || true
    sleep 2
fi

if [ "$SKIP_WIFI" = "false" ] && [ "$HWSIM_LOADED" = "true" ]; then
    info "--- [PHASE 6] IWD Virtual WiFi Interoperability ---"
    
    # Restart IWD to ensure it registers the clean, sanitized wlan0 radios
    m_exec "$SERVER" systemctl restart iwd
    m_exec "$CLIENT" systemctl restart iwd
    wait_iwd_ready "$SERVER"
    wait_iwd_ready "$CLIENT"
    
    # Defensive check: verify IWD stayed alive after detecting the radios
    if ! m_exec "$SERVER" systemctl is-active iwd >/dev/null 2>&1; then
        err "IWD crashed on Server! Likely missing Kernel AF_ALG crypto modules or /dev/rfkill permissions."
        m_exec "$SERVER" journalctl -u iwd --no-pager | tail -n 20
        exit 1
    fi
    
    # 1. Bring up the AP on the Server
    info "Starting Virtual AP (Debug Mode)..."
    # Added --share so that AP mode acts as a router and emits a pingable gateway default route
    m_exec "$SERVER" rxnm --debug wifi ap start "RXNM_Test_Net" --password "supersecret" --share
    
    # 2. Wait for simulated beaconing to initialize
    sleep 3
    
    # 3. Perform a Scan on the Client
    info "Scanning for Virtual AP (Debug Mode)..."
    SCAN_RESULT=$(m_exec "$CLIENT" rxnm --debug wifi scan --format json || echo "{}")
    if echo "$SCAN_RESULT" | grep -q "RXNM_Test_Net"; then
        info "✓ Simulated AP detected in client scan"
    else
        err "Failed to detect simulated AP"
        echo "Scan Output: $SCAN_RESULT"
        exit 1
    fi
    
    # 4. Connect the Client
    info "Connecting to Virtual AP (Debug Mode)..."
    m_exec "$CLIENT" rxnm --debug wifi connect "RXNM_Test_Net" --password "supersecret"
    
    # 5. Validate the L2 Connection and L3 IP Convergence
    info "Waiting for WiFi L2/L3 Convergence..."
    CONVERGED=false
    for i in $(seq 1 20); do
        CLI_WLAN=$(m_exec "$CLIENT" iw dev | awk '$1=="Interface"{print $2; exit}' | tr -d '\r\n')
        STATE="unknown"
        
        if [ -n "$CLI_WLAN" ]; then
            STATE=$(m_exec "$CLIENT" rxnm interface "$CLI_WLAN" show --get wifi.state 2>/dev/null || echo "unknown")
            
            if [ "$STATE" == "connected" ]; then
                IP=$(m_exec "$CLIENT" ip -j addr show "$CLI_WLAN" | jq -r '.[0].addr_info[]? | select(.family=="inet") | .local // empty' | head -n1 || true)
                GW=$(m_exec "$CLIENT" ip -4 route show dev "$CLI_WLAN" 2>/dev/null | awk '/default/ {print $3; exit}')
                [ -z "$GW" ] && GW=$(m_exec "$CLIENT" ip -4 route show dev "$CLI_WLAN" 2>/dev/null | awk '/src/ {print $1; exit}' | cut -d/ -f1 | sed 's/\.0\.0$/.1.1/; s/\.0$/.1/')

                if [ -n "$IP" ] && [ -n "$GW" ]; then
                    if m_exec "$CLIENT" ping -c 1 -W 2 "$GW" >/dev/null 2>&1; then
                        info "✓ Client successfully authenticated and routed over Virtual WiFi (IP: $IP, GW: $GW)"
                        CONVERGED=true
                        break
                    fi
                fi
            fi
        fi
        sleep 2
    done
    
    [ "$CONVERGED" = "false" ] && { err "Simulated WiFi connection or DHCP failed"; exit 1; }
elif [ "$SKIP_WIFI" = "false" ]; then
    info "--- [PHASE 6] SKIPPED (Virtual WiFi module unavailable) ---"
fi

info "All Integration Phases Passed."
exit 0
