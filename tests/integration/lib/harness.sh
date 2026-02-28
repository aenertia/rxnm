#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: harness.sh
# PURPOSE: Shared integration test logic for nspawn containers
# -----------------------------------------------------------------------------

set -eo pipefail

SKIP_WIFI=false
WIFI_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --skip-wifi) SKIP_WIFI=true ;;
        --wifi-only) WIFI_ONLY=true ;;
    esac
done

info() { echo -e "\033[0;36m[TEST]\033[0m $1"; }
err() { echo -e "\033[0;31m[FAIL]\033[0m $1"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $1"; }

m_exec() {
    local machine="$1"
    shift
    # Note: RXNM_FORCE_NETWORKCTL bypasses dbus-broker policy rejections in CI containers
    timeout 40s systemd-run -M "$machine" \
        --quiet --wait --pipe \
        --setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        --setenv=RXNM_FORCE_NETWORKCTL=true \
        --property=After=dbus.service \
        --property=CollectMode=inactive \
        -- "$@"
}

cleanup() {
    EXIT_CODE=$?
    echo "--- Teardown (Exit Code: $EXIT_CODE) ---"
    
    [ -n "$TCPDUMP_PID" ] && { kill "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true; }
    [ -n "$WIFI_TCPDUMP_PID" ] && { kill "$WIFI_TCPDUMP_PID" 2>/dev/null || true; wait "$WIFI_TCPDUMP_PID" 2>/dev/null || true; }
    
    if [ "$EXIT_CODE" -ne 0 ]; then
        err "TEST FAILED - DUMPING DIAGNOSTICS"
        info "=== systemd-networkd logs (Server) ==="
        journalctl -M "$SERVER" -u systemd-networkd -n 50 --no-pager 2>/dev/null || true
        info "=== systemd-networkd logs (Client) ==="
        journalctl -M "$CLIENT" -u systemd-networkd -n 50 --no-pager 2>/dev/null || true

        info "=== Failed units (Server) ==="
        m_exec "$SERVER" systemctl --failed --no-pager 2>/dev/null || true
        info "=== Failed units (Client) ==="
        m_exec "$CLIENT" systemctl --failed --no-pager 2>/dev/null || true

        if [ "$SKIP_WIFI" = "false" ]; then
            info "=== iwd logs (Server) ==="
            journalctl -M "$SERVER" -u iwd -n 80 --no-pager 2>/dev/null || true
            info "=== iwd logs (Client) ==="
            journalctl -M "$CLIENT" -u iwd -n 80 --no-pager 2>/dev/null || true

            info "=== Host WiFi state ==="
            iw dev 2>/dev/null || true
            lsmod | grep -E "mac80211|cfg80211|hwsim" 2>/dev/null || true
            info "=== Host dmesg (hwsim) ==="
            dmesg | grep -i -E "hwsim|mac80211|cfg80211" | tail -n 20 2>/dev/null || true
        fi
    fi

    machinectl terminate "$SERVER" 2>/dev/null || true
    machinectl terminate "$CLIENT" 2>/dev/null || true
    ip link delete "$BRIDGE" 2>/dev/null || true
}

setup_bridge() {
    info "Setting up network bridge ($BRIDGE)..."
    sudo ip link add name "$BRIDGE" type bridge 2>/dev/null || true
    sudo ip link set "$BRIDGE" up
}

build_rootfs() {
    info "Building Container RootFS at $ROOTFS..."
    if [ ! -d "$ROOTFS/etc" ]; then
        sudo mkdir -p "$ROOTFS"
        local engine="docker"
        if command -v podman >/dev/null 2>&1; then engine="podman"; fi

        info "Using $engine to build base image..."
        sudo $engine build -t rxnm-base -f tests/integration/Containerfile tests/integration/
        local ctr
        ctr=$(sudo $engine create rxnm-base)
        sudo $engine export "$ctr" | sudo tar -x -C "$ROOTFS"
        sudo $engine rm "$ctr"
    else
        info "RootFS already exists, reusing."
    fi

    # Inject sanitize_wifi.sh as documented in UPSTREAM.md to prevent ghost P2P interfaces
    sudo mkdir -p "$ROOTFS/usr/local/bin"
    cat << 'EOF' | sudo tee "$ROOTFS/usr/local/bin/sanitize_wifi.sh" > /dev/null
#!/bin/bash
for wdev in $(iw dev | awk '/Interface/ {iface=$2} /type P2P-device/ {print iface}'); do
    iw dev "$wdev" del 2>/dev/null || true
done
EOF
    sudo chmod +x "$ROOTFS/usr/local/bin/sanitize_wifi.sh"
}

setup_hwsim() {
    info "Setting up Virtual WiFi (mac80211_hwsim)..."
    HWSIM_LOADED=false
    WLAN_SRV=""
    WLAN_CLI=""

    if lsmod | grep -q mac80211_hwsim; then
        for i in $(seq 1 30); do
            WLAN_IFACES=$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}')
            [ $(echo "$WLAN_IFACES" | wc -w) -ge 2 ] && break
            sleep 0.5
        done
        
        for iface in $WLAN_IFACES; do
            if [ -z "$WLAN_SRV" ]; then
                WLAN_SRV="$iface"
                sudo ip link set "$WLAN_SRV" down 2>/dev/null || true
            elif [ -z "$WLAN_CLI" ]; then
                WLAN_CLI="$iface"
                sudo ip link set "$WLAN_CLI" down 2>/dev/null || true
                break
            fi
        done
        
        if [ -n "$WLAN_SRV" ] && [ -n "$WLAN_CLI" ]; then
            HWSIM_LOADED=true
            info "✓ Virtual radios allocated: $WLAN_SRV, $WLAN_CLI"
        fi
    else
        warn "mac80211_hwsim module not loaded on host. WiFi testing will be skipped."
    fi
}

wait_iwd_ready() {
    local machine="$1"
    local retries=45
    for i in $(seq 1 "$retries"); do
        if m_exec "$machine" busctl list 2>/dev/null | grep -q 'net.connman.iwd'; then
            for j in $(seq 1 15); do
                if m_exec "$machine" busctl call net.connman.iwd / org.freedesktop.DBus.ObjectManager GetManagedObjects --json=short 2>/dev/null | grep -q "net.connman.iwd.Device"; then
                    info "✓ IWD Service & Radio registered on $machine"
                    return 0
                fi
                sleep 1
            done
        fi
        sleep 1
    done
    err "IWD Radio discovery failed on $machine"
    return 1
}

wait_ip_convergence() {
    local machine="$1" iface="$2" prefix="$3" family="$4" timeout="$5"
    for i in $(seq 1 "$timeout"); do
        # Robust IP extraction masking errors to prevent shell aborts
        local ip_json
        ip_json=$(m_exec "$machine" ip -j addr show "$iface" 2>/dev/null || echo "[]")
        IP=$(echo "$ip_json" | jq -e -r '.[0].addr_info[]? | select(.family=="'"$family"'") | .local // empty' 2>/dev/null | grep "$prefix" | head -n1 || true)
        if [ -n "$IP" ]; then echo "$IP"; return 0; fi
        sleep 2
    done
    err "IP convergence failed for $machine $iface. Interface state:" >&2
    m_exec "$machine" ip addr show "$iface" >&2 || true
    m_exec "$machine" networkctl status "$iface" >&2 || true
    return 1
}

check_ready() {
    local machine="$1"
    for i in $(seq 1 60); do
        if m_exec "$machine" systemctl is-active systemd-networkd 2>/dev/null | grep -q "active"; then return 0; fi
        sleep 1
    done
    return 1
}

boot_machines() {
    info "Booting Machines..."
    COMMON_ARGS=(
        "--network-bridge=$BRIDGE"
        "--boot"
        "--capability=all"
        "--private-users=no"
        "--system-call-filter=bpf keyctl add_key"
        "--rlimit=RLIMIT_MEMLOCK=infinity"
        "--ephemeral"
    )

    if [ -c /dev/rfkill ]; then
        COMMON_ARGS+=("--bind=/dev/rfkill")
    fi

    systemd-nspawn -D "$ROOTFS" -M "$SERVER" "${COMMON_ARGS[@]}" > "/tmp/$SERVER.log" 2>&1 &
    systemd-nspawn -D "$ROOTFS" -M "$CLIENT" "${COMMON_ARGS[@]}" > "/tmp/$CLIENT.log" 2>&1 &

    info "Waiting for systemd initialization..."
    check_ready "$SERVER" || { err "$SERVER failed"; exit 1; }
    check_ready "$CLIENT" || { err "$CLIENT failed"; exit 1; }
    
    if [ "$SKIP_WIFI" = "true" ]; then
        info "Masking IWD to prevent noise during wired-only tests..."
        m_exec "$SERVER" systemctl stop iwd 2>/dev/null || true
        m_exec "$CLIENT" systemctl stop iwd 2>/dev/null || true
    fi
}

inject_phy_and_wait() {
    local machine="$1" phy="$2" pid="$3"
    sudo iw phy "$phy" set netns "$pid" 2>/dev/null \
        || { warn "Failed to inject $phy into $machine"; return 1; }

    local retries=20
    for i in $(seq 1 "$retries"); do
        if m_exec "$machine" iw dev 2>/dev/null | grep -q 'Interface'; then
            info "✓ PHY $phy visible inside $machine"
            return 0
        fi
        sleep 0.5
    done
    warn "PHY $phy injection timed out for $machine"
    return 1
}

sanitize_in_machine() {
    local machine="$1" pid="$2"
    if m_exec "$machine" sanitize_wifi.sh 2>/dev/null; then
        return 0
    fi
    warn "systemd-run path failed for sanitize on $machine, falling back to nsenter"
    warn "Note: This fallback requires the host environment to have CAP_SYS_PTRACE."
    sudo nsenter --mount --pid --net --uts -t "$pid" -- \
        /usr/local/bin/sanitize_wifi.sh
}
