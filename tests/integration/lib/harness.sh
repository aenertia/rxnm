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

# Helper for colored output
info() { echo -e "\033[0;36m[TEST]\033[0m $1"; }
err() { echo -e "\033[0;31m[FAIL]\033[0m $1"; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $1"; }

# CI-friendly execution helper
m_exec() {
    local machine="$1"
    shift
    # --setenv is critical to avoid Exit 203 (command not found) in transient units
    # --wait --pipe ensures we get output and wait for completion
    # RXNM_FORCE_NETWORKCTL bypasses raw DBus broker strictness in Fedora nspawn
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
    
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    
    if [ -n "$WIFI_TCPDUMP_PID" ]; then
        kill "$WIFI_TCPDUMP_PID" 2>/dev/null || true
        wait "$WIFI_TCPDUMP_PID" 2>/dev/null || true
    fi
    
    if [ "$EXIT_CODE" -ne 0 ]; then
        err "TEST FAILED - DUMPING LOGS"
        
        echo ">>> NETWORK TRAFFIC (TCPDUMP BRIDGE) <<<"
        if [ -f "$PCAP_FILE" ] && command -v tcpdump >/dev/null; then
            tcpdump -n -e -vv -r "$PCAP_FILE" || echo "Error parsing pcap"
        fi
        
        echo ">>> WIFI TRAFFIC (TCPDUMP HWSIM0) <<<"
        if [ -f "$WIFI_PCAP_FILE" ] && command -v tcpdump >/dev/null; then
            tcpdump -n -e -vv -r "$WIFI_PCAP_FILE" || echo "Error parsing wifi pcap"
        fi
        
        [ -f "/tmp/$SERVER.log" ] && { echo ">>> SERVER CONSOLE <<<"; cat "/tmp/$SERVER.log"; }
        [ -f "/tmp/$CLIENT.log" ] && { echo ">>> CLIENT CONSOLE <<<"; cat "/tmp/$CLIENT.log"; }

        echo ">>> SERVER JOURNAL <<<"
        journalctl -M "$SERVER" -u systemd-networkd -n 100 --no-pager || true
        journalctl -M "$SERVER" -u iwd -n 100 --no-pager || true
        
        echo ">>> CLIENT JOURNAL <<<"
        journalctl -M "$CLIENT" -u systemd-networkd -n 100 --no-pager || true
        journalctl -M "$CLIENT" -u iwd -n 100 --no-pager || true
        
        echo ">>> FINAL STATUS CHECK <<<"
        m_exec "$SERVER" ip addr show || true
        m_exec "$CLIENT" ip addr show || true
    fi

    machinectl terminate "$SERVER" 2>/dev/null || true
    machinectl terminate "$CLIENT" 2>/dev/null || true
    
    ip link delete "$BRIDGE" 2>/dev/null || true
    sudo modprobe -r mac80211_hwsim 2>/dev/null || true
    
    if [ "$EXIT_CODE" -eq 0 ]; then
        rm -f "$PCAP_FILE" "$WIFI_PCAP_FILE" 2>/dev/null
    else
        info "Test failed: PCAPs retained at /tmp/ for forensics."
    fi
}

setup_bridge() {
    info "Setting up Host Bridge ($BRIDGE)..."
    if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
        ip link add "$BRIDGE" type bridge
        ip link set "$BRIDGE" up
        # CRITICAL: Disable multicast snooping to prevent IPv6 Neighbor Discovery drop failures in isolated bridges
        echo 0 > "/sys/class/net/$BRIDGE/bridge/multicast_snooping" 2>/dev/null || true
        sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
        sysctl -w "net.ipv4.conf.$BRIDGE.forwarding=1" 2>/dev/null || true
    fi

    # Ensure Host Kernel allows unprivileged BPF if restricted (helps inside container context)
    sysctl -w kernel.unprivileged_bpf_disabled=0 2>/dev/null || true

    if command -v tcpdump >/dev/null; then
        info "Starting packet capture on $BRIDGE..."
        sudo tcpdump -U -i "$BRIDGE" -w "$PCAP_FILE" -s 0 >/dev/null 2>&1 &
        TCPDUMP_PID=$!
    fi
}

setup_hwsim() {
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
            
            # Start WiFi Sniffer on the virtual airwaves
            if command -v tcpdump >/dev/null && ip link show hwsim0 >/dev/null 2>&1; then
                sudo ip link set hwsim0 up
                info "Starting WiFi packet capture on hwsim0..."
                sudo tcpdump -U -i hwsim0 -w "$WIFI_PCAP_FILE" -s 0 >/dev/null 2>&1 &
                WIFI_TCPDUMP_PID=$!
            fi
        else
            warn "mac80211_hwsim loaded but interfaces not found (Found: $WLAN_IFACES)."
        fi
    else
        warn "mac80211_hwsim module not available on host. Virtual WiFi tests will be skipped."
    fi
}

build_rootfs() {
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
        
        rm -rf "$ROOTFS/etc/systemd/network"
        ln -sf /run/systemd/network "$ROOTFS/etc/systemd/network"
        echo "$HASH" > "$ROOTFS/.rxnm_hash"
    fi

    # Pre-stage PHY sanitization script into the base rootfs before overlayfs snapshot.
    # This surgically removes any host-inherited P2P-devices that consume AP capability slots.
    mkdir -p "$ROOTFS/usr/local/bin"
    cat <<'EOF' > "$ROOTFS/usr/local/bin/sanitize_wifi.sh"
#!/bin/bash
PHY=$(iw phy | awk '/Wiphy/{print "phy"$2}' | head -n1)
[ -z "$PHY" ] && exit 0

# Grab the wdev ID precisely by looking for the wdev hex immediately preceding a P2P-device assignment
for wdev in $(iw dev | awk '/wdev 0x/{w=$2} /type P2P-device/{print w}'); do
    iw wdev "$wdev" del 2>/dev/null || true
done

WLAN_IFACE=$(iw dev | awk '$1=="Interface"{print $2; exit}')
if [ -n "$WLAN_IFACE" ]; then
    ip link set "$WLAN_IFACE" down 2>/dev/null || true
    ip link set "$WLAN_IFACE" up 2>/dev/null || true
fi
EOF
    chmod +x "$ROOTFS/usr/local/bin/sanitize_wifi.sh"
}

boot_machines() {
    info "Booting Machines..."
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
    if [ -c /dev/rfkill ]; then
        COMMON_ARGS+=("--bind=/dev/rfkill")
    fi

    # Launch containers without --network-interface injection to prevent mac80211 hangs
    systemd-nspawn -D "$ROOTFS" -M "$SERVER" "${COMMON_ARGS[@]}" > "/tmp/$SERVER.log" 2>&1 &
    systemd-nspawn -D "$ROOTFS" -M "$CLIENT" "${COMMON_ARGS[@]}" > "/tmp/$CLIENT.log" 2>&1 &

    info "Waiting for systemd initialization..."
    for i in $(seq 1 30); do
        if machinectl status "$SERVER" >/dev/null 2>&1 && machinectl status "$CLIENT" >/dev/null 2>&1; then break; fi
        sleep 1
    done

    check_ready "$SERVER" || { err "$SERVER failed"; exit 1; }
    check_ready "$CLIENT" || { err "$CLIENT failed"; exit 1; }
}

check_ready() {
    local machine="$1"
    for i in $(seq 1 60); do
        if m_exec "$machine" systemctl is-active systemd-networkd 2>/dev/null | grep -q "active"; then return 0; fi
        sleep 1
    done
    return 1
}

wait_iwd_ready() {
    local machine="$1"
    local retries=30
    for i in $(seq 1 "$retries"); do
        if m_exec "$machine" busctl list 2>/dev/null | grep -q 'net.connman.iwd'; then
            info "✓ IWD DBus registered on $machine"
            return 0
        fi
        sleep 1
    done
    err "IWD never registered on DBus in $machine after ${retries}s"
    m_exec "$machine" journalctl -u iwd --no-pager -n 30 || true
    return 1
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
    sudo nsenter --mount --pid --net --uts -t "$pid" -- \
        /usr/local/bin/sanitize_wifi.sh
}
