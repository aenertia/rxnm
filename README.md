# RXNM (ROCKNIX Network Manager)

**RXNM** is a lightweight, modular CLI wrapper for `systemd-networkd` and `iwd`, optimized for low-power ARM devices (specifically RK3326/RK3566 handhelds) but compatible with general Linux environments. While designed specifically for the ROCKNIX ecosystem, this project is developed independently and is not a core component of the ROCKNIX distribution itself.

## Key Features

* **Zero-Overhead Architecture**: Ephemeral execution. Runs, generates config, reloads systemd, and exits. 0MB resident memory when idle.
* **Target-First Syntax**: Intuitive RouterOS-style syntax (e.g., `rxnm interface wlan0 show`).
* **Modular Architecture**: Split into domain-specific libraries (`rxnm-wifi.sh`, `rxnm-virt.sh`, etc.) for maintainability.
* **Frontend Ready**: Strict stdout hygiene with `--format json` output for easy integration into EmulationStation or other UIs.
* **Advanced WiFi**: Full `iwd` integration. Supports SAE (WPA3), OWE, Enterprise (802.1x), WPS, and Wi-Fi 7 Multi-Link Operation (MLO).
* **IPv6 Native**: Automatic SLAAC, DHCPv6, and Prefix Delegation support for both clients and hotspots.
* **Virtual Devices**: Native support for **Bridges**, **VLANs**, **Bonds** (Active-Backup/LACP), **VRFs**, **MacVLANs**, **IPVLANs**, and **WireGuard**.
* **Tethering & NAT**: One-command hotspot creation (WiFi AP or Bluetooth PAN) with automatic NAT/Masquerading via `iptables` or `nftables`.
* **Profiles**: Snapshot, export, and restore complete network states or interface-specific configurations.

## Target Environments

* **Embedded Handhelds (ROCKNIX):** Provides a "single pane of glass" abstraction over `iwd`, `networkctl`, `ip`, and `resolvectl`.
* **Lightweight Containers:** Ideal for "fat" systemd containers where persistent daemons (NetworkManager) are too heavy.
* **Headless SBCs:** A scriptable, persistent alternative to `nmcli` or `netplan`.

---

## Installation

### Dependencies
Ensure the following tools are available in your path:
* `bash` (4.4+)
* `systemd` (specifically `systemd-networkd` and `systemd-resolved`)
* `iwd` (Wireless daemon)
* `jq` (JSON processing)
* `curl` (Connectivity checks)
* `iptables` or `nftables` (NAT/Masquerading)

### Manual Deployment
RXNM is a script-based tool. Deploy the `bin` and `lib` directories to a system path.

```bash
mkdir -p /usr/lib/rocknix-network-manager
cp -r bin lib /usr/lib/rocknix-network-manager/
ln -s /usr/lib/rocknix-network-manager/bin/rocknix-network-manager /usr/bin/rxnm
```

---

## Command Syntax

RXNM uses a hierarchical command structure:

`rxnm <category> [target] <action> [options]`

* **Category**: `wifi`, `interface`, `system`, `bridge`, `vpn`, `profile`, etc.
* **Target** (Optional): The interface name (e.g., `wlan0`). If omitted, RXNM attempts to auto-detect appropriate interfaces for `wifi` commands.
* **Action**: `connect`, `show`, `create`, `set`, etc.

### Global Options
* `--json`: Output results in JSON format (shortcut for `--format json`).
* `--format <fmt>`: Specify output format: `human` (default), `json`, or `table`.
* `--yes`, `-y`: Skip confirmation prompts for destructive actions.
* `--debug`: Enable verbose shell tracing.

---

## Usage Guide

### 1. System Status & Diagnostics (`rxnm system`)

Get a quick overview of the network state.

```bash
# Human readable status table (Interfaces, IP, WiFi signal, Links)
rxnm system status

# JSON output for UI integration
rxnm system status --format json

# Check internet connectivity (IPv4/IPv6 detection)
rxnm system check internet

# Check for Captive Portal (Hotspot login pages)
rxnm system check portal
```

### 2. WiFi Operations (`rxnm wifi`)

Manage wireless connections via `iwd`.

```bash
# Scan for networks (Auto-detects wireless interface)
rxnm wifi scan

# List known (saved) networks
rxnm wifi list

# Connect to a network (Prompts for password if not provided)
rxnm wifi connect "MyWiFi"
rxnm wifi connect "MyWiFi" --password "s3cret"
rxnm wifi connect "HiddenSSID" --hidden --password "s3cret"

# Securely pipe password (prevents history logging)
echo "s3cret" | rxnm wifi connect "MyWiFi" --password-stdin

# Start a Hotspot (Access Point) with NAT/DHCP
rxnm wifi ap start "MyHotspot" --password "12345678" --share

# Connect via WPS (Push Button)
rxnm wifi wps

# Set Regulatory Domain (Country Code)
rxnm wifi country US
```

### 3. Interface Configuration (`rxnm interface`)

Manage IP addressing and link state.

```bash
# Show details for specific interface
rxnm interface wlan0 show

# Enable DHCP (Default)
rxnm interface eth0 set dhcp

# Set Static IP (CIDR notation required)
rxnm interface eth0 set static 192.168.1.50/24 --gateway 192.168.1.1 --dns 8.8.8.8,1.1.1.1

# Enable/Disable interface
rxnm interface wlan0 disable
rxnm interface wlan0 enable
```

### 4. Virtual Devices (`rxnm bridge`, `bond`, `vlan`, `vrf`)

Create complex network topologies easily.

```bash
# --- Bridges ---
# Create a bridge
rxnm bridge create br0
# Add a member interface
rxnm bridge add-member eth0 --bridge br0

# --- VLANs ---
# Create VLAN ID 10 on eth0
rxnm vlan create vlan10 --parent eth0 --id 10

# --- Bonding (Link Aggregation) ---
# Create an active-backup bond
rxnm bond create bond0 --mode active-backup
rxnm bond add-slave eth0 --bond bond0
rxnm bond add-slave wlan0 --bond bond0

# --- VRF (Virtual Routing and Forwarding) ---
# Create a VRF with routing table 100
rxnm vrf create blue --table 100
rxnm vrf add-member eth0 --vrf blue
```

### 5. VPN & Tunnels (`rxnm vpn`)

Native WireGuard support via `systemd-networkd`.

```bash
# Connect to WireGuard VPN
rxnm vpn wireguard connect wg0 \
    --address 10.100.0.2/24 \
    --private-key "PRIVATE_KEY" \
    --peer-key "PEER_PUB_KEY" \
    --endpoint "vpn.example.com:51820" \
    --allowed-ips "0.0.0.0/0"

# Disconnect and remove interface
rxnm vpn wireguard disconnect wg0

# Create TUN/TAP devices
rxnm tun create tun0 --user root
```

### 6. Bluetooth Tethering (`rxnm bluetooth`)

Manage Bluetooth PAN (Personal Area Network).

```bash
# Scan for devices
rxnm bluetooth scan

# Pair with a phone
rxnm bluetooth pair AA:BB:CC:DD:EE:FF

# Enable Bluetooth Tethering Client (Connect to phone hotspot)
rxnm bluetooth pan enable --mode client

# Enable Bluetooth Tethering Server (Share internet to others)
rxnm bluetooth pan enable --mode host --share
```

### 7. Profile Management (`rxnm profile`)

Save and switch between network environments (e.g., Home vs. Travel).

```bash
# Save current global network state as 'Home'
rxnm profile save Home

# Load 'Home' profile (Overwrites current config)
rxnm profile load Home

# Save only specific interface config
rxnm profile save Hotel --interface wlan0

# Export profile for backup
rxnm profile export Home --file /storage/backups/home_net.tar.gz

# Import profile
rxnm profile import /storage/backups/work_net.tar.gz
```

---

## Configuration Paths

* **Network Configs**: `/storage/.config/network/` (Override via `$CONF_DIR`)
    * `.network` files: `systemd-networkd` configuration.
    * `.netdev` files: Virtual device definitions.
* **WiFi Credentials**: `/var/lib/iwd/` (Secure storage 0600 permissions)
* **Profiles**: `/storage/.config/network/profiles/`
* **Runtime Locks**: `/run/rocknix/network.lock`

---

## Comparison: RXNM vs. Others

| Feature | RXNM | NetworkManager | ConnMan | OpenWrt (netifd) |
| :--- | :---: | :---: | :---: | :---: |
| **Backend** | systemd-networkd + iwd | Internal / wpa_supplicant | Internal / wpa_supplicant | netifd + hostapd |
| **Resident Memory** | **0 MB** (Ephemeral) | ~15-50 MB | ~5-15 MB | ~2-5 MB |
| **WireGuard** | Native | Yes | No (Plugins) | Native |
| **Bonding/Bridging** | Native | Yes | Basic | Native |
| **VRF/VLAN** | Native | Yes | Basic | Native |
| **Startup Time** | **~70ms** | ~1200ms | ~450ms | ~150ms |
| **Philosophy** | "Run & Done" Script | Persistent Daemon | Persistent Daemon | Event Loop |

### Why RXNM?
1.  **Single Pane of Glass**: Aggregates `ip`, `iwd`, `resolvectl`, and `networkctl` into one JSON API.
2.  **Resource Efficiency**: It exits immediately after generating config. Zero CPU/RAM usage while gaming.
3.  **Respects Manual Config**: It only modifies files it is explicitly told to. You can manually drop standard `.network` files in the config dir and RXNM will respect them.

## License

GPL-2.0-or-later
Copyright (C) 2026-present Joel Wirāmu Pauling
