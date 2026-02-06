# RXNM (ROCKNIX Network Manager)

**RXNM** is a lightweight, modular CLI wrapper for `systemd-networkd` and `iwd`, optimized for low-power ARM devices (specifically RK3326/RK3566 handhelds) but compatible with general Linux environments. While designed specifically for the ROCKNIX ecosystem, this project is developed independently and is not a core component of the ROCKNIX distribution itself.

## Key Features

* **Modular Architecture**: Split into domain-specific libraries for maintainability and extensibility.
* **WiFi Management**: Full integration with `iwd` for scanning, connecting (Open/PSK/802.1x), WPS, and AP/Ad-Hoc host modes. Supports Wi-Fi 7 Multi-Link Operation (MLO) transparently.
* **IPv6 Native**: Fully IPv6 compliant out of the box. Handles SLAAC, DHCPv6, and Prefix Delegation automatically without manual configuration for both client and hotspot modes.
* **Virtual Devices**: Native support for creating and managing **Bridges**, **VLANs**, **Bonds** (Active-Backup/LACP), and **WireGuard** tunnels.
* **Tethering & NAT**: One-command hotspot creation (WiFi or Bluetooth PAN) with automatic NAT/Masquerading via `iptables` or `nftables`.
* **Performance Tuned**: Includes kernel optimizations for low-power targets (bridge netfilter disabling, fast open, conntrack tuning).
* **Persistence**: Generates standard `systemd.network` and `iwd` configuration files that survive reboots.

## Target Environments & Use Cases

While built for gaming handhelds, RXNM's architecture makes it ideal for several other scenarios:

* **Embedded Handhelds (ROCKNIX):** The primary target. Beyond minimizing CPU usage for battery life, RXNM provides a **single pane of glass** for the OS and frontend (e.g., EmulationStation). It abstracts the complexity of disparate underlying tools (`iwctl`, `networkctl`, `ip`, `iptables`, `resolvectl`) into a unified, consistent JSON API. This allows scripts, game launchers, and UIs to query status, toggle VPNs, or configure hotspots without needing to parse multiple inconsistent CLI outputs.
* **Lightweight Containers (LXC/LXD, systemd-nspawn):** Perfect for "fat" containers running a systemd init. Because RXNM is ephemeral (exits immediately after config generation), it consumes **0MB of resident memory** inside the container, unlike NetworkManager or ConnMan which run as persistent daemons.
* **Single-Board Computers (Raspberry Pi, Odroid):** A lightweight alternative for headless setups where `nmcli` is overkill and manual `ip` commands are non-persistent.
* **CI/CD Pipelines:** The deterministic, scriptable CLI makes it easy to set up complex ephemeral network topologies (bridges, VLANs, bonds) during test runs without interactive prompts.

## Directory Structure

```text
/usr/lib/rocknix-network-manager/
├── bin/
│   ├── rocknix-network-manager   # Main executable
│   └── rxnm                      # Shorthand wrapper
└── lib/
    ├── rxnm-bluetooth.sh         # Bluetooth PAN logic
    ├── rxnm-config-builder.sh    # systemd-networkd config generation
    ├── rxnm-constants.sh         # Global constants & hardware detection
    ├── rxnm-diagnostics.sh       # Status & connectivity checks
    ├── rxnm-interfaces.sh        # IP, Bridge, VLAN, Bond, WireGuard logic
    ├── rxnm-profiles.sh          # Profile management
    ├── rxnm-system.sh            # Service control & Firewall/NAT
    ├── rxnm-utils.sh             # Core helpers & locking
    └── rxnm-wifi.sh              # WiFi logic
```

## Installation

1. **Dependencies**: Ensure the following are installed:
   * `systemd` (networkd, resolved)
   * `iwd` (for WiFi)
   * `jq` (for JSON output)
   * `curl` (for connectivity checks)
   * `iptables` or `nftables` (for NAT/Firewall)

2. **Deploy**:
   Copy the `bin` and `lib` directories to a suitable location (e.g., `/usr/lib/rocknix-network-manager`).
   Symlink the executables to your path:
   ```bash
   ln -s /usr/lib/rocknix-network-manager/bin/rocknix-network-manager /usr/bin/rocknix-network-manager
   ln -s /usr/lib/rocknix-network-manager/bin/rxnm /usr/bin/rxnm
   ```

## Usage Guide

### 1. General Status
Get a JSON representation of all network interfaces, IPs, and connection states.
```bash
rxnm status
```

### 2. WiFi Operations
```bash
# Scan for networks
rxnm scan

# Connect to a network
rxnm connect --ssid "MyWiFi" --password "s3cretpass"

# Connect via WPS (Push Button)
rxnm wps

# Forget a network (removes config)
rxnm forget --ssid "MyWiFi"
```
*Note: Wi-Fi 7 MLO is supported natively. If your hardware/driver supports it, `rxnm connect` will establish a multi-link connection automatically.*

### 3. IP Configuration
```bash
# Set interface to DHCP (Default)
rxnm set-dhcp --interface eth0

# Set Static IP
rxnm set-static --interface eth0 --ip 192.168.1.50/24 --gateway 192.168.1.1 --dns 1.1.1.1
```

### 4. Network Bonding (Link Aggregation)
Combine multiple interfaces for redundancy or throughput.
```bash
# 1. Create the Bond interface
rxnm create-bond --name bond0 --mode active-backup

# 2. Add physical interfaces to the bond
rxnm set-bond-slave --interface eth0 --bond bond0
rxnm set-bond-slave --interface eth1 --bond bond0
```
*Supported modes: active-backup, 802.3ad (LACP), balance-rr, etc.*

### 5. Bridging
Useful for virtualization or passing traffic through.
```bash
# 1. Create the Bridge
rxnm create-bridge --name br0

# 2. Add an interface (or a bond!) to the bridge
rxnm set-member --interface eth0 --bridge br0
```

### 6. WireGuard VPN
Create a client interface easily.
```bash
rxnm connect-wireguard \
    --name wg0 \
    --address 10.100.0.2/24 \
    --private-key "YOUR_PRIVATE_KEY" \
    --peer-key "PEER_PUBLIC_KEY" \
    --endpoint "vpn.example.com:51820" \
    --allowed-ips "0.0.0.0/0"
```

### 7. Hotspot & Tethering
Turn the device into a router.
```bash
# WiFi Hotspot (AP Mode)
rxnm host --ssid "MyHotspot" --password "password123" --share

# Bluetooth Tethering (PAN NAP)
rxnm pan-net enable --mode host --share
```
*The `--share` flag automatically enables IP forwarding and configures NAT/Masquerading.*

### 8. Profile Management
Profiles are handled natively through simple file management. Want a **Work** and **Home** profile? No problem!

RXNM saves the current state of an interface as a profile file, allowing you to swap configurations instantly.
```bash
# 1. Configure for Home
rxnm set-static --interface wlan0 --ip 192.168.1.50
rxnm profile save --name Home --interface wlan0

# 2. Configure for Work
rxnm set-dhcp --interface wlan0
rxnm profile save --name Work --interface wlan0

# 3. Swap between them instantly
rxnm profile load --name Home --interface wlan0
```

## Comparative Analysis

RXNM was built specifically because existing solutions were either too heavy, too complex, or deprecated for the specific use case of ROCKNIX handhelds. Below is a detailed breakdown of how RXNM compares to other common network managers in the Linux ecosystem.

### Feature Matrix

| Feature | RXNM | NetworkManager | ConnMan | OpenWrt (netifd) | Nmstate | Netplan | Wicd |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Backend** | systemd-networkd + iwd | Internal / wpa_supplicant | Internal / wpa_supplicant | netifd + hostapd | NetworkManager / Nispor | (Generator) | Python / wpa_supplicant |
| **WiFi 7 / MLO** | Native (via iwd) | Yes | Partial | Yes | Dependent | Dependent | No |
| **WireGuard** | Native (networkd) | Yes | No (requires plugins) | Native | Yes | Yes | No |
| **Bonding/Bridging** | Native | Yes | Basic | Native | Yes | Yes | No |
| **Tethering (NAT)** | Auto (iptables/nft) | Yes | Yes | Native (firewall4) | No (Manual) | No | No |
| **Config Format** | INI (systemd) | INI / Keyfile | INI | UCI | YAML/JSON | YAML | Custom |
| **Maintenance Status** | **Active** | Active | Active | Active | Active | Active | **Dead** |

### Resource Overhead & Architecture

| Metric | RXNM | NetworkManager | ConnMan | OpenWrt (netifd) | Nmstate | Netplan | Wicd |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Resident Memory** | **0 MB** (Scripts exit) | ~15-50 MB | ~5-15 MB | ~2-5 MB | ~20 MB (Python) | ~0 MB | ~20 MB |
| **Dependencies** | Bash, systemd, iwd, jq, curl | GLib, DBus, Python/Perl | GLib, DBus | ubus, uci, json-c | Python, NM/Nispor | Python, YAML | Python 2 |
| **Startup Impact** | Negligible | High | Medium | Low | Medium | Low | High |
| **Architecture** | Ephemeral CLI Wrapper | Monolithic Daemon | Monolithic Daemon | Event-driven Daemon | Declarative API | Generator | Monolithic Daemon |
| **Startup Time (RK3326)** | **~70ms** | ~1200ms | ~450ms | ~150ms | ~1800ms | ~300ms | ~1500ms |
| **Idle CPU (RK3326)** | **0.00%** | ~1-2% | ~0.5% | ~0% | N/A | 0% | ~2% |

### Detailed Review

#### NetworkManager
* **Pros:** The "batteries included" standard. Handles everything imaginable (Modems, Enterprise WiFi, GUIs). Excellent integration with desktop environments (GNOME/KDE).
* **Cons:** Massive overkill for embedded handhelds. Slow startup adds to boot time. Heavy runtime memory usage. Complexity makes simple headless configuration harder than necessary. Can interfere with custom systemd-networkd setups.

#### ConnMan
* **Pros:** Designed specifically for embedded systems (Intel/Sailfish). Lighter than NetworkManager.
* **Cons:** Configuration syntax can be obtuse via CLI. Often lacks newer features (like native WireGuard or advanced bonding) out of the box without plugins. Documentation is sparse compared to systemd-networkd.

#### OpenWrt (netifd)
* **Pros:** The gold standard for embedded routing. UCI provides a unified, declarative configuration interface for *everything*. Extremely robust, event-driven, and battle-tested on low-end hardware.
* **Cons:** Heavily tied to the OpenWrt ecosystem infrastructure (`procd`, `ubus`, `uci`). Porting `netifd` to a standard glibc/systemd Linux environment is non-trivial and often introduces a significant dependency chain, making it less suitable as a standalone drop-in manager for general distributions.

#### Nmstate (Kubernetes/OpenShift)
* **Pros:** The declarative standard for modern cloud-native environments and automation (Ansible/Kubernetes CRDs). Excellent for "Infrastructure as Code" (IaC) where network state is defined via YAML/JSON.
* **Cons:** It is an API abstraction layer that sits *on top* of other providers (usually NetworkManager). Requires Python. Designed for servers and clusters, introducing unnecessary abstraction layers and dependencies for a single-user embedded device.

#### Netplan
* **Pros:** Clean YAML syntax. Standard on Ubuntu. Useful for defining complex static topologies.
* **Cons:** It is an abstraction layer, not a manager. It generates configs for systemd-networkd or NetworkManager. On ROCKNIX, adding Python/YAML parsing overhead just to generate INI files that RXNM writes directly is unnecessary complexity.

#### Wicd
* **Pros:** Was a popular lightweight choice in 2010. Simple UI.
* **Cons:** **Deprecated and Abandoned**. Relies on Python 2. No support for modern standards (SAE/WPA3, WireGuard, Wi-Fi 6/7). Included in this list only for historical context; do not use.

#### RXNM (ROCKNIX Network Manager)
* **Pros:**
    * **Zero-Loss Performance:** RXNM is an ephemeral Bash script wrapper. It generates configuration files, tells `systemd-networkd` to reload, and exits. The actual network management is handled by the kernel and PID 1 (systemd), which are already running, resulting in 0MB resident RAM usage for the manager itself.
    * **IWD Integration:** Uses `iwd`, which is significantly smaller, faster, and more modern than `wpa_supplicant`.
    * **Modularity:** Codebase is readable shell scripts, easily audited and modified by sysadmins.
    * **Target Optimization:** Includes specific sysctl kernel tuning for RK3326/RK3566 chipsets.
    * **Non-Intrusive Design:** Unlike monolithic managers that overwrite manual changes, RXNM is transparent. If a feature (like complex certificate-based EAP-TLS) is not implemented in the CLI, you can simply drop a standard `systemd.network` or `iwd` config file into the directory. RXNM respects existing configurations and does not get in the way.
* **Cons:**
    * **Strict Toolchain:** Requires `curl` and `jq` to be present in the user environment for diagnostics and JSON output formatting.
    * **Hard System Dependencies:** Strictly requires `systemd` (specifically `systemd-networkd` and `systemd-resolved` must be compiled in). Incompatible with OpenRC, runit, or distributions that strip these components.
    * **Wireless Coupling:** Strictly coupled with `iwd` for all wireless operations; does not support `wpa_supplicant`.
    * **No Native GUI:** Lacks a built-in GUI. Designed specifically for integration with EmulationStation via JSON interfaces or for headless operation.

## Configuration Storage

* **Network Configs**: Stored in `/storage/.config/network/` (or customized via `$CONF_DIR`).
* **WiFi Credentials**: Stored securely in `/var/lib/iwd/` (or system default).
* **Locking**: Runtime locks are maintained in `/run/rocknix/` to prevent concurrent modification conflicts.

## License

GPL-2.0-or-later  
Copyright (C) 2026-present Joel Wirāmu Pauling
