# RXNM (ROCKNIX Network Manager)

**RXNM** is a lightning-fast, modular CLI wrapper for `systemd-networkd` and `iwd`. It is aggressively optimized for low-power ARM and RISC-V embedded devices (specifically RK3326/RK3566 and SG2002 handhelds) while remaining 100% compatible with general Linux environments.

By eliminating monolithic middleware daemons, RXNM achieves a **0MB idle memory footprint** and sub-5ms read latencies, making it the ultimate networking stack for emulation handhelds, immutable OS designs, and containerized cloud environments.

**Latest Version:** `1.0.0-rc1`

## ⚡ Architecture & Performance

RXNM uses a **Hybrid C/Shell Architecture** to overcome the performance bottlenecks of embedded shell scripts while retaining the flexibility of Bash for high-level logic.

1. **The Native C Agent (`rxnm-agent`)**: A statically-linked (via `musl-gcc`), zero-dependency C binary that directly queries kernel Netlink (RTM/Genl) and implements a custom DBus wire protocol. It handles all fast-path read operations, atomic writes, and hardware polling.

2. **The Logic Dispatcher (`rxnm`)**: A lazy-loaded Bash frontend that handles complex state machine validation, JSON schema enforcement, and declarative configuration routing.

### Self-Documenting Logic Layer

Because the high-level orchestration and business logic are written in standard, structured Bash, **the documentation is the Bash itself**. The source code (`lib/rxnm-*.sh`) is designed to be readable and serves as the definitive reference for exact behaviors, state transitions, and file generation logic. This ensures that developers auditing the system never have to rely on potentially outdated external documentation to understand how the network stack is being manipulated.

### Latency Benchmarks (Read vs. Write Paths)

*Benchmarks conducted on Rockchip RK3326 (1.5GHz Quad-Core Cortex-A35).*

| Operation | RXNM Latency | NetworkManager (nmcli) | ConnMan (connmanctl) | IWD (Standalone) | Technical Context | 
 | ----- | ----- | ----- | ----- | ----- | ----- | 
| **Status Read (JSON)** | **< 5ms** | ~45-80ms | ~30-60ms | ~15-30ms | RXNM Agent bypasses DBus daemons, directly polling Netlink. | 
| **Internet Probe (TCP)** | **~20ms** | ~100ms+ | ~100ms+ | N/A | RXNM uses raw TCP sockets; others rely on HTTP/portal checks. | 
| **Config Write** | **~80ms** | ~150-300ms | ~100-200ms | ~50-100ms | Atomic `rename()` vs DBus/Disk Transaction overhead. | 
| **Roaming Trigger** | **< 15ms** | ~200ms+ | ~200ms+ | Internal | Event-driven Netlink monitor instantly nudges `iwd`. | 

### Resident Memory Footprint (The "Cost of Idle")

RXNM relies entirely on the native capabilities of the Linux kernel and systemd. It does not run an active management daemon in the background.

* **IWD Standalone**: Refers to `iwd` running with `EnableNetworkConfiguration=true` (Internal DHCP), bypassing networkd/NM.

| Component | RXNM Stack (Hybrid) | NetworkManager Stack | ConnMan Stack | IWD Stack (Standalone) | 
 | ----- | ----- | ----- | ----- | ----- | 
| **L2 Wifi** | **iwd**: ~3.5 MB | **wpa_supplicant**: ~6-12 MB | **wpa_supplicant**: ~6-12 MB | **iwd**: ~3.5 MB | 
| **L3 Network** | **systemd-networkd**: ~4.0 MB | **NetworkManager**: ~18-45 MB | **connman**: ~8-15 MB | *(Internal DHCP)* | 
| **DNS/LLMNR** | **systemd-resolved**: ~3.2 MB | *(Internal or dnsmasq)* | *(Internal)* | **resolved**: ~3.2 MB | 
| **Management** | **RXNM**: **0 MB** (Ephemeral) | *(Included in NM)* | *(Included in connman)* | **0 MB** | 
| **TOTAL** | **~10.7 MB** | **~24 MB - 57 MB** | **~14 MB - 27 MB** | **~6.7 MB*** | 

*\*Note: While IWD Standalone offers a marginally smaller footprint, the RXNM/systemd-networkd stack is the preferred default. This architecture provides robust hotplug handling, advanced profile management, and standardized configuration formats. Crucially, it allows RXNM to support any level of network complexity supported by `networkd` (VLANs, Bonds, VRFs, Bridges, WireGuard) "for free"—meaning these advanced enterprise features are available without incurring additional daemon overhead or requiring custom implementation logic.*

### Storage Longevity (eMMC/NAND Wear Leveling)

On embedded devices, frequent disk writes and `fsync()` calls accelerate hardware wear and cause UI stuttering due to I/O wait. RXNM uses a **RAM-First Configuration Strategy**, writing active configurations to `/run/systemd/network` (tmpfs).

| Stack | Writes to Flash | Syncs/Fdatasync | Persistence Strategy | 
 | ----- | ----- | ----- | ----- | 
| **RXNM (Hybrid)** | **1** | **1** | **RAM-only by default**; 1 write only if saving Profile/WiFi Creds. | 
| **IWD (Standalone)** | ~2 | ~1 | Writes credentials and lease files to `/var/lib/iwd`. | 
| **ConnMan** | ~5 | ~3 | Periodic updates to settings/state files. | 
| **NetworkManager** | ~6 - 12+ | ~4+ | Heavy persistence for leases, history, timestamps, and state. | 

### Wakeups & Battery Life

Comparative analysis of CPU wakeups induced by the network stack while connected but idle.

| Stack | Avg. Wakeups / Minute | Battery Impact | Technical Context | 
 | ----- | ----- | ----- | ----- | 
| **RXNM (Standard)** | **0** | **None** | **Binary exits after execution.** Zero background processes. | 
| **systemd-networkd** | ~0.1 | Near zero | Pure Netlink event subscriber; sleeps until kernel signal. | 
| **IWD (Standalone)** | ~0.3 | Negligible | Efficient event loop; minimal polling. | 
| **ConnMan** | ~10 - 30 | Low/Mod | Periodic housekeeping and state checks. | 
| **NetworkManager** | ~60 - 150+ | Moderate | Polling-heavy D-Bus architecture & periodic scanning. | 

## 🚀 Feature Set

* **Target-First RouterOS Syntax**: Intuitive command structure (e.g., `rxnm interface wlan0 show`).

* **Frontend/UI Ready**: Strict `stdout` hygiene with `--format json` output for robust integration into EmulationStation, React frontends, or web APIs.

* **IPv6 Native**: Automatic SLAAC, DHCPv6, IPv6 Privacy Extensions, and Prefix Delegation for both clients and hotspots.

* **Automated NAT/Tethering**: One-command hotspot creation with automatic `iptables` or `nftables` Masquerading and MSS Clamping.

### Advanced Wireless Modes

* **WiFi Client (Station)**: Standard WPA2/WPA3 connections.

* **WiFi Access Point (AP)**: Host a local network or share your internet connection.

* **WiFi Ad-Hoc (IBSS)**: Decentralized mesh connections.

* **WiFi Direct (P2P)**: Full support for P2P Client and **P2P Group Owner (GO)**.

* **DPP (Easy Connect)**: QR-code based, passwordless WiFi enrollment.

* **Opportunistic Roaming**: Native background monitor that steers `iwd` to better BSSIDs and dynamically switches profiles based on physical location (GPS/Gateway mapping).

### Virtualization & Software-Defined Networking (SDN)

* **Bridge**: Layer 2 bridging with STP and IGMP Snooping support.

* **Bonding**: Link aggregation supporting `active-backup`, `balance-rr`, and `802.3ad` (LACP).

* **VLAN**: 802.1Q Virtual LAN tagging.

* **VRF (Virtual Routing Forwarding)**: Create isolated routing tables and network namespaces.

* **MacVLAN / IPVLAN**: Specialized high-performance interfaces for containerized applications.

* **VPNs**: Native integration for **WireGuard** (`wg`), **TUN**, and **TAP** devices.

### Nullify Mode (Zero-Stack Lockdown)

**Designed for offline gaming, extreme battery conservation, or stabilizing devices with broken/flaky RF hardware.**

Executing `rxnm system nullify enable` performs a complete, aggressive teardown of the Linux networking subsystem. This mode renders the device effectively air-gapped at the kernel level and is persistent for the session.

**⚠️ WARNING:** This action is **NON-DETERMINISTIC** and may destabilize the system depending on hardware specifics. It will permanently disable all network functionality (SSH, SMB, WiFi, Bluetooth) for the current session until a reboot. Due to its destructive nature, this command **requires explicit confirmation** via the `--yes` flag.

* **Driver Unbinding**: Aggressively unbinds drivers from PCI and SDIO buses. This physically powers down radio chips, preventing battery drain and stopping kernel panics caused by faulty hardware drivers.
* **Stack Disable**: Sets kernel sysctls (`net.ipv4.conf.all.disable_ipv4=1`, etc.) to completely disable the IP stack handling.
* **Daemon Masking**: Masks `systemd-networkd`, `iwd`, `wpa_supplicant`, and `bluetoothd` to prevent them from attempting to re-initialize hardware or trigger wakeups.
* **Namespace Isolation**: Moves any remaining stubborn interfaces into a "null" network namespace to ensure no traffic can be processed.

## 🛠️ Installation & Building

For constrained environments (Initramfs, Embedded) and general distribution, RXNM defaults to **static linking** to create a zero-dependency binary.

### Compilation

```bash
# Clone the repository
git clone [https://codeberg.org/aenertia/rxnm.git](https://codeberg.org/aenertia/rxnm.git)
cd rxnm

# Compile the Agent (Optimized for size and static linking)
# If musl-gcc is available, this produces a ~50KB binary.
# Otherwise, it falls back to a standard static build (~700KB).
make tiny

# Install to /usr/lib/rocknix-network-manager and link to /usr/bin/rxnm
sudo make install
```

### Running Tests

The project includes a robust testing suite comparing C-Agent outputs against legacy bash fallback logic:

```bash
make test-all
```

## 📖 Comprehensive Usage Guide

RXNM commands follow the structure: `rxnm <category> [target] <action> [options]`.
Append `--format json` or `--format table` to any command to change output structure.

### 1. System Status & Diagnostics

```bash
# Human-readable consolidated status table (IPs, Routes, WiFi stats, Interfaces)
rxnm system status

# JSON output for UI/Container monitoring
rxnm system status --format json

# Check for Internet connectivity via fast TCP probes
rxnm system check internet

# Check for Captive Portals (Hotel/Airport WiFi)
rxnm system check portal

# Set global HTTP/HTTPS proxy
rxnm system proxy set --http "[http://10.0.0.1:8080](http://10.0.0.1:8080)" --https "[http://10.0.0.1:8080](http://10.0.0.1:8080)"
```

### 2. WiFi Operations (`rxnm wifi`)

```bash
# Scan for available networks (Returns SSID, Signal %, Security)
rxnm wifi scan

# Connect to a standard network (Interactive password prompt if omitted)
rxnm wifi connect "HomeWiFi" --password "supersecret"

# Connect to a hidden network
rxnm wifi connect "HiddenNet" --password "supersecret" --hidden

# Start a WiFi Hotspot (Sharing your current internet connection via NAT)
rxnm wifi ap start "MyHotspot" --password "12345678" --share

# Start a local-only WiFi Hotspot (No internet forwarding)
rxnm wifi ap start "LocalPlay" --password "12345678"

# Disconnect and return to client mode
rxnm wifi disconnect
rxnm wifi ap stop

# Forget a saved network
rxnm wifi forget "HomeWiFi"

# List saved/known networks
rxnm wifi list

# Start WPS Push-Button connection
rxnm wifi wps
```

### 3. WiFi Direct / P2P (`rxnm wifi p2p`)

```bash
# Scan for nearby P2P devices (e.g., Android phones, other handhelds)
rxnm wifi p2p scan

# Connect to a P2P device
rxnm wifi p2p connect "Android_Device_123"

# Check active P2P connections and Group Owner status
rxnm wifi p2p status

# Disconnect current P2P session
rxnm wifi p2p disconnect
```

### 4. Interface Configuration (`rxnm interface`)

```bash
# Show specific interface details
rxnm interface eth0 show

# Set an interface to DHCP
rxnm interface eth0 set dhcp

# Set a Static IP with Gateway and custom DNS
rxnm interface wlan0 set static 192.168.1.50/24 --gateway 192.168.1.1 --dns 1.1.1.1,8.8.8.8

# Modify hardware link properties (Speed, Duplex, Auto-neg, Wake-on-LAN)
rxnm interface eth0 set hardware --speed 1000 --duplex full --autoneg no --wol magic

# Administratively bring an interface up or down
rxnm interface eth0 enable
rxnm interface eth0 disable

# Manually trigger a hotplug evaluation event
rxnm interface eth0 hotplug
```

### 5. Virtualization & Tunnels

```bash
# Bridge: Create and assign members
rxnm bridge create br0
rxnm bridge add-member eth0 --bridge br0

# VLAN: Create VLAN 10 on parent eth0
rxnm vlan create eth0.10 --parent eth0 --id 10

# VRF: Create an isolated routing table (Table 100)
rxnm vrf create mgmt_vrf --table 100
rxnm vrf add-member eth0 --vrf mgmt_vrf

# WireGuard: Establish a secure tunnel
rxnm vpn wireguard connect wg0 \
  --private-key "aBcDeF..." \
  --peer-key "XyZaBc..." \
  --endpoint "198.51.100.1:51820" \
  --address "10.0.0.2/24" \
  --allowed-ips "0.0.0.0/0"
```

### 6. Bluetooth Tethering (`rxnm bluetooth`)

```bash
# Scan and Pair
rxnm bluetooth scan
rxnm bluetooth pair "XX:XX:XX:XX:XX:XX"

# Enable PAN Client (Receive internet from your phone)
rxnm bluetooth pan enable --mode client

# Enable PAN Host (Share your device's internet with paired Bluetooth devices)
rxnm bluetooth pan enable --mode host --share
```

### 7. Profile Management (`rxnm profile`)

Because RXNM utilizes a RAM-first architecture, reboots clear any configurations not explicitly saved.
The system automatically loads the `default` profile at boot.

```bash
# Save current active runtime configuration to the persistent 'default' profile
rxnm profile save default

# Save a snapshot of the current state under a specific location name
rxnm profile save "Work"

# Load a saved profile into RAM, immediately applying it
rxnm profile load "Work"

# List available persistent profiles
rxnm profile list
```

## 📁 File & Configuration Paths

* **Persistent Network Configs**: `/storage/.config/network/`
* **Persistent Profiles**: `/storage/.config/network/profiles/`
* **WiFi Credentials (PSK/802.1x)**: `/var/lib/iwd/` *(Requires 0600 secure permissions)*
* **Global DNS/Resolved Overrides**: `/storage/.config/resolved.conf.d/`
* **Ephemeral/Runtime Configs (RAM)**: `/run/systemd/network/`
* **Runtime Locks & Status Caches**: `/run/rocknix/`
* **API JSON Schema Definition**: `api-schema.json` (Root of repository)

## 🤝 Plugins & Extensibility

RXNM supports external plugin execution without modifying core code. Executables placed in `/storage/.config/network/plugins` or `/usr/lib/rocknix-network-manager/plugins` are automatically exposed as top-level categories in the CLI.

Plugins inherit the environment configuration, standard bash utilities (`rxnm-api.sh`), and the user's `--format` request.

## License

GPL-2.0-or-later
Copyright (C) 2026-present Joel Wirāmu Pauling
