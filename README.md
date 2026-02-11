# RXNM (ROCKNIX Network Manager)

**RXNM** is a lightweight, modular CLI wrapper for `systemd-networkd` and `iwd`, optimized for low-power ARM and RISC-V devices (specifically RK3326/RK3566 and SG2002 handhelds) but compatible with general Linux environments. While designed specifically for the ROCKNIX ecosystem, this project is developed independently and is not a core component of the ROCKNIX distribution itself.

**Latest Version:** `1.0.0-rc1`

## Key Features

* **Hybrid C/Shell Architecture**: Uses a statically linked C agent (`rxnm-agent`) for high-frequency read operations (status, diagnostics) and atomic writes, falling back to Bash for complex logic.

* **Zero-Overhead Architecture**: Ephemeral execution. Runs, generates config, reloads systemd, and exits. 0MB resident memory when idle.

* **Target-First Syntax**: Intuitive RouterOS-style syntax (e.g., `rxnm interface wlan0 show`).

* **Frontend Ready**: Strict stdout hygiene with `--format json` output for easy integration into EmulationStation or other UIs.

* **Advanced Wireless Modes**:

  * **WiFi**: Station (Client), Access Point (AP), Ad-Hoc (IBSS), P2P Client, and **P2P Group Owner (P2P-GO)**.

  * **Bluetooth**: PAN Client (Tethering from phone) and PAN Host/NAP (Sharing internet to others).

* **IPv6 Native**: Automatic SLAAC, DHCPv6, and Prefix Delegation support for both clients and hotspots.

* **Virtualization & SDN**: Native support for **Bridges**, **VLANs**, **Bonds** (Active-Backup/LACP), **VRFs** (Virtual Routing Functions), **MacVLANs**, **IPVLANs**, and **WireGuard**.

* **Tethering & NAT**: One-command hotspot creation (WiFi AP or Bluetooth PAN) with automatic NAT/Masquerading via `iptables` or `nftables`.

* **Profiles**: Snapshot, export, and restore complete network states or interface-specific configurations.

## Architectural Analysis & Performance

RXNM allows for a "headless" network stack configuration, relying on the native capabilities of the Linux kernel and systemd rather than running a monolithic middleware daemon.

### Latency: Read vs. Write Paths

RXNM employs a split-path architecture to optimize for the specific constraints of embedded user interfaces.

* **Read Path (Status/Diagnostics): < 5ms**

  * Handled by `rxnm-agent` (C/Netlink).

  * Bypasses heavy shell forking and directly queries kernel Netlink and DBus interfaces.

* **Write Path (Configuration): \~50-100ms**

  * Handled by Bash logic + `systemd-networkd` reload.

  * Optimized for correctness and atomicity over raw speed.

### Resident Memory Footprint (The "Cost of Idle")

Comparison of the total network stack footprint on a typical embedded Linux system (glibc). RXNM utilizes the existing `systemd` ecosystem, adding **0MB** to the idle footprint.

| Component | RXNM Stack (L2+L3) | NetworkManager Stack | ConnMan Stack | 
 | ----- | ----- | ----- | ----- | 
| **L2 Wifi** | **iwd**: \~3.5 MB | **wpa_supplicant**: \~6-12 MB | **wpa_supplicant**: \~6-12 MB | 
| **L3 Network** | **systemd-networkd**: \~4.0 MB | **NetworkManager**: \~18-45 MB | **connman**: \~8-15 MB | 
| **DNS/LLMNR** | **systemd-resolved**: \~3.2 MB | *(Internal or dnsmasq)* | *(Internal)* | 
| **Management** | **RXNM**: **0 MB** (Ephemeral) | *(Included in NM)* | *(Included in connman)* | 
| **TOTAL** | **\~10.7 MB** | **\~24 MB - 57 MB** | **\~14 MB - 27 MB** | 

*Note: While `iwd` can handle internal DHCP, `systemd-networkd` is the chosen backend because it provides advanced profile switching, native hotplug event handling, standardized configuration formats, and seamless roaming integration effectively "for free" while maintaining a tiny footprint.*

### Storage Longevity: NAND/eMMC Wear Efficiency

On embedded devices using SD cards or internal eMMC/NAND flash, frequent disk writes and `fsync()` calls accelerate hardware wear and can cause UI stuttering due to I/O wait. RXNM is architected to treat the filesystem as an ephemeral target, using a **RAM-first configuration strategy**.

#### Comparative Disk Operations (Per Connection Event)

| Stack | Writes to Flash | Syncs/Fdatasync | Persistence Strategy | 
 | ----- | ----- | ----- | ----- | 
| **RXNM (Hybrid)** | **1 - 2** | **1** | **RAM-only by default; explicit Profile save.** | 
| **ConnMan** | \~5 | \~3 | Periodic updates to settings/state files. | 
| **NetworkManager** | \~6 - 12+ | \~4+ | Heavy persistence for leases, history, and state. | 

* **RXNM Atomic Fastpath**: When RXNM writes a configuration, it uses `rxnm-agent --atomic-write`, which performs a single buffered write to a temporary file followed by an atomic `rename()`. By targeting `/run/systemd/network` (tmpfs/RAM) for active configurations, RXNM generates **zero flash wear** during normal session operation. Permanent changes are only committed to flash when the user explicitly saves a profile.

### Wakeups & Battery Life

#### Comparative Wakeup Metrics (Idle/Connected)

| Stack / Component | Avg. Wakeups / Minute | Battery Impact | Technical Context | 
 | ----- | ----- | ----- | ----- | 
| **RXNM (Standard)** | **0** | **None** | **Standard operation generates zero wakeups; binary exits.** | 
| **RXNM (Passive Monitor)** | \~0.6 - 2.0 | Negligible | Wakes only on kernel events (Signal Change / Roam) | 
| **systemd-networkd** | \~0.1 | Near zero | Pure Netlink event subscriber; sleeps until kernel signal | 
| **NetworkManager** | \~60 - 150+ | Moderate/High | Polling-heavy D-Bus architecture & periodic scanning | 

## Cloud & Container Use Cases

RXNM's "Run & Done" philosophy makes it uniquely suited for high-density cloud environments and specialized container networking.

* **Zero-Overhead Scale**: In microservice architectures, the per-instance overhead of a persistent network daemon results in gigabytes of wasted RAM across a cluster. RXNM allows containers to have managed networking with **zero resident memory overhead**.

* **Immutable Infrastructure**: RXNM generates standard `.network` files, making its state 100% transparent and auditable. It is ideal for sidecar patterns providing health metrics via JSON without impacting primary application resources.

## Extremis & Tiny Environments

### Rescue Mode & Initramfs

RXNM includes a robust **Rescue Mode**. If system daemons are missing or fail to start, RXNM can fallback to standard kernel tools and BusyBox applets (`udhcpc`, `ip`) to establish an emergency uplink.

### Tiny Mode & spilinux

For ultra-minimal environments like **spilinux**, RXNM can operate in **Tiny Mode**. So long as the `rxnm-agent` C binary is present, RXNM can bypass systemd, D-Bus, and glibc dependencies entirely. The statically linked agent is typically **< 100KB**.

## Supported Modes & Esoterica

### Advanced Virtual Interfaces

* **VRF (Virtual Routing Forwarding)**: Create isolated routing tables for management isolation.

* **Bonding**: Supports `active-backup`, `balance-rr`, `802.3ad` (LACP).

* **Bridge**: Layer 2 bridging with STP and IGMP Snooping support.

* **MacVLAN / IPVLAN**: Specialized types for high-performance container networking.

## Installation

### Build & Install

```
# 1. Compile Agent (Optimized for size/static linking)
make tiny

# 2. Install to /usr/lib/rocknix-network-manager
sudo make install


```

## Usage Guide

### 1. System Status & Diagnostics (`rxnm system`)

```
# Human readable status table
rxnm system status

# JSON output for UI/Container monitoring
rxnm system status --format json

# Check for Captive Portal
rxnm system check portal


```

### 2. WiFi Operations (`rxnm wifi`)

```
# Scan for networks
rxnm wifi scan

# Connect to a network
rxnm wifi connect "MyWiFi" --password "s3cret"


```

## Configuration Paths

* **Network Configs**: `/storage/.config/network/`

* **WiFi Credentials**: `/var/lib/iwd/` (Secure 0600 permissions)

* **Profiles**: `/storage/.config/network/profiles/`

* **Runtime Locks**: `/run/rocknix/network.lock`

## License

GPL-2.0-or-later
Copyright (C) 2026-present Joel Wirāmu Pauling
