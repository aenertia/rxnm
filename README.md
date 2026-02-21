# RXNM (ROCKNIX Network Manager)

[![Version](https://img.shields.io/badge/version-1.1.0--rc3-blue.svg?style=flat-square)](https://codeberg.org/aenertia/rxnm)
[![API](https://img.shields.io/badge/API-v1.1-brightgreen.svg?style=flat-square)](https://codeberg.org/aenertia/rxnm/src/branch/main/api-schema.json)
[![Arch](https://img.shields.io/badge/arch-Hybrid%20(Bash%20%7C%20POSIX%20%7C%20C)-orange.svg?style=flat-square)](https://codeberg.org/aenertia/rxnm/src/branch/main/BUILD.md)
[![Footprint](https://img.shields.io/badge/footprint-%7E300KB-blueviolet.svg?style=flat-square)](https://codeberg.org/aenertia/rxnm/src/branch/main/BENCHMARKS.md)
[![License](https://img.shields.io/badge/license-GPL--2.0--or--later-green.svg?style=flat-square)](https://codeberg.org/aenertia/rxnm/src/branch/main/LICENSE)

**RXNM** is a lightning-fast, modular CLI suite and API gateway for `systemd-networkd` and `iwd`. It is aggressively optimized for battery-powered ARM handhelds, high-performance mobile SoCs, and RISC-V development platforms—specifically the **Rockchip RK3326/RK3566**, **Allwinner H700**, **Qualcomm Snapdragon SM8250/SM8550**, **Canaan K230**, **Terasic SoC boards**, and the **Milk-V** ecosystem—while remaining 100% compatible with general Linux environments.

By eliminating monolithic middleware daemons, RXNM achieves a **0MB idle memory footprint** and sub-5ms read latencies, making it the ultimate networking stack for emulation handhelds, mobile Linux devices, RISC-V hardware development, and immutable OS designs.

---

## 📚 Primary Documentation

RXNM's architecture is documented across several targeted specifications. Please refer to the following guides for deep dives into specific subsystems:

* 🚀 [**Performance & Memory Benchmarks**](https://codeberg.org/aenertia/rxnm/src/branch/main/BENCHMARKS.md) - How RXNM achieves a Zero-Resident RAM profile and beats Android/NetworkManager performance.
* 🛡️ [**Project Silence (Nullify Architecture)**](https://codeberg.org/aenertia/rxnm/src/branch/main/NULLIFY.md) - A deep dive into XDP/eBPF hardware sleep mechanisms, Software-WoL, and standby battery optimization.
* 🛠️ [**Build & Integration Guide**](https://codeberg.org/aenertia/rxnm/src/branch/main/BUILD.md) - Compiling the native C agent, testing, cross-compilation, and generating flat-file deployment bundles.
* 🔮 [**RXNM 2.0 Roadmap**](https://codeberg.org/aenertia/rxnm/src/branch/main/PLAN.md) - Our path toward a monolithic, Zero-IPC networking runtime.

---

## 👨‍💻 Origins & Motivation

RXNM is developed independently, targeting the **ROCKNIX** ecosystem and high-performance mobile/embedded Linux distributions as primary consumers.

This project was born out of a specific void in the Linux ecosystem: while `systemd-networkd` offers a gold standard for performance and stability in the kernel, it has historically lacked a comprehensive, user-facing CLI wrapper equivalent to `NetworkManager`'s `nmcli`.

Until now, managing `networkd` meant manually authoring INI files or relying on rigid orchestration tools. RXNM is that missing link—a frontend that provides the interactive convenience of a modern network manager without sacrificing the raw efficiency of the systemd stack.

When you have devices that need to connect to WiFi in under a second to sync save states or download boxart, every millisecond of latency and megabyte of RAM counts. RXNM exists to ensure the network is a transparent utility, not a boot-time bottleneck. Ultimately, RXNM exists to support a crippling addiction... err, passionate and perfectly healthy hobby... for collecting mainline compatible retro gaming handhelds.

## ⚡ Architecture: The Middleware for Scripters

The primary goal of RXNM is to provide a **reliable, ultra-lightweight abstraction layer**. It allows users and developers to perform complex network operations without needing to understand—or implement—concurrency, state machines, or hardware synchronization.

### "Super Tiny" by Design
Unlike traditional managers that link against massive libraries (`GLib`, `libdbus`, `GObject`), RXNM is built to be "super tiny":

* **DBus-Lite:** The C-agent implements the DBus wire protocol manually to trigger `networkd` reloads. This eliminates a ~2MB dependency chain, resulting in a binary that is **~50KB** when statically linked with `musl`.
* **Zero-Dependency Core:** The native agent requires only a standard C library, making it trivial to drop into an Initramfs or a minimalist recovery environment.
* **Low-Power Optimization:** The logic is 100% event-driven. It consumes **zero CPU cycles** and **zero resident RAM** when not in use.

### "State-for-Free": Eliminating Scripting Boilerplate
In traditional embedded development, scripters often ignore state management and locking because it is difficult to implement correctly in shell. RXNM provides these features natively:

* **Internal Concurrency Guarding:** Multiple `rxnm` commands from different background scripts are handled via internal queuing and per-interface dynamically allocated FD locking.
* **Hardware-Aware Wait Cycles:** Commands manage the state transition from IWD to Networkd, waiting for valid carrier and L3 routability before returning.
* **Zero-Parsing Data Fetching:** RXNM's `--get` flag and JSON API provide deterministic data that won't break if a system tool changes its output format.

> 🔗 *Read more about the Hybrid Bash/POSIX execution environments in the [Build & Integration Guide](https://codeberg.org/aenertia/rxnm/src/branch/main/BUILD.md).*

## 🔋 Power Residency: The "Project Silence" Focus

On modern Linux kernels, the primary cause of battery drain during sleep is "Network Noise." Devices standardized around `s2idle` (Suspend-to-Idle), particularly high-end **Snapdragon**, **Rockchip**, and prototype **RISC-V** SoCs, are extremely sensitive to hardware interrupts.

### XDP Nullify Solution
RXNM implements a multi-layered hardware silencing strategy to extend standby battery life by **5-12%**:

1. **WoWLAN (Firmware Layer):** Instructs the WiFi module to drop background chatter (mDNS/ARP) and only wake the host for authorized magic packets.
2. **XDP Nullify (Driver Layer):** Attaches an eBPF program to the driver. Incoming packets are discarded instantly at the driver ring-buffer, preventing the CPU from ever leaving its deepest C-state (C6-C10).
3. **HCI Air-Gap:** Logically closes the Bluetooth HCI interface during sleep, preventing BLE advertisements (from trackers/watches) from triggering unwanted SoC wakeups.

### Software-Defined Wake-on-LAN (SWOL)
Budget handhelds, development boards, and mobile adapters often ship with SDIO WiFi or USB Ethernet dongles lacking hardware WoL. RXNM's `--soft-wol yes` flag injects a specialized eBPF filter that provides **high-end Wake-on-LAN functionality to $10 hardware** with zero resident memory cost. 

By evaluating Magic Packets directly at the driver boundary in software, RXNM enables **universal Wake-on-LAN support irrespective of lower-level hardware or firmware capabilities.** Even if the vendor explicitly omitted WoL support from the silicon or shipped broken drivers, this software-defined approach guarantees remote wake reliability.

> 🔗 *Dive deep into the eBPF bytecode and hardware states in [Project Silence (NULLIFY.md)](https://codeberg.org/aenertia/rxnm/src/branch/main/NULLIFY.md).*

## 🛠️ Configuration Philosophy: The Unified Orchestrator

RXNM replaces fragmented, bespoke scripting with a unified, state-aware management layer designed for deterministic reliability.

### Solving the "Split-Brain" Interaction
In traditional embedded environments, the network stack often suffers from a "Split-Brain" condition where multiple tools (`iwd`, `connman`, custom scripts) operate simultaneously but remain entirely unaware of each other's interactions.

* **The Conflict:** `iwd` might attempt to manage L3 IP addressing on a WiFi link while a bespoke script triggers a conflicting `udhcpc` instance.
* **The RXNM Solution:** RXNM enforces a strict separation of concerns. It forces `iwd` to act purely as an L2 (Authentication) worker, delegating all L3 (IP/DHCP/Routing) logic to `systemd-networkd`. This ensures that plugging in a USB dock or switching from WiFi to Bluetooth tethering is a deterministic, conflict-free transition.

### Deterministic Component Ordering
RXNM recognizes that the Linux network stack is sensitive to the order of operations:
1. **Pre-flight Safety:** Scans for existing hardware blocks (`rfkill`) before initiating L2.
2. **L2 Authorization:** Triggers WiFi authentication (IWD) as an isolated worker.
3. **L3 Lifecycle:** Confirms L2 carrier before triggering `systemd-networkd` for IP addressing.
4. **Tuning:** Final kernel protocol tuning is applied only after the link reaches a "routable" state.

## 📂 Profile Management & Persistence

Configurations are written to the ephemeral `/run` directory to avoid flash wear on SD cards or internal UFS/eMMC storage.

1. **The Default Profile:** At boot, the `rxnm.service` wipes ephemeral state and loads the `default` profile from `/storage/.config/network/profiles/global/default/`, syncing persistent overrides into RAM.
2. **Named Profiles:** Users can capture state into profiles (e.g., "Lab", "Work", "Home", "Multiplayer_VLAN"):
   * **Save:** `rxnm profile save lab_work`
   * **Load:** `rxnm profile load lab_work` (Swaps active config in RAM and reloads `networkd` instantly).
   * **Reset:** `rxnm profile load default` (If no 'default' exists, resets to system factory state).

## ⌨️ Interactive Discovery & "Tab-Mashing"

RXNM features a deep, context-aware **Bash Completion** system.

* **Contextual Suggestions:** `rxnm interface [TAB]` shows only active devices; `rxnm wifi connect [TAB]` triggers a lookup of available scan results.
* **Zero-Latency:** Completions read the high-speed `/run/rocknix/status.json` cache generated by the C-agent, ensuring instant feedback even on low-power hardware.

## 📊 Comparative Command Reference

How `rxnm` translates from traditional Linux networking tools.

| Operation | **RXNM** | **NM (nmcli)** | **ConnMan (connmanctl)** | **iproute2 (ip)** | 
| ----- | ----- | ----- | ----- | ----- | 
| **Status (Global)** | `rxnm system status` | `nmcli general status` | `connmanctl state` | `ip addr` / `ip route` | 
| **Status (Device)** | `rxnm interface eth0 show` | `nmcli device show eth0` | `connmanctl services` | `ip addr show eth0` | 
| **WiFi Scan** | `rxnm wifi scan` | `nmcli dev wifi list` | `connmanctl scan wifi` | `iw dev wlan0 scan` | 
| **WiFi Connect** | `rxnm wifi connect SSID` | `nmcli dev wifi connect SSID` | `connmanctl connect wifi_...` | `iwctl station connect SSID` | 
| **Set DHCP** | `rxnm interface eth0 set dhcp` | `nmcli con mod eth0 ipv4.method auto` | *(Automatic)* | `udhcpc -i eth0` | 
| **Set Static IP** | `rxnm interface eth0 set static IP/24` | `nmcli con mod eth0 ipv4.addresses IP/24` | `connmanctl config ... ipv4 manual ...` | `ip addr add IP/24 dev eth0` | 
| **Set Gateway** | `... set static ... --gateway GW` | `nmcli con mod eth0 ipv4.gateway GW` | *(As above)* | `ip route add default via GW` | 
| **Link Up/Down** | `rxnm interface eth0 enable/disable` | `nmcli device connect/disconnect eth0` | `connmanctl enable/disable ethernet` | `ip link set eth0 up/down` | 
| **Internet Check** | `rxnm system check internet` | `nmcli networking connectivity` | *(None)* | `ping -c 1 8.8.8.8` | 
| **Power Silence** | `rxnm system nullify enable` | *(None)* | *(None)* | *(Requires custom XDP/eBPF code)* | 

## 📖 Documentation & Usage Examples

This section provides a definitive reference for all RXNM capabilities.

### 1. Wireless Operations (`rxnm wifi`)

| Action | Description | 
| ----- | ----- | 
| `scan` | Scan for visible Access Points | 
| `connect` | Associate with an SSID | 
| `disconnect` | Terminate current association | 
| `ap` | Manage Host/Hotspot mode | 
| `networks` | List known (saved) profiles | 
| `p2p` | Wi-Fi Direct / Peer-to-Peer management | 
| `dpp` | QR-based Device Provisioning | 
| `roaming` | Configure opportunistic steering | 

**Examples:**
```bash
# Basic connection (interactive prompt for password)
rxnm wifi connect "HomeWiFi"

# Connect with inline password and hidden SSID
rxnm wifi connect "HiddenLab" --password "s3cr3t" --hidden

# Setup a Hotspot (NAT + DHCP auto-configured)
rxnm wifi ap start "RocknixAP" --password "12345678" --share

# Join a WiFi Direct multiplayer session
rxnm wifi p2p scan
rxnm wifi p2p connect "Opponent_Device"

# Enroll via DPP (QR Code URI)
rxnm wifi dpp enroll "DPP:C:81/1;M:001122334455;K:..."
```

### 2. Interface Management (`rxnm interface`)

| Action | Description | 
| ----- | ----- | 
| `show` | Detailed JSON/Human status for an interface | 
| `set dhcp` | Enable dynamic addressing | 
| `set static` | Configure fixed IP/Gateway/DNS | 
| `set hardware` | Adjust MAC, Speed, Duplex, or MTU | 
| `enable/disable` | Administrative UP/DOWN toggle | 

**Examples:**
```bash
# Set Static IP with specific DNS and Route Metric
rxnm interface eth0 set static 192.168.1.50/24 --gateway 192.168.1.1 --dns 8.8.8.8 --metric 10

# Extract specific data for a script (Single Pane of Glass)
rxnm interface wlan0 show --get wifi.rssi

# Force 100Mbps Full Duplex on a fixed link
rxnm interface eth0 set hardware --speed 100 --duplex full --autoneg no
```

### 3. Power Management & System (`rxnm system`)

| Action | Description | 
| ----- | ----- | 
| `nullify` | Engage eBPF hardware silence | 
| `ipv4/ipv6` | Protocol stack toggles | 
| `check internet` | High-speed TCP reachability probe | 
| `proxy set` | Global/Interface HTTP proxy config | 

**Examples:**
```bash
# Global "Project Silence" (XDP + WoWLAN + BT Air-gap)
rxnm system nullify enable

# Enable silence on a specific interface only
rxnm system nullify enable --interface wlan0

# Advanced Nullify: silence everything EXCEPT Magic Packets (Soft-WoL)
rxnm system nullify enable --soft-wol yes

# Power saving: disable IPv6 stack completely
rxnm system ipv6 disable
```

### 4. Virtual Networking & VPN (`rxnm bridge|bond|vlan|vrf|vpn`)

**Examples:**
```bash
# Create a bridge and add eth0 as a member
rxnm bridge create br0
rxnm bridge add-member eth0 --bridge br0

# Create a WireGuard link
rxnm vpn wireguard connect wg0 \
  --private-key "..." --peer-key "..." \
  --endpoint "vpn.host.com:51820" --address "10.0.0.2/24"
```

## 🥗 User Stories & Cookbooks

### Scenario: The Retro Handheld Gamer
*Goal: Connect to Home WiFi, tether to a phone via Bluetooth, and set up a local multiplayer lobby.*

1. **WiFi:** `rxnm wifi connect "Home_SSID" --password "mypassword"`
2. **BT Tether:** `rxnm bluetooth pan enable --mode client`
3. **Multiplayer:** `rxnm wifi p2p status` on Host; `rxnm wifi p2p connect "Host"` on Client.

### Scenario: The "Zero Loss" Suspend
*Goal: Maximize battery during s2idle while preserving protocol state.*

1. **Engage:** `rxnm system nullify enable --soft-wol yes`
2. **Result:** XDP drops background mDNS/ARP storms. The CPU hits C10 sleep. The radio stays powered in a low-power state. On resume, SSH sessions are still alive because the TCP stack never saw a link-down event.

### Scenario: The RISC-V Prototype Lab
*Goal: Rapidly swap between "Development" (Static IP/Proxy) and "Field" (DHCP/No Proxy) modes.*

1. **Save Dev:** `rxnm profile save lab_work`
2. **Switch:** `rxnm profile load default` (Reset to baseline)
3. **Switch Back:** `rxnm profile load lab_work`

## 🔌 API & Integration

### REST-Lite Input (JSON over Stdin)
RXNM acts as a REST-lite backend for graphical frontends and daemons. You can pass complex JSON objects via standard input to cleanly bypass fragile CLI argument parsing:

```bash
echo '{"category":"wifi", "action":"connect", "ssid":"HomeNet", "password":"test", "format":"json"}' | rxnm --stdin
```

### Integration Contract
The [api-schema.json](https://codeberg.org/aenertia/rxnm/src/branch/main/api-schema.json) serves as the strict stability contract. It guarantees that frontend UI/C++ code won't break even if the underlying Linux kernel tools (like `iproute2` or `networkctl`) change their CLI output formatting. All structured output is strictly validated against this JSON schema.

## 📦 Deployment & Build Profiles

RXNM uses standard `make` targets to adapt to various target environments:

* **Standard Build (`make install`):** Dynamically linked C-Agent and modular bash libraries in `/usr/lib/rocknix-network-manager`.
* **Static Build (`make tiny`):** Statically-linked C-accelerator binary (~50KB) built with `musl-gcc` for maximal portability.
* **Minimal Bundle (`make rocknix-release`):** Amalgamates "Retro Core" logic into a single flat script. **Recommended for handhelds, Milk-V, and K230 distributions.**
* **Full Bundle (`make combined-full`):** One monolithic script containing all features including Enterprise modules (MPLS, Namespaces, VRF).

> 🔗 *Detailed instructions are available in the [Build & Integration Guide](https://codeberg.org/aenertia/rxnm/src/branch/main/BUILD.md).*

## 📖 Rescue Mode & Initramfs

RXNM automatically detects missing daemons in environments like Initramfs or catastrophic service failures. If `systemd-networkd` is not present, `rxnm hotplug` gracefully degrades into rescue mode and triggers `configure_standalone_gadget` to provide emergency SSH/RNDIS networking, ensuring you are never permanently locked out of a headless system.

## 📄 License

**GPL-2.0-or-later** Copyright (C) 2026-present Joel Wirāmu Pauling
