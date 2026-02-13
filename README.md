# RXNM (ROCKNIX Network Manager)

**RXNM** is a lightning-fast, modular CLI suite and API gateway for `systemd-networkd` and `iwd`. It is aggressively optimized for low-power ARM and RISC-V embedded devices (specifically RK3326, RK3566, RK3588, and SG2002 handhelds) while remaining 100% compatible with general Linux environments.

By eliminating monolithic middleware daemons, RXNM achieves a **0MB idle memory footprint** and sub-5ms read latencies, making it the ultimate networking stack for emulation handhelds, immutable OS designs, and containerized cloud environments.

**Latest Version:** `1.0.0-rc2`  
**API Specification:** `v1.0`

## ⚡ Architecture & Performance

RXNM uses a **Hybrid C/Shell Architecture** to overcome the performance bottlenecks of embedded shell scripts while retaining the flexibility of Bash for high-level logic.

1. **The Native C Agent (`rxnm-agent`)**: A statically-linked (via `musl-gcc`), zero-dependency C binary that directly queries kernel Netlink (RTM/Genl). It handles all fast-path read operations, atomic writes, and hardware polling.
2. **The Logic Dispatcher (`rxnm`)**: A lazy-loaded Bash frontend that handles complex state machine validation, JSON schema enforcement, and declarative configuration routing.
3. **REST-Lite Integration**: Natively "JSON-Aware" logic that accepts full configuration payloads via `stdin` and outputs versioned, schema-compliant JSON.
4. **Bash-Only Fallback**: In environments where the C binary is missing, RXNM automatically falls back to native shell logic (using `/proc`, `/sys`, and `/dev/tcp`), ensuring 100% service availability at the cost of higher latency.
5. **Opt-in Monitoring**: Background services (like the Roaming Monitor) are **disabled by default**. RXNM only consumes system resources when actively invoked, maintaining its "0MB Idle" contract unless these features are explicitly enabled by the user.

### Pre-Flight Schema Validation
Unlike traditional managers that might partially apply a broken configuration, RXNM performs **Atomic Intent Validation**. Before any file is written to the filesystem or any Netlink command is dispatched, the logic builder constructs a "Descriptor" of the requested state. This descriptor is validated against `api-schema.json` using `jaq` or `jq`. If the request violates the schema (e.g., an invalid VLAN ID, a malformed IP, or a missing required parameter), RXNM aborts with a structured error, keeping the system state pristine.

### Latency Benchmarks (Read vs. Write Paths)

*Measured on Rockchip RK3326 (1.5GHz Quad-Core Cortex-A35).*

| Operation | RXNM (Hybrid) | RXNM (Bash Fallback) | NetworkManager | ConnMan | IWD (Standalone) | Technical Context | 
 | ----- | ----- | ----- | ----- | ----- | ----- | ----- | 
| **Status Read (JSON)** | **< 5ms** | **\~25ms** | \~45-80ms | \~30-60ms | \~15-30ms | Agent polls Netlink; Fallback forks `grep/awk`. | 
| **Internet Probe (TCP)** | **\~20ms** | **\~45ms** | \~100ms+ | \~100ms+ | N/A | Agent uses raw sockets; Fallback uses `/dev/tcp`. | 
| **Config Write** | **\~80ms** | **\~90ms** | \~150-300ms | \~100-200ms | \~50-100ms | Both use atomic `rename()` for integrity. | 
| **Roaming Trigger** | **< 15ms** | **\~65ms** | \~200ms+ | \~200ms+ | Internal | Hybrid is event-driven; Fallback is poll-driven. | 

### Resident Memory Footprint (The "Cost of Idle")

RXNM relies entirely on native kernel capabilities. It does not run an active management daemon in the background.

| Component | RXNM (Hybrid) | RXNM (Bash Fallback) | NetworkManager | ConnMan | IWD (Standalone) | 
 | ----- | ----- | ----- | ----- | ----- | ----- | 
| **L2 Wifi** | **iwd**: \~3.5 MB | **iwd**: \~3.5 MB | **wpa_supplicant**: \~6-12 MB | **wpa_supplicant**: \~6-12 MB | **iwd**: \~3.5 MB | 
| **L3 Network** | **systemd-networkd**: \~4.0 MB | **systemd-networkd**: \~4.0 MB | **NetworkManager**: \~18-45 MB | **connman**: \~8-15 MB | *(Internal DHCP)* | 
| **DNS/LLMNR** | **systemd-resolved**: \~3.2 MB | **systemd-resolved**: \~3.2 MB | *(Internal or dnsmasq)* | *(Internal)* | **resolved**: \~3.2 MB | 
| **Management** | **RXNM**: **0 MB** | **RXNM**: **0 MB** | *(Included in NM)* | *(Included in connman)* | **0 MB** | 
| **TOTAL (Default)** | **\~10.7 MB** | **\~10.7 MB** | **\~24 MB - 57 MB** | **\~14 MB - 27 MB** | **\~6.7 MB**\* | 
| **TOTAL (w/ Monitor)** | **\~13.5 MB** | **\~13.5 MB** | N/A | N/A | N/A | 

*\*Note: Enabling optional background monitoring adds \~2.8MB resident overhead.*

### Storage Longevity (Flash Wear)

RXNM uses a **RAM-First Configuration Strategy**, writing active configurations to `/run/systemd/network` (tmpfs) to avoid disk I/O wait and hardware wear.

| Stack | Writes to Flash | Syncs/Fdatasync | Persistence Strategy | 
 | ----- | ----- | ----- | ----- | 
| **RXNM (Hybrid)** | **1** | **1** | **RAM-only by default**; 1 write only if saving Profile. | 
| **RXNM (Bash Fallback)** | **1** | **1** | **RAM-only by default**. | 
| **IWD (Standalone)** | \~2 | \~1 | Writes credentials and lease files to `/var/lib/iwd`. | 
| **ConnMan** | \~5 | \~3 | Periodic updates to settings/state files. | 
| **NetworkManager** | \~6 - 12+ | \~4+ | Heavy persistence for leases and history. | 

### Wakeups & Battery Life

| Stack | Avg. Wakeups / Min | Battery Impact | Technical Context | 
 | ----- | ----- | ----- | ----- | 
| **RXNM (Hybrid)** | **0** | **None** | **Process exits.** Zero background management overhead. | 
| **RXNM (Bash Fallback)** | **0** | **None** | **Process exits.** | 
| **RXNM (with Monitor)** | **\~1 - 3** | **Negligible** | **Opt-in** service for BSSID steering/RSSI tracking. | 
| **systemd-networkd** | \~0.1 | Near zero | Pure Netlink event subscriber; sleeps until signal. | 
| **IWD (Standalone)** | \~0.3 | Negligible | Efficient event loop; minimal polling. | 
| **ConnMan** | \~10 - 30 | Low/Mod | Periodic housekeeping and state checks. | 
| **NetworkManager** | \~60 - 150+ | Moderate | Polling-heavy D-Bus architecture & scanning. | 

---

## 📋 Environment Requirements

RXNM is designed to be highly resilient, scaling its functionality based on available system components.

### 1. Hard Dependencies (Core Logic)
* **Bash 4.4+**: Required for the Logic Dispatcher (uses associative arrays and local scopes).
* **systemd-networkd**: The primary L3 configuration engine.
* **JSON Processor**: One of `jaq` (preferred), `gojq`, or `jq` must be in `$PATH`.

### 2. Functional Reductions (Feature Availability)

| Mode | Dependencies | Capability Reduction | 
 | ----- | ----- | ----- | 
| **Standard Hybrid** | \+ `rxnm-agent` | **None**. Full performance, low-latency Netlink polling, atomic writes. | 
| **Bash Fallback** | \- `rxnm-agent` | **Status Performance**. Uses `grep/awk` on `/proc` and `/sys`. diagnostics use `/dev/tcp` shell pipes. | 
| **Wireless Mode** | \+ `iwd` | **None**. Enables WiFi Station, AP, P2P, and DPP modes. | 
| **Hotspot Sharing** | \+ `iptables` or `nft` | **None**. RXNM auto-detects and uses the available firewall backend for NAT. | 

---

## 🎹 Pseudo-Interactive "Tab-Driven" UX

RXNM transforms the standard CLI into a fluid, pseudo-interactive environment via its advanced **Bash Completion Engine**. Instead of memorizing SSIDs or interface names, you can "mash Tab" your way through complex commands.

### Intelligent Contextual Polling
The completion engine performs **live hardware and environment polling**:
* **WiFi Stations**: Typing `rxnm wifi connect [TAB]` triggers a high-speed scan (accelerated by the C-Agent) to suggest live SSIDs currently in range.
* **Interfaces**: Typing `rxnm interface [TAB]` polls the kernel for active and physical network devices.
* **Profiles**: Typing `rxnm profile load [TAB]` lists available persistent profiles found on disk.
* **VPNs**: Typing `rxnm vpn disconnect [TAB]` suggests currently active WireGuard tunnels.

---

## 📦 'Tiny' Mode & Minimalist Environments

For extremely constrained environments such as **initramfs**, **recovery images**, or **BusyBox-only distributions**, RXNM provides a specialized build target: `make tiny`.

### 1. The Statically Linked Agent
Running `make tiny` utilizes `musl-gcc` to produce a single, self-contained binary (\~50KB). 
* **Zero Dependencies**: Does not require `glibc`, `libdbus`, or even a working shell.
* **Initramfs Portability**: Ideally suited for bringing up a network link to mount a remote NFS/iSCSI root before the main OS starts.

### 2. Capability in BusyBox/Non-Bash Shells
The `rxnm-agent` can be used standalone in **BusyBox `ash`** or **Dash** scripts as a high-performance network metadata provider.
* **Fast Status**: `rxnm-agent --is-connected` returns an instant exit code.
* **Atomic Filesystem Bridge**: Use `rxnm-agent --atomic-write [file]` to ensure configuration integrity in environments where `mktemp` might not be available.

---

## 🛠️ System Builder Integration (Declarative Defaults)

RXNM is designed for OS maintainers who want to provide a "it just works" networking experience. This is achieved through a combination of lexical priority and **Netdev/Network Masking**.

### Handling Conflicting Matches
`systemd-networkd` processes configuration files in lexical order and stops at the first file that matches an interface. RXNM leverages this by using a split-priority directory structure:

1. **Policy Overrides (`10-*.network`)**: High-priority user or builder overrides.
2. **Standard Configs (`60-*.network`)**: Standard RXNM-managed configurations.
3. **Vendor Defaults (`80-*.network`)**: Generic system fallbacks.

If a system builder defines a generic match for `usb*` in `80-tether.network`, but RXNM needs to apply a specific static IP to `usb0`, RXNM generates a `10-usb0.network` file. Systemd will match the `10-` file first, effectively resolving the conflict without needing to modify the builder's original file.

### Default Behavior Masking
In scenarios where a builder's default behavior is undesirable but the file cannot be easily moved (e.g., provided by a read-only squashfs package), RXNM supports **Masking**. By creating a symbolic link in `/run/systemd/network/` with the same name as a file in `/usr/lib/systemd/network/` pointing to `/dev/null`, the builder's default is completely neutralized for that session, allowing the user's logic to take full control.

**Example: Zero-Touch USB Tethering**
OS maintainers can drop this into `/usr/lib/systemd/network/80-tether.network`:
```ini
[Match]
Name=usb* rndis* eth*

[Network]
DHCP=yes
IPv6PrivacyExtensions=yes

[DHCP]
RouteMetric=10
```
This ensures that any phone plugged in is automatically configured, while RXNM remains ready to mask or override this behavior if the user initiates a manual `rxnm interface usb0 set static` command.

---

## 📖 User Stories & Common Tasks

### 🏠 Scenario: The Home Lab Setup
*Goal: Configure a static IP on Ethernet, set custom DNS, and create a network bridge for virtual machines.*

1. **Set Static IP and Priority DNS**:
   ```bash
   rxnm interface eth0 set static 192.168.1.10/24 --gateway 192.168.1.1 --dns 1.1.1.1,8.8.8.8
   ```
2. **Create a Bridge for Containers/VMs**:
   ```bash
   rxnm bridge create br0
   rxnm bridge add-member eth0 --bridge br0
   ```
3. **Save as Persistent Profile**:
   ```bash
   rxnm profile save "HomeLab"
   ```

### 🎮 Scenario: The Retro Handheld Gamer
*Goal: Connect to Home WiFi, tether to a phone over Bluetooth/USB, and coordinate local multiplayer.*

1. **Connect to Home WiFi**:
   ```bash
   rxnm wifi connect "Home_SSID" --password "mypassword"
   ```
2. **Tether to Phone (Bluetooth or USB)**:
   ```bash
   # Option A: Bluetooth Tethering (PAN)
   rxnm bluetooth pan enable --mode client
   
   # Option B: USB Tethering (Plug phone in - works automatically if pre-configured by OS)
   rxnm interface usb0 set dhcp
   ```
3. **Local P2P Multiplayer (WiFi Direct)**:
   ```bash
   # On Unit 1 (Group Owner)
   rxnm wifi p2p status
   
   # On Unit 2 (Client)
   rxnm wifi p2p scan
   rxnm wifi p2p connect "Handheld_A"
   ```

### 🛰️ Scenario: The Remote Pro
*Goal: Connect to a corporate WireGuard VPN and set a global proxy for secure browsing.*

1. **Connect to WireGuard**:
   ```bash
   rxnm vpn wireguard connect wg0 \
     --private-key "Base64Key..." \
     --peer-key "PeerKey..." \
     --endpoint "vpn.work.com:51820" \
     --address "10.0.0.5/24" \
     --allowed-ips "0.0.0.0/0"
   ```
2. **Configure Proxy**:
   ```bash
   rxnm system proxy set --http "http://proxy.work.com:8080" --noproxy "localhost,127.0.0.1,10.0.0.0/8"
   ```

---

## 🚀 Feature Set

* **Target-First RouterOS Syntax**: Intuitive command structure (e.g., `rxnm interface wlan0 show`).
* **Unified API (1.0)**: Strict JSON contract (`api-schema.json`) for frontend integration.
* **IPv6 Native**: Automatic SLAAC, DHCPv6, Privacy Extensions, and Prefix Delegation.
* **Automated NAT/Tethering**: One-command hotspot creation with `iptables` or `nftables` Masquerading.

### Nullify Mode (Zero-Stack Lockdown)
Executing `rxnm system nullify enable` performs a complete teardown of the Linux networking subsystem for offline gaming or extreme battery conservation. Requires confirmation via `--yes`.

* **Driver Unbinding**: Aggressively unbinds drivers from PCI/SDIO buses.
* **Stack Disable**: Sets kernel sysctls to completely disable IP stack handling.
* **Daemon Masking**: Prevents daemons from attempting to re-initialize hardware.

---

## 🔌 Zero-Overhead API Gateway (Example Only)

RXNM includes example **Socket Activated** unit files in the `systemd/` directory. This allows remote applications to control networking without an HTTP server consuming resident RAM.

* **Service**: `rxnm-api.socket`
* **Default Port**: `29304` (Hex: `0x7278` — ASCII for "**rx**")
* **Idle Overhead**: 0MB RAM (Systemd manages the socket; RXNM only spawns on connection).

---

## 📖 Comprehensive Usage Guide

### 1. System Status & API
```bash
# Formatted table
rxnm system status --format table

# Pure JSON (API v1.0)
rxnm system status --json

# Check connectivity via fast TCP probes
rxnm system check internet
```

### 2. JSON API (REST-Lite)
```bash
echo '{
  "category": "wifi",
  "action": "connect",
  "ssid": "MyNet",
  "password": "pass",
  "api_version": "1.0"
}' | rxnm --stdin
```

**Normalization:** RXNM maps `snake_case` keys (JSON) to `kebab-case` flags (CLI) automatically.

---

## 🛠️ Installation & Building

### Compilation
```bash
# Standard Build
make

# 'Tiny' Mode (Statically linked for initramfs/BusyBox recovery)
make tiny

# Install to system paths
sudo make install

# (Optional) Enable the example API Socket Gateway (Port 29304)
# sudo systemctl enable --now rxnm-api.socket
```

## License

**GPL-2.0-or-later** Copyright (C) 2026-present Joel Wirāmu Pauling

Part of the **ROCKNIX** Ecosystem.
