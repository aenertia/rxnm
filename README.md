# RXNM (ROCKNIX Network Manager)

**RXNM** is a lightning-fast, modular CLI suite and API gateway for `systemd-networkd` and `iwd`. It is aggressively optimized for low-power ARM and RISC-V embedded devices (specifically RK3326, RK3566, RK3588, and SG2002 handhelds) while remaining 100% compatible with general Linux environments.

By eliminating monolithic middleware daemons, RXNM achieves a **0MB idle memory footprint** and sub-5ms read latencies, making it the ultimate networking stack for emulation handhelds, immutable OS designs, and containerized cloud environments.

| **Version** | **API Specification** | **Architecture** | **License** | 
 | ----- | ----- | ----- | ----- | 
| `1.1.0` | `v1.1` (Current) | Hybrid (Dual-Path Bash/POSIX) | GPL-2.0-or-later | 

## 👨‍💻 Origins & Motivation

RXNM is developed independently, targeting the **ROCKNIX** ecosystem as a primary consumer.

The author is a veteran engineer with **25+ years of experience** working with Linux systems and major Network Equipment Vendors. This project was born out of a specific void in the Linux ecosystem: while `systemd-networkd` offers a gold standard for performance and stability, it has historically lacked a comprehensive, user-facing CLI wrapper equivalent to `NetworkManager`'s `nmcli`.

Until now, managing `networkd` meant manually authoring INI files or relying on rigid orchestration tools. RXNM is that missing link—a frontend that provides the interactive convenience of a modern network manager without sacrificing the raw efficiency of the systemd stack.

When you have 40+ devices that need to connect to WiFi in under a second to sync save states or download boxart, every millisecond of latency and megabyte of RAM counts. RXNM exists to ensure the network is a transparent utility, not a boot-time bottleneck.

## 🛠️ Configuration Philosophy: Standards-First

RXNM is built on the principle of transparency. Unlike other managers that hide state in proprietary databases or binary blobs, RXNM is a pure orchestrator of standard Linux interfaces.

* **Standard Files:** Every action performed by RXNM results in the generation of standard `systemd-networkd` `.network` or `.netdev` files (and `udev` `.link` files for hardware properties).

* **Drop-in Compatibility:** RXNM operates within the standard systemd filesystem hierarchy. It is designed to be a "good citizen" and will honor any user-supplied overrides or custom 'dropped-in' configurations.

* **No Hidden State:** What you see in `/run/systemd/network` is exactly what RXNM is managing. This makes the system trivial to debug and 100% compatible with existing systemd-based automation.

## 🔌 Application-Centric API: The REST-Lite Gateway

RXNM is designed to be the "Networking Engine" for modern applications. It provides an application-centric API that decouples the UI from the underlying shell complexity.

### The Application Gateway (Socket & STDIN)

Applications (such as EmulationStation, React-based web dashboards, or Qt apps) can communicate with RXNM either **directly through STDIN** or via the `rxnm-api.socket` gateway (Unix domain socket or TCP port 29304). This gateway uses systemd socket activation to ensure it consumes **zero memory** when not actively processing a request, while direct STDIN support provides an easy path for simple integration from parent processes and scripts.

### Deterministic JSON Contract

RXNM enforces a strict JSON schema (`api-schema.json`) for all input and output. This eliminates the need for applications to parse fragile command-line output using `grep` or `awk`.

* **Input:** Send a JSON object to `stdin` or the socket.

* **Output:** Receive a structured JSON response containing success status, error hints, and data.

### Unified SDK (`rxnm-api.sh`)

For third-party shell scripts or internal plugins, RXNM provides a standard API library. By sourcing `rxnm-api.sh`, any script gains the ability to query the network state or apply configurations using the same optimized paths as the main binary.

## ⚡ Architecture: The Dual-Path Execution Model

RXNM v1.1 introduces an adaptive execution strategy that ensures carrier-grade performance on high-end systems and unbreakable portability on restricted recovery environments.

### 1. The Intelligent Shell Upgrade

When invoked, RXNM performs an immediate capability check. If executed via a minimal `/bin/sh` (Dash/Ash) but a full `/bin/bash` is available on the host, it seamlessly re-executes itself under Bash. This automatically unlocks performance optimizations like associative array caching and native regex without user intervention.

### 2. Path A: The Bash Path (Robust Resilience)

* **Bash (Agent):** Prefers the `rxnm-agent` C-accelerator for <5ms Netlink/DBus operations.

* **Bash (Fallback):** If the agent is deleted or crashes, the script gracefully degrades to a pure shell implementation using `jq`, `iproute2`, and `busctl`.

* **Validation:** Full schema validation is performed before the execution layer is reached.

### 3. Path B: The POSIX Path (Agent-Forced)

* **Behavior:** Anchors logic to a strict POSIX `/bin/sh` implementation. It bypasses external CLI dependencies entirely by routing all complex data aggregation to the **C Agent**.

* **Dependencies:** Strictly requires `rxnm-agent`. Does not require `jq`, `ip`, `awk`, or `busctl`.

* **Universal Validation:** The schema intent layer uses strict POSIX loops, ensuring invalid configs are caught even in the most restricted shells.

## 🔋 "Project Silence": The Power Residency Analysis

RXNM implements "Project Silence" (XDP Nullify), a high-performance power-saving mode designed to extend battery life by 5-10% during `s2idle` (Suspend-to-Idle) sleep.

On modern kernels, background broadcast traffic (mDNS, ARP, SSDP) frequently wakes the CPU from deep sleep. This prevents the SoC from reaching its lowest power state (C6-C10), resulting in significant battery drain while the device is "off."

### Network Wakeup & Battery Impact Matrix

| Method | Packet Handling | CPU State during Packet | Resume Latency | Battery Life Impact | 
 | ----- | ----- | ----- | ----- | ----- | 
| **Default Linux** | Full OS Stack Processing | **C0 (Active)** | Instant | **High Drain**: CPU wakes fully to route packet. | 
| **RFKill (Soft)** | Soft-blocked in kernel | **C1/C2 (Shallow)** | Moderate | **Varies**: NIC may still poll; bus often stays powered. | 
| **Modprobe -r** | Driver removed entirely | **C10 (Deepest)** | **Fatal (\~4s)** | **Minimal**: No IRQs, but kills state and slow resume. | 
| **Android (APF)** | Firmware-level filtering | **Off/Sleep** | Instant | **Gold Standard**: Hardware filters before CPU wake. | 
| **RXNM XDP Native** | Driver Ring Buffer Drop | **C6-C10 (Deep)** | **Instant (<5ms)** | **Near-Android**: Dropped in driver context before OS wake. | 
| **RXNM XDP Generic** | Kernel Ingress Drop | **C1-C2 (Shallow)** | **Instant (<5ms)** | **Optimized**: CPU wakes briefly to drop, then idles. | 

### Why XDP Native vs. Generic?

* **XDP Native (HW Driver Support):** Used on high-end PCIe NICs. The packet verdict happens inside the driver's RX loop. The CPU processes the instruction so fast it rarely leaves the hardware-controlled deep sleep state.

* **XDP Generic (SKB Mode):** Used on legacy SDIO modules (Realtek/Broadcom). The kernel must allocate an `sk_buff` (memory buffer) before the BPF program can discard it. While this forces a brief CPU wake, it prevents the "thundering herd" of userspace processes (avahi, systemd) from waking up, providing a 10x efficiency gain over the default behavior.

### 🛡️ Buggy Driver & RF Chip Safety

Embedded devices often ship with "crappy" SDIO WiFi chips (RTL8723DS, RTL8821CS, etc.) whose drivers are notoriously fragile.

* **The Danger of `modprobe -r`:** Unloading a driver on these chips often leads to kernel panics or SDIO bus hangs.

* **The XDP Solution:** XDP operates strictly on the **data plane**. It does not unload the driver or alter the firmware state. The driver remains stable, but the CPU simply ignores the incoming noise. This makes XDP Nullify the only power-saving method that is truly safe for unstable hardware.

### 🔒 Security Context: The Logical Air-Gap

While Nullify Mode is designed for power management, it serves a secondary role as a **Robust Security Feature**.

By utilizing eBPF to implement a data-plane drop-all filter, RXNM provides a "Logical Air-Gap." When enabled, the network interface is effectively blind and deaf to the network at the driver level. Unlike a standard firewall (which still allows the OS to process packet headers), XDP Nullify prevents the protocol stack from even seeing the traffic. This acts as a network kill-switch that prevents unsolicited telemetry, remote access, or lateral movement attacks while the system in a low-power state, all without tearing down the authenticated WiFi link or losing IP state.

---

## 🚀 Performance Benchmarks

*Measured on Rockchip RK3326 (1.5GHz Quad-Core Cortex-A35).*

### Latency Comparison

*Time from command invocation to valid JSON output.*

| Operation | RXNM (Bash/POSIX+Agent) | RXNM (Bash Fallback) | ConnMan | NetworkManager | 
 | ----- | ----- | ----- | ----- | ----- | 
| **Status Read** | **< 5ms** | \~45ms | \~60ms | \~80ms | 
| **Route Dump** | **< 3ms** | \~35ms | N/A | \~15ms | 
| **Namespace Create** | **< 8ms** | \~20ms | N/A | \~40ms | 
| **Roaming Trigger** | **< 15ms** | \~50ms | \~200ms | \~250ms+ | 
| **Cold Boot** | **\~0.1s** | \~0.3s | \~0.8s | \~1.5s+ | 

### Resident Footprint & background activity (Cost of Idle)

This comparison highlights the "Background Overhead" of each stack. RXNM achieves a near-zero idle profile by using pure event-driven backends and ephemeral management logic.

| Metric / Component | RXNM (All Paths) | ConnMan Stack | NetworkManager | 
 | ----- | ----- | ----- | ----- | 
| **L2 WiFi** | `iwd`: **3.5 MB** | `wpa_supplicant`: 8.0 MB | `wpa_supplicant`: 8.0 MB | 
| **L3 Core** | `networkd`: **4.0 MB** | `connman`: 10.5 MB | `NetworkManager`: 24.2 MB | 
| **Management** | **0.0 MB** (Exits) | *(In L3 Core)* | *(In L3 Core)* | 
| **API/UI Bus** | **0.1 MB** (Socket) | N/A | `nm-applet`: 15.0 MB | 
| **TOTAL RAM** | **\~7.6 MB** | **\~18.5 MB** | **\~47.2 MB+** | 
| **Idle Wakeups / sec** | **< 2** (Netlink) | **\~12** (Polling) | **\~35+** (D-Bus/Plugins) | 

*Note: Internal wakeups are software-initiated interrupts (timers/polls). A lower number allows the CPU to stay in deeper sleep states longer, even if the radio is silent.*

---

## 📖 Command Reference

### 1. WiFi & Roaming (`rxnm wifi`)

* **Connect:** `rxnm wifi connect "MySSID" --password "s3cr3t"`

* **Hotspot:** `rxnm wifi ap start "MyHotspot" --share`

* **Roaming:** `rxnm wifi roaming enable` (Signal steering for opportunistic AP switching)

* **Direct:** `rxnm wifi p2p scan` / `rxnm wifi p2p connect`

### 2. Interface & IP (`rxnm interface`)

* **DHCP:** `rxnm interface eth0 set dhcp --metric 100`

* **Static:** `rxnm interface eth0 set static 192.168.1.50/24 --gateway 192.168.1.1`

* **Hardware:** `rxnm interface eth0 set hardware --speed 1000 --duplex full`

* **Status:** `rxnm interface eth0 show --get ip` (Extract specific values for scripts)

### 3. Power & System (`rxnm system`)

* **Nullify:** `rxnm system nullify enable --yes` (Activate eBPF silence mode)

* **Diagnostics:** `rxnm system check internet` (High-speed TCP probing)

* **Proxy:** `rxnm system proxy set --http "http://proxy:8080"`

### 4. Advanced Virtualization (`rxnm bridge|bond|vlan|vrf|service`)

* **Bridge:** `rxnm bridge create br0`

* **Namespaces:** `rxnm service create my-isolated-ns`

* **Exec:** `rxnm service exec my-isolated-ns "ping 8.8.8.8"`

---

## 🏠 User Stories & Cookbooks

### Scenario: The Retro Handheld Gamer

*Goal: Connect to Home WiFi, tether to a phone via Bluetooth, and set up a local multiplayer lobby.*

1. **Connect:** `rxnm wifi connect "Home_SSID" --password "mypassword"`

2. **Tether:** `rxnm bluetooth pan enable --mode client`

3. **Multiplayer:** `rxnm wifi p2p status` on Host; `rxnm wifi p2p connect "Host"` on Client.

### Scenario: The "Zero Loss" Suspend

*Goal: Maximize battery during s2idle while preserving SSH sessions.*

1. **Enable Silence:** `rxnm system nullify enable --yes`

2. **Result:** All incoming broadcast packets are dropped by XDP. The CPU remains in deep sleep. The link remains logically "UP," so TCP sessions (SSH) don't time out on resume.

---

## 🔌 API & Integration

### REST-Lite Input

```bash
echo '{"category":"wifi", "action":"connect", "ssid":"MyNet", "password":"pass"}' | rxnm --stdin
```

### Capability Discovery

Query feature status (Stable, Beta, Experimental):

```bash
rxnm api capabilities
```

---

## 📦 Deployment & Build Profiles

* **Standard Build (`make`):** Modular library system. Best for general Linux.

* **Static Build (`make tiny`):** Statically linked accelerator binary (\~50KB). Best for recovery environments.

* **Minimal Bundle (`make rocknix-release`):** Amalgamates "Retro Core" logic into a single flat script. Zero boot-time `source` overhead.

### Installation

```bash
make tiny
sudo make install
```

**Installed Paths:**

* `/usr/bin/rxnm`: Main CLI entrypoint (symlink).

* `/usr/lib/rocknix-network-manager/bin/rxnm`: Actual dispatcher script.

* `/usr/lib/rocknix-network-manager/bin/rxnm-agent`: Native C-accelerator.

* `/usr/lib/systemd/network/`: Default network templates.

## License

**GPL-2.0-or-later** Copyright (C) 2026-present Joel Wirāmu Pauling
