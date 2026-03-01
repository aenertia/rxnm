# RXNM 2.0: The Monolithic Convergent Evolution

**Status:** Future Planning (Post-v1.0 RC3)

**Target:** Unified Network Runtime for Extremis (MCU), Handhelds, and Cloud.

**Core Philosophy:** Convergence of the "Micro" and "Full Fat" stacks into a single, power-aware high-performance C engine with eBPF/XDP at the center.

## 1. Vision: From "Hybrid" to "Monolithic"

RXNM 1.0 established the **Hybrid Path** (Bash logic + C acceleration + `systemd-networkd`).
RXNM 2.0 moves to a **Converged Engine** where the C Agent becomes the primary logic engine. For handhelds and extremis environments, this eliminates the overhead of the `systemd-networkd` daemon and its associated XML/INI parsing logic in favor of a monolithic state machine.

### Evolution Comparison

| Metric | 1.1 (Hybrid) | OpenWrt (netifd) | 2.0 (Converged Mono) | 
| :--- | :--- | :--- | :--- | 
| **Logic Engine** | Bash / systemd-networkd | C / **ubus** / Shell Scripts | Monolithic C Engine | 
| **Connectivity** | `iwd` (D-Bus) | `hostapd` / `wpa_s` | Internalized `ell`/`iwd` Logic | 
| **Data Plane** | Kernel IP Stack | Kernel IP Stack / Bridge | **eBPF / XDP (Primary)** | 
| **IPC** | D-Bus (System/Lite) | **ubus** (libubox) | **Zero-IPC (Internal)** | 
| **Service Logic** | Native `unshare`/`setns` (Agent) | Flat Router Namespace | Native `setns` / BPF Maps | 
| **CPU Wakeups (Idle)** | \~20-40 / sec | \~10-20 / sec | **< 2 / sec** | 
| **Resident RAM** | \~7.7 MB | \~6.5MB | **\~2.5MB (Unified)** | 

## 2. Core Architecture Pillars

### A. The "Cannibalized" Engine (Zero-IPC Connectivity)

2.0 integrates core connectivity components directly into the agent memory space.

* **Power Benefit:** Eliminates the D-Bus/ubus daemon requirement. By removing the context-switching between connectivity daemons and the manager, the CPU stays in deep sleep (C-state) longer.
* **Unified State:** Authentication and L3 addressing happen in the same process memory space, enabling atomic, instant transitions from "Resume" to "Connected."

### B. eBPF/XDP: The Power-Aware Data Plane

2.0 uses eBPF maps as the primary source of truth for routing and firewalling.

* **Interrupt Coalescing:** XDP allows packets to be processed at the driver level. Inter-service (SOA) traffic never traverses the kernel's heavy IP stack, significantly reducing CPU interrupts.
* **Comparison with netifd:** While `netifd` handles the control plane efficiently, its data plane is standard Linux bridging/routing. RXNM 2.0 uses XDP-Redirect to shunt packets between namespaces with sub-microsecond latency.

### C. Reactive Power Management

The 2.0 engine is 100% event-driven, blocking on a single Netlink socket for kernel events.

* **Hardware Filter Offloading:** On supported handheld NICs, the engine configures eBPF filters to drop background ARP/MDNS chatter in hardware, ensuring the SoC stays in deep C-states (C10+) longer.

## 3. Compile-Time Harvesting & Build Complexity

To minimize reinventing the wheel while maintaining an "Extremis" footprint, RXNM 2.0 utilizes a **Harvesting Build Pipeline**. Instead of linking against heavy external libraries, the build system surgically extracts source files from upstream projects.

### A. Upstream Source Harvesting

| Component | Harvest Target | Purpose | 
| :--- | :--- | :--- | 
| **iwd** | `src/station.c`, `src/network.c`, `src/wsc.c` | PSK State Machines & Scanning | 
| **ell** | `ell/main.c`, `ell/genl.c`, `ell/tls.c` | Event Loop, Netlink, and Crypto Primitives | 
| **systemd** | `src/shared/conf-parser.c` | Standard `.network` file compatibility | 

### B. Automated Logic Surgery

The build system (Make/Meson) performs automated preprocessing on harvested code:

* **D-Bus Excision:** Uses `sed` and preprocessor macros to strip all `dbus_` function calls and object-manager logic from the harvested `iwd` source.
* **Feature Pruning:** Removes Enterprise (EAP) and SIM-card logic from `ell/tls`, reducing the static binary size by \~40%.
* **Symbol Namespacing:** Wraps harvested logic in `rxnm_` namespaces to prevent collisions while allowing us to track upstream bug fixes easily.

## 4. Performance & Efficiency Matrix

Comparison of the Monolithic 2.0 stack against standard `systemd-networkd` and OpenWrt `netifd`.

| Metric | systemd-networkd | OpenWrt (netifd) | Micro-RXNM 2.0 (Mono) | 
| :--- | :--- | :--- | :--- | 
| **Resident RAM** | \~7.7 MB (Total Stack) | \~6.5 MB | **\~2.5 MB** | 
| **Binary Footprint** | \~5.2 MB | \~1.2 MB | **\~0.9 MB** | 
| **Cold Start Latency** | \~450ms | \~250ms | **\~15ms** | 
| **USB/TB Hotplug** | \~180ms | \~80ms | **< 5ms** | 
| **Idle Wakeups** | \~25/sec | \~12/sec | **< 2/sec** | 
| **Throughput (PPS)** | Kernel Limited | Kernel Limited | **Line Rate (XDP)** | 

## 5. Use Case Scenarios: The ROI of Zero-IPC

### A. Handhelds (Anbernic, Powkiddy, Retroid, Ayaneo)

* **Problem:** RAM is contested between network daemons and emulators.
* **RXNM Solution:** Recovers **4MB - 45MB** of Resident RAM vs. traditional stacks.
* **Power:** Extended standby by eliminating `ubus`/`dbus` polling interrupts.

### B. Embedded Router (MIPS/RISC-V MCU)

* **Comparison with OpenWrt:** `netifd` is the standard here, but RXNM 2.0's SOA approach allows for hardware-isolated namespaces (e.g., WAN vs. LAN) on the same 16MB Flash board.
* **Benefit:** XDP offloading allows a 64MB RAM MCU to route gigabit traffic without pegging the CPU.

### C. Cloud & Container Edge

* **CNI Replacement:** RXNM 2.0 acts as a high-density networking runtime.
* **Efficiency:** Supports up to **20x more isolated services** on the same hardware compared to standard container networking due to the monolithic management plane.

## 6. Implementation Roadmap

### Phase 1: Harvesting Infrastructure
* Create `scripts/harvest-upstream.sh` to pull specific source trees.
* Establish the "Surgery" patchset to strip D-Bus/Glib from harvested files.
* Implement the raw `bpf()` loader in the Agent.

### Phase 2: Integrated Logic Convergence
* Integrate harvested `iwd` station logic into the Agent's event loop.
* **Wakeup Audit:** Optimize the main loop to ensure zero wakeups when idle.
* Demonstrate Zero-IPC WiFi connection (no external daemon).

### Phase 3: XDP-Native SOA & Data Plane
* Implement the inter-namespace fast-path using `XDP-Redirect`.
* Migrate "Nullify Mode" and "Firewall" logic to driver-level XDP programs.

### Phase 4: Release & Extremis Validation
* Update the `rxnm` dispatcher to detect hardware capabilities and launch the 2.0 runtime.
* Final validation on 16MB SPI Flash and 64MB RAM targets.

## 7. Functionality Matrix: The 2.0 Standard

| Feature | RXNM 1.1 (Hybrid) | OpenWrt (netifd) | RXNM 2.0 (Mono) | 
| :--- | :--- | :--- | :--- | 
| **Logic Engine** | systemd-networkd | C + Shell Scripts | **Internal C Logic** | 
| **WiFi Auth** | External `iwd` | External `wpa_s` | **Internal Module** | 
| **Firewall** | `iptables`/`nft` | `fw4` (nftables) | **eBPF (Stateless)** | 
| **IPC Bus** | D-Bus | **ubus** | **NONE (Monolithic)** | 
| **Power Mgmt** | Passive | Passive | **Proactive** | 

## 8. Summary

RXNM 2.0 is the evolution from a "Manager" to a "Network Runtime." By cannibalizing the best-in-class logic from `iwd` and merging it with **XDP hardware-acceleration**, we create a stack that is invisible to the user but carrier-grade in performance.

While OpenWrt's `netifd` is significantly leaner than `systemd-networkd`, it still relies on an IPC bus (`ubus`) and external shell scripts for L3 configuration. RXNM 2.0 eliminates these remaining overheads, providing a single-binary networking solution that scales from 64MB MCUs to 128-core x86_64 cloud hosts.
