# RXNM 2.0: The Monolithic Convergent Evolution

**Status:** Future Planning (Post-v1.0 RC3)
**Target:** Unified Network Runtime for Extremis (MCU), Handhelds, and Cloud.
**Core Philosophy:** Convergence of the "Micro" and "Full Fat" stacks into a single, power-aware high-performance C engine with eBPF/XDP at the center.

## 1. Vision: From "Hybrid" to "Monolithic"

RXNM 1.0 established the **Hybrid Path** (Bash logic + C acceleration).
RXNM 2.0 moves to a **Converged Engine** where the C Agent becomes the primary logic engine, and Bash/CLI becomes a thin wrapper or is eliminated entirely for extremis targets. For handhelds, this shift is primarily driven by the need to eliminate background "jitter" and maximize battery life during deep sleep and active gameplay.

### Evolution Comparison

| Metric | 1.0 (Hybrid RC3) | 2.0 (Converged Mono) | 
| :--- | :--- | :--- | 
| **Logic Engine** | Bash / `systemd-networkd` | Monolithic C Engine | 
| **Connectivity** | `iwd` (D-Bus) | Internalized `ell`/`iwd` Logic | 
| **Data Plane** | Kernel IP Stack | **eBPF / XDP (Primary)** | 
| **IPC** | D-Bus (System/Lite) | **Zero-IPC (Internal)** | 
| **Service Logic** | `ip netns` (Fork) | Native `setns` / BPF Maps | 
| **CPU Wakeups (Idle)** | \~20-40 / sec | **< 2 / sec** | 
| **Resident RAM** | \~11.5MB | **\~2.5MB (Unified)** | 

## 2. Core Architecture Pillars

### A. The "Cannibalized" Engine (Zero-IPC Connectivity)

2.0 integrates core connectivity components directly into the agent memory space.

* **Power Benefit:** Eliminates the D-Bus daemon requirement. In traditional stacks, every signal (RSSI change, scan results) triggers a context switch and CPU wakeup as messages bounce between `iwd`, `dbus`, and `NetworkManager`.
* **Unified State:** Authentication and L3 addressing happen in the same process memory space, enabling atomic, instant transitions from "Resume" to "Connected."

### B. eBPF/XDP: The Power-Aware Data Plane

2.0 uses eBPF maps as the primary source of truth for routing and firewalling.

* **Interrupt Coalescing:** XDP allows packets to be processed at the driver level. Inter-service (SOA) traffic never traverses the kernel's heavy IP stack, reducing the "Instructions Per Packet" (IPP).
* **Stateless Firewalling:** Moves all "Nullify" and "Service Isolation" logic into XDP_DROP programs.

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

### C. Build Complexity Requirements

* **LLVM/Clang Integrated:** Required for eBPF/XDP bytecode generation (CO-RE - Compile Once, Run Everywhere).
* **Header Generation:** An expanded version of `sync-constants.sh` that generates C structures directly from the API schema to ensure 100% alignment between harvested logic and the RXNM API.
* **Static Analysis:** Mandatory Valgrind and Bear checks to ensure the monolithic engine doesn't introduce memory leaks in high-uptime cloud or handheld environments.

## 4. Handheld-Specific Gains (Anbernic, Powkiddy, Retroid, Ayaneo)

### Tier 1: Low-Power Recovery (RK3326 / H700)

* **RAM Recovery:** Recovering \~45MB compared to a standard stack allows 1GB devices to allocate more memory to GPU texture buffers.
* **Standby Efficiency:** Reduces "idle drain" by \~15% by removing the "Daemon Storm" of background processes.

### Tier 2: The Competitive Gamer (SM8550 / RK3588)

* **Jitter Elimination:** XDP processing ensures that RetroArch Netplay packets bypass the kernel's standard task scheduler.
* **Docking Response:** Instant handover between WiFi and USB Ethernet without dropping TCP save-sync streams.

## 5. Implementation Roadmap

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

## 6. Functionality Matrix: The 2.0 Standard

| Feature | RXNM 1.0 (RC3) | RXNM 2.0 (Plan) | Transition Benefit | 
| :--- | :--- | :--- | :--- | 
| **Hotplug Logic** | Netlink -> Bash | **Netlink (Atomic C)** | \~100x Faster Response | 
| **WiFi Auth** | External Daemon | **Internal Module** | Zero-IPC, No D-Bus overhead | 
| **Firewall** | `iptables`/`nft` | **eBPF (Stateless)** | Zero CPU usage on idle | 
| **Address Sync** | systemd-networkd | **Internal SLAAC/DHCP** | Reduced context switches | 
| **Power Mgmt** | Passive | **Proactive (Wakeup-Free)** | **Extended Standby Time** | 
| **IPv6** | Kernel Stack | **eBPF Accelerated** | Near-zero latency routing | 

## 7. Summary

RXNM 2.0 is the evolution from a "Manager" to a "Network Runtime." By cannibalizing the best-in-class logic from `iwd` and merging it with **XDP hardware-acceleration**, we create a stack that is invisible to the user but carrier-grade in performance.

The use of "Harvesting" ensures we benefit from the massive security and stability testing of upstream projects while discarding the desktop bloat that hinders handheld and extremis targets.
