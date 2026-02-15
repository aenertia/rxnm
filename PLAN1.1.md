# RXNM v1.1: Universal Portability & Feature Completeness

**Status:** Planning Phase (Post-v1.0 Release)
**Target:** Feature Parity & BusyBox/Ash Compatibility
**Codename:** "Universal"

## 1. Executive Summary

While v1.0 established the architecture and stabilized core Wi-Fi/Ethernet functions, v1.1 focuses on **Environment Portability** and **Essential Feature Realization**.

The primary architectural shift in v1.1 is the **"Forced Agent Path" for CLI Logic**. To support minimalist userspaces (Alpine, Buildroot, BusyBox) where `bash` is absent, the entry-point script will be rewritten as a POSIX-compliant shim (`/bin/sh`). This shim delegates argument parsing and logic to the `rxnm-agent` binary.

**Crucially, v1.1 retains `systemd-networkd` as the backend engine.** The goal is to make the *management tool* (`rxnm`) portable across shells, while relying on the proven stability of the systemd stack for the actual networking implementation.

Additionally, **Tunnels** and **PPPoE** (currently stubbed in v1.0) will be promoted to **Stable** implementations.

## 2. The "Any-Shell" Mandate (Ash/Dash Compatibility)

### A. The Problem with v1.0

RXNM v1.0 relies on `#!/bin/bash`. It uses arrays, `[[ ]]` tests, and specific string manipulations not available in standard POSIX `sh` (used by Ash/Dash in BusyBox systems). This prevents the CLI tool from running on lightweight distributions or rescue shells.

### B. The v1.1 Solution: The Shim & Delegate Model

Instead of rewriting complex Bash logic into difficult-to-maintain POSIX shell script, v1.1 implements a **Router Shim**:

1. **The Entry Point (`bin/rxnm`):** Rewritten as a strict POSIX `/bin/sh` script.

2. **Detection Logic:**

   * Checks for `rxnm-agent` binary.

   * Checks shell capabilities.

3. **Routing:**

   * **Bash Environment:** Sources legacy libraries (optional backward compat).

   * **Ash/Dash Environment:** Immediately `exec`s the C Agent, passing all arguments raw. The Agent then generates the necessary `systemd-networkd` configuration files.

### C. Agent CLI Evolution

For this to work, `rxnm-agent` must understand the full semantic CLI structure, not just flags.

* **Current:** `rxnm-agent --connect "SSID"`

* **v1.1 Target:** `rxnm-agent wifi connect "SSID"`

The Agent will implement a subcommand parser (tokenizing `argv`) to match the v1.0 dispatcher logic exactly, generating standard `.network` files.

## 3. De-Stubbing: Advanced Feature Implementation

### A. Tunnels (Overlay Networks)

* **Status:** Stub -> Stable

* **Implementation:** The Agent will generate `systemd-networkd` compatible `.netdev` files.

  * **Logic:** Generate `[NetDev]` sections for `Kind=vxlan|gre|wireguard`.

  * **Validation:** Agent pre-validates local/remote IPs before writing config.

* **Supported Types:** VXLAN, GRE, IPIP, GRETAP, WireGuard.

### B. PPPoE (Point-to-Point over Ethernet)

* **Status:** Deferred -> Stable

* **Implementation:**

  * **Target:** Use `systemd-networkd`'s native `[PPPoE]` section.

  * **Legacy Fallback:** If the systemd version is too old (<254) to support native PPPoE, the Agent will generate a `.network` file but trigger a legacy `pppd` wrapper service.

### C. Cellular / WWAN (Native AT Controller)

* **Status:** New -> Stable

* **Use Case:** 5G/LTE connectivity for Handhelds (SIM slots) and Edge Routers (BPI-R4) without the bloat of ModemManager.

* **Architecture:** **Native Serial Implementation**.

  * **Control Plane:** The `rxnm-agent` implements a lightweight serial terminal (`termios`). It connects to the modem's control port (e.g., `/dev/ttyUSB2`).

  * **Logic:** It executes a standard 3GPP initialization sequence: `AT+CGDCONT` (Set APN) -> `AT+CGACT` (Activate Context).

  * **Data Plane:** Once the modem firmware activates the context, the kernel network interface (e.g., `wwan0`) detects carrier. RXNM manages this interface via standard `systemd-networkd` DHCP config.

  * **Benefit:** Zero external dependencies. No Glib, No Python, No D-Bus required for cellular.

## 4. Implementation Roadmap

### Phase 1: The Agent CLI Upgrade

* Refactor `src/rxnm-agent.c` to use a hierarchical command parser instead of `getopt_long` flat flags.

* Ensure Agent can generate `.network` files identical to the Bash `config-builder`.

### Phase 2: The POSIX Shim

* Replace `bin/rocknix-network-manager` with a `/bin/sh` script.

* Ensure seamless handover to the Agent on `ash`.

### Phase 3: Networkd Feature Integration

* Implement `.netdev` generation for Tunnels and PPPoE in the Agent.

* Validate compatibility with `systemd-networkd` v250+.

### Phase 4: Native Cellular Support

* Implement `cmd_cellular_connect` in the C Agent.

* Add simple AT-command response parsing (expect/send logic).

## 5. Functional Matrix (v1.1 Target)

| Feature | v1.0 (Bash/RC3) | v1.1 (Universal) | 
 | ----- | ----- | ----- | 
| **Shell Requirement** | Bash 4.4+ | **POSIX sh (Any)** | 
| **Deployment Size** | \~150KB Scripts | **\~900KB Static Binary** | 
| **Tunnels** | Stubbed | **Stable (.netdev)** | 
| **PPPoE** | Stubbed | **Stable** | 
| **Cellular (5G)** | Manual | **Native AT Controller** | 
| **Dependency** | `systemd-networkd` | **`systemd-networkd`** | 

## 6. Migration Guide

Existing users on v1.0 can update to v1.1 transparently. The new POSIX shim accepts the exact same arguments. Users on embedded BusyBox systems (where v1.0 refused to run) will now be able to execute `rxnm` commands, which will transparently pass through to the Agent to generate standard `systemd-networkd` configurations.
