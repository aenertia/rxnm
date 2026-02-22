# Upstream Bug Tracking Register

This document serves as a central register for tracking bugs, architectural limitations, and missing features discovered in upstream projects (e.g., `systemd`, `iwd`, `linux kernel`) during the development of RXNM (ROCKNIX Network Manager).

By maintaining this register, we track the status of our upstream contributions (Issues/PRs) and document the rationale behind any downstream patches, forks, or workarounds currently maintained within the RXNM ecosystem.

## Active Tracking

### 1. systemd: Managed IPv4 Link-Local (RFC 3927) Restrictions

* **Project**: `systemd` (`systemd-networkd`)

* **Discovered**: During RXNM USB Gadget (NCM/RNDIS) and Point-to-Point integration testing.

* **Upstream Issue**: [systemd/systemd#40783](https://github.com/systemd/systemd/issues/40783)

* **Upstream PR**: [systemd/systemd#40785](https://github.com/systemd/systemd/pull/40785)

* **Impact on RXNM**: High. Prevented the use of `169.254.x.x` subnets for managed Point-to-Point links, forcing the use of standard RFC 1918 space (e.g., `192.168.x.x`) which introduced severe subnet collision hazards with host networks.

* **Description**: `systemd-networkd` hard-coded aggressive restrictions against the `169.254.0.0/16` subnet, conflating the physical address space with the unmanaged ZeroConf Auto-IP mechanism. It prevented `DHCPServer` from binding to IPv4LL addresses, trapped `DHCP4` client leases in a `degraded` (`RT_SCOPE_LINK`) state, and rejected IPv4LL default gateways as unreachable.

* **Current Mitigation**: We maintain a downstream patchset (documented in `ADR-001: Support for Managed IPv4 Link-Local Networks`) in our `systemd` fork to unblock the DHCP Server, promote the client scope to `RT_SCOPE_UNIVERSE`, and whitelist the gateway readiness checks. Awaiting upstream merge.

### 2. dbus-broker: Rejection of lightweight DBus connections in systemd-nspawn

* **Project**: `dbus-broker` / `systemd`

* **Discovered**: During CI integration testing when using the C agent to trigger `systemd-networkd` DBus reloads.

* **Upstream Issue**: TBD

* **Impact on RXNM**: Medium. Breaks the zero-fork DBus-lite accelerated reload path in CI environments, forcing a fallback to the slower `networkctl` shell execution.

* **Description**: When executing inside a `systemd-nspawn` container environment, `dbus-broker` connection guards reject the lightweight raw DBus socket connection (`rxnm_dbus_lite.h`) made by `rxnm-agent --reload`. This prevents the agent from communicating directly with `systemd-networkd` over the system bus in CI, whereas the exact same bare-metal implementation succeeds.

* **Current Mitigation**: `rxnm-system.sh` (specifically `reload_networkd()`) detects the agent DBus reload failure and falls back to the legacy path (`timeout 5s networkctl reload`).

### 3. systemd: networkctl JSON MAC Address Array Quirk

* **Project**: `systemd` (`networkctl`)

* **Discovered**: During RXNM status JSON consistency validations (`test_consistency.sh`).

* **Upstream Issue**: TBD

* **Impact on RXNM**: Low. Requires strict JSON normalization in legacy shell parsing.

* **Description**: `networkctl --json=short` occasionally outputs MAC hardware addresses as a raw decimal array (e.g., `[202, 2, ...]`) instead of a standard formatted hex string, breaking strict downstream schema expectations.

* **Current Mitigation**: `test_consistency.sh` includes an explicit parsing block (`case "$raw_mac_legacy" in \[*)...`) to detect the integer array format, iterate through the numbers, and format them back into a standard `XX:XX:XX:XX:XX:XX` hex string for comparison.

### 4. iwd: WPA Handshake Abort Race Condition

* **Project**: `iwd`

* **Discovered**: During WiFi connection resilience testing (`rxnm-wifi.sh`).

* **Upstream Issue**: TBD

* **Impact on RXNM**: Medium. Caused false-negative connection failures during aggressive connection retries.

* **Description**: If a `Connect()` DBus method (or `iwctl connect`) is issued to `iwd` while the daemon is actively in the `connecting` or `authenticating` state (e.g., performing the WPA handshake), `iwd` abruptly aborts the current handshake and errors out, rather than debouncing or queuing the request.

* **Current Mitigation**: `action_connect()` in `rxnm-wifi.sh` explicitly polls `iwd`'s state before issuing a retry. If the state is `connecting` or `authenticating`, it skips the command execution and patiently waits for the timeout to allow the slow SoC to complete the handshake.

### 5. Linux Kernel: SDIO WiFi Driver RX Ring Stalls (XDP Generic)

* **Project**: Linux Kernel / WiFi Drivers (e.g., `rtw88`, `brcmfmac`)

* **Discovered**: During "Project Silence" (Nullify Mode) hardware testing on budget handhelds (`rxnm-agent.c`).

* **Upstream Issue**: TBD

* **Impact on RXNM**: High. Forced the implementation of complex state tracking and "Atomic Kicks" to prevent hardware lockups.

* **Description**: Budget SDIO WiFi drivers often wedge their RX ring buffers or saturate the SDIO bus when subjected to rapid packet drops via XDP Generic (`SKB_MODE`). Dropping the packets via XDP successfully prevents the host CPU from waking, but the driver/firmware boundary crashes.

* **Current Mitigation**: `rxnm-agent.c` implements two workarounds. 1) Stateless Back-Pressure: Forces the WiFi chip into Power Save Mode (`NL80211_PS_ENABLED`) to command the AP to buffer broadcast noise. 2) The "Atomic Kick": Synchronously toggles the `IFF_UP` flag off and on when detaching XDP to instantly flush the wedged RX ring buffers without dropping the WiFi carrier.

### 6. Linux Kernel: mac80211 Ghost P2P Interfaces

* **Project**: Linux Kernel (`mac80211`)

* **Discovered**: During Systemd-Nspawn container bootstrapping for Virtual WiFi testing (`run_interop.sh`).

* **Upstream Issue**: TBD

* **Impact on RXNM**: Medium. Breaks AP/Hotspot provisioning out-of-the-box due to concurrency limits.

* **Description**: The `mac80211` subsystem (and many physical drivers) automatically spawn hidden `type P2P-device` virtual interfaces alongside the primary `wlan0` interface. These ghost interfaces consume the radio's limited concurrency slots. When RXNM attempts to start a Host/AP interface, it fails because the hardware reports no available capabilities.

* **Current Mitigation**: `run_interop.sh` includes a `sanitize_wifi.sh` script that queries the physical hierarchy via `iw dev`, identifies the ghost WDEVs associated with `type P2P-device`, and surgically deletes them (`iw wdev <id> del`) to free up the concurrency slots for AP mode.

## Resolved / Merged

*(No resolved upstream issues yet)*
