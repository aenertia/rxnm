# RXNM ([ROCKNIX](https://github.com/ROCKNIX/distribution) Network Manager)

**RXNM** is a lightning-fast, modular CLI suite and API gateway for `systemd-networkd` and `iwd`. It is aggressively optimized for low-power ARM and RISC-V embedded devices (specifically RK3326, RK3566, RK3588, and SG2002 handhelds) while remaining 100% compatible with general Linux environments.

By eliminating monolithic middleware daemons, RXNM achieves a **0MB idle memory footprint** and sub-5ms read latencies, making it the ultimate networking stack for emulation handhelds, immutable OS designs, and containerized cloud environments.

| **Version** | **API Specification** | **Architecture** | **License** |
| :--- | :--- | :--- | :--- |
| `1.0.0-rc2` | `v1.0` (Frozen) | Hybrid (Interface + SOA) | GPL-2.0-or-later |

---

## 👨‍💻 Origins & Motivation

**RXNM** is developed independently, though it targets the **ROCKNIX** ecosystem as a primary consumer.

The author is a veteran engineer with **25+ years of experience** working with both Linux systems and major Network Equipment Vendors. This project was born not out of necessity, but out of frustration. Existing management stacks (NetworkManager, ConnMan) were found to be too heavy, too slow, or too opaque for the critical mission of low-power embedded devices.

Ultimately, RXNM exists to support a crippling addiction... *err, passionate and perfectly healthy hobby*... for collecting retro gaming handhelds. When you have 40 devices that need to connect to WiFi in under a second to sync save states, every millisecond of latency and megabyte of RAM counts.

---

## ⚡ Architecture: The Hybrid Model

RXNM v1.0 introduces a **Hybrid Architecture** that bridges the gap between simple embedded use-cases and carrier-grade networking.

### 1. Interface-Centric (The Fast Path)
*Default mode. Best for handhelds, single-board computers, and workstations.*

This mode treats physical network interfaces (`wlan0`, `eth0`) as the primary configuration objects. It maps 1:1 with `systemd-networkd` link files.
* **Zero Overhead:** No daemon processes run in the background. Configuration is compiled to static files in `/run/systemd/network`.
* **Hardware Focused:** Optimized for bringing up WiFi, setting static IPs, and managing power states.

### 2. Service-Oriented (The Carrier Path)
*Experimental mode. Best for virtualization, multi-tenant setups, and complex routing.*

This mode abstracts networking into **Services** (Namespaces) and **Overlays**. It allows for isolated routing tables, VRF-lite topologies, and independent network environments on a single device.
* **Isolation:** Uses Linux Network Namespaces (`netns`) accelerated by the native C agent.
* **Advanced Features:** Enables MPLS, PPPoE, and complex Tunneling without cluttering the root namespace.

---

## 🚀 Performance Benchmarks

RXNM relies on a **Native C Agent (`rxnm-agent`)** linked against `musl` for critical path operations. By leveraging existing kernel facilities rather than wrapping them in a heavy abstraction layer, RXNM drastically reduces resource consumption compared to **NetworkManager** (the desktop standard) and **ConnMan** (the embedded standard).

*Measured on Rockchip RK3326 (1.5GHz Quad-Core Cortex-A35).*

### 1. Latency & Responsiveness
*Time measured from command invocation to valid JSON output.*

| Operation | RXNM (Hybrid) | ConnMan | NetworkManager | Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Status Read** | **< 5ms** | ~30-60ms | ~45-80ms | Instant UI rendering vs noticeable lag. |
| **Route Dump** | **< 3ms** | N/A | ~15ms | Faster routing decisions. |
| **Namespace Create**| **< 8ms** | N/A | ~40ms | Rapid container spawning. |
| **Roaming Trigger** | **< 15ms** | ~200ms | ~250ms+ | Smoother WiFi handoff while gaming. |
| **Cold Boot** | **~0.1s** | ~0.8s | ~1.5s+ | Device ready to use sooner. |

### 2. Resident Memory Footprint (RAM)
*The "Cost of Idle". Memory consumed while the device is connected but user is inactive.*

| Component | RXNM Stack | ConnMan Stack | NetworkManager Stack | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **L2 WiFi** | `iwd`: ~3.5 MB | `wpa_supplicant`: ~8 MB | `wpa_supplicant`: ~8 MB | `iwd` is 50% lighter than `wpa_s`. |
| **L3 Network** | `networkd`: ~4.0 MB | `connman`: ~10 MB | `NetworkManager`: ~24 MB | RXNM uses systemd built-ins. |
| **Management** | **RXNM: 0 MB** | *(Included above)* | *(Included above)* | **RXNM process exits after task.** |
| **API Gateway** | ~0 MB (Socket) | N/A | ~15 MB (`nm-applet` etc) | RXNM uses systemd socket activation. |
| **TOTAL IDLE** | **~7.5 MB** | **~18 MB** | **~47 MB+** | **RXNM saves ~10-40MB RAM.** |

### 3. Storage Footprint (Disk)
*Installation size including binary dependencies (excluding shared system libraries like libc).*

| Stack | Binary Size | Config Size | Dependencies | Total Impact |
| :--- | :--- | :--- | :--- | :--- |
| **RXNM** | **~0.1 MB** | **~0 KB** | `bash`, `jq` | **Tiny.** Ideal for initramfs/recovery. |
| **ConnMan** | ~3.5 MB | ~100 KB | `glib2`, `dbus`, `iptables` | Moderate. Requires GLib. |
| **NetworkManager**| ~15 MB+ | ~500 KB | `glib2`, `dbus`, `libndp`, `libpsl`... | Heavy. Requires massive dep tree. |

---

## 📖 Command Reference

### 1. WiFi Management (`rxnm wifi`)
Manage wireless connections, Access Points, and P2P.

* **Scan & Connect:**
    ```bash
    rxnm wifi scan
    rxnm wifi connect "SSID_Name" --password "s3cr3t"
    rxnm wifi connect "Hidden_SSID" --password "xyz" --hidden
    ```
* **Access Point (Hotspot):**
    ```bash
    # Start a shared hotspot (NAT + DHCP)
    rxnm wifi ap start "MyHotspot" --password "12345678" --share

    # Stop AP and return to client mode
    rxnm wifi ap stop
    ```
* **WiFi Direct (P2P):**
    ```bash
    rxnm wifi p2p scan
    rxnm wifi p2p connect "Android_TV"
    rxnm wifi p2p status
    rxnm wifi p2p disconnect
    ```
* **Roaming:**
    ```bash
    # Enable background roaming monitor (opportunistic switching)
    rxnm wifi roaming enable
    # Monitor signal strength in foreground (debug)
    rxnm wifi roaming monitor
    ```
* **Advanced:**
    ```bash
    rxnm wifi country US
    rxnm wifi list       # Show known networks
    rxnm wifi forget "SSID"
    ```

### 2. Interface Configuration (`rxnm interface`)
Configure IP addressing, link properties, and DHCP.

* **DHCP:**
    ```bash
    # Standard DHCP with custom metric
    rxnm interface eth0 set dhcp --metric 100
    ```
* **Static IP:**
    ```bash
    rxnm interface eth0 set static 192.168.1.50/24 \
        --gateway 192.168.1.1 \
        --dns 8.8.8.8,1.1.1.1
    ```
* **Hardware Settings:**
    ```bash
    # Force link speed, duplex, or MAC address
    rxnm interface eth0 set hardware --speed 1000 --duplex full --autoneg on
    rxnm interface wlan0 set hardware --mac 00:11:22:33:44:55
    ```
* **Link State:**
    ```bash
    rxnm interface eth0 disable
    rxnm interface eth0 enable
    ```

### 3. Route Management (`rxnm route`)
Direct manipulation of the kernel routing table.

* **Add/Delete Routes:**
    ```bash
    # Add a static route to a specific subnet
    rxnm route add 10.0.0.0/8 --gateway 192.168.1.254

    # Add a blackhole route
    rxnm route add blackhole 192.0.2.0/24
    
    # Delete a route
    rxnm route del 10.0.0.0/8
    ```
* **Routing Decisions:**
    ```bash
    # Simulate kernel routing decision
    rxnm route get 8.8.8.8
    # Output: { "success": true, "route": { "dst": "8.8.8.8", "dev": "wlan0", "src": "192.168.1.50" } }
    ```
* **Maintenance:**
    ```bash
    rxnm route flush cache
    rxnm route list --table main
    ```

### 4. Virtual Devices (`rxnm bridge`, `bond`, `vlan`, `vrf`)
Create software-defined networking structures.

* **Bridge:**
    ```bash
    rxnm bridge create br0
    rxnm bridge add-member eth0 --bridge br0
    rxnm bridge add-member eth1 --bridge br0
    ```
* **VLAN:**
    ```bash
    # Create VLAN ID 10 on eth0
    rxnm vlan create vlan10 --parent eth0 --id 10
    ```
* **Bonding:**
    ```bash
    rxnm bond create bond0 --mode active-backup
    rxnm bond add-slave eth0 --bond bond0
    ```
* **MacVLAN / IPVLAN:**
    ```bash
    rxnm macvlan create mv0 --parent eth0 --mode bridge
    ```

### 5. System & Diagnostics (`rxnm system`)
Global health checks and settings.

* **Status:**
    ```bash
    rxnm system status --format human   # Detailed text
    rxnm system status --format json    # Machine readable
    rxnm system status --simple         # One-line summary
    ```
* **Connectivity Checks:**
    ```bash
    # Fast TCP-based internet check
    rxnm system check internet

    # Captive Portal detection
    rxnm system check portal
    ```
* **Proxy Settings:**
    ```bash
    rxnm system proxy set --http "http://proxy:8080" --noproxy "localhost"
    ```
* **Nullify Mode (Battery Saver):**
    ```bash
    # Completely teardown network stack and unbind drivers
    rxnm system nullify enable --yes
    ```

### 6. Profiles (`rxnm profile`)
Manage persistent configuration snapshots.

* **Operations:**
    ```bash
    rxnm profile save "Home"
    rxnm profile load "Work"
    rxnm profile list
    rxnm profile export "Home" --file /tmp/home.tar
    ```

### 7. Bluetooth (`rxnm bluetooth`)
Tethering and PAN management.

* **Operations:**
    ```bash
    rxnm bluetooth scan
    rxnm bluetooth pair AA:BB:CC:DD:EE:FF
    rxnm bluetooth pan enable --mode client # Connect to phone hotspot
    rxnm bluetooth pan enable --mode host   # Share internet
    ```

### 8. VPN (`rxnm vpn`)
WireGuard integration.

* **Operations:**
    ```bash
    rxnm vpn wireguard connect wg0 --private-key "KEY" --peer-key "PUB" --endpoint "IP:PORT" --allowed-ips "0.0.0.0/0"
    rxnm vpn wireguard disconnect wg0
    ```

### 9. Service Isolation (`rxnm service`)
*Experimental: Requires `RXNM_EXPERIMENTAL=true`*

Create isolated network namespaces for specific applications or routing domains.

```bash
export RXNM_EXPERIMENTAL=true

# Create a separated namespace
rxnm service create secure-enclave

# Move a physical interface into the enclave
rxnm service attach secure-enclave --interface eth1

# Execute a command inside the enclave
rxnm service exec secure-enclave "ip addr show"
```

---

## 📖 User Stories & Cookbooks

### 🏠 Scenario: The Home Lab
*Goal: Configure a static IP on Ethernet, set custom DNS, and create a network bridge for virtual machines.*

1.  **Set Static IP**:
    ```bash
    rxnm interface eth0 set static 192.168.1.10/24 --gateway 192.168.1.1 --dns 1.1.1.1
    ```
2.  **Create Bridge for VMs**:
    ```bash
    rxnm bridge create br0
    rxnm bridge add-member eth0 --bridge br0
    ```
3.  **Save Profile**: Persist this configuration as "HomeLab".
    ```bash
    rxnm profile save "HomeLab"
    ```

### 🎮 Scenario: The Retro Handheld Gamer
*Goal: Connect to Home WiFi, tether to a phone via Bluetooth, and set up a local multiplayer lobby.*

1.  **Connect to WiFi**:
    ```bash
    rxnm wifi connect "Home_SSID" --password "mypassword"
    ```
2.  **Bluetooth Tethering**:
    ```bash
    rxnm bluetooth pair AA:BB:CC:DD:EE:FF
    rxnm bluetooth pan enable --mode client
    ```
3.  **Local Multiplayer (WiFi Direct)**:
    ```bash
    # Player 1 (Host)
    rxnm wifi p2p status
    # Player 2 (Client)
    rxnm wifi p2p connect "Player1_Device"
    ```

### 🛰️ Scenario: The Remote Pro
*Goal: Connect to a corporate WireGuard VPN and set a global proxy.*

1.  **WireGuard Connection**:
    ```bash
    rxnm vpn wireguard connect wg0 \
      --private-key "Base64Key..." \
      --peer-key "PeerKey..." \
      --endpoint "vpn.work.com:51820" \
      --allowed-ips "10.0.0.0/8"
    ```
2.  **Global Proxy**:
    ```bash
    rxnm system proxy set --http "[http://proxy.corp:8080](http://proxy.corp:8080)" --noproxy "localhost,10.0.0.0/8"
    ```

---

## 🔌 API & Integration

RXNM v1.0 defines a strict **JSON Schema** (`api-schema.json`) for all inputs and outputs. This allows external tools (GUIs, web interfaces) to reliably interact with the network stack.

### Feature Introspection
Query the installed version to check which features are Stable, Beta, or Experimental.

```bash
rxnm api capabilities
```
**Response:**
```json
{
  "success": true,
  "systemd_networkd_version": 252,
  "agent_available": true,
  "features": {
    "wifi": { "status": "stable", "since_version": "1.0" },
    "service": { "status": "experimental", "since_version": "1.0" },
    "mpls": { "status": "planned", "since_version": "1.1" }
  }
}
```

### REST-Lite Input
Pass JSON configuration payloads directly to `stdin`. This is ideal for IPC from GUI frontends (React/QT) or web interfaces.

```bash
echo '{"category":"wifi", "action":"connect", "ssid":"MyNet", "password":"pass"}' | rxnm --stdin
```

---

## 📦 Installation

### Requirements
* **Runtime:** `bash 4.4+`, `systemd-networkd`, `iproute2`.
* **Wireless:** `iwd` (Recommended) or `wpa_supplicant` (Partial support via `networkd`).
* **JSON Processor:** `jq`, `jaq`, or `gojq`.

### Build from Source
```bash
# 1. Compile the native agent (Tiny/Static profile)
make tiny

# 2. Install to system paths
sudo make install
```

**Installed Components:**
* `/usr/bin/rxnm`: The main dispatcher.
* `/usr/lib/rocknix-network-manager/`: Core libraries & Agent binary.
* `/usr/share/bash-completion/completions/rxnm`: Tab completion definitions.
* `/usr/lib/systemd/network/`: Default network templates.

---

## License

**GPL-2.0-or-later** Copyright (C) 2026-present Joel Wirāmu Pauling
