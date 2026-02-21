# RXNM Nullify Architecture: Power, Stability & Project Silence

**Context:** Architecture and Implementation Specification for "Project Silence" (Nullify) in RXNM v1.1.x.
**Kernel Baseline:** Linux 6.18+ (Mainline).
**Target Hardware:**

* **Legacy/Minimal:** Rockchip RK3266, RK3326, Allwinner H700 (Budget Handhelds).

* **Mid-Range:** Rockchip RK3566 (RGB30, RG353 series).

* **Performance:** Rockchip RK3588 (Orange Pi 5 Handhelds, GameForce Ace).

* **High-End:** Qualcomm SM8550/SM8250 (Snapdragon 8 Gen 2 / 865, Retroid Pocket 5).

* **Specialized:** RF-less devices (Offline-only / Wired Secure endpoints).

## 1. The Core Problem: The Cost of "Idle" on Mainline

On modern Linux 6.18+ kernels, power management is standardized around `s2idle` (Suspend-to-Idle). While highly reliable for CPU state management, `s2idle` is extremely sensitive to hardware interrupts.

The traditional Linux stack struggles on embedded and handheld devices due to three primary drain vectors:

1. **Network Broadcast Storms:** Routers and IoT devices constantly send ARP, mDNS, and SSDP packets. Without intervention, the network interface receives these packets, asserts an interrupt (via SDIO or PCIe), and forces the host CPU to wake up to `C0` (Active) to process them. If a packet arrives *during* the suspend entry sequence, it causes a "Suspend Bounce"—the kernel aborts the sleep transition entirely.

2. **The Combo-Chip Dilemma (BLE Spam):** WiFi and Bluetooth almost always share physical silicon (e.g., Realtek/Broadcom) and bus interrupts (SDIO/PCIe). Silencing WiFi is insufficient if background Bluetooth Low Energy (BLE) advertisements (from smartwatches, trackers) continue to trigger hardware interrupts that wake the SoC.

3. **Input Fragmentation & "Bag Wakes":** Handhelds wake up or consume active CPU cycles while the screen is off due to joystick drift or buttons pressed inside a bag.

## 2. The RXNM Solution: Defense in Depth (Zero Resident Memory)

To silence IP networking and guarantee deep sleep residency, RXNM utilizes a multi-layered approach. We strictly avoid background daemons or resident memory processes; instead, we directly program the existing kernel and hardware boundaries.

### Layer 1: WoWLAN (Firmware Filtering)

WoWLAN allows the OS to instruct the WiFi module's MAC/PHY firmware on which packets justify waking the host.
By executing `iw phy0 wowlan enable disconnect magic-packet`, RXNM tells the firmware to drop all background chatter (mDNS/ARP) and only wake the host if the AP forcibly disconnects us or sends a magic packet.

*The Hardware Reality:*

* **High-End (`ath11k` / `ath12k`):** Excellent. The PCIe/SNOC firmware successfully filters multicast traffic, allowing the SoC to remain in deep `s2idle` indefinitely.

* **Mid-Range (`brcmfmac`):** Hit or Miss. While supported, SDIO bus implementations on cheaper boards are often flaky. WoWLAN can sometimes prevent the bus controller from entering its lowest power mode.

* **Budget/Legacy (`rtw88`, Out-of-Tree SDIO):** Poor to Non-Existent. Many Realtek drivers lack WoWLAN support or panic upon resume.

### Layer 2: XDP Nullify (Host/Driver Filtering)

Because we cannot trust WoWLAN across all hardware, RXNM implements **XDP_DROP** via eBPF as the ultimate safety net. We embed a trivial BPF program in `rxnm-agent` that returns `1` (Drop) for all incoming traffic:

```
struct bpf_insn xdp_drop_prog[] = {
    { 0xb7, 0, 0, 0, 1 }, /* mov r0, 1 (XDP_DROP) */
    { 0x95, 0, 0, 0, 0 }, /* exit */
};

```

* **How it works:** `rxnm system nullify enable` attaches this program directly to the network interface. If WoWLAN fails and the firmware wakes the CPU, the XDP program intercepts the packet at the lowest driver level. It is discarded instantly—before the kernel allocates an `sk_buff` or attempts to route it.

* **Native vs. Generic Mode:** High-end PCIe NICs use XDP Native (packet dropped in the driver's RX ring buffer). Legacy SDIO modules use XDP Generic (SKB Mode), which still prevents the massive "thundering herd" of userspace wakeups (avahi, systemd).

## 3. "Software WoL": Backporting Magic Packets via eBPF

A critical challenge arises on budget devices (like generic Realtek SDIO chips or cheap USB-C Ethernet dongles) that lack hardware-level Wake-on-LAN (WoL) or WoWLAN support.
If a user wants the ability to wake the device over the network, disabling the interface entirely makes WoL impossible. However, leaving the interface active without filtering drains the battery rapidly.

To solve this, RXNM introduces the `--soft-wol yes` flag. This dynamically replaces the "dumb" `XDP_DROP` program with an expanded, hand-crafted eBPF bytecode filter.

### 3.1. How Software WoL Works

Instead of blindly dropping everything, the XDP program inspects the raw network packet headers in nanoseconds:

1. **Validation:** It verifies the Ethernet boundary, checks for the IPv4 protocol (`0x0800`), and confirms the payload is UDP (`17`).

2. **Port Triage:** It checks the destination port. Standard Magic Packets are dispatched over UDP Port 7 or 9.

3. **The Verdict:** \* If the packet is destined for Port 7/9, the program issues an `XDP_PASS`. The packet flows into the Linux network stack, userspace is alerted, a wakelock is acquired, and the system resumes from sleep.

   * For all other packets (ARP, mDNS, generic routing noise), it issues an `XDP_DROP`.

The host CPU still wakes up briefly at the driver boundary to process the event, but the eBPF triage is so computationally trivial that the battery penalty is negligible. We effectively "backport" high-end WoL functionality to $5 USB ethernet adapters and budget SDIO chips.

### 3.2. Medium-Agnostic Filtering

Because the eBPF bytecode evaluates standard IEEE 802.3 Ethernet frames, it does not care about the physical transmission medium. It works identically across:

* `wlan0` (SDIO/PCIe WiFi)

* `eth0` (Physical MACs or USB Hub Dongles)

* `usb0` / `rndis0` (USB Gadget Interfaces)

### 3.3. The USB Gadget Use Case: "The Powered Air-Gap"

This feature shines particularly bright when the handheld is plugged into a PC acting as a USB Gadget (`rndis0` / `ncm`).

* **The Problem:** Host PCs (Windows/macOS) constantly blast network discovery packets over all active interfaces. This prevents a docked/plugged-in handheld from staying asleep.

* **The RXNM Solution:** By applying `--soft-wol yes` to the USB Gadget interface, the host PC sees the connection as fully `UP` (allowing stable 5V charging without "Device Disconnected" errors). Meanwhile, the handheld's XDP filter instantly drops the Windows background noise, allowing the handheld to sleep soundly.

* **The Benefit:** If the user wants to interact with the device via SSH, they can run a script on their PC to send a Magic Packet over the USB subnet. The XDP filter passes the packet, the handheld instantly wakes up, and `rxnm-resume` strips the filter so SSH traffic can flow. It is a perfect, powered air-gap.

## 4. Overlay Networks, VPNs, & Containers

Virtual interfaces (`tun`, `wg0`, `veth`, `docker0`) interact with the Nullify architecture in a highly efficient manner due to the "Underlay vs. Overlay" nature of Linux networking.

### 4.1. Global Nullify: The Underlay Choke-Point

When a user executes a global sweep (`rxnm system nullify enable`), **virtual interfaces are intentionally ignored.** They lack the `/sys/class/net/<iface>/device` hardware symlink, so the orchestrator skips them, applying XDP strictly to the physical underlay (`wlan0`, `eth0`).

This is completely safe and optimal for power savings:

* **Ingress:** Any incoming WireGuard/Tailscale UDP packet hits the physical WiFi driver, gets intercepted by XDP, and is instantly dropped *before* it can reach the VPN decryption stack or the container bridge.

* **Egress (Keepalives):** During `s2idle` sleep, the kernel freezes userspace timers, halting persistent keepalives. During "Offline Gaming Mode" (awake but nullified), if WireGuard constructs a keepalive packet and sends it down to the physical interface, the `wlan0` XDP filter traps and drops it. No actual radio transmission occurs, sparing the battery.

### 4.2. Container Networking: The "Local Sandbox"

Because the global Nullify sweep only targets physical egress boundaries, an excellent byproduct emerges for containerized environments (Docker, Podman, `systemd-nspawn`): **Local microservices remain online.**

* Traffic traveling between containers on a local software bridge (`docker0`) never touches the physical network interface.

* Therefore, local REST APIs, databases, or inter-container communications function perfectly while the host remains completely, logically air-gapped from the external internet via the physical XDP drop filter.

### 4.3. Per-Interface Nullify: Logical Kill-Switches

If a user explicitly targets a virtual interface (`rxnm system nullify enable --interface wg0` or `--interface veth_app1`), `rxnm-agent` automatically falls back to **Generic XDP (SKB Mode)** to attach the eBPF filter directly to the virtual link.

This creates a targeted "Logical Kill-Switch." In this scenario, the physical WiFi interface remains fully active (allowing standard LAN traffic or un-tunneled internet), but all traffic entering or leaving the specific WireGuard tunnel or Docker container is instantly dropped at the virtual boundary by eBPF.

## 5. Beyond IP Networking: Bluetooth and Inputs

### 5.1. Bluetooth: The Logical Air-Gap

During the design phase, extending eBPF to Bluetooth via `BPF_PROG_TYPE_SOCKET_FILTER` was evaluated and rejected. Raw socket filters in Linux act as sniffers; dropping a BLE packet in a socket filter only hides it from the daemon holding the socket, it *does not* prevent the kernel's HCI core from processing the packet and waking the system.

* **The RXNM Approach:** To establish a true logical air-gap and save power, we use the native `hciconfig hci0 down` (or `bluetoothctl power off`). This logically closes the HCI interface at the hardware boundary, guaranteeing zero wakeups without risking notoriously buggy SDIO driver unloads (`modprobe -r`).

### 5.2. Inputs: The Proxy Trap (Explicitly Out-of-Scope)

Why not use `EVIOCSMASK` ioctls or eBPF to mask joystick drift while asleep?

1. **Per-FD Limitations:** `EVIOCSMASK` is file-descriptor specific. Masking a joystick in an RXNM daemon does not mask it for `systemd-logind` or RetroArch, meaning the CPU still wakes up.

2. **USB Composite Hardware:** On devices like the Retroid Pocket 5, the power button and joystick share the same internal USB MCU. If you globally grab/disable that device to stop joystick drift, the OS will never see the power button press, trapping the device in sleep forever.

* **The RXNM Approach:** Inputs are explicitly out-of-scope for RXNM. Input filtering belongs in dedicated userspace abstractions (like `input-plumber`, `Steam Input`, or `systemd-logind` udev rules) which are designed to handle `/dev/uinput` proxying and complex composite MCU devices natively.

## 6. Orchestration & State Persistence (`rxnm-resume`)

The Nullify mechanisms (XDP, WoWLAN flags, Bluetooth HCI state) are highly persistent. They survive `s2idle` and `S3` sleep cycles. To prevent the device from waking up "deaf," RXNM utilizes symmetric state tracking baked directly into the core library, invoked cleanly by the `systemd-sleep` hook.

### 6.1. Automatic State Tracking

When `rxnm system nullify enable` is called, the system natively records the pre-existing state of the hardware:

* **Bluetooth:** Captures the `/sys/class/rfkill` state (e.g., if BT was already turned off by the user).

* **WiFi:** Captures the currently connected SSID.
  When disabled, it intelligently restores only what was previously active.

### 6.2. The `systemd-sleep` Hook (`usr/lib/systemd/system-sleep/rxnm-resume`)

RXNM ships with an intelligent sleep hook that supports an optional `NULLIFY_ON_SLEEP` behavior (configured via `/storage/.config/network/nullify.conf`).

* **Pre-Suspend (`pre/*`):**
  If `NULLIFY_ON_SLEEP="true"`, the hook checks if the user has already manually enabled Nullify (e.g., for "Offline Gaming Mode"). If not, it engages Nullify automatically and creates a sentinel file (`auto_nullified`).

* **Post-Resume (`post/*`):**
  If the sentinel file exists, the hook instantly triggers `rxnm system nullify disable`, stripping the eBPF filters and bringing Bluetooth back up. The hook then spawns a detached subshell that waits for `iwd` to stabilize and gracefully re-authenticates the saved WiFi SSID.

## 7. Security Context (The "Happy Accident")

While the "Project Silence" architecture was designed strictly as a power-management tool to maximize `s2idle` battery life, this aggressive hardware-level silencing produces a highly beneficial side effect: a **Logical Air-Gap**.

Because our primary goal was to prevent the CPU from waking up to parse network headers (which drains battery), the resulting implementation drops packets at the absolute lowest boundaries (XDP for IP networking, HCI `down` for Bluetooth). This makes the interfaces effectively blind and deaf to the outside world while the device is "asleep."

Unlike a standard `iptables` or `nftables` firewall (which still requires the OS kernel to wake up, allocate memory, and parse IP headers), XDP Nullify prevents the OS protocol stack from even seeing the traffic. As a byproduct of saving battery, this mechanism inadvertently secures the device against:

* **Zero-Click Exploits:** Prevents background BLE exploits (e.g., BlueBorne variants) or rogue network packet attacks while the device is unattended in a backpack.

* **Lateral Movement:** Stops compromised devices on a public/hotel WiFi from probing the handheld while it is suspended.

* **Unauthorized Telemetry:** Guarantees that applications cannot phone home or leak data while the user believes the device is "off"—all without tearing down the authenticated WiFi link or losing the local IP address for when the device wakes up.
