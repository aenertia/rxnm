
Hierachy refactor
---
RXNM (ROCKNIX Network Manager)RXNM is a lightweight, modular CLI wrapper for systemd-networkd and iwd, optimized for low-power ARM devices (specifically RK3326/RK3566 handhelds) but compatible with general Linux environments. While designed specifically for the ROCKNIX ecosystem, this project is developed independently.Key FeaturesZero-Overhead Architecture: Ephemeral execution. Runs, generates config, and exits. 0MB resident memory.Hierarchical CLI: RouterOS/Cisco-style command structure (e.g., rxnm wifi connect) for intuitive management.WiFi Management: Full integration with iwd for scanning, connecting (Open/PSK/802.1x), WPS, and AP/Ad-Hoc host modes.IPv6 Native: Fully IPv6 compliant out of the box. Handles SLAAC, DHCPv6, and Prefix Delegation automatically.Virtual Devices: Native support for Bridges, VLANs, Bonds (Active-Backup/LACP), and WireGuard tunnels.Tethering & NAT: One-command hotspot creation (WiFi or Bluetooth PAN) with automatic NAT/Masquerading.Aliases: Short commands (e.g., rxnm wi co) for easy typing on handheld inputs.InstallationDependencies: systemd (networkd, resolved), iwd, jq, curl, iptables/nftables.Deploy:Copy bin and lib to /usr/lib/rocknix-network-manager.Symlink: ln -s /usr/lib/rocknix-network-manager/bin/rocknix-network-manager /usr/bin/rxnmUsage GuideRXNM uses a strict hierarchical structure: rxnm [category] [action] [arguments].1. General System & Status# Show status of all interfaces (Human readable by default)
rxnm system status

# JSON output for scripts/frontends
rxnm system status --json
2. WiFi Operations (rxnm wifi)# Scan for networks
rxnm wifi scan

# Connect (Aliases: 'wi co')
rxnm wifi connect --ssid "MyWiFi" --password "s3cret"

# Connect (Shortest form, auto-selects interface)
rxnm wi co MyWiFi s3cret

# Forget a network
rxnm wifi networks forget "MyWiFi"

# Start Access Point (Hotspot)
rxnm wifi ap start --ssid "MyHotspot" --password "12345678" --share
3. Interface Management (rxnm interface)# Show specific interface details
rxnm interface wlan0 show

# Set to DHCP
rxnm interface wlan0 set dhcp

# Set Static IP
rxnm interface wlan0 set static --ip 192.168.1.50/24 --gateway 192.168.1.1 --dns 1.1.1.1
4. Bluetooth Tethering (rxnm bluetooth)# Enable Bluetooth PAN (Client)
rxnm bluetooth pan enable

# Enable Bluetooth NAP (Host/Router) with NAT
rxnm bluetooth pan enable --mode host --share
5. Virtual Devices# Create a Bridge
rxnm bridge create br0
rxnm bridge add-member eth0 br0

# Create a Bond
rxnm bond create bond0
rxnm bond add-slave eth0 bond0

# WireGuard VPN
rxnm vpn wireguard connect wg0 \
    --address 10.100.0.2/24 \
    --private-key "KEY" \
    --peer-key "PUBKEY" \
    --endpoint "vpn.example.com:51820"
6. ProfilesSave and load interface states instantly.rxnm profile save Home --interface wlan0
rxnm profile load Work --interface wlan0
Directory Structure/usr/lib/rocknix-network-manager/
├── bin/
│   └── rocknix-network-manager   # Main hierarchical dispatcher
└── lib/
    ├── rxnm-wifi.sh              # WiFi logic
    ├── rxnm-interfaces.sh        # Virtual devices & IP logic
    ├── rxnm-bluetooth.sh         # Bluetooth PAN
    ├── rxnm-system.sh            # Service & Firewall
    ├── rxnm-profiles.sh          # Profile management
    └── ...
LicenseGPL-2.0-or-laterCopyright (C) 2026-present Joel Wirāmu Pauling
