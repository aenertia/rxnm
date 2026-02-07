RXNM (ROCKNIX Network Manager)RXNM is a lightweight, modular CLI wrapper for systemd-networkd and iwd, optimized for low-power ARM devices (specifically RK3326/RK3566 handhelds) but compatible with general Linux environments.Key FeaturesZero-Overhead Architecture: Ephemeral execution. Runs, generates config, and exits. 0MB resident memory.Target-First Syntax: Intuitive rxnm interface wlan0 show structure.EmulationStation Ready: JSON output mode (--format json) for UI integration.Virtual Devices: Native support for Bridges, VLANs, Bonds, WireGuard, and Bluetooth PAN.Profiles: Save and load complete network states (Home, Work, RetroNet).Usage Guide1. General System & Status# Human readable status table
rxnm system status

# JSON output for frontends
rxnm system status --format json

# Check internet connectivity
rxnm system check internet
2. WiFi Operations (rxnm wifi)# Scan for networks
rxnm wifi scan

# List known/saved networks
rxnm wifi list

# Connect to a network
rxnm wifi connect "MyWiFi" --password "s3cret"

# Start Hotspot (AP Mode)
rxnm wifi ap start "MyHotspot" --password "12345678" --share

# Forget a network
rxnm wifi forget "OldNetwork"
3. Interface Management (rxnm interface)# Show specific interface
rxnm interface wlan0 show

# Set DHCP
rxnm interface wlan0 set dhcp

# Set Static IP
rxnm interface wlan0 set static 192.168.1.50/24 --gateway 192.168.1.1 --dns 1.1.1.1
4. Bluetooth (rxnm bluetooth)# Scan for devices
rxnm bluetooth scan

# Pair with a controller/phone
rxnm bluetooth pair AA:BB:CC:DD:EE:FF

# Enable Bluetooth Tethering (Client)
rxnm bluetooth pan enable
5. Virtual Devices & VPN# Create a Bridge
rxnm bridge create br0
rxnm bridge add-member eth0 --bridge br0

# Create a VLAN
rxnm vlan create vlan10 --parent eth0 --id 10

# WireGuard VPN
rxnm vpn wireguard connect wg0 \
    --address 10.100.0.2/24 \
    --private-key "KEY" \
    --peer-key "PUBKEY" \
    --endpoint "vpn.example.com:51820"

# Disconnect/Delete VPN
rxnm vpn wireguard disconnect wg0
6. Profiles# Save current state as 'Home'
rxnm profile save Home

# Load 'Home' profile
rxnm profile load Home

# Export profile to file
rxnm profile export Home --file /storage/backups/home.tar.gz
InstallationCopy bin and lib to /usr/lib/rocknix-network-manager and symlink the binary.ln -s /usr/lib/rocknix-network-manager/bin/rocknix-network-manager /usr/bin/rxnm
LicenseGPL-2.0-or-laterCopyright (C) 2026-present Joel Wirāmu Pauling
