# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: rxnm-help.sh
# PURPOSE: Help Text Definitions & Output
# ARCHITECTURE: Foundation / Help
#
# Contains all help text and usage examples. Separated from the main binary
# to prevent Heredoc parsing issues and keep the dispatcher clean.
# -----------------------------------------------------------------------------

rxnm_help_show_main() {
    cat <<'EOF'
Usage: rxnm <category> [target] <action> [options]
       echo '{"category":"wifi", "action":"connect", "ssid":"MyNet"}' | rxnm --stdin

Categories:
  wifi          Manage Wireless connections
  interface     Configure interfaces (IP, DHCP, State)
  route         Manage Routing Table (Static routes, Gateways)
  system        Status, diagnostics, global settings
  profile       Manage configuration profiles
  bluetooth     Bluetooth Tethering (PAN/NAP)
  vpn           WireGuard and Tunnels
  bridge        Manage Network Bridges
  bond          Manage Interface Bonding
  vlan          Manage VLANs
  vrf           Manage Virtual Routing Functions
  api           Schema and Versioning
  
  Service Architecture (Experimental):
  service       Namespace Isolation
  tunnel        Overlay Networks (VXLAN, Geneve)

Global Options:
  --format <fmt>  Output format: human (default), json, table, simple
  --simple        Shortcut for '--format simple' (Bash friendly)
  --get <key>     Extract specific value (implies --simple)
  --yes, -y       Skip confirmation prompts
  --force         Force action (same as --yes)
  --stdin         Read configuration from JSON on stdin
  --help, -h      Show help
  --version       Show version

Examples:
  rxnm wifi connect "MyNetwork"
  rxnm interface wlan0 set dhcp
  rxnm route add default --gateway 192.168.1.1
  rxnm system status --format table

Use 'rxnm <category> --help' for specific commands.
EOF
}

rxnm_help_show_category() {
    local category="$1"
    case "$category" in
        wifi)
            cat <<'EOF'
Usage: rxnm wifi <action> [options]

Actions:
  scan [iface]          Scan for networks
  connect <ssid>        Connect to a network
  disconnect [iface]    Disconnect from current AP
  list                  List known networks (saved profiles)
  forget <ssid>         Forget a known network
  ap start <ssid>       Start Access Point (Hotspot)
  country <code>        Set WiFi Country Code
  
  p2p scan              Scan for WiFi Direct peers
  p2p connect <name>    Connect to P2P peer
  p2p disconnect        Disconnect P2P
  p2p status            Show P2P status (Peers/GO Mode)
  
  dpp enroll <uri>      Start DPP enrollment (QR code string)
  dpp stop              Stop DPP session
  
  roaming monitor       Start opportunistic roaming monitor (Foreground)
  roaming enable        Enable roaming background service
  roaming disable       Disable roaming background service

Options:
  --password <pass>     WiFi Password
  --password-stdin      Read password from stdin (Secure)
  --hidden              Connect to hidden SSID
  --interface <iface>   Target interface (Auto-detected if omitted)
  --ip <cidr>           Custom IP for AP mode
  --share               Enable NAT/Masquerading for AP
  --ipv6-pd <yes|no>    Enable/Disable IPv6 Prefix Delegation (Default: yes)

Examples:
  # Connect to a secure network
  rxnm wifi connect "HomeWiFi" --password "s3cr3t"

  # Connect to a hidden network
  rxnm wifi connect "HiddenLab" --password "xyz" --hidden

  # Start a Personal Hotspot (Access Point)
  rxnm wifi ap start "MyHotspot" --password "12345678" --share

  # WiFi Direct (P2P) Connection
  rxnm wifi p2p scan
  rxnm wifi p2p connect "Android_1234"
EOF
            ;;
        interface)
            cat <<'EOF'
Usage: rxnm interface [name] <action> [options]

Actions:
  show                  Show interface details
  nullify <cmd>         Suspend/Resume hardware traffic (enable, disable, status)
  hotplug               Trigger hotplug event (Standard/Rescue)
  set dhcp              Enable DHCP
  set static <ip>       Set Static IP (CIDR format)
  set hardware          Set physical link properties (speed, duplex)
  enable / disable      Set link state
  list                  List all interfaces

Options:
  --gateway <ip>        Set Gateway
  --dns <ip>            Set DNS servers (comma separated)
  --routes <list>       Set static routes (dest@gw@metric, comma separated)
  --metric <int>        Route metric priority
  --mtu <int>           Set MTU (68-65535)
  --mac <addr>          Set MAC Address (XX:XX:XX:XX:XX:XX)
  --ipv6-privacy <opt>  Set IPv6 Privacy (yes|no|prefer-public|kernel)
  --dhcp-id <opt>       Set DHCP Client ID (mac|duid)
  --ipv6-pd <yes|no>    Enable/Disable IPv6 Prefix Delegation (Default: yes)
  --get <key>           Get single value (e.g. 'ip', 'mac', 'state')
  
  --speed <mbps>        Link speed (e.g. 100, 1000)
  --duplex <mode>       Duplex mode (half, full)
  --autoneg <yes|no>    Enable/Disable auto-negotiation
  --wol <magic|off>     Wake-on-LAN
  --mac-policy <opt>    MAC Policy (persistent, random, none)
  --name-policy <opt>   Name Policy (kernel, database, onboard, keep)

Examples:
  # Set Static IP
  rxnm interface eth0 set static 192.168.1.50/24 --gateway 192.168.1.1 --dns 8.8.8.8

  # Power Management: Suspend hardware traffic on specific interface
  rxnm interface wlan0 nullify enable --yes

  # Get just the IP address (useful for scripts)
  rxnm interface eth0 show --get ip

  # Change MAC address
        route)
            cat <<'EOF'
Usage: rxnm route <action> [destination] [options]

Actions:
  list                  List routing table
  add <dest>            Add new route
  del <dest>            Delete route
  get <dest>            Simulate routing decision (get route to host)
  flush cache           Flush routing cache

Options:
  --destination <cidr>  Destination network (e.g. 10.0.0.0/24)
  --gateway <ip>        Next hop gateway
  --interface <iface>   Output interface
  --metric <int>        Route priority
  --table <id>          Routing table ID (default: main)
  --scope <scope>       Scope (global, link, host)
  --proto <proto>       Protocol (static, boot, etc)

Examples:
  # Add default gateway
  rxnm route add default --gateway 192.168.1.1 --interface eth0

  # Add static route to subnet
  rxnm route add 10.10.0.0/16 --gateway 10.0.0.2

  # Check which interface handles a specific IP
  rxnm route get 8.8.8.8
EOF
            ;;
        profile)
            cat <<'EOF'
Usage: rxnm profile <action> [name] [options]

RXNM uses a RAM-first architecture. Changes are ephemeral unless saved to a profile.
The 'default' profile is automatically loaded to RAM at boot.

Actions:
  list                  List saved persistent profiles
  save [name]           Save active state to profile (defaults to 'default')
  load [name]           Load profile into RAM (defaults to 'default')
  delete <name>         Delete a persistent profile
  export <name>         Export profile to tarball
  import <file>         Import profile from tarball

Options:
  --interface <iface>   Scope profile to a specific interface
  --file <path>         File path for import/export

Examples:
  # Save current active configuration as 'work'
  rxnm profile save work

  # Load 'home' profile
  rxnm profile load home

  # List all available profiles
  rxnm profile list

  # Export 'work' profile to a file
  rxnm profile export work --file /tmp/work-profile.tar
EOF
            ;;
        bridge|bond|vlan|vrf|macvlan|ipvlan|veth)
            cat <<'EOF'
Usage: rxnm <category> <action> <name> [options]

Categories: bridge, bond, vlan, vrf, macvlan, ipvlan, veth

Actions:
  create <name>         Create new virtual device
  delete <name>         Delete device
  add-member <iface>    Add interface to category (Bridge/VRF only)
  add-slave <iface>     Add interface to category (Bond only)
  list                  List devices (via rxnm interface list)

Options:
  --parent <iface>      Parent interface (VLAN/MacVLAN/IPVLAN)
  --id <vlan-id>        VLAN ID (1-4094)
  --mode <mode>         Mode for Bond (active-backup, etc) or MacVLAN
  --table <id>          Routing table ID for VRF
  --peer <name>         Peer interface name (veth only)

Examples:
  # Create a Bridge and add ports
  rxnm bridge create br0
  rxnm bridge add-member eth0 --bridge br0
  rxnm bridge add-member eth1 --bridge br0

  # Create a VLAN on eth0
  rxnm vlan create vlan10 --parent eth0 --id 10

  # Create a Bond interface
  rxnm bond create bond0 --mode active-backup
  rxnm bond add-slave eth0 --bond bond0
EOF
            ;;
        vpn)
            cat <<'EOF'
Usage: rxnm vpn wireguard <action> <name> [options]

Actions:
  connect <name>        Create/Connect WireGuard interface
  disconnect <name>     Remove WireGuard interface
  delete <name>         Alias for disconnect

Options:
  --private-key <key>   WireGuard Private Key
  --peer-key <key>      Peer Public Key
  --endpoint <addr:port> Remote Endpoint
  --allowed-ips <cidr>  Allowed IPs (e.g. 0.0.0.0/0)
  --address <cidr>      Interface Address

Examples:
  # Connect to WireGuard VPN
  rxnm vpn wireguard connect wg0 \
    --private-key "YOUR_PRIVATE_KEY" \
    --peer-key "PEER_PUBLIC_KEY" \
    --endpoint "vpn.example.com:51820" \
    --address "10.100.0.2/24" \
    --allowed-ips "10.100.0.0/24"

  # Disconnect
  rxnm vpn wireguard disconnect wg0
EOF
            ;;
        tun|tap)
            cat <<'EOF'
Usage: rxnm <tun|tap> create <name> [options]
       rxnm <tun|tap> delete <name>

Options:
  --user <user>         Owner of the interface
  --group <group>       Group owner

Examples:
  # Create a persistent TUN device for a user
  rxnm tun create tun0 --user rocknix
EOF
            ;;
        system|config)
            cat <<'EOF'
Usage: rxnm system <action> [options]

Actions:
  status                Show network status
  check internet        Check internet connectivity
  check portal          Check for captive portal
  reload                Reload network configuration
  proxy set             Configure global/interface proxy
  nullify enable        Suspend hardware network traffic via XDP (requires --yes)
  nullify disable       Resume hardware network traffic
  nullify status        Show current nullify XDP status

Options:
  --http <url>          Set HTTP proxy
  --https <url>         Set HTTPS proxy
  --noproxy <list>      Set no_proxy exclusions
  --interface <iface>   Target a specific interface (e.g., for proxy or nullify)
  --dry-run             Show actions without executing (nullify only)

Examples:
  # Check Internet Connectivity
  rxnm system check internet

  # Set System Proxy
  rxnm system proxy set --http "http://proxy.example.com:8080" --noproxy "localhost,127.0.0.1"

  # Remove Proxy
  rxnm system proxy set

  # Power Management: Suspend all network traffic globally via XDP
  rxnm system nullify enable --yes

  # Power Management: Suspend traffic on a specific interface only
  rxnm system nullify enable --interface wlan0
EOF
            ;;
        api)
            cat <<'EOF'
Usage: rxnm api <action>
Actions: schema, version, capabilities

Examples:
  # Get API Version
  rxnm api version

  # Check feature status (Stable/Experimental)
  rxnm api capabilities
EOF
            ;;
        bluetooth)
            cat <<'EOF'
Usage: rxnm bluetooth <action> [options]

Actions:
  scan                  Scan for devices
  pair <mac>            Pair with a device
  unpair <mac>          Unpair/Remove device
  pan enable            Enable Bluetooth Tethering (PAN)
  pan disable           Disable Bluetooth Tethering

Options:
  --mode <client|host>  PAN Mode (default: client)
  --share               Enable Internet Sharing (Host mode)

Examples:
  # Scan for devices
  rxnm bluetooth scan

  # Pair with a phone
  rxnm bluetooth pair AA:BB:CC:DD:EE:FF

  # Enable Tethering Client (Connect to phone hotspot)
  rxnm bluetooth pan enable --mode client
EOF
            ;;
        service)
            cat <<'EOF'
Usage: rxnm service <action> [name] [options] (Experimental)

Actions:
  create <name>         Create new namespace service
  delete <name>         Delete service
  list                  List services
  attach <service>      Move interface to service
  detach <service>      Return interface to root
  exec <service> <cmd>  Execute command in service context

Options:
  --interface <iface>   Target interface for attach/detach

Note:
  This feature requires RXNM_EXPERIMENTAL=true in environment.
  Services use 'ip netns' isolation.
EOF
            ;;
        *)
            # Fallback to main help if category is unknown or generic
            rxnm_help_show_main
            ;;
    esac
}
