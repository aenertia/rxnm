#!/bin/bash
set -e

# ==============================================================================
# RXNM LIVE INTEROPERABILITY TEST SUITE
# ==============================================================================
# Orchestrates two systemd containers connected via a private bridge.
# Node A (Server): Creates a bridge (br-usb) and serves DHCP.
# Node B (Client): Connects via eth0 and requests DHCP.
#
# ARCHITECTURE MIMICRY:
# - /run, /tmp: tmpfs (RAM) - Wiped on boot/restart (Standard Systemd Req)
# - /storage:   Volume (Disk) - Persists across reboots (Rocknix specific)
# ==============================================================================

# Cleanup function to ensure no zombie containers/volumes are left
cleanup() {
    echo "--- Teardown ---"
    podman rm -f rxnm-server rxnm-client 2>/dev/null || true
    podman volume rm -f rxnm-server-storage rxnm-client-storage 2>/dev/null || true
    podman network rm rxnm-net 2>/dev/null || true
}
trap cleanup EXIT

echo "--- Booting Test Environment ---"

# Create persistent storage volumes (Simulating SD Card/Internal Flash)
podman volume create rxnm-server-storage
podman volume create rxnm-client-storage

# Start Server Node
# --privileged: Required for network stack manipulation, namespaces, and cgroups
# --mount type=tmpfs: Ensures /run is volatile (Mandatory for systemd)
# -v ...:/storage: Simulates the persistent partition
podman run -d --privileged --name rxnm-server \
    --network rxnm-net \
    --hostname server \
    --mount type=tmpfs,destination=/run \
    --mount type=tmpfs,destination=/tmp \
    -v rxnm-server-storage:/storage \
    -v $(pwd):/usr/src/rxnm \
    rxnm-test-node

# Start Client Node
podman run -d --privileged --name rxnm-client \
    --network rxnm-net \
    --hostname client \
    --mount type=tmpfs,destination=/run \
    --mount type=tmpfs,destination=/tmp \
    -v rxnm-client-storage:/storage \
    -v $(pwd):/usr/src/rxnm \
    rxnm-test-node

echo "Waiting for systemd initialization (5s)..."
sleep 5

# Validate services are actually running and masked ones are dead
echo "[Health] Checking for interference..."
if podman exec rxnm-server systemctl is-active --quiet NetworkManager; then
    echo "FAIL: NetworkManager is active! Masking failed."
    exit 1
fi
echo "PASS: NetworkManager is dead. networkd is free to operate."

echo "--- Deploying RXNM Stack ---"
# Compile and install RXNM from the mounted source inside both containers
podman exec rxnm-server bash -c "cd /usr/src/rxnm && make install"
podman exec rxnm-client bash -c "cd /usr/src/rxnm && make install"

echo "--- Scenario: USB Gadget Bridge (Server) <-> DHCP Client (Client) ---"

# ==============================================================================
# SERVER CONFIGURATION (The "Device")
# We simulate the device acting as a USB Host/Gadget Router
# ==============================================================================
echo "[Server] Configuring Bridge with DHCP Server..."

# 1. Create the bridge 'br-usb'. 
# Note: Creating 'br-usb' triggers the default system template 
# '70-br-usb-host.network' (installed by rxnm) which enables DHCPServer=yes.
podman exec rxnm-server rxnm bridge create br-usb

# 2. Add eth0 (link to client) to the bridge
# This generates a config that enslaves eth0 to br-usb, effectively making
# eth0 the "cable" connecting the client to our DHCP server.
podman exec rxnm-server rxnm bridge add-member eth0 --bridge br-usb

# ==============================================================================
# CLIENT CONFIGURATION (The "PC" or "Peer")
# We simulate a standard client connecting to the device
# ==============================================================================
echo "[Client] Configuring eth0 as DHCP Client..."
# This generates a standard DHCP client config for eth0
podman exec rxnm-client rxnm interface eth0 set dhcp

echo "Waiting for DHCP negotiation and Link Training (10s)..."
sleep 10

# ==============================================================================
# VERIFICATION
# ==============================================================================
echo "--- Verifying State ---"

# 1. Check Server State
echo "[Server] Interface Status (br-usb):"
podman exec rxnm-server rxnm interface br-usb show --simple
# Expecting: 169.254.10.2 (defined in 70-br-usb-host.network)

# 2. Check Client State
echo "[Client] Interface Status (eth0):"
podman exec rxnm-client rxnm interface eth0 show --simple

# Extract IPs for validation
SERVER_IP=$(podman exec rxnm-server ip -j addr show br-usb | jq -r '.[0].addr_info[0].local')
CLIENT_IP=$(podman exec rxnm-client ip -j addr show eth0 | jq -r '.[0].addr_info[0].local')

echo "Server IP: $SERVER_IP"
echo "Client IP: $CLIENT_IP"

# Validate Client IP Range (Should be 169.254.10.x based on RXNM template)
if [[ "$CLIENT_IP" != "169.254.10."* ]]; then
    echo "FAIL: Client IP ($CLIENT_IP) is not in the expected range (169.254.10.x)."
    echo "This implies the default template was not applied or DHCP failed."
    echo "--- Server Logs (networkd) ---"
    podman exec rxnm-server journalctl -u systemd-networkd --no-pager | tail -n 20
    exit 1
fi

# 3. Connectivity Test (Bidirectional Traffic)
echo "[Test] Pinging Server ($SERVER_IP) from Client..."
if podman exec rxnm-client ping -c 3 "$SERVER_IP"; then
    echo "PASS: Client -> Server traffic OK."
else
    echo "FAIL: Client cannot reach Server."
    exit 1
fi

echo "[Test] Pinging Client ($CLIENT_IP) from Server..."
if podman exec rxnm-server ping -c 3 "$CLIENT_IP"; then
    echo "PASS: Server -> Client traffic OK."
else
    echo "FAIL: Server cannot reach Client."
    exit 1
fi

echo "--- Scenario Complete: SUCCESS ---"
