# CI WiFi Hardware Simulation (mac80211_hwsim)

This document describes how the GitHub Actions CI pipeline sets up virtual WiFi radios using the Linux kernel's `mac80211_hwsim` module to test RXNM's WiFi functionality (IWD integration, AP mode, client mode, scan, connect) without physical hardware.

## Overview

The `integration-wifi` job in `.github/workflows/integration.yml` creates a fully functional virtual WiFi environment:

```
  Host (GitHub Actions runner, Ubuntu 24.04)
    ├── mac80211_hwsim (kernel module, creates 2 virtual radios)
    ├── wlan0 → injected into nspawn container "server" (AP mode)
    └── wlan1 → injected into nspawn container "client" (station mode)

  Container: rxnm-server (Fedora 42 via systemd-nspawn)
    ├── systemd-networkd (L3 addressing, DHCP server)
    ├── iwd (L2 WiFi, AP profile)
    └── rxnm (orchestrator)

  Container: rxnm-client (Fedora 42 via systemd-nspawn)
    ├── systemd-networkd (L3 addressing, DHCP client)
    ├── iwd (L2 WiFi, station mode)
    └── rxnm (orchestrator)
```

The two virtual radios can "see" each other and perform real WPA2 handshakes, DHCP exchanges, and IP-level connectivity — identical to physical hardware.

## Module Loading Strategy

The pipeline uses a 2-stage approach to load `mac80211_hwsim`:

### Stage 1: Prebuilt Modules (Fast Path)

1. Attempt `modprobe mac80211_hwsim` directly
2. If missing, install `linux-modules-extra-$(uname -r)` and `linux-modules-extra-azure`
3. Re-sweep all required modules

This works when the GitHub runner's kernel ships with `mac80211_hwsim` prebuilt (uncommon on Azure runners).

### Stage 2: Compile from Kernel.org Source (Fallback)

When prebuilt modules aren't available:

1. **Cache check**: `actions/cache@v4` keyed on `hashFiles('/proc/version')` restores previously compiled `.ko` files from `/tmp/hwsim-cache/`. On cache hit, modules are copied to `/lib/modules/$(uname -r)/updates/` and loaded — skipping compilation entirely.

2. **Cache miss**: Download matching kernel source from `cdn.kernel.org/pub/linux/kernel/`:
   - Extract the base kernel version from `uname -r` (e.g., `6.14.0-1234-azure` → `6.14`)
   - Patch `Makefile` EXTRAVERSION to match the full running kernel version exactly (vermagic alignment)
   - Copy `/boot/config-$(uname -r)` as `.config`
   - **Critically**: Copy `Module.symvers` from the linux-headers package — without this file, modpost cannot resolve kernel symbols and all compiled modules will have unresolved references

3. **Build only what's missing**: Instead of building all 17 potential module targets, the pipeline maps `$MISSING_MODULES` to specific `.ko` paths and builds only those:
   ```
   arc4         → crypto/arc4.ko
   cfg80211     → net/wireless/cfg80211.ko
   mac80211     → net/mac80211/mac80211.ko
   mac80211_hwsim → drivers/net/wireless/virtual/mac80211_hwsim.ko
   ```

4. **KBUILD_MODPOST_WARN=1**: Turns modpost symbol resolution errors into warnings. Some symbols (e.g., `__x86_return_thunk`, `__fentry__`) are provided by the running kernel at load time and don't need to resolve at build time.

5. Compiled `.ko` files are saved to `/tmp/hwsim-cache/` for the `actions/cache` to persist across runs.

### Required Modules

IWD requires a specific set of crypto modules for WPA2 handshakes. The full dependency chain:

| Module | Purpose |
|---|---|
| `cfg80211` | Wireless configuration framework |
| `mac80211` | IEEE 802.11 software MAC layer |
| `mac80211_hwsim` | Virtual radio hardware simulator |
| `rfkill` | RF kill switch subsystem |
| `arc4` | RC4 stream cipher (WPA TKIP) |
| `cmac` | AES-CMAC (802.11w/PMF) |
| `ccm` | AES-CCM (WPA2-CCMP) |
| `ecb` | Electronic Codebook mode |
| `cbc` | Cipher Block Chaining mode |
| `sha256_generic` | SHA-256 hash |
| `sha512_generic` | SHA-512 hash |
| `md4` | MD4 hash (NTLM/MSCHAPv2) |
| `des3_ede` / `des_generic` | Triple DES |
| `algif_skcipher` | AF_ALG symmetric cipher interface |
| `algif_hash` | AF_ALG hash interface |
| `af_alg` | Kernel crypto userspace API |
| `pkcs8_key_parser` | PKCS#8 key format parser |

## Module.symvers Resolution

`Module.symvers` is the single most critical file for out-of-tree compilation. It maps every exported kernel symbol to its CRC — without it, `modpost` emits `undefined!` for every symbol reference and the resulting `.ko` files cannot be loaded.

The pipeline searches these paths in order:
1. `/usr/src/linux-headers-$(uname -r)/Module.symvers`
2. `/lib/modules/$(uname -r)/build/Module.symvers`
3. `/usr/src/linux-headers-$(uname -r | sed 's/-azure//')/Module.symvers`

On Ubuntu 24.04 Azure runners, the `linux-headers-$(uname -r)` package typically provides it.

## Vermagic Alignment

The kernel rejects modules whose `vermagic` string doesn't match the running kernel exactly. The pipeline patches the source tree's `Makefile`:

```
FULL_VER=$(uname -r)                    # e.g., 6.14.0-1234-azure
KVER=$(uname -r | cut -d- -f1)          # e.g., 6.14.0
EXTRA_VER=${FULL_VER#$KVER}             # e.g., -1234-azure
sed -i "s/^EXTRAVERSION.*/EXTRAVERSION = $EXTRA_VER/" Makefile
```

This ensures compiled modules report the same vermagic as the running kernel (e.g., `6.14.0-1234-azure SMP preempt mod_unload`).

## PHY Injection into Containers

After `mac80211_hwsim radios=2` creates two virtual interfaces on the host:

1. The test harness discovers them via `iw dev`
2. Extracts the underlying PHY ID: `iw dev wlan0 info | awk '/wiphy/{print "phy"$2}'`
3. Gets the container's PID: `machinectl show rxnm-server -p Leader`
4. Injects the PHY into the container's network namespace: `iw phy phy0 set netns <pid>`
5. The PHY disappears from the host and appears inside the container

Inside the container, IWD automatically detects the new wireless device and registers it on D-Bus.

## Ghost P2P Interface Cleanup

The `mac80211` subsystem automatically spawns hidden `type P2P-device` virtual interfaces alongside each radio. These consume the radio's limited concurrency slots. Before starting AP mode, the `sanitize_wifi.sh` script (injected into the container rootfs) deletes them:

```bash
for wdev in $(iw dev | awk '/Interface/ {iface=$2} /type P2P-device/ {print iface}'); do
    iw dev "$wdev" del 2>/dev/null || true
done
```

This is a workaround for a kernel `mac80211` behavior documented in `UPSTREAM.md` issue #6.

## Container Architecture

Each test suite boots two `systemd-nspawn` containers from a Fedora 42 rootfs:

```
systemd-nspawn -D /var/lib/machines/fedora-rxnm -M rxnm-server \
    --network-bridge=rxnm-br \
    --boot \
    --capability=all \
    --private-users=no \
    --system-call-filter="bpf keyctl add_key" \
    --rlimit=RLIMIT_MEMLOCK=infinity \
    --ephemeral
```

Key flags:
- `--network-bridge`: Connects the container's `host0` interface to a virtual bridge
- `--capability=all`: Required for XDP/BPF attachment, namespace ops
- `--system-call-filter=bpf`: Allows BPF syscalls (needed for XDP nullify tests)
- `--rlimit=RLIMIT_MEMLOCK=infinity`: Required for BPF map allocation
- `--ephemeral`: COW overlay — container changes don't persist to rootfs

The rootfs is built from `tests/integration/Containerfile` (Fedora 42 with systemd-networkd, iwd, and tools) using Docker/Podman, exported as a tarball, and extracted to `/var/lib/machines/`.

## Container Cleanup Between Suites

Three test suites run sequentially (standard, ROCKNIX bundle, full combined bundle). Each suite creates its own pair of containers. A cleanup step between suites ensures the previous containers are fully terminated before the next suite boots:

```yaml
- name: Cleanup between test suites
  if: always()
  run: |
    for m in $(sudo machinectl list --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
        sudo machinectl terminate "$m" 2>/dev/null || true
    done
    sleep 3
    sudo rm -rf /var/lib/machines/fedora-rxnm-bundle 2>/dev/null || true
```

Without this, stale containers from the previous suite cause `systemd-machined` namespace conflicts.

## D-Bus in Containers

`rxnm-agent` communicates with `systemd-networkd` via the D-Bus system bus socket. Inside `systemd-nspawn` containers, `dbus-broker` enforces stricter connection policies than on bare metal. The agent's lightweight DBus wire protocol implementation gets rejected.

Workaround: All container commands are run with `RXNM_FORCE_NETWORKCTL=true`, which forces the shell fallback path (`networkctl reload`) instead of the agent's native DBus reload.

This is documented in `UPSTREAM.md` issue #2.

## WiFi Test Phases (Phase 6)

When hwsim is available, the integration tests execute:

1. Restart IWD in both containers
2. Wait for IWD to register on D-Bus and discover the wireless device (45 retries)
3. Server starts AP: `rxnm wifi ap start "RXNM_Test_Net" --password "supersecret" --share`
4. Wait for server AP interface to reach `routable` state (DHCP server running)
5. Client scans: `rxnm wifi scan` — verify `RXNM_Test_Net` appears
6. Client connects: `rxnm wifi connect "RXNM_Test_Net" --password "supersecret"`
7. Wait for client to get DHCP lease and reach L3 connectivity
8. Verify ping to gateway
9. Server switches back to client mode — verify AP state cleaned up

## Local Reproduction

To run the WiFi integration tests locally:

```bash
# Load hwsim (requires root)
sudo modprobe mac80211_hwsim radios=2

# Build agent
make tiny

# Run WiFi-only tests
sudo ./tests/integration/run_interop.sh --wifi-only

# Or skip WiFi and run wired only
sudo ./tests/integration/run_interop.sh --skip-wifi
```

Prerequisites: `systemd-container` (provides `systemd-nspawn`, `machinectl`), `bridge-utils`, `docker` or `podman`, `iw`, `jq`.
