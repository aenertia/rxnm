# RXNM Build & Integration Guide

This document outlines the build process, deployment profiles, and test infrastructure for **RXNM v1.1.x**.

RXNM employs a **Hybrid Architecture** consisting of a highly-optimized native C agent (`rxnm-agent`) and a modular, POSIX-compatible shell dispatcher. The build system is designed to produce artifacts that range from standard desktop Linux packages to extremely minimal, statically linked flat-files suitable for initramfs and deeply embedded gaming OSes (like ROCKNIX).

## 🛠️ Prerequisites

To build and fully test RXNM from source, you need a standard Linux development environment.

### Build Dependencies

* **GNU Make**

* **C Compiler**: `gcc` (Standard) or `musl-gcc` (Highly Recommended for 'Tiny' static builds).

* **Coreutils**: `bash`, `jq`, `sed`, `awk`.

### Test Suite Dependencies (Optional but recommended)

* **Static Analysis**: `shellcheck`

* **Memory Profiling**: `valgrind`

* **Integration Harness**: `systemd-container` (provides `machinectl`/`systemd-nspawn`), `bridge-utils`, `dbus-user-session`.

### Runtime Dependencies

RXNM's dependencies vary drastically based on which execution path your target environment utilizes.

* **Network Stack (Both Paths)**: `systemd` (specifically `systemd-networkd`, `systemd-resolved`) and `iwd` (for WiFi).

* **The Bash Path (Path A)**: Requires `bash 4.4+`, `jq`, `iproute2`, and `systemd` CLI tools (`networkctl`, `busctl`).

* **The POSIX Path (Path B)**: Requires a basic `/bin/sh` (`ash`/`dash`). **Zero external CLI dependencies** (does not need `jq`, `ip`, or `busctl`), but *strictly requires* the `rxnm-agent` C binary.

#### Minimum Viable Dependency Matrix

Several critical paths have specific fallbacks when preferred tools are absent.

| Dependency | Required For | Fallback | 
 | ----- | ----- | ----- | 
| `jq` | Status output, `--stdin` mode, WiFi scan | Basic text output only; `--stdin` unavailable | 
| `busctl` | IWD DBus queries | `iwctl` fallback for most operations | 
| `iw` | PHY management, WoWLAN | No fallback | 
| `networkctl` | All networkd operations | None — hard dependency | 
| `rxnm-agent` | XDP/BPF, DBus reload hot path, namespaces | Shell fallback via `networkctl reload` | 

## 🚀 Build Profiles

RXNM provides three primary compilation targets depending on your deployment constraints.

### 1. The Standard Build (Dynamic Linking)

Best for desktop development, debugging, or standard glibc-based distributions (Fedora, Debian, Arch).

```
make
sudo make install

```

* **Result:** Dynamically linked `rxnm-agent` and modular shell libraries in `/usr/lib/rocknix-network-manager/lib/`.

* **Footprint:** \~25KB (code) + shared `libc` overhead.

### 2. The 'Tiny' Build (Static Linking)

Best for standard embedded devices, initramfs, or Alpine/Buildroot environments. This profile aggressively optimizes for size and portability, prioritizing `musl-gcc`.

```
make tiny
sudo make install

```

* **Result:** Statically linked `rxnm-agent`.

* **Optimization:** LTO enabled, symbols stripped, unused sections garbage collected (`-Os -ffunction-sections -fdata-sections -Wl,--gc-sections`).

* **Footprint:** \~50KB (with musl) or \~700KB (with glibc static).

### 3. The Minimal Bundle (ROCKNIX Release)

**Target:** Highly constrained retro-gaming handhelds (Rockchip, Allwinner) demanding absolute minimum boot overhead and complexity.

This target triggers `scripts/bundle.sh` to forcefully strip out enterprise networking features (MPLS, Virtual Routing Functions, Namespaces) and amalgamate the remaining "Retro Core" (WiFi, Bluetooth PAN, USB Gadget, VPNs) into a single, flat executable script.

```
make rocknix-release

```

* **Result:** Outputs exactly two files to the `build/` directory:

  1. `build/rxnm`: A single \~2,500-line POSIX-compliant shell script (No `source` includes, reducing boot-time IO/`stat` overhead).

  2. `build/rxnm-agent`: The tiny static C-agent.

* **Validation:** Automatically runs a dedicated bundle fuzzer to ensure the script amalgamation did not introduce syntax errors.

## 🔀 Architecture: Dual Execution Paths (Bash vs. POSIX)

RXNM is uniquely designed to adapt its execution strategy based on the host shell environment. It dynamically selects between two distinct architectural paths at runtime.

### The Intelligent Shell Upgrade

When RXNM executes, the very first operation it performs is a **Shell Capability Check**. If it detects it was invoked by a basic `/bin/sh` environment (like Dash or Ash) but observes that `bash` is installed on the underlying host, it will seamlessly `exec bash` to re-execute itself. This guarantees that systems automatically receive the "Full Fat" performance optimizations regardless of how the script was initially invoked.

### Path A: The Bash Path (Robust Fallback)

When executing under `/bin/bash`, RXNM enters its most resilient and performant mode.

* **Performance:** It enables associative array caching (`declare -A` for sysfs data) and native bash regular expressions (`[[ =~ ]]`), significantly cutting down on fork/exec IO penalties in tight loops.

* **Resilience:** It will attempt to use the native `rxnm-agent` for maximum speed. However, if the agent crashes, is deleted, or fails to execute (e.g., OS architecture mismatch), the script gracefully degrades to a pure shell implementation.

* **Dependencies:** To achieve this fallback, the Bash path relies heavily on external system utilities (`jq` for JSON manipulation, `ip` for Netlink queries, `busctl` for DBus messaging, and `networkctl`).

* **Advantage:** Unbreakable reliability. The network stack can still be managed even if the C binary is completely compromised.

### Path B: The Strict POSIX Path (Agent-Forced)

When executing in an environment that truly lacks `bash` (like `ash` on BusyBox or within a minimalistic initramfs recovery shell), RXNM anchors itself to strict POSIX compliance.

* **Behavior:** Because standard POSIX shell lacks arrays and safe regex capabilities, this path **strictly relies on the `rxnm-agent`** C binary to perform the heavy lifting (Netlink data aggregation, complex JSON generation, DBus API interactions).

* **Dependencies:** It requires **zero** external CLI tools. It does not need `jq`, `awk`, `iproute2`, or DBus utilities to return network status or make routine interface changes.

* **Universal Intent Validation:** The configuration schema (`rxnm-config-schema.sh`) has been written entirely in POSIX shell using strict `case` logic and safe Here-Doc looping. This guarantees that invalid configuration intents (like trying to assign an active bridge member a DHCP address) are caught and rejected cleanly *before* hitting the execution layer, even in the most restricted shell environments.

* **Trade-off:** If the `rxnm-agent` binary dies or is missing in a pure POSIX environment, advanced JSON state aggregation will fail, degrading to an extremely basic string-based fallback.

## 🧩 Architecture: Single Source of Truth (SSoT)

RXNM enforces strict consistency between the Shell logic, JSON APIs, and the C Agent using an automated synchronization pipeline triggered on every build.

1. **Source:** `lib/rxnm-constants.sh` contains configuration defaults (timeouts, lock FDs).

2. **Schema:** `api-schema.json` defines the API contract.

3. **Generator:** `scripts/sync-constants.sh` runs automatically during `make`.

4. **Output:** `src/rxnm_generated.h` is generated. This guarantees the C Agent shares the exact same operational parameters as the shell scripts without requiring runtime IPC synchronization.

*Note: Do not manually edit `src/rxnm_generated.h`. Edit the constants shell script or schema instead.*

## 🧪 Testing & Verification Infrastructure

RXNM features a comprehensive, multi-stage test suite covering everything from static linting to isolated systemd container convergence.

### Quick Sanity Check

Runs basic linting, binary footprint validation, and Phase 2 Netlink checks.

```
make check

```

### Full Regression Suite

Executes the entire local validation matrix (Fuzzing, Consistency, Profiling).

```
make test-all

```

#### Test Matrix Breakdown:

* **Static Analysis (`test_shellcheck.sh`):** Strict POSIX/Bash linting across all scripts.

* **Foundation (`test_foundation.sh`):** Validates static linkage, binary size limits (<100KB), and timestamp synchrony.

* **Consistency (`test_consistency.sh`):** Strict JSON diffing. Compares the hardware data (IPs, Routes, MACs) extracted by the C-Agent against data parsed by the legacy Shell fallback.

* **Performance (`test_performance.sh`):** Nanosecond latency benchmarking. Ensures the Agent responds in `< 5ms` on average, failing the build if a performance regression occurs.

* **Stability (`test_stability.sh`):** Executes memory leak detection via `valgrind` across the C-Agent's dynamic realloc buffers.

* **Fuzzing (`test_cli_fuzz.sh` & `test_bundle_fuzz.sh`):** Injects malformed arguments into the CLI dispatcher within an isolated, mocked environment to ensure graceful degradation (no unhandled shell panics).

### Interoperability Tests (Systemd-Nspawn)

The deepest level of testing spins up isolated OS containers (`systemd-nspawn`) connected via virtual bridges to simulate real-world hotplugging, DHCP convergence, and XDP behavior.

```
# Test the modular architecture
sudo ./tests/integration/run_interop.sh

# Test the flat-file ROCKNIX minimal bundle architecture
sudo ./tests/integration/run_rocknix_interop.sh

```

## 📂 Installation Paths

`make install` deploys files to standard system paths compliant with FHS and systemd conventions.

> **Security Note:** `rxnm-agent` uses `setns(fd, CLONE_NEWNET)` for namespace and service operations, which requires `CAP_SYS_ADMIN`. It must be run as root or granted the capability (e.g. via `setcap cap_sys_admin+ep`). In `systemd-nspawn` environments, passing `--capability=all` covers this. In production systemd units, consider adding `AmbientCapabilities=CAP_SYS_ADMIN`.

**Note on the Main Entry Point:** To protect the relative path hierarchy required by the modular library system (and to keep `/usr/bin/` clean), the actual executable script is installed to `/usr/lib/rocknix-network-manager/bin/rxnm`. A symbolic link is then placed at `/usr/bin/rxnm` to expose the command globally. The dispatcher script inherently uses `readlink` to resolve its true location before attempting to source dependencies from `../lib/`.

| Component | Path | Description | 
 | ----- | ----- | ----- | 
| **Dispatcher** | `/usr/bin/rxnm` | Symlink to the main CLI entry point. | 
| **Actual Executable** | `/usr/lib/rocknix-network-manager/bin/rxnm` | The physical script file. | 
| **Agent** | `/usr/lib/rocknix-network-manager/bin/rxnm-agent` | Native C accelerator. | 
| **Libraries** | `/usr/lib/rocknix-network-manager/lib/*.sh` | Core logic modules (Standard build only). | 
| **Templates** | `/usr/lib/systemd/network/` | Configuration defaults (e.g., USB Gadget, WiFi). | 
| **Hooks** | `/usr/lib/systemd/system-sleep/rxnm-resume` | WiFi state restoration logic for suspend. | 
| **Completion** | `/usr/share/bash-completion/completions/rxnm` | Tab completion logic. | 
| **Service** | `/etc/systemd/system/rxnm.service` | Main boot-time orchestrator service. | 

To override the installation prefix (default `/usr`):

```
make install PREFIX=/usr/local

```

## ⚔️ Cross-Compilation

RXNM's zero-dependency design makes it trivial to cross-compile for target embedded architectures (ARM64, RISC-V).

### Cross-Compiling for ARM64 (Aarch64)

```
export CC=aarch64-linux-gnu-gcc
make tiny

```

### Cross-Compiling for RISC-V

```
export CC=riscv64-linux-gnu-gcc
make tiny

```

## 🧹 Cleaning Up

To remove build artifacts, object files, generated headers, and temporary build directories:

```
make clean

```
