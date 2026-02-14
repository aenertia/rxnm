# RXNM Build Guide

This document outlines the build process for **RXNM 1.0.0-rc2**.

RXNM employs a **Hybrid Architecture** consisting of a high-performance native C agent (`rxnm-agent`) and a modular Bash logic dispatcher. The build system is designed to produce extremely small, statically linked binaries suitable for initramfs, recovery images, and embedded filesystems.

---

## 🛠️ Prerequisites

To build RXNM from source, you need a standard Linux development environment.

### Build Dependencies
* **GNU Make**
* **C Compiler**: `gcc` (Standard) or `musl-gcc` (Highly Recommended for 'Tiny' builds).
* **Bash**: Required for the build scripts.
* **jq**: Required for schema validation during build.

### Runtime Dependencies
* **Bash 4.4+**
* **systemd** (specifically `systemd-networkd` and `networkctl`)
* **iproute2** (`ip`)
* **JSON Processor**: One of `jq`, `jaq`, or `gojq`.
* **Wireless**: `iwd` (Recommended) or `wpa_supplicant`.

---

## 🚀 Quick Start

### 1. The Standard Build (Dynamic Linking)
Best for desktop development, debugging, or standard glibc-based distributions (Fedora, Debian, Arch).

```bash
make
sudo make install
```
* **Result:** Dynamically linked `rxnm-agent`.
* **Size:** ~25KB (code) + shared libs overhead.

### 2. The 'Tiny' Build (Static Linking)
**Target:** Embedded devices (Rockchip, Allwinner), Initramfs, BusyBox systems.

This profile aggressively optimizes for size and portability. It prioritizes `musl-gcc` to produce a static binary with zero external dependencies.

```bash
make tiny
sudo make install
```
* **Result:** Statically linked `rxnm-agent`.
* **Size:** ~50KB (with musl) or ~700KB (with glibc static).
* **Optimization:** LTO enabled, symbols stripped, unused sections garbage collected.

---

## 🧩 Architecture: Single Source of Truth (SSoT)

RXNM enforces strict consistency between the Bash logic and the C Agent using a synchronization pipeline.

1.  **Source:** `lib/rxnm-constants.sh` contains configuration defaults.
2.  **Schema:** `api-schema.json` defines the API contract.
3.  **Generator:** `scripts/sync-constants.sh` runs automatically during `make`.
4.  **Output:** `src/rxnm_generated.h` is generated, ensuring the C Agent shares the exact same versioning, probing targets, and configuration defaults as the shell scripts.

**Note:** You do not need to manually edit `src/rxnm_generated.h`. Edit `lib/rxnm-constants.sh` instead.

---

## 🧪 Testing & Verification

The project includes a comprehensive test suite in the `tests/` directory.

### Quick Sanity Check
Runs foundation tests and basic Agent logic.
```bash
make check
```

### Full Regression Suite
Runs memory leak analysis (Valgrind), CLI fuzzing, and consistency checks between the Agent and Legacy Bash logic.
```bash
make test-all
```

**Test Coverage:**
* **Foundation:** Binary integrity, static linking verification.
* **Consistency:** Compares `ip route` output against Agent Netlink dumps.
* **Performance:** Benchmarks latency against defined SLAs (<5ms).
* **Stability:** Valgrind memory leak detection.
* **Fuzzing:** Validates robust handling of garbage CLI arguments.

---

## ⚔️ Cross-Compilation

RXNM is primarily deployed on ARM64 (aarch64) and RISC-V (riscv64).

### Cross-Compiling for ARM64 (Example)
```bash
export CC=aarch64-linux-gnu-gcc
make tiny
```

### Cross-Compiling for RISC-V
```bash
export CC=riscv64-linux-gnu-gcc
make tiny
```

---

## 📂 Installation Paths

`make install` deploys files to standard system paths compliant with FHS and systemd conventions.

| Component | Path | Description |
| :--- | :--- | :--- |
| **Dispatcher** | `/usr/bin/rxnm` | Symlink to the main entry point. |
| **Agent** | `/usr/lib/rocknix-network-manager/bin/rxnm-agent` | Native accelerator. |
| **Libraries** | `/usr/lib/rocknix-network-manager/lib/*.sh` | Core logic modules. |
| **Templates** | `/usr/lib/systemd/network/` | Default networkd configuration templates. |
| **Hooks** | `/usr/lib/systemd/system-sleep/rxnm-resume` | WiFi restoration logic for suspend/resume. |
| **Completion** | `/usr/share/bash-completion/completions/rxnm` | Tab completion logic. |

To override the installation prefix (default `/usr`):
```bash
make install PREFIX=/usr/local
```

---

## 🧹 Cleaning Up

To remove build artifacts and generated headers:
```bash
make clean
```
