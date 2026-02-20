# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: Makefile
# PURPOSE: Build System for RXNM Agent
# ARCHITECTURE: Integration / Build
#
# Handles compilation of the C Agent (standard and tiny profiles), constant
# synchronization (SSoT), installation, and test suite execution.
# -----------------------------------------------------------------------------

CC ?= gcc
# Standard CFLAGS for development (Debug symbols, safe optimization)
CFLAGS ?= -O2 -Wall -Wextra -std=c11

# Tiny CFLAGS for embedded/release (Size optimization, static linking, strip symbols)
# -Os: Optimize for size
# -static: Include all libraries in the binary (portable)
# -s: Strip debug symbols
# -flto: Link Time Optimization
# -ffunction-sections -fdata-sections: Allow linker to discard unused code
# -Wl,--gc-sections: Tell linker to garbage collect unused sections
# -idirafter /usr/include: Fallback to system headers for linux/netlink.h (Required for musl-gcc wrapper)
CFLAGS_TINY = -Os -static -s -flto -ffunction-sections -fdata-sections -Wl,--gc-sections -idirafter /usr/include -std=c11

# Directories
BIN_DIR = bin
LIB_DIR = lib
SRC_DIR = src
SCRIPTS_DIR = scripts

# Installation Paths
PREFIX ?= /usr
LIBEXEC_DIR ?= $(PREFIX)/lib/rocknix-network-manager
BIN_SYMLINK ?= $(PREFIX)/bin/rxnm
SHARE_DIR ?= $(PREFIX)/share
BASH_COMP_DIR ?= $(SHARE_DIR)/bash-completion/completions
SYSTEMD_NET_DIR ?= $(PREFIX)/lib/systemd/network
SYSTEMD_SLEEP_DIR ?= $(PREFIX)/lib/systemd/system-sleep

# Targets
TARGET = $(BIN_DIR)/rxnm-agent
CONSTANTS_HEADER = $(SRC_DIR)/rxnm_generated.h

.PHONY: all clean check lint dirs constants tiny test-all install verify rocknix-release combined-full

all: dirs constants $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)
	@mkdir -p build

# Step 1: Sync Constants (SSoT)
constants: $(CONSTANTS_HEADER)

$(CONSTANTS_HEADER): $(LIB_DIR)/rxnm-constants.sh api-schema.json $(SCRIPTS_DIR)/sync-constants.sh
	@echo "[SYNC] Generating constants header..."
	@bash $(SCRIPTS_DIR)/sync-constants.sh

# Step 2: Standard Compilation (Dynamic)
$(TARGET): $(SRC_DIR)/rxnm-agent.c $(CONSTANTS_HEADER)
	@echo "[CC]   $@"
	@$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< $(LDFLAGS)

# Step 3: Tiny Compilation (Static)
# Usage: make tiny
# Logic: Tries musl-gcc first. If missing (Buildroot/LibreELEC), falls back to $(CC) -static.
tiny: dirs constants
	@echo "[CC]   $(TARGET) (Static Profile)"
	@if command -v musl-gcc >/dev/null; then \
		musl-gcc $(CFLAGS_TINY) -I$(SRC_DIR) -o $(TARGET) $(SRC_DIR)/rxnm-agent.c; \
		echo "       [INFO] Used musl-gcc. Optimized for size (~50KB)."; \
	else \
		echo "       [WARN] musl-gcc not found. Using $(CC) -static."; \
		echo "       [INFO] Binary will be larger (~700KB) due to glibc, but latency remains <5ms."; \
		$(CC) $(CFLAGS_TINY) -I$(SRC_DIR) -o $(TARGET) $(SRC_DIR)/rxnm-agent.c || \
		(echo "       [ERROR] Build failed. Missing static libc?" && \
		 echo "       [HINT] Fedora/Bazzite/RHEL: sudo dnf install glibc-static" && \
		 echo "       [HINT] Debian/Ubuntu: sudo apt install libc6-dev" && exit 1); \
	fi
	@ls -lh $(TARGET)

# Step 4: Installation
install: all
	@echo "[INSTALL] Deploying to $(LIBEXEC_DIR)..."
	@mkdir -p $(LIBEXEC_DIR)/bin
	@mkdir -p $(LIBEXEC_DIR)/lib
	@mkdir -p $(LIBEXEC_DIR)/plugins
	@cp -f $(BIN_DIR)/* $(LIBEXEC_DIR)/bin/
	@cp -f $(LIB_DIR)/* $(LIBEXEC_DIR)/lib/
	@chmod 755 $(LIBEXEC_DIR)/bin/*
	@chmod 644 $(LIBEXEC_DIR)/lib/*
	@echo "[LINK]    Creating symlink $(BIN_SYMLINK)..."
	@ln -sf $(LIBEXEC_DIR)/bin/rxnm $(BIN_SYMLINK)
	
	@echo "[INSTALL] Bash completion..."
	@mkdir -p $(BASH_COMP_DIR)
	@cp -f usr/share/bash-completion/completions/rxnm $(BASH_COMP_DIR)/
	@chmod 644 $(BASH_COMP_DIR)/rxnm

	@echo "[INSTALL] Systemd network templates..."
	@mkdir -p $(SYSTEMD_NET_DIR)
	@cp -f usr/lib/systemd/network/* $(SYSTEMD_NET_DIR)/
	# Fixed: Only apply chmod to files to prevent stripping +x from dirs
	@find $(SYSTEMD_NET_DIR) -type f -exec chmod 644 {} +

	@echo "[INSTALL] System sleep hooks..."
	@mkdir -p $(SYSTEMD_SLEEP_DIR)
	@cp -f usr/lib/systemd/system-sleep/rxnm-resume $(SYSTEMD_SLEEP_DIR)/
	@chmod 755 $(SYSTEMD_SLEEP_DIR)/rxnm-resume

	@echo "✓ Installation complete."

clean:
	@echo "[CLEAN]"
	@rm -f $(TARGET)
	@rm -f $(CONSTANTS_HEADER)
	@rm -rf build/

# New: Static Analysis
lint:
	@echo "[TEST] Running ShellCheck..."
	@bash tests/test_shellcheck.sh

# Quick check (Foundation + Phase 2 Logic)
check: all
	@echo "[TEST] Running Foundation Tests..."
	@bash tests/test_foundation.sh
	@bash tests/test_phase2.sh

# Full Phase 3 Validation (Updated for Release)
# Now includes linting as a prerequisite
test-all: all lint
	@echo "[TEST] Running Full Validation Suite..."
	@bash tests/test_foundation.sh
	@bash tests/test_phase2.sh
	@bash tests/test_query.sh
	@bash tests/test_consistency.sh
	@bash tests/test_performance.sh
	@bash tests/test_stability.sh
	@bash tests/test_cli_fuzz.sh
	@bash tests/verify_release.sh

# Final Implementation Verification
verify:
	@echo "[VERIFY] Running Implementation Verification..."
	@bash tests/verify_release.sh

# Target for ROCKNIX Minimal Edition
rocknix-release: tiny
	@echo "[ROCKNIX] Building Minimal Bundle..."
	@bash scripts/bundle.sh
	@cp -f $(TARGET) build/rxnm-agent
	@echo "[ROCKNIX] Running Bundle Fuzzer..."
	@BUNDLE_BIN=build/rxnm bash tests/test_bundle_fuzz.sh
	@echo "[ROCKNIX] Deployment artifacts ready in build/"
	@echo "    - build/rxnm       (Single Script)"
	@echo "    - build/rxnm-agent (Tiny C Agent)"

# Target for Full Combined Edition (All Features)
combined-full: tiny
	@echo "[RXNM] Building Full Combined Bundle..."
	@BUNDLE_MODE=full bash scripts/bundle.sh
	@cp -f $(TARGET) build/rxnm-agent
	@echo "[RXNM] Running Bundle Fuzzer on Full Edition..."
	@BUNDLE_BIN=build/rxnm-full bash tests/test_bundle_fuzz.sh
	@echo "[RXNM] Deployment artifacts ready in build/"
	@echo "    - build/rxnm-full  (Single Script - All Features)"
	@echo "    - build/rxnm-agent (Tiny C Agent)"
