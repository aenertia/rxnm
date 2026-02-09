# RXNM Hybrid Architecture Makefile
# Automates SSoT generation and Agent compilation

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

# Targets
TARGET = $(BIN_DIR)/rxnm-agent
CONSTANTS_HEADER = $(SRC_DIR)/rxnm_generated.h

.PHONY: all clean check dirs constants tiny test-all

all: dirs constants $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

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

clean:
	@echo "[CLEAN]"
	@rm -f $(TARGET)
	@rm -f $(CONSTANTS_HEADER)

# Quick check (Foundation + Phase 2 Logic)
check: all
	@echo "[TEST] Running Foundation Tests..."
	@bash tests/test_foundation.sh
	@bash tests/test_phase2.sh

# Full Phase 3 Validation
test-all: all
	@echo "[TEST] Running Full Validation Suite..."
	@bash tests/test_foundation.sh
	@bash tests/test_phase2.sh
	@bash tests/test_query.sh
	@bash tests/test_consistency.sh
	@bash tests/test_performance.sh
	@bash tests/test_stability.sh
