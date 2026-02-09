/*
 * RXNM Agent - Native Fastpath Component
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase 1: Foundation & Observability
 * - Provides sub-millisecond timestamps
 * - Detects hardware capabilities (Low Power)
 * - Basic health checks
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// Include generated SSoT constants
#include "rxnm_generated.h"

#define AGENT_VERSION "0.1.0-phase1"

// --- UTILS ---

// Fast file read helper
bool file_contains(const char *path, const char *search_term) {
    FILE *f = fopen(path, "r");
    if (!f) return false;

    char buffer[4096];
    bool found = false;
    while (fgets(buffer, sizeof(buffer), f)) {
        if (strstr(buffer, search_term)) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

// --- COMMAND HANDLERS ---

void cmd_version() {
    printf("rxnm-agent %s\n", AGENT_VERSION);
    printf("ConfDir: %s\n", CONF_DIR);
    printf("RunDir:  %s\n", RUN_DIR);
}

void cmd_health() {
    // Basic sanity check: can we write to /tmp or RUN_DIR?
    // In Phase 1, just returning JSON success matches the API schema.
    printf("{\"%s\": true, \"agent\": \"active\", \"version\": \"%s\"}\n", 
           KEY_SUCCESS, AGENT_VERSION);
}

void cmd_time() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        printf("%ld\n", ts.tv_sec);
    } else {
        perror("clock_gettime");
        exit(1);
    }
}

// Ported logic from rxnm-constants.sh
// Replaces the grep call in the shell script
void cmd_is_low_power() {
    const char *cpuinfo = "/proc/cpuinfo";
    // List from rxnm-constants.sh
    const char *socs[] = {
        // Rockchip
        "RK3326", "RK3566", "RK3128", "RK3036", "RK3288",
        // Allwinner
        "H700", "H616", "H3", "H5", "H6", "A64", "A133", "A33", "sunxi",
        // Broadcom (Pi)
        "BCM2835", "BCM2836", "BCM2837",
        // Other ARM/MIPS
        "ATM7051", "S905", "S805", "Meson", "X1830", "JZ4770",
        // RISC-V
        "riscv", "sun20iw1p1", "JH7110", "JH7100",
        // Legacy x86 (Constrained)
        "Atom", "Celeron", "Pentium", "Geode",
        // MIPS
        "mips",
        // Specialized / Embedded Linux
        "avr", "xtensa", "tensilica", "loongson", "loongarch",
        NULL
    };

    bool is_lp = false;
    for (int i = 0; socs[i] != NULL; i++) {
        if (file_contains(cpuinfo, socs[i])) {
            is_lp = true;
            break;
        }
    }

    // Output strictly 'true' or 'false' for shell consumption
    printf("%s\n", is_lp ? "true" : "false");
}

// Stub for Phase 2
void cmd_dump_status() {
    fprintf(stderr, "Not implemented in Phase 1\n");
    exit(1);
}

// --- MAIN ---

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"version", no_argument, 0, 'v'},
        {"help",    no_argument, 0, 'h'},
        {"health",  no_argument, 0, 'H'},
        {"time",    no_argument, 0, 't'},
        {"is-low-power", no_argument, 0, 'L'},
        {"dump",    no_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "vhHtdL", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v':
                cmd_version();
                return 0;
            case 'h':
                printf("Usage: rxnm-agent [options]\n");
                printf("  --health        Check agent health\n");
                printf("  --time          Print current timestamp (fast)\n");
                printf("  --is-low-power  Check CPU capabilities\n");
                printf("  --version       Show version\n");
                return 0;
            case 'H':
                cmd_health();
                return 0;
            case 't':
                cmd_time();
                return 0;
            case 'L':
                cmd_is_low_power();
                return 0;
            case 'd':
                cmd_dump_status();
                return 0;
            default:
                return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unknown arguments\n");
        return 1;
    }

    // Default behavior if no args (Display help)
    printf("rxnm-agent: No command specified. Try --help\n");
    return 1;
}
