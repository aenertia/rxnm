/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>
 */

/**
 * @file rxnm-agent.c
 * @brief High-Performance Network State Aggregator & Accelerator
 * @architecture Accelerator / Core
 *
 * RESPONSIBILITIES:
 * 1. Read-Only State: Queries Kernel Netlink (RTM/Genl) for interface stats.
 * 2. Atomic Writes: Implements safe config writing (write-tmp-and-rename).
 * 3. IPC: Talks directly to systemd-networkd & IWD via DBus socket.
 * 4. Diagnostics: Performs TCP connectivity probes (internet checks).
 * 5. Namespace/Service: Native containerization primitives (unshare/mount/setns).
 * 6. XDP/eBPF: Fast-path packet dropping for Nullify Mode.
 * 7. Regex: Provides POSIX regex matching for shell scripts on constrained systems.
 *
 * DESIGN PHILOSOPHY:
 * - No external dependencies (glibc/musl only).
 * - Static linking preferred for portability across distros.
 * - Configuration logic is derived strictly from rxnm_generated.h (SSoT).
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
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sched.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>
#include <linux/wireless.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <regex.h>
// New headers for BPF/XDP
#include <linux/bpf.h>
#include <sys/syscall.h>

/* Generated SSoT Constants */
#include "rxnm_generated.h"
#include "rxnm_dbus_lite.h"

/* --- Fallback Defaults (if generation fails) --- */
#ifndef RXNM_VERSION
#define RXNM_VERSION "0.0.0-dev"
#endif
#ifndef DEFAULT_HOSTNAME
#define DEFAULT_HOSTNAME "ROCKNIX"
#endif
#ifndef CONF_DIR
#define CONF_DIR "/storage/.config"
#endif
#ifndef RUN_DIR
#define RUN_DIR "/run/rocknix"
#endif
#ifndef RXNM_PROBE_TARGETS_V4
#define RXNM_PROBE_TARGETS_V4 "1.1.1.1:80 8.8.8.8:443"
#endif
#ifndef RXNM_PROBE_TARGETS_V6
#define RXNM_PROBE_TARGETS_V6 "[2606:4700:4700::1111]:80 [2001:4860:4860::8888]:443"
#endif

/* Runtime Globals (Populated from Constants/Env) */
char g_conf_dir[PATH_MAX] = CONF_DIR;
char g_run_dir[PATH_MAX] = RUN_DIR;
char g_agent_version[64] = RXNM_VERSION;

/* Increased buffers for probe targets (4KB) to prevent truncation of long env vars */
char g_conn_targets_v4[4096] = RXNM_PROBE_TARGETS_V4;
char g_conn_targets_v6[4096] = RXNM_PROBE_TARGETS_V6;

/* Configurable DBus Timeout (Default 5s) */
long g_dbus_timeout_us = 5000000;

/* Global DBus serial counter — shared across all DBus send functions to prevent
 * duplicate serial numbers within a single connection. */
static uint32_t g_dbus_serial = 0;

/* Routing Table Filter (Default: Main) */
uint32_t g_target_table = RT_TABLE_MAIN;
bool g_filter_table = true; /* If false, dump all tables */

/* --- Internal Limits --- */
#define BUF_SIZE 32768
#define IPV4_CIDR_LEN (INET_ADDRSTRLEN + 4)
#define IPV6_CIDR_LEN (INET6_ADDRSTRLEN + 5)
#define NETNS_RUN_DIR "/var/run/netns"

/* --- Timeout & Backoff Configuration --- */
/* Optimized for SG2002/RK3326: Start slow to allow CPU yield, cap lower for responsiveness */
#define DBUS_BACKOFF_START_US 2000       /* 2.0ms Initial Backoff (Yield CPU) */
#define DBUS_BACKOFF_CAP_US 100000       /* 100ms Cap (Ensure < 0.1s latency on wake) */

#ifndef IWD_DBUS_MAX_KB
#define IWD_DBUS_MAX_KB 512
#endif
#define IWD_DBUS_MAX_BYTES ((size_t)(IWD_DBUS_MAX_KB) * 1024)

/* --- Netlink/WiFi Constants --- */
#define NL80211_GENL_NAME           "nl80211"
#define NL80211_CMD_GET_INTERFACE   5
#define NL80211_CMD_GET_STATION     17
#define NL80211_ATTR_WIPHY          1
#define NL80211_ATTR_IFINDEX        3
#define NL80211_ATTR_IFNAME         4
#define NL80211_ATTR_MAC            6
#define NL80211_ATTR_SSID           52
#define NL80211_ATTR_WIPHY_FREQ     38
#define NL80211_ATTR_STATION_INFO   21
#define NL80211_ATTR_PARSE_MAX      400
#define NL80211_STA_INFO_SIGNAL     7

#ifndef NL80211_CMD_SET_POWER_SAVE
#define NL80211_CMD_SET_POWER_SAVE  55
#endif
#ifndef NL80211_ATTR_PS_STATE
#define NL80211_ATTR_PS_STATE       88
#endif
#ifndef NL80211_PS_ENABLED
#define NL80211_PS_ENABLED          1
#endif
#ifndef NL80211_PS_DISABLED
#define NL80211_PS_DISABLED         0
#endif

/* --- XDP Constants (Fallback definitions) --- */
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1 << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1 << 2)
#endif
#ifndef IFLA_XDP
#define IFLA_XDP 43
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD 1
#endif

// Drift Guard: Ensure the compiler's view of IFLA_XDP_FLAGS matches the synced/expected value
#ifdef IFLA_XDP_FLAGS
    // Check against SYNC_IFLA_XDP_FLAGS if generated by scripts/sync-constants.sh
    #ifdef SYNC_IFLA_XDP_FLAGS
        #if IFLA_XDP_FLAGS != SYNC_IFLA_XDP_FLAGS
            // Emit warning during build if header definition differs from heuristic/grep
            #warning "Build Environment Drift: System IFLA_XDP_FLAGS differs from sync script."
        #endif
    #endif
#else
    // If not defined by system headers (older kernel headers), use our fallback logic
    #ifdef SYNC_IFLA_XDP_FLAGS
        #define IFLA_XDP_FLAGS SYNC_IFLA_XDP_FLAGS
    #else
        #define IFLA_XDP_FLAGS 3 // Known stable default for modern kernels
    #endif
#endif

// BPF syscall wrapper
static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

// XDP Drop Program: r0 = 1 (XDP_DROP), exit
static const struct bpf_insn xdp_drop_prog[] = {
    { 0xb7, 0, 0, 0, 1 },
    { 0x95, 0, 0, 0, 0 },
};

/*
 * XDP Software WoL Program: Drop all EXCEPT Magic Packets
 * Evaluates raw BPF bytecode directly to bypass libbpf dependencies.
 * Handles IPv4 UDP Port 7/9, IPv6 UDP Port 7/9, and Raw EtherType 0x0842.
 */
static const struct bpf_insn xdp_soft_wol_prog[] = {
    { 0x61, 2, 1, offsetof(struct xdp_md, data), 0 },
    { 0x61, 3, 1, offsetof(struct xdp_md, data_end), 0 },
    { 0xbf, 4, 2, 0, 0 },
    { 0x07, 4, 0, 0, 14 },
    { 0x2d, 4, 3, 29, 0 },      // 04: if r4 > r3 goto DROP (34)
    { 0x71, 5, 2, 12, 0 },
    { 0x67, 5, 0, 8, 8 },
    { 0x71, 6, 2, 13, 0 },
    { 0x4f, 5, 6, 0, 0 },       // r5 = EtherType
    { 0x15, 5, 0, 26, 0x0842 }, // 09: if == 0x0842 goto PASS (36)
    { 0x15, 5, 0, 2, 0x0800 },  // 10: if == 0x0800 goto IPv4 (13)
    { 0x15, 5, 0, 11, 0x86DD }, // 11: if == 0x86DD goto IPv6 (23)
    { 0x05, 0, 0, 21, 0 },      // 12: goto DROP (34)
    
    /* IPv4 Header Evaluation (Index 13) */
    { 0xbf, 4, 2, 0, 0 },
    { 0x07, 4, 0, 0, 42 },      // Min len: Eth(14) + IPv4(20) + UDP(8)
    { 0x2d, 4, 3, 18, 0 },      // 15: if r4 > r3 goto DROP (34)
    { 0x71, 5, 2, 23, 0 },
    { 0x55, 5, 0, 16, 17 },     // 17: if proto != UDP(17) goto DROP (34)
    { 0x71, 5, 2, 36, 0 },
    { 0x67, 5, 0, 8, 8 },
    { 0x71, 6, 2, 37, 0 },
    { 0x4f, 5, 6, 0, 0 },       // r5 = DPORT
    { 0x05, 0, 0, 9, 0 },       // 22: goto DPORT_CHECK (32)
    
    /* IPv6 Header Evaluation (Index 23) */
    { 0xbf, 4, 2, 0, 0 },
    { 0x07, 4, 0, 0, 62 },      // Min len: Eth(14) + IPv6(40) + UDP(8)
    { 0x2d, 4, 3, 8, 0 },       // 25: if r4 > r3 goto DROP (34)
    { 0x71, 5, 2, 20, 0 },
    { 0x55, 5, 0, 6, 17 },      // 27: if next_hdr != UDP(17) goto DROP (34)
    { 0x71, 5, 2, 56, 0 },
    { 0x67, 5, 0, 8, 8 },
    { 0x71, 6, 2, 57, 0 },
    { 0x4f, 5, 6, 0, 0 },       // r5 = DPORT
    
    /* DPORT Validation (Index 32) */
    { 0x15, 5, 0, 3, 7 },       // 32: if == 7 goto PASS (36)
    { 0x15, 5, 0, 2, 9 },       // 33: if == 9 goto PASS (36)
    
    /* DROP (Index 34) */
    { 0xb7, 0, 0, 0, 1 },       // r0 = 1 (XDP_DROP)
    { 0x95, 0, 0, 0, 0 },       // exit
    
    /* PASS (Index 36) */
    { 0xb7, 0, 0, 0, 2 },       // r0 = 2 (XDP_PASS)
    { 0x95, 0, 0, 0, 0 }        // exit
};

/* --- Structures --- */

typedef struct {
    char dst[IPV6_CIDR_LEN];
    char gw[INET6_ADDRSTRLEN];
    uint32_t metric;
    uint32_t table;
    bool is_default;
} route_entry_t;

typedef struct {
    int index;
    int master_index;
    char name[IFNAMSIZ];
    char mac[18];
    
    /* Dynamically scaled IPv4 array */
    char (*ipv4)[IPV4_CIDR_LEN];
    size_t ipv4_count;
    size_t ipv4_capacity;
    
    /* Dynamically scaled IPv6 array */
    char (*ipv6)[IPV6_CIDR_LEN];
    size_t ipv6_count;
    size_t ipv6_capacity;
    
    char gateway[INET6_ADDRSTRLEN];
    uint32_t metric;
    
    /* Dynamically scaled Routes array */
    route_entry_t *routes;
    size_t route_count;
    size_t route_capacity;
    
    char state[16];
    int mtu;
    bool exists;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    int speed_mbps;
    /* Hardware Info (Udev) */
    char vendor[64];
    char model[64];
    char driver[32];
    char bus_info[32];
    uint16_t hw_type;
    /* Wireless Specifics */
    bool is_wifi;
    bool is_bridge;
    bool is_bond;
    uint32_t wiphy_id;
    char ssid[33];
    char bssid[18];
    int signal_dbm;
    uint32_t frequency;
    bool wifi_connected;
} iface_entry_t;

/* Global Dynamic Interface Cache */
iface_entry_t **ifaces = NULL;
size_t ifaces_count = 0;
size_t ifaces_capacity = 0;

/* --- Utilities --- */

/**
 * @brief Dynamic Buffer struct for flexible payload construction
 */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} dyn_buf_t;

bool dyn_buf_append(dyn_buf_t *b, const void *data, size_t dlen) {
    if (b->len + dlen > b->cap) {
        size_t new_cap = b->cap == 0 ? 1024 : b->cap * 2;
        while (b->len + dlen > new_cap) new_cap *= 2;
        uint8_t *n = realloc(b->data, new_cap);
        if (!n) return false;
        b->data = n;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, data, dlen);
    b->len += dlen;
    return true;
}

bool dyn_buf_align4(dyn_buf_t *b) {
    uint8_t pad = 0;
    while (b->len % 4 != 0) {
        if (!dyn_buf_append(b, &pad, 1)) return false;
    }
    return true;
}

bool dyn_buf_align8(dyn_buf_t *b) {
    uint8_t pad = 0;
    while (b->len % 8 != 0) {
        if (!dyn_buf_append(b, &pad, 1)) return false;
    }
    return true;
}

bool dyn_buf_append_string(dyn_buf_t *b, const char *str) {
    /* Ensure 4-byte alignment before appending string length (D-Bus Spec) */
    if (!dyn_buf_align4(b)) return false;
    
    /* Encode length in native byte order to match DBUS_NATIVE_ENDIAN */
    uint32_t len = strlen(str);
    if (!dyn_buf_append(b, &len, sizeof(len))) return false;
    if (!dyn_buf_append(b, str, len + 1)) return false;
    return true;
}

void dyn_buf_free(dyn_buf_t *b) {
    if (b->data) free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/**
 * @brief Safely frees all dynamically allocated memory tracking the network state.
 */
void cleanup_ifaces(void) {
    if (!ifaces) return;
    for (size_t i = 0; i < ifaces_count; i++) {
        if (ifaces[i]) {
            if (ifaces[i]->ipv4) free(ifaces[i]->ipv4);
            if (ifaces[i]->ipv6) free(ifaces[i]->ipv6);
            if (ifaces[i]->routes) free(ifaces[i]->routes);
            free(ifaces[i]);
        }
    }
    free(ifaces);
    ifaces = NULL;
    ifaces_count = 0;
    ifaces_capacity = 0;
}

/**
 * @brief Checks if a file contains a specific string substring.
 * Used for CPU detection (/proc/cpuinfo).
 */
bool file_contains(const char *path, const char *search_term) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buffer[4096];
    bool found = false;
    while (fgets(buffer, sizeof(buffer), f)) {
        if (strcasestr(buffer, search_term)) { found = true; break; }
    }
    fclose(f);
    return found;
}

/**
 * @brief Robust sleep using nanosleep (POSIX.1-2008)
 */
void safe_usleep(long us) {
    struct timespec ts;
    ts.tv_sec = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

/**
 * @brief Retrieve or initialize an interface entry by kernel index.
 * Automatically scales the global ifaces array if capacity is reached.
 */
iface_entry_t* get_iface(int index) {
    /* 1. Search existing */
    for (size_t i = 0; i < ifaces_count; i++) {
        if (ifaces[i]->exists && ifaces[i]->index == index) return ifaces[i];
    }
    
    /* 2. Scale array if necessary */
    if (ifaces_count >= ifaces_capacity) {
        size_t new_cap = (ifaces_capacity == 0) ? 16 : ifaces_capacity * 2;
        iface_entry_t **new_ifaces = realloc(ifaces, new_cap * sizeof(iface_entry_t*));
        if (!new_ifaces) {
            fprintf(stderr, "OOM expanding interfaces array\n");
            return NULL; /* Graceful degradation */
        }
        ifaces = new_ifaces;
        ifaces_capacity = new_cap;
    }
    
    /* 3. Allocate and initialize new entry */
    iface_entry_t *entry = calloc(1, sizeof(iface_entry_t));
    if (!entry) {
        fprintf(stderr, "OOM allocating interface entry\n");
        return NULL;
    }
    
    entry->exists = true;
    entry->index = index;
    entry->signal_dbm = -100;
    entry->speed_mbps = -1;
    strncpy(entry->state, "unknown", sizeof(entry->state) - 1);
    entry->state[sizeof(entry->state)-1] = '\0';
    
    /* Pre-allocate inner arrays with sensible defaults */
    entry->ipv4_capacity = 2;
    entry->ipv4 = calloc(entry->ipv4_capacity, IPV4_CIDR_LEN);
    
    entry->ipv6_capacity = 4;
    entry->ipv6 = calloc(entry->ipv6_capacity, IPV6_CIDR_LEN);
    
    entry->route_capacity = 8;
    entry->routes = calloc(entry->route_capacity, sizeof(route_entry_t));
    
    ifaces[ifaces_count++] = entry;
    return entry;
}

bool sysfs_has_subdir(const char *ifname, const char *subdir) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, subdir);
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

/**
 * @brief Heuristics to determine simplified interface type (wifi, ethernet, bridge).
 */
const char* detect_iface_type(iface_entry_t *entry) {
    if (entry->hw_type == ARPHRD_ETHER && !entry->is_wifi && !entry->is_bridge && !entry->is_bond) {
         if (sysfs_has_subdir(entry->name, "wireless") || sysfs_has_subdir(entry->name, "phy80211")) {
             entry->is_wifi = true;
         }
         else if (sysfs_has_subdir(entry->name, "bridge")) {
             entry->is_bridge = true;
         }
         else if (sysfs_has_subdir(entry->name, "bonding")) {
             entry->is_bond = true;
         }
    }
    if (entry->hw_type == ARPHRD_LOOPBACK) return "loopback";
    if (entry->hw_type == ARPHRD_TUNNEL || entry->hw_type == ARPHRD_TUNNEL6) return "tun";
    if (entry->hw_type == ARPHRD_IEEE80211 || entry->is_wifi) return "wifi";
    if (entry->is_bridge) return "bridge";
    if (entry->is_bond) return "bond";
    
    // Naming convention fallbacks
    const char *name = entry->name;
    if (strncmp(name, "wl", 2) == 0) return "wifi";
    if (strncmp(name, "et", 2) == 0) return "ethernet";
    if (strncmp(name, "en", 2) == 0) return "ethernet";
    if (strncmp(name, "br", 2) == 0) return "bridge";
    if (strncmp(name, "lo", 2) == 0) return "loopback";
    if (strncmp(name, "usb", 3) == 0) return "gadget";
    if (strncmp(name, "rndis", 5) == 0) return "gadget";
    if (strncmp(name, "veth", 4) == 0) return "veth";
    if (strncmp(name, "tun", 3) == 0) return "tun";
    if (strncmp(name, "tap", 3) == 0) return "tap";
    if (strncmp(name, "wg", 2) == 0) return "wireguard";
    if (entry->hw_type == ARPHRD_ETHER) return "ethernet";
    return "unknown";
}

/* --- Configuration Loading --- */

/**
 * @brief Reads runtime config logic from environment overrides.
 * Acts as a runtime fallback for compiled-in constants.
 */
static void apply_env_overrides(void) {
    const char *env_timeout = getenv("RXNM_DBUS_TIMEOUT_MS");
    if (env_timeout) {
        long ms = atol(env_timeout);
        if (ms > 0 && ms < 60000)           /* sanity: 1ms–60s */
            g_dbus_timeout_us = ms * 1000L;
    }
    /* Future runtime overrides go here, not in a file parser */
}

/* --- Udev Enrichment --- */

static inline void safe_udev_copy(char *dest, size_t dest_size, const char *src) {
    if (!src || !dest) return;
    size_t len = strlen(src);
    /* Safely trim trailing CR/LF */
    while (len > 0 && (src[len-1] == '\n' || src[len-1] == '\r')) len--;
    if (len >= dest_size) len = dest_size - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

void udev_enrich(iface_entry_t *entry) {
    char path[PATH_MAX];
    // Check udev database in /run/udev/data
    snprintf(path, sizeof(path), "/run/udev/data/n%d", entry->index);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(path, sizeof(path), "/run/udev/data/+net:%s", entry->name);
        f = fopen(path, "r");
    }
    if (!f) return;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "E:ID_VENDOR_FROM_DATABASE=", 26) == 0) {
            safe_udev_copy(entry->vendor, sizeof(entry->vendor), line + 26);
        } else if (strncmp(line, "E:ID_MODEL_FROM_DATABASE=", 25) == 0) {
            safe_udev_copy(entry->model, sizeof(entry->model), line + 25);
        } else if (strncmp(line, "E:ID_NET_DRIVER=", 16) == 0) {
            safe_udev_copy(entry->driver, sizeof(entry->driver), line + 16);
        } else if (strncmp(line, "E:ID_PATH=", 10) == 0) {
            safe_udev_copy(entry->bus_info, sizeof(entry->bus_info), line + 10);
        }
    }
    fclose(f);
}

/* --- DBus Implementation --- */

int dbus_connect_system(void) {
    long current_backoff = DBUS_BACKOFF_START_US;
    long total_waited = 0;
    int sock = -1;
    int res = -1;

    // Proportionally scale the internal select/recv IO timeout to 40% of the total budget
    long io_timeout_us = (g_dbus_timeout_us * 40) / 100;
    if (io_timeout_us < 1000000) io_timeout_us = 1000000; // Safeguard: minimum 1 second

    while (total_waited < g_dbus_timeout_us) {
        if (sock >= 0) close(sock); // Clean up previous attempt
        
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) return -1;
        
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, DBUS_SOCK_PATH, sizeof(addr.sun_path)-1);
        
        /* Set Non-Blocking for Connect (Fail Fast) */
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        
        // Success or In-Progress -> Break loop to proceed to Select phase
        if (res == 0) break;
        if (res < 0 && errno == EINPROGRESS) break;
        
        // Fatal errors (Not worth retrying)
        if (errno == EACCES || errno == EAFNOSUPPORT || errno == EPROTOTYPE) {
            close(sock);
            return -2;
        }
        
        // Retryable errors (ENOENT=No Socket, ECONNREFUSED=No Listener, EAGAIN)
        // Backoff and retry
        safe_usleep(current_backoff);
        total_waited += current_backoff;
        
        // Exponential backoff, capped at 100ms per sleep for responsiveness
        current_backoff *= 2;
        if (current_backoff > DBUS_BACKOFF_CAP_US) current_backoff = DBUS_BACKOFF_CAP_US; 
    }
    
    if (total_waited >= g_dbus_timeout_us) {
        if (sock >= 0) close(sock);
        return -2; // Timeout
    }

    /* Wait for connection completion (Select) if EINPROGRESS */
    if (res < 0 && errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv = { .tv_sec = io_timeout_us / 1000000, .tv_usec = io_timeout_us % 1000000 };
        
        if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
            close(sock);
            return -2; /* Timeout or Error */
        }
        
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error != 0) {
            close(sock);
            return -2;
        }
    }
    
    /* Restore Blocking Mode */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    
    /* Set RCV/SND Timeouts to prevent hangs on read/write proportionally */
    struct timeval tv = { .tv_sec = io_timeout_us / 1000000, .tv_usec = io_timeout_us % 1000000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    /* SASL Auth */
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%u", getuid());
    char auth_buf[128];
    char uid_hex[33];
    for (int i=0; uid_str[i]; i++) snprintf(uid_hex+(i*2), 3, "%02x", uid_str[i]);
    auth_buf[0] = 0;
    
    int len = snprintf(auth_buf + 1, sizeof(auth_buf) - 1, "%s%s\r\n", SASL_AUTH_EXTERNAL, uid_hex);
    if (len < 0) { close(sock); return -4; }
    
    send(sock, auth_buf, len + 1, 0); // Leading zero required
    
    char resp[512];
    int n = recv(sock, resp, sizeof(resp)-1, 0);
    if (n <= 0 || strncmp(resp, "OK", 2) != 0) { close(sock); return -3; }
    
    send(sock, SASL_BEGIN, strlen(SASL_BEGIN), 0);
    return sock;
}

/**
 * @brief Constructs and sends a DBus Method Call using dynamic buffers.
 */
int dbus_send_method_call(int sock, const char *dest, const char *path, const char *iface, const char *method, bool expect_reply) {
    dyn_buf_t b = {0};
    
    dbus_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.endian = DBUS_NATIVE_ENDIAN;
    hdr.type = DBUS_MESSAGE_TYPE_METHOD_CALL;
    hdr.flags = expect_reply ? 0 : DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED;
    hdr.version = DBUS_PROTOCOL_VERSION;
    
    hdr.serial = ++g_dbus_serial;
    
    if (!dyn_buf_append(&b, &hdr, sizeof(hdr))) { dyn_buf_free(&b); return -1; }
    
    uint8_t field_type;
    
    field_type = DBUS_HEADER_FIELD_PATH;
    if (!dyn_buf_append(&b, &field_type, 1) || !dyn_buf_append(&b, "\x01o\x00", 3) || !dyn_buf_append_string(&b, path) || !dyn_buf_align8(&b)) { dyn_buf_free(&b); return -1; }
    
    field_type = DBUS_HEADER_FIELD_DESTINATION;
    if (!dyn_buf_append(&b, &field_type, 1) || !dyn_buf_append(&b, "\x01s\x00", 3) || !dyn_buf_append_string(&b, dest) || !dyn_buf_align8(&b)) { dyn_buf_free(&b); return -1; }
    
    field_type = DBUS_HEADER_FIELD_INTERFACE;
    if (!dyn_buf_append(&b, &field_type, 1) || !dyn_buf_append(&b, "\x01s\x00", 3) || !dyn_buf_append_string(&b, iface) || !dyn_buf_align8(&b)) { dyn_buf_free(&b); return -1; }
    
    field_type = DBUS_HEADER_FIELD_MEMBER;
    if (!dyn_buf_append(&b, &field_type, 1) || !dyn_buf_append(&b, "\x01s\x00", 3) || !dyn_buf_append_string(&b, method) || !dyn_buf_align8(&b)) { dyn_buf_free(&b); return -1; }
    
    dbus_header_t *out_hdr = (dbus_header_t *)b.data;
    out_hdr->fields_len = (uint32_t)(b.len - sizeof(dbus_header_t));
    out_hdr->body_len = 0;
    
    int ret = send(sock, b.data, b.len, 0);
    dyn_buf_free(&b);
    return ret;
}

/**
 * @brief Drains the DBus socket of initial Hello broadcasts or queued signals
 * to ensure the next synchronous blocking read hits the exact expected method return.
 */
static void dbus_drain_socket(int sock) {
    safe_usleep(10000); /* Yield 10.0ms to allow dbus-broker to flush standard internal responses (NameAcquired etc) */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    char discard[4096];
    while (recv(sock, discard, sizeof(discard), 0) > 0) {}
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
}

/**
 * @brief Triggers 'Reload' on org.freedesktop.network1 via DBus socket.
 */
int dbus_trigger_reload() {
    int sock = dbus_connect_system();
    if (sock < 0) return sock;
    
    // Appease dbus-broker strict state machine requirement
    dbus_send_method_call(sock, 
                          "org.freedesktop.DBus", 
                          "/org/freedesktop/DBus", 
                          "org.freedesktop.DBus", 
                          "Hello", true);
                          
    dbus_drain_socket(sock);
    
    // Now trigger the actual payload
    dbus_send_method_call(sock, 
                          "org.freedesktop.network1", 
                          "/org/freedesktop/network1", 
                          "org.freedesktop.network1.Manager", 
                          "Reload", true);
                          
    // Synchronously wait for MethodReturn to ensure broker dispatched it before we close the socket
    char reply[4096];
    recv(sock, reply, sizeof(reply), 0);
    
    close(sock);
    return 0;
}

/* --- IWD Connection Logic (Discovery & Connect) --- */

/* Helper to check if a Variant String Signature exists before current position */
int check_variant_sig_string(const char *buf, int pos) {
    /* Stricter lower bound check to prevent underflow reads */
    if (pos < 2) return 0;
    
    int i = pos - 1;
    /* Skip alignment padding */
    while (i > 0 && buf[i] == 0) i--;
    
    /* Ensure we have space for sig len and char */
    if (i < 1) return 0;
    
    /* Now we should see the signature string "s" (null terminated) */
    /* Expect 0 (null term), 's', 1 (len) */
    /* Check pattern: [1]['s'][0] */
    if (i >= 2) {
        if (buf[i] == 0 && buf[i-1] == 's' && buf[i-2] == 1) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Finds an IWD network object path by SSID and optional hardware prefix
 */
int find_iwd_network_path(int sock, const char *ssid, const char *prefix, char *out_path, size_t max_len) {
    /* 1. Request ObjectManager Dump */
    dyn_buf_t req = {0};
    dbus_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.endian = DBUS_NATIVE_ENDIAN;
    hdr.type = DBUS_MESSAGE_TYPE_METHOD_CALL;
    hdr.flags = 0; /* Expect Reply */
    hdr.version = DBUS_PROTOCOL_VERSION;
    
    static uint32_t _serial_counter = 0;
    hdr.serial = ++_serial_counter;
    
    if (!dyn_buf_append(&req, &hdr, sizeof(hdr))) return -1;
    
    uint8_t field_type;
    field_type = DBUS_HEADER_FIELD_PATH;
    if (!dyn_buf_append(&req, &field_type, 1) || !dyn_buf_append(&req, "\x01o\x00", 3) || !dyn_buf_append_string(&req, "/") || !dyn_buf_align8(&req)) { dyn_buf_free(&req); return -1; }
    
    field_type = DBUS_HEADER_FIELD_DESTINATION;
    if (!dyn_buf_append(&req, &field_type, 1) || !dyn_buf_append(&req, "\x01s\x00", 3) || !dyn_buf_append_string(&req, "net.connman.iwd") || !dyn_buf_align8(&req)) { dyn_buf_free(&req); return -1; }
    
    field_type = DBUS_HEADER_FIELD_INTERFACE;
    if (!dyn_buf_append(&req, &field_type, 1) || !dyn_buf_append(&req, "\x01s\x00", 3) || !dyn_buf_append_string(&req, "org.freedesktop.DBus.ObjectManager") || !dyn_buf_align8(&req)) { dyn_buf_free(&req); return -1; }
    
    field_type = DBUS_HEADER_FIELD_MEMBER;
    if (!dyn_buf_append(&req, &field_type, 1) || !dyn_buf_append(&req, "\x01s\x00", 3) || !dyn_buf_append_string(&req, "GetManagedObjects") || !dyn_buf_align8(&req)) { dyn_buf_free(&req); return -1; }
    
    dbus_header_t *out_hdr = (dbus_header_t *)req.data;
    out_hdr->fields_len = (uint32_t)(req.len - sizeof(dbus_header_t));
    out_hdr->body_len = 0;
    
    if (send(sock, req.data, req.len, 0) < 0) {
        dyn_buf_free(&req);
        return -1;
    }
    dyn_buf_free(&req);
    
    /* 2. Read Response — Dynamically expanded to avoid static max/malformed bloat */
    char hdr_raw[sizeof(dbus_header_t)];
    int n = recv(sock, hdr_raw, sizeof(hdr_raw), 0);
    if (n < (int)sizeof(hdr_raw)) return -1;
    
    dbus_header_t *resp_hdr = (dbus_header_t *)hdr_raw;
    size_t total_msg_size = sizeof(dbus_header_t)
                            + (size_t)ALIGN8(resp_hdr->fields_len)
                            + (size_t)resp_hdr->body_len;
                            
    if (total_msg_size < sizeof(dbus_header_t)) return -2;  /* underflow/malformed */
    if (total_msg_size > IWD_DBUS_MAX_BYTES)    return -2;  /* exceeds tunable cap */
    
    size_t cap = 4096;
    char *buf = malloc(cap);
    if (!buf) return -3;
    memcpy(buf, hdr_raw, sizeof(hdr_raw));
    
    size_t received = (size_t)n;
    while (received < total_msg_size) {
        if (received >= cap) {
            size_t new_cap = cap * 2;
            char *new_buf = realloc(buf, new_cap);
            if (!new_buf) { free(buf); return -3; }
            buf = new_buf;
            cap = new_cap;
        }
        size_t want = cap - received;
        if (total_msg_size - received < want) want = total_msg_size - received;
        
        int r = recv(sock, buf + received, want, 0);
        if (r <= 0) break;                                    /* timeout or peer close */
        received += (size_t)r;
    }
    
    /* Ensure the buffer wasn't truncated prematurely before parsing bounds */
    if (received < total_msg_size) { free(buf); return -5; }
    
    /* 3. Scan for SSID */
    char last_path[256] = {0};
    uint32_t ssid_len = strlen(ssid);
    
    /* * Iterating 4 bytes at a time (Alignment of uint32 length) 
     * Start after header
     */
    int start_offset = sizeof(dbus_header_t) + ALIGN8(resp_hdr->fields_len);
    
    /* Explicit upper bound check */
    int loop_limit = (int)total_msg_size - 8; /* Ensure 4 byte len + at least 4 byte string data */
    int result = -1;
    
    for (int i = start_offset; i < loop_limit; i += 4) {
        
        /* Avoid unaligned 32-bit loads on ARM/RISC-V */
        uint32_t len;
        memcpy(&len, &buf[i], sizeof(len));
        
        /* Sanity Check Length */
        if (len > 255 || len == 0) continue;
        
        /* Boundary check for the string content itself */
        if (i + 4 + len >= (uint32_t)total_msg_size) continue;
        
        /* Is this an Object Path? */
        if (len > 15 && strncmp(&buf[i+4], "/net/connman/iwd", 16) == 0) {
            /* If a hardware interface prefix is provided, strictly enforce it */
            if (prefix && prefix[0] != '\0') {
                if (strncmp(&buf[i+4], prefix, strlen(prefix)) != 0) {
                    last_path[0] = '\0'; /* Invalidate cache for mismatched interface */
                    continue;
                }
            }
            
            strncpy(last_path, &buf[i+4], 255);
            last_path[len] = '\0'; // Ensure null term if not present in buffer logic (it is in dbus)
            continue;
        }
        
        /* Is this our SSID? */
        if (len == ssid_len && memcmp(&buf[i+4], ssid, ssid_len) == 0) {
            /* * Robustness Check:
             * 1. We must have seen an Object Path recently.
             * 2. The string must be inside a Variant.
             */
            if (last_path[0] != '\0') {
                if (check_variant_sig_string(buf, i)) {
                    strncpy(out_path, last_path, max_len);
                    result = 0;
                    break;
                }
            }
        }
    }
    
    free(buf);
    return result;
}

void collect_network_state(); /* Forward declare for interface resolution */

int cmd_connect(const char *ssid, const char *iface) {
    char target_prefix[64] = "";
    
    /* Map logical interface name to physical IWD DBus Path */
    if (iface && iface[0] != '\0') {
        collect_network_state(); /* Populates global ifaces dynamically */
        for (size_t i = 0; i < ifaces_count; i++) {
            if (ifaces[i]->exists && strcmp(ifaces[i]->name, iface) == 0) {
                /* IWD paths map deterministically to the underlying kernel wiphy_id and ifindex */
                snprintf(target_prefix, sizeof(target_prefix), "/net/connman/iwd/phy%u/%u", 
                         ifaces[i]->wiphy_id, ifaces[i]->index);
                break;
            }
        }
    }
    
    int sock = dbus_connect_system();
    if (sock < 0) {
        printf("{\"success\": false, \"error\": \"DBus connection failed\"}\n");
        return 1;
    }
    
    /* Appease dbus-broker strict state machine requirement */
    dbus_send_method_call(sock, 
                          "org.freedesktop.DBus", 
                          "/org/freedesktop/DBus", 
                          "org.freedesktop.DBus", 
                          "Hello", true);
    
    /* Deterministic drain: discard Hello responses and NameAcquired broadcasts */
    dbus_drain_socket(sock);
    
    char path[256];
    if (find_iwd_network_path(sock, ssid, target_prefix, path, sizeof(path)) != 0) {
        printf("{\"success\": false, \"error\": \"Network '%s' not found on %s\"}\n", ssid, iface ? iface : "any interface");
        close(sock);
        return 1;
    }
    
    /* Call Connect() on the specific network object path and EXPECT reply */
    dbus_send_method_call(sock, "net.connman.iwd", path, "net.connman.iwd.Network", "Connect", true);
    
    /* Wait for MethodReturn or Error. 
     * If iwd hasn't parsed the inotify PSK file yet, it will return a NoAgent Error.
     * Returning 1 forces the shell to fall back to the iwctl retry loop, 
     * elegantly bridging the filesystem sync race condition. */
    char reply[4096];
    int len = recv(sock, reply, sizeof(reply), 0);
    if (len >= (int)sizeof(dbus_header_t)) {
        dbus_header_t *rh = (dbus_header_t *)reply;
        if (rh->type == DBUS_MESSAGE_TYPE_ERROR) {
            printf("{\"success\": false, \"error\": \"IWD rejected connection (Wait for inotify PSK sync)\"}\n");
            close(sock);
            return 1;
        }
    }
    
    printf("{\"success\": true, \"action\": \"connect\", \"ssid\": \"%s\", \"path\": \"%s\"}\n", ssid, path);
    close(sock);
    return 0;
}

/* --- Netlink Implementation --- */

int open_netlink_rt() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return -1;
    
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    return sock;
}

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

/* RTM_NEWLINK Parser */
void process_link_msg(struct nlmsghdr *nh) {
    struct ifinfomsg *ifi = NLMSG_DATA(nh);
    struct rtattr *tb[IFLA_MAX + 1];
    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
    
    iface_entry_t *entry = get_iface(ifi->ifi_index);
    if (!entry) return; /* Safely abort on OOM */
    
    entry->hw_type = ifi->ifi_type;
    if (tb[IFLA_IFNAME]) strncpy(entry->name, (char *)RTA_DATA(tb[IFLA_IFNAME]), IFNAMSIZ - 1);
    
    if (tb[IFLA_ADDRESS]) {
        unsigned char *mac = (unsigned char *)RTA_DATA(tb[IFLA_ADDRESS]);
        snprintf(entry->mac, sizeof(entry->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
    if (tb[IFLA_MTU]) entry->mtu = *(unsigned int *)RTA_DATA(tb[IFLA_MTU]);
    if (tb[IFLA_MASTER]) entry->master_index = *(int *)RTA_DATA(tb[IFLA_MASTER]);
    
    if (ifi->ifi_type == ARPHRD_IEEE80211 || ifi->ifi_type == ARPHRD_IEEE80211_RADIOTAP ||
        strncmp(entry->name, "wl", 2) == 0) entry->is_wifi = true;
        
    if (tb[IFLA_STATS64]) {
        struct rtnl_link_stats64 *stats = (struct rtnl_link_stats64 *)RTA_DATA(tb[IFLA_STATS64]);
        entry->rx_bytes = stats->rx_bytes;
        entry->tx_bytes = stats->tx_bytes;
    }
    
    /* Operational State Translation (using strncpy) */
    if ((ifi->ifi_flags & IFF_UP) && (ifi->ifi_flags & IFF_RUNNING)) {
        strncpy(entry->state, "routable", sizeof(entry->state)-1);
    }
    else if (ifi->ifi_flags & IFF_UP) {
        strncpy(entry->state, "no-carrier", sizeof(entry->state)-1);
    }
    else {
        strncpy(entry->state, "off", sizeof(entry->state)-1);
    }
    entry->state[sizeof(entry->state)-1] = '\0';
    
    if (tb[IFLA_MASTER]) {
        strncpy(entry->state, "enslaved", sizeof(entry->state)-1);
        entry->state[sizeof(entry->state)-1] = '\0';
    }
    
    udev_enrich(entry);
}

/* RTM_NEWADDR Parser */
void process_addr_msg(struct nlmsghdr *nh) {
    struct ifaddrmsg *ifa = NLMSG_DATA(nh);
    struct rtattr *tb[IFA_MAX + 1];
    parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
    
    iface_entry_t *entry = get_iface(ifa->ifa_index);
    if (!entry) return; /* Safely abort on OOM */
    
    if (tb[IFA_ADDRESS]) {
        void *addr_ptr = RTA_DATA(tb[IFA_ADDRESS]);
        if (ifa->ifa_family == AF_INET) {
            /* Prefer global scope addresses */
            if (ifa->ifa_scope < RT_SCOPE_HOST) {
                char ipv4_buf[INET_ADDRSTRLEN];
                
                /* Dynamically expand IPv4 array if full */
                if (entry->ipv4_count >= entry->ipv4_capacity) {
                    size_t new_cap = entry->ipv4_capacity * 2;
                    void *new_ipv4 = realloc(entry->ipv4, new_cap * IPV4_CIDR_LEN);
                    if (!new_ipv4) return;
                    entry->ipv4 = new_ipv4;
                    entry->ipv4_capacity = new_cap;
                    memset((char*)entry->ipv4 + (entry->ipv4_count * IPV4_CIDR_LEN), 0, (new_cap - entry->ipv4_count) * IPV4_CIDR_LEN);
                }
                
                if (inet_ntop(AF_INET, addr_ptr, ipv4_buf, sizeof(ipv4_buf))) {
                    snprintf(entry->ipv4[entry->ipv4_count], IPV4_CIDR_LEN, "%s/%d", ipv4_buf, ifa->ifa_prefixlen);
                    entry->ipv4_count++;
                }
            }
        } else if (ifa->ifa_family == AF_INET6) {
            if (ifa->ifa_scope < RT_SCOPE_HOST) { // Ignore link-local for brevity in summary
                char ipv6_buf[INET6_ADDRSTRLEN];
                
                /* Dynamically expand IPv6 array if full */
                if (entry->ipv6_count >= entry->ipv6_capacity) {
                    size_t new_cap = entry->ipv6_capacity * 2;
                    void *new_ipv6 = realloc(entry->ipv6, new_cap * IPV6_CIDR_LEN);
                    if (!new_ipv6) return;
                    entry->ipv6 = new_ipv6;
                    entry->ipv6_capacity = new_cap;
                    memset((char*)entry->ipv6 + (entry->ipv6_count * IPV6_CIDR_LEN), 0, (new_cap - entry->ipv6_count) * IPV6_CIDR_LEN);
                }
                
                if (inet_ntop(AF_INET6, addr_ptr, ipv6_buf, sizeof(ipv6_buf))) {
                    snprintf(entry->ipv6[entry->ipv6_count], IPV6_CIDR_LEN, "%s/%d", ipv6_buf, ifa->ifa_prefixlen);
                    entry->ipv6_count++;
                }
            }
        }
    }
}

/* RTM_NEWROUTE Parser */
void process_route_msg(struct nlmsghdr *nh) {
    struct rtmsg *rt = NLMSG_DATA(nh);
    struct rtattr *tb[RTA_MAX + 1];
    
    /* Route Filtering Logic (SOA Update) */
    if (g_filter_table && rt->rtm_table != g_target_table) return;
    
    parse_rtattr(tb, RTA_MAX, RTM_RTA(rt), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rt)));
    
    if (!tb[RTA_OIF]) return;
    int oif = *(int *)RTA_DATA(tb[RTA_OIF]);
    
    iface_entry_t *entry = get_iface(oif);
    if (!entry) return; /* Safely abort on OOM */
    
    /* Dynamically expand Routes array if full */
    if (entry->route_count >= entry->route_capacity) {
        size_t new_cap = entry->route_capacity * 2;
        void *new_routes = realloc(entry->routes, new_cap * sizeof(route_entry_t));
        if (!new_routes) return;
        entry->routes = new_routes;
        entry->route_capacity = new_cap;
        memset(entry->routes + entry->route_count, 0, (new_cap - entry->route_count) * sizeof(route_entry_t));
    }
    
    route_entry_t *route = &entry->routes[entry->route_count];
    memset(route, 0, sizeof(route_entry_t));
    
    route->table = rt->rtm_table;
    if (tb[RTA_PRIORITY]) route->metric = *(uint32_t *)RTA_DATA(tb[RTA_PRIORITY]);
    
    if (tb[RTA_GATEWAY]) {
        void *gw_ptr = RTA_DATA(tb[RTA_GATEWAY]);
        if (rt->rtm_family == AF_INET) inet_ntop(AF_INET, gw_ptr, route->gw, INET_ADDRSTRLEN);
        else if (rt->rtm_family == AF_INET6) inet_ntop(AF_INET6, gw_ptr, route->gw, INET6_ADDRSTRLEN);
    }
    
    /* Default Gateway Check */
    if (rt->rtm_dst_len == 0) {
        strcpy(route->dst, "default"); /* Safe: 40+ chars allocated */
        route->is_default = true;
        if (rt->rtm_family == AF_INET || entry->gateway[0] == '\0') {
            if (route->gw[0] != '\0') strncpy(entry->gateway, route->gw, INET6_ADDRSTRLEN);
            entry->metric = route->metric;
        }
    } else if (tb[RTA_DST]) {
        void *dst_ptr = RTA_DATA(tb[RTA_DST]);
        char tmp_buf[INET6_ADDRSTRLEN];
        if (rt->rtm_family == AF_INET) {
            if (inet_ntop(AF_INET, dst_ptr, tmp_buf, sizeof(tmp_buf))) {
                if (rt->rtm_dst_len == 32) snprintf(route->dst, sizeof(route->dst), "%s", tmp_buf);
                else snprintf(route->dst, sizeof(route->dst), "%s/%d", tmp_buf, rt->rtm_dst_len);
            }
        } else if (rt->rtm_family == AF_INET6) {
            if (inet_ntop(AF_INET6, dst_ptr, tmp_buf, sizeof(tmp_buf))) {
                if (rt->rtm_dst_len == 128) snprintf(route->dst, sizeof(route->dst), "%s", tmp_buf);
                else snprintf(route->dst, sizeof(route->dst), "%s/%d", tmp_buf, rt->rtm_dst_len);
            }
        }
    }
    entry->route_count++;
}

void send_dump_request(int sock, int type) {
    struct { struct nlmsghdr nlh; struct rtgenmsg rtg; } req;
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.nlh.nlmsg_type = type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = time(NULL);
    req.rtg.rtgen_family = AF_UNSPEC;
    send(sock, &req, req.nlh.nlmsg_len, 0);
}

void read_rtnetlink_response(int sock) {
    char buf[BUF_SIZE];
    int len;
    while ((len = recv(sock, buf, sizeof(buf), 0)) > 0) {
        struct nlmsghdr *nh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) return;
            if (nh->nlmsg_type == NLMSG_ERROR) return;
            if (nh->nlmsg_type == RTM_NEWLINK) process_link_msg(nh);
            else if (nh->nlmsg_type == RTM_NEWADDR) process_addr_msg(nh);
            else if (nh->nlmsg_type == RTM_NEWROUTE) process_route_msg(nh);
        }
    }
}

/* --- Generic Netlink (nl80211) Implementation --- */

int open_netlink_genl() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0) return -1;
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

void parse_genl_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

bool add_nl_attr(struct nlmsghdr *n, size_t max_buf_size, int type, const void *data, int len) {
    int alen = RTA_LENGTH(len);
    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(alen) > max_buf_size) return false;
    struct rtattr *rta = (struct rtattr *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = alen;
    memcpy(RTA_DATA(rta), data, len);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(alen);
    return true;
}

int get_genl_family_id(int sock, const char *family_name) {
    struct { struct nlmsghdr n; struct genlmsghdr g; char buf[256]; } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_seq = 1;
    req.n.nlmsg_pid = getpid();
    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.g.version = 1;
    
    add_nl_attr(&req.n, sizeof(req), CTRL_ATTR_FAMILY_NAME, family_name, strlen(family_name) + 1);
    send(sock, &req, req.n.nlmsg_len, 0);
    
    char buf[BUF_SIZE];
    int len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) return -1;
    
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    if (NLMSG_OK(nh, len) && nh->nlmsg_type != NLMSG_ERROR) {
        struct genlmsghdr *gh = NLMSG_DATA(nh);
        struct rtattr *tb[CTRL_ATTR_MAX + 1];
        parse_genl_rtattr(tb, CTRL_ATTR_MAX, (struct rtattr *)((char *)gh + GENL_HDRLEN), nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));
        if (tb[CTRL_ATTR_FAMILY_ID]) return *(uint16_t *)RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
    }
    return -1;
}

void process_nl80211_msg(struct nlmsghdr *nh, int cmd) {
    struct genlmsghdr *gh = NLMSG_DATA(nh);
    struct rtattr *tb[NL80211_ATTR_PARSE_MAX + 1];
    parse_genl_rtattr(tb, NL80211_ATTR_PARSE_MAX, (struct rtattr *)((char *)gh + GENL_HDRLEN), nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));
    
    if (!tb[NL80211_ATTR_IFINDEX]) return;
    int ifindex = *(uint32_t *)RTA_DATA(tb[NL80211_ATTR_IFINDEX]);
    
    iface_entry_t *entry = get_iface(ifindex);
    if (!entry) return; /* Safely abort on OOM */
    entry->is_wifi = true;
    
    if (cmd == NL80211_CMD_GET_INTERFACE) {
        /* Map underlying kernel PHY hierarchy into interface array dynamically */
        if (tb[NL80211_ATTR_WIPHY]) {
            entry->wiphy_id = *(uint32_t *)RTA_DATA(tb[NL80211_ATTR_WIPHY]);
        }
        
        if (tb[NL80211_ATTR_SSID]) {
            char *ssid_data = (char *)RTA_DATA(tb[NL80211_ATTR_SSID]);
            int ssid_len = RTA_PAYLOAD(tb[NL80211_ATTR_SSID]);
            int safe_ssid_len = (ssid_len >= (int)sizeof(entry->ssid)) ? (int)sizeof(entry->ssid) - 1 : ssid_len;
            memcpy(entry->ssid, ssid_data, safe_ssid_len);
            entry->ssid[safe_ssid_len] = '\0';
            entry->wifi_connected = true;
        }
        if (tb[NL80211_ATTR_WIPHY_FREQ]) entry->frequency = *(uint32_t *)RTA_DATA(tb[NL80211_ATTR_WIPHY_FREQ]);
    } else if (cmd == NL80211_CMD_GET_STATION) {
        if (tb[NL80211_ATTR_MAC]) {
            unsigned char *bssid_bytes = (unsigned char *)RTA_DATA(tb[NL80211_ATTR_MAC]);
            snprintf(entry->bssid, sizeof(entry->bssid), "%02x:%02x:%02x:%02x:%02x:%02x",
                     bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
                     bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]);
        }
        if (tb[NL80211_ATTR_STATION_INFO]) {
            struct rtattr *si = tb[NL80211_ATTR_STATION_INFO];
            struct rtattr *nested = RTA_DATA(si);
            int len = RTA_PAYLOAD(si);
            while (RTA_OK(nested, len)) {
                if (nested->rta_type == NL80211_STA_INFO_SIGNAL) entry->signal_dbm = (int)(*(int8_t *)RTA_DATA(nested));
                nested = RTA_NEXT(nested, len);
            }
        }
    }
}

void sysfs_collect_bssid_fallback(iface_entry_t *entry) {
    if (!entry->is_wifi || entry->name[0] == '\0') return;
    /* Only if we haven't got it via netlink */
    if (entry->bssid[0] != '\0' && strcmp(entry->bssid, "00:00:00:00:00:00") != 0) return;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    
    struct iwreq iwr;
    memset(&iwr, 0, sizeof(iwr));
    snprintf(iwr.ifr_name, sizeof(iwr.ifr_name), "%s", entry->name);
    
    if (ioctl(sock, SIOCGIWAP, &iwr) == 0) {
        struct sockaddr *sa = &iwr.u.ap_addr;
        if (sa->sa_family == ARPHRD_ETHER) {
            unsigned char *b = (unsigned char *)sa->sa_data;
            if (b[0]|b[1]|b[2]|b[3]|b[4]|b[5]) snprintf(entry->bssid, sizeof(entry->bssid), "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
        }
    }
    close(sock);
}

void collect_wifi_state() {
    int sock = open_netlink_genl();
    if (sock < 0) return;
    
    int fid = get_genl_family_id(sock, NL80211_GENL_NAME);
    if (fid <= 0) { close(sock); return; }
    
    /* Request Interface Info */
    struct { struct nlmsghdr n; struct genlmsghdr g; char buf[4]; } req = {
        .n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN), .n.nlmsg_type = fid, .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
        .g.cmd = NL80211_CMD_GET_INTERFACE, .g.version = 1
    };
    send(sock, &req, req.n.nlmsg_len, 0);
    
    char buf[BUF_SIZE];
    int len;
    while ((len = recv(sock, buf, sizeof(buf), 0)) > 0) {
        struct nlmsghdr *nh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == fid) process_nl80211_msg(nh, NL80211_CMD_GET_INTERFACE);
            else if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) goto step2;
        }
    }
    
step2:
    /* Request Station Info for each WiFi Interface */
    for (size_t i = 0; i < ifaces_count; i++) {
        if (ifaces[i]->exists && ifaces[i]->is_wifi) {
            struct { struct nlmsghdr n; struct genlmsghdr g; char buf[64]; } sta_req;
            memset(&sta_req, 0, sizeof(sta_req));
            sta_req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
            sta_req.n.nlmsg_type = fid;
            sta_req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            sta_req.n.nlmsg_seq = time(NULL) + i;
            sta_req.g.cmd = NL80211_CMD_GET_STATION;
            sta_req.g.version = 1;
            
            uint32_t idx = ifaces[i]->index;
            add_nl_attr(&sta_req.n, sizeof(sta_req), NL80211_ATTR_IFINDEX, &idx, sizeof(idx));
            
            send(sock, &sta_req, sta_req.n.nlmsg_len, 0);
            while ((len = recv(sock, buf, sizeof(buf), 0)) > 0) {
                struct nlmsghdr *nh = (struct nlmsghdr *)buf;
                for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
                    if (nh->nlmsg_type == fid) process_nl80211_msg(nh, NL80211_CMD_GET_STATION);
                    else if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) goto next_iface;
                }
            }
            next_iface:;
        }
    }
    close(sock);
    
    /* Fallback for drivers that don't support NL80211 station dump (e.g., some realtek) */
    for (size_t i = 0; i < ifaces_count; i++) {
        if (ifaces[i]->exists && ifaces[i]->is_wifi) {
            sysfs_collect_bssid_fallback(ifaces[i]);
        }
    }
}

void collect_network_state() {
    int sock = open_netlink_rt();
    if (sock >= 0) {
        send_dump_request(sock, RTM_GETLINK); read_rtnetlink_response(sock);
        send_dump_request(sock, RTM_GETADDR); read_rtnetlink_response(sock);
        send_dump_request(sock, RTM_GETROUTE); read_rtnetlink_response(sock);
        close(sock);
    }
    collect_wifi_state();
}

/* --- Connectivity Check --- */

bool tcp_probe(const char *ip_str, int port, int family) {
    int sock = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return false;
    
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    int res = -1;
    if (family == AF_INET) {
        struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET; addr.sin_port = htons(port);
        inet_pton(AF_INET, ip_str, &addr.sin_addr);
        res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_in6 addr; memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6; addr.sin6_port = htons(port);
        inet_pton(AF_INET6, ip_str, &addr.sin6_addr);
        res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    }
    
    bool success = false;
    if (res == 0) success = true;
    else if (errno == EINPROGRESS) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
        if (select(sock + 1, NULL, &wfds, NULL, &timeout) > 0) {
            int so_error; socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) success = true;
        }
    }
    close(sock); return success;
}

void parse_target(char *token, char *ip, size_t ip_size, int *port) {
    ip[0] = '\0';
    char *colon = strrchr(token, ':');
    if (colon) {
        *colon = '\0';
        *port = atoi(colon + 1);
        if (token[0] == '[' && token[strlen(token)-1] == ']') {
            token[strlen(token)-1] = '\0';
            strncpy(ip, token + 1, ip_size - 1);
        } else {
            strncpy(ip, token, ip_size - 1);
        }
        ip[ip_size - 1] = '\0';
    }
}

void cmd_check_internet() {
    bool v4 = false, v6 = false;
    
    /* Check IPv4 */
    char list_v4[4096]; 
    strncpy(list_v4, g_conn_targets_v4, sizeof(list_v4) - 1); 
    list_v4[sizeof(list_v4)-1] = '\0';
    
    char *token_v4, *saveptr_v4; token_v4 = strtok_r(list_v4, " ", &saveptr_v4);
    while (token_v4 != NULL) {
        char ip[64]; int port = 80;
        parse_target(token_v4, ip, sizeof(ip), &port);
        if (tcp_probe(ip, port, AF_INET)) { v4 = true; break; }
        token_v4 = strtok_r(NULL, " ", &saveptr_v4);
    }
    
    /* Check IPv6 */
    char list_v6[4096]; 
    strncpy(list_v6, g_conn_targets_v6, sizeof(list_v6) - 1); 
    list_v6[sizeof(list_v6)-1] = '\0';
    
    char *token_v6, *saveptr_v6; token_v6 = strtok_r(list_v6, " ", &saveptr_v6);
    while (token_v6 != NULL) {
        char ip[128]; int port = 80;
        parse_target(token_v6, ip, sizeof(ip), &port);
        if (tcp_probe(ip, port, AF_INET6)) { v6 = true; break; }
        token_v6 = strtok_r(NULL, " ", &saveptr_v6);
    }
    
    printf("{\n  \"%s\": true,\n  \"connected\": %s,\n  \"ipv4\": %s,\n  \"ipv6\": %s\n}\n", KEY_SUCCESS, (v4 || v6) ? "true" : "false", v4 ? "true" : "false", v6 ? "true" : "false");
}

/* --- JSON Formatting --- */

void get_proxy_config(char* http, char* https, char* no_proxy) {
    char path[PATH_MAX + 128];
    snprintf(path, sizeof(path), "%s/proxy.conf", g_conf_dir);
    FILE *f = fopen(path, "r"); if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *val_start = strchr(line, '='); if (!val_start) continue;
        val_start++; line[strcspn(line, "\n")] = 0;
        if (val_start[0] == '"' || val_start[0] == '\'') val_start++;
        char *val_end = val_start + strlen(val_start) - 1;
        if (*val_end == '"' || *val_end == '\'') *val_end = 0;
        
        if (strncmp(line, "http_proxy", 10) == 0 || strncmp(line, "HTTP_PROXY", 10) == 0) { strncpy(http, val_start, 255); http[255] = '\0'; }
        else if (strncmp(line, "https_proxy", 11) == 0 || strncmp(line, "HTTPS_PROXY", 11) == 0) { strncpy(https, val_start, 255); https[255] = '\0'; }
        else if (strncmp(line, "no_proxy", 8) == 0 || strncmp(line, "NO_PROXY", 8) == 0) { strncpy(no_proxy, val_start, 255); no_proxy[255] = '\0'; }
    }
    fclose(f);
}

void json_print_string(const char *key, const char *val, bool comma) {
    if (key) printf("    \"%s\": \"", key);
    else printf("\"");
    for (const char *p = val; *p; p++) {
        if (*p == '"') printf("\\\"");
        else if (*p == '\\') printf("\\\\");
        else if (*p == '\n') printf("\\n");
        else if (*p == '\r') printf("\\r");
        else if (*p == '\t') printf("\\t");
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    printf("\"%s\n", comma ? "," : "");
}

/* Helper for cmd_ns_list array escaping without trailing newlines */
void print_escaped_string(const char *val) {
    printf("\"");
    for (const char *p = val; *p; p++) {
        if (*p == '"') printf("\\\"");
        else if (*p == '\\') printf("\\\\");
        else putchar(*p);
    }
    printf("\"");
}

void print_json_status() {
    printf("{\n  \"%s\": true,\n  \"agent_version\": \"%s\",\n", KEY_SUCCESS, g_agent_version);
    
    char hostname[256] = DEFAULT_HOSTNAME;
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        FILE *f = fopen("/etc/hostname", "r");
        if (f) { if (fgets(hostname, sizeof(hostname), f)) hostname[strcspn(hostname, "\n")] = 0; fclose(f); }
    }
    printf("  "); json_print_string("hostname", hostname, true);
    
    char p_http[256] = "", p_https[256] = "", p_no[256] = "";
    get_proxy_config(p_http, p_https, p_no);
    bool has_proxy = (strlen(p_http) > 0 || strlen(p_https) > 0 || strlen(p_no) > 0);
    printf("  \"global_proxy\": {\n");
    if (has_proxy) {
        bool need_comma = false;
        if (strlen(p_http) > 0)  { printf("  "); json_print_string("http", p_http, false); need_comma = true; }
        if (strlen(p_https) > 0) { if (need_comma) printf(",\n"); printf("  "); json_print_string("https", p_https, false); need_comma = true; }
        if (strlen(p_no) > 0)    { if (need_comma) printf(",\n"); printf("  "); json_print_string("noproxy", p_no, false); need_comma = true; }
        printf(",\n    \"status\": \"active\"\n");
    } else {
        printf("    \"status\": \"none\"\n");
    }
    printf("  },\n  \"interfaces\": {\n");
    
    bool first_iface = true;
    for (size_t i = 0; i < ifaces_count; i++) {
        iface_entry_t *entry = ifaces[i];
        if (!entry->exists || entry->name[0] == '\0') continue;
        if (!first_iface) printf(",\n");
        
        printf("    \"%s\": {\n      \"name\": \"%s\",\n      \"state\": \"%s\",\n      \"mtu\": %d,\n      \"type\": \"%s\",\n", 
               entry->name, entry->name, entry->state, entry->mtu, detect_iface_type(entry));
        
        if (entry->mac[0]) printf("      \"mac\": \"%s\",\n", entry->mac);
        if (entry->vendor[0]) json_print_string("vendor", entry->vendor, true);
        if (entry->driver[0]) json_print_string("driver", entry->driver, true);
        if (entry->bus_info[0]) json_print_string("bus_info", entry->bus_info, true);
        
        if (entry->ipv4_count > 0) printf("      \"ip\": \"%s\",\n", entry->ipv4[0]);
        else printf("      \"ip\": null,\n");
        
        printf("      \"ipv4\": [");
        for(size_t j=0; j<entry->ipv4_count; j++) printf("\"%s\"%s", entry->ipv4[j], (j < entry->ipv4_count - 1) ? ", " : "");
        printf("],\n");
        
        if (entry->gateway[0]) printf("      \"gateway\": \"%s\",\n", entry->gateway);
        if (entry->metric > 0) printf("      \"metric\": %u,\n", entry->metric);
        
        printf("      \"ipv6\": [");
        for(size_t j=0; j<entry->ipv6_count; j++) printf("\"%s\"%s", entry->ipv6[j], (j < entry->ipv6_count - 1) ? ", " : "");
        printf("],\n      \"routes\": [");
        for(size_t k=0; k<entry->route_count; k++) {
            printf("\n        { \"dst\": \"%s\"", entry->routes[k].dst);
            if (entry->routes[k].gw[0]) printf(", \"gw\": \"%s\"", entry->routes[k].gw);
            if (entry->routes[k].metric > 0) printf(", \"metric\": %u", entry->routes[k].metric);
            printf(" }%s", (k < entry->route_count - 1) ? "," : "");
        }
        printf("%s],\n      \"stats\": {\n        \"rx_bytes\": %llu,\n        \"tx_bytes\": %llu\n      },\n", entry->route_count > 0 ? "\n      " : "", (unsigned long long)entry->rx_bytes, (unsigned long long)entry->tx_bytes);
        
        int speed_mbps = -1; char speed_path[256]; snprintf(speed_path, sizeof(speed_path), "/sys/class/net/%s/speed", entry->name);
        FILE *f_speed = fopen(speed_path, "r");
        if (f_speed) { if (fscanf(f_speed, "%d", &speed_mbps) != 1) speed_mbps = -1; fclose(f_speed); }
        if (speed_mbps > 0) printf("      \"speed\": %d,\n", speed_mbps);
        
        if (entry->is_wifi) {
            printf("      \"wifi\": {\n");
            json_print_string("ssid", entry->ssid, true);
            if (entry->bssid[0]) printf("        \"bssid\": \"%s\",\n", entry->bssid); else printf("        \"bssid\": null,\n");
            printf("        \"rssi\": %d,\n        \"frequency\": %u\n      },\n", entry->signal_dbm, entry->frequency);
        }
        
        bool is_connected = (strcmp(entry->state, "routable") == 0 || strcmp(entry->state, "enslaved") == 0 || strcmp(entry->state, "online") == 0 || strcmp(entry->state, "up") == 0);
        printf("      \"connected\": %s\n    }", is_connected ? "true" : "false");
        first_iface = false;
    }
    printf("\n  }\n}\n");
}

/* --- Route Listing (Optimized for JSON) --- */
void print_json_routes() {
    printf("{\n  \"%s\": true,\n  \"routes\": [\n", KEY_SUCCESS);
    
    bool first = true;
    for (size_t i = 0; i < ifaces_count; i++) {
        iface_entry_t *entry = ifaces[i];
        for (size_t k = 0; k < entry->route_count; k++) {
            if (!first) printf(",\n");
            route_entry_t *r = &entry->routes[k];
            printf("    { \"destination\": \"%s\", \"interface\": \"%s\", \"table\": %u", r->dst, entry->name, r->table);
            if (r->gw[0]) printf(", \"gateway\": \"%s\"", r->gw);
            if (r->metric > 0) printf(", \"metric\": %u", r->metric);
            printf(" }");
            first = false;
        }
    }
    printf("\n  ]\n}\n");
}

void cmd_get_value(char *key) {
    collect_network_state();
    char *segment = strtok(key, ".");
    
    if (segment && strcmp(segment, "hostname") == 0) { char hostname[256] = DEFAULT_HOSTNAME; gethostname(hostname, sizeof(hostname)); printf("%s\n", hostname); return; }
    
    if (!segment || strcmp(segment, "interfaces") != 0) return;
    char *ifname = strtok(NULL, "."); if (!ifname) return;
    
    iface_entry_t *iface = NULL;
    for (size_t i = 0; i < ifaces_count; i++) { 
        if (ifaces[i]->exists && strcmp(ifaces[i]->name, ifname) == 0) { 
            iface = ifaces[i]; 
            break; 
        } 
    }
    if (!iface) return;
    
    char *field = strtok(NULL, "."); if (!field) return;
    
    if (strcmp(field, "ip") == 0) {
        if (iface->ipv4_count > 0) printf("%s\n", iface->ipv4[0]);
    }
    else if (strcmp(field, "mac") == 0) printf("%s\n", iface->mac);
    else if (strcmp(field, "state") == 0) printf("%s\n", iface->state);
    else if (strcmp(field, "gateway") == 0) printf("%s\n", iface->gateway);
    else if (strcmp(field, "type") == 0) printf("%s\n", detect_iface_type(iface));
    else if (strcmp(field, "vendor") == 0) printf("%s\n", iface->vendor);
    else if (strcmp(field, "wifi") == 0) {
        char *sub = strtok(NULL, ".");
        if (sub) {
            if (strcmp(sub, "ssid") == 0) printf("%s\n", iface->ssid);
            else if (strcmp(sub, "bssid") == 0) printf("%s\n", iface->bssid);
            else if (strcmp(sub, "rssi") == 0) printf("%d\n", iface->signal_dbm);
            else if (strcmp(sub, "frequency") == 0) printf("%u\n", iface->frequency);
        }
    }
}

void write_sysctl(const char *path, const char *value) {
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s", value);
        fclose(f);
    }
}

void cmd_tune(char *profile) {
    write_sysctl("/proc/sys/net/netfilter/nf_conntrack_max", "16384");
    write_sysctl("/proc/sys/net/ipv4/tcp_fastopen", "3");
    write_sysctl("/proc/sys/net/ipv4/tcp_keepalive_time", "300");
    
    if (access("/proc/sys/net/bridge", F_OK) == 0) {
        write_sysctl("/proc/sys/net/bridge/bridge-nf-call-iptables", "0");
        write_sysctl("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "0");
        write_sysctl("/proc/sys/net/bridge/bridge-nf-call-arptables", "0");
    }
    
    if (profile && strcmp(profile, "host") == 0) {
        write_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
        write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "1");
        write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
        write_sysctl("/proc/sys/net/ipv4/ip_local_port_range", "1024 65535");
    } else {
        write_sysctl("/proc/sys/net/ipv4/ip_forward", "1");
        write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "1");
        write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1");
    }
    
    printf("{\"success\": true, \"action\": \"tune\", \"profile\": \"%s\"}\n", profile ? profile : "client");
}

/* --- XDP/eBPF Logic --- */

int load_xdp_drop_prog(bool soft_wol) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_XDP;
    
    if (soft_wol) {
        attr.insn_cnt = sizeof(xdp_soft_wol_prog) / sizeof(struct bpf_insn);
        attr.insns = (__aligned_u64)(uintptr_t)xdp_soft_wol_prog;
    } else {
        attr.insn_cnt = sizeof(xdp_drop_prog) / sizeof(struct bpf_insn);
        attr.insns = (__aligned_u64)(uintptr_t)xdp_drop_prog;
    }
    
    /* Use uintptr_t to prevent truncation on 32-bit architectures */
    attr.license = (__aligned_u64)(uintptr_t)"GPL";
    
    /* Try without verifier log first to avoid unnecessary kernel strings and save stack space */
    attr.log_level = 0;
    
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        /* Failed, retry with a large heap-allocated log buffer to provide debug info */
        char *log_buf = calloc(1, 16384);
        if (log_buf) {
            attr.log_buf = (__aligned_u64)(uintptr_t)log_buf;
            attr.log_size = 16384;
            attr.log_level = 1;
            fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
            if (fd < 0) {
                fprintf(stderr, "BPF_PROG_LOAD failed: %s\nVerifier log:\n%s\n", strerror(errno), log_buf);
            }
            free(log_buf);
        } else {
             fprintf(stderr, "BPF_PROG_LOAD failed: %s\n", strerror(errno));
        }
    }
    return fd;
}

int attach_xdp_prog(int ifindex, int fd, int flags) {
    int sock = open_netlink_rt();
    if (sock < 0) return -1;
    
    struct {
        struct nlmsghdr n;
        struct ifinfomsg i;
        char buf[1024];
    } req;
    
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.n.nlmsg_type = RTM_SETLINK;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_seq = time(NULL);
    req.i.ifi_family = AF_UNSPEC;
    req.i.ifi_index = ifindex;
    
    /* Use bounds-checked attribute helper to construct nested IFLA_XDP */
    /* Note: NLA_F_NESTED requires a parent attribute to encapsulate the children */
    
    /* We temporarily store the nested attributes in a scratch buffer before appending the parent */
    char nested_buf[256];
    struct nlmsghdr *nested_dummy = (struct nlmsghdr *)nested_buf;
    memset(nested_dummy, 0, sizeof(*nested_dummy));
    nested_dummy->nlmsg_len = NLMSG_LENGTH(0);
    
    if (!add_nl_attr(nested_dummy, sizeof(nested_buf), IFLA_XDP_FD, &fd, sizeof(int))) {
        close(sock); return -1; 
    }
    
    if (flags != 0) {
        if (!add_nl_attr(nested_dummy, sizeof(nested_buf), IFLA_XDP_FLAGS, &flags, sizeof(int))) {
            close(sock); return -1;
        }
    }
    
    int nested_payload_len = nested_dummy->nlmsg_len - NLMSG_LENGTH(0);
    
    if (!add_nl_attr(&req.n, sizeof(req), IFLA_XDP | NLA_F_NESTED, (char*)nested_dummy + NLMSG_LENGTH(0), nested_payload_len)) {
        close(sock);
        return -1;
    }
    
    if (send(sock, &req, req.n.nlmsg_len, 0) < 0) {
        close(sock);
        return -1;
    }
    
    // Read ACK
    char buf[1024];
    int len = recv(sock, buf, sizeof(buf), 0);
    close(sock);
    
    if (len > 0) {
        struct nlmsghdr *nh = (struct nlmsghdr *)buf;
        if (nh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
            if (err->error != 0) return err->error;
        }
    }
    
    return 0;
}

/**
 * @brief Toggles 802.11 Power Save Mode (PSM) via Netlink
 * Used as stateless back-pressure to force the AP to buffer broadcast noise,
 * protecting weak SDIO buses during XDP generic drops.
 */
void set_wifi_power_save(int ifindex, bool enable) {
    int sock = open_netlink_genl();
    if (sock < 0) return;
    int fid = get_genl_family_id(sock, NL80211_GENL_NAME);
    if (fid <= 0) { close(sock); return; }

    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[64];
    } req;
    
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type = fid;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.g.cmd = NL80211_CMD_SET_POWER_SAVE;
    req.g.version = 1;

    uint32_t ps_state = enable ? NL80211_PS_ENABLED : NL80211_PS_DISABLED;
    add_nl_attr(&req.n, sizeof(req), NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
    add_nl_attr(&req.n, sizeof(req), NL80211_ATTR_PS_STATE, &ps_state, sizeof(ps_state));

    send(sock, &req, req.n.nlmsg_len, 0);
    
    char buf[1024];
    recv(sock, buf, sizeof(buf), 0); // Consume ACK to ensure transaction completes
    close(sock);
}

/**
 * @brief Instantly flushes the driver's RX ring buffer
 * Toggles the IFF_UP flag synchronously to un-wedge stalled DMA engines.
 */
void atomic_driver_kick(const char *ifname) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
        int orig_flags = ifr.ifr_flags;
        /* Only kick if it's actually UP */
        if (orig_flags & IFF_UP) {
            ifr.ifr_flags &= ~IFF_UP;
            ioctl(sock, SIOCSIFFLAGS, &ifr); // Bring DOWN

            ifr.ifr_flags = orig_flags;
            ioctl(sock, SIOCSIFFLAGS, &ifr); // Bring UP
        }
    }
    close(sock);
}

void cmd_nullify_xdp(char *iface, char *action) {
    if (!iface || !action) {
        fprintf(stderr, "Usage: --nullify-xdp <iface> <enable|enable-swol|disable>\n");
        exit(1);
    }
    
    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", iface);
        exit(1);
    }
    
    /* Ensure BPF eBPF bytecode limits are explicitly raised for older kernels/constrained envs */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);
    
    if (strncmp(action, "enable", 6) == 0) {
        bool soft_wol = (strcmp(action, "enable-swol") == 0);
        int fd = load_xdp_drop_prog(soft_wol);
        if (fd < 0) {
            // Already prints to stderr in load_xdp_drop_prog
            exit(1);
        }
        
        /* Mitigation 5.1: Protocol-Level Flow Control (Stateless Back-Pressure)
         * Force WiFi into Power Save Mode to tell the AP to buffer broadcast traffic.
         * This prevents SDIO bus saturation when dropping packets in SKB mode.
         */
        set_wifi_power_save(ifindex, true);
        
        // Try Native (Driver) Mode first (default 0)
        int err = attach_xdp_prog(ifindex, fd, 0);
        if (err != 0) {
            // Fallback to SKB (Generic) Mode
            err = attach_xdp_prog(ifindex, fd, XDP_FLAGS_SKB_MODE);
        }
        
        // Close FD (Kernel holds reference via attachment)
        close(fd);
        
        if (err != 0) {
            fprintf(stderr, "Failed to attach XDP: %s\n", strerror(-err));
            exit(1);
        }
        printf("{\"success\": true, \"action\": \"xdp_drop\", \"status\": \"%s\", \"iface\": \"%s\"}\n", soft_wol ? "enabled-swol" : "enabled", iface);
        
    } else if (strcmp(action, "disable") == 0) {
        // Attach FD -1 to detach
        int err = attach_xdp_prog(ifindex, -1, 0);
        if (err != 0) {
             err = attach_xdp_prog(ifindex, -1, XDP_FLAGS_SKB_MODE);
        }
        
        if (err != 0) {
            fprintf(stderr, "Warning: Failed to detach XDP (may not be attached): %s\n", strerror(-err));
            // Do not exit fatally on disable; allow partial cleanups to proceed.
        }
        
        /* Mitigation 5.1: The "Atomic Kick"
         * Reset the driver's RX ring buffer pointers and disable PSM.
         * This instantaneously un-wedges stalled budget SDIO MACs without dropping the carrier.
         */
        set_wifi_power_save(ifindex, false);
        atomic_driver_kick(iface);
        
        printf("{\"success\": true, \"action\": \"xdp_drop\", \"status\": \"disabled\", \"iface\": \"%s\"}\n", iface);
    }
}

/**
 * @brief Atomically writes stdin to a file using dynamic re-allocation.
 */
int cmd_atomic_write(char *path, char *perm_str) {
    size_t capacity = 65536; // Start with 64KB
    size_t total_len = 0;
    char *buf = malloc(capacity);
    if (!buf) {
        fprintf(stderr, "OOM allocating atomic buffer\n");
        return 1;
    }

    while (1) {
        size_t bytes_read = fread(buf + total_len, 1, capacity - total_len, stdin);
        total_len += bytes_read;

        if (feof(stdin)) break;

        if (ferror(stdin)) {
            fprintf(stderr, "Error reading stdin\n");
            free(buf);
            return 1;
        }

        if (total_len == capacity) {
            capacity *= 2;
            char *new_buf = realloc(buf, capacity);
            if (!new_buf) {
                fprintf(stderr, "OOM expanding atomic buffer\n");
                free(buf);
                return 1;
            }
            buf = new_buf;
        }
    }

    bool changed = true;
    struct stat st;
    if (stat(path, &st) == 0 && (size_t)st.st_size == total_len) {
        FILE *f = fopen(path, "r");
        if (f) {
            changed = false;
            size_t offset = 0;
            char chunk[8192];
            while (offset < total_len) {
                size_t to_read = (total_len - offset > sizeof(chunk)) ? sizeof(chunk) : (total_len - offset);
                if (fread(chunk, 1, to_read, f) != to_read) {
                    changed = true;
                    break;
                }
                if (memcmp(buf + offset, chunk, to_read) != 0) {
                    changed = true;
                    break;
                }
                offset += to_read;
            }
            fclose(f);
        }
    }

    if (!changed) {
        free(buf);
        return 0;
    }

    /* Mitigate predictable temp file symlink races by using mkstemp.
     * Note: This prevents TOCTOU on the filename itself, though the narrow permissions
     * window between mkstemp() and fchmod() remains the same as open(O_CREAT). */
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", path);

    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        fprintf(stderr, "Error creating secure temp file\n");
        free(buf);
        return 1;
    }

    size_t written = 0;
    while (written < total_len) {
        ssize_t w = write(fd, buf + written, total_len - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Error writing to temp file\n");
            close(fd);
            unlink(tmp_path);
            free(buf);
            return 1;
        }
        written += w;
    }

    if (perm_str) {
        int mode = strtol(perm_str, NULL, 8);
        fchmod(fd, mode);
    }

    fsync(fd);
    close(fd);

    if (rename(tmp_path, path) != 0) {
         fprintf(stderr, "Error renaming temp file\n");
         unlink(tmp_path);
         free(buf);
         return 1;
    }
    
    free(buf);
    return 0;
}

/**
 * @brief Appends a line to a file safely using dynamically expanding file buffer.
 */
int cmd_append_config(char *path, char *line) {
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        fprintf(stderr, "Error opening config file\n");
        return 1;
    }
    
    if (flock(fd, LOCK_EX) != 0) {
        fprintf(stderr, "Failed to lock file\n");
        close(fd);
        return 1;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }
    
    size_t file_size = st.st_size;
    char *file_buf = malloc(file_size + 1);
    if (!file_buf) {
        fprintf(stderr, "OOM allocating append buffer\n");
        /* Prevent FD lock leakage on OOM */
        flock(fd, LOCK_UN);
        close(fd);
        return 1;
    }
    
    ssize_t total_read = 0;
    while (total_read < (ssize_t)file_size) {
        ssize_t read_len = read(fd, file_buf + total_read, file_size - total_read);
        if (read_len <= 0) break;
        total_read += read_len;
    }
    file_buf[total_read] = '\0';
    
    bool found = false;
    if (strstr(file_buf, line)) {
        found = true;
    }
    free(file_buf);
    
    if (!found) {
        lseek(fd, 0, SEEK_END);
        if (write(fd, line, strlen(line)) < 0) {
            fprintf(stderr, "Error appending to file\n");
        }
        if (write(fd, "\n", 1) < 0) {
            fprintf(stderr, "Error appending newline\n");
        }
        fsync(fd);
    }
    
    flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

static void trigger_roaming_event(const char *iface) {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("rxnm", "rxnm", "wifi", "roaming", "trigger", iface, NULL);
        execlp("/usr/bin/rxnm", "rxnm", "wifi", "roaming", "trigger", iface, NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        while (waitpid(pid, &status, 0) == -1) {
            if (errno != EINTR) break; 
        }
    }
}

void cmd_monitor_roam(char *iface, char *threshold_str) {
    (void)threshold_str;
    int sock = open_netlink_rt();
    if (sock < 0) exit(1);
    
    struct timespec last_trigger = {0, 0};
    unsigned int last_flags = 0;
    
    /* Initialize last_flags to prevent spurious triggers on already-up interfaces */
    int io_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (io_sock >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(io_sock, SIOCGIFFLAGS, &ifr) == 0) {
            last_flags = ifr.ifr_flags;
        }
        close(io_sock);
    }
    
    while (1) {
        char buf[4096];
        int len = recv(sock, buf, sizeof(buf), 0);
        
        /* Robust Recv Error Handling */
        if (len < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Netlink socket error, reconnecting...\n");
            sleep(5);
            close(sock);
            sock = open_netlink_rt();
            if (sock < 0) exit(1);
            continue;
        }
        
        if (len > 0) {
            struct nlmsghdr *nh = (struct nlmsghdr *)buf;
            for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
                if (nh->nlmsg_type == RTM_NEWLINK) {
                    struct ifinfomsg *ifi = NLMSG_DATA(nh);
                    struct rtattr *tb[IFLA_MAX + 1];
                    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
                    
                    if (tb[IFLA_IFNAME]) {
                        char *name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
                        if (strcmp(name, iface) == 0) {
                            
                            /* Transition monitoring + Debounce */
                            unsigned int current_flags = ifi->ifi_flags;
                            bool is_running = (current_flags & IFF_RUNNING) && (current_flags & IFF_LOWER_UP);
                            bool was_running = (last_flags & IFF_RUNNING) && (last_flags & IFF_LOWER_UP);
                            
                            last_flags = current_flags;
                            
                            /* Only trigger on state change to running (Carrier UP) */
                            if (is_running && !was_running) {
                                struct timespec now;
                                clock_gettime(CLOCK_MONOTONIC, &now);
                                
                                long delta = now.tv_sec - last_trigger.tv_sec;
                                if (delta >= 5) { /* 5s mechanical debounce */
                                    last_trigger = now;
                                    trigger_roaming_event(iface);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    close(sock);
}

/* --- Namespace Management (Accelerated) --- */

void cmd_ns_list() {
    DIR *d = opendir(NETNS_RUN_DIR);
    if (!d) {
        printf("{\"services\": []}\n");
        return;
    }
    
    printf("{\"services\": [");
    bool first = true;
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) continue;
        if (!first) printf(", ");
        /* Escape namespace JSON arrays */
        print_escaped_string(dir->d_name);
        first = false;
    }
    printf("]}\n");
    closedir(d);
}

int cmd_ns_create(const char *name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, name);
    
    /* Ensure directory exists */
    mkdir(NETNS_RUN_DIR, 0755);
    
    /* Create mount point file */
    int fd = open(path, O_RDONLY | O_CREAT | O_EXCL, 0000);
    if (fd < 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "Namespace '%s' already exists\n", name);
            return 1;
        }
        perror("open");
        return 1;
    }
    close(fd);
    
    /* Unshare network namespace in child to protect parent process state */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        unlink(path);
        return 1;
    }
    
    if (pid == 0) {
        if (unshare(CLONE_NEWNET) < 0) {
            perror("unshare");
            exit(1);
        }
        
        /* Bind mount new namespace to file */
        if (mount("/proc/self/ns/net", path, "none", MS_BIND, NULL) < 0) {
            perror("mount");
            exit(1);
        }
        exit(0);
    }
    
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        unlink(path);
        return 1;
    }
    
    return 0;
}

int cmd_ns_delete(const char *name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, name);
    
    if (umount2(path, MNT_DETACH) < 0) {
        if (errno != EINVAL && errno != ENOENT) {
            perror("umount");
            return 1;
        }
    }
    
    if (unlink(path) < 0) {
        if (errno != ENOENT) {
            perror("unlink");
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Executes a command inside a named network namespace.
 * Replaces the need for 'ip netns exec'.
 */
int cmd_ns_exec(const char *name, int argc, char **argv) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", NETNS_RUN_DIR, name);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open netns");
        return 1;
    }
    
    if (setns(fd, CLONE_NEWNET) < 0) {
        perror("setns");
        close(fd);
        return 1;
    }
    close(fd);
    
    if (argc > 0) {
        execvp(argv[0], argv);
        perror("execvp");
        return 1;
    }
    
    return 0;
}

/**
 * @brief Tests whether a string matches an extended POSIX regex.
 * @param str   The string to test.
 * @param pat   The extended regex pattern (ERE).
 * @return 0 on match, 1 on no-match, 2 on regex compile error.
 */
int cmd_match(const char *str, const char *pat) {
    regex_t re;
    int ret;

    ret = regcomp(&re, pat, REG_EXTENDED | REG_NOSUB);
    if (ret != 0) {
        char errbuf[256];
        regerror(ret, &re, errbuf, sizeof(errbuf));
        fprintf(stderr, "rxnm-agent --match: invalid pattern: %s\n", errbuf);
        return 2;
    }

    ret = regexec(&re, str, 0, NULL, 0);
    regfree(&re);
    return (ret == 0) ? 0 : 1;
}

/**
 * @brief Encodes an SSID strictly matching IWD's hex-encoding parity scheme.
 * Replaces non-alphanumeric characters with '=XX'
 */
void cmd_encode_ssid(const char *ssid) {
    if (!ssid) return;
    for (int i = 0; ssid[i] != '\0'; i++) {
        unsigned char c = (unsigned char)ssid[i];
        if (isalnum(c) || c == '_' || c == '.' || c == '-') {
            putchar(c);
        } else {
            printf("=%02x", c);
        }
    }
    putchar('\n');
}

void cmd_version() { printf("rxnm-agent %s\n", g_agent_version); }
void cmd_health() { printf("{\"%s\": true, \"agent\": \"active\", \"version\": \"%s\"}\n", KEY_SUCCESS, g_agent_version); }
void cmd_time() { struct timespec ts; if (clock_gettime(CLOCK_REALTIME, &ts) == 0) printf("%ld\n", ts.tv_sec); else exit(1); }

void cmd_is_low_power() {
    const char *socs[] = LOW_POWER_SOCS;
    bool is_lp = false;
    if (socs[0] != NULL) {
        for (int i = 0; socs[i] != NULL; i++) {
            if (file_contains("/proc/cpuinfo", socs[i])) { 
                is_lp = true; 
                break; 
            }
        }
    }
    printf("%s\n", is_lp ? "true" : "false");
}

/* CLI Globals */
char *g_atomic_path = NULL;
char *g_perm_str = NULL;
char *g_append_path = NULL;
char *g_append_line = NULL;
char *g_monitor_iface = NULL;
char *g_monitor_thresh = NULL;
char *g_connect_ssid = NULL;
char *g_connect_iface = NULL;
char *g_nullify_cmd = NULL;
char *g_nullify_xdp_iface = NULL;
char *g_nullify_xdp_action = NULL;
char *g_ns_create = NULL;
char *g_ns_delete = NULL;
char *g_ns_exec_name = NULL;
char *g_route_table = NULL;

int main(int argc, char *argv[]) {
    atexit(cleanup_ifaces);
    apply_env_overrides();
    
    static struct option long_options[] = {
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"health",  no_argument, 0, 'H'},
        {"time",    no_argument, 0, 't'},
        {"is-low-power", no_argument, 0, 'L'},
        {"dump",    no_argument, 0, 'd'},
        {"check-internet", no_argument, 0, 'c'},
        {"reload",  no_argument, 0, 'r'},
        {"connect", required_argument, 0, 'C'},
        {"iface", required_argument, 0, 'i'},
        {"get",     required_argument, 0, 'g'},
        {"atomic-write", required_argument, 0, 'W'},
        {"perm",    required_argument, 0, 'P'},
        {"tune", required_argument, 0, 'T'},
        {"append-config", required_argument, 0, 'A'},
        {"line", required_argument, 0, 'l'},
        {"monitor-roam", required_argument, 0, 'M'},
        {"threshold", required_argument, 0, 'S'},
        {"nullify", required_argument, 0, 'N'},
        {"nullify-xdp", required_argument, 0, 'X'},
        {"encode-ssid", required_argument, 0, 'E'},
        {"ns-create", required_argument, 0, 1001},
        {"ns-delete", required_argument, 0, 1002},
        {"ns-list", no_argument, 0, 1003},
        {"route-dump", required_argument, 0, 1004},
        {"ns-exec", required_argument, 0, 1005},
        {"match", required_argument, 0, 1006},
        {0, 0, 0, 0}
    };
    
    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "vhHtdLcrC:i:g:W:P:T:A:l:M:S:N:X:E:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v': cmd_version(); return 0;
            case 'h': printf("Usage: rxnm-agent [options]\n--dump  Full JSON status\n--ns-create <name> Create namespace\n--route-dump <table_id> Dump routing table\n--nullify-xdp <iface>\n"); return 0;
            case 'H': cmd_health(); return 0;
            case 't': cmd_time(); return 0;
            case 'L': cmd_is_low_power(); return 0;
            case 'd': collect_network_state(); print_json_status(); return 0;
            case 'c': cmd_check_internet(); return 0;
            case 'r': return dbus_trigger_reload();
            case 'g': cmd_get_value(optarg); return 0;
            case 'T': cmd_tune(optarg); return 0;
            case 'W': g_atomic_path = optarg; break;
            case 'P': g_perm_str = optarg; break;
            case 'A': g_append_path = optarg; break;
            case 'l': g_append_line = optarg; break;
            case 'M': g_monitor_iface = optarg; break;
            case 'S': g_monitor_thresh = optarg; break;
            case 'C': g_connect_ssid = optarg; break;
            case 'i': g_connect_iface = optarg; break;
            case 'N': g_nullify_cmd = optarg; break;
            case 'X': g_nullify_xdp_iface = optarg; break;
            case 'E': cmd_encode_ssid(optarg); return 0;
            case 1001: g_ns_create = optarg; break;
            case 1002: g_ns_delete = optarg; break;
            case 1003: cmd_ns_list(); return 0;
            case 1004: g_route_table = optarg; break;
            case 1005: 
                g_ns_exec_name = optarg;
                // Stop option parsing here to pass remaining args to execvp
                goto end_args;
            case 1006:
                if (optind < argc) {
                    return cmd_match(optarg, argv[optind]);
                } else {
                    fprintf(stderr, "Usage: rxnm-agent --match <string> <pattern>\n");
                    return 1;
                }
            default: return 1;
        }
    }

end_args:
    // Handle ns-exec immediately if invoked
    if (g_ns_exec_name) {
        // optind points to the next argument after --ns-exec <name>
        return cmd_ns_exec(g_ns_exec_name, argc - optind, argv + optind);
    }
    
    // XDP Command: requires --nullify-xdp <iface> AND a following "enable/enable-swol/disable"
    if (g_nullify_xdp_iface) {
        // Look for next arg as action
        if (optind < argc) {
            cmd_nullify_xdp(g_nullify_xdp_iface, argv[optind]);
            return 0;
        } else {
            fprintf(stderr, "Missing action for --nullify-xdp (enable|enable-swol|disable)\n");
            return 1;
        }
    }
    
    if (g_atomic_path) { return cmd_atomic_write(g_atomic_path, g_perm_str); }
    if (g_append_path && g_append_line) { return cmd_append_config(g_append_path, g_append_line); }
    if (g_monitor_iface) { cmd_monitor_roam(g_monitor_iface, g_monitor_thresh); return 0; }
    if (g_connect_ssid) { return cmd_connect(g_connect_ssid, g_connect_iface); }
    if (g_nullify_cmd) { 
        fprintf(stderr, "Legacy nullify not supported. Use --nullify-xdp\n");
        return 1;
    }
    if (g_ns_create) { return cmd_ns_create(g_ns_create); }
    if (g_ns_delete) { return cmd_ns_delete(g_ns_delete); }
    if (g_route_table) {
        char *endp;
        long tbl = strtol(g_route_table, &endp, 10);
        if (*endp != '\0' || tbl < 0 || tbl > UINT32_MAX) {
            fprintf(stderr, "Invalid route table ID: %s\n", g_route_table);
            return 1;
        }
        g_target_table = (uint32_t)tbl;
        g_filter_table = true;
        collect_network_state();
        print_json_routes();
        return 0;
    }

    if (optind == 1) { collect_network_state(); print_json_status(); return 0; }
    return 1;
}
