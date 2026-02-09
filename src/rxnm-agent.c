/*
 * RXNM Agent - Native Fastpath Component
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase 2: Core Network Status (Netlink)
 * - Direct Kernel Netlink (RTNETLINK) integration
 * - Zero-dependency JSON generation
 * - Replaces 'networkctl status' overhead
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
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>

// Include generated SSoT constants
#include "rxnm_generated.h"

#define AGENT_VERSION "0.2.0-phase2"
#define BUF_SIZE 8192

// --- DATA STRUCTURES ---
// Minimal structure to hold interface state during Netlink dump
typedef struct {
    int index;
    char name[IFNAMSIZ];
    char mac[18];
    char ipv4[INET_ADDRSTRLEN];
    char ipv6[INET6_ADDRSTRLEN]; // Only holding first IPv6 for simplified status
    char state[16];
    int mtu;
    bool exists;
} iface_entry_t;

// Simple fixed-size map for constrained devices (max 16 interfaces usually enough for handhelds)
#define MAX_IFACES 32
iface_entry_t ifaces[MAX_IFACES];

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

iface_entry_t* get_iface(int index) {
    for (int i = 0; i < MAX_IFACES; i++) {
        if (ifaces[i].exists && ifaces[i].index == index) return &ifaces[i];
    }
    // Create new
    for (int i = 0; i < MAX_IFACES; i++) {
        if (!ifaces[i].exists) {
            ifaces[i].exists = true;
            ifaces[i].index = index;
            // Defaults
            strcpy(ifaces[i].state, "unknown");
            return &ifaces[i];
        }
    }
    return NULL; // Full
}

// --- NETLINK ENGINE ---

int open_netlink() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    return sock;
}

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

void process_link_msg(struct nlmsghdr *nh) {
    struct ifinfomsg *ifi = NLMSG_DATA(nh);
    struct rtattr *tb[IFLA_MAX + 1];
    
    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
    
    iface_entry_t *entry = get_iface(ifi->ifi_index);
    if (!entry) return;

    if (tb[IFLA_IFNAME]) {
        strncpy(entry->name, (char *)RTA_DATA(tb[IFLA_IFNAME]), IFNAMSIZ - 1);
    }
    
    if (tb[IFLA_ADDRESS]) {
        unsigned char *mac = (unsigned char *)RTA_DATA(tb[IFLA_ADDRESS]);
        snprintf(entry->mac, sizeof(entry->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    entry->mtu = ifi->ifi_mtu; // Can also use IFLA_MTU

    // Map Kernel Flags to Systemd-like State
    // IFF_UP (0x1) && IFF_RUNNING (0x40)
    if ((ifi->ifi_flags & IFF_UP) && (ifi->ifi_flags & IFF_RUNNING)) {
        strcpy(entry->state, "routable"); // Simplified mapping for UI
    } else if (ifi->ifi_flags & IFF_UP) {
        strcpy(entry->state, "no-carrier");
    } else {
        strcpy(entry->state, "off");
    }
}

void process_addr_msg(struct nlmsghdr *nh) {
    struct ifaddrmsg *ifa = NLMSG_DATA(nh);
    struct rtattr *tb[IFA_MAX + 1];
    
    parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
    
    iface_entry_t *entry = get_iface(ifa->ifa_index);
    if (!entry) return;

    if (tb[IFA_ADDRESS]) {
        void *addr_ptr = RTA_DATA(tb[IFA_ADDRESS]);
        if (ifa->ifa_family == AF_INET) {
            inet_ntop(AF_INET, addr_ptr, entry->ipv4, INET_ADDRSTRLEN);
        } else if (ifa->ifa_family == AF_INET6) {
            // Only capture global scope or unique local, skip link-local fe80:: for brevity if desired
            // For now, capture first found
            if (entry->ipv6[0] == '\0') { 
                inet_ntop(AF_INET6, addr_ptr, entry->ipv6, INET6_ADDRSTRLEN);
            }
        }
    }
}

void send_dump_request(int sock, int type) {
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg rtg;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.nlh.nlmsg_type = type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = time(NULL);
    req.rtg.rtgen_family = AF_PACKET; // AF_PACKET for links, or AF_UNSPEC

    send(sock, &req, req.nlh.nlmsg_len, 0);
}

void read_netlink_response(int sock) {
    char buf[BUF_SIZE];
    int len;

    while ((len = recv(sock, buf, sizeof(buf), 0)) > 0) {
        struct nlmsghdr *nh = (struct nlmsghdr *)buf;
        
        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) return;
            if (nh->nlmsg_type == NLMSG_ERROR) return;

            if (nh->nlmsg_type == RTM_NEWLINK) {
                process_link_msg(nh);
            } else if (nh->nlmsg_type == RTM_NEWADDR) {
                process_addr_msg(nh);
            }
        }
    }
}

void collect_network_state() {
    int sock = open_netlink();
    if (sock < 0) return;

    // 1. Dump Links
    send_dump_request(sock, RTM_GETLINK);
    read_netlink_response(sock);

    // 2. Dump Addresses
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req_addr;
    memset(&req_addr, 0, sizeof(req_addr));
    req_addr.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req_addr.nlh.nlmsg_type = RTM_GETADDR;
    req_addr.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req_addr.nlh.nlmsg_seq = 1;
    req_addr.ifa.ifa_family = AF_UNSPEC; // All families
    
    send(sock, &req_addr, req_addr.nlh.nlmsg_len, 0);
    read_netlink_response(sock);

    close(sock);
}

// --- JSON GENERATION (Simple Printer) ---

void print_json_status() {
    printf("{\n");
    printf("  \"%s\": true,\n", KEY_SUCCESS);
    printf("  \"agent_version\": \"%s\",\n", AGENT_VERSION);
    printf("  \"interfaces\": {\n");

    bool first = true;
    for (int i = 0; i < MAX_IFACES; i++) {
        if (!ifaces[i].exists) continue;
        
        if (!first) printf(",\n");
        printf("    \"%s\": {\n", ifaces[i].name);
        printf("      \"name\": \"%s\",\n", ifaces[i].name);
        printf("      \"state\": \"%s\",\n", ifaces[i].state);
        printf("      \"mtu\": %d,\n", ifaces[i].mtu);
        if (strlen(ifaces[i].mac) > 0) 
            printf("      \"mac\": \"%s\",\n", ifaces[i].mac);
        if (strlen(ifaces[i].ipv4) > 0) 
            printf("      \"ip\": \"%s\",\n", ifaces[i].ipv4);
        if (strlen(ifaces[i].ipv6) > 0)
            printf("      \"ipv6\": [\"%s\"],\n", ifaces[i].ipv6);
        
        // Basic Type Inference
        const char *type = "unknown";
        if (strncmp(ifaces[i].name, "wl", 2) == 0) type = "wifi";
        else if (strncmp(ifaces[i].name, "et", 2) == 0) type = "ethernet";
        else if (strncmp(ifaces[i].name, "en", 2) == 0) type = "ethernet";
        else if (strncmp(ifaces[i].name, "br", 2) == 0) type = "bridge";
        else if (strncmp(ifaces[i].name, "lo", 2) == 0) type = "loopback";
        else if (strncmp(ifaces[i].name, "usb", 3) == 0) type = "gadget";
        else if (strncmp(ifaces[i].name, "tun", 3) == 0) type = "tun";
        else if (strncmp(ifaces[i].name, "wg", 2) == 0) type = "wireguard";
        
        printf("      \"type\": \"%s\",\n", type);
        
        // Connected Logic (Simplified)
        bool connected = (strcmp(ifaces[i].state, "routable") == 0);
        printf("      \"connected\": %s\n", connected ? "true" : "false");
        
        printf("    }");
        first = false;
    }
    printf("\n  }\n");
    printf("}\n");
}

// --- COMMAND HANDLERS ---

void cmd_version() {
    printf("rxnm-agent %s\n", AGENT_VERSION);
    printf("ConfDir: %s\n", CONF_DIR);
    printf("RunDir:  %s\n", RUN_DIR);
}

void cmd_health() {
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

void cmd_is_low_power() {
    const char *cpuinfo = "/proc/cpuinfo";
    // List from rxnm-constants.sh logic (replicated)
    const char *socs[] = {
        "RK3326", "RK3566", "RK3128", "RK3036", "RK3288",
        "H700", "H616", "H3", "H5", "H6", "A64", "A133", "A33", "sunxi",
        "BCM2835", "BCM2836", "BCM2837", "ATM7051", "S905", "S805", 
        "Meson", "X1830", "JZ4770", "riscv", "mips", "avr", "xtensa", 
        "tensilica", "loongson", "loongarch", "Atom", "Geode", NULL
    };

    bool is_lp = false;
    for (int i = 0; socs[i] != NULL; i++) {
        if (file_contains(cpuinfo, socs[i])) {
            is_lp = true;
            break;
        }
    }
    printf("%s\n", is_lp ? "true" : "false");
}

void cmd_dump_status() {
    // 1. Gather Data (Netlink)
    collect_network_state();
    
    // 2. Output JSON
    print_json_status();
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
            case 'v': cmd_version(); return 0;
            case 'h': 
                printf("Usage: rxnm-agent [options]\n--dump  Full JSON status\n"); 
                return 0;
            case 'H': cmd_health(); return 0;
            case 't': cmd_time(); return 0;
            case 'L': cmd_is_low_power(); return 0;
            case 'd': cmd_dump_status(); return 0;
            default: return 1;
        }
    }
    // Default to help if no args
    if (optind < argc) { fprintf(stderr, "Unknown arg\n"); return 1; }
    printf("rxnm-agent: Use --help\n");
    return 1;
}
