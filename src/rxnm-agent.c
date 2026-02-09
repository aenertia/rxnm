/*
 * RXNM Agent - Native Fastpath Component
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Phase 2: Core Network Status (Netlink)
 * Phase 4: Connectivity Probing (TCP)
 * Phase 5: Runtime Configuration Sync
 * - Direct Kernel Netlink (RTNETLINK) integration
 * - Zero-dependency JSON generation
 * - Raw TCP WAN Probing
 * - Live parsing of Bash constants for hot-patching
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
#include <sys/select.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>

// Include generated SSoT constants
#include "rxnm_generated.h"

// Fallbacks if header generation fails (Safety)
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

// --- RUNTIME CONFIGURATION ---
// These default to compile-time constants but can be overridden by parsing the bash script at runtime.
char g_conf_dir[PATH_MAX] = CONF_DIR;
char g_run_dir[PATH_MAX] = RUN_DIR;
char g_agent_version[64] = RXNM_VERSION;
char g_conn_targets_v4[256] = RXNM_PROBE_TARGETS_V4;
char g_conn_targets_v6[512] = RXNM_PROBE_TARGETS_V6;

#define BUF_SIZE 8192
#define MAX_IPV6_PER_IFACE 8
#define MAX_ROUTES_PER_IFACE 16

// Buffer sizes with room for CIDR suffix (e.g. "/24" or "/128")
#define IPV4_CIDR_LEN (INET_ADDRSTRLEN + 4)
#define IPV6_CIDR_LEN (INET6_ADDRSTRLEN + 5)

// --- DATA STRUCTURES ---

typedef struct {
    char dst[IPV6_CIDR_LEN]; // "default" or "10.0.0.0/8"
    char gw[INET6_ADDRSTRLEN];
    uint32_t metric;
    bool is_default;
} route_entry_t;

// Minimal structure to hold interface state during Netlink dump
typedef struct {
    int index;
    int master_index; // For bridge membership (IFLA_MASTER)
    char name[IFNAMSIZ];
    char mac[18];
    char ipv4[IPV4_CIDR_LEN];
    char ipv6[MAX_IPV6_PER_IFACE][IPV6_CIDR_LEN]; 
    int ipv6_count;
    
    // Routing Info
    char gateway[INET6_ADDRSTRLEN]; // Primary default gateway
    uint32_t metric;                // Primary metric (of default route)
    route_entry_t routes[MAX_ROUTES_PER_IFACE];
    int route_count;

    char state[16];
    int mtu;
    bool exists;
} iface_entry_t;

// Simple fixed-size map for constrained devices (max 32 interfaces)
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
            ifaces[i].master_index = 0;
            // Defaults
            strcpy(ifaces[i].state, "unknown");
            ifaces[i].ipv6_count = 0;
            ifaces[i].route_count = 0;
            ifaces[i].gateway[0] = '\0';
            ifaces[i].metric = 0;
            return &ifaces[i];
        }
    }
    return NULL; // Full
}

const char* detect_iface_type(const char* name) {
    if (strncmp(name, "wl", 2) == 0) return "wifi";
    if (strncmp(name, "et", 2) == 0) return "ethernet";
    if (strncmp(name, "en", 2) == 0) return "ethernet";
    
    // Bridges
    if (strncmp(name, "br", 2) == 0) return "bridge";
    if (strncmp(name, "podman", 6) == 0) return "bridge";
    if (strncmp(name, "docker", 6) == 0) return "bridge";
    if (strncmp(name, "cni", 3) == 0) return "bridge";
    
    // Virtual / Gadgets
    if (strncmp(name, "lo", 2) == 0) return "loopback";
    if (strncmp(name, "usb", 3) == 0) return "gadget";
    if (strncmp(name, "rndis", 5) == 0) return "gadget";
    if (strncmp(name, "veth", 4) == 0) return "veth";
    
    // Tunnels / VPNs
    if (strncmp(name, "tun", 3) == 0) return "tun";
    if (strncmp(name, "tap", 3) == 0) return "tap";
    if (strncmp(name, "tailscale", 9) == 0) return "tun";
    if (strncmp(name, "wg", 2) == 0) return "wireguard";
    
    return "unknown";
}

// --- CONFIGURATION PARSER ---

// Helper to extract value from bash syntax: : "${VAR:=VALUE}" or export VAR=VALUE
void extract_bash_var(const char *line, const char *key, char *dest, size_t dest_size) {
    char search_pattern[128];
    
    // Pattern 1: : "${KEY:=VALUE}"
    snprintf(search_pattern, sizeof(search_pattern), "${%s:=", key);
    char *p = strstr(line, search_pattern);
    if (p) {
        p += strlen(search_pattern);
        char *end = strchr(p, '}');
        if (end) {
            // Check for quotes inside
            if (p[0] == '"' && end[-1] == '"') {
                p++; end--;
            }
            size_t len = end - p;
            if (len < dest_size) {
                strncpy(dest, p, len);
                dest[len] = '\0';
                return;
            }
        }
    }

    // Pattern 2: export KEY=VALUE
    snprintf(search_pattern, sizeof(search_pattern), "export %s=", key);
    p = strstr(line, search_pattern);
    if (p) {
        p += strlen(search_pattern);
        // Simple value extraction (stops at newline or space if unquoted)
        char *end = strpbrk(p, "\n");
        if (!end) end = p + strlen(p);
        
        // Handle quotes
        if (p[0] == '"') {
            p++;
            end = strchr(p, '"');
        }
        
        if (end) {
            size_t len = end - p;
            if (len < dest_size) {
                strncpy(dest, p, len);
                dest[len] = '\0';
            }
        }
    }
}

void load_runtime_config() {
    // 1. Find the script path relative to the binary
    // Binary: .../bin/rxnm-agent
    // Script: .../lib/rxnm-constants.sh
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len == -1) return;
    self_path[len] = '\0';

    // Strip filename
    char *last_slash = strrchr(self_path, '/');
    if (!last_slash) return;
    *last_slash = '\0'; // Now we have .../bin

    // Go up one level
    last_slash = strrchr(self_path, '/');
    if (!last_slash) return;
    *last_slash = '\0'; // Now we have .../

    // Append lib path safely
    char script_path[PATH_MAX];
    if (strlen(self_path) + 32 < sizeof(script_path)) {
        snprintf(script_path, sizeof(script_path), "%s/lib/rxnm-constants.sh", self_path);
    } else {
        return; // Path too long, bail
    }

    // 2. Parse the file
    FILE *f = fopen(script_path, "r");
    if (!f) return; // Fallback to compiled defaults silently

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        // Skip comments
        char *trimmed = line;
        while(*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (*trimmed == '#') continue;

        extract_bash_var(trimmed, "CONF_DIR", g_conf_dir, sizeof(g_conf_dir));
        extract_bash_var(trimmed, "RUN_DIR", g_run_dir, sizeof(g_run_dir));
        extract_bash_var(trimmed, "RXNM_VERSION", g_agent_version, sizeof(g_agent_version));
        extract_bash_var(trimmed, "RXNM_PROBE_TARGETS_V4", g_conn_targets_v4, sizeof(g_conn_targets_v4));
        extract_bash_var(trimmed, "RXNM_PROBE_TARGETS_V6", g_conn_targets_v6, sizeof(g_conn_targets_v6));
    }
    fclose(f);
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

    if (tb[IFLA_MTU]) {
        entry->mtu = *(unsigned int *)RTA_DATA(tb[IFLA_MTU]);
    } else {
        entry->mtu = 0;
    }

    if (tb[IFLA_MASTER]) {
        entry->master_index = *(int *)RTA_DATA(tb[IFLA_MASTER]);
    }

    // Map Kernel Flags to Systemd-like State
    if ((ifi->ifi_flags & IFF_UP) && (ifi->ifi_flags & IFF_RUNNING)) {
        strcpy(entry->state, "routable");
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
            char ipv4_buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, addr_ptr, ipv4_buf, sizeof(ipv4_buf))) {
                snprintf(entry->ipv4, sizeof(entry->ipv4), "%s/%d", ipv4_buf, ifa->ifa_prefixlen);
            }
        } else if (ifa->ifa_family == AF_INET6) {
            char ipv6_buf[INET6_ADDRSTRLEN];
            if (entry->ipv6_count < MAX_IPV6_PER_IFACE) {
                if (inet_ntop(AF_INET6, addr_ptr, ipv6_buf, sizeof(ipv6_buf))) {
                    snprintf(entry->ipv6[entry->ipv6_count], IPV6_CIDR_LEN, "%s/%d", ipv6_buf, ifa->ifa_prefixlen);
                    entry->ipv6_count++;
                }
            }
        }
    }
}

void process_route_msg(struct nlmsghdr *nh) {
    struct rtmsg *rt = NLMSG_DATA(nh);
    struct rtattr *tb[RTA_MAX + 1];
    
    if (rt->rtm_table != RT_TABLE_MAIN) return;
    
    parse_rtattr(tb, RTA_MAX, RTM_RTA(rt), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rt)));

    if (!tb[RTA_OIF]) return;

    int oif = *(int *)RTA_DATA(tb[RTA_OIF]);
    iface_entry_t *entry = get_iface(oif);
    if (!entry) return;

    if (entry->route_count >= MAX_ROUTES_PER_IFACE) return;

    route_entry_t *route = &entry->routes[entry->route_count];
    memset(route, 0, sizeof(route_entry_t));

    if (tb[RTA_PRIORITY]) {
        route->metric = *(uint32_t *)RTA_DATA(tb[RTA_PRIORITY]);
    } else {
        route->metric = 0;
    }

    if (tb[RTA_GATEWAY]) {
        void *gw_ptr = RTA_DATA(tb[RTA_GATEWAY]);
        if (rt->rtm_family == AF_INET) {
            inet_ntop(AF_INET, gw_ptr, route->gw, INET_ADDRSTRLEN);
        } else if (rt->rtm_family == AF_INET6) {
            inet_ntop(AF_INET6, gw_ptr, route->gw, INET6_ADDRSTRLEN);
        }
    }

    if (rt->rtm_dst_len == 0) {
        strcpy(route->dst, "default");
        route->is_default = true;
        
        if (rt->rtm_family == AF_INET || entry->gateway[0] == '\0') {
            if (route->gw[0] != '\0') {
                strcpy(entry->gateway, route->gw);
            }
            entry->metric = route->metric;
        }
    } else if (tb[RTA_DST]) {
        void *dst_ptr = RTA_DATA(tb[RTA_DST]);
        char tmp_buf[INET6_ADDRSTRLEN];
        if (rt->rtm_family == AF_INET) {
            if (inet_ntop(AF_INET, dst_ptr, tmp_buf, sizeof(tmp_buf))) {
                snprintf(route->dst, sizeof(route->dst), "%s/%d", tmp_buf, rt->rtm_dst_len);
            }
        } else if (rt->rtm_family == AF_INET6) {
            if (inet_ntop(AF_INET6, dst_ptr, tmp_buf, sizeof(tmp_buf))) {
                snprintf(route->dst, sizeof(route->dst), "%s/%d", tmp_buf, rt->rtm_dst_len);
            }
        }
    }

    entry->route_count++;
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
    req.rtg.rtgen_family = AF_UNSPEC; 

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
            } else if (nh->nlmsg_type == RTM_NEWROUTE) {
                process_route_msg(nh);
            }
        }
    }
}

void collect_network_state() {
    int sock = open_netlink();
    if (sock < 0) return;

    send_dump_request(sock, RTM_GETLINK);
    read_netlink_response(sock);

    send_dump_request(sock, RTM_GETADDR);
    read_netlink_response(sock);

    send_dump_request(sock, RTM_GETROUTE);
    read_netlink_response(sock);

    close(sock);
}

// --- CONNECTIVITY CHECK (TCP PROBE) ---

bool tcp_probe(const char *ip_str, int port, int family) {
    int sock = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return false;

    struct timeval timeout;
    timeout.tv_sec = 2; // 2 second timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    int res = -1;
    if (family == AF_INET) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip_str, &addr.sin_addr);
        res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        inet_pton(AF_INET6, ip_str, &addr.sin6_addr);
        res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    }

    bool success = false;
    if (res == 0) {
        success = true;
    } else if (errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        if (select(sock + 1, NULL, &wfds, NULL, &timeout) > 0) {
            int so_error;
            socklen_t len = sizeof so_error;
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) success = true;
        }
    }

    close(sock);
    return success;
}

// Parse "IP:Port" string
void parse_target(char *token, char *ip, int *port) {
    char *colon = strrchr(token, ':');
    if (colon) {
        *colon = '\0';
        *port = atoi(colon + 1);
        
        // Handle [IPv6] brackets
        if (token[0] == '[' && token[strlen(token)-1] == ']') {
            token[strlen(token)-1] = '\0'; // remove closing
            strcpy(ip, token + 1); // skip opening
        } else {
            strcpy(ip, token);
        }
    }
}

void cmd_check_internet() {
    bool v4 = false;
    bool v6 = false;

    // IPv4 Probe (using runtime list)
    char list_v4[256];
    strncpy(list_v4, g_conn_targets_v4, sizeof(list_v4));
    char *token_v4, *saveptr_v4;
    token_v4 = strtok_r(list_v4, " ", &saveptr_v4);
    
    while (token_v4 != NULL) {
        char ip[64];
        int port = 80;
        parse_target(token_v4, ip, &port);
        if (tcp_probe(ip, port, AF_INET)) {
            v4 = true;
            break; 
        }
        token_v4 = strtok_r(NULL, " ", &saveptr_v4);
    }

    // IPv6 Probe
    char list_v6[512];
    strncpy(list_v6, g_conn_targets_v6, sizeof(list_v6));
    char *token_v6, *saveptr_v6;
    token_v6 = strtok_r(list_v6, " ", &saveptr_v6);
    
    while (token_v6 != NULL) {
        char ip[128];
        int port = 80;
        parse_target(token_v6, ip, &port);
        if (tcp_probe(ip, port, AF_INET6)) {
            v6 = true;
            break;
        }
        token_v6 = strtok_r(NULL, " ", &saveptr_v6);
    }

    printf("{\n");
    printf("  \"%s\": true,\n", KEY_SUCCESS);
    printf("  \"connected\": %s,\n", (v4 || v6) ? "true" : "false");
    printf("  \"ipv4\": %s,\n", v4 ? "true" : "false");
    printf("  \"ipv6\": %s\n", v6 ? "true" : "false");
    printf("}\n");
}

// --- HELPER: Parse Simple Key=Val Config (Proxy) ---
void get_proxy_config(char* http, char* https, char* no_proxy) {
    char path[PATH_MAX];
    // FIX: Add length check to silence -Wformat-truncation
    if (strlen(g_conf_dir) + 20 >= sizeof(path)) return;
    
    snprintf(path, sizeof(path), "%s/proxy.conf", g_conf_dir);
    
    FILE *f = fopen(path, "r");
    if (!f) return;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *val_start = strchr(line, '=');
        if (!val_start) continue;
        val_start++;
        line[strcspn(line, "\n")] = 0;
        if (val_start[0] == '"' || val_start[0] == '\'') val_start++;
        char *val_end = val_start + strlen(val_start) - 1;
        if (*val_end == '"' || *val_end == '\'') *val_end = 0;
        
        if (strncmp(line, "http_proxy", 10) == 0) strcpy(http, val_start);
        else if (strncmp(line, "HTTP_PROXY", 10) == 0) strcpy(http, val_start);
        else if (strncmp(line, "https_proxy", 11) == 0) strcpy(https, val_start);
        else if (strncmp(line, "HTTPS_PROXY", 11) == 0) strcpy(https, val_start);
        else if (strncmp(line, "no_proxy", 8) == 0) strcpy(no_proxy, val_start);
    }
    fclose(f);
}

// --- JSON GENERATION (Simple Printer) ---

void print_json_status() {
    printf("{\n");
    printf("  \"%s\": true,\n", KEY_SUCCESS);
    printf("  \"agent_version\": \"%s\",\n", g_agent_version);
    
    char hostname[256] = DEFAULT_HOSTNAME;
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        FILE *f = fopen("/etc/hostname", "r");
        if (f) {
            if (fgets(hostname, sizeof(hostname), f)) hostname[strcspn(hostname, "\n")] = 0;
            fclose(f);
        }
    }
    printf("  \"hostname\": \"%s\",\n", hostname);

    char p_http[256] = "", p_https[256] = "", p_no[256] = "";
    get_proxy_config(p_http, p_https, p_no);
    if (strlen(p_http) > 0 || strlen(p_https) > 0 || strlen(p_no) > 0) {
        printf("  \"global_proxy\": {\n");
        if (strlen(p_http) > 0) printf("    \"http\": \"%s\",\n", p_http);
        if (strlen(p_https) > 0) printf("    \"https\": \"%s\",\n", p_https);
        if (strlen(p_no) > 0) printf("    \"noproxy\": \"%s\"\n", p_no);
        printf("  },\n");
    } else {
        printf("  \"global_proxy\": null,\n");
    }

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
        
        if (strlen(ifaces[i].gateway) > 0)
            printf("      \"gateway\": \"%s\",\n", ifaces[i].gateway);
        
        if (ifaces[i].metric > 0)
            printf("      \"metric\": %u,\n", ifaces[i].metric);
        
        printf("      \"ipv6\": [");
        for(int j=0; j<ifaces[i].ipv6_count; j++) {
            printf("\"%s\"%s", ifaces[i].ipv6[j], (j < ifaces[i].ipv6_count - 1) ? ", " : "");
        }
        printf("],\n");
        
        printf("      \"routes\": [");
        for(int k=0; k<ifaces[i].route_count; k++) {
            printf("\n        { \"dst\": \"%s\"", ifaces[i].routes[k].dst);
            if (strlen(ifaces[i].routes[k].gw) > 0)
                printf(", \"gw\": \"%s\"", ifaces[i].routes[k].gw);
            if (ifaces[i].routes[k].metric > 0)
                printf(", \"metric\": %u", ifaces[i].routes[k].metric);
            printf(" }");
            if (k < ifaces[i].route_count - 1) printf(",");
        }
        if (ifaces[i].route_count > 0) printf("\n      ");
        printf("],\n");

        const char *type = detect_iface_type(ifaces[i].name);
        printf("      \"type\": \"%s\",\n", type);
        
        if (strcmp(type, "bridge") == 0) {
            printf("      \"members\": \"");
            bool first_mem = true;
            for (int c = 0; c < MAX_IFACES; c++) {
                if (ifaces[c].exists && ifaces[c].master_index == ifaces[i].index) {
                    if (!first_mem) printf(",");
                    printf("%s", ifaces[c].name);
                    first_mem = false;
                }
            }
            printf("\",\n");
        }
        
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
    // Use dynamic version
    printf("rxnm-agent %s\n", g_agent_version);
    printf("ConfDir: %s\n", g_conf_dir);
    printf("RunDir:  %s\n", g_run_dir);
}

void cmd_health() {
    // Use dynamic version
    printf("{\"%s\": true, \"agent\": \"active\", \"version\": \"%s\"}\n", 
           KEY_SUCCESS, g_agent_version);
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
    const char *socs[] = LOW_POWER_SOCS;
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
    collect_network_state();
    print_json_status();
}

// --- MAIN ---

int main(int argc, char *argv[]) {
    // Phase 5: Load runtime configuration from Bash script if available
    load_runtime_config();

    static struct option long_options[] = {
        {"version", no_argument, 0, 'v'},
        {"help",    no_argument, 0, 'h'},
        {"health",  no_argument, 0, 'H'},
        {"time",    no_argument, 0, 't'},
        {"is-low-power", no_argument, 0, 'L'},
        {"dump",    no_argument, 0, 'd'},
        {"check-internet", no_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "vhHtdLc", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v': cmd_version(); return 0;
            case 'h': 
                printf("Usage: rxnm-agent [options]\n--dump  Full JSON status\n--check-internet  Verify WAN (TCP probe)\n"); 
                return 0;
            case 'H': cmd_health(); return 0;
            case 't': cmd_time(); return 0;
            case 'L': cmd_is_low_power(); return 0;
            case 'd': cmd_dump_status(); return 0;
            case 'c': cmd_check_internet(); return 0;
            default: return 1;
        }
    }
    if (optind < argc) { fprintf(stderr, "Unknown arg\n"); return 1; }
    printf("rxnm-agent: Use --help\n");
    return 1;
}
