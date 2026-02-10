/*
 * RXNM Agent - Native Fastpath Component
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>
 *
 * Phase 8: Hybrid Fastpath & Rescue Resilience (Merged)
 * - Netlink (RT/GENL) for instant status
 * - Udev Parser (Direct /run read)
 * - LitePath DBus (Direct socket)
 * - TCP Connectivity Probing
 * - Runtime Configuration Sync
 * - Query Interface (Litepath)
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
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include "rxnm_generated.h"
#include "rxnm_dbus_lite.h"

// Fallbacks
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

// --- GLOBALS & CONFIG ---
char g_conf_dir[PATH_MAX] = CONF_DIR;
char g_run_dir[PATH_MAX] = RUN_DIR;
char g_agent_version[64] = RXNM_VERSION;
char g_conn_targets_v4[256] = RXNM_PROBE_TARGETS_V4;
char g_conn_targets_v6[512] = RXNM_PROBE_TARGETS_V6;

#define BUF_SIZE 8192
#define MAX_IFACES 64
#define MAX_IPV6_PER_IFACE 8
#define MAX_ROUTES_PER_IFACE 32

#define IPV4_CIDR_LEN (INET_ADDRSTRLEN + 4)
#define IPV6_CIDR_LEN (INET6_ADDRSTRLEN + 5)

// NL80211 Constants
#define NL80211_GENL_NAME "nl80211"
#define NL80211_CMD_GET_INTERFACE 5
#define NL80211_CMD_GET_STATION 17

enum nl80211_attrs {
    NL80211_ATTR_UNSPEC,
    NL80211_ATTR_WIPHY,
    NL80211_ATTR_WIPHY_FREQ,
    NL80211_ATTR_FREQ,
    NL80211_ATTR_CHANNEL,
    NL80211_ATTR_IFINDEX,
    NL80211_ATTR_IFNAME,
    NL80211_ATTR_IFTYPE,
    NL80211_ATTR_MAC,
    NL80211_ATTR_KEY_DATA,
    NL80211_ATTR_GENERATION,
    NL80211_ATTR_FLAGS,
    NL80211_ATTR_WIPHY_ANTENNA_TX,
    NL80211_ATTR_WIPHY_ANTENNA_RX,
    NL80211_ATTR_WIPHY_NAME,
    NL80211_ATTR_STATUS,
    NL80211_ATTR_SSID,
    NL80211_ATTR_MBSSID_CONFIG,
    NL80211_ATTR_STATION_INFO = 20,
    __NL80211_ATTR_AFTER_LAST
};
#define NL80211_ATTR_MAX (__NL80211_ATTR_AFTER_LAST - 1)

enum nl80211_sta_info {
    __NL80211_STA_INFO_INVALID,
    NL80211_STA_INFO_INACTIVE_TIME,
    NL80211_STA_INFO_RX_BYTES,
    NL80211_STA_INFO_TX_BYTES,
    NL80211_STA_INFO_LLID,
    NL80211_STA_INFO_PLID,
    NL80211_STA_INFO_PLINK_STATE,
    NL80211_STA_INFO_SIGNAL,
    __NL80211_STA_INFO_AFTER_LAST
};

typedef struct {
    char dst[IPV6_CIDR_LEN];
    char gw[INET6_ADDRSTRLEN];
    uint32_t metric;
    bool is_default;
} route_entry_t;

typedef struct {
    int index;
    int master_index;
    char name[IFNAMSIZ];
    char mac[18];
    char ipv4[IPV4_CIDR_LEN];
    char ipv6[MAX_IPV6_PER_IFACE][IPV6_CIDR_LEN];
    int ipv6_count;
    char gateway[INET6_ADDRSTRLEN];
    uint32_t metric;
    route_entry_t routes[MAX_ROUTES_PER_IFACE];
    int route_count;
    char state[16];
    int mtu;
    bool exists;
    
    // Stats
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    int speed_mbps;
    
    // Metadata (Udev) - Phase 8
    char vendor[64];
    char model[64];
    char driver[32];
    char bus_info[32];

    // WiFi
    bool is_wifi;
    char ssid[33];
    int signal_dbm;
    uint32_t frequency;
    bool wifi_connected;
} iface_entry_t;

iface_entry_t ifaces[MAX_IFACES];

// --- UTILS ---

bool file_contains(const char *path, const char *search_term) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buffer[4096];
    bool found = false;
    while (fgets(buffer, sizeof(buffer), f)) {
        if (strstr(buffer, search_term)) { found = true; break; }
    }
    fclose(f);
    return found;
}

iface_entry_t* get_iface(int index) {
    for (int i = 0; i < MAX_IFACES; i++) {
        if (ifaces[i].exists && ifaces[i].index == index) return &ifaces[i];
    }
    for (int i = 0; i < MAX_IFACES; i++) {
        if (!ifaces[i].exists) {
            memset(&ifaces[i], 0, sizeof(iface_entry_t));
            ifaces[i].exists = true;
            ifaces[i].index = index;
            ifaces[i].signal_dbm = -100;
            ifaces[i].speed_mbps = -1;
            strcpy(ifaces[i].state, "unknown");
            return &ifaces[i];
        }
    }
    return NULL;
}

const char* detect_iface_type(iface_entry_t *entry) {
    if (entry->is_wifi) return "wifi";
    const char *name = entry->name;
    if (strncmp(name, "wl", 2) == 0) return "wifi";
    if (strncmp(name, "et", 2) == 0) return "ethernet";
    if (strncmp(name, "en", 2) == 0) return "ethernet";
    if (strncmp(name, "br", 2) == 0) return "bridge";
    if (strncmp(name, "podman", 6) == 0) return "bridge";
    if (strncmp(name, "docker", 6) == 0) return "bridge";
    if (strncmp(name, "cni", 3) == 0) return "bridge";
    if (strncmp(name, "lo", 2) == 0) return "loopback";
    if (strncmp(name, "usb", 3) == 0) return "gadget";
    if (strncmp(name, "rndis", 5) == 0) return "gadget";
    if (strncmp(name, "veth", 4) == 0) return "veth";
    if (strncmp(name, "tun", 3) == 0) return "tun";
    if (strncmp(name, "tap", 3) == 0) return "tap";
    if (strncmp(name, "tailscale", 9) == 0) return "tun";
    if (strncmp(name, "wg", 2) == 0) return "wireguard";
    return "unknown";
}

void extract_bash_var(const char *line, const char *key, char *dest, size_t dest_size) {
    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "${%s:=", key);
    char *p = strstr(line, search_pattern);
    if (p) {
        p += strlen(search_pattern);
        char *end = strchr(p, '}');
        if (end) {
            if (p[0] == '"' && end[-1] == '"') { p++; end--; }
            size_t len = end - p;
            if (len < dest_size) { strncpy(dest, p, len); dest[len] = '\0'; return; }
        }
    }
    snprintf(search_pattern, sizeof(search_pattern), "export %s=", key);
    p = strstr(line, search_pattern);
    if (p) {
        p += strlen(search_pattern);
        char *end = strpbrk(p, "\n");
        if (!end) end = p + strlen(p);
        if (p[0] == '"') { p++; end = strchr(p, '"'); }
        if (end) {
            size_t len = end - p;
            if (len < dest_size) { strncpy(dest, p, len); dest[len] = '\0'; }
        }
    }
}

void load_runtime_config() {
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len == -1) return;
    self_path[len] = '\0';
    
    char *last_slash = strrchr(self_path, '/');
    if (!last_slash) return;
    *last_slash = '\0';
    
    last_slash = strrchr(self_path, '/');
    if (!last_slash) return;
    *last_slash = '\0';

    char script_path[PATH_MAX];
    if (strlen(self_path) + 32 < sizeof(script_path)) {
        snprintf(script_path, sizeof(script_path), "%s/lib/rxnm-constants.sh", self_path);
    } else { return; }

    FILE *f = fopen(script_path, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
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

// --- UDEV PARSER (DIRECT READ) ---
// Reads from /run/udev/data/n<ifindex> or +net:<ifindex>
void udev_enrich(iface_entry_t *entry) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/run/udev/data/n%d", entry->index);
    
    FILE *f = fopen(path, "r");
    if (!f) {
        // Try alternate path (some systemd versions)
        snprintf(path, sizeof(path), "/run/udev/data/+net:%s", entry->name);
        f = fopen(path, "r");
    }
    
    if (!f) return;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "E:ID_VENDOR_FROM_DATABASE=", 26) == 0) {
            strncpy(entry->vendor, line + 26, sizeof(entry->vendor) - 1);
            entry->vendor[strcspn(entry->vendor, "\n")] = 0;
        } else if (strncmp(line, "E:ID_MODEL_FROM_DATABASE=", 25) == 0) {
            strncpy(entry->model, line + 25, sizeof(entry->model) - 1);
            entry->model[strcspn(entry->model, "\n")] = 0;
        } else if (strncmp(line, "E:ID_NET_DRIVER=", 16) == 0) {
            strncpy(entry->driver, line + 16, sizeof(entry->driver) - 1);
            entry->driver[strcspn(entry->driver, "\n")] = 0;
        } else if (strncmp(line, "E:ID_PATH=", 10) == 0) {
            strncpy(entry->bus_info, line + 10, sizeof(entry->bus_info) - 1);
            entry->bus_info[strcspn(entry->bus_info, "\n")] = 0;
        }
    }
    fclose(f);
}

// --- DBUS LITE (RELOAD TRIGGER) ---
void append_string(uint8_t **ptr, const char *str) {
    uint32_t len = strlen(str);
    *((uint32_t *)*ptr) = len;
    *ptr += 4;
    memcpy(*ptr, str, len + 1);
    *ptr += len + 1;
}

int dbus_trigger_reload() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DBUS_SOCK_PATH, sizeof(addr.sun_path)-1);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -2;
    }
    
    // SASL Auth
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%u", getuid());
    char auth_buf[128];
    // Hex encode UID
    char uid_hex[33];
    for (int i=0; uid_str[i]; i++) snprintf(uid_hex+(i*2), 3, "%02x", uid_str[i]);
    
    snprintf(auth_buf, sizeof(auth_buf), "\0%s%s\r\n", SASL_AUTH_EXTERNAL, uid_hex);
    send(sock, auth_buf, strlen(auth_buf), 0);
    
    char resp[512];
    int n = recv(sock, resp, sizeof(resp)-1, 0);
    if (n <= 0 || strncmp(resp, "OK", 2) != 0) { close(sock); return -3; }
    
    send(sock, SASL_BEGIN, strlen(SASL_BEGIN), 0);
    
    // Send Method Call: org.freedesktop.network1.Manager.Reload
    uint8_t msg[1024];
    memset(msg, 0, sizeof(msg));
    
    dbus_header_t *hdr = (dbus_header_t *)msg;
    hdr->endian = DBUS_ENDIAN_LITTLE;
    hdr->type = DBUS_MESSAGE_TYPE_METHOD_CALL;
    hdr->flags = DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED;
    hdr->version = DBUS_PROTOCOL_VERSION;
    hdr->serial = 1;
    
    uint8_t *ptr = msg + sizeof(dbus_header_t);
    
    // Fields
    // 1. PATH
    *ptr++ = DBUS_HEADER_FIELD_PATH;
    *ptr++ = 1; *ptr++ = 'o'; *ptr++ = 0;
    append_string(&ptr, "/org/freedesktop/network1");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);

    // 2. DESTINATION
    *ptr++ = DBUS_HEADER_FIELD_DESTINATION;
    *ptr++ = 1; *ptr++ = 's'; *ptr++ = 0;
    append_string(&ptr, "org.freedesktop.network1");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);
    
    // 3. INTERFACE
    *ptr++ = DBUS_HEADER_FIELD_INTERFACE;
    *ptr++ = 1; *ptr++ = 's'; *ptr++ = 0;
    append_string(&ptr, "org.freedesktop.network1.Manager");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);
    
    // 4. MEMBER
    *ptr++ = DBUS_HEADER_FIELD_MEMBER;
    *ptr++ = 1; *ptr++ = 's'; *ptr++ = 0;
    append_string(&ptr, "Reload");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);
    
    // Finalize Header
    hdr->fields_len = (uint32_t)(ptr - (msg + sizeof(dbus_header_t)));
    while (((uintptr_t)ptr) % 8 != 0) *ptr++ = 0;
    
    hdr->body_len = 0; // No body arguments
    
    send(sock, msg, (ptr - msg), 0);
    close(sock);
    return 0;
}

// --- RTNETLINK ENGINE ---

int open_netlink_rt() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return -1;
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
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

void process_link_msg(struct nlmsghdr *nh) {
    struct ifinfomsg *ifi = NLMSG_DATA(nh);
    struct rtattr *tb[IFLA_MAX + 1];
    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
    iface_entry_t *entry = get_iface(ifi->ifi_index);
    if (!entry) return;

    if (tb[IFLA_IFNAME]) strncpy(entry->name, (char *)RTA_DATA(tb[IFLA_IFNAME]), IFNAMSIZ - 1);
    if (tb[IFLA_ADDRESS]) {
        unsigned char *mac = (unsigned char *)RTA_DATA(tb[IFLA_ADDRESS]);
        snprintf(entry->mac, sizeof(entry->mac), "%02x:%02x:%02x:%02x:%02x:%02x", 
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    if (tb[IFLA_MTU]) entry->mtu = *(unsigned int *)RTA_DATA(tb[IFLA_MTU]);
    else entry->mtu = 0;
    if (tb[IFLA_MASTER]) entry->master_index = *(int *)RTA_DATA(tb[IFLA_MASTER]);
    
    // Stats
    if (tb[IFLA_STATS64]) {
        struct rtnl_link_stats64 *stats = (struct rtnl_link_stats64 *)RTA_DATA(tb[IFLA_STATS64]);
        entry->rx_bytes = stats->rx_bytes;
        entry->tx_bytes = stats->tx_bytes;
    }

    if ((ifi->ifi_flags & IFF_UP) && (ifi->ifi_flags & IFF_RUNNING)) strcpy(entry->state, "routable");
    else if (ifi->ifi_flags & IFF_UP) strcpy(entry->state, "no-carrier");
    else strcpy(entry->state, "off");

    // Phase 8: Trigger Udev Enrichment
    udev_enrich(entry);
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
            if (entry->ipv4[0] == '\0') {
                char ipv4_buf[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, addr_ptr, ipv4_buf, sizeof(ipv4_buf))) {
                    snprintf(entry->ipv4, sizeof(entry->ipv4), "%s/%d", ipv4_buf, ifa->ifa_prefixlen);
                }
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
    if (tb[RTA_PRIORITY]) route->metric = *(uint32_t *)RTA_DATA(tb[RTA_PRIORITY]);
    if (tb[RTA_GATEWAY]) {
        void *gw_ptr = RTA_DATA(tb[RTA_GATEWAY]);
        if (rt->rtm_family == AF_INET) inet_ntop(AF_INET, gw_ptr, route->gw, INET_ADDRSTRLEN);
        else if (rt->rtm_family == AF_INET6) inet_ntop(AF_INET6, gw_ptr, route->gw, INET6_ADDRSTRLEN);
    }
    if (rt->rtm_dst_len == 0) {
        strcpy(route->dst, "default");
        route->is_default = true;
        if (rt->rtm_family == AF_INET || entry->gateway[0] == '\0') {
            if (route->gw[0] != '\0') strcpy(entry->gateway, route->gw);
            entry->metric = route->metric;
        }
    } else if (tb[RTA_DST]) {
        void *dst_ptr = RTA_DATA(tb[RTA_DST]);
        char tmp_buf[INET6_ADDRSTRLEN];
        if (rt->rtm_family == AF_INET) {
            if (inet_ntop(AF_INET, dst_ptr, tmp_buf, sizeof(tmp_buf))) snprintf(route->dst, sizeof(route->dst), "%s/%d", tmp_buf, rt->rtm_dst_len);
        } else if (rt->rtm_family == AF_INET6) {
            if (inet_ntop(AF_INET6, dst_ptr, tmp_buf, sizeof(tmp_buf))) snprintf(route->dst, sizeof(route->dst), "%s/%d", tmp_buf, rt->rtm_dst_len);
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

// --- GENL WIFI ---
int open_netlink_genl() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0) return -1;
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    return sock;
}

int get_genl_family_id(int sock, const char *family_name) {
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
        .n.nlmsg_type = GENL_ID_CTRL,
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_seq = 1,
        .n.nlmsg_pid = getpid(),
        .g.cmd = CTRL_CMD_GETFAMILY,
        .g.version = 1
    };
    struct rtattr *rta = (struct rtattr *) req.buf;
    rta->rta_type = CTRL_ATTR_FAMILY_NAME;
    rta->rta_len = RTA_LENGTH(strlen(family_name) + 1);
    strcpy(RTA_DATA(rta), family_name);
    req.n.nlmsg_len += rta->rta_len;
    send(sock, &req, req.n.nlmsg_len, 0);

    char buf[BUF_SIZE];
    int len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) return -1;
    
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    if (NLMSG_OK(nh, len) && nh->nlmsg_type != NLMSG_ERROR) {
        struct genlmsghdr *gh = NLMSG_DATA(nh);
        struct rtattr *tb[CTRL_ATTR_MAX + 1];
        parse_rtattr(tb, CTRL_ATTR_MAX, (struct rtattr *)((char *)gh + GENL_HDRLEN), nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));
        if (tb[CTRL_ATTR_FAMILY_ID]) return *(uint16_t *)RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
    }
    return -1;
}

void process_nl80211_msg(struct nlmsghdr *nh, int cmd) {
    struct genlmsghdr *gh = NLMSG_DATA(nh);
    struct rtattr *tb[NL80211_ATTR_MAX + 1];
    parse_rtattr(tb, NL80211_ATTR_MAX, (struct rtattr *)((char *)gh + GENL_HDRLEN), nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));

    if (!tb[NL80211_ATTR_IFINDEX]) return;
    int ifindex = *(uint32_t *)RTA_DATA(tb[NL80211_ATTR_IFINDEX]);
    iface_entry_t *entry = get_iface(ifindex);
    if (!entry) return;
    entry->is_wifi = true;

    if (cmd == NL80211_CMD_GET_INTERFACE) {
        if (tb[NL80211_ATTR_SSID]) {
            char *ssid_data = (char *)RTA_DATA(tb[NL80211_ATTR_SSID]);
            int ssid_len = RTA_PAYLOAD(tb[NL80211_ATTR_SSID]);
            if (ssid_len > 32) ssid_len = 32;
            memcpy(entry->ssid, ssid_data, ssid_len);
            entry->ssid[ssid_len] = '\0';
            entry->wifi_connected = true;
        }
        if (tb[NL80211_ATTR_WIPHY_FREQ]) {
            entry->frequency = *(uint32_t *)RTA_DATA(tb[NL80211_ATTR_WIPHY_FREQ]);
        }
    } else if (cmd == NL80211_CMD_GET_STATION) {
        if (tb[NL80211_ATTR_STATION_INFO]) {
            struct rtattr *si = tb[NL80211_ATTR_STATION_INFO];
            struct rtattr *nested = RTA_DATA(si);
            int len = RTA_PAYLOAD(si);
            while (RTA_OK(nested, len)) {
                if (nested->rta_type == NL80211_STA_INFO_SIGNAL) {
                    entry->signal_dbm = (int)(*(int8_t *)RTA_DATA(nested));
                }
                nested = RTA_NEXT(nested, len);
            }
        }
    }
}

void collect_wifi_state() {
    int sock = open_netlink_genl();
    if (sock < 0) return;
    int fid = get_genl_family_id(sock, NL80211_GENL_NAME);
    if (fid <= 0) { close(sock); return; }

    // Request Interface Info (SSID, Freq)
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
    // Request Station Info (RSSI)
    req.g.cmd = NL80211_CMD_GET_STATION;
    req.n.nlmsg_seq++;
    send(sock, &req, req.n.nlmsg_len, 0);
    while ((len = recv(sock, buf, sizeof(buf), 0)) > 0) {
        struct nlmsghdr *nh = (struct nlmsghdr *)buf;
        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == fid) process_nl80211_msg(nh, NL80211_CMD_GET_STATION);
            else if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) goto done;
        }
    }
done:
    close(sock);
}

void collect_network_state() {
    // 1. RTNETLINK (0 = DUMP only, no groups)
    int sock = open_netlink_rt();
    if (sock >= 0) {
        send_dump_request(sock, RTM_GETLINK);
        read_rtnetlink_response(sock);
        send_dump_request(sock, RTM_GETADDR);
        read_rtnetlink_response(sock);
        send_dump_request(sock, RTM_GETROUTE);
        read_rtnetlink_response(sock);
        close(sock);
    }
    
    // 2. GENL (WiFi)
    collect_wifi_state();
}

// --- TCP PROBE (Restored functionality) ---
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
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) success = true;
        }
    }

    close(sock);
    return success;
}

void parse_target(char *token, char *ip, int *port) {
    char *colon = strrchr(token, ':');
    if (colon) {
        *colon = '\0';
        *port = atoi(colon + 1);
        if (token[0] == '[' && token[strlen(token)-1] == ']') {
            token[strlen(token)-1] = '\0'; 
            strcpy(ip, token + 1); 
        } else {
            strcpy(ip, token);
        }
    }
}

void cmd_check_internet() {
    bool v4 = false;
    bool v6 = false;

    // IPv4 Probe
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

// --- MAIN OUTPUT ---
void print_json_status() {
    printf("{\n  \"%s\": true,\n", KEY_SUCCESS);
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
        
        // Basic Info
        printf("    \"%s\": {\n", ifaces[i].name);
        printf("      \"name\": \"%s\",\n", ifaces[i].name);
        printf("      \"state\": \"%s\",\n", ifaces[i].state);
        printf("      \"mtu\": %d,\n", ifaces[i].mtu);
        printf("      \"type\": \"%s\",\n", detect_iface_type(&ifaces[i]));
        
        // Metadata
        if (ifaces[i].mac[0]) printf("      \"mac\": \"%s\",\n", ifaces[i].mac);
        if (ifaces[i].vendor[0]) printf("      \"vendor\": \"%s\",\n", ifaces[i].vendor);
        if (ifaces[i].driver[0]) printf("      \"driver\": \"%s\",\n", ifaces[i].driver);
        if (ifaces[i].bus_info[0]) printf("      \"bus_info\": \"%s\",\n", ifaces[i].bus_info);
        
        // IP Config
        if (ifaces[i].ipv4[0]) printf("      \"ip\": \"%s\",\n", ifaces[i].ipv4);
        if (ifaces[i].gateway[0]) printf("      \"gateway\": \"%s\",\n", ifaces[i].gateway);
        if (ifaces[i].metric > 0) printf("      \"metric\": %u,\n", ifaces[i].metric);
        
        printf("      \"ipv6\": [");
        for(int j=0; j<ifaces[i].ipv6_count; j++) {
            printf("\"%s\"%s", ifaces[i].ipv6[j], (j < ifaces[i].ipv6_count - 1) ? ", " : "");
        }
        printf("],\n");
        
        // Routes
        printf("      \"routes\": [");
        for(int k=0; k<ifaces[i].route_count; k++) {
            printf("\n        { \"dst\": \"%s\"", ifaces[i].routes[k].dst);
            if (ifaces[i].routes[k].gw[0]) printf(", \"gw\": \"%s\"", ifaces[i].routes[k].gw);
            if (ifaces[i].routes[k].metric > 0) printf(", \"metric\": %u", ifaces[i].routes[k].metric);
            printf(" }");
            if (k < ifaces[i].route_count - 1) printf(",");
        }
        if (ifaces[i].route_count > 0) printf("\n      ");
        printf("],\n");
        
        // Stats
        printf("      \"stats\": {\n");
        printf("        \"rx_bytes\": %llu,\n", (unsigned long long)ifaces[i].rx_bytes);
        printf("        \"tx_bytes\": %llu\n", (unsigned long long)ifaces[i].tx_bytes);
        printf("      },\n");
        
        // Speed
        int speed_mbps = -1;
        char speed_path[256];
        snprintf(speed_path, sizeof(speed_path), "/sys/class/net/%s/speed", ifaces[i].name);
        FILE *f_speed = fopen(speed_path, "r");
        if (f_speed) {
            if (fscanf(f_speed, "%d", &speed_mbps) != 1) speed_mbps = -1;
            fclose(f_speed);
        }
        if (speed_mbps > 0) printf("      \"speed\": %d,\n", speed_mbps);

        // WiFi
        if (ifaces[i].is_wifi) {
            printf("      \"wifi\": {\n");
            printf("        \"ssid\": \"%s\",\n", ifaces[i].ssid);
            printf("        \"rssi\": %d,\n", ifaces[i].signal_dbm);
            printf("        \"frequency\": %u\n", ifaces[i].frequency);
            printf("      },\n");
        }
        
        printf("      \"connected\": %s\n", (strcmp(ifaces[i].state, "routable") == 0) ? "true" : "false");
        printf("    }");
        first = false;
    }
    printf("\n  }\n}\n");
}

// --- QUERY INTERFACE (LITEPATH) ---
void cmd_get_value(char *key) {
    collect_network_state();
    
    // Simple parser for interfaces.<name>.<field>
    char *segment = strtok(key, ".");
    
    // Handle Global
    if (segment && strcmp(segment, "hostname") == 0) {
        char hostname[256] = DEFAULT_HOSTNAME;
        gethostname(hostname, sizeof(hostname));
        printf("%s\n", hostname);
        return;
    }
    
    if (!segment || strcmp(segment, "interfaces") != 0) return;
    
    char *ifname = strtok(NULL, ".");
    if (!ifname) return;
    
    iface_entry_t *iface = NULL;
    for (int i = 0; i < MAX_IFACES; i++) {
        if (ifaces[i].exists && strcmp(ifaces[i].name, ifname) == 0) {
            iface = &ifaces[i];
            break;
        }
    }
    if (!iface) return;
    
    char *field = strtok(NULL, ".");
    if (!field) return;
    
    // Field dispatch
    if (strcmp(field, "ip") == 0) printf("%s\n", iface->ipv4);
    else if (strcmp(field, "mac") == 0) printf("%s\n", iface->mac);
    else if (strcmp(field, "state") == 0) printf("%s\n", iface->state);
    else if (strcmp(field, "gateway") == 0) printf("%s\n", iface->gateway);
    else if (strcmp(field, "type") == 0) printf("%s\n", detect_iface_type(iface));
    else if (strcmp(field, "vendor") == 0) printf("%s\n", iface->vendor);
    else if (strcmp(field, "wifi") == 0) {
        char *sub = strtok(NULL, ".");
        if (sub) {
            if (strcmp(sub, "ssid") == 0) printf("%s\n", iface->ssid);
            else if (strcmp(sub, "rssi") == 0) printf("%d\n", iface->signal_dbm);
            else if (strcmp(sub, "frequency") == 0) printf("%u\n", iface->frequency);
        }
    }
}

// --- COMMAND HANDLERS ---
void cmd_version() {
    printf("rxnm-agent %s\n", g_agent_version);
    printf("ConfDir: %s\n", g_conf_dir);
    printf("RunDir:  %s\n", g_run_dir);
}

void cmd_health() {
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

// Original "Low Power" detection via file string search
void cmd_is_low_power() {
    // This string list matches the original shell script regex
    const char *socs[] = { 
        "RK3326", "RK3566", "RK3128", "RK3036", "RK3288", 
        "H700", "H616", "H3", "H5", "H6", "A64", "A133", "A33", 
        "sunxi", "BCM2835", "BCM2836", "BCM2837", "ATM7051", 
        "S905", "S805", "Meson", "X1830", "JZ4770", "riscv", 
        "sun20iw1p1", "JH7110", "JH7100", "Atom", "Celeron", 
        "Pentium", "Geode", "MIPS32", "MIPS64", "avr", 
        "xtensa", "tensilica", "loongson", "loongarch", NULL 
    };
    bool is_lp = false;
    for (int i = 0; socs[i] != NULL; i++) {
        if (file_contains("/proc/cpuinfo", socs[i])) {
            is_lp = true;
            break;
        }
    }
    printf("%s\n", is_lp ? "true" : "false");
}

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
        {"reload",  no_argument, 0, 'r'},
        {"get",     required_argument, 0, 'g'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "vhHtdLcrg:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v': cmd_version(); return 0;
            case 'h': 
                printf("Usage: rxnm-agent [options]\n--dump  Full JSON status\n--get <key>  Get specific value\n--reload  Trigger networkd reload\n"); 
                return 0;
            case 'H': cmd_health(); return 0;
            case 't': cmd_time(); return 0;
            case 'L': cmd_is_low_power(); return 0;
            case 'd': 
                collect_network_state();
                print_json_status(); 
                return 0;
            case 'c': cmd_check_internet(); return 0;
            case 'r': return dbus_trigger_reload();
            case 'g': cmd_get_value(optarg); return 0;
            default: return 1;
        }
    }
    
    // Default action if no args: dump status
    if (optind == 1) {
        collect_network_state();
        print_json_status();
        return 0;
    }
    
    return 1;
}
