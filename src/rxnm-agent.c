/*
 * RXNM Agent - Native Fastpath Component
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>
 *
 * Phase 7 Remediation:
 * - Parity Fix: Routes now omit /32 (IPv4) and /128 (IPv6) CIDR suffixes to
 * match standard IP tool output and legacy script behavior.
 * - Parity Fix: IPv6 addresses now respect RT_SCOPE_HOST filtering to hide
 * loopback (::1) addresses, matching legacy script filtering.
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
#include <sys/ioctl.h>

/* CRITICAL: Include glibc network headers BEFORE linux kernel headers */
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

#define BUF_SIZE 32768
#define MAX_IFACES 64
#define MAX_IPV6_PER_IFACE 8
#define MAX_ROUTES_PER_IFACE 32

#define IPV4_CIDR_LEN (INET_ADDRSTRLEN + 4)
#define IPV6_CIDR_LEN (INET6_ADDRSTRLEN + 5)

// NL80211 Constants (Verified Kernel ABI)
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

// --- DATA STRUCTURES ---

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
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    int speed_mbps;
    char vendor[64];
    char model[64];
    char driver[32];
    char bus_info[32];
    uint16_t hw_type;
    bool is_wifi;
    char ssid[33];
    char bssid[18];
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
    if (entry->hw_type == ARPHRD_ETHER && !entry->is_wifi) return "ethernet";
    if (entry->hw_type == ARPHRD_LOOPBACK) return "loopback";
    if (entry->hw_type == ARPHRD_TUNNEL || entry->hw_type == ARPHRD_TUNNEL6) return "tun";
    if (entry->hw_type == ARPHRD_IEEE80211) return "wifi";
    
    if (entry->is_wifi) return "wifi";
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
    
    char *bin_parent = strdup(self_path);
    if (!bin_parent) return;

    last_slash = strrchr(bin_parent, '/');
    if (last_slash) *last_slash = '\0';

    char script_path[PATH_MAX];
    snprintf(script_path, sizeof(script_path), "%s/lib/rxnm-constants.sh", bin_parent);
    
    FILE *f = fopen(script_path, "r");
    if (!f) {
        f = fopen("/usr/lib/rocknix-network-manager/lib/rxnm-constants.sh", "r");
    }
    
    if (f) {
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
    free(bin_parent);
}

static inline void safe_udev_copy(char *dest, size_t dest_size, const char *src) {
    if (!src || !dest) return;
    size_t len = strlen(src);
    if (len > 0 && src[len-1] == '\n') len--;
    if (len >= dest_size) len = dest_size - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

void udev_enrich(iface_entry_t *entry) {
    char path[PATH_MAX];
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

// Helper: Append DBus string to buffer
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
    
    char uid_str[16];
    snprintf(uid_str, sizeof(uid_str), "%u", getuid());
    char auth_buf[128];
    char uid_hex[33];
    for (int i=0; uid_str[i]; i++) snprintf(uid_hex+(i*2), 3, "%02x", uid_str[i]);
    
    auth_buf[0] = 0;
    int len = snprintf(auth_buf + 1, sizeof(auth_buf) - 1, "%s%s\r\n", SASL_AUTH_EXTERNAL, uid_hex);
    if (len < 0) { close(sock); return -4; }

    send(sock, auth_buf, len + 1, 0);
    
    char resp[512];
    int n = recv(sock, resp, sizeof(resp)-1, 0);
    if (n <= 0 || strncmp(resp, "OK", 2) != 0) { close(sock); return -3; }
    
    send(sock, SASL_BEGIN, strlen(SASL_BEGIN), 0);
    
    uint8_t msg[1024];
    memset(msg, 0, sizeof(msg));
    
    dbus_header_t *hdr = (dbus_header_t *)msg;
    hdr->endian = DBUS_ENDIAN_LITTLE;
    hdr->type = DBUS_MESSAGE_TYPE_METHOD_CALL;
    hdr->flags = DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED;
    hdr->version = DBUS_PROTOCOL_VERSION;
    hdr->serial = 1;
    
    uint8_t *ptr = msg + sizeof(dbus_header_t);
    *ptr++ = DBUS_HEADER_FIELD_PATH; *ptr++ = 1; *ptr++ = 'o'; *ptr++ = 0;
    append_string(&ptr, "/org/freedesktop/network1");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);

    *ptr++ = DBUS_HEADER_FIELD_DESTINATION; *ptr++ = 1; *ptr++ = 's'; *ptr++ = 0;
    append_string(&ptr, "org.freedesktop.network1");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);
    
    *ptr++ = DBUS_HEADER_FIELD_INTERFACE; *ptr++ = 1; *ptr++ = 's'; *ptr++ = 0;
    append_string(&ptr, "org.freedesktop.network1.Manager");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);
    
    *ptr++ = DBUS_HEADER_FIELD_MEMBER; *ptr++ = 1; *ptr++ = 's'; *ptr++ = 0;
    append_string(&ptr, "Reload");
    ptr = (uint8_t*)ALIGN8((uintptr_t)ptr);
    
    hdr->fields_len = (uint32_t)(ptr - (msg + sizeof(dbus_header_t)));
    while (((uintptr_t)ptr) % 8 != 0) *ptr++ = 0;
    hdr->body_len = 0;
    
    send(sock, msg, (ptr - msg), 0);
    close(sock);
    return 0;
}

int open_netlink_rt() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) return -1;
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
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

void process_link_msg(struct nlmsghdr *nh) {
    struct ifinfomsg *ifi = NLMSG_DATA(nh);
    struct rtattr *tb[IFLA_MAX + 1];
    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
    iface_entry_t *entry = get_iface(ifi->ifi_index);
    if (!entry) return;

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

    if ((ifi->ifi_flags & IFF_UP) && (ifi->ifi_flags & IFF_RUNNING)) strcpy(entry->state, "routable");
    else if (ifi->ifi_flags & IFF_UP) strcpy(entry->state, "no-carrier");
    else strcpy(entry->state, "off");

    if (tb[IFLA_MASTER]) strcpy(entry->state, "enslaved");

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
            if (entry->ipv4[0] == '\0' && ifa->ifa_scope < RT_SCOPE_HOST) {
                char ipv4_buf[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, addr_ptr, ipv4_buf, sizeof(ipv4_buf))) {
                    snprintf(entry->ipv4, sizeof(entry->ipv4), "%s/%d", ipv4_buf, ifa->ifa_prefixlen);
                }
            }
        } else if (ifa->ifa_family == AF_INET6) {
            // Updated Scope Check to match Legacy Script behavior
            if (ifa->ifa_scope < RT_SCOPE_HOST) {
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
        // Updated Route Formatting to omit implicit CIDR /32 or /128
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

int open_netlink_genl() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock < 0) return -1;
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    return sock;
}

int get_genl_family_id(int sock, const char *family_name) {
    struct { struct nlmsghdr n; struct genlmsghdr g; char buf[256]; } req = {
        .n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN), .n.nlmsg_type = GENL_ID_CTRL,
        .n.nlmsg_flags = NLM_F_REQUEST, .n.nlmsg_seq = 1, .n.nlmsg_pid = getpid(),
        .g.cmd = CTRL_CMD_GETFAMILY, .g.version = 1
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

// Helper to add Netlink attribute
void add_nl_attr(struct nlmsghdr *n, int type, const void *data, int len) {
    int alen = RTA_LENGTH(len);
    struct rtattr *rta = (struct rtattr *)((char *)n + n->nlmsg_len);
    rta->rta_type = type;
    rta->rta_len = alen;
    memcpy(RTA_DATA(rta), data, len);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len + alen);
}

void process_nl80211_msg(struct nlmsghdr *nh, int cmd) {
    struct genlmsghdr *gh = NLMSG_DATA(nh);
    struct rtattr *tb[NL80211_ATTR_PARSE_MAX + 1];
    parse_rtattr(tb, NL80211_ATTR_PARSE_MAX, (struct rtattr *)((char *)gh + GENL_HDRLEN), nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));

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
        if (tb[NL80211_ATTR_WIPHY_FREQ]) entry->frequency = *(uint32_t *)RTA_DATA(tb[NL80211_ATTR_WIPHY_FREQ]);
    } else if (cmd == NL80211_CMD_GET_STATION) {
        // Correctly capture BSSID from Station info (Peer MAC)
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

    // Step 1: Dump all interfaces to find WiFi ones
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
    // Step 2: Iterate WiFi interfaces and dump stations PER INTERFACE
    // Targeted dumps are required by many drivers/kernels to return station data
    for (int i = 0; i < MAX_IFACES; i++) {
        if (ifaces[i].exists && ifaces[i].is_wifi) {
            // Reconstruct request for GET_STATION with specific IFINDEX
            struct { struct nlmsghdr n; struct genlmsghdr g; char buf[64]; } sta_req = {
                .n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN), .n.nlmsg_type = fid, 
                .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP, .n.nlmsg_seq = time(NULL) + i,
                .g.cmd = NL80211_CMD_GET_STATION, .g.version = 1
            };
            
            // Append NL80211_ATTR_IFINDEX
            uint32_t idx = ifaces[i].index;
            add_nl_attr(&sta_req.n, NL80211_ATTR_IFINDEX, &idx, sizeof(idx));
            
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
    for (int i = 0; i < MAX_IFACES; i++) if (ifaces[i].exists && ifaces[i].is_wifi) sysfs_collect_bssid_fallback(&ifaces[i]);
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
    char list_v4[256]; strncpy(list_v4, g_conn_targets_v4, sizeof(list_v4) - 1); list_v4[sizeof(list_v4)-1] = '\0';
    char *token_v4, *saveptr_v4; token_v4 = strtok_r(list_v4, " ", &saveptr_v4);
    while (token_v4 != NULL) {
        char ip[64]; int port = 80;
        parse_target(token_v4, ip, sizeof(ip), &port);
        if (tcp_probe(ip, port, AF_INET)) { v4 = true; break; }
        token_v4 = strtok_r(NULL, " ", &saveptr_v4);
    }
    char list_v6[512]; strncpy(list_v6, g_conn_targets_v6, sizeof(list_v6) - 1); list_v6[sizeof(list_v6)-1] = '\0';
    char *token_v6, *saveptr_v6; token_v6 = strtok_r(list_v6, " ", &saveptr_v6);
    while (token_v6 != NULL) {
        char ip[128]; int port = 80;
        parse_target(token_v6, ip, sizeof(ip), &port);
        if (tcp_probe(ip, port, AF_INET6)) { v6 = true; break; }
        token_v6 = strtok_r(NULL, " ", &saveptr_v6);
    }
    printf("{\n  \"%s\": true,\n  \"connected\": %s,\n  \"ipv4\": %s,\n  \"ipv6\": %s\n}\n", KEY_SUCCESS, (v4 || v6) ? "true" : "false", v4 ? "true" : "false", v6 ? "true" : "false");
}

void get_proxy_config(char* http, char* https, char* no_proxy) {
    char path[PATH_MAX + 128]; // Larger buffer to prevent format-truncation warning
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

void print_json_status() {
    printf("{\n  \"%s\": true,\n  \"agent_version\": \"%s\",\n", KEY_SUCCESS, g_agent_version);
    char hostname[256] = DEFAULT_HOSTNAME;
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        FILE *f = fopen("/etc/hostname", "r");
        if (f) { if (fgets(hostname, sizeof(hostname), f)) hostname[strcspn(hostname, "\n")] = 0; fclose(f); }
    }
    printf("  \"hostname\": \"%s\",\n", hostname);
    char p_http[256] = "", p_https[256] = "", p_no[256] = "";
    get_proxy_config(p_http, p_https, p_no);
    bool first_proxy = true; printf("  \"global_proxy\": {\n");
    if (strlen(p_http) > 0)  { printf("%s    \"http\": \"%s\"",  first_proxy ? "" : ",\n", p_http);  first_proxy = false; }
    if (strlen(p_https) > 0) { printf("%s    \"https\": \"%s\"", first_proxy ? "" : ",\n", p_https); first_proxy = false; }
    if (strlen(p_no) > 0)    { printf("%s    \"noproxy\": \"%s\"",first_proxy ? "" : ",\n", p_no);   first_proxy = false; }
    if (first_proxy) printf("    \"status\": \"none\"\n"); else printf("\n");
    printf("  },\n  \"interfaces\": {\n");
    bool first_iface = true;
    for (int i = 0; i < MAX_IFACES; i++) {
        if (!ifaces[i].exists || ifaces[i].name[0] == '\0') continue;
        if (!first_iface) printf(",\n");
        printf("    \"%s\": {\n      \"name\": \"%s\",\n      \"state\": \"%s\",\n      \"mtu\": %d,\n      \"type\": \"%s\",\n", ifaces[i].name, ifaces[i].name, ifaces[i].state, ifaces[i].mtu, detect_iface_type(&ifaces[i]));
        if (ifaces[i].mac[0]) printf("      \"mac\": \"%s\",\n", ifaces[i].mac);
        if (ifaces[i].vendor[0]) printf("      \"vendor\": \"%s\",\n", ifaces[i].vendor);
        if (ifaces[i].driver[0]) printf("      \"driver\": \"%s\",\n", ifaces[i].driver);
        if (ifaces[i].bus_info[0]) printf("      \"bus_info\": \"%s\",\n", ifaces[i].bus_info);
        if (ifaces[i].ipv4[0]) printf("      \"ip\": \"%s\",\n", ifaces[i].ipv4);
        if (ifaces[i].gateway[0]) printf("      \"gateway\": \"%s\",\n", ifaces[i].gateway);
        if (ifaces[i].metric > 0) printf("      \"metric\": %u,\n", ifaces[i].metric);
        printf("      \"ipv6\": [");
        for(int j=0; j<ifaces[i].ipv6_count; j++) printf("\"%s\"%s", ifaces[i].ipv6[j], (j < ifaces[i].ipv6_count - 1) ? ", " : "");
        printf("],\n      \"routes\": [");
        for(int k=0; k<ifaces[i].route_count; k++) {
            printf("\n        { \"dst\": \"%s\"", ifaces[i].routes[k].dst);
            if (ifaces[i].routes[k].gw[0]) printf(", \"gw\": \"%s\"", ifaces[i].routes[k].gw);
            if (ifaces[i].routes[k].metric > 0) printf(", \"metric\": %u", ifaces[i].routes[k].metric);
            printf(" }%s", (k < ifaces[i].route_count - 1) ? "," : "");
        }
        printf("%s],\n      \"stats\": {\n        \"rx_bytes\": %llu,\n        \"tx_bytes\": %llu\n      },\n", ifaces[i].route_count > 0 ? "\n      " : "", (unsigned long long)ifaces[i].rx_bytes, (unsigned long long)ifaces[i].tx_bytes);
        int speed_mbps = -1; char speed_path[256]; snprintf(speed_path, sizeof(speed_path), "/sys/class/net/%s/speed", ifaces[i].name);
        FILE *f_speed = fopen(speed_path, "r");
        if (f_speed) { if (fscanf(f_speed, "%d", &speed_mbps) != 1) speed_mbps = -1; fclose(f_speed); }
        if (speed_mbps > 0) printf("      \"speed\": %d,\n", speed_mbps);
        if (ifaces[i].is_wifi) {
            printf("      \"wifi\": {\n        \"ssid\": \"%s\",\n", ifaces[i].ssid);
            if (ifaces[i].bssid[0]) printf("        \"bssid\": \"%s\",\n", ifaces[i].bssid); else printf("        \"bssid\": null,\n");
            printf("        \"rssi\": %d,\n        \"frequency\": %u\n      },\n", ifaces[i].signal_dbm, ifaces[i].frequency);
        }
        bool is_connected = (strcmp(ifaces[i].state, "routable") == 0 || strcmp(ifaces[i].state, "enslaved") == 0 || strcmp(ifaces[i].state, "online") == 0 || strcmp(ifaces[i].state, "up") == 0);
        printf("      \"connected\": %s\n    }", is_connected ? "true" : "false");
        first_iface = false;
    }
    printf("\n  }\n}\n");
}

void cmd_get_value(char *key) {
    collect_network_state();
    char *segment = strtok(key, ".");
    if (segment && strcmp(segment, "hostname") == 0) { char hostname[256] = DEFAULT_HOSTNAME; gethostname(hostname, sizeof(hostname)); printf("%s\n", hostname); return; }
    if (!segment || strcmp(segment, "interfaces") != 0) return;
    char *ifname = strtok(NULL, "."); if (!ifname) return;
    iface_entry_t *iface = NULL;
    for (int i = 0; i < MAX_IFACES; i++) { if (ifaces[i].exists && strcmp(ifaces[i].name, ifname) == 0) { iface = &ifaces[i]; break; } }
    if (!iface) return;
    char *field = strtok(NULL, "."); if (!field) return;
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
            else if (strcmp(sub, "bssid") == 0) printf("%s\n", iface->bssid);
            else if (strcmp(sub, "rssi") == 0) printf("%d\n", iface->signal_dbm);
            else if (strcmp(sub, "frequency") == 0) printf("%u\n", iface->frequency);
        }
    }
}

void cmd_version() { printf("rxnm-agent %s\n", g_agent_version); }
void cmd_health() { printf("{\"%s\": true, \"agent\": \"active\", \"version\": \"%s\"}\n", KEY_SUCCESS, g_agent_version); }
void cmd_time() { struct timespec ts; if (clock_gettime(CLOCK_REALTIME, &ts) == 0) printf("%ld\n", ts.tv_sec); else exit(1); }

void cmd_is_low_power() {
    const char *socs[] = LOW_POWER_SOCS; bool is_lp = false;
    for (int i = 0; socs[i] != NULL; i++) if (file_contains("/proc/cpuinfo", socs[i])) { is_lp = true; break; }
    printf("%s\n", is_lp ? "true" : "false");
}

int main(int argc, char *argv[]) {
    load_runtime_config();
    static struct option long_options[] = { {"version", no_argument, 0, 'v'}, {"help", no_argument, 0, 'h'}, {"health",  no_argument, 0, 'H'}, {"time",    no_argument, 0, 't'}, {"is-low-power", no_argument, 0, 'L'}, {"dump",    no_argument, 0, 'd'}, {"check-internet", no_argument, 0, 'c'}, {"reload",  no_argument, 0, 'r'}, {"get",     required_argument, 0, 'g'}, {0, 0, 0, 0} };
    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "vhHtdLcrg:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v': cmd_version(); return 0;
            case 'h': printf("Usage: rxnm-agent [options]\n--dump  Full JSON status\n--get <key>  Get specific value\n--reload  Trigger networkd reload\n"); return 0;
            case 'H': cmd_health(); return 0;
            case 't': cmd_time(); return 0;
            case 'L': cmd_is_low_power(); return 0;
            case 'd': collect_network_state(); print_json_status(); return 0;
            case 'c': cmd_check_internet(); return 0;
            case 'r': return dbus_trigger_reload();
            case 'g': cmd_get_value(optarg); return 0;
            default: return 1;
        }
    }
    if (optind == 1) { collect_network_state(); print_json_status(); return 0; }
    return 1;
}
