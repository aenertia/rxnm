/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>
 */

/**
 * @file rxnm_dbus_lite.h
 * @brief Zero-Dependency DBus Wire Protocol Definitions
 * @architecture Accelerator / IPC
 *
 * This header defines the raw binary structures required to communicate with
 * systemd-networkd via the system bus socket (/run/dbus/system_bus_socket).
 *
 * Rationale:
 * Linking against libdbus or GDBus adds ~500KB-2MB to the binary size and
 * introduces dynamic linking complexities for "tiny" static builds.
 * Since RXNM only needs to send a single method call (Reload), implementing
 * the wire protocol manually reduces the binary footprint to <50KB.
 */

#ifndef RXNM_DBUS_LITE_H
#define RXNM_DBUS_LITE_H

#include <stdint.h>

/* --- DBus Constants --- */
#define DBUS_MESSAGE_TYPE_METHOD_CALL 1
#define DBUS_MESSAGE_TYPE_METHOD_RETURN 2
#define DBUS_MESSAGE_TYPE_ERROR 3
#define DBUS_MESSAGE_TYPE_SIGNAL 4
#define DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED 0x1

/* Detect Endianness at Compile Time */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define DBUS_NATIVE_ENDIAN 'l'
#else
#define DBUS_NATIVE_ENDIAN 'B'
#endif

#define DBUS_PROTOCOL_VERSION 1

/* --- Header Field Types --- */
#define DBUS_HEADER_FIELD_PATH 1
#define DBUS_HEADER_FIELD_INTERFACE 2
#define DBUS_HEADER_FIELD_MEMBER 3
#define DBUS_HEADER_FIELD_ERROR_NAME 4
#define DBUS_HEADER_FIELD_REPLY_SERIAL 5
#define DBUS_HEADER_FIELD_DESTINATION 6
#define DBUS_HEADER_FIELD_SENDER 7
#define DBUS_HEADER_FIELD_SIGNATURE 8
#define DBUS_HEADER_FIELD_UNIX_FDS 9

/* --- Alignment Macros --- */
/* DBus requires 4-byte alignment for lengths and 8-byte for headers */
#define ALIGN4(x) (((x) + 3) & ~3)
#define ALIGN8(x) (((x) + 7) & ~7)

/**
 * @struct dbus_header_t
 * @brief Fixed-size header for all DBus messages.
 *
 * The protocol puts this at the very start of the packet.
 * - Endianness determines how we read the uint32s.
 * - body_len is the length of the payload (excluding header).
 * - fields_len is the length of the variable arrays (Path, Interface, etc).
 */
typedef struct {
    uint8_t endian;       /* 'l' for Little Endian, 'B' for Big Endian */
    uint8_t type;         /* Message Type (Method Call, Signal, etc.) */
    uint8_t flags;        /* Bitmask (No Reply, No Auto Start) */
    uint8_t version;      /* Protocol Version (Always 1) */
    uint32_t body_len;    /* Length of body in bytes */
    uint32_t serial;      /* Message Serial Number */
    uint32_t fields_len;  /* Length of header fields array */
} __attribute__((packed)) dbus_header_t;

/* --- Connection Defaults --- */
#define DBUS_SOCK_PATH "/run/dbus/system_bus_socket"

/* --- SASL Authentication --- */
/* DBus uses SASL EXTERNAL auth (sending UID as hex) over UNIX sockets */
#define SASL_AUTH_EXTERNAL "AUTH EXTERNAL "
#define SASL_BEGIN "BEGIN\r\n"

#endif
