/*
 * RXNM DBus Lite - Zero-Dependency Wire Protocol
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Implements minimal SASL EXTERNAL authentication and message construction
 * to trigger systemd-networkd reloads without external libraries.
 */

#ifndef RXNM_DBUS_LITE_H
#define RXNM_DBUS_LITE_H

#include <stdint.h>

// DBus Types
#define DBUS_MESSAGE_TYPE_METHOD_CALL 1
#define DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED 0x1
#define DBUS_ENDIAN_LITTLE 'l'
#define DBUS_PROTOCOL_VERSION 1

// Header Fields
#define DBUS_HEADER_FIELD_PATH 1
#define DBUS_HEADER_FIELD_INTERFACE 2
#define DBUS_HEADER_FIELD_MEMBER 3
#define DBUS_HEADER_FIELD_ERROR_NAME 4
#define DBUS_HEADER_FIELD_REPLY_SERIAL 5
#define DBUS_HEADER_FIELD_DESTINATION 6
#define DBUS_HEADER_FIELD_SENDER 7
#define DBUS_HEADER_FIELD_SIGNATURE 8
#define DBUS_HEADER_FIELD_UNIX_FDS 9

// Basic alignment macros
#define ALIGN4(x) (((x) + 3) & ~3)
#define ALIGN8(x) (((x) + 7) & ~7)

typedef struct {
    uint8_t endian;
    uint8_t type;
    uint8_t flags;
    uint8_t version;
    uint32_t body_len;
    uint32_t serial;
    uint32_t fields_len;
} __attribute__((packed)) dbus_header_t;

// Minimal SASL State
#define DBUS_SOCK_PATH "/run/dbus/system_bus_socket"
#define SASL_AUTH_EXTERNAL "AUTH EXTERNAL "
#define SASL_BEGIN "BEGIN\r\n"

#endif // RXNM_DBUS_LITE_H
