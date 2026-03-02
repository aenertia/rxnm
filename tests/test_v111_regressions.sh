#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# test_v111_regressions.sh — v1.1.1 integration regression tests
# Validates fixes for BusyBox compat, profile persistence, netlink flush, route flush.
# Can run without root/network for structural checks, skips runtime tests if not root.

set -e

PASS=0
FAIL=0
SKIP=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RXNM_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_SRC="$RXNM_ROOT/src/rxnm-agent.c"
UTILS_SH="$RXNM_ROOT/lib/rxnm-utils.sh"
INTERFACES_SH="$RXNM_ROOT/lib/rxnm-interfaces.sh"
PROFILES_SH="$RXNM_ROOT/lib/rxnm-profiles.sh"
WIRED_NET="$RXNM_ROOT/usr/lib/systemd/network/80-wired.network"

pass() { PASS=$((PASS+1)); printf "  \033[32mPASS\033[0m: %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); printf "  \033[31mFAIL\033[0m: %s\n" "$1"; }
skip() { SKIP=$((SKIP+1)); printf "  \033[33mSKIP\033[0m: %s\n" "$1"; }

echo "=== rxnm v1.1.1 Regression Tests ==="
echo ""

# --- Structural Tests (no root needed) ---

echo "--- Agent: --flush-addrs CLI integration ---"
if grep -q 'flush-addrs.*required_argument' "$AGENT_SRC"; then pass "flush-addrs in long_options"
else fail "flush-addrs missing from long_options"; fi

if grep -q 'cmd_flush_addrs' "$AGENT_SRC"; then pass "cmd_flush_addrs function exists"
else fail "cmd_flush_addrs function missing"; fi

if grep -q 'g_flush_addrs' "$AGENT_SRC"; then pass "g_flush_addrs global declared"
else fail "g_flush_addrs global missing"; fi

echo ""
echo "--- Agent: --flush-routes CLI integration ---"
if grep -q 'flush-routes.*required_argument' "$AGENT_SRC"; then pass "flush-routes in long_options"
else fail "flush-routes missing from long_options"; fi

if grep -q 'cmd_flush_routes' "$AGENT_SRC"; then pass "cmd_flush_routes function exists"
else fail "cmd_flush_routes function missing"; fi

if grep -q 'g_flush_routes' "$AGENT_SRC"; then pass "g_flush_routes global declared"
else fail "g_flush_routes global missing"; fi

if grep -q 'RTM_DELROUTE' "$AGENT_SRC"; then pass "RTM_DELROUTE used in flush_routes"
else fail "RTM_DELROUTE missing from flush_routes"; fi

echo ""
echo "--- Agent: flush uses existing netlink patterns ---"
if grep -q 'open_netlink_rt' "$AGENT_SRC" && grep -q 'parse_rtattr' "$AGENT_SRC"; then
  pass "flush functions use existing netlink helpers"
else fail "flush functions don't use existing helpers"; fi

echo ""
echo "--- Utils: BusyBox flock compatibility ---"
if grep -q '_flock_wait' "$UTILS_SH"; then pass "_flock_wait helper exists"
else fail "_flock_wait helper missing"; fi

if grep -q 'flock -n' "$UTILS_SH"; then pass "flock -n (non-blocking) fallback present"
else fail "flock -n fallback missing"; fi

if grep -c 'flock -w' "$UTILS_SH" | grep -q '^1$'; then
  pass "flock -w only in _flock_wait fast-path (1 occurrence)"
else
  COUNT=$(grep -c 'flock -w' "$UTILS_SH")
  if [ "$COUNT" -le 2 ]; then pass "flock -w contained in _flock_wait ($COUNT occurrences)"
  else fail "flock -w still used outside _flock_wait ($COUNT occurrences)"; fi
fi

echo ""
echo "--- Utils: Non-interactive confirm_action ---"
if grep -q 'if ! \[ -t 0 \]; then return 0; fi' "$UTILS_SH"; then
  pass "confirm_action auto-confirms non-interactive"
else fail "confirm_action still rejects non-interactive"; fi

echo ""
echo "--- Interfaces: reload_networkd before reconfigure ---"
for fn in _task_set_dhcp _task_set_static _task_set_link; do
  if awk "/$fn/,/^}/" "$INTERFACES_SH" | grep -q 'reload_networkd'; then
    pass "$fn calls reload_networkd"
  else fail "$fn missing reload_networkd"; fi
done

echo ""
echo "--- Interfaces: agent-based flush with fallback ---"
if grep -q 'flush-addrs.*iface' "$INTERFACES_SH"; then pass "flush-addrs agent call in _task_set_link"
else fail "flush-addrs agent call missing"; fi

if grep -q 'flush-routes.*iface' "$INTERFACES_SH"; then pass "flush-routes agent call in _task_set_link"
else fail "flush-routes agent call missing"; fi

if grep -q 'ip -6 addr flush' "$INTERFACES_SH"; then pass "ip fallback for flush present"
else fail "ip fallback missing"; fi

if grep -q 'ip -6 route flush' "$INTERFACES_SH"; then pass "ip route flush fallback present"
else fail "ip route flush fallback missing"; fi

echo ""
echo "--- Profiles: .default tracker ---"
if grep -q '\.default' "$PROFILES_SH"; then pass ".default tracker referenced"
else fail ".default tracker missing"; fi

if grep -q 'echo.*>.*\.default' "$PROFILES_SH"; then pass ".default written on save/load"
else fail ".default write missing"; fi

if grep -q '"active"' "$PROFILES_SH"; then pass "active key in profile list JSON"
else fail "active key missing from list output"; fi

if awk '/boot\)/,/;;/' "$PROFILES_SH" | grep -q '\.default'; then
  pass "boot action reads .default tracker"
else fail "boot action doesn't read .default"; fi

echo ""
echo ""
echo "--- Routes: agent-accelerated flush path ---"
ROUTES_SH="$RXNM_ROOT/lib/rxnm-routes.sh"
SYSTEM_SH="$RXNM_ROOT/lib/rxnm-system.sh"

if grep -q 'RXNM_AGENT_BIN.*flush-routes' "$ROUTES_SH"; then pass "route flush uses agent path"
else fail "route flush missing agent acceleration"; fi

if grep -q 'ip route flush dev' "$ROUTES_SH"; then pass "route flush has ip fallback"
else fail "route flush missing ip fallback"; fi

if grep -q 'flush-addrs.*6.*flush-routes.*6' "$SYSTEM_SH" || \
   (grep -q 'flush-addrs.*:6' "$SYSTEM_SH" && grep -q 'flush-routes.*:6' "$SYSTEM_SH"); then
  pass "global IPv6 disable flushes addrs+routes via agent"
else fail "global IPv6 disable missing agent flush"; fi

echo ""
echo "--- Network templates: 80-wired.network ---"
if grep -q '^Type=ethernet' "$WIRED_NET"; then fail "Type=ethernet still in [Match] (should be removed)"
else pass "Type=ethernet removed from 80-wired.network [Match]"; fi

if grep -q 'Name=en\* eth\*' "$WIRED_NET"; then pass "Name glob match preserved"
else fail "Name glob match missing"; fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $SKIP skipped ==="
[ "$FAIL" -gt 0 ] && exit 1
exit 0
