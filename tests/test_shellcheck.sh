#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026-present Joel Wirāmu Pauling <aenertia@aenertia.net>

# -----------------------------------------------------------------------------
# FILE: test_shellcheck.sh
# PURPOSE: Static Analysis via ShellCheck
# ARCHITECTURE: Test Suite
#
# Scans core binaries, libraries, and test scripts for bash syntax errors
# and common pitfalls.
# -----------------------------------------------------------------------------

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}ℹ INFO:${NC} $1"; }
pass() { echo -e "${GREEN}✓ PASS:${NC} $1"; }
fail() { echo -e "${RED}✗ FAIL:${NC} $1"; exit 1; }

# Check for existence
if ! command -v shellcheck >/dev/null; then
    echo -e "${YELLOW}⚠ WARN: shellcheck not found. Skipping linting.${NC}"
    echo "       Install via: sudo apt install shellcheck / sudo dnf install ShellCheck"
    
    # Strictly enforce presence in CI environment
    if [ "${GITHUB_ACTIONS}" == "true" ]; then
        fail "ShellCheck is required in CI environment but was not found."
    fi
    exit 0
fi

# 1. Define specific executables (no extension)
SOURCES=(
    "bin/rocknix-network-manager"
    "bin/rxnm"
    "usr/lib/systemd/system-sleep/rxnm-resume"
)

# 2. Add directories of .sh files (Excluding tests/old)
# Using find logic to properly handle path exclusions
while IFS= read -r -d '' file; do
    SOURCES+=("$file")
done < <(find lib scripts tests -name "*.sh" -not -path "tests/old/*" -print0)

info "Scanning ${#SOURCES[@]} shell scripts with ShellCheck..."

# --- Exclusions ---
# Structural/Architecture Exclusions:
# SC1090, SC1091: Can't follow non-constant source (Dynamic libraries).
# SC2148: Tips depend on target shell (Libraries don't have shebangs).
# SC2034: Variable appears unused (Defined in constants, used in others).
# SC2153: Possible misspelling (Variable defined in sourced file).
# SC2329: Function never invoked (Defined in library, used by dispatcher).

# Idiom/Style Exclusions:
# SC2155: Declare and assign separately (Acceptable risk for local vars).
# SC2016: Expressions in single quotes (False positives with jq/awk).
# SC2164: cd without exit (Acceptable in short-lived test scripts).
# SC2188: Redirection without command (Valid bash idiom `> file`).
# SC2086: Double quote to prevent splitting (Used intentionally for args).
# SC2129: Multiple redirects (Style preference).
# SC2001: See if you can use ${variable//search/replace} (Sed is fine).
# SC2015: A && B || C (Standard shorthand).
# SC2295: Expansions inside ${..} (Bash specific).
# SC2053: Quote rhs of == (Style).
# SC2181: Check exit code directly (Style).
# SC2046: Quote $(...) (Word splitting intended for lists).
# SC2002: Useless cat (Style preference for pipelines).
# SC2120: Function references arguments but none passed (Optional args).
# SC2119: Use foo "$@" if function's $1 should mean script's $1 (Optional args).
# SC2317: Command appears unreachable (False positive on trap functions).

EXCLUDES="SC1090,SC1091,SC2148,SC2034,SC2153,SC2329,SC2155,SC2016,SC2164,SC2188,SC2086,SC2129,SC2001,SC2015,SC2295,SC2053,SC2181,SC2046,SC2002,SC2120,SC2119,SC2317"

# Run check
if shellcheck -e "$EXCLUDES" --format=tty --color=always "${SOURCES[@]}"; then
    pass "No issues found."
    exit 0
else
    echo ""
    fail "ShellCheck found issues (see above)."
fi
