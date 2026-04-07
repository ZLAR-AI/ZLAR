#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR — Clean Uninstall
#
# curl -fsSL https://zlar.ai/uninstall.sh | bash
#
# Removes hooks from all frameworks, deletes ~/.zlar/.
# Preserves ~/.zlar-signing.key (may be shared with other ZLAR products).
# ═══════════════════════════════════════════════════════════════════════════════

set -eu

INSTALL_DIR="${HOME}/.zlar"

# If this script is running from inside INSTALL_DIR, relocate ourselves
# to a temp path and re-exec. Otherwise the rm -rf below deletes the
# currently-executing script, which works on most filesystems via
# open-file-handle semantics but is brittle on edge cases.
_SELF="${BASH_SOURCE:-$0}"
if [ -n "${_SELF}" ] && [ "${_SELF#${INSTALL_DIR}}" != "${_SELF}" ] && [ -z "${ZLAR_UNINSTALL_RELOCATED:-}" ]; then
    _RELOCATED="$(mktemp -t zlar-uninstall.XXXXXX)"
    cp "${_SELF}" "${_RELOCATED}"
    chmod +x "${_RELOCATED}"
    export ZLAR_UNINSTALL_RELOCATED=1
    exec bash "${_RELOCATED}" "$@"
fi
# Clean up the relocated copy on exit if we're the relocated instance.
if [ -n "${ZLAR_UNINSTALL_RELOCATED:-}" ] && [ -n "${_SELF}" ] && [ "${_SELF#/tmp}" != "${_SELF}" -o "${_SELF#/var/folders}" != "${_SELF}" ]; then
    trap 'rm -f "${_SELF}"' EXIT
fi

# Colors
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BOLD=''; NC=''
fi

ok()   { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
fail() { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
warn() { printf "${YELLOW}  ⚠${NC} %s\n" "$*"; }

printf "\n"
printf "${BOLD}ZLAR — Uninstall${NC}\n"
printf "\n"

# ─── Check if installed ─────────────────────────────────────────────────────

if [ ! -d "${INSTALL_DIR}" ]; then
    fail "ZLAR is not installed (${INSTALL_DIR} not found)"
    exit 0
fi

# Verify this is actually a ZLAR installation
if [ ! -f "${INSTALL_DIR}/bin/zlar-gate" ] && [ ! -f "${INSTALL_DIR}/VERSION" ]; then
    fail "${INSTALL_DIR} exists but does not appear to be a ZLAR installation"
    exit 1
fi

# ─── Remove Claude Code hooks ───────────────────────────────────────────────

CC_SETTINGS="${HOME}/.claude/settings.json"
if [ -f "${CC_SETTINGS}" ] && grep -q "zlar" "${CC_SETTINGS}" 2>/dev/null; then
    TEMP=$(mktemp)
    # Remove PreToolUse hooks that reference zlar
    jq 'if .hooks.PreToolUse then
        .hooks.PreToolUse = [.hooks.PreToolUse[] |
            .hooks = [.hooks[] | select(.command | test("zlar") | not)] |
            select(.hooks | length > 0)
        ] |
        if .hooks.PreToolUse | length == 0 then del(.hooks.PreToolUse) else . end |
        if .hooks | keys | length == 0 then del(.hooks) else . end
    else . end' "${CC_SETTINGS}" > "${TEMP}" 2>/dev/null
    if [ -s "${TEMP}" ]; then
        mv "${TEMP}" "${CC_SETTINGS}"
        ok "Claude Code: ZLAR hooks removed from settings.json"
    else
        rm -f "${TEMP}"
        warn "Claude Code: could not auto-remove hooks — edit ~/.claude/settings.json manually"
    fi
else
    ok "Claude Code: no ZLAR hooks to remove"
fi

# ─── Remove Cursor hooks ────────────────────────────────────────────────────

CURSOR_HOOKS="${HOME}/.cursor/hooks.json"
if [ -f "${CURSOR_HOOKS}" ] && grep -q "zlar" "${CURSOR_HOOKS}" 2>/dev/null; then
    TEMP=$(mktemp)
    jq 'with_entries(
        if (.value | type) == "array" then
            .value = [.value[] | select(.command | test("zlar") | not)]
        else . end
    ) | with_entries(select(
        if (.value | type) == "array" then (.value | length > 0) else true end
    ))' "${CURSOR_HOOKS}" > "${TEMP}" 2>/dev/null
    if [ -s "${TEMP}" ]; then
        mv "${TEMP}" "${CURSOR_HOOKS}"
        ok "Cursor: ZLAR hooks removed from hooks.json"
    else
        rm -f "${TEMP}"
        warn "Cursor: could not auto-remove hooks — edit ~/.cursor/hooks.json manually"
    fi
else
    ok "Cursor: no ZLAR hooks to remove"
fi

# ─── Remove Windsurf hooks ──────────────────────────────────────────────────

WS_HOOKS="${HOME}/.codeium/windsurf/hooks.json"
if [ -f "${WS_HOOKS}" ] && grep -q "zlar" "${WS_HOOKS}" 2>/dev/null; then
    TEMP=$(mktemp)
    jq 'with_entries(
        if (.value | type) == "array" then
            .value = [.value[] | select(.command | test("zlar") | not)]
        else . end
    ) | with_entries(select(
        if (.value | type) == "array" then (.value | length > 0) else true end
    ))' "${WS_HOOKS}" > "${TEMP}" 2>/dev/null
    if [ -s "${TEMP}" ]; then
        mv "${TEMP}" "${WS_HOOKS}"
        ok "Windsurf: ZLAR hooks removed from hooks.json"
    else
        rm -f "${TEMP}"
        warn "Windsurf: could not auto-remove hooks — edit ~/.codeium/windsurf/hooks.json manually"
    fi
else
    ok "Windsurf: no ZLAR hooks to remove"
fi

# ─── Remove install directory ────────────────────────────────────────────────

AUDIT_COUNT=0
if [ -f "${INSTALL_DIR}/var/log/audit.jsonl" ]; then
    AUDIT_COUNT=$(wc -l < "${INSTALL_DIR}/var/log/audit.jsonl" 2>/dev/null | tr -d ' ')
fi

rm -rf "${INSTALL_DIR}"
ok "Removed ${INSTALL_DIR}"

if [ "${AUDIT_COUNT}" -gt 0 ]; then
    warn "Removed ${AUDIT_COUNT} audit log entries"
fi

# ─── Preserve signing key ───────────────────────────────────────────────────

if [ -f "${HOME}/.zlar-signing.key" ]; then
    warn "Preserved ~/.zlar-signing.key (may be used by other ZLAR products)"
    printf "       To remove: ${BOLD}rm ~/.zlar-signing.key${NC}\n"
fi

printf "\n"
ok "ZLAR uninstalled."
printf "\n"
