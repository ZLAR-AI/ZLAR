#!/bin/bash
# zlar-tg-boot.sh — Boot-time setup for ZLAR Telegram dispatcher
# Called by com.zlar.tg-dispatcher LaunchDaemon on every boot.
#
# Creates volatile directories, copies the persistent bot token,
# sets ownership so both root (dispatcher) and vincentnijjar (OC gate)
# can access the inbox, then starts the polling dispatcher.
#
# BOOT-TIME NOTE: LaunchDaemons run before any user logs in to the console.
# At that point /dev/console is owned by root, SUDO_USER is unset, and
# whoami returns "root". The user resolution chain below handles this by:
#   1. Checking a persistent config file (/etc/zlar/admin-user)
#   2. Searching /Users/ for the actual token file
# This survives reboots even if the user hasn't logged in yet.

set -euo pipefail

# ── Resolve the real admin user ──────────────────────────────────────────────
# Resolution order (first non-root wins):
#   1. ZLAR_ADMIN_USER env var (explicit override, e.g. from plist)
#   2. /etc/zlar/admin-user persistent config (survives reboot)
#   3. SUDO_USER (set by sudo, points to the real invoking user)
#   4. macOS console user (works after login, not at boot)
#   5. Search /Users/ for the token file (boot-safe fallback)
#   6. whoami (last resort)
_console_user() { /usr/bin/stat -f '%Su' /dev/console 2>/dev/null || echo ""; }

_find_token_owner() {
    # Search for the token file in /Users/*/. Skips Shared and root.
    for d in /Users/*/; do
        local user
        user=$(basename "${d}")
        [ "${user}" = "Shared" ] && continue
        [ "${user}" = "root" ] && continue
        if [ -f "${d}.config/zlar/tg-token" ]; then
            echo "${user}"
            return 0
        fi
    done
    return 1
}

ADMIN_USER="${ZLAR_ADMIN_USER:-}"

# Try persistent config
if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    if [ -f /etc/zlar/admin-user ]; then
        ADMIN_USER=$(cat /etc/zlar/admin-user 2>/dev/null | tr -d '[:space:]')
    fi
fi

# Try SUDO_USER
if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="${SUDO_USER:-}"
fi

# Try console user
if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="$(_console_user)"
fi

# Try searching for the token
if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="$(_find_token_owner || true)"
fi

# Final fallback
if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="$(whoami)"
fi

ADMIN_GROUP="${ZLAR_ADMIN_GROUP:-staff}"
PERSISTENT_TOKEN="/Users/${ADMIN_USER}/.config/zlar/tg-token"
RUNTIME_DIR="/var/run/zlar-tg"
OC_RUNTIME_DIR="/var/run/zlar-oc"
DISPATCHER="/usr/local/bin/zlar-tg-poll"
LOG="/var/log/zlar-tg-boot.log"

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "${LOG}" 2>/dev/null || true
}

log "Boot setup starting (resolved ADMIN_USER=${ADMIN_USER})"

# ── Create volatile directories ──
mkdir -p "${RUNTIME_DIR}/inbox/cc" "${RUNTIME_DIR}/inbox/oc"
mkdir -p "${OC_RUNTIME_DIR}/decisions"
# Restrict inbox dirs — only dispatcher (root) and gate user can access.
# Prevents forged approval files from other processes.
chmod 700 "${RUNTIME_DIR}/inbox/cc" "${RUNTIME_DIR}/inbox/oc"
log "Directories created (inbox dirs chmod 700)"

# ── Generate per-boot HMAC secret for inbox integrity ──
HMAC_SECRET_FILE="${RUNTIME_DIR}/inbox-hmac-secret"
openssl rand -hex 32 > "${HMAC_SECRET_FILE}"
# Mode 640 group-readable so the gate (running as ADMIN_USER in group staff) can read it.
# Mode 600 was the old value — it caused the gate to crash because only root could read.
chmod 640 "${HMAC_SECRET_FILE}"
chown "root:${ADMIN_GROUP}" "${HMAC_SECRET_FILE}"
log "HMAC secret generated at ${HMAC_SECRET_FILE} (mode 640, group ${ADMIN_GROUP})"

# ── Write persistent admin user config (so next boot doesn't need to search) ──
mkdir -p /etc/zlar 2>/dev/null || true
echo "${ADMIN_USER}" > /etc/zlar/admin-user 2>/dev/null || true

# ── Copy persistent token ──
if [ -f "${PERSISTENT_TOKEN}" ]; then
    cp "${PERSISTENT_TOKEN}" "${RUNTIME_DIR}/token"
    chmod 640 "${RUNTIME_DIR}/token"
    chown "root:${ADMIN_GROUP}" "${RUNTIME_DIR}/token"
    log "Token copied from ${PERSISTENT_TOKEN} (readable by ${ADMIN_GROUP})"
else
    log "FATAL: Persistent token not found at ${PERSISTENT_TOKEN}"
    log "  ADMIN_USER resolved to: ${ADMIN_USER}"
    log "  Console user: $(_console_user || echo 'unavailable')"
    log "  Token search: $(_find_token_owner || echo 'no token found in /Users/*/')"
    exit 1
fi

# ── Set ownership ──
# Dispatcher runs as root but OC gate runs as vincentnijjar.
# Both need access to the inbox directories.
chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${RUNTIME_DIR}/inbox"
chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${OC_RUNTIME_DIR}"
log "Ownership set"

# ── Kill any stale dispatcher instances ──
pkill -9 -f zlar-tg-poll 2>/dev/null || true
sleep 1

# ── Start dispatcher ──
if [ -x "${DISPATCHER}" ]; then
    log "Exec dispatcher"
    exec "${DISPATCHER}"
else
    log "FATAL: Dispatcher not found at ${DISPATCHER}"
    exit 1
fi
