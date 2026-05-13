#!/bin/bash
# zlar-tg-boot.sh - Boot-time setup for the ZLAR Telegram dispatcher.
# Called by com.zlar.tg-dispatcher LaunchDaemon on every boot.
#
# Creates volatile directories, copies the persistent bot token, sets
# ownership so the user-space gates can read callback inboxes, then starts
# the polling dispatcher.

set -euo pipefail

# LaunchDaemons run before any user logs in. At that point /dev/console may be
# owned by root, SUDO_USER is unset, and whoami returns root. Resolve the real
# admin user from persistent config first, then fall back to boot-safe probes.
_console_user() { /usr/bin/stat -f '%Su' /dev/console 2>/dev/null || echo ""; }

_find_token_owner() {
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

if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    if [ -f /etc/zlar/admin-user ]; then
        ADMIN_USER=$(cat /etc/zlar/admin-user 2>/dev/null | tr -d '[:space:]')
    fi
fi

if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="${SUDO_USER:-}"
fi

if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="$(_console_user)"
fi

if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="$(_find_token_owner || true)"
fi

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

# Create volatile directories before ownership handoff. The dispatcher also
# has a mkdir fallback, but if it creates a new inbox as root mode 700 the
# user-space MCP gate cannot read callbacks from it.
mkdir -p "${RUNTIME_DIR}/inbox/cc" "${RUNTIME_DIR}/inbox/oc" "${RUNTIME_DIR}/inbox/mcp"
mkdir -p "${OC_RUNTIME_DIR}/decisions"
chmod 700 "${RUNTIME_DIR}/inbox/cc" "${RUNTIME_DIR}/inbox/oc" "${RUNTIME_DIR}/inbox/mcp"
log "Directories created (cc, oc, mcp inbox dirs chmod 700)"

# Generate per-boot HMAC secret for inbox integrity. Mode 640 keeps the
# secret root-owned while preserving existing gate readability via staff.
HMAC_SECRET_FILE="${RUNTIME_DIR}/inbox-hmac-secret"
openssl rand -hex 32 > "${HMAC_SECRET_FILE}"
chmod 640 "${HMAC_SECRET_FILE}"
chown "root:${ADMIN_GROUP}" "${HMAC_SECRET_FILE}"
log "HMAC secret generated at ${HMAC_SECRET_FILE} (mode 640, group ${ADMIN_GROUP})"

mkdir -p /etc/zlar 2>/dev/null || true
echo "${ADMIN_USER}" > /etc/zlar/admin-user 2>/dev/null || true

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

# Dispatcher runs as root; gates run as ADMIN_USER and must be able to
# read/search callback inboxes.
chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${RUNTIME_DIR}/inbox"
chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${OC_RUNTIME_DIR}"
log "Ownership set"

pkill -9 -f zlar-tg-poll 2>/dev/null || true
sleep 1

if [ -x "${DISPATCHER}" ]; then
    log "Exec dispatcher"
    exec "${DISPATCHER}"
else
    log "FATAL: Dispatcher not found at ${DISPATCHER}"
    exit 1
fi
