#!/bin/bash
# zlar-tg-boot.sh — Boot-time setup for ZLAR Telegram dispatcher
# Called by com.zlar.tg-dispatcher LaunchDaemon on every boot.
#
# Creates volatile directories, copies the persistent bot token,
# sets ownership so both root (dispatcher) and vincentnijjar (OC gate)
# can access the inbox, then starts the polling dispatcher.

set -euo pipefail

ADMIN_USER="vincentnijjar"
ADMIN_GROUP="staff"
PERSISTENT_TOKEN="/Users/${ADMIN_USER}/.config/zlar/tg-token"
RUNTIME_DIR="/var/run/zlar-tg"
OC_RUNTIME_DIR="/var/run/zlar-oc"
DISPATCHER="/usr/local/bin/zlar-tg-poll"
LOG="/var/log/zlar-tg-boot.log"

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "${LOG}" 2>/dev/null || true
}

log "Boot setup starting"

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
chmod 600 "${HMAC_SECRET_FILE}"
chown "${ADMIN_USER}:${ADMIN_GROUP}" "${HMAC_SECRET_FILE}"
log "HMAC secret generated at ${HMAC_SECRET_FILE}"

# ── Copy persistent token ──
if [ -f "${PERSISTENT_TOKEN}" ]; then
    cp "${PERSISTENT_TOKEN}" "${RUNTIME_DIR}/token"
    chmod 600 "${RUNTIME_DIR}/token"
    log "Token copied from ${PERSISTENT_TOKEN}"
else
    log "FATAL: Persistent token not found at ${PERSISTENT_TOKEN}"
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

log "Boot setup complete"
