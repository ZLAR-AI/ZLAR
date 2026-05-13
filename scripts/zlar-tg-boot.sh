#!/bin/bash
# zlar-tg-boot.sh - Boot-time setup for the ZLAR Telegram dispatcher.
# Called by com.zlar.tg-dispatcher LaunchDaemon on every boot.
#
# Creates volatile directories, loads durable Telegram config from the
# installed ZLAR tree, sets ownership so the user-space gates can read
# callback inboxes, then starts the polling dispatcher.

set -euo pipefail

# LaunchDaemons run before any user logs in. At that point /dev/console may be
# owned by root, SUDO_USER is unset, and whoami returns root. Resolve the real
# admin user from persistent config first, then fall back to boot-safe probes.
_console_user() { /usr/bin/stat -f '%Su' /dev/console 2>/dev/null || echo ""; }

_find_config_owner() {
    for d in /Users/*/; do
        local user
        user=$(basename "${d}")
        [ "${user}" = "Shared" ] && continue
        [ "${user}" = "root" ] && continue
        if [ -f "${d}.zlar/.env" ] || \
           [ -f "${d}.zlar/etc/gate.json" ] || \
           [ -f "${d}.config/zlar/tg-token" ]; then
            echo "${user}"
            return 0
        fi
    done
    return 1
}

_read_env_token() {
    local env_file="$1"
    local key value

    [ -f "${env_file}" ] || return 1
    while IFS='=' read -r key value || [ -n "${key}" ]; do
        key=$(printf '%s' "${key}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        key="${key#export }"
        case "${key}" in
            ''|\#*) continue ;;
            ZLAR_TELEGRAM_TOKEN|TELEGRAM_BOT_TOKEN) ;;
            *) continue ;;
        esac

        value=$(printf '%s' "${value:-}" | sed "s/^[[:space:]]*//;s/[[:space:]]*$//;s/^['\"]//;s/['\"]$//")
        case "${value}" in
            ''|your_bot_token_here|YOUR_TELEGRAM_TOKEN|YOUR_TELEGRAM_BOT_TOKEN) continue ;;
        esac
        printf '%s' "${value}"
        return 0
    done < "${env_file}"

    return 1
}

_read_gate_chat_id() {
    local gate_config="$1"
    local chat_id

    [ -f "${gate_config}" ] || return 1
    command -v jq >/dev/null 2>&1 || return 1

    chat_id=$(jq -r '.telegram.chat_id // ""' "${gate_config}" 2>/dev/null | tr -d '[:space:]')
    case "${chat_id}" in
        ''|YOUR_TELEGRAM_CHAT_ID|your_chat_id_here|'<telegram_chat_id>'|'<CHAT_ID>'|TELEGRAM_CHAT_ID)
            return 1
            ;;
    esac

    printf '%s' "${chat_id}"
    return 0
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
    ADMIN_USER="$(_find_config_owner || true)"
fi

if [ -z "${ADMIN_USER}" ] || [ "${ADMIN_USER}" = "root" ]; then
    ADMIN_USER="$(whoami)"
fi

ADMIN_GROUP="${ZLAR_ADMIN_GROUP:-staff}"
INSTALL_DIR="/Users/${ADMIN_USER}/.zlar"
ENV_FILE="${INSTALL_DIR}/.env"
GATE_CONFIG="${INSTALL_DIR}/etc/gate.json"
PERSISTENT_TOKEN="/Users/${ADMIN_USER}/.config/zlar/tg-token"
RUNTIME_DIR="/var/run/zlar-tg"
RUNTIME_TOKEN="${RUNTIME_DIR}/token"
RUNTIME_CHAT_ID="${RUNTIME_DIR}/chat-id"
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

TELEGRAM_BOT_TOKEN=""
TELEGRAM_TOKEN_SOURCE=""
if TELEGRAM_BOT_TOKEN="$(_read_env_token "${ENV_FILE}")"; then
    TELEGRAM_TOKEN_SOURCE="installed .env"
elif [ -f "${PERSISTENT_TOKEN}" ]; then
    TELEGRAM_BOT_TOKEN=$(cat "${PERSISTENT_TOKEN}" 2>/dev/null | tr -d '[:space:]')
    if [ -n "${TELEGRAM_BOT_TOKEN}" ]; then
        TELEGRAM_TOKEN_SOURCE="legacy token file"
    fi
fi

if [ -n "${TELEGRAM_BOT_TOKEN}" ]; then
    printf '%s\n' "${TELEGRAM_BOT_TOKEN}" > "${RUNTIME_TOKEN}"
    chmod 640 "${RUNTIME_TOKEN}"
    chown "root:${ADMIN_GROUP}" "${RUNTIME_TOKEN}"
    log "Token loaded from ${TELEGRAM_TOKEN_SOURCE} (runtime file mode 640, readable by ${ADMIN_GROUP})"
else
    log "FATAL: Telegram token not found in installed .env or legacy token file"
    log "  ADMIN_USER resolved to: ${ADMIN_USER}"
    log "  Console user: $(_console_user || echo 'unavailable')"
    log "  Config search: $(_find_config_owner || echo 'no config found in /Users/*/')"
    exit 1
fi

if TELEGRAM_CHAT_ID="$(_read_gate_chat_id "${GATE_CONFIG}")"; then
    printf '%s\n' "${TELEGRAM_CHAT_ID}" > "${RUNTIME_CHAT_ID}"
    chmod 640 "${RUNTIME_CHAT_ID}"
    chown "root:${ADMIN_GROUP}" "${RUNTIME_CHAT_ID}"
    log "Chat ID loaded from installed gate config (runtime file mode 640, value not logged)"
else
    log "FATAL: Telegram chat_id missing or placeholder in installed gate config"
    exit 1
fi

export ZLAR_PROJECT_DIR="${INSTALL_DIR}"
export ZLAR_TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"

# Dispatcher runs as root; gates run as ADMIN_USER and must be able to
# read/search callback inboxes.
chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${RUNTIME_DIR}/inbox"
chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${OC_RUNTIME_DIR}"
log "Ownership set"

pkill -9 -f zlar-tg-poll 2>/dev/null || true
sleep 1

if [ -x "${DISPATCHER}" ]; then
    log "Exec dispatcher with installed project dir"
    exec "${DISPATCHER}"
else
    log "FATAL: Dispatcher not found at ${DISPATCHER}"
    exit 1
fi
