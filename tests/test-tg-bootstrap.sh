#!/bin/bash
# test-tg-bootstrap.sh - Static checks for Telegram dispatcher bootstrap.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
BOOT_SCRIPT="${PROJECT_DIR}/scripts/zlar-tg-boot.sh"
POLLER="${PROJECT_DIR}/scripts/zlar-tg-poll"
INSTALLER="${PROJECT_DIR}/install.sh"
PLIST="${PROJECT_DIR}/etc/com.zlar.tg-dispatcher.plist"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

assert_contains() {
    local label="$1" needle="$2" file="$3"
    if grep -Fq -- "${needle}" "${file}"; then
        pass "${label}"
    else
        fail "${label}"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" file="$3"
    if grep -Fq -- "${needle}" "${file}"; then
        fail "${label}"
    else
        pass "${label}"
    fi
}

assert_line_order() {
    local label="$1" first="$2" second="$3" file="$4"
    local first_line second_line
    first_line=$(grep -nF -- "${first}" "${file}" | head -1 | cut -d: -f1 || true)
    second_line=$(grep -nF -- "${second}" "${file}" | head -1 | cut -d: -f1 || true)
    if [ -n "${first_line}" ] && [ -n "${second_line}" ] && [ "${first_line}" -lt "${second_line}" ]; then
        pass "${label}"
    else
        fail "${label}"
    fi
}

assert_syntax() {
    local label="$1" file="$2"
    if bash -n "${file}"; then
        pass "${label}"
    else
        fail "${label}"
    fi
}

echo "=== Telegram Bootstrap ==="
echo

assert_syntax "boot script parses" "${BOOT_SCRIPT}"
assert_syntax "dispatcher parses" "${POLLER}"

assert_contains "plist runs boot helper" '/usr/local/bin/zlar-tg-boot.sh' "${PLIST}"
assert_not_contains "LaunchDaemon plist stays env-free" '<key>EnvironmentVariables</key>' "${PLIST}"
assert_not_contains "LaunchDaemon plist contains no token env" 'ZLAR_TELEGRAM_TOKEN' "${PLIST}"
assert_not_contains "LaunchDaemon plist contains no chat id env" 'ZLAR_TELEGRAM_CHAT_ID' "${PLIST}"

assert_contains "boot creates cc inbox before handoff" '${RUNTIME_DIR}/inbox/cc' "${BOOT_SCRIPT}"
assert_contains "boot creates oc inbox before handoff" '${RUNTIME_DIR}/inbox/oc' "${BOOT_SCRIPT}"
assert_contains "boot creates mcp inbox before handoff" '${RUNTIME_DIR}/inbox/mcp' "${BOOT_SCRIPT}"
assert_contains "boot hands off inbox ownership recursively" 'chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${RUNTIME_DIR}/inbox"' "${BOOT_SCRIPT}"
assert_contains "boot keeps HMAC secret root-owned" 'chown "root:${ADMIN_GROUP}" "${HMAC_SECRET_FILE}"' "${BOOT_SCRIPT}"
assert_contains "boot keeps HMAC secret group-readable" 'chmod 640 "${HMAC_SECRET_FILE}"' "${BOOT_SCRIPT}"
assert_contains "boot resolves installed project dir" 'INSTALL_DIR="/Users/${ADMIN_USER}/.zlar"' "${BOOT_SCRIPT}"
assert_contains "boot reads installed env token" '_read_env_token "${ENV_FILE}"' "${BOOT_SCRIPT}"
assert_contains "boot keeps legacy token fallback" 'PERSISTENT_TOKEN="/Users/${ADMIN_USER}/.config/zlar/tg-token"' "${BOOT_SCRIPT}"
assert_line_order "boot prefers installed .env before legacy token" '_read_env_token "${ENV_FILE}"' '[ -f "${PERSISTENT_TOKEN}" ]' "${BOOT_SCRIPT}"
assert_contains "boot reads chat id from installed gate config" '_read_gate_chat_id "${GATE_CONFIG}"' "${BOOT_SCRIPT}"
assert_contains "boot rejects placeholder chat id" 'YOUR_TELEGRAM_CHAT_ID' "${BOOT_SCRIPT}"
assert_contains "boot writes restricted runtime token" 'chmod 640 "${RUNTIME_TOKEN}"' "${BOOT_SCRIPT}"
assert_contains "boot writes restricted runtime chat id" 'chmod 640 "${RUNTIME_CHAT_ID}"' "${BOOT_SCRIPT}"
assert_contains "boot exports project dir for dispatcher" 'export ZLAR_PROJECT_DIR="${INSTALL_DIR}"' "${BOOT_SCRIPT}"
assert_contains "boot exports chat id for dispatcher" 'export ZLAR_TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"' "${BOOT_SCRIPT}"
assert_contains "boot logs chat id without value" 'value not logged' "${BOOT_SCRIPT}"
assert_not_contains "boot does not log legacy token path value" 'Token copied from ${PERSISTENT_TOKEN}' "${BOOT_SCRIPT}"
assert_not_contains "boot does not log runtime chat id value" 'log "${TELEGRAM_CHAT_ID}' "${BOOT_SCRIPT}"
assert_contains "dispatcher has mcp inbox fallback" '${INBOX_DIR}/mcp' "${POLLER}"
assert_contains "dispatcher routes mcp callbacks" 'mcp:*) target_dir="${INBOX_DIR}/mcp"' "${POLLER}"
assert_contains "dispatcher honors ZLAR_PROJECT_DIR" 'PROJECT_DIR="${ZLAR_PROJECT_DIR}"' "${POLLER}"
assert_contains "dispatcher has runtime chat id fallback" 'CHAT_ID_FILE="${RUNTIME_DIR}/chat-id"' "${POLLER}"
assert_contains "dispatcher reads runtime chat id fallback" '[ -f "${CHAT_ID_FILE}" ]' "${POLLER}"
assert_contains "installer creates lib directory" 'mkdir -p "${INSTALL_DIR}/lib"' "${INSTALLER}"
assert_contains "installer copies shared libs" 'cp "${SCRIPT_SOURCE_DIR}/lib/"* "${INSTALL_DIR}/lib/"' "${INSTALLER}"
assert_contains "installer copies boot source" 'scripts/zlar-tg-boot.sh" "${INSTALL_DIR}/scripts/zlar-tg-boot.sh"' "${INSTALLER}"
assert_contains "installer copies dispatcher source" 'scripts/zlar-tg-poll"    "${INSTALL_DIR}/scripts/zlar-tg-poll"' "${INSTALLER}"
assert_contains "installer deploys boot script to /usr/local/bin" '/usr/local/bin/zlar-tg-boot.sh' "${INSTALLER}"
assert_contains "installer deploys dispatcher to /usr/local/bin" '/usr/local/bin/zlar-tg-poll' "${INSTALLER}"

echo
echo "${PASS} passed, ${FAIL} failed out of $((PASS + FAIL)) tests"
[ "${FAIL}" -eq 0 ] || exit 1
