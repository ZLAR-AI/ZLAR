#!/bin/bash
# test-tg-bootstrap.sh - Static checks for Telegram dispatcher bootstrap.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
BOOT_SCRIPT="${PROJECT_DIR}/scripts/zlar-tg-boot.sh"
POLLER="${PROJECT_DIR}/scripts/zlar-tg-poll"
INSTALLER="${PROJECT_DIR}/install.sh"

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

assert_contains "boot creates cc inbox before handoff" '${RUNTIME_DIR}/inbox/cc' "${BOOT_SCRIPT}"
assert_contains "boot creates oc inbox before handoff" '${RUNTIME_DIR}/inbox/oc' "${BOOT_SCRIPT}"
assert_contains "boot creates mcp inbox before handoff" '${RUNTIME_DIR}/inbox/mcp' "${BOOT_SCRIPT}"
assert_contains "boot hands off inbox ownership recursively" 'chown -R "${ADMIN_USER}:${ADMIN_GROUP}" "${RUNTIME_DIR}/inbox"' "${BOOT_SCRIPT}"
assert_contains "boot keeps HMAC secret root-owned" 'chown "root:${ADMIN_GROUP}" "${HMAC_SECRET_FILE}"' "${BOOT_SCRIPT}"
assert_contains "boot keeps HMAC secret group-readable" 'chmod 640 "${HMAC_SECRET_FILE}"' "${BOOT_SCRIPT}"
assert_contains "dispatcher has mcp inbox fallback" '${INBOX_DIR}/mcp' "${POLLER}"
assert_contains "dispatcher routes mcp callbacks" 'mcp:*) target_dir="${INBOX_DIR}/mcp"' "${POLLER}"
assert_contains "installer copies boot source" 'scripts/zlar-tg-boot.sh" "${INSTALL_DIR}/scripts/zlar-tg-boot.sh"' "${INSTALLER}"
assert_contains "installer copies dispatcher source" 'scripts/zlar-tg-poll"    "${INSTALL_DIR}/scripts/zlar-tg-poll"' "${INSTALLER}"
assert_contains "installer deploys boot script to /usr/local/bin" '/usr/local/bin/zlar-tg-boot.sh' "${INSTALLER}"
assert_contains "installer deploys dispatcher to /usr/local/bin" '/usr/local/bin/zlar-tg-poll' "${INSTALLER}"

echo
echo "${PASS} passed, ${FAIL} failed out of $((PASS + FAIL)) tests"
[ "${FAIL}" -eq 0 ] || exit 1
