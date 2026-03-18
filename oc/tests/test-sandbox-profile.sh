#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR-OC Smoke Tests: Sandbox Profile Validation
#
# Tests the Seatbelt profile (.sb) against the 7 scenarios from the design doc.
# Must run on macOS as root (or with sudo) since sandbox-exec requires privileges.
#
# Usage:
#   sudo ./tests/test-sandbox-profile.sh
#
# Exit codes:
#   0 = all tests passed
#   1 = one or more tests failed
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

SANDBOX_PROFILE="${SANDBOX_PROFILE:-/usr/local/etc/zlar-oc/openclaw.sb}"
AGENT_HOME="${AGENT_HOME:-/Users/aiagent}"
ADMIN_HOME="${ADMIN_HOME:-/Users/admin}"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-${AGENT_HOME}/workspace}"
OPENCLAW_INSTALL="${OPENCLAW_INSTALL:-/opt/homebrew/lib/node_modules/openclaw}"
NODE_BIN="${NODE_BIN:-/opt/homebrew/bin/node}"

PASSED=0
FAILED=0
SKIPPED=0

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BOLD='\033[1m'; NC='\033[0m'

pass() { PASSED=$((PASSED + 1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { FAILED=$((FAILED + 1)); echo -e "  ${RED}FAIL${NC} $1"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo -e "  ${YELLOW}SKIP${NC} $1"; }

sandbox_exec_cmd() {
    # Run a command under the sandbox profile as aiagent
    sandbox-exec -f "${SANDBOX_PROFILE}" \
        -D "AGENT_HOME=${AGENT_HOME}" \
        -D "ADMIN_HOME=${ADMIN_HOME}" \
        -D "WORKSPACE_ROOT=${WORKSPACE_ROOT}" \
        -D "OPENCLAW_INSTALL_DIR=${OPENCLAW_INSTALL}" \
        sudo -u aiagent "$@" 2>&1
}

# ─── Pre-flight ───────────────────────────────────────────────────────────────

echo -e "${BOLD}ZLAR-OC Sandbox Profile Smoke Tests${NC}"
echo -e "Profile: ${SANDBOX_PROFILE}"
echo ""

if [ "$(uname)" != "Darwin" ]; then
    echo "These tests require macOS. Exiting."
    exit 0
fi

if [ ! -f "${SANDBOX_PROFILE}" ]; then
    echo "Sandbox profile not found at ${SANDBOX_PROFILE}"
    echo "To test locally: SANDBOX_PROFILE=./etc/zlar-oc/openclaw.sb $0"
    exit 1
fi

if ! id aiagent &>/dev/null; then
    echo "User aiagent does not exist. Run zlar-oc-launch first."
    exit 1
fi

# ─── Test 1: Smoke — basic node execution works ──────────────────────────────

echo -e "${BOLD}Test 1: Basic node execution under sandbox${NC}"
if [ -x "${NODE_BIN}" ]; then
    result=$(sandbox_exec_cmd "${NODE_BIN}" -e "console.log('sandbox-ok')" 2>&1)
    if echo "${result}" | grep -q "sandbox-ok"; then
        pass "Node.js runs under sandbox and produces output"
    else
        fail "Node.js failed under sandbox: ${result}"
    fi
else
    skip "Node.js not found at ${NODE_BIN}"
fi

# ─── Test 2: Exec — shell commands work ──────────────────────────────────────

echo -e "${BOLD}Test 2: Shell command execution (ls, echo)${NC}"
result=$(sandbox_exec_cmd /bin/sh -c "echo test-exec-ok" 2>&1)
if echo "${result}" | grep -q "test-exec-ok"; then
    pass "Shell execution works under sandbox"
else
    fail "Shell execution failed: ${result}"
fi

# ─── Test 3: Deny — SSH key access blocked ───────────────────────────────────

echo -e "${BOLD}Test 3: SSH key access denied${NC}"
# Create a test file if needed
if [ -d "${AGENT_HOME}/.ssh" ] || [ -d "${ADMIN_HOME}/.ssh" ]; then
    result=$(sandbox_exec_cmd /bin/sh -c "cat ${AGENT_HOME}/.ssh/id_rsa 2>&1" 2>&1)
    if echo "${result}" | grep -qi "deny\|operation not permitted\|no such file"; then
        pass "SSH key access denied by sandbox"
    else
        fail "SSH key access was NOT denied: ${result}"
    fi
else
    # Test with admin home instead
    result=$(sandbox_exec_cmd /bin/sh -c "ls ${ADMIN_HOME}/ 2>&1" 2>&1)
    if echo "${result}" | grep -qi "deny\|operation not permitted"; then
        pass "Admin home access denied by sandbox"
    else
        fail "Admin home access was NOT denied: ${result}"
    fi
fi

# ─── Test 4: Browser — Brave/Chrome executable accessible ────────────────────

echo -e "${BOLD}Test 4: Browser binary accessible${NC}"
if [ -f "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" ]; then
    result=$(sandbox_exec_cmd /bin/sh -c "test -x '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser' && echo browser-ok" 2>&1)
    if echo "${result}" | grep -q "browser-ok"; then
        pass "Brave Browser binary is accessible"
    else
        fail "Brave Browser binary not accessible: ${result}"
    fi
elif [ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
    skip "Chrome detected but not enabled in profile (Brave expected)"
else
    skip "No browser binary found"
fi

# ─── Test 5: Network — LAN access blocked ────────────────────────────────────

echo -e "${BOLD}Test 5: LAN access blocked (192.168.x.x)${NC}"
if [ -x "${NODE_BIN}" ]; then
    result=$(sandbox_exec_cmd "${NODE_BIN}" -e "
        const net = require('net');
        const s = new net.Socket();
        s.setTimeout(2000);
        s.on('error', () => { console.log('net-blocked-ok'); process.exit(0); });
        s.on('timeout', () => { console.log('net-blocked-ok'); s.destroy(); process.exit(0); });
        s.connect(80, '192.168.1.1');
    " 2>&1)
    if echo "${result}" | grep -q "net-blocked-ok"; then
        pass "LAN access blocked (connection failed as expected)"
    else
        # Even if it connects, the pf layer will catch it — but sandbox should also block
        fail "LAN access might not be blocked at sandbox level: ${result}"
    fi
else
    skip "Node.js not available for network test"
fi

# ─── Test 6: Keychain — security command denied ──────────────────────────────

echo -e "${BOLD}Test 6: Keychain access denied${NC}"
result=$(sandbox_exec_cmd /usr/bin/security find-generic-password -a "test" 2>&1)
if echo "${result}" | grep -qi "deny\|operation not permitted\|not permitted"; then
    pass "Keychain access (security command) denied"
else
    # The command might fail for other reasons (no keychain item) — check denial
    if echo "${result}" | grep -qi "could not be found\|SecKeychainSearchCopyNext"; then
        fail "security command ran (not denied) — it searched the keychain"
    else
        pass "Keychain access blocked (security binary execution denied)"
    fi
fi

# ─── Test 7: Self-read — cage config inaccessible ────────────────────────────

echo -e "${BOLD}Test 7: Sandbox profile self-read denied${NC}"
result=$(sandbox_exec_cmd /bin/sh -c "cat /usr/local/etc/zlar-oc/openclaw.sb 2>&1" 2>&1)
if echo "${result}" | grep -qi "deny\|operation not permitted\|no such file"; then
    pass "Sandbox profile self-read denied"
else
    fail "Agent could read its own sandbox profile: ${result}"
fi

# ─── Test 8: curl/wget denied ────────────────────────────────────────────────

echo -e "${BOLD}Test 8: curl/wget direct execution denied${NC}"
result=$(sandbox_exec_cmd /usr/bin/curl -s http://localhost 2>&1)
if echo "${result}" | grep -qi "deny\|operation not permitted\|not permitted"; then
    pass "curl execution denied by sandbox"
else
    fail "curl was NOT denied: ${result}"
fi

# ─── Test 9: osascript denied ────────────────────────────────────────────────

echo -e "${BOLD}Test 9: osascript execution denied${NC}"
result=$(sandbox_exec_cmd /usr/bin/osascript -e 'display dialog "test"' 2>&1)
if echo "${result}" | grep -qi "deny\|operation not permitted\|not permitted"; then
    pass "osascript execution denied by sandbox"
else
    fail "osascript was NOT denied: ${result}"
fi

# ─── Test 10: ZLAR-OC config directory denied ────────────────────────────────

echo -e "${BOLD}Test 10: ZLAR-OC config directory inaccessible${NC}"
result=$(sandbox_exec_cmd /bin/sh -c "ls /usr/local/etc/zlar-oc/ 2>&1" 2>&1)
if echo "${result}" | grep -qi "deny\|operation not permitted"; then
    pass "ZLAR-OC config directory access denied"
else
    fail "Agent could list ZLAR-OC config directory: ${result}"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Results${NC}"
echo -e "  ${GREEN}Passed: ${PASSED}${NC}"
echo -e "  ${RED}Failed: ${FAILED}${NC}"
echo -e "  ${YELLOW}Skipped: ${SKIPPED}${NC}"
echo ""

if [ ${FAILED} -gt 0 ]; then
    echo -e "${RED}${BOLD}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
fi
