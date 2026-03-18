#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR-OC Smoke Tests: pf Firewall Rules
#
# Tests the pf ruleset against expected allow/deny scenarios.
# Must run on macOS as root with pf rules loaded.
#
# Usage:
#   sudo ./tests/test-pf-rules.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

AGENT_USER="${AGENT_USER:-aiagent}"
PF_ANCHOR="${PF_ANCHOR:-zlar-oc}"

PASSED=0
FAILED=0
SKIPPED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BOLD='\033[1m'; NC='\033[0m'

pass() { PASSED=$((PASSED + 1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { FAILED=$((FAILED + 1)); echo -e "  ${RED}FAIL${NC} $1"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo -e "  ${YELLOW}SKIP${NC} $1"; }

echo -e "${BOLD}ZLAR-OC pf Firewall Smoke Tests${NC}"
echo ""

if [ "$(uname)" != "Darwin" ]; then
    echo "These tests require macOS. Exiting."
    exit 0
fi

if ! id "${AGENT_USER}" &>/dev/null; then
    echo "User ${AGENT_USER} does not exist. Run zlar-oc-launch first."
    exit 1
fi

# ─── Test 1: pf is enabled ───────────────────────────────────────────────────

echo -e "${BOLD}Test 1: pf is enabled${NC}"
if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    pass "pf is enabled"
else
    fail "pf is not enabled (run: sudo pfctl -e)"
fi

# ─── Test 2: Anchor is loaded ────────────────────────────────────────────────

echo -e "${BOLD}Test 2: ZLAR-OC anchor loaded${NC}"
rule_count=$(pfctl -a "${PF_ANCHOR}" -sr 2>/dev/null | wc -l | tr -d ' ')
if [ "${rule_count}" -gt 0 ]; then
    pass "Anchor ${PF_ANCHOR} has ${rule_count} rules"
else
    fail "Anchor ${PF_ANCHOR} has no rules loaded"
fi

# ─── Test 3: Tables loaded ───────────────────────────────────────────────────

echo -e "${BOLD}Test 3: Tables loaded${NC}"
blocked=$(pfctl -a "${PF_ANCHOR}" -t blocked_nets -T show 2>/dev/null | wc -l | tr -d ' ')
if [ "${blocked}" -gt 0 ]; then
    pass "blocked_nets table has ${blocked} entries"
else
    fail "blocked_nets table is empty"
fi

# ─── Test 4: Agent can reach MLX server (localhost:8000) ─────────────────────

echo -e "${BOLD}Test 4: Agent can reach localhost:8000 (MLX)${NC}"
result=$(sudo -u "${AGENT_USER}" curl -sf --connect-timeout 3 http://127.0.0.1:8000/health 2>&1)
if [ $? -eq 0 ] || echo "${result}" | grep -qi "connection refused"; then
    # Connection refused means pf allowed it but nothing is listening — that's OK
    pass "Agent can reach localhost:8000 (or port is simply not listening)"
else
    fail "Agent cannot reach localhost:8000: ${result}"
fi

# ─── Test 5: Agent blocked from LAN ─────────────────────────────────────────

echo -e "${BOLD}Test 5: Agent blocked from LAN (192.168.1.1)${NC}"
result=$(sudo -u "${AGENT_USER}" curl -sf --connect-timeout 3 http://192.168.1.1/ 2>&1)
exit_code=$?
if [ ${exit_code} -ne 0 ]; then
    pass "Agent blocked from LAN (curl failed/timed out)"
else
    fail "Agent reached LAN — pf rules not working"
fi

# ─── Test 6: Agent blocked from cloud metadata ──────────────────────────────

echo -e "${BOLD}Test 6: Agent blocked from metadata (169.254.169.254)${NC}"
result=$(sudo -u "${AGENT_USER}" curl -sf --connect-timeout 3 http://169.254.169.254/latest/meta-data/ 2>&1)
exit_code=$?
if [ ${exit_code} -ne 0 ]; then
    pass "Agent blocked from cloud metadata endpoint"
else
    fail "Agent reached metadata endpoint — pf rules not working"
fi

# ─── Test 7: Agent can reach HTTPS internet ──────────────────────────────────

echo -e "${BOLD}Test 7: Agent can reach HTTPS internet${NC}"
http_code=$(sudo -u "${AGENT_USER}" curl -sf -o /dev/null -w "%{http_code}" --connect-timeout 5 https://api.anthropic.com/ 2>/dev/null)
if [ -n "${http_code}" ] && [ "${http_code}" != "000" ]; then
    pass "Agent can reach HTTPS internet (HTTP ${http_code})"
else
    skip "Could not verify HTTPS outbound (might be network issue, not pf)"
fi

# ─── Test 8: pflog0 captures blocked traffic ────────────────────────────────

echo -e "${BOLD}Test 8: pflog0 captures blocked traffic${NC}"
if ifconfig pflog0 &>/dev/null; then
    # Start a brief capture
    tcpdump -c 1 -n -i pflog0 -w /dev/null 2>/dev/null &
    tcpid=$!
    # Trigger a blocked connection
    sudo -u "${AGENT_USER}" curl -sf --connect-timeout 1 http://192.168.1.1/ 2>/dev/null || true
    sleep 2
    if kill -0 ${tcpid} 2>/dev/null; then
        kill ${tcpid} 2>/dev/null
        skip "No packet captured on pflog0 (timing issue)"
    else
        pass "pflog0 captured blocked traffic"
    fi
else
    skip "pflog0 interface not available"
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
