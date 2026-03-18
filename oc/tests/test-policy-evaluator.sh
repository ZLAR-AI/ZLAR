#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR-OC Smoke Tests: Policy Evaluator
#
# Tests the gate's policy evaluation logic by sourcing its functions and
# running events against the default policy.
#
# This test does NOT require macOS — it tests pure logic.
#
# Usage:
#   ./tests/test-policy-evaluator.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
POLICY_FILE="${REPO_ROOT}/etc/zlar-oc/policies/default.policy.json"

PASSED=0
FAILED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BOLD='\033[1m'; NC='\033[0m'

pass() { PASSED=$((PASSED + 1)); echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { FAILED=$((FAILED + 1)); echo -e "  ${RED}FAIL${NC} $1"; }

echo -e "${BOLD}ZLAR-OC Policy Evaluator Tests${NC}"
echo -e "Policy: ${POLICY_FILE}"
echo ""

# ─── Pre-flight ───────────────────────────────────────────────────────────────

if [ ! -f "${POLICY_FILE}" ]; then
    echo "Policy file not found: ${POLICY_FILE}"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "jq is required for these tests. Install with: brew install jq / apt install jq"
    exit 1
fi

# ─── Inline Policy Evaluator (extracted from gate logic) ─────────────────────
# We replicate the core evaluation to test it without starting the daemon.

POLICY_DEFAULT_ACTION=""
POLICY_RULE_COUNT=0
declare -a RULE_IDS=()
declare -a RULE_ENABLED=()
declare -a RULE_DOMAINS=()
declare -a RULE_SOURCES=()
declare -a RULE_DETAIL_JSON=()
declare -a RULE_ACTION=()
EVAL_RULE_ID=""

load_test_policy() {
    POLICY_DEFAULT_ACTION=$(jq -r '.default_action' "${POLICY_FILE}")
    local rule_count
    rule_count=$(jq '.rules | length' "${POLICY_FILE}")

    RULE_IDS=()
    RULE_ENABLED=()
    RULE_DOMAINS=()
    RULE_SOURCES=()
    RULE_DETAIL_JSON=()
    RULE_ACTION=()

    local i=0
    while [ ${i} -lt "${rule_count}" ]; do
        RULE_IDS+=("$(jq -r ".rules[${i}].id" "${POLICY_FILE}")")
        RULE_ENABLED+=("$(jq -r ".rules[${i}].enabled" "${POLICY_FILE}")")
        RULE_DOMAINS+=("$(jq -r ".rules[${i}].match.domain // \"\"" "${POLICY_FILE}")")
        RULE_SOURCES+=("$(jq -r ".rules[${i}].match.source // \"\"" "${POLICY_FILE}")")
        RULE_DETAIL_JSON+=("$(jq -c ".rules[${i}].match.detail // {}" "${POLICY_FILE}")")
        RULE_ACTION+=("$(jq -r ".rules[${i}].action" "${POLICY_FILE}")")
        i=$((i + 1))
    done

    POLICY_RULE_COUNT=${#RULE_IDS[@]}
}

# Simplified evaluator (matches gate logic)
evaluate() {
    local event_domain="$1"
    local event_source="$2"
    local event_detail="$3"

    EVAL_RULE_ID=""

    local i=0
    while [ ${i} -lt ${POLICY_RULE_COUNT} ]; do
        if [ "${RULE_ENABLED[${i}]}" = "false" ]; then
            i=$((i + 1))
            continue
        fi

        local matched="true"

        # Match domain
        if [ -n "${RULE_DOMAINS[${i}]}" ] && [ "${RULE_DOMAINS[${i}]}" != "${event_domain}" ]; then
            matched="false"
        fi

        # Match source
        if [ -n "${RULE_SOURCES[${i}]}" ] && [ "${RULE_SOURCES[${i}]}" != "${event_source}" ]; then
            matched="false"
        fi

        # Match detail fields
        if [ "${matched}" = "true" ] && [ "${RULE_DETAIL_JSON[${i}]}" != "{}" ]; then
            local fields
            fields=$(echo "${RULE_DETAIL_JSON[${i}]}" | jq -r 'keys[]')

            for field in ${fields}; do
                local matcher_type
                matcher_type=$(echo "${RULE_DETAIL_JSON[${i}]}" | jq -r ".${field} | keys[0]")
                local event_value
                event_value=$(echo "${event_detail}" | jq -r ".${field} // \"\"")

                case "${matcher_type}" in
                    eq)
                        local matcher_value
                        matcher_value=$(echo "${RULE_DETAIL_JSON[${i}]}" | jq -r ".${field}.eq")
                        if [ "${event_value}" != "${matcher_value}" ]; then
                            matched="false"
                        fi
                        ;;
                    in)
                        local found="false"
                        local items
                        items=$(echo "${RULE_DETAIL_JSON[${i}]}" | jq -r ".${field}.in[]")
                        for item in ${items}; do
                            if [ "${event_value}" = "${item}" ]; then
                                found="true"
                                break
                            fi
                        done
                        if [ "${found}" = "false" ]; then
                            matched="false"
                        fi
                        ;;
                    prefix)
                        local matcher_value
                        matcher_value=$(echo "${RULE_DETAIL_JSON[${i}]}" | jq -r ".${field}.prefix")
                        if [[ ! "${event_value}" == "${matcher_value}"* ]]; then
                            matched="false"
                        fi
                        ;;
                    contains)
                        local matcher_value
                        matcher_value=$(echo "${RULE_DETAIL_JSON[${i}]}" | jq -r ".${field}.contains")
                        if [[ ! "${event_value}" == *"${matcher_value}"* ]]; then
                            matched="false"
                        fi
                        ;;
                    regex)
                        local matcher_value
                        matcher_value=$(echo "${RULE_DETAIL_JSON[${i}]}" | jq -r ".${field}.regex")
                        if [[ ! "${event_value}" =~ ${matcher_value} ]]; then
                            matched="false"
                        fi
                        ;;
                esac
            done
        fi

        if [ "${matched}" = "true" ]; then
            echo "${RULE_ACTION[${i}]}:${RULE_IDS[${i}]}"
            return
        fi

        i=$((i + 1))
    done

    echo "${POLICY_DEFAULT_ACTION}:"
}

# ─── Load Policy ─────────────────────────────────────────────────────────────

load_test_policy
echo "  Loaded ${POLICY_RULE_COUNT} rules, default=${POLICY_DEFAULT_ACTION}"
echo ""

# ─── Helper to parse result ──────────────────────────────────────────────────
# evaluate returns "action:rule_id" — parse both parts
check() {
    local test_name="$1"
    local raw="$2"
    local expected_action="$3"
    local expected_rule="$4"

    local action="${raw%%:*}"
    local rule="${raw#*:}"

    if [ "${action}" = "${expected_action}" ] && [ "${rule}" = "${expected_rule}" ]; then
        pass "${test_name} → ${action} (${rule})"
    else
        fail "${test_name} → ${action} (${rule}), expected ${expected_action} (${expected_rule})"
    fi
}

# ─── Test Cases ──────────────────────────────────────────────────────────────

echo -e "${BOLD}Test 1: uname allowed (R001)${NC}"
check "/usr/bin/uname" "$(evaluate "exec" "gate" '{"binary":"/usr/bin/uname"}')" "allow" "R001"

echo -e "${BOLD}Test 2: git in workspace allowed (R002)${NC}"
check "git in workspace" "$(evaluate "exec" "gate" '{"binary":"/usr/bin/git","cwd":"/Users/aiagent/workspace/project"}')" "allow" "R002"

echo -e "${BOLD}Test 3: git outside workspace falls through to ask (R010)${NC}"
check "git in /etc" "$(evaluate "exec" "gate" '{"binary":"/usr/bin/git","cwd":"/etc"}')" "ask" "R010"

echo -e "${BOLD}Test 4: ffmpeg allowed (R003)${NC}"
check "ffmpeg" "$(evaluate "exec" "gate" '{"binary":"/opt/homebrew/bin/ffmpeg"}')" "allow" "R003"

echo -e "${BOLD}Test 5: Unknown binary gets ask (R010)${NC}"
check "python3" "$(evaluate "exec" "gate" '{"binary":"/usr/bin/python3"}')" "ask" "R010"

echo -e "${BOLD}Test 6: LAN access denied (R020)${NC}"
check "192.168.1.50:22" "$(evaluate "net.outbound" "gate" '{"dst_ip":"192.168.1.50","dst_port":22}')" "deny" "R020"

echo -e "${BOLD}Test 7: Known API HTTPS allowed (R021)${NC}"
check "api.anthropic.com:443" "$(evaluate "net.outbound" "gate" '{"dst_host":"api.anthropic.com","dst_port":443}')" "allow" "R021"

echo -e "${BOLD}Test 8: Admin home file access denied (R030)${NC}"
check "/Users/admin/.ssh/id_rsa" "$(evaluate "fs" "gate" '{"path":"/Users/admin/.ssh/id_rsa"}')" "deny" "R030"

echo -e "${BOLD}Test 9: ZLAR-OC config access denied (R031)${NC}"
check "ZLAR-OC config" "$(evaluate "fs" "gate" '{"path":"/usr/local/etc/zlar-oc/openclaw.sb"}')" "deny" "R031"

echo -e "${BOLD}Test 10: SSH key access denied (R032)${NC}"
check "SSH key" "$(evaluate "fs" "gate" '{"path":"/Users/aiagent/.ssh/id_ed25519"}')" "deny" "R032"

echo -e "${BOLD}Test 11: Browser navigation allowed (R040)${NC}"
check "browser.nav" "$(evaluate "browser.nav" "gate" '{"url":"https://example.com"}')" "allow" "R040"

echo -e "${BOLD}Test 12: Sub-agent spawn allowed (R050)${NC}"
check "subagent" "$(evaluate "subagent" "gate" '{"agent_id":"sub-001"}')" "allow" "R050"

echo -e "${BOLD}Test 13: Sandbox denial passes through as log (R060)${NC}"
check "sandbox denial" "$(evaluate "fs" "sandbox" '{"operation":"file-read-data","path":"/Users/admin/.env"}')" "log" "R060"

echo -e "${BOLD}Test 14: pf drop passes through as log (R061)${NC}"
check "pf drop" "$(evaluate "net.outbound" "pf" '{"dst_ip":"192.168.1.1","dst_port":80}')" "log" "R061"

echo -e "${BOLD}Test 15: Unknown domain falls to default (deny)${NC}"
raw=$(evaluate "message.out" "gate" '{"channel":"slack","text":"hello"}')
action="${raw%%:*}"
if [ "${action}" = "deny" ]; then
    pass "message.out → deny (default)"
else
    fail "message.out → ${action}, expected deny (default)"
fi

echo -e "${BOLD}Test 16: Node.js runtime allowed (R004)${NC}"
check "node" "$(evaluate "exec" "gate" '{"binary":"/opt/homebrew/bin/node"}')" "allow" "R004"

echo -e "${BOLD}Test 17: Known API HTTPS → allow (R021), unknown HTTPS → log (R022)${NC}"
check "known HTTPS" "$(evaluate "net.outbound" "gate" '{"dst_host":"api.anthropic.com","dst_port":443}')" "allow" "R021"
check "unknown HTTPS" "$(evaluate "net.outbound" "gate" '{"dst_host":"evil.example.com","dst_port":443}')" "log" "R022"
check "unknown HTTP" "$(evaluate "net.outbound" "gate" '{"dst_host":"some-api.io","dst_port":80}')" "log" "R022"

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}Results${NC}"
echo -e "  ${GREEN}Passed: ${PASSED}${NC}"
echo -e "  ${RED}Failed: ${FAILED}${NC}"
echo ""

if [ ${FAILED} -gt 0 ]; then
    echo -e "${RED}${BOLD}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
    exit 0
fi
