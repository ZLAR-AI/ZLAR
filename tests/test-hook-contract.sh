#!/bin/bash
# test-hook-contract.sh — Process-level regression test for the ZLAR hook
# contract with Claude Code.
#
# Drives bin/zlar-gate as a subprocess with fixture stdin + isolated audit
# file + isolated approvals + isolated inbox + PATH-shim curl. Asserts that
# every intended-block path emits BOTH:
#   - JSON deny on stdout (hookSpecificOutput.permissionDecision=deny)
#   - exit code 2
# and that allow paths emit JSON allow + exit 0.
#
# This is the belt-and-suspenders contract test landed alongside R041
# contract hardening (2026-05-12). The previous JSON-deny-on-exit-0 form
# was already blocking per Anthropic's documented contract; this test
# locks in the second signal so a future regression on either is caught.
#
# Scope is intentionally narrow: three scenarios that directly exercise
# the patch surfaces. ASK-retry deny/approve paths share the same response
# helpers (respond_deny / respond_allow_or_sandbox) and are covered for
# JSON-shape regression by test-deny-then-retry-hook.sh. The exit-code
# emission they share with TC1/TC2 here is by construction.
#
# Live-harness verification (does Claude Code actually honor both signals
# in combination?) is a separate manual smoke step — this file only proves
# the gate emits the right shape from its own subprocess.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GATE="${PROJECT_DIR}/bin/zlar-gate"

if [ ! -x "${GATE}" ]; then
    echo "FATAL: cannot locate executable bin/zlar-gate at ${GATE}" >&2
    exit 1
fi

# Gate-off preflight. With /etc/zlar/off-flag present, every subprocess
# bin/zlar-gate invocation hits the off-flag short-circuit at the top of
# the gate and returns allow without evaluating policy. The test cannot
# validate enforcement in that state. Skip loud so the operator knows
# why and what to do.
if [ -f /etc/zlar/off-flag ]; then
    echo "SKIP: /etc/zlar/off-flag is present — gate is globally off." >&2
    echo "SKIP: This test validates the gate's enforcement contract." >&2
    echo "SKIP: Run 'zlar on' to re-enable enforcement, then re-run this test." >&2
    exit 2
fi

TEST_DIR=$(mktemp -d)
INBOX_DIR="${TEST_DIR}/inbox"
APPROVAL_DIR="${TEST_DIR}/approvals"
AUDIT_FILE="${TEST_DIR}/audit.jsonl"
STUB_DIR="${TEST_DIR}/stubs"
STDERR_LOG="${TEST_DIR}/stderr.log"
mkdir -p "${INBOX_DIR}" "${APPROVAL_DIR}" "${STUB_DIR}"
: > "${AUDIT_FILE}"
: > "${STDERR_LOG}"
trap 'rm -rf "${TEST_DIR}"' EXIT

# ── PATH-shim curl ────────────────────────────────────────────────────────────
# The gate calls curl exclusively for Telegram API. Replace with a stub that
# returns a synthetic sendMessage success without making any network calls.
# Prepended to PATH so the gate's `curl` resolves to this stub; real curl
# elsewhere is unaffected.
cat > "${STUB_DIR}/curl" <<'CURLSH'
#!/bin/bash
cat </dev/null >/dev/null 2>&1 || true
while [ "$#" -gt 0 ]; do shift; done
echo '{"ok":true,"result":{"message_id":1,"date":1700000000,"chat":{"id":123456}}}'
exit 0
CURLSH
chmod +x "${STUB_DIR}/curl"

# ── Gate-invocation environment ──────────────────────────────────────────────
export ZLAR_AUDIT_FILE="${AUDIT_FILE}"
export ZLAR_APPROVAL_DIR="${APPROVAL_DIR}"
export ZLAR_INBOX_DIR="${INBOX_DIR}"
export ZLAR_MANIFEST_FILE="${TEST_DIR}/manifest.json"
export ZLAR_MANIFEST_SEQ_FILE="${TEST_DIR}/manifest-last-seq"
export ZLAR_TELEGRAM_CHAT_ID="123456"
export TELEGRAM_CHAT_ID="123456"
export TELEGRAM_BOT_TOKEN="stub-token-not-real"
export ZLAR_TELEGRAM_TOKEN="stub-token-not-real"
unset ZLAR_INBOX_HMAC_SECRET 2>/dev/null || true

PATH="${STUB_DIR}:${PATH}"
export PATH

# ── Assertion helpers ────────────────────────────────────────────────────────
passed=0
failed=0
fail_lines=()

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    else
        echo "  ✗ ${desc} (expected=${expected}, got=${actual})"
        fail_lines+=("FAIL: ${desc} (expected=${expected}, got=${actual})")
        failed=$((failed + 1))
    fi
}

assert_match() {
    local desc="$1" pattern="$2" actual="$3"
    if echo "${actual}" | grep -qE "${pattern}"; then
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    else
        echo "  ✗ ${desc} (pattern=${pattern})"
        echo "    actual: ${actual}"
        fail_lines+=("FAIL: ${desc} (pattern=${pattern})")
        failed=$((failed + 1))
    fi
}

assert_jq() {
    local desc="$1" jq_expr="$2" expected="$3" stdout="$4"
    local actual
    actual=$(echo "${stdout}" | jq -r "${jq_expr}" 2>/dev/null)
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    else
        echo "  ✗ ${desc} (jq ${jq_expr}: expected=${expected}, got=${actual})"
        fail_lines+=("FAIL: ${desc} (jq ${jq_expr}: expected=${expected}, got=${actual})")
        failed=$((failed + 1))
    fi
}

audit_lines() {
    wc -l < "${AUDIT_FILE}" 2>/dev/null | tr -d '[:space:]'
}

# ── Gate runner ──────────────────────────────────────────────────────────────
# Pipes JSON to bin/zlar-gate, captures stdout + exit code + audit delta.
# Sets globals: OUT, RC, AUDIT_PRE, AUDIT_POST, AUDIT_DELTA.
run_gate() {
    local input="$1"
    AUDIT_PRE=$(audit_lines)
    OUT=$(printf '%s' "${input}" | "${GATE}" 2>>"${STDERR_LOG}")
    RC=$?
    AUDIT_POST=$(audit_lines)
    AUDIT_DELTA=$((AUDIT_POST - AUDIT_PRE))
}

echo "═══════════════════════════════════════════════════════════════"
echo "  ZLAR hook contract test (process-level)"
echo "  Gate: ${GATE}"
echo "  Test dir: ${TEST_DIR}"
echo "═══════════════════════════════════════════════════════════════"
echo

# ── TC1: deterministic deny via Bash sudo (R003-family) ──────────────────
# Bash + sudo is a load-bearing deterministic deny. Tests respond_deny →
# _GATE_EXIT_CODE=2 → final exit 2 path; JSON deny on stdout; audit gain.
echo "── TC1: deterministic deny (Bash sudo) ──"
TC1_INPUT='{"session_id":"test-hook-contract-tc1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sudo ls /etc"}}'
run_gate "${TC1_INPUT}"
assert_eq    "TC1 exit code is 2"             "2"     "${RC}"
assert_jq    "TC1 hookEventName=PreToolUse"   '.hookSpecificOutput.hookEventName'       "PreToolUse" "${OUT}"
assert_jq    "TC1 permissionDecision=deny"    '.hookSpecificOutput.permissionDecision'  "deny"       "${OUT}"
assert_match "TC1 reason has policy/manifest tag" '^\[(policy|manifest|gate)' "$(echo "${OUT}" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')"
assert_eq    "TC1 audit gained 1 line"        "1"     "${AUDIT_DELTA}"
echo

# ── TC2: deterministic deny via Edit on enforcement path (R041 base) ────
# Edit on bin/zlar-gate or similar enforcement-layer path triggers R041
# deterministic deny. Tests the same respond_deny → exit 2 path via a
# different tool (Edit instead of Bash) and a different rule.
echo "── TC2: deterministic deny (Edit on enforcement path) ──"
TC2_INPUT='{"session_id":"test-hook-contract-tc2","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/Users/tester/Desktop/ZLAR/ZLAR_Repo/bin/zlar-gate","old_string":"_GATE_EXIT_CODE=0","new_string":"_GATE_EXIT_CODE=99"}}'
run_gate "${TC2_INPUT}"
assert_eq    "TC2 exit code is 2"             "2"     "${RC}"
assert_jq    "TC2 hookEventName=PreToolUse"   '.hookSpecificOutput.hookEventName'       "PreToolUse" "${OUT}"
assert_jq    "TC2 permissionDecision=deny"    '.hookSpecificOutput.permissionDecision'  "deny"       "${OUT}"
assert_match "TC2 reason has policy tag"      '^\[(policy|manifest|gate)' "$(echo "${OUT}" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""')"
assert_eq    "TC2 audit gained 1 line"        "1"     "${AUDIT_DELTA}"
echo

# ── TC3: internal-tool fast-path allow ─────────────────────────────────────
# TodoWrite is DOMAIN=internal — hits the fast-path at bin/zlar-gate:2518.
# Tests respond_allow path → _GATE_EXIT_CODE stays 0 → final exit 0.
echo "── TC3: internal-tool fast-path (TodoWrite) ──"
TC3_INPUT='{"session_id":"test-hook-contract-tc3","hook_event_name":"PreToolUse","tool_name":"TodoWrite","tool_input":{"todos":[]}}'
run_gate "${TC3_INPUT}"
assert_eq    "TC3 exit code is 0"             "0"     "${RC}"
assert_jq    "TC3 hookEventName=PreToolUse"   '.hookSpecificOutput.hookEventName'       "PreToolUse" "${OUT}"
assert_jq    "TC3 permissionDecision=allow"   '.hookSpecificOutput.permissionDecision'  "allow"      "${OUT}"
assert_eq    "TC3 audit gained 1 line"        "1"     "${AUDIT_DELTA}"
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════"
echo "Results: ${passed}/$((passed + failed)) passed, ${failed} failed"
echo "═══════════════════════════════════════════════════════════════"

if [ "${failed}" -gt 0 ]; then
    echo
    echo "FAILED ASSERTIONS:"
    for line in "${fail_lines[@]}"; do
        echo "  ${line}"
    done
    if [ -s "${STDERR_LOG}" ]; then
        echo
        echo "Gate stderr captured during test (tail 50):"
        tail -n 50 "${STDERR_LOG}"
    fi
    exit 1
fi
exit 0
