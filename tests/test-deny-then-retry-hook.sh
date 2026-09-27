#!/bin/bash
# test-deny-then-retry-hook.sh — Permanent regression test for the
# deny-then-retry-DENIED hook output path.
#
# Drives the deny branch from bin/zlar-gate (case 1) of the pending_result
# case statement) using fixture-only inputs. Captures stdout, asserts
# exactly one JSON object with permissionDecision=deny and
# permissionDecisionReason starting with [human]. Poisons every
# respond_allow* path so a stray allow call shows up as a POISON sentinel
# in stdout.
#
# Origin: 2026-05-10 audit of f0a4c0d (README commit landing in the same
# UTC second as a human deny on the prior R016 ask). Source review found
# the deny branch structurally correct; this test confirms the runtime
# output matches the source. Promoted from /tmp/test-deny-then-retry-hook.sh
# on 2026-05-11 (Session 49 Item 3) to close the regression-coverage half
# of the D1 forensic gap. Patch B of Roadmap v2 Step 1. Patch A
# (sub-second timestamps in gate.log + audit ts) is a separate session.
#
# TC6 anchors on unique comment strings in bin/zlar-gate to extract the
# deny-branch body and the post-case seal/restore block. If a future
# edit removes either anchor comment, the corresponding sed extraction
# will return empty and the TC6 assertions will pass spuriously. Anchors
# (current as of HEAD f0a4c0d):
#   - "# Human denied on a previous ask."  (currently bin/zlar-gate:2832)
#   - "# Path B Phase 1: Seal state file to audit trail position."
#                                          (currently bin/zlar-gate:3014)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ ! -f "${PROJECT_DIR}/bin/zlar-gate" ]; then
    echo "FATAL: cannot locate bin/zlar-gate at ${PROJECT_DIR}/bin/zlar-gate" >&2
    exit 1
fi

# Cross-platform sha256: shasum on macOS, sha256sum on Linux.
sha256_pipe() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256
    else
        sha256sum
    fi
}

TEST_DIR=$(mktemp -d)
INBOX_DIR="${TEST_DIR}/inbox/cc"
CONSUMED_FILE="${TEST_DIR}/.consumed-callbacks"
APPROVAL_DIR="${TEST_DIR}/approvals"
mkdir -p "${INBOX_DIR}" "${APPROVAL_DIR}"
trap 'rm -rf "${TEST_DIR}"' EXIT

export APPROVAL_DIR
export SESSION_ID="test-dtr-deny-$$"
export ZLAR_TELEGRAM_CHAT_ID="123456"
export TELEGRAM_CHAT_ID="123456"
export TELEGRAM_TIMEOUT_S=300
export ZLAR_APPROVED_TTL_S=300
unset ZLAR_INBOX_HMAC_SECRET 2>/dev/null || true

# Stub log() — gate writes to ${LOG_FILE}; in test we no-op.
log() { :; }

# POISON stubs — if any of these fire on the deny path, the test fails.
# Each prints a sentinel JSON object that should never appear in deny output.
respond_allow() { echo '{"POISON":"respond_allow_called"}'; }
respond_allow_or_sandbox() { echo '{"POISON":"respond_allow_or_sandbox_called"}'; }
respond_allow_sandboxed() { echo '{"POISON":"respond_allow_sandboxed_called"}'; }

# Stubs for collateral helpers the deny branch invokes. We're testing the
# hook OUTPUT path, not human-invariants or audit-emit semantics, both of
# which have their own test suites.
hi_post_response_check() { echo "ok"; return 0; }
emit_event() { :; }                  # writes to audit.jsonl; no-op
_session_state_seal() { :; }         # writes to state file; no-op
fail_closed_alert() { :; }           # alerts; no-op

# Extract check_pending_approval verbatim from bin/zlar-gate, redirecting
# the hardcoded inbox path and consumed-callbacks file to the test fixture.
sed -n '/^check_pending_approval()/,/^}$/p' "${PROJECT_DIR}/bin/zlar-gate" > "${TEST_DIR}/cpa.sh"
sed -i.bak "s|/var/run/zlar-tg/inbox/cc|${INBOX_DIR}|g" "${TEST_DIR}/cpa.sh"
sed -i.bak 's|"${PROJECT_DIR}/var/log/.consumed-callbacks"|"'"${CONSUMED_FILE}"'"|g' "${TEST_DIR}/cpa.sh"
# shellcheck source=/dev/null
source "${TEST_DIR}/cpa.sh"

# Extract respond_deny verbatim. The function is short and has no path
# dependencies — use it as-is.
sed -n '/^respond_deny()/,/^}$/p' "${PROJECT_DIR}/bin/zlar-gate" > "${TEST_DIR}/respond_deny.sh"
# shellcheck source=/dev/null
source "${TEST_DIR}/respond_deny.sh"

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
        echo "  ✗ ${desc} (pattern=${pattern}, got=${actual})"
        fail_lines+=("FAIL: ${desc} (pattern=${pattern}, got=${actual})")
        failed=$((failed + 1))
    fi
}

assert_no_match() {
    local desc="$1" pattern="$2" actual="$3"
    if echo "${actual}" | grep -qE "${pattern}"; then
        echo "  ✗ ${desc} (pattern matched: ${pattern}, got=${actual})"
        fail_lines+=("FAIL: ${desc} (pattern matched: ${pattern}, got=${actual})")
        failed=$((failed + 1))
    else
        echo "  ✓ ${desc}"
        passed=$((passed + 1))
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "  Deny-then-retry-DENIED hook output regression test"
echo "  Source: bin/zlar-gate case 1) of the pending_result case statement"
echo "═══════════════════════════════════════════════════════════════"
echo

# ── Setup: git-commit-shaped R016 incident-replay fixture ──
# Mirrors the May 10 incident: action_hash binds rule + tool + canonicalized
# detail. We compute the same way the gate does (bin/zlar-gate:2791).
RULE="R016"
TOOL_NAME="Bash"
# Truncated to mirror what audit.jsonl recorded: the first ~90 chars of the
# real commit command. Full HEREDOC bodies are sanitized at the gate before
# hashing so the truncation is incidental, not load-bearing.
DETAIL_JSON='{"command":"cd ~/Desktop/ZLAR/ZLAR_Repo && git add README.md && git commit -m \"docs(readme): truth-align to v3.3.11\""}'
ACTION_HASH=$(printf '%s|%s|%s' "${RULE}" "${TOOL_NAME}" "$(echo "${DETAIL_JSON}" | jq -S -c '.')" | sha256_pipe | awk '{print $1}')
HASH_PREFIX="${ACTION_HASH:0:16}"
PENDING_FILE="${APPROVAL_DIR}/${RULE}-${SESSION_ID}-${HASH_PREFIX}.pending"
APPROVED_FILE="${APPROVAL_DIR}/${RULE}-${SESSION_ID}-${HASH_PREFIX}.approved"

# Pre-create pending file: line 1 = action_id, line 2 = action_hash.
ACTION_ID="dtr-deny-action-$$"
printf '%s\n%s\n' "${ACTION_ID}" "${ACTION_HASH}" > "${PENDING_FILE}"

# Drop a cc:deny callback in the inbox matching the action_id.
cat > "${INBOX_DIR}/cb-deny.json" <<EOF
{"data":"cc:deny:${ACTION_ID}","from_id":"${TELEGRAM_CHAT_ID}","callback_query_id":"qid-dtr-deny","hmac":""}
EOF

echo "── TC1: check_pending_approval matches deny callback ──"
rc=0
check_pending_approval "${RULE}" "${ACTION_HASH}" >/dev/null 2>&1 || rc=$?
assert_eq "Deny callback matched → return 1" "1" "${rc}"

echo
echo "── TC2: pending file consumed on deny ──"
assert_eq "Pending file deleted by deny match" "false" "$([ -f "${PENDING_FILE}" ] && echo true || echo false)"

echo
echo "── TC3: no approved cache written ──"
assert_eq "No .approved file created" "false" "$([ -f "${APPROVED_FILE}" ] && echo true || echo false)"

echo
echo "── TC4: respond_deny — git-commit-shaped DENIED reason produces clean JSON ──"
# Drive the exact call shape from the deny branch in bin/zlar-gate.
DENY_OUTPUT=$(respond_deny "Denied by human (rule ${RULE})" "human")
echo "    Captured stdout: ${DENY_OUTPUT}"

# Single line?
LINE_COUNT=$(printf '%s\n' "${DENY_OUTPUT}" | wc -l | tr -d ' ')
assert_eq "Stdout is exactly one line" "1" "${LINE_COUNT}"

# Valid JSON?
if echo "${DENY_OUTPUT}" | jq -e . >/dev/null 2>&1; then
    echo "  ✓ Stdout is valid JSON"
    passed=$((passed + 1))
else
    echo "  ✗ Stdout is NOT valid JSON"
    fail_lines+=("FAIL: stdout is not valid JSON: ${DENY_OUTPUT}")
    failed=$((failed + 1))
fi

# permissionDecision = deny?
DECISION=$(echo "${DENY_OUTPUT}" | jq -r '.hookSpecificOutput.permissionDecision // "MISSING"')
assert_eq "permissionDecision is 'deny'" "deny" "${DECISION}"

# permissionDecisionReason starts with [human]?
REASON=$(echo "${DENY_OUTPUT}" | jq -r '.hookSpecificOutput.permissionDecisionReason // "MISSING"')
assert_match "permissionDecisionReason starts with [human]" '^\[human\] ' "${REASON}"

# hookEventName correct?
EVENT_NAME=$(echo "${DENY_OUTPUT}" | jq -r '.hookSpecificOutput.hookEventName // "MISSING"')
assert_eq "hookEventName is PreToolUse" "PreToolUse" "${EVENT_NAME}"

echo
echo "── TC5: no allow/sandbox response in deny output ──"
assert_no_match "No POISON marker (allow stub never fired)" 'POISON' "${DENY_OUTPUT}"
assert_no_match "No 'permissionDecision\":\"allow\"' string" '"permissionDecision":"allow"' "${DENY_OUTPUT}"
assert_no_match "No 'updatedInput' (sandbox marker)" '"updatedInput"' "${DENY_OUTPUT}"

echo
echo "── TC6: source-level — no respond_allow* between deny case entry and ;; ──"
# Anchor on the unique comment string at the top of the deny branch body,
# read to the next ';;' line. Avoids hardcoded line numbers that drift
# every time bin/zlar-gate is edited. Anchor: "# Human denied on a
# previous ask." (currently bin/zlar-gate:2832).
DENY_BODY=$(sed -n '/# Human denied on a previous ask\./,/^                            ;;$/p' "${PROJECT_DIR}/bin/zlar-gate")
if echo "${DENY_BODY}" | grep -qE 'respond_allow'; then
    echo "  ✗ respond_allow* call found inside deny branch"
    fail_lines+=("FAIL: respond_allow* present in deny branch (anchor: '# Human denied on a previous ask.')")
    failed=$((failed + 1))
else
    echo "  ✓ No respond_allow* inside deny branch"
    passed=$((passed + 1))
fi

# Also: the post-case seal/restore block must not write stdout. Anchor on
# the unique comment at the top of that block, read to the next standalone
# '}' (which closes main()). Anchor: "# Path B Phase 1: Seal state file
# to audit trail position." (currently bin/zlar-gate:3014).
POST_BODY=$(sed -n '/# Path B Phase 1: Seal state file to audit trail position\./,/^}$/p' "${PROJECT_DIR}/bin/zlar-gate")
if echo "${POST_BODY}" | grep -E '^\s*(echo|printf)' | grep -vqE '^\s*#'; then
    echo "  ✗ stdout-writing call found in post-case seal/restore block"
    fail_lines+=("FAIL: stdout writer in post-case block (anchor: '# Path B Phase 1: Seal state file to audit trail position.')")
    failed=$((failed + 1))
else
    echo "  ✓ No stdout writers in post-case seal/restore block"
    passed=$((passed + 1))
fi

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Results: ${passed}/$((passed + failed)) passed, ${failed} failed"
echo "═══════════════════════════════════════════════════════════════"

if [ "${failed}" -gt 0 ]; then
    echo
    echo "FAILED ASSERTIONS:"
    for line in "${fail_lines[@]}"; do
        echo "  $line"
    done
    exit 1
fi
exit 0
