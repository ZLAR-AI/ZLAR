#!/bin/bash
# Test suite for canary.sh — governance health probes for HITL integrity
#
# v3.3.6 — Cross-Session Canary Lifecycle
#   Trigger eligibility (counter, cooldown, pending lock) is per-human, not
#   per-session. The .pending file in var/canary/{session_id}.canary.pending
#   stays as a routing artifact; authoritative state is in human state.
#
#   Demotion requires evidence, not absence of evidence. A missing routing
#   artifact is bookkeeping loss (canary_pending_lost) — clear, no demote.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TEST_DIR=$(mktemp -d)
trap 'rm -rf "${TEST_DIR}"' EXIT

# ── Mock environment ──
export _HI_PROJECT_DIR="${TEST_DIR}"
mkdir -p "${TEST_DIR}/var/human-state" "${TEST_DIR}/var/log"

export ZLAR_CANARY_ENABLED="true"
export ZLAR_CANARY_MIN_APPROVALS=3
export ZLAR_CANARY_PROBABILITY=100  # always trigger (deterministic)
export ZLAR_CANARY_COOLDOWN=0       # no cooldown for tests
export ZLAR_CANARY_STATE_DIR="${TEST_DIR}/canary"
mkdir -p "${ZLAR_CANARY_STATE_DIR}"

# Mock gate dependencies (canary.sh delegates HMAC + send + audit to the gate).
log() { :; }
gen_id() { echo "test-canary-$(date +%s)-$$-${RANDOM}"; }
TELEGRAM_CHAT_ID="9999999999"
TELEGRAM_TIMEOUT_S=900
telegram_api() { echo '{"ok":true,"result":{"message_id":42}}'; }
LAST_EMIT_OUTCOME=""
LAST_EMIT_DETAIL=""
ALL_EMIT_OUTCOMES=()
emit_event() {
    LAST_EMIT_OUTCOME="$3"
    LAST_EMIT_DETAIL="$4"
    ALL_EMIT_OUTCOMES+=("$3")
}
# Reset the all-emits array — useful between tests that emit multiple events.
reset_emits() { ALL_EMIT_OUTCOMES=(); LAST_EMIT_OUTCOME=""; LAST_EMIT_DETAIL=""; }
# Returns "true" if the given outcome appears in any emit since reset.
emits_contain() {
    local needle="$1"
    local e
    for e in "${ALL_EMIT_OUTCOMES[@]:-}"; do
        [ "${e}" = "${needle}" ] && { echo true; return; }
    done
    echo false
}
zlar_hmac_verify() { return 0; }

# Source dependencies. Order matters: human-invariants must load before
# canary.sh because canary.sh's new helpers delegate to hi_canary_*.
source "${PROJECT_DIR}/lib/human-invariants.sh"
source "${PROJECT_DIR}/lib/canary.sh"

PASS=0
FAIL=0
FAILED_DESCS=()

assert() {
    local desc="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        echo "  ✓ ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${desc} (expected=${expected}, actual=${actual})"
        # Record the failure for the end-of-run summary so CI logs that
        # only capture the tail of test output still show what broke.
        FAILED_DESCS+=("${desc} | expected='${expected}' actual='${actual}'")
        FAIL=$((FAIL + 1))
    fi
}

# Helper: read a field from per-human state (ignoring _hmac).
hstate() {
    local human_id="$1" field="$2"
    jq -r ".${field} // \"\"" "${TEST_DIR}/var/human-state/${human_id}.json" 2>/dev/null
}

echo "v3.3.6 Cross-Session Canary Tests"
echo "================================="
echo

# ── TC-1: hi_record_canary_approval increments per-human counter ──
echo "TC-1: per-human approval counter"
hi_record_canary_approval "human-A"
assert "counter=1 after one approval" "1" "$(hstate human-A canary_approvals_since_last)"
hi_record_canary_approval "human-A"
hi_record_canary_approval "human-A"
assert "counter=3 after three approvals" "3" "$(hstate human-A canary_approvals_since_last)"

# ── TC-2 (CS-1): counter accumulates across sessions for same human ──
echo "TC-2: cross-session accumulation (CS-1)"
canary_record_approval "session-A-1" "human-B"
canary_record_approval "session-A-1" "human-B"
canary_record_approval "session-B-1" "human-B"
assert "human-B counter=3 across two sessions" "3" "$(hstate human-B canary_approvals_since_last)"

# ── TC-3 (CS-5): counter does NOT cross humans ──
echo "TC-3: counter isolated per human (CS-5)"
canary_record_approval "session-shared" "human-C"
canary_record_approval "session-shared" "human-D"
canary_record_approval "session-shared" "human-D"
assert "human-C counter=1 (not affected by D)" "1" "$(hstate human-C canary_approvals_since_last)"
assert "human-D counter=2 (not affected by C)" "2" "$(hstate human-D canary_approvals_since_last)"

# ── TC-4: should_trigger returns false below threshold ──
echo "TC-4: should_trigger false below threshold"
canary_record_approval "sess" "human-T1"  # counter=1, threshold=3
result=0
canary_should_trigger "sess" "human-T1" && result=0 || result=$?
assert "below threshold → false" "1" "${result}"

# ── TC-5: should_trigger returns true at threshold ──
echo "TC-5: should_trigger true at threshold"
canary_record_approval "sess" "human-T1"
canary_record_approval "sess" "human-T1"  # counter=3
result=0
canary_should_trigger "sess" "human-T1" && result=0 || result=$?
assert "at threshold → true" "0" "${result}"

# ── TC-6 (CS-3): per-human pending lock blocks new trigger across sessions ──
echo "TC-6: per-human pending lock (CS-3)"
canary_send "session-X" "human-L"
result=0
canary_should_trigger "session-Y" "human-L" && result=0 || result=$?
assert "second session blocked by per-human pending" "1" "${result}"
assert "pending session is X (set by canary_send)" "session-X" "$(hstate human-L canary_pending_session_id)"

# ── TC-7: cooldown blocks trigger ──
# Set canary_last_epoch directly to "now" so the cooldown check fails.
# (Avoids relying on set_pending/clear_pending side effects on last_epoch.)
echo "TC-7: cooldown blocks trigger"
hi_record_canary_approval "human-CD"
hi_record_canary_approval "human-CD"
hi_record_canary_approval "human-CD"
NOW_EPOCH=$(date +%s)
jq --argjson now "${NOW_EPOCH}" 'del(._hmac) | .canary_last_epoch = $now' \
    "${TEST_DIR}/var/human-state/human-CD.json" > "${TEST_DIR}/h.tmp" \
    && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-CD.json"
CANARY_COOLDOWN_S=86400
result=0
canary_should_trigger "sess" "human-CD" && result=0 || result=$?
assert "cooldown not elapsed → false" "1" "${result}"
CANARY_COOLDOWN_S=0

# ── TC-8: canary_send sets per-human pending + writes routing file + resets counter ──
echo "TC-8: send persists pending state correctly"
canary_record_approval "sess" "human-S1"
canary_record_approval "sess" "human-S1"
canary_record_approval "sess" "human-S1"
canary_send "sess-S" "human-S1"
assert "routing file exists" "true" "$([ -f "${ZLAR_CANARY_STATE_DIR}/sess-S.canary.pending" ] && echo true || echo false)"
assert "human-state pending session = sess-S" "sess-S" "$(hstate human-S1 canary_pending_session_id)"
pending_id_h=$(hstate human-S1 canary_pending_id)
pending_id_f=$(cat "${ZLAR_CANARY_STATE_DIR}/sess-S.canary.pending" | tr -d '[:space:]')
assert "human-state and routing file agree on canary_id" "${pending_id_h}" "${pending_id_f}"
assert "counter reset to 0 on send" "0" "$(hstate human-S1 canary_approvals_since_last)"

# ── TC-9: approve callback → fatigue, lane demoted, pending cleared ──
# A fatigue event emits TWO audit records: governance_health_check (outcome
# fatigue_detected) and trust_lane_demoted (outcome logged). We check the
# fatigue_detected outcome via membership across all emits since reset, not
# the last-seen value (which would be trust_lane_demoted's "logged").
echo "TC-9: approve callback → fatigue + demote"
reset_emits
jq '.trust_lane = "fast"' "${TEST_DIR}/var/human-state/human-S1.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-S1.json"
canary_id_S1=$(hstate human-S1 canary_pending_id)
_canary_log_fatigue "sess-S" "${canary_id_S1}" "human-S1"
assert "trust_lane demoted fast→guarded" "guarded" "$(hstate human-S1 trust_lane)"
assert "human-state pending cleared" "" "$(hstate human-S1 canary_pending_id)"
assert "audit emitted fatigue_detected" "true" "$(emits_contain fatigue_detected)"

# ── TC-10: deny callback → healthy, pending cleared ──
echo "TC-10: deny callback → healthy + pending cleared"
hi_canary_claim_pending "human-H1" "cid-H1" "sess-H"
_canary_log_healthy "sess-H" "cid-H1" "human-H1"
assert "human-state pending cleared on healthy" "" "$(hstate human-H1 canary_pending_id)"
assert "clean_run_count incremented to 1" "1" "$(hstate human-H1 clean_run_count)"

# ── TC-11: delivery evidence + timeout + intact artifact → canary_missed → demote ──
# v3.3.7: the resolver looks at state.canary_pending_msg_id (delivery evidence)
# plus state.canary_pending_started_epoch (timeout test) plus artifact contents
# (intact vs. tampered vs. missing). msg_id is delivery/posting evidence —
# Telegram POST returned a message_id — NOT proof of human attention.
echo "TC-11: delivery + timeout + intact artifact → canary_missed → demote"
hi_canary_claim_pending "human-M1" "cid-M1" "sess-M"
hi_canary_record_delivery "human-M1" "cid-M1" "msg-M1" ""
jq '.trust_lane = "fast"' "${TEST_DIR}/var/human-state/human-M1.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-M1.json"
# Backdate started_epoch past the timeout so the resolver judges past-deadline.
jq '.canary_pending_started_epoch = 1' "${TEST_DIR}/var/human-state/human-M1.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-M1.json"
echo "cid-M1" > "${ZLAR_CANARY_STATE_DIR}/sess-M.canary.pending"
canary_check_result "sess-ignored" "human-M1" 2>/dev/null || true
assert "trust_lane demoted on canary_missed" "guarded" "$(hstate human-M1 trust_lane)"
assert "pending cleared after miss" "" "$(hstate human-M1 canary_pending_id)"
assert "stale artifact deleted" "false" "$([ -f "${ZLAR_CANARY_STATE_DIR}/sess-M.canary.pending" ] && echo true || echo false)"

# ── TC-12 (PL-1): missing artifact past timeout → canary_pending_lost, NO DEMOTE ──
# THE INVARIANT: Demotion requires evidence, not absence of evidence.
# A missing routing artifact is bookkeeping loss, not a human miss.
echo "TC-12: pending_lost — clear, NO demote (invariant: evidence not absence)"
hi_canary_claim_pending "human-P1" "cid-P1" "sess-P"
jq '.trust_lane = "fast"' "${TEST_DIR}/var/human-state/human-P1.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-P1.json"
jq '.canary_pending_started_epoch = 1' "${TEST_DIR}/var/human-state/human-P1.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-P1.json"
canary_check_result "sess-ignored" "human-P1" 2>/dev/null || true
assert "trust_lane UNCHANGED on pending_lost" "fast" "$(hstate human-P1 trust_lane)"
assert "pending cleared on pending_lost" "" "$(hstate human-P1 canary_pending_id)"

# ── TC-13 (CS-2): cross-session result resolution ──
echo "TC-13: cross-session resolution (CS-2)"
hi_canary_claim_pending "human-CS" "cid-CS" "session-A-fired"
assert "pending_session correctly recorded as A" "session-A-fired" "$(hstate human-CS canary_pending_session_id)"
_canary_log_healthy "$(hstate human-CS canary_pending_session_id)" "cid-CS" "human-CS"
assert "pending cleared after cross-session resolution" "" "$(hstate human-CS canary_pending_id)"

# ── TC-14 (CS-4): orphan .pending sweep at canary_init ──
echo "TC-14: orphan .pending sweep (CS-4)"
echo "orphan-cid-1" > "${ZLAR_CANARY_STATE_DIR}/orphan-sess.canary.pending"
python3 -c "import os, sys; os.utime(sys.argv[1], (0, 0))" "${ZLAR_CANARY_STATE_DIR}/orphan-sess.canary.pending" 2>/dev/null
hi_canary_claim_pending "human-K" "live-cid-1" "live-sess"
echo "live-cid-1" > "${ZLAR_CANARY_STATE_DIR}/live-sess.canary.pending"
python3 -c "import os, sys; os.utime(sys.argv[1], (0, 0))" "${ZLAR_CANARY_STATE_DIR}/live-sess.canary.pending" 2>/dev/null
ZLAR_HUMAN_STATE_DIR="${TEST_DIR}/var/human-state" PROJECT_DIR="${TEST_DIR}" canary_init
assert "orphan .pending swept" "false" "$([ -f "${ZLAR_CANARY_STATE_DIR}/orphan-sess.canary.pending" ] && echo true || echo false)"
assert "live-referenced .pending preserved" "true" "$([ -f "${ZLAR_CANARY_STATE_DIR}/live-sess.canary.pending" ] && echo true || echo false)"

# ── TC-15 (CS-6): bin/zlar-gate-style call (single arg + TELEGRAM_CHAT_ID fallback) ──
echo "TC-15: back-compat — TELEGRAM_CHAT_ID fallback (CS-6)"
TELEGRAM_CHAT_ID="back-compat-human"
canary_record_approval "sess-bc"
canary_record_approval "sess-bc"
assert "fallback resolved human = TELEGRAM_CHAT_ID" "2" "$(hstate back-compat-human canary_approvals_since_last)"
TELEGRAM_CHAT_ID="9999999999"

# ── TC-16 (CS-7): missing human_id is a no-op, NOT a demotion ──
# Fail-safe: when human_id cannot be resolved (no arg AND no TELEGRAM_CHAT_ID),
# do nothing. Do not punish a human that wasn't even named.
echo "TC-16: missing human_id is a no-op (CS-7)"
TELEGRAM_CHAT_ID_BACKUP="${TELEGRAM_CHAT_ID}"
TELEGRAM_CHAT_ID=""
canary_record_approval "sess-noop" "" 2>/dev/null
result=0
canary_should_trigger "sess-noop" "" && result=0 || result=$?
assert "should_trigger returns false on missing human_id" "1" "${result}"
canary_send "sess-noop" "" 2>/dev/null
assert "no .pending file created on missing human_id" "false" "$([ -f "${ZLAR_CANARY_STATE_DIR}/sess-noop.canary.pending" ] && echo true || echo false)"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID_BACKUP}"

# ── TC-17: scenario picker returns valid JSON ──
echo "TC-17: scenario picker"
scenario=$(canary_pick_scenario)
tool=$(echo "${scenario}" | jq -r '.tool' 2>/dev/null)
assert "scenario has tool field" "true" "$([ -n "${tool}" ] && echo true || echo false)"

# ── TC-18: CANARY_ENABLED=false → record + trigger are inert ──
# Restored from v3.3.5 test 5: top-level disable flag must short-circuit both
# the counter increment and the trigger evaluator.
echo "TC-18: CANARY_ENABLED=false guard"
CANARY_ENABLED="false"
canary_record_approval "sess-D1" "human-D1"
assert "disabled: counter NOT incremented" "" "$(hstate human-D1 canary_approvals_since_last)"
result=0
canary_should_trigger "sess-D1" "human-D1" && result=0 || result=$?
assert "disabled: should_trigger returns false" "1" "${result}"
CANARY_ENABLED="true"

# ── TC-19: scenarios file missing → hardcoded fallback ──
# Restored from v3.3.5 test 13: the safety net when canary-scenarios.json is
# absent or malformed. Fallback must always return a valid Bash scenario.
echo "TC-19: scenarios file missing → fallback"
_orig_scenarios="${CANARY_SCENARIOS_FILE}"
CANARY_SCENARIOS_FILE="/nonexistent/scenarios-file.json"
fallback=$(canary_pick_scenario)
fb_tool=$(echo "${fallback}" | jq -r '.tool' 2>/dev/null)
fb_display=$(echo "${fallback}" | jq -r '.display' 2>/dev/null)
assert "fallback tool = Bash" "Bash" "${fb_tool}"
assert "fallback display contains curl" "true" "$(echo "${fb_display}" | grep -q 'curl' && echo true || echo false)"
CANARY_SCENARIOS_FILE="${_orig_scenarios}"

# ── TC-20: probability=0 never triggers ──
# Restored from v3.3.5 test 16: the probability gate is the final filter even
# when counter, cooldown, and pending-lock conditions all clear.
echo "TC-20: probability=0 never triggers"
CANARY_PROBABILITY=0
canary_record_approval "sess-P0" "human-P0"
canary_record_approval "sess-P0" "human-P0"
canary_record_approval "sess-P0" "human-P0"
result=0
canary_should_trigger "sess-P0" "human-P0" && result=0 || result=$?
assert "probability=0: never triggers" "1" "${result}"
CANARY_PROBABILITY=100

# ─── v3.3.7 Canary Evidence Hardening ─────────────────────────────────────────
# A1: locked claim CAS — two parallel sessions cannot both fire.
# A2: delivery-evidence-anchored resolve. msg_id (Telegram POST evidence) is
#     the discriminator between canary_missed (demote) and canary_pending_lost
#     (no demote). Tampered or destroyed artifacts are handled per evidence-
#     conservation: tampered → no demote, destroyed-post-delivery → demote
#     plus correlation audit.

# ── TC-21 (v3.3.7 A1): hi_canary_claim_pending locked CAS first wins ──
# Two consecutive claims for the same human: first wins, second loses.
# Demonstrates the CAS without needing parallel subshells (the lock body
# is what actually races; sequential calls test the same invariant).
echo "TC-21: locked claim CAS — first wins, second refused"
hi_canary_claim_pending "human-RC" "cid-RC-A" "sess-A" && r1=0 || r1=$?
hi_canary_claim_pending "human-RC" "cid-RC-B" "sess-B" && r2=0 || r2=$?
assert "first claim wins" "0" "${r1}"
assert "second claim loses" "1" "${r2}"
assert "state holds first canary_id" "cid-RC-A" "$(hstate human-RC canary_pending_id)"
assert "state holds first session_id" "sess-A" "$(hstate human-RC canary_pending_session_id)"

# ── TC-22 (v3.3.7 A2): hi_canary_record_delivery only if claim still ours ──
# msg_id update must verify the pending_id still matches the canary_id we
# claimed. A stale record_delivery from a different canary cannot overwrite
# delivery evidence belonging to the actual claim holder.
echo "TC-22: record_delivery refuses when claim no longer ours"
hi_canary_claim_pending "human-RD" "cid-RD-A" "sess-RD"
hi_canary_record_delivery "human-RD" "cid-RD-A" "msg-A" "hash-A" && r3=0 || r3=$?
hi_canary_record_delivery "human-RD" "cid-RD-WRONG" "msg-WRONG" "hash-WRONG" && r4=0 || r4=$?
assert "record_delivery for our claim succeeds" "0" "${r3}"
assert "record_delivery for foreign claim refused" "1" "${r4}"
assert "msg_id reflects our delivery, not the foreign one" "msg-A" "$(hstate human-RD canary_pending_msg_id)"

# ── TC-23 (v3.3.7 A1): hi_canary_release_pending only matching pending_id ──
# Rollback safety: release path refuses to clear another canary's claim.
echo "TC-23: release_pending rolls back only its own claim"
hi_canary_claim_pending "human-RL" "cid-RL-A" "sess-RL"
hi_canary_release_pending "human-RL" "cid-RL-WRONG" && r5=0 || r5=$?
assert "release for non-matching canary refused" "1" "${r5}"
assert "state still holds our claim" "cid-RL-A" "$(hstate human-RL canary_pending_id)"
hi_canary_release_pending "human-RL" "cid-RL-A" && r6=0 || r6=$?
assert "release for our claim succeeds" "0" "${r6}"
assert "state cleared after our release" "" "$(hstate human-RL canary_pending_id)"

# ── TC-24 (v3.3.7 A2): missing artifact + delivery proven + timeout → DEMOTE ──
# THE INVARIANT: deletion of .pending no longer suppresses canary_missed
# when delivery evidence (msg_id) exists. Demote AND emit a separate
# canary_artifact_destroyed_post_delivery audit so operators correlate.
echo "TC-24: artifact destroyed post-delivery — demote, plus correlation audit"
reset_emits
hi_canary_claim_pending "human-AD" "cid-AD" "sess-AD"
hi_canary_record_delivery "human-AD" "cid-AD" "msg-AD" "hash-AD"
jq '.trust_lane = "fast"' "${TEST_DIR}/var/human-state/human-AD.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-AD.json"
jq '.canary_pending_started_epoch = 1' "${TEST_DIR}/var/human-state/human-AD.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-AD.json"
# NO .pending file written — simulating attacker deletion.
canary_check_result "sess-ignored" "human-AD" 2>/dev/null || true
assert "trust_lane demoted (delivery evidence stands)" "guarded" "$(hstate human-AD trust_lane)"
assert "pending cleared after demote" "" "$(hstate human-AD canary_pending_id)"
assert "audit contains canary_artifact_destroyed_post_delivery" "true" "$(emits_contain warn)"

# ── TC-25 (v3.3.7 A2): tampered artifact contents → canary_pending_tampered, NO DEMOTE ──
# THE INVARIANT: tampered evidence is not delivery evidence we can act on.
# Cannot rule out attacker corruption of our own bookkeeping.
echo "TC-25: tampered artifact contents — clear, NO demote, warn audit"
reset_emits
hi_canary_claim_pending "human-TA" "cid-TA-real" "sess-TA"
hi_canary_record_delivery "human-TA" "cid-TA-real" "msg-TA" "hash-TA"
jq '.trust_lane = "fast"' "${TEST_DIR}/var/human-state/human-TA.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-TA.json"
jq '.canary_pending_started_epoch = 1' "${TEST_DIR}/var/human-state/human-TA.json" > "${TEST_DIR}/h.tmp" && mv "${TEST_DIR}/h.tmp" "${TEST_DIR}/var/human-state/human-TA.json"
# Write artifact with WRONG canary_id — simulating attacker corruption.
echo "cid-TA-tampered" > "${ZLAR_CANARY_STATE_DIR}/sess-TA.canary.pending"
canary_check_result "sess-ignored" "human-TA" 2>/dev/null || true
assert "trust_lane UNCHANGED on tampered (no demote)" "fast" "$(hstate human-TA trust_lane)"
assert "pending cleared after tampered" "" "$(hstate human-TA canary_pending_id)"
assert "tampered artifact deleted" "false" "$([ -f "${ZLAR_CANARY_STATE_DIR}/sess-TA.canary.pending" ] && echo true || echo false)"

echo
if [ "${FAIL}" -gt 0 ]; then
    echo "FAILED ASSERTIONS:"
    for d in "${FAILED_DESCS[@]}"; do
        echo "  ✗ ${d}"
    done
    echo
fi
echo "═══════════════════"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════"

exit "${FAIL}"
