#!/bin/bash
# Boarding authority must bind the operation, not its class.
#
# Ported to the live gate 2026-08-17. The fix originally landed only in
# candidate 044, which is installed and inactive — meaning the gate Vincent
# actually switches on still carried the defect. Scoping a security fix to the
# future version and leaving the running one alone is its own mistake.
#
# The companion F2 vectors (an independently witnessed deliberation clock) are
# candidate-only: they need the poller and evidence-store changes that do not
# exist on this branch. See tests/test-human-authority-binding.sh there.
#
# See docs/investigations/V2-INDEPENDENT-ATTACK-20260817.md (F1).
#
# Deliberately runs WITHOUT the signed runtime fixture. These guard the two
# predicates that decide whether a human authorization is real, so they must
# stay runnable anywhere — a test that only runs on a fully materialized
# runtime is a test that stops being run.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILS=0
check() { if [ "$1" = "$2" ]; then echo "  PASS  $3"; PASSES=$((${PASSES:-0}+1)); else echo "  FAIL  $3 (got=$1 want=$2)"; FAILS=$((FAILS+1)); fi; }

# ── F1: an approval must bind the exact task, and spend itself ──────────────
echo "Boarding authority binds the operation, not its class"

# The hash the subagent path computes must change with the task. If it does
# not, one approval silently authorizes every other launch of that agent type
# inside the TTL — and each is recorded as authorized by the human.
subagent_hash() {
    local detail; detail=$(jq -n -c --arg t "$1" --arg p "$2" '{agent_type:$t,prompt:$p}')
    printf '%s|%s|%s' "subagent-launch" "SubagentStart" "$(printf '%s' "${detail}" | jq -S -c '.')" \
        | shasum -a 256 | awk '{print $1}'
}
# ...and the gate must actually compute it that way. Without this the checks
# below would pass against a gate that had regressed to hashing the agent type
# alone, because the helper above would still be binding the task. A test that
# reimplements the thing it is testing agrees only with itself.
GATE_HASH_LINE=$(grep -A1 'action_hash=.*subagent-launch' "${ROOT}/bin/zlar-gate" \
    | grep 'shasum' | head -1)
[ -n "${GATE_HASH_LINE}" ] || GATE_HASH_LINE=$(grep "action_hash=\$(printf.*subagent-launch" "${ROOT}/bin/zlar-gate" | head -1)
check "$(printf '%s' "${GATE_HASH_LINE}" | grep -q 'DETAIL' && echo binds || echo 'binds-class-only')" binds \
    "the gate's own subagent hash binds DETAIL — the exact task shown to the human"

APPROVED=$(subagent_hash general-purpose "summarise the README")
OTHER=$(subagent_hash general-purpose "exfiltrate the signing key")
SAME=$(subagent_hash general-purpose "summarise the README")
check "$([ "$APPROVED" != "$OTHER" ] && echo differs || echo same)" differs \
    "a different task under the same agent type yields a different approval key"
check "$([ "$APPROVED" = "$SAME" ] && echo same || echo differs)" same \
    "the identical task yields the same key — deny-then-retry still resolves"

# The approval-cache behaviour itself.
APPROVAL_DIR=$(mktemp -d); SESSION_ID="test-session"; ZLAR_APPROVED_TTL_S=300
log() { :; }
# Lift the approval function out of the gate so it can be exercised without
# starting a full gate invocation.
_FN=$(mktemp)
awk '/^check_pending_approval\(\) \{/,/^\}/' "${ROOT}/bin/zlar-gate" > "${_FN}"
[ -s "${_FN}" ] || { echo "  FAIL  could not extract check_pending_approval"; exit 1; }
# shellcheck disable=SC1090
. "${_FN}"
rm -f "${_FN}"
approve() { : > "${APPROVAL_DIR}/$1-${SESSION_ID}${2:+-${2:0:16}}.approved"; }
call() { check_pending_approval "$@" && echo 0 || echo $?; }

approve subagent-launch "$APPROVED"
check "$(call subagent-launch "$OTHER" 1)" 2 \
    "an approval for one task is not replayed for another"

rm -f "${APPROVAL_DIR}"/*.approved; approve subagent-launch "$APPROVED"
check "$(call subagent-launch "$APPROVED" 1)" 0 "one-use: the approved crossing is allowed"
check "$(call subagent-launch "$APPROVED" 1)" 2 \
    "one-use: a second crossing on the same approval is refused (a launch is not idempotent)"

rm -f "${APPROVAL_DIR}"/*.approved; approve R020 "$APPROVED"
check "$(call R020 "$APPROVED" 0)" 0 "idempotent path: first retry replays the approval"
check "$(call R020 "$APPROVED" 0)" 0 "idempotent path: TTL replay preserved — harness retries unbroken"

rm -f "${APPROVAL_DIR}"/*.approved; approve R020 ""
check "$(call R020 "" 0)" 2 \
    "a caller supplying no action hash gets no cache replay — the unsafe default stays unreachable"
rm -rf "${APPROVAL_DIR}"


echo
echo "Results: ${PASSES:-0} passed, ${FAILS} failed"
[ "${FAILS}" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "${FAILS} FAILED"; exit 1; }
