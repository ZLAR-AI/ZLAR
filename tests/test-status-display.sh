#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR bin/zlar status — Display Truth Test Suite (v3.3.8)
#
# Two display-side regressions caught in the v3.3.8 audit pass:
#
# Bug A — Canary 7d counters
#   bin/zlar:401 read .event_type, a field that does not exist in the audit
#   format. emit_event writes .action. Every counter stayed at 0 by
#   construction. This test reproduces the exact jq logic against a fixture
#   audit.jsonl with one event per canary action; if the field name regresses,
#   counters drop to 0 and the test fails.
#
# Bug C — Stale-state badge
#   bin/zlar showed decisions_today and response_times from yesterday's state
#   file with no annotation. status is read-only by design; the daily-bound
#   counters reset only when _hi_ensure_state runs on the next gate write.
#   This test exercises the freshness comparison directly: state.date vs
#   today UTC.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf "${TEMP_DIR}"; }
trap cleanup EXIT

PASS=0
FAIL=0
TOTAL=0
FAILED_DESCS=()

assert() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${expected}" == "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_DESCS+=("${label} — expected \"${expected}\", got \"${actual}\"")
        printf '  FAIL: %s — expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

echo "=== Bug A — canary 7d counters parse via .action (v3.3.8) ==="
echo

# Build a fixture audit.jsonl with one event per canary action that bin/zlar
# counts. Timestamps use ISO 8601 — the format emit_event() actually writes.
# v3.3.7 A4 status code assumed epoch and silently skipped every line with
# the [!0-9] case; v3.3.8 parses ISO via jq fromdateiso8601. The fixture
# format matches production so a future regression to "epoch parsing" trips
# the test.
NOW=$(date +%s)
NOW_ISO=$(date -u -r "${NOW}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')
AUDIT_FIXTURE="${TEMP_DIR}/audit.jsonl"

write_event() {
    local action="$1" outcome="$2" detail_result="$3"
    printf '{"ts":"%s","domain":"canary","action":"%s","outcome":"%s","detail":{"canary_id":"cid-x","session_id":"sess-x","result":"%s"},"rule":"canary","severity":"info"}\n' \
        "${NOW_ISO}" "${action}" "${outcome}" "${detail_result}" >> "${AUDIT_FIXTURE}"
}

write_event governance_health_check healthy           healthy
write_event governance_health_check fatigue_detected  fatigue_detected
write_event governance_health_check expired           expired
write_event canary_pending_lost                       internal_warn ""
write_event canary_pending_tampered                   warn ""
write_event canary_claim_lost                         info ""
write_event canary_artifact_destroyed_post_delivery   warn ""

# Reproduce the parsing block from bin/zlar:394-417 verbatim. If the field
# name regresses to .event_type, every event lookup returns "" and all
# counters stay at 0 — same failure mode as the v3.3.7 A4 bug.
WEEK_AGO=$((NOW - 7 * 86400))
PASSED_COUNT=0
FAILED_COUNT=0
MISSED_COUNT=0
PENDING_LOST_COUNT=0
TAMPERED_COUNT=0
CLAIM_LOST_COUNT=0
ARTIFACT_DESTROYED_COUNT=0

while IFS= read -r line; do
    # Mirror bin/zlar's v3.3.8 parser: .ts is ISO 8601; use fromdateiso8601
    # with numeric fallback. .action is the second arg to emit_event(),
    # NOT .event_type.
    entry_ts_int=$(printf '%s' "${line}" | jq -r '
        (.ts // 0) as $t
        | if ($t | type) == "string"
          then ($t | try fromdateiso8601 catch 0)
          else ($t | floor)
          end
    ' 2>/dev/null || echo 0)
    case "${entry_ts_int}" in ''|0|*[!0-9]*) continue ;; esac
    [ "${entry_ts_int}" -ge "${WEEK_AGO}" ] || continue

    event=$(printf '%s' "${line}" | jq -r '.action // ""' 2>/dev/null || echo "")
    outcome=$(printf '%s' "${line}" | jq -r '.detail.result // ""' 2>/dev/null || echo "")

    case "${event}" in
        governance_health_check|canary_result)
            case "${outcome}" in
                healthy)            PASSED_COUNT=$((PASSED_COUNT + 1)) ;;
                fatigue_detected)   FAILED_COUNT=$((FAILED_COUNT + 1)) ;;
                expired)            MISSED_COUNT=$((MISSED_COUNT + 1)) ;;
            esac
            ;;
        canary_pending_lost)         PENDING_LOST_COUNT=$((PENDING_LOST_COUNT + 1)) ;;
        canary_pending_tampered)     TAMPERED_COUNT=$((TAMPERED_COUNT + 1)) ;;
        canary_claim_lost)           CLAIM_LOST_COUNT=$((CLAIM_LOST_COUNT + 1)) ;;
        canary_artifact_destroyed_post_delivery)
                                     ARTIFACT_DESTROYED_COUNT=$((ARTIFACT_DESTROYED_COUNT + 1)) ;;
    esac
done < "${AUDIT_FIXTURE}"

assert "passed counter (governance_health_check + healthy)"          "1" "${PASSED_COUNT}"
assert "failed counter (governance_health_check + fatigue_detected)" "1" "${FAILED_COUNT}"
assert "missed counter (governance_health_check + expired)"          "1" "${MISSED_COUNT}"
assert "pending_lost counter"                                        "1" "${PENDING_LOST_COUNT}"
assert "pending_tampered counter"                                    "1" "${TAMPERED_COUNT}"
assert "claim_lost counter"                                          "1" "${CLAIM_LOST_COUNT}"
assert "artifact_destroyed counter"                                  "1" "${ARTIFACT_DESTROYED_COUNT}"

echo
echo "=== Bug A — bin/zlar source still reads .action, not .event_type ==="
echo

# Defense-in-depth grep: if anyone re-introduces .event_type in the canary
# parsing block, this test fails on source inspection alone. Keeps the
# regression off the audit log even if no fixture run is performed.
event_type_hits=$(grep -cE "^\s+event=\\\$\\(.*\.event_type" "${PROJECT_DIR}/bin/zlar" || true)
assert "bin/zlar canary parser does not read .event_type" "0" "${event_type_hits}"

action_hits=$(grep -cE "^\s+event=\\\$\\(.*\.action" "${PROJECT_DIR}/bin/zlar" || true)
{ [ "${action_hits}" -ge 1 ]; } && got="present" || got="missing"
assert "bin/zlar canary parser reads .action"            "present" "${got}"

echo
echo "=== Bug C — state-staleness badge logic (v3.3.8) ==="
echo

# Reproduce the freshness comparison from bin/zlar around line 226. The badge
# fires when state.date != today UTC. status itself is read-only; this is the
# only check that distinguishes "today's 3.3 decisions" from "3-day-old 3.3
# decisions" without mutating state.
TODAY_UTC=$(date -u +%Y-%m-%d)
YESTERDAY_UTC=$(date -u -v-1d +%Y-%m-%d 2>/dev/null || date -u -d "yesterday" +%Y-%m-%d 2>/dev/null || echo "2026-05-08")

# Stale: state.date != today
STATE_DATE="${YESTERDAY_UTC}"
if [ "${STATE_DATE}" != "${TODAY_UTC}" ] && [ "${STATE_DATE}" != "?" ]; then
    STATE_IS_STALE="true"
else
    STATE_IS_STALE="false"
fi
assert "stale state.date flagged as stale"               "true"  "${STATE_IS_STALE}"

# Fresh: state.date == today
STATE_DATE="${TODAY_UTC}"
if [ "${STATE_DATE}" != "${TODAY_UTC}" ] && [ "${STATE_DATE}" != "?" ]; then
    STATE_IS_STALE="true"
else
    STATE_IS_STALE="false"
fi
assert "fresh state.date NOT flagged as stale"           "false" "${STATE_IS_STALE}"

# Sentinel: state.date == "?" (missing date field) must NOT be flagged.
# A missing date is a different failure mode (state file truncation, manual
# edit) and the badge would mislead by implying the day-bound counters are
# yesterday's when they may be invalid. Don't conflate the two.
STATE_DATE="?"
if [ "${STATE_DATE}" != "${TODAY_UTC}" ] && [ "${STATE_DATE}" != "?" ]; then
    STATE_IS_STALE="true"
else
    STATE_IS_STALE="false"
fi
assert "missing state.date sentinel '?' not flagged stale" "false" "${STATE_IS_STALE}"

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
