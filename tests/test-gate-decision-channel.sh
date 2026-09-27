#!/bin/bash
# The gate's stdout IS its decision. It must carry exactly one parseable
# instruction and nothing else.
#
# On 2026-08-17 a human denied a command, the gate recorded "DENIED by human",
# and the command executed. Cause: the deny branch called
# hi_post_response_check without capturing stdout. That helper echoes "ok",
# so the gate emitted:
#
#     ok
#     {"hookSpecificOutput":{...,"permissionDecision":"deny",...}}
#
# The harness could not parse it and fell back to allowing. The gate decided
# no, logged no, told the human no, and did not stop the action.
#
# tests/test-deny-then-retry-hook.sh TC6 already guarded this branch — it
# checked that no literal `echo`/`printf` appeared in the source. The output
# came from a called function, so a source-shape check could never see it.
# These tests run the branch and read what actually comes out.
set -uo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILS=0
check() { if [ "$1" = "$2" ]; then echo "  PASS  $3"; PASSES=$((${PASSES:-0}+1)); else echo "  FAIL  $3 (got=$1 want=$2)"; FAILS=$((FAILS+1)); fi; }

echo "Every branch that answers the harness emits exactly one JSON object"

TMP=$(mktemp -d)
# Stub everything the branch touches except the thing under test: what reaches
# stdout. The helpers below deliberately echo, exactly as the real ones do.
cat > "${TMP}/harness.sh" <<'STUB'
hi_post_response_check() { echo "ok"; return 0; }
emit_event() { :; }
log() { :; }
_session_state_seal() { :; }
hi_get_canary_tier() { echo 0; }
canary_record_approval() { :; }
canary_should_trigger() { return 1; }
TELEGRAM_CHAT_ID="123"; MATCHED_RULE="R020"; MATCHED_SEVERITY="warn"
MATCHED_RISK_SCORE="60"; action_hash="deadbeef"; DOMAIN="bash"
TOOL_DISPLAY="probe"; DETAIL="{}"; SESSION_STATE_ENABLED="false"
LAST_EMITTED_EVENT_ID=""; SESSION_STATE_FILE=""
STUB

# Lift respond_deny out of the gate rather than reimplementing it.
sed -n '/^respond_deny()/,/^}$/p' "${PROJECT_DIR}/bin/zlar-gate" > "${TMP}/respond_deny.sh"
[ -s "${TMP}/respond_deny.sh" ] || { echo "  FAIL  could not extract respond_deny"; exit 1; }

# The deny branch body, anchored on its comment the way TC6 anchors.
sed -n '/# Human denied on a previous ask\./,/^                            ;;$/p' \
    "${PROJECT_DIR}/bin/zlar-gate" | sed 's/;;$//' > "${TMP}/deny_body.sh"
[ -s "${TMP}/deny_body.sh" ] || { echo "  FAIL  could not extract the deny branch"; exit 1; }

OUT=$(bash -c "
    source '${TMP}/harness.sh'
    source '${TMP}/respond_deny.sh'
    deny_branch() { source '${TMP}/deny_body.sh'; }
    deny_branch
" 2>/dev/null)

LINES=$(printf '%s' "${OUT}" | grep -c . )
check "${LINES}" 1 "the deny branch writes exactly one line to stdout"

if printf '%s' "${OUT}" | jq -e . >/dev/null 2>&1; then PARSES=yes; else PARSES=no; fi
check "${PARSES}" yes "that line parses as JSON — the harness can read the decision"

DECISION=$(printf '%s' "${OUT}" | jq -r '.hookSpecificOutput.permissionDecision // "ABSENT"' 2>/dev/null)
check "${DECISION}" deny "the decision it carries is deny"

# The specific regression: a stray token ahead of the JSON.
if printf '%s' "${OUT}" | head -1 | grep -qE '^(ok|[a-z_]+)$'; then STRAY=yes; else STRAY=no; fi
check "${STRAY}" no "no helper output precedes the decision"

rm -rf "${TMP}"
echo
echo "Results: ${PASSES:-0} passed, ${FAILS} failed"
[ "${FAILS}" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "${FAILS} FAILED"; exit 1; }
