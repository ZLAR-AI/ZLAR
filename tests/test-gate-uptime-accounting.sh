#!/bin/bash
# The gate must never count time it did not observe.
#
# Before 2026-08-17 a streak closed only on an explicit `zlar off`. Every other
# route to off — the /etc/zlar/off-flag written directly, a reboot, the hook
# unwired, the gate crashing — left the streak open, and the next heartbeat
# absorbed the entire dark period. The ledger on this machine ended up claiming
# a 15.7-day continuous streak on a laptop whose normal state is gate-off.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILS=0
check() { if [ "$1" = "$2" ]; then echo "  PASS  $3"; else echo "  FAIL  $3 (got=$1 want=$2)"; FAILS=$((FAILS+1)); fi; }

TMP=$(mktemp -d); mkdir -p "${TMP}/var" "${TMP}/etc/keys"
cp "${ROOT}/etc/keys/gate-uptime-hmac.key" "${TMP}/etc/keys/" 2>/dev/null || \
  head -c 32 /dev/urandom | xxd -p | tr -d '\n' > "${TMP}/etc/keys/gate-uptime-hmac.key"

# Controllable clock: the library calls bare `date`, so a shell function wins.
NOW=1000000000
date() { case "${1:-}" in +%s) printf '%s' "${NOW}" ;; *) command date "$@" ;; esac; }

_GU_PROJECT_DIR="${TMP}"
# shellcheck source=../lib/gate-uptime.sh
source "${ROOT}/lib/gate-uptime.sh"
read_state() { jq -r "$1" "${TMP}/var/gate-uptime.json"; }

echo "A gap in the record is not uptime"

# Gate on, then two hours of real observed use.
gu_record_enable
for step in 1800 3400 5000 7200; do NOW=$((1000000000+step)); gu_record_heartbeat; done
check "$(read_state '.state')" on "gate reads as on while heartbeats arrive"

# Now the gate goes away without `zlar off` — flag written, reboot, crash.
# Sixteen days later a single tool call fires one heartbeat.
NOW=$((1000000000+7200+1382400))
gu_record_heartbeat

LONGEST=$(read_state '.longest_streak_seconds')
LIFETIME=$(read_state '.lifetime_on_seconds')
GAPS=$(read_state '.unobserved_gaps')
UNOBS=$(read_state '.unobserved_seconds')

check "$([ "${LONGEST}" -le 7200 ] && echo bounded || echo "spans-the-gap")" bounded \
  "longest streak is bounded by observed time (${LONGEST}s), not the 16-day silence"
check "$([ "${LIFETIME}" -le 7200 ] && echo bounded || echo "spans-the-gap")" bounded \
  "lifetime total excludes the silence (${LIFETIME}s)"
check "${GAPS}" 1 "the gap is counted, not discarded"
check "$([ "${UNOBS}" -ge 1382400 ] && echo recorded || echo missing)" recorded \
  "the unobserved interval is recorded as unknown time (${UNOBS}s)"
check "$(read_state '.current_streak_start_epoch')" "${NOW}" \
  "a fresh streak starts at the heartbeat that broke the silence"

echo
echo "Ordinary use is unaffected"
NOW=$((NOW+60)); gu_record_heartbeat
check "$(read_state '.unobserved_gaps')" 1 "a heartbeat inside the threshold opens no gap"
NOW=$((NOW+120)); gu_record_heartbeat
check "$(read_state '.current_streak_start_epoch')" "$((NOW-180))" \
  "and does not restart the streak — idle is still not a disable"

# An explicit off must still close at the last heartbeat, not at `off` time.
BEFORE_LIFETIME=$(read_state '.lifetime_on_seconds')
NOW=$((NOW+9999)); gu_record_disable
check "$(read_state '.state')" off "explicit disable still closes the streak"
check "$([ "$(read_state '.lifetime_on_seconds')" -lt "$((BEFORE_LIFETIME+9999))" ] && echo excluded || echo counted)" excluded \
  "idle before an explicit off is still excluded from lifetime"

echo
echo "The observed symptom: a 15.7-day streak on a machine that is mostly off"
# This is the reproduction proper. On the old code the inflated figure did not
# appear until `zlar off` finally ran and banked (last_heartbeat - streak_start)
# across the whole silence. Asserting before the disable therefore proves
# nothing: the number is still 0 either way.
TMP2=$(mktemp -d); mkdir -p "${TMP2}/var" "${TMP2}/etc/keys"
cp "${TMP}/etc/keys/gate-uptime-hmac.key" "${TMP2}/etc/keys/" 2>/dev/null || true
_GU_STATE_FILE="${TMP2}/var/gate-uptime.json"
NOW=2000000000; gu_record_enable
NOW=$((2000000000+600)); gu_record_heartbeat          # ten honest minutes
NOW=$((2000000000+600+1356000)); gu_record_heartbeat  # gate gone ~15.7 days
NOW=$((NOW+30)); gu_record_disable                    # `zlar off`, at last
LONGEST2=$(jq -r '.longest_streak_seconds' "${TMP2}/var/gate-uptime.json")
check "$([ "${LONGEST2}" -lt 86400 ] && echo plausible || echo "inflated-to-${LONGEST2}s")" plausible \
  "after an eventual \`zlar off\`, longest streak is ${LONGEST2}s — not the 15.7 days of silence"
rm -rf "${TMP2}"

rm -rf "${TMP}"
echo
[ "${FAILS}" = 0 ] && { echo "ALL PASS"; exit 0; } || { echo "${FAILS} FAILED"; exit 1; }
