#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR Gate Uptime — Test Suite (v3.1.4)
#
# Covers: heartbeat transitions, enable/disable state changes, longest-streak
# updates, lifetime accumulation, last_disable_at recording, batched writes,
# crash-safe atomic rename, HMAC tamper detection.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf "${TEMP_DIR}"; }
trap cleanup EXIT

# Point lib at temp dir so we don't pollute the real var/gate-uptime.json
export _GU_PROJECT_DIR="${TEMP_DIR}"
mkdir -p "${TEMP_DIR}/var" "${TEMP_DIR}/etc/keys"

# Install a test key so writes actually seal
openssl rand -hex 32 > "${TEMP_DIR}/etc/keys/gate-uptime-hmac.key"
chmod 600 "${TEMP_DIR}/etc/keys/gate-uptime-hmac.key"

# Shrink thresholds so the tests stay fast
export _GU_STALE_THRESHOLD_SECONDS=5
export _GU_HEARTBEAT_BATCH_SECONDS=0   # write on every heartbeat for observability

source "${PROJECT_DIR}/lib/gate-uptime.sh"

STATE_FILE="${TEMP_DIR}/var/gate-uptime.json"

PASS=0
FAIL=0
TOTAL=0

assert() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${expected}" == "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

echo "=== Heartbeat: off → on transition ==="
echo

gu_record_heartbeat
state=$(jq -r '.state' "${STATE_FILE}")
assert "first heartbeat transitions state to on" "on" "${state}"

has_hmac=$(jq -r 'has("_hmac")' "${STATE_FILE}")
assert "state file is sealed with _hmac" "true" "${has_hmac}"

streak_start=$(jq -r '.current_streak_start_epoch' "${STATE_FILE}")
[ "${streak_start}" -gt 0 ] && got="set" || got="zero"
assert "streak start epoch recorded" "set" "${got}"

last_enable=$(jq -r '.last_enable_at_epoch' "${STATE_FILE}")
[ "${last_enable}" -gt 0 ] && got="set" || got="zero"
assert "first heartbeat records last_enable_at" "set" "${got}"

echo
echo "=== Explicit enable / disable ==="
echo

gu_record_disable
state=$(jq -r '.state' "${STATE_FILE}")
assert "disable sets state to off" "off" "${state}"

last_disable=$(jq -r '.last_disable_at_epoch' "${STATE_FILE}")
[ "${last_disable}" -gt 0 ] && got="set" || got="zero"
assert "disable records last_disable_at" "set" "${got}"

start_after_disable=$(jq -r '.current_streak_start_epoch' "${STATE_FILE}")
assert "disable clears current streak start" "0" "${start_after_disable}"

gu_record_enable
state=$(jq -r '.state' "${STATE_FILE}")
assert "enable sets state to on" "on" "${state}"

streak_start_2=$(jq -r '.current_streak_start_epoch' "${STATE_FILE}")
[ "${streak_start_2}" -gt 0 ] && got="set" || got="zero"
assert "enable opens new streak" "set" "${got}"

echo
echo "=== Longest-streak and lifetime accumulation ==="
echo

# Force a 4-second streak then disable. Since our stale threshold is 5s,
# we can cleanly model an artificial streak by manipulating start epoch.
now=$(date +%s)
fake_start=$(( now - 4 ))
jq --argjson s "${fake_start}" --argjson n "${now}" \
    '.current_streak_start_epoch = $s | .last_heartbeat_epoch = $n | .state = "on"' \
    "${STATE_FILE}" | _gu_sealed_write

gu_record_disable
longest=$(jq -r '.longest_streak_seconds' "${STATE_FILE}")
[ "${longest}" -ge 4 ] && got="ge4" || got="lt4"
assert "longest streak updated after disable" "ge4" "${got}"

lifetime=$(jq -r '.lifetime_on_seconds' "${STATE_FILE}")
[ "${lifetime}" -ge 4 ] && got="ge4" || got="lt4"
assert "lifetime_on accumulated after disable" "ge4" "${got}"

echo
echo "=== Stale heartbeat preserves streak (idle is not disable) ==="
echo

# Arrange: state on, heartbeat 10s old (> 5s threshold), streak started 20s ago.
# The streak must survive. Idle time (laptop closed, lunch, a long read) is
# not a disable and must not reset a motivational counter.
now=$(date +%s)
stale_start=$(( now - 20 ))
stale_hb=$(( now - 10 ))
jq --argjson s "${stale_start}" --argjson hb "${stale_hb}" \
    '.state = "on" | .current_streak_start_epoch = $s | .last_heartbeat_epoch = $hb | .longest_streak_seconds = 0 | .lifetime_on_seconds = 0' \
    "${STATE_FILE}" | _gu_sealed_write

gu_record_heartbeat

# Streak start must be preserved across the idle gap.
preserved_start=$(jq -r '.current_streak_start_epoch' "${STATE_FILE}")
assert "stale heartbeat preserves streak start" "${stale_start}" "${preserved_start}"

# Heartbeat is updated (so the next invocation sees fresh liveness).
preserved_hb=$(jq -r '.last_heartbeat_epoch' "${STATE_FILE}")
[ "${preserved_hb}" -ge "${now}" ] && got="fresh" || got="stale"
assert "stale heartbeat updates last_heartbeat_epoch" "fresh" "${got}"

# Lifetime is not rolled at idle — it accumulates only on explicit disable.
lifetime_after_stale=$(jq -r '.lifetime_on_seconds' "${STATE_FILE}")
assert "idle does not roll lifetime" "0" "${lifetime_after_stale}"

echo
echo "=== Disable after idle: idle tail not counted in lifetime ==="
echo

# Arrange: gate on, last active heartbeat 50s ago, streak started 100s ago.
# The 50s idle tail (between last heartbeat and now) must not enter lifetime.
now=$(date +%s)
idle_start=$(( now - 100 ))
last_active_hb=$(( now - 50 ))
jq --argjson s "${idle_start}" --argjson hb "${last_active_hb}" \
    '.state = "on" | .current_streak_start_epoch = $s | .last_heartbeat_epoch = $hb | .longest_streak_seconds = 0 | .lifetime_on_seconds = 0' \
    "${STATE_FILE}" | _gu_sealed_write

gu_record_disable

# Active span = last_hb - streak_start = 50s. Idle tail (50s) must not be added.
# Accept [45, 60] — tight enough to confirm the fix, loose enough for slow runners.
lifetime_idle=$(jq -r '.lifetime_on_seconds' "${STATE_FILE}")
{ [ "${lifetime_idle}" -ge 45 ] && [ "${lifetime_idle}" -le 60 ]; } && got="near50" || got="wrong:${lifetime_idle}"
assert "disable after idle: lifetime uses last_heartbeat not wall clock" "near50" "${got}"

longest_idle=$(jq -r '.longest_streak_seconds' "${STATE_FILE}")
{ [ "${longest_idle}" -ge 45 ] && [ "${longest_idle}" -le 60 ]; } && got="near50" || got="wrong:${longest_idle}"
assert "disable after idle: longest_streak uses last_heartbeat not wall clock" "near50" "${got}"

echo
echo "=== HMAC tamper detection ==="
echo

gu_record_enable
# Tamper: inflate longest_streak without resealing
jq '.longest_streak_seconds = 999999' "${STATE_FILE}" > "${STATE_FILE}.attacker"
mv "${STATE_FILE}.attacker" "${STATE_FILE}"

# Next load should detect tamper and rebuild with defaults
state_json=$(_gu_load_state)
rebuilt_longest=$(printf '%s' "${state_json}" | jq -r '.longest_streak_seconds')
assert "tampered longest rebuilt to safe default" "0" "${rebuilt_longest}"

rebuilt_state=$(printf '%s' "${state_json}" | jq -r '.state')
assert "rebuild starts from 'off' state" "off" "${rebuilt_state}"

echo
echo "=== Format helpers ==="
echo

assert "format 0 seconds" "< 1m" "$(gu_format_duration 0)"
assert "format 59 seconds" "< 1m" "$(gu_format_duration 59)"
assert "format 90 seconds" "1m" "$(gu_format_duration 90)"
assert "format 1 hour" "1h 0m" "$(gu_format_duration 3600)"
assert "format 1 day 2 hours" "1d 2h 0m" "$(gu_format_duration 93600)"
assert "format epoch 0" "—" "$(gu_format_epoch 0)"

echo
echo "=== Crash-safe write semantics ==="
echo

# The tmp + rename path is used on every write. Verify no stray .tmp is left.
ls "${STATE_FILE}.tmp" 2>/dev/null | wc -l | tr -d ' ' > /tmp/gu_stray_tmp
stray=$(cat /tmp/gu_stray_tmp); rm -f /tmp/gu_stray_tmp
assert "no stray .tmp after writes" "0" "${stray}"

# ─── Results ──────────────────────────────────────────────────────────────────

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [[ ${FAIL} -gt 0 ]]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
else
    echo " ✓"
fi
