#!/bin/bash
# Public-copy guard for the log-versus-receipt authority boundary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_DIR}"

PASS=0
FAIL=0
TOTAL=0

PUBLIC_PATHS=(README.md docs spec scripts/quickstart.sh)
EXCLUDED_PATHS=(':(exclude)docs/review-checklist.md')

pass() {
    PASS=$((PASS + 1))
}

fail() {
    local label="$1"
    local detail="${2:-}"
    FAIL=$((FAIL + 1))
    printf '  FAIL: %s\n' "${label}"
    if [ -n "${detail}" ]; then
        printf '%s\n' "${detail}" | sed 's/^/    /'
    fi
}

assert_contains_fixed() {
    local label="$1"
    local path="$2"
    local needle="$3"
    TOTAL=$((TOTAL + 1))

    if grep -Fq "${needle}" "${path}"; then
        pass
    else
        fail "${label}" "missing in ${path}: ${needle}"
    fi
}

assert_no_public_regex() {
    local label="$1"
    local pattern="$2"
    TOTAL=$((TOTAL + 1))

    local matches rc
    set +e
    matches=$(git grep -n -i -E "${pattern}" -- "${PUBLIC_PATHS[@]}" "${EXCLUDED_PATHS[@]}" 2>&1)
    rc=$?
    set -e

    if [ "${rc}" -eq 0 ]; then
        fail "${label}" "${matches}"
    elif [ "${rc}" -eq 1 ]; then
        pass
    else
        fail "${label}" "${matches}"
    fi
}

echo "=== Receipt Authority Public-Copy Guard ==="

assert_contains_fixed \
    "review checklist keeps log/receipt invariant" \
    "docs/review-checklist.md" \
    "A log records what happened. A ZLAR receipt records what counted as authorized effect."

assert_contains_fixed \
    "review checklist names rejected category drift" \
    "docs/review-checklist.md" \
    "Reject draft language that treats the receipt as an after-the-fact narrative"

assert_no_public_regex \
    "public copy must not say receipts prove/record what happened" \
    '(^|[^[:alnum:]_])receipts?[^.?!]{0,80}(records?|shows?|captures?|explains?|proves?)[^.?!]{0,80}what happened'

assert_no_public_regex \
    "public copy must not say a receipt is proof of what happened" \
    '(^|[^[:alnum:]_])receipts?[^.?!]{0,80}proof of[^.?!]{0,80}what happened'

assert_no_public_regex \
    "public copy must not describe receipts as receipts of what happened" \
    '(^|[^[:alnum:]_])receipts?[^.?!]{0,80}of what happened'

assert_no_public_regex \
    "public copy must not claim ZLAR reconstructs agent history" \
    '(^|[^[:alnum:]_])ZLAR[[:space:]]+reconstructs?[[:space:]]+what[[:space:]]+the[[:space:]]+agent[[:space:]]+did'

assert_no_public_regex \
    "public copy must not say receipts record the agent full history" \
    '(^|[^[:alnum:]_])the[[:space:]]+receipt[[:space:]]+records?[[:space:]]+the[[:space:]]+agent.?s[[:space:]]+full[[:space:]]+history'

assert_no_public_regex \
    "public copy must not say receipts prove agent intent" \
    '(^|[^[:alnum:]_])the[[:space:]]+receipt[[:space:]]+proves?[[:space:]]+what[[:space:]]+the[[:space:]]+agent[[:space:]]+intended'

assert_no_public_regex \
    "public copy must not say receipts prove correctness" \
    '(^|[^[:alnum:]_])the[[:space:]]+receipt[[:space:]]+proves?[[:space:]]+the[[:space:]]+decision[[:space:]]+was[[:space:]]+correct'

assert_contains_fixed \
    "quickstart keeps constructed receipt boundary" \
    "scripts/quickstart.sh" \
    "The gate decisions are real. The receipt is a bounded demo artifact over a"

assert_no_public_regex \
    "public copy must not claim quickstart has no simulation boundary" \
    'Nothing[[:space:]]+is[[:space:]]+simulated'

assert_no_public_regex \
    "public copy must not claim gate unconditionally writes action receipts" \
    'audit[[:space:]]+entry[[:space:]]+[+][[:space:]]+receipt[[:space:]]+written|writes[[:space:]]+audit[[:space:]]+trail[[:space:]]+and[[:space:]]+receipts'

assert_no_public_regex \
    "public copy must not equate logs and receipts" \
    '(^|[^[:alnum:]_])a[[:space:]]+log[[:space:]]+is[[:space:]]+the[[:space:]]+same[[:space:]]+as[[:space:]]+a[[:space:]]+receipt'

assert_no_public_regex \
    "public copy must not claim unconditional phone approval routing" \
    'message[[:space:]]+appears[[:space:]]+on[[:space:]]+the[[:space:]]+operator.?s[[:space:]]+phone|human.?s[[:space:]]+only[[:space:]]+interface[[:space:]]+is[^.?!]{0,80}phone|person[[:space:]]+behind[[:space:]]+the[[:space:]]+phone'

assert_no_public_regex \
    "public copy must not claim unconditional Telegram approval routing" \
    'human[-[:space:]]+in[-[:space:]]+the[-[:space:]]+loop[[:space:]]+approval[[:space:]]+via[[:space:]]+Telegram|approval[[:space:]]+via[[:space:]]+Telegram|human[[:space:]]+notified[[:space:]]+via[[:space:]]+Telegram|routes?[[:space:]]+to[[:space:]]+a[[:space:]]+human[[:space:]]+via[[:space:]]+Telegram|single[[:space:]]+bot[[:space:]]+that[[:space:]]+routes[[:space:]]+all[[:space:]]+governed[[:space:]]+asks|Telegram[[:space:]]+unreachable:[[:space:]]+deny'

assert_no_public_regex \
    "public copy must not claim absolute agent inability to modify governance" \
    'you[[:space:]]+cannot[[:space:]]+modify[[:space:]]+the[[:space:]]+gate,[[:space:]]+the[[:space:]]+policy,[[:space:]]+or[[:space:]]+the[[:space:]]+signing[[:space:]]+key|agents[[:space:]]+cannot[[:space:]]+modify[[:space:]]+their[[:space:]]+own[[:space:]]+rules'

assert_no_public_regex \
    "public copy must not claim the gate is unconditionally outside agent writable space" \
    'the[[:space:]]+gate[[:space:]]+sits[[:space:]]+outside[[:space:]]+your[[:space:]]+writable[[:space:]]+space'

assert_no_public_regex \
    "public copy must not claim structurally impossible outcomes without a bounded deployment qualifier" \
    'structurally[[:space:]]+impossible'

assert_no_public_regex \
    "public copy must not claim every action is denied when gate is down" \
    'if[[:space:]]+the[[:space:]]+gate[[:space:]]+is[[:space:]]+down,[[:space:]]+all[[:space:]]+actions[[:space:]]+are[[:space:]]+denied'

assert_no_public_regex \
    "public copy must not claim impossible-by-design agent disablement" \
    'impossible[[:space:]]+by[[:space:]]+design'

assert_no_public_regex \
    "public copy must not say traditions inform ZLAR architecture" \
    'traditions[[:space:]]+that[[:space:]]+inform[[:space:]]+ZLAR'

assert_no_public_regex \
    "public copy must not say an external framework is applied to AI as a ZLAR invariant" \
    'applied[[:space:]]+to[[:space:]]+AI'

assert_no_public_regex \
    "public copy must not claim the agent cannot touch first authority without route qualifier" \
    '(^|[^[:alnum:]_])the[[:space:]]+agent[[:space:]]+cannot[[:space:]]+touch[[:space:]]+the[[:space:]]+first[[:space:]]+authority'

assert_no_public_regex \
    "public copy must not claim unqualified agent reach/write prevention" \
    '(^|[^[:alnum:]_])the[[:space:]]+agent[[:space:]]+cannot[[:space:]]+(reach|write)'

assert_no_public_regex \
    "public copy must not claim legacy wrapper flag alone is the current off-switch" \
    'wrapper[-[:space:]]+flag[[:space:]]+fallback|wrapper[[:space:]]+path[[:space:]]+still[[:space:]]+(active|works)|either[[:space:]]+being[[:space:]]+present[[:space:]]+means[[:space:]]+the[[:space:]]+gate[[:space:]]+is[[:space:]]+off'

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ✓"
