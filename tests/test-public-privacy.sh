#!/bin/bash
# Public privacy and claim hygiene guards for tracked public surfaces.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ALLOWLIST_FILE="${ZLAR_PUBLIC_PRIVACY_ALLOWLIST:-${PROJECT_DIR}/tests/public-privacy-allowlist.txt}"

cd "${PROJECT_DIR}"

PASS=0
FAIL=0
TOTAL=0

PUBLIC_SURFACES=(
    AGENTS.md
    CODE_OF_CONDUCT.md
    CONTRIBUTING.md
    LEGAL.md
    README.md
    SECURITY.md
    docs
    demos
    profiles
    spec
    tools/verifier-kit-src
    .github
)

FIXTURE_SURFACES=(
    tests/fixtures
)

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

assert_no_tracked_fixed() {
    local label="$1"
    local needle="$2"
    TOTAL=$((TOTAL + 1))

    local matches
    if matches=$(git grep -n -F "${needle}" -- . 2>/dev/null); then
        fail "${label}" "${matches}"
    else
        pass
    fi
}

assert_no_tracked_regex() {
    local label="$1"
    local pattern="$2"
    TOTAL=$((TOTAL + 1))

    local matches
    if matches=$(git grep -n -E "${pattern}" -- . 2>/dev/null); then
        fail "${label}" "${matches}"
    else
        pass
    fi
}

filter_allowlisted_matches() {
    local label="$1"
    local matches="$2"
    local filtered="${matches}"
    local entry allow_label pattern tab
    tab=$'\t'

    if [ ! -f "${ALLOWLIST_FILE}" ]; then
        printf '%s\n' "${filtered}"
        return
    fi

    while IFS= read -r entry || [ -n "${entry}" ]; do
        case "${entry}" in
            ""|\#*) continue ;;
        esac
        if [[ "${entry}" != *"${tab}"* ]]; then
            continue
        fi
        allow_label="${entry%%${tab}*}"
        pattern="${entry#*${tab}}"
        if [ "${allow_label}" != "${label}" ]; then
            continue
        fi
        filtered=$(printf '%s\n' "${filtered}" | grep -Ev "${pattern}" || true)
    done < "${ALLOWLIST_FILE}"

    if [ -n "${filtered}" ]; then
        printf '%s\n' "${filtered}"
    fi
}

assert_no_public_regex() {
    local label="$1"
    local pattern="$2"
    shift 2
    TOTAL=$((TOTAL + 1))

    local matches rc filtered
    set +e
    matches=$(git grep -n -i -E "${pattern}" -- "$@" 2>&1)
    rc=$?
    set -e

    if [ "${rc}" -eq 0 ]; then
        filtered=$(filter_allowlisted_matches "${label}" "${matches}")
        if [ -n "${filtered}" ]; then
            fail "${label}" "${filtered}"
        else
            pass
        fi
    elif [ "${rc}" -eq 1 ]; then
        pass
    else
        fail "${label}" "${matches}"
    fi
}

assert_contains_fixed() {
    local label="$1"
    local path="$2"
    local needle="$3"
    TOTAL=$((TOTAL + 1))

    if grep -Fq -- "${needle}" "${path}"; then
        pass
    else
        fail "${label}" "${path} missing: ${needle}"
    fi
}

assert_regex_matches_text() {
    local label="$1"
    local pattern="$2"
    local text="$3"
    TOTAL=$((TOTAL + 1))

    if printf '%s\n' "${text}" | grep -Eiq "${pattern}"; then
        pass
    else
        fail "${label}" "pattern did not match representative bad example: ${text}"
    fi
}

assert_allowlist_filters_text() {
    local label="$1"
    local guard_label="$2"
    local text="$3"
    TOTAL=$((TOTAL + 1))

    local filtered
    filtered=$(filter_allowlisted_matches "${guard_label}" "${text}")
    if [ -z "${filtered}" ]; then
        pass
    else
        fail "${label}" "allowlist did not filter: ${filtered}"
    fi
}

assert_allowlist_keeps_text() {
    local label="$1"
    local guard_label="$2"
    local text="$3"
    TOTAL=$((TOTAL + 1))

    local filtered
    filtered=$(filter_allowlisted_matches "${guard_label}" "${text}")
    if [ -n "${filtered}" ]; then
        pass
    else
        fail "${label}" "allowlist filtered a line for the wrong guard: ${text}"
    fi
}

assert_allowlist_well_formed() {
    TOTAL=$((TOTAL + 1))

    local entry allow_label pattern tab problems
    tab=$'\t'
    problems=""
    if [ ! -f "${ALLOWLIST_FILE}" ]; then
        fail "privacy allowlist file exists" "${ALLOWLIST_FILE} missing"
        return
    fi

    while IFS= read -r entry || [ -n "${entry}" ]; do
        case "${entry}" in
            ""|\#*) continue ;;
        esac
        if [[ "${entry}" != *"${tab}"* ]]; then
            problems="${problems}"$'\n'"missing tab delimiter: ${entry}"
            continue
        fi
        allow_label="${entry%%${tab}*}"
        pattern="${entry#*${tab}}"
        case "${allow_label}" in
            "no public private absolute local paths outside placeholders") ;;
            *)
                problems="${problems}"$'\n'"unknown guard label: ${allow_label}"
                ;;
        esac
        case "${pattern}" in
            ^*:* ) ;;
            *)
                problems="${problems}"$'\n'"allowlist pattern must be anchored to path:line:content: ${pattern}"
                ;;
        esac
    done < "${ALLOWLIST_FILE}"

    if [ -n "${problems}" ]; then
        fail "privacy allowlist entries are label-scoped and path-anchored" "${problems}"
    else
        pass
    fi
}

active_changelog_window_lines() {
    awk '
        /^## / {
            heading_count += 1
            if (heading_count == 1) {
                in_window = 1
            } else if (heading_count == 3) {
                exit
            }
        }
        in_window {
            printf "CHANGELOG.md:%d:%s\n", NR, $0
        }
    ' CHANGELOG.md
}

assert_active_changelog_window_contains() {
    local label="$1"
    local needle="$2"
    TOTAL=$((TOTAL + 1))

    local lines
    lines=$(active_changelog_window_lines)
    if printf '%s\n' "${lines}" | grep -Fq -- "${needle}"; then
        pass
    else
        fail "${label}" "active changelog window missing: ${needle}"
    fi
}

assert_active_changelog_window_release_heading_count() {
    local label="$1"
    TOTAL=$((TOTAL + 1))

    local count
    count=$(active_changelog_window_lines | grep -E -c '^CHANGELOG\.md:[0-9]+:## [0-9]+\.[0-9]+\.[0-9]+')
    if [ "${count}" -eq 1 ]; then
        pass
    else
        fail "${label}" "expected exactly one newest release heading in active changelog window; found ${count}"
    fi
}

assert_no_active_changelog_regex() {
    local label="$1"
    local pattern="$2"
    TOTAL=$((TOTAL + 1))

    local matches rc
    set +e
    matches=$(active_changelog_window_lines | grep -i -E "${pattern}")
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

assert_gate_json_not_committed_with_numeric_chat_id() {
    TOTAL=$((TOTAL + 1))

    if ! git ls-files --error-unmatch etc/gate.json >/dev/null 2>&1; then
        pass
        return
    fi

    local chat_id
    chat_id=$(jq -r '.telegram.chat_id // ""' etc/gate.json 2>/dev/null || echo "")
    if [[ "${chat_id}" =~ ^[0-9]{7,}$ ]]; then
        fail "tracked etc/gate.json must not contain a numeric Telegram chat id" "etc/gate.json telegram.chat_id=${chat_id}"
    else
        pass
    fi
}

assert_gate_example_uses_placeholder() {
    TOTAL=$((TOTAL + 1))

    local chat_id
    chat_id=$(jq -r '.telegram.chat_id // ""' etc/gate.example.json 2>/dev/null || echo "")
    if [[ "${chat_id}" =~ ^[0-9]{7,}$ ]]; then
        fail "gate example must use a placeholder chat id" "etc/gate.example.json telegram.chat_id=${chat_id}"
    else
        pass
    fi
}

echo "=== Public Privacy Hygiene ==="

private_user="vincentnijjar"
private_path="/Users/${private_user}"
private_absolute_path_pattern='/Users/[A-Za-z0-9._-]+(/[^[:space:]]*)?'
fixture_operator_name_pattern='"(user|operator|authorizer|approver|reviewer|maintainer)"[[:space:]]*:[[:space:]]*"(vincent|vincentnijjar|Vincent|Vincent Nijjar)"'
hardware_serial_pattern='(YubiKey|hardware|device|security key|key)[[:print:]]{0,100}(serial|s/n|serial number)[[:print:]]{0,60}[0-9]{6,}|(serial|s/n|serial number)[[:print:]]{0,60}[0-9]{6,}[[:print:]]{0,100}(YubiKey|hardware|device|security key|key)'
machine_model_pattern='(^|[^[:alnum:]])(Mac mini|MacBook|Mac Studio|Mac Pro|iMac)([^[:alnum:]]|$)'
numeric_human_id_pattern='(human|authorizer|approver|telegram|chat_id|telegram[_ -]?(chat|human)?[_ -]?id)[^[:space:]]{0,30}(:|=| )[[:space:]]*[0-9]{7,}|human:[0-9]{7,}'
token_secret_pattern="(Bearer[[:space:]]+[A-Za-z0-9._-]{20,}|(token|api[_-]?key|secret)[[:space:]]*[:=][[:space:]]*['\"]?([A-Za-z0-9._-]{20,}|sk-[A-Za-z0-9_-]{8,}|pk-[A-Za-z0-9_-]{8,}))"
unsupported_claim_pattern='(ZLAR (is )?(production[- ]ready|enterprise[- ]ready|externally attested|independently attested|sovereign infrastructure)|production[- ]ready ZLAR|enterprise[- ]ready ZLAR|enterprise readiness (is )?(complete|completed|done|achieved|received|proven|validated|verified)|external attestation (is )?(complete|completed|done|achieved|received|proven|validated|verified)|public external attestation (is )?(complete|completed|done|achieved|received|proven|validated|verified)|non[- ]Vincent verifier (has )?(verified|attested)|production (adapter|adaptor) proof|current[- ]machine governance (is )?(proven|validated|verified|complete|completed|done|achieved)|production (authority|downstream recognition) (is )?(proven|validated|verified|complete|completed|done|achieved)|live (MCP coverage|downstream recognition|records[- ]system coverage|records[- ]system recognition|coverage) (is )?(proven|validated|verified|complete|completed|done|achieved)|sovereign recognition (is )?(proven|validated|verified|complete|completed|done|achieved))'
unsupported_recognition_claim_pattern='(recognized infrastructure|production[- ]recognized|live[- ]recognized|recognized by (an? )?(external|independent|non[- ]operator) verifier|recognized by (production|live) (systems?|services?)|ZLAR (is |has been |was )recognized (as (production|live|external|independent)|by))'
bad_serial_digits="37175116"
bad_numeric_human_id="123456789"
bad_token_suffix="live-secret-1234567890"

assert_allowlist_well_formed
assert_gate_json_not_committed_with_numeric_chat_id
assert_gate_example_uses_placeholder
assert_no_tracked_fixed "no tracked private local user path" "${private_path}"
assert_no_public_regex "no public private absolute local paths outside placeholders" "${private_absolute_path_pattern}" "${PUBLIC_SURFACES[@]}"
assert_no_public_regex "no fixture role fields named after operator" "${fixture_operator_name_pattern}" "${FIXTURE_SURFACES[@]}"
assert_no_tracked_regex "no tracked Telegram-shaped human authorizer examples" 'human:[0-9]{7,}'
assert_no_tracked_regex "no references to the founder's private folders" 'Embod[y]ment|potential-cofound[e]rs'
assert_no_tracked_regex "no tracked public YubiKey serial numbers" 'YubiKey[[:print:]]{0,120}serial[[:print:]]{0,80}[0-9]{6,}|serial[[:print:]]{0,80}[0-9]{6,}[[:print:]]{0,120}YubiKey'
assert_no_public_regex "no public hardware serial numbers" "${hardware_serial_pattern}" "${PUBLIC_SURFACES[@]}" "${FIXTURE_SURFACES[@]}"
assert_no_public_regex "no machine model names in public guard surfaces" "${machine_model_pattern}" "${PUBLIC_SURFACES[@]}"
assert_no_public_regex "no public numeric Telegram or human ids" "${numeric_human_id_pattern}" "${PUBLIC_SURFACES[@]}" "${FIXTURE_SURFACES[@]}"
assert_no_public_regex "no public token or API-key shaped strings" "${token_secret_pattern}" "${PUBLIC_SURFACES[@]}"
assert_no_public_regex "no unsupported production, adaptor, or public-attestation claims" "${unsupported_claim_pattern}" "${PUBLIC_SURFACES[@]}" "${FIXTURE_SURFACES[@]}"
assert_no_public_regex "no unsupported recognition-overclaim language" "${unsupported_recognition_claim_pattern}" "${PUBLIC_SURFACES[@]}" "${FIXTURE_SURFACES[@]}"
assert_contains_fixed "privacy guard documentation exists" "docs/public-privacy-claim-guard.md" "## Allowlist Policy"
assert_contains_fixed "guard doc names covered surfaces" "docs/public-privacy-claim-guard.md" "## Covered Surfaces"
assert_contains_fixed "guard doc names out-of-scope surfaces" "docs/public-privacy-claim-guard.md" "## Out Of Scope"
assert_contains_fixed "guard doc names changelog policy" "docs/public-privacy-claim-guard.md" "CHANGELOG.md"
assert_contains_fixed "guard doc names active changelog window policy" "docs/public-privacy-claim-guard.md" "active changelog window"
assert_contains_fixed "changelog privacy provenance note present" "CHANGELOG.md" "Historical entries may name maintainer-local observations"
assert_active_changelog_window_contains "active changelog window includes Unreleased" "## Unreleased"
assert_active_changelog_window_release_heading_count "active changelog window includes exactly one newest release"
assert_no_active_changelog_regex "no active changelog private absolute local paths" "${private_absolute_path_pattern}"
assert_no_active_changelog_regex "no active changelog hardware serial numbers" "${hardware_serial_pattern}"
assert_no_active_changelog_regex "no active changelog numeric Telegram or human ids" "${numeric_human_id_pattern}"
assert_no_active_changelog_regex "no active changelog token or API-key shaped strings" "${token_secret_pattern}"
assert_no_active_changelog_regex "no active changelog unsupported production or public-attestation claims" "${unsupported_claim_pattern}"
assert_no_active_changelog_regex "no active changelog unsupported recognition-overclaim language" "${unsupported_recognition_claim_pattern}"
assert_allowlist_filters_text "legacy placeholder local path allowlist is scoped" "no public private absolute local paths outside placeholders" "docs/cli-reference.md:158:    Claude legacy/current hook target:           /Users/yourname/.claude/zlar-gate.sh"
assert_allowlist_keeps_text "path allowlist cannot hide token guard" "no public token or API-key shaped strings" "docs/cli-reference.md:158:    Claude legacy/current hook target:           /Users/yourname/.claude/zlar-gate.sh api_key=sk-${bad_token_suffix}"
assert_allowlist_keeps_text "path allowlist cannot hide claim guard" "no unsupported production, adaptor, or public-attestation claims" "docs/cli-reference.md:158:    Claude legacy/current hook target:           /Users/yourname/.claude/zlar-gate.sh ZLAR is externally attested"
assert_allowlist_keeps_text "path allowlist cannot hide a second private path" "no public private absolute local paths outside placeholders" "docs/cli-reference.md:158:    Claude legacy/current hook target:           /Users/yourname/.claude/zlar-gate.sh /Users/alice/.ssh/id_ed25519"
assert_regex_matches_text "guard catches private absolute path examples" "${private_absolute_path_pattern}" "docs/example.md:1:/Users/alice/.ssh/id_ed25519"
assert_regex_matches_text "guard catches operator fixture names" "${fixture_operator_name_pattern}" 'tests/fixtures/example.json:1:{"user":"Vincent"}'
assert_regex_matches_text "guard catches hardware serial examples" "${hardware_serial_pattern}" "docs/example.md:1:YubiKey spare device serial ${bad_serial_digits}"
assert_regex_matches_text "guard catches machine model examples" "${machine_model_pattern}" "docs/example.md:1:Mac mini filesystem checked"
assert_regex_matches_text "guard catches numeric human id examples" "${numeric_human_id_pattern}" "tests/fixtures/example.json:1:{\"authorizer\":\"human:${bad_numeric_human_id}\"}"
assert_regex_matches_text "guard catches token examples" "${token_secret_pattern}" "docs/example.md:1:api_key=sk-${bad_token_suffix}"
assert_regex_matches_text "guard catches unsupported public claim examples" "${unsupported_claim_pattern}" "docs/example.md:1:ZLAR is externally attested"
assert_regex_matches_text "guard catches mixed-case unsupported claim examples" "${unsupported_claim_pattern}" "docs/example.md:1:zlar is externally attested"
assert_regex_matches_text "guard catches current-machine governance proof overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:current-machine governance is proven"
assert_regex_matches_text "guard catches production authority proof overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:production authority is proven"
assert_regex_matches_text "guard catches production downstream recognition overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:production downstream recognition is proven"
assert_regex_matches_text "guard catches live MCP coverage proof overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:live MCP coverage is proven"
assert_regex_matches_text "guard catches enterprise-readiness overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:ZLAR is enterprise-ready"
assert_regex_matches_text "guard catches sovereign-infrastructure overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:ZLAR is sovereign infrastructure"
assert_regex_matches_text "guard catches sovereign-recognition overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:sovereign recognition achieved"
assert_regex_matches_text "guard catches external-attestation proof overclaims" "${unsupported_claim_pattern}" "docs/example.md:1:external attestation is proven"
assert_regex_matches_text "guard catches recognized infrastructure examples" "${unsupported_recognition_claim_pattern}" "docs/example.md:1:ZLAR is recognized infrastructure"
assert_regex_matches_text "guard catches external recognition-overclaim examples" "${unsupported_recognition_claim_pattern}" "docs/example.md:1:recognized by an external verifier"
assert_regex_matches_text "guard catches production-recognized examples" "${unsupported_recognition_claim_pattern}" "docs/example.md:1:production-recognized receipt infrastructure"
assert_regex_matches_text "active changelog guard catches private path examples" "${private_absolute_path_pattern}" "CHANGELOG.md:20:/Users/alice/.ssh/id_ed25519"
assert_regex_matches_text "active changelog guard catches hardware serial examples" "${hardware_serial_pattern}" "CHANGELOG.md:20:YubiKey spare device serial ${bad_serial_digits}"
assert_regex_matches_text "active changelog guard catches numeric human id examples" "${numeric_human_id_pattern}" "CHANGELOG.md:20:telegram human id: ${bad_numeric_human_id}"
assert_regex_matches_text "active changelog guard catches token examples" "${token_secret_pattern}" "CHANGELOG.md:20:token=sk-${bad_token_suffix}"
assert_regex_matches_text "active changelog guard catches unsupported public claim examples" "${unsupported_claim_pattern}" "CHANGELOG.md:20:public external attestation is complete"
assert_regex_matches_text "active changelog guard catches recognition-overclaim examples" "${unsupported_recognition_claim_pattern}" "CHANGELOG.md:20:recognized by production systems"

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ✓"
