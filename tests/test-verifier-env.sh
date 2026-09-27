#!/bin/bash
# Guard the verifier-environment preflight used by external verifier packets.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PASS=0
FAIL=0
TOTAL=0

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${haystack}" == *"${needle}"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected output to contain "%s"\n' "${label}" "${needle}"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "${haystack}" != *"${needle}"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected output NOT to contain "%s"\n' "${label}" "${needle}"
    fi
}

assert_status() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "${expected}" -eq "${actual}" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — expected status %s, got %s\n' "${label}" "${expected}" "${actual}"
    fi
}

assert_json_expr() {
    local label="$1" json="$2" expr="$3"
    TOTAL=$((TOTAL + 1))
    if JSON_INPUT="${json}" JSON_EXPR="${expr}" node <<'NODE' >/dev/null 2>&1
const report = JSON.parse(process.env.JSON_INPUT);
const ok = Function('report', `return (${process.env.JSON_EXPR});`)(report);
process.exit(ok ? 0 : 1);
NODE
    then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s — JSON assertion failed: %s\n' "${label}" "${expr}"
    fi
}

echo "=== Verifier Environment Preflight Guard ==="

fake_dir="$(mktemp -d "${TMPDIR:-/tmp}/zlar-verifier-env-test.XXXXXX")"
mkdir -p "${fake_dir}/ok-bin" "${fake_dir}/fail-bin"

cat > "${fake_dir}/ok-bin/openssl" <<'FAKEOPENSSL'
#!/bin/bash
if [ "${1:-}" = "version" ]; then
    echo "OpenSSL 3.6.2"
    exit 0
fi
if [ "${1:-}" = "genpkey" ]; then
    exit 0
fi
exit 1
FAKEOPENSSL
chmod +x "${fake_dir}/ok-bin/openssl"

ok_output=$(PATH="${fake_dir}/ok-bin:${PATH}" bash "${PROJECT_DIR}/bin/zlar" verifier-env 2>&1)
ok_status=$?
assert_status "fake OpenSSL verifier-env exits zero" 0 "${ok_status}"
assert_contains "ok output has title" "ZLAR Verifier Environment Preflight v0" "${ok_output}"
assert_contains "ok output checks git" "git:" "${ok_output}"
assert_contains "ok output checks bash" "bash:" "${ok_output}"
assert_contains "ok output checks node" "node:" "${ok_output}"
assert_contains "ok output checks jq" "jq:" "${ok_output}"
assert_contains "ok output checks openssl" "openssl:" "${ok_output}"
assert_contains "ok output checks Ed25519" "openssl_ed25519:" "${ok_output}"
assert_contains "ok output names boundary" "Verifier environment readiness only" "${ok_output}"
assert_contains "ok output is pass" "Result: PASS" "${ok_output}"
assert_not_contains "ok output does not claim attestation" "Result: external attestation" "${ok_output}"
assert_not_contains "ok output omits temp path" "${fake_dir}" "${ok_output}"

ok_json=$(PATH="${fake_dir}/ok-bin:${PATH}" bash "${PROJECT_DIR}/bin/zlar" verifier-env --json 2>&1)
ok_json_status=$?
assert_status "fake OpenSSL json exits zero" 0 "${ok_json_status}"
assert_json_expr "ok json report type" "${ok_json}" "report.report_type === 'zlar-verifier-env-v0'"
assert_json_expr "ok json readiness schema" "${ok_json}" "report.schema === 'zlar-verifier-env-readiness-report-v0'"
assert_json_expr "ok json result pass" "${ok_json}" "report.result === 'PASS'"
assert_json_expr "ok json failure count zero" "${ok_json}" "report.failure_count === 0"
assert_json_expr "ok json not failure evidence" "${ok_json}" "report.failure_evidence_only === false"
assert_json_expr "ok json private by default" "${ok_json}" "report.private_by_default === true"
assert_json_expr "ok json evidence model" "${ok_json}" "report.evidence_model === 'local-verifier-environment-readiness'"
assert_json_expr "ok json read only" "${ok_json}" "report.read_only === true"
assert_json_expr "ok json live probing false" "${ok_json}" "report.live_probing === false"
assert_json_expr "ok json has Ed25519 check" "${ok_json}" "report.checks.some(c => c.id === 'openssl_ed25519' && c.status === 'OK')"
assert_json_expr "ok json does not claim attestation" "${ok_json}" "report.external_attestation === false"
assert_json_expr "ok json does not prove custody" "${ok_json}" "report.key_custody_proven === false"
assert_json_expr "ok json does not prove live issuer status" "${ok_json}" "report.live_issuer_status_proven === false"
assert_json_expr "ok json does not prove production authority" "${ok_json}" "report.production_authority_proven === false"
assert_json_expr "ok json boundary names attestation non-claim" "${ok_json}" "report.boundary.not.includes('external_attestation')"
assert_json_expr "ok json non-claims include verifier pass" "${ok_json}" "report.non_claims.some(v => v.includes('not a verifier pass'))"
assert_json_expr "ok json privacy says no credentials" "${ok_json}" "report.privacy.credentials_included === false"
assert_json_expr "ok json privacy says no private key material" "${ok_json}" "report.privacy.private_key_material_included === false"
assert_json_expr "ok json redaction excludes usernames" "${ok_json}" "report.redaction_policy.excluded.includes('usernames')"
assert_json_expr "ok json redaction excludes private paths" "${ok_json}" "report.redaction_policy.excluded.includes('private_filesystem_paths')"
assert_not_contains "ok json omits text heading" "Required tools:" "${ok_json}"
assert_not_contains "ok json omits temp path" "${fake_dir}" "${ok_json}"

cat > "${fake_dir}/fail-bin/openssl" <<'FAKEOPENSSL'
#!/bin/bash
if [ "${1:-}" = "version" ]; then
    echo "LibreSSL 3.3.6"
    exit 0
fi
if [ "${1:-}" = "genpkey" ]; then
    echo "Algorithm ED25519 not found" >&2
    echo "debug path /Users/vincent/.ssh/id_ed25519 token=secret person@example.com" >&2
    echo "-----BEGIN PRIVATE KEY-----" >&2
    exit 1
fi
exit 1
FAKEOPENSSL
chmod +x "${fake_dir}/fail-bin/openssl"

set +e
fail_output=$(PATH="${fake_dir}/fail-bin:${PATH}" bash "${PROJECT_DIR}/bin/zlar" verifier-env 2>&1)
fail_status=$?
set -e

assert_status "fake LibreSSL verifier-env exits one" 1 "${fail_status}"
assert_contains "fake failure reports LibreSSL" "LibreSSL 3.3.6" "${fail_output}"
assert_contains "fake failure reports Ed25519 not found" "Algorithm ED25519 not found" "${fail_output}"
assert_contains "fake failure tells verifier to select Ed25519 openssl" "OpenSSL" "${fail_output}"
assert_contains "fake failure remains boundary-scoped" "not a verifier pass" "${fail_output}"
assert_contains "fake failure is fail" "Result: FAIL" "${fail_output}"
assert_not_contains "fake failure omits temp path" "${fake_dir}" "${fail_output}"
assert_not_contains "fake failure redacts home path" "/Users/" "${fail_output}"
assert_not_contains "fake failure redacts token" "token=secret" "${fail_output}"
assert_not_contains "fake failure redacts private key marker" "BEGIN PRIVATE KEY" "${fail_output}"
assert_not_contains "fake failure redacts email" "person@example.com" "${fail_output}"

set +e
fail_json=$(PATH="${fake_dir}/fail-bin:${PATH}" bash "${PROJECT_DIR}/bin/zlar" verifier-env --json 2>&1)
fail_json_status=$?
set -e

assert_status "fake LibreSSL json exits one" 1 "${fail_json_status}"
assert_json_expr "fail json report type" "${fail_json}" "report.report_type === 'zlar-verifier-env-v0'"
assert_json_expr "fail json failure schema" "${fail_json}" "report.schema === 'zlar-verifier-env-failure-report-v0'"
assert_json_expr "fail json result fail" "${fail_json}" "report.result === 'FAIL'"
assert_json_expr "fail json failure count positive" "${fail_json}" "report.failure_count > 0"
assert_json_expr "fail json failure evidence only" "${fail_json}" "report.failure_evidence_only === true"
assert_json_expr "fail json private by default" "${fail_json}" "report.private_by_default === true"
assert_json_expr "fail json no external attestation" "${fail_json}" "report.external_attestation === false"
assert_json_expr "fail json no key custody" "${fail_json}" "report.key_custody_proven === false"
assert_json_expr "fail json no live issuer status" "${fail_json}" "report.live_issuer_status_proven === false"
assert_json_expr "fail json no production authority" "${fail_json}" "report.production_authority_proven === false"
assert_json_expr "fail json has Ed25519 failure" "${fail_json}" "report.checks.some(c => c.id === 'openssl_ed25519' && c.status === 'FAIL')"
assert_json_expr "fail json carries observed Ed25519 failure" "${fail_json}" "report.checks.some(c => c.id === 'openssl_ed25519' && c.observed && c.observed.some(line => line.includes('Algorithm ED25519 not found')))"
assert_contains "fail json names boundary" "verifier_environment_readiness_only" "${fail_json}"
assert_not_contains "fail json omits temp path" "${fake_dir}" "${fail_json}"
assert_not_contains "fail json redacts home path" "/Users/" "${fail_json}"
assert_not_contains "fail json redacts token" "token=secret" "${fail_json}"
assert_not_contains "fail json redacts private key marker" "BEGIN PRIVATE KEY" "${fail_json}"
assert_not_contains "fail json redacts email" "person@example.com" "${fail_json}"

json_out_path="${fake_dir}/env-report.json"
set +e
json_out_text=$(PATH="${fake_dir}/fail-bin:${PATH}" bash "${PROJECT_DIR}/bin/zlar" verifier-env --json-out "${json_out_path}" 2>&1)
json_out_status=$?
set -e
assert_status "json-out failure exits one" 1 "${json_out_status}"
assert_contains "json-out text keeps artifact note" "Artifact: verifier environment JSON report written" "${json_out_text}"
assert_contains "json-out text keeps fail result" "Result: FAIL" "${json_out_text}"
assert_not_contains "json-out text omits output path" "${json_out_path}" "${json_out_text}"
json_out_body="$(cat "${json_out_path}")"
assert_json_expr "json-out file result fail" "${json_out_body}" "report.result === 'FAIL'"
assert_json_expr "json-out file failure schema" "${json_out_body}" "report.schema === 'zlar-verifier-env-failure-report-v0'"
assert_json_expr "json-out file failure evidence only" "${json_out_body}" "report.failure_evidence_only === true"
assert_json_expr "json-out file carries Ed25519 failure" "${json_out_body}" "report.checks.some(c => c.id === 'openssl_ed25519' && c.status === 'FAIL')"
assert_not_contains "json-out file omits temp path" "${fake_dir}" "${json_out_body}"
assert_not_contains "json-out file redacts home path" "/Users/" "${json_out_body}"
assert_not_contains "json-out file redacts token" "token=secret" "${json_out_body}"
assert_not_contains "json-out file redacts private key marker" "BEGIN PRIVATE KEY" "${json_out_body}"
assert_not_contains "json-out file redacts email" "person@example.com" "${json_out_body}"

set +e
overwrite_output=$(PATH="${fake_dir}/ok-bin:${PATH}" bash "${PROJECT_DIR}/bin/zlar" verifier-env --json-out "${json_out_path}" 2>&1)
overwrite_status=$?
set -e
assert_status "json-out refuses overwrite" 2 "${overwrite_status}"
assert_contains "json-out overwrite names refusal" "JSON output file already exists" "${overwrite_output}"
assert_not_contains "json-out overwrite omits output path" "${json_out_path}" "${overwrite_output}"

help_output=$(bash "${PROJECT_DIR}/bin/zlar" verifier-env --help 2>&1)
help_status=$?
assert_status "help exits zero" 0 "${help_status}"
assert_contains "help names usage" "Usage: zlar verifier-env" "${help_output}"
assert_contains "help names json" "--json" "${help_output}"
assert_contains "help names json-out" "--json-out <file>" "${help_output}"
assert_contains "help names no attestation" "external attestation" "${help_output}"

set +e
unsupported_output=$(bash "${PROJECT_DIR}/bin/zlar" verifier-env --latest 2>&1)
unsupported_status=$?
set -e
if [ "${unsupported_status}" -eq 0 ]; then
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    printf '  FAIL: unsupported option exits nonzero — expected nonzero, got 0\n'
else
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
fi
assert_contains "unsupported option names unsupported" "unsupported option" "${unsupported_output}"
assert_not_contains "unsupported option emits no local home path" "/Users/" "${unsupported_output}"

set +e
json_unsupported_output=$(bash "${PROJECT_DIR}/bin/zlar" verifier-env --json --latest 2>&1)
json_unsupported_status=$?
set -e
assert_status "json unsupported option exits two" 2 "${json_unsupported_status}"
assert_contains "json unsupported option names unsupported" "unsupported option" "${json_unsupported_output}"
assert_not_contains "json unsupported emits no report" "report_type" "${json_unsupported_output}"
assert_not_contains "json unsupported emits no local home path" "/Users/" "${json_unsupported_output}"

set +e
missing_json_out_output=$(bash "${PROJECT_DIR}/bin/zlar" verifier-env --json-out 2>&1)
missing_json_out_status=$?
set -e
assert_status "json-out missing path exits two" 2 "${missing_json_out_status}"
assert_contains "json-out missing path names requirement" "--json-out requires a file path" "${missing_json_out_output}"

set +e
json_mode_conflict_output=$(bash "${PROJECT_DIR}/bin/zlar" verifier-env --json --json-out "${fake_dir}/conflict.json" 2>&1)
json_mode_conflict_status=$?
set -e
assert_status "json and json-out conflict exits two" 2 "${json_mode_conflict_status}"
assert_contains "json and json-out conflict named" "use either --json or --json-out" "${json_mode_conflict_output}"

help_list=$(bash "${PROJECT_DIR}/bin/zlar" help 2>&1)
assert_contains "main help lists verifier-env" "verifier-env" "${help_list}"

rm -rf "${fake_dir}"

echo
printf "Results: %d/%d passed" "${PASS}" "${TOTAL}"
if [ "${FAIL}" -gt 0 ]; then
    printf " (%d FAILED)" "${FAIL}"
    echo
    exit 1
fi
echo " ✓"
