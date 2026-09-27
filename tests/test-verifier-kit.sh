#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# test-verifier-kit.sh — repo-side coverage for the ZLAR Verifier Kit v0.1.
#
# T-KIT-1..T-KIT-29. Builds the kit with an ephemeral publisher key, runs
# every behavior the kit is supposed to guarantee, and asserts on exit
# codes, output text, and JSON shape.
#
# Most-security-critical assertion: T-KIT-11 confirms the kit emits no
# verdict before its integrity check completes (STOP-8 in
# verifier-kit-v0.1-implementation-checklist.md §13).
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TMP_DIR="$(mktemp -d -t zlar-verifier-kit-test.XXXXXX)"
KIT_DIR="${TMP_DIR}/kit"
FIX_DIR="${TMP_DIR}/fixtures"

# shellcheck disable=SC2329
cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

PASS=0
FAIL=0
FAILED_NAMES=""

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [ "${expected}" = "${actual}" ]; then
        PASS=$((PASS + 1))
        return 0
    fi
    FAIL=$((FAIL + 1))
    FAILED_NAMES="${FAILED_NAMES}  ${name}\n"
    echo "  FAIL ${name}: expected '${expected}', got '${actual}'"
    return 1
}

assert_match() {
    local name="$1" pattern="$2" haystack="$3"
    if grep -qE "${pattern}" <<<"${haystack}"; then
        PASS=$((PASS + 1))
        return 0
    fi
    FAIL=$((FAIL + 1))
    FAILED_NAMES="${FAILED_NAMES}  ${name}\n"
    echo "  FAIL ${name}: pattern '${pattern}' not in output"
    echo "      first lines:"
    printf '%s\n' "${haystack}" | sed -n '1,5p' | sed 's/^/        /'
    echo "      last lines:"
    printf '%s\n' "${haystack}" | tail -20 | sed 's/^/        /'
    return 1
}

assert_nomatch() {
    local name="$1" pattern="$2" haystack="$3"
    if grep -qE "${pattern}" <<<"${haystack}"; then
        FAIL=$((FAIL + 1))
        FAILED_NAMES="${FAILED_NAMES}  ${name}\n"
        echo "  FAIL ${name}: pattern '${pattern}' SHOULD NOT be in output"
        return 1
    fi
    PASS=$((PASS + 1))
    return 0
}

# ─── Preflight ────────────────────────────────────────────────────────────────

for tool in node openssl shasum tar gzip awk sed; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "SKIP: tool ${tool} not on PATH (preflight)"
        exit 77
    fi
done

if ! echo "" | openssl genpkey -algorithm ED25519 -out /dev/null 2>/dev/null; then
    echo "SKIP: openssl Ed25519 unavailable (preflight)"
    exit 77
fi

mkdir -p "${FIX_DIR}"

# ─── T-KIT-1: BUILD kit with ephemeral key ────────────────────────────────────

echo "  T-KIT-1   build kit (ephemeral publisher)"
BUILD_LOG="${TMP_DIR}/build.log"

CHECK_ENV_OUT="$(bash "${REPO_ROOT}/tools/build-verifier-kit.sh" --check-env 2>&1)"
CHECK_ENV_EC=$?
assert_eq "T-KIT-1.check-env-exits-zero" "0" "${CHECK_ENV_EC}"
assert_match "T-KIT-1.check-env-title" "Verifier Kit Source Build Environment Preflight v0" "${CHECK_ENV_OUT}"
assert_match "T-KIT-1.check-env-verifier-env" "ZLAR Verifier Environment Preflight v0" "${CHECK_ENV_OUT}"
assert_match "T-KIT-1.check-env-result-pass" "Result: PASS" "${CHECK_ENV_OUT}"
assert_match "T-KIT-1.check-env-boundary" "Source-build environment readiness only" "${CHECK_ENV_OUT}"
assert_nomatch "T-KIT-1.check-env-no-home-path" "/Users/|/home/|/private/" "${CHECK_ENV_OUT}"

bash "${REPO_ROOT}/tools/build-verifier-kit.sh" >"${BUILD_LOG}" 2>&1
BUILD_EC=$?
assert_eq "T-KIT-1.build-exits-zero" "0" "${BUILD_EC}"

if [ "${BUILD_EC}" -ne 0 ]; then
    echo "  Build log:"
    sed 's/^/    /' "${BUILD_LOG}"
    echo ""
    echo "Results: ${PASS}/${PASS} passed, ${FAIL} failed"
    exit 1
fi

cp -R "${REPO_ROOT}/dist/zlar-verifier-kit-v0.1.0" "${KIT_DIR}"
TARBALL_REPO="${REPO_ROOT}/dist/zlar-verifier-kit-v0.1.0.tar.gz"
TARBALL_SHA_REPO="${TARBALL_REPO}.sha256"

if [ -f "${TARBALL_REPO}" ]; then
    assert_eq "T-KIT-1.tarball-exists" "1" "1"
else
    assert_eq "T-KIT-1.tarball-exists" "1" "0"
fi
if [ -f "${TARBALL_SHA_REPO}" ]; then
    assert_eq "T-KIT-1.tarball-sha-sidecar" "1" "1"
else
    assert_eq "T-KIT-1.tarball-sha-sidecar" "1" "0"
fi

# ─── T-KIT-2: SELF-TEST GREEN ─────────────────────────────────────────────────

echo "  T-KIT-2   self-test green"
SELFTEST_OUT="$(cd "${KIT_DIR}" && node verify.mjs --self-test-report 2>&1)"
assert_match "T-KIT-2.report-ok" "^self-test OK" "${SELFTEST_OUT}"
assert_match "T-KIT-2.test-vectors-ok" "test_vectors_ok: true" "${SELFTEST_OUT}"

# ─── Fixtures ─────────────────────────────────────────────────────────────────

echo "  ...   build fixtures"

node --input-type=module -e "
import { readFileSync, writeFileSync } from 'node:fs';
const md = readFileSync('${KIT_DIR}/spec/governed-action-receipt-v1.md', 'utf8');
const re = /\*\*Complete signed envelope\*\*:\s*\`\`\`json\s*([\s\S]*?)\s*\`\`\`/g;
const envelopes = [];
let m;
while ((m = re.exec(md)) !== null) envelopes.push(JSON.parse(m[1]));
writeFileSync('${FIX_DIR}/v1-valid.json', JSON.stringify(envelopes[0]));
const tampered = { ...envelopes[0], sig: 'A' + envelopes[0].sig.slice(1) };
writeFileSync('${FIX_DIR}/v1-tampered-sig.json', JSON.stringify(tampered));
const tamperedP = { ...envelopes[0], payload: 'A' + envelopes[0].payload.slice(1) };
writeFileSync('${FIX_DIR}/v1-tampered-payload.json', JSON.stringify(tamperedP));
writeFileSync('${FIX_DIR}/v1-semantic-invalid.json', JSON.stringify(envelopes[3]));
" 2>&1

ALT_KEY="${FIX_DIR}/alt.key"
ALT_PUB="${FIX_DIR}/alt.pub"
openssl genpkey -algorithm ED25519 -out "${ALT_KEY}" 2>/dev/null
openssl pkey -in "${ALT_KEY}" -pubout -out "${ALT_PUB}" 2>/dev/null

cat > "${FIX_DIR}/v0-shape.json" <<'EOF'
{
  "receipt_version": "0.1.0",
  "id": "abcd",
  "governed_action": {"tool": "Bash", "domain": "general", "detail_hash": "0000000000000000000000000000000000000000000000000000000000000000"},
  "decision": {"outcome": "allow", "rule": "R001", "authorizer": "policy", "timestamp": "2026-01-01T00:00:00.000Z"},
  "evidence": {"policy_version": "v3.3.11", "audit_event_id": "x", "audit_prev_hash": "genesis"},
  "signature": {"algorithm": "Ed25519", "hash_algorithm": "SHA-256", "value": "AAAA", "key_id": "0000000000000000"}
}
EOF

node --input-type=module -e "
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
function sha(s) { return createHash('sha256').update(s, 'utf8').digest('hex'); }
const lines = [];
let prev = 'genesis';
for (let i = 0; i < 5; i++) {
  const ev = {
    id: 'evt-' + String(i+1).padStart(3, '0'),
    ts: '2026-01-01T00:00:0' + i + '.000Z',
    action: 'Bash',
    domain: 'general',
    outcome: 'allow',
    rule: 'R001',
    authorizer: 'policy',
    prev_hash: prev
  };
  const line = JSON.stringify(ev);
  lines.push(line);
  prev = sha(line);
}
writeFileSync('${FIX_DIR}/chain-intact.jsonl', lines.join('\n') + '\n');

const broken = lines.slice();
const ev3 = JSON.parse(broken[2]);
ev3.action = 'Edit';
broken[2] = JSON.stringify(ev3);
writeFileSync('${FIX_DIR}/chain-broken.jsonl', broken.join('\n') + '\n');

const oc = lines.slice();
const ev2 = JSON.parse(oc[1]);
delete ev2.prev_hash;
oc[1] = JSON.stringify(ev2);
writeFileSync('${FIX_DIR}/chain-oc-shape.jsonl', oc.join('\n') + '\n');
" 2>&1

# ─── T-KIT-3: VALID receipt ───────────────────────────────────────────────────

echo "  T-KIT-3   VALID receipt"
V_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v1-valid.json" --pubkey "${KIT_DIR}/spec/test-key.pub" 2>&1)"
V_EC=$?
assert_eq "T-KIT-3.exit-zero" "0" "${V_EC}"
assert_match "T-KIT-3.verdict-VALID" "^VALID" "${V_OUT}"

# ─── T-KIT-4: TAMPERED receipt ────────────────────────────────────────────────

echo "  T-KIT-4   TAMPERED receipt"
V_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v1-tampered-sig.json" --pubkey "${KIT_DIR}/spec/test-key.pub" 2>&1)"
V_EC=$?
assert_eq "T-KIT-4.exit-one" "1" "${V_EC}"
assert_match "T-KIT-4.verdict-INVALID" "^INVALID" "${V_OUT}"

V_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v1-tampered-payload.json" --pubkey "${KIT_DIR}/spec/test-key.pub" 2>&1)"
V_EC=$?
assert_eq "T-KIT-4.payload-exit-one" "1" "${V_EC}"
assert_match "T-KIT-4.payload-INVALID" "^INVALID" "${V_OUT}"

# ─── T-KIT-5: UNKNOWN-SIGNER ──────────────────────────────────────────────────

echo "  T-KIT-5   UNKNOWN-SIGNER"
V_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v1-valid.json" --pubkey "${ALT_PUB}" 2>&1)"
V_EC=$?
assert_eq "T-KIT-5.exit-three" "3" "${V_EC}"
assert_match "T-KIT-5.verdict-UNKNOWN" "^UNKNOWN-SIGNER" "${V_OUT}"

# ─── T-KIT-6: v0 receipt rejection ────────────────────────────────────────────

echo "  T-KIT-6   v0 rejected"
V_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v0-shape.json" --pubkey "${KIT_DIR}/spec/test-key.pub" 2>&1)"
V_EC=$?
assert_eq "T-KIT-6.exit-one" "1" "${V_EC}"
assert_match "T-KIT-6.verdict-INVALID" "^INVALID" "${V_OUT}"
assert_match "T-KIT-6.reason-v0" "v0 receipt rejected" "${V_OUT}"

# ─── T-KIT-7: Semantic INVALID ────────────────────────────────────────────────

echo "  T-KIT-7   semantic INVALID"
V_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v1-semantic-invalid.json" --pubkey "${KIT_DIR}/spec/test-key.pub" 2>&1)"
V_EC=$?
assert_eq "T-KIT-7.exit-one" "1" "${V_EC}"
assert_match "T-KIT-7.semantic-named" "RULE_OUTCOME_CONTRADICTION|semantically invalid" "${V_OUT}"

# ─── T-KIT-8: Chain INTACT ────────────────────────────────────────────────────

echo "  T-KIT-8   chain INTACT"
C_OUT="$(cd "${KIT_DIR}" && node verify-chain.mjs "${FIX_DIR}/chain-intact.jsonl" 2>&1)"
C_EC=$?
assert_eq "T-KIT-8.exit-zero" "0" "${C_EC}"
assert_match "T-KIT-8.result-INTACT" "Result: INTACT" "${C_OUT}"
assert_match "T-KIT-8.events-5" "Chain check: 5 events" "${C_OUT}"

# ─── T-KIT-9: Chain BREAK ─────────────────────────────────────────────────────

echo "  T-KIT-9   chain BREAK"
C_OUT="$(cd "${KIT_DIR}" && node verify-chain.mjs "${FIX_DIR}/chain-broken.jsonl" 2>&1)"
C_EC=$?
assert_eq "T-KIT-9.exit-one" "1" "${C_EC}"
assert_match "T-KIT-9.result-BREAK" "Result: BREAK" "${C_OUT}"
assert_match "T-KIT-9.first-break-line" "First break at line" "${C_OUT}"

# ─── T-KIT-10: OC-shape refusal ───────────────────────────────────────────────

echo "  T-KIT-10  OC-shape refusal"
C_OUT="$(cd "${KIT_DIR}" && node verify-chain.mjs "${FIX_DIR}/chain-oc-shape.jsonl" 2>&1)"
C_EC=$?
assert_eq "T-KIT-10.exit-two" "2" "${C_EC}"
assert_match "T-KIT-10.oc-message" "OC-shape audit chain detected" "${C_OUT}"

# ─── T-KIT-11: MANIFEST tamper (STOP-8) ───────────────────────────────────────

echo "  T-KIT-11  MANIFEST tamper -> BUNDLE-INTEGRITY-FAIL (STOP-8)"
KIT_TAMPER="${TMP_DIR}/kit-tampered"
cp -R "${KIT_DIR}" "${KIT_TAMPER}"
node --input-type=module -e "
import { readFileSync, writeFileSync } from 'node:fs';
const m = readFileSync('${KIT_TAMPER}/MANIFEST.json', 'utf8');
const tampered = m.replace(/\"sha256\":\s*\"([^\"]+)\"/, (mtch, hex) => {
  const flipped = (hex[0] === 'a' ? 'b' : 'a') + hex.slice(1);
  return mtch.replace(hex, flipped);
});
writeFileSync('${KIT_TAMPER}/MANIFEST.json', tampered);
" 2>&1
V_OUT="$(cd "${KIT_TAMPER}" && node verify.mjs "${FIX_DIR}/v1-valid.json" --pubkey "${KIT_TAMPER}/spec/test-key.pub" 2>&1)"
V_EC=$?
assert_eq "T-KIT-11.exit-four" "4" "${V_EC}"
assert_match "T-KIT-11.bundle-fail" "BUNDLE-INTEGRITY-FAIL" "${V_OUT}"
assert_nomatch "T-KIT-11.no-VALID-before-fail" "^VALID" "${V_OUT}"
assert_nomatch "T-KIT-11.no-INVALID-before-fail" "^INVALID" "${V_OUT}"

# ─── T-KIT-12: File body tamper ───────────────────────────────────────────────

echo "  T-KIT-12  lib file tamper -> BUNDLE-INTEGRITY-FAIL"
KIT_TAMPER2="${TMP_DIR}/kit-tampered2"
cp -R "${KIT_DIR}" "${KIT_TAMPER2}"
printf '\n' >> "${KIT_TAMPER2}/lib/receipt.mjs"
V_OUT="$(cd "${KIT_TAMPER2}" && node verify.mjs "${FIX_DIR}/v1-valid.json" --pubkey "${KIT_TAMPER2}/spec/test-key.pub" 2>&1)"
V_EC=$?
assert_eq "T-KIT-12.exit-four" "4" "${V_EC}"
assert_match "T-KIT-12.bundle-fail-named" "SHA-256 mismatch on lib/receipt.mjs" "${V_OUT}"
assert_nomatch "T-KIT-12.no-VALID-before-fail" "^VALID" "${V_OUT}"

# ─── T-KIT-13: Zero-npm posture ───────────────────────────────────────────────

echo "  T-KIT-13  zero-npm posture"
KIT_BARE="${TMP_DIR}/kit-bare"
cp -R "${KIT_DIR}" "${KIT_BARE}"
HAS_NM="$(find "${KIT_BARE}" -name node_modules -type d | head -1)"
assert_eq "T-KIT-13.no-node_modules" "" "${HAS_NM}"
V_OUT="$(cd "${KIT_BARE}" && node verify.mjs --self-test-report 2>&1)"
V_EC=$?
assert_eq "T-KIT-13.exit-zero-from-tmp" "0" "${V_EC}"

# ─── T-KIT-14: --json contract ────────────────────────────────────────────────

echo "  T-KIT-14  --json output contract"
J_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v1-valid.json" --pubkey "${KIT_DIR}/spec/test-key.pub" --json 2>&1)"
J_CHECK="$(echo "${J_OUT}" | node --input-type=module -e "
let txt = '';
process.stdin.on('data', d => txt += d);
process.stdin.on('end', () => {
  try {
    const j = JSON.parse(txt);
    const must = ['verdict','reason','receipt_id','receipt_version','format','self_test_passed','kit_version','spec_version','strict_canonical','warnings','canonicalization_caveat'];
    for (const k of must) {
      if (!(k in j)) { process.stdout.write('MISSING:' + k); process.exit(1); }
    }
    if (j.verdict !== 'VALID') { process.stdout.write('BADVERDICT:' + j.verdict); process.exit(1); }
    if (j.self_test_passed !== true) { process.stdout.write('SELFTEST:' + j.self_test_passed); process.exit(1); }
    process.stdout.write('OK');
  } catch (e) { process.stdout.write('PARSE:' + e.message); process.exit(1); }
});
" 2>&1)"
assert_eq "T-KIT-14.json-shape" "OK" "${J_CHECK}"

J_OUT="$(cd "${KIT_DIR}" && node verify.mjs "${FIX_DIR}/v1-valid.json" --pubkey "${ALT_PUB}" --json 2>&1)"
J_CHECK="$(echo "${J_OUT}" | node --input-type=module -e "
let txt = '';
process.stdin.on('data', d => txt += d);
process.stdin.on('end', () => {
  try {
    const j = JSON.parse(txt);
    if (j.verdict === 'UNKNOWN-SIGNER' && j.kid_match === false) process.stdout.write('OK');
    else process.stdout.write('FAIL:' + JSON.stringify({v: j.verdict, k: j.kid_match}));
  } catch (e) { process.stdout.write('PARSE:' + e.message); }
});" 2>&1)"
assert_eq "T-KIT-14.json-unknown-signer" "OK" "${J_CHECK}"

J_OUT="$(cd "${KIT_DIR}" && node verify-chain.mjs "${FIX_DIR}/chain-intact.jsonl" --json 2>&1)"
J_CHECK="$(echo "${J_OUT}" | node --input-type=module -e "
let txt = '';
process.stdin.on('data', d => txt += d);
process.stdin.on('end', () => {
  try {
    const j = JSON.parse(txt);
    const must = ['events','genesis_ok','intact','first_break','subsequent_breaks','canonical_form','self_test_passed','kit_version','cross_gate_caveat'];
    for (const k of must) if (!(k in j)) { process.stdout.write('MISSING:' + k); process.exit(1); }
    if (!j.intact) { process.stdout.write('NOTINTACT'); process.exit(1); }
    process.stdout.write('OK');
  } catch (e) { process.stdout.write('PARSE:' + e.message); }
});" 2>&1)"
assert_eq "T-KIT-14.chain-json-shape" "OK" "${J_CHECK}"

# ─── T-KIT-15: Runtime budget ─────────────────────────────────────────────────

echo "  T-KIT-15  self-test runtime budget"
T0=$(node -e "console.log(Date.now())")
(cd "${KIT_DIR}" && node verify.mjs --help >/dev/null 2>&1)
T1=$(node -e "console.log(Date.now())")
ELAPSED=$((T1 - T0))
if [ "${ELAPSED}" -lt 500 ]; then
    PASS=$((PASS + 1))
    echo "  PASS T-KIT-15.runtime-under-500ms: ${ELAPSED}ms"
else
    FAIL=$((FAIL + 1))
    FAILED_NAMES="${FAILED_NAMES}  T-KIT-15.runtime-over-500ms\n"
    echo "  FAIL T-KIT-15.runtime-over-500ms: ${ELAPSED}ms (CI safety floor 500ms)"
fi

# ─── T-KIT-16: sample receipt fixture ships in kit ────────────────────────────

echo "  T-KIT-16  examples/sample-receipt.json ships in kit"
if [ -f "${KIT_DIR}/examples/sample-receipt.json" ]; then
    assert_eq "T-KIT-16.exists" "1" "1"
else
    assert_eq "T-KIT-16.exists" "1" "0"
fi

# ─── T-KIT-17: README quick-start verify command works as documented ─────────

echo "  T-KIT-17  README sample-receipt verify command works as documented"
V_OUT="$(cd "${KIT_DIR}" && node verify.mjs examples/sample-receipt.json --pubkey spec/test-key.pub 2>&1)"
V_EC=$?
assert_eq "T-KIT-17.exit-zero" "0" "${V_EC}"
assert_match "T-KIT-17.verdict-VALID" "^VALID" "${V_OUT}"

# ─── T-KIT-18: sample chain fixture ships in kit ─────────────────────────────

echo "  T-KIT-18  examples/sample-chain.jsonl ships in kit"
if [ -f "${KIT_DIR}/examples/sample-chain.jsonl" ]; then
    assert_eq "T-KIT-18.exists" "1" "1"
else
    assert_eq "T-KIT-18.exists" "1" "0"
fi

# ─── T-KIT-19: README quick-start chain command works as documented ──────────

echo "  T-KIT-19  README sample-chain walk command works as documented"
C_OUT="$(cd "${KIT_DIR}" && node verify-chain.mjs examples/sample-chain.jsonl 2>&1)"
C_EC=$?
assert_eq "T-KIT-19.exit-zero" "0" "${C_EC}"
assert_match "T-KIT-19.result-INTACT" "Result: INTACT" "${C_OUT}"
assert_match "T-KIT-19.events-5" "Chain check: 5 events" "${C_OUT}"

# ─── T-KIT-20: README references the shipped sample paths ────────────────────
# Regression: catches the case where the Quick start drifts from the
# fixtures the build actually ships. If the README points at a path the
# kit no longer produces, the README is wrong before the next hardening
# run finds out.

echo "  T-KIT-20  README quick start references the shipped sample paths"
README_TXT="$(cat "${KIT_DIR}/README.md")"
assert_match "T-KIT-20.receipt-path-in-readme" \
    "examples/sample-receipt.json --pubkey spec/test-key.pub" \
    "${README_TXT}"
assert_match "T-KIT-20.chain-path-in-readme" \
    "examples/sample-chain.jsonl" \
    "${README_TXT}"
assert_match "T-KIT-20.recognition-path-in-readme" \
    "examples/trusted-receipt-issuers-v1.json" \
    "${README_TXT}"
assert_match "T-KIT-20.smoke-test-mentions-vectors" \
    "verify-test-vectors.mjs" \
    "${README_TXT}"

# ─── T-KIT-21: external runner files ship in kit ─────────────────────────────

echo "  T-KIT-21  external-runner files ship in kit"
for shipped_file in EXTERNAL-RUNNER.md EXTERNAL-RUNNER-RESULT-TEMPLATE.md external-runner-dry-run.sh; do
    if [ -f "${KIT_DIR}/${shipped_file}" ]; then
        assert_eq "T-KIT-21.${shipped_file}.exists" "1" "1"
    else
        assert_eq "T-KIT-21.${shipped_file}.exists" "1" "0"
    fi
done

# ─── T-KIT-22: dry-run helper passes with bundled samples only ───────────────

echo "  T-KIT-22  external-runner dry-run passes with bundled samples"
DRY_OUT="$(cd "${KIT_DIR}" && bash external-runner-dry-run.sh 2>&1)"
DRY_EC=$?
assert_eq "T-KIT-22.exit-zero" "0" "${DRY_EC}"
assert_match "T-KIT-22.result-pass" "^result: PASS" "${DRY_OUT}"
assert_match "T-KIT-22.boundary" "No external attestation is claimed for this run unless a real non-operator runner" "${DRY_OUT}"
assert_match "T-KIT-22.issuer-text-command" "node verify-issuer-status\\.mjs" "${DRY_OUT}"
assert_match "T-KIT-22.issuer-json-command" "node verify-issuer-status\\.mjs --json" "${DRY_OUT}"
assert_match "T-KIT-22.issuer-verdict" "ISSUER-STATUS-FIXTURE-VERIFIED" "${DRY_OUT}"
assert_match "T-KIT-22.issuer-json-live-false" '"live_probing": false' "${DRY_OUT}"
assert_match "T-KIT-22.issuer-json-attestation-nonclaim" "external attestation" "${DRY_OUT}"
assert_match "T-KIT-22.issuer-json-artifact" "issuer-status fixture JSON result" "${DRY_OUT}"
assert_match "T-KIT-22.recognition-command" "node verify-recognition\\.mjs --receipt examples/sample-receipt\\.json --registry examples/trusted-receipt-issuers-v1\\.json --scope verifier-kit-sample" "${DRY_OUT}"
assert_match "T-KIT-22.recognition-verdict" "^RECOGNIZED" "${DRY_OUT}"
assert_match "T-KIT-22.recognition-json-live-false" '"live_probing": false' "${DRY_OUT}"
assert_match "T-KIT-22.recognition-json-attestation-nonclaim" "external attestation" "${DRY_OUT}"
assert_match "T-KIT-22.recognition-json-artifact" "trusted issuer registry fixture JSON result" "${DRY_OUT}"

# ─── T-KIT-23: dry-run helper verifies synthetic engagement bundle ───────────

echo "  T-KIT-23  external-runner dry-run passes with synthetic engagement"
ENGAGE_DIR="${FIX_DIR}/engagement-bundle"
mkdir -p "${ENGAGE_DIR}"
cp "${KIT_DIR}/examples/sample-receipt.json" "${ENGAGE_DIR}/engagement-receipt.json"
cp "${KIT_DIR}/spec/test-key.pub" "${ENGAGE_DIR}/engagement-pubkey.pub"
cp "${KIT_DIR}/examples/sample-chain.jsonl" "${ENGAGE_DIR}/engagement-chain.jsonl"
if [ -f "${ENGAGE_DIR}/engagement-receipt.json" ]; then
    assert_eq "T-KIT-23.engagement-receipt-copied" "1" "1"
else
    assert_eq "T-KIT-23.engagement-receipt-copied" "1" "0"
fi
if [ -f "${ENGAGE_DIR}/engagement-pubkey.pub" ]; then
    assert_eq "T-KIT-23.engagement-pubkey-copied" "1" "1"
else
    assert_eq "T-KIT-23.engagement-pubkey-copied" "1" "0"
fi
if [ -f "${ENGAGE_DIR}/engagement-chain.jsonl" ]; then
    assert_eq "T-KIT-23.engagement-chain-copied" "1" "1"
else
    assert_eq "T-KIT-23.engagement-chain-copied" "1" "0"
fi
DRY_OUT="$(cd "${KIT_DIR}" && bash external-runner-dry-run.sh --engagement-dir "${ENGAGE_DIR}" 2>&1)"
DRY_EC=$?
if [ "${DRY_EC}" -ne 0 ]; then
    echo "  T-KIT-23 dry-run failed; last 40 lines:"
    printf '%s\n' "${DRY_OUT}" | tail -40 | sed 's/^/    /'
fi
assert_eq "T-KIT-23.exit-zero" "0" "${DRY_EC}"
assert_match "T-KIT-23.result-pass" "^result: PASS" "${DRY_OUT}"
assert_match "T-KIT-23.engagement-receipt" "engagement-bundle/engagement-receipt.json" "${DRY_OUT}"
assert_match "T-KIT-23.engagement-chain" "engagement-bundle/engagement-chain.jsonl" "${DRY_OUT}"

# ─── T-KIT-24: runner files stay privacy and claim bounded ───────────────────

echo "  T-KIT-24  external-runner files avoid private paths and broad claims"
RUNNER_TEXT="$(cat "${KIT_DIR}/EXTERNAL-RUNNER.md" "${KIT_DIR}/EXTERNAL-RUNNER-RESULT-TEMPLATE.md" "${KIT_DIR}/external-runner-dry-run.sh")"
phrase2() { printf '%s %s' "$1" "$2"; }
phrase3() { printf '%s %s %s' "$1" "$2" "$3"; }
GENERIC_PRIVATE_PATH="/Users/tester"
NUMERIC_HUMAN_PATTERN="human:""[0-9]"
assert_nomatch "T-KIT-24.no-private-path" "${GENERIC_PRIVATE_PATH}" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-numeric-human" "${NUMERIC_HUMAN_PATTERN}" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-all-actions" "$(phrase2 "all" "actions")" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-every-tool-call" "$(phrase3 "every" "tool" "call")" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-governs-codex" "$(phrase2 "governs" "Codex")" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-governs-hermes" "$(phrase2 "governs" "Hermes")" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-zlar-governs-codex" "$(phrase3 "ZLAR" "governs" "Codex")" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-zlar-governs-hermes" "$(phrase3 "ZLAR" "governs" "Hermes")" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-external-verification-completed" "$(phrase3 "external" "verification" "completed")" "${RUNNER_TEXT}"
assert_nomatch "T-KIT-24.no-independently-attested" "$(phrase2 "independently" "attested")" "${RUNNER_TEXT}"
assert_match "T-KIT-24.issuer-json-command" "verify-issuer-status\\.mjs --json" "${RUNNER_TEXT}"
assert_match "T-KIT-24.recognition-command" "verify-recognition\\.mjs --receipt examples/sample-receipt\\.json --registry examples/trusted-receipt-issuers-v1\\.json --scope verifier-kit-sample" "${RUNNER_TEXT}"
assert_match "T-KIT-24.issuer-json-out-flag" "issuer-status-json-out" "${RUNNER_TEXT}"
assert_match "T-KIT-24.live-issuer-nonclaim" "live active issuer status" "${RUNNER_TEXT}"
assert_match "T-KIT-24.trust-registry-nonclaim" "production trust-registry state" "${RUNNER_TEXT}"

# ─── T-KIT-25: verify help names issuer-recognition non-claim ────────────────

echo "  T-KIT-25  verifier help names issuer-recognition non-claim"
HELP_OUT="$(cd "${KIT_DIR}" && node verify.mjs --help 2>&1)"
HELP_EC=$?
assert_eq "T-KIT-25.exit-zero" "0" "${HELP_EC}"
assert_match "T-KIT-25.nine-limits-count" "nine" "${HELP_OUT}"
assert_match "T-KIT-25.nine-limits-range" "\\(L1-L9\\)" "${HELP_OUT}"
assert_match "T-KIT-25.issuer-recognition-non-claim" "active[[:space:]]+issuer[[:space:]]+recognition" "${HELP_OUT}"

# ─── T-KIT-26: kit-local issuer-status fixture ──────────────────────────────

echo "  T-KIT-26  verifier kit issuer-status fixture"
if [ -f "${KIT_DIR}/verify-issuer-status.mjs" ]; then
    assert_eq "T-KIT-26.entrypoint-exists" "1" "1"
else
    assert_eq "T-KIT-26.entrypoint-exists" "1" "0"
fi
if [ -f "${KIT_DIR}/lib/issuer-status-proof.mjs" ]; then
    assert_eq "T-KIT-26.issuer-status-lib-exists" "1" "1"
else
    assert_eq "T-KIT-26.issuer-status-lib-exists" "1" "0"
fi
if [ -f "${KIT_DIR}/lib/downstream-recognition-rule.mjs" ]; then
    assert_eq "T-KIT-26.recognition-lib-exists" "1" "1"
else
    assert_eq "T-KIT-26.recognition-lib-exists" "1" "0"
fi
assert_match "T-KIT-26.readme-command" "node verify-issuer-status\\.mjs" "${README_TXT}"

ISSUER_OUT="$(cd "${KIT_DIR}" && node verify-issuer-status.mjs 2>&1)"
ISSUER_EC=$?
assert_eq "T-KIT-26.text-exit-zero" "0" "${ISSUER_EC}"
assert_match "T-KIT-26.text-verdict" "^ISSUER-STATUS-FIXTURE-VERIFIED" "${ISSUER_OUT}"
assert_match "T-KIT-26.text-title" "Issuer Status Proof v1" "${ISSUER_OUT}"
assert_match "T-KIT-26.text-active" "active_issuer_recognized: accept" "${ISSUER_OUT}"
assert_match "T-KIT-26.text-retired" "retired_issuer_refused: refuse; reason=issuer_not_active" "${ISSUER_OUT}"
assert_match "T-KIT-26.text-compromised" "compromised_issuer_refused: refuse; reason=issuer_compromised" "${ISSUER_OUT}"
assert_match "T-KIT-26.text-unknown" "unknown_issuer_refused: refuse; reason=unknown_issuer" "${ISSUER_OUT}"
assert_match "T-KIT-26.text-nonclaim" "not live or production signing authority" "${ISSUER_OUT}"
assert_nomatch "T-KIT-26.text-no-private-path" "/Users/|/home/|/private/|/tmp/|/var/" "${ISSUER_OUT}"
assert_nomatch "T-KIT-26.text-no-key-material" "BEGIN [A-Z ]*KEY" "${ISSUER_OUT}"

ISSUER_JSON="$(cd "${KIT_DIR}" && node verify-issuer-status.mjs --json 2>&1)"
ISSUER_JSON_EC=$?
assert_eq "T-KIT-26.json-exit-zero" "0" "${ISSUER_JSON_EC}"
ISSUER_JSON_CHECK="$(echo "${ISSUER_JSON}" | node --input-type=module -e "
let txt = '';
process.stdin.on('data', d => txt += d);
process.stdin.on('end', () => {
  try {
    const j = JSON.parse(txt);
    const checks = [
      j.verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED',
      j.self_test_passed === true,
      j.command === 'verify-issuer-status.mjs',
      j.proof_type === 'issuer-status-proof-v1',
      j.evidence_model === 'local-hermetic-fixture',
      j.live_probing === false,
      j.trust_anchor_model === 'local-fixture-recognition-rule',
      j.active_issuer?.boarded === true,
      j.retired_issuer?.reason_code === 'issuer_not_active',
      j.compromised_issuer?.reason_code === 'issuer_compromised',
      j.missing_status_issuer?.reason_code === 'issuer_status_missing',
      j.unknown_issuer?.reason_code === 'unknown_issuer',
      j.missing_key_issuer?.reason_code === 'issuer_key_missing',
      j.issuer_boundary?.active_issuer_boards === true,
      j.issuer_boundary?.compromised_issuer_refuses === true,
      j.issuer_boundary?.raw_public_key_material_included === false,
      j.issuer_boundary?.raw_private_key_material_included === false
    ];
    if (checks.every(Boolean)) process.stdout.write('OK');
    else process.stdout.write('FAIL:' + JSON.stringify(j));
  } catch (e) { process.stdout.write('PARSE:' + e.message); process.exit(1); }
});
" 2>&1)"
assert_eq "T-KIT-26.json-shape" "OK" "${ISSUER_JSON_CHECK}"
assert_nomatch "T-KIT-26.json-no-private-path" "/Users/|/home/|/private/|/tmp/|/var/" "${ISSUER_JSON}"
assert_nomatch "T-KIT-26.json-no-key-material" "BEGIN [A-Z ]*KEY" "${ISSUER_JSON}"

ISSUER_HELP="$(cd "${KIT_DIR}" && node verify-issuer-status.mjs --help 2>&1)"
ISSUER_HELP_EC=$?
assert_eq "T-KIT-26.help-exit-zero" "0" "${ISSUER_HELP_EC}"
assert_match "T-KIT-26.help-names-command" "verify-issuer-status\\.mjs" "${ISSUER_HELP}"
assert_match "T-KIT-26.help-names-boundary" "live active issuer status" "${ISSUER_HELP}"
assert_match "T-KIT-26.help-names-nonclaim" "production trust-registry state" "${ISSUER_HELP}"

ISSUER_BAD="$(cd "${KIT_DIR}" && node verify-issuer-status.mjs --latest 2>&1)"
ISSUER_BAD_EC=$?
assert_eq "T-KIT-26.bad-arg-exit-two" "2" "${ISSUER_BAD_EC}"
assert_match "T-KIT-26.bad-arg-message" "unsupported argument" "${ISSUER_BAD}"
assert_nomatch "T-KIT-26.bad-arg-no-report" "Issuer Status Proof v1" "${ISSUER_BAD}"

KIT_TAMPER3="${TMP_DIR}/kit-tampered3"
cp -R "${KIT_DIR}" "${KIT_TAMPER3}"
printf '\n' >> "${KIT_TAMPER3}/lib/issuer-status-proof.mjs"
ISSUER_TAMPER_OUT="$(cd "${KIT_TAMPER3}" && node verify-issuer-status.mjs 2>&1)"
ISSUER_TAMPER_EC=$?
assert_eq "T-KIT-26.tamper-exit-four" "4" "${ISSUER_TAMPER_EC}"
assert_match "T-KIT-26.tamper-bundle-fail" "BUNDLE-INTEGRITY-FAIL" "${ISSUER_TAMPER_OUT}"
assert_nomatch "T-KIT-26.tamper-no-verdict" "^ISSUER-STATUS-FIXTURE-VERIFIED" "${ISSUER_TAMPER_OUT}"
assert_nomatch "T-KIT-26.tamper-no-report" "Issuer Status Proof v1" "${ISSUER_TAMPER_OUT}"

# ─── T-KIT-27: dry-run can write issuer-status JSON artifact ────────────────

echo "  T-KIT-27  external-runner dry-run writes issuer-status JSON artifact"
ISSUER_STATUS_JSON_OUT="${FIX_DIR}/zlar-verifier-kit-issuer-status-fixture.json"
DRY_JSON_OUT="$(cd "${KIT_DIR}" && bash external-runner-dry-run.sh --issuer-status-json-out "${ISSUER_STATUS_JSON_OUT}" 2>&1)"
DRY_JSON_EC=$?
assert_eq "T-KIT-27.exit-zero" "0" "${DRY_JSON_EC}"
if [ -f "${ISSUER_STATUS_JSON_OUT}" ]; then
    assert_eq "T-KIT-27.artifact-exists" "1" "1"
else
    assert_eq "T-KIT-27.artifact-exists" "1" "0"
fi
assert_match "T-KIT-27.written-marker" "issuer_status_json_written: yes" "${DRY_JSON_OUT}"
assert_match "T-KIT-27.artifact-listed" "zlar-verifier-kit-issuer-status-fixture\\.json" "${DRY_JSON_OUT}"
assert_nomatch "T-KIT-27.no-private-output-path" "/Users/|/home/|/private/|/tmp/|/var/" "${DRY_JSON_OUT}"

ISSUER_STATUS_JSON_CHECK="$(node --input-type=module -e "
import { readFileSync } from 'node:fs';
try {
  const j = JSON.parse(readFileSync('${ISSUER_STATUS_JSON_OUT}', 'utf8'));
  const checks = [
    j.verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED',
    j.self_test_passed === true,
    j.command === 'verify-issuer-status.mjs',
    j.evidence_model === 'local-hermetic-fixture',
    j.live_probing === false,
    j.issuer_boundary?.active_issuer_boards === true,
    j.issuer_boundary?.compromised_issuer_refuses === true
  ];
  if (checks.every(Boolean)) process.stdout.write('OK');
  else process.stdout.write('FAIL:' + JSON.stringify(j));
} catch (e) {
  process.stdout.write('PARSE:' + e.message);
  process.exit(1);
}
" 2>&1)"
assert_eq "T-KIT-27.artifact-json-shape" "OK" "${ISSUER_STATUS_JSON_CHECK}"

DRY_OVERWRITE_OUT="$(cd "${KIT_DIR}" && bash external-runner-dry-run.sh --issuer-status-json-out "${ISSUER_STATUS_JSON_OUT}" 2>&1)"
DRY_OVERWRITE_EC=$?
assert_eq "T-KIT-27.overwrite-exit-one" "1" "${DRY_OVERWRITE_EC}"
assert_match "T-KIT-27.overwrite-refused" "refusing to overwrite issuer-status JSON output" "${DRY_OVERWRITE_OUT}"

# ─── T-KIT-28: kit-local trusted issuer registry recognition ────────────────

echo "  T-KIT-28  verifier kit trusted issuer registry recognition"
if [ -f "${KIT_DIR}/verify-recognition.mjs" ]; then
    assert_eq "T-KIT-28.entrypoint-exists" "1" "1"
else
    assert_eq "T-KIT-28.entrypoint-exists" "1" "0"
fi
if [ -f "${KIT_DIR}/examples/trusted-receipt-issuers-v1.json" ]; then
    assert_eq "T-KIT-28.registry-fixture-exists" "1" "1"
else
    assert_eq "T-KIT-28.registry-fixture-exists" "1" "0"
fi
if [ -f "${KIT_DIR}/spec/trusted-receipt-issuers-v1.schema.json" ]; then
    assert_eq "T-KIT-28.registry-schema-exists" "1" "1"
else
    assert_eq "T-KIT-28.registry-schema-exists" "1" "0"
fi
REGISTRY_SCHEMA_CHECK="$(
    cd "${KIT_DIR}" && node --input-type=module - 2>&1 <<'NODE'
import { readFileSync } from 'node:fs';

const schema = JSON.parse(readFileSync('spec/trusted-receipt-issuers-v1.schema.json', 'utf8'));
const registry = JSON.parse(readFileSync('examples/trusted-receipt-issuers-v1.json', 'utf8'));

function assert(name, condition) {
  if (!condition) throw new Error(name);
}
function assertOnlyKeys(name, object, allowed) {
  const allowedSet = new Set(allowed);
  const extra = Object.keys(object).filter(key => !allowedSet.has(key));
  assert(`${name} has no extra fields`, extra.length === 0);
}
function assertStringArray(name, value) {
  assert(`${name} is array`, Array.isArray(value));
  assert(`${name} has only non-empty strings`, value.every(item => typeof item === 'string' && item.length > 0));
}

const required = [
  'registry_type',
  'version',
  'evidence_model',
  'live_probing',
  'deployment_scope',
  'trusted_issuers',
  'accepted_policy_versions',
  'accepted_domains',
  'accepted_tools',
  'accepted_outcomes',
  'non_claims',
];
const optional = ['required_audit_event_id', 'required_detail_hash'];
const topKeys = [...required, ...optional];
assert('schema id names trusted issuer registry', schema.$id === 'https://zlar.ai/spec/trusted-receipt-issuers-v1.schema.json');
assert('schema forbids extra top-level fields', schema.additionalProperties === false);
assert('schema required fields match v1 contract', JSON.stringify(schema.required) === JSON.stringify(required));
assert('schema issuer entries forbid extra fields', schema.properties.trusted_issuers.items.additionalProperties === false);
assertOnlyKeys('registry', registry, topKeys);
for (const key of required) assert(`registry includes ${key}`, Object.hasOwn(registry, key));
assert('registry type matches schema const', registry.registry_type === schema.properties.registry_type.const);
assert('registry version matches schema const', registry.version === schema.properties.version.const);
assert('registry evidence model non-empty', typeof registry.evidence_model === 'string' && registry.evidence_model.length > 0);
assert('registry live probing false', registry.live_probing === false);
assert('registry deployment scope non-empty', typeof registry.deployment_scope === 'string' && registry.deployment_scope.length > 0);
assert('registry has trusted issuers', Array.isArray(registry.trusted_issuers) && registry.trusted_issuers.length > 0);
for (const issuer of registry.trusted_issuers) {
  assertOnlyKeys('trusted issuer', issuer, ['kid', 'public_key_pem', 'status']);
  assert('trusted issuer kid shape', /^[0-9a-f]{16}$/.test(issuer.kid));
  assert('trusted issuer public key shape', typeof issuer.public_key_pem === 'string' && issuer.public_key_pem.startsWith('-----BEGIN PUBLIC KEY-----'));
  assert('trusted issuer status enum', ['active', 'retired', 'compromised'].includes(issuer.status));
}
for (const key of ['accepted_policy_versions', 'accepted_domains', 'accepted_tools', 'accepted_outcomes', 'non_claims']) {
  assertStringArray(key, registry[key]);
}
if (Object.hasOwn(registry, 'required_audit_event_id')) {
  assert('required_audit_event_id non-empty', typeof registry.required_audit_event_id === 'string' && registry.required_audit_event_id.length > 0);
}
if (Object.hasOwn(registry, 'required_detail_hash')) {
  assert('required_detail_hash hex shape', /^[0-9a-f]{64}$/.test(registry.required_detail_hash));
}
process.stdout.write('OK');
NODE
)"
assert_eq "T-KIT-28.registry-schema-contract" "OK" "${REGISTRY_SCHEMA_CHECK}"
assert_match "T-KIT-28.readme-command" \
    "node verify-recognition\\.mjs --receipt examples/sample-receipt\\.json --registry examples/trusted-receipt-issuers-v1\\.json --scope verifier-kit-sample" \
    "${README_TXT}"

RECOGNITION_OUT="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample 2>&1)"
RECOGNITION_EC=$?
assert_eq "T-KIT-28.text-exit-zero" "0" "${RECOGNITION_EC}"
assert_match "T-KIT-28.text-verdict" "^RECOGNIZED" "${RECOGNITION_OUT}"
assert_match "T-KIT-28.text-title" "Trusted Receipt Issuer Recognition v1" "${RECOGNITION_OUT}"
assert_match "T-KIT-28.text-reason" "reason=recognized" "${RECOGNITION_OUT}"
assert_match "T-KIT-28.text-live-false" "live_probing=false" "${RECOGNITION_OUT}"
assert_match "T-KIT-28.text-nonclaim" "external attestation" "${RECOGNITION_OUT}"
assert_nomatch "T-KIT-28.text-no-private-path" "/Users/|/home/|/private/|/tmp/|/var/" "${RECOGNITION_OUT}"
assert_nomatch "T-KIT-28.text-no-key-material" "BEGIN [A-Z ]*KEY" "${RECOGNITION_OUT}"

RECOGNITION_JSON="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample --json 2>&1)"
RECOGNITION_JSON_EC=$?
assert_eq "T-KIT-28.json-exit-zero" "0" "${RECOGNITION_JSON_EC}"
RECOGNITION_JSON_CHECK="$(echo "${RECOGNITION_JSON}" | node --input-type=module -e "
let txt = '';
process.stdin.on('data', d => txt += d);
process.stdin.on('end', () => {
  try {
    const j = JSON.parse(txt);
    const checks = [
      j.verdict === 'RECOGNIZED',
      j.self_test_passed === true,
      j.command === 'verify-recognition.mjs',
      j.registry_type === 'trusted-receipt-issuers-v1',
      j.registry_evidence_model === 'bundled-local-fixture',
      j.live_probing === false,
      j.requested_scope === 'verifier-kit-sample',
      j.registry_scope === 'verifier-kit-sample',
      j.recognized === true,
      j.reason_code === 'recognized',
      j.issuer_status === 'active',
      j.signature_valid === true,
      j.payload?.policy_version === '2.7.2',
      j.payload?.domain === 'bash',
      j.payload?.tool === 'Bash',
      j.payload?.outcome === 'allow',
      typeof j.safe_claim_ceiling === 'string',
      Array.isArray(j.non_claims) && j.non_claims.some(s => s.includes('external attestation'))
    ];
    if (checks.every(Boolean)) process.stdout.write('OK');
    else process.stdout.write('FAIL:' + JSON.stringify(j));
  } catch (e) { process.stdout.write('PARSE:' + e.message); process.exit(1); }
});
" 2>&1)"
assert_eq "T-KIT-28.json-shape" "OK" "${RECOGNITION_JSON_CHECK}"
assert_nomatch "T-KIT-28.json-no-private-path" "/Users/|/home/|/private/|/tmp/|/var/" "${RECOGNITION_JSON}"
assert_nomatch "T-KIT-28.json-no-key-material" "BEGIN [A-Z ]*KEY" "${RECOGNITION_JSON}"

node --input-type=module -e "
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
const out = '${FIX_DIR}/recognition-registries';
mkdirSync(out, { recursive: true });
const base = JSON.parse(readFileSync('${KIT_DIR}/examples/trusted-receipt-issuers-v1.json', 'utf8'));
function write(name, mutate) {
  const copy = JSON.parse(JSON.stringify(base));
  mutate(copy);
  writeFileSync(out + '/' + name + '.json', JSON.stringify(copy, null, 2) + '\n');
}
write('unknown-issuer', r => { r.trusted_issuers[0].kid = '0000000000000000'; });
write('retired-issuer', r => { r.trusted_issuers[0].status = 'retired'; });
write('compromised-issuer', r => { r.trusted_issuers[0].status = 'compromised'; });
write('wrong-policy', r => { r.accepted_policy_versions = ['wrong-policy-version']; });
write('bad-registry-missing-live-probing', r => { delete r.live_probing; });
write('bad-registry-missing-evidence-model', r => { delete r.evidence_model; });
write('bad-registry-extra-field', r => { r.production_authority = true; });
write('bad-registry-issuer-extra-field', r => { r.trusted_issuers[0].custody_verified = true; });
write('bad-registry-missing-public-key', r => { delete r.trusted_issuers[0].public_key_pem; });
write('bad-registry-bad-detail-hash', r => { r.required_detail_hash = 'ABCDEF'; });
" 2>&1

RECOGNITION_UNKNOWN="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/unknown-issuer.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_UNKNOWN_EC=$?
assert_eq "T-KIT-28.unknown-issuer-exit-one" "1" "${RECOGNITION_UNKNOWN_EC}"
assert_match "T-KIT-28.unknown-issuer-verdict" "^RECOGNITION-REFUSED" "${RECOGNITION_UNKNOWN}"
assert_match "T-KIT-28.unknown-issuer-reason" "unknown_issuer" "${RECOGNITION_UNKNOWN}"

RECOGNITION_RETIRED="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/retired-issuer.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_RETIRED_EC=$?
assert_eq "T-KIT-28.retired-issuer-exit-one" "1" "${RECOGNITION_RETIRED_EC}"
assert_match "T-KIT-28.retired-issuer-verdict" "^RECOGNITION-REFUSED" "${RECOGNITION_RETIRED}"
assert_match "T-KIT-28.retired-issuer-reason" "issuer_not_active" "${RECOGNITION_RETIRED}"

RECOGNITION_COMPROMISED="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/compromised-issuer.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_COMPROMISED_EC=$?
assert_eq "T-KIT-28.compromised-issuer-exit-one" "1" "${RECOGNITION_COMPROMISED_EC}"
assert_match "T-KIT-28.compromised-issuer-verdict" "^RECOGNITION-REFUSED" "${RECOGNITION_COMPROMISED}"
assert_match "T-KIT-28.compromised-issuer-reason" "issuer_compromised" "${RECOGNITION_COMPROMISED}"

RECOGNITION_WRONG_POLICY="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/wrong-policy.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_WRONG_POLICY_EC=$?
assert_eq "T-KIT-28.wrong-policy-exit-one" "1" "${RECOGNITION_WRONG_POLICY_EC}"
assert_match "T-KIT-28.wrong-policy-verdict" "^RECOGNITION-REFUSED" "${RECOGNITION_WRONG_POLICY}"
assert_match "T-KIT-28.wrong-policy-reason" "policy_not_recognized" "${RECOGNITION_WRONG_POLICY}"

RECOGNITION_SCOPE_OUT="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope wrong-scope 2>&1)"
RECOGNITION_SCOPE_EC=$?
assert_eq "T-KIT-28.wrong-scope-exit-one" "1" "${RECOGNITION_SCOPE_EC}"
assert_match "T-KIT-28.wrong-scope-verdict" "^RECOGNITION-REFUSED" "${RECOGNITION_SCOPE_OUT}"
assert_match "T-KIT-28.wrong-scope-reason" "scope_not_found" "${RECOGNITION_SCOPE_OUT}"

RECOGNITION_BAD_REGISTRY="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/bad-registry-missing-live-probing.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_BAD_REGISTRY_EC=$?
assert_eq "T-KIT-28.bad-registry-exit-two" "2" "${RECOGNITION_BAD_REGISTRY_EC}"
assert_match "T-KIT-28.bad-registry-message" "live_probing=false" "${RECOGNITION_BAD_REGISTRY}"
assert_nomatch "T-KIT-28.bad-registry-no-verdict" "^RECOGNIZED|^RECOGNITION-REFUSED" "${RECOGNITION_BAD_REGISTRY}"

RECOGNITION_BAD_EVIDENCE_MODEL="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/bad-registry-missing-evidence-model.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_BAD_EVIDENCE_MODEL_EC=$?
assert_eq "T-KIT-28.bad-evidence-model-exit-two" "2" "${RECOGNITION_BAD_EVIDENCE_MODEL_EC}"
assert_match "T-KIT-28.bad-evidence-model-message" "evidence_model" "${RECOGNITION_BAD_EVIDENCE_MODEL}"
assert_nomatch "T-KIT-28.bad-evidence-model-no-verdict" "^RECOGNIZED|^RECOGNITION-REFUSED" "${RECOGNITION_BAD_EVIDENCE_MODEL}"

RECOGNITION_BAD_EXTRA_FIELD="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/bad-registry-extra-field.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_BAD_EXTRA_FIELD_EC=$?
assert_eq "T-KIT-28.bad-extra-field-exit-two" "2" "${RECOGNITION_BAD_EXTRA_FIELD_EC}"
assert_match "T-KIT-28.bad-extra-field-message" "unsupported field: production_authority" "${RECOGNITION_BAD_EXTRA_FIELD}"
assert_nomatch "T-KIT-28.bad-extra-field-no-verdict" "^RECOGNIZED|^RECOGNITION-REFUSED" "${RECOGNITION_BAD_EXTRA_FIELD}"

RECOGNITION_BAD_ISSUER_EXTRA_FIELD="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/bad-registry-issuer-extra-field.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_BAD_ISSUER_EXTRA_FIELD_EC=$?
assert_eq "T-KIT-28.bad-issuer-extra-field-exit-two" "2" "${RECOGNITION_BAD_ISSUER_EXTRA_FIELD_EC}"
assert_match "T-KIT-28.bad-issuer-extra-field-message" "Trusted issuer contains unsupported field: custody_verified" "${RECOGNITION_BAD_ISSUER_EXTRA_FIELD}"
assert_nomatch "T-KIT-28.bad-issuer-extra-field-no-verdict" "^RECOGNIZED|^RECOGNITION-REFUSED" "${RECOGNITION_BAD_ISSUER_EXTRA_FIELD}"

RECOGNITION_BAD_PUBLIC_KEY="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/bad-registry-missing-public-key.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_BAD_PUBLIC_KEY_EC=$?
assert_eq "T-KIT-28.bad-public-key-exit-two" "2" "${RECOGNITION_BAD_PUBLIC_KEY_EC}"
assert_match "T-KIT-28.bad-public-key-message" "public_key_pem" "${RECOGNITION_BAD_PUBLIC_KEY}"
assert_nomatch "T-KIT-28.bad-public-key-no-verdict" "^RECOGNIZED|^RECOGNITION-REFUSED" "${RECOGNITION_BAD_PUBLIC_KEY}"

RECOGNITION_BAD_DETAIL_HASH="$(cd "${KIT_DIR}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry "${FIX_DIR}/recognition-registries/bad-registry-bad-detail-hash.json" --scope verifier-kit-sample 2>&1)"
RECOGNITION_BAD_DETAIL_HASH_EC=$?
assert_eq "T-KIT-28.bad-detail-hash-exit-two" "2" "${RECOGNITION_BAD_DETAIL_HASH_EC}"
assert_match "T-KIT-28.bad-detail-hash-message" "required_detail_hash" "${RECOGNITION_BAD_DETAIL_HASH}"
assert_nomatch "T-KIT-28.bad-detail-hash-no-verdict" "^RECOGNIZED|^RECOGNITION-REFUSED" "${RECOGNITION_BAD_DETAIL_HASH}"

RECOGNITION_BAD="$(cd "${KIT_DIR}" && node verify-recognition.mjs --latest 2>&1)"
RECOGNITION_BAD_EC=$?
assert_eq "T-KIT-28.bad-arg-exit-two" "2" "${RECOGNITION_BAD_EC}"
assert_match "T-KIT-28.bad-arg-message" "unsupported argument" "${RECOGNITION_BAD}"
assert_nomatch "T-KIT-28.bad-arg-no-verdict" "^RECOGNIZED|^RECOGNITION-REFUSED" "${RECOGNITION_BAD}"

KIT_TAMPER4="${TMP_DIR}/kit-tampered4"
cp -R "${KIT_DIR}" "${KIT_TAMPER4}"
printf '\n' >> "${KIT_TAMPER4}/verify-recognition.mjs"
RECOGNITION_TAMPER_OUT="$(cd "${KIT_TAMPER4}" && node verify-recognition.mjs --receipt examples/sample-receipt.json --registry examples/trusted-receipt-issuers-v1.json --scope verifier-kit-sample 2>&1)"
RECOGNITION_TAMPER_EC=$?
assert_eq "T-KIT-28.tamper-exit-four" "4" "${RECOGNITION_TAMPER_EC}"
assert_match "T-KIT-28.tamper-bundle-fail" "BUNDLE-INTEGRITY-FAIL" "${RECOGNITION_TAMPER_OUT}"
assert_nomatch "T-KIT-28.tamper-no-recognized" "^RECOGNIZED" "${RECOGNITION_TAMPER_OUT}"
assert_nomatch "T-KIT-28.tamper-no-refused" "^RECOGNITION-REFUSED" "${RECOGNITION_TAMPER_OUT}"

# ─── T-KIT-29: source-build reproducibility evidence ───────────────────────

echo "  T-KIT-29  verifier kit source-build reproducibility"
REPRO_JSON="${FIX_DIR}/zlar-verifier-kit-reproducibility-v1.json"
REPRO_OUT="$(cd "${REPO_ROOT}" && bash tools/verifier-kit-reproducibility-check.sh --json-out "${REPRO_JSON}" 2>&1)"
REPRO_EC=$?
assert_eq "T-KIT-29.exit-zero" "0" "${REPRO_EC}"
assert_match "T-KIT-29.result-pass" "Result: PASS" "${REPRO_OUT}"
assert_match "T-KIT-29.tarball-reproducible" "Tarball reproducible: true" "${REPRO_OUT}"
assert_match "T-KIT-29.manifest-reproducible" "Manifest/signature reproducible: true" "${REPRO_OUT}"
assert_match "T-KIT-29.boundary" "does not prove production publisher key custody" "${REPRO_OUT}"
assert_nomatch "T-KIT-29.output-no-private-path" "/Users/|/home/|/private/|/tmp/|/var/" "${REPRO_OUT}"
assert_nomatch "T-KIT-29.output-no-key-material" "BEGIN [A-Z ]*KEY" "${REPRO_OUT}"
if [ -f "${REPRO_JSON}" ]; then
    assert_eq "T-KIT-29.json-exists" "1" "1"
else
    assert_eq "T-KIT-29.json-exists" "1" "0"
fi
REPRO_JSON_CHECK="$(node --input-type=module -e "
import { readFileSync } from 'node:fs';
try {
  const j = JSON.parse(readFileSync('${REPRO_JSON}', 'utf8'));
  const hashes = j.public_artifact_hashes || [];
  const allBoundariesFalse = Object.values(j.claim_boundary || {}).every(value => value === false);
  const checks = [
    j.report_type === 'zlar-verifier-kit-reproducibility-v1',
    j.schema_version === 1,
    j.result === 'PASS',
    j.kit_version === 'v0.1.0',
    j.evidence_model === 'local-source-build-same-test-publisher-key-twice',
    /^([0-9a-f]{16})$/.test(j.publisher_kid),
    Array.isArray(j.builds) && j.builds.length === 2,
    j.builds?.[0]?.tarball_sha256 === j.builds?.[1]?.tarball_sha256,
    j.builds?.[0]?.manifest_sha256 === j.builds?.[1]?.manifest_sha256,
    j.builds?.[0]?.manifest_sig_sha256 === j.builds?.[1]?.manifest_sig_sha256,
    j.reproducible?.tarball_sha256_identical === true,
    j.reproducible?.manifest_and_signature_sha256_identical === true,
    j.reproducible?.sidecar_matches_tarball === true,
    hashes.some(entry => entry.path === 'dist/zlar-verifier-kit-v0.1.0.tar.gz' && /^[0-9a-f]{64}$/.test(entry.sha256)),
    hashes.some(entry => entry.path === 'dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256' && /^[0-9a-f]{64}$/.test(entry.sha256)),
    hashes.some(entry => entry.path === 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.json' && /^[0-9a-f]{64}$/.test(entry.sha256)),
    hashes.some(entry => entry.path === 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.sig' && /^[0-9a-f]{64}$/.test(entry.sha256)),
    allBoundariesFalse
  ];
  if (checks.every(Boolean)) process.stdout.write('OK');
  else process.stdout.write('FAIL:' + JSON.stringify(j));
} catch (e) {
  process.stdout.write('PARSE:' + e.message);
  process.exit(1);
}
" 2>&1)"
assert_eq "T-KIT-29.json-shape" "OK" "${REPRO_JSON_CHECK}"
REPRO_JSON_TEXT="$(cat "${REPRO_JSON}")"
assert_nomatch "T-KIT-29.json-no-private-path" "/Users/|/home/|/private/|/tmp/|/var/" "${REPRO_JSON_TEXT}"
assert_nomatch "T-KIT-29.json-no-key-material" "BEGIN [A-Z ]*KEY" "${REPRO_JSON_TEXT}"

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "───────────────────────────────────────────────────"
TOTAL=$((PASS + FAIL))
printf "Results: %d/%d passed\n" "${PASS}" "${TOTAL}"
echo "───────────────────────────────────────────────────"
if [ "${FAIL}" -gt 0 ]; then
    printf "Failed:\n%b" "${FAILED_NAMES}"
    exit 1
fi
exit 0
