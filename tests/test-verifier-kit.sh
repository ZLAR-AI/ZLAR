#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# test-verifier-kit.sh — repo-side coverage for the ZLAR Verifier Kit v0.1.
#
# T-KIT-1..T-KIT-15. Builds the kit with an ephemeral publisher key, runs
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
    if echo "${haystack}" | grep -qE "${pattern}"; then
        PASS=$((PASS + 1))
        return 0
    fi
    FAIL=$((FAIL + 1))
    FAILED_NAMES="${FAILED_NAMES}  ${name}\n"
    echo "  FAIL ${name}: pattern '${pattern}' not in output"
    echo "      output: $(echo "${haystack}" | head -5)"
    return 1
}

assert_nomatch() {
    local name="$1" pattern="$2" haystack="$3"
    if echo "${haystack}" | grep -qE "${pattern}"; then
        FAIL=$((FAIL + 1))
        FAILED_NAMES="${FAILED_NAMES}  ${name}\n"
        echo "  FAIL ${name}: pattern '${pattern}' SHOULD NOT be in output"
        return 1
    fi
    PASS=$((PASS + 1))
    return 0
}

# ─── Preflight ────────────────────────────────────────────────────────────────

for tool in node openssl shasum tar awk sed; do
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
assert_match "T-KIT-22.boundary" "Not externally attested yet" "${DRY_OUT}"

# ─── T-KIT-23: dry-run helper verifies synthetic engagement bundle ───────────

echo "  T-KIT-23  external-runner dry-run passes with synthetic engagement"
ENGAGE_DIR="${FIX_DIR}/engagement-bundle"
mkdir -p "${ENGAGE_DIR}"
cp "${KIT_DIR}/examples/sample-receipt.json" "${ENGAGE_DIR}/engagement-receipt.json"
cp "${KIT_DIR}/spec/test-key.pub" "${ENGAGE_DIR}/engagement-pubkey.pub"
cp "${KIT_DIR}/examples/sample-chain.jsonl" "${ENGAGE_DIR}/engagement-chain.jsonl"
DRY_OUT="$(cd "${KIT_DIR}" && bash external-runner-dry-run.sh --engagement-dir "${ENGAGE_DIR}" 2>&1)"
DRY_EC=$?
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

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "───────────────────────────────────────────────────"
TOTAL=$((PASS + FAIL))
printf "Results: %d/%d passed\n" "${PASS}" "${TOTAL}"
echo "───────────────────────────────────────────────────"
if [ "${FAIL}" -gt 0 ]; then
    printf "Failed:\n${FAILED_NAMES}"
    exit 1
fi
exit 0
