#!/bin/bash
# Worker Receipt + /why v0.1 - bash-gate first-slice tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE_FILE="${PROJECT_DIR}/tests/fixtures/worker-receipt-bash-events.jsonl"
TEMP_DIR=$(mktemp -d)
STORE_FILE="${TEMP_DIR}/worker-receipts.jsonl"
AUDIT_FILE="${TEMP_DIR}/audit.jsonl"

cleanup() { rm -rf "${TEMP_DIR}"; }
trap cleanup EXIT

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
        printf '  FAIL: %s - expected "%s", got "%s"\n' "${label}" "${expected}" "${actual}"
    fi
}

assert_truthy() {
    local label="$1" actual="$2"
    TOTAL=$((TOTAL + 1))
    if [[ -n "${actual}" ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL: %s - expected non-empty, got empty\n' "${label}"
    fi
}

run_node_projection_tests() {
    node --input-type=module - "${FIXTURE_FILE}" "${STORE_FILE}" <<'NODE'
import { readFileSync, writeFileSync } from 'node:fs';
import {
  projectWorkerReceipt,
  validateWorkerReceipt,
  canonicalize
} from './lib/worker-receipt.mjs';

const [fixtureFile, storeFile] = process.argv.slice(2);
const events = readFileSync(fixtureFile, 'utf8')
  .trim()
  .split(/\n/)
  .map((line) => JSON.parse(line));

const receipts = events.map((event) => projectWorkerReceipt(event)).filter(Boolean);
const fail = (message) => {
  console.error(message);
  process.exit(1);
};
const assert = (label, condition) => {
  if (!condition) fail(`FAIL: ${label}`);
};

assert('five final bash-gate fixtures produce receipts', receipts.length === 5);
assert('ask_pending does not produce receipt', projectWorkerReceipt(events.find((event) => event.id === 'wr-ask-pending-001')) === null);
assert('operational event does not produce receipt', projectWorkerReceipt(events.find((event) => event.id === 'wr-operational-001')) === null);
assert('MCP event does not produce receipt in first slice', projectWorkerReceipt(events.find((event) => event.id === 'wr-mcp-001')) === null);

const allow = receipts.find((receipt) => receipt.event.id === 'wr-allow-001');
const deny = receipts.find((receipt) => receipt.event.id === 'wr-deny-001');
const authorized = receipts.find((receipt) => receipt.event.id === 'wr-authorized-001');
const denied = receipts.find((receipt) => receipt.event.id === 'wr-denied-001');
const timeout = receipts.find((receipt) => receipt.event.id === 'wr-timeout-001');
const allowedTopLevel = [
  'worker_receipt_version',
  'type',
  'event',
  'time',
  'action',
  'decision',
  'limitations',
  'contest'
].sort().join(',');

for (const receipt of receipts) {
  validateWorkerReceipt(receipt);
  assert(`allowlist only for ${receipt.event.id}`, Object.keys(receipt).sort().join(',') === allowedTopLevel);
  assert(`local clock declaration for ${receipt.event.id}`, receipt.time.source === 'local_clock');
  assert(`contest not implemented for ${receipt.event.id}`, receipt.contest.status === 'not_implemented' && receipt.contest.handle === null);
  assert(`limitations include out-of-gate non-claim for ${receipt.event.id}`, receipt.limitations.non_claims.some((claim) => claim.includes('outside this gate')));
  assert(`detail hash present for ${receipt.event.id}`, /^[a-f0-9]{64}$/.test(receipt.action.detail_hash));
  assert(`audit hash present for ${receipt.event.id}`, /^[a-f0-9]{64}$/.test(receipt.event.audit_hash));
}

assert('stable projection output', canonicalize(projectWorkerReceipt(events[1])) === canonicalize(projectWorkerReceipt(events[1])));
assert('allow label', allow.decision.label === 'Allowed by policy');
assert('deny label', deny.decision.label === 'Denied by policy');
assert('authorized label', authorized.decision.label === 'Authorized by human');
assert('denied label', denied.decision.label === 'Denied by human');
assert('timeout label', timeout.decision.label === 'Denied after approval timeout');
assert('frozen rule id', deny.decision.rule_id === 'R002');
assert('frozen rule description', deny.decision.rule_description === 'Deny commands that expose credentials or private key material.');
assert('policy version', deny.decision.policy_version === '3.3.12');
assert('policy key id', deny.decision.policy_key_id === 'policy-key-test');
assert('human authorizer summarized without chat id', authorized.decision.authorizer === 'human' && !JSON.stringify(authorized).includes('123456789'));
assert('human channel preserved generically', authorized.decision.approval_channel === 'telegram');
assert('redacts private path', !JSON.stringify(deny).includes('/Users/tester/.ssh/id_rsa'));
assert('redacts secret token', !JSON.stringify(deny).includes('sk-live-1234567890'));
assert('redacted summary still explains action class', deny.action.summary.includes('Bash: cat [REDACTED_PATH]'));
assert('raw audit detail excluded', !Object.prototype.hasOwnProperty.call(deny, 'detail'));
assert('host excluded', !JSON.stringify(receipts).includes('test-host'));
assert('session id excluded', !JSON.stringify(receipts).includes('test-session'));
assert('operational telemetry excluded', !JSON.stringify(receipts).includes('clean_run_count') && !JSON.stringify(receipts).includes('dice'));

writeFileSync(storeFile, receipts.map((receipt) => JSON.stringify(receipt)).join('\n') + '\n');
NODE
}

echo "=== Worker Receipt projection contract ==="
run_node_projection_tests
assert "projection store written" "true" "$([ -s "${STORE_FILE}" ] && echo true || echo false)"
assert "receipt count" "5" "$(wc -l < "${STORE_FILE}" | tr -d ' ')"

echo "fixture audit file" > "${AUDIT_FILE}"
STORE_BEFORE=$(shasum -a 256 "${STORE_FILE}" | awk '{print $1}')
AUDIT_BEFORE=$(shasum -a 256 "${AUDIT_FILE}" | awk '{print $1}')

echo
echo "=== zlar why exact-id lookup ==="
WHY_HUMAN=$(ZLAR_WORKER_RECEIPT_FILE="${STORE_FILE}" "${PROJECT_DIR}/bin/zlar" why wr-deny-001)
assert_truthy "human output present" "${WHY_HUMAN}"
assert "human output title" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'ZLAR Worker Receipt v0.1.0' && echo true || echo false)"
assert "human output event" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'Event: wr-deny-001' && echo true || echo false)"
assert "human output rule" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'Rule: R002' && echo true || echo false)"
assert "human output redacted" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q '\[REDACTED_PATH\]' && echo true || echo false)"
assert "human output no raw secret" "false" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'sk-live' && echo true || echo false)"

WHY_JSON="${TEMP_DIR}/why.json"
ZLAR_WORKER_RECEIPT_FILE="${STORE_FILE}" "${PROJECT_DIR}/bin/zlar" why wr-authorized-001 --json > "${WHY_JSON}"
assert "json event id" "wr-authorized-001" "$(jq -r '.event.id' "${WHY_JSON}")"
assert "json authorizer summary" "human" "$(jq -r '.decision.authorizer' "${WHY_JSON}")"
assert "json contest status" "not_implemented" "$(jq -r '.contest.status' "${WHY_JSON}")"

if ZLAR_WORKER_RECEIPT_FILE="${STORE_FILE}" "${PROJECT_DIR}/bin/zlar" why missing-id >/tmp/zlar-why-missing.out 2>/tmp/zlar-why-missing.err; then
    assert "missing id exits nonzero" "nonzero" "zero"
else
    assert "missing id exits nonzero" "nonzero" "nonzero"
    assert "missing id clear error" "true" "$(grep -q 'not found for event id: missing-id' /tmp/zlar-why-missing.err && echo true || echo false)"
fi

if ZLAR_WORKER_RECEIPT_FILE="${STORE_FILE}" "${PROJECT_DIR}/bin/zlar" why --list >/tmp/zlar-why-list.out 2>/tmp/zlar-why-list.err; then
    assert "list mode unsupported" "nonzero" "zero"
else
    assert "list mode unsupported" "nonzero" "nonzero"
    assert "list mode clear error" "true" "$(grep -q 'Unsupported option' /tmp/zlar-why-list.err && echo true || echo false)"
fi

BAD_STORE="${TEMP_DIR}/bad-worker-receipts.jsonl"
{
    head -n 1 "${STORE_FILE}"
    printf '%s\n' '{bad json'
} > "${BAD_STORE}"
if ZLAR_WORKER_RECEIPT_FILE="${BAD_STORE}" "${PROJECT_DIR}/bin/zlar" why wr-allow-001 >/tmp/zlar-why-bad.out 2>/tmp/zlar-why-bad.err; then
    assert "malformed store exits nonzero" "nonzero" "zero"
else
    assert "malformed store exits nonzero" "nonzero" "nonzero"
    assert "malformed store clear error" "true" "$(grep -q 'Malformed Worker Receipt store' /tmp/zlar-why-bad.err && echo true || echo false)"
fi

STORE_AFTER=$(shasum -a 256 "${STORE_FILE}" | awk '{print $1}')
AUDIT_AFTER=$(shasum -a 256 "${AUDIT_FILE}" | awk '{print $1}')
assert "zlar why leaves worker receipt store unchanged" "${STORE_BEFORE}" "${STORE_AFTER}"
assert "zlar why leaves audit file unchanged" "${AUDIT_BEFORE}" "${AUDIT_AFTER}"

echo
printf "Worker Receipt tests: %d/%d passed, %d failed\n" "${PASS}" "${TOTAL}" "${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
    exit 1
fi
