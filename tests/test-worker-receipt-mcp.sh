#!/bin/bash
# Worker Receipt + /why v0.1 - MCP contract fixtures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MCP_FIXTURE_FILE="${PROJECT_DIR}/tests/fixtures/worker-receipt-mcp-events.jsonl"
BASH_FIXTURE_FILE="${PROJECT_DIR}/tests/fixtures/worker-receipt-bash-events.jsonl"
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
    node --input-type=module - "${MCP_FIXTURE_FILE}" "${BASH_FIXTURE_FILE}" "${STORE_FILE}" <<'NODE'
import { readFileSync, writeFileSync } from 'node:fs';
import {
  projectWorkerReceipt,
  validateWorkerReceipt,
  canonicalize
} from './lib/worker-receipt.mjs';

const [mcpFixtureFile, bashFixtureFile, storeFile] = process.argv.slice(2);
const readJsonl = (path) => readFileSync(path, 'utf8')
  .trim()
  .split(/\n/)
  .map((line) => JSON.parse(line));

const mcpEvents = readJsonl(mcpFixtureFile);
const bashEvents = readJsonl(bashFixtureFile);
const receipts = mcpEvents.map((event) => projectWorkerReceipt(event)).filter(Boolean);
const receiptById = new Map(receipts.map((receipt) => [receipt.event.id, receipt]));

const fail = (message) => {
  console.error(message);
  process.exit(1);
};
const assert = (label, condition) => {
  if (!condition) fail(`FAIL: ${label}`);
};

const expectedReceiptIds = [
  'wr-mcp-allow-001',
  'wr-mcp-deny-001',
  'wr-mcp-standing-001',
  'wr-mcp-authorized-001',
  'wr-mcp-denied-001',
  'wr-mcp-timeout-001'
];
const excludedIds = [
  'wr-mcp-ask-sent-001',
  'wr-mcp-logged-001',
  'wr-mcp-gate-start-001',
  'wr-mcp-upstream-error-001',
  'wr-mcp-restore-escalation-001'
];

assert('six final MCP fixtures produce receipts', receipts.length === expectedReceiptIds.length);
for (const id of expectedReceiptIds) {
  assert(`${id} produced receipt`, receiptById.has(id));
}
for (const id of excludedIds) {
  assert(`${id} does not produce receipt`, projectWorkerReceipt(mcpEvents.find((event) => event.id === id)) === null);
}

for (const receipt of receipts) {
  validateWorkerReceipt(receipt);
  assert(`surface mcp-gate for ${receipt.event.id}`, receipt.event.surface === 'mcp-gate');
  assert(`source mcp-gate for ${receipt.event.id}`, receipt.event.source === 'mcp-gate');
  assert(`class MCP tool call for ${receipt.event.id}`, receipt.action.class === 'MCP tool call');
  assert(`domain mcp for ${receipt.event.id}`, receipt.action.domain === 'mcp');
  assert(`summary names MCP tool for ${receipt.event.id}`, /^MCP tool: [A-Za-z0-9_.-]+$/.test(receipt.action.summary));
  assert(`detail hash present for ${receipt.event.id}`, /^[a-f0-9]{64}$/.test(receipt.action.detail_hash));
  assert(`audit hash present for ${receipt.event.id}`, /^[a-f0-9]{64}$/.test(receipt.event.audit_hash));
  assert(`MCP limitation scope for ${receipt.event.id}`, receipt.limitations.scope.includes('MCP tool call routed through the ZLAR MCP gate'));
  assert(`out-of-gate non-claim for ${receipt.event.id}`, receipt.limitations.non_claims.some((claim) => claim.includes('outside this gate')));
  assert(`contest not implemented for ${receipt.event.id}`, receipt.contest.status === 'not_implemented' && receipt.contest.handle === null);
  assert(`no raw args key for ${receipt.event.id}`, !JSON.stringify(receipt).includes('args_preview') && !JSON.stringify(receipt).includes('args'));
}

const allow = receiptById.get('wr-mcp-allow-001');
const deny = receiptById.get('wr-mcp-deny-001');
const standing = receiptById.get('wr-mcp-standing-001');
const authorized = receiptById.get('wr-mcp-authorized-001');
const denied = receiptById.get('wr-mcp-denied-001');
const timeout = receiptById.get('wr-mcp-timeout-001');

assert('allow label', allow.decision.label === 'Allowed by policy');
assert('deny label', deny.decision.label === 'Denied by policy');
assert('standing authorizer normalized', standing.decision.authorizer === 'standing_approval');
assert('standing approval channel', standing.decision.approval_channel === 'standing_approval');
assert('authorized label', authorized.decision.label === 'Authorized by human');
assert('denied label', denied.decision.label === 'Denied by human');
assert('timeout label uses gate timeout authorizer', timeout.decision.label === 'Denied after approval timeout');
assert('timeout approval channel preserved', timeout.decision.approval_channel === 'telegram');
assert('human authorizer summarized without chat id', authorized.decision.authorizer === 'human' && !JSON.stringify(authorized).includes('123456789'));
assert('policy version preserved', deny.decision.policy_version === '3.3.12');
assert('policy key id preserved', deny.decision.policy_key_id === 'policy-key-test');
assert('rule description preserved', deny.decision.rule_description === 'Deny MCP writes to credential-adjacent files.');
assert('summary includes tool name', deny.action.summary === 'MCP tool: filesystem.write_file');
assert('stable MCP projection output', canonicalize(projectWorkerReceipt(mcpEvents[1])) === canonicalize(projectWorkerReceipt(mcpEvents[1])));

const serialized = JSON.stringify(receipts);
assert('no MCP fixture secrets leak', !serialized.includes('sk-live-mcp') && !serialized.includes('api_key='));
assert('no MCP fixture private paths leak', !serialized.includes('/Users/vincentnijjar'));
assert('no MCP fixture raw argument values leak', !serialized.includes('launch plan') && !serialized.includes('customer escalation') && !serialized.includes('routine status'));
assert('host excluded', !serialized.includes('test-host'));
assert('agent id excluded', !serialized.includes('codex-cli'));
assert('session id excluded', !serialized.includes('mcp-test-session'));
assert('transport excluded', !Object.prototype.hasOwnProperty.call(allow.event, 'transport'));

const bashReceipt = projectWorkerReceipt(bashEvents.find((event) => event.id === 'wr-allow-001'));
assert('bash receipt still projects for mixed store', bashReceipt.event.surface === 'bash-gate');
const legacyMcp = bashEvents.find((event) => event.id === 'wr-mcp-001');
assert('legacy source=gate MCP fixture remains ineligible', projectWorkerReceipt(legacyMcp) === null);

writeFileSync(storeFile, [bashReceipt, ...receipts].map((receipt) => JSON.stringify(receipt)).join('\n') + '\n');
NODE
}

echo "=== MCP Worker Receipt projection contract ==="
run_node_projection_tests
assert "mixed projection store written" "true" "$([ -s "${STORE_FILE}" ] && echo true || echo false)"
assert "mixed receipt count" "7" "$(wc -l < "${STORE_FILE}" | tr -d ' ')"

echo "fixture audit file" > "${AUDIT_FILE}"
STORE_BEFORE=$(shasum -a 256 "${STORE_FILE}" | awk '{print $1}')
AUDIT_BEFORE=$(shasum -a 256 "${AUDIT_FILE}" | awk '{print $1}')

echo
echo "=== zlar why mixed-store exact-id lookup ==="
WHY_JSON="${TEMP_DIR}/why-mcp.json"
ZLAR_WORKER_RECEIPT_FILE="${STORE_FILE}" "${PROJECT_DIR}/bin/zlar" why wr-mcp-deny-001 --json > "${WHY_JSON}"
assert "mcp json event id" "wr-mcp-deny-001" "$(jq -r '.event.id' "${WHY_JSON}")"
assert "mcp json surface" "mcp-gate" "$(jq -r '.event.surface' "${WHY_JSON}")"
assert "mcp json action class" "MCP tool call" "$(jq -r '.action.class' "${WHY_JSON}")"
assert "mcp json summary" "MCP tool: filesystem.write_file" "$(jq -r '.action.summary' "${WHY_JSON}")"
assert "mcp json no raw args" "false" "$(grep -q 'args_preview\|sk-live-mcp\|/Users/vincentnijjar' "${WHY_JSON}" && echo true || echo false)"

WHY_HUMAN=$(ZLAR_WORKER_RECEIPT_FILE="${STORE_FILE}" "${PROJECT_DIR}/bin/zlar" why wr-mcp-authorized-001)
assert_truthy "mcp human output present" "${WHY_HUMAN}"
assert "mcp human output surface" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'Surface: mcp-gate' && echo true || echo false)"
assert "mcp human output action" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'Action: MCP tool: linear.create_issue' && echo true || echo false)"
assert "mcp human output decision" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'Decision: Authorized by human' && echo true || echo false)"
assert "mcp human output limitation" "true" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'MCP tool call routed through the ZLAR MCP gate' && echo true || echo false)"
assert "mcp human output no raw secret" "false" "$(printf '%s' "${WHY_HUMAN}" | grep -q 'sk-live-mcp\|customer escalation\|123456789' && echo true || echo false)"

BASH_HUMAN=$(ZLAR_WORKER_RECEIPT_FILE="${STORE_FILE}" "${PROJECT_DIR}/bin/zlar" why wr-allow-001)
assert_truthy "bash human output present from mixed store" "${BASH_HUMAN}"
assert "bash mixed output surface" "true" "$(printf '%s' "${BASH_HUMAN}" | grep -q 'Surface: bash-gate' && echo true || echo false)"

STORE_AFTER=$(shasum -a 256 "${STORE_FILE}" | awk '{print $1}')
AUDIT_AFTER=$(shasum -a 256 "${AUDIT_FILE}" | awk '{print $1}')
assert "zlar why leaves mixed worker receipt store unchanged" "${STORE_BEFORE}" "${STORE_AFTER}"
assert "zlar why leaves audit file unchanged" "${AUDIT_BEFORE}" "${AUDIT_AFTER}"

echo
printf "MCP Worker Receipt tests: %d/%d passed, %d failed\n" "${PASS}" "${TOTAL}" "${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
    exit 1
fi
