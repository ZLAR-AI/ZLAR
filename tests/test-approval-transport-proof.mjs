#!/usr/bin/env node

import {
  APPROVAL_TRANSPORT_PROOF_TYPE,
  SAFE_CLAIM_CEILING,
  assertApprovalTransportProof,
  assertNoUnsafeApprovalTransportProofText,
  formatApprovalTransportProofSummary,
  runApprovalTransportProof,
} from '../lib/approval-transport-proof.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

section('approval transport proof report');
const report = runApprovalTransportProof();
assert('valid report passes validation', assertApprovalTransportProof(report));
assertEqual('proof type', APPROVAL_TRANSPORT_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local hermetic fixture evidence', 'local-hermetic-fixture', report.evidence_model);
assertEqual('transport model', 'channel-neutral-approval-transport-v1', report.transport_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('action class', 'records.write', report.action_class);
assertEqual('checkpoint rule', 'RASK_RECORDS_WRITE', report.checkpoint_rule);

section('transport inventory');
const reference = report.transports.find((item) => item.transport_id === 'reference-fixture-transport');
const telegram = report.transports.find((item) => item.transport_id === 'telegram-adapter');
assertEqual('reference fixture configured', true, reference.configured);
assertEqual('reference fixture healthy', true, reference.healthy);
assertEqual('reference fixture does not live deliver', false, reference.live_delivery);
assertEqual('reference fixture sends no real notification', false, reference.sends_real_notification);
assertEqual('telegram adapter not configured', false, telegram.configured);
assertEqual('telegram adapter not healthy in fixture', false, telegram.healthy);
assertEqual('telegram adapter not required', false, telegram.required_for_fixture);
assertEqual('telegram adapter not live probed', false, telegram.live_delivery);

section('transport failure and pending cases');
assertEqual('unavailable case id', 'transport_unavailable_without_receipt', report.cases.transport_unavailable.case_id);
assertEqual('unavailable transport does not board', false, report.cases.transport_unavailable.boarded);
assertEqual('unavailable reason missing receipt', 'receipt_missing', report.cases.transport_unavailable.reason_code);
assertEqual('pending case id', 'transport_delivered_no_human_decision', report.cases.delivered_without_decision.case_id);
assertEqual('pending delivered but no receipt', true, report.cases.delivered_without_decision.delivery_accepted);
assertEqual('pending does not board', false, report.cases.delivered_without_decision.boarded);
assertEqual('pending reason missing receipt', 'receipt_missing', report.cases.delivered_without_decision.reason_code);

section('signed human decision boards');
assertEqual('authorized case id', 'transport_delivered_signed_human_decision', report.cases.signed_human_decision.case_id);
assertEqual('authorized receipt present', true, report.cases.signed_human_decision.receipt_present);
assertEqual('authorized receipt id matches expected', true, report.cases.signed_human_decision.receipt_id_matches_expected);
assertEqual('authorized boards', true, report.cases.signed_human_decision.boarded);
assertEqual('authorized decision accepts', 'accept', report.cases.signed_human_decision.decision);
assertEqual('authorized reason recognized', 'recognized', report.cases.signed_human_decision.reason_code);
assertEqual('authorized authorizer is human fixture', 'human:fixture-operator', report.cases.signed_human_decision.authorizer);

section('telegram nonessential case');
assertEqual('telegram nonessential case id', 'telegram_adapter_not_configured_nonessential', report.cases.telegram_not_required.case_id);
assertEqual('telegram nonessential configured false', false, report.cases.telegram_not_required.configured);
assertEqual('telegram nonessential required false', false, report.cases.telegram_not_required.required_for_fixture);
assertEqual('telegram nonessential live probed false', false, report.cases.telegram_not_required.live_probed);
assertEqual('telegram does not block reference fixture', false, report.cases.telegram_not_required.blocks_reference_fixture);

section('receipt evidence remains bounded');
assertEqual('signed receipt present', true, report.receipt.signed_human_decision_receipt_present);
assertEqual('receipt authorizer', 'human:fixture-operator', report.receipt.authorizer);
assertEqual('receipt outcome', 'authorized', report.receipt.outcome);
assertEqual('receipt raw detail absent', false, report.receipt.raw_detail_present);
assertEqual('receipt public key absent', false, report.receipt.public_key_present);
assertEqual('receipt private key absent', false, report.receipt.private_key_present);

section('safe output formatting');
const summary = formatApprovalTransportProofSummary(report);
assert('summary title present', summary.includes('Approval Transport Proof v1'));
assert('summary names channel-neutral model', summary.includes('channel-neutral-approval-transport-v1'));
assert('summary names reference fixture', summary.includes('reference-fixture-transport'));
assert('summary names Telegram nonessential status', summary.includes('not_configured_not_required_for_fixture'));
assert('summary includes no live delivery', summary.includes('live_delivery=false'));
assert('summary output is privacy safe', assertNoUnsafeApprovalTransportProofText(summary));

const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeApprovalTransportProofText(jsonText));
assert('json omits raw fixture record', !jsonText.includes('approval-transport-fixture-record'));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertApprovalTransportProof(liveProbeClaim), 'must not perform live probing');

const telegramRequiredClaim = structuredClone(report);
telegramRequiredClaim.transports.find((item) => item.transport_id === 'telegram-adapter').required_for_fixture = true;
assertThrows('telegram required claim fails', () => assertApprovalTransportProof(telegramRequiredClaim), 'Telegram adapter');

const brokenUnavailable = structuredClone(report);
brokenUnavailable.cases.transport_unavailable.boarded = true;
assertThrows('unavailable boarding fails', () => assertApprovalTransportProof(brokenUnavailable), 'fail closed');

const brokenPending = structuredClone(report);
brokenPending.cases.delivered_without_decision.boarded = true;
assertThrows('pending boarding fails', () => assertApprovalTransportProof(brokenPending), 'without human decision');

const brokenAuthorized = structuredClone(report);
brokenAuthorized.cases.signed_human_decision.boarded = false;
assertThrows('missing authorized boarding fails', () => assertApprovalTransportProof(brokenAuthorized), 'Signed human decision');

const liveDeliveryClaim = structuredClone(report);
liveDeliveryClaim.transports[0].live_delivery = true;
assertThrows('live delivery claim fails', () => assertApprovalTransportProof(liveDeliveryClaim), 'Reference approval transport');

const leakedReceipt = structuredClone(report);
leakedReceipt.receipt.raw_detail_present = true;
assertThrows('raw detail leakage fails', () => assertApprovalTransportProof(leakedReceipt), 'raw detail');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
