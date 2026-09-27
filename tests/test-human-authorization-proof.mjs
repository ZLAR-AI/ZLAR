#!/usr/bin/env node

import {
  HUMAN_AUTHORIZATION_PROOF_TYPE,
  SAFE_CLAIM_CEILING,
  assertHumanAuthorizationProof,
  assertNoUnsafeHumanAuthorizationProofText,
  formatHumanAuthorizationProofSummary,
  runHumanAuthorizationProof,
} from '../lib/human-authorization-proof.mjs';

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

section('human authorization proof report');
const report = runHumanAuthorizationProof();
assert('valid report passes validation', assertHumanAuthorizationProof(report));
assertEqual('proof type', HUMAN_AUTHORIZATION_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local hermetic fixture evidence', 'local-hermetic-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('approval channel is simulated', 'simulated-human-fixture', report.approval_channel);
assertEqual('action class', 'records.write', report.action_class);
assertEqual('checkpoint rule', 'RASK_RECORDS_WRITE', report.checkpoint_rule);

section('pending ask refuses before human decision');
assertEqual('pending case id', 'ask_pending_without_human_decision', report.pending_without_decision.case_id);
assertEqual('pending has no receipt', false, report.pending_without_decision.receipt_present);
assertEqual('pending does not board', false, report.pending_without_decision.boarded);
assertEqual('pending decision refuses', 'refuse', report.pending_without_decision.decision);
assertEqual('pending reason is missing receipt', 'receipt_missing', report.pending_without_decision.reason_code);

section('simulated human authorization boards');
assertEqual('authorized case id', 'simulated_human_approved', report.authorized_boarding.case_id);
assertEqual('authorized receipt present', true, report.authorized_boarding.receipt_present);
assertEqual('authorized receipt id matches expected', true, report.authorized_boarding.receipt_id_matches_expected);
assertEqual('authorized boards', true, report.authorized_boarding.boarded);
assertEqual('authorized decision accepts', 'accept', report.authorized_boarding.decision);
assertEqual('authorized reason recognized', 'recognized', report.authorized_boarding.reason_code);
assertEqual('authorized authorizer is human fixture', 'human:fixture-operator', report.authorized_boarding.authorizer);
assertEqual('authorized outcome', 'authorized', report.authorized_boarding.outcome);

section('simulated human denial refuses');
assertEqual('denied case id', 'simulated_human_denied', report.denied_boarding.case_id);
assertEqual('denied receipt present', true, report.denied_boarding.receipt_present);
assertEqual('denied does not board', false, report.denied_boarding.boarded);
assertEqual('denied decision refuses', 'refuse', report.denied_boarding.decision);
assertEqual('denied reason outcome not boarding', 'outcome_not_boarding', report.denied_boarding.reason_code);
assertEqual('denied authorizer is human fixture', 'human:fixture-operator', report.denied_boarding.authorizer);
assertEqual('denied outcome', 'denied', report.denied_boarding.outcome);

section('receipt evidence remains bounded');
assertEqual('authorized receipt present', true, report.receipt.authorized_receipt_present);
assertEqual('receipt authorizer', 'human:fixture-operator', report.receipt.authorizer);
assertEqual('receipt outcome', 'authorized', report.receipt.outcome);
assertEqual('receipt raw detail absent', false, report.receipt.raw_detail_present);
assertEqual('receipt public key absent', false, report.receipt.public_key_present);
assertEqual('receipt private key absent', false, report.receipt.private_key_present);

section('safe output formatting');
const summary = formatHumanAuthorizationProofSummary(report);
assert('summary title present', summary.includes('Human Authorization Proof v1'));
assert('summary names simulated channel', summary.includes('Approval channel: simulated-human-fixture'));
assert('summary includes pending refusal', summary.includes('ask_pending_without_human_decision: refuse'));
assert('summary includes authorized boarding', summary.includes('simulated_human_approved: accept'));
assert('summary includes denial refusal', summary.includes('simulated_human_denied: refuse'));
assert('summary states Telegram non-claim', summary.includes('not live Telegram'));
assert('summary output is privacy safe', assertNoUnsafeHumanAuthorizationProofText(summary));

const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeHumanAuthorizationProofText(jsonText));
assert('json omits raw fixture record', !jsonText.includes('authorized-fixture-record'));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertHumanAuthorizationProof(liveProbeClaim), 'must not perform live probing');

const liveChannelClaim = structuredClone(report);
liveChannelClaim.approval_channel = 'telegram';
assertThrows('live channel claim fails', () => assertHumanAuthorizationProof(liveChannelClaim), 'simulated human approval channel');

const brokenPending = structuredClone(report);
brokenPending.pending_without_decision.boarded = true;
assertThrows('pending boarding fails', () => assertHumanAuthorizationProof(brokenPending), 'Pending ask');

const brokenAuthorized = structuredClone(report);
brokenAuthorized.authorized_boarding.boarded = false;
assertThrows('missing authorized boarding fails', () => assertHumanAuthorizationProof(brokenAuthorized), 'recognized boarding');

const brokenDenied = structuredClone(report);
brokenDenied.denied_boarding.boarded = true;
assertThrows('denied boarding fails', () => assertHumanAuthorizationProof(brokenDenied), 'denial boarded');

const leakedReceipt = structuredClone(report);
leakedReceipt.receipt.raw_detail_present = true;
assertThrows('raw detail leakage fails', () => assertHumanAuthorizationProof(leakedReceipt), 'raw detail');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
