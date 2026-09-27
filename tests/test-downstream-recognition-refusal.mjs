#!/usr/bin/env node

import {
  DOWNSTREAM_REFUSAL_PROOF_TYPE,
  REQUIRED_REFUSAL_REASONS,
  SAFE_CLAIM_CEILING,
  assertDownstreamRefusalProof,
  assertNoUnsafeDownstreamRefusalProofText,
  formatDownstreamRefusalProofSummary,
  runHermeticDownstreamRefusalProof,
} from '../lib/downstream-refusal-proof.mjs';

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

section('hermetic downstream refusal proof report');
const report = runHermeticDownstreamRefusalProof();
assert('valid report passes validation', assertDownstreamRefusalProof(report));
assertEqual('proof type', DOWNSTREAM_REFUSAL_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local hermetic fixture evidence', 'local-hermetic-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('action class', 'records.write', report.action_class);
assertEqual('deployment scope', 'fixture-records-terminal', report.deployment_scope);

section('recognized receipt boards into fake downstream effect');
assertEqual('recognized case id', 'recognized', report.recognized_boarding.case_id);
assertEqual('recognized receipt boards', true, report.recognized_boarding.boarded);
assertEqual('recognized decision accepts', 'accept', report.recognized_boarding.decision);
assertEqual('recognized reason', 'recognized', report.recognized_boarding.reason_code);
assertEqual('one effect marker written', 1, report.recognized_boarding.marker_count_delta);

section('missing, invalid, unknown, out-of-scope, and stale receipts do not board');
assertEqual('eleven refusal cases', 11, report.refusals.length);
for (const reason of REQUIRED_REFUSAL_REASONS) {
  assert(`required refusal reason present: ${reason}`, report.refusals.some((item) => item.reason_code === reason));
}
assert('all refusals do not board', report.refusals.every((item) => item.boarded === false));
assert('all refusals decide refuse', report.refusals.every((item) => item.decision === 'refuse'));
assert('all refusals write no effect marker', report.refusals.every((item) => item.marker_count_delta === 0));

section('effect marker remains bounded evidence');
assertEqual('only recognized marker exists', 1, report.marker.final_count);
assertEqual('marker contains bounded receipt id', true, report.marker.receipt_id_present);
assertEqual('marker omits raw record id', false, report.marker.raw_record_id_present);
assertEqual('marker omits public key', false, report.marker.public_key_present);

section('safe output formatting');
const summary = formatDownstreamRefusalProofSummary(report);
assert('summary title present', summary.includes('Downstream Refusal Proof v1'));
assert('summary includes evidence model', summary.includes('Evidence model: local-hermetic-fixture; live probing=false'));
assert('summary includes recognized boarding', summary.includes('- recognized: accept; marker_delta=1'));
for (const reason of REQUIRED_REFUSAL_REASONS) {
  assert(`summary includes refusal reason: ${reason}`, summary.includes(reason));
}
assert('summary states non-claim boundary', summary.includes('does not inspect live downstream systems'));
assert('summary output is privacy safe', assertNoUnsafeDownstreamRefusalProofText(summary));

const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeDownstreamRefusalProofText(jsonText));
assert('json omits raw record id', !jsonText.includes('fixture-record-001'));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertDownstreamRefusalProof(liveProbeClaim), 'must not perform live probing');

const boardedRefusal = structuredClone(report);
boardedRefusal.refusals[0].boarded = true;
assertThrows('boarding refusal fails', () => assertDownstreamRefusalProof(boardedRefusal), 'boarded unexpectedly');

const missingReason = structuredClone(report);
missingReason.refusals = missingReason.refusals.filter((item) => item.reason_code !== 'receipt_stale');
assertThrows('missing required refusal reason fails', () => assertDownstreamRefusalProof(missingReason), 'receipt_stale');

const missingUnknownIssuer = structuredClone(report);
missingUnknownIssuer.refusals = missingUnknownIssuer.refusals.filter((item) => item.reason_code !== 'unknown_issuer');
assertThrows('missing unknown issuer reason fails', () => assertDownstreamRefusalProof(missingUnknownIssuer), 'unknown_issuer');

const missingOutOfScope = structuredClone(report);
missingOutOfScope.refusals = missingOutOfScope.refusals.filter((item) => item.reason_code !== 'domain_out_of_scope');
assertThrows('missing out-of-scope reason fails', () => assertDownstreamRefusalProof(missingOutOfScope), 'domain_out_of_scope');

const leakedMarker = structuredClone(report);
leakedMarker.marker.raw_record_id_present = true;
assertThrows('raw marker leakage fails', () => assertDownstreamRefusalProof(leakedMarker), 'raw record id');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
