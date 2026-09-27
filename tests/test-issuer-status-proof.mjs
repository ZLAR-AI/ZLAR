#!/usr/bin/env node

import {
  ISSUER_STATUS_PROOF_TYPE,
  SAFE_CLAIM_CEILING,
  assertIssuerStatusProof,
  assertNoUnsafeIssuerStatusProofText,
  formatIssuerStatusProofSummary,
  runIssuerStatusProof,
} from '../lib/issuer-status-proof.mjs';

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

section('issuer status proof report');
const report = runIssuerStatusProof();
assert('valid report passes validation', assertIssuerStatusProof(report));
assertEqual('proof type', ISSUER_STATUS_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local hermetic fixture evidence', 'local-hermetic-fixture', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('trust anchor model', 'local-fixture-recognition-rule', report.trust_anchor_model);
assertEqual('action class', 'records.write', report.action_class);

section('active issuer boards');
assertEqual('active case id', 'active_issuer_recognized', report.active_issuer.case_id);
assertEqual('active receipt present', true, report.active_issuer.receipt_present);
assertEqual('active key id present', true, report.active_issuer.issuer_key_id_present);
assertEqual('active issuer known', true, report.active_issuer.issuer_known);
assertEqual('active status', 'active', report.active_issuer.issuer_status);
assertEqual('active signature valid', true, report.active_issuer.signature_valid);
assertEqual('active lifecycle recognized', true, report.active_issuer.issuer_lifecycle_status_recognized);
assertEqual('active downstream key recognized', true, report.active_issuer.issuer_public_key_recognized_for_downstream);
assertEqual('active downstream recognized', true, report.active_issuer.receipt_recognized_for_downstream);
assertEqual('active boards', true, report.active_issuer.boarded);
assertEqual('active decision accepts', 'accept', report.active_issuer.decision);
assertEqual('active reason recognized', 'recognized', report.active_issuer.reason_code);
assertEqual('active receipt id present', true, report.active_issuer.receipt_id_present);

section('retired issuer refuses');
assertEqual('retired case id', 'retired_issuer_refused', report.retired_issuer.case_id);
assertEqual('retired receipt present', true, report.retired_issuer.receipt_present);
assertEqual('retired key id present', true, report.retired_issuer.issuer_key_id_present);
assertEqual('retired issuer known', true, report.retired_issuer.issuer_known);
assertEqual('retired status', 'retired', report.retired_issuer.issuer_status);
assertEqual('retired signature valid diagnostically', true, report.retired_issuer.signature_valid);
assertEqual('retired lifecycle not recognized', false, report.retired_issuer.issuer_lifecycle_status_recognized);
assertEqual('retired downstream key not recognized', false, report.retired_issuer.issuer_public_key_recognized_for_downstream);
assertEqual('retired downstream not recognized', false, report.retired_issuer.receipt_recognized_for_downstream);
assertEqual('retired does not board', false, report.retired_issuer.boarded);
assertEqual('retired decision refuses', 'refuse', report.retired_issuer.decision);
assertEqual('retired reason inactive', 'issuer_not_active', report.retired_issuer.reason_code);

section('compromised issuer refuses');
assertEqual('compromised case id', 'compromised_issuer_refused', report.compromised_issuer.case_id);
assertEqual('compromised receipt present', true, report.compromised_issuer.receipt_present);
assertEqual('compromised key id present', true, report.compromised_issuer.issuer_key_id_present);
assertEqual('compromised issuer known', true, report.compromised_issuer.issuer_known);
assertEqual('compromised status', 'compromised', report.compromised_issuer.issuer_status);
assertEqual('compromised signature valid diagnostically', true, report.compromised_issuer.signature_valid);
assertEqual('compromised lifecycle not recognized', false, report.compromised_issuer.issuer_lifecycle_status_recognized);
assertEqual('compromised downstream key not recognized', false, report.compromised_issuer.issuer_public_key_recognized_for_downstream);
assertEqual('compromised downstream not recognized', false, report.compromised_issuer.receipt_recognized_for_downstream);
assertEqual('compromised does not board', false, report.compromised_issuer.boarded);
assertEqual('compromised decision refuses', 'refuse', report.compromised_issuer.decision);
assertEqual('compromised reason', 'issuer_compromised', report.compromised_issuer.reason_code);

section('missing status issuer refuses');
assertEqual('missing status case id', 'missing_status_issuer_refused', report.missing_status_issuer.case_id);
assertEqual('missing status receipt present', true, report.missing_status_issuer.receipt_present);
assertEqual('missing status key id present', true, report.missing_status_issuer.issuer_key_id_present);
assertEqual('missing status issuer known', true, report.missing_status_issuer.issuer_known);
assertEqual('missing status absent', null, report.missing_status_issuer.issuer_status);
assertEqual('missing status signature valid diagnostically', true, report.missing_status_issuer.signature_valid);
assertEqual('missing status lifecycle not recognized', false, report.missing_status_issuer.issuer_lifecycle_status_recognized);
assertEqual('missing status downstream key not recognized', false, report.missing_status_issuer.issuer_public_key_recognized_for_downstream);
assertEqual('missing status downstream not recognized', false, report.missing_status_issuer.receipt_recognized_for_downstream);
assertEqual('missing status does not board', false, report.missing_status_issuer.boarded);
assertEqual('missing status decision refuses', 'refuse', report.missing_status_issuer.decision);
assertEqual('missing status reason', 'issuer_status_missing', report.missing_status_issuer.reason_code);

section('unknown issuer refuses');
assertEqual('unknown case id', 'unknown_issuer_refused', report.unknown_issuer.case_id);
assertEqual('unknown receipt present', true, report.unknown_issuer.receipt_present);
assertEqual('unknown key id present', true, report.unknown_issuer.issuer_key_id_present);
assertEqual('unknown issuer not known', false, report.unknown_issuer.issuer_known);
assertEqual('unknown status absent', null, report.unknown_issuer.issuer_status);
assertEqual('unknown signature valid diagnostically', true, report.unknown_issuer.signature_valid);
assertEqual('unknown lifecycle not recognized', false, report.unknown_issuer.issuer_lifecycle_status_recognized);
assertEqual('unknown downstream key not recognized', false, report.unknown_issuer.issuer_public_key_recognized_for_downstream);
assertEqual('unknown downstream not recognized', false, report.unknown_issuer.receipt_recognized_for_downstream);
assertEqual('unknown does not board', false, report.unknown_issuer.boarded);
assertEqual('unknown decision refuses', 'refuse', report.unknown_issuer.decision);
assertEqual('unknown reason unknown issuer', 'unknown_issuer', report.unknown_issuer.reason_code);

section('missing key issuer refuses');
assertEqual('missing key case id', 'missing_key_issuer_refused', report.missing_key_issuer.case_id);
assertEqual('missing key receipt present', true, report.missing_key_issuer.receipt_present);
assertEqual('missing key id present', true, report.missing_key_issuer.issuer_key_id_present);
assertEqual('missing key issuer known', true, report.missing_key_issuer.issuer_known);
assertEqual('missing key status active', 'active', report.missing_key_issuer.issuer_status);
assertEqual('missing key signature valid diagnostically', true, report.missing_key_issuer.signature_valid);
assertEqual('missing key lifecycle recognized', true, report.missing_key_issuer.issuer_lifecycle_status_recognized);
assertEqual('missing key downstream key not recognized', false, report.missing_key_issuer.issuer_public_key_recognized_for_downstream);
assertEqual('missing key downstream not recognized', false, report.missing_key_issuer.receipt_recognized_for_downstream);
assertEqual('missing key does not board', false, report.missing_key_issuer.boarded);
assertEqual('missing key decision refuses', 'refuse', report.missing_key_issuer.decision);
assertEqual('missing key reason', 'issuer_key_missing', report.missing_key_issuer.reason_code);

section('safe output formatting');
const summary = formatIssuerStatusProofSummary(report);
assert('summary title present', summary.includes('Issuer Status Proof v1'));
assert('summary names fixture trust anchor', summary.includes('Trust anchor model: local-fixture-recognition-rule'));
assert('summary includes active recognition', summary.includes('active_issuer_recognized: accept'));
assert('summary includes retired refusal', summary.includes('retired_issuer_refused: refuse; reason=issuer_not_active'));
assert('summary includes compromised refusal', summary.includes('compromised_issuer_refused: refuse; reason=issuer_compromised'));
assert('summary includes missing status refusal', summary.includes('missing_status_issuer_refused: refuse; reason=issuer_status_missing'));
assert('summary includes unknown refusal', summary.includes('unknown_issuer_refused: refuse; reason=unknown_issuer'));
assert('summary includes missing key refusal', summary.includes('missing_key_issuer_refused: refuse; reason=issuer_key_missing'));
assert('summary names recognition split', summary.includes('signature_valid is distinct from issuer_lifecycle_status_recognized'));
assert('summary names downstream key split', summary.includes('issuer_public_key_recognized_for_downstream'));
assert('summary states production key non-claim', summary.includes('not live or production signing authority'));
assert('summary output is privacy safe', assertNoUnsafeIssuerStatusProofText(summary));

const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeIssuerStatusProofText(jsonText));
assert('json omits raw fixture record', !jsonText.includes('issuer-status-fixture-record'));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

section('fail closed validation');
const liveProbeClaim = structuredClone(report);
liveProbeClaim.live_probing = true;
assertThrows('live probing claim fails', () => assertIssuerStatusProof(liveProbeClaim), 'must not perform live probing');

const brokenTrustAnchor = structuredClone(report);
brokenTrustAnchor.trust_anchor_model = 'live-registry';
assertThrows('live trust anchor claim fails', () => assertIssuerStatusProof(brokenTrustAnchor), 'trust anchor model');

const brokenActive = structuredClone(report);
brokenActive.active_issuer.boarded = false;
assertThrows('active issuer refusal fails', () => assertIssuerStatusProof(brokenActive), 'Active issuer');

const brokenRetired = structuredClone(report);
brokenRetired.retired_issuer.boarded = true;
assertThrows('retired issuer boarding fails', () => assertIssuerStatusProof(brokenRetired), 'Retired issuer');

const brokenRetiredSignature = structuredClone(report);
brokenRetiredSignature.retired_issuer.signature_valid = null;
assertThrows('retired diagnostic signature drift fails', () => assertIssuerStatusProof(brokenRetiredSignature), 'Retired issuer');

const brokenCompromised = structuredClone(report);
brokenCompromised.compromised_issuer.reason_code = 'issuer_not_active';
assertThrows('compromised issuer generic inactive drift fails', () => assertIssuerStatusProof(brokenCompromised), 'Compromised issuer');

const brokenCompromisedSignature = structuredClone(report);
brokenCompromisedSignature.compromised_issuer.signature_valid = null;
assertThrows('compromised diagnostic signature drift fails', () => assertIssuerStatusProof(brokenCompromisedSignature), 'Compromised issuer');

const brokenMissingStatus = structuredClone(report);
brokenMissingStatus.missing_status_issuer.reason_code = 'recognized';
assertThrows('missing status reason drift fails', () => assertIssuerStatusProof(brokenMissingStatus), 'Missing-status issuer');

const brokenMissingStatusLifecycle = structuredClone(report);
brokenMissingStatusLifecycle.missing_status_issuer.issuer_lifecycle_status_recognized = true;
assertThrows('missing status lifecycle drift fails', () => assertIssuerStatusProof(brokenMissingStatusLifecycle), 'Missing-status issuer');

const brokenUnknown = structuredClone(report);
brokenUnknown.unknown_issuer.issuer_known = true;
assertThrows('unknown issuer known fails', () => assertIssuerStatusProof(brokenUnknown), 'Unknown issuer');

const brokenUnknownDownstream = structuredClone(report);
brokenUnknownDownstream.unknown_issuer.receipt_recognized_for_downstream = true;
assertThrows('unknown downstream recognition drift fails', () => assertIssuerStatusProof(brokenUnknownDownstream), 'Unknown issuer');

const brokenMissingKey = structuredClone(report);
brokenMissingKey.missing_key_issuer.reason_code = 'recognized';
assertThrows('missing key reason drift fails', () => assertIssuerStatusProof(brokenMissingKey), 'Missing-key issuer');

const brokenMissingKeyPublicKey = structuredClone(report);
brokenMissingKeyPublicKey.missing_key_issuer.issuer_public_key_recognized_for_downstream = true;
assertThrows('missing key public key recognition drift fails', () => assertIssuerStatusProof(brokenMissingKeyPublicKey), 'Missing-key issuer');

const leakedPublicKey = structuredClone(report);
leakedPublicKey.issuer_boundary.raw_public_key_material_included = true;
assertThrows('public key material boundary fails', () => assertIssuerStatusProof(leakedPublicKey), 'Issuer status boundary');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
