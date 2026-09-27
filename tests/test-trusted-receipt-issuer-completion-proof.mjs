#!/usr/bin/env node

import {
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE,
  assertTrustedReceiptIssuerCompletionProof,
  buildTrustedReceiptIssuerCompletionProofTestVector,
  buildTrustedReceiptIssuerCompletionVerification,
  formatTrustedReceiptIssuerCompletionVerification,
  trustedReceiptIssuerCompletionProofBodySha256,
} from '../lib/trusted-receipt-issuer-completion-proof.mjs';

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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const proof = buildTrustedReceiptIssuerCompletionProofTestVector();
const oneTerminalProof = buildTrustedReceiptIssuerCompletionProofTestVector({
  selected_surface_id: TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
});

section('valid proof contract');
assert('valid proof passes validation', assertTrustedReceiptIssuerCompletionProof(proof));
assertEqual('proof type', TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE, proof.proof_type);
assertEqual('selected surface', TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID, proof.selected_surface_id);
assertEqual('core sentence', TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE, proof.core_sentence);
assertEqual('receipt validity is not human intention', false, proof.claim_boundary.receipt_validity_is_human_intention);
assertEqual('issuer recognition is not human yes', false, proof.claim_boundary.issuer_recognition_is_human_yes);
assertEqual('authority event is not legal consent', false, proof.claim_boundary.authority_event_is_legal_consent);
assertEqual('operator registry is not customer production trust', false, proof.claim_boundary.operator_registry_is_customer_production_trust);
assertEqual('software custody is not hardware custody', false, proof.claim_boundary.software_custody_is_hardware_backed);
assertEqual('revocation status is not global certainty', false, proof.claim_boundary.revocation_status_is_global_certainty);

const verification = buildTrustedReceiptIssuerCompletionVerification(proof);
assertEqual('verification type', TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification verified', true, verification.verified);
assertEqual('verification proof sha', trustedReceiptIssuerCompletionProofBodySha256(proof), verification.proof_sha256);
assertEqual('verification completion selected surface', true, verification.completed_for_selected_surface);
assertEqual('verification summary-only false', false, verification.summary_only_evidence_accepted);
assertEqual('verification fixture-only false', false, verification.fixture_only_evidence_accepted);
assertEqual('verification overclaim false', false, verification.overclaim_flags_accepted);

assert(
  'one-terminal surface proof passes validation',
  assertTrustedReceiptIssuerCompletionProof(oneTerminalProof)
);
const oneTerminalVerification = buildTrustedReceiptIssuerCompletionVerification(oneTerminalProof);
assertEqual(
  'one-terminal proof names private-operator terminal surface',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  oneTerminalProof.selected_surface_id,
);
assertEqual(
  'one-terminal recognition contract names same surface',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  oneTerminalProof.recognition_contract_identity.surface_id,
);
assertEqual(
  'one-terminal verification preserves selected surface',
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  oneTerminalVerification.selected_surface_id,
);

const summary = formatTrustedReceiptIssuerCompletionVerification(verification);
assert('summary names recognized authority event', summary.includes('recognized_authority_event'));
assert('summary carries core sentence', summary.includes(TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE));
assert('summary names local contract boundary', summary.includes('local recognized-authority-event contract only'));
assert('summary forbids human intention claim', summary.includes('absolute human intention'));
assert('summary forbids legal consent claim', summary.includes('legal consent'));

section('fail closed overclaim and drift');
const wrongSurface = clone(proof);
wrongSurface.selected_surface_id = 'protected-records.service-profile.records.write';
assertThrows('wrong surface fails', () => assertTrustedReceiptIssuerCompletionProof(wrongSurface), 'selected surface');

const mismatchedRecognitionSurface = clone(oneTerminalProof);
mismatchedRecognitionSurface.recognition_contract_identity.surface_id = TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID;
assertThrows(
  'mismatched one-terminal recognition surface fails',
  () => assertTrustedReceiptIssuerCompletionProof(mismatchedRecognitionSurface),
  'recognition contract surface',
);

const receiptAsIntention = clone(proof);
receiptAsIntention.claim_boundary.receipt_validity_is_human_intention = true;
assertThrows('receipt validity into human intention fails', () => assertTrustedReceiptIssuerCompletionProof(receiptAsIntention), 'claim_boundary.receipt_validity_is_human_intention');

const issuerAsHumanYes = clone(proof);
issuerAsHumanYes.authority_event_contract.human_yes_claimed = true;
assertThrows('issuer recognition into human yes fails', () => assertTrustedReceiptIssuerCompletionProof(issuerAsHumanYes), 'human_yes_claimed');

const eventAsLegalConsent = clone(proof);
eventAsLegalConsent.authority_event_contract.legal_consent_claimed = true;
assertThrows('authority event into legal consent fails', () => assertTrustedReceiptIssuerCompletionProof(eventAsLegalConsent), 'legal_consent_claimed');

const productionTrust = clone(proof);
productionTrust.registry_identity.customer_production_trust = true;
assertThrows('operator registry into customer production trust fails', () => assertTrustedReceiptIssuerCompletionProof(productionTrust), 'customer_production_trust');

const hardwareClaim = clone(proof);
hardwareClaim.custody_posture_identity.hardware_backed_custody_claimed = true;
assertThrows('software custody into hardware custody fails', () => assertTrustedReceiptIssuerCompletionProof(hardwareClaim), 'hardware_backed_custody_claimed');

const globalRevocation = clone(proof);
globalRevocation.revocation_status_evidence_identity.global_revocation_certainty_claimed = true;
assertThrows('revocation into global certainty fails', () => assertTrustedReceiptIssuerCompletionProof(globalRevocation), 'global_revocation_certainty_claimed');

const collapsedAuthorized = clone(proof);
collapsedAuthorized.authority_event_contract.collapsed_authorized_category = true;
assertThrows('single authorized category fails', () => assertTrustedReceiptIssuerCompletionProof(collapsedAuthorized), 'collapsed_authorized_category');

const fixtureOnly = clone(proof);
fixtureOnly.claim_boundary.fixture_only_evidence = true;
assertThrows('fixture-only completion evidence fails', () => assertTrustedReceiptIssuerCompletionProof(fixtureOnly), 'claim_boundary.fixture_only_evidence');

const summaryOnly = clone(proof);
summaryOnly.command_posture.summary_only_evidence_accepted = true;
assertThrows('summary-only evidence fails', () => assertTrustedReceiptIssuerCompletionProof(summaryOnly), 'summary_only_evidence_accepted');

const overclaim = clone(proof);
overclaim.command_posture.overclaim_flags_accepted = true;
assertThrows('overclaim flags fail', () => assertTrustedReceiptIssuerCompletionProof(overclaim), 'overclaim_flags_accepted');

const v0Receipt = clone(proof);
v0Receipt.issuer_identity.receipt_format = 'v0';
assertThrows('v0 receipt identity fails completion', () => assertTrustedReceiptIssuerCompletionProof(v0Receipt), 'v1 receipt identity');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
