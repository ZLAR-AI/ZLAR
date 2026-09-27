#!/usr/bin/env node

import {
  LOCAL_BOARDING_NON_CLAIMS,
  LOCAL_BOARDING_SAFE_CLAIM_CEILING,
  PROTECTED_RECORDS_LOCAL_BOARDING_DESTINATION_CONTRACT_TYPE,
  PROTECTED_RECORDS_LOCAL_BOARDING_EVIDENCE_MODEL,
  PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE,
  PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_COMMAND_POSTURE,
  PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_CONTRACT_TYPE,
  PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE,
  REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES,
  assertNoUnsafeProtectedRecordsLocalBoardingProofText,
  assertProtectedRecordsLocalBoardingProof,
  formatProtectedRecordsLocalBoardingProofSummary,
  runProtectedRecordsLocalBoardingProof,
} from '../lib/protected-records-local-boarding-proof.mjs';

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

function caseById(report, caseId) {
  return report.case_summaries.find((item) => item.case_id === caseId);
}

section('protected records local boarding proof report');
const report = runProtectedRecordsLocalBoardingProof();
assert('valid report passes validation', assertProtectedRecordsLocalBoardingProof(report));
assertEqual('proof type', PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE, report.proof_type);
assertEqual('command', 'zlar protected-records-local-boarding-proof', report.command);
assert('source commit shape', report.source_commit === null || /^[a-f0-9]{40}$/.test(report.source_commit));
assertEqual('evidence model', PROTECTED_RECORDS_LOCAL_BOARDING_EVIDENCE_MODEL, report.evidence_model);
assertEqual('live probing false', false, report.live_probing);
assertEqual('action class', 'records.write', report.action_class);
assertEqual('safe claim ceiling exact', LOCAL_BOARDING_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('source state commit matches source commit', report.source_commit, report.source_state.commit);
assert('source state provenance named', ['clean-commit', 'commit-plus-uncommitted-worktree'].includes(report.source_state.provenance));
assertEqual('source state booleans oppose', report.source_state.worktree_clean, !report.source_state.uncommitted_changes);

section('destination contract');
assertEqual('destination contract type', PROTECTED_RECORDS_LOCAL_BOARDING_DESTINATION_CONTRACT_TYPE, report.destination_contract.contract_type);
assertEqual('destination replay scope', PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE, report.destination_contract.destination_scope);
assertEqual('destination route', 'receipt-recognition-before-local-proof-effect', report.destination_contract.mutation_authoritative_route);
assertEqual('destination effect model', 'in-memory-bounded-proof-effect', report.destination_contract.effect_model);
assertEqual('no live records system', false, report.destination_contract.live_records_system);
assertEqual('no persistent store write', false, report.destination_contract.persistent_store_written);
assertEqual('no current-machine governance', false, report.destination_contract.current_machine_governance_proven);

section('recognition and replay contract');
assertEqual('recognition contract type', 'downstream-recognition-rule-v1', report.recognition_contract.contract_type);
assertEqual('active issuer required', true, report.recognition_contract.recognized_receipt_requires_active_issuer);
assertEqual('signature valid required', true, report.recognition_contract.recognized_receipt_requires_signature_valid);
assertEqual('detail hash match required', true, report.recognition_contract.recognized_receipt_requires_detail_hash_match);
assertEqual('recognition rule binds policy/domain/tool/outcome/audit/freshness', true, report.recognition_contract.recognized_receipt_rule_binds_policy_domain_tool_outcome_audit_freshness);
assertEqual('extra policy/domain/tool/outcome/audit/freshness refusal cases not claimed', false, report.recognition_contract.policy_domain_tool_outcome_audit_freshness_refusal_cases_proven);
assertEqual('policy/domain/tool/detail/freshness refusal cases proven', true, report.recognition_contract.policy_domain_tool_detail_freshness_refusal_cases_proven);
assertEqual('v1 identity contract required', true, report.recognition_contract.recognized_receipt_requires_v1_identity_contract);
assertEqual('legacy v0 refusal proven', true, report.recognition_contract.legacy_v0_unsupported_refusal_case_proven);
assertEqual('legacy v0 not recognized as boarding identity', false, report.recognition_contract.legacy_v0_receipts_recognized_as_boarding_identity);
assertEqual('three proven scope mismatch refusals', 3, report.recognition_contract.proven_scope_mismatch_refusal_reason_codes.length);
assertEqual('proven scope mismatch refusal domain', 'domain_out_of_scope', report.recognition_contract.proven_scope_mismatch_refusal_reason_codes[0]);
assertEqual('proven scope mismatch refusal tool', 'tool_out_of_scope', report.recognition_contract.proven_scope_mismatch_refusal_reason_codes[1]);
assertEqual('proven scope mismatch refusal detail hash', 'detail_hash_mismatch', report.recognition_contract.proven_scope_mismatch_refusal_reason_codes[2]);
assertEqual('proven refusal code count', REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES.filter((item) => item.expected_decision === 'refuse').length, report.recognition_contract.proven_refusal_reason_codes.length);
assertEqual('current implementation fixture only', true, report.recognition_contract.current_implementation_fixture_recognition_only);
assertEqual('full receipt v1 conformance not claimed', false, report.recognition_contract.full_receipt_v1_conformance_claimed);
assertEqual('replay cache model', 'in-memory-single-run', report.replay_contract.cache_model);
assertEqual('replay scope', PROTECTED_RECORDS_LOCAL_BOARDING_REPLAY_SCOPE, report.replay_contract.scope);
assertEqual('durable replay store false', false, report.replay_contract.durable_replay_store);
assertEqual('exactly once production effects false', false, report.replay_contract.exactly_once_production_effects);
assertEqual('replay cache final size', 1, report.replay_contract.replay_cache_final_size);
assert('fixture contract hash shape', /^[a-f0-9]{64}$/.test(report.fixture_contract_sha256));

section('receipt identity contract');
assertEqual('receipt identity contract type', PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_CONTRACT_TYPE, report.receipt_identity_contract.contract_type);
assertEqual('receipt identity evidence model', 'local-fixture-v1-receipt-identity', report.receipt_identity_contract.evidence_model);
assertEqual('receipt identity command posture', PROTECTED_RECORDS_LOCAL_BOARDING_RECEIPT_IDENTITY_COMMAND_POSTURE, report.receipt_identity_contract.command_posture);
assertEqual('receipt identity format', 'v1', report.receipt_identity_contract.recognized_receipt_format);
assert('receipt identity receipt sha shape', /^[a-f0-9]{64}$/.test(report.receipt_identity_contract.canonical_signed_receipt_object_sha256));
assert('receipt identity pubkey sha shape', /^[a-f0-9]{64}$/.test(report.receipt_identity_contract.provided_pubkey_sha256));
assert('receipt identity receipt id hash shape', /^[a-f0-9]{64}$/.test(report.receipt_identity_contract.receipt_id_hash));
assert('receipt identity kid hash shape', /^[a-f0-9]{64}$/.test(report.receipt_identity_contract.kid_hash));
assertEqual('receipt id matched', true, report.receipt_identity_contract.required_receipt_id_matched);
assertEqual('receipt sha matched', true, report.receipt_identity_contract.required_receipt_sha256_matched);
assertEqual('kid matched', true, report.receipt_identity_contract.required_kid_matched);
assertEqual('pubkey sha matched', true, report.receipt_identity_contract.required_pubkey_sha256_matched);
assertEqual('format matched', true, report.receipt_identity_contract.required_format_matched);
assertEqual('v1 only matched', true, report.receipt_identity_contract.required_v1_only_matched);
assertEqual('receipt identity no v0 boarding', false, report.receipt_identity_contract.legacy_v0_recognized_boarding_identity);
assertEqual('receipt identity no issuer liveness truth', false, report.receipt_identity_contract.issuer_liveness_truth_proven);
assertEqual('receipt identity no key custody', false, report.receipt_identity_contract.key_custody_proven);
assertEqual('receipt identity no revocation truth', false, report.receipt_identity_contract.revocation_truth_proven);
assertEqual('receipt identity no production downstream', false, report.receipt_identity_contract.production_downstream_recognition_proven);

section('required cases');
assertEqual('case count', REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES.length, report.case_summaries.length);
for (const expected of REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES) {
  const item = caseById(report, expected.case_id);
  assert(`case present: ${expected.case_id}`, Boolean(item));
  assertEqual(`receipt class: ${expected.case_id}`, expected.receipt_class, item.receipt_class);
  assertEqual(`expected reason: ${expected.case_id}`, expected.expected_reason_code, item.expected_reason_code);
  assertEqual(`observed reason: ${expected.case_id}`, expected.expected_reason_code, item.observed_reason_code);
  assertEqual(`expected decision: ${expected.case_id}`, expected.expected_decision, item.expected_decision);
  assertEqual(`observed decision: ${expected.case_id}`, expected.expected_decision, item.decision);
  assertEqual(`effect delta: ${expected.case_id}`, expected.expected_effect_delta, item.effect_count_delta);
  if (expected.expected_decision === 'refuse') {
    assertEqual(`refused before effect: ${expected.case_id}`, true, item.refused_before_effect);
  }
}

assertEqual('no receipt reason', 'receipt_missing', caseById(report, 'no_receipt_refused').observed_reason_code);
assertEqual('invalid receipt reason', 'receipt_invalid', caseById(report, 'invalid_receipt_refused').observed_reason_code);
assertEqual('unknown issuer reason', 'unknown_issuer', caseById(report, 'unknown_issuer_refused').observed_reason_code);
assertEqual('inactive issuer reason', 'issuer_not_active', caseById(report, 'inactive_issuer_refused').observed_reason_code);
assertEqual('wrong destination reason', 'domain_out_of_scope', caseById(report, 'wrong_destination_refused').observed_reason_code);
assertEqual('wrong action reason', 'tool_out_of_scope', caseById(report, 'wrong_action_refused').observed_reason_code);
assertEqual('wrong policy reason', 'policy_not_recognized', caseById(report, 'wrong_policy_refused').observed_reason_code);
assertEqual('stale receipt reason', 'receipt_stale', caseById(report, 'stale_receipt_refused').observed_reason_code);
assertEqual('wrong detail reason', 'detail_hash_mismatch', caseById(report, 'wrong_detail_refused').observed_reason_code);
assertEqual('legacy v0 reason', 'unsupported_receipt_format', caseById(report, 'legacy_v0_unsupported_refused').observed_reason_code);

section('accepted once and replay refusal');
const recognized = caseById(report, 'recognized_receipt_accepted_once');
assertEqual('recognized accepted', 'accept', recognized.decision);
assertEqual('recognized marker true', true, recognized.accepted_once_marker);
assertEqual('recognized starts at zero effects', 0, recognized.effect_count_before);
assertEqual('recognized ends at one effect', 1, recognized.effect_count_after);
assertEqual('recognized delta one', 1, recognized.effect_count_delta);
assertEqual('recognized receipt recognized', true, recognized.recognized);

const replay = caseById(report, 'replay_refused');
assertEqual('replay refused', 'refuse', replay.decision);
assertEqual('replay reason', 'receipt_replay', replay.observed_reason_code);
assertEqual('replay starts after accepted effect', 1, replay.effect_count_before);
assertEqual('replay final effect count unchanged', 1, replay.effect_count_after);
assertEqual('replay delta zero', 0, replay.effect_count_delta);
assertEqual('replay refused before effect', true, replay.refused_before_effect);
assertEqual('replay recognition flag false', false, replay.recognized);

section('effect and summary');
assertEqual('one effect emitted', 1, report.effects.length);
assertEqual('effect type', 'protected-records-local-boarding-effect-v1', report.effects[0].effect_type);
assertEqual('effect action class', 'records.write', report.effects[0].action_class);
assertEqual('effect transition', 'recognized_receipt_boarded', report.effects[0].transition);
assert('effect detail hash shape', /^[a-f0-9]{64}$/.test(report.effects[0].detail_hash));
assert('effect receipt hash shape', /^[a-f0-9]{64}$/.test(report.effects[0].receipt_id_hash));
assertEqual('summary cases present', true, report.summary.all_required_cases_present);
assertEqual('summary reason codes match', true, report.summary.all_expected_reason_codes_match);
assertEqual('summary refusals before effect', true, report.summary.all_refusals_before_effect);
assertEqual('summary refusal deltas zero', true, report.summary.all_refusal_effect_deltas_zero);
assertEqual('summary consequence absent on every refusal', true, report.summary.consequence_absent_on_every_refusal);
assertEqual('summary consequence present exactly once', true, report.summary.consequence_present_exactly_once_on_acceptance);
assertEqual('summary v1 receipt identity verified', true, report.summary.v1_receipt_identity_verified);
assertEqual('summary legacy v0 not recognized', false, report.summary.legacy_v0_recognized_boarding_identity);
assertEqual('summary recognized accepted once', true, report.summary.recognized_receipt_accepted_once);
assertEqual('summary recognized delta one', true, report.summary.recognized_effect_delta_is_one);
assertEqual('summary replay refused', true, report.summary.replay_refused_after_acceptance);
assertEqual('summary final effect count', 1, report.summary.final_effect_count);
assertEqual('summary current-machine governance false', false, report.summary.current_machine_governance_proven);
assertEqual('summary production downstream false', false, report.summary.production_downstream_recognition_proven);

section('non-claims and privacy');
assertEqual('non-claims exact count', LOCAL_BOARDING_NON_CLAIMS.length, report.non_claims.length);
for (const claim of LOCAL_BOARDING_NON_CLAIMS) {
  assert(`non-claim present: ${claim.slice(0, 42)}`, report.non_claims.includes(claim));
}
const jsonText = JSON.stringify(report, null, 2);
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsLocalBoardingProofText(jsonText));
assert('json omits raw record id', !jsonText.includes('local-boarding-fixture-record'));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(jsonText));

const summary = formatProtectedRecordsLocalBoardingProofSummary(report);
assert('summary title present', summary.includes('Protected Records Local Boarding Proof v1'));
assert('summary names source provenance', summary.includes(`provenance=${report.source_state.provenance}`));
assert('summary names in-memory fixture', summary.includes('Evidence model: local-in-memory-fixture'));
assert('summary names extra scope refusal boundary', summary.includes('extra_scope_refusals_proven=false'));
assert('summary names non-install boundary', summary.includes('not an install, not activation, not current-machine governance'));
for (const expected of REQUIRED_PROTECTED_RECORDS_LOCAL_BOARDING_CASES) {
  assert(`summary includes case ${expected.case_id}`, summary.includes(expected.case_id));
  assert(`summary includes reason ${expected.expected_reason_code}`, summary.includes(expected.expected_reason_code));
}
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsLocalBoardingProofText(summary));

section('fail closed validation');
const liveProbe = structuredClone(report);
liveProbe.live_probing = true;
assertThrows('live probing claim fails', () => assertProtectedRecordsLocalBoardingProof(liveProbe), 'top-level contract drifted');

const productionRecognition = structuredClone(report);
productionRecognition.summary.production_downstream_recognition_proven = true;
assertThrows('production downstream claim fails', () => assertProtectedRecordsLocalBoardingProof(productionRecognition), 'summary boundary drifted');

const currentMachine = structuredClone(report);
currentMachine.destination_contract.current_machine_governance_proven = true;
assertThrows('current-machine claim fails', () => assertProtectedRecordsLocalBoardingProof(currentMachine), 'destination contract drifted');

const missingCase = structuredClone(report);
missingCase.case_summaries = missingCase.case_summaries.filter((item) => item.case_id !== 'unknown_issuer_refused');
assertThrows('missing case fails', () => assertProtectedRecordsLocalBoardingProof(missingCase), 'case count drifted');

const mutatedRefusal = structuredClone(report);
mutatedRefusal.case_summaries[0].effect_count_delta = 1;
assertThrows('refusal mutation fails', () => assertProtectedRecordsLocalBoardingProof(mutatedRefusal), 'case no_receipt_refused drifted');

const changedReason = structuredClone(report);
changedReason.case_summaries[1].observed_reason_code = 'accepted_anyway';
assertThrows('reason code drift fails', () => assertProtectedRecordsLocalBoardingProof(changedReason), 'case invalid_receipt_refused drifted');

const replayAccepted = structuredClone(report);
replayAccepted.case_summaries.find((item) => item.case_id === 'replay_refused').effect_count_after = 2;
assertThrows('replay second effect fails', () => assertProtectedRecordsLocalBoardingProof(replayAccepted), 'replay was not refused');

const missingIdentity = structuredClone(report);
delete missingIdentity.receipt_identity_contract;
assertThrows('missing receipt identity contract fails', () => assertProtectedRecordsLocalBoardingProof(missingIdentity), 'unexpected fields');

const mismatchedIdentity = structuredClone(report);
mismatchedIdentity.receipt_identity_contract.required_receipt_sha256_matched = false;
assertThrows('receipt identity mismatch fails', () => assertProtectedRecordsLocalBoardingProof(mismatchedIdentity), 'receipt identity contract drifted');

const v0BoardingIdentity = structuredClone(report);
v0BoardingIdentity.receipt_identity_contract.legacy_v0_recognized_boarding_identity = true;
assertThrows('v0 boarding identity claim fails', () => assertProtectedRecordsLocalBoardingProof(v0BoardingIdentity), 'receipt identity contract drifted');

const missingConsequenceProof = structuredClone(report);
missingConsequenceProof.summary.consequence_absent_on_every_refusal = false;
assertThrows('refusal consequence absence claim fails', () => assertProtectedRecordsLocalBoardingProof(missingConsequenceProof), 'summary consequence_absent_on_every_refusal must be true');

const extraAcceptanceEffect = structuredClone(report);
extraAcceptanceEffect.summary.consequence_present_exactly_once_on_acceptance = false;
assertThrows('acceptance consequence count claim fails', () => assertProtectedRecordsLocalBoardingProof(extraAcceptanceEffect), 'summary consequence_present_exactly_once_on_acceptance must be true');

const summaryOnlyV0Claim = structuredClone(report);
summaryOnlyV0Claim.summary.legacy_v0_recognized_boarding_identity = true;
assertThrows('summary v0 boarding claim fails', () => assertProtectedRecordsLocalBoardingProof(summaryOnlyV0Claim), 'summary boundary drifted');

const conformanceClaim = structuredClone(report);
conformanceClaim.recognition_contract.full_receipt_v1_conformance_claimed = true;
assertThrows('full receipt conformance claim fails', () => assertProtectedRecordsLocalBoardingProof(conformanceClaim), 'recognition contract drifted');

const extraNonClaim = structuredClone(report);
extraNonClaim.non_claims = [...extraNonClaim.non_claims, 'extra claim'];
assertThrows('non-claim drift fails', () => assertProtectedRecordsLocalBoardingProof(extraNonClaim), 'non-claims drifted');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
