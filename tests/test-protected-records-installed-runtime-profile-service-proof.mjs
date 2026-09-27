#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { canonicalize } from '../lib/canonicalize.mjs';
import { sha256hex } from '../lib/receipt.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
  parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS,
  INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAFE_CLAIM_CEILING,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
  assertProtectedRecordsInstalledRuntimeProfileServiceProof,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification,
  buildProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
  formatProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification,
  formatProtectedRecordsInstalledRuntimeProfileServiceProofSummary,
  parseProtectedRecordsInstalledRuntimeProfileServiceProofArtifactText,
  protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256,
  runProtectedRecordsInstalledRuntimeProfileServiceProof,
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  PROTECTED_RECORDS_CONSEQUENCE_PATH,
  PROTECTED_RECORDS_TARGET_HANDLE,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL += 1;
  if (condition) {
    PASS += 1;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL += 1;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, fragment = '') {
  TOTAL += 1;
  try {
    fn();
    FAIL += 1;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!fragment || String(err.message).includes(fragment)) {
      PASS += 1;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL += 1;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function resealArtifact(artifact) {
  const { integrity, ...body } = artifact;
  artifact.integrity.body_sha256 = sha256hex(canonicalize(body));
  return artifact;
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const input = parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText(
  readFileSync('tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json', 'utf8')
);

section('fresh fixture rightful-issuance service proof');
const report = runProtectedRecordsInstalledRuntimeProfileServiceProof(input);
assert('report validates', assertProtectedRecordsInstalledRuntimeProfileServiceProof(report));
assertEqual('proof type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_TYPE, report.proof_type);
assertEqual('safe claim exact', INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('fixture consequence exact', PROTECTED_RECORDS_CONSEQUENCE_PATH, report.target_binding.consequence_path);
assertEqual('fixture target exact', PROTECTED_RECORDS_TARGET_HANDLE, report.target_binding.target_handle);
assertEqual('source remains read only', true, report.source_preflight.read_only);
assertEqual('source generic rightful issuance false', false, report.source_preflight.rightful_issuance_proven);
assertEqual('source lifecycle closed false', false, report.source_preflight.consequence_lifecycle_closed);

section('positive issuance and effect are ordered and hash-bound');
const order = report.authority_contract.construction_order;
assertEqual('ten construction stages', 10, order.length);
assertEqual('launcher scope first', 'launcher_scope_evidence', order[0]);
assertEqual('grant contract before appointment', 'authority_grant_contract', order[1]);
assertEqual('appointment before authorized effect', 'issuer_appointment', order[2]);
assertEqual('unsigned receipt before issuance decision', 'unsigned_receipt', order[4]);
assertEqual('issuance decision before signing', 'accepted_issuance_decision', order[5]);
assertEqual('signature after issuance decision', 'receipt_signature', order[6]);
assertEqual('effect gate before consumption', 'recognized_effect_gate', order[7]);
assertEqual('consumption before mutation', 'authority_grant_consumption', order[8]);
assertEqual('state append last', 'runtime_state_append', order[9]);
const summary = report.authority_contract.public_safe_grant_summary;
assertEqual('public summary type', 'zlar-protected-records-fixture-authority-grant-summary-v1', summary.summary_type);
assertEqual('fixture domain exact', 'protected-records.local-disposable-fixture', summary.authority_domain_id);
assertEqual('grantor role exact', 'fixture-consequence-authority', summary.grantor_role_id);
assertEqual('fixture rightful path evidenced', true, summary.fixture_rightful_issuance_path_evidenced);
assertEqual('generic rightful issuance false', false, summary.rightful_issuance_proven);
assertEqual('portable rightful issuance false', false, summary.portable_rightful_issuance_proven);
assertEqual('production rightful issuance false', false, summary.production_rightful_issuance_proven);
assertEqual('private issuer identity not disclosed', false, summary.runtime_private_issuer_identity_disclosed);
assertEqual('private appointment not disclosed', false, summary.runtime_private_grant_appointment_disclosed);
const transition = report.accepted_runtime_transition_binding;
assertEqual('ordered transition type', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', transition.binding_type);
assertEqual('one launcher lock held', true, transition.one_launcher_store_lock_held_across_transition);
assert('replay check precedes effect gate', transition.signed_payload_replay_check_sequence < transition.effect_gate_sequence);
assert('effect gate precedes grant store', transition.effect_gate_sequence < transition.grant_store_commit_sequence);
assert('grant store precedes state append', transition.grant_store_commit_sequence < transition.state_append_sequence);
assert('state append precedes helper promotion', transition.state_append_sequence < transition.helper_state_promotion_sequence);
assertEqual('transition grant matches public summary', summary.authority_grant_contract_sha256, transition.authority_grant_contract_sha256);
assertEqual('receipt binds authorized effect detail', true, report.target_binding.receipt_binds_authorized_effect_detail);
assertEqual('target effect nested inside authorized detail', true, report.target_binding.target_effect_bound_inside_authorized_effect_detail);
assert('target effect differs from receipt detail', report.target_binding.target_effect_sha256 !== report.target_binding.receipt_detail_sha256);
assertEqual('recognized write accepted', true, report.recognized_boarding.service_write_accepted);
assertEqual('recognized write appends one', 1, report.recognized_boarding.state_entry_count_delta);
assertEqual('recognized grant satisfied', true, report.recognized_boarding.authority_grant_satisfied);

section('recognition and authority refusal taxonomies remain separate');
assertEqual('recognition refusal count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.refusal_cases.length);
assertEqual('recognition refusal order exact', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES), JSON.stringify(report.refusal_cases.map((item) => item.case_id)));
assert('all recognition refusals mutate zero state', report.refusal_cases.every((item) => item.service_write_accepted === false && item.state_entry_count_delta === 0));
assertEqual('authority refusal count', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.authority_refusal_cases.length);
assertEqual('authority refusal order exact', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES), JSON.stringify(report.authority_refusal_cases.map((item) => item.case_id)));
assert('all authority refusals precede consumption', report.authority_refusal_cases.every((item) => item.service_write_accepted === false && item.state_entry_count_delta === 0 && item.consumed_authority_grant_count === 0));
assertEqual('missing grant reason', 'authority_grant_missing', report.authority_refusal_cases[0].reason_code);
assertEqual('mismatch grant reason', 'authority_grant_contract_mismatch', report.authority_refusal_cases[1].reason_code);
assertEqual('expired grant reason', 'authority_grant_expired', report.authority_refusal_cases[2].reason_code);
assertEqual('revoked grant reason', 'authority_grant_revoked', report.authority_refusal_cases[3].reason_code);
assertEqual('request supplied grant reason', 'agent_supplied_authority_material', report.authority_refusal_cases[4].reason_code);
assertEqual('taxonomies explicitly separate', true, report.service_boundary.recognition_refusal_taxonomy_separate && report.service_boundary.authority_refusal_taxonomy_separate);

section('replay identities and consequence side doors');
assertEqual('same-process replay uses signed payload identity', 'receipt_replay', report.service_replay_cases[0].reason_code);
assertEqual('restart replay uses consumed grant identity', 'authority_grant_already_consumed', report.service_replay_cases[1].reason_code);
assert('replays mutate zero state', report.service_replay_cases.every((item) => item.state_entry_count_delta === 0));
assertEqual('state append failure after grant commit named', 'runtime_state_append_failed_after_consumed_store_commit', report.partial_commit_cases[0].reason_code);
assertEqual('state append failure burned grant', 1, report.partial_commit_cases[0].consumed_authority_grant_count);
assertEqual('witness partial commit named', 'consumed_store_write_failed_after_grant_commit', report.partial_commit_cases[1].reason_code);
assertEqual('witness partial commit burned grant', 1, report.partial_commit_cases[1].consumed_authority_grant_count);
assertEqual('partial commits append no state', 0, report.marker.partial_commit_state_append_count);
assertEqual('store plus anchor rollback refused while witness ahead', 'consumed_store_rollback_detected', report.joint_rollback_case.store_and_anchor_only.reason_code);
assertEqual('three-file joint rollback reopens reuse', true, report.joint_rollback_case.store_anchor_and_witness.service_write_accepted);
assertEqual('three-file joint rollback detection false', false, report.proof_boundary.store_anchor_and_witness_joint_rollback_detection);
assertEqual('joint rollback side door explicitly observed', true, report.proof_boundary.joint_rollback_reopened_authority_grant_reuse);
assertEqual('fixture total appends truthful', 4, report.marker.total_fixture_state_append_count);

section('claim ceiling and privacy');
assertEqual('fixture path true', true, report.proof_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('generic rightful false', false, report.proof_boundary.rightful_issuance_proven);
assertEqual('portable rightful false', false, report.proof_boundary.portable_rightful_issuance_proven);
assertEqual('production rightful false', false, report.proof_boundary.production_rightful_issuance_proven);
assertEqual('current machine false', false, report.proof_boundary.current_machine_governance_proven);
assertEqual('lifecycle closure false', false, report.proof_boundary.consequence_lifecycle_closed);
assertEqual('non-claims exact', JSON.stringify(INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS), JSON.stringify(report.non_claims));
assertEqual('raw receipt id absent', false, report.marker.raw_receipt_id_present);
assertEqual('runtime issuer material absent', false, report.marker.runtime_private_issuer_material_present);
assert('report privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report)));
assert('public summary carries no PEM', !JSON.stringify(summary).includes('BEGIN'));
assert('public summary carries no appointment object', !Object.hasOwn(summary, 'authority_grant_appointment'));

section('determinism, artifact, and verifier');
const repeat = runProtectedRecordsInstalledRuntimeProfileServiceProof(input);
assert('second fresh report validates', assertProtectedRecordsInstalledRuntimeProfileServiceProof(repeat));
assertEqual('grant contract identity is deterministic', summary.authority_grant_contract_sha256, repeat.authority_contract.public_safe_grant_summary.authority_grant_contract_sha256);
assert('ephemeral issuer keeps crossing identity run-local', transition.authority_grant_crossing_binding_sha256 !== repeat.accepted_runtime_transition_binding.authority_grant_crossing_binding_sha256);
const artifact = buildProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(report);
assert('artifact validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact));
assertEqual('artifact type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_TYPE, artifact.artifact_type);
assertEqual('artifact body helper exact', artifact.integrity.body_sha256, protectedRecordsInstalledRuntimeProfileServiceProofArtifactBodySha256(report));
const parsed = parseProtectedRecordsInstalledRuntimeProfileServiceProofArtifactText(JSON.stringify(artifact));
assertEqual('parsed artifact hash exact', artifact.integrity.body_sha256, parsed.integrity.body_sha256);
const verification = verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
assert('verification validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(verification));
assertEqual('verification type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification fixture path false without expected artifact identity', false, verification.fixture_rightful_issuance_path_evidenced);
assertEqual('verification generic rightful false', false, verification.rightful_issuance_proven);
assertEqual('verification recognition refusals 18', 18, verification.recognition_refusal_case_count);
assertEqual('verification authority refusals 5', 5, verification.authority_refusal_case_count);
assertEqual('verification ordered binding exact', transition.binding_type, verification.ordered_transition_binding_type);
assertEqual('verification structural self-integrity true', true, verification.structural_self_integrity_verified);
assertEqual('verification identity needs expected sha', true, verification.artifact_identity_match_requires_expected_sha256);
assertEqual('verification scope is structural only', 'structural-self-integrity-only', verification.verification_scope);
assertEqual('verification artifact identity unmatched without pin', false, verification.artifact_identity_sha256_matched);
assertEqual('verification source identity not bound without pin', false, verification.source_preflight_identity_bound_to_expected_artifact_sha256);
assertEqual('verification signed envelope identity not bound without pin', false, verification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256);
assertEqual('verification recognized boarding false without pin', false, verification.recognized_write_boarded);
const pinnedVerification = verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
  artifact,
  { expectedArtifactBodySha256: artifact.integrity.body_sha256 }
);
assert('pinned verification validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(pinnedVerification));
assertEqual('pinned artifact identity matched', true, pinnedVerification.artifact_identity_sha256_matched);
assertEqual('pinned source identity bound', true, pinnedVerification.source_preflight_identity_bound_to_expected_artifact_sha256);
assertEqual('pinned signed envelope identity bound', true, pinnedVerification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256);
assertEqual('pinned fixture path true', true, pinnedVerification.fixture_rightful_issuance_path_evidenced);
assertEqual('pinned recognized boarding true', true, pinnedVerification.recognized_write_boarded);
const signedEnvelopeIdentityReseal = clone(artifact);
signedEnvelopeIdentityReseal.payload.proof.accepted_crossing_evidence
  .signed_receipt_envelope_sha256 = 'f'.repeat(64);
resealArtifact(signedEnvelopeIdentityReseal);
const signedEnvelopeResealStructuralVerification =
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
    signedEnvelopeIdentityReseal
  );
assertEqual('coherent signed-envelope reseal remains structurally valid', true, signedEnvelopeResealStructuralVerification.structural_self_integrity_verified);
assertEqual('coherent signed-envelope reseal has no signed-envelope identity claim', false, signedEnvelopeResealStructuralVerification.signed_receipt_envelope_identity_bound_to_expected_artifact_sha256);
assertEqual('coherent signed-envelope reseal has no fixture-rightful claim', false, signedEnvelopeResealStructuralVerification.fixture_rightful_issuance_path_evidenced);
assertThrows(
  'coherent signed-envelope reseal refuses pinned original artifact identity',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
    signedEnvelopeIdentityReseal,
    { expectedArtifactBodySha256: artifact.integrity.body_sha256 }
  ),
  'expected SHA-256 identity'
);
const summaryText = formatProtectedRecordsInstalledRuntimeProfileServiceProofSummary(report);
const verificationText = formatProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(verification);
assert('summary names fixture rightful path', summaryText.includes('fixture_rightful_issuance_path_evidenced=true'));
assert('summary names both replay identities', summaryText.includes('restart_consumed_grant_reason=authority_grant_already_consumed'));
assert('summary names joint rollback side door', summaryText.includes('joint_rollback_reopened_authority_grant_reuse=true'));
assert('verification text names ordered binding', verificationText.includes('ordered_transition_binding_type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
assert('verification text names structural scope', verificationText.includes('verification_scope=structural-self-integrity-only'));
assert('verification text keeps detached fixture claim false', verificationText.includes('fixture_rightful_issuance_path_evidenced=false'));
assert('formatted text privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summaryText + verificationText));

const committedArtifactText = readFileSync(
  'tests/fixtures/protected-records-installed-runtime-profile-service-proof-artifact-v1.json',
  'utf8'
);
const committedArtifact =
  parseProtectedRecordsInstalledRuntimeProfileServiceProofArtifactText(committedArtifactText);
assert('committed artifact validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(committedArtifact));
const committedVerification =
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(committedArtifact);
assert('committed verification validates', assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(committedVerification));
assertEqual('committed verification is structural', true, committedVerification.structural_self_integrity_verified);
assertEqual('committed artifact identity remains unanchored without expected sha', true, committedVerification.artifact_identity_match_requires_expected_sha256);
assertEqual('committed detached fixture claim false', false, committedVerification.fixture_rightful_issuance_path_evidenced);
assert('committed artifact is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(committedArtifactText));

section('tamper refusals');
const oldAtomic = clone(report);
oldAtomic.accepted_runtime_transition_binding.binding_type = 'protected-records-runtime-atomic-transition-binding-v1';
assertThrows('old atomic label refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProof(oldAtomic), 'ordered transition');
const genericOverclaim = clone(report);
genericOverclaim.authority_contract.public_safe_grant_summary.rightful_issuance_proven = true;
assertThrows('generic rightful overclaim refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProof(genericOverclaim), 'summary');
const restartIdentitySwap = clone(report);
restartIdentitySwap.service_replay_cases[1].reason_code = 'receipt_replay';
assertThrows('restart replay identity swap refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProof(restartIdentitySwap), 'replay identity');
const recognitionReorder = clone(report);
recognitionReorder.refusal_cases.reverse();
assertThrows('recognition taxonomy reorder refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProof(recognitionReorder), 'recognition refusal');
const authorityConsumption = clone(report);
authorityConsumption.authority_refusal_cases[0].consumed_authority_grant_count = 1;
assertThrows('authority refusal consumption refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProof(authorityConsumption), 'authority refusal');
const hiddenJointSideDoor = clone(report);
hiddenJointSideDoor.joint_rollback_case.store_anchor_and_witness.service_write_accepted = false;
hiddenJointSideDoor.joint_rollback_case.store_anchor_and_witness.boarded = false;
assertThrows('hidden joint rollback reuse refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProof(hiddenJointSideDoor), 'joint rollback');
const privateIssuerLeak = clone(report);
privateIssuerLeak.authority_contract.public_safe_grant_summary.issuer_kid = 'private-runtime-kid';
assertThrows('private issuer material refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProof(privateIssuerLeak), 'unexpected fields');

const signedPayloadRewrite = clone(artifact);
const signedPayloadProof = signedPayloadRewrite.payload.proof;
const forgedPayloadSha = 'f'.repeat(64);
signedPayloadProof.accepted_crossing_evidence.signed_payload_sha256 = forgedPayloadSha;
signedPayloadProof.accepted_crossing_evidence.issuance_decision.binding.signed_payload_sha256 = forgedPayloadSha;
signedPayloadProof.accepted_crossing_evidence.effect_decision.binding.signed_payload_sha256 = forgedPayloadSha;
const forgedCrossingSha = sha256hex(canonicalize({
  authority_grant_contract_sha256:
    signedPayloadProof.accepted_crossing_evidence.authority_grant_contract_sha256,
  authorized_effect_detail_sha256:
    signedPayloadProof.accepted_crossing_evidence.authorized_effect_detail_sha256,
  signed_payload_sha256: forgedPayloadSha,
  receipt_semantic_binding_sha256:
    signedPayloadProof.accepted_crossing_evidence.receipt_semantic_binding_sha256,
}));
for (const decisionKey of ['issuance_decision', 'effect_decision']) {
  signedPayloadProof.accepted_crossing_evidence[decisionKey].binding.crossing_binding_sha256 =
    forgedCrossingSha;
}
signedPayloadProof.accepted_crossing_evidence.authority_grant_crossing_binding_sha256 = forgedCrossingSha;
signedPayloadProof.accepted_crossing_evidence.issuance_decision_sha256 = sha256hex(canonicalize(
  signedPayloadProof.accepted_crossing_evidence.issuance_decision
));
signedPayloadProof.accepted_crossing_evidence.effect_decision_sha256 = sha256hex(canonicalize(
  signedPayloadProof.accepted_crossing_evidence.effect_decision
));
signedPayloadProof.accepted_runtime_transition_binding.signed_payload_sha256 = forgedPayloadSha;
signedPayloadProof.accepted_runtime_transition_binding.authority_grant_crossing_binding_sha256 =
  forgedCrossingSha;
resealArtifact(signedPayloadRewrite);
assertThrows(
  're-sealed signed payload rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(signedPayloadRewrite),
  'signed payload'
);

const crossingBindingRewrite = clone(artifact);
const crossingProof = crossingBindingRewrite.payload.proof;
crossingProof.accepted_crossing_evidence.authority_grant_crossing_binding_sha256 = 'e'.repeat(64);
crossingProof.accepted_runtime_transition_binding.authority_grant_crossing_binding_sha256 = 'e'.repeat(64);
crossingProof.accepted_crossing_evidence.issuance_decision.binding.crossing_binding_sha256 = 'e'.repeat(64);
crossingProof.accepted_crossing_evidence.effect_decision.binding.crossing_binding_sha256 = 'e'.repeat(64);
crossingProof.accepted_crossing_evidence.issuance_decision_sha256 = sha256hex(canonicalize(
  crossingProof.accepted_crossing_evidence.issuance_decision
));
crossingProof.accepted_crossing_evidence.effect_decision_sha256 = sha256hex(canonicalize(
  crossingProof.accepted_crossing_evidence.effect_decision
));
resealArtifact(crossingBindingRewrite);
assertThrows(
  're-sealed crossing binding rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(crossingBindingRewrite),
  'decision identity'
);

const sourceProfileRewrite = clone(artifact);
sourceProfileRewrite.payload.proof.source_preflight.body_sha256 = 'd'.repeat(64);
sourceProfileRewrite.payload.proof.selected_profile.profile_sha256 = 'c'.repeat(64);
sourceProfileRewrite.payload.proof.target_binding.source_preflight_body_sha256 = 'd'.repeat(64);
sourceProfileRewrite.payload.proof.target_binding.source_profile_sha256 = 'c'.repeat(64);
sourceProfileRewrite.payload.proof.accepted_crossing_evidence.source_preflight_body_sha256 = 'd'.repeat(64);
sourceProfileRewrite.payload.proof.accepted_crossing_evidence.selected_profile_sha256 = 'c'.repeat(64);
resealArtifact(sourceProfileRewrite);
assertThrows(
  're-sealed source preflight and profile rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(sourceProfileRewrite),
  'source preflight projection'
);

const constructionOrderRewrite = clone(artifact);
constructionOrderRewrite.payload.proof.authority_contract.construction_order.reverse();
constructionOrderRewrite.payload.proof.accepted_crossing_evidence.authority_construction_order_sha256 =
  sha256hex(canonicalize(constructionOrderRewrite.payload.proof.authority_contract.construction_order));
resealArtifact(constructionOrderRewrite);
assertThrows(
  're-sealed construction order rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(constructionOrderRewrite),
  'construction order'
);

const authorityRefusalRewrite = clone(artifact);
authorityRefusalRewrite.payload.proof.authority_refusal_cases[0].authority_grant_satisfied = true;
resealArtifact(authorityRefusalRewrite);
assertThrows(
  're-sealed authority refusal acceptance rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(authorityRefusalRewrite),
  'authority refusal'
);

const partialWitnessRewrite = clone(artifact);
partialWitnessRewrite.payload.proof.partial_commit_cases[1].consumed_grant_store_witness_exists_after = true;
resealArtifact(partialWitnessRewrite);
assertThrows(
  're-sealed partial witness rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(partialWitnessRewrite),
  'witness commit burn'
);

const publicSummaryInjection = clone(artifact);
publicSummaryInjection.payload.proof.authority_contract.public_safe_grant_summary.runtime_kid =
  'private-runtime-kid';
resealArtifact(publicSummaryInjection);
assertThrows(
  're-sealed public summary runtime kid injection refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(publicSummaryInjection),
  'unexpected fields'
);

const transitionCountRewrite = clone(artifact);
transitionCountRewrite.payload.proof.accepted_runtime_transition_binding.state_entry_count_before = 50;
transitionCountRewrite.payload.proof.accepted_runtime_transition_binding.state_entry_count_after = 50;
resealArtifact(transitionCountRewrite);
assertThrows(
  're-sealed transition count rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(transitionCountRewrite),
  'transition reconstruction'
);

const targetSourceRewrite = clone(artifact);
targetSourceRewrite.payload.proof.target_binding.source_profile_id = 'other-profile';
resealArtifact(targetSourceRewrite);
assertThrows(
  're-sealed target source profile rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(targetSourceRewrite),
  'target binding reconstruction'
);

const recognizedCountRewrite = clone(artifact);
recognizedCountRewrite.payload.proof.recognized_boarding.consumed_authority_grant_count = 77;
resealArtifact(recognizedCountRewrite);
assertThrows(
  're-sealed recognized grant count rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(recognizedCountRewrite),
  'recognized boarding'
);

const publicGrantPowerRewrite = clone(artifact);
publicGrantPowerRewrite.payload.proof.authority_contract.public_grant_contract.powers[0].power_id =
  'invented_power';
resealArtifact(publicGrantPowerRewrite);
assertThrows(
  're-sealed public grant power rewrite refuses',
  () => verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(publicGrantPowerRewrite),
  'human authorization body drifted'
);
const brokenIntegrity = clone(artifact);
brokenIntegrity.integrity.body_sha256 = '0'.repeat(64);
assertThrows('artifact integrity tamper refuses', () => assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(brokenIntegrity), 'SHA-256 mismatch');
assertThrows('invalid artifact JSON refuses', () => parseProtectedRecordsInstalledRuntimeProfileServiceProofArtifactText('{'), 'valid JSON');

console.log(`\n=== Results: ${PASS}/${TOTAL} passed, ${FAIL} failed ===`);
if (FAIL > 0) process.exit(1);
