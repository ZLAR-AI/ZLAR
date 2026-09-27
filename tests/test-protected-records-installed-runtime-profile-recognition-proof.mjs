#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { canonicalize } from '../lib/canonicalize.mjs';
import { sha256hex } from '../lib/receipt.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
  parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_NON_CLAIMS,
  INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_SAFE_CLAIM_CEILING,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE,
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof,
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact,
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification,
  buildProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact,
  formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactSummary,
  formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification,
  formatProtectedRecordsInstalledRuntimeProfileRecognitionProofSummary,
  parseProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactText,
  runProtectedRecordsInstalledRuntimeProfileRecognitionProof,
  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact,
} from '../lib/protected-records-installed-runtime-profile-recognition-proof.mjs';
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

const PREFLIGHT_FIXTURE =
  'tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json';
const RECOGNITION_FIXTURE =
  'tests/fixtures/protected-records-installed-runtime-profile-recognition-proof-artifact-v1.json';
const input = parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText(
  readFileSync(PREFLIGHT_FIXTURE, 'utf8')
);

section('fresh recognition proof');
const report = runProtectedRecordsInstalledRuntimeProfileRecognitionProof(input);
assert('report validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(report));
assertEqual('proof type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_TYPE, report.proof_type);
assertEqual('safe claim exact', INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('local hermetic model', 'local-hermetic-installed-runtime-profile-recognition-fixture', report.evidence_model);
assertEqual('live probing false', false, report.live_probing);

section('source route and fixed recognition taxonomy');
assertEqual('source verified', true, report.source_preflight.verified);
assertEqual('source read only', true, report.source_preflight.read_only);
assertEqual('source selected explicitly', true, report.source_preflight.selected_by_explicit_id_and_sha);
assertEqual('source latest false', false, report.source_preflight.selects_latest_profile);
assertEqual('recognition contract preserved', true, report.source_preflight.recognition_contract_preserved);
assertEqual('target contract preserved', true, report.source_preflight.target_contract_preserved);
assertEqual('authority requirement preserved', true, report.source_preflight.authority_grant_requirement_preserved);
assertEqual('exact grant deferred by preflight', true, report.source_preflight.exact_runtime_authority_grant_contract_deferred);
assertEqual('new mutation route exact', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', report.source_preflight.mutation_authoritative_route);
assertEqual('source generic rightful false', false, report.source_preflight.rightful_issuance_proven);
assertEqual('recognition count 18', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.refusal_cases.length);
assertEqual('recognition taxonomy exact order', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES), JSON.stringify(report.refusal_cases.map((item) => item.case_id)));
assertEqual('recognition contract count exact', 18, report.recognition_contract.required_refusal_case_count);
assert('recognition taxonomy hash present', /^[a-f0-9]{64}$/.test(report.recognition_contract.observed_refusal_taxonomy_sha256));
for (const refusal of report.refusal_cases) {
  assert(`${refusal.case_id} refuses`, refusal.service_write_accepted === false && refusal.decision === 'refuse');
  assertEqual(`${refusal.case_id} state delta zero`, 0, refusal.state_entry_count_delta);
}

section('positive fixture issuance before signing');
const order = report.fixture_authority.construction_order;
assertEqual('eleven construction stages', 11, order.length);
assertEqual('launcher scope first', 'launcher_scope_evidence', order[0]);
assertEqual('grant contract second', 'authority_grant_contract', order[1]);
assertEqual('appointment third', 'issuer_appointment', order[2]);
assertEqual('authorized effect fourth', 'authorized_effect_detail', order[3]);
assertEqual('unsigned receipt before issuance decision', 'unsigned_receipt', order[4]);
assertEqual('issuance decision before signature', 'accepted_issuance_decision', order[5]);
assertEqual('signature follows issuance', 'receipt_signature', order[6]);
assertEqual('downstream recognition follows signature', 'downstream_recognition', order[7]);
assertEqual('effect gate before consumption', 'effect_gate', order[8]);
assertEqual('grant consumption before mutation', 'authority_grant_consumption', order[9]);
assertEqual('runtime mutation last', 'runtime_state_mutation', order[10]);
assertEqual('request supplied authority rejected', false, report.fixture_authority.request_supplied_authority_accepted);
const summary = report.fixture_authority.public_safe_grant_summary;
assertEqual('public summary type', 'zlar-protected-records-fixture-authority-grant-summary-v1', summary.summary_type);
assertEqual('fixture authority domain', 'protected-records.local-disposable-fixture', summary.authority_domain_id);
assertEqual('fixture grantor role', 'fixture-consequence-authority', summary.grantor_role_id);
assertEqual('consequence path exact', PROTECTED_RECORDS_CONSEQUENCE_PATH, summary.consequence_path);
assertEqual('target exact', PROTECTED_RECORDS_TARGET_HANDLE, summary.target_handle);
assertEqual('power ids exact', JSON.stringify([
  'bind_runtime_issuer_to_slot',
  'issue_governed_action_receipt',
  'issue_replacement_authority_grant',
  'revoke_authority_grant',
]), JSON.stringify(summary.power_ids));
assertEqual('fixture rightful path true', true, summary.fixture_rightful_issuance_path_evidenced);
assertEqual('generic rightful false', false, summary.rightful_issuance_proven);
assertEqual('portable rightful false', false, summary.portable_rightful_issuance_proven);
assertEqual('production rightful false', false, summary.production_rightful_issuance_proven);
assertEqual('private issuer not disclosed', false, summary.runtime_private_issuer_identity_disclosed);
assertEqual('private appointment not disclosed', false, summary.runtime_private_grant_appointment_disclosed);

section('recognized transition and identities');
assertEqual('recognized write boards', true, report.recognized_boarding.boarded);
assertEqual('recognized reason grant effect', 'fixture_authority_grant_effect_satisfied', report.recognized_boarding.reason_code);
assertEqual('recognized appends one', 1, report.recognized_boarding.state_entry_count_delta);
assertEqual('recognized consumes one grant', 1, report.recognized_boarding.consumed_authority_grant_count);
assertEqual('recognized grant satisfied', true, report.recognized_boarding.authority_grant_satisfied);
assertEqual('recognized signed payload present', true, report.recognized_boarding.verified_signed_payload_identity_present);
const transition = report.accepted_runtime_transition_binding;
assertEqual('ordered binding type exact', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', transition.binding_type);
assertEqual('one launcher lock held', true, transition.one_launcher_store_lock_held_across_transition);
assert('signed payload check before effect', transition.signed_payload_replay_check_sequence < transition.effect_gate_sequence);
assert('effect before grant store', transition.effect_gate_sequence < transition.grant_store_commit_sequence);
assert('grant store before state append', transition.grant_store_commit_sequence < transition.state_append_sequence);
assert('state append before helper promotion', transition.state_append_sequence < transition.helper_state_promotion_sequence);
assertEqual('signed payload replay identity exact', 'verified-signed-payload-sha256', report.runtime_identity_boundary.signed_payload_replay_identity);
assertEqual('grant consumption identity exact', 'authority-grant-contract-sha256', report.runtime_identity_boundary.authority_grant_consumption_identity);
assertEqual('non-atomic multi-file model exact', 'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness', report.runtime_identity_boundary.consumed_store_write_model);
assertEqual('receipt binds authorized detail', true, report.target_binding.receipt_binds_authorized_effect_detail);
assertEqual('target effect nested in authorized detail', true, report.target_binding.target_effect_bound_inside_authorized_effect_detail);
assert('target effect differs from receipt detail', report.target_binding.target_effect_sha256 !== report.target_binding.receipt_detail_sha256);
assertEqual('transition grant matches summary', summary.authority_grant_contract_sha256, transition.authority_grant_contract_sha256);

section('claim boundary and side doors');
assertEqual('fixture rightful path acknowledged', true, report.proof_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('generic rightful false', false, report.proof_boundary.rightful_issuance_proven);
assertEqual('portable rightful false', false, report.proof_boundary.portable_rightful_issuance_proven);
assertEqual('production rightful false', false, report.proof_boundary.production_rightful_issuance_proven);
assertEqual('live authority false', false, report.proof_boundary.live_authority_proven);
assertEqual('current machine false', false, report.proof_boundary.current_machine_governance_proven);
assertEqual('lifecycle closure false', false, report.proof_boundary.consequence_lifecycle_closed);
assertEqual('install false', false, report.proof_boundary.install_performed);
assertEqual('runtime service false', false, report.proof_boundary.runtime_service_started);
assertEqual('local store written', true, report.proof_boundary.disposable_consumed_grant_store_written);
assertEqual('local anchor written', true, report.proof_boundary.disposable_consumed_grant_store_anchor_written);
assertEqual('local witness written', true, report.proof_boundary.disposable_consumed_grant_store_witness_written);
assert('nonclaims name state-append burn', report.non_claims.some((item) => item.includes('state-append failure')));
assert('nonclaims name non-atomic metadata burn', report.non_claims.some((item) => item.includes('metadata write failure')));
assert('nonclaims name joint rollback side door', report.non_claims.some((item) => item.includes('move together')));
assert('nonclaims name path TOCTOU side door', report.non_claims.some((item) => item.includes('time-of-check/time-of-use')));
assertEqual('nonclaims exact', JSON.stringify(INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_NON_CLAIMS), JSON.stringify(report.non_claims));
assertEqual('raw receipt id absent', false, report.marker.raw_receipt_id_present);
assertEqual('private issuer material absent', false, report.marker.runtime_private_issuer_material_present);
assert('report privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report)));

section('artifact and verifier');
const artifact = buildProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(report);
assert('generated artifact validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact));
assertEqual('artifact type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_TYPE, artifact.artifact_type);
const verification = verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact);
assert('generated verification validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(verification));
assertEqual('verification type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_RECOGNITION_PROOF_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification route exact', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', verification.source_preflight_route);
assertEqual('verification refusal count 18', 18, verification.refusal_case_count);
assertEqual('verification structural self-integrity true', true, verification.structural_self_integrity_verified);
assertEqual('verification scope structural only', 'structural-self-integrity-only', verification.verification_scope);
assertEqual('verification artifact identity unmatched without expected sha', false, verification.artifact_identity_sha256_matched);
assertEqual('verification source identity unmatched without expected sha', false, verification.source_preflight_body_sha256_matched);
assertEqual('verification signed payload identity not bound without pins', false, verification.signed_payload_identity_bound_to_expected_artifact_and_source_sha256);
assertEqual('verification fixture rightful false without pins', false, verification.fixture_rightful_issuance_path_evidenced);
assertEqual('verification boarded claim false without pins', false, verification.recognized_write_boarded);
assertEqual('verification generic rightful false', false, verification.rightful_issuance_proven);
assertEqual('verification ordered binding', transition.binding_type, verification.ordered_transition_binding_type);
assertEqual('verification power ids exact', JSON.stringify(summary.power_ids), JSON.stringify(verification.power_ids));
const artifactOnlyVerification =
  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact, {
    expectedArtifactBodySha256: artifact.integrity.body_sha256,
  });
assertEqual('artifact-only identity matches', true, artifactOnlyVerification.artifact_identity_sha256_matched);
assertEqual('artifact-only source identity remains unmatched', false, artifactOnlyVerification.source_preflight_body_sha256_matched);
assertEqual('artifact-only fixture rightful remains false', false, artifactOnlyVerification.fixture_rightful_issuance_path_evidenced);
const pinnedVerification =
  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(artifact, {
    expectedArtifactBodySha256: artifact.integrity.body_sha256,
    expectedSourcePreflightBodySha256: report.source_preflight.body_sha256,
  });
assert('pinned verification validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(pinnedVerification));
assertEqual('pinned artifact identity matched', true, pinnedVerification.artifact_identity_sha256_matched);
assertEqual('pinned source identity matched', true, pinnedVerification.source_preflight_body_sha256_matched);
assertEqual('pinned signed payload identity bound', true, pinnedVerification.signed_payload_identity_bound_to_expected_artifact_and_source_sha256);
assertEqual('pinned fixture rightful true', true, pinnedVerification.fixture_rightful_issuance_path_evidenced);
assertEqual('pinned boarded claim true', true, pinnedVerification.recognized_write_boarded);
const sourcePreflightIdentityReseal = clone(artifact);
sourcePreflightIdentityReseal.payload.proof.source_preflight.body_sha256 = 'd'.repeat(64);
resealArtifact(sourcePreflightIdentityReseal);
const sourceResealStructuralVerification =
  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(
    sourcePreflightIdentityReseal
  );
assertEqual('coherent source-preflight reseal remains structurally valid', true, sourceResealStructuralVerification.structural_self_integrity_verified);
assertEqual('coherent source-preflight reseal cannot claim source identity', false, sourceResealStructuralVerification.source_preflight_body_sha256_matched);
assertEqual('coherent source-preflight reseal cannot claim fixture rightful', false, sourceResealStructuralVerification.fixture_rightful_issuance_path_evidenced);
assertThrows(
  'coherent source-preflight reseal refuses original expected artifact identity',
  () => verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(
    sourcePreflightIdentityReseal,
    {
      expectedArtifactBodySha256: artifact.integrity.body_sha256,
      expectedSourcePreflightBodySha256: report.source_preflight.body_sha256,
    }
  ),
  'expected SHA-256 identity'
);
assertThrows(
  'attacker-pinned source-preflight reseal still refuses independent expected source identity',
  () => verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(
    sourcePreflightIdentityReseal,
    {
      expectedArtifactBodySha256: sourcePreflightIdentityReseal.integrity.body_sha256,
      expectedSourcePreflightBodySha256: report.source_preflight.body_sha256,
    }
  ),
  'expected SHA-256 identity'
);
const parsed = parseProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactText(JSON.stringify(artifact));
assertEqual('parsed artifact sha exact', artifact.integrity.body_sha256, parsed.integrity.body_sha256);
const committed = parseProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactText(
  readFileSync(RECOGNITION_FIXTURE, 'utf8')
);
assert('committed fixture validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(committed));
assertEqual(
  'committed fixture binds current target route',
  report.target_binding.target_binding_sha256,
  committed.payload.proof.target_binding.target_binding_sha256
);
assertEqual(
  'committed fixture binds current deterministic grant contract',
  summary.authority_grant_contract_sha256,
  committed.payload.proof.fixture_authority.public_safe_grant_summary
    .authority_grant_contract_sha256
);
const committedVerification = verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(committed);
assert('committed verification validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(committedVerification));
assertEqual('committed detached verification stays structural', 'structural-self-integrity-only', committedVerification.verification_scope);
assertEqual('committed detached fixture rightful false', false, committedVerification.fixture_rightful_issuance_path_evidenced);
const summaryText = formatProtectedRecordsInstalledRuntimeProfileRecognitionProofSummary(report);
const verificationText = formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(verification);
const artifactText = formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactSummary(artifact);
assert('summary names fixture rightful path', summaryText.includes('fixture_rightful_issuance_path_evidenced=true'));
assert('summary names ordered binding', summaryText.includes('ordered_transition_binding_type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
assert('summary names grant identity', summaryText.includes('authority_grant_consumption_identity=authority-grant-contract-sha256'));
assert('verification names powers', verificationText.includes('issue_replacement_authority_grant'));
assert('verification text names structural-only scope', verificationText.includes('verification_scope=structural-self-integrity-only'));
assert('verification text keeps fixture rightful false', verificationText.includes('fixture_rightful_issuance_path_evidenced=false'));
assert('artifact summary names hash', artifactText.includes(artifact.integrity.body_sha256));
assert('formatted text privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summaryText + verificationText + artifactText));

section('tamper refusals');
const oldRoute = clone(report);
oldRoute.source_preflight.mutation_authoritative_route = 'receipt-recognition-before-runtime-state-mutation';
assertThrows('old route refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(oldRoute), 'source preflight');
const oldAtomic = clone(report);
oldAtomic.accepted_runtime_transition_binding.binding_type = 'protected-records-runtime-atomic-transition-binding-v1';
assertThrows('old atomic label refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(oldAtomic), 'ordered transition');
const powerDrop = clone(report);
powerDrop.fixture_authority.public_safe_grant_summary.power_ids.pop();
assertThrows('missing power refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(powerDrop), 'powers');
const requestAuthority = clone(report);
requestAuthority.fixture_authority.request_supplied_authority_accepted = true;
assertThrows('request supplied authority overclaim refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(requestAuthority), 'construction');
const genericOverclaim = clone(report);
genericOverclaim.proof_boundary.rightful_issuance_proven = true;
assertThrows('generic rightful overclaim refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(genericOverclaim), 'claim boundary');
const taxonomyReorder = clone(report);
taxonomyReorder.refusal_cases.reverse();
assertThrows('recognition taxonomy reorder refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(taxonomyReorder), 'recognition contract');
const refusalBoards = clone(report);
refusalBoards.refusal_cases[0].service_write_accepted = true;
refusalBoards.refusal_cases[0].boarded = true;
assertThrows('recognition refusal boarding refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(refusalBoards), 'recognition contract');
const privateLeak = clone(report);
privateLeak.fixture_authority.public_safe_grant_summary.issuer_kid = 'private-runtime-kid';
assertThrows('private issuer leak refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(privateLeak), 'unexpected fields');
const brokenArtifact = clone(artifact);
brokenArtifact.integrity.body_sha256 = '0'.repeat(64);
assertThrows('artifact integrity tamper refuses', () => assertProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(brokenArtifact), 'SHA-256 mismatch');
assertThrows('invalid artifact JSON refuses', () => parseProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactText('{'), 'valid JSON');

console.log(`\n=== Results: ${PASS}/${TOTAL} passed, ${FAIL} failed ===`);
if (FAIL > 0) process.exit(1);
