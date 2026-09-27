#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';
import { sha256hex } from '../lib/receipt.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS,
  INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NON_CLAIMS,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
  buildProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactSummary,
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainSummary,
  parseProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactText,
  runProtectedRecordsInstalledRuntimeProfileTerminalChain,
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
} from '../lib/protected-records-one-terminal-deployment-profile.mjs';

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

function resealTerminalArtifact(value) {
  value.integrity.body_sha256 = sha256hex(canonicalize(value.payload));
  return value;
}

function resealNestedServiceArtifact(value) {
  const nested = value.payload.chain.nested_artifacts.generated_service_proof_artifact;
  const { integrity, ...body } = nested;
  nested.integrity.body_sha256 = sha256hex(canonicalize(body));
  return resealTerminalArtifact(value);
}

const PLAN_PATH = 'profiles/protected-records-runtime-profile-installation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH =
  'tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 =
  '0f8db51f11885e7867c6f0fa4d737adf51774e7cd9ad711cd2073b5b684c303f';
const plan = JSON.parse(readFileSync(PLAN_PATH, 'utf8'));
const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));

section('fresh installed runtime profile terminal chain');
const report = runProtectedRecordsInstalledRuntimeProfileTerminalChain(plan, profile);
assert('terminal chain passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChain(report));
assertEqual('chain type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE, report.chain_type);
assertEqual('evidence model fresh', 'fresh-local-disposable-installed-runtime-profile-terminal-chain', report.evidence_model);
assertEqual('no live probing', false, report.live_probing);
assertEqual('sample artifact not used', false, report.terminal_chain.sample_artifact_used);
assertEqual('generated installed root preflighted', true, report.terminal_chain.generated_installed_root_preflighted);
assertEqual('generated preflight consumed by service proof', true, report.terminal_chain.generated_preflight_artifact_consumed_by_service_proof);
assertEqual('service proof bound to generated preflight', true, report.terminal_chain.service_proof_bound_to_generated_preflight);
assertEqual('service artifact verification bound', true, report.terminal_chain.service_artifact_verification_bound_to_service_proof);
assertEqual('service structural self-integrity verified', true, report.generated_service_proof.service_structural_self_integrity_verified);
assertEqual('service identity requires expected sha', true, report.generated_service_proof.service_artifact_identity_match_requires_expected_sha256);
assertEqual('service expected sha exact', report.generated_service_proof.artifact_body_sha256, report.generated_service_proof.expected_service_proof_artifact_body_sha256);
assertEqual('service expected sha matched', true, report.generated_service_proof.expected_service_proof_artifact_body_sha256_matched);
assertEqual('terminal carries service expected sha', report.generated_service_proof.artifact_body_sha256, report.terminal_chain.expected_generated_service_proof_artifact_body_sha256);
assertEqual('terminal carries service expected sha match', true, report.terminal_chain.expected_generated_service_proof_artifact_body_sha256_matched);
assertEqual('recognized write boarded', true, report.terminal_chain.recognized_write_boarded);
assertEqual('missing receipt refused before mutation', true, report.terminal_chain.missing_receipt_refused_before_mutation);
assertEqual('invalid receipt refused before mutation', true, report.terminal_chain.invalid_receipt_refused_before_mutation);
assertEqual('all required recognition refusals before mutation', true, report.terminal_chain.all_required_recognition_refusals_before_mutation);
assertEqual('required recognition refusal count', 18, report.terminal_chain.required_recognition_refusal_case_count);
assertEqual('observed recognition refusal count', 18, report.terminal_chain.observed_recognition_refusal_case_count);
assertEqual('recognition refusal taxonomy hash bound', report.generated_service_proof.recognition_refusal_taxonomy_sha256, report.terminal_chain.recognition_refusal_taxonomy_sha256);
assert('recognition refusal taxonomy sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.recognition_refusal_taxonomy_sha256));
assertEqual('all required authority refusals before consumption and mutation', true, report.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('required authority refusal count', 5, report.terminal_chain.required_authority_refusal_case_count);
assertEqual('observed authority refusal count', 5, report.terminal_chain.observed_authority_refusal_case_count);
assertEqual('authority refusal taxonomy hash bound', report.generated_service_proof.authority_refusal_taxonomy_sha256, report.terminal_chain.authority_refusal_taxonomy_sha256);
assert('authority refusal taxonomy sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.authority_refusal_taxonomy_sha256));
assertEqual('public-safe grant summary carried exact', JSON.stringify(report.generated_service_proof.public_safe_grant_summary), JSON.stringify(report.terminal_chain.public_safe_grant_summary));
assertEqual('public grant contract carried exact', JSON.stringify(report.generated_service_proof.public_grant_contract), JSON.stringify(report.terminal_chain.public_grant_contract));
assertEqual('public grant contract sha recomputable', sha256hex(canonicalize(report.terminal_chain.public_grant_contract)), report.terminal_chain.public_grant_contract_sha256);
assertEqual('public grant contract matches summary identity', report.terminal_chain.public_safe_grant_summary.authority_grant_contract_sha256, report.terminal_chain.public_grant_contract_sha256);
assertEqual('public grant contract powers exact', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS), JSON.stringify(report.terminal_chain.public_grant_contract.powers.map((power) => power.power_id)));
assertEqual('public-safe grant powers exact', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS), JSON.stringify(report.terminal_chain.public_safe_grant_summary.power_ids));
assert('public-safe grant summary sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.public_safe_grant_summary_sha256));
assertEqual('ordered transition type exact', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', report.terminal_chain.ordered_transition_binding_type);
assert('ordered transition sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.ordered_transition_binding_sha256));
const nestedAcceptedCrossing = report.nested_artifacts.generated_service_proof_artifact.payload.proof.accepted_crossing_evidence;
assertEqual('accepted crossing evidence sha recomputable', sha256hex(canonicalize({ accepted_crossing_evidence: nestedAcceptedCrossing })), report.terminal_chain.accepted_crossing_evidence_sha256);
assertEqual('accepted crossing binding exact', nestedAcceptedCrossing.authority_grant_crossing_binding_sha256, report.terminal_chain.authority_grant_crossing_binding_sha256);
assertEqual('accepted signed payload exact', nestedAcceptedCrossing.signed_payload_sha256, report.terminal_chain.signed_payload_sha256);
assertEqual('accepted target binding exact', report.terminal_chain.boarded_service_target_binding.launcher_target_binding_sha256, report.terminal_chain.accepted_crossing_target_binding_sha256);
assertEqual('accepted effect detail exact', report.terminal_chain.boarded_service_target_binding.authorized_effect_detail_sha256, report.terminal_chain.accepted_crossing_authorized_effect_detail_sha256);
assertEqual('accepted state effect exact', report.terminal_chain.boarded_service_target_binding.state_effect_binding_sha256, report.terminal_chain.accepted_crossing_state_effect_binding_sha256);
assertEqual('named receipt refusals hash bound', report.generated_service_proof.named_receipt_refusals_sha256, report.terminal_chain.named_receipt_refusals_sha256);
assert('named receipt refusals sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.named_receipt_refusals_sha256));
assertEqual('recognition refusal groups hash bound', report.generated_service_proof.recognition_refusal_groups_sha256, report.terminal_chain.recognition_refusal_groups_sha256);
assert('recognition refusal groups sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.recognition_refusal_groups_sha256));
assert('recognition contract digest sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.recognition_contract_sha256));
assertEqual('recognition contract digest preflight bound', report.generated_preflight.recognition_contract_sha256, report.terminal_chain.recognition_contract_sha256);
assertEqual('recognition contract digest service proof bound', report.generated_service_proof.recognition_contract_sha256, report.terminal_chain.recognition_contract_sha256);
assertEqual('boarded service target binding carried into terminal chain', JSON.stringify(report.generated_service_proof.boarded_service_target_binding), JSON.stringify(report.terminal_chain.boarded_service_target_binding));
assertEqual('boarded service target binding sha carried into terminal chain', report.generated_service_proof.boarded_service_target_binding_sha256, report.terminal_chain.boarded_service_target_binding_sha256);
assertEqual('boarded service target binding sha recomputable', sha256hex(canonicalize({ boarded_service_target_binding: report.terminal_chain.boarded_service_target_binding })), report.terminal_chain.boarded_service_target_binding_sha256);
assertEqual('boarded service target handle bound', report.nested_artifacts.generated_service_proof_artifact.payload.proof.target_binding.target_handle, report.terminal_chain.boarded_service_target_binding.target_handle);
assertEqual('boarded service target effect bound', report.nested_artifacts.generated_service_proof_artifact.payload.proof.target_binding.target_effect_sha256, report.terminal_chain.boarded_service_target_binding.target_effect_sha256);
assertEqual('boarded service authorized effect detail bound', report.nested_artifacts.generated_service_proof_artifact.payload.proof.target_binding.authorized_effect_detail_sha256, report.terminal_chain.boarded_service_target_binding.authorized_effect_detail_sha256);
assertEqual('boarded service receipt detail bound', report.nested_artifacts.generated_service_proof_artifact.payload.proof.target_binding.receipt_detail_sha256, report.terminal_chain.boarded_service_target_binding.boarded_service_receipt_detail_sha256);
assertEqual('boarded service receipt binds authorized effect detail', true, report.terminal_chain.boarded_service_target_binding.receipt_binds_authorized_effect_detail);
assertEqual('boarded service target effect nested in authorized detail', true, report.terminal_chain.boarded_service_target_binding.target_effect_bound_inside_authorized_effect_detail);
assertEqual('boarded service state effect bound', report.nested_artifacts.generated_service_proof_artifact.payload.proof.target_binding.state_effect_binding_sha256, report.terminal_chain.boarded_service_target_binding.state_effect_binding_sha256);
assertEqual('boarded service profile hash bound', report.runtime_profile.profile_sha256, report.terminal_chain.boarded_service_target_binding.source_profile_sha256);
assertEqual('boarded service preflight hash bound', report.generated_preflight.artifact_body_sha256, report.terminal_chain.boarded_service_target_binding.source_preflight_body_sha256);
assertEqual('boarded service recognition hash bound', report.generated_preflight.recognition_contract_sha256, report.terminal_chain.boarded_service_target_binding.source_recognition_contract_sha256);
assertEqual('boarded service artifact hash bound', report.generated_service_proof.artifact_body_sha256, report.terminal_chain.boarded_service_target_binding.generated_service_proof_artifact_body_sha256);
assertEqual('boarded service target metadata is post-effect only', 'post-effect-hash-bound-metadata-only', report.terminal_chain.boarded_service_target_binding.metadata_role);
assertEqual('boarded service target fixture rightful issuance evidenced', true, report.terminal_chain.boarded_service_target_binding.fixture_rightful_issuance_path_evidenced);
assertEqual('boarded service target no profile-wide authority', false, report.terminal_chain.boarded_service_target_binding.profile_wide_target_authority_proven);
assertEqual('boarded service target no rightful issuance', false, report.terminal_chain.boarded_service_target_binding.rightful_issuance_proven);
assertEqual('boarded service target no live target', false, report.terminal_chain.boarded_service_target_binding.live_target_proven);
assertEqual('boarded service target no current-machine governance', false, report.terminal_chain.boarded_service_target_binding.current_machine_governance_proven);
assertEqual('boarded service target no lifecycle closure', false, report.terminal_chain.boarded_service_target_binding.consequence_lifecycle_closed);
assertEqual('trusted registry binding verdict', 'RECOGNIZED', report.terminal_chain.trusted_issuer_registry_recognition_binding.verdict);
assertEqual('trusted registry binding recognized', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.recognized);
assertEqual('trusted registry binding fixture validated', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_fixture_validated);
assertEqual('trusted registry binding rule evaluated', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated);
assertEqual('trusted registry binding evaluator result type', 'downstream-recognition-rule-v1', report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_evaluation_result_type);
assertEqual('trusted registry binding issuer count', 1, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_trusted_issuer_count);
assertEqual('trusted registry binding signature valid', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.signature_valid);
assertEqual('trusted registry binding audit event bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.required_audit_event_id_bound);
assertEqual('trusted registry binding detail hash bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.required_detail_hash_bound);
assert('trusted registry binding contract sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_fixture_contract_sha256));
assertEqual('trusted registry binding contract evidence', 'no-secret-registry-contract-v2', report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_contract_evidence);
assert('trusted registry binding public-safe summary sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_safe_summary_sha256));
assert('trusted registry binding receipt payload contract sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_payload_contract_sha256));
assertEqual('trusted registry binding contract hash bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound);
assertEqual('trusted registry binding carries boarded target binding sha metadata', report.terminal_chain.boarded_service_target_binding_sha256, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_metadata_boarded_service_target_binding_sha256);
assertEqual('trusted registry receipt is not boarded service receipt', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_is_boarded_service_receipt);
assertEqual('trusted registry receipt does not authorize service write', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write);
assertEqual('trusted registry and boarded service receipt roles distinct', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_detail_hash_roles_distinct);
assert('trusted registry and boarded service receipt hashes differ', report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_detail_hash !== report.terminal_chain.trusted_issuer_registry_recognition_binding.boarded_service_receipt_detail_hash);
assertEqual('trusted registry binding public key material omitted', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included);
assertEqual('trusted registry binding receipt envelope omitted', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_envelope_included);
assertEqual('trusted registry binding no artifact cryptographic reconstruction', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact);
assertEqual('trusted registry binding accepted domain', 'records', report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_accepted_domains[0]);
assertEqual('trusted registry binding accepted tool', 'records.write', report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_accepted_tools[0]);
assertEqual('trusted registry binding malformed registry refused', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.malformed_registry_fail_closed_before_verdict);
assertEqual('trusted registry binding selected profile hash bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.selected_profile_hash_bound);
assertEqual('trusted registry binding recognition contract hash bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound);
assertEqual('trusted registry binding service artifact hash bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.service_artifact_hash_bound);
assert('trusted registry binding sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256));
assertEqual('trusted registry binding sha bound', report.terminal_chain.trusted_issuer_registry_recognition_binding.binding_sha256, report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256);
assertEqual('recognized receipt path evidence verdict', 'RECOGNIZED', report.terminal_chain.recognized_receipt_path_evidence.verdict);
assertEqual('recognized receipt path evidence recognized', true, report.terminal_chain.recognized_receipt_path_evidence.recognized);
assertEqual('recognized receipt path evidence source binding sha', report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256, report.terminal_chain.recognized_receipt_path_evidence.source_binding_sha256);
assertEqual('recognized receipt path evidence receipt contract sha', report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_payload_contract_sha256, report.terminal_chain.recognized_receipt_path_evidence.receipt_payload_contract_sha256);
assertEqual('recognized receipt path carries boarded target binding sha', report.terminal_chain.boarded_service_target_binding_sha256, report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_binding_sha256);
assertEqual('recognized receipt path carries boarded target handle', report.terminal_chain.boarded_service_target_binding.target_handle, report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_handle);
assertEqual('recognized receipt path carries boarded target effect hash', report.terminal_chain.boarded_service_target_binding.target_effect_sha256, report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_effect_hash);
assertEqual('recognized receipt path target metadata is post-effect only', 'post-effect-hash-bound-metadata-only', report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_metadata_role);
assertEqual('recognized receipt path keeps registry receipt non-authorizing', false, report.terminal_chain.recognized_receipt_path_evidence.registry_receipt_authorized_service_write);
assertEqual('recognized receipt path keeps receipt identities distinct', false, report.terminal_chain.recognized_receipt_path_evidence.registry_receipt_is_boarded_service_receipt);
assertEqual('recognized receipt path evidence raw public key omitted', false, report.terminal_chain.recognized_receipt_path_evidence.registry_public_key_material_included);
assertEqual('recognized receipt path evidence receipt envelope omitted', false, report.terminal_chain.recognized_receipt_path_evidence.receipt_envelope_included);
assertEqual('recognized receipt path evidence no artifact crypto reconstruction', false, report.terminal_chain.recognized_receipt_path_evidence.cryptographic_evidence_reproducible_from_artifact);
assert('recognized receipt path evidence sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.recognized_receipt_path_evidence_sha256));
assertEqual('trusted registry local refusal case count', REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length, report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.case_count);
assertEqual('trusted registry local refusals all refused', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.all_refused);
assert('trusted registry local refusals sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256));
REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.forEach((expected, index) => {
  const observed = report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.cases[index];
  assertEqual(`trusted registry local refusal ${expected.case_id} case`, expected.case_id, observed.case_id);
  assertEqual(`trusted registry local refusal ${expected.case_id} decision`, 'refuse', observed.decision);
  assertEqual(`trusted registry local refusal ${expected.case_id} recognized`, false, observed.recognized);
  assertEqual(`trusted registry local refusal ${expected.case_id} reason`, expected.reason_code, observed.reason_code);
  assertEqual(`trusted registry local refusal ${expected.case_id} requested scope`, expected.requested_scope, observed.requested_scope);
  assertEqual(`trusted registry local refusal ${expected.case_id} registry scope`, expected.registry_scope, observed.registry_scope);
  assertEqual(`trusted registry local refusal ${expected.case_id} signature valid`, expected.signature_valid, observed.signature_valid);
  assertEqual(`trusted registry local refusal ${expected.case_id} issuer status`, expected.issuer_status, observed.issuer_status);
});
assertEqual('trusted registry binding no live registry', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.live_trust_registry_state);
assertEqual('trusted registry binding no live issuer status', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.live_issuer_status_proven);
assertEqual('trusted registry binding no key custody', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.key_custody_proven);
assertEqual('trusted registry binding no revocation truth', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.revocation_truth_proven);
assertEqual('trusted registry binding no production trust registry', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.production_trust_registry_proven);
assertEqual('trusted registry binding no production downstream', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.production_downstream_recognition_proven);
assertEqual('trusted registry binding no production authority', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.production_authority);
assertEqual('trusted registry binding no sovereign recognition', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.sovereign_recognition);
assertEqual('trusted registry binding no public attestation', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.public_external_attestation);
assertEqual('trusted registry binding no real non-operator review', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.real_non_operator_review);
assertEqual('trusted registry binding no current-machine governance', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.current_machine_governance_proven);
assertEqual('deployment-profile authority refusal mirror source', 'committed-one-terminal-deployment-profile-fixture', report.terminal_chain.deployment_profile_authority_refusal_mirror.source);
assert('deployment-profile authority refusal mirror source proof sha present', /^[a-f0-9]{64}$/.test(report.terminal_chain.deployment_profile_authority_refusal_mirror.source_proof_sha256));
assertEqual('deployment-profile authority refusal mirror source runtime profile sha bound', report.runtime_profile.profile_sha256, report.terminal_chain.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha256);
assertEqual('deployment-profile authority refusal mirror profile sha matches terminal chain', true, report.terminal_chain.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha_matches_terminal_chain);
assertEqual('deployment-profile authority refusal mirror case count', REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_count);
assertEqual(
  'deployment-profile authority refusal mirror case IDs',
  JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES),
  JSON.stringify(report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_ids)
);
assertEqual('deployment-profile authority refusal mirror before service proof', true, report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_service_proof);
assertEqual('deployment-profile authority refusal mirror before mutation', true, report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_mutation);
assertEqual('deployment-profile authority refusal mirror service proof not started', false, report.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_service_proof_started);
assertEqual('deployment-profile authority refusal mirror stale artifact refused', true, report.terminal_chain.deployment_profile_authority_refusal_mirror.stale_deployment_profile_artifact_refused_before_service_proof);
assertEqual('deployment-profile authority refusal mirror profile mismatch refused', true, report.terminal_chain.deployment_profile_authority_refusal_mirror.profile_recognition_mismatch_refused_before_service_proof);
assertEqual('deployment-profile authority refusal mirror latest selection refused', true, report.terminal_chain.deployment_profile_authority_refusal_mirror.latest_profile_selection_refused_before_service_proof);
assertEqual('deployment-profile authority refusal mirror request authority refused', true, report.terminal_chain.deployment_profile_authority_refusal_mirror.request_stream_authority_material_refused_before_service_proof);
assertEqual('deployment-profile authority refusal mirror no current-machine governance', false, report.terminal_chain.deployment_profile_authority_refusal_mirror.current_machine_governance);
assertEqual('deployment-profile authority refusal mirror no production authority', false, report.terminal_chain.deployment_profile_authority_refusal_mirror.production_authority);
assertEqual('deployment-profile authority refusal mirror no external attestation', false, report.terminal_chain.deployment_profile_authority_refusal_mirror.external_attestation);
assertEqual('required recognition refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.generated_service_proof.required_recognition_refusal_cases.length);
assertEqual('observed recognition refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.generated_service_proof.observed_recognition_refusal_cases.length);
assertEqual('first observed recognition refusal case', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES[0], report.generated_service_proof.observed_recognition_refusal_cases[0].case_id);
assertEqual('first observed recognition refusal reason', 'receipt_missing', report.generated_service_proof.observed_recognition_refusal_cases[0].reason_code);
assertEqual('last observed recognition refusal case', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES[17], report.generated_service_proof.observed_recognition_refusal_cases[17].case_id);
assertEqual('last observed recognition refusal reason', 'agent_supplied_authority_material', report.generated_service_proof.observed_recognition_refusal_cases[17].reason_code);
assert('observed recognition refusals are before mutation', report.generated_service_proof.observed_recognition_refusal_cases.every((item) => item.refused_before_mutation === true));
assertEqual('required authority refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.generated_service_proof.required_authority_refusal_cases.length);
assertEqual('observed authority refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.generated_service_proof.observed_authority_refusal_cases.length);
assertEqual('first observed authority refusal case', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES[0], report.generated_service_proof.observed_authority_refusal_cases[0].case_id);
assert('observed authority refusals precede consumption and mutation', report.generated_service_proof.observed_authority_refusal_cases.every((item) => item.refused_before_consumption_and_mutation === true));
for (const [name, expected] of Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS)) {
  assertEqual(`named refusal ${name} case`, expected.case_id, report.terminal_chain.named_receipt_refusals[name].case_id);
  assertEqual(`named refusal ${name} reason`, expected.reason_code, report.terminal_chain.named_receipt_refusals[name].reason_code);
  assertEqual(`named refusal ${name} before mutation`, true, report.terminal_chain.named_receipt_refusals[name].refused_before_mutation);
}
for (const [groupName, expectedCases] of Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)) {
  const group = report.terminal_chain.recognition_refusal_groups[groupName];
  assertEqual(`recognition refusal group ${groupName} count`, expectedCases.length, group.case_count);
  assertEqual(`recognition refusal group ${groupName} before mutation`, true, group.all_refused_before_mutation);
  expectedCases.forEach((expected, index) => {
    assertEqual(`recognition refusal group ${groupName} case ${index} id`, expected.case_id, group.cases[index].case_id);
    assertEqual(`recognition refusal group ${groupName} case ${index} reason`, expected.reason_code, group.cases[index].reason_code);
    assertEqual(`recognition refusal group ${groupName} case ${index} before mutation`, true, group.cases[index].refused_before_mutation);
  });
}

section('disposable install and generated evidence boundaries');
assertEqual('install root kind', 'launcher-owned-disposable-proof-root', report.disposable_installation.install_root_kind);
assertEqual('install root path omitted', null, report.disposable_installation.install_root_path_in_report);
assertEqual('profile copy written', true, report.disposable_installation.profile_copy_written);
assertEqual('active profile index written', true, report.disposable_installation.active_profile_index_written);
assertEqual('selected by explicit id and sha', true, report.disposable_installation.selected_by_explicit_id_and_sha);
assertEqual('does not select latest profile', false, report.disposable_installation.selects_latest_profile);
assertEqual('disposable root removed after run', true, report.disposable_installation.disposable_root_removed_after_run);
assertEqual('preflight verified', true, report.generated_preflight.verified);
assertEqual('preflight read only', true, report.generated_preflight.read_only);
assertEqual('preflight source does not claim downstream refusal', false, report.generated_preflight.downstream_refusal_proven);
assertEqual('preflight no current machine governance', false, report.generated_preflight.current_machine_governance_proven);
assertEqual('service proof artifact verified', true, report.generated_service_proof.artifact_verification_verified);
assertEqual('service proof source preflight hash bound', report.generated_preflight.artifact_body_sha256, report.generated_service_proof.source_preflight_body_sha256);
assertEqual('service proof artifact hash bound', report.generated_service_proof.artifact_body_sha256, report.generated_service_proof.verification_body_sha256);
assertEqual('nested binding preflight type', 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1', report.terminal_chain.nested_artifact_binding.generated_preflight_artifact_type);
assertEqual('nested binding service proof type', 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1', report.terminal_chain.nested_artifact_binding.generated_service_proof_artifact_type);
assertEqual('nested binding preflight hash bound', true, report.terminal_chain.nested_artifact_binding.preflight_artifact_hash_bound);
assertEqual('nested binding service source preflight hash bound', true, report.terminal_chain.nested_artifact_binding.service_proof_source_preflight_hash_bound);
assertEqual('nested binding service artifact hash bound', true, report.terminal_chain.nested_artifact_binding.service_artifact_hash_bound);
assertEqual('nested binding service artifact verification bound', true, report.terminal_chain.nested_artifact_binding.service_artifact_verification_bound_to_service_proof);
assertEqual('nested binding no current-machine governance', false, report.terminal_chain.nested_artifact_binding.proves_current_machine_governance);
assertEqual('nested binding no production downstream', false, report.terminal_chain.nested_artifact_binding.proves_production_downstream_recognition);
assertEqual('service runtime started', true, report.generated_service_proof.runtime_service_started);
assertEqual('service disposable config written', true, report.generated_service_proof.disposable_runtime_config_written);
assertEqual('service persistent config false', false, report.generated_service_proof.persistent_runtime_config_written);
assertEqual('service current machine false', false, report.generated_service_proof.current_machine_governance_proven);
assertEqual('service production recognition false', false, report.generated_service_proof.production_downstream_recognition);
assertEqual('same-process signed-payload replay refused', true, report.generated_service_proof.same_process_signed_payload_replay_refused);
assertEqual('restart consumed-grant reuse refused', true, report.generated_service_proof.restart_consumed_authority_grant_refused);
assertEqual('state append burn observed', true, report.generated_service_proof.state_append_after_grant_commit_burn_observed);
assertEqual('metadata partial-commit burn observed', true, report.generated_service_proof.metadata_partial_commit_burn_observed);
assertEqual('store and anchor rollback refused against witness', true, report.generated_service_proof.store_and_anchor_rollback_refused_while_witness_ahead);
assertEqual('joint rollback detection remains false', false, report.generated_service_proof.store_anchor_and_witness_joint_rollback_detection);
assertEqual('joint rollback reopened grant reuse', true, report.generated_service_proof.joint_rollback_reopened_authority_grant_reuse);
assertEqual('local fixture rightful issuance path evidenced', true, report.generated_service_proof.fixture_rightful_issuance_path_evidenced);
assertEqual('generic rightful issuance remains false', false, report.generated_service_proof.rightful_issuance_proven);
assertEqual('portable rightful issuance remains false', false, report.generated_service_proof.portable_rightful_issuance_proven);
assertEqual('production rightful issuance remains false', false, report.generated_service_proof.production_rightful_issuance_proven);
assertEqual('lifecycle closure remains false', false, report.generated_service_proof.consequence_lifecycle_closed);

section('non-claims and side doors');
assertEqual('persistent profile not installed', false, report.side_door_report.persistent_runtime_profile_installed);
assertEqual('activation not performed', false, report.side_door_report.runtime_profile_activation_performed);
assertEqual('hook config not written', false, report.side_door_report.hook_configuration_written);
assertEqual('user config not written', false, report.side_door_report.user_config_written);
assertEqual('machine config not written', false, report.side_door_report.machine_config_written);
assertEqual('live runtime unchecked', false, report.side_door_report.live_runtime_profile_checked);
assertEqual('live records unchecked', false, report.side_door_report.live_records_system_checked);
assertEqual('production service unchecked', false, report.side_door_report.production_records_service_checked);
assertEqual('current-machine governance false', false, report.side_door_report.current_machine_governance_proven);
assertEqual('external attestation false', false, report.side_door_report.external_attestation);
assertEqual('sovereign recognition false', false, report.side_door_report.sovereign_recognition);
assertEqual('unrouted records unchecked', false, report.side_door_report.unrouted_records_paths_checked);
assertEqual('store anchor witness commit remains non-atomic', false, report.side_door_report.atomic_store_anchor_witness_commit);
assertEqual('host path TOCTOU remains open', false, report.side_door_report.host_filesystem_path_toctou_closed);
assertEqual('side door fixture rightful path evidenced', true, report.side_door_report.fixture_rightful_issuance_path_evidenced);
assertEqual('side door generic rightful false', false, report.side_door_report.rightful_issuance_proven);
assertEqual('side door lifecycle false', false, report.side_door_report.consequence_lifecycle_closed);
for (const boundary of REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_OPEN_BOUNDARIES) {
  assert(`open boundary present: ${boundary}`, report.known_open_boundaries.includes(boundary));
}
for (const claim of INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NON_CLAIMS) {
  assert(`non-claim present: ${claim}`, report.non_claims.includes(claim));
}
assert('json output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report, null, 2)));
assert('json omits private and temp paths', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\//.test(JSON.stringify(report)));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(JSON.stringify(report)));

section('formatters');
const summary = formatProtectedRecordsInstalledRuntimeProfileTerminalChainSummary(report);
assert('summary title present', summary.includes('ZLAR Protected Records Installed Runtime Profile Terminal Chain v1'));
assert('summary includes generated preflight', summary.includes('generated_preflight_consumed=true'));
assert('summary includes missing receipt refusal', summary.includes('missing_receipt_refused=true'));
assert('summary includes named refusal hash', summary.includes('named_receipt_refusals_sha256='));
assert('summary includes named refusal booleans', summary.includes('Named receipt refusals: missing=true; invalid=true; stale=true; stale_or_expired=true; unknown_issuer=true; wrong_policy=true; wrong_domain=true; wrong_tool=true'));
assert('summary includes recognition refusal groups hash', summary.includes('recognition_refusal_groups_sha256='));
assert('summary includes fixture grant powers', summary.includes('power_ids=bind_runtime_issuer_to_slot,issue_governed_action_receipt,issue_replacement_authority_grant,revoke_authority_grant'));
assert('summary includes ordered transition', summary.includes('Ordered transition binding: type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
assert('summary includes replay split', summary.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
assert('summary includes joint rollback side door', summary.includes('joint_rollback_reopened_authority_grant_reuse=true'));
assert('summary includes recognition refusal group booleans', summary.includes('Recognition refusal groups: no_usable_recognized_receipt_authority=true; recognized_receipt_scope_mismatch=true; route_or_request_authority_material_refused=true'));
assert('summary includes trusted registry binding', summary.includes('Trusted issuer registry recognition binding: verdict=RECOGNIZED'));
assert('summary includes trusted registry binding hash', summary.includes('binding_sha256='));
assert('summary includes trusted registry nonclaims', summary.includes('Trusted issuer registry recognition non-claims: live_trust_registry_state=false'));
assert('summary includes nested binding', summary.includes('nested_artifact_binding.preflight_artifact_hash_bound=true'));
assert('summary includes current-machine non-claim', summary.includes('current_machine_governance_proven=false'));
assert('summary output is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));

section('portable artifact and verification');
const artifact = buildProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(report);
assert('artifact passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact));
assertEqual('artifact type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE, artifact.artifact_type);
assertEqual('artifact canonicalization', 'zlar-canonical-json-v1', artifact.canonicalization);
assertEqual('artifact generator', 'zlar protected-records-installed-runtime-profile-terminal-chain --artifact', artifact.generator);
assertEqual('artifact hash scope', 'canonical artifact body without integrity', artifact.hash_scope);
assert('fresh artifact sha present', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
assertEqual('artifact embeds chain type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE, artifact.payload.chain.chain_type);
assert('artifact text is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact, null, 2)));

const parsedArtifact = parseProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactText(
  JSON.stringify(artifact, null, 2)
);
assert('parsed artifact passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(parsedArtifact));
assertEqual('parsed artifact sha stable', artifact.integrity.body_sha256, parsedArtifact.integrity.body_sha256);

const structuralVerification =
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(parsedArtifact);
assert('structural verification passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(structuralVerification));
assertEqual('structural verification scope exact', 'structural-self-integrity-only', structuralVerification.verification_scope);
assertEqual('structural verification outer artifact identity unmatched', false, structuralVerification.artifact_identity_sha256_matched);
assertEqual('structural verification outer fixture metadata unbound', false, structuralVerification.outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256);
assertEqual('structural verification registry signature identity unbound', false, structuralVerification.trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('structural verification receipt source identity unbound', false, structuralVerification.recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('structural verification recognized write claim false', false, structuralVerification.recognized_write_boarded);
assertEqual('structural verification fixture rightful claim false', false, structuralVerification.fixture_rightful_issuance_path_evidenced);
assertEqual('structural verification public fixture summary withheld', null, structuralVerification.public_safe_grant_summary);
assertEqual('structural verification signed payload identity withheld', null, structuralVerification.signed_payload_sha256);
assertEqual('structural verification boarded target identity withheld', null, structuralVerification.boarded_service_target_binding);
assertEqual('structural verification registry signature projection withheld', null, structuralVerification.trusted_issuer_registry_recognition_binding);
assertEqual('structural verification recognized source projection withheld', null, structuralVerification.recognized_receipt_path_evidence);
const verification = verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
  parsedArtifact,
  { expectedArtifactBodySha256: parsedArtifact.integrity.body_sha256 }
);
assert('verification passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(verification));
assertEqual('verification structural self-integrity true', true, verification.structural_self_integrity_verified);
assertEqual('verification outer identity requires expected sha', true, verification.artifact_identity_match_requires_expected_sha256);
assertEqual('verification outer identity matched', true, verification.artifact_identity_sha256_matched);
assertEqual('verification outer fixture metadata bound', true, verification.outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256);
assertEqual('verification registry signature identity bound', true, verification.trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('verification receipt source identity bound', true, verification.recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
assertEqual('verification pinned scope exact', 'expected-terminal-artifact-identity-bound-local-fixture-projection', verification.verification_scope);
assertEqual('verification embedded service structural true', true, verification.embedded_service_artifact_structural_self_integrity_verified);
assertEqual('verification embedded service expected sha exact', report.generated_service_proof.artifact_body_sha256, verification.embedded_service_artifact_expected_body_sha256);
assertEqual('verification embedded service expected sha matched', true, verification.embedded_service_artifact_expected_body_sha256_matched);
assertEqual('verification public contract exact', JSON.stringify(report.terminal_chain.public_grant_contract), JSON.stringify(verification.public_grant_contract));
assertEqual('verification public contract sha exact', report.terminal_chain.public_grant_contract_sha256, verification.public_grant_contract_sha256);
assertEqual('verification accepted crossing evidence sha exact', report.terminal_chain.accepted_crossing_evidence_sha256, verification.accepted_crossing_evidence_sha256);
assertEqual('verification type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification verified true', true, verification.verified);
assertEqual('fresh verification body sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
assertEqual('verification generated preflight true', true, verification.generated_preflight_artifact_consumed_by_service_proof);
assertEqual('verification service proof bound', true, verification.service_proof_bound_to_generated_preflight);
assertEqual('verification recognized write boarded', true, verification.recognized_write_boarded);
assertEqual('verification missing receipt refused', true, verification.missing_receipt_refused_before_mutation);
assertEqual('verification all recognition refusals before mutation', true, verification.all_required_recognition_refusals_before_mutation);
assertEqual('verification recognition refusal taxonomy hash bound', report.terminal_chain.recognition_refusal_taxonomy_sha256, verification.recognition_refusal_taxonomy_sha256);
assertEqual('verification all authority refusals before consumption and mutation', true, verification.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('verification authority refusal taxonomy hash bound', report.terminal_chain.authority_refusal_taxonomy_sha256, verification.authority_refusal_taxonomy_sha256);
assertEqual('verification public grant summary exact', JSON.stringify(report.terminal_chain.public_safe_grant_summary), JSON.stringify(verification.public_safe_grant_summary));
assertEqual('verification public grant powers exact', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS), JSON.stringify(verification.public_safe_grant_summary.power_ids));
assertEqual('verification ordered transition type exact', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', verification.ordered_transition_binding_type);
assertEqual('verification named receipt refusals hash bound', report.terminal_chain.named_receipt_refusals_sha256, verification.named_receipt_refusals_sha256);
assertEqual('verification recognition refusal groups hash bound', report.terminal_chain.recognition_refusal_groups_sha256, verification.recognition_refusal_groups_sha256);
assertEqual('verification recognition contract digest bound', report.terminal_chain.recognition_contract_sha256, verification.recognition_contract_sha256);
assertEqual('verification boarded target binding preserved', report.terminal_chain.boarded_service_target_binding_sha256, verification.boarded_service_target_binding_sha256);
assertEqual('verification boarded target binding recomputable', sha256hex(canonicalize({ boarded_service_target_binding: verification.boarded_service_target_binding })), verification.boarded_service_target_binding_sha256);
assertEqual('verification boarded target handle preserved', report.terminal_chain.boarded_service_target_binding.target_handle, verification.boarded_service_target_binding.target_handle);
assertEqual('verification boarded target no profile authority', false, verification.boarded_service_target_binding.profile_wide_target_authority_proven);
assertEqual('verification boarded target no rightful issuance', false, verification.boarded_service_target_binding.rightful_issuance_proven);
assertEqual('verification boarded target no live target', false, verification.boarded_service_target_binding.live_target_proven);
assertEqual('verification boarded target no current machine', false, verification.boarded_service_target_binding.current_machine_governance_proven);
assertEqual('verification boarded target no lifecycle closure', false, verification.boarded_service_target_binding.consequence_lifecycle_closed);
assertEqual('verification trusted registry binding verdict', 'RECOGNIZED', verification.trusted_issuer_registry_recognition_binding.verdict);
assertEqual('verification trusted registry binding recognized', true, verification.trusted_issuer_registry_recognition_binding.recognized);
assertEqual('verification trusted registry binding rule evaluated', true, verification.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated);
assertEqual('verification trusted registry binding contract hash bound', true, verification.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound);
assertEqual('verification trusted registry local refusal case count', REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length, verification.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.case_count);
assertEqual('verification trusted registry local refusals all refused', true, verification.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.all_refused);
assertEqual('verification trusted registry local refusal hash preserved', report.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256, verification.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals_sha256);
assertEqual('verification trusted registry binding no live registry', false, verification.trusted_issuer_registry_recognition_binding.live_trust_registry_state);
assertEqual('verification trusted registry binding no public attestation', false, verification.trusted_issuer_registry_recognition_binding.public_external_attestation);
assertEqual('verification trusted registry binding no production authority', false, verification.trusted_issuer_registry_recognition_binding.production_authority);
assertEqual('verification trusted registry binding sha bound', report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256, verification.trusted_issuer_registry_recognition_binding_sha256);
assertEqual('verification trusted registry receipt is not boarded receipt', false, verification.trusted_issuer_registry_recognition_binding.registry_receipt_is_boarded_service_receipt);
assertEqual('verification trusted registry receipt is not service authority', false, verification.trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write);
assertEqual('verification trusted registry receipt detail role is distinct', true, verification.trusted_issuer_registry_recognition_binding.receipt_detail_hash_roles_distinct);
assertEqual('verification recognized receipt path verdict', 'RECOGNIZED', verification.recognized_receipt_path_evidence.verdict);
assertEqual('verification recognized receipt path source binding sha', verification.trusted_issuer_registry_recognition_binding_sha256, verification.recognized_receipt_path_evidence.source_binding_sha256);
assertEqual('verification recognized receipt path evidence sha bound', report.terminal_chain.recognized_receipt_path_evidence_sha256, verification.recognized_receipt_path_evidence_sha256);
assertEqual('verification recognized receipt path bound to artifact body', true, verification.recognized_receipt_path_evidence_bound_to_artifact_body);
assertEqual('verification recognized receipt path envelope omitted', false, verification.recognized_receipt_path_evidence.receipt_envelope_included);
assertEqual('verification recognized path boarded target sha', verification.boarded_service_target_binding_sha256, verification.recognized_receipt_path_evidence.boarded_service_target_binding_sha256);
assertEqual('verification recognized path boarded target handle', verification.boarded_service_target_binding.target_handle, verification.recognized_receipt_path_evidence.boarded_service_target_handle);
assertEqual('verification recognized path post-effect metadata only', 'post-effect-hash-bound-metadata-only', verification.recognized_receipt_path_evidence.boarded_service_target_metadata_role);
assertEqual('verification runtime profile sha bound', report.runtime_profile.profile_sha256, verification.runtime_profile_sha256);
assertEqual('verification deployment-profile authority refusal mirror source', report.terminal_chain.deployment_profile_authority_refusal_mirror.source, verification.deployment_profile_authority_refusal_mirror.source);
assertEqual('verification deployment-profile authority refusal mirror source proof sha', report.terminal_chain.deployment_profile_authority_refusal_mirror.source_proof_sha256, verification.deployment_profile_authority_refusal_mirror.source_proof_sha256);
assertEqual('verification deployment-profile authority refusal mirror source runtime profile sha', report.runtime_profile.profile_sha256, verification.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha256);
assertEqual('verification deployment-profile authority refusal mirror profile sha matches', true, verification.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha_matches_terminal_chain);
assertEqual('verification deployment-profile authority refusal mirror case count', REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length, verification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_count);
assertEqual(
  'verification deployment-profile authority refusal mirror case IDs',
  JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES),
  JSON.stringify(verification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_ids)
);
assertEqual('verification deployment-profile authority refusal mirror before service proof', true, verification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusals_before_service_proof);
assertEqual('verification deployment-profile authority refusal mirror service proof not started', false, verification.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_service_proof_started);
assertEqual('verification deployment-profile authority refusal mirror no production authority', false, verification.deployment_profile_authority_refusal_mirror.production_authority);
assertEqual('verification observed recognition refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, verification.observed_recognition_refusal_cases.length);
assertEqual('verification observed authority refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length, verification.observed_authority_refusal_cases.length);
assertEqual('verification same-process signed-payload replay refused', true, verification.same_process_signed_payload_replay_refused);
assertEqual('verification restart consumed grant refused', true, verification.restart_consumed_authority_grant_refused);
assertEqual('verification state append burn observed', true, verification.state_append_after_grant_commit_burn_observed);
assertEqual('verification metadata burn observed', true, verification.metadata_partial_commit_burn_observed);
assertEqual('verification joint rollback detection false', false, verification.store_anchor_and_witness_joint_rollback_detection);
assertEqual('verification joint rollback reopened reuse', true, verification.joint_rollback_reopened_authority_grant_reuse);
assertEqual('verification fixture rightful path true', true, verification.fixture_rightful_issuance_path_evidenced);
assertEqual('verification generic rightful false', false, verification.rightful_issuance_proven);
assertEqual('verification portable rightful false', false, verification.portable_rightful_issuance_proven);
assertEqual('verification production rightful false', false, verification.production_rightful_issuance_proven);
assertEqual('verification lifecycle false', false, verification.consequence_lifecycle_closed);
assertEqual('verification nested binding preflight type', report.terminal_chain.nested_artifact_binding.generated_preflight_artifact_type, verification.nested_artifact_binding.generated_preflight_artifact_type);
assertEqual('verification nested binding service proof type', report.terminal_chain.nested_artifact_binding.generated_service_proof_artifact_type, verification.nested_artifact_binding.generated_service_proof_artifact_type);
assertEqual('verification nested binding preflight body sha', report.terminal_chain.nested_artifact_binding.generated_preflight_artifact_body_sha256, verification.nested_artifact_binding.generated_preflight_artifact_body_sha256);
assertEqual('verification nested binding service body sha', report.terminal_chain.nested_artifact_binding.generated_service_proof_artifact_body_sha256, verification.nested_artifact_binding.generated_service_proof_artifact_body_sha256);
assertEqual('verification nested binding preflight hash bound', true, verification.nested_artifact_binding.preflight_artifact_hash_bound);
assertEqual('verification nested binding service source preflight hash bound', true, verification.nested_artifact_binding.service_proof_source_preflight_hash_bound);
assertEqual('verification nested binding service artifact hash bound', true, verification.nested_artifact_binding.service_artifact_hash_bound);
assertEqual('verification nested binding service artifact verification bound', true, verification.nested_artifact_binding.service_artifact_verification_bound_to_service_proof);
assertEqual('verification nested binding no attestation', false, verification.nested_artifact_binding.creates_public_external_attestation);
assertEqual('verification nested binding no current-machine governance', false, verification.nested_artifact_binding.proves_current_machine_governance);
assertEqual('verification nested binding no production downstream', false, verification.nested_artifact_binding.proves_production_downstream_recognition);
for (const [name, expected] of Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS)) {
  assertEqual(`verification named refusal ${name} case`, expected.case_id, verification.named_receipt_refusals[name].case_id);
  assertEqual(`verification named refusal ${name} reason`, expected.reason_code, verification.named_receipt_refusals[name].reason_code);
  assertEqual(`verification named refusal ${name} before mutation`, true, verification.named_receipt_refusals[name].refused_before_mutation);
}
for (const [groupName, expectedCases] of Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_RECOGNITION_REFUSAL_GROUPS)) {
  const group = verification.recognition_refusal_groups[groupName];
  assertEqual(`verification recognition refusal group ${groupName} count`, expectedCases.length, group.case_count);
  assertEqual(`verification recognition refusal group ${groupName} before mutation`, true, group.all_refused_before_mutation);
}
assertEqual('verification production recognition false', false, verification.production_downstream_recognition);
const verificationSummary = formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(verification);
const structuralVerificationSummary =
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
    structuralVerification
  );
assert('structural verification summary names structural-only scope', structuralVerificationSummary.includes('verification_scope=structural-self-integrity-only'));
assert('structural verification summary keeps outer fixture claim false', structuralVerificationSummary.includes('fixture_rightful_issuance_path_evidenced=false'));
assert('verification summary says verified', verificationSummary.includes('verified=true'));
assert('verification summary limits outer identity to structural', verificationSummary.includes('artifact_identity_match_requires_expected_sha256=true'));
assert('verification summary includes embedded service pin', verificationSummary.includes('embedded_service_artifact.expected_body_sha256_matched=true'));
assert('verification summary includes refusal', verificationSummary.includes('missing_receipt_refused_before_mutation=true'));
assert('verification summary includes recognition contract digest', verificationSummary.includes('recognition_contract_sha256='));
assert('verification summary includes nested preflight binding', verificationSummary.includes('nested_artifact_binding.preflight_artifact_hash_bound=true'));
assert('verification summary includes nested service binding', verificationSummary.includes('nested_artifact_binding.service_artifact_hash_bound=true'));
assert('verification summary includes trusted registry verdict', verificationSummary.includes('trusted_issuer_registry_recognition_binding.verdict=RECOGNIZED'));
assert('verification summary includes trusted registry binding hash', verificationSummary.includes('trusted_issuer_registry_recognition_binding.binding_sha256='));
assert('verification summary includes trusted registry refusal hash', verificationSummary.includes('trusted_issuer_registry_recognition_binding.refusals_sha256='));
assert('verification summary includes recognized receipt path evidence', verificationSummary.includes('recognized_receipt_path_evidence.verdict=RECOGNIZED'));
assert('verification summary includes recognized receipt path sha', verificationSummary.includes('recognized_receipt_path_evidence.sha256='));
assert('verification summary includes deployment-profile authority mirror', verificationSummary.includes('deployment_profile_authority_refusal_mirror.before_service_proof=true'));
assert('verification summary includes deployment-profile authority source proof hash', verificationSummary.includes('deployment_profile_authority_refusal_mirror.source_proof_sha256='));
assert('verification summary includes named refusal hash', verificationSummary.includes('named_receipt_refusals_sha256='));
assert('verification summary includes recognition refusal groups hash', verificationSummary.includes('recognition_refusal_groups_sha256='));
assert('verification summary includes grant powers', verificationSummary.includes('public_safe_grant_summary.power_ids=bind_runtime_issuer_to_slot,issue_governed_action_receipt,issue_replacement_authority_grant,revoke_authority_grant'));
assert('verification summary includes public contract sha', verificationSummary.includes('public_grant_contract.sha256='));
assert('verification summary includes accepted crossing', verificationSummary.includes('accepted_crossing.evidence_sha256='));
assert('verification summary includes ordered transition', verificationSummary.includes('ordered_transition_binding.type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
assert('verification summary includes replay split', verificationSummary.includes('same_process_signed_payload_replay_refused=true'));
assert('verification summary includes joint rollback side door', verificationSummary.includes('joint_rollback_reopened_authority_grant_reuse=true'));
assert('verification summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(verificationSummary));

const artifactSummary = formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactSummary(artifact);
assert('artifact summary includes sha', artifactSummary.includes(artifact.integrity.body_sha256));
assert('artifact summary is privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(artifactSummary));

const alternateReport = runProtectedRecordsInstalledRuntimeProfileTerminalChain(
  plan,
  profile
);
const coherentlyDifferentArtifact =
  buildProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(alternateReport);
assert('coherently different terminal artifact remains structurally valid', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(coherentlyDifferentArtifact));
assert('coherently different terminal artifact has a different run-local identity', coherentlyDifferentArtifact.integrity.body_sha256 !== artifact.integrity.body_sha256);
const coherentlyDifferentStructuralVerification =
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    coherentlyDifferentArtifact
  );
assertEqual('coherently different terminal artifact stays structural when unpinned', false, coherentlyDifferentStructuralVerification.fixture_rightful_issuance_path_evidenced);
assertThrows('coherently different terminal artifact refuses the original expected outer identity', () => {
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    coherentlyDifferentArtifact,
    { expectedArtifactBodySha256: artifact.integrity.body_sha256 }
  );
}, 'expected SHA-256 identity');

section('committed sample artifact');
const sampleArtifact = parseProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactText(
  readFileSync(SAMPLE_ARTIFACT_PATH, 'utf8')
);
assert('sample artifact passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(sampleArtifact));
assertEqual('sample artifact sha stable', SAMPLE_ARTIFACT_SHA256, sampleArtifact.integrity.body_sha256);
const sampleVerification = verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(sampleArtifact);
assert('sample verification passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(sampleVerification));
assertEqual('sample verification body sha stable', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);

section('tamper refusal');
const resealedNestedGrantPower = structuredClone(artifact);
resealedNestedGrantPower.payload.chain.nested_artifacts.generated_service_proof_artifact
  .payload.proof.authority_contract.public_grant_contract.powers[0].power_id =
    'invented_power';
resealNestedServiceArtifact(resealedNestedGrantPower);
assertThrows('coherently re-sealed nested public grant power is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    resealedNestedGrantPower
  );
}, 'service proof drifted');

const resealedNestedSignedPayload = structuredClone(artifact);
resealedNestedSignedPayload.payload.chain.nested_artifacts
  .generated_service_proof_artifact.payload.proof.accepted_crossing_evidence
  .verified_signed_payload_base64url = 'e30';
resealNestedServiceArtifact(resealedNestedSignedPayload);
assertThrows('coherently re-sealed nested signed payload is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    resealedNestedSignedPayload
  );
}, 'signed payload');

const resealedNestedSourceProfile = structuredClone(artifact);
resealedNestedSourceProfile.payload.chain.nested_artifacts
  .generated_service_proof_artifact.payload.proof.target_binding.source_profile_id =
    'forged-profile';
resealNestedServiceArtifact(resealedNestedSourceProfile);
assertThrows('coherently re-sealed nested source profile is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    resealedNestedSourceProfile
  );
}, 'target binding reconstruction');

const resealedServiceExpectedSha = structuredClone(artifact);
resealedServiceExpectedSha.payload.chain.generated_service_proof
  .expected_service_proof_artifact_body_sha256 = 'f'.repeat(64);
resealedServiceExpectedSha.payload.chain.terminal_chain
  .expected_generated_service_proof_artifact_body_sha256 = 'f'.repeat(64);
resealTerminalArtifact(resealedServiceExpectedSha);
assertThrows('re-sealed service expected SHA mismatch is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    resealedServiceExpectedSha
  );
}, 'service proof drifted');

const resealedPublicContractSummarySplit = structuredClone(artifact);
resealedPublicContractSummarySplit.payload.chain.terminal_chain
  .public_grant_contract.scope.profile_id = 'forged-profile';
resealTerminalArtifact(resealedPublicContractSummarySplit);
assertThrows('re-sealed public contract and summary split is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    resealedPublicContractSummarySplit
  );
}, 'service proof drifted');

const tampered = structuredClone(artifact);
tampered.payload.chain.generated_service_proof.production_downstream_recognition = true;
assertThrows('tampered artifact is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(tampered);
}, 'service proof drifted');

const taxonomyTampered = structuredClone(artifact);
taxonomyTampered.payload.chain.generated_service_proof.observed_recognition_refusal_cases[0].reason_code =
  'receipt_invalid';
assertThrows('taxonomy-tampered artifact is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(taxonomyTampered);
}, 'refusal taxonomy');

const grantPowersTampered = structuredClone(artifact);
grantPowersTampered.payload.chain.terminal_chain.public_safe_grant_summary.power_ids =
  grantPowersTampered.payload.chain.terminal_chain.public_safe_grant_summary.power_ids.slice(0, 3);
grantPowersTampered.integrity.body_sha256 =
  sha256hex(canonicalize(grantPowersTampered.payload));
assertThrows('missing fixture grant power with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(grantPowersTampered);
}, 'power ids');

const orderedTransitionTampered = structuredClone(artifact);
orderedTransitionTampered.payload.chain.generated_service_proof.ordered_transition_binding_sha256 =
  'f'.repeat(64);
orderedTransitionTampered.payload.chain.terminal_chain.ordered_transition_binding_sha256 =
  'f'.repeat(64);
orderedTransitionTampered.integrity.body_sha256 =
  sha256hex(canonicalize(orderedTransitionTampered.payload));
assertThrows('forged ordered transition hash with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(orderedTransitionTampered);
}, 'nested service proof artifact binding');

const genericRightfulClaimTampered = structuredClone(artifact);
genericRightfulClaimTampered.payload.chain.terminal_chain.rightful_issuance_proven = true;
genericRightfulClaimTampered.integrity.body_sha256 =
  sha256hex(canonicalize(genericRightfulClaimTampered.payload));
assertThrows('generic rightful issuance claim with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(genericRightfulClaimTampered);
}, 'binding drifted');

const recognitionGroupTampered = structuredClone(artifact);
recognitionGroupTampered.payload.chain.terminal_chain.recognition_refusal_groups.recognized_receipt_scope_mismatch.cases[0].reason_code =
  'receipt_missing';
assertThrows('recognition-group-tampered artifact is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(recognitionGroupTampered);
}, 'recognition refusal group');

const deploymentProfileMirrorTampered = structuredClone(artifact);
deploymentProfileMirrorTampered.payload.chain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_ids =
  deploymentProfileMirrorTampered.payload.chain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_ids.slice(1);
deploymentProfileMirrorTampered.payload.chain.terminal_chain.deployment_profile_authority_refusal_mirror.deployment_profile_authority_refusal_case_count -= 1;
deploymentProfileMirrorTampered.integrity.body_sha256 =
  sha256hex(canonicalize(deploymentProfileMirrorTampered.payload));
assertThrows('deployment-profile authority mirror tampered artifact is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(deploymentProfileMirrorTampered);
}, 'deployment-profile authority refusal mirror');

const deploymentProfileMirrorProfileShaTampered = structuredClone(artifact);
deploymentProfileMirrorProfileShaTampered.payload.chain.terminal_chain.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha_matches_terminal_chain =
  false;
deploymentProfileMirrorProfileShaTampered.integrity.body_sha256 =
  sha256hex(canonicalize(deploymentProfileMirrorProfileShaTampered.payload));
assertThrows('deployment-profile authority mirror profile sha mismatch with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(deploymentProfileMirrorProfileShaTampered);
}, 'deployment-profile authority refusal mirror');

const deploymentProfileMirrorSourceProofShaTampered = structuredClone(artifact);
deploymentProfileMirrorSourceProofShaTampered.payload.chain.terminal_chain.deployment_profile_authority_refusal_mirror.source_proof_sha256 =
  'f'.repeat(64);
deploymentProfileMirrorSourceProofShaTampered.integrity.body_sha256 =
  sha256hex(canonicalize(deploymentProfileMirrorSourceProofShaTampered.payload));
assertThrows('deployment-profile authority mirror source proof hash drift with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(deploymentProfileMirrorSourceProofShaTampered);
}, 'deployment-profile authority refusal mirror');

const deploymentProfileMirrorSourceProfileShaTampered = structuredClone(artifact);
deploymentProfileMirrorSourceProfileShaTampered.payload.chain.terminal_chain.deployment_profile_authority_refusal_mirror.source_runtime_profile_sha256 =
  'f'.repeat(64);
deploymentProfileMirrorSourceProfileShaTampered.integrity.body_sha256 =
  sha256hex(canonicalize(deploymentProfileMirrorSourceProfileShaTampered.payload));
assertThrows('deployment-profile authority mirror source profile hash drift with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(deploymentProfileMirrorSourceProfileShaTampered);
}, 'deployment-profile authority refusal mirror');

const forgedInnerPreflightHash = structuredClone(artifact);
forgedInnerPreflightHash.payload.chain.generated_preflight.artifact_body_sha256 =
  'e'.repeat(64);
forgedInnerPreflightHash.payload.chain.generated_service_proof.source_preflight_body_sha256 =
  'e'.repeat(64);
forgedInnerPreflightHash.integrity.body_sha256 =
  sha256hex(canonicalize(forgedInnerPreflightHash.payload));
assertThrows('forged inner preflight artifact hash with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedInnerPreflightHash);
}, 'service proof drifted');

const forgedInnerServiceHash = structuredClone(artifact);
forgedInnerServiceHash.payload.chain.generated_service_proof.artifact_body_sha256 =
  'f'.repeat(64);
forgedInnerServiceHash.payload.chain.generated_service_proof.verification_body_sha256 =
  'f'.repeat(64);
forgedInnerServiceHash.integrity.body_sha256 =
  sha256hex(canonicalize(forgedInnerServiceHash.payload));
assertThrows('forged inner service artifact hash with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedInnerServiceHash);
}, 'service proof drifted');

const forgedBoardedTargetEffect = structuredClone(artifact);
forgedBoardedTargetEffect.payload.chain.generated_service_proof.boarded_service_target_binding.target_effect_sha256 =
  'f'.repeat(64);
forgedBoardedTargetEffect.payload.chain.terminal_chain.boarded_service_target_binding.target_effect_sha256 =
  'f'.repeat(64);
const forgedBoardedTargetEffectSha = sha256hex(canonicalize({
  boarded_service_target_binding:
    forgedBoardedTargetEffect.payload.chain.generated_service_proof
      .boarded_service_target_binding,
}));
forgedBoardedTargetEffect.payload.chain.generated_service_proof.boarded_service_target_binding_sha256 =
  forgedBoardedTargetEffectSha;
forgedBoardedTargetEffect.payload.chain.terminal_chain.boarded_service_target_binding_sha256 =
  forgedBoardedTargetEffectSha;
forgedBoardedTargetEffect.integrity.body_sha256 =
  sha256hex(canonicalize(forgedBoardedTargetEffect.payload));
assertThrows('forged boarded target effect with recomputed binding and outer hashes is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedBoardedTargetEffect);
}, 'nested service proof artifact binding');

const forgedTrustedRegistryBinding = structuredClone(artifact);
forgedTrustedRegistryBinding.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound =
  false;
forgedTrustedRegistryBinding.integrity.body_sha256 =
  sha256hex(canonicalize(forgedTrustedRegistryBinding.payload));
assertThrows('forged trusted registry binding with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedTrustedRegistryBinding);
}, 'trusted issuer registry recognition binding drifted');

const forgedTrustedRegistryReceiptBinding = structuredClone(artifact);
forgedTrustedRegistryReceiptBinding.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound =
  false;
forgedTrustedRegistryReceiptBinding.integrity.body_sha256 =
  sha256hex(canonicalize(forgedTrustedRegistryReceiptBinding.payload));
assertThrows('forged trusted registry receipt binding with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedTrustedRegistryReceiptBinding);
}, 'trusted issuer registry recognition binding drifted');

const forgedRegistryReceiptAuthorityRole = structuredClone(artifact);
forgedRegistryReceiptAuthorityRole.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write =
  true;
forgedRegistryReceiptAuthorityRole.integrity.body_sha256 =
  sha256hex(canonicalize(forgedRegistryReceiptAuthorityRole.payload));
assertThrows('forged registry receipt service authority with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedRegistryReceiptAuthorityRole);
}, 'trusted issuer registry recognition binding drifted');

const forgedTrustedRegistryRefusalReason = structuredClone(artifact);
forgedTrustedRegistryRefusalReason.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.cases[1].reason_code =
  'recognized';
forgedTrustedRegistryRefusalReason.integrity.body_sha256 =
  sha256hex(canonicalize(forgedTrustedRegistryRefusalReason.payload));
assertThrows('forged trusted registry refusal reason with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedTrustedRegistryRefusalReason);
}, 'trusted issuer registry recognition refusals case drifted');

const forgedTrustedRegistryRefusalCount = structuredClone(artifact);
forgedTrustedRegistryRefusalCount.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.trusted_issuer_registry_recognition_refusals.case_count =
  1;
forgedTrustedRegistryRefusalCount.integrity.body_sha256 =
  sha256hex(canonicalize(forgedTrustedRegistryRefusalCount.payload));
assertThrows('forged trusted registry refusal count with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedTrustedRegistryRefusalCount);
}, 'trusted issuer registry recognition refusals drifted');

const forgedTrustedRegistryPublicSafetyFlag = structuredClone(artifact);
forgedTrustedRegistryPublicSafetyFlag.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.public_external_attestation =
  true;
forgedTrustedRegistryPublicSafetyFlag.integrity.body_sha256 =
  sha256hex(canonicalize(forgedTrustedRegistryPublicSafetyFlag.payload));
assertThrows('forged trusted registry public safety flag with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedTrustedRegistryPublicSafetyFlag);
}, 'trusted issuer registry recognition binding drifted');

const missingRecognizedReceiptPathEvidence = structuredClone(artifact);
delete missingRecognizedReceiptPathEvidence.payload.chain.terminal_chain.recognized_receipt_path_evidence;
missingRecognizedReceiptPathEvidence.integrity.body_sha256 =
  sha256hex(canonicalize(missingRecognizedReceiptPathEvidence.payload));
assertThrows('missing recognized receipt path evidence with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(missingRecognizedReceiptPathEvidence);
}, 'unexpected fields');

const summaryOnlyRecognizedReceiptPathEvidence = structuredClone(artifact);
summaryOnlyRecognizedReceiptPathEvidence.payload.chain.terminal_chain.recognized_receipt_path_evidence = {
  verdict: 'RECOGNIZED',
};
summaryOnlyRecognizedReceiptPathEvidence.integrity.body_sha256 =
  sha256hex(canonicalize(summaryOnlyRecognizedReceiptPathEvidence.payload));
assertThrows('summary-only recognized receipt path evidence with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(summaryOnlyRecognizedReceiptPathEvidence);
}, 'unexpected fields');

const forgedRecognizedPathTargetHandle = structuredClone(artifact);
forgedRecognizedPathTargetHandle.payload.chain.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_handle =
  `zlar-target:v1:logical-fixture:${'f'.repeat(64)}`;
forgedRecognizedPathTargetHandle.integrity.body_sha256 =
  sha256hex(canonicalize(forgedRecognizedPathTargetHandle.payload));
assertThrows('forged recognized path target handle with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(forgedRecognizedPathTargetHandle);
}, 'recognized receipt path evidence drifted');

const tamperedRecognizedReceiptPathEvidenceHash = structuredClone(artifact);
tamperedRecognizedReceiptPathEvidenceHash.payload.chain.terminal_chain.recognized_receipt_path_evidence_sha256 =
  '0'.repeat(64);
tamperedRecognizedReceiptPathEvidenceHash.integrity.body_sha256 =
  sha256hex(canonicalize(tamperedRecognizedReceiptPathEvidenceHash.payload));
assertThrows('tampered recognized receipt path evidence hash with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(tamperedRecognizedReceiptPathEvidenceHash);
}, 'terminal chain binding drifted');

const mismatchedRecognizedReceiptPathEvidence = structuredClone(artifact);
mismatchedRecognizedReceiptPathEvidence.payload.chain.terminal_chain.recognized_receipt_path_evidence.source_binding_sha256 =
  'f'.repeat(64);
mismatchedRecognizedReceiptPathEvidence.integrity.body_sha256 =
  sha256hex(canonicalize(mismatchedRecognizedReceiptPathEvidence.payload));
assertThrows('mismatched recognized receipt path evidence with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(mismatchedRecognizedReceiptPathEvidence);
}, 'recognized receipt path evidence drifted');

const unrecognizedReceiptPathEvidence = structuredClone(artifact);
unrecognizedReceiptPathEvidence.payload.chain.terminal_chain.recognized_receipt_path_evidence.verdict =
  'NOT_RECOGNIZED';
unrecognizedReceiptPathEvidence.payload.chain.terminal_chain.recognized_receipt_path_evidence.recognized =
  false;
unrecognizedReceiptPathEvidence.integrity.body_sha256 =
  sha256hex(canonicalize(unrecognizedReceiptPathEvidence.payload));
assertThrows('unrecognized receipt path evidence with recomputed outer hash is refused', () => {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(unrecognizedReceiptPathEvidence);
}, 'recognized receipt path evidence drifted');

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
