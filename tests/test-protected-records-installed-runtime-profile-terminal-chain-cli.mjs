#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import { sha256hex } from '../lib/receipt.mjs';

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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const PLAN_PATH = 'profiles/protected-records-runtime-profile-installation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_PATH =
  'tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json';
const SAMPLE_ARTIFACT_SHA256 =
  '0f8db51f11885e7867c6f0fa4d737adf51774e7cd9ad711cd2073b5b684c303f';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

function runZlar(args, options = {}) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

section('text summary command');
const textRun = runZlar(['protected-records-installed-runtime-profile-terminal-chain', '--sample']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Installed Runtime Profile Terminal Chain v1'));
assert('text summary includes generated preflight', textRun.stdout.includes('generated_preflight_consumed=true'));
assert('text summary includes service artifact verification', textRun.stdout.includes('generated_service_artifact_verified=true'));
assert('text summary includes missing receipt refusal', textRun.stdout.includes('missing_receipt_refused=true'));
assert('text summary includes recognition refusal taxonomy hash', textRun.stdout.includes('recognition_refusal_taxonomy_sha256='));
assert('text summary includes authority refusal taxonomy hash', textRun.stdout.includes('authority_refusal_taxonomy_sha256='));
assert('text summary includes fixture grant powers', textRun.stdout.includes('power_ids=bind_runtime_issuer_to_slot,issue_governed_action_receipt,issue_replacement_authority_grant,revoke_authority_grant'));
assert('text summary includes ordered transition binding', textRun.stdout.includes('Ordered transition binding: type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
assert('text summary includes replay split', textRun.stdout.includes('same_process_signed_payload_replay_refused=true; restart_consumed_authority_grant_refused=true'));
assert('text summary includes joint rollback side door', textRun.stdout.includes('joint_rollback_reopened_authority_grant_reuse=true'));
assert('text summary includes named refusal hash', textRun.stdout.includes('named_receipt_refusals_sha256='));
assert('text summary includes named refusal booleans', textRun.stdout.includes('Named receipt refusals: missing=true; invalid=true; stale=true; stale_or_expired=true; unknown_issuer=true; wrong_policy=true; wrong_domain=true; wrong_tool=true'));
assert('text summary includes recognition refusal groups hash', textRun.stdout.includes('recognition_refusal_groups_sha256='));
assert('text summary includes recognition refusal group booleans', textRun.stdout.includes('Recognition refusal groups: no_usable_recognized_receipt_authority=true; recognized_receipt_scope_mismatch=true; route_or_request_authority_material_refused=true'));
assert('text summary includes trusted registry binding', textRun.stdout.includes('Trusted issuer registry recognition binding: verdict=RECOGNIZED'));
assert('text summary includes boarded target binding', textRun.stdout.includes('Boarded service target binding: handle=zlar-target:v1:logical-fixture:'));
assert('text summary keeps registry receipt non-authorizing', textRun.stdout.includes('registry_receipt_authorized_service_write=false'));
assert('text summary includes trusted registry nonclaims', textRun.stdout.includes('Trusted issuer registry recognition non-claims: live_trust_registry_state=false'));
assert('text summary includes nested binding', textRun.stdout.includes('nested_artifact_binding.preflight_artifact_hash_bound=true'));
assert('text summary includes current-machine non-claim', textRun.stdout.includes('current_machine_governance_proven=false'));
assert('text summary includes production non-claim', textRun.stdout.includes('production_downstream_recognition=false'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['protected-records-installed-runtime-profile-terminal-chain', '--sample', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChain(report));
assertEqual('json chain type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TYPE, report.chain_type);
assertEqual('json sample artifact false', false, report.terminal_chain.sample_artifact_used);
assertEqual('json generated installed root preflighted', true, report.terminal_chain.generated_installed_root_preflighted);
assertEqual('json service proof bound', true, report.terminal_chain.service_proof_bound_to_generated_preflight);
assertEqual('json recognized write boarded', true, report.terminal_chain.recognized_write_boarded);
assertEqual('json missing receipt refused', true, report.terminal_chain.missing_receipt_refused_before_mutation);
assertEqual('json all recognition refusals before mutation', true, report.terminal_chain.all_required_recognition_refusals_before_mutation);
assertEqual('json recognition refusal taxonomy hash bound', report.generated_service_proof.recognition_refusal_taxonomy_sha256, report.terminal_chain.recognition_refusal_taxonomy_sha256);
assertEqual('json all authority refusals before consumption and mutation', true, report.terminal_chain.all_required_authority_refusals_before_consumption_and_mutation);
assertEqual('json authority refusal taxonomy hash bound', report.generated_service_proof.authority_refusal_taxonomy_sha256, report.terminal_chain.authority_refusal_taxonomy_sha256);
assertEqual('json named receipt refusals hash bound', report.generated_service_proof.named_receipt_refusals_sha256, report.terminal_chain.named_receipt_refusals_sha256);
assertEqual('json recognition refusal groups hash bound', report.generated_service_proof.recognition_refusal_groups_sha256, report.terminal_chain.recognition_refusal_groups_sha256);
assert('json recognition refusal taxonomy sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.recognition_refusal_taxonomy_sha256));
assert('json authority refusal taxonomy sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.authority_refusal_taxonomy_sha256));
assertEqual('json grant powers exact', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS), JSON.stringify(report.terminal_chain.public_safe_grant_summary.power_ids));
assertEqual('json ordered transition type exact', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', report.terminal_chain.ordered_transition_binding_type);
assertEqual('json recognition refusal count exact', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.terminal_chain.observed_recognition_refusal_case_count);
assertEqual('json authority refusal count exact', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.terminal_chain.observed_authority_refusal_case_count);
assertEqual('json same process replay refused', true, report.terminal_chain.same_process_signed_payload_replay_refused);
assertEqual('json restart consumed grant refused', true, report.terminal_chain.restart_consumed_authority_grant_refused);
assertEqual('json fixture rightful issuance path evidenced', true, report.terminal_chain.fixture_rightful_issuance_path_evidenced);
assertEqual('json generic rightful issuance false', false, report.terminal_chain.rightful_issuance_proven);
assertEqual('json lifecycle closure false', false, report.terminal_chain.consequence_lifecycle_closed);
assert('json named receipt refusals sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.named_receipt_refusals_sha256));
assert('json recognition refusal groups sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.recognition_refusal_groups_sha256));
assertEqual('json boarded target binding sha carried', report.generated_service_proof.boarded_service_target_binding_sha256, report.terminal_chain.boarded_service_target_binding_sha256);
assertEqual('json boarded target binding sha recomputable', sha256hex(canonicalize({ boarded_service_target_binding: report.terminal_chain.boarded_service_target_binding })), report.terminal_chain.boarded_service_target_binding_sha256);
assertEqual('json boarded target metadata post-effect only', 'post-effect-hash-bound-metadata-only', report.terminal_chain.boarded_service_target_binding.metadata_role);
assertEqual('json boarded target no profile authority', false, report.terminal_chain.boarded_service_target_binding.profile_wide_target_authority_proven);
assertEqual('json boarded target no rightful issuance', false, report.terminal_chain.boarded_service_target_binding.rightful_issuance_proven);
assertEqual('json boarded target no live target', false, report.terminal_chain.boarded_service_target_binding.live_target_proven);
assertEqual('json boarded target no lifecycle closure', false, report.terminal_chain.boarded_service_target_binding.consequence_lifecycle_closed);
assertEqual('json trusted registry binding verdict', 'RECOGNIZED', report.terminal_chain.trusted_issuer_registry_recognition_binding.verdict);
assertEqual('json trusted registry binding recognized', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.recognized);
assertEqual('json trusted registry binding rule evaluated', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_to_recognition_rule_evaluated);
assertEqual('json trusted registry binding contract hash bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound);
assertEqual('json trusted registry binding registry/receipt contract hash bound', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound);
assertEqual('json registry receipt is not boarded service receipt', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_is_boarded_service_receipt);
assertEqual('json registry receipt does not authorize service write', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write);
assertEqual('json receipt detail roles distinct', true, report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_detail_hash_roles_distinct);
assertEqual('json trusted registry binding public key material omitted', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.registry_public_key_material_included);
assertEqual('json trusted registry binding receipt envelope omitted', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.receipt_envelope_included);
assertEqual('json trusted registry binding no artifact cryptographic reconstruction', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.cryptographic_evidence_reproducible_from_artifact);
assertEqual('json trusted registry binding no live registry', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.live_trust_registry_state);
assertEqual('json trusted registry binding no key custody', false, report.terminal_chain.trusted_issuer_registry_recognition_binding.key_custody_proven);
assert('json trusted registry binding sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256));
assertEqual('json recognized receipt path evidence verdict', 'RECOGNIZED', report.terminal_chain.recognized_receipt_path_evidence.verdict);
assertEqual('json recognized receipt path evidence source binding sha', report.terminal_chain.trusted_issuer_registry_recognition_binding_sha256, report.terminal_chain.recognized_receipt_path_evidence.source_binding_sha256);
assertEqual('json recognized receipt path target binding sha', report.terminal_chain.boarded_service_target_binding_sha256, report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_binding_sha256);
assertEqual('json recognized receipt path target handle', report.terminal_chain.boarded_service_target_binding.target_handle, report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_handle);
assertEqual('json recognized receipt path metadata post-effect only', 'post-effect-hash-bound-metadata-only', report.terminal_chain.recognized_receipt_path_evidence.boarded_service_target_metadata_role);
assertEqual('json recognized receipt path evidence receipt envelope omitted', false, report.terminal_chain.recognized_receipt_path_evidence.receipt_envelope_included);
assert('json recognized receipt path evidence sha is hex', /^[a-f0-9]{64}$/.test(report.terminal_chain.recognized_receipt_path_evidence_sha256));
assertEqual('json observed recognition refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.generated_service_proof.observed_recognition_refusal_cases.length);
assertEqual('json observed authority refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.generated_service_proof.observed_authority_refusal_cases.length);
assertEqual('json stale receipt named refusal', true, report.terminal_chain.named_receipt_refusals.stale.refused_before_mutation);
assertEqual('json stale-or-expired receipt named refusal', true, report.terminal_chain.named_receipt_refusals.stale_or_expired.refused_before_mutation);
assertEqual('json unknown issuer named refusal', true, report.terminal_chain.named_receipt_refusals.unknown_issuer.refused_before_mutation);
assertEqual('json wrong policy named refusal reason', 'policy_not_recognized', report.terminal_chain.named_receipt_refusals.wrong_policy.reason_code);
assertEqual('json no usable authority group refused', true, report.terminal_chain.recognition_refusal_groups.no_usable_recognized_receipt_authority.all_refused_before_mutation);
assertEqual('json no usable authority group count', 6, report.terminal_chain.recognition_refusal_groups.no_usable_recognized_receipt_authority.case_count);
assertEqual('json scope mismatch group refused', true, report.terminal_chain.recognition_refusal_groups.recognized_receipt_scope_mismatch.all_refused_before_mutation);
assertEqual('json scope mismatch group count', 6, report.terminal_chain.recognition_refusal_groups.recognized_receipt_scope_mismatch.case_count);
assertEqual('json route/request authority group refused', true, report.terminal_chain.recognition_refusal_groups.route_or_request_authority_material_refused.all_refused_before_mutation);
assertEqual('json route/request authority group count', 6, report.terminal_chain.recognition_refusal_groups.route_or_request_authority_material_refused.case_count);
assertEqual('json current-machine governance false', false, report.side_door_report.current_machine_governance_proven);

section('explicit plan/profile command');
const explicitRun = runZlar([
  'protected-records-installed-runtime-profile-terminal-chain',
  '--plan',
  PLAN_PATH,
  '--profile',
  PROFILE_PATH,
  '--json',
]);
assertEqual('explicit command exits zero', 0, explicitRun.status);
assertEqual('explicit command emits no stderr', '', explicitRun.stderr);
const explicitReport = JSON.parse(explicitRun.stdout);
assertEqual('explicit report profile sha matches sample', report.runtime_profile.profile_sha256, explicitReport.runtime_profile.profile_sha256);
assertEqual('explicit report generated preflight sha matches sample', report.generated_preflight.artifact_body_sha256, explicitReport.generated_preflight.artifact_body_sha256);

section('plan/profile mismatch boundary');
const mismatchScratch = mkdtempSync(join(tmpdir(), 'zlar-installed-terminal-chain-mismatch-'));
try {
  const mismatchedPlan = JSON.parse(readFileSync(PLAN_PATH, 'utf8'));
  mismatchedPlan.runtime_profile_sha256 = '0'.repeat(64);
  const mismatchedPlanPath = join(mismatchScratch, 'mismatched-plan.json');
  writeFileSync(mismatchedPlanPath, `${JSON.stringify(mismatchedPlan, null, 2)}\n`);
  const mismatchRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    '--plan',
    mismatchedPlanPath,
    '--profile',
    PROFILE_PATH,
    '--json',
  ]);
  assert('mismatched plan/profile exits nonzero', mismatchRun.status !== 0);
  assertEqual('mismatched plan/profile emits no stdout', '', mismatchRun.stdout);
  assert('mismatched plan/profile names mismatch', mismatchRun.stderr.includes('plan/profile mismatch'));
  assert('mismatched plan/profile output is privacy safe', !unsafeOutputPattern.test(mismatchRun.stderr));
} finally {
  rmSync(mismatchScratch, { recursive: true, force: true });
}

section('artifact command and verify command');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-installed-terminal-chain-cli-'));
try {
  const artifactPath = join(scratch, 'installed-terminal-chain-artifact.json');
  const artifactRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    '--sample',
    '--artifact',
    artifactPath,
  ]);
  assertEqual('artifact command exits zero', 0, artifactRun.status);
  assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
  assert('artifact command keeps summary', artifactRun.stdout.includes('Portable installed runtime profile terminal chain artifact:'));
  assert('artifact command output is privacy safe', !unsafeOutputPattern.test(artifactRun.stdout));
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  assert('artifact file passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact));
  assertEqual('artifact file type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE, artifact.artifact_type);
  assert('artifact file sha present', /^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256));
  assert('artifact command prints artifact sha', artifactRun.stdout.includes(artifact.integrity.body_sha256));

  const artifactStdoutRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    '--sample',
    '--artifact',
    '-',
  ]);
  assertEqual('artifact stdout command exits zero', 0, artifactStdoutRun.status);
  assertEqual('artifact stdout command emits no stderr', '', artifactStdoutRun.stderr);
  assert('artifact stdout output is privacy safe', !unsafeOutputPattern.test(artifactStdoutRun.stdout));
  const artifactStdout = JSON.parse(artifactStdoutRun.stdout);
  assert('artifact stdout passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifactStdout));
  assert('artifact stdout sha present', /^[a-f0-9]{64}$/.test(artifactStdout.integrity.body_sha256));

  const verifyRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    artifactPath,
  ]);
  assertEqual('verify command exits zero', 0, verifyRun.status);
  assertEqual('verify command emits no stderr', '', verifyRun.stderr);
  assert('verify summary says verified', verifyRun.stdout.includes('verified=true'));
  assert('verify summary limits outer identity to structural', verifyRun.stdout.includes('artifact_identity_match_requires_expected_sha256=true'));
  assert('verify summary names structural-only outer scope', verifyRun.stdout.includes('verification_scope=structural-self-integrity-only'));
  assert('verify summary says outer artifact identity unmatched', verifyRun.stdout.includes('sha256_matched=false'));
  assert('verify summary includes embedded service pin', verifyRun.stdout.includes('embedded_service_artifact.expected_body_sha256_matched=true'));
  assert('verify summary includes generated preflight', verifyRun.stdout.includes('generated_preflight_artifact_consumed_by_service_proof=true'));
  assert('verify summary includes missing receipt refusal', verifyRun.stdout.includes('missing_receipt_refused_before_mutation=true'));
  assert('verify summary includes recognition refusal taxonomy hash', verifyRun.stdout.includes('recognition_refusal_taxonomy_sha256='));
  assert('verify summary includes authority refusal taxonomy hash', verifyRun.stdout.includes('authority_refusal_taxonomy_sha256='));
  assert('verify summary withholds fixture grant summary without outer pin', verifyRun.stdout.includes('public_safe_grant_summary.power_ids=withheld-until-outer-artifact-identity-match'));
  assert('verify summary includes public grant contract sha', verifyRun.stdout.includes('public_grant_contract.sha256='));
  assert('verify summary includes accepted crossing', verifyRun.stdout.includes('accepted_crossing.evidence_sha256='));
  assert('verify summary includes ordered transition', verifyRun.stdout.includes('ordered_transition_binding.type=protected-records-runtime-ordered-single-lock-transition-binding-v1'));
  assert('verify summary includes replay split', verifyRun.stdout.includes('same_process_signed_payload_replay_refused=true'));
  assert('verify summary withholds fixture rightful evidence without outer pin', verifyRun.stdout.includes('fixture_rightful_issuance_path_evidenced=false'));
  assert('verify summary includes named refusal hash', verifyRun.stdout.includes('named_receipt_refusals_sha256='));
  assert('verify summary includes recognition refusal groups hash', verifyRun.stdout.includes('recognition_refusal_groups_sha256='));
  assert('verify summary withholds trusted registry identity without outer pin', verifyRun.stdout.includes('trusted_issuer_registry_recognition_binding.verdict=withheld-until-outer-artifact-identity-match'));
  assert('verify summary names registry signature identity unbound', verifyRun.stdout.includes('trusted_issuer_registry_signature_bound=false'));
  assert('verify summary withholds boarded target identity without outer pin', verifyRun.stdout.includes('boarded_service_target_binding.target_handle=withheld-until-outer-artifact-identity-match'));
  assert('verify summary keeps registry receipt non-authorizing', verifyRun.stdout.includes('trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write=false'));
  assert('verify summary includes production non-claim', verifyRun.stdout.includes('production_downstream_recognition=false'));
  assert('verify summary is privacy safe', !unsafeOutputPattern.test(verifyRun.stdout));

  const verifyJsonRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    artifactPath,
    '--json',
  ]);
  assertEqual('verify json command exits zero', 0, verifyJsonRun.status);
  assertEqual('verify json command emits no stderr', '', verifyJsonRun.stderr);
  assert('verify json output is privacy safe', !unsafeOutputPattern.test(verifyJsonRun.stdout));
  const verification = JSON.parse(verifyJsonRun.stdout);
  assert('verify json passes validation', assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(verification));
  assertEqual('verify json type', PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verify json body sha matches artifact', artifact.integrity.body_sha256, verification.body_sha256);
  assertEqual('verify json structural self-integrity true', true, verification.structural_self_integrity_verified);
  assertEqual('verify json outer identity requires expected sha', true, verification.artifact_identity_match_requires_expected_sha256);
  assertEqual('verify json without expected sha has no match field', false, Object.hasOwn(verification, 'required_body_sha256_matched'));
  assertEqual('verify json outer artifact identity unmatched', false, verification.artifact_identity_sha256_matched);
  assertEqual('verify json outer fixture metadata unbound', false, verification.outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256);
  assertEqual('verify json embedded service expected sha matched', true, verification.embedded_service_artifact_expected_body_sha256_matched);
  assertEqual('verify json public fixture summary withheld without outer pin', null, verification.public_safe_grant_summary);
  assert('verify json public contract sha remains structural', /^[a-f0-9]{64}$/.test(verification.public_grant_contract_sha256));
  assert('verify json accepted crossing sha present', /^[a-f0-9]{64}$/.test(verification.accepted_crossing_evidence_sha256));
  assertEqual('verify json recognized write claim false without outer pin', false, verification.recognized_write_boarded);
  assertEqual('verify json missing receipt refused', true, verification.missing_receipt_refused_before_mutation);
  assertEqual('verify json recognition refusal taxonomy hash bound', artifact.payload.chain.terminal_chain.recognition_refusal_taxonomy_sha256, verification.recognition_refusal_taxonomy_sha256);
  assertEqual('verify json authority refusal taxonomy hash bound', artifact.payload.chain.terminal_chain.authority_refusal_taxonomy_sha256, verification.authority_refusal_taxonomy_sha256);
  assertEqual('verify json public contract powers remain structural', JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_FIXTURE_AUTHORITY_POWER_IDS), JSON.stringify(verification.public_grant_contract.powers.map((power) => power.power_id)));
  assertEqual('verify json ordered transition type exact', 'protected-records-runtime-ordered-single-lock-transition-binding-v1', verification.ordered_transition_binding_type);
  assertEqual('verify json same-process replay refused', true, verification.same_process_signed_payload_replay_refused);
  assertEqual('verify json restart consumed grant refused', true, verification.restart_consumed_authority_grant_refused);
  assertEqual('verify json joint rollback detection false', false, verification.store_anchor_and_witness_joint_rollback_detection);
  assertEqual('verify json fixture rightful evidence false without outer pin', false, verification.fixture_rightful_issuance_path_evidenced);
  assertEqual('verify json generic rightful false', false, verification.rightful_issuance_proven);
  assertEqual('verify json lifecycle false', false, verification.consequence_lifecycle_closed);
  assertEqual('verify json named receipt refusals hash bound', artifact.payload.chain.terminal_chain.named_receipt_refusals_sha256, verification.named_receipt_refusals_sha256);
  assertEqual('verify json recognition refusal groups hash bound', artifact.payload.chain.terminal_chain.recognition_refusal_groups_sha256, verification.recognition_refusal_groups_sha256);
  assertEqual('verify json boarded target projection withheld', null, verification.boarded_service_target_binding);
  assertEqual('verify json trusted registry signature projection withheld', null, verification.trusted_issuer_registry_recognition_binding);
  assertEqual('verify json trusted registry signature identity unbound', false, verification.trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256);
  assertEqual('verify json recognized receipt source projection withheld', null, verification.recognized_receipt_path_evidence);
  assertEqual('verify json recognized receipt source identity unbound', false, verification.recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
  assertEqual('verify json recognized receipt path evidence not claim-bound', false, verification.recognized_receipt_path_evidence_bound_to_artifact_body);
  assertEqual('verify json wrong tool named refusal', true, verification.named_receipt_refusals.wrong_tool.refused_before_mutation);
  assertEqual('verify json no usable authority group refused', true, verification.recognition_refusal_groups.no_usable_recognized_receipt_authority.all_refused_before_mutation);
  assertEqual('verify json no usable authority group count', 6, verification.recognition_refusal_groups.no_usable_recognized_receipt_authority.case_count);
  assertEqual('verify json scope mismatch group refused', true, verification.recognition_refusal_groups.recognized_receipt_scope_mismatch.all_refused_before_mutation);
  assertEqual('verify json scope mismatch group count', 6, verification.recognition_refusal_groups.recognized_receipt_scope_mismatch.case_count);
  assertEqual('verify json route/request authority group refused', true, verification.recognition_refusal_groups.route_or_request_authority_material_refused.all_refused_before_mutation);
  assertEqual('verify json route/request authority group count', 6, verification.recognition_refusal_groups.route_or_request_authority_material_refused.case_count);
  assertEqual('verify json observed recognition refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, verification.observed_recognition_refusal_cases.length);
  assertEqual('verify json observed authority refusal taxonomy count', REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASES.length, verification.observed_authority_refusal_cases.length);
  assertEqual('verify json current machine false', false, verification.current_machine_governance_proven);

  const verifyRequiredShaRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    artifactPath,
    '--require-sha',
    artifact.integrity.body_sha256,
    '--json',
  ]);
  assertEqual('verify required sha exits zero', 0, verifyRequiredShaRun.status);
  assertEqual('verify required sha emits no stderr', '', verifyRequiredShaRun.stderr);
  const requiredShaVerification = JSON.parse(verifyRequiredShaRun.stdout);
  assertEqual('verify required sha exact', artifact.integrity.body_sha256, requiredShaVerification.required_body_sha256);
  assertEqual('verify required sha matched', true, requiredShaVerification.required_body_sha256_matched);
  assertEqual('verify required sha outer artifact identity matched', true, requiredShaVerification.artifact_identity_sha256_matched);
  assertEqual('verify required sha outer fixture metadata bound', true, requiredShaVerification.outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256);
  assertEqual('verify required sha recognized write claim true', true, requiredShaVerification.recognized_write_boarded);
  assertEqual('verify required sha fixture rightful evidence true', true, requiredShaVerification.fixture_rightful_issuance_path_evidenced);
  assertEqual('verify required sha pinned scope exact', 'expected-terminal-artifact-identity-bound-local-fixture-projection', requiredShaVerification.verification_scope);
  assertEqual('verify required sha registry signature identity bound', true, requiredShaVerification.trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256);
  assertEqual('verify required sha recognized receipt source identity bound', true, requiredShaVerification.recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256);
  assertEqual('verify required sha trusted registry verdict projected', 'RECOGNIZED', requiredShaVerification.trusted_issuer_registry_recognition_binding.verdict);
  assertEqual('verify required sha recognized receipt path projected', 'RECOGNIZED', requiredShaVerification.recognized_receipt_path_evidence.verdict);

  const verifyBadRequiredShaRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    artifactPath,
    '--require-sha',
    '0'.repeat(64),
  ]);
  assert('verify bad required sha refuses', verifyBadRequiredShaRun.status !== 0);
  assertEqual('verify bad required sha emits no stdout', '', verifyBadRequiredShaRun.stdout);
  assert('verify bad required sha output is privacy safe', !unsafeOutputPattern.test(verifyBadRequiredShaRun.stderr));

  const verifyStdinRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    '-',
  ], {
    input: readFileSync(artifactPath, 'utf8'),
  });
  assertEqual('verify stdin command exits zero', 0, verifyStdinRun.status);
  assertEqual('verify stdin command emits no stderr', '', verifyStdinRun.stderr);
  assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));

  const sampleVerifyRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--sample',
  ]);
  assertEqual('sample verify command exits zero', 0, sampleVerifyRun.status);
  assertEqual('sample verify command emits no stderr', '', sampleVerifyRun.stderr);
  assert('sample verify includes stable sha', sampleVerifyRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));

  const sampleVerifyJsonRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--sample',
    '--json',
  ]);
  assertEqual('sample verify json exits zero', 0, sampleVerifyJsonRun.status);
  assertEqual('sample verify json emits no stderr', '', sampleVerifyJsonRun.stderr);
  const sampleVerification = JSON.parse(sampleVerifyJsonRun.stdout);
  assertEqual('sample verify json sha stable', SAMPLE_ARTIFACT_SHA256, sampleVerification.body_sha256);
  assertEqual('sample verify json stays structural without outer pin', 'structural-self-integrity-only', sampleVerification.verification_scope);
  assertEqual('sample verify json fixture rightful false without outer pin', false, sampleVerification.fixture_rightful_issuance_path_evidenced);
  assertEqual('sample verify json recognition refusal groups hash bound', report.terminal_chain.recognition_refusal_groups_sha256, sampleVerification.recognition_refusal_groups_sha256);
  assertEqual('sample verify json route/request authority group refused', true, sampleVerification.recognition_refusal_groups.route_or_request_authority_material_refused.all_refused_before_mutation);
  assertEqual('sample verify json trusted registry signature withheld without outer pin', null, sampleVerification.trusted_issuer_registry_recognition_binding);
  assertEqual('sample verify json recognized receipt source withheld without outer pin', null, sampleVerification.recognized_receipt_path_evidence);
  assertEqual('sample verify json recognized receipt path evidence not claim-bound', false, sampleVerification.recognized_receipt_path_evidence_bound_to_artifact_body);
  assertEqual('sample verify json nested preflight type', 'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1', sampleVerification.nested_artifact_binding.generated_preflight_artifact_type);
  assertEqual('sample verify json nested service type', 'zlar-protected-records-installed-runtime-profile-service-proof-artifact-v1', sampleVerification.nested_artifact_binding.generated_service_proof_artifact_type);
  assertEqual('sample verify json nested preflight hash bound', true, sampleVerification.nested_artifact_binding.preflight_artifact_hash_bound);
  assertEqual('sample verify json nested service source preflight hash bound', true, sampleVerification.nested_artifact_binding.service_proof_source_preflight_hash_bound);
  assertEqual('sample verify json nested service artifact hash bound', true, sampleVerification.nested_artifact_binding.service_artifact_hash_bound);
  assertEqual('sample verify json nested no production downstream', false, sampleVerification.nested_artifact_binding.proves_production_downstream_recognition);

  const tamperedArtifact = structuredClone(artifact);
  tamperedArtifact.payload.chain.side_door_report.current_machine_governance_proven = true;
  const tamperedPath = join(scratch, 'tampered-terminal-chain-artifact.json');
  writeFileSync(tamperedPath, `${JSON.stringify(tamperedArtifact, null, 2)}\n`);
  const tamperedRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    tamperedPath,
  ]);
  assert('tampered artifact exits nonzero', tamperedRun.status !== 0);
  assertEqual('tampered artifact emits no verification', '', tamperedRun.stdout);
  assert('tampered artifact failure is sanitized', !unsafeOutputPattern.test(tamperedRun.stderr));

  const forgedInnerPreflightHash = structuredClone(artifact);
  forgedInnerPreflightHash.payload.chain.generated_preflight.artifact_body_sha256 =
    'e'.repeat(64);
  forgedInnerPreflightHash.payload.chain.generated_service_proof.source_preflight_body_sha256 =
    'e'.repeat(64);
  forgedInnerPreflightHash.integrity.body_sha256 =
    sha256hex(canonicalize(forgedInnerPreflightHash.payload));
  const forgedInnerPreflightHashPath = join(
    scratch,
    'forged-inner-preflight-hash-terminal-chain-artifact.json'
  );
  writeFileSync(
    forgedInnerPreflightHashPath,
    `${JSON.stringify(forgedInnerPreflightHash, null, 2)}\n`
  );
  const forgedInnerPreflightHashRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    forgedInnerPreflightHashPath,
  ]);
  assert('forged inner preflight hash artifact exits nonzero', forgedInnerPreflightHashRun.status !== 0);
  assertEqual('forged inner preflight hash artifact emits no verification', '', forgedInnerPreflightHashRun.stdout);
  assert('forged inner preflight hash artifact names binding drift', forgedInnerPreflightHashRun.stderr.includes('service proof drifted'));
  assert('forged inner preflight hash artifact failure is sanitized', !unsafeOutputPattern.test(forgedInnerPreflightHashRun.stderr));

  const forgedInnerServiceHash = structuredClone(artifact);
  forgedInnerServiceHash.payload.chain.generated_service_proof.artifact_body_sha256 =
    'f'.repeat(64);
  forgedInnerServiceHash.payload.chain.generated_service_proof.verification_body_sha256 =
    'f'.repeat(64);
  forgedInnerServiceHash.integrity.body_sha256 =
    sha256hex(canonicalize(forgedInnerServiceHash.payload));
  const forgedInnerHashPath = join(scratch, 'forged-inner-service-hash-terminal-chain-artifact.json');
  writeFileSync(forgedInnerHashPath, `${JSON.stringify(forgedInnerServiceHash, null, 2)}\n`);
  const forgedInnerHashRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    forgedInnerHashPath,
  ]);
  assert('forged inner service hash artifact exits nonzero', forgedInnerHashRun.status !== 0);
  assertEqual('forged inner service hash artifact emits no verification', '', forgedInnerHashRun.stdout);
  assert('forged inner service hash artifact names binding drift', forgedInnerHashRun.stderr.includes('service proof drifted'));
  assert('forged inner service hash artifact failure is sanitized', !unsafeOutputPattern.test(forgedInnerHashRun.stderr));

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
  const forgedBoardedTargetEffectPath = join(
    scratch,
    'forged-boarded-target-effect-terminal-chain-artifact.json'
  );
  writeFileSync(
    forgedBoardedTargetEffectPath,
    `${JSON.stringify(forgedBoardedTargetEffect, null, 2)}\n`
  );
  const forgedBoardedTargetEffectRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    forgedBoardedTargetEffectPath,
  ]);
  assert('forged boarded target effect artifact exits nonzero', forgedBoardedTargetEffectRun.status !== 0);
  assertEqual('forged boarded target effect artifact emits no verification', '', forgedBoardedTargetEffectRun.stdout);
  assert('forged boarded target effect artifact names nested binding drift', forgedBoardedTargetEffectRun.stderr.includes('nested service proof artifact binding'));
  assert('forged boarded target effect artifact failure is sanitized', !unsafeOutputPattern.test(forgedBoardedTargetEffectRun.stderr));

  const forgedTrustedRegistryBinding = structuredClone(artifact);
  forgedTrustedRegistryBinding.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.recognition_contract_hash_bound =
    false;
  forgedTrustedRegistryBinding.integrity.body_sha256 =
    sha256hex(canonicalize(forgedTrustedRegistryBinding.payload));
  const forgedTrustedRegistryBindingPath = join(
    scratch,
    'forged-trusted-registry-binding-terminal-chain-artifact.json'
  );
  writeFileSync(
    forgedTrustedRegistryBindingPath,
    `${JSON.stringify(forgedTrustedRegistryBinding, null, 2)}\n`
  );
  const forgedTrustedRegistryBindingRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    forgedTrustedRegistryBindingPath,
  ]);
  assert('forged trusted registry binding artifact exits nonzero', forgedTrustedRegistryBindingRun.status !== 0);
  assertEqual('forged trusted registry binding artifact emits no verification', '', forgedTrustedRegistryBindingRun.stdout);
  assert('forged trusted registry binding artifact names binding drift', forgedTrustedRegistryBindingRun.stderr.includes('trusted issuer registry recognition binding drifted'));
  assert('forged trusted registry binding artifact failure is sanitized', !unsafeOutputPattern.test(forgedTrustedRegistryBindingRun.stderr));

  const forgedTrustedRegistryReceiptBinding = structuredClone(artifact);
  forgedTrustedRegistryReceiptBinding.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_contract_hash_bound =
    false;
  forgedTrustedRegistryReceiptBinding.integrity.body_sha256 =
    sha256hex(canonicalize(forgedTrustedRegistryReceiptBinding.payload));
  const forgedTrustedRegistryReceiptBindingPath = join(
    scratch,
    'forged-trusted-registry-receipt-binding-terminal-chain-artifact.json'
  );
  writeFileSync(
    forgedTrustedRegistryReceiptBindingPath,
    `${JSON.stringify(forgedTrustedRegistryReceiptBinding, null, 2)}\n`
  );
  const forgedTrustedRegistryReceiptBindingRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    forgedTrustedRegistryReceiptBindingPath,
  ]);
  assert('forged trusted registry receipt binding artifact exits nonzero', forgedTrustedRegistryReceiptBindingRun.status !== 0);
  assertEqual('forged trusted registry receipt binding artifact emits no verification', '', forgedTrustedRegistryReceiptBindingRun.stdout);
  assert('forged trusted registry receipt binding artifact names binding drift', forgedTrustedRegistryReceiptBindingRun.stderr.includes('trusted issuer registry recognition binding drifted'));
  assert('forged trusted registry receipt binding artifact failure is sanitized', !unsafeOutputPattern.test(forgedTrustedRegistryReceiptBindingRun.stderr));

  const forgedRegistryReceiptAuthorityRole = structuredClone(artifact);
  forgedRegistryReceiptAuthorityRole.payload.chain.terminal_chain.trusted_issuer_registry_recognition_binding.registry_receipt_authorized_service_write =
    true;
  forgedRegistryReceiptAuthorityRole.integrity.body_sha256 =
    sha256hex(canonicalize(forgedRegistryReceiptAuthorityRole.payload));
  const forgedRegistryReceiptAuthorityRolePath = join(
    scratch,
    'forged-registry-receipt-authority-role-terminal-chain-artifact.json'
  );
  writeFileSync(
    forgedRegistryReceiptAuthorityRolePath,
    `${JSON.stringify(forgedRegistryReceiptAuthorityRole, null, 2)}\n`
  );
  const forgedRegistryReceiptAuthorityRoleRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    forgedRegistryReceiptAuthorityRolePath,
  ]);
  assert('forged registry receipt authority role artifact exits nonzero', forgedRegistryReceiptAuthorityRoleRun.status !== 0);
  assertEqual('forged registry receipt authority role artifact emits no verification', '', forgedRegistryReceiptAuthorityRoleRun.stdout);
  assert('forged registry receipt authority role names binding drift', forgedRegistryReceiptAuthorityRoleRun.stderr.includes('trusted issuer registry recognition binding drifted'));
  assert('forged registry receipt authority role failure is sanitized', !unsafeOutputPattern.test(forgedRegistryReceiptAuthorityRoleRun.stderr));

  const summaryOnlyRecognizedReceiptPathEvidence = structuredClone(artifact);
  summaryOnlyRecognizedReceiptPathEvidence.payload.chain.terminal_chain.recognized_receipt_path_evidence = {
    verdict: 'RECOGNIZED',
  };
  summaryOnlyRecognizedReceiptPathEvidence.integrity.body_sha256 =
    sha256hex(canonicalize(summaryOnlyRecognizedReceiptPathEvidence.payload));
  const summaryOnlyRecognizedReceiptPathEvidencePath = join(
    scratch,
    'summary-only-recognized-receipt-path-terminal-chain-artifact.json'
  );
  writeFileSync(
    summaryOnlyRecognizedReceiptPathEvidencePath,
    `${JSON.stringify(summaryOnlyRecognizedReceiptPathEvidence, null, 2)}\n`
  );
  const summaryOnlyRecognizedReceiptPathEvidenceRun = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--input',
    summaryOnlyRecognizedReceiptPathEvidencePath,
  ]);
  assert('summary-only recognized receipt path artifact exits nonzero', summaryOnlyRecognizedReceiptPathEvidenceRun.status !== 0);
  assertEqual('summary-only recognized receipt path artifact emits no verification', '', summaryOnlyRecognizedReceiptPathEvidenceRun.stdout);
  assert('summary-only recognized receipt path artifact names receipt path evidence', summaryOnlyRecognizedReceiptPathEvidenceRun.stderr.includes('recognized receipt path'));
  assert('summary-only recognized receipt path artifact failure is sanitized', !unsafeOutputPattern.test(summaryOnlyRecognizedReceiptPathEvidenceRun.stderr));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

section('bad option boundaries');
const helpRun = runZlar(['protected-records-installed-runtime-profile-terminal-chain', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assertEqual('help emits no stdout', '', helpRun.stdout);
assert('help emits usage', helpRun.stderr.includes('Usage: zlar protected-records-installed-runtime-profile-terminal-chain'));
assert('help states proof-only terminal-chain proof', helpRun.stderr.includes('proof-only local disposable protected-records installed runtime-profile terminal-chain proof'));
assert('help names first safe sample run', helpRun.stderr.includes('Use --sample as the first safe run'));
assert('help states fresh launcher-owned disposable evidence', helpRun.stderr.includes('fresh launcher-owned disposable chain evidence'));
assert('help refuses install or activation', helpRun.stderr.includes('does not persistently install, activate'));
assert('help refuses current-machine governance', helpRun.stderr.includes('prove current-machine governance'));
assert('help refuses production downstream recognition', helpRun.stderr.includes('claim production downstream recognition'));

const missingArgsRun = runZlar(['protected-records-installed-runtime-profile-terminal-chain']);
assert('missing args exits nonzero', missingArgsRun.status !== 0);
assert('missing args emits usage', missingArgsRun.stderr.includes('Usage: zlar protected-records-installed-runtime-profile-terminal-chain'));

const combinedSampleRun = runZlar([
  'protected-records-installed-runtime-profile-terminal-chain',
  '--sample',
  '--plan',
  PLAN_PATH,
  '--profile',
  PROFILE_PATH,
]);
assert('sample plus plan/profile exits nonzero', combinedSampleRun.status !== 0);
assert('sample plus plan/profile emits no private data', !unsafeOutputPattern.test(combinedSampleRun.stderr));

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
