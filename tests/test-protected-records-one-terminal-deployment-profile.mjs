#!/usr/bin/env node

import {
  EXPECTED_REFUSAL_REASONS,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING,
  ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_REASONS,
  PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_INPUT_PROVENANCE_TYPE,
  PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE,
  PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_TYPE,
  REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
  assertProtectedRecordsOneTerminalDeploymentProfile,
  assertProtectedRecordsOneTerminalDeploymentProfileProof,
  formatProtectedRecordsOneTerminalDeploymentProfileProofSummary,
  oneTerminalDeploymentProfileSha256,
  readSampleProtectedRecordsOneTerminalDeploymentProfileInputs,
  runProtectedRecordsOneTerminalDeploymentProfileProof,
} from '../lib/protected-records-one-terminal-deployment-profile.mjs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';

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

const SAMPLE_RUNTIME_PROFILE_SHA =
  'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469';

section('local fixture deployment profile');
const inputs = readSampleProtectedRecordsOneTerminalDeploymentProfileInputs();
assert('deployment profile validates', assertProtectedRecordsOneTerminalDeploymentProfile(inputs.deploymentProfile));
assertEqual('deployment profile type', PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_TYPE, inputs.deploymentProfile.profile_type);
assertEqual('deployment profile status is sample only', 'sample_not_active', inputs.deploymentProfile.profile_status);
assertEqual('deployment model is local fixture', 'one-terminal-local-fixture', inputs.deploymentProfile.deployment_model);
assertEqual('selected runtime profile sha stable', SAMPLE_RUNTIME_PROFILE_SHA, inputs.deploymentProfile.selected_runtime_profile.profile_sha256);
assertEqual('selected by explicit id and sha', true, inputs.deploymentProfile.selected_runtime_profile.selected_by_explicit_id_and_sha);
assertEqual('does not select latest', false, inputs.deploymentProfile.selected_runtime_profile.selects_latest_profile);
assert('deployment profile sha present', /^[a-f0-9]{64}$/.test(oneTerminalDeploymentProfileSha256(inputs.deploymentProfile)));

section('one-terminal deployment profile proof');
const report = runProtectedRecordsOneTerminalDeploymentProfileProof(inputs);
assert('proof validates', assertProtectedRecordsOneTerminalDeploymentProfileProof(report));
assertEqual('proof type', PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE, report.proof_type);
assertEqual('safe claim ceiling exact', ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('evidence model', 'local-fixture-one-terminal-deployment-profile-authority-bridge', report.evidence_model);
assertEqual('live probing false', false, report.live_probing);
assertEqual('input provenance type', PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_INPUT_PROVENANCE_TYPE, report.input_provenance.provenance_type);
assertEqual('input mode sample', 'sample', report.input_provenance.input_mode);
assertEqual('source text hashes bound', true, report.input_provenance.source_text_hashes_bound);
assertEqual('source paths public safe', true, report.input_provenance.source_paths_public_safe);
assertEqual('absolute paths not emitted', false, report.input_provenance.absolute_paths_emitted);
assertEqual('deployment profile sample source', 'embedded-sample', report.input_provenance.deployment_profile.source);
assertEqual('deployment profile sample display path', 'profiles/protected-records-one-terminal-deployment-profile.fixture.json', report.input_provenance.deployment_profile.display_path);
assertEqual('runtime profile sample display path', 'profiles/protected-records-runtime-fixture.profile.json', report.input_provenance.runtime_profile.display_path);
assertEqual('preflight artifact sample display path', 'tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json', report.input_provenance.preflight_artifact.display_path);
assert('input provenance hashes present', [
  report.input_provenance.deployment_profile.text_sha256,
  report.input_provenance.runtime_profile.text_sha256,
  report.input_provenance.preflight_artifact.text_sha256,
].every((value) => /^[a-f0-9]{64}$/.test(value)));
assertEqual('deployment artifact authoritative', true, report.deployment_profile.deployment_owned_profile_artifact);
assert('deployment profile sha present in proof', /^[a-f0-9]{64}$/.test(report.deployment_profile.profile_sha256));
assertEqual('runtime profile sha matches fixture', SAMPLE_RUNTIME_PROFILE_SHA, report.selected_runtime_profile.profile_sha256);
assertEqual('runtime profile sha matches deployment profile', true, report.selected_runtime_profile.profile_sha_matches_deployment_profile);
assertEqual('runtime profile explicit selection', true, report.selected_runtime_profile.selected_by_explicit_id_and_sha);
assertEqual('runtime profile no latest selection', false, report.selected_runtime_profile.selects_latest_profile);
assertEqual('preflight verified', true, report.preflight_bridge.verified);
assertEqual('preflight selected explicit id and sha', true, report.preflight_bridge.selected_by_explicit_id_and_sha);
assertEqual('preflight no latest selection', false, report.preflight_bridge.selects_latest_profile);
assertEqual('preflight request authority rejected', false, report.preflight_bridge.request_stream_authority_material_accepted);
assertEqual('preflight recognition rule not agent supplied', false, report.preflight_bridge.recognition_rule_supplied_by_agent);
assertEqual('preflight current-machine governance false', false, report.preflight_bridge.current_machine_governance_proven);
assertEqual('recognized receipt mutates once', true, report.service_proof_bridge.recognized_receipt_mutates_once);
assertEqual('recognized state delta one', 1, report.service_proof_bridge.recognized_state_entry_count_delta);
assertEqual('required refusal count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.service_proof_bridge.required_refusal_case_count);
assertEqual('observed refusal count', REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length, report.service_proof_bridge.observed_refusal_case_count);
assertEqual('all refusals before mutation', true, report.service_proof_bridge.all_refusals_before_mutation);
assertEqual('agent-supplied authority refused before mutation', true, report.service_proof_bridge.agent_supplied_authority_refused_before_mutation);
assertEqual('direct API refused before mutation', true, report.service_proof_bridge.direct_api_refused_before_mutation);
assertEqual('downstream refusal proven', true, report.service_proof_bridge.downstream_refusal_proven);
assertEqual('deployment profile authority refusal count', REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length, report.deployment_profile_authority_refusals.observed_refusal_case_count);
assertEqual('deployment profile authority refusals before service proof', true, report.deployment_profile_authority_refusals.all_refused_before_service_proof);
assertEqual('deployment profile authority refusals before mutation', true, report.deployment_profile_authority_refusals.all_refused_before_mutation);
assertEqual('deployment profile authority refusals did not start service proof', false, report.deployment_profile_authority_refusals.service_proof_started_for_refusals);
assertEqual('deployment profile authority refusal case IDs', JSON.stringify(REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES), JSON.stringify(report.deployment_profile_authority_refusals.refusal_case_ids));
assertEqual('stale deployment profile artifact refused before service proof', true, report.deployment_profile_authority_refusals.stale_deployment_profile_artifact_refused_before_service_proof);
assertEqual('profile recognition mismatch refused before service proof', true, report.deployment_profile_authority_refusals.profile_recognition_mismatch_refused_before_service_proof);
assertEqual('latest profile selection refused before service proof', true, report.deployment_profile_authority_refusals.latest_profile_selection_refused_before_service_proof);
assertEqual('request stream authority material refused before service proof', true, report.deployment_profile_authority_refusals.request_stream_authority_material_refused_before_service_proof);
for (const refusal of report.deployment_profile_authority_refusals.cases) {
  assertEqual(
    `${refusal.case_id} deployment authority reason`,
    ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_REASONS[refusal.case_id],
    refusal.reason_code
  );
  assertEqual(`${refusal.case_id} refused before service proof`, true, refusal.refused_before_service_proof);
  assertEqual(`${refusal.case_id} service proof not started`, false, refusal.service_proof_started);
  assertEqual(`${refusal.case_id} state delta zero`, 0, refusal.state_entry_count_delta);
}
assertEqual('request stream authority not accepted', false, report.authority_boundary.request_stream_authority_material_accepted);
assertEqual('agent-supplied authority material not accepted', false, report.authority_boundary.agent_supplied_authority_material_accepted);
assertEqual('deployment profile artifact sha bound', true, report.acceptance_gates.deployment_profile_artifact_sha_bound);
assertEqual('source text hash bound gate', true, report.acceptance_gates.source_text_hashes_bound);
assertEqual('runtime profile sha bound', true, report.acceptance_gates.runtime_profile_sha_bound);
assertEqual('deployment profile authority refusal acceptance gate', true, report.acceptance_gates.deployment_profile_authority_refusals_before_service_proof);
assertEqual('current-machine governance false', false, report.proof_boundary.current_machine_governance);
assertEqual('production downstream false', false, report.proof_boundary.production_downstream_recognition);
assertEqual('production authority false', false, report.proof_boundary.production_authority);
assertEqual('enterprise readiness false', false, report.proof_boundary.enterprise_readiness);
assertEqual('external attestation false', false, report.proof_boundary.external_attestation);
assertEqual('sovereign recognition false', false, report.proof_boundary.sovereign_recognition);
assertEqual('unrouted coverage false', false, report.proof_boundary.unrouted_surface_coverage);

section('refusal taxonomy is exact and zero-mutation');
assertEqual(
  'refusal case order preserved',
  JSON.stringify(REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES),
  JSON.stringify(report.observed_refusal_cases.map((item) => item.case_id)),
);
for (const refusal of report.observed_refusal_cases) {
  assertEqual(`${refusal.case_id} reason`, EXPECTED_REFUSAL_REASONS[refusal.case_id], refusal.reason_code);
  assertEqual(`${refusal.case_id} refused before mutation`, true, refusal.refused_before_mutation);
  assertEqual(`${refusal.case_id} state delta zero`, 0, refusal.state_entry_count_delta);
}
assertEqual(
  'agent-supplied recognition rule uses existing authority-material reason',
  'agent_supplied_authority_material',
  report.observed_refusal_cases.find((item) =>
    item.case_id === 'agent_supplied_recognition_rule_refused_before_runtime_mutation'
  )?.reason_code,
);

section('output boundary');
const summary = formatProtectedRecordsOneTerminalDeploymentProfileProofSummary(report);
assert('summary title present', summary.includes('ZLAR Protected Records One-Terminal Deployment Profile Proof v1'));
assert('summary includes input mode', summary.includes('input_mode=sample'));
assert('summary includes source hash binding', summary.includes('source_text_hashes_bound=true'));
assert('summary includes explicit selection', summary.includes('selected_by_explicit_id_and_sha=true'));
assert('summary includes no latest selection', summary.includes('selects_latest_profile=false'));
assert('summary includes exactly once', summary.includes('recognized_receipt_mutates_once=true'));
assert('summary includes authority refusal', summary.includes('agent_supplied_authority_refused_before_mutation=true'));
assert('summary includes stale artifact refusal', summary.includes('stale_deployment_profile_artifact_refused_before_service_proof=true'));
assert('summary includes profile mismatch refusal', summary.includes('profile_recognition_mismatch_refused_before_service_proof=true'));
assert('summary includes latest selection refusal', summary.includes('latest_profile_selection_refused_before_service_proof=true'));
assert('summary includes request authority refusal', summary.includes('request_stream_authority_material_refused_before_service_proof=true'));
assert('summary includes production non-claim', summary.includes('production_downstream_recognition=false'));
assert('summary output privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(summary));
assert('json output privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report, null, 2)));

section('fail closed validation');
const selectedByLatest = structuredClone(inputs.deploymentProfile);
selectedByLatest.selected_runtime_profile.selects_latest_profile = true;
assertThrows('selecting latest fails', () => assertProtectedRecordsOneTerminalDeploymentProfile(selectedByLatest), 'runtime-profile selection drifted');

const noExplicitSelection = structuredClone(inputs.deploymentProfile);
noExplicitSelection.selected_runtime_profile.selected_by_explicit_id_and_sha = false;
assertThrows('missing explicit profile selection fails', () => assertProtectedRecordsOneTerminalDeploymentProfile(noExplicitSelection), 'runtime-profile selection drifted');

const authorityAccepted = structuredClone(inputs.deploymentProfile);
authorityAccepted.authority_boundary.agent_supplied_authority_material_accepted = true;
assertThrows('accepted agent authority fails', () => assertProtectedRecordsOneTerminalDeploymentProfile(authorityAccepted), 'authority boundary drifted');

const productionProfileClaim = structuredClone(inputs.deploymentProfile);
productionProfileClaim.proof_boundary.production_authority = true;
assertThrows('deployment profile production authority claim fails', () => assertProtectedRecordsOneTerminalDeploymentProfile(productionProfileClaim), 'proof boundary drifted');

const latestReport = structuredClone(report);
latestReport.selected_runtime_profile.selects_latest_profile = true;
assertThrows('proof latest selection fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(latestReport), 'runtime profile drifted');

const absolutePathProvenance = structuredClone(report);
absolutePathProvenance.input_provenance.deployment_profile.display_path =
  '/tmp/zlar-proof/profiles/protected-records-one-terminal-deployment-profile.fixture.json';
assertThrows('absolute input provenance path fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(absolutePathProvenance), 'safe display path');

const unboundSourceHash = structuredClone(report);
unboundSourceHash.input_provenance.source_text_hashes_bound = false;
assertThrows('unbound source hash provenance fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(unboundSourceHash), 'input provenance');

const missingRefusal = structuredClone(report);
missingRefusal.observed_refusal_cases = missingRefusal.observed_refusal_cases.filter(
  (item) => item.case_id !== 'stale_receipt_refused_before_runtime_mutation',
);
assertThrows('missing refusal case fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(missingRefusal), 'refusal cases');

const mutatedRefusal = structuredClone(report);
mutatedRefusal.observed_refusal_cases[0].state_entry_count_delta = 1;
assertThrows('mutated refusal fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(mutatedRefusal), 'refusal case drifted');

const doubleMutation = structuredClone(report);
doubleMutation.service_proof_bridge.recognized_state_entry_count_delta = 2;
assertThrows('double mutation claim fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(doubleMutation), 'service bridge drifted');

const missingDeploymentAuthorityRefusal = structuredClone(report);
missingDeploymentAuthorityRefusal.deployment_profile_authority_refusals.refusal_case_ids =
  missingDeploymentAuthorityRefusal.deployment_profile_authority_refusals.refusal_case_ids.filter(
    (item) => item !== 'preflight_profile_sha_mismatch_refused_before_service_proof',
  );
assertThrows('missing deployment authority refusal fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(missingDeploymentAuthorityRefusal), 'authority refusal case IDs');

const staleDeploymentAuthorityClaim = structuredClone(report);
staleDeploymentAuthorityClaim.deployment_profile_authority_refusals
  .stale_deployment_profile_artifact_refused_before_service_proof = false;
assertThrows('stale deployment authority refusal claim fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(staleDeploymentAuthorityClaim), 'authority refusal summary');

const deploymentAuthorityReasonDrift = structuredClone(report);
deploymentAuthorityReasonDrift.deployment_profile_authority_refusals.cases[0].reason_code =
  'unclassified_deployment_profile_authority_failure';
assertThrows('deployment authority reason drift fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(deploymentAuthorityReasonDrift), 'authority refusal drifted');

const malformedPreflightArtifact = structuredClone(inputs);
malformedPreflightArtifact.preflightArtifact = {
  artifact_type: 'generic-malformed-preflight-artifact-v1',
};
assertThrows('generic malformed preflight artifact cannot satisfy deployment bridge', () => runProtectedRecordsOneTerminalDeploymentProfileProof(malformedPreflightArtifact));

const liveServiceClaim = structuredClone(report);
liveServiceClaim.proof_boundary.live_runtime_service = true;
assertThrows('live runtime service claim fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(liveServiceClaim), 'proof boundary drifted');

const currentMachineClaim = structuredClone(report);
currentMachineClaim.proof_boundary.current_machine_governance = true;
assertThrows('current-machine governance claim fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(currentMachineClaim), 'proof boundary drifted');

const productionClaim = structuredClone(report);
productionClaim.proof_boundary.production_downstream_recognition = true;
assertThrows('production downstream claim fails', () => assertProtectedRecordsOneTerminalDeploymentProfileProof(productionClaim), 'proof boundary drifted');

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed${FAIL ? ` (${FAIL} FAILED)` : ' ✓'}`);
if (FAIL > 0) process.exit(1);
