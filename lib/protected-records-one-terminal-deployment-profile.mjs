import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
  verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
} from './protected-records-installed-runtime-profile-preflight.mjs';
import {
  buildCanonicalProtectedRecordsInstalledPreflightSampleArtifact,
  readProtectedRecordsInstalledSampleProfile,
  readProtectedRecordsOneTerminalDeploymentProfileSampleText,
  SAMPLE_DEPLOYMENT_PROFILE_DISPLAY_PATH,
  SAMPLE_DEPLOYMENT_PROFILE_TEXT_SHA256,
  SAMPLE_PREFLIGHT_ARTIFACT_DISPLAY_PATH,
  SAMPLE_PREFLIGHT_ARTIFACT_TEXT_SHA256,
  SAMPLE_PROFILE_DISPLAY_PATH,
  SAMPLE_PROFILE_TEXT_SHA256,
} from './protected-records-installed-proof-samples.mjs';
import {
  EXPECTED_REFUSAL_REASONS,
  INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256,
  assertProtectedRecordsInstalledRuntimeProfileServiceProof,
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
} from './protected-records-installed-runtime-profile-service-proof.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
  protectedRecordsFixtureAuthorityGrantStatus,
} from './protected-records-fixture-authority-status.mjs';

export const PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_TYPE =
  'zlar-protected-records-one-terminal-deployment-profile-v1';

export const PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE =
  'zlar-protected-records-one-terminal-deployment-profile-proof-v1';

export const PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_INPUT_PROVENANCE_TYPE =
  'zlar-protected-records-one-terminal-deployment-profile-input-provenance-v1';

export const ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING =
  'ZLAR can validate a local fixture one-terminal deployment profile artifact, bind the exact proof inputs by safe source labels and SHA-256, bind the selected runtime profile by explicit profile id and SHA-256, consume the matching installed-profile preflight artifact, and prove through a local disposable child-service proof that one recognized receipt mutates once while required refusal cases and agent-supplied authority material mutate zero state.';

export const ONE_TERMINAL_DEPLOYMENT_PROFILE_NON_CLAIMS = Object.freeze([
  'This proof validates a local fixture deployment-profile artifact only; it does not install, activate, or persist a runtime profile.',
  'This proof consumes local fixture runtime-profile and preflight artifacts; it does not use current-machine defaults, --latest, operator state, or live probing.',
  'This proof starts only a local disposable child-service proof harness; it does not start a live runtime service or inspect a live records system.',
  'This proof does not write hook configuration, user configuration, machine configuration, production configuration, production receipts, production audit logs, or production stores.',
  'This proof does not prove production downstream recognition, production authority, current-machine governance, live MCP coverage, enterprise readiness, external attestation, sovereign recognition, or coverage of unrouted surfaces.',
]);

export const REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES =
  Object.freeze([
    'stale_deployment_profile_runtime_sha_refused_before_service_proof',
    'runtime_profile_id_mismatch_refused_before_service_proof',
    'preflight_profile_sha_mismatch_refused_before_service_proof',
    'preflight_latest_selection_refused_before_service_proof',
    'preflight_request_authority_material_refused_before_service_proof',
  ]);

export const ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_REASONS =
  Object.freeze({
    stale_deployment_profile_runtime_sha_refused_before_service_proof:
      'stale_deployment_profile_artifact',
    runtime_profile_id_mismatch_refused_before_service_proof:
      'runtime_profile_id_mismatch',
    preflight_profile_sha_mismatch_refused_before_service_proof:
      'preflight_profile_sha_mismatch',
    preflight_latest_selection_refused_before_service_proof:
      'latest_profile_selection',
    preflight_request_authority_material_refused_before_service_proof:
      'request_stream_authority_material',
  });

const PROTECTED_RECORDS_ONE_TERMINAL_COMMITTED_SERVICE_PROOF_ARTIFACT_PATH =
  fileURLToPath(new URL(
    '../tests/fixtures/protected-records-installed-runtime-profile-service-proof-artifact-v1.json',
    import.meta.url,
  ));

function readCommittedProtectedRecordsInstalledRuntimeProfileServiceProofArtifact() {
  const artifact = JSON.parse(readFileSync(
    PROTECTED_RECORDS_ONE_TERMINAL_COMMITTED_SERVICE_PROOF_ARTIFACT_PATH,
    'utf8',
  ));
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(artifact);
  if (
    artifact.integrity.body_sha256 !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256
  ) {
    throw new Error(
      'Protected records one-terminal committed service-proof artifact identity drifted',
    );
  }
  return artifact;
}

function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function assertExactKeys(label, value, expectedKeys) {
  requireObject(label, value);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
  return true;
}

function assertExactArray(label, value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`${label} drifted`);
  }
  for (let i = 0; i < expected.length; i++) {
    if (value[i] !== expected[i]) {
      throw new Error(`${label} drifted`);
    }
  }
  return true;
}

function assertSha256(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex digest`);
  }
  return true;
}

function assertSafeDisplayPath(label, value) {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > 200 ||
    value.startsWith('/') ||
    value.includes('..') ||
    value.includes('\\') ||
    value.includes('/Users/') ||
    value.includes('/var/folders/')
  ) {
    throw new Error(`${label} is not a safe display path`);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(value);
  return true;
}

function assertInputSource(source) {
  if (!['embedded-sample', 'explicit-file', 'stdin-redacted', 'outside-repo-redacted'].includes(source)) {
    throw new Error('Protected records one-terminal input source is malformed');
  }
  return true;
}

function assertProfileId(label, value) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(value)) {
    throw new Error(`${label} is malformed`);
  }
  return true;
}

function parseJsonText(text, label) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

export function parseProtectedRecordsOneTerminalDeploymentProfileText(text) {
  return parseJsonText(text, 'Protected records one-terminal deployment profile');
}

export function readSampleProtectedRecordsOneTerminalDeploymentProfileInputs() {
  return {
    deploymentProfile: parseProtectedRecordsOneTerminalDeploymentProfileText(
      readProtectedRecordsOneTerminalDeploymentProfileSampleText()
    ),
    runtimeProfile: readProtectedRecordsInstalledSampleProfile(),
    preflightArtifact: buildCanonicalProtectedRecordsInstalledPreflightSampleArtifact(),
  };
}

function inputProvenanceEntry({ source, displayPath, textSha256 }) {
  assertInputSource(source);
  assertSafeDisplayPath('Protected records one-terminal input display path', displayPath);
  assertSha256('Protected records one-terminal input text SHA-256', textSha256);
  return {
    source,
    display_path: displayPath,
    text_sha256: textSha256,
  };
}

export function buildProtectedRecordsOneTerminalDeploymentProfileInputProvenance({
  inputMode = 'sample',
  deploymentProfile,
  runtimeProfile,
  preflightArtifact,
} = {}) {
  if (!['sample', 'explicit-files'].includes(inputMode)) {
    throw new Error('Protected records one-terminal input mode is malformed');
  }

  const fallbackSource = inputMode === 'sample' ? 'embedded-sample' : 'explicit-file';
  const provenance = {
    provenance_type: PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_INPUT_PROVENANCE_TYPE,
    input_mode: inputMode,
    source_text_hashes_bound: true,
    source_paths_public_safe: true,
    absolute_paths_emitted: false,
    deployment_profile: inputProvenanceEntry({
      source: deploymentProfile?.source || fallbackSource,
      displayPath: deploymentProfile?.displayPath || SAMPLE_DEPLOYMENT_PROFILE_DISPLAY_PATH,
      textSha256: deploymentProfile?.textSha256 || SAMPLE_DEPLOYMENT_PROFILE_TEXT_SHA256,
    }),
    runtime_profile: inputProvenanceEntry({
      source: runtimeProfile?.source || fallbackSource,
      displayPath: runtimeProfile?.displayPath || SAMPLE_PROFILE_DISPLAY_PATH,
      textSha256: runtimeProfile?.textSha256 || SAMPLE_PROFILE_TEXT_SHA256,
    }),
    preflight_artifact: inputProvenanceEntry({
      source: preflightArtifact?.source || fallbackSource,
      displayPath: preflightArtifact?.displayPath || SAMPLE_PREFLIGHT_ARTIFACT_DISPLAY_PATH,
      textSha256: preflightArtifact?.textSha256 || SAMPLE_PREFLIGHT_ARTIFACT_TEXT_SHA256,
    }),
  };
  assertProtectedRecordsOneTerminalDeploymentProfileInputProvenance(provenance);
  return provenance;
}

export function assertProtectedRecordsOneTerminalDeploymentProfileInputProvenance(provenance) {
  assertExactKeys('Protected records one-terminal input provenance', provenance, [
    'absolute_paths_emitted',
    'deployment_profile',
    'input_mode',
    'preflight_artifact',
    'provenance_type',
    'runtime_profile',
    'source_paths_public_safe',
    'source_text_hashes_bound',
  ]);
  if (
    provenance.provenance_type !== PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_INPUT_PROVENANCE_TYPE ||
    !['sample', 'explicit-files'].includes(provenance.input_mode) ||
    provenance.source_text_hashes_bound !== true ||
    provenance.source_paths_public_safe !== true ||
    provenance.absolute_paths_emitted !== false
  ) {
    throw new Error('Protected records one-terminal input provenance top-level contract drifted');
  }
  for (const key of ['deployment_profile', 'runtime_profile', 'preflight_artifact']) {
    assertExactKeys(`Protected records one-terminal input provenance ${key}`, provenance[key], [
      'display_path',
      'source',
      'text_sha256',
    ]);
    assertInputSource(provenance[key].source);
    assertSafeDisplayPath(`Protected records one-terminal input provenance ${key} display path`, provenance[key].display_path);
    assertSha256(`Protected records one-terminal input provenance ${key} text SHA-256`, provenance[key].text_sha256);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(provenance));
  return true;
}

export function oneTerminalDeploymentProfileSha256(profile) {
  assertProtectedRecordsOneTerminalDeploymentProfile(profile);
  return sha256hex(canonicalize(profile));
}

export function assertProtectedRecordsOneTerminalDeploymentProfile(profile) {
  assertExactKeys('Protected records one-terminal deployment profile', profile, [
    'action_class',
    'authority_boundary',
    'deployment_model',
    'non_claims',
    'profile_id',
    'profile_status',
    'profile_type',
    'proof_boundary',
    'proof_command',
    'request_contract',
    'selected_runtime_profile',
  ]);
  assertProfileId('Protected records one-terminal deployment profile id', profile.profile_id);
  if (
    profile.profile_type !== PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_TYPE ||
    profile.profile_status !== 'sample_not_active' ||
    profile.deployment_model !== 'one-terminal-local-fixture' ||
    profile.action_class !== 'records.write' ||
    profile.request_contract !== 'receipt-record-update-and-routing-metadata-only' ||
    profile.proof_command !== 'zlar protected-records-one-terminal-deployment-profile --sample'
  ) {
    throw new Error('Protected records one-terminal deployment profile top-level contract drifted');
  }

  assertExactKeys('Protected records one-terminal deployment selected runtime profile', profile.selected_runtime_profile, [
    'profile_id',
    'profile_path',
    'profile_sha256',
    'runtime_profile_id',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
    'source',
  ]);
  assertProfileId(
    'Protected records one-terminal deployment selected profile id',
    profile.selected_runtime_profile.profile_id
  );
  assertSha256(
    'Protected records one-terminal deployment selected profile SHA-256',
    profile.selected_runtime_profile.profile_sha256
  );
  if (
    profile.selected_runtime_profile.source !== 'deployment-owned-profile-artifact' ||
    profile.selected_runtime_profile.profile_path !==
      'profiles/protected-records-runtime-fixture.profile.json' ||
    profile.selected_runtime_profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    profile.selected_runtime_profile.selected_by_explicit_id_and_sha !== true ||
    profile.selected_runtime_profile.selects_latest_profile !== false
  ) {
    throw new Error('Protected records one-terminal deployment runtime-profile selection drifted');
  }

  assertExactKeys('Protected records one-terminal deployment authority boundary', profile.authority_boundary, [
    'agent_supplied_authority_material_accepted',
    'deployment_owned_profile_artifact',
    'fixture_mode_supplied_by_agent',
    'profile_selected_by_id_and_sha',
    'recognition_rule_supplied_by_agent',
    'request_stream_authority_material_accepted',
    'unsupported_request_fields_accepted',
  ]);
  if (
    profile.authority_boundary.deployment_owned_profile_artifact !== true ||
    profile.authority_boundary.profile_selected_by_id_and_sha !== true ||
    profile.authority_boundary.request_stream_authority_material_accepted !== false ||
    profile.authority_boundary.recognition_rule_supplied_by_agent !== false ||
    profile.authority_boundary.fixture_mode_supplied_by_agent !== false ||
    profile.authority_boundary.unsupported_request_fields_accepted !== false ||
    profile.authority_boundary.agent_supplied_authority_material_accepted !== false
  ) {
    throw new Error('Protected records one-terminal deployment authority boundary drifted');
  }

  assertExactKeys('Protected records one-terminal deployment proof boundary', profile.proof_boundary, [
    'activation_performed',
    'current_machine_governance',
    'enterprise_readiness',
    'external_attestation',
    'live_records_system',
    'live_runtime_service',
    'local_fixture_only',
    'persistent_install',
    'production_authority',
    'production_downstream_recognition',
    'sovereign_recognition',
    'unrouted_surface_coverage',
  ]);
  if (
    profile.proof_boundary.local_fixture_only !== true ||
    profile.proof_boundary.persistent_install !== false ||
    profile.proof_boundary.activation_performed !== false ||
    profile.proof_boundary.live_runtime_service !== false ||
    profile.proof_boundary.live_records_system !== false ||
    profile.proof_boundary.production_downstream_recognition !== false ||
    profile.proof_boundary.production_authority !== false ||
    profile.proof_boundary.current_machine_governance !== false ||
    profile.proof_boundary.enterprise_readiness !== false ||
    profile.proof_boundary.external_attestation !== false ||
    profile.proof_boundary.sovereign_recognition !== false ||
    profile.proof_boundary.unrouted_surface_coverage !== false
  ) {
    throw new Error('Protected records one-terminal deployment proof boundary drifted');
  }
  if (!Array.isArray(profile.non_claims) || profile.non_claims.length < 5) {
    throw new Error('Protected records one-terminal deployment non-claims drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(profile));
  return true;
}

function observedRefusalCases(serviceProof) {
  return serviceProof.refusal_cases.map((item) => ({
    case_id: item.case_id,
    reason_code: item.reason_code,
    state_entry_count_delta: item.state_entry_count_delta,
    refused_before_mutation:
      item.boarded === false &&
      item.service_write_accepted === false &&
      item.decision === 'refuse' &&
      item.state_entry_count_delta === 0,
  }));
}

function recomputePreflightArtifactIntegrity(artifact) {
  const next = structuredClone(artifact);
  const { integrity, ...body } = next;
  next.integrity = {
    ...integrity,
    algorithm: 'SHA-256',
    body_sha256: sha256hex(canonicalize(body)),
  };
  return next;
}

class DeploymentProfileAuthorityRefusalError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.reasonCode = reasonCode;
  }
}

function throwDeploymentProfileAuthorityRefusal(reasonCode, message) {
  throw new DeploymentProfileAuthorityRefusalError(reasonCode, message);
}

function authorityRefusalReasonFromError(err) {
  if (err instanceof DeploymentProfileAuthorityRefusalError) {
    return err.reasonCode;
  }
  return 'unclassified_deployment_profile_authority_failure';
}

function assertDeploymentProfileBridgeInputs({
  deploymentProfile,
  runtimeProfile,
  preflightArtifact,
}) {
  assertProtectedRecordsRuntimePreflightProfile(runtimeProfile);
  const runtimeProfileDigest = runtimeProfileSha256(runtimeProfile);
  const selectedRuntimeProfile = deploymentProfile?.selected_runtime_profile || {};
  if (selectedRuntimeProfile.runtime_profile_id !== runtimeProfile.runtime_profile_id) {
    throwDeploymentProfileAuthorityRefusal(
      'runtime_profile_id_mismatch',
      'Protected records one-terminal deployment runtime profile id mismatch'
    );
  }
  if (selectedRuntimeProfile.profile_sha256 !== runtimeProfileDigest) {
    throwDeploymentProfileAuthorityRefusal(
      'stale_deployment_profile_artifact',
      'Protected records one-terminal deployment runtime profile SHA mismatch'
    );
  }

  assertProtectedRecordsOneTerminalDeploymentProfile(deploymentProfile);

  const preflightArtifactPreflight = preflightArtifact?.payload?.preflight || {};
  if (
    preflightArtifactPreflight.requested_selection?.profile_sha256 !== undefined &&
    preflightArtifactPreflight.requested_selection.profile_sha256 !==
      deploymentProfile.selected_runtime_profile.profile_sha256
  ) {
    throwDeploymentProfileAuthorityRefusal(
      'preflight_profile_sha_mismatch',
      'Protected records one-terminal deployment preflight profile SHA mismatch'
    );
  }
  if (
    preflightArtifactPreflight.requested_selection?.selects_latest_profile !== undefined &&
    preflightArtifactPreflight.requested_selection.selects_latest_profile !== false
  ) {
    throwDeploymentProfileAuthorityRefusal(
      'latest_profile_selection',
      'Protected records one-terminal deployment preflight selected latest profile'
    );
  }
  if (
    preflightArtifactPreflight.inspection_boundary?.selects_latest_profile !== undefined &&
    preflightArtifactPreflight.inspection_boundary.selects_latest_profile !== false
  ) {
    throwDeploymentProfileAuthorityRefusal(
      'latest_profile_selection',
      'Protected records one-terminal deployment preflight selected latest profile'
    );
  }
  if (
    preflightArtifactPreflight.recognition_contract?.launcher_authority
      ?.request_stream_authority_material_accepted !== undefined &&
    preflightArtifactPreflight.recognition_contract.launcher_authority
      .request_stream_authority_material_accepted !== false
  ) {
    throwDeploymentProfileAuthorityRefusal(
      'request_stream_authority_material',
      'Protected records one-terminal deployment preflight accepted request-stream authority material'
    );
  }

  if (
    runtimeProfile.profile_id !== deploymentProfile.selected_runtime_profile.profile_id ||
    runtimeProfile.runtime_profile_id !== deploymentProfile.selected_runtime_profile.runtime_profile_id ||
    runtimeProfile.action_class !== deploymentProfile.action_class ||
    runtimeProfileDigest !== deploymentProfile.selected_runtime_profile.profile_sha256
  ) {
    throw new Error('Protected records one-terminal deployment selected runtime profile mismatch');
  }

  const preflightVerification =
    verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(preflightArtifact);
  if (
    preflightVerification.requested_profile_sha256 !==
      deploymentProfile.selected_runtime_profile.profile_sha256
  ) {
    throwDeploymentProfileAuthorityRefusal(
      'preflight_profile_sha_mismatch',
      'Protected records one-terminal deployment preflight profile SHA mismatch'
    );
  }
  if (preflightVerification.selects_latest_profile !== false) {
    throwDeploymentProfileAuthorityRefusal(
      'latest_profile_selection',
      'Protected records one-terminal deployment preflight selected latest profile'
    );
  }
  if (
    preflightVerification.request_stream_authority_material_accepted !== false ||
    preflightVerification.recognition_rule_supplied_by_agent !== false
  ) {
    throwDeploymentProfileAuthorityRefusal(
      'request_stream_authority_material',
      'Protected records one-terminal deployment preflight accepted request-stream authority material'
    );
  }
  if (
    preflightVerification.verified !== true ||
    preflightVerification.requested_profile_id !== deploymentProfile.selected_runtime_profile.profile_id ||
    preflightVerification.requested_profile_sha256 !==
      deploymentProfile.selected_runtime_profile.profile_sha256 ||
    preflightVerification.selected_by_explicit_id_and_sha !== true ||
    preflightVerification.selects_latest_profile !== false ||
    preflightVerification.request_stream_authority_material_accepted !== false ||
    preflightVerification.recognition_rule_supplied_by_agent !== false
  ) {
    throw new Error('Protected records one-terminal deployment preflight bridge drifted');
  }

  return { runtimeProfileDigest, preflightVerification };
}

function observeAuthorityRefusalCase(baseInputs, caseId, mutateInputs) {
  const attemptInputs = structuredClone(baseInputs);
  mutateInputs(attemptInputs);
  let refusedBeforeServiceProof = false;
  let reasonCode = 'bridge_accepted';
  try {
    assertDeploymentProfileBridgeInputs(attemptInputs);
  } catch (err) {
    refusedBeforeServiceProof = true;
    reasonCode = authorityRefusalReasonFromError(err);
  }
  return {
    case_id: caseId,
    reason_code: reasonCode,
    refused_before_service_proof: refusedBeforeServiceProof,
    refused_before_mutation: refusedBeforeServiceProof,
    service_proof_started: false,
    state_entry_count_delta: 0,
  };
}

function observedDeploymentProfileAuthorityRefusalCases(baseInputs) {
  return [
    observeAuthorityRefusalCase(
      baseInputs,
      'stale_deployment_profile_runtime_sha_refused_before_service_proof',
      (attempt) => {
        attempt.deploymentProfile.selected_runtime_profile.profile_sha256 = '0'.repeat(64);
      },
    ),
    observeAuthorityRefusalCase(
      baseInputs,
      'runtime_profile_id_mismatch_refused_before_service_proof',
      (attempt) => {
        attempt.deploymentProfile.selected_runtime_profile.runtime_profile_id =
          'wrong-runtime-profile';
      },
    ),
    observeAuthorityRefusalCase(
      baseInputs,
      'preflight_profile_sha_mismatch_refused_before_service_proof',
      (attempt) => {
        attempt.preflightArtifact.payload.preflight.requested_selection.profile_sha256 =
          '1'.repeat(64);
        attempt.preflightArtifact = recomputePreflightArtifactIntegrity(
          attempt.preflightArtifact,
        );
      },
    ),
    observeAuthorityRefusalCase(
      baseInputs,
      'preflight_latest_selection_refused_before_service_proof',
      (attempt) => {
        attempt.preflightArtifact.payload.preflight.requested_selection.selects_latest_profile =
          true;
        attempt.preflightArtifact.payload.preflight.inspection_boundary.selects_latest_profile =
          true;
        attempt.preflightArtifact = recomputePreflightArtifactIntegrity(
          attempt.preflightArtifact,
        );
      },
    ),
    observeAuthorityRefusalCase(
      baseInputs,
      'preflight_request_authority_material_refused_before_service_proof',
      (attempt) => {
        attempt.preflightArtifact.payload.preflight.recognition_contract
          .launcher_authority.request_stream_authority_material_accepted = true;
        attempt.preflightArtifact = recomputePreflightArtifactIntegrity(
          attempt.preflightArtifact,
        );
      },
    ),
  ];
}

function buildDeploymentProfileAuthorityRefusals(baseInputs) {
  const cases = observedDeploymentProfileAuthorityRefusalCases(baseInputs);
  const allRefusedBeforeServiceProof =
    cases.length === REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length &&
    cases.every((item, index) => (
      item.case_id === REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES[index] &&
      item.reason_code ===
        ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_REASONS[item.case_id] &&
      item.refused_before_service_proof === true &&
      item.refused_before_mutation === true &&
      item.service_proof_started === false &&
      item.state_entry_count_delta === 0
    ));

  return {
    required_refusal_case_count:
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length,
    observed_refusal_case_count: cases.length,
    refusal_case_ids: cases.map((item) => item.case_id),
    all_refused_before_service_proof: allRefusedBeforeServiceProof,
    all_refused_before_mutation: allRefusedBeforeServiceProof,
    service_proof_started_for_refusals: false,
    stale_deployment_profile_artifact_refused_before_service_proof:
      cases.some((item) =>
        item.case_id ===
          'stale_deployment_profile_runtime_sha_refused_before_service_proof' &&
        item.refused_before_service_proof === true
      ),
    profile_recognition_mismatch_refused_before_service_proof:
      cases
        .filter((item) => [
          'runtime_profile_id_mismatch_refused_before_service_proof',
          'preflight_profile_sha_mismatch_refused_before_service_proof',
        ].includes(item.case_id))
        .every((item) => item.refused_before_service_proof === true),
    latest_profile_selection_refused_before_service_proof:
      cases.some((item) =>
        item.case_id ===
          'preflight_latest_selection_refused_before_service_proof' &&
        item.refused_before_service_proof === true
      ),
    request_stream_authority_material_refused_before_service_proof:
      cases.some((item) =>
        item.case_id ===
          'preflight_request_authority_material_refused_before_service_proof' &&
        item.refused_before_service_proof === true
      ),
    cases,
  };
}

export function runProtectedRecordsOneTerminalDeploymentProfileProof({
  deploymentProfile,
  runtimeProfile,
  preflightArtifact,
  serviceProofArtifact = null,
  inputProvenance,
  nowEpoch = PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
} = {}) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'One-terminal deployment-profile proof generation',
  );
  const { runtimeProfileDigest, preflightVerification } =
    assertDeploymentProfileBridgeInputs({
      deploymentProfile,
      runtimeProfile,
      preflightArtifact,
    });

  if (nowEpoch !== PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH) {
    throw new Error(
      'Protected records one-terminal committed service-proof artifact has a fixed fixture evaluation epoch',
    );
  }
  const committedServiceProofArtifact =
    serviceProofArtifact ||
    readCommittedProtectedRecordsInstalledRuntimeProfileServiceProofArtifact();
  assertProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
    committedServiceProofArtifact,
  );
  const serviceProof = committedServiceProofArtifact.payload.proof;
  const authorityGrantContractSha256 =
    serviceProof.authority_contract.public_safe_grant_summary
      .authority_grant_contract_sha256;
  const authorityGrantStatus = protectedRecordsFixtureAuthorityGrantStatus(
    authorityGrantContractSha256,
  );
  if (authorityGrantStatus.fresh_fixture_rightful_projection_allowed !== true) {
    const reason = protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      authorityGrantContractSha256,
    );
    throw new Error(
      `Protected records one-terminal committed service-proof fixture-rightful projection refused: ${reason.code}`,
    );
  }
  const serviceProofArtifactVerification =
    verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
      committedServiceProofArtifact,
      {
        expectedArtifactBodySha256:
          PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256,
      },
    );
  if (
    serviceProofArtifactVerification.source_preflight_body_sha256 !==
      preflightArtifact.integrity.body_sha256
  ) {
    throw new Error(
      'Protected records one-terminal committed service-proof source preflight identity drifted',
    );
  }
  assertProtectedRecordsInstalledRuntimeProfileServiceProof(serviceProof);
  const refusals = observedRefusalCases(serviceProof);
  const allRefusalsBeforeMutation =
    refusals.length === REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length &&
    refusals.every((item, index) => (
      item.case_id === REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES[index] &&
      item.reason_code === EXPECTED_REFUSAL_REASONS[item.case_id] &&
      item.refused_before_mutation === true
    ));
  const agentSuppliedAuthorityRefusedBeforeMutation = refusals.some((item) => (
    item.case_id === 'agent_supplied_recognition_rule_refused_before_runtime_mutation' &&
    item.reason_code === EXPECTED_REFUSAL_REASONS[item.case_id] &&
    item.refused_before_mutation === true
  ));
  const directApiRefusedBeforeMutation = refusals
    .filter((item) => item.case_id.startsWith('direct_api_'))
    .every((item) => item.refused_before_mutation === true);
  const deploymentProfileAuthorityRefusals =
    buildDeploymentProfileAuthorityRefusals({
      deploymentProfile,
      runtimeProfile,
      preflightArtifact,
    });
  const normalizedInputProvenance =
    inputProvenance || buildProtectedRecordsOneTerminalDeploymentProfileInputProvenance();
  assertProtectedRecordsOneTerminalDeploymentProfileInputProvenance(normalizedInputProvenance);

  const report = {
    proof_type: PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE,
    evidence_model: 'local-fixture-one-terminal-deployment-profile-authority-bridge',
    live_probing: false,
    safe_claim_ceiling: ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING,
    input_provenance: normalizedInputProvenance,
    deployment_profile: {
      profile_type: deploymentProfile.profile_type,
      profile_id: deploymentProfile.profile_id,
      profile_sha256: oneTerminalDeploymentProfileSha256(deploymentProfile),
      deployment_owned_profile_artifact: true,
      deployment_model: deploymentProfile.deployment_model,
      action_class: deploymentProfile.action_class,
      proof_command: deploymentProfile.proof_command,
    },
    selected_runtime_profile: {
      profile_id: runtimeProfile.profile_id,
      runtime_profile_id: runtimeProfile.runtime_profile_id,
      profile_sha256: runtimeProfileDigest,
      profile_sha_matches_deployment_profile: true,
      selected_by_explicit_id_and_sha:
        deploymentProfile.selected_runtime_profile.selected_by_explicit_id_and_sha,
      selects_latest_profile: deploymentProfile.selected_runtime_profile.selects_latest_profile,
    },
    preflight_bridge: {
      verified: preflightVerification.verified,
      artifact_type: preflightVerification.artifact_type,
      body_sha256: preflightVerification.body_sha256,
      selected_profile_id: preflightVerification.requested_profile_id,
      selected_profile_sha256: preflightVerification.requested_profile_sha256,
      selected_by_explicit_id_and_sha: preflightVerification.selected_by_explicit_id_and_sha,
      selects_latest_profile: preflightVerification.selects_latest_profile,
      recognition_contract_preserved: preflightVerification.recognition_contract_preserved,
      recognition_contract_sha256: preflightVerification.recognition_contract_sha256,
      request_stream_authority_material_accepted:
        preflightVerification.request_stream_authority_material_accepted,
      recognition_rule_supplied_by_agent:
        preflightVerification.recognition_rule_supplied_by_agent,
      current_machine_governance_proven:
        preflightVerification.current_machine_governance_proven,
    },
    service_proof_bridge: {
      proof_type: serviceProof.proof_type,
      evidence_model: serviceProof.evidence_model,
      recognized_case_id: serviceProof.recognized_boarding.case_id,
      recognized_state_entry_count_delta:
        serviceProof.recognized_boarding.state_entry_count_delta,
      recognized_receipt_mutates_once:
        serviceProof.recognized_boarding.state_entry_count_delta === 1 &&
        serviceProof.recognized_boarding.boarded === true,
      required_refusal_case_count:
        REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
      observed_refusal_case_count: refusals.length,
      all_refusals_before_mutation: allRefusalsBeforeMutation,
      agent_supplied_authority_refused_before_mutation:
        agentSuppliedAuthorityRefusedBeforeMutation,
      direct_api_refused_before_mutation: directApiRefusedBeforeMutation,
      downstream_refusal_proven: true,
      service_process_boundary: 'local-disposable-child-service',
    },
    deployment_profile_authority_refusals:
      deploymentProfileAuthorityRefusals,
    authority_boundary: {
      deployment_profile_artifact_authoritative: true,
      request_authority_limited_to_receipt_and_record_update: true,
      request_stream_authority_material_accepted: false,
      recognition_rule_supplied_by_agent: false,
      fixture_mode_supplied_by_agent: false,
      unsupported_request_fields_accepted: false,
      agent_supplied_authority_material_accepted: false,
      agent_supplied_authority_refused_before_mutation:
        agentSuppliedAuthorityRefusedBeforeMutation,
    },
    acceptance_gates: {
      deployment_profile_artifact_sha_bound: true,
      source_text_hashes_bound:
        normalizedInputProvenance.source_text_hashes_bound === true,
      runtime_profile_sha_bound: true,
      preflight_selected_by_id_and_sha: true,
      no_latest_selection: true,
      recognized_receipt_mutates_once:
        serviceProof.recognized_boarding.state_entry_count_delta === 1,
      all_required_refusals_before_mutation: allRefusalsBeforeMutation,
      agent_supplied_authority_refused_before_mutation:
        agentSuppliedAuthorityRefusedBeforeMutation,
      direct_api_refused_before_mutation: directApiRefusedBeforeMutation,
      deployment_profile_authority_refusals_before_service_proof:
        deploymentProfileAuthorityRefusals.all_refused_before_service_proof,
      no_live_probing: true,
    },
    proof_boundary: {
      local_fixture_only: true,
      local_disposable_child_service: true,
      persistent_install: false,
      activation_performed: false,
      live_runtime_service: false,
      live_records_system: false,
      production_downstream_recognition: false,
      production_authority: false,
      current_machine_governance: false,
      enterprise_readiness: false,
      external_attestation: false,
      sovereign_recognition: false,
      unrouted_surface_coverage: false,
    },
    observed_refusal_cases: refusals,
    non_claims: [
      ...ONE_TERMINAL_DEPLOYMENT_PROFILE_NON_CLAIMS,
      ...INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_NON_CLAIMS.slice(0, 2),
    ],
  };
  assertProtectedRecordsOneTerminalDeploymentProfileProof(report);
  return report;
}

export function assertProtectedRecordsOneTerminalDeploymentProfileProof(report) {
  assertExactKeys('Protected records one-terminal deployment profile proof', report, [
    'acceptance_gates',
    'authority_boundary',
    'deployment_profile',
    'deployment_profile_authority_refusals',
    'evidence_model',
    'input_provenance',
    'live_probing',
    'non_claims',
    'observed_refusal_cases',
    'preflight_bridge',
    'proof_boundary',
    'proof_type',
    'safe_claim_ceiling',
    'selected_runtime_profile',
    'service_proof_bridge',
  ]);
  if (
    report.proof_type !== PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_PROOF_TYPE ||
    report.evidence_model !== 'local-fixture-one-terminal-deployment-profile-authority-bridge' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== ONE_TERMINAL_DEPLOYMENT_PROFILE_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records one-terminal deployment profile proof top-level contract drifted');
  }
  assertProtectedRecordsOneTerminalDeploymentProfileInputProvenance(report.input_provenance);

  assertExactKeys('Protected records one-terminal deployment profile proof deployment profile', report.deployment_profile, [
    'action_class',
    'deployment_model',
    'deployment_owned_profile_artifact',
    'profile_id',
    'profile_sha256',
    'profile_type',
    'proof_command',
  ]);
  assertSha256('Protected records one-terminal deployment profile proof profile SHA-256', report.deployment_profile.profile_sha256);
  if (
    report.deployment_profile.profile_type !== PROTECTED_RECORDS_ONE_TERMINAL_DEPLOYMENT_PROFILE_TYPE ||
    report.deployment_profile.deployment_owned_profile_artifact !== true ||
    report.deployment_profile.deployment_model !== 'one-terminal-local-fixture' ||
    report.deployment_profile.action_class !== 'records.write'
  ) {
    throw new Error('Protected records one-terminal deployment profile proof deployment profile drifted');
  }

  assertExactKeys('Protected records one-terminal deployment profile proof selected runtime profile', report.selected_runtime_profile, [
    'profile_id',
    'profile_sha256',
    'profile_sha_matches_deployment_profile',
    'runtime_profile_id',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
  ]);
  assertSha256('Protected records one-terminal deployment profile proof runtime profile SHA-256', report.selected_runtime_profile.profile_sha256);
  if (
    report.selected_runtime_profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.selected_runtime_profile.profile_sha_matches_deployment_profile !== true ||
    report.selected_runtime_profile.selected_by_explicit_id_and_sha !== true ||
    report.selected_runtime_profile.selects_latest_profile !== false
  ) {
    throw new Error('Protected records one-terminal deployment profile proof runtime profile drifted');
  }

  assertExactKeys('Protected records one-terminal deployment profile proof preflight bridge', report.preflight_bridge, [
    'artifact_type',
    'body_sha256',
    'current_machine_governance_proven',
    'recognition_contract_preserved',
    'recognition_contract_sha256',
    'recognition_rule_supplied_by_agent',
    'request_stream_authority_material_accepted',
    'selected_by_explicit_id_and_sha',
    'selected_profile_id',
    'selected_profile_sha256',
    'selects_latest_profile',
    'verified',
  ]);
  if (
    report.preflight_bridge.verified !== true ||
    report.preflight_bridge.selected_profile_id !== report.selected_runtime_profile.profile_id ||
    report.preflight_bridge.selected_profile_sha256 !== report.selected_runtime_profile.profile_sha256 ||
    report.preflight_bridge.selected_by_explicit_id_and_sha !== true ||
    report.preflight_bridge.selects_latest_profile !== false ||
    report.preflight_bridge.recognition_contract_preserved !== true ||
    report.preflight_bridge.request_stream_authority_material_accepted !== false ||
    report.preflight_bridge.recognition_rule_supplied_by_agent !== false ||
    report.preflight_bridge.current_machine_governance_proven !== false
  ) {
    throw new Error('Protected records one-terminal deployment profile proof preflight bridge drifted');
  }

  assertExactKeys('Protected records one-terminal deployment profile proof service bridge', report.service_proof_bridge, [
    'agent_supplied_authority_refused_before_mutation',
    'all_refusals_before_mutation',
    'direct_api_refused_before_mutation',
    'downstream_refusal_proven',
    'evidence_model',
    'observed_refusal_case_count',
    'proof_type',
    'recognized_case_id',
    'recognized_receipt_mutates_once',
    'recognized_state_entry_count_delta',
    'required_refusal_case_count',
    'service_process_boundary',
  ]);
  if (
    report.service_proof_bridge.recognized_receipt_mutates_once !== true ||
    report.service_proof_bridge.recognized_state_entry_count_delta !== 1 ||
    report.service_proof_bridge.required_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.service_proof_bridge.observed_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.service_proof_bridge.all_refusals_before_mutation !== true ||
    report.service_proof_bridge.agent_supplied_authority_refused_before_mutation !== true ||
    report.service_proof_bridge.direct_api_refused_before_mutation !== true ||
    report.service_proof_bridge.downstream_refusal_proven !== true
  ) {
    throw new Error('Protected records one-terminal deployment profile proof service bridge drifted');
  }

  assertExactKeys(
    'Protected records one-terminal deployment profile proof authority refusals',
    report.deployment_profile_authority_refusals,
    [
      'all_refused_before_mutation',
      'all_refused_before_service_proof',
      'cases',
      'latest_profile_selection_refused_before_service_proof',
      'observed_refusal_case_count',
      'profile_recognition_mismatch_refused_before_service_proof',
      'refusal_case_ids',
      'request_stream_authority_material_refused_before_service_proof',
      'required_refusal_case_count',
      'service_proof_started_for_refusals',
      'stale_deployment_profile_artifact_refused_before_service_proof',
    ],
  );
  if (
    report.deployment_profile_authority_refusals.required_refusal_case_count !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    report.deployment_profile_authority_refusals.observed_refusal_case_count !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length ||
    report.deployment_profile_authority_refusals.all_refused_before_service_proof !== true ||
    report.deployment_profile_authority_refusals.all_refused_before_mutation !== true ||
    report.deployment_profile_authority_refusals.service_proof_started_for_refusals !== false ||
    report.deployment_profile_authority_refusals
      .stale_deployment_profile_artifact_refused_before_service_proof !== true ||
    report.deployment_profile_authority_refusals
      .profile_recognition_mismatch_refused_before_service_proof !== true ||
    report.deployment_profile_authority_refusals
      .latest_profile_selection_refused_before_service_proof !== true ||
    report.deployment_profile_authority_refusals
      .request_stream_authority_material_refused_before_service_proof !== true
  ) {
    throw new Error('Protected records one-terminal deployment authority refusal summary drifted');
  }
  assertExactArray(
    'Protected records one-terminal deployment authority refusal case IDs',
    report.deployment_profile_authority_refusals.refusal_case_ids,
    REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES,
  );
  if (
    !Array.isArray(report.deployment_profile_authority_refusals.cases) ||
    report.deployment_profile_authority_refusals.cases.length !==
      REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES.length
  ) {
    throw new Error('Protected records one-terminal deployment authority refusal cases drifted');
  }
  for (const [index, item] of report.deployment_profile_authority_refusals.cases.entries()) {
    assertExactKeys('Protected records one-terminal deployment authority refusal case', item, [
      'case_id',
      'reason_code',
      'refused_before_mutation',
      'refused_before_service_proof',
      'service_proof_started',
      'state_entry_count_delta',
    ]);
    if (
      item.case_id !== REQUIRED_ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_CASES[index] ||
      item.reason_code !==
        ONE_TERMINAL_DEPLOYMENT_PROFILE_AUTHORITY_REFUSAL_REASONS[item.case_id] ||
      item.refused_before_service_proof !== true ||
      item.refused_before_mutation !== true ||
      item.service_proof_started !== false ||
      item.state_entry_count_delta !== 0
    ) {
      throw new Error(`Protected records one-terminal deployment authority refusal drifted: ${item.case_id}`);
    }
  }

  assertExactKeys('Protected records one-terminal deployment profile proof authority boundary', report.authority_boundary, [
    'agent_supplied_authority_material_accepted',
    'agent_supplied_authority_refused_before_mutation',
    'deployment_profile_artifact_authoritative',
    'fixture_mode_supplied_by_agent',
    'recognition_rule_supplied_by_agent',
    'request_authority_limited_to_receipt_and_record_update',
    'request_stream_authority_material_accepted',
    'unsupported_request_fields_accepted',
  ]);
  if (
    report.authority_boundary.deployment_profile_artifact_authoritative !== true ||
    report.authority_boundary.request_authority_limited_to_receipt_and_record_update !== true ||
    report.authority_boundary.request_stream_authority_material_accepted !== false ||
    report.authority_boundary.recognition_rule_supplied_by_agent !== false ||
    report.authority_boundary.fixture_mode_supplied_by_agent !== false ||
    report.authority_boundary.unsupported_request_fields_accepted !== false ||
    report.authority_boundary.agent_supplied_authority_material_accepted !== false ||
    report.authority_boundary.agent_supplied_authority_refused_before_mutation !== true
  ) {
    throw new Error('Protected records one-terminal deployment profile proof authority boundary drifted');
  }

  assertExactKeys('Protected records one-terminal deployment profile proof acceptance gates', report.acceptance_gates, [
    'agent_supplied_authority_refused_before_mutation',
    'all_required_refusals_before_mutation',
    'deployment_profile_artifact_sha_bound',
    'deployment_profile_authority_refusals_before_service_proof',
    'direct_api_refused_before_mutation',
    'no_latest_selection',
    'no_live_probing',
    'preflight_selected_by_id_and_sha',
    'recognized_receipt_mutates_once',
    'runtime_profile_sha_bound',
    'source_text_hashes_bound',
  ]);
  if (!Object.values(report.acceptance_gates).every((value) => value === true)) {
    throw new Error('Protected records one-terminal deployment profile proof acceptance gate drifted');
  }

  assertExactKeys('Protected records one-terminal deployment profile proof boundary', report.proof_boundary, [
    'activation_performed',
    'current_machine_governance',
    'enterprise_readiness',
    'external_attestation',
    'live_records_system',
    'live_runtime_service',
    'local_disposable_child_service',
    'local_fixture_only',
    'persistent_install',
    'production_authority',
    'production_downstream_recognition',
    'sovereign_recognition',
    'unrouted_surface_coverage',
  ]);
  if (
    report.proof_boundary.local_fixture_only !== true ||
    report.proof_boundary.local_disposable_child_service !== true ||
    report.proof_boundary.persistent_install !== false ||
    report.proof_boundary.activation_performed !== false ||
    report.proof_boundary.live_runtime_service !== false ||
    report.proof_boundary.live_records_system !== false ||
    report.proof_boundary.production_downstream_recognition !== false ||
    report.proof_boundary.production_authority !== false ||
    report.proof_boundary.current_machine_governance !== false ||
    report.proof_boundary.enterprise_readiness !== false ||
    report.proof_boundary.external_attestation !== false ||
    report.proof_boundary.sovereign_recognition !== false ||
    report.proof_boundary.unrouted_surface_coverage !== false
  ) {
    throw new Error('Protected records one-terminal deployment profile proof boundary drifted');
  }

  assertExactArray(
    'Protected records one-terminal deployment profile proof refusal cases',
    report.observed_refusal_cases.map((item) => item.case_id),
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  for (const refusal of report.observed_refusal_cases) {
    assertExactKeys('Protected records one-terminal deployment profile proof refusal case', refusal, [
      'case_id',
      'reason_code',
      'refused_before_mutation',
      'state_entry_count_delta',
    ]);
    if (
      refusal.reason_code !== EXPECTED_REFUSAL_REASONS[refusal.case_id] ||
      refusal.refused_before_mutation !== true ||
      refusal.state_entry_count_delta !== 0
    ) {
      throw new Error(`Protected records one-terminal deployment refusal case drifted: ${refusal.case_id}`);
    }
  }
  if (!Array.isArray(report.non_claims) || report.non_claims.length < 5) {
    throw new Error('Protected records one-terminal deployment profile proof non-claims drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsOneTerminalDeploymentProfileProofSummary(report) {
  assertProtectedRecordsOneTerminalDeploymentProfileProof(report);
  const lines = [
    'ZLAR Protected Records One-Terminal Deployment Profile Proof v1',
    `proof_type=${report.proof_type}`,
    `evidence_model=${report.evidence_model}`,
    `input_mode=${report.input_provenance.input_mode}`,
    `source_text_hashes_bound=${report.input_provenance.source_text_hashes_bound}`,
    `deployment_profile_id=${report.deployment_profile.profile_id}`,
    `deployment_profile_sha256=${report.deployment_profile.profile_sha256}`,
    `selected_runtime_profile_id=${report.selected_runtime_profile.profile_id}`,
    `selected_runtime_profile_sha256=${report.selected_runtime_profile.profile_sha256}`,
    `selected_by_explicit_id_and_sha=${report.selected_runtime_profile.selected_by_explicit_id_and_sha}`,
    `selects_latest_profile=${report.selected_runtime_profile.selects_latest_profile}`,
    `preflight_artifact_verified=${report.preflight_bridge.verified}`,
    `recognized_receipt_mutates_once=${report.service_proof_bridge.recognized_receipt_mutates_once}`,
    `all_required_refusals_before_mutation=${report.service_proof_bridge.all_refusals_before_mutation}`,
    `agent_supplied_authority_refused_before_mutation=${report.service_proof_bridge.agent_supplied_authority_refused_before_mutation}`,
    `direct_api_refused_before_mutation=${report.service_proof_bridge.direct_api_refused_before_mutation}`,
    `deployment_profile_authority_refusals_before_service_proof=${report.deployment_profile_authority_refusals.all_refused_before_service_proof}`,
    `deployment_profile_authority_refusal_case_count=${report.deployment_profile_authority_refusals.observed_refusal_case_count}`,
    `stale_deployment_profile_artifact_refused_before_service_proof=${report.deployment_profile_authority_refusals.stale_deployment_profile_artifact_refused_before_service_proof}`,
    `profile_recognition_mismatch_refused_before_service_proof=${report.deployment_profile_authority_refusals.profile_recognition_mismatch_refused_before_service_proof}`,
    `latest_profile_selection_refused_before_service_proof=${report.deployment_profile_authority_refusals.latest_profile_selection_refused_before_service_proof}`,
    `request_stream_authority_material_refused_before_service_proof=${report.deployment_profile_authority_refusals.request_stream_authority_material_refused_before_service_proof}`,
    `downstream_refusal_proven=${report.service_proof_bridge.downstream_refusal_proven}`,
    `production_downstream_recognition=${report.proof_boundary.production_downstream_recognition}`,
    `production_authority=${report.proof_boundary.production_authority}`,
    `current_machine_governance=${report.proof_boundary.current_machine_governance}`,
    `enterprise_readiness=${report.proof_boundary.enterprise_readiness}`,
    `external_attestation=${report.proof_boundary.external_attestation}`,
    'observed_refusal_cases:',
    ...report.observed_refusal_cases.map((item) => (
      `- ${item.case_id}: reason=${item.reason_code} delta=${item.state_entry_count_delta}`
    )),
    '',
  ];
  const output = `${lines.join('\n')}`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  return output;
}
