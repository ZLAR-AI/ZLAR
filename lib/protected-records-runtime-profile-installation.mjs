import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS,
  protectedRecordsFixtureAuthorityGrantEffectStatusReason,
} from './protected-records-fixture-authority-status.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  sha256hex,
} from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeProfileProof,
  createProtectedRecordsRuntimeAuthorityReceiptEvidence,
  createProtectedRecordsRuntimeFixtureAuthorityGrantContract,
  createProtectedRecordsRuntimeLauncherScopeEvidence,
  createProtectedRecordsRuntimeTargetBinding,
  createProtectedRecordsRuntimeService,
  protectedRecordsTargetEffect,
  runProtectedRecordsRuntimeProfileProof,
} from './protected-records-runtime-profile.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  createProtectedRecordsFixtureAuthorityGrantAppointment,
  evaluateProtectedRecordsFixtureAuthorityGrantIssuance,
  protectedRecordsAuthorizedEffectDetail,
} from './protected-records-fixture-authority-grant.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';

export const PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PLAN_TYPE =
  'zlar-protected-records-runtime-profile-installation-plan-v1';
export const PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE =
  'zlar-protected-records-runtime-profile-installation-proof-v1';
export const PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE =
  'zlar-protected-records-runtime-profile-installation-artifact-v1';
export const PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';
export const PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-runtime-profile-installation-artifact-verification-v1';

export const REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS = Object.freeze([
  'explicit_disposable_install_command',
  'profile_sha_verified_before_installation',
  'launcher_owned_disposable_install_root',
  'active_profile_selected_by_id_and_sha',
  'launcher_owned_fixture_authority_grant_material',
  'downstream_refuses_missing_or_unrecognized_receipts',
  'rightful_issuance_and_grant_refusals_proven',
  'store_anchor_witness_boundaries_accepted_or_external_custody_added',
]);

export const REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES = Object.freeze([
  'disposable_install_only',
  'persistent_runtime_profile_installation',
  'hook_configuration',
  'user_or_machine_configuration',
  'live_runtime_profile',
  'live_records_system',
  'production_records_service',
  'current_machine_governance',
  'live_mcp_coverage',
  'live_approval_channel_health',
  'exactly_once_effect_semantics',
  'store_anchor_and_witness_rollback_or_deletion',
  'store_anchor_witness_commit_atomicity',
  'host_filesystem_path_toctou',
  'anti_rollback_anchor_custody',
  'stale_lock_recovery',
  'multi_host_consumed_store_coordination',
  'production_durable_consumed_store',
  'host_process_or_memory_introspection',
  'external_attestation',
  'sovereign_recognition',
  'unrouted_records_paths',
]);

export const RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING =
  'ZLAR can install a pinned protected-records runtime profile inside a launcher-owned disposable proof root, select it by explicit profile id and SHA without --latest or request-stream authority, then run local JSONL child-service proof that accepts one exactly scoped fixture-authority records.write and refuses signed-payload replay, consumed-grant reuse, missing, mismatched, expired, revoked, or request-supplied grants, and required receipt-recognition failures before runtime-state mutation.';

export const RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS = Object.freeze([
  'This proof installs a runtime profile only inside a launcher-owned disposable proof root; it is not a persistent install or production deployment.',
  'This proof writes only disposable proof-harness files; it does not modify hooks, user config, machine configuration, or production configuration.',
  'This proof selects by explicit profile id and SHA; it does not select --latest, a live profile, or a current-machine profile.',
  'This proof starts local JSONL child service processes only through the bounded runtime-profile proof; it does not start or inspect a live records system or production records service.',
  'This proof does not use Telegram or prove live human approval-channel delivery.',
  'This proof does not prove current-machine governance, live MCP coverage, external attestation, enterprise readiness, production authority, sovereign recognition, or coverage of unrouted surfaces.',
  'This proof carries local fixture rightful-issuance evidence only; it does not prove production authority, portable rightful issuance, a live target, current-machine governance, or consequence-lifecycle closure.',
  'This proof inherits runtime-profile storage boundaries: no exactly-once effects, no atomic all-or-nothing commit across the consumed-authority-grant store, local anchor, and local witness, no joint store-anchor-witness rollback detection, no host-path TOCTOU closure, no production durable storage, no stale-lock recovery, no multi-host coordination, and no external anti-rollback custody.',
  'This proof does not close host process, memory, debugger, operator filesystem, hook-configuration, user-configuration, machine-configuration, or unrouted records side doors.',
]);

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

function proofCase(proof, caseId) {
  const item = proof.cases.find((candidate) => candidate.case_id === caseId);
  if (!item) {
    throw new Error(`Runtime profile installation proof missing case ${caseId}`);
  }
  return item;
}

function caseSummary(item) {
  return {
    case_id: item.case_id,
    service_process_invocation: item.service_process_invocation,
    request_ordinal: item.request_ordinal,
    service_write_accepted: item.service_write_accepted,
    reason_code: item.reason_code,
    state_entry_count_delta: item.state_entry_count_delta,
    direct_api_attempted: item.direct_api_attempted,
  };
}

export function runtimeProfileInstallationPlanSha256(plan) {
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  return sha256hex(canonicalize(plan));
}

export function assertProtectedRecordsRuntimeProfileInstallationPlan(plan) {
  assertExactKeys('Protected records runtime profile installation plan', plan, [
    'action_class',
    'activation_contract',
    'deployment_posture',
    'installation_boundary',
    'installation_command',
    'known_open_boundaries',
    'non_claims',
    'operator_requirements',
    'plan_id',
    'plan_status',
    'plan_type',
    'runtime_profile_id',
    'runtime_profile_proof_command',
    'runtime_profile_sha256',
    'runtime_profile_source',
    'service_command',
  ]);
  if (
    plan.plan_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PLAN_TYPE ||
    plan.plan_id !== 'protected-records-runtime-profile-installation-fixture-plan' ||
    plan.plan_status !== 'sample_local_disposable_only' ||
    plan.deployment_posture !== 'local_disposable_profile_installation_only' ||
    plan.action_class !== 'records.write' ||
    plan.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    plan.runtime_profile_source !== 'profiles/protected-records-runtime-fixture.profile.json' ||
    !/^[a-f0-9]{64}$/.test(plan.runtime_profile_sha256) ||
    plan.installation_command !== 'zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json' ||
    plan.runtime_profile_proof_command !== 'zlar protected-records-runtime-profile-proof' ||
    plan.service_command !== 'zlar protected-records-runtime-service --config <launcher-owned-disposable-config>'
  ) {
    throw new Error('Protected records runtime profile installation plan contract drifted');
  }

  assertExactKeys('Protected records runtime profile installation boundary', plan.installation_boundary, [
    'active_profile_index_written',
    'local_disposable_install_root_created',
    'persistent_runtime_profile_installed',
    'profile_copied_to_install_root',
    'profile_selected_from_install_root',
    'request_stream_authority_material_accepted',
    'selects_latest_profile',
    'uses_live_records_system',
    'uses_live_runtime_profile',
    'writes_hook_configuration',
    'writes_machine_config',
    'writes_user_config',
  ]);
  const boundary = plan.installation_boundary;
  if (
    boundary.local_disposable_install_root_created !== true ||
    boundary.profile_copied_to_install_root !== true ||
    boundary.active_profile_index_written !== true ||
    boundary.profile_selected_from_install_root !== true ||
    boundary.persistent_runtime_profile_installed !== false ||
    boundary.writes_hook_configuration !== false ||
    boundary.writes_user_config !== false ||
    boundary.writes_machine_config !== false ||
    boundary.selects_latest_profile !== false ||
    boundary.request_stream_authority_material_accepted !== false ||
    boundary.uses_live_runtime_profile !== false ||
    boundary.uses_live_records_system !== false
  ) {
    throw new Error('Protected records runtime profile installation boundary drifted');
  }

  assertExactKeys('Protected records runtime profile installation activation contract', plan.activation_contract, [
    'authority_grant_material_agent_supplied',
    'config_path_agent_supplied',
    'consumed_grant_store_anchor_path_agent_supplied',
    'consumed_grant_store_witness_path_agent_supplied',
    'consumed_grants_path_agent_supplied',
    'downstream_recognition_required',
    'issuer_registry_agent_supplied',
    'launcher_supplies_authority_grant_appointment',
    'launcher_supplies_authority_grant_contract',
    'launcher_supplies_authority_grant_issuance_decision',
    'launcher_supplies_authorized_record_update',
    'launcher_supplies_config',
    'missing_mismatched_expired_revoked_or_consumed_grant_refused',
    'missing_or_unrecognized_receipt_refused',
    'recognition_rule_agent_supplied',
    'state_path_agent_supplied',
  ]);
  const contract = plan.activation_contract;
  if (
    contract.launcher_supplies_config !== true ||
    contract.launcher_supplies_authority_grant_contract !== true ||
    contract.launcher_supplies_authority_grant_appointment !== true ||
    contract.launcher_supplies_authority_grant_issuance_decision !== true ||
    contract.launcher_supplies_authorized_record_update !== true ||
    contract.config_path_agent_supplied !== false ||
    contract.state_path_agent_supplied !== false ||
    contract.consumed_grants_path_agent_supplied !== false ||
    contract.consumed_grant_store_anchor_path_agent_supplied !== false ||
    contract.consumed_grant_store_witness_path_agent_supplied !== false ||
    contract.recognition_rule_agent_supplied !== false ||
    contract.issuer_registry_agent_supplied !== false ||
    contract.authority_grant_material_agent_supplied !== false ||
    contract.downstream_recognition_required !== true ||
    contract.missing_or_unrecognized_receipt_refused !== true ||
    contract.missing_mismatched_expired_revoked_or_consumed_grant_refused !== true
  ) {
    throw new Error('Protected records runtime profile installation activation contract drifted');
  }

  assertExactArray(
    'Protected records runtime profile installation operator requirements',
    plan.operator_requirements,
    REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS
  );
  assertExactArray(
    'Protected records runtime profile installation open boundaries',
    plan.known_open_boundaries,
    REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records runtime profile installation non-claims',
    plan.non_claims,
    RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(plan));
  return true;
}

function installDisposableProfile(plan, profile, profileSha) {
  let root = null;
  try {
    root = mkdtempSync(join(tmpdir(), 'zlar-runtime-profile-installation-'));
    const profilesDir = join(root, 'profiles');
    mkdirSync(profilesDir, { recursive: true });
    const installedProfilePath = join(profilesDir, `${profile.runtime_profile_id}.json`);
    writeFileSync(installedProfilePath, `${JSON.stringify(profile, null, 2)}\n`, { mode: 0o600 });

    const index = {
      index_type: 'zlar-disposable-runtime-profile-active-index-v1',
      selected_profile_id: profile.profile_id,
      selected_runtime_profile_id: profile.runtime_profile_id,
      selected_profile_sha256: profileSha,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      installed_profile_path: '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
    };
    const activeIndexPath = join(root, 'active-runtime-profile.json');
    writeFileSync(activeIndexPath, `${JSON.stringify(index, null, 2)}\n`, { mode: 0o600 });

    const installedProfile = JSON.parse(readFileSync(installedProfilePath, 'utf8'));
    assertProtectedRecordsRuntimePreflightProfile(installedProfile);
    const installedProfileSha = runtimeProfileSha256(installedProfile);
    const activeIndex = JSON.parse(readFileSync(activeIndexPath, 'utf8'));
    if (
      activeIndex.selected_profile_id !== profile.profile_id ||
      activeIndex.selected_runtime_profile_id !== plan.runtime_profile_id ||
      activeIndex.selected_profile_sha256 !== profileSha ||
      activeIndex.selected_by_explicit_id_and_sha !== true ||
      activeIndex.selects_latest_profile !== false ||
      installedProfile.runtime_profile_id !== plan.runtime_profile_id ||
      installedProfileSha !== profileSha
    ) {
      throw new Error('selection drifted');
    }

    return {
      install_root_kind: 'launcher-owned-disposable-proof-root',
      install_root_path_in_report: null,
      active_index_path_in_report:
        '<launcher-owned-disposable-install-root>/active-runtime-profile.json',
      installed_profile_path_in_report:
        '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
      install_root_created: true,
      profile_copy_written: true,
      active_profile_index_written: true,
      profile_selected_from_install_root: true,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      profile_sha_verified_before_selection: true,
      profile_status_before_installation: profile.profile_status,
      installed_profile_status: 'installed_in_disposable_proof_root',
      selected_profile_id: profile.profile_id,
      selected_runtime_profile_id: profile.runtime_profile_id,
      selected_profile_sha256: installedProfileSha,
    };
  } catch {
    throw new Error('Protected records runtime profile installation proof failed inside disposable install root');
  } finally {
    if (root) {
      rmSync(root, { recursive: true, force: true });
    }
  }
}

function requestAuthorityGuardCase(field, value) {
  let root = null;
  try {
    root = mkdtempSync(join(tmpdir(), 'zlar-runtime-profile-installation-guard-'));
    const runtimeDir = join(root, 'runtime');
    mkdirSync(runtimeDir, { recursive: true });
    const nowEpoch = PROTECTED_RECORDS_RUNTIME_FIXTURE_EVALUATION_EPOCH;
    const { publicKey: publicPem, privateKey: privatePem } = generateKeyPairSync(
      'ed25519',
      {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      }
    );
    void privatePem;
    const kid = sha256hex(publicPem).slice(0, 16);
    const authorizedRecordUpdate = {
      ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
    };
    const targetBinding = createProtectedRecordsRuntimeTargetBinding();
    const recognitionRule = {
      deployment_scope: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      accepted_issuers: [{ kid, public_key_pem: publicPem, status: 'active' }],
      accepted_policy_versions: ['recognition-policy-v1'],
      accepted_domains: ['records'],
      accepted_tools: ['records.write'],
      accepted_outcomes: ['allow', 'authorized'],
      max_age_seconds: 120,
      required_audit_event_id: 'protected-records-runtime-001',
    };
    const scopeEvidence = createProtectedRecordsRuntimeLauncherScopeEvidence({
      actionClass: 'records.write',
      authorizedRecordUpdate,
      profileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      recognitionRuleSnapshot: recognitionRule,
      targetBinding,
    });
    const authorityGrantContract = createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
      scopeEvidence,
      validFromEpoch: nowEpoch - 30,
      expiresAtEpoch: nowEpoch + 120,
    });
    const authorityGrantAppointment =
      createProtectedRecordsFixtureAuthorityGrantAppointment({
        contract: authorityGrantContract,
        granteeIssuerKid: kid,
        granteePublicKeySha256: sha256hex(publicPem),
      });
    const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetail({
      contract: authorityGrantContract,
      targetEffect: protectedRecordsTargetEffect({
        targetHandle: targetBinding.target_handle,
        recordUpdate: authorizedRecordUpdate,
      }),
    });
    const unsignedReceipt = createReceiptV1FromEvent({
      id: 'protected-records-runtime-001',
      ts: new Date((nowEpoch - 5) * 1000).toISOString(),
      action: 'records.write',
      domain: 'records',
      detail: authorizedEffectDetail,
      outcome: 'allow',
      rule: 'RRECORDS_ALLOW',
      authorizer: 'policy',
      policy_version: 'recognition-policy-v1',
      prev_hash: '0'.repeat(64),
    });
    const unsignedPayload = decodePayloadV1(unsignedReceipt);
    const authorityGrantIssuanceDecision =
      evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
        contract: authorityGrantContract,
        appointment: authorityGrantAppointment,
        scopeEvidence,
        receiptEvidence: createProtectedRecordsRuntimeAuthorityReceiptEvidence({
          envelope: unsignedReceipt,
          issuerKid: kid,
          issuerStatus: null,
          payload: unsignedPayload,
          publicKeySha256: sha256hex(publicPem),
          source: 'unsigned-receipt-payload-before-signing',
          signatureVerified: false,
          downstreamRecognitionAccepted: false,
          verifiedSignedPayloadSha256: null,
        }),
        authorizedEffectDetail,
        evaluationEpoch: nowEpoch - 5,
        grantPreviouslyConsumed: false,
      });
    const service = createProtectedRecordsRuntimeService({
      profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      action_class: 'records.write',
      now_epoch: nowEpoch,
      authorized_record_update: authorizedRecordUpdate,
      authority_grant_appointment: authorityGrantAppointment,
      authority_grant_contract: authorityGrantContract,
      authority_grant_issuance_decision: authorityGrantIssuanceDecision,
      consumed_grants_path: join(runtimeDir, 'consumed-authority-grants.json'),
      consumed_grant_store_anchor_path: join(runtimeDir, 'consumed-authority-grants.anchor.json'),
      consumed_grant_store_witness_path: join(runtimeDir, 'consumed-authority-grants.witness.json'),
      recognition_rule: recognitionRule,
      target_binding: targetBinding,
    });
    const result = service.applyRequest({
      request_mode: `agent_supplied_${field}_runtime_write`,
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      [field]: value,
    });
    return {
      refused_before_mutation:
        result.service_write_accepted === false &&
        result.service_state_changed === false &&
        result.state_entry_count_after === result.state_entry_count_before &&
        result.decision?.reason_code === 'agent_supplied_authority_material',
      reason_code: result.decision?.reason_code || null,
      state_entry_count_delta: result.state_entry_count_after - result.state_entry_count_before,
    };
  } catch {
    throw new Error('Protected records runtime profile installation authority guard failed');
  } finally {
    if (root) {
      rmSync(root, { recursive: true, force: true });
    }
  }
}

function runRequestAuthorityGuardSummary() {
  const installedProfileState = requestAuthorityGuardCase('installed_profile_state', {
    selected_runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  });
  const runtimeConfig = requestAuthorityGuardCase('runtime_config', {
    profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  });
  const runtimeProfile = requestAuthorityGuardCase('runtime_profile', {
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  });
  const recognitionRule = requestAuthorityGuardCase('recognition_rule', {
    accepted_issuers: [],
  });
  const authorityGrant = requestAuthorityGuardCase('authority_grant_contract', {
    grant_id: 'request-supplied-grant-forbidden',
  });
  const cases = [
    installedProfileState,
    runtimeConfig,
    runtimeProfile,
    recognitionRule,
    authorityGrant,
  ];
  return {
    installed_profile_state_refused: installedProfileState.refused_before_mutation,
    runtime_config_refused: runtimeConfig.refused_before_mutation,
    runtime_profile_refused: runtimeProfile.refused_before_mutation,
    recognition_rule_refused: recognitionRule.refused_before_mutation,
    authority_grant_refused: authorityGrant.refused_before_mutation,
    all_refused_before_mutation: cases.every((item) => item.refused_before_mutation === true),
    state_entry_count_delta_total: cases.reduce((total, item) => total + item.state_entry_count_delta, 0),
    reason_codes: cases.map((item) => item.reason_code),
  };
}

export function runProtectedRecordsRuntimeProfileInstallationProof(plan, profile) {
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
    'Protected records runtime-profile installation proof generation',
  );
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const profileSha = runtimeProfileSha256(profile);
  if (plan.runtime_profile_sha256 !== profileSha) {
    throw new Error('Protected records runtime profile installation plan profile SHA mismatch');
  }

  const installation = installDisposableProfile(plan, profile, profileSha);
  const requestAuthorityGuardSummary = runRequestAuthorityGuardSummary();
  const runtimeProof = runProtectedRecordsRuntimeProfileProof();
  assertProtectedRecordsRuntimeProfileProof(runtimeProof);

  const accepted = proofCase(runtimeProof, 'recognized_runtime_write_first_request');
  const replayAfterRestart = proofCase(runtimeProof, 'replay_runtime_write_refused_after_service_restart');
  const missingReceipt = proofCase(runtimeProof, 'missing_receipt_refused_before_runtime_mutation');
  const invalidReceipt = proofCase(runtimeProof, 'invalid_receipt_refused_before_runtime_mutation');
  const unknownIssuer = proofCase(runtimeProof, 'unknown_issuer_refused_before_runtime_mutation');
  const retiredIssuer = proofCase(runtimeProof, 'retired_issuer_refused_before_runtime_mutation');
  const missingIssuerStatus = proofCase(runtimeProof, 'missing_issuer_status_refused_before_runtime_mutation');
  const missingGrantAppointment = proofCase(
    runtimeProof,
    'missing_authority_grant_appointment_refused_before_consumption'
  );
  const mismatchedGrantAppointment = proofCase(
    runtimeProof,
    'mismatched_authority_grant_appointment_refused_before_consumption'
  );
  const revokedGrant = proofCase(
    runtimeProof,
    'revoked_authority_grant_refused_before_consumption'
  );
  const expiredGrant = proofCase(
    runtimeProof,
    'expired_authority_grant_refused_before_consumption'
  );
  const staleReceipt = proofCase(runtimeProof, 'stale_receipt_refused_before_runtime_mutation');
  const wrongPolicy = proofCase(runtimeProof, 'wrong_policy_refused_before_runtime_mutation');
  const wrongDomain = proofCase(runtimeProof, 'wrong_domain_refused_before_runtime_mutation');
  const wrongTool = proofCase(runtimeProof, 'wrong_tool_refused_before_runtime_mutation');
  const wrongRuntimeProfileId = proofCase(runtimeProof, 'wrong_runtime_profile_id_refused_before_runtime_mutation');
  const wrongAuditEvent = proofCase(runtimeProof, 'wrong_audit_event_refused_before_runtime_mutation');
  const wrongDetail = proofCase(runtimeProof, 'wrong_detail_refused_before_runtime_mutation');
  const nonBoardingOutcome = proofCase(runtimeProof, 'non_boarding_outcome_refused_before_runtime_mutation');
  const directApiWithoutReceipt = proofCase(runtimeProof, 'direct_api_without_receipt_refused_before_runtime_mutation');
  const directApiWithReceipt = proofCase(runtimeProof, 'direct_api_with_receipt_refused_before_runtime_mutation');
  const authorityCases = runtimeProof.cases.filter((item) => item.case_id.startsWith('agent_supplied_'));
  const identityPolicy = runtimeProof.runtime_profile_identity_policy;

  const report = {
    proof_type: PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE,
    evidence_model: 'local-disposable-runtime-profile-installation-fixture',
    live_probing: false,
    safe_claim_ceiling: RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING,
    plan: {
      plan_type: plan.plan_type,
      plan_id: plan.plan_id,
      plan_status: plan.plan_status,
      deployment_posture: plan.deployment_posture,
      plan_sha256: runtimeProfileInstallationPlanSha256(plan),
    },
    runtime_profile: {
      profile_id: profile.profile_id,
      runtime_profile_id: profile.runtime_profile_id,
      profile_status: profile.profile_status,
      profile_sha256: profileSha,
      profile_sha_matches_plan: true,
    },
    installation,
    installation_boundary: { ...plan.installation_boundary },
    activation_contract: { ...plan.activation_contract },
    request_authority_guard_summary: requestAuthorityGuardSummary,
    runtime_proof_summary: {
      proof_type: runtimeProof.proof_type,
      proof_command: plan.runtime_profile_proof_command,
      proof_run: true,
      service_command: plan.service_command,
      service_process_boundary: 'local-jsonl-child-process',
      case_count: runtimeProof.cases.length,
      required_case_count: profile.required_cases.length,
      boundary_observation_count: runtimeProof.boundary_observations.length,
      required_boundary_observation_count: profile.required_boundary_observations.length,
      recognized_write_accepted: accepted.service_write_accepted === true,
      replay_after_restart_refused: replayAfterRestart.service_write_accepted === false,
      same_process_signed_payload_replay_refused:
        proofCase(runtimeProof, 'replay_runtime_write_refused_same_service_process')
          .reason_code === 'receipt_replay',
      restart_consumed_authority_grant_refused:
        replayAfterRestart.reason_code === 'authority_grant_already_consumed',
      missing_receipt_refused: missingReceipt.service_write_accepted === false,
      invalid_receipt_refused: invalidReceipt.service_write_accepted === false,
      unknown_issuer_refused: unknownIssuer.service_write_accepted === false,
      retired_issuer_refused: retiredIssuer.service_write_accepted === false,
      missing_issuer_status_refused: missingIssuerStatus.service_write_accepted === false,
      missing_authority_grant_appointment_refused:
        missingGrantAppointment.service_write_accepted === false,
      mismatched_authority_grant_appointment_refused:
        mismatchedGrantAppointment.service_write_accepted === false,
      revoked_authority_grant_refused: revokedGrant.service_write_accepted === false,
      expired_authority_grant_refused: expiredGrant.service_write_accepted === false,
      request_supplied_authority_grant_refused:
        proofCase(runtimeProof, 'agent_supplied_authority_grant_refused_before_runtime_mutation')
          .service_write_accepted === false,
      fixture_rightful_issuance_path_evidenced:
        accepted.reason_code === 'fixture_authority_grant_effect_satisfied' &&
        runtimeProof.accepted_runtime_transition_binding !== null,
      stale_receipt_refused: staleReceipt.service_write_accepted === false,
      wrong_policy_refused: wrongPolicy.service_write_accepted === false,
      wrong_domain_refused: wrongDomain.service_write_accepted === false,
      wrong_tool_refused: wrongTool.service_write_accepted === false,
      wrong_runtime_profile_id_refused: wrongRuntimeProfileId.service_write_accepted === false,
      wrong_audit_event_refused: wrongAuditEvent.service_write_accepted === false,
      wrong_detail_refused: wrongDetail.service_write_accepted === false,
      non_boarding_outcome_refused: nonBoardingOutcome.service_write_accepted === false,
      direct_api_without_receipt_refused: directApiWithoutReceipt.service_write_accepted === false,
      direct_api_with_receipt_refused: directApiWithReceipt.service_write_accepted === false,
      agent_supplied_authority_material_refused:
        authorityCases.length > 0 && authorityCases.every((item) => item.service_write_accepted === false),
      runtime_profile_identity_authority_source: identityPolicy.authority_source,
      runtime_profile_identity_request_stream_policy: identityPolicy.request_stream_policy,
      request_runtime_profile_id_required: identityPolicy.request_runtime_profile_id_required,
      omitted_request_runtime_profile_id_present:
        identityPolicy.omitted_request_runtime_profile_id_present,
      omitted_runtime_profile_id_uses_launcher_config:
        identityPolicy.omitted_runtime_profile_id_uses_launcher_config,
      omitted_runtime_profile_id_reason_code: identityPolicy.omitted_runtime_profile_id_reason_code,
      omitted_runtime_profile_id_state_entry_count_delta:
        identityPolicy.omitted_runtime_profile_id_state_entry_count_delta,
      omitted_runtime_profile_id_consumed_authority_grant_count:
        identityPolicy.omitted_runtime_profile_id_consumed_authority_grant_count,
      supplied_mismatched_runtime_profile_id_refused:
        identityPolicy.supplied_mismatched_runtime_profile_id_refused,
      supplied_mismatch_reason_code: identityPolicy.supplied_mismatch_reason_code,
      supplied_mismatch_state_entry_count_delta:
        identityPolicy.supplied_mismatch_state_entry_count_delta,
      atomic_store_anchor_witness_commit:
        runtimeProof.side_door_report.atomic_store_anchor_witness_commit,
      partial_grant_commit_burn_window_named:
        runtimeProof.side_door_report.partial_grant_commit_burn_window_named,
      store_anchor_and_witness_joint_rollback_detection:
        runtimeProof.side_door_report.store_anchor_and_witness_joint_rollback_detection,
      host_filesystem_path_toctou_closed:
        runtimeProof.side_door_report.host_filesystem_path_toctou_closed,
    },
    case_summaries: runtimeProof.cases.map(caseSummary),
    side_door_report: {
      disposable_profile_installation_applied: true,
      local_disposable_install_root_created: true,
      profile_copied_to_install_root: true,
      active_profile_index_written: true,
      profile_selected_from_install_root: true,
      disposable_runtime_config_written: true,
      persistent_runtime_config_written: false,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      runtime_service_started: true,
      persistent_runtime_profile_installed: false,
      latest_profile_selected: false,
      request_stream_authority_material_accepted: false,
      live_runtime_profile_checked: false,
      live_records_system_checked: false,
      production_records_service_checked: false,
      live_mcp_coverage_checked: false,
      live_approval_channel_health_checked: false,
      exactly_once_effect_semantics: false,
      atomic_store_anchor_witness_commit:
        runtimeProof.side_door_report.atomic_store_anchor_witness_commit,
      partial_grant_commit_burn_window_named:
        runtimeProof.side_door_report.partial_grant_commit_burn_window_named,
      store_anchor_and_witness_joint_rollback_detection:
        runtimeProof.side_door_report.store_anchor_and_witness_joint_rollback_detection,
      host_filesystem_path_toctou_closed:
        runtimeProof.side_door_report.host_filesystem_path_toctou_closed,
      host_process_or_memory_introspection_closed: false,
      external_attestation: false,
      sovereign_recognition: false,
      unrouted_records_paths_checked: false,
    },
    operator_requirements: [...plan.operator_requirements],
    known_open_boundaries: [...plan.known_open_boundaries],
    non_claims: [...RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS],
  };
  assertProtectedRecordsRuntimeProfileInstallationProof(report, plan, profile);
  return report;
}

export function assertProtectedRecordsRuntimeProfileInstallationProof(report, plan, profile) {
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  assertExactKeys('Protected records runtime profile installation proof', report, [
    'activation_contract',
    'case_summaries',
    'evidence_model',
    'installation',
    'installation_boundary',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'operator_requirements',
    'plan',
    'proof_type',
    'request_authority_guard_summary',
    'runtime_profile',
    'runtime_proof_summary',
    'safe_claim_ceiling',
    'side_door_report',
  ]);
  if (
    report.proof_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_PROOF_TYPE ||
    report.evidence_model !== 'local-disposable-runtime-profile-installation-fixture' ||
    report.live_probing !== false ||
    report.safe_claim_ceiling !== RUNTIME_PROFILE_INSTALLATION_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records runtime profile installation proof top-level contract drifted');
  }

  assertExactKeys('Protected records runtime profile installation plan identity', report.plan, [
    'deployment_posture',
    'plan_id',
    'plan_sha256',
    'plan_status',
    'plan_type',
  ]);
  if (
    report.plan.plan_type !== plan.plan_type ||
    report.plan.plan_id !== plan.plan_id ||
    report.plan.plan_status !== plan.plan_status ||
    report.plan.deployment_posture !== plan.deployment_posture ||
    report.plan.plan_sha256 !== runtimeProfileInstallationPlanSha256(plan)
  ) {
    throw new Error('Protected records runtime profile installation plan identity drifted');
  }

  assertExactKeys('Protected records runtime profile installation profile identity', report.runtime_profile, [
    'profile_id',
    'profile_sha256',
    'profile_sha_matches_plan',
    'profile_status',
    'runtime_profile_id',
  ]);
  if (
    report.runtime_profile.profile_id !== profile.profile_id ||
    report.runtime_profile.runtime_profile_id !== profile.runtime_profile_id ||
    report.runtime_profile.profile_status !== profile.profile_status ||
    report.runtime_profile.profile_sha256 !== runtimeProfileSha256(profile) ||
    report.runtime_profile.profile_sha_matches_plan !== true ||
    report.runtime_profile.profile_sha256 !== plan.runtime_profile_sha256
  ) {
    throw new Error('Protected records runtime profile installation profile identity drifted');
  }

  assertExactKeys('Protected records runtime profile installation selection', report.installation, [
    'active_index_path_in_report',
    'active_profile_index_written',
    'install_root_created',
    'install_root_kind',
    'install_root_path_in_report',
    'installed_profile_path_in_report',
    'installed_profile_status',
    'profile_copy_written',
    'profile_selected_from_install_root',
    'profile_sha_verified_before_selection',
    'profile_status_before_installation',
    'selected_by_explicit_id_and_sha',
    'selected_profile_id',
    'selected_profile_sha256',
    'selected_runtime_profile_id',
    'selects_latest_profile',
  ]);
  const installation = report.installation;
  if (
    installation.install_root_kind !== 'launcher-owned-disposable-proof-root' ||
    installation.install_root_path_in_report !== null ||
    installation.active_index_path_in_report !==
      '<launcher-owned-disposable-install-root>/active-runtime-profile.json' ||
    installation.installed_profile_path_in_report !==
      '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json' ||
    installation.install_root_created !== true ||
    installation.profile_copy_written !== true ||
    installation.active_profile_index_written !== true ||
    installation.profile_selected_from_install_root !== true ||
    installation.selected_by_explicit_id_and_sha !== true ||
    installation.selects_latest_profile !== false ||
    installation.profile_sha_verified_before_selection !== true ||
    installation.profile_status_before_installation !== profile.profile_status ||
    installation.installed_profile_status !== 'installed_in_disposable_proof_root' ||
    installation.selected_profile_id !== profile.profile_id ||
    installation.selected_runtime_profile_id !== profile.runtime_profile_id ||
    installation.selected_profile_sha256 !== runtimeProfileSha256(profile)
  ) {
    throw new Error('Protected records runtime profile installation selection drifted');
  }

  if (canonicalize(report.installation_boundary) !== canonicalize(plan.installation_boundary)) {
    throw new Error('Protected records runtime profile installation boundary drifted');
  }
  if (canonicalize(report.activation_contract) !== canonicalize(plan.activation_contract)) {
    throw new Error('Protected records runtime profile installation activation contract drifted');
  }

  assertExactKeys(
    'Protected records runtime profile installation request authority guard summary',
    report.request_authority_guard_summary,
    [
      'all_refused_before_mutation',
      'authority_grant_refused',
      'installed_profile_state_refused',
      'reason_codes',
      'recognition_rule_refused',
      'runtime_config_refused',
      'runtime_profile_refused',
      'state_entry_count_delta_total',
    ]
  );
  const guard = report.request_authority_guard_summary;
  if (
    guard.installed_profile_state_refused !== true ||
    guard.runtime_config_refused !== true ||
    guard.runtime_profile_refused !== true ||
    guard.recognition_rule_refused !== true ||
    guard.authority_grant_refused !== true ||
    guard.all_refused_before_mutation !== true ||
    guard.state_entry_count_delta_total !== 0 ||
    !Array.isArray(guard.reason_codes) ||
    guard.reason_codes.length !== 5 ||
    guard.reason_codes.some((item) => item !== 'agent_supplied_authority_material')
  ) {
    throw new Error('Protected records runtime profile installation request authority guard drifted');
  }

  assertExactKeys('Protected records runtime profile installation proof summary', report.runtime_proof_summary, [
    'agent_supplied_authority_material_refused',
    'atomic_store_anchor_witness_commit',
    'boundary_observation_count',
    'case_count',
    'direct_api_with_receipt_refused',
    'direct_api_without_receipt_refused',
    'expired_authority_grant_refused',
    'fixture_rightful_issuance_path_evidenced',
    'host_filesystem_path_toctou_closed',
    'invalid_receipt_refused',
    'missing_receipt_refused',
    'missing_issuer_status_refused',
    'missing_authority_grant_appointment_refused',
    'mismatched_authority_grant_appointment_refused',
    'non_boarding_outcome_refused',
    'omitted_request_runtime_profile_id_present',
    'omitted_runtime_profile_id_consumed_authority_grant_count',
    'omitted_runtime_profile_id_reason_code',
    'omitted_runtime_profile_id_state_entry_count_delta',
    'omitted_runtime_profile_id_uses_launcher_config',
    'proof_command',
    'proof_run',
    'proof_type',
    'partial_grant_commit_burn_window_named',
    'recognized_write_accepted',
    'request_runtime_profile_id_required',
    'replay_after_restart_refused',
    'request_supplied_authority_grant_refused',
    'restart_consumed_authority_grant_refused',
    'revoked_authority_grant_refused',
    'required_boundary_observation_count',
    'required_case_count',
    'retired_issuer_refused',
    'runtime_profile_identity_authority_source',
    'runtime_profile_identity_request_stream_policy',
    'service_command',
    'service_process_boundary',
    'same_process_signed_payload_replay_refused',
    'stale_receipt_refused',
    'store_anchor_and_witness_joint_rollback_detection',
    'supplied_mismatch_reason_code',
    'supplied_mismatch_state_entry_count_delta',
    'supplied_mismatched_runtime_profile_id_refused',
    'unknown_issuer_refused',
    'wrong_audit_event_refused',
    'wrong_detail_refused',
    'wrong_domain_refused',
    'wrong_policy_refused',
    'wrong_runtime_profile_id_refused',
    'wrong_tool_refused',
  ]);
  const summary = report.runtime_proof_summary;
  if (
    summary.proof_command !== plan.runtime_profile_proof_command ||
    summary.proof_run !== true ||
    summary.service_command !== plan.service_command ||
    summary.service_process_boundary !== 'local-jsonl-child-process' ||
    summary.case_count !== profile.required_cases.length ||
    summary.required_case_count !== profile.required_cases.length ||
    summary.boundary_observation_count !== profile.required_boundary_observations.length ||
    summary.required_boundary_observation_count !== profile.required_boundary_observations.length ||
    summary.recognized_write_accepted !== true ||
    summary.replay_after_restart_refused !== true ||
    summary.same_process_signed_payload_replay_refused !== true ||
    summary.restart_consumed_authority_grant_refused !== true ||
    summary.missing_receipt_refused !== true ||
    summary.invalid_receipt_refused !== true ||
    summary.unknown_issuer_refused !== true ||
    summary.retired_issuer_refused !== true ||
    summary.missing_issuer_status_refused !== true ||
    summary.missing_authority_grant_appointment_refused !== true ||
    summary.mismatched_authority_grant_appointment_refused !== true ||
    summary.revoked_authority_grant_refused !== true ||
    summary.expired_authority_grant_refused !== true ||
    summary.request_supplied_authority_grant_refused !== true ||
    summary.fixture_rightful_issuance_path_evidenced !== true ||
    summary.stale_receipt_refused !== true ||
    summary.wrong_policy_refused !== true ||
    summary.wrong_domain_refused !== true ||
    summary.wrong_tool_refused !== true ||
    summary.wrong_runtime_profile_id_refused !== true ||
    summary.wrong_audit_event_refused !== true ||
    summary.wrong_detail_refused !== true ||
    summary.non_boarding_outcome_refused !== true ||
    summary.direct_api_without_receipt_refused !== true ||
    summary.direct_api_with_receipt_refused !== true ||
    summary.agent_supplied_authority_material_refused !== true ||
    summary.runtime_profile_identity_authority_source !== 'launcher-owned-service-config' ||
    summary.runtime_profile_identity_request_stream_policy !==
      'runtime_profile_id_may_be_omitted_but_if_supplied_must_match_config' ||
    summary.request_runtime_profile_id_required !== false ||
    summary.omitted_request_runtime_profile_id_present !== false ||
    summary.omitted_runtime_profile_id_uses_launcher_config !== true ||
    summary.omitted_runtime_profile_id_reason_code !== 'fixture_authority_grant_effect_satisfied' ||
    summary.omitted_runtime_profile_id_state_entry_count_delta !== 1 ||
    summary.omitted_runtime_profile_id_consumed_authority_grant_count !== 1 ||
    summary.supplied_mismatched_runtime_profile_id_refused !== true ||
    summary.supplied_mismatch_reason_code !== 'agent_supplied_authority_material' ||
    summary.supplied_mismatch_state_entry_count_delta !== 0 ||
    summary.atomic_store_anchor_witness_commit !== false ||
    summary.partial_grant_commit_burn_window_named !== true ||
    summary.store_anchor_and_witness_joint_rollback_detection !== false ||
    summary.host_filesystem_path_toctou_closed !== false
  ) {
    throw new Error('Protected records runtime profile installation proof summary drifted');
  }

  if (!Array.isArray(report.case_summaries) || report.case_summaries.length !== profile.required_cases.length) {
    throw new Error('Protected records runtime profile installation case summaries drifted');
  }
  for (const item of report.case_summaries) {
    assertExactKeys('Protected records runtime profile installation case summary', item, [
      'case_id',
      'direct_api_attempted',
      'reason_code',
      'request_ordinal',
      'service_process_invocation',
      'service_write_accepted',
      'state_entry_count_delta',
    ]);
  }

  assertExactKeys('Protected records runtime profile installation side-door report', report.side_door_report, [
    'active_profile_index_written',
    'atomic_store_anchor_witness_commit',
    'disposable_profile_installation_applied',
    'disposable_runtime_config_written',
    'exactly_once_effect_semantics',
    'external_attestation',
    'hook_configuration_written',
    'host_process_or_memory_introspection_closed',
    'host_filesystem_path_toctou_closed',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'local_disposable_install_root_created',
    'machine_config_written',
    'persistent_runtime_config_written',
    'persistent_runtime_profile_installed',
    'partial_grant_commit_burn_window_named',
    'production_records_service_checked',
    'profile_copied_to_install_root',
    'profile_selected_from_install_root',
    'request_stream_authority_material_accepted',
    'runtime_service_started',
    'sovereign_recognition',
    'store_anchor_and_witness_joint_rollback_detection',
    'unrouted_records_paths_checked',
    'user_config_written',
  ]);
  const sideDoor = report.side_door_report;
  if (
    sideDoor.disposable_profile_installation_applied !== true ||
    sideDoor.local_disposable_install_root_created !== true ||
    sideDoor.profile_copied_to_install_root !== true ||
    sideDoor.active_profile_index_written !== true ||
    sideDoor.profile_selected_from_install_root !== true ||
    sideDoor.disposable_runtime_config_written !== true ||
    sideDoor.persistent_runtime_config_written !== false ||
    sideDoor.hook_configuration_written !== false ||
    sideDoor.user_config_written !== false ||
    sideDoor.machine_config_written !== false ||
    sideDoor.runtime_service_started !== true ||
    sideDoor.persistent_runtime_profile_installed !== false ||
    sideDoor.latest_profile_selected !== false ||
    sideDoor.request_stream_authority_material_accepted !== false ||
    sideDoor.live_runtime_profile_checked !== false ||
    sideDoor.live_records_system_checked !== false ||
    sideDoor.production_records_service_checked !== false ||
    sideDoor.live_mcp_coverage_checked !== false ||
    sideDoor.live_approval_channel_health_checked !== false ||
    sideDoor.exactly_once_effect_semantics !== false ||
    sideDoor.atomic_store_anchor_witness_commit !== false ||
    sideDoor.partial_grant_commit_burn_window_named !== true ||
    sideDoor.store_anchor_and_witness_joint_rollback_detection !== false ||
    sideDoor.host_filesystem_path_toctou_closed !== false ||
    sideDoor.host_process_or_memory_introspection_closed !== false ||
    sideDoor.external_attestation !== false ||
    sideDoor.sovereign_recognition !== false ||
    sideDoor.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records runtime profile installation side-door report drifted');
  }

  assertExactArray(
    'Protected records runtime profile installation operator requirements',
    report.operator_requirements,
    REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPERATOR_REQUIREMENTS
  );
  assertExactArray(
    'Protected records runtime profile installation open boundaries',
    report.known_open_boundaries,
    REQUIRED_RUNTIME_PROFILE_INSTALLATION_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records runtime profile installation non-claims',
    report.non_claims,
    RUNTIME_PROFILE_INSTALLATION_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

function runtimeProfileInstallationArtifactBody(payload) {
  return {
    artifact_type: PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE,
    canonicalization: PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-runtime-profile-installation --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload,
  };
}

export function buildProtectedRecordsRuntimeProfileInstallationArtifact(
  plan,
  profile,
  report = runProtectedRecordsRuntimeProfileInstallationProof(plan, profile)
) {
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  assertProtectedRecordsRuntimeProfileInstallationProof(report, plan, profile);
  const payload = {
    plan,
    runtime_profile: profile,
    proof: report,
  };
  const body = runtimeProfileInstallationArtifactBody(payload);
  const artifact = {
    ...body,
    integrity: {
      algorithm: 'SHA-256',
      body_sha256: sha256hex(canonicalize(body)),
    },
  };
  assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact);
  return artifact;
}

export function assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact) {
  if (!artifact || artifact.artifact_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE) {
    throw new Error('Protected records runtime profile installation artifact has the wrong artifact type');
  }
  assertExactKeys('Protected records runtime profile installation artifact', artifact, [
    'artifact_type',
    'canonicalization',
    'generator',
    'hash_scope',
    'integrity',
    'payload',
  ]);
  if (artifact.canonicalization !== PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_CANONICALIZATION) {
    throw new Error('Protected records runtime profile installation artifact canonicalization drifted');
  }
  if (artifact.generator !== 'zlar protected-records-runtime-profile-installation --artifact') {
    throw new Error('Protected records runtime profile installation artifact generator drifted');
  }
  if (artifact.hash_scope !== 'canonical artifact body without integrity') {
    throw new Error('Protected records runtime profile installation artifact hash scope drifted');
  }

  assertExactKeys('Protected records runtime profile installation artifact payload', artifact.payload, [
    'plan',
    'proof',
    'runtime_profile',
  ]);
  assertProtectedRecordsRuntimeProfileInstallationPlan(artifact.payload.plan);
  assertProtectedRecordsRuntimePreflightProfile(artifact.payload.runtime_profile);
  assertProtectedRecordsRuntimeProfileInstallationProof(
    artifact.payload.proof,
    artifact.payload.plan,
    artifact.payload.runtime_profile
  );

  if (!artifact.integrity || artifact.integrity.algorithm !== 'SHA-256') {
    throw new Error('Protected records runtime profile installation artifact integrity algorithm drifted');
  }
  assertExactKeys('Protected records runtime profile installation artifact integrity', artifact.integrity, [
    'algorithm',
    'body_sha256',
  ]);
  if (!/^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256 || '')) {
    throw new Error('Protected records runtime profile installation artifact SHA-256 is malformed');
  }
  const { integrity, ...body } = artifact;
  const expectedHash = sha256hex(canonicalize(body));
  if (integrity.body_sha256 !== expectedHash) {
    throw new Error('Protected records runtime profile installation artifact SHA-256 mismatch');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact));
  return true;
}

export function writeProtectedRecordsRuntimeProfileInstallationArtifact(artifact, outputPath) {
  assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact);
  if (!outputPath || outputPath === '-') {
    throw new Error('Protected records runtime profile installation artifact output path is required');
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseProtectedRecordsRuntimeProfileInstallationArtifactText(text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Protected records runtime profile installation artifact input is not valid JSON');
  }
  assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact);
  return artifact;
}

export function verifyProtectedRecordsRuntimeProfileInstallationArtifact(artifact) {
  assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact);
  const report = artifact.payload.proof;
  const authorityStatus =
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS;
  const authorityStatusReason =
    protectedRecordsFixtureAuthorityGrantEffectStatusReason(
      PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256
    );
  const verification = {
    verification_type: PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: report.proof_type,
    evidence_model: report.evidence_model,
    live_probing: report.live_probing,
    plan_sha256: report.plan.plan_sha256,
    runtime_profile_sha256: report.runtime_profile.profile_sha256,
    runtime_profile_sha_matches_plan: report.runtime_profile.profile_sha_matches_plan,
    runtime_profile_identity_authority_source:
      report.runtime_proof_summary.runtime_profile_identity_authority_source,
    runtime_profile_identity_request_stream_policy:
      report.runtime_proof_summary.runtime_profile_identity_request_stream_policy,
    request_runtime_profile_id_required:
      report.runtime_proof_summary.request_runtime_profile_id_required,
    omitted_request_runtime_profile_id_present:
      report.runtime_proof_summary.omitted_request_runtime_profile_id_present,
    omitted_runtime_profile_id_uses_launcher_config:
      report.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config,
    omitted_runtime_profile_id_reason_code:
      report.runtime_proof_summary.omitted_runtime_profile_id_reason_code,
    omitted_runtime_profile_id_state_entry_count_delta:
      report.runtime_proof_summary.omitted_runtime_profile_id_state_entry_count_delta,
    omitted_runtime_profile_id_consumed_authority_grant_count:
      report.runtime_proof_summary.omitted_runtime_profile_id_consumed_authority_grant_count,
    supplied_mismatched_runtime_profile_id_refused:
      report.runtime_proof_summary.supplied_mismatched_runtime_profile_id_refused,
    supplied_mismatch_reason_code:
      report.runtime_proof_summary.supplied_mismatch_reason_code,
    supplied_mismatch_state_entry_count_delta:
      report.runtime_proof_summary.supplied_mismatch_state_entry_count_delta,
    request_authority_guard_refused:
      report.request_authority_guard_summary.all_refused_before_mutation,
    disposable_profile_installation_applied:
      report.side_door_report.disposable_profile_installation_applied,
    profile_copied_to_install_root: report.side_door_report.profile_copied_to_install_root,
    active_profile_index_written: report.side_door_report.active_profile_index_written,
    profile_selected_from_install_root: report.side_door_report.profile_selected_from_install_root,
    selected_by_explicit_id_and_sha: report.installation.selected_by_explicit_id_and_sha,
    selects_latest_profile: report.installation.selects_latest_profile,
    persistent_runtime_profile_installed:
      report.side_door_report.persistent_runtime_profile_installed,
    hook_configuration_written: report.side_door_report.hook_configuration_written,
    user_config_written: report.side_door_report.user_config_written,
    machine_config_written: report.side_door_report.machine_config_written,
    runtime_service_started: report.side_door_report.runtime_service_started,
    recognized_write_accepted: report.runtime_proof_summary.recognized_write_accepted,
    historical_artifact_recognized_write_accepted:
      report.runtime_proof_summary.recognized_write_accepted,
    recognized_write_accepted_is_current_authority_projection: false,
    replay_after_restart_refused: report.runtime_proof_summary.replay_after_restart_refused,
    same_process_signed_payload_replay_refused:
      report.runtime_proof_summary.same_process_signed_payload_replay_refused,
    restart_consumed_authority_grant_refused:
      report.runtime_proof_summary.restart_consumed_authority_grant_refused,
    historical_artifact_fixture_rightful_issuance_path_evidenced:
      report.runtime_proof_summary.fixture_rightful_issuance_path_evidenced,
    fixture_rightful_issuance_path_evidenced: false,
    authority_grant_status_type: authorityStatus.status_type,
    authority_grant_status_contract_sha256:
      authorityStatus.authority_grant_contract_sha256,
    artifact_authority_grant_contract_sha256: null,
    artifact_contract_bound_to_authority_status: false,
    historical_only_due_to_missing_artifact_grant_contract_binding: true,
    authority_grant_status: authorityStatus.status,
    authority_grant_status_source: authorityStatus.status_source,
    authority_grant_fresh_effect_allowed:
      authorityStatus.fresh_effect_allowed,
    authority_grant_repeated_use_provenance_valid:
      authorityStatus.repeated_use_provenance_valid,
    authority_grant_status_allows_fixture_rightful_projection: false,
    authority_grant_status_reason_code: authorityStatusReason?.code || null,
    missing_authority_grant_appointment_refused:
      report.runtime_proof_summary.missing_authority_grant_appointment_refused,
    mismatched_authority_grant_appointment_refused:
      report.runtime_proof_summary.mismatched_authority_grant_appointment_refused,
    revoked_authority_grant_refused:
      report.runtime_proof_summary.revoked_authority_grant_refused,
    expired_authority_grant_refused:
      report.runtime_proof_summary.expired_authority_grant_refused,
    request_supplied_authority_grant_refused:
      report.runtime_proof_summary.request_supplied_authority_grant_refused,
    atomic_store_anchor_witness_commit:
      report.side_door_report.atomic_store_anchor_witness_commit,
    partial_grant_commit_burn_window_named:
      report.side_door_report.partial_grant_commit_burn_window_named,
    store_anchor_and_witness_joint_rollback_detection:
      report.side_door_report.store_anchor_and_witness_joint_rollback_detection,
    host_filesystem_path_toctou_closed:
      report.side_door_report.host_filesystem_path_toctou_closed,
    missing_receipt_refused: report.runtime_proof_summary.missing_receipt_refused,
    invalid_receipt_refused: report.runtime_proof_summary.invalid_receipt_refused,
    unknown_issuer_refused: report.runtime_proof_summary.unknown_issuer_refused,
    retired_issuer_refused: report.runtime_proof_summary.retired_issuer_refused,
    missing_issuer_status_refused: report.runtime_proof_summary.missing_issuer_status_refused,
    stale_receipt_refused: report.runtime_proof_summary.stale_receipt_refused,
    wrong_policy_refused: report.runtime_proof_summary.wrong_policy_refused,
    wrong_domain_refused: report.runtime_proof_summary.wrong_domain_refused,
    wrong_tool_refused: report.runtime_proof_summary.wrong_tool_refused,
    wrong_runtime_profile_id_refused: report.runtime_proof_summary.wrong_runtime_profile_id_refused,
    wrong_audit_event_refused: report.runtime_proof_summary.wrong_audit_event_refused,
    wrong_detail_refused: report.runtime_proof_summary.wrong_detail_refused,
    non_boarding_outcome_refused: report.runtime_proof_summary.non_boarding_outcome_refused,
    direct_api_with_receipt_refused: report.runtime_proof_summary.direct_api_with_receipt_refused,
    agent_supplied_authority_material_refused:
      report.runtime_proof_summary.agent_supplied_authority_material_refused,
    claim_boundary:
      'artifact integrity and historical embedded local disposable runtime profile installation facts only; current fixture-rightful projection refused by shared authority status',
    non_claims: [...report.non_claims],
  };
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification));
  return verification;
}

export function formatProtectedRecordsRuntimeProfileInstallationProofSummary(report, plan, profile) {
  assertProtectedRecordsRuntimeProfileInstallationProof(report, plan, profile);
  const lines = [
    'ZLAR Protected Records Runtime Profile Installation Historical Proof v1',
    'Current authority: fixture_rightful_issuance_path_evidenced=false; legacy artifact has no grant-contract SHA binding',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Plan: id=${report.plan.plan_id}; status=${report.plan.plan_status}; posture=${report.plan.deployment_posture}; sha256=${report.plan.plan_sha256}`,
    `Runtime profile: id=${report.runtime_profile.profile_id}; runtime_profile=${report.runtime_profile.runtime_profile_id}; profile_sha256=${report.runtime_profile.profile_sha256}; sha_matches_plan=${report.runtime_profile.profile_sha_matches_plan}`,
    `Installation: disposable_root_created=${report.installation.install_root_created}; profile_copy_written=${report.installation.profile_copy_written}; active_profile_index_written=${report.installation.active_profile_index_written}; selected_from_install_root=${report.installation.profile_selected_from_install_root}; selected_by_id_and_sha=${report.installation.selected_by_explicit_id_and_sha}; selects_latest_profile=${report.installation.selects_latest_profile}`,
    `Activation contract: launcher_config=${report.activation_contract.launcher_supplies_config}; launcher_grant_contract=${report.activation_contract.launcher_supplies_authority_grant_contract}; launcher_grant_appointment=${report.activation_contract.launcher_supplies_authority_grant_appointment}; launcher_issuance_decision=${report.activation_contract.launcher_supplies_authority_grant_issuance_decision}; config_path_agent_supplied=${report.activation_contract.config_path_agent_supplied}; consumed_grant_witness_path_agent_supplied=${report.activation_contract.consumed_grant_store_witness_path_agent_supplied}; authority_grant_material_agent_supplied=${report.activation_contract.authority_grant_material_agent_supplied}; downstream_recognition_required=${report.activation_contract.downstream_recognition_required}; grant_refusals_required=${report.activation_contract.missing_mismatched_expired_revoked_or_consumed_grant_refused}`,
    `Request authority guard: installed_profile_state_refused=${report.request_authority_guard_summary.installed_profile_state_refused}; runtime_config_refused=${report.request_authority_guard_summary.runtime_config_refused}; runtime_profile_refused=${report.request_authority_guard_summary.runtime_profile_refused}; recognition_rule_refused=${report.request_authority_guard_summary.recognition_rule_refused}; authority_grant_refused=${report.request_authority_guard_summary.authority_grant_refused}; state_delta_total=${report.request_authority_guard_summary.state_entry_count_delta_total}`,
    `Runtime proof: command=${report.runtime_proof_summary.proof_command}; run=${report.runtime_proof_summary.proof_run}; service_command=${report.runtime_proof_summary.service_command}; cases=${report.runtime_proof_summary.case_count}/${report.runtime_proof_summary.required_case_count}; boundary_observations=${report.runtime_proof_summary.boundary_observation_count}/${report.runtime_proof_summary.required_boundary_observation_count}`,
    `Runtime profile identity policy: authority_source=${report.runtime_proof_summary.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${report.runtime_proof_summary.request_runtime_profile_id_required}; omitted_request_field_present=${report.runtime_proof_summary.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${report.runtime_proof_summary.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${report.runtime_proof_summary.supplied_mismatched_runtime_profile_id_refused}`,
    `Runtime authority checks: historical_artifact_fixture_rightful_issuance_path_recorded=${report.runtime_proof_summary.fixture_rightful_issuance_path_evidenced}; current_fixture_rightful_issuance_path_evidenced=false; artifact_contract_bound_to_authority_status=false; same_process_signed_payload_replay_refused=${report.runtime_proof_summary.same_process_signed_payload_replay_refused}; restart_consumed_authority_grant_refused=${report.runtime_proof_summary.restart_consumed_authority_grant_refused}; missing_grant_refused=${report.runtime_proof_summary.missing_authority_grant_appointment_refused}; mismatched_grant_refused=${report.runtime_proof_summary.mismatched_authority_grant_appointment_refused}; revoked_grant_refused=${report.runtime_proof_summary.revoked_authority_grant_refused}; expired_grant_refused=${report.runtime_proof_summary.expired_authority_grant_refused}; request_supplied_grant_refused=${report.runtime_proof_summary.request_supplied_authority_grant_refused}`,
    `Runtime refusal checks: recognized_write_accepted=${report.runtime_proof_summary.recognized_write_accepted}; missing_receipt_refused=${report.runtime_proof_summary.missing_receipt_refused}; invalid_receipt_refused=${report.runtime_proof_summary.invalid_receipt_refused}; unknown_issuer_refused=${report.runtime_proof_summary.unknown_issuer_refused}; retired_issuer_refused=${report.runtime_proof_summary.retired_issuer_refused}; missing_issuer_status_refused=${report.runtime_proof_summary.missing_issuer_status_refused}; stale_receipt_refused=${report.runtime_proof_summary.stale_receipt_refused}; wrong_policy_refused=${report.runtime_proof_summary.wrong_policy_refused}; wrong_domain_refused=${report.runtime_proof_summary.wrong_domain_refused}; wrong_tool_refused=${report.runtime_proof_summary.wrong_tool_refused}; wrong_runtime_profile_id_refused=${report.runtime_proof_summary.wrong_runtime_profile_id_refused}; wrong_audit_event_refused=${report.runtime_proof_summary.wrong_audit_event_refused}; wrong_detail_refused=${report.runtime_proof_summary.wrong_detail_refused}; non_boarding_outcome_refused=${report.runtime_proof_summary.non_boarding_outcome_refused}; direct_api_with_receipt_refused=${report.runtime_proof_summary.direct_api_with_receipt_refused}; authority_material_refused=${report.runtime_proof_summary.agent_supplied_authority_material_refused}`,
    `Side-door report: disposable_profile_installation_applied=${report.side_door_report.disposable_profile_installation_applied}; atomic_store_anchor_witness_commit=${report.side_door_report.atomic_store_anchor_witness_commit}; partial_grant_commit_burn_window_named=${report.side_door_report.partial_grant_commit_burn_window_named}; joint_rollback_detection=${report.side_door_report.store_anchor_and_witness_joint_rollback_detection}; host_path_toctou_closed=${report.side_door_report.host_filesystem_path_toctou_closed}; persistent_runtime_profile_installed=${report.side_door_report.persistent_runtime_profile_installed}; live_records_system_checked=${report.side_door_report.live_records_system_checked}; production_records_service_checked=${report.side_door_report.production_records_service_checked}; external_attestation=${report.side_door_report.external_attestation}; sovereign_recognition=${report.side_door_report.sovereign_recognition}`,
    `Operator requirements: ${report.operator_requirements.join(',')}`,
    `Known open boundaries: ${report.known_open_boundaries.join(',')}`,
    'Non-claims:',
  ];
  for (const claim of report.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}

export function formatProtectedRecordsRuntimeProfileInstallationArtifactVerification(verification) {
  if (
    !verification ||
    verification.verification_type !== PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Protected records runtime profile installation artifact verification has the wrong type');
  }
  if (verification.verified !== true) {
    throw new Error('Protected records runtime profile installation artifact verification is not verified');
  }
  const lines = [
    'ZLAR Protected Records Runtime Profile Installation Artifact Verification v1',
    `verified=${verification.verified}`,
    `artifact_type=${verification.artifact_type}`,
    `sha256=${verification.body_sha256}`,
    `payload_type=${verification.payload_type}`,
    `evidence_model=${verification.evidence_model}; live_probing=${verification.live_probing}`,
    `plan_sha256=${verification.plan_sha256}`,
    `runtime_profile_sha256=${verification.runtime_profile_sha256}; sha_matches_plan=${verification.runtime_profile_sha_matches_plan}`,
    `runtime_profile_identity_policy: authority_source=${verification.runtime_profile_identity_authority_source}; request_runtime_profile_id_required=${verification.request_runtime_profile_id_required}; omitted_request_field_present=${verification.omitted_request_runtime_profile_id_present}; omitted_uses_launcher_config=${verification.omitted_runtime_profile_id_uses_launcher_config}; supplied_mismatch_refused=${verification.supplied_mismatched_runtime_profile_id_refused}`,
    `request_authority_guard_refused=${verification.request_authority_guard_refused}`,
    `installation_applied=${verification.disposable_profile_installation_applied}; profile_copied=${verification.profile_copied_to_install_root}; active_profile_index_written=${verification.active_profile_index_written}; selected_from_install_root=${verification.profile_selected_from_install_root}; selected_by_id_and_sha=${verification.selected_by_explicit_id_and_sha}; selects_latest_profile=${verification.selects_latest_profile}`,
    `persistent_runtime_profile_installed=${verification.persistent_runtime_profile_installed}; hook_configuration_written=${verification.hook_configuration_written}; user_config_written=${verification.user_config_written}; machine_config_written=${verification.machine_config_written}; runtime_service_started=${verification.runtime_service_started}`,
    `historical_artifact_recognized_write_accepted=${verification.historical_artifact_recognized_write_accepted}; is_current_authority_projection=${verification.recognized_write_accepted_is_current_authority_projection}; replay_after_restart_refused=${verification.replay_after_restart_refused}; missing_receipt_refused=${verification.missing_receipt_refused}; wrong_runtime_profile_id_refused=${verification.wrong_runtime_profile_id_refused}; direct_api_with_receipt_refused=${verification.direct_api_with_receipt_refused}; authority_material_refused=${verification.agent_supplied_authority_material_refused}`,
    `fixture_authority_status: status=${verification.authority_grant_status}; status_contract_sha256=${verification.authority_grant_status_contract_sha256}; artifact_contract_bound=${verification.artifact_contract_bound_to_authority_status}; historical_only_missing_contract_binding=${verification.historical_only_due_to_missing_artifact_grant_contract_binding}; fresh_effect_allowed=${verification.authority_grant_fresh_effect_allowed}; repeated_use_provenance_valid=${verification.authority_grant_repeated_use_provenance_valid}; allows_fixture_rightful_projection=${verification.authority_grant_status_allows_fixture_rightful_projection}; reason_code=${verification.authority_grant_status_reason_code}`,
    `fixture_rightful_issuance: historical_artifact_fixture_rightful_issuance_path_evidenced=${verification.historical_artifact_fixture_rightful_issuance_path_evidenced}; fixture_rightful_issuance_path_evidenced=${verification.fixture_rightful_issuance_path_evidenced}`,
    `claim_boundary=${verification.claim_boundary}`,
    'Non-claims:',
  ];
  for (const claim of verification.non_claims) {
    lines.push(`- ${claim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}

export function formatProtectedRecordsRuntimeProfileInstallationArtifactSummary(artifact) {
  assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact);
  const lines = [
    'Portable runtime profile installation artifact:',
    `- type=${artifact.artifact_type}`,
    `- sha256=${artifact.integrity.body_sha256}`,
    `- hash_scope=${artifact.hash_scope}`,
  ];
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}
