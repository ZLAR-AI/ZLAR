import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';
import {
  assertProtectedRecordsRuntimeProfileInstallationPlan,
} from './protected-records-runtime-profile-installation.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE,
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
  buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact,
  parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText,
  runProtectedRecordsInstalledRuntimeProfilePreflight,
} from './protected-records-installed-runtime-profile-preflight.mjs';

export const PROTECTED_RECORDS_INSTALLED_PROOF_SAMPLE_CONTEXT_TYPE =
  'zlar-protected-records-installed-proof-sample-context-v1';

export const PROTECTED_RECORDS_INSTALLED_SAMPLE_CONTEXT_CLAIM_BOUNDARY =
  'installed-local canonical sample context only; no repo checkout, no source freshness, no live runtime, no current-machine governance, no production downstream recognition, and no public or external attestation claim';

export const SAMPLE_DEPLOYMENT_PROFILE_DISPLAY_PATH =
  'profiles/protected-records-one-terminal-deployment-profile.fixture.json';
export const SAMPLE_PLAN_DISPLAY_PATH =
  'profiles/protected-records-runtime-profile-installation-plan.fixture.json';
export const SAMPLE_PROFILE_DISPLAY_PATH =
  'profiles/protected-records-runtime-fixture.profile.json';
export const SAMPLE_PREFLIGHT_ARTIFACT_DISPLAY_PATH =
  'tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json';

export const SAMPLE_DEPLOYMENT_PROFILE_TEXT_SHA256 = 'fcde2bf8427c235ab9cc89ebe53d9067fb1d760d5903d7286ee5af53b8a3a28d';
export const SAMPLE_PLAN_TEXT_SHA256 = 'e38e4dc1b03ee11a01f73901ff9d23dadda97b8044ab117c6889562896715464';
export const SAMPLE_PROFILE_TEXT_SHA256 = '7e0016e92590e1bda7a124aea4e6c9fec68e01fba438abce4239f26c3608bfb9';
export const SAMPLE_PREFLIGHT_ARTIFACT_TEXT_SHA256 = 'c797bcb6269bc9e1b9377bf8a7b7f375db65c3a9a45d7de672b774eb2ea514c2';
export const SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256 = '2b5427aec78c63cc9768bb25ed8cdde316d4b8e3f07dac11c80baa54e1b71bec';

const SAMPLE_DEPLOYMENT_PROFILE_TEXT = "{\n  \"profile_type\": \"zlar-protected-records-one-terminal-deployment-profile-v1\",\n  \"profile_id\": \"protected-records-one-terminal-deployment-profile-fixture\",\n  \"profile_status\": \"sample_not_active\",\n  \"deployment_model\": \"one-terminal-local-fixture\",\n  \"action_class\": \"records.write\",\n  \"selected_runtime_profile\": {\n    \"source\": \"deployment-owned-profile-artifact\",\n    \"profile_path\": \"profiles/protected-records-runtime-fixture.profile.json\",\n    \"profile_id\": \"protected-records-runtime-fixture-profile\",\n    \"runtime_profile_id\": \"protected-records-disposable-runtime-profile\",\n    \"profile_sha256\": \"e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469\",\n    \"selected_by_explicit_id_and_sha\": true,\n    \"selects_latest_profile\": false\n  },\n  \"authority_boundary\": {\n    \"deployment_owned_profile_artifact\": true,\n    \"profile_selected_by_id_and_sha\": true,\n    \"request_stream_authority_material_accepted\": false,\n    \"recognition_rule_supplied_by_agent\": false,\n    \"fixture_mode_supplied_by_agent\": false,\n    \"unsupported_request_fields_accepted\": false,\n    \"agent_supplied_authority_material_accepted\": false\n  },\n  \"request_contract\": \"receipt-record-update-and-routing-metadata-only\",\n  \"proof_boundary\": {\n    \"local_fixture_only\": true,\n    \"persistent_install\": false,\n    \"activation_performed\": false,\n    \"live_runtime_service\": false,\n    \"live_records_system\": false,\n    \"production_downstream_recognition\": false,\n    \"production_authority\": false,\n    \"current_machine_governance\": false,\n    \"enterprise_readiness\": false,\n    \"external_attestation\": false,\n    \"sovereign_recognition\": false,\n    \"unrouted_surface_coverage\": false\n  },\n  \"proof_command\": \"zlar protected-records-one-terminal-deployment-profile --sample\",\n  \"non_claims\": [\n    \"This deployment profile is a local fixture artifact, not an active enterprise deployment.\",\n    \"This proof does not install, activate, or persist a runtime profile.\",\n    \"This proof does not start a live runtime service or inspect a live records system.\",\n    \"This proof does not write hook, user, machine, production, receipt, audit, or records-system configuration.\",\n    \"This proof does not prove production downstream recognition, production authority, enterprise readiness, current-machine governance, external attestation, sovereign recognition, or coverage of unrouted surfaces.\"\n  ]\n}\n";
const SAMPLE_PLAN_TEXT = "{\n  \"plan_type\": \"zlar-protected-records-runtime-profile-installation-plan-v1\",\n  \"plan_id\": \"protected-records-runtime-profile-installation-fixture-plan\",\n  \"plan_status\": \"sample_local_disposable_only\",\n  \"deployment_posture\": \"local_disposable_profile_installation_only\",\n  \"action_class\": \"records.write\",\n  \"runtime_profile_id\": \"protected-records-disposable-runtime-profile\",\n  \"runtime_profile_source\": \"profiles/protected-records-runtime-fixture.profile.json\",\n  \"runtime_profile_sha256\": \"e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469\",\n  \"installation_command\": \"zlar protected-records-runtime-profile-installation --plan profiles/protected-records-runtime-profile-installation-plan.fixture.json --profile profiles/protected-records-runtime-fixture.profile.json\",\n  \"runtime_profile_proof_command\": \"zlar protected-records-runtime-profile-proof\",\n  \"service_command\": \"zlar protected-records-runtime-service --config <launcher-owned-disposable-config>\",\n  \"installation_boundary\": {\n    \"local_disposable_install_root_created\": true,\n    \"profile_copied_to_install_root\": true,\n    \"active_profile_index_written\": true,\n    \"profile_selected_from_install_root\": true,\n    \"persistent_runtime_profile_installed\": false,\n    \"writes_hook_configuration\": false,\n    \"writes_user_config\": false,\n    \"writes_machine_config\": false,\n    \"selects_latest_profile\": false,\n    \"request_stream_authority_material_accepted\": false,\n    \"uses_live_runtime_profile\": false,\n    \"uses_live_records_system\": false\n  },\n  \"activation_contract\": {\n    \"launcher_supplies_config\": true,\n    \"launcher_supplies_authority_grant_contract\": true,\n    \"launcher_supplies_authority_grant_appointment\": true,\n    \"launcher_supplies_authority_grant_issuance_decision\": true,\n    \"launcher_supplies_authorized_record_update\": true,\n    \"config_path_agent_supplied\": false,\n    \"state_path_agent_supplied\": false,\n    \"consumed_grants_path_agent_supplied\": false,\n    \"consumed_grant_store_anchor_path_agent_supplied\": false,\n    \"consumed_grant_store_witness_path_agent_supplied\": false,\n    \"recognition_rule_agent_supplied\": false,\n    \"issuer_registry_agent_supplied\": false,\n    \"authority_grant_material_agent_supplied\": false,\n    \"downstream_recognition_required\": true,\n    \"missing_or_unrecognized_receipt_refused\": true,\n    \"missing_mismatched_expired_revoked_or_consumed_grant_refused\": true\n  },\n  \"operator_requirements\": [\n    \"explicit_disposable_install_command\",\n    \"profile_sha_verified_before_installation\",\n    \"launcher_owned_disposable_install_root\",\n    \"active_profile_selected_by_id_and_sha\",\n    \"launcher_owned_fixture_authority_grant_material\",\n    \"downstream_refuses_missing_or_unrecognized_receipts\",\n    \"rightful_issuance_and_grant_refusals_proven\",\n    \"store_anchor_witness_boundaries_accepted_or_external_custody_added\"\n  ],\n  \"known_open_boundaries\": [\n    \"disposable_install_only\",\n    \"persistent_runtime_profile_installation\",\n    \"hook_configuration\",\n    \"user_or_machine_configuration\",\n    \"live_runtime_profile\",\n    \"live_records_system\",\n    \"production_records_service\",\n    \"current_machine_governance\",\n    \"live_mcp_coverage\",\n    \"live_approval_channel_health\",\n    \"exactly_once_effect_semantics\",\n    \"store_anchor_and_witness_rollback_or_deletion\",\n    \"store_anchor_witness_commit_atomicity\",\n    \"host_filesystem_path_toctou\",\n    \"anti_rollback_anchor_custody\",\n    \"stale_lock_recovery\",\n    \"multi_host_consumed_store_coordination\",\n    \"production_durable_consumed_store\",\n    \"host_process_or_memory_introspection\",\n    \"external_attestation\",\n    \"sovereign_recognition\",\n    \"unrouted_records_paths\"\n  ],\n  \"non_claims\": [\n    \"This proof installs a runtime profile only inside a launcher-owned disposable proof root; it is not a persistent install or production deployment.\",\n    \"This proof writes only disposable proof-harness files; it does not modify hooks, user config, machine configuration, or production configuration.\",\n    \"This proof selects by explicit profile id and SHA; it does not select --latest, a live profile, or a current-machine profile.\",\n    \"This proof starts local JSONL child service processes only through the bounded runtime-profile proof; it does not start or inspect a live records system or production records service.\",\n    \"This proof does not use Telegram or prove live human approval-channel delivery.\",\n    \"This proof does not prove current-machine governance, live MCP coverage, external attestation, enterprise readiness, production authority, sovereign recognition, or coverage of unrouted surfaces.\",\n    \"This proof carries local fixture rightful-issuance evidence only; it does not prove production authority, portable rightful issuance, a live target, current-machine governance, or consequence-lifecycle closure.\",\n    \"This proof inherits runtime-profile storage boundaries: no exactly-once effects, no atomic all-or-nothing commit across the consumed-authority-grant store, local anchor, and local witness, no joint store-anchor-witness rollback detection, no host-path TOCTOU closure, no production durable storage, no stale-lock recovery, no multi-host coordination, and no external anti-rollback custody.\",\n    \"This proof does not close host process, memory, debugger, operator filesystem, hook-configuration, user-configuration, machine-configuration, or unrouted records side doors.\"\n  ]\n}\n";
const SAMPLE_PROFILE_TEXT = "{\n  \"profile_type\": \"zlar-protected-records-runtime-profile-v1\",\n  \"profile_id\": \"protected-records-runtime-fixture-profile\",\n  \"profile_status\": \"sample_not_active\",\n  \"deployment_posture\": \"runtime_profile_preflight_only\",\n  \"action_class\": \"records.write\",\n  \"runtime_profile_id\": \"protected-records-disposable-runtime-profile\",\n  \"runtime_environment\": \"local-disposable-jsonl-child-process\",\n  \"service_command\": \"zlar protected-records-runtime-service --config <file>\",\n  \"proof_command\": \"zlar protected-records-runtime-profile-proof\",\n  \"result_type\": \"protected-records-runtime-service-result-v1\",\n  \"proof_type\": \"protected-records-runtime-profile-proof-v1\",\n  \"request_contract\": \"receipt-record-update-and-routing-metadata-only\",\n  \"recognition_boundary\": \"service-configured-recognition-rule\",\n  \"mutation_authoritative_route\": \"receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation\",\n  \"state_storage\": \"process-private-memory\",\n  \"consumed_authority_grant_store\": \"persistent-single-use-authority-grant-contract-sha256-store\",\n  \"consumption_identity\": \"authority-grant-contract-sha256\",\n  \"signed_payload_replay_identity\": \"verified-signed-payload-sha256\",\n  \"consumed_store_lock\": \"launcher-owned-per-store-lockfile\",\n  \"consumed_store_validation\": \"exact-schema-unique-grant-contract-sha256s\",\n  \"consumed_store_anchor\": \"launcher-owned-local-store-hash-anchor\",\n  \"consumed_store_witness\": \"launcher-owned-local-store-hash-witness\",\n  \"consumed_store_rollback_detection\": \"single-host-anchor-and-witness-match-before-mutation\",\n  \"consumed_store_write_model\": \"per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness\",\n  \"replay_scope\": \"helper-signed-payload-identity-and-persistent-authority-grant-contract-sha256\",\n  \"authority_boundary\": {\n    \"config_supplied_by_launcher\": true,\n    \"authority_grant_contract_required_from_launcher\": true,\n    \"authority_grant_appointment_required_from_launcher\": true,\n    \"authority_grant_issuance_decision_required_from_launcher\": true,\n    \"authorized_record_update_required_from_launcher\": true,\n    \"source_profile_authority_grant_present\": false,\n    \"request_stream_authority_material_accepted\": false,\n    \"state_path_exposed_to_agent\": false,\n    \"consumed_grants_path_exposed_to_agent\": false,\n    \"consumed_grant_store_anchor_path_exposed_to_agent\": false,\n    \"consumed_grant_store_witness_path_exposed_to_agent\": false,\n    \"recognition_rule_supplied_by_agent\": false,\n    \"fixture_mode_supplied_by_agent\": false,\n    \"unsupported_request_fields_accepted\": false\n  },\n  \"storage_boundary\": {\n    \"persistent_consumed_authority_grant_store\": true,\n    \"lockfile_owned_by_launcher\": true,\n    \"local_anchor_owned_by_launcher\": true,\n    \"local_witness_owned_by_launcher\": true,\n    \"single_host_rollback_detection\": true,\n    \"store_and_anchor_joint_rollback_refused_while_witness_ahead\": true,\n    \"store_anchor_and_witness_joint_rollback_detection\": false,\n    \"atomic_store_anchor_witness_commit\": false,\n    \"partial_grant_commit_burn_window_named\": true,\n    \"partial_commit_witness_missing_observed\": true,\n    \"host_filesystem_path_toctou_closed\": false,\n    \"production_grade_anti_rollback\": false,\n    \"production_grade_durable_storage\": false,\n    \"stale_lock_recovery\": false,\n    \"multi_host_coordination\": false,\n    \"tamper_resistance\": false,\n    \"exactly_once_effect_semantics\": false\n  },\n  \"required_cases\": [\n    \"recognized_runtime_write_first_request\",\n    \"replay_runtime_write_refused_same_service_process\",\n    \"replay_runtime_write_refused_after_service_restart\",\n    \"invalid_consumed_store_refused_before_runtime_mutation\",\n    \"duplicate_consumed_store_refused_before_runtime_mutation\",\n    \"locked_consumed_store_refused_before_runtime_mutation\",\n    \"invalid_consumed_store_anchor_refused_before_runtime_mutation\",\n    \"valid_consumed_store_rollback_refused_before_runtime_mutation\",\n    \"consumed_store_deletion_refused_before_runtime_mutation\",\n    \"valid_consumed_store_replacement_refused_before_runtime_mutation\",\n    \"runtime_state_append_failed_after_consumed_store_commit\",\n    \"witness_commit_failed_after_authority_grant_store_commit\",\n    \"store_and_anchor_joint_rollback_refused_against_witness_before_runtime_mutation\",\n    \"missing_receipt_refused_before_runtime_mutation\",\n    \"invalid_receipt_refused_before_runtime_mutation\",\n    \"unknown_issuer_refused_before_runtime_mutation\",\n    \"retired_issuer_refused_before_runtime_mutation\",\n    \"missing_issuer_status_refused_before_runtime_mutation\",\n    \"missing_authority_grant_appointment_refused_before_consumption\",\n    \"mismatched_authority_grant_appointment_refused_before_consumption\",\n    \"revoked_authority_grant_refused_before_consumption\",\n    \"expired_authority_grant_refused_before_consumption\",\n    \"wrong_policy_refused_before_runtime_mutation\",\n    \"wrong_domain_refused_before_runtime_mutation\",\n    \"wrong_tool_refused_before_runtime_mutation\",\n    \"wrong_runtime_profile_id_refused_before_runtime_mutation\",\n    \"wrong_audit_event_refused_before_runtime_mutation\",\n    \"wrong_detail_refused_before_runtime_mutation\",\n    \"non_boarding_outcome_refused_before_runtime_mutation\",\n    \"stale_receipt_refused_before_runtime_mutation\",\n    \"direct_api_without_receipt_refused_before_runtime_mutation\",\n    \"direct_api_with_receipt_refused_before_runtime_mutation\",\n    \"agent_supplied_state_path_refused_before_runtime_mutation\",\n    \"agent_supplied_consumed_grants_path_refused_before_runtime_mutation\",\n    \"agent_supplied_consumed_grant_store_anchor_path_refused_before_runtime_mutation\",\n    \"agent_supplied_fixture_mode_refused_before_runtime_mutation\",\n    \"agent_supplied_recognition_rule_refused_before_runtime_mutation\",\n    \"agent_supplied_authority_grant_refused_before_runtime_mutation\",\n    \"unsupported_request_field_refused_before_runtime_mutation\"\n  ],\n  \"required_boundary_observations\": [\n    \"preconsumed_authority_grant_without_runtime_state_refuses_reuse\",\n    \"store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse\"\n  ],\n  \"known_open_boundaries\": [\n    \"host_process_or_memory_introspection\",\n    \"live_records_system\",\n    \"production_records_service\",\n    \"exactly_once_effect_semantics\",\n    \"store_anchor_and_witness_rollback_or_deletion\",\n    \"store_anchor_witness_commit_atomicity\",\n    \"host_filesystem_path_toctou\",\n    \"anti_rollback_anchor_custody\",\n    \"stale_lock_recovery\",\n    \"multi_host_consumed_store_coordination\",\n    \"production_durable_consumed_store\",\n    \"persistent_runtime_profile_installation\",\n    \"unrouted_records_paths\"\n  ],\n  \"non_claims\": [\n    \"This profile is a sample runtime-profile preflight profile, not an active or installed runtime profile.\",\n    \"This preflight runs local disposable runtime-profile proof only.\",\n    \"This proof is a local disposable runtime-profile proof, not production deployment.\",\n    \"This proof does not inspect a live records system.\",\n    \"This proof does not install a persistent runtime profile.\",\n    \"This proof does not prove a production records service.\",\n    \"This profile declares launcher-owned authority-grant inputs as activation requirements; it contains no exact grant contract, appointment, issuance decision, authorized record update, issuer key, or grant window.\",\n    \"This proof does not prove production-grade durable storage, stale-lock recovery, multi-host coordination, or tamper resistance for the consumed-authority-grant store or local anchor.\",\n    \"This proof does not prove exactly-once effect semantics; a crash after authority-grant consumption and before runtime-state mutation can burn the one-use grant.\",\n    \"This proof does not prove an atomic all-or-nothing commit across the consumed-authority-grant store, local anchor, and local witness; a metadata write failure after grant-store commit can burn the one-use grant before runtime-state mutation.\",\n    \"This proof does not detect rollback, deletion, or replacement when the consumed-authority-grant store, local anchor, and local witness are moved together without stronger custody or an external witness.\",\n    \"This proof does not close host process, memory, debugger, or operator filesystem side doors.\",\n    \"This proof does not close host filesystem path-replacement or symlink time-of-check/time-of-use side doors after launcher config validation.\",\n    \"This proof does not prove live MCP coverage, live approval-channel health, or current-machine governance.\",\n    \"This proof does not prove external attestation, enterprise readiness, production authority, or sovereign recognition.\",\n    \"This proof does not prove coverage of unrouted records paths.\"\n  ]\n}\n";

function sha256Text(value) {
  return sha256hex(value);
}

function parseCanonicalJsonText(label, text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${label} sample JSON is malformed: ${err.message}`);
  }
}

function assertTextHash(label, text, expectedSha256) {
  if (sha256Text(text) !== expectedSha256) {
    throw new Error(`${label} sample SHA-256 mismatch`);
  }
  return true;
}

export function protectedRecordsInstalledProofSampleContext() {
  return {
    sample_context_type: PROTECTED_RECORDS_INSTALLED_PROOF_SAMPLE_CONTEXT_TYPE,
    evidence_model: 'installed-local-canonical-sample-fixture',
    deployment_profile_display_path: SAMPLE_DEPLOYMENT_PROFILE_DISPLAY_PATH,
    plan_display_path: SAMPLE_PLAN_DISPLAY_PATH,
    profile_display_path: SAMPLE_PROFILE_DISPLAY_PATH,
    preflight_artifact_display_path: SAMPLE_PREFLIGHT_ARTIFACT_DISPLAY_PATH,
    deployment_profile_text_sha256: SAMPLE_DEPLOYMENT_PROFILE_TEXT_SHA256,
    plan_text_sha256: SAMPLE_PLAN_TEXT_SHA256,
    profile_text_sha256: SAMPLE_PROFILE_TEXT_SHA256,
    preflight_artifact_body_sha256: SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256,
    repo_paths_required_at_runtime: false,
    installed_profiles_path_required: false,
    installed_tests_fixtures_path_required: false,
    claim_boundary: PROTECTED_RECORDS_INSTALLED_SAMPLE_CONTEXT_CLAIM_BOUNDARY,
    source_freshness_claimed: false,
    current_machine_governance_proven: false,
    production_downstream_recognition_proven: false,
    external_attestation_proven: false,
  };
}

export function readProtectedRecordsOneTerminalDeploymentProfileSampleText() {
  assertTextHash('Protected records one-terminal deployment profile', SAMPLE_DEPLOYMENT_PROFILE_TEXT, SAMPLE_DEPLOYMENT_PROFILE_TEXT_SHA256);
  return SAMPLE_DEPLOYMENT_PROFILE_TEXT;
}

export function readProtectedRecordsInstalledSamplePlanText() {
  assertTextHash('Protected records installed runtime profile plan', SAMPLE_PLAN_TEXT, SAMPLE_PLAN_TEXT_SHA256);
  return SAMPLE_PLAN_TEXT;
}

export function readProtectedRecordsInstalledSampleProfileText() {
  assertTextHash('Protected records installed runtime profile', SAMPLE_PROFILE_TEXT, SAMPLE_PROFILE_TEXT_SHA256);
  return SAMPLE_PROFILE_TEXT;
}

export function readProtectedRecordsInstalledSamplePlan() {
  const plan = parseCanonicalJsonText(
    'Protected records installed runtime profile plan',
    readProtectedRecordsInstalledSamplePlanText()
  );
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  return plan;
}

export function readProtectedRecordsInstalledSampleProfile() {
  const profile = parseCanonicalJsonText(
    'Protected records installed runtime profile',
    readProtectedRecordsInstalledSampleProfileText()
  );
  assertProtectedRecordsRuntimePreflightProfile(profile);
  return profile;
}

export function assertProtectedRecordsInstalledSampleInputs(plan, profile) {
  assertProtectedRecordsRuntimeProfileInstallationPlan(plan);
  assertProtectedRecordsRuntimePreflightProfile(profile);
  const profileSha = runtimeProfileSha256(profile);
  if (
    profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    plan.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    plan.runtime_profile_sha256 !== profileSha ||
    canonicalize(plan) !== canonicalize(readProtectedRecordsInstalledSamplePlan()) ||
    canonicalize(profile) !== canonicalize(readProtectedRecordsInstalledSampleProfile())
  ) {
    throw new Error('Protected records installed proof sample input drifted');
  }
  return true;
}

function createDisposableInstalledProfileRoot(profile, profileSha) {
  const installRoot = mkdtempSync(join(tmpdir(), 'zlar-installed-sample-preflight-'));
  try {
    const profilesDir = join(installRoot, 'profiles');
    mkdirSync(profilesDir, { recursive: true, mode: 0o700 });
    writeFileSync(
      join(profilesDir, `${profile.runtime_profile_id}.json`),
      `${JSON.stringify(profile, null, 2)}\n`,
      { mode: 0o600 }
    );
    const activeIndex = {
      index_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE,
      selected_profile_id: profile.profile_id,
      selected_runtime_profile_id: profile.runtime_profile_id,
      selected_profile_sha256: profileSha,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
      installed_profile_path:
        '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json',
    };
    writeFileSync(
      join(installRoot, 'active-runtime-profile.json'),
      `${JSON.stringify(activeIndex, null, 2)}\n`,
      { mode: 0o600 }
    );
    return installRoot;
  } catch (err) {
    rmSync(installRoot, { recursive: true, force: true });
    throw err;
  }
}

export function buildCanonicalProtectedRecordsInstalledPreflightSampleArtifact() {
  const plan = readProtectedRecordsInstalledSamplePlan();
  const profile = readProtectedRecordsInstalledSampleProfile();
  assertProtectedRecordsInstalledSampleInputs(plan, profile);
  const profileSha = runtimeProfileSha256(profile);
  const installRoot = createDisposableInstalledProfileRoot(profile, profileSha);
  try {
    const report = runProtectedRecordsInstalledRuntimeProfilePreflight({
      installRoot,
      expectedProfile: profile,
      profileId: profile.profile_id,
      profileSha256: profileSha,
    });
    const artifact = buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact(report);
    assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
    if (artifact.integrity.body_sha256 !== SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256) {
      throw new Error('Protected records installed proof sample preflight artifact SHA-256 mismatch');
    }
    return artifact;
  } finally {
    rmSync(installRoot, { recursive: true, force: true });
  }
}

export function readCanonicalProtectedRecordsInstalledPreflightSampleArtifactText() {
  const artifact = buildCanonicalProtectedRecordsInstalledPreflightSampleArtifact();
  const text = `${JSON.stringify(artifact, null, 2)}\n`;
  assertTextHash('Protected records installed proof sample preflight artifact text', text, SAMPLE_PREFLIGHT_ARTIFACT_TEXT_SHA256);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText(text);
  return text;
}
