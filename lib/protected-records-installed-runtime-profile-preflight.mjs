import {
  lstatSync,
  mkdirSync,
  realpathSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';
import {
  PROTECTED_RECORDS_CONSEQUENCE_PATH,
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_TARGET_DESCRIPTOR,
  PROTECTED_RECORDS_TARGET_HANDLE,
  PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR,
  PROTECTED_RECORDS_TARGET_KIND,
  PROTECTED_RECORDS_TARGET_SCOPE,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsTargetHandle,
} from './protected-records-runtime-profile.mjs';
import {
  assertProtectedRecordsRuntimePreflightProfile,
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS,
  PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT,
} from './protected-records-fixture-authority-grant.mjs';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_TYPE =
  'zlar-protected-records-installed-runtime-profile-preflight-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_TYPE =
  'zlar-protected-records-installed-runtime-profile-preflight-artifact-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_CANONICALIZATION =
  'zlar-canonical-json-v1';
export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE =
  'zlar-protected-records-installed-runtime-profile-preflight-artifact-verification-v1';

export const PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE =
  'zlar-disposable-runtime-profile-active-index-v1';

export const INSTALLED_RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING =
  'ZLAR can read an explicit protected-records installed runtime profile root, verify its active-profile index selects a pinned profile by explicit profile id and SHA, validate the installed profile contract, preserve the selected profile recognition contract, and describe a deterministic launcher-owned local-fixture authority-grant requirement without instantiating an exact runtime grant, issuer appointment, key binding, or grant window; no latest selection, runtime activation, service start, hook/user/machine configuration write, live records-system inspection, downstream refusal proof, current-machine governance proof, or production authority is performed by this preflight.';

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_OPEN_BOUNDARIES = Object.freeze([
  'read_only_preflight_only',
  'runtime_profile_installation_not_performed',
  'runtime_profile_activation_not_performed',
  'hook_user_machine_configuration_not_written',
  'runtime_configuration_not_written',
  'runtime_service_not_started',
  'live_runtime_profile_health',
  'live_records_system',
  'production_records_service',
  'downstream_refusal',
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
  'exact_runtime_authority_grant_contract',
  'runtime_private_issuer_appointment',
  'concrete_authority_grant_window',
]);

export const INSTALLED_RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS = Object.freeze([
  'This preflight reads an explicit install root only; it does not install, activate, or persist a runtime profile.',
  'This preflight requires an explicit install root, profile id, and profile SHA-256; it does not select --latest, use a default current-machine profile, or infer authority from operator state.',
  'This preflight validates active-profile selection metadata, the installed profile contract, and the selected profile recognition contract; it does not start a runtime service, run a downstream refusal proof, or inspect a live records system.',
  'This preflight is read-only; it does not write runtime configuration, hook configuration, user configuration, machine configuration, production configuration, receipts, stores, anchors, or audit logs.',
  'This preflight does not use Telegram or prove live human approval-channel delivery.',
  'This preflight does not prove current-machine governance, live MCP coverage, external attestation, enterprise readiness, production authority, sovereign recognition, or coverage of unrouted surfaces.',
  'This preflight inherits runtime-profile boundaries: no exactly-once effects, no atomic all-or-nothing store-anchor-witness commit, no joint store-anchor-witness rollback detection, no host-path TOCTOU closure, no production durable consumed-grant store, no stale-lock recovery, no multi-host coordination, and no external anti-rollback custody.',
  'This preflight does not close host process, memory, debugger, operator filesystem, hook-configuration, user-configuration, machine-configuration, or unrouted records side doors.',
  'This preflight carries a deterministic launcher-owned local-fixture authority-grant requirement only; the selected source profile contains no authority grant.',
  'This preflight does not instantiate an exact runtime grant, issuer appointment, issuer kid, issuer public key, concrete grant window, record update, or target effect.',
  'The exact runtime grant must be created downstream after the preflight body SHA exists; this preflight does not encode a placeholder as an exact grant and does not prove rightful issuance.',
]);

export const INSTALLED_RUNTIME_PROFILE_RECOGNITION_CONTRACT_TYPE =
  'zlar-installed-runtime-profile-recognition-contract-summary-v1';
export const INSTALLED_RUNTIME_PROFILE_TARGET_CONTRACT_TYPE =
  'zlar-installed-runtime-profile-target-contract-v1';
export const INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_REQUIREMENT_TYPE =
  'zlar-installed-runtime-profile-authority-grant-requirement-v1';

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_DEFERRED_BINDINGS =
  Object.freeze([
    'source_preflight_body_sha256',
    'launcher_target_binding_sha256',
    'record_update_sha256',
    'target_effect_sha256',
    'runtime_private_issuer_kid',
    'runtime_private_issuer_public_key_sha256',
    'concrete_grant_window',
  ]);

export const REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES = Object.freeze([
  'missing_receipt_refused_before_runtime_mutation',
  'invalid_receipt_refused_before_runtime_mutation',
  'unknown_issuer_refused_before_runtime_mutation',
  'retired_issuer_refused_before_runtime_mutation',
  'missing_issuer_status_refused_before_runtime_mutation',
  'wrong_policy_refused_before_runtime_mutation',
  'wrong_domain_refused_before_runtime_mutation',
  'wrong_tool_refused_before_runtime_mutation',
  'wrong_runtime_profile_id_refused_before_runtime_mutation',
  'wrong_audit_event_refused_before_runtime_mutation',
  'wrong_detail_refused_before_runtime_mutation',
  'non_boarding_outcome_refused_before_runtime_mutation',
  'stale_receipt_refused_before_runtime_mutation',
  'direct_api_without_receipt_refused_before_runtime_mutation',
  'direct_api_with_receipt_refused_before_runtime_mutation',
  'agent_supplied_recognition_rule_refused_before_runtime_mutation',
  'agent_supplied_fixture_mode_refused_before_runtime_mutation',
  'unsupported_request_field_refused_before_runtime_mutation',
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

function assertProfileId(profileId) {
  if (typeof profileId !== 'string' || !/^[a-z0-9][a-z0-9._-]{2,127}$/.test(profileId)) {
    throw new Error('Protected records installed runtime profile id is malformed');
  }
}

function assertProfileSha256(profileSha256) {
  if (typeof profileSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(profileSha256)) {
    throw new Error('Protected records installed runtime profile SHA-256 is malformed');
  }
}

function buildRecognitionContractSummary(installedProfile) {
  const requiredCases = Array.isArray(installedProfile.required_cases)
    ? installedProfile.required_cases
    : [];
  const missingCase = REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
    .find((caseId) => !requiredCases.includes(caseId));
  if (missingCase) {
    throw new Error('Protected records installed runtime profile recognition contract drifted');
  }
  const authority = installedProfile.authority_boundary || {};
  return {
    contract_type: INSTALLED_RUNTIME_PROFILE_RECOGNITION_CONTRACT_TYPE,
    source: 'selected-installed-runtime-profile',
    action_class: installedProfile.action_class,
    recognition_boundary: installedProfile.recognition_boundary,
    mutation_authoritative_route: installedProfile.mutation_authoritative_route,
    request_contract: installedProfile.request_contract,
    downstream_recognition_required: true,
    launcher_authority: {
      config_supplied_by_launcher: authority.config_supplied_by_launcher,
      request_stream_authority_material_accepted:
        authority.request_stream_authority_material_accepted,
      recognition_rule_supplied_by_agent: authority.recognition_rule_supplied_by_agent,
      fixture_mode_supplied_by_agent: authority.fixture_mode_supplied_by_agent,
      unsupported_request_fields_accepted: authority.unsupported_request_fields_accepted,
    },
    required_refusal_cases: [
      ...REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES,
    ],
    required_refusal_case_count:
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length,
    downstream_refusal_proven: false,
    current_machine_governance_proven: false,
  };
}

function buildTargetContractSummary(installedProfile) {
  const targetDescriptor = { ...PROTECTED_RECORDS_TARGET_DESCRIPTOR };
  return {
    contract_type: INSTALLED_RUNTIME_PROFILE_TARGET_CONTRACT_TYPE,
    source: 'selected-installed-runtime-profile-plus-fixed-logical-fixture-target-descriptor',
    consequence_path: PROTECTED_RECORDS_CONSEQUENCE_PATH,
    action_class: installedProfile.action_class,
    runtime_profile_id: installedProfile.runtime_profile_id,
    mutation_authoritative_route: installedProfile.mutation_authoritative_route,
    target_kind: PROTECTED_RECORDS_TARGET_KIND,
    target_scope: PROTECTED_RECORDS_TARGET_SCOPE,
    target_instance_scope: 'logical-fixture-not-per-run',
    target_descriptor: targetDescriptor,
    target_descriptor_sha256: sha256hex(canonicalize(targetDescriptor)),
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
    target_handle_grammar: PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR,
    target_handle_source: 'required-launcher-owned-service-config',
    request_target_semantics: 'assertion-only',
    receipt_detail_binding:
      'receipt.payload.detail_hash == sha256(canonical(authorized_effect_detail)); authorized_effect_detail binds authority_grant_contract_sha256 and target_effect_sha256',
    state_storage: installedProfile.state_storage,
    source_profile_target_handle_present: false,
    profile_wide_target_authority_proven: false,
    rightful_issuance_proven: false,
    live_target_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
  };
}

export function assertProtectedRecordsInstalledRuntimeProfileTargetContract(contract) {
  assertExactKeys('Protected records installed runtime profile target contract', contract, [
    'action_class',
    'consequence_lifecycle_closed',
    'consequence_path',
    'contract_type',
    'current_machine_governance_proven',
    'live_target_proven',
    'mutation_authoritative_route',
    'profile_wide_target_authority_proven',
    'receipt_detail_binding',
    'request_target_semantics',
    'rightful_issuance_proven',
    'runtime_profile_id',
    'source',
    'source_profile_target_handle_present',
    'state_storage',
    'target_descriptor',
    'target_descriptor_sha256',
    'target_handle',
    'target_handle_grammar',
    'target_handle_source',
    'target_instance_scope',
    'target_kind',
    'target_scope',
  ]);
  const descriptorSha256 = sha256hex(canonicalize(contract.target_descriptor));
  if (
    contract.contract_type !== INSTALLED_RUNTIME_PROFILE_TARGET_CONTRACT_TYPE ||
    contract.source !==
      'selected-installed-runtime-profile-plus-fixed-logical-fixture-target-descriptor' ||
    contract.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    contract.action_class !== 'records.write' ||
    contract.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    contract.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    contract.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    contract.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    contract.target_instance_scope !== 'logical-fixture-not-per-run' ||
    canonicalize(contract.target_descriptor) !== canonicalize(PROTECTED_RECORDS_TARGET_DESCRIPTOR) ||
    contract.target_descriptor_sha256 !== descriptorSha256 ||
    contract.target_handle !== `zlar-target:v1:logical-fixture:${descriptorSha256}` ||
    contract.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    contract.target_handle_grammar !== PROTECTED_RECORDS_TARGET_HANDLE_GRAMMAR ||
    contract.target_handle_source !== 'required-launcher-owned-service-config' ||
    contract.request_target_semantics !== 'assertion-only' ||
    contract.receipt_detail_binding !==
      'receipt.payload.detail_hash == sha256(canonical(authorized_effect_detail)); authorized_effect_detail binds authority_grant_contract_sha256 and target_effect_sha256' ||
    contract.state_storage !== 'process-private-memory' ||
    contract.source_profile_target_handle_present !== false ||
    contract.profile_wide_target_authority_proven !== false ||
    contract.rightful_issuance_proven !== false ||
    contract.live_target_proven !== false ||
    contract.current_machine_governance_proven !== false ||
    contract.consequence_lifecycle_closed !== false
  ) {
    throw new Error('Protected records installed runtime profile target contract drifted');
  }
  assertProtectedRecordsTargetHandle(contract.target_handle);
  return true;
}

export function protectedRecordsInstalledRuntimeProfileTargetContractSha256(contract) {
  assertProtectedRecordsInstalledRuntimeProfileTargetContract(contract);
  return sha256hex(canonicalize(contract));
}

function buildAuthorityGrantRequirementSummary(
  installedProfile,
  recognitionContract,
  targetContract
) {
  const summary = {
    requirement_type: INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_REQUIREMENT_TYPE,
    expected_runtime_contract_type:
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE,
    source: 'launcher-owned-local-fixture-overlay-requirement',
    launcher_owned_local_fixture_overlay: true,
    source_profile_authority_grant_present: false,
    authority_domain_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID,
    grantor_role_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID,
    issuer_slot: PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT,
    consequence_path: targetContract.consequence_path,
    action_class: installedProfile.action_class,
    profile_id: installedProfile.profile_id,
    runtime_profile_id: installedProfile.runtime_profile_id,
    profile_sha256: runtimeProfileSha256(installedProfile),
    recognition_contract_sha256:
      protectedRecordsInstalledRuntimeProfileRecognitionContractSha256(
        recognitionContract
      ),
    target_contract_sha256:
      protectedRecordsInstalledRuntimeProfileTargetContractSha256(targetContract),
    target_kind: targetContract.target_kind,
    target_scope: targetContract.target_scope,
    target_instance_scope: targetContract.target_instance_scope,
    target_handle: targetContract.target_handle,
    required_power_ids: PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS.map(
      (power) => power.power_id
    ),
    deferred_runtime_bindings: [
      ...REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_DEFERRED_BINDINGS,
    ],
    exact_runtime_contract_instantiated: false,
    exact_runtime_contract_deferred_until_preflight_body_sha_available: true,
    hash_cycle_avoided: true,
    actual_issuer_appointment_present: false,
    actual_issuer_kid_present: false,
    actual_issuer_public_key_present: false,
    concrete_grant_window_present: false,
    runtime_enforcement_performed: false,
    rightful_issuance_proven: false,
    portable_rightful_issuance_proven: false,
    production_rightful_issuance_proven: false,
    live_authority_proven: false,
    current_machine_governance_proven: false,
    consequence_lifecycle_closed: false,
  };
  assertProtectedRecordsInstalledRuntimeProfileAuthorityGrantRequirement(summary);
  return summary;
}

export function assertProtectedRecordsInstalledRuntimeProfileAuthorityGrantRequirement(
  summary
) {
  assertExactKeys(
    'Protected records installed runtime profile authority grant requirement',
    summary,
    [
      'action_class',
      'actual_issuer_appointment_present',
      'actual_issuer_kid_present',
      'actual_issuer_public_key_present',
      'authority_domain_id',
      'concrete_grant_window_present',
      'consequence_lifecycle_closed',
      'consequence_path',
      'current_machine_governance_proven',
      'deferred_runtime_bindings',
      'exact_runtime_contract_deferred_until_preflight_body_sha_available',
      'exact_runtime_contract_instantiated',
      'expected_runtime_contract_type',
      'grantor_role_id',
      'hash_cycle_avoided',
      'issuer_slot',
      'launcher_owned_local_fixture_overlay',
      'live_authority_proven',
      'portable_rightful_issuance_proven',
      'production_rightful_issuance_proven',
      'profile_id',
      'profile_sha256',
      'recognition_contract_sha256',
      'required_power_ids',
      'requirement_type',
      'rightful_issuance_proven',
      'runtime_enforcement_performed',
      'runtime_profile_id',
      'source',
      'source_profile_authority_grant_present',
      'target_contract_sha256',
      'target_handle',
      'target_instance_scope',
      'target_kind',
      'target_scope',
    ]
  );
  assertExactArray(
    'Protected records installed runtime profile authority grant deferred bindings',
    summary.deferred_runtime_bindings,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_DEFERRED_BINDINGS
  );
  assertExactArray(
    'Protected records installed runtime profile authority grant required powers',
    summary.required_power_ids,
    PROTECTED_RECORDS_FIXTURE_AUTHORITY_POWERS.map((power) => power.power_id)
  );
  if (
    summary.requirement_type !==
      INSTALLED_RUNTIME_PROFILE_AUTHORITY_GRANT_REQUIREMENT_TYPE ||
    summary.expected_runtime_contract_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE ||
    summary.source !== 'launcher-owned-local-fixture-overlay-requirement' ||
    summary.launcher_owned_local_fixture_overlay !== true ||
    summary.source_profile_authority_grant_present !== false ||
    summary.authority_domain_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID ||
    summary.grantor_role_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID ||
    summary.issuer_slot !== PROTECTED_RECORDS_FIXTURE_ISSUER_SLOT ||
    summary.consequence_path !== PROTECTED_RECORDS_CONSEQUENCE_PATH ||
    summary.action_class !== 'records.write' ||
    summary.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    summary.target_kind !== PROTECTED_RECORDS_TARGET_KIND ||
    summary.target_scope !== PROTECTED_RECORDS_TARGET_SCOPE ||
    summary.target_instance_scope !== 'logical-fixture-not-per-run' ||
    summary.target_handle !== PROTECTED_RECORDS_TARGET_HANDLE ||
    !/^[a-f0-9]{64}$/.test(summary.profile_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(summary.recognition_contract_sha256 || '') ||
    !/^[a-f0-9]{64}$/.test(summary.target_contract_sha256 || '') ||
    summary.exact_runtime_contract_instantiated !== false ||
    summary.exact_runtime_contract_deferred_until_preflight_body_sha_available !==
      true ||
    summary.hash_cycle_avoided !== true ||
    summary.actual_issuer_appointment_present !== false ||
    summary.actual_issuer_kid_present !== false ||
    summary.actual_issuer_public_key_present !== false ||
    summary.concrete_grant_window_present !== false ||
    summary.runtime_enforcement_performed !== false ||
    summary.rightful_issuance_proven !== false ||
    summary.portable_rightful_issuance_proven !== false ||
    summary.production_rightful_issuance_proven !== false ||
    summary.live_authority_proven !== false ||
    summary.current_machine_governance_proven !== false ||
    summary.consequence_lifecycle_closed !== false
  ) {
    throw new Error(
      'Protected records installed runtime profile authority grant requirement drifted'
    );
  }
  return true;
}

export function protectedRecordsInstalledRuntimeProfileAuthorityGrantRequirementSha256(
  summary
) {
  assertProtectedRecordsInstalledRuntimeProfileAuthorityGrantRequirement(summary);
  return sha256hex(canonicalize(summary));
}

function recognitionContractDigestInput(contract) {
  requireObject('Protected records installed runtime profile recognition contract', contract);
  assertExactKeys('Protected records installed runtime profile recognition contract', contract, [
    'action_class',
    'contract_type',
    'current_machine_governance_proven',
    'downstream_recognition_required',
    'downstream_refusal_proven',
    'launcher_authority',
    'mutation_authoritative_route',
    'recognition_boundary',
    'request_contract',
    'required_refusal_case_count',
    'required_refusal_cases',
    'source',
  ]);
  assertExactKeys('Protected records installed runtime profile launcher authority', contract.launcher_authority, [
    'config_supplied_by_launcher',
    'fixture_mode_supplied_by_agent',
    'recognition_rule_supplied_by_agent',
    'request_stream_authority_material_accepted',
    'unsupported_request_fields_accepted',
  ]);
  return {
    contract_type: contract.contract_type,
    source: contract.source,
    action_class: contract.action_class,
    recognition_boundary: contract.recognition_boundary,
    mutation_authoritative_route: contract.mutation_authoritative_route,
    request_contract: contract.request_contract,
    downstream_recognition_required: contract.downstream_recognition_required,
    launcher_authority: {
      config_supplied_by_launcher: contract.launcher_authority.config_supplied_by_launcher,
      request_stream_authority_material_accepted:
        contract.launcher_authority.request_stream_authority_material_accepted,
      recognition_rule_supplied_by_agent:
        contract.launcher_authority.recognition_rule_supplied_by_agent,
      fixture_mode_supplied_by_agent:
        contract.launcher_authority.fixture_mode_supplied_by_agent,
      unsupported_request_fields_accepted:
        contract.launcher_authority.unsupported_request_fields_accepted,
    },
    required_refusal_cases: contract.required_refusal_cases,
    required_refusal_case_count: contract.required_refusal_case_count,
    downstream_refusal_proven: contract.downstream_refusal_proven,
    current_machine_governance_proven: contract.current_machine_governance_proven,
  };
}

export function protectedRecordsInstalledRuntimeProfileRecognitionContractSha256(contract) {
  return sha256hex(canonicalize(recognitionContractDigestInput(contract)));
}

function readJsonFile(path, label) {
  let text = '';
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new Error(`Protected records installed runtime profile preflight could not read ${label}`);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Protected records installed runtime profile preflight ${label} is not valid JSON`);
  }
}

function assertNotSymlink(path, label) {
  try {
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error(`${label} must not be a symlink`);
    }
  } catch (err) {
    if (String(err.message).includes('must not be a symlink')) {
      throw err;
    }
    throw new Error(`Protected records installed runtime profile preflight could not inspect ${label}`);
  }
}

function assertResolvesInsideInstallRoot(installRoot, path, label) {
  try {
    const rootRealPath = realpathSync(installRoot);
    const pathRealPath = realpathSync(path);
    const relativePath = relative(rootRealPath, pathRealPath);
    if (relativePath === '' || relativePath === '..' || relativePath.startsWith(`..${sep}`)) {
      throw new Error(`${label} must resolve inside install root`);
    }
  } catch (err) {
    if (String(err.message).includes('must resolve inside install root')) {
      throw err;
    }
    throw new Error(`Protected records installed runtime profile preflight could not resolve ${label}`);
  }
}

export function assertProtectedRecordsInstalledRuntimeProfileActiveIndex(
  index,
  expectedProfileId,
  expectedProfileSha256
) {
  assertProfileId(expectedProfileId);
  assertProfileSha256(expectedProfileSha256);
  assertExactKeys('Protected records installed runtime profile active index', index, [
    'index_type',
    'installed_profile_path',
    'selected_by_explicit_id_and_sha',
    'selected_profile_id',
    'selected_profile_sha256',
    'selected_runtime_profile_id',
    'selects_latest_profile',
  ]);
  if (
    index.index_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE ||
    index.selected_profile_id !== expectedProfileId ||
    index.selected_runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    index.selected_profile_sha256 !== expectedProfileSha256 ||
    index.selected_by_explicit_id_and_sha !== true ||
    index.selects_latest_profile !== false ||
    index.installed_profile_path !==
      '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json'
  ) {
    throw new Error('Protected records installed runtime profile active index drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(index));
  return true;
}

export function runProtectedRecordsInstalledRuntimeProfilePreflight({
  installRoot,
  expectedProfile,
  profileId,
  profileSha256,
}) {
  if (!installRoot || typeof installRoot !== 'string') {
    throw new Error('Protected records installed runtime profile install root is required');
  }
  assertProfileId(profileId);
  assertProfileSha256(profileSha256);
  assertProtectedRecordsRuntimePreflightProfile(expectedProfile);
  const expectedProfileSha256 = runtimeProfileSha256(expectedProfile);
  if (
    expectedProfile.profile_id !== profileId ||
    expectedProfile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    expectedProfileSha256 !== profileSha256
  ) {
    throw new Error('Protected records installed runtime profile expected profile mismatch');
  }

  const activeIndexPath = join(installRoot, 'active-runtime-profile.json');
  const installedProfilesDir = join(installRoot, 'profiles');
  const installedProfilePath = join(installedProfilesDir, PROTECTED_RECORDS_RUNTIME_PROFILE_ID + '.json');
  assertNotSymlink(installRoot, 'install root');
  assertNotSymlink(installedProfilesDir, 'installed runtime profiles directory');
  assertNotSymlink(activeIndexPath, 'active-profile index');
  assertNotSymlink(installedProfilePath, 'installed runtime profile');
  assertResolvesInsideInstallRoot(installRoot, activeIndexPath, 'active-profile index');
  assertResolvesInsideInstallRoot(installRoot, installedProfilePath, 'installed runtime profile');

  const activeIndex = readJsonFile(activeIndexPath, 'active-profile index');
  assertProtectedRecordsInstalledRuntimeProfileActiveIndex(activeIndex, profileId, profileSha256);

  const installedProfile = readJsonFile(installedProfilePath, 'installed runtime profile');
  assertProtectedRecordsRuntimePreflightProfile(installedProfile);
  const installedProfileSha256 = runtimeProfileSha256(installedProfile);
  if (
    installedProfile.profile_id !== profileId ||
    installedProfile.runtime_profile_id !== activeIndex.selected_runtime_profile_id ||
    installedProfileSha256 !== profileSha256 ||
    installedProfileSha256 !== activeIndex.selected_profile_sha256 ||
    installedProfileSha256 !== expectedProfileSha256 ||
    canonicalize(installedProfile) !== canonicalize(expectedProfile)
  ) {
    throw new Error('Protected records installed runtime profile selection mismatch');
  }

  const recognitionContract = buildRecognitionContractSummary(installedProfile);
  const targetContract = buildTargetContractSummary(installedProfile);
  const authorityGrantRequirement = buildAuthorityGrantRequirementSummary(
    installedProfile,
    recognitionContract,
    targetContract
  );

  const report = {
    preflight_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_TYPE,
    evidence_model: 'supplied-installed-runtime-profile-root-read-only',
    live_probing: false,
    read_only: true,
    safe_claim_ceiling: INSTALLED_RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING,
    requested_selection: {
      install_root_required: true,
      expected_profile_required: true,
      current_machine_default_used: false,
      profile_id: profileId,
      profile_sha256: profileSha256,
      profile_sha_source: 'explicit-cli-argument-and-expected-profile-file',
      selects_latest_profile: false,
    },
    expected_profile: {
      expected_profile_path_in_report: '<operator-supplied-expected-profile>',
      profile_id: expectedProfile.profile_id,
      runtime_profile_id: expectedProfile.runtime_profile_id,
      profile_sha256: expectedProfileSha256,
      profile_sha_matches_cli_argument: true,
      profile_sha_matches_installed_profile: true,
      profile_content_matches_installed_profile: true,
      contract_valid: true,
    },
    active_index: {
      index_type: activeIndex.index_type,
      active_index_path_in_report: '<install-root>/active-runtime-profile.json',
      installed_profile_path_in_report: '<install-root>/profiles/protected-records-disposable-runtime-profile.json',
      selected_profile_id: activeIndex.selected_profile_id,
      selected_runtime_profile_id: activeIndex.selected_runtime_profile_id,
      selected_profile_sha256: activeIndex.selected_profile_sha256,
      selected_by_explicit_id_and_sha: activeIndex.selected_by_explicit_id_and_sha,
      selects_latest_profile: activeIndex.selects_latest_profile,
      installed_profile_path_metadata: activeIndex.installed_profile_path,
    },
    installed_profile: {
      profile_type: installedProfile.profile_type,
      profile_id: installedProfile.profile_id,
      profile_status: installedProfile.profile_status,
      runtime_profile_id: installedProfile.runtime_profile_id,
      action_class: installedProfile.action_class,
      deployment_posture: installedProfile.deployment_posture,
      runtime_environment: installedProfile.runtime_environment,
      service_command: installedProfile.service_command,
      proof_command: installedProfile.proof_command,
      profile_sha256: installedProfileSha256,
      profile_sha_matches_expected: true,
      profile_sha_matches_active_index: true,
      contract_valid: true,
    },
    recognition_contract: recognitionContract,
    target_contract: targetContract,
    authority_grant_requirement: authorityGrantRequirement,
    inspection_boundary: {
      install_root_read: true,
      install_root_symlink_refused: true,
      active_index_read: true,
      active_index_symlink_refused: true,
      installed_profile_read: true,
      installed_profile_symlink_refused: true,
      installed_profile_contract_validated: true,
      explicit_install_root_required: true,
      explicit_expected_profile_required: true,
      explicit_profile_id_required: true,
      explicit_profile_sha256_required: true,
      read_only: true,
      current_machine_default_used: false,
      selects_latest_profile: false,
      profile_selected_from_install_root: true,
      selected_by_explicit_id_and_sha: true,
      runtime_profile_installation_performed: false,
      runtime_profile_activation_performed: false,
      runtime_config_written: false,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      runtime_service_started: false,
      live_runtime_profile_checked: false,
      live_records_system_checked: false,
      production_records_service_checked: false,
      downstream_refusal_proven: false,
      current_machine_governance_proven: false,
    },
    side_door_report: {
      explicit_install_root_read: true,
      install_root_symlink_refused: true,
      active_profile_index_read: true,
      active_profile_index_symlink_refused: true,
      installed_profile_file_read: true,
      installed_profile_file_symlink_refused: true,
      expected_profile_file_read: true,
      profile_selected_from_install_root: true,
      selected_by_explicit_id_and_sha: true,
      latest_profile_selected: false,
      read_only: true,
      runtime_profile_installation_performed: false,
      runtime_profile_activation_performed: false,
      runtime_config_written: false,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      runtime_service_started: false,
      live_runtime_profile_checked: false,
      live_records_system_checked: false,
      production_records_service_checked: false,
      downstream_refusal_proven: false,
      current_machine_governance_proven: false,
      live_mcp_coverage_checked: false,
      live_approval_channel_health_checked: false,
      exactly_once_effect_semantics: false,
      atomic_store_anchor_witness_commit: false,
      partial_grant_commit_burn_window_proven: false,
      store_anchor_and_witness_joint_rollback_detection: false,
      host_filesystem_path_toctou_closed: false,
      host_process_or_memory_introspection_closed: false,
      external_attestation: false,
      sovereign_recognition: false,
      unrouted_records_paths_checked: false,
    },
    known_open_boundaries: [...REQUIRED_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_OPEN_BOUNDARIES],
    non_claims: [...INSTALLED_RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS],
  };
  assertProtectedRecordsInstalledRuntimeProfilePreflight(report);
  return report;
}

export function assertProtectedRecordsInstalledRuntimeProfilePreflight(report) {
  assertExactKeys('Protected records installed runtime profile preflight', report, [
    'active_index',
    'authority_grant_requirement',
    'evidence_model',
    'expected_profile',
    'inspection_boundary',
    'installed_profile',
    'known_open_boundaries',
    'live_probing',
    'non_claims',
    'preflight_type',
    'read_only',
    'recognition_contract',
    'requested_selection',
    'safe_claim_ceiling',
    'side_door_report',
    'target_contract',
  ]);
  if (
    report.preflight_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_TYPE ||
    report.evidence_model !== 'supplied-installed-runtime-profile-root-read-only' ||
    report.live_probing !== false ||
    report.read_only !== true ||
    report.safe_claim_ceiling !== INSTALLED_RUNTIME_PROFILE_PREFLIGHT_SAFE_CLAIM_CEILING
  ) {
    throw new Error('Protected records installed runtime profile preflight top-level contract drifted');
  }

  assertExactKeys('Protected records installed runtime profile requested selection', report.requested_selection, [
    'current_machine_default_used',
    'expected_profile_required',
    'install_root_required',
    'profile_id',
    'profile_sha256',
    'profile_sha_source',
    'selects_latest_profile',
  ]);
  assertProfileId(report.requested_selection.profile_id);
  assertProfileSha256(report.requested_selection.profile_sha256);
  if (
    report.requested_selection.install_root_required !== true ||
    report.requested_selection.expected_profile_required !== true ||
    report.requested_selection.current_machine_default_used !== false ||
    report.requested_selection.profile_sha_source !== 'explicit-cli-argument-and-expected-profile-file' ||
    report.requested_selection.selects_latest_profile !== false
  ) {
    throw new Error('Protected records installed runtime profile requested selection drifted');
  }

  assertExactKeys('Protected records installed runtime profile expected profile summary', report.expected_profile, [
    'contract_valid',
    'expected_profile_path_in_report',
    'profile_content_matches_installed_profile',
    'profile_id',
    'profile_sha256',
    'profile_sha_matches_cli_argument',
    'profile_sha_matches_installed_profile',
    'runtime_profile_id',
  ]);
  if (
    report.expected_profile.expected_profile_path_in_report !== '<operator-supplied-expected-profile>' ||
    report.expected_profile.profile_id !== report.requested_selection.profile_id ||
    report.expected_profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.expected_profile.profile_sha256 !== report.requested_selection.profile_sha256 ||
    report.expected_profile.profile_sha_matches_cli_argument !== true ||
    report.expected_profile.profile_sha_matches_installed_profile !== true ||
    report.expected_profile.profile_content_matches_installed_profile !== true ||
    report.expected_profile.contract_valid !== true
  ) {
    throw new Error('Protected records installed runtime profile expected profile summary drifted');
  }

  assertExactKeys('Protected records installed runtime profile active index summary', report.active_index, [
    'active_index_path_in_report',
    'index_type',
    'installed_profile_path_in_report',
    'installed_profile_path_metadata',
    'selected_by_explicit_id_and_sha',
    'selected_profile_id',
    'selected_profile_sha256',
    'selected_runtime_profile_id',
    'selects_latest_profile',
  ]);
  if (
    report.active_index.index_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_ACTIVE_INDEX_TYPE ||
    report.active_index.active_index_path_in_report !== '<install-root>/active-runtime-profile.json' ||
    report.active_index.installed_profile_path_in_report !==
      '<install-root>/profiles/protected-records-disposable-runtime-profile.json' ||
    report.active_index.installed_profile_path_metadata !==
      '<launcher-owned-disposable-install-root>/profiles/protected-records-disposable-runtime-profile.json' ||
    report.active_index.selected_profile_id !== report.requested_selection.profile_id ||
    report.active_index.selected_runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.active_index.selected_profile_sha256 !== report.requested_selection.profile_sha256 ||
    report.active_index.selected_by_explicit_id_and_sha !== true ||
    report.active_index.selects_latest_profile !== false
  ) {
    throw new Error('Protected records installed runtime profile active index summary drifted');
  }

  assertExactKeys('Protected records installed runtime profile summary', report.installed_profile, [
    'action_class',
    'contract_valid',
    'deployment_posture',
    'profile_id',
    'profile_sha256',
    'profile_sha_matches_active_index',
    'profile_sha_matches_expected',
    'profile_status',
    'profile_type',
    'proof_command',
    'runtime_environment',
    'runtime_profile_id',
    'service_command',
  ]);
  if (
    report.installed_profile.profile_id !== report.requested_selection.profile_id ||
    report.installed_profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID ||
    report.installed_profile.profile_sha256 !== report.requested_selection.profile_sha256 ||
    report.installed_profile.profile_sha256 !== report.active_index.selected_profile_sha256 ||
    report.installed_profile.profile_sha_matches_expected !== true ||
    report.installed_profile.profile_sha_matches_active_index !== true ||
    report.installed_profile.contract_valid !== true ||
    report.installed_profile.action_class !== 'records.write' ||
    report.installed_profile.deployment_posture !== 'runtime_profile_preflight_only' ||
    report.installed_profile.runtime_environment !== 'local-disposable-jsonl-child-process' ||
    report.installed_profile.service_command !== 'zlar protected-records-runtime-service --config <file>' ||
    report.installed_profile.proof_command !== 'zlar protected-records-runtime-profile-proof'
  ) {
    throw new Error('Protected records installed runtime profile summary drifted');
  }

  assertExactKeys('Protected records installed runtime profile recognition contract', report.recognition_contract, [
    'action_class',
    'contract_type',
    'current_machine_governance_proven',
    'downstream_recognition_required',
    'downstream_refusal_proven',
    'launcher_authority',
    'mutation_authoritative_route',
    'recognition_boundary',
    'request_contract',
    'required_refusal_case_count',
    'required_refusal_cases',
    'source',
  ]);
  assertExactKeys('Protected records installed runtime profile launcher authority', report.recognition_contract.launcher_authority, [
    'config_supplied_by_launcher',
    'fixture_mode_supplied_by_agent',
    'recognition_rule_supplied_by_agent',
    'request_stream_authority_material_accepted',
    'unsupported_request_fields_accepted',
  ]);
  assertExactArray(
    'Protected records installed runtime profile recognition refusal cases',
    report.recognition_contract.required_refusal_cases,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES
  );
  if (
    report.recognition_contract.contract_type !==
      INSTALLED_RUNTIME_PROFILE_RECOGNITION_CONTRACT_TYPE ||
    report.recognition_contract.source !== 'selected-installed-runtime-profile' ||
    report.recognition_contract.action_class !== 'records.write' ||
    report.recognition_contract.recognition_boundary !== 'service-configured-recognition-rule' ||
    report.recognition_contract.mutation_authoritative_route !==
      'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation' ||
    report.recognition_contract.request_contract !==
      'receipt-record-update-and-routing-metadata-only' ||
    report.recognition_contract.downstream_recognition_required !== true ||
    report.recognition_contract.launcher_authority.config_supplied_by_launcher !== true ||
    report.recognition_contract.launcher_authority.request_stream_authority_material_accepted !== false ||
    report.recognition_contract.launcher_authority.recognition_rule_supplied_by_agent !== false ||
    report.recognition_contract.launcher_authority.fixture_mode_supplied_by_agent !== false ||
    report.recognition_contract.launcher_authority.unsupported_request_fields_accepted !== false ||
    report.recognition_contract.required_refusal_case_count !==
      REQUIRED_INSTALLED_RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASES.length ||
    report.recognition_contract.downstream_refusal_proven !== false ||
    report.recognition_contract.current_machine_governance_proven !== false
  ) {
    throw new Error('Protected records installed runtime profile recognition contract drifted');
  }
  assertProtectedRecordsInstalledRuntimeProfileTargetContract(report.target_contract);
  assertProtectedRecordsInstalledRuntimeProfileAuthorityGrantRequirement(
    report.authority_grant_requirement
  );
  if (
    report.authority_grant_requirement.profile_id !==
      report.installed_profile.profile_id ||
    report.authority_grant_requirement.profile_sha256 !==
      report.installed_profile.profile_sha256 ||
    report.authority_grant_requirement.recognition_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileRecognitionContractSha256(
        report.recognition_contract
      ) ||
    report.authority_grant_requirement.target_contract_sha256 !==
      protectedRecordsInstalledRuntimeProfileTargetContractSha256(
        report.target_contract
      )
  ) {
    throw new Error(
      'Protected records installed runtime profile authority grant requirement source binding drifted'
    );
  }

  assertExactKeys('Protected records installed runtime profile inspection boundary', report.inspection_boundary, [
    'active_index_read',
    'active_index_symlink_refused',
    'current_machine_default_used',
    'current_machine_governance_proven',
    'downstream_refusal_proven',
    'explicit_expected_profile_required',
    'explicit_install_root_required',
    'explicit_profile_id_required',
    'explicit_profile_sha256_required',
    'hook_configuration_written',
    'install_root_read',
    'install_root_symlink_refused',
    'installed_profile_contract_validated',
    'installed_profile_read',
    'installed_profile_symlink_refused',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'machine_config_written',
    'production_records_service_checked',
    'profile_selected_from_install_root',
    'read_only',
    'runtime_config_written',
    'runtime_profile_activation_performed',
    'runtime_profile_installation_performed',
    'runtime_service_started',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
    'user_config_written',
  ]);
  const boundary = report.inspection_boundary;
  if (
    boundary.install_root_read !== true ||
    boundary.install_root_symlink_refused !== true ||
    boundary.active_index_read !== true ||
    boundary.active_index_symlink_refused !== true ||
    boundary.installed_profile_read !== true ||
    boundary.installed_profile_symlink_refused !== true ||
    boundary.installed_profile_contract_validated !== true ||
    boundary.explicit_install_root_required !== true ||
    boundary.explicit_expected_profile_required !== true ||
    boundary.explicit_profile_id_required !== true ||
    boundary.explicit_profile_sha256_required !== true ||
    boundary.read_only !== true ||
    boundary.current_machine_default_used !== false ||
    boundary.selects_latest_profile !== false ||
    boundary.profile_selected_from_install_root !== true ||
    boundary.selected_by_explicit_id_and_sha !== true ||
    boundary.runtime_profile_installation_performed !== false ||
    boundary.runtime_profile_activation_performed !== false ||
    boundary.runtime_config_written !== false ||
    boundary.hook_configuration_written !== false ||
    boundary.user_config_written !== false ||
    boundary.machine_config_written !== false ||
    boundary.runtime_service_started !== false ||
    boundary.live_runtime_profile_checked !== false ||
    boundary.live_records_system_checked !== false ||
    boundary.production_records_service_checked !== false ||
    boundary.downstream_refusal_proven !== false ||
    boundary.current_machine_governance_proven !== false
  ) {
    throw new Error('Protected records installed runtime profile inspection boundary drifted');
  }

  assertExactKeys('Protected records installed runtime profile side-door report', report.side_door_report, [
    'active_profile_index_symlink_refused',
    'active_profile_index_read',
    'atomic_store_anchor_witness_commit',
    'current_machine_governance_proven',
    'downstream_refusal_proven',
    'exactly_once_effect_semantics',
    'explicit_install_root_read',
    'expected_profile_file_read',
    'external_attestation',
    'hook_configuration_written',
    'host_process_or_memory_introspection_closed',
    'host_filesystem_path_toctou_closed',
    'installed_profile_file_read',
    'installed_profile_file_symlink_refused',
    'install_root_symlink_refused',
    'latest_profile_selected',
    'live_approval_channel_health_checked',
    'live_mcp_coverage_checked',
    'live_records_system_checked',
    'live_runtime_profile_checked',
    'machine_config_written',
    'production_records_service_checked',
    'partial_grant_commit_burn_window_proven',
    'profile_selected_from_install_root',
    'read_only',
    'runtime_config_written',
    'runtime_profile_activation_performed',
    'runtime_profile_installation_performed',
    'runtime_service_started',
    'selected_by_explicit_id_and_sha',
    'sovereign_recognition',
    'store_anchor_and_witness_joint_rollback_detection',
    'unrouted_records_paths_checked',
    'user_config_written',
  ]);
  const sideDoor = report.side_door_report;
  if (
    sideDoor.explicit_install_root_read !== true ||
    sideDoor.install_root_symlink_refused !== true ||
    sideDoor.active_profile_index_read !== true ||
    sideDoor.active_profile_index_symlink_refused !== true ||
    sideDoor.installed_profile_file_read !== true ||
    sideDoor.installed_profile_file_symlink_refused !== true ||
    sideDoor.expected_profile_file_read !== true ||
    sideDoor.profile_selected_from_install_root !== true ||
    sideDoor.selected_by_explicit_id_and_sha !== true ||
    sideDoor.latest_profile_selected !== false ||
    sideDoor.read_only !== true ||
    sideDoor.runtime_profile_installation_performed !== false ||
    sideDoor.runtime_profile_activation_performed !== false ||
    sideDoor.runtime_config_written !== false ||
    sideDoor.hook_configuration_written !== false ||
    sideDoor.user_config_written !== false ||
    sideDoor.machine_config_written !== false ||
    sideDoor.runtime_service_started !== false ||
    sideDoor.live_runtime_profile_checked !== false ||
    sideDoor.live_records_system_checked !== false ||
    sideDoor.production_records_service_checked !== false ||
    sideDoor.downstream_refusal_proven !== false ||
    sideDoor.current_machine_governance_proven !== false ||
    sideDoor.live_mcp_coverage_checked !== false ||
    sideDoor.live_approval_channel_health_checked !== false ||
    sideDoor.exactly_once_effect_semantics !== false ||
    sideDoor.atomic_store_anchor_witness_commit !== false ||
    sideDoor.partial_grant_commit_burn_window_proven !== false ||
    sideDoor.store_anchor_and_witness_joint_rollback_detection !== false ||
    sideDoor.host_filesystem_path_toctou_closed !== false ||
    sideDoor.host_process_or_memory_introspection_closed !== false ||
    sideDoor.external_attestation !== false ||
    sideDoor.sovereign_recognition !== false ||
    sideDoor.unrouted_records_paths_checked !== false
  ) {
    throw new Error('Protected records installed runtime profile side-door report drifted');
  }

  assertExactArray(
    'Protected records installed runtime profile open boundaries',
    report.known_open_boundaries,
    REQUIRED_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_OPEN_BOUNDARIES
  );
  assertExactArray(
    'Protected records installed runtime profile non-claims',
    report.non_claims,
    INSTALLED_RUNTIME_PROFILE_PREFLIGHT_NON_CLAIMS
  );
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

function installedRuntimeProfilePreflightArtifactBody(payload) {
  return {
    artifact_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_TYPE,
    canonicalization: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_CANONICALIZATION,
    generator: 'zlar protected-records-installed-runtime-profile-preflight --artifact',
    hash_scope: 'canonical artifact body without integrity',
    payload,
  };
}

export function buildProtectedRecordsInstalledRuntimeProfilePreflightArtifact(report) {
  assertProtectedRecordsInstalledRuntimeProfilePreflight(report);
  const body = installedRuntimeProfilePreflightArtifactBody({ preflight: report });
  const artifact = {
    ...body,
    integrity: {
      algorithm: 'SHA-256',
      body_sha256: sha256hex(canonicalize(body)),
    },
  };
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
  return artifact;
}

export function assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact) {
  if (
    !artifact ||
    artifact.artifact_type !== PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_TYPE
  ) {
    throw new Error('Protected records installed runtime profile preflight artifact has the wrong artifact type');
  }
  assertExactKeys('Protected records installed runtime profile preflight artifact', artifact, [
    'artifact_type',
    'canonicalization',
    'generator',
    'hash_scope',
    'integrity',
    'payload',
  ]);
  if (
    artifact.canonicalization !==
    PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_CANONICALIZATION
  ) {
    throw new Error('Protected records installed runtime profile preflight artifact canonicalization drifted');
  }
  if (artifact.generator !== 'zlar protected-records-installed-runtime-profile-preflight --artifact') {
    throw new Error('Protected records installed runtime profile preflight artifact generator drifted');
  }
  if (artifact.hash_scope !== 'canonical artifact body without integrity') {
    throw new Error('Protected records installed runtime profile preflight artifact hash scope drifted');
  }
  assertExactKeys('Protected records installed runtime profile preflight artifact payload', artifact.payload, [
    'preflight',
  ]);
  assertProtectedRecordsInstalledRuntimeProfilePreflight(artifact.payload.preflight);
  assertExactKeys('Protected records installed runtime profile preflight artifact integrity', artifact.integrity, [
    'algorithm',
    'body_sha256',
  ]);
  if (artifact.integrity.algorithm !== 'SHA-256') {
    throw new Error('Protected records installed runtime profile preflight artifact integrity algorithm drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(artifact.integrity.body_sha256 || '')) {
    throw new Error('Protected records installed runtime profile preflight artifact SHA-256 is malformed');
  }
  const { integrity, ...body } = artifact;
  const expectedHash = sha256hex(canonicalize(body));
  if (integrity.body_sha256 !== expectedHash) {
    throw new Error('Protected records installed runtime profile preflight artifact SHA-256 mismatch');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(artifact));
  return true;
}

export function writeProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact, outputPath) {
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
  if (!outputPath || outputPath === '-') {
    throw new Error('Protected records installed runtime profile preflight artifact output path is required');
  }
  mkdirSync(dirname(outputPath), { recursive: true });
  const output = `${JSON.stringify(artifact, null, 2)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  writeFileSync(outputPath, output, { mode: 0o600 });
  return artifact.integrity.body_sha256;
}

export function parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText(text) {
  assertNoUnsafeProtectedRecordsRuntimeProfileText(text);
  let artifact;
  try {
    artifact = JSON.parse(text);
  } catch {
    throw new Error('Protected records installed runtime profile preflight artifact input is not valid JSON');
  }
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
  return artifact;
}

export function verifyProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact) {
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
  const preflight = artifact.payload.preflight;
  const verification = {
    verification_type: PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE,
    verified: true,
    artifact_type: artifact.artifact_type,
    canonicalization: artifact.canonicalization,
    hash_scope: artifact.hash_scope,
    body_sha256: artifact.integrity.body_sha256,
    payload_type: preflight.preflight_type,
    evidence_model: preflight.evidence_model,
    live_probing: preflight.live_probing,
    read_only: preflight.read_only,
    requested_profile_id: preflight.requested_selection.profile_id,
    requested_profile_sha256: preflight.requested_selection.profile_sha256,
    active_index_read: preflight.inspection_boundary.active_index_read,
    installed_profile_read: preflight.inspection_boundary.installed_profile_read,
    installed_profile_contract_validated:
      preflight.inspection_boundary.installed_profile_contract_validated,
    profile_selected_from_install_root:
      preflight.inspection_boundary.profile_selected_from_install_root,
    selected_by_explicit_id_and_sha:
      preflight.inspection_boundary.selected_by_explicit_id_and_sha,
    selects_latest_profile: preflight.inspection_boundary.selects_latest_profile,
    profile_sha_matches_expected: preflight.installed_profile.profile_sha_matches_expected,
    profile_sha_matches_active_index: preflight.installed_profile.profile_sha_matches_active_index,
    recognition_contract_preserved: true,
    recognition_contract_sha256:
      protectedRecordsInstalledRuntimeProfileRecognitionContractSha256(
        preflight.recognition_contract
      ),
    recognition_boundary: preflight.recognition_contract.recognition_boundary,
    mutation_authoritative_route: preflight.recognition_contract.mutation_authoritative_route,
    request_stream_authority_material_accepted:
      preflight.recognition_contract.launcher_authority.request_stream_authority_material_accepted,
    recognition_rule_supplied_by_agent:
      preflight.recognition_contract.launcher_authority.recognition_rule_supplied_by_agent,
    required_refusal_case_count: preflight.recognition_contract.required_refusal_case_count,
    target_contract_preserved: true,
    target_contract_sha256:
      protectedRecordsInstalledRuntimeProfileTargetContractSha256(preflight.target_contract),
    authority_grant_requirement_preserved: true,
    authority_grant_requirement_type:
      preflight.authority_grant_requirement.requirement_type,
    authority_grant_requirement_sha256:
      protectedRecordsInstalledRuntimeProfileAuthorityGrantRequirementSha256(
        preflight.authority_grant_requirement
      ),
    expected_runtime_authority_grant_contract_type:
      preflight.authority_grant_requirement.expected_runtime_contract_type,
    launcher_owned_local_fixture_authority_grant_overlay:
      preflight.authority_grant_requirement.launcher_owned_local_fixture_overlay,
    source_profile_authority_grant_present:
      preflight.authority_grant_requirement.source_profile_authority_grant_present,
    exact_runtime_authority_grant_contract_instantiated:
      preflight.authority_grant_requirement.exact_runtime_contract_instantiated,
    exact_runtime_authority_grant_contract_deferred:
      preflight.authority_grant_requirement
        .exact_runtime_contract_deferred_until_preflight_body_sha_available,
    authority_grant_hash_cycle_avoided:
      preflight.authority_grant_requirement.hash_cycle_avoided,
    actual_issuer_appointment_present:
      preflight.authority_grant_requirement.actual_issuer_appointment_present,
    actual_issuer_kid_present:
      preflight.authority_grant_requirement.actual_issuer_kid_present,
    actual_issuer_public_key_present:
      preflight.authority_grant_requirement.actual_issuer_public_key_present,
    concrete_grant_window_present:
      preflight.authority_grant_requirement.concrete_grant_window_present,
    authority_grant_runtime_enforcement_performed:
      preflight.authority_grant_requirement.runtime_enforcement_performed,
    consequence_path: preflight.target_contract.consequence_path,
    target_kind: preflight.target_contract.target_kind,
    target_scope: preflight.target_contract.target_scope,
    target_instance_scope: preflight.target_contract.target_instance_scope,
    target_descriptor_sha256: preflight.target_contract.target_descriptor_sha256,
    target_handle: preflight.target_contract.target_handle,
    source_profile_target_handle_present:
      preflight.target_contract.source_profile_target_handle_present,
    profile_wide_target_authority_proven:
      preflight.target_contract.profile_wide_target_authority_proven,
    rightful_issuance_proven: preflight.target_contract.rightful_issuance_proven,
    consequence_lifecycle_closed: preflight.target_contract.consequence_lifecycle_closed,
    runtime_profile_installation_performed:
      preflight.inspection_boundary.runtime_profile_installation_performed,
    runtime_profile_activation_performed:
      preflight.inspection_boundary.runtime_profile_activation_performed,
    runtime_config_written: preflight.inspection_boundary.runtime_config_written,
    hook_configuration_written: preflight.inspection_boundary.hook_configuration_written,
    user_config_written: preflight.inspection_boundary.user_config_written,
    machine_config_written: preflight.inspection_boundary.machine_config_written,
    runtime_service_started: preflight.inspection_boundary.runtime_service_started,
    live_runtime_profile_checked: preflight.inspection_boundary.live_runtime_profile_checked,
    live_records_system_checked: preflight.inspection_boundary.live_records_system_checked,
    production_records_service_checked: preflight.inspection_boundary.production_records_service_checked,
    downstream_refusal_proven: preflight.inspection_boundary.downstream_refusal_proven,
    current_machine_governance_proven:
      preflight.inspection_boundary.current_machine_governance_proven,
    claim_boundary:
      'artifact integrity and embedded read-only installed runtime profile preflight boundaries only',
    non_claims: [...preflight.non_claims],
  };
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(verification));
  return verification;
}

export function formatProtectedRecordsInstalledRuntimeProfilePreflightSummary(report) {
  assertProtectedRecordsInstalledRuntimeProfilePreflight(report);
  const lines = [
    'ZLAR Protected Records Installed Runtime Profile Preflight v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}; read_only=${report.read_only}`,
    `Requested selection: install_root_required=${report.requested_selection.install_root_required}; profile_id=${report.requested_selection.profile_id}; profile_sha256=${report.requested_selection.profile_sha256}; selects_latest=${report.requested_selection.selects_latest_profile}; current_machine_default_used=${report.requested_selection.current_machine_default_used}`,
    `Active index: type=${report.active_index.index_type}; selected_profile_id=${report.active_index.selected_profile_id}; selected_runtime_profile_id=${report.active_index.selected_runtime_profile_id}; selected_by_id_and_sha=${report.active_index.selected_by_explicit_id_and_sha}; selects_latest=${report.active_index.selects_latest_profile}`,
    `Installed profile: id=${report.installed_profile.profile_id}; runtime_profile=${report.installed_profile.runtime_profile_id}; status=${report.installed_profile.profile_status}; action_class=${report.installed_profile.action_class}; contract_valid=${report.installed_profile.contract_valid}; sha_matches_expected=${report.installed_profile.profile_sha_matches_expected}; sha_matches_index=${report.installed_profile.profile_sha_matches_active_index}`,
    `Recognition contract: boundary=${report.recognition_contract.recognition_boundary}; route=${report.recognition_contract.mutation_authoritative_route}; request_stream_authority_material_accepted=${report.recognition_contract.launcher_authority.request_stream_authority_material_accepted}; recognition_rule_supplied_by_agent=${report.recognition_contract.launcher_authority.recognition_rule_supplied_by_agent}; required_refusal_cases=${report.recognition_contract.required_refusal_case_count}; downstream_refusal_proven=${report.recognition_contract.downstream_refusal_proven}`,
    `Target contract: consequence_path=${report.target_contract.consequence_path}; target_kind=${report.target_contract.target_kind}; target_scope=${report.target_contract.target_scope}; target_instance_scope=${report.target_contract.target_instance_scope}; target_handle=${report.target_contract.target_handle}; request_target_semantics=${report.target_contract.request_target_semantics}; profile_wide_target_authority_proven=${report.target_contract.profile_wide_target_authority_proven}; rightful_issuance_proven=${report.target_contract.rightful_issuance_proven}; lifecycle_closed=${report.target_contract.consequence_lifecycle_closed}`,
    `Authority grant requirement: type=${report.authority_grant_requirement.requirement_type}; expected_runtime_contract_type=${report.authority_grant_requirement.expected_runtime_contract_type}; authority_domain=${report.authority_grant_requirement.authority_domain_id}; grantor_role=${report.authority_grant_requirement.grantor_role_id}; issuer_slot=${report.authority_grant_requirement.issuer_slot}; launcher_owned_local_fixture_overlay=${report.authority_grant_requirement.launcher_owned_local_fixture_overlay}; source_profile_authority_grant_present=${report.authority_grant_requirement.source_profile_authority_grant_present}; exact_runtime_contract_instantiated=${report.authority_grant_requirement.exact_runtime_contract_instantiated}; exact_runtime_contract_deferred=${report.authority_grant_requirement.exact_runtime_contract_deferred_until_preflight_body_sha_available}; hash_cycle_avoided=${report.authority_grant_requirement.hash_cycle_avoided}; issuer_appointment_present=${report.authority_grant_requirement.actual_issuer_appointment_present}; concrete_grant_window_present=${report.authority_grant_requirement.concrete_grant_window_present}; runtime_enforcement_performed=${report.authority_grant_requirement.runtime_enforcement_performed}; rightful_issuance_proven=${report.authority_grant_requirement.rightful_issuance_proven}`,
    `Inspection boundary: install_root_read=${report.inspection_boundary.install_root_read}; active_index_read=${report.inspection_boundary.active_index_read}; installed_profile_read=${report.inspection_boundary.installed_profile_read}; profile_selected_from_install_root=${report.inspection_boundary.profile_selected_from_install_root}; selected_by_id_and_sha=${report.inspection_boundary.selected_by_explicit_id_and_sha}; read_only=${report.inspection_boundary.read_only}`,
    `No-effect boundary: installation_performed=${report.inspection_boundary.runtime_profile_installation_performed}; activation_performed=${report.inspection_boundary.runtime_profile_activation_performed}; runtime_config_written=${report.inspection_boundary.runtime_config_written}; hook_configuration_written=${report.inspection_boundary.hook_configuration_written}; user_config_written=${report.inspection_boundary.user_config_written}; machine_config_written=${report.inspection_boundary.machine_config_written}; runtime_service_started=${report.inspection_boundary.runtime_service_started}`,
    `Claim boundary: live_runtime_profile_checked=${report.inspection_boundary.live_runtime_profile_checked}; live_records_system_checked=${report.inspection_boundary.live_records_system_checked}; downstream_refusal_proven=${report.inspection_boundary.downstream_refusal_proven}; current_machine_governance_proven=${report.inspection_boundary.current_machine_governance_proven}`,
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

export function formatProtectedRecordsInstalledRuntimeProfilePreflightArtifactVerification(verification) {
  if (
    !verification ||
    verification.verification_type !==
      PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_PREFLIGHT_ARTIFACT_VERIFICATION_TYPE
  ) {
    throw new Error('Protected records installed runtime profile preflight artifact verification has the wrong type');
  }
  if (verification.verified !== true) {
    throw new Error('Protected records installed runtime profile preflight artifact verification is not verified');
  }
  const lines = [
    'ZLAR Protected Records Installed Runtime Profile Preflight Artifact Verification v1',
    `verified=${verification.verified}`,
    `artifact_type=${verification.artifact_type}`,
    `sha256=${verification.body_sha256}`,
    `payload_type=${verification.payload_type}`,
    `evidence_model=${verification.evidence_model}; live_probing=${verification.live_probing}; read_only=${verification.read_only}`,
    `requested_profile_id=${verification.requested_profile_id}; requested_profile_sha256=${verification.requested_profile_sha256}`,
    `installed_profile_read=${verification.installed_profile_read}; contract_validated=${verification.installed_profile_contract_validated}; selected_from_install_root=${verification.profile_selected_from_install_root}; selected_by_id_and_sha=${verification.selected_by_explicit_id_and_sha}; selects_latest=${verification.selects_latest_profile}`,
    `recognition_contract_preserved=${verification.recognition_contract_preserved}; recognition_contract_sha256=${verification.recognition_contract_sha256}; recognition_boundary=${verification.recognition_boundary}; mutation_authoritative_route=${verification.mutation_authoritative_route}; request_stream_authority_material_accepted=${verification.request_stream_authority_material_accepted}; recognition_rule_supplied_by_agent=${verification.recognition_rule_supplied_by_agent}; required_refusal_cases=${verification.required_refusal_case_count}; downstream_refusal_proven=${verification.downstream_refusal_proven}`,
    `target_contract_preserved=${verification.target_contract_preserved}; target_contract_sha256=${verification.target_contract_sha256}; consequence_path=${verification.consequence_path}; target_kind=${verification.target_kind}; target_scope=${verification.target_scope}; target_instance_scope=${verification.target_instance_scope}; target_handle=${verification.target_handle}; profile_wide_target_authority_proven=${verification.profile_wide_target_authority_proven}; rightful_issuance_proven=${verification.rightful_issuance_proven}; lifecycle_closed=${verification.consequence_lifecycle_closed}`,
    `authority_grant_requirement_preserved=${verification.authority_grant_requirement_preserved}; authority_grant_requirement_sha256=${verification.authority_grant_requirement_sha256}; launcher_owned_local_fixture_overlay=${verification.launcher_owned_local_fixture_authority_grant_overlay}; source_profile_authority_grant_present=${verification.source_profile_authority_grant_present}; exact_runtime_contract_instantiated=${verification.exact_runtime_authority_grant_contract_instantiated}; exact_runtime_contract_deferred=${verification.exact_runtime_authority_grant_contract_deferred}; hash_cycle_avoided=${verification.authority_grant_hash_cycle_avoided}; issuer_appointment_present=${verification.actual_issuer_appointment_present}; issuer_kid_present=${verification.actual_issuer_kid_present}; issuer_public_key_present=${verification.actual_issuer_public_key_present}; concrete_grant_window_present=${verification.concrete_grant_window_present}; runtime_enforcement_performed=${verification.authority_grant_runtime_enforcement_performed}`,
    `no_effects: installation_performed=${verification.runtime_profile_installation_performed}; activation_performed=${verification.runtime_profile_activation_performed}; runtime_config_written=${verification.runtime_config_written}; hook_configuration_written=${verification.hook_configuration_written}; user_config_written=${verification.user_config_written}; machine_config_written=${verification.machine_config_written}; runtime_service_started=${verification.runtime_service_started}`,
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

export function formatProtectedRecordsInstalledRuntimeProfilePreflightArtifactSummary(artifact) {
  assertProtectedRecordsInstalledRuntimeProfilePreflightArtifact(artifact);
  const lines = [
    'Portable installed runtime profile preflight artifact:',
    `- type=${artifact.artifact_type}`,
    `- sha256=${artifact.integrity.body_sha256}`,
    `- hash_scope=${artifact.hash_scope}`,
  ];
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(summary);
  return summary;
}
