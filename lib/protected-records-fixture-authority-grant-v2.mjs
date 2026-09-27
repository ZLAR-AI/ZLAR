import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './receipt.mjs';

// Version 2 deliberately separates four identities:
//
//   source preflight P -> conditional grant contract G -> exact confirmation A
//                                                 \-> appointment I
//                                      A + I + source status -> evaluation
//
// G binds P but cannot bind A or I because both downstream artifacts name G.
// A conditional authorization body therefore cannot activate its own contract.

export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_SOURCE_PRECONDITION_TYPE_V2 =
  'zlar-protected-records-fixture-authority-source-precondition-v2';
// Compatibility alias for callers that use "source preflight" as the generic
// record category. Contract fields use "source_precondition" so this record
// cannot be confused with the installed-profile provenance preflight.
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_SOURCE_PREFLIGHT_TYPE_V2 =
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_SOURCE_PRECONDITION_TYPE_V2;
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE_V2 =
  'zlar-protected-records-fixture-authority-grant-contract-v2';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_AUTHORIZATION_BODY_TYPE_V2 =
  'zlar-protected-records-fixture-conditional-authorization-body-v2';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_APPOINTMENT_TYPE_V2 =
  'zlar-protected-records-fixture-authority-appointment-v2';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONFIRMATION_TYPE_V2 =
  'zlar-protected-records-fixture-authority-exact-confirmation-v2';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_STATUS_TYPE_V2 =
  'zlar-protected-records-fixture-authority-status-v2';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_SCOPE_EVIDENCE_TYPE_V2 =
  'zlar-protected-records-fixture-authority-scope-evidence-v2';
export const PROTECTED_RECORDS_AUTHORIZED_EFFECT_DETAIL_TYPE_V2 =
  'zlar-protected-records-authorized-effect-detail-v2';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2 =
  'zlar-protected-records-fixture-authority-receipt-evidence-v2';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_DECISION_TYPE_V2 =
  'zlar-protected-records-fixture-authority-decision-v2';

export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID_V2 =
  'protected-records.local-disposable-fixture';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID_V2 =
  'fixture-deployment-owner';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID_V2 =
  'fixture-consequence-authority';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_ISSUER_ACTOR_ID_V2 =
  'fixture-receipt-issuer';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_ISSUER_SLOT_V2 =
  'protected-records-fixture-receipt-issuer';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONSEQUENCE_PATH_V2 =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2 =
  'runtime-process-wall-clock-at-effect';

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const GIT_SHA1_OID_PATTERN = /^[a-f0-9]{40}$/;
const LOGICAL_FIXTURE_TARGET_HANDLE_PATTERN =
  /^zlar-target:v1:logical-fixture:[a-f0-9]{64}$/;

const SOURCE_PRECONDITION_KEYS = Object.freeze([
  'claim_boundary',
  'git_object_format',
  'no_reexecution_call_graph_sha256',
  'precondition_type',
  'precondition_version',
  'refusal_test_manifest',
  'repository_id',
  'service_artifact_schema_contract_sha256',
  'source_commit_oid',
  'source_completeness_manifest',
  'terminal_artifact_schema_contract_sha256',
]);

const IMPLEMENTATION_BINDING_KEYS = Object.freeze([
  'git_object_format',
  'no_reexecution_call_graph_sha256',
  'repository_id',
  'service_artifact_schema_contract_sha256',
  'source_commit_oid',
  'terminal_artifact_schema_contract_sha256',
]);

const CONTRACT_KEYS = Object.freeze([
  'authority_domain',
  'authorization_record',
  'claim_ceiling',
  'contract_type',
  'contract_version',
  'delegation_policy',
  'grantor',
  'grantee',
  'implementation_binding',
  'powers',
  'scope',
  'time_policy',
  'usage_policy',
]);

const SCOPE_KEYS = Object.freeze([
  'action_class',
  'consequence_path',
  'installed_profile_preflight_artifact_body_sha256',
  'launcher_target_binding_sha256',
  'policy_version',
  'profile_id',
  'profile_sha256',
  'recognition_contract_sha256',
  'receipt_audit_event_id',
  'receipt_authorizer',
  'receipt_domain',
  'receipt_outcome',
  'receipt_rule',
  'receipt_type',
  'receipt_version',
  'record_update_sha256',
  'runtime_profile_id',
  'source_precondition_artifact_body_sha256',
  'target_contract_sha256',
  'target_effect_sha256',
  'target_handle',
  'target_instance_scope',
  'target_kind',
  'target_scope',
]);

const CLAIM_CEILING = Object.freeze({
  all_surface_governance_proven: false,
  consequence_lifecycle_closed: false,
  current_machine_governance_proven: false,
  enterprise_readiness_proven: false,
  exactly_once_effect_proven: false,
  generic_rightful_issuance_proven: false,
  live_authority_proven: false,
  local_disposable_fixture_only: true,
  portable_rightful_issuance_proven: false,
  production_governance_proven: false,
  public_external_attestation_proven: false,
  side_door_closure_proven: false,
  sovereign_recognition_proven: false,
});

const SOURCE_PREFLIGHT_CLAIM_BOUNDARY = Object.freeze({
  active_authority_status_present: false,
  exact_human_confirmation_present: false,
  executable_authority_present: false,
  positive_crossing_executed: false,
  source_only_precondition: true,
});

const SOURCE_COMPLETENESS_PATHS_V2 = Object.freeze({
  authority_contract_and_evaluator_source_path:
    'lib/protected-records-fixture-authority-grant-v2.mjs',
  downstream_no_reexecution_source_path:
    'lib/protected-records-replacement-artifact-set-v2.mjs',
  no_reexecution_call_graph_spec_path:
    'spec/protected-records-no-reexecution-call-graph-v2.json',
  replacement_artifact_verifier_source_path:
    'bin/zlar-protected-records-replacement-artifact-set-v2',
  replacement_crossing_driver_cli_source_path:
    'bin/zlar-protected-records-replacement-crossing-v2',
  replacement_crossing_driver_cli_implementation_source_path:
    'lib/protected-records-replacement-crossing-cli-v2.mjs',
  replacement_crossing_driver_library_source_path:
    'lib/protected-records-replacement-crossing-driver-v2.mjs',
  replacement_hash_utility_source_path: 'lib/sha256.mjs',
  replacement_runtime_service_child_source_path:
    'lib/protected-records-replacement-runtime-child-v2.mjs',
  replacement_source_snapshot_boundary_source_path:
    'lib/protected-records-replacement-source-snapshot-v2.mjs',
  runtime_authority_adapter_source_path:
    'lib/protected-records-runtime-authority-v2.mjs',
  runtime_consequence_boundary_source_path:
    'lib/protected-records-runtime-profile.mjs',
  runtime_service_cli_source_path:
    'bin/zlar-protected-records-runtime-service',
  service_artifact_schema_source_path:
    'lib/protected-records-replacement-artifacts-v2.mjs',
  terminal_artifact_schema_source_path:
    'lib/protected-records-replacement-artifacts-v2.mjs',
});

const POWERS = Object.freeze([
  Object.freeze({
    delegable: false,
    holder: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID_V2,
    maximum_uses: 1,
    power_id: 'bind_one_runtime_private_fixture_issuer',
  }),
  Object.freeze({
    delegable: false,
    holder: PROTECTED_RECORDS_FIXTURE_AUTHORITY_ISSUER_SLOT_V2,
    maximum_uses: 1,
    power_id: 'issue_one_governed_action_receipt',
  }),
  Object.freeze({
    delegable: false,
    holder: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID_V2,
    maximum_uses: 1,
    power_id: 'revoke_before_effect',
  }),
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
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} contains unexpected or missing fields`);
  }
}

function assertString(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function assertBoolean(label, value) {
  if (typeof value !== 'boolean') throw new Error(`${label} must be boolean`);
}

function assertInteger(label, value) {
  if (!Number.isInteger(value)) throw new Error(`${label} must be an integer`);
}

function assertSha256(label, value) {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be SHA-256 hex`);
  }
}

function assertGitSha1Oid(label, value) {
  if (typeof value !== 'string' || !GIT_SHA1_OID_PATTERN.test(value)) {
    throw new Error(`${label} must be a 40-character Git sha1 object id`);
  }
}

function assertCanonicalEqual(label, actual, expected) {
  if (canonicalize(actual) !== canonicalize(expected)) {
    throw new Error(`${label} drifted`);
  }
}

function clone(value) {
  return JSON.parse(canonicalize(value));
}

function fixedPowers() {
  return POWERS.map((power) => ({ ...power }));
}

function fixedClaimCeiling() {
  return { ...CLAIM_CEILING };
}

function fixedSourcePreflightClaimBoundary() {
  return { ...SOURCE_PREFLIGHT_CLAIM_BOUNDARY };
}

export function createProtectedRecordsFixtureAuthoritySourcePreconditionV2({
  sourceCommitOid,
  serviceArtifactSchemaContractSha256,
  terminalArtifactSchemaContractSha256,
  noReexecutionCallGraphSha256,
  sourceCompletenessManifest,
  refusalTestManifest,
} = {}) {
  const precondition = {
    precondition_type:
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_SOURCE_PRECONDITION_TYPE_V2,
    precondition_version: 2,
    repository_id: 'ZLAR_Repo',
    git_object_format: 'sha1',
    source_commit_oid: sourceCommitOid,
    service_artifact_schema_contract_sha256:
      serviceArtifactSchemaContractSha256,
    terminal_artifact_schema_contract_sha256:
      terminalArtifactSchemaContractSha256,
    no_reexecution_call_graph_sha256: noReexecutionCallGraphSha256,
    source_completeness_manifest: clone(sourceCompletenessManifest),
    refusal_test_manifest: clone(refusalTestManifest),
    claim_boundary: fixedSourcePreflightClaimBoundary(),
  };
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(precondition);
  return precondition;
}

export const createProtectedRecordsFixtureAuthoritySourcePreflightV2 =
  createProtectedRecordsFixtureAuthoritySourcePreconditionV2;

export function assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(precondition) {
  assertExactKeys(
    'Protected records fixture authority v2 source preflight',
    precondition,
    SOURCE_PRECONDITION_KEYS,
  );
  assertExactKeys(
    'Protected records fixture authority v2 source completeness manifest',
    precondition.source_completeness_manifest,
    [
      'authority_contract_and_evaluator_source_path',
      'downstream_no_reexecution_source_path',
      'no_reexecution_call_graph_spec_path',
      'replacement_artifact_verifier_source_path',
      'replacement_crossing_driver_cli_source_path',
      'replacement_crossing_driver_cli_implementation_source_path',
      'replacement_crossing_driver_library_source_path',
      'replacement_hash_utility_source_path',
      'replacement_runtime_service_child_source_path',
      'replacement_source_snapshot_boundary_source_path',
      'runtime_authority_adapter_source_path',
      'runtime_consequence_boundary_source_path',
      'runtime_service_cli_source_path',
      'service_artifact_schema_source_path',
      'source_complete',
      'terminal_artifact_schema_source_path',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 no-consequence test manifest',
    precondition.refusal_test_manifest,
    [
      'key_generation_performed',
      'positive_consequence_executed',
      'receipt_signing_performed',
      'test_paths',
      'test_scope',
      'tests_passed',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 source preflight claim boundary',
    precondition.claim_boundary,
    Object.keys(SOURCE_PREFLIGHT_CLAIM_BOUNDARY),
  );
  if (
    precondition.precondition_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_SOURCE_PRECONDITION_TYPE_V2 ||
    precondition.precondition_version !== 2 ||
    precondition.repository_id !== 'ZLAR_Repo' ||
    precondition.git_object_format !== 'sha1'
  ) {
    throw new Error('Protected records fixture authority v2 source identity drifted');
  }
  assertGitSha1Oid(
    'Protected records fixture authority v2 source commit oid',
    precondition.source_commit_oid,
  );
  for (const field of [
    'service_artifact_schema_contract_sha256',
    'terminal_artifact_schema_contract_sha256',
    'no_reexecution_call_graph_sha256',
  ]) {
    assertSha256(`Protected records fixture authority v2 ${field}`, precondition[field]);
  }
  for (const field of [
    'authority_contract_and_evaluator_source_path',
    'downstream_no_reexecution_source_path',
    'no_reexecution_call_graph_spec_path',
    'replacement_artifact_verifier_source_path',
    'replacement_crossing_driver_cli_source_path',
    'replacement_crossing_driver_cli_implementation_source_path',
    'replacement_crossing_driver_library_source_path',
    'replacement_hash_utility_source_path',
    'replacement_runtime_service_child_source_path',
    'replacement_source_snapshot_boundary_source_path',
    'runtime_authority_adapter_source_path',
    'runtime_consequence_boundary_source_path',
    'runtime_service_cli_source_path',
    'service_artifact_schema_source_path',
    'terminal_artifact_schema_source_path',
  ]) {
    assertString(
      `Protected records fixture authority v2 source completeness ${field}`,
      precondition.source_completeness_manifest[field],
    );
    if (
      precondition.source_completeness_manifest[field] !==
      SOURCE_COMPLETENESS_PATHS_V2[field]
    ) {
      throw new Error(
        `Protected records fixture authority v2 source completeness ${field} drifted`,
      );
    }
  }
  if (precondition.source_completeness_manifest.source_complete !== true) {
    throw new Error('Protected records fixture authority v2 source is not complete');
  }
  if (
    precondition.refusal_test_manifest.test_scope !==
      'pure-schema-refusal-static-no-consequence' ||
    precondition.refusal_test_manifest.tests_passed !== true ||
    precondition.refusal_test_manifest.key_generation_performed !== false ||
    precondition.refusal_test_manifest.receipt_signing_performed !== false ||
    precondition.refusal_test_manifest.positive_consequence_executed !== false ||
    !Array.isArray(precondition.refusal_test_manifest.test_paths) ||
    precondition.refusal_test_manifest.test_paths.length < 1
  ) {
    throw new Error('Protected records fixture authority v2 no-consequence tests are not proven');
  }
  for (const path of precondition.refusal_test_manifest.test_paths) {
    assertString('Protected records fixture authority v2 refusal test path', path);
  }
  assertCanonicalEqual(
    'Protected records fixture authority v2 source preflight claim boundary',
    precondition.claim_boundary,
    SOURCE_PREFLIGHT_CLAIM_BOUNDARY,
  );
  return true;
}

export const assertProtectedRecordsFixtureAuthoritySourcePreflightV2 =
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2;

export function protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(
  precondition,
) {
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(precondition);
  return sha256hex(canonicalize(precondition));
}

export const protectedRecordsFixtureAuthoritySourcePreflightBodySha256V2 =
  protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2;

export function protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2(
  precondition,
) {
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(precondition);
  return {
    repository_id: precondition.repository_id,
    git_object_format: precondition.git_object_format,
    source_commit_oid: precondition.source_commit_oid,
    service_artifact_schema_contract_sha256:
      precondition.service_artifact_schema_contract_sha256,
    terminal_artifact_schema_contract_sha256:
      precondition.terminal_artifact_schema_contract_sha256,
    no_reexecution_call_graph_sha256:
      precondition.no_reexecution_call_graph_sha256,
  };
}

export const protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreflightV2 =
  protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2;

function conditionalAuthorizationBody(contract) {
  return {
    body_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_AUTHORIZATION_BODY_TYPE_V2,
    authorization_record: {
      authorization_mode: contract.authorization_record.authorization_mode,
      exact_post_presentation_confirmation_required:
        contract.authorization_record.exact_post_presentation_confirmation_required,
      portable_attestation: contract.authorization_record.portable_attestation,
      record_id: contract.authorization_record.record_id,
      source: contract.authorization_record.source,
    },
    authority_domain: clone(contract.authority_domain),
    claim_ceiling: clone(contract.claim_ceiling),
    contract_type: contract.contract_type,
    contract_version: contract.contract_version,
    delegation_policy: clone(contract.delegation_policy),
    grantor: clone(contract.grantor),
    grantee: clone(contract.grantee),
    implementation_binding: clone(contract.implementation_binding),
    powers: clone(contract.powers),
    scope: clone(contract.scope),
    time_policy: clone(contract.time_policy),
    usage_policy: clone(contract.usage_policy),
  };
}

export function protectedRecordsFixtureAuthorityConditionalAuthorizationBodyV2(
  contract,
) {
  requireObject('Protected records fixture authority v2 contract', contract);
  return conditionalAuthorizationBody(contract);
}

export function protectedRecordsFixtureAuthorityConditionalAuthorizationBodySha256V2(
  contract,
) {
  return sha256hex(canonicalize(
    protectedRecordsFixtureAuthorityConditionalAuthorizationBodyV2(contract),
  ));
}

export function createProtectedRecordsFixtureAuthorityGrantContractV2({
  authorizationRecordId,
  implementationBinding,
  scope,
  validFromEpoch,
  expiresAtEpoch,
} = {}) {
  const contract = {
    contract_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE_V2,
    contract_version: 2,
    authorization_record: {
      record_id: authorizationRecordId,
      source: 'explicit-in-thread-control-tower-conditional-human-authorization',
      authorization_mode: 'conditional-source-precondition-then-exact-confirmation',
      portable_attestation: false,
      exact_post_presentation_confirmation_required: true,
      authorization_body_type:
        PROTECTED_RECORDS_FIXTURE_AUTHORITY_AUTHORIZATION_BODY_TYPE_V2,
      authorization_body_sha256: '0'.repeat(64),
    },
    authority_domain: {
      domain_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID_V2,
      domain_kind: 'local-disposable-fixture',
      named_machine_scope: false,
      production_domain: false,
    },
    grantor: {
      actor_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID_V2,
      role_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID_V2,
    },
    grantee: {
      actor_id: PROTECTED_RECORDS_FIXTURE_AUTHORITY_ISSUER_ACTOR_ID_V2,
      binding_mode: 'runtime-private-exact-kid-and-public-key-sha256',
      issuer_slot: PROTECTED_RECORDS_FIXTURE_AUTHORITY_ISSUER_SLOT_V2,
    },
    implementation_binding: clone(implementationBinding),
    scope: clone(scope),
    time_policy: {
      clock_source: PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
      expires_at_epoch: expiresAtEpoch,
      interval: 'half-open-[valid_from,expires_at)',
      receipt_ts_must_be_within_grant: true,
      receipt_ts_must_not_exceed_effect_time: true,
      valid_from_epoch: validFromEpoch,
    },
    usage_policy: {
      consumption_identity: 'authority-grant-contract-sha256',
      further_replacement_requires_explicit_human_authority: true,
      max_uses: 1,
      mutable_extension_allowed: false,
    },
    powers: fixedPowers(),
    delegation_policy: {
      delegation_allowed: false,
      delegated_grant_acceptance_allowed: false,
    },
    claim_ceiling: fixedClaimCeiling(),
  };
  contract.authorization_record.authorization_body_sha256 =
    protectedRecordsFixtureAuthorityConditionalAuthorizationBodySha256V2(contract);
  assertProtectedRecordsFixtureAuthorityGrantContractShapeV2(contract);
  return contract;
}

export function isProtectedRecordsFixtureAuthorityGrantContractV2(value) {
  return Boolean(
    value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      value.contract_type ===
        PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_CONTRACT_TYPE_V2 &&
      value.contract_version === 2,
  );
}

export function assertProtectedRecordsFixtureAuthorityGrantContractShapeV2(
  contract,
) {
  assertExactKeys(
    'Protected records fixture authority v2 grant contract',
    contract,
    CONTRACT_KEYS,
  );
  assertExactKeys(
    'Protected records fixture authority v2 authorization record',
    contract.authorization_record,
    [
      'authorization_body_sha256',
      'authorization_body_type',
      'authorization_mode',
      'exact_post_presentation_confirmation_required',
      'portable_attestation',
      'record_id',
      'source',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 domain',
    contract.authority_domain,
    ['domain_id', 'domain_kind', 'named_machine_scope', 'production_domain'],
  );
  assertExactKeys(
    'Protected records fixture authority v2 grantor',
    contract.grantor,
    ['actor_id', 'role_id'],
  );
  assertExactKeys(
    'Protected records fixture authority v2 grantee',
    contract.grantee,
    ['actor_id', 'binding_mode', 'issuer_slot'],
  );
  assertExactKeys(
    'Protected records fixture authority v2 implementation binding',
    contract.implementation_binding,
    IMPLEMENTATION_BINDING_KEYS,
  );
  assertExactKeys(
    'Protected records fixture authority v2 scope',
    contract.scope,
    SCOPE_KEYS,
  );
  assertExactKeys(
    'Protected records fixture authority v2 time policy',
    contract.time_policy,
    [
      'clock_source',
      'expires_at_epoch',
      'interval',
      'receipt_ts_must_be_within_grant',
      'receipt_ts_must_not_exceed_effect_time',
      'valid_from_epoch',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 usage policy',
    contract.usage_policy,
    [
      'consumption_identity',
      'further_replacement_requires_explicit_human_authority',
      'max_uses',
      'mutable_extension_allowed',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 delegation policy',
    contract.delegation_policy,
    ['delegated_grant_acceptance_allowed', 'delegation_allowed'],
  );
  assertExactKeys(
    'Protected records fixture authority v2 claim ceiling',
    contract.claim_ceiling,
    Object.keys(CLAIM_CEILING),
  );
  if (!isProtectedRecordsFixtureAuthorityGrantContractV2(contract)) {
    throw new Error('Protected records fixture authority v2 contract type drifted');
  }
  assertString(
    'Protected records fixture authority v2 authorization record id',
    contract.authorization_record.record_id,
  );
  assertSha256(
    'Protected records fixture authority v2 conditional authorization body SHA-256',
    contract.authorization_record.authorization_body_sha256,
  );
  if (
    contract.authorization_record.source !==
      'explicit-in-thread-control-tower-conditional-human-authorization' ||
    contract.authorization_record.authorization_mode !==
      'conditional-source-precondition-then-exact-confirmation' ||
    contract.authorization_record.portable_attestation !== false ||
    contract.authorization_record.exact_post_presentation_confirmation_required !==
      true ||
    contract.authorization_record.authorization_body_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_AUTHORIZATION_BODY_TYPE_V2
  ) {
    throw new Error('Protected records fixture authority v2 conditional authorization boundary drifted');
  }
  if (
    contract.authorization_record.authorization_body_sha256 !==
    protectedRecordsFixtureAuthorityConditionalAuthorizationBodySha256V2(contract)
  ) {
    throw new Error('Protected records fixture authority v2 conditional authorization body hash drifted');
  }
  if (
    contract.authority_domain.domain_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_DOMAIN_ID_V2 ||
    contract.authority_domain.domain_kind !== 'local-disposable-fixture' ||
    contract.authority_domain.named_machine_scope !== false ||
    contract.authority_domain.production_domain !== false ||
    contract.grantor.actor_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID_V2 ||
    contract.grantor.role_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID_V2 ||
    contract.grantee.actor_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_ISSUER_ACTOR_ID_V2 ||
    contract.grantee.issuer_slot !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_ISSUER_SLOT_V2 ||
    contract.grantee.binding_mode !==
      'runtime-private-exact-kid-and-public-key-sha256'
  ) {
    throw new Error('Protected records fixture authority v2 authority domain or actor boundary drifted');
  }
  if (
    contract.implementation_binding.repository_id !== 'ZLAR_Repo' ||
    contract.implementation_binding.git_object_format !== 'sha1'
  ) {
    throw new Error('Protected records fixture authority v2 implementation identity drifted');
  }
  assertGitSha1Oid(
    'Protected records fixture authority v2 source commit oid',
    contract.implementation_binding.source_commit_oid,
  );
  for (const field of [
    'service_artifact_schema_contract_sha256',
    'terminal_artifact_schema_contract_sha256',
    'no_reexecution_call_graph_sha256',
  ]) {
    assertSha256(
      `Protected records fixture authority v2 implementation ${field}`,
      contract.implementation_binding[field],
    );
  }
  if (
    contract.scope.consequence_path !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONSEQUENCE_PATH_V2 ||
    contract.scope.action_class !== 'records.write' ||
    contract.scope.target_kind !==
      'process-private-recognized-effect-state' ||
    contract.scope.target_scope !== 'logical-fixture' ||
    contract.scope.target_instance_scope !== 'logical-fixture-not-per-run' ||
    contract.scope.profile_id !== 'protected-records-runtime-fixture-profile' ||
    contract.scope.runtime_profile_id !==
      'protected-records-disposable-runtime-profile' ||
    contract.scope.policy_version !== 'recognition-policy-v1' ||
    contract.scope.receipt_version !== 1 ||
    contract.scope.receipt_type !== 'governed-action' ||
    contract.scope.receipt_domain !== 'records' ||
    contract.scope.receipt_rule !== 'RRECORDS_ALLOW' ||
    contract.scope.receipt_authorizer !== 'policy' ||
    contract.scope.receipt_outcome !== 'allow'
  ) {
    throw new Error('Protected records fixture authority v2 consequence path drifted');
  }
  if (!LOGICAL_FIXTURE_TARGET_HANDLE_PATTERN.test(contract.scope.target_handle || '')) {
    throw new Error('Protected records fixture authority v2 target handle grammar drifted');
  }
  for (const field of [
    'profile_id',
    'runtime_profile_id',
    'target_instance_scope',
    'target_kind',
    'target_scope',
    'policy_version',
    'receipt_audit_event_id',
    'receipt_type',
    'receipt_domain',
    'receipt_rule',
    'receipt_authorizer',
    'receipt_outcome',
  ]) {
    assertString(`Protected records fixture authority v2 scope ${field}`, contract.scope[field]);
  }
  for (const field of SCOPE_KEYS.filter((key) => key.endsWith('_sha256'))) {
    assertSha256(`Protected records fixture authority v2 scope ${field}`, contract.scope[field]);
  }
  assertInteger(
    'Protected records fixture authority v2 valid_from_epoch',
    contract.time_policy.valid_from_epoch,
  );
  assertInteger(
    'Protected records fixture authority v2 expires_at_epoch',
    contract.time_policy.expires_at_epoch,
  );
  if (
    contract.time_policy.clock_source !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2 ||
    contract.time_policy.interval !== 'half-open-[valid_from,expires_at)' ||
    contract.time_policy.receipt_ts_must_be_within_grant !== true ||
    contract.time_policy.receipt_ts_must_not_exceed_effect_time !== true ||
    contract.time_policy.valid_from_epoch >= contract.time_policy.expires_at_epoch
  ) {
    throw new Error('Protected records fixture authority v2 half-open window drifted');
  }
  if (
    contract.usage_policy.max_uses !== 1 ||
    contract.usage_policy.consumption_identity !==
      'authority-grant-contract-sha256' ||
    contract.usage_policy.further_replacement_requires_explicit_human_authority !==
      true ||
    contract.usage_policy.mutable_extension_allowed !== false
  ) {
    throw new Error('Protected records fixture authority v2 one-use boundary drifted');
  }
  if (
    contract.delegation_policy.delegation_allowed !== false ||
    contract.delegation_policy.delegated_grant_acceptance_allowed !== false
  ) {
    throw new Error('Protected records fixture authority v2 delegation is forbidden');
  }
  assertCanonicalEqual(
    'Protected records fixture authority v2 powers',
    contract.powers,
    POWERS,
  );
  assertCanonicalEqual(
    'Protected records fixture authority v2 claim ceiling',
    contract.claim_ceiling,
    CLAIM_CEILING,
  );
  return true;
}

export function protectedRecordsFixtureAuthorityGrantContractSha256V2(contract) {
  assertProtectedRecordsFixtureAuthorityGrantContractShapeV2(contract);
  return sha256hex(canonicalize(contract));
}

export function assertProtectedRecordsFixtureAuthorityGrantContractV2(
  contract,
  { expectedContractSha256 } = {},
) {
  assertProtectedRecordsFixtureAuthorityGrantContractShapeV2(contract);
  assertSha256(
    'Protected records fixture authority v2 expected contract SHA-256',
    expectedContractSha256,
  );
  if (
    protectedRecordsFixtureAuthorityGrantContractSha256V2(contract) !==
    expectedContractSha256
  ) {
    throw new Error('Protected records fixture authority v2 exact contract identity mismatched');
  }
  return true;
}

export function createProtectedRecordsFixtureAuthorityAppointmentV2({
  contract,
  expectedContractSha256,
  issuerKid,
  publicKeySha256,
  issuedAtEpoch,
} = {}) {
  assertProtectedRecordsFixtureAuthorityGrantContractV2(contract, {
    expectedContractSha256,
  });
  const appointment = {
    appointment_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_APPOINTMENT_TYPE_V2,
    appointment_version: 2,
    authority_grant_contract_sha256: expectedContractSha256,
    appointment_state: 'appointed-pending-exact-confirmation',
    binding_scope: 'runtime-private-local-disposable-fixture-only',
    delegation_allowed: false,
    expires_at_epoch: contract.time_policy.expires_at_epoch,
    issued_at_epoch: issuedAtEpoch,
    issuer_kid: issuerKid,
    issuer_slot: contract.grantee.issuer_slot,
    maximum_receipt_issuances: 1,
    private_key_material_disclosed: false,
    public_key_sha256: publicKeySha256,
    valid_from_epoch: contract.time_policy.valid_from_epoch,
  };
  assertProtectedRecordsFixtureAuthorityAppointmentV2(appointment, {
    contract,
    expectedContractSha256,
  });
  return appointment;
}

export function assertProtectedRecordsFixtureAuthorityAppointmentV2(
  appointment,
  { contract, expectedContractSha256 } = {},
) {
  assertProtectedRecordsFixtureAuthorityGrantContractV2(contract, {
    expectedContractSha256,
  });
  assertExactKeys(
    'Protected records fixture authority v2 appointment',
    appointment,
    [
      'appointment_state',
      'appointment_type',
      'appointment_version',
      'authority_grant_contract_sha256',
      'binding_scope',
      'delegation_allowed',
      'expires_at_epoch',
      'issued_at_epoch',
      'issuer_kid',
      'issuer_slot',
      'maximum_receipt_issuances',
      'private_key_material_disclosed',
      'public_key_sha256',
      'valid_from_epoch',
    ],
  );
  if (
    appointment.appointment_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_APPOINTMENT_TYPE_V2 ||
    appointment.appointment_version !== 2 ||
    appointment.authority_grant_contract_sha256 !== expectedContractSha256 ||
    appointment.appointment_state !== 'appointed-pending-exact-confirmation' ||
    appointment.binding_scope !==
      'runtime-private-local-disposable-fixture-only' ||
    appointment.issuer_slot !== contract.grantee.issuer_slot ||
    appointment.maximum_receipt_issuances !== 1 ||
    appointment.delegation_allowed !== false ||
    appointment.private_key_material_disclosed !== false ||
    appointment.valid_from_epoch !== contract.time_policy.valid_from_epoch ||
    appointment.expires_at_epoch !== contract.time_policy.expires_at_epoch
  ) {
    throw new Error('Protected records fixture authority v2 appointment boundary drifted');
  }
  assertString('Protected records fixture authority v2 issuer kid', appointment.issuer_kid);
  assertSha256(
    'Protected records fixture authority v2 public key SHA-256',
    appointment.public_key_sha256,
  );
  assertInteger(
    'Protected records fixture authority v2 appointment issued_at_epoch',
    appointment.issued_at_epoch,
  );
  if (appointment.issued_at_epoch > appointment.valid_from_epoch) {
    throw new Error('Protected records fixture authority v2 appointment must precede the grant window');
  }
  return true;
}

export function protectedRecordsFixtureAuthorityAppointmentSha256V2(
  appointment,
  options,
) {
  assertProtectedRecordsFixtureAuthorityAppointmentV2(appointment, options);
  return sha256hex(canonicalize(appointment));
}

export function protectedRecordsFixtureAuthorityIssuerBindingSha256V2(
  appointment,
  options,
) {
  assertProtectedRecordsFixtureAuthorityAppointmentV2(appointment, options);
  return sha256hex(canonicalize({
    issuer_kid: appointment.issuer_kid,
    issuer_slot: appointment.issuer_slot,
    public_key_sha256: appointment.public_key_sha256,
  }));
}

export function assertProtectedRecordsFixtureAuthorityExactConfirmationV2(
  confirmation,
  { contract, expectedContractSha256, appointment } = {},
) {
  assertProtectedRecordsFixtureAuthorityAppointmentV2(appointment, {
    contract,
    expectedContractSha256,
  });
  assertExactKeys(
    'Protected records fixture authority v2 exact confirmation',
    confirmation,
    [
      'appointment_sha256',
      'authority_grant_contract_sha256',
      'authority_source',
      'confirmation_type',
      'confirmation_version',
      'confirmed_at_epoch',
      'confirmed_by',
      'decision',
      'issuer_binding',
      'no_delegation',
      'post_hardening_authorization_packet_body_sha256',
      'source_precondition_presented',
      'time_window',
      'use_limit',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 confirmation actor',
    confirmation.confirmed_by,
    ['actor_id', 'role_id'],
  );
  assertExactKeys(
    'Protected records fixture authority v2 confirmation issuer binding',
    confirmation.issuer_binding,
    ['issuer_kid', 'issuer_slot', 'public_key_sha256'],
  );
  assertExactKeys(
    'Protected records fixture authority v2 confirmation time window',
    confirmation.time_window,
    ['expires_at_epoch', 'interval', 'valid_from_epoch'],
  );
  const appointmentSha256 = protectedRecordsFixtureAuthorityAppointmentSha256V2(
    appointment,
    { contract, expectedContractSha256 },
  );
  if (
    confirmation.confirmation_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_CONFIRMATION_TYPE_V2 ||
    confirmation.confirmation_version !== 2 ||
    confirmation.authority_source !==
      'explicit-in-thread-control-tower-exact-human-confirmation' ||
    confirmation.decision !== 'authorize-one-canonical-positive-crossing' ||
    confirmation.source_precondition_presented !== true ||
    confirmation.authority_grant_contract_sha256 !== expectedContractSha256 ||
    confirmation.appointment_sha256 !== appointmentSha256 ||
    confirmation.confirmed_by.actor_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ACTOR_ID_V2 ||
    confirmation.confirmed_by.role_id !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANTOR_ROLE_ID_V2 ||
    confirmation.issuer_binding.issuer_slot !== appointment.issuer_slot ||
    confirmation.issuer_binding.issuer_kid !== appointment.issuer_kid ||
    confirmation.issuer_binding.public_key_sha256 !==
      appointment.public_key_sha256 ||
    confirmation.time_window.valid_from_epoch !==
      contract.time_policy.valid_from_epoch ||
    confirmation.time_window.expires_at_epoch !==
      contract.time_policy.expires_at_epoch ||
    confirmation.time_window.interval !== 'half-open-[valid_from,expires_at)' ||
    confirmation.use_limit !== 1 ||
    confirmation.no_delegation !== true
  ) {
    throw new Error('Protected records fixture authority v2 exact confirmation mismatched');
  }
  assertSha256(
    'Protected records fixture authority v2 post-hardening packet SHA-256',
    confirmation.post_hardening_authorization_packet_body_sha256,
  );
  assertInteger(
    'Protected records fixture authority v2 confirmed_at_epoch',
    confirmation.confirmed_at_epoch,
  );
  if (
    confirmation.confirmed_at_epoch < appointment.issued_at_epoch ||
    confirmation.confirmed_at_epoch > contract.time_policy.valid_from_epoch
  ) {
    throw new Error('Protected records fixture authority v2 confirmation timing drifted');
  }
  return true;
}

export function protectedRecordsFixtureAuthorityExactConfirmationSha256V2(
  confirmation,
  options,
) {
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2(
    confirmation,
    options,
  );
  return sha256hex(canonicalize(confirmation));
}

export function assertProtectedRecordsFixtureAuthorityStatusV2(
  status,
  {
    contract,
    expectedContractSha256,
    appointment,
    confirmation,
  } = {},
) {
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2(confirmation, {
    contract,
    expectedContractSha256,
    appointment,
  });
  assertExactKeys(
    'Protected records fixture authority v2 status',
    status,
    [
      'appointment_sha256',
      'authority_grant_contract_sha256',
      'confirmation_sha256',
      'consumed_crossing_binding_sha256',
      'fresh_effect_allowed',
      'historical_fixture_authority_at_effect_projection_allowed',
      'maximum_effect_uses',
      'recorded_effect_uses',
      'repeated_use_provenance_valid',
      'revocation_reason_code',
      'revoked_at_epoch',
      'status',
      'status_source',
      'status_type',
      'status_updated_at_epoch',
      'status_version',
    ],
  );
  const appointmentSha256 = protectedRecordsFixtureAuthorityAppointmentSha256V2(
    appointment,
    { contract, expectedContractSha256 },
  );
  const confirmationSha256 =
    protectedRecordsFixtureAuthorityExactConfirmationSha256V2(confirmation, {
      contract,
      expectedContractSha256,
      appointment,
    });
  if (
    status.status_type !== PROTECTED_RECORDS_FIXTURE_AUTHORITY_STATUS_TYPE_V2 ||
    status.status_version !== 2 ||
    status.authority_grant_contract_sha256 !== expectedContractSha256 ||
    status.appointment_sha256 !== appointmentSha256 ||
    status.confirmation_sha256 !== confirmationSha256 ||
    status.maximum_effect_uses !== 1
  ) {
    throw new Error('Protected records fixture authority v2 status binding drifted');
  }
  assertInteger(
    'Protected records fixture authority v2 status_updated_at_epoch',
    status.status_updated_at_epoch,
  );
  const active =
    status.status === 'active' &&
    status.status_source === 'source-recorded-exact-human-confirmation' &&
    status.recorded_effect_uses === 0 &&
    status.fresh_effect_allowed === true &&
    status.repeated_use_provenance_valid === true &&
    status.historical_fixture_authority_at_effect_projection_allowed === false &&
    status.consumed_crossing_binding_sha256 === null &&
    status.revoked_at_epoch === null &&
    status.revocation_reason_code === null;
  const revoked =
    status.status === 'revoked' &&
    status.status_source === 'source-recorded-fixture-authority-revocation' &&
    status.recorded_effect_uses === 0 &&
    status.fresh_effect_allowed === false &&
    status.repeated_use_provenance_valid === false &&
    status.historical_fixture_authority_at_effect_projection_allowed === false &&
    status.consumed_crossing_binding_sha256 === null &&
    Number.isInteger(status.revoked_at_epoch) &&
    typeof status.revocation_reason_code === 'string' &&
    status.revocation_reason_code.length > 0;
  const exhausted =
    status.status === 'exhausted' &&
    status.status_source === 'source-recorded-single-use-consumption' &&
    status.recorded_effect_uses === 1 &&
    status.fresh_effect_allowed === false &&
    status.repeated_use_provenance_valid === false &&
    status.historical_fixture_authority_at_effect_projection_allowed === true &&
    SHA256_PATTERN.test(status.consumed_crossing_binding_sha256 || '') &&
    status.revoked_at_epoch === null &&
    status.revocation_reason_code === null;
  const unrecognized =
    status.status === 'unrecognized' &&
    status.status_source === 'no-source-authorized-v2-status-record' &&
    status.recorded_effect_uses === 0 &&
    status.fresh_effect_allowed === false &&
    status.repeated_use_provenance_valid === false &&
    status.historical_fixture_authority_at_effect_projection_allowed === false &&
    status.consumed_crossing_binding_sha256 === null &&
    status.revoked_at_epoch === null &&
    status.revocation_reason_code === null;
  if (!active && !revoked && !exhausted && !unrecognized) {
    throw new Error('Protected records fixture authority v2 status state is incoherent');
  }
  if (
    status.status !== 'unrecognized' &&
    status.status_updated_at_epoch < confirmation.confirmed_at_epoch
  ) {
    throw new Error('Protected records fixture authority v2 status predates exact confirmation');
  }
  if (
    status.status === 'revoked' &&
    (
      status.revoked_at_epoch >= contract.time_policy.expires_at_epoch ||
      status.status_updated_at_epoch !== status.revoked_at_epoch
    )
  ) {
    throw new Error('Protected records fixture authority v2 revocation timing drifted');
  }
  return true;
}

export function protectedRecordsFixtureAuthorityStatusSha256V2(status, options) {
  assertProtectedRecordsFixtureAuthorityStatusV2(status, options);
  return sha256hex(canonicalize(status));
}

export function assertProtectedRecordsFixtureAuthorityScopeEvidenceV2(
  scopeEvidence,
  contract,
) {
  assertExactKeys(
    'Protected records fixture authority v2 scope evidence',
    scopeEvidence,
    [
      'derived_from_authority_grant_contract',
      'derived_from_request_stream',
      'evidence_type',
      'scope',
      'source',
      'validated_launcher_config',
    ],
  );
  if (
    scopeEvidence.evidence_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_SCOPE_EVIDENCE_TYPE_V2 ||
    scopeEvidence.source !==
      'validated-launcher-profile-recognition-target-config' ||
    scopeEvidence.validated_launcher_config !== true ||
    scopeEvidence.derived_from_authority_grant_contract !== false ||
    scopeEvidence.derived_from_request_stream !== false
  ) {
    throw new Error('Protected records fixture authority v2 scope provenance drifted');
  }
  assertCanonicalEqual(
    'Protected records fixture authority v2 independently validated scope',
    scopeEvidence.scope,
    contract.scope,
  );
  return true;
}

export function protectedRecordsAuthorizedEffectDetailV2({
  contract,
  expectedContractSha256,
  targetEffect,
} = {}) {
  assertProtectedRecordsFixtureAuthorityGrantContractV2(contract, {
    expectedContractSha256,
  });
  const detail = {
    detail_type: PROTECTED_RECORDS_AUTHORIZED_EFFECT_DETAIL_TYPE_V2,
    authority_grant_contract_sha256: expectedContractSha256,
    target_effect: clone(targetEffect),
  };
  assertProtectedRecordsAuthorizedEffectDetailV2(detail, {
    contract,
    expectedContractSha256,
  });
  return detail;
}

export function assertProtectedRecordsAuthorizedEffectDetailV2(
  detail,
  { contract, expectedContractSha256 } = {},
) {
  assertProtectedRecordsFixtureAuthorityGrantContractV2(contract, {
    expectedContractSha256,
  });
  assertExactKeys(
    'Protected records fixture authority v2 authorized effect detail',
    detail,
    ['authority_grant_contract_sha256', 'detail_type', 'target_effect'],
  );
  assertExactKeys(
    'Protected records fixture authority v2 target effect',
    detail.target_effect,
    ['record_update', 'target_handle'],
  );
  requireObject(
    'Protected records fixture authority v2 record update',
    detail.target_effect.record_update,
  );
  if (
    detail.detail_type !== PROTECTED_RECORDS_AUTHORIZED_EFFECT_DETAIL_TYPE_V2 ||
    detail.authority_grant_contract_sha256 !== expectedContractSha256 ||
    detail.target_effect.target_handle !== contract.scope.target_handle ||
    sha256hex(canonicalize(detail.target_effect.record_update)) !==
      contract.scope.record_update_sha256 ||
    sha256hex(canonicalize(detail.target_effect)) !==
      contract.scope.target_effect_sha256
  ) {
    throw new Error('Protected records fixture authority v2 target effect identity mismatched');
  }
  return true;
}

export function protectedRecordsAuthorizedEffectDetailSha256V2(detail, options) {
  assertProtectedRecordsAuthorizedEffectDetailV2(detail, options);
  return sha256hex(canonicalize(detail));
}

export function assertProtectedRecordsFixtureAuthorityReceiptEvidenceV2(
  receiptEvidence,
  { phase, contract } = {},
) {
  assertExactKeys(
    'Protected records fixture authority v2 receipt evidence',
    receiptEvidence,
    [
      'authority_grant_contract_sha256',
      'authorized_effect_detail_sha256',
      'delegation_chain',
      'delegation_chain_present',
      'evidence_type',
      'issued_at_epoch',
      'issuer_kid',
      'policy_version',
      'public_key_sha256',
      'receipt_action_class',
      'receipt_audit_event_id',
      'receipt_evidence_phase',
      'receipt_authorizer',
      'receipt_domain',
      'receipt_outcome',
      'receipt_payload_sha256',
      'receipt_rule',
      'receipt_type',
      'receipt_version',
      'signed_receipt_sha256',
      'signature_verified',
      'source',
    ],
  );
  if (!['issuance', 'effect'].includes(phase)) {
    throw new Error('Protected records fixture authority v2 receipt evidence phase is required');
  }
  assertBoolean(
    'Protected records fixture authority v2 receipt delegation-chain presence',
    receiptEvidence.delegation_chain_present,
  );
  if (
    receiptEvidence.delegation_chain_present !== true ||
    !Array.isArray(receiptEvidence.delegation_chain)
  ) {
    throw new Error('Protected records fixture authority v2 receipt requires a canonical explicit delegation chain');
  }
  if (receiptEvidence.delegation_chain.length !== 0) {
    throw new Error('Protected records fixture authority v2 receipt delegation is forbidden');
  }
  if (
    receiptEvidence.evidence_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_RECEIPT_EVIDENCE_TYPE_V2 ||
    receiptEvidence.receipt_evidence_phase !== phase ||
    receiptEvidence.receipt_action_class !== contract?.scope?.action_class ||
    receiptEvidence.receipt_audit_event_id !==
      contract?.scope?.receipt_audit_event_id ||
    receiptEvidence.policy_version !== contract?.scope?.policy_version ||
    receiptEvidence.receipt_version !== contract?.scope?.receipt_version ||
    receiptEvidence.receipt_type !== contract?.scope?.receipt_type ||
    receiptEvidence.receipt_domain !== contract?.scope?.receipt_domain ||
    receiptEvidence.receipt_rule !== contract?.scope?.receipt_rule ||
    receiptEvidence.receipt_authorizer !== contract?.scope?.receipt_authorizer ||
    receiptEvidence.receipt_outcome !== contract?.scope?.receipt_outcome
  ) {
    throw new Error('Protected records fixture authority v2 receipt semantics drifted');
  }
  for (const field of [
    'authority_grant_contract_sha256',
    'authorized_effect_detail_sha256',
    'public_key_sha256',
    'receipt_payload_sha256',
  ]) {
    assertSha256(`Protected records fixture authority v2 receipt ${field}`, receiptEvidence[field]);
  }
  if (phase === 'issuance') {
    if (
      receiptEvidence.source !== 'canonical-unsigned-receipt-payload-pre-signing' ||
      receiptEvidence.signature_verified !== false ||
      receiptEvidence.signed_receipt_sha256 !== null
    ) {
      throw new Error('Protected records fixture authority v2 issuance must occur before signing');
    }
  } else if (
    receiptEvidence.source !== 'independent-signed-receipt-verification' ||
    receiptEvidence.signature_verified !== true
  ) {
    throw new Error('Protected records fixture authority v2 effect requires verified signed receipt evidence');
  } else {
    assertSha256(
      'Protected records fixture authority v2 signed receipt SHA-256',
      receiptEvidence.signed_receipt_sha256,
    );
  }
  assertString('Protected records fixture authority v2 receipt issuer kid', receiptEvidence.issuer_kid);
  assertString(
    'Protected records fixture authority v2 receipt audit event id',
    receiptEvidence.receipt_audit_event_id,
  );
  assertInteger(
    'Protected records fixture authority v2 receipt issued_at_epoch',
    receiptEvidence.issued_at_epoch,
  );
  return true;
}

export function protectedRecordsFixtureAuthorityReceiptDelegationStateSha256V2(
  receiptEvidence,
) {
  requireObject(
    'Protected records fixture authority v2 receipt evidence',
    receiptEvidence,
  );
  assertBoolean(
    'Protected records fixture authority v2 receipt delegation-chain presence',
    receiptEvidence.delegation_chain_present,
  );
  if (
    receiptEvidence.delegation_chain_present !== true ||
    !Array.isArray(receiptEvidence.delegation_chain)
  ) {
    throw new Error('Protected records fixture authority v2 receipt requires a canonical explicit delegation chain');
  }
  if (receiptEvidence.delegation_chain.length !== 0) {
    throw new Error('Protected records fixture authority v2 receipt delegation is forbidden');
  }
  return sha256hex(canonicalize({
    delegation_chain: receiptEvidence.delegation_chain,
    delegation_chain_present: receiptEvidence.delegation_chain_present,
  }));
}

function decisionBindingValue(value, pattern = SHA256_PATTERN) {
  return typeof value === 'string' && pattern.test(value) ? value : null;
}

function addReason(reasons, code, message) {
  if (!reasons.some((reason) => reason.code === code)) reasons.push({ code, message });
}

function tryCheck(reasons, code, message, fn) {
  try {
    fn();
    return true;
  } catch {
    addReason(reasons, code, message);
    return false;
  }
}

function buildProtectedRecordsFixtureAuthorityDecisionV2({
  phase,
  contract,
  expectedContractSha256,
  sourcePrecondition,
  appointment,
  confirmation,
  authorityStatus,
  scopeEvidence,
  receiptEvidence,
  authorizedEffectDetail,
  evaluationEpoch,
  grantPreviouslyConsumed,
  issuanceDecision,
}) {
  const reasons = [];
  const contractValid = tryCheck(
    reasons,
    'authority_contract_invalid_or_identity_mismatched',
    'The v2 fixture authority contract is invalid or does not match the exact expected contract SHA-256.',
    () => assertProtectedRecordsFixtureAuthorityGrantContractV2(contract, {
      expectedContractSha256,
    }),
  );
  const preconditionValid = contractValid && tryCheck(
    reasons,
    'source_precondition_invalid_or_unbound',
    'The source-complete precondition record is invalid or is not bound to the grant contract.',
    () => {
      assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(sourcePrecondition);
      if (
        protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(sourcePrecondition) !==
          contract.scope.source_precondition_artifact_body_sha256 ||
        canonicalize(
          protectedRecordsFixtureAuthorityImplementationBindingFromSourcePreconditionV2(
            sourcePrecondition,
          ),
        ) !== canonicalize(contract.implementation_binding)
      ) {
        throw new Error('source precondition binding mismatched');
      }
    },
  );
  const appointmentValid = contractValid && tryCheck(
    reasons,
    'issuer_appointment_invalid_or_unbound',
    'The runtime-private issuer appointment is invalid or is not bound to the exact grant.',
    () => assertProtectedRecordsFixtureAuthorityAppointmentV2(appointment, {
      contract,
      expectedContractSha256,
    }),
  );
  const confirmationValid = appointmentValid && tryCheck(
    reasons,
    'exact_human_confirmation_invalid_or_absent',
    'The downstream exact human confirmation is invalid or absent; the conditional authorization body cannot execute itself.',
    () => assertProtectedRecordsFixtureAuthorityExactConfirmationV2(confirmation, {
      contract,
      expectedContractSha256,
      appointment,
    }),
  );
  const statusValid = confirmationValid && tryCheck(
    reasons,
    'authority_status_invalid_or_unbound',
    'The source-authorized fixture authority status is invalid or unbound.',
    () => assertProtectedRecordsFixtureAuthorityStatusV2(authorityStatus, {
      contract,
      expectedContractSha256,
      appointment,
      confirmation,
    }),
  );
  const authorityStatusSha256 = statusValid
    ? protectedRecordsFixtureAuthorityStatusSha256V2(authorityStatus, {
        contract,
        expectedContractSha256,
        appointment,
        confirmation,
      })
    : null;
  const issuerBindingSha256 = appointmentValid
    ? protectedRecordsFixtureAuthorityIssuerBindingSha256V2(appointment, {
        contract,
        expectedContractSha256,
      })
    : null;
  const scopeValid = contractValid && tryCheck(
    reasons,
    'launcher_scope_evidence_invalid_or_mismatched',
    'Independent launcher scope evidence is invalid or does not match the exact grant scope.',
    () => assertProtectedRecordsFixtureAuthorityScopeEvidenceV2(
      scopeEvidence,
      contract,
    ),
  );
  const effectValid = contractValid && tryCheck(
    reasons,
    'authorized_effect_identity_invalid_or_mismatched',
    'The target effect identity is invalid or does not match the exact grant scope.',
    () => assertProtectedRecordsAuthorizedEffectDetailV2(
      authorizedEffectDetail,
      { contract, expectedContractSha256 },
    ),
  );
  const receiptValid = tryCheck(
    reasons,
    'receipt_evidence_invalid',
    'The signed receipt evidence is invalid.',
    () => assertProtectedRecordsFixtureAuthorityReceiptEvidenceV2(
      receiptEvidence,
      { phase, contract },
    ),
  );
  if (
    receiptEvidence?.delegation_chain_present === true &&
    Array.isArray(receiptEvidence?.delegation_chain) &&
    receiptEvidence.delegation_chain.length > 0
  ) {
    addReason(
      reasons,
      'receipt_delegation_forbidden',
      'The v2 fixture authority contract and exact confirmation forbid delegated receipt authority.',
    );
  } else if (
    receiptEvidence?.delegation_chain_present !== true ||
    !Array.isArray(receiptEvidence?.delegation_chain)
  ) {
    addReason(
      reasons,
      'receipt_delegation_state_invalid',
      'The v2 fixture authority requires the canonical explicit empty delegation chain emitted by v1 receipt creation.',
    );
  }
  const receiptDelegationStateSha256 = receiptValid
    ? protectedRecordsFixtureAuthorityReceiptDelegationStateSha256V2(
        receiptEvidence,
      )
    : null;

  if (!Number.isInteger(evaluationEpoch)) {
    addReason(reasons, 'evaluation_epoch_invalid', 'The authority evaluation epoch is invalid.');
  }
  if (typeof grantPreviouslyConsumed !== 'boolean') {
    addReason(reasons, 'one_use_state_invalid', 'The one-use consumption state is not an exact boolean.');
  } else if (grantPreviouslyConsumed) {
    addReason(reasons, 'authority_grant_previously_consumed', 'The one-use fixture authority grant was already consumed.');
  }
  if (
    statusValid &&
    (
      authorityStatus.status !== 'active' ||
      authorityStatus.fresh_effect_allowed !== true ||
      authorityStatus.recorded_effect_uses !== 0
    )
  ) {
    addReason(reasons, 'authority_status_not_active', 'The source-authorized fixture authority status does not allow a fresh effect.');
  }
  if (
    statusValid &&
    Number.isInteger(evaluationEpoch) &&
    authorityStatus.status_updated_at_epoch > evaluationEpoch
  ) {
    addReason(reasons, 'authority_status_future_dated', 'The authority status was updated after this evaluation epoch.');
  }
  if (
    contractValid &&
    Number.isInteger(evaluationEpoch) &&
    (
      evaluationEpoch < contract.time_policy.valid_from_epoch ||
      evaluationEpoch >= contract.time_policy.expires_at_epoch
    )
  ) {
    addReason(reasons, 'grant_outside_half_open_window', 'The evaluation is outside the exact half-open fixture window.');
  }
  if (receiptValid && appointmentValid) {
    if (
      receiptEvidence.authority_grant_contract_sha256 !==
        expectedContractSha256 ||
      receiptEvidence.issuer_kid !== appointment.issuer_kid ||
      receiptEvidence.public_key_sha256 !== appointment.public_key_sha256
    ) {
      addReason(reasons, 'receipt_issuer_or_grant_binding_mismatched', 'The receipt is not bound to the exact grant and runtime-private issuer appointment.');
    }
    if (
      contractValid &&
      (
        receiptEvidence.issued_at_epoch < contract.time_policy.valid_from_epoch ||
        receiptEvidence.issued_at_epoch >= contract.time_policy.expires_at_epoch ||
        (Number.isInteger(evaluationEpoch) &&
          receiptEvidence.issued_at_epoch > evaluationEpoch)
      )
    ) {
      addReason(reasons, 'receipt_outside_half_open_window', 'The receipt timestamp is outside the grant window or after effect evaluation.');
    }
  }
  let authorizedEffectDetailSha256 = null;
  if (effectValid) {
    authorizedEffectDetailSha256 =
      protectedRecordsAuthorizedEffectDetailSha256V2(
        authorizedEffectDetail,
        { contract, expectedContractSha256 },
      );
  }
  if (
    receiptValid &&
    effectValid &&
    receiptEvidence.authorized_effect_detail_sha256 !==
      authorizedEffectDetailSha256
  ) {
    addReason(reasons, 'receipt_effect_binding_mismatched', 'The signed receipt is not bound to the exact authorized effect detail.');
  }

  let issuanceDecisionSha256 = null;
  let acceptedIssuanceDecisionBound = phase === 'issuance';
  if (phase === 'effect') {
    const issuanceValid = tryCheck(
      reasons,
      'accepted_issuance_decision_missing_or_unbound',
      'Effect evaluation requires the accepted issuance decision for this exact crossing.',
      () => {
        assertProtectedRecordsFixtureAuthorityDecisionV2(issuanceDecision);
        if (
          issuanceDecision.phase !== 'issuance' ||
          issuanceDecision.decision !== 'accept' ||
          issuanceDecision.binding.authority_grant_contract_sha256 !==
            expectedContractSha256 ||
          issuanceDecision.binding.appointment_sha256 !==
            (appointmentValid
              ? protectedRecordsFixtureAuthorityAppointmentSha256V2(
                  appointment,
                  { contract, expectedContractSha256 },
                )
              : null) ||
          issuanceDecision.binding.authority_status_sha256 !==
            authorityStatusSha256 ||
          issuanceDecision.binding.authorized_effect_detail_sha256 !==
            authorizedEffectDetailSha256 ||
          issuanceDecision.binding.confirmation_sha256 !==
            (confirmationValid
              ? protectedRecordsFixtureAuthorityExactConfirmationSha256V2(
                  confirmation,
                  { contract, expectedContractSha256, appointment },
                )
              : null) ||
          issuanceDecision.binding.issuer_binding_sha256 !==
            issuerBindingSha256 ||
          issuanceDecision.binding.receipt_payload_sha256 !==
            receiptEvidence?.receipt_payload_sha256 ||
          issuanceDecision.binding.receipt_audit_event_id !==
            receiptEvidence?.receipt_audit_event_id ||
          issuanceDecision.binding.receipt_delegation_state_sha256 !==
            receiptDelegationStateSha256 ||
          issuanceDecision.binding.source_precondition_artifact_body_sha256 !==
            contract?.scope?.source_precondition_artifact_body_sha256 ||
          issuanceDecision.evidence.issuance_pre_signing_boundary_matched !== true
        ) {
          throw new Error('issuance decision does not bind this crossing');
        }
      },
    );
    if (issuanceValid) {
      acceptedIssuanceDecisionBound = true;
      issuanceDecisionSha256 = protectedRecordsFixtureAuthorityDecisionSha256V2(
        issuanceDecision,
      );
    }
  }

  const accepted = reasons.length === 0;
  const decision = {
    decision_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_DECISION_TYPE_V2,
    decision_version: 2,
    phase,
    decision: accepted ? 'accept' : 'refuse',
    reason_code: accepted
      ? `fixture_authority_v2_${phase}_satisfied`
      : reasons[0].code,
    reasons: accepted
      ? [{
          code: `fixture_authority_v2_${phase}_satisfied`,
          message: `The exact local fixture authority satisfied the ${phase} boundary.`,
        }]
      : reasons,
    binding: {
      appointment_sha256:
        appointmentValid
          ? protectedRecordsFixtureAuthorityAppointmentSha256V2(appointment, {
              contract,
              expectedContractSha256,
            })
          : null,
      authority_grant_contract_sha256: decisionBindingValue(
        expectedContractSha256,
      ),
      authority_status_sha256: authorityStatusSha256,
      authorized_effect_detail_sha256: authorizedEffectDetailSha256,
      confirmation_sha256:
        confirmationValid
          ? protectedRecordsFixtureAuthorityExactConfirmationSha256V2(
              confirmation,
              { contract, expectedContractSha256, appointment },
            )
          : null,
      issuance_decision_sha256: issuanceDecisionSha256,
      issuer_binding_sha256: issuerBindingSha256,
      receipt_audit_event_id:
        typeof receiptEvidence?.receipt_audit_event_id === 'string' &&
        receiptEvidence.receipt_audit_event_id.length > 0
          ? receiptEvidence.receipt_audit_event_id
          : null,
      receipt_delegation_state_sha256: receiptDelegationStateSha256,
      receipt_payload_sha256: decisionBindingValue(
        receiptEvidence?.receipt_payload_sha256,
      ),
      signed_receipt_sha256: decisionBindingValue(
        receiptEvidence?.signed_receipt_sha256,
      ),
      source_precondition_artifact_body_sha256:
        preconditionValid
          ? protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(
              sourcePrecondition,
            )
          : null,
    },
    evidence: {
      conditional_authorization_does_not_self_execute: true,
      exact_contract_identity_matched: contractValid,
      exact_human_confirmation_matched: confirmationValid,
      fresh_source_authorized_status_matched:
        statusValid &&
        authorityStatus.status === 'active' &&
        authorityStatus.fresh_effect_allowed === true,
      grant_not_previously_consumed: grantPreviouslyConsumed === false,
      half_open_window_matched:
        contractValid &&
        Number.isInteger(evaluationEpoch) &&
        evaluationEpoch >= contract.time_policy.valid_from_epoch &&
        evaluationEpoch < contract.time_policy.expires_at_epoch,
      issuer_appointment_matched: appointmentValid,
      issuance_pre_signing_boundary_matched:
        phase === 'issuance'
          ? receiptValid &&
            receiptEvidence.signature_verified === false &&
            receiptEvidence.signed_receipt_sha256 === null
          : acceptedIssuanceDecisionBound,
      launcher_scope_matched: scopeValid,
      no_delegation_matched:
        receiptValid &&
        receiptEvidence.delegation_chain_present === true &&
        Array.isArray(receiptEvidence.delegation_chain) &&
        receiptEvidence.delegation_chain.length === 0,
      receipt_and_effect_identity_matched:
        receiptValid &&
        effectValid &&
        receiptEvidence.authorized_effect_detail_sha256 ===
          authorizedEffectDetailSha256,
      source_precondition_matched: preconditionValid,
    },
    claim_ceiling: fixedClaimCeiling(),
  };
  assertProtectedRecordsFixtureAuthorityDecisionV2(decision);
  return decision;
}

export function evaluateProtectedRecordsFixtureAuthorityIssuanceV2(inputs = {}) {
  return buildProtectedRecordsFixtureAuthorityDecisionV2({
    ...inputs,
    phase: 'issuance',
    issuanceDecision: null,
  });
}

export function evaluateProtectedRecordsFixtureAuthorityEffectV2(inputs = {}) {
  return buildProtectedRecordsFixtureAuthorityDecisionV2({
    ...inputs,
    phase: 'effect',
  });
}

export function assertProtectedRecordsFixtureAuthorityDecisionV2(decision) {
  assertExactKeys(
    'Protected records fixture authority v2 decision',
    decision,
    [
      'binding',
      'claim_ceiling',
      'decision',
      'decision_type',
      'decision_version',
      'evidence',
      'phase',
      'reason_code',
      'reasons',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 decision binding',
    decision.binding,
    [
      'appointment_sha256',
      'authority_grant_contract_sha256',
      'authority_status_sha256',
      'authorized_effect_detail_sha256',
      'confirmation_sha256',
      'issuance_decision_sha256',
      'issuer_binding_sha256',
      'receipt_audit_event_id',
      'receipt_delegation_state_sha256',
      'receipt_payload_sha256',
      'signed_receipt_sha256',
      'source_precondition_artifact_body_sha256',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 decision evidence',
    decision.evidence,
    [
      'conditional_authorization_does_not_self_execute',
      'exact_contract_identity_matched',
      'exact_human_confirmation_matched',
      'fresh_source_authorized_status_matched',
      'grant_not_previously_consumed',
      'half_open_window_matched',
      'issuer_appointment_matched',
      'issuance_pre_signing_boundary_matched',
      'launcher_scope_matched',
      'no_delegation_matched',
      'receipt_and_effect_identity_matched',
      'source_precondition_matched',
    ],
  );
  assertExactKeys(
    'Protected records fixture authority v2 decision claim ceiling',
    decision.claim_ceiling,
    Object.keys(CLAIM_CEILING),
  );
  if (
    decision.decision_type !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_DECISION_TYPE_V2 ||
    decision.decision_version !== 2 ||
    !['issuance', 'effect'].includes(decision.phase) ||
    !['accept', 'refuse'].includes(decision.decision)
  ) {
    throw new Error('Protected records fixture authority v2 decision boundary drifted');
  }
  assertString('Protected records fixture authority v2 decision reason code', decision.reason_code);
  if (!Array.isArray(decision.reasons) || decision.reasons.length < 1) {
    throw new Error('Protected records fixture authority v2 decision reasons must be non-empty');
  }
  for (const reason of decision.reasons) {
    assertExactKeys('Protected records fixture authority v2 decision reason', reason, ['code', 'message']);
    assertString('Protected records fixture authority v2 decision reason code', reason.code);
    assertString('Protected records fixture authority v2 decision reason message', reason.message);
  }
  for (const value of Object.values(decision.evidence)) {
    assertBoolean('Protected records fixture authority v2 decision evidence value', value);
  }
  if (decision.evidence.conditional_authorization_does_not_self_execute !== true) {
    throw new Error('Protected records fixture authority v2 conditional body cannot self-execute');
  }
  for (const [field, value] of Object.entries(decision.binding)) {
    if (value === null) continue;
    if (field === 'receipt_audit_event_id') {
      assertString(
        'Protected records fixture authority v2 decision binding receipt audit event id',
        value,
      );
    } else {
      assertSha256(`Protected records fixture authority v2 decision binding ${field}`, value);
    }
  }
  if (
    decision.decision === 'refuse' &&
    decision.reason_code !== decision.reasons[0].code
  ) {
    throw new Error('Protected records fixture authority v2 refusal reason code drifted');
  }
  if (
    decision.decision === 'accept' &&
    Object.entries(decision.evidence).some(
      ([field, value]) =>
        field !== 'conditional_authorization_does_not_self_execute' && value !== true,
    )
  ) {
    throw new Error('Protected records fixture authority v2 accepted decision lacks required evidence');
  }
  if (decision.decision === 'accept') {
    for (const field of [
      'appointment_sha256',
      'authority_grant_contract_sha256',
      'authority_status_sha256',
      'authorized_effect_detail_sha256',
      'confirmation_sha256',
      'issuer_binding_sha256',
      'receipt_delegation_state_sha256',
      'source_precondition_artifact_body_sha256',
    ]) {
      assertSha256(
        `Protected records fixture authority v2 accepted binding ${field}`,
        decision.binding[field],
      );
    }
    assertString(
      'Protected records fixture authority v2 accepted binding receipt audit event id',
      decision.binding.receipt_audit_event_id,
    );
    assertSha256(
      'Protected records fixture authority v2 accepted binding receipt payload SHA-256',
      decision.binding.receipt_payload_sha256,
    );
    if (
      decision.reason_code !== `fixture_authority_v2_${decision.phase}_satisfied` ||
      decision.reasons.length !== 1 ||
      decision.reasons[0].code !== decision.reason_code
    ) {
      throw new Error('Protected records fixture authority v2 acceptance reason drifted');
    }
    if (
      decision.phase === 'issuance' &&
      (
        decision.binding.issuance_decision_sha256 !== null ||
        decision.binding.signed_receipt_sha256 !== null
      )
    ) {
      throw new Error('Protected records fixture authority v2 issuance decision must precede signing');
    }
    if (decision.phase === 'effect') {
      assertSha256(
        'Protected records fixture authority v2 accepted effect issuance decision SHA-256',
        decision.binding.issuance_decision_sha256,
      );
      assertSha256(
        'Protected records fixture authority v2 accepted effect signed receipt SHA-256',
        decision.binding.signed_receipt_sha256,
      );
    }
  }
  assertCanonicalEqual(
    'Protected records fixture authority v2 decision claim ceiling',
    decision.claim_ceiling,
    CLAIM_CEILING,
  );
  return true;
}

export function protectedRecordsFixtureAuthorityDecisionSha256V2(decision) {
  assertProtectedRecordsFixtureAuthorityDecisionV2(decision);
  return sha256hex(canonicalize(decision));
}
