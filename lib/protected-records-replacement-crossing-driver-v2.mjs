import { canonicalize } from './canonicalize.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2,
  assertProtectedRecordsAuthorizedEffectDetailV2,
  assertProtectedRecordsFixtureAuthorityAppointmentV2,
  assertProtectedRecordsFixtureAuthorityDecisionV2,
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2,
  assertProtectedRecordsFixtureAuthorityGrantContractV2,
  assertProtectedRecordsFixtureAuthorityScopeEvidenceV2,
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2,
  assertProtectedRecordsFixtureAuthorityStatusV2,
  protectedRecordsAuthorizedEffectDetailSha256V2,
  protectedRecordsFixtureAuthorityAppointmentSha256V2,
  protectedRecordsFixtureAuthorityDecisionSha256V2,
  protectedRecordsFixtureAuthorityExactConfirmationSha256V2,
  protectedRecordsFixtureAuthorityGrantContractSha256V2,
  protectedRecordsFixtureAuthorityIssuerBindingSha256V2,
  protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2,
  protectedRecordsFixtureAuthorityStatusSha256V2,
} from './protected-records-fixture-authority-grant-v2.mjs';
import {
  assertProtectedRecordsRuntimeServiceConfigV2,
  assertProtectedRecordsRuntimeServiceResultV2,
  assertProtectedRecordsRuntimeTargetBinding,
  protectedRecordsReplacementCrossingInputsFromRuntimeServiceResultV2,
  protectedRecordsReplacementSourceBindingFromRuntimeServiceResultV2,
} from './protected-records-runtime-profile.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2,
  createProtectedRecordsRuntimeAuthorityContextV2,
  evaluateProtectedRecordsRuntimeEffectMarginV2,
} from './protected-records-runtime-authority-v2.mjs';
import {
  buildProtectedRecordsReplacementCrossingEvidenceV2,
  buildProtectedRecordsReplacementServiceArtifactV2,
  buildProtectedRecordsReplacementTerminalArtifactV2,
  canonicalProtectedRecordsReplacementArtifactBytesV2,
  assertProtectedRecordsReplacementConfirmationRelayV2,
  protectedRecordsReplacementConfirmationRelayInputsV2,
  protectedRecordsReplacementServiceArtifactSchemaContractSha256V2,
  protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2,
  verifyProtectedRecordsReplacementServiceArtifactV2RawBytes,
  verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes,
} from './protected-records-replacement-artifacts-v2.mjs';
import {
  PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2,
  buildProtectedRecordsReplacementArtifactSetManifestV2,
  buildProtectedRecordsReplacementDownstreamProjectionV2,
  canonicalProtectedRecordsReplacementArtifactSetManifestBytesV2,
  protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2,
  protectedRecordsReplacementNoReexecutionCallGraphDescriptorV2,
  protectedRecordsReplacementNoReexecutionCallGraphSha256V2,
  verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes,
} from './protected-records-replacement-artifact-set-v2.mjs';
import { sha256hex, verifyReceiptV1 } from './receipt.mjs';

export const PROTECTED_RECORDS_REPLACEMENT_CROSSING_DRIVER_TYPE_V2 =
  'zlar.protected-records.replacement-crossing-driver.v2';
export const PROTECTED_RECORDS_REPLACEMENT_MINIMUM_SAFETY_SECONDS_V2 =
  PROTECTED_RECORDS_RUNTIME_MINIMUM_EFFECT_MARGIN_SECONDS_V2;

const SHA256_RE = /^[a-f0-9]{64}$/;
const GIT_SHA1_RE = /^[a-f0-9]{40}$/;

export const PROTECTED_RECORDS_REPLACEMENT_PACKET_KEYS_V2 = Object.freeze([
  'appointment',
  'appointment_sha256',
  'authorized_effect_detail',
  'authorized_effect_detail_sha256',
  'ceremony_authorization',
  'claim_boundary',
  'conditional_authorization_body_sha256',
  'confirmation_requirements',
  'grant_contract',
  'grant_contract_sha256',
  'issuer_binding_sha256',
  'no_reexecution_binding',
  'one_use_policy',
  'packet_type',
  'packet_version',
  'public_issuer_identity',
  'receipt_payload',
  'receipt_payload_sha256',
  'recognition_rule',
  'record_update',
  'revocation_boundary',
  'scope_evidence',
  'side_doors',
  'source_precondition',
  'source_precondition_sha256',
  'source_repository_checkpoint',
  'source_repository_checkpoint_body_sha256',
  'target_binding',
  'target_effect',
  'time_window',
  'transport_precondition',
  'unsigned_receipt',
  'unsigned_receipt_envelope_sha256',
]);

export const PROTECTED_RECORDS_REPLACEMENT_HOLDER_SIGNED_ONCE_KEYS_V2 =
Object.freeze([
  'authority_status',
  'authority_status_sha256',
  'ceremony_id',
  'confirmation',
  'confirmation_sha256',
  'control_tower_confirmation_relay_delay_seconds',
  'control_tower_confirmation_relay_max_seconds',
  'cryptographic_erasure_proven',
  'event',
  'holder_observed_confirmation_epoch',
  'holder_observed_signing_epoch',
  'holder_observed_signing_milliseconds',
  'holder_protocol',
  'issuance_decision',
  'key_generation_count',
  'packet_body_sha256',
  'private_key_exported',
  'process_exit_releases_address_space_best_effort',
  'receipt_payload_sha256',
  'signed_receipt',
  'signed_receipt_sha256',
  'signing_attempt_count',
  'signing_window_early_wakeup_count',
  'signing_window_early_wakeup_limit',
  'signing_window_timer_guard_milliseconds',
]);

export const PROTECTED_RECORDS_REPLACEMENT_HOLDER_BOUND_KEYS_V2 = Object.freeze([
  'activation_nonce',
  'activation_record_body_sha256',
  'activation_record_file_sha256',
  'active_turn_user_steer_evidence_body_sha256',
  'active_turn_user_steer_evidence_file_sha256',
  'appointment_sha256',
  'authorized_effect_detail_sha256',
  'bind_frame_sha256',
  'bind_nonce',
  'bound_at_epoch',
  'brokered_holder_key_generation_claim_body_sha256',
  'brokered_holder_key_generation_claim_file_sha256',
  'brokered_holder_key_generation_claim_ordinal',
  'brokered_holder_key_generation_claimed_at_epoch',
  'canonical_packet_body_length',
  'ceremony_authorization_sha256',
  'ceremony_id',
  'control_tower_activation_first_observed_at_epoch',
  'controller_capability_generation_admission_body_sha256',
  'controller_capability_generation_admission_file_sha256',
  'controller_source_sha256',
  'dry_run_evidence_body_sha256',
  'dry_run_harness_source_sha256',
  'event',
  'failed_ceremony_deny_set_body_sha256',
  'failed_ceremony_deny_set_source_sha256',
  'failed_ceremony_family_count',
  'frame_codec_source_sha256',
  'frame_protocol',
  'grant_contract_sha256',
  'holder_bound_body_sha256',
  'holder_claim_capability_sha256',
  'holder_claim_request_body_sha256',
  'holder_instance_nonce',
  'holder_launch_capability_sha256',
  'holder_protocol',
  'holder_source_sha256',
  'inner_harness_source_sha256',
  'inner_rehearsal_evidence_body_sha256',
  'issuer_binding_sha256',
  'issuer_kid',
  'key_generation_attempt_body_sha256',
  'key_generation_attempt_file_sha256',
  'key_generation_call_observed_at_epoch',
  'key_generation_count',
  'no_confirmation_destruction_deadline_epoch',
  'outer_controller_rehearsal_evidence_body_sha256',
  'packet_body_sha256',
  'packet_builder_source_sha256',
  'private_key_exported',
  'private_key_extractable',
  'public_key_sha256',
  'receipt_payload_sha256',
  'source_checkpoint_evidence_body_sha256',
  'source_checkpoint_evidence_sha256',
  'source_checkpoint_harness_source_sha256',
  'source_precondition_file_sha256',
  'source_repository_checkpoint_body_sha256',
  'transport_descriptor_shape',
]);

const PACKET_KEYS = PROTECTED_RECORDS_REPLACEMENT_PACKET_KEYS_V2;
const HOLDER_SIGNED_ONCE_KEYS =
  PROTECTED_RECORDS_REPLACEMENT_HOLDER_SIGNED_ONCE_KEYS_V2;
const HOLDER_BOUND_KEYS = PROTECTED_RECORDS_REPLACEMENT_HOLDER_BOUND_KEYS_V2;

const SOURCE_REPOSITORY_CHECKPOINT_KEYS = Object.freeze([
  'artifact_set_manifest_schema_contract_sha256',
  'authorization_file_path',
  'authorization_file_sha256',
  'checkpoint_type',
  'checkpoint_version',
  'git_index_entries_sha256',
  'git_index_flags_sha256',
  'git_metadata_files',
  'git_object_format',
  'git_status_porcelain_sha256',
  'head_tree_oid',
  'hidden_index_flags_present',
  'no_reexecution_call_graph_sha256',
  'repository_id',
  'repository_realpath',
  'required_file_count',
  'required_files',
  'required_files_manifest_sha256',
  'service_artifact_schema_contract_sha256',
  'source_commit_oid',
  'source_precondition_file_sha256',
  'source_precondition_path',
  'source_precondition_sha256',
  'source_repository_checkpoint_body_sha256',
  'source_worktree_clean',
  'terminal_artifact_schema_contract_sha256',
]);

const SOURCE_REPOSITORY_CHECKPOINT_FILE_KEYS = Object.freeze([
  'byte_length',
  'git_mode',
  'head_blob_oid',
  'head_blob_sha256',
  'index_blob_oid',
  'path',
  'worktree_sha256',
]);

const SOURCE_REPOSITORY_CHECKPOINT_METADATA_KEYS = Object.freeze([
  'byte_length',
  'file_mode',
  'path',
  'sha256',
]);

const CEREMONY_AUTHORIZATION_KEYS = Object.freeze([
  'activation_nonce',
  'activation_record_body_sha256',
  'activation_record_file_sha256',
  'authorization_file_path',
  'authorization_file_sha256',
  'authorization_mode',
  'brokered_holder_key_generation_claim_body_sha256',
  'brokered_holder_key_generation_claim_file_sha256',
  'brokered_holder_key_generation_claim_ordinal',
  'brokered_holder_key_generation_claimed_at_epoch',
  'consequence_execution_authorized',
  'control_tower_activation_first_observed_at_epoch',
  'controller_capability_generation_admission_body_sha256',
  'controller_capability_generation_admission_file_sha256',
  'holder_claim_capability_sha256',
  'holder_claim_request_body_sha256',
  'holder_instance_nonce',
  'holder_launch_capability_sha256',
  'key_generation_attempt_body_sha256',
  'key_generation_attempt_file_sha256',
  'key_generation_call_observed_at_epoch',
  'keypair_limit',
  'receipt_signing_authorized',
]);

const HOLDER_TRANSPORT_DESCRIPTOR_SHAPE_KEYS = Object.freeze([
  'all_non_tty',
  'brokered_claim_path_fs_write_permission',
  'fs_write_permission_any',
  'node_permission_model_enabled',
  'runtime_scope',
  'stderr_fd_type',
  'stdin_fd_type',
  'stdout_fd_type',
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

function assertSha256(label, value) {
  if (!SHA256_RE.test(value || '')) {
    throw new Error(`${label} must be lowercase SHA-256 hex`);
  }
}

function assertEqual(label, expected, actual) {
  if (canonicalize(actual) !== canonicalize(expected)) {
    throw new Error(`${label} mismatch`);
  }
}

function assertSafeNonnegativeInteger(label, value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a nonnegative safe integer`);
  }
}

function sha256WithoutField(value, field) {
  const body = { ...requireObject('SHA-256 body', value) };
  delete body[field];
  return sha256hex(canonicalize(body));
}

function sourceCompletenessPaths(sourcePrecondition) {
  const manifest = requireObject(
    'Protected records replacement source completeness manifest',
    sourcePrecondition.source_completeness_manifest,
  );
  return [...new Set(
    Object.values(manifest).filter((value) => typeof value === 'string'),
  )].sort();
}

function assertSourceRepositoryCheckpointV2({
  packet,
  requiredManifestSchemaSha256,
  sourceCommitOid,
  sourceRepositoryRealpath,
}) {
  const checkpoint = packet.source_repository_checkpoint;
  assertExactKeys(
    'Protected records replacement source repository checkpoint',
    checkpoint,
    SOURCE_REPOSITORY_CHECKPOINT_KEYS,
  );
  const checkpointBodySha256 = sha256WithoutField(
    checkpoint,
    'source_repository_checkpoint_body_sha256',
  );
  for (const [label, value] of [
    ['checkpoint body', checkpoint.source_repository_checkpoint_body_sha256],
    ['packet checkpoint body', packet.source_repository_checkpoint_body_sha256],
    [
      'transport checkpoint body',
      packet.transport_precondition?.source_repository_checkpoint_body_sha256,
    ],
    [
      'no-reexecution checkpoint body',
      packet.no_reexecution_binding?.source_repository_checkpoint_body_sha256,
    ],
  ]) {
    assertSha256(`Protected records replacement ${label}`, value);
    if (value !== checkpointBodySha256) {
      throw new Error(
        'Protected records replacement source repository checkpoint identity mismatch',
      );
    }
  }
  if (
    checkpoint.checkpoint_type !== 'zlar.source-repository-checkpoint.v1' ||
    checkpoint.checkpoint_version !== 1 ||
    checkpoint.repository_id !== packet.source_precondition.repository_id ||
    checkpoint.repository_realpath !== sourceRepositoryRealpath ||
    checkpoint.git_object_format !== packet.source_precondition.git_object_format ||
    checkpoint.source_commit_oid !== sourceCommitOid ||
    checkpoint.source_commit_oid !== packet.source_precondition.source_commit_oid ||
    checkpoint.source_worktree_clean !== true ||
    checkpoint.hidden_index_flags_present !== false ||
    checkpoint.git_status_porcelain_sha256 !== sha256hex('') ||
    checkpoint.authorization_file_path !==
      packet.ceremony_authorization.authorization_file_path ||
    checkpoint.authorization_file_sha256 !==
      packet.ceremony_authorization.authorization_file_sha256 ||
    checkpoint.source_precondition_file_sha256 !==
      packet.transport_precondition.source_precondition_file_sha256 ||
    checkpoint.source_precondition_sha256 !== packet.source_precondition_sha256 ||
    checkpoint.service_artifact_schema_contract_sha256 !==
      packet.source_precondition.service_artifact_schema_contract_sha256 ||
    checkpoint.terminal_artifact_schema_contract_sha256 !==
      packet.source_precondition.terminal_artifact_schema_contract_sha256 ||
    checkpoint.artifact_set_manifest_schema_contract_sha256 !==
      requiredManifestSchemaSha256 ||
    checkpoint.no_reexecution_call_graph_sha256 !==
      packet.source_precondition.no_reexecution_call_graph_sha256
  ) {
    throw new Error(
      'Protected records replacement source repository checkpoint binding mismatch',
    );
  }
  for (const [label, value] of [
    ['checkpoint Git index entries', checkpoint.git_index_entries_sha256],
    ['checkpoint Git index flags', checkpoint.git_index_flags_sha256],
    ['checkpoint tree', checkpoint.head_tree_oid],
    ['checkpoint source precondition file', checkpoint.source_precondition_file_sha256],
    ['checkpoint required-files manifest', checkpoint.required_files_manifest_sha256],
  ]) {
    if (label === 'checkpoint tree') {
      if (!GIT_SHA1_RE.test(value || '')) {
        throw new Error(`Protected records replacement ${label} malformed`);
      }
    } else {
      assertSha256(`Protected records replacement ${label}`, value);
    }
  }
  if (
    typeof checkpoint.source_precondition_path !== 'string' ||
    !checkpoint.source_precondition_path.startsWith('/') ||
    !Array.isArray(checkpoint.required_files) ||
    checkpoint.required_files.length === 0 ||
    checkpoint.required_file_count !== checkpoint.required_files.length ||
    sha256hex(canonicalize(checkpoint.required_files)) !==
      checkpoint.required_files_manifest_sha256
  ) {
    throw new Error(
      'Protected records replacement source repository checkpoint manifest mismatch',
    );
  }
  const requiredPaths = [];
  for (const entry of checkpoint.required_files) {
    assertExactKeys(
      'Protected records replacement checkpoint required file',
      entry,
      SOURCE_REPOSITORY_CHECKPOINT_FILE_KEYS,
    );
    assertSafeNonnegativeInteger(
      'Protected records replacement checkpoint required file byte length',
      entry.byte_length,
    );
    if (
      typeof entry.path !== 'string' ||
      entry.path.length === 0 ||
      !/^[0-7]{6}$/.test(entry.git_mode || '') ||
      !GIT_SHA1_RE.test(entry.head_blob_oid || '') ||
      entry.index_blob_oid !== entry.head_blob_oid ||
      !SHA256_RE.test(entry.head_blob_sha256 || '') ||
      entry.worktree_sha256 !== entry.head_blob_sha256
    ) {
      throw new Error(
        'Protected records replacement checkpoint required file identity mismatch',
      );
    }
    requiredPaths.push(entry.path);
  }
  if (
    canonicalize([...requiredPaths].sort()) !==
      canonicalize(sourceCompletenessPaths(packet.source_precondition))
  ) {
    throw new Error(
      'Protected records replacement checkpoint required source paths mismatch',
    );
  }
  if (!Array.isArray(checkpoint.git_metadata_files) || checkpoint.git_metadata_files.length < 2) {
    throw new Error('Protected records replacement checkpoint Git metadata missing');
  }
  for (const metadata of checkpoint.git_metadata_files) {
    assertExactKeys(
      'Protected records replacement checkpoint Git metadata file',
      metadata,
      SOURCE_REPOSITORY_CHECKPOINT_METADATA_KEYS,
    );
    assertSafeNonnegativeInteger(
      'Protected records replacement checkpoint Git metadata byte length',
      metadata.byte_length,
    );
    if (
      typeof metadata.path !== 'string' ||
      !metadata.path.startsWith(`${sourceRepositoryRealpath}/.git/`) ||
      !/^[0-7]{3,4}$/.test(metadata.file_mode || '') ||
      !SHA256_RE.test(metadata.sha256 || '')
    ) {
      throw new Error(
        'Protected records replacement checkpoint Git metadata identity mismatch',
      );
    }
  }
}

function assertHolderBoundProducerConsumerParityV2({
  packet,
  holderBound,
  requiredHolderBoundSha256,
  requiredPacketSha256,
}) {
  const authorization = packet.ceremony_authorization;
  const transport = packet.transport_precondition;
  assertExactKeys(
    'Protected records replacement ceremony authorization',
    authorization,
    CEREMONY_AUTHORIZATION_KEYS,
  );
  for (const [label, value] of [
    ['authorization file', authorization.authorization_file_sha256],
    ['activation nonce', authorization.activation_nonce],
    ['activation record body', authorization.activation_record_body_sha256],
    ['activation record file', authorization.activation_record_file_sha256],
    [
      'controller admission body',
      authorization.controller_capability_generation_admission_body_sha256,
    ],
    [
      'controller admission file',
      authorization.controller_capability_generation_admission_file_sha256,
    ],
    ['key-generation attempt body', authorization.key_generation_attempt_body_sha256],
    ['key-generation attempt file', authorization.key_generation_attempt_file_sha256],
    ['holder launch capability', authorization.holder_launch_capability_sha256],
    ['holder claim capability', authorization.holder_claim_capability_sha256],
    ['holder claim request', authorization.holder_claim_request_body_sha256],
    ['holder instance nonce', authorization.holder_instance_nonce],
    [
      'brokered holder claim body',
      authorization.brokered_holder_key_generation_claim_body_sha256,
    ],
    [
      'brokered holder claim file',
      authorization.brokered_holder_key_generation_claim_file_sha256,
    ],
  ]) {
    assertSha256(`Protected records replacement ${label}`, value);
  }
  if (
    typeof authorization.authorization_file_path !== 'string' ||
    !authorization.authorization_file_path.startsWith('/') ||
    typeof authorization.authorization_mode !== 'string' ||
    authorization.authorization_mode.length === 0 ||
    authorization.keypair_limit !== 1 ||
    authorization.receipt_signing_authorized !== false ||
    authorization.consequence_execution_authorized !== false ||
    authorization.brokered_holder_key_generation_claim_ordinal !== 1
  ) {
    throw new Error(
      'Protected records replacement ceremony authorization boundary mismatch',
    );
  }
  const exactAuthorizationBindings = [
    ['activation_nonce', 'activation_nonce'],
    ['activation_record_body_sha256', 'activation_record_body_sha256'],
    ['activation_record_file_sha256', 'activation_record_file_sha256'],
    [
      'control_tower_activation_first_observed_at_epoch',
      'control_tower_activation_first_observed_at_epoch',
    ],
    [
      'controller_capability_generation_admission_body_sha256',
      'controller_capability_generation_admission_body_sha256',
    ],
    [
      'controller_capability_generation_admission_file_sha256',
      'controller_capability_generation_admission_file_sha256',
    ],
    ['key_generation_attempt_body_sha256', 'key_generation_attempt_body_sha256'],
    ['key_generation_attempt_file_sha256', 'key_generation_attempt_file_sha256'],
    ['holder_launch_capability_sha256', 'holder_launch_capability_sha256'],
    ['holder_claim_capability_sha256', 'holder_claim_capability_sha256'],
    ['holder_claim_request_body_sha256', 'holder_claim_request_body_sha256'],
    ['holder_instance_nonce', 'holder_instance_nonce'],
    [
      'brokered_holder_key_generation_claim_body_sha256',
      'brokered_holder_key_generation_claim_body_sha256',
    ],
    [
      'brokered_holder_key_generation_claim_file_sha256',
      'brokered_holder_key_generation_claim_file_sha256',
    ],
    [
      'brokered_holder_key_generation_claimed_at_epoch',
      'brokered_holder_key_generation_claimed_at_epoch',
    ],
    [
      'brokered_holder_key_generation_claim_ordinal',
      'brokered_holder_key_generation_claim_ordinal',
    ],
    ['key_generation_call_observed_at_epoch', 'key_generation_call_observed_at_epoch'],
  ];
  for (const [holderField, authorizationField] of exactAuthorizationBindings) {
    if (holderBound[holderField] !== authorization[authorizationField]) {
      throw new Error(
        `Protected records replacement holder authorization binding mismatch: ${holderField}`,
      );
    }
  }
  if (
    holderBound.ceremony_authorization_sha256 !==
      authorization.authorization_file_sha256 ||
    holderBound.canonical_packet_body_length !==
      Buffer.byteLength(canonicalize(packet), 'utf8') ||
    holderBound.packet_body_sha256 !== requiredPacketSha256
  ) {
    throw new Error('Protected records replacement holder packet binding mismatch');
  }
  const exactTransportBindings = [
    ['active_turn_user_steer_evidence_body_sha256', 'active_turn_user_steer_evidence_body_sha256'],
    ['active_turn_user_steer_evidence_file_sha256', 'active_turn_user_steer_evidence_file_sha256'],
    ['controller_source_sha256', 'controller_source_sha256'],
    ['dry_run_evidence_body_sha256', 'packet_builder_dry_run_evidence_body_sha256'],
    ['dry_run_harness_source_sha256', 'dry_run_harness_source_sha256'],
    ['failed_ceremony_deny_set_body_sha256', 'failed_ceremony_deny_set_body_sha256'],
    ['failed_ceremony_deny_set_source_sha256', 'failed_ceremony_deny_set_source_sha256'],
    ['failed_ceremony_family_count', 'failed_ceremony_family_count'],
    ['frame_codec_source_sha256', 'frame_codec_source_sha256'],
    ['frame_protocol', 'frame_protocol'],
    ['holder_source_sha256', 'holder_source_sha256'],
    ['inner_harness_source_sha256', 'inner_harness_source_sha256'],
    ['inner_rehearsal_evidence_body_sha256', 'inner_rehearsal_evidence_body_sha256'],
    ['outer_controller_rehearsal_evidence_body_sha256', 'outer_controller_rehearsal_evidence_body_sha256'],
    ['packet_builder_source_sha256', 'packet_builder_source_sha256'],
    ['source_checkpoint_evidence_body_sha256', 'source_checkpoint_evidence_body_sha256'],
    ['source_checkpoint_evidence_sha256', 'source_checkpoint_evidence_file_sha256'],
    ['source_checkpoint_harness_source_sha256', 'source_checkpoint_harness_source_sha256'],
    ['source_precondition_file_sha256', 'source_precondition_file_sha256'],
    ['source_repository_checkpoint_body_sha256', 'source_repository_checkpoint_body_sha256'],
  ];
  for (const [holderField, transportField] of exactTransportBindings) {
    if (holderBound[holderField] !== transport[transportField]) {
      throw new Error(
        `Protected records replacement holder transport binding mismatch: ${holderField}`,
      );
    }
  }
  assertExactKeys(
    'Protected records replacement holder transport descriptor shape',
    holderBound.transport_descriptor_shape,
    HOLDER_TRANSPORT_DESCRIPTOR_SHAPE_KEYS,
  );
  assertEqual(
    'Protected records replacement holder transport descriptor shape',
    {
      all_non_tty: true,
      brokered_claim_path_fs_write_permission: false,
      fs_write_permission_any: false,
      node_permission_model_enabled: true,
      runtime_scope: 'this-macos-node-runtime',
      stderr_fd_type: 'socket',
      stdin_fd_type: 'socket',
      stdout_fd_type: 'socket',
    },
    holderBound.transport_descriptor_shape,
  );
  for (const [label, value] of [
    ['holder bind frame', holderBound.bind_frame_sha256],
    ['holder bind nonce', holderBound.bind_nonce],
    ['holder-bound identity', holderBound.holder_bound_body_sha256],
    ['required holder-bound identity', requiredHolderBoundSha256],
  ]) {
    assertSha256(`Protected records replacement ${label}`, value);
  }
  const holderBoundBodySha256 = sha256WithoutField(
    holderBound,
    'holder_bound_body_sha256',
  );
  if (
    holderBoundBodySha256 !== requiredHolderBoundSha256 ||
    holderBound.holder_bound_body_sha256 !== requiredHolderBoundSha256
  ) {
    throw new Error('Protected records replacement holder-bound identity mismatch');
  }
  for (const [label, value] of [
    [
      'Control Tower activation first-observed epoch',
      authorization.control_tower_activation_first_observed_at_epoch,
    ],
    [
      'brokered holder claim epoch',
      authorization.brokered_holder_key_generation_claimed_at_epoch,
    ],
    ['key-generation call epoch', authorization.key_generation_call_observed_at_epoch],
    ['holder bound epoch', holderBound.bound_at_epoch],
  ]) {
    assertSafeNonnegativeInteger(`Protected records replacement ${label}`, value);
  }
  if (
    authorization.control_tower_activation_first_observed_at_epoch >
      authorization.brokered_holder_key_generation_claimed_at_epoch ||
    authorization.brokered_holder_key_generation_claimed_at_epoch !==
      authorization.key_generation_call_observed_at_epoch ||
    holderBound.bound_at_epoch < authorization.key_generation_call_observed_at_epoch ||
    holderBound.bound_at_epoch >= packet.grant_contract.time_policy.valid_from_epoch
  ) {
    throw new Error('Protected records replacement holder chronology mismatch');
  }
}

export function assertProtectedRecordsReplacementSignedReceiptEnvelopeProjectionV2({
  appointedIssuerKid,
  signedReceipt,
  unsignedReceipt,
  unsignedReceiptEnvelopeSha256,
} = {}) {
  const receiptEnvelopeKeys = [
    'iat', 'id', 'kid', 'payload', 'prev', 'sig', 'type', 'v',
  ];
  assertExactKeys(
    'Protected records replacement unsigned receipt envelope',
    unsignedReceipt,
    receiptEnvelopeKeys,
  );
  assertExactKeys(
    'Protected records replacement signed receipt envelope',
    signedReceipt,
    receiptEnvelopeKeys,
  );
  assertSha256(
    'Protected records replacement unsigned receipt envelope identity',
    unsignedReceiptEnvelopeSha256,
  );
  if (
    sha256hex(canonicalize(unsignedReceipt)) !==
      unsignedReceiptEnvelopeSha256 ||
    unsignedReceipt.kid !== '' ||
    unsignedReceipt.sig !== '' ||
    typeof appointedIssuerKid !== 'string' ||
    appointedIssuerKid.length === 0 ||
    signedReceipt.kid !== appointedIssuerKid ||
    typeof signedReceipt.sig !== 'string' ||
    signedReceipt.sig.length === 0 ||
    ['iat', 'id', 'payload', 'prev', 'type', 'v'].some(
      (field) =>
        canonicalize(signedReceipt[field]) !==
        canonicalize(unsignedReceipt[field]),
    )
  ) {
    throw new Error(
      'Protected records replacement signed receipt identity or unsigned-envelope projection mismatch',
    );
  }
  return true;
}

function expectedCrossingOptions(crossingInputs) {
  return Object.fromEntries(
    Object.entries(crossingInputs).map(([key, value]) => [
      `expected${key[0].toUpperCase()}${key.slice(1)}`,
      value,
    ]),
  );
}

function validateSourceBinding({
  packet,
  requiredManifestSchemaSha256,
  sourceCommitOid,
  sourceRepositoryRealpath,
  sourceWorktreeClean,
}) {
  if (sourceWorktreeClean !== true) {
    throw new Error('Replacement crossing requires the exact clean source commit');
  }
  if (!GIT_SHA1_RE.test(sourceCommitOid || '')) {
    throw new Error('Replacement crossing source commit must be a Git SHA-1 object id');
  }
  if (
    typeof sourceRepositoryRealpath !== 'string' ||
    !sourceRepositoryRealpath.startsWith('/')
  ) {
    throw new Error('Replacement crossing source repository realpath is invalid');
  }
  const source = packet.source_precondition;
  if (source.source_commit_oid !== sourceCommitOid) {
    throw new Error('Replacement crossing source commit does not match the packet');
  }
  assertSourceRepositoryCheckpointV2({
    packet,
    requiredManifestSchemaSha256,
    sourceCommitOid,
    sourceRepositoryRealpath,
  });
  const currentServiceSchema =
    protectedRecordsReplacementServiceArtifactSchemaContractSha256V2();
  const currentTerminalSchema =
    protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2();
  const currentCallGraph =
    protectedRecordsReplacementNoReexecutionCallGraphSha256V2(
      protectedRecordsReplacementNoReexecutionCallGraphDescriptorV2(),
    );
  const currentManifestSchema =
    protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2();
  for (const [label, expected, actual] of [
    ['service schema', currentServiceSchema, source.service_artifact_schema_contract_sha256],
    ['terminal schema', currentTerminalSchema, source.terminal_artifact_schema_contract_sha256],
    ['no-reexecution call graph', currentCallGraph, source.no_reexecution_call_graph_sha256],
    ['manifest schema', currentManifestSchema, requiredManifestSchemaSha256],
    [
      'packet manifest schema',
      currentManifestSchema,
      packet.no_reexecution_binding?.artifact_set_manifest_schema_contract_sha256,
    ],
  ]) {
    if (actual !== expected) throw new Error(`Replacement crossing ${label} mismatch`);
  }
  const noReexecution = packet.no_reexecution_binding;
  for (const [label, expected, actual] of [
    ['repository', source.repository_id, noReexecution.repository_id],
    ['Git object format', source.git_object_format, noReexecution.git_object_format],
    ['source commit', source.source_commit_oid, noReexecution.source_commit_oid],
    [
      'service schema projection',
      source.service_artifact_schema_contract_sha256,
      noReexecution.service_artifact_schema_contract_sha256,
    ],
    [
      'terminal schema projection',
      source.terminal_artifact_schema_contract_sha256,
      noReexecution.terminal_artifact_schema_contract_sha256,
    ],
    [
      'call graph projection',
      source.no_reexecution_call_graph_sha256,
      noReexecution.no_reexecution_call_graph_sha256,
    ],
    [
      'source precondition projection',
      packet.source_precondition_sha256,
      noReexecution.source_precondition_sha256,
    ],
  ]) {
    if (actual !== expected) {
      throw new Error(`Replacement crossing ${label} mismatch`);
    }
  }
  if (noReexecution.post_effect_outputs_absent !== true) {
    throw new Error('Replacement crossing packet falsely predeclares post-effect output');
  }
  const completeness = source.source_completeness_manifest;
  if (
    completeness.replacement_crossing_driver_cli_source_path !==
      'bin/zlar-protected-records-replacement-crossing-v2' ||
    completeness.replacement_crossing_driver_cli_implementation_source_path !==
      'lib/protected-records-replacement-crossing-cli-v2.mjs' ||
    completeness.replacement_crossing_driver_library_source_path !==
      'lib/protected-records-replacement-crossing-driver-v2.mjs' ||
    completeness.replacement_hash_utility_source_path !== 'lib/sha256.mjs' ||
    completeness.replacement_runtime_service_child_source_path !==
      'lib/protected-records-replacement-runtime-child-v2.mjs' ||
    completeness.replacement_source_snapshot_boundary_source_path !==
      'lib/protected-records-replacement-source-snapshot-v2.mjs' ||
    completeness.replacement_artifact_verifier_source_path !==
      'bin/zlar-protected-records-replacement-artifact-set-v2'
  ) {
    throw new Error('Replacement crossing operational source manifest is incomplete');
  }
  assertProtectedRecordsRuntimeTargetBinding(packet.target_binding);
  assertProtectedRecordsFixtureAuthorityScopeEvidenceV2(
    packet.scope_evidence,
    packet.grant_contract,
  );
}

export function validateProtectedRecordsReplacementCrossingAuthorityV2(params) {
  assertExactKeys(
    'Protected records replacement crossing authority input',
    params,
    [
      'holderSignedOnce',
      'holderBound',
      'observedEpoch',
      'packet',
      'requiredGrantSha256',
      'requiredHolderBoundSha256',
      'requiredHolderSignedOnceSha256',
      'requiredManifestSchemaSha256',
      'requiredPacketSha256',
      'sourceCommitOid',
      'sourceRepositoryRealpath',
      'sourceWorktreeClean',
    ],
  );
  const {
    packet,
    holderSignedOnce,
    holderBound,
    requiredPacketSha256,
    requiredGrantSha256,
    requiredHolderBoundSha256,
    requiredHolderSignedOnceSha256,
    requiredManifestSchemaSha256,
    observedEpoch,
    sourceCommitOid,
    sourceRepositoryRealpath,
    sourceWorktreeClean,
  } = params;
  assertExactKeys('Protected records replacement packet', packet, PACKET_KEYS);
  assertExactKeys(
    'Protected records replacement holder-signed-once event',
    holderSignedOnce,
    HOLDER_SIGNED_ONCE_KEYS,
  );
  assertExactKeys(
    'Protected records replacement holder-bound event',
    holderBound,
    HOLDER_BOUND_KEYS,
  );
  for (const [label, value] of [
    ['required packet', requiredPacketSha256],
    ['required grant', requiredGrantSha256],
    ['required holder-bound', requiredHolderBoundSha256],
    ['required holder-signed-once', requiredHolderSignedOnceSha256],
    ['required manifest schema', requiredManifestSchemaSha256],
  ]) {
    assertSha256(`Protected records replacement ${label}`, value);
  }
  if (!Number.isSafeInteger(observedEpoch) || observedEpoch < 0) {
    throw new Error('Protected records replacement observed epoch is invalid');
  }
  if (
    sha256hex(canonicalize(holderSignedOnce)) !==
    requiredHolderSignedOnceSha256
  ) {
    throw new Error(
      'Protected records replacement holder-signed-once identity mismatch',
    );
  }
  if (
    packet.packet_type !==
      'zlar.protected-records.replacement-post-hardening-authorization-packet.v2' ||
    packet.packet_version !== 2
  ) {
    throw new Error('Protected records replacement packet type drifted');
  }
  const packetSha256 = sha256hex(canonicalize(packet));
  if (
    packetSha256 !== requiredPacketSha256 ||
    holderSignedOnce.packet_body_sha256 !== requiredPacketSha256
  ) {
    throw new Error('Protected records replacement packet identity mismatch');
  }
  const holderBoundBody = { ...holderBound };
  delete holderBoundBody.holder_bound_body_sha256;
  const computedHolderBoundSha256 = sha256hex(canonicalize(holderBoundBody));
  if (
    holderBound.holder_bound_body_sha256 !== requiredHolderBoundSha256 ||
    computedHolderBoundSha256 !== requiredHolderBoundSha256 ||
    holderBound.event !== 'holder_bound' ||
    holderBound.holder_protocol !== 'zlar-ephemeral-issuer-holder-v1' ||
    holderBound.key_generation_count !== 1 ||
    holderBound.private_key_exported !== false ||
    holderBound.private_key_extractable !== false ||
    holderBound.packet_body_sha256 !== requiredPacketSha256 ||
    holderBound.grant_contract_sha256 !== requiredGrantSha256
  ) {
    throw new Error('Protected records replacement holder-bound identity mismatch');
  }
  assertHolderBoundProducerConsumerParityV2({
    packet,
    holderBound,
    requiredHolderBoundSha256,
    requiredPacketSha256,
  });
  assertProtectedRecordsFixtureAuthoritySourcePreconditionV2(
    packet.source_precondition,
  );
  if (
    protectedRecordsFixtureAuthoritySourcePreconditionBodySha256V2(
      packet.source_precondition,
    ) !== packet.source_precondition_sha256
  ) {
    throw new Error('Protected records replacement source precondition identity mismatch');
  }
  const issuerBindingSha256 =
    protectedRecordsFixtureAuthorityIssuerBindingSha256V2(
      packet.appointment,
      {
        contract: packet.grant_contract,
        expectedContractSha256: requiredGrantSha256,
      },
    );
  const publicIdentity = packet.public_issuer_identity;
  const recognizedIssuer = packet.recognition_rule?.accepted_issuers?.[0];
  if (
    issuerBindingSha256 !== packet.issuer_binding_sha256 ||
    holderBound.issuer_binding_sha256 !== packet.issuer_binding_sha256 ||
    holderBound.appointment_sha256 !== packet.appointment_sha256 ||
    holderBound.authorized_effect_detail_sha256 !==
      packet.authorized_effect_detail_sha256 ||
    holderBound.receipt_payload_sha256 !== packet.receipt_payload_sha256 ||
    holderBound.issuer_kid !== packet.appointment.issuer_kid ||
    holderBound.public_key_sha256 !== packet.appointment.public_key_sha256 ||
    holderBound.no_confirmation_destruction_deadline_epoch !==
      packet.grant_contract.time_policy.valid_from_epoch ||
    publicIdentity.ceremony_id !== holderBound.ceremony_id ||
    publicIdentity.issuer_kid !== packet.appointment.issuer_kid ||
    publicIdentity.issuer_slot !== packet.appointment.issuer_slot ||
    publicIdentity.public_key_sha256 !== packet.appointment.public_key_sha256 ||
    publicIdentity.public_key_pem !== recognizedIssuer?.public_key_pem ||
    publicIdentity.private_key_exported !== false ||
    publicIdentity.private_key_extractable !== false
  ) {
    throw new Error('Protected records replacement issuer or holder binding mismatch');
  }
  assertProtectedRecordsFixtureAuthorityGrantContractV2(packet.grant_contract, {
    expectedContractSha256: requiredGrantSha256,
  });
  if (
    packet.grant_contract_sha256 !== requiredGrantSha256 ||
    protectedRecordsFixtureAuthorityGrantContractSha256V2(
      packet.grant_contract,
    ) !== requiredGrantSha256 ||
    packet.grant_contract.time_policy.clock_source !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2
  ) {
    throw new Error('Protected records replacement grant identity or clock mismatch');
  }
  assertProtectedRecordsFixtureAuthorityAppointmentV2(packet.appointment, {
    contract: packet.grant_contract,
    expectedContractSha256: requiredGrantSha256,
  });
  if (
    protectedRecordsFixtureAuthorityAppointmentSha256V2(packet.appointment, {
      contract: packet.grant_contract,
      expectedContractSha256: requiredGrantSha256,
    }) !== packet.appointment_sha256
  ) {
    throw new Error('Protected records replacement appointment identity mismatch');
  }
  assertProtectedRecordsFixtureAuthorityExactConfirmationV2(
    holderSignedOnce.confirmation,
    {
      contract: packet.grant_contract,
      expectedContractSha256: requiredGrantSha256,
      appointment: packet.appointment,
    },
  );
  const confirmationSha256 =
    protectedRecordsFixtureAuthorityExactConfirmationSha256V2(
      holderSignedOnce.confirmation,
      {
        contract: packet.grant_contract,
        expectedContractSha256: requiredGrantSha256,
        appointment: packet.appointment,
      },
    );
  if (
    confirmationSha256 !== holderSignedOnce.confirmation_sha256 ||
    holderSignedOnce.confirmation.post_hardening_authorization_packet_body_sha256 !==
      requiredPacketSha256
  ) {
    throw new Error('Protected records replacement confirmation identity mismatch');
  }
  assertProtectedRecordsFixtureAuthorityStatusV2(
    holderSignedOnce.authority_status,
    {
      contract: packet.grant_contract,
      expectedContractSha256: requiredGrantSha256,
      appointment: packet.appointment,
      confirmation: holderSignedOnce.confirmation,
    },
  );
  const statusSha256 = protectedRecordsFixtureAuthorityStatusSha256V2(
    holderSignedOnce.authority_status,
    {
      contract: packet.grant_contract,
      expectedContractSha256: requiredGrantSha256,
      appointment: packet.appointment,
      confirmation: holderSignedOnce.confirmation,
    },
  );
  if (
    statusSha256 !== holderSignedOnce.authority_status_sha256 ||
    holderSignedOnce.authority_status.status !== 'active' ||
    holderSignedOnce.authority_status.fresh_effect_allowed !== true ||
    holderSignedOnce.authority_status.recorded_effect_uses !== 0
  ) {
    throw new Error('Protected records replacement authority status is not fresh');
  }
  assertProtectedRecordsFixtureAuthorityDecisionV2(
    holderSignedOnce.issuance_decision,
  );
  if (
    holderSignedOnce.issuance_decision.phase !== 'issuance' ||
    holderSignedOnce.issuance_decision.decision !== 'accept'
  ) {
    throw new Error('Protected records replacement issuance decision is not accepted');
  }
  assertProtectedRecordsAuthorizedEffectDetailV2(
    packet.authorized_effect_detail,
    {
      contract: packet.grant_contract,
      expectedContractSha256: requiredGrantSha256,
    },
  );
  if (
    protectedRecordsAuthorizedEffectDetailSha256V2(
      packet.authorized_effect_detail,
      {
        contract: packet.grant_contract,
        expectedContractSha256: requiredGrantSha256,
      },
    ) !== packet.authorized_effect_detail_sha256
  ) {
    throw new Error('Protected records replacement effect identity mismatch');
  }
  const runtimeContext = createProtectedRecordsRuntimeAuthorityContextV2({
    actionClass: packet.grant_contract.scope.action_class,
    authorizedRecordUpdate: packet.record_update,
    authorityGrantAppointment: packet.appointment,
    authorityGrantConfirmation: holderSignedOnce.confirmation,
    authorityGrantContract: packet.grant_contract,
    authorityGrantExpectedContractSha256: requiredGrantSha256,
    authorityGrantIssuanceDecision: holderSignedOnce.issuance_decision,
    authorityGrantStatus: holderSignedOnce.authority_status,
    profileId: packet.grant_contract.scope.runtime_profile_id,
    recognitionRule: packet.recognition_rule,
    sourcePrecondition: packet.source_precondition,
    targetBinding: packet.target_binding,
  });
  assertEqual(
    'Protected records replacement scope evidence',
    runtimeContext.scopeEvidence,
    packet.scope_evidence,
  );
  assertEqual(
    'Protected records replacement target effect',
    runtimeContext.targetEffect,
    packet.target_effect,
  );
  assertEqual(
    'Protected records replacement authorized effect detail',
    runtimeContext.authorizedEffectDetail,
    packet.authorized_effect_detail,
  );
  const confirmationRelayInputs =
    protectedRecordsReplacementConfirmationRelayInputsV2({
      confirmationConfirmedAtEpoch:
        holderSignedOnce.confirmation.confirmed_at_epoch,
      holderObservedConfirmationEpoch:
        holderSignedOnce.holder_observed_confirmation_epoch,
    });
  for (const [label, value] of [
    [
      'holder-observed signing milliseconds',
      holderSignedOnce.holder_observed_signing_milliseconds,
    ],
    [
      'signing-window early wakeup count',
      holderSignedOnce.signing_window_early_wakeup_count,
    ],
    [
      'signing-window early wakeup limit',
      holderSignedOnce.signing_window_early_wakeup_limit,
    ],
    [
      'signing-window timer guard milliseconds',
      holderSignedOnce.signing_window_timer_guard_milliseconds,
    ],
  ]) {
    assertSafeNonnegativeInteger(`Protected records replacement ${label}`, value);
  }
  if (
    holderSignedOnce.event !== 'holder_signed_once' ||
    holderSignedOnce.ceremony_id !== holderBound.ceremony_id ||
    holderSignedOnce.holder_protocol !== holderBound.holder_protocol ||
    holderSignedOnce.key_generation_count !== 1 ||
    holderSignedOnce.signing_attempt_count !== 1 ||
    holderSignedOnce.private_key_exported !== false ||
    holderSignedOnce.cryptographic_erasure_proven !== false ||
    holderSignedOnce.process_exit_releases_address_space_best_effort !== true ||
    holderSignedOnce.control_tower_confirmation_relay_delay_seconds !==
      confirmationRelayInputs.controlTowerConfirmationRelayDelaySeconds ||
    holderSignedOnce.control_tower_confirmation_relay_max_seconds !==
      confirmationRelayInputs.controlTowerConfirmationRelayMaxSeconds ||
    holderSignedOnce.confirmation.confirmed_at_epoch >=
      packet.grant_contract.time_policy.valid_from_epoch ||
    holderSignedOnce.holder_observed_confirmation_epoch >
      packet.grant_contract.time_policy.valid_from_epoch ||
    holderSignedOnce.holder_observed_confirmation_epoch >
      holderSignedOnce.holder_observed_signing_epoch ||
    holderSignedOnce.holder_observed_signing_epoch <
      packet.grant_contract.time_policy.valid_from_epoch ||
    holderSignedOnce.holder_observed_signing_epoch >=
      packet.grant_contract.time_policy.expires_at_epoch ||
    holderSignedOnce.holder_observed_signing_epoch !==
      holderSignedOnce.signed_receipt.iat ||
    Math.floor(holderSignedOnce.holder_observed_signing_milliseconds / 1000) !==
      holderSignedOnce.holder_observed_signing_epoch ||
    holderSignedOnce.signing_window_early_wakeup_limit !== 8 ||
    holderSignedOnce.signing_window_early_wakeup_count >
      holderSignedOnce.signing_window_early_wakeup_limit ||
    holderSignedOnce.signing_window_timer_guard_milliseconds !== 1
  ) {
    throw new Error('Protected records replacement holder event is not single-use');
  }
  const signedReceiptSha256 = sha256hex(
    canonicalize(holderSignedOnce.signed_receipt),
  );
  assertProtectedRecordsReplacementSignedReceiptEnvelopeProjectionV2({
    appointedIssuerKid: packet.appointment.issuer_kid,
    signedReceipt: holderSignedOnce.signed_receipt,
    unsignedReceipt: packet.unsigned_receipt,
    unsignedReceiptEnvelopeSha256:
      packet.unsigned_receipt_envelope_sha256,
  });
  if (
    signedReceiptSha256 !== holderSignedOnce.signed_receipt_sha256 ||
    holderSignedOnce.receipt_payload_sha256 !== packet.receipt_payload_sha256
  ) {
    throw new Error('Protected records replacement signed receipt identity mismatch');
  }
  const issuer = packet.recognition_rule?.accepted_issuers?.[0];
  const receiptVerification = verifyReceiptV1(
    holderSignedOnce.signed_receipt,
    issuer?.public_key_pem,
  );
  if (
    packet.recognition_rule.accepted_issuers.length !== 1 ||
    receiptVerification.valid !== true ||
    !receiptVerification.payload ||
    receiptVerification.verified_signed_payload_sha256 !==
      packet.receipt_payload_sha256 ||
    canonicalize(receiptVerification.payload) !==
      canonicalize(packet.receipt_payload)
  ) {
    throw new Error('Protected records replacement receipt verification failed');
  }
  const receiptEpoch = Math.floor(
    new Date(receiptVerification.payload.ts).getTime() / 1000,
  );
  const validFrom = packet.grant_contract.time_policy.valid_from_epoch;
  const grantExpiry = packet.grant_contract.time_policy.expires_at_epoch;
  const recognitionExpiry =
    receiptEpoch + packet.recognition_rule.max_age_seconds;
  const preflightMargin = evaluateProtectedRecordsRuntimeEffectMarginV2({
    grantWindowRemainingSeconds: grantExpiry - observedEpoch,
    receiptRecognitionRemainingSeconds: recognitionExpiry - observedEpoch,
  });
  if (
    !Number.isSafeInteger(receiptEpoch) ||
    observedEpoch < validFrom ||
    !preflightMargin.accepted
  ) {
    throw new Error(
      'Protected records replacement authority window lacks the fixed safety margin',
    );
  }
  validateSourceBinding({
    packet,
    requiredManifestSchemaSha256,
    sourceCommitOid,
    sourceRepositoryRealpath,
    sourceWorktreeClean,
  });
  return Object.freeze({
    validation_type:
      'zlar.protected-records.replacement-crossing-authority-validation.v2',
    validated: true,
    consequence_executed: false,
    required_packet_sha256: requiredPacketSha256,
    required_grant_sha256: requiredGrantSha256,
    required_holder_bound_sha256: requiredHolderBoundSha256,
    required_holder_signed_once_sha256: requiredHolderSignedOnceSha256,
    required_manifest_schema_sha256: requiredManifestSchemaSha256,
    observed_epoch: observedEpoch,
    grant_expires_at_epoch: grantExpiry,
    receipt_recognition_expires_at_epoch: recognitionExpiry,
    fixed_safety_seconds:
      PROTECTED_RECORDS_REPLACEMENT_MINIMUM_SAFETY_SECONDS_V2,
    caller_supplied_consequence_time_accepted: false,
    confirmation_relay_inputs: confirmationRelayInputs,
  });
}

export function deriveProtectedRecordsReplacementRuntimeConfigV2({
  packet,
  holderSignedOnce,
  authorityStatusRefreshPath,
  consumedGrantsPath,
  consumedGrantStoreAnchorPath,
  consumedGrantStoreWitnessPath,
}) {
  return {
    action_class: packet.grant_contract.scope.action_class,
    authorized_record_update: packet.record_update,
    authority_grant_appointment: packet.appointment,
    authority_grant_confirmation: holderSignedOnce.confirmation,
    authority_grant_contract: packet.grant_contract,
    authority_grant_expected_contract_sha256: packet.grant_contract_sha256,
    authority_grant_issuance_decision: holderSignedOnce.issuance_decision,
    authority_grant_status: holderSignedOnce.authority_status,
    authority_grant_status_refresh_path: authorityStatusRefreshPath,
    authority_source_precondition: packet.source_precondition,
    consumed_grant_store_anchor_path: consumedGrantStoreAnchorPath,
    consumed_grant_store_witness_path: consumedGrantStoreWitnessPath,
    consumed_grants_path: consumedGrantsPath,
    profile_id: packet.grant_contract.scope.runtime_profile_id,
    recognition_rule: packet.recognition_rule,
    target_binding: packet.target_binding,
  };
}

export function assertDerivedProtectedRecordsReplacementRuntimeConfigV2(config) {
  return assertProtectedRecordsRuntimeServiceConfigV2(config);
}

export function deriveProtectedRecordsReplacementRuntimeRequestV2({
  packet,
  holderSignedOnce,
}) {
  return {
    receipt: holderSignedOnce.signed_receipt,
    record_update: packet.record_update,
    request_mode: 'recognized_runtime_write',
    runtime_profile_id: packet.grant_contract.scope.runtime_profile_id,
    target_handle: packet.target_binding.target_handle,
  };
}

export function composeProtectedRecordsReplacementArtifactSetFromResultV2({
  confirmationRelayInputs,
  runtimeResult,
  requiredGrantSha256,
  requiredManifestSchemaSha256,
}) {
  assertProtectedRecordsRuntimeServiceResultV2(runtimeResult);
  if (
    runtimeResult.service_write_accepted !== true ||
    runtimeResult.authority_grant_satisfied !== true ||
    runtimeResult.authority_grant_contract_sha256 !== requiredGrantSha256 ||
    runtimeResult.state_entry_count_delta !== 1 ||
    runtimeResult.consumed_authority_grant_count !== 1
  ) {
    throw new Error('Replacement artifact composition requires one accepted crossing');
  }
  if (
    requiredManifestSchemaSha256 !==
      protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2()
  ) {
    throw new Error('Replacement artifact manifest schema mismatch');
  }
  assertProtectedRecordsReplacementConfirmationRelayV2(
    confirmationRelayInputs,
  );
  if (
    confirmationRelayInputs.confirmationConfirmedAtEpoch !==
      runtimeResult.authority_grant_confirmation.confirmed_at_epoch
  ) {
    throw new Error(
      'Replacement artifact relay does not bind the persisted runtime confirmation',
    );
  }
  const crossingInputs = Object.freeze({
    ...protectedRecordsReplacementCrossingInputsFromRuntimeServiceResultV2(
      runtimeResult,
    ),
    ...confirmationRelayInputs,
  });
  const sourceBinding =
    protectedRecordsReplacementSourceBindingFromRuntimeServiceResultV2(
      runtimeResult,
    );
  const expectedCrossing = expectedCrossingOptions(crossingInputs);
  const crossingEvidence =
    buildProtectedRecordsReplacementCrossingEvidenceV2(crossingInputs);
  const serviceArtifact = buildProtectedRecordsReplacementServiceArtifactV2({
    crossingEvidence,
    expectedServiceArtifactSchemaContractSha256:
      sourceBinding.service_artifact_schema_contract_sha256,
    sourceBinding,
    ...expectedCrossing,
  });
  const serviceArtifactRawBytes =
    canonicalProtectedRecordsReplacementArtifactBytesV2(serviceArtifact);
  verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
    serviceArtifactRawBytes,
    {
      expectedArtifactBodySha256: serviceArtifact.integrity.body_sha256,
      expectedServiceArtifactSchemaContractSha256:
        sourceBinding.service_artifact_schema_contract_sha256,
      expectedSourceBinding: sourceBinding,
      ...expectedCrossing,
    },
  );
  const terminalArtifact =
    buildProtectedRecordsReplacementTerminalArtifactV2({
      expectedServiceArtifactBodySha256:
        serviceArtifact.integrity.body_sha256,
      expectedServiceArtifactSchemaContractSha256:
        sourceBinding.service_artifact_schema_contract_sha256,
      expectedSourceBinding: sourceBinding,
      expectedTerminalArtifactSchemaContractSha256:
        sourceBinding.terminal_artifact_schema_contract_sha256,
      serviceArtifactRawBytes,
      ...expectedCrossing,
    });
  const terminalArtifactRawBytes =
    canonicalProtectedRecordsReplacementArtifactBytesV2(terminalArtifact);
  verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes(
    terminalArtifactRawBytes,
    {
      expectedArtifactBodySha256: terminalArtifact.integrity.body_sha256,
      expectedServiceArtifactBodySha256:
        serviceArtifact.integrity.body_sha256,
      expectedServiceArtifactSchemaContractSha256:
        sourceBinding.service_artifact_schema_contract_sha256,
      expectedSourceBinding: sourceBinding,
      expectedTerminalArtifactSchemaContractSha256:
        sourceBinding.terminal_artifact_schema_contract_sha256,
      ...expectedCrossing,
    },
  );
  const manifest = buildProtectedRecordsReplacementArtifactSetManifestV2({
    expectedServiceArtifactBodySha256:
      serviceArtifact.integrity.body_sha256,
    expectedServiceArtifactSchemaContractSha256:
      sourceBinding.service_artifact_schema_contract_sha256,
    expectedSourceBinding: sourceBinding,
    expectedTerminalArtifactBodySha256:
      terminalArtifact.integrity.body_sha256,
    expectedTerminalArtifactSchemaContractSha256:
      sourceBinding.terminal_artifact_schema_contract_sha256,
    serviceArtifactRawBytes,
    terminalArtifactRawBytes,
    ...expectedCrossing,
  });
  const manifestRawBytes =
    canonicalProtectedRecordsReplacementArtifactSetManifestBytesV2(manifest);
  const rawArtifactSet = {
    expectedManifestArtifactBodySha256: manifest.integrity.body_sha256,
    manifestRawBytes,
    serviceArtifactRawBytes,
    terminalArtifactRawBytes,
  };
  const artifactSetVerification =
    verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes(rawArtifactSet);
  const downstreamProjections = Object.fromEntries(
    PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2.map(
      (consumerId) => [
        consumerId,
        buildProtectedRecordsReplacementDownstreamProjectionV2(
          consumerId,
          rawArtifactSet,
        ),
      ],
    ),
  );
  return {
    crossingInputs,
    sourceBinding,
    serviceArtifact,
    serviceArtifactRawBytes,
    terminalArtifact,
    terminalArtifactRawBytes,
    manifest,
    manifestRawBytes,
    artifactSetVerification,
    downstreamProjections,
  };
}

export function buildProtectedRecordsReplacementExhaustedStatusV2({
  confirmationRelayInputs,
  runtimeResult,
  crossingBindingSha256,
}) {
  assertProtectedRecordsRuntimeServiceResultV2(runtimeResult);
  assertSha256(
    'Protected records replacement crossing binding',
    crossingBindingSha256,
  );
  if (
    runtimeResult.service_write_accepted !== true ||
    runtimeResult.authority_grant_satisfied !== true ||
    runtimeResult.authority_effect_gate_binding
      ?.caller_supplied_consequence_time_accepted !== false ||
    runtimeResult.authority_effect_gate_binding?.consequence_clock_source !==
      PROTECTED_RECORDS_FIXTURE_AUTHORITY_CLOCK_SOURCE_V2
  ) {
    throw new Error(
      'Protected records replacement exhausted status requires one accepted runtime-clock-bound crossing',
    );
  }
  assertProtectedRecordsReplacementConfirmationRelayV2(
    confirmationRelayInputs,
  );
  if (
    confirmationRelayInputs.confirmationConfirmedAtEpoch !==
      runtimeResult.authority_grant_confirmation.confirmed_at_epoch
  ) {
    throw new Error(
      'Protected records replacement exhausted status relay does not bind the persisted confirmation',
    );
  }
  const derivedCrossing = buildProtectedRecordsReplacementCrossingEvidenceV2({
    ...protectedRecordsReplacementCrossingInputsFromRuntimeServiceResultV2(
      runtimeResult,
    ),
    ...confirmationRelayInputs,
  });
  if (derivedCrossing.crossing_binding_sha256 !== crossingBindingSha256) {
    throw new Error(
      'Protected records replacement exhausted status crossing binding mismatch',
    );
  }
  const effectEpoch = runtimeResult.authority_effect_gate_binding
    .authority_effect_evaluation_epoch;
  const exhaustedStatus = {
    ...JSON.parse(canonicalize(runtimeResult.authority_grant_status_at_effect)),
    status: 'exhausted',
    status_source: 'source-recorded-single-use-consumption',
    recorded_effect_uses: 1,
    fresh_effect_allowed: false,
    repeated_use_provenance_valid: false,
    historical_fixture_authority_at_effect_projection_allowed: true,
    consumed_crossing_binding_sha256: crossingBindingSha256,
    revoked_at_epoch: null,
    revocation_reason_code: null,
    status_updated_at_epoch: effectEpoch,
  };
  assertProtectedRecordsFixtureAuthorityStatusV2(exhaustedStatus, {
    contract: runtimeResult.authority_grant_contract,
    expectedContractSha256:
      runtimeResult.authority_grant_contract_sha256,
    appointment: runtimeResult.authority_grant_appointment,
    confirmation: runtimeResult.authority_grant_confirmation,
  });
  return {
    authority_status: exhaustedStatus,
    authority_status_sha256:
      protectedRecordsFixtureAuthorityStatusSha256V2(exhaustedStatus, {
        contract: runtimeResult.authority_grant_contract,
        expectedContractSha256:
          runtimeResult.authority_grant_contract_sha256,
        appointment: runtimeResult.authority_grant_appointment,
        confirmation: runtimeResult.authority_grant_confirmation,
      }),
  };
}

export function protectedRecordsReplacementRuntimeResultCanonicalBytesV2(result) {
  assertProtectedRecordsRuntimeServiceResultV2(result);
  return Buffer.from(canonicalize(result), 'utf8');
}

export function protectedRecordsReplacementIssuanceDecisionSha256V2(
  holderSignedOnce,
) {
  assertProtectedRecordsFixtureAuthorityDecisionV2(
    holderSignedOnce.issuance_decision,
  );
  return protectedRecordsFixtureAuthorityDecisionSha256V2(
    holderSignedOnce.issuance_decision,
  );
}
