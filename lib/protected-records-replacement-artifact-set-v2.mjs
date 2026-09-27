import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './sha256.mjs';
import {
  PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
  PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2,
  PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
  PROTECTED_RECORDS_REPLACEMENT_CROSSING_PROJECTION_KEYS_V2,
  assertProtectedRecordsReplacementExactKeysV2,
  assertProtectedRecordsReplacementSha256V2,
  assertProtectedRecordsReplacementSourceBindingV2,
  buildProtectedRecordsReplacementCrossingEvidenceV2,
  protectedRecordsReplacementCrossingInputsFromProjectionV2,
  protectedRecordsReplacementServiceArtifactSchemaContractSha256V2,
  protectedRecordsReplacementSourceBindingEqualsV2,
  protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2,
  verifyProtectedRecordsReplacementServiceArtifactV2RawBytes,
  verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes,
} from './protected-records-replacement-artifacts-v2.mjs';

export const PROTECTED_RECORDS_REPLACEMENT_ARTIFACT_SET_MANIFEST_TYPE_V2 =
  'zlar.protected-records.replacement-artifact-set-manifest.v2';
export const PROTECTED_RECORDS_REPLACEMENT_NO_REEXECUTION_CALL_GRAPH_TYPE_V2 =
  'zlar.protected-records.no-reexecution-call-graph.v2';
export const PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2 = Object.freeze([
  'consequence-lifecycle-map',
  'governed-surface-coverage',
  'installed-runtime-profile-recognition',
  'local-proof-pack',
  'north-star-readiness',
  'one-terminal-deployment-profile',
  'product-proof-path',
  'proof-smoke',
]);

const SCHEMA_VERSION = 2;
const CANONICALIZATION = 'ZLAR canonical JSON v1';
const HASH_SCOPE = 'canonical artifact body without integrity';
const MAX_RAW_BYTES = 8 * 1024 * 1024;

const CALL_GRAPH_DESCRIPTOR = Object.freeze({
  descriptor_type: PROTECTED_RECORDS_REPLACEMENT_NO_REEXECUTION_CALL_GRAPH_TYPE_V2,
  schema_version: SCHEMA_VERSION,
  action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
  consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
  consequence_node: 'runtime_service_v2',
  coverage_boundary: {
    authority_domain: 'protected-records.local-disposable-fixture',
    included_positive_entrypoint:
      'bin/zlar-protected-records-replacement-crossing-v2',
    excluded_paths: [
      {
        path:
          'direct-node-invocation-or-custom-import-of-lib/protected-records-replacement-runtime-child-v2.mjs',
        mapping: 'outside-defined-governed-route',
        reason:
          'same-user source/module execution has no external capability boundary in this local fixture',
      },
      {
        path:
          'direct-custom-import-or-call-of-createProtectedRecordsRuntimeServiceV2-including-loader-preload',
        mapping: 'outside-defined-governed-route',
        reason:
          'the source library is inspectable and callable by the same user outside the supported CLI route',
      },
    ],
    side_door_closure_proven: false,
  },
  nodes: [
    {
      id: 'replacement_crossing_driver_v2',
      kind: 'authority-bound-single-attempt-orchestrator',
      source_symbol: 'zlar-protected-records-replacement-crossing-v2',
      capability:
        'preflight exact authority, spawn one runtime request without retry, persist the accepted result, and pin the artifact set',
    },
    {
      id: 'runtime_service_v2',
      kind: 'source-consequence-boundary',
      source_symbol: 'createProtectedRecordsRuntimeServiceV2',
      capability:
        'one separately authorized canonical effect under launcher-owned authority with runtime-process wall-clock evaluation',
    },
    {
      id: 'general_runtime_service_cli_v2_refusal',
      kind: 'pre-effect-refusal-only-entrypoint',
      source_symbol: 'zlar-protected-records-runtime-service',
      capability:
        'refuse every direct v2 positive config before request reading or state-path mutation',
    },
    {
      id: 'exact_source_materialization_v2',
      kind: 'pre-effect-exact-source-boundary',
      source_symbol:
        'materializeProtectedRecordsReplacementSourceSnapshotV2',
      capability:
        'materialize a hook-disabled private detached clone of the packet-bound source commit, reject hidden index flags, recheck it, and remove write bits before the one runtime child imports it',
    },
    {
      id: 'replacement_runtime_child_v2',
      kind: 'non-dispatched-exact-source-child-entrypoint',
      source_symbol: 'protected-records-replacement-runtime-child-v2.mjs',
      capability:
        'accept one driver-marked JSONL request from the rechecked read-only source snapshot; direct module invocation remains outside coverage',
    },
    {
      id: 'authorized_crossing_result',
      kind: 'immutable-value-boundary',
      source_symbol: null,
      capability: 'immutable post-effect crossing evidence values',
    },
    {
      id: 'accepted_result_persistence_v2',
      kind: 'write-once-post-effect-evidence-boundary',
      source_symbol: 'writeOnce',
      capability:
        'persist the canonical accepted result before artifact composition without retrying the consequence',
    },
    {
      id: 'runtime_crossing_inputs_mapper_v2',
      kind: 'pure-mapper',
      source_symbol: 'protectedRecordsReplacementCrossingInputsFromRuntimeServiceResultV2',
      capability: 'map one accepted runtime result to exact crossing inputs only',
    },
    {
      id: 'runtime_source_binding_mapper_v2',
      kind: 'pure-mapper',
      source_symbol: 'protectedRecordsReplacementSourceBindingFromRuntimeServiceResultV2',
      capability: 'map one accepted runtime result to exact source binding only',
    },
    {
      id: 'service_artifact_builder_v2',
      kind: 'pure-builder',
      source_symbol: 'buildProtectedRecordsReplacementServiceArtifactV2',
      capability: 'compose service artifact only',
    },
    {
      id: 'service_artifact_raw_verifier_v2',
      kind: 'verification-only',
      source_symbol: 'verifyProtectedRecordsReplacementServiceArtifactV2RawBytes',
      capability: 'verify canonical service artifact bytes only',
    },
    {
      id: 'terminal_artifact_builder_v2',
      kind: 'verification-only-builder',
      source_symbol: 'buildProtectedRecordsReplacementTerminalArtifactV2',
      capability: 'compose terminal artifact from verified service bytes only',
    },
    {
      id: 'terminal_artifact_raw_verifier_v2',
      kind: 'verification-only',
      source_symbol: 'verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes',
      capability: 'verify canonical terminal artifact bytes only',
    },
    {
      id: 'artifact_set_manifest_builder_v2',
      kind: 'verification-only-builder',
      source_symbol: 'buildProtectedRecordsReplacementArtifactSetManifestV2',
      capability: 'compose one central artifact lineage from verified bytes only',
    },
    {
      id: 'artifact_set_raw_verifier_v2',
      kind: 'verification-only',
      source_symbol: 'verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes',
      capability: 'verify the central manifest and its exact artifact bytes only',
    },
    {
      id: 'independent_artifact_set_verifier_cli_v2',
      kind: 'verification-only-entrypoint',
      source_symbol: 'zlar-protected-records-replacement-artifact-set-v2',
      capability:
        'require external manifest, grant, and schema identities and verify raw artifact bytes without runtime imports',
    },
    {
      id: 'exhausted_authority_status_closeout_v2',
      kind: 'pure-post-effect-lifecycle-closeout-builder',
      source_symbol: 'buildProtectedRecordsReplacementExhaustedStatusV2',
      capability:
        'bind the consumed crossing identity into a fresh-effect-forbidden exhausted status after artifact-set verification',
    },
    {
      id: 'exhausted_authority_status_refresh_write_v2',
      kind: 'post-effect-lifecycle-state-write',
      source_symbol: 'replaceCanonical',
      capability:
        'replace the live mutable active status with the exact exhausted status before immutable closeout evidence',
    },
    {
      id: 'crossing_route_closeout_record_v2',
      kind: 'write-once-post-effect-evidence-boundary',
      source_symbol: 'writeCanonical',
      capability:
        'persist route closeout only after manifest verification and exhausted live status',
    },
    {
      id: 'exhausted_authority_status_evidence_v2',
      kind: 'write-once-post-effect-evidence-boundary',
      source_symbol: 'writeCanonical',
      capability:
        'persist immutable exhausted-status evidence after the live status replacement',
    },
    ...PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2.map((id) => ({
      id: `downstream_${id.replaceAll('-', '_')}_v2`,
      kind: 'declared-verification-only-consumer',
      source_symbol: 'buildProtectedRecordsReplacementDownstreamProjectionV2',
      capability: `project verified central lineage for ${id} only`,
    })),
  ],
  edges: [
    {
      from: 'replacement_crossing_driver_v2',
      to: 'exact_source_materialization_v2',
      transport: 'externally bound clean source commit identity',
    },
    {
      from: 'exact_source_materialization_v2',
      to: 'replacement_runtime_child_v2',
      transport:
        'one non-dispatched child path from the rechecked read-only detached source snapshot',
    },
    {
      from: 'replacement_runtime_child_v2',
      to: 'runtime_service_v2',
      transport:
        'exactly one driver-marked JSONL request with no automatic retry',
    },
    {
      from: 'runtime_service_v2',
      to: 'authorized_crossing_result',
      transport: 'immutable result values',
    },
    {
      from: 'authorized_crossing_result',
      to: 'accepted_result_persistence_v2',
      transport: 'canonical write-once accepted result bytes',
    },
    {
      from: 'accepted_result_persistence_v2',
      to: 'runtime_crossing_inputs_mapper_v2',
      transport: 'strictly validated accepted runtime result',
    },
    {
      from: 'accepted_result_persistence_v2',
      to: 'runtime_source_binding_mapper_v2',
      transport: 'strictly validated accepted runtime result',
    },
    {
      from: 'runtime_crossing_inputs_mapper_v2',
      to: 'service_artifact_builder_v2',
      transport: 'exact crossing input hashes only',
    },
    {
      from: 'runtime_source_binding_mapper_v2',
      to: 'service_artifact_builder_v2',
      transport: 'exact source binding only',
    },
    {
      from: 'service_artifact_builder_v2',
      to: 'service_artifact_raw_verifier_v2',
      transport: 'canonical raw bytes plus exact expected SHA identities',
    },
    {
      from: 'service_artifact_raw_verifier_v2',
      to: 'terminal_artifact_builder_v2',
      transport: 'verification projection only',
    },
    {
      from: 'terminal_artifact_builder_v2',
      to: 'terminal_artifact_raw_verifier_v2',
      transport: 'canonical raw bytes plus exact expected SHA identities',
    },
    {
      from: 'service_artifact_raw_verifier_v2',
      to: 'artifact_set_manifest_builder_v2',
      transport: 'verified service identity and binding projection',
    },
    {
      from: 'terminal_artifact_raw_verifier_v2',
      to: 'artifact_set_manifest_builder_v2',
      transport: 'verified terminal identity and binding projection',
    },
    {
      from: 'artifact_set_manifest_builder_v2',
      to: 'artifact_set_raw_verifier_v2',
      transport: 'canonical central manifest plus exact artifact bytes',
    },
    {
      from: 'independent_artifact_set_verifier_cli_v2',
      to: 'artifact_set_raw_verifier_v2',
      transport:
        'externally required manifest, grant, and schema identities plus canonical raw artifact bytes',
    },
    {
      from: 'accepted_result_persistence_v2',
      to: 'exhausted_authority_status_closeout_v2',
      transport: 'accepted runtime authority-at-effect evidence only',
    },
    {
      from: 'artifact_set_raw_verifier_v2',
      to: 'exhausted_authority_status_closeout_v2',
      transport: 'verified consumed crossing binding only',
    },
    {
      from: 'exhausted_authority_status_closeout_v2',
      to: 'exhausted_authority_status_refresh_write_v2',
      transport: 'exact validated exhausted status bytes',
    },
    {
      from: 'exhausted_authority_status_refresh_write_v2',
      to: 'exhausted_authority_status_evidence_v2',
      transport: 'observed exhausted live-status posture',
    },
    {
      from: 'exhausted_authority_status_evidence_v2',
      to: 'crossing_route_closeout_record_v2',
      transport: 'immutable exhausted-status evidence identity',
    },
    ...PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2.map((id) => ({
      from: 'artifact_set_raw_verifier_v2',
      to: `downstream_${id.replaceAll('-', '_')}_v2`,
      transport: 'verified central lineage projection with reexecution=false',
    })),
  ],
  forbidden_edges: [
    {
      from: 'general_runtime_service_cli_v2_refusal',
      to: 'runtime_service_v2',
      reason:
        'the supported general runtime-service CLI must not bypass the exact crossing driver, artifact pin, or exhausted-status closeout',
    },
    {
      from: 'accepted_result_persistence_v2',
      to: 'runtime_service_v2',
      reason: 'recovery from result persistence must not re-execute consequence',
    },
    {
      from: 'independent_artifact_set_verifier_cli_v2',
      to: 'runtime_service_v2',
      reason: 'the independent verifier must not import or execute runtime code',
    },
    {
      from: 'exhausted_authority_status_closeout_v2',
      to: 'runtime_service_v2',
      reason: 'exhausted lifecycle closeout must not re-execute consequence',
    },
    {
      from: 'exhausted_authority_status_refresh_write_v2',
      to: 'runtime_service_v2',
      reason: 'exhausted status application must not re-execute consequence',
    },
    {
      from: 'crossing_route_closeout_record_v2',
      to: 'runtime_service_v2',
      reason: 'route closeout persistence must not re-execute consequence',
    },
    {
      from: 'exhausted_authority_status_evidence_v2',
      to: 'runtime_service_v2',
      reason: 'exhausted status evidence must not re-execute consequence',
    },
    {
      from: 'runtime_crossing_inputs_mapper_v2',
      to: 'runtime_service_v2',
      reason: 'artifact input mapping must not re-execute consequence',
    },
    {
      from: 'runtime_source_binding_mapper_v2',
      to: 'runtime_service_v2',
      reason: 'source binding mapping must not re-execute consequence',
    },
    {
      from: 'service_artifact_builder_v2',
      to: 'runtime_service_v2',
      reason: 'service artifact composition must not re-execute consequence',
    },
    {
      from: 'service_artifact_raw_verifier_v2',
      to: 'runtime_service_v2',
      reason: 'verification must not execute consequence',
    },
    {
      from: 'terminal_artifact_builder_v2',
      to: 'runtime_service_v2',
      reason: 'terminal composition must not re-execute consequence',
    },
    {
      from: 'terminal_artifact_raw_verifier_v2',
      to: 'runtime_service_v2',
      reason: 'verification must not re-execute consequence',
    },
    {
      from: 'artifact_set_manifest_builder_v2',
      to: 'runtime_service_v2',
      reason: 'manifest composition must not re-execute consequence',
    },
    {
      from: 'artifact_set_raw_verifier_v2',
      to: 'runtime_service_v2',
      reason: 'downstream verification must not re-execute consequence',
    },
    ...PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2.map((id) => ({
      from: `downstream_${id.replaceAll('-', '_')}_v2`,
      to: 'runtime_service_v2',
      reason: `${id} projection must not re-execute consequence`,
    })),
  ],
  invariants: [
    'the runtime consequence boundary has exactly one outgoing result edge and no post-effect incoming edge',
    'runtime-to-artifact bridges are pure mappers over one strictly validated accepted result',
    'all post-crossing builders are pure or verification-only',
    'all downstream consumers enter through one exact expected central manifest SHA-256',
    'service and terminal artifact output SHA-256 values are computed, never caller nominated',
    'no sample artifact identity or filesystem reader is embedded in the route',
    'authority status at effect remains bound after the fresh-use status becomes exhausted',
    'v2 config and request input cannot nominate consequence time; the effect gate binds the runtime-observed epoch while stronger clock custody remains unproven',
    'the crossing binding carries confirmation-confirmed and holder-observed epochs and independently enforces their directional inclusive relay delay from 0 through 300 seconds',
    'the crossing driver invokes one runtime child once, persists the accepted result before composition, and never retries an ambiguous or consumed route',
    'the consequence child runs from a private detached materialization of the exact packet-bound source commit rather than the mutable controller worktree',
    'the central manifest is the last artifact-set lineage file pinned by the crossing driver',
    'the independent verifier imports no runtime or crossing driver module and requires external manifest, grant, and schema identities',
    'post-effect closeout binds the consumed crossing into exhausted status and cannot reopen fresh-effect authority',
    'the live status is replaced with exhausted state before immutable exhausted-status and route-closeout evidence is written',
    'each named downstream consumer receives only the verified central lineage projection',
  ],
  claim_boundary:
    'source-only runtime and no-reexecution topology; no active authority, executed consequence, production, or lifecycle closure claim',
});

const MANIFEST_SCHEMA_CONTRACT = Object.freeze({
  schema_contract_type:
    'zlar.protected-records.replacement-artifact-set-manifest-schema-contract.v2',
  schema_version: SCHEMA_VERSION,
  action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
  consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
  artifact_type: PROTECTED_RECORDS_REPLACEMENT_ARTIFACT_SET_MANIFEST_TYPE_V2,
  canonicalization: CANONICALIZATION,
  hash_scope: HASH_SCOPE,
  payload_required_keys: [
    'artifact_binding',
    'authority_binding',
    'crossing_binding_projection',
    'evidence_binding',
    'route_policy',
    'schema_binding',
    'source_binding',
  ],
  crossing_binding_projection_required_keys:
    PROTECTED_RECORDS_REPLACEMENT_CROSSING_PROJECTION_KEYS_V2,
  confirmation_relay_policy: {
    direction:
      'holder_observed_confirmation_epoch-minus-confirmation_confirmed_at_epoch',
    inclusive_maximum_seconds:
      PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2,
    inclusive_minimum_seconds: 0,
    future_dated_confirmation_allowed: false,
  },
  root_policy:
    'one externally expected manifest body SHA-256 selects the only accepted service and terminal lineage',
  output_identity_policy: 'computed by builder; caller nomination forbidden',
});

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertEqual(label, expected, actual) {
  if (expected !== actual) throw new Error(`${label} mismatch`);
}

function expectedOptionsFromProjection(projection) {
  const inputs = protectedRecordsReplacementCrossingInputsFromProjectionV2(projection);
  return Object.fromEntries(
    Object.entries(inputs).map(([key, value]) => [
      `expected${key[0].toUpperCase()}${key.slice(1)}`,
      value,
    ])
  );
}

function parseCanonicalRawBytes(rawBytes, label) {
  let bytes;
  if (typeof rawBytes === 'string') bytes = Buffer.from(rawBytes, 'utf8');
  else if (Buffer.isBuffer(rawBytes) || rawBytes instanceof Uint8Array) bytes = Buffer.from(rawBytes);
  else throw new Error(`${label} raw bytes must be a string, Buffer, or Uint8Array`);
  if (bytes.length === 0 || bytes.length > MAX_RAW_BYTES) {
    throw new Error(`${label} raw byte length is outside the accepted range`);
  }
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) throw new Error(`${label} raw bytes are not valid UTF-8`);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label} raw bytes are not valid JSON`);
  }
  if (canonicalize(value) !== text) throw new Error(`${label} raw bytes must be exact canonical JSON`);
  return value;
}

export function protectedRecordsReplacementNoReexecutionCallGraphDescriptorV2() {
  return cloneJson(CALL_GRAPH_DESCRIPTOR);
}

export function assertProtectedRecordsReplacementNoReexecutionCallGraphDescriptorV2(descriptor) {
  if (canonicalize(descriptor) !== canonicalize(CALL_GRAPH_DESCRIPTOR)) {
    throw new Error('Protected records replacement no-reexecution call graph descriptor drifted');
  }
  return true;
}

export function protectedRecordsReplacementNoReexecutionCallGraphSha256V2(descriptor) {
  assertProtectedRecordsReplacementNoReexecutionCallGraphDescriptorV2(descriptor);
  return sha256hex(canonicalize(descriptor));
}

export function protectedRecordsReplacementArtifactSetManifestSchemaContractV2() {
  return cloneJson(MANIFEST_SCHEMA_CONTRACT);
}

export function protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2() {
  return sha256hex(canonicalize(MANIFEST_SCHEMA_CONTRACT));
}

function buildIntegrity(body) {
  return { algorithm: 'SHA-256', body_sha256: sha256hex(canonicalize(body)) };
}

function assertManifestIntegrity(manifest) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set manifest integrity',
    manifest.integrity,
    ['algorithm', 'body_sha256']
  );
  if (manifest.integrity.algorithm !== 'SHA-256') {
    throw new Error('Protected records replacement artifact-set manifest integrity algorithm drifted');
  }
  assertProtectedRecordsReplacementSha256V2(
    'Protected records replacement artifact-set manifest body SHA-256',
    manifest.integrity.body_sha256
  );
  const { integrity, ...body } = manifest;
  if (manifest.integrity.body_sha256 !== sha256hex(canonicalize(body))) {
    throw new Error('Protected records replacement artifact-set manifest structural self-integrity mismatch');
  }
}

const EXPECTED_CROSSING_SHA256_OPTION_KEYS = [
    'expectedActivationConfirmationArtifactBodySha256',
    'expectedAuthorityGrantContractSha256',
    'expectedAuthorityStatusAtEffectArtifactBodySha256',
    'expectedAuthorizedEffectDetailSha256',
    'expectedEffectDecisionSha256',
    'expectedExecutionTraceSha256',
    'expectedInstalledProfilePreflightArtifactBodySha256',
    'expectedIssuerAppointmentArtifactBodySha256',
    'expectedIssuanceDecisionSha256',
    'expectedReceiptEnvelopeBodySha256',
    'expectedRecognitionContractSha256',
    'expectedRecordUpdateSha256',
    'expectedRuntimeProfileSha256',
    'expectedRuntimeTransitionSha256',
    'expectedSourcePreconditionArtifactBodySha256',
    'expectedTargetBindingSha256',
    'expectedTargetContractSha256',
    'expectedTargetEffectSha256',
];

const EXPECTED_CONFIRMATION_RELAY_OPTION_KEYS = [
  'expectedConfirmationConfirmedAtEpoch',
  'expectedControlTowerConfirmationRelayDelaySeconds',
  'expectedControlTowerConfirmationRelayMaxSeconds',
  'expectedHolderObservedConfirmationEpoch',
];

const EXPECTED_CROSSING_OPTION_KEYS = [
  ...EXPECTED_CROSSING_SHA256_OPTION_KEYS,
  ...EXPECTED_CONFIRMATION_RELAY_OPTION_KEYS,
];

export function buildProtectedRecordsReplacementArtifactSetManifestV2(params) {
  const expectedCrossingKeys = EXPECTED_CROSSING_OPTION_KEYS;
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set manifest builder input',
    params,
    [
      'expectedServiceArtifactBodySha256',
      'expectedServiceArtifactSchemaContractSha256',
      'expectedSourceBinding',
      'expectedTerminalArtifactBodySha256',
      'expectedTerminalArtifactSchemaContractSha256',
      'serviceArtifactRawBytes',
      'terminalArtifactRawBytes',
      ...expectedCrossingKeys,
    ]
  );
  assertProtectedRecordsReplacementSourceBindingV2(params.expectedSourceBinding);
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement service artifact body SHA-256',
    params.expectedServiceArtifactBodySha256
  );
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement service schema contract SHA-256',
    params.expectedServiceArtifactSchemaContractSha256
  );
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement terminal schema contract SHA-256',
    params.expectedTerminalArtifactSchemaContractSha256
  );
  assertEqual(
    'Protected records replacement manifest source service schema contract',
    params.expectedServiceArtifactSchemaContractSha256,
    params.expectedSourceBinding.service_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement manifest source terminal schema contract',
    params.expectedTerminalArtifactSchemaContractSha256,
    params.expectedSourceBinding.terminal_artifact_schema_contract_sha256
  );
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement terminal artifact body SHA-256',
    params.expectedTerminalArtifactBodySha256
  );
  const expectedCrossing = Object.fromEntries(
    expectedCrossingKeys.map((key) => [key, params[key]])
  );
  const service = verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
    params.serviceArtifactRawBytes,
    {
      expectedArtifactBodySha256: params.expectedServiceArtifactBodySha256,
      expectedServiceArtifactSchemaContractSha256:
        params.expectedServiceArtifactSchemaContractSha256,
      expectedSourceBinding: params.expectedSourceBinding,
      ...expectedCrossing,
    }
  );
  const terminal = verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes(
    params.terminalArtifactRawBytes,
    {
      expectedArtifactBodySha256: params.expectedTerminalArtifactBodySha256,
      expectedServiceArtifactBodySha256: params.expectedServiceArtifactBodySha256,
      expectedServiceArtifactSchemaContractSha256:
        params.expectedServiceArtifactSchemaContractSha256,
      expectedSourceBinding: params.expectedSourceBinding,
      expectedTerminalArtifactSchemaContractSha256:
        params.expectedTerminalArtifactSchemaContractSha256,
      ...expectedCrossing,
    }
  );
  if (
    canonicalize(service.authority_binding) !== canonicalize(terminal.authority_binding) ||
    canonicalize(service.crossing_binding_projection) !==
      canonicalize(terminal.crossing_binding_projection) ||
    service.crossing_evidence_body_sha256 !== terminal.crossing_evidence_body_sha256
  ) {
    throw new Error('Protected records replacement artifact-set lineage mismatch');
  }
  const body = {
    action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
    artifact_type: PROTECTED_RECORDS_REPLACEMENT_ARTIFACT_SET_MANIFEST_TYPE_V2,
    canonicalization: CANONICALIZATION,
    composition_mode: 'verification-only central lineage; no consequence re-execution',
    consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
    hash_scope: HASH_SCOPE,
    payload: {
      artifact_binding: {
        service_artifact_body_sha256: service.artifact_body_sha256,
        terminal_artifact_body_sha256: terminal.artifact_body_sha256,
      },
      authority_binding: cloneJson(service.authority_binding),
      crossing_binding_projection: cloneJson(service.crossing_binding_projection),
      evidence_binding: {
        crossing_evidence_body_sha256: service.crossing_evidence_body_sha256,
      },
      route_policy: {
        central_manifest_required: true,
        consequence_reexecution_performed: false,
        downstream_consequence_reexecution_forbidden: true,
        global_sample_identity_allowed: false,
        per_consumer_artifact_lineage_allowed: false,
      },
      schema_binding: {
        artifact_set_manifest_schema_contract_sha256:
          protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2(),
        no_reexecution_call_graph_sha256:
          params.expectedSourceBinding.no_reexecution_call_graph_sha256,
        service_artifact_schema_contract_sha256:
          params.expectedServiceArtifactSchemaContractSha256,
        terminal_artifact_schema_contract_sha256:
          params.expectedTerminalArtifactSchemaContractSha256,
      },
      source_binding: cloneJson(params.expectedSourceBinding),
    },
    schema_version: SCHEMA_VERSION,
  };
  const manifest = { ...body, integrity: buildIntegrity(body) };
  assertProtectedRecordsReplacementArtifactSetManifestV2(manifest);
  return manifest;
}

export function assertProtectedRecordsReplacementArtifactSetManifestV2(manifest) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set manifest',
    manifest,
    [
      'action_class',
      'artifact_type',
      'canonicalization',
      'composition_mode',
      'consequence_path',
      'hash_scope',
      'integrity',
      'payload',
      'schema_version',
    ]
  );
  if (
    manifest.action_class !== PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS ||
    manifest.consequence_path !== PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH ||
    manifest.artifact_type !== PROTECTED_RECORDS_REPLACEMENT_ARTIFACT_SET_MANIFEST_TYPE_V2 ||
    manifest.canonicalization !== CANONICALIZATION ||
    manifest.composition_mode !== 'verification-only central lineage; no consequence re-execution' ||
    manifest.hash_scope !== HASH_SCOPE ||
    manifest.schema_version !== SCHEMA_VERSION
  ) {
    throw new Error('Protected records replacement artifact-set manifest boundary drifted');
  }
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set manifest payload',
    manifest.payload,
    MANIFEST_SCHEMA_CONTRACT.payload_required_keys
  );
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set binding',
    manifest.payload.artifact_binding,
    ['service_artifact_body_sha256', 'terminal_artifact_body_sha256']
  );
  assertProtectedRecordsReplacementSha256V2(
    'Protected records replacement artifact-set service artifact SHA-256',
    manifest.payload.artifact_binding.service_artifact_body_sha256
  );
  assertProtectedRecordsReplacementSha256V2(
    'Protected records replacement artifact-set terminal artifact SHA-256',
    manifest.payload.artifact_binding.terminal_artifact_body_sha256
  );
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set authority binding',
    manifest.payload.authority_binding,
    [
      'activation_confirmation_artifact_body_sha256',
      'authority_grant_contract_sha256',
      'authority_status_at_effect_artifact_body_sha256',
      'crossing_binding_sha256',
      'issuer_appointment_artifact_body_sha256',
    ]
  );
  for (const value of Object.values(manifest.payload.authority_binding)) {
    assertProtectedRecordsReplacementSha256V2(
      'Protected records replacement artifact-set authority identity',
      value
    );
  }
  const expectedCrossing = expectedOptionsFromProjection(
    manifest.payload.crossing_binding_projection
  );
  const reconstructedCrossing = buildProtectedRecordsReplacementCrossingEvidenceV2(
    protectedRecordsReplacementCrossingInputsFromProjectionV2(
      manifest.payload.crossing_binding_projection
    )
  );
  if (
    canonicalize(reconstructedCrossing.crossing_binding_projection) !==
      canonicalize(manifest.payload.crossing_binding_projection) ||
    reconstructedCrossing.crossing_binding_sha256 !==
      manifest.payload.authority_binding.crossing_binding_sha256 ||
    reconstructedCrossing.crossing_binding_projection.authority_grant_contract_sha256 !==
      manifest.payload.authority_binding.authority_grant_contract_sha256 ||
    reconstructedCrossing.crossing_binding_projection.activation_confirmation_artifact_body_sha256 !==
      manifest.payload.authority_binding.activation_confirmation_artifact_body_sha256 ||
    reconstructedCrossing.crossing_binding_projection.authority_status_at_effect_artifact_body_sha256 !==
      manifest.payload.authority_binding.authority_status_at_effect_artifact_body_sha256 ||
    reconstructedCrossing.crossing_binding_projection.issuer_appointment_artifact_body_sha256 !==
      manifest.payload.authority_binding.issuer_appointment_artifact_body_sha256
  ) {
    throw new Error('Protected records replacement artifact-set crossing authority projection mismatch');
  }
  for (const key of EXPECTED_CROSSING_SHA256_OPTION_KEYS) {
    assertProtectedRecordsReplacementSha256V2(
      'Protected records replacement artifact-set crossing identity',
      expectedCrossing[key]
    );
  }
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set evidence binding',
    manifest.payload.evidence_binding,
    ['crossing_evidence_body_sha256']
  );
  assertProtectedRecordsReplacementSha256V2(
    'Protected records replacement artifact-set crossing evidence SHA-256',
    manifest.payload.evidence_binding.crossing_evidence_body_sha256
  );
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set route policy',
    manifest.payload.route_policy,
    [
      'central_manifest_required',
      'consequence_reexecution_performed',
      'downstream_consequence_reexecution_forbidden',
      'global_sample_identity_allowed',
      'per_consumer_artifact_lineage_allowed',
    ]
  );
  const policy = manifest.payload.route_policy;
  if (
    policy.central_manifest_required !== true ||
    policy.consequence_reexecution_performed !== false ||
    policy.downstream_consequence_reexecution_forbidden !== true ||
    policy.global_sample_identity_allowed !== false ||
    policy.per_consumer_artifact_lineage_allowed !== false
  ) {
    throw new Error('Protected records replacement artifact-set route policy drifted');
  }
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set schema binding',
    manifest.payload.schema_binding,
    [
      'artifact_set_manifest_schema_contract_sha256',
      'no_reexecution_call_graph_sha256',
      'service_artifact_schema_contract_sha256',
      'terminal_artifact_schema_contract_sha256',
    ]
  );
  assertEqual(
    'Protected records replacement artifact-set manifest schema contract',
    protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2(),
    manifest.payload.schema_binding.artifact_set_manifest_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement artifact-set service schema contract',
    protectedRecordsReplacementServiceArtifactSchemaContractSha256V2(),
    manifest.payload.schema_binding.service_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement artifact-set terminal schema contract',
    protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2(),
    manifest.payload.schema_binding.terminal_artifact_schema_contract_sha256
  );
  assertProtectedRecordsReplacementSourceBindingV2(manifest.payload.source_binding);
  assertEqual(
    'Protected records replacement artifact-set source service schema contract',
    manifest.payload.schema_binding.service_artifact_schema_contract_sha256,
    manifest.payload.source_binding.service_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement artifact-set source terminal schema contract',
    manifest.payload.schema_binding.terminal_artifact_schema_contract_sha256,
    manifest.payload.source_binding.terminal_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement artifact-set installed-profile preflight binding',
    manifest.payload.crossing_binding_projection
      .installed_profile_preflight_artifact_body_sha256,
    manifest.payload.source_binding
      .installed_profile_preflight_artifact_body_sha256
  );
  assertEqual(
    'Protected records replacement artifact-set source-precondition binding',
    manifest.payload.crossing_binding_projection
      .source_precondition_artifact_body_sha256,
    manifest.payload.source_binding.source_precondition_artifact_body_sha256
  );
  assertEqual(
    'Protected records replacement artifact-set no-reexecution call graph',
    manifest.payload.source_binding.no_reexecution_call_graph_sha256,
    manifest.payload.schema_binding.no_reexecution_call_graph_sha256
  );
  assertEqual(
    'Protected records replacement artifact-set known no-reexecution call graph',
    protectedRecordsReplacementNoReexecutionCallGraphSha256V2(
      CALL_GRAPH_DESCRIPTOR
    ),
    manifest.payload.source_binding.no_reexecution_call_graph_sha256
  );
  assertManifestIntegrity(manifest);
  return true;
}

export function canonicalProtectedRecordsReplacementArtifactSetManifestBytesV2(manifest) {
  assertProtectedRecordsReplacementArtifactSetManifestV2(manifest);
  return Buffer.from(canonicalize(manifest), 'utf8');
}

export function verifyProtectedRecordsReplacementArtifactSetManifestV2RawBytes(
  rawBytes,
  { expectedArtifactBodySha256 }
) {
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement artifact-set manifest body SHA-256',
    expectedArtifactBodySha256
  );
  const manifest = parseCanonicalRawBytes(rawBytes, 'Protected records replacement artifact-set manifest');
  assertProtectedRecordsReplacementArtifactSetManifestV2(manifest);
  assertEqual(
    'Protected records replacement artifact-set manifest body identity',
    expectedArtifactBodySha256,
    manifest.integrity.body_sha256
  );
  return manifest;
}

export function verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes(params) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement artifact-set verifier input',
    params,
    [
      'expectedManifestArtifactBodySha256',
      'manifestRawBytes',
      'serviceArtifactRawBytes',
      'terminalArtifactRawBytes',
    ]
  );
  const manifest = verifyProtectedRecordsReplacementArtifactSetManifestV2RawBytes(
    params.manifestRawBytes,
    { expectedArtifactBodySha256: params.expectedManifestArtifactBodySha256 }
  );
  const expectedCrossing = expectedOptionsFromProjection(
    manifest.payload.crossing_binding_projection
  );
  const service = verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
    params.serviceArtifactRawBytes,
    {
      expectedArtifactBodySha256:
        manifest.payload.artifact_binding.service_artifact_body_sha256,
      expectedServiceArtifactSchemaContractSha256:
        manifest.payload.schema_binding.service_artifact_schema_contract_sha256,
      expectedSourceBinding: manifest.payload.source_binding,
      ...expectedCrossing,
    }
  );
  const terminal = verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes(
    params.terminalArtifactRawBytes,
    {
      expectedArtifactBodySha256:
        manifest.payload.artifact_binding.terminal_artifact_body_sha256,
      expectedServiceArtifactBodySha256:
        manifest.payload.artifact_binding.service_artifact_body_sha256,
      expectedServiceArtifactSchemaContractSha256:
        manifest.payload.schema_binding.service_artifact_schema_contract_sha256,
      expectedSourceBinding: manifest.payload.source_binding,
      expectedTerminalArtifactSchemaContractSha256:
        manifest.payload.schema_binding.terminal_artifact_schema_contract_sha256,
      ...expectedCrossing,
    }
  );
  if (
    !protectedRecordsReplacementSourceBindingEqualsV2(
      service.source_binding,
      terminal.source_binding
    ) ||
    service.crossing_evidence_body_sha256 !==
      manifest.payload.evidence_binding.crossing_evidence_body_sha256 ||
    terminal.crossing_evidence_body_sha256 !==
      manifest.payload.evidence_binding.crossing_evidence_body_sha256
  ) {
    throw new Error('Protected records replacement artifact-set downstream lineage mismatch');
  }
  return {
    verification_type: 'zlar.protected-records.replacement-artifact-set-verification.v2',
    verified: true,
    verification_mode: 'verification-only',
    central_manifest_required: true,
    consequence_reexecution_performed: false,
    downstream_consequence_reexecution_forbidden: true,
    manifest_artifact_body_sha256: manifest.integrity.body_sha256,
    service_artifact_body_sha256: service.artifact_body_sha256,
    terminal_artifact_body_sha256: terminal.artifact_body_sha256,
    authority_binding: cloneJson(manifest.payload.authority_binding),
    crossing_binding_projection: cloneJson(manifest.payload.crossing_binding_projection),
    source_binding: cloneJson(manifest.payload.source_binding),
    authority_status_evaluated: false,
    rightful_issuance_projected: false,
  };
}

export function buildProtectedRecordsReplacementDownstreamProjectionV2(
  consumerId,
  rawArtifactSet
) {
  if (!PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2.includes(consumerId)) {
    throw new Error('Protected records replacement downstream consumer is not declared');
  }
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement downstream raw artifact set',
    rawArtifactSet,
    [
      'expectedManifestArtifactBodySha256',
      'manifestRawBytes',
      'serviceArtifactRawBytes',
      'terminalArtifactRawBytes',
    ]
  );
  const verifiedArtifactSet =
    verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes(rawArtifactSet);
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement verified artifact set',
    verifiedArtifactSet,
    [
      'authority_binding',
      'authority_status_evaluated',
      'central_manifest_required',
      'consequence_reexecution_performed',
      'crossing_binding_projection',
      'downstream_consequence_reexecution_forbidden',
      'manifest_artifact_body_sha256',
      'rightful_issuance_projected',
      'service_artifact_body_sha256',
      'source_binding',
      'terminal_artifact_body_sha256',
      'verification_mode',
      'verification_type',
      'verified',
    ]
  );
  if (
    verifiedArtifactSet.verification_type !==
      'zlar.protected-records.replacement-artifact-set-verification.v2' ||
    verifiedArtifactSet.verified !== true ||
    verifiedArtifactSet.verification_mode !== 'verification-only' ||
    verifiedArtifactSet.central_manifest_required !== true ||
    verifiedArtifactSet.consequence_reexecution_performed !== false ||
    verifiedArtifactSet.downstream_consequence_reexecution_forbidden !== true ||
    verifiedArtifactSet.authority_status_evaluated !== false ||
    verifiedArtifactSet.rightful_issuance_projected !== false
  ) {
    throw new Error('Protected records replacement verified artifact-set posture drifted');
  }
  for (const [label, value] of [
    ['manifest artifact', verifiedArtifactSet.manifest_artifact_body_sha256],
    ['service artifact', verifiedArtifactSet.service_artifact_body_sha256],
    ['terminal artifact', verifiedArtifactSet.terminal_artifact_body_sha256],
  ]) {
    assertProtectedRecordsReplacementSha256V2(
      `Protected records replacement downstream ${label} SHA-256`,
      value
    );
  }
  assertProtectedRecordsReplacementSourceBindingV2(verifiedArtifactSet.source_binding);
  const reconstructedCrossing = buildProtectedRecordsReplacementCrossingEvidenceV2(
    protectedRecordsReplacementCrossingInputsFromProjectionV2(
      verifiedArtifactSet.crossing_binding_projection
    )
  );
  if (
    canonicalize(reconstructedCrossing.crossing_binding_projection) !==
      canonicalize(verifiedArtifactSet.crossing_binding_projection) ||
    reconstructedCrossing.crossing_binding_sha256 !==
      verifiedArtifactSet.authority_binding.crossing_binding_sha256
  ) {
    throw new Error('Protected records replacement downstream crossing projection drifted');
  }
  return {
    projection_type: 'zlar.protected-records.replacement-downstream-projection.v2',
    schema_version: SCHEMA_VERSION,
    action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
    consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
    consumer_id: consumerId,
    verification_mode: 'verification-only',
    central_manifest_required: true,
    consequence_reexecution_performed: false,
    downstream_consequence_reexecution_forbidden: true,
    manifest_artifact_body_sha256:
      verifiedArtifactSet.manifest_artifact_body_sha256,
    service_artifact_body_sha256:
      verifiedArtifactSet.service_artifact_body_sha256,
    terminal_artifact_body_sha256:
      verifiedArtifactSet.terminal_artifact_body_sha256,
    authority_binding: cloneJson(verifiedArtifactSet.authority_binding),
    crossing_binding_projection: cloneJson(
      verifiedArtifactSet.crossing_binding_projection
    ),
    source_binding: cloneJson(verifiedArtifactSet.source_binding),
    authority_status_evaluated: false,
    rightful_issuance_projected: false,
    claim_boundary:
      'local source-only verification projection; no consequence, current authority, lifecycle closure, production, or public claim',
  };
}
