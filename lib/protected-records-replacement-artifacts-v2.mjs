import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './sha256.mjs';

export const PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS = 'records.write';
export const PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
export const PROTECTED_RECORDS_REPLACEMENT_CROSSING_BINDING_TYPE_V2 =
  'zlar.protected-records.canonical-crossing-binding.v2';
export const PROTECTED_RECORDS_REPLACEMENT_CROSSING_EVIDENCE_TYPE_V2 =
  'zlar.protected-records.canonical-crossing-evidence.v2';
export const PROTECTED_RECORDS_REPLACEMENT_SERVICE_ARTIFACT_TYPE_V2 =
  'zlar.protected-records.replacement-service-artifact.v2';
export const PROTECTED_RECORDS_REPLACEMENT_TERMINAL_ARTIFACT_TYPE_V2 =
  'zlar.protected-records.replacement-terminal-artifact.v2';
export const PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2 =
  300;

const SCHEMA_VERSION = 2;
const CANONICALIZATION = 'ZLAR canonical JSON v1';
const HASH_SCOPE = 'canonical artifact body without integrity';
const SHA256_RE = /^[a-f0-9]{64}$/;
const GIT_SHA1_RE = /^[a-f0-9]{40}$/;
const MAX_RAW_BYTES = 8 * 1024 * 1024;

const CROSSING_SHA256_INPUT_KEYS = [
  'activationConfirmationArtifactBodySha256',
  'authorityGrantContractSha256',
  'authorityStatusAtEffectArtifactBodySha256',
  'authorizedEffectDetailSha256',
  'effectDecisionSha256',
  'executionTraceSha256',
  'installedProfilePreflightArtifactBodySha256',
  'issuerAppointmentArtifactBodySha256',
  'issuanceDecisionSha256',
  'receiptEnvelopeBodySha256',
  'recognitionContractSha256',
  'recordUpdateSha256',
  'runtimeProfileSha256',
  'runtimeTransitionSha256',
  'sourcePreconditionArtifactBodySha256',
  'targetBindingSha256',
  'targetContractSha256',
  'targetEffectSha256',
];

const CONFIRMATION_RELAY_INPUT_KEYS = [
  'confirmationConfirmedAtEpoch',
  'controlTowerConfirmationRelayDelaySeconds',
  'controlTowerConfirmationRelayMaxSeconds',
  'holderObservedConfirmationEpoch',
];

const CROSSING_INPUT_KEYS = [
  ...CROSSING_SHA256_INPUT_KEYS,
  ...CONFIRMATION_RELAY_INPUT_KEYS,
];

const EXPECTED_CROSSING_KEYS = CROSSING_INPUT_KEYS.map(
  (key) => `expected${key[0].toUpperCase()}${key.slice(1)}`
);

const AUTHORITY_BINDING_KEYS = [
  'activation_confirmation_artifact_body_sha256',
  'authority_grant_contract_sha256',
  'authority_status_at_effect_artifact_body_sha256',
  'crossing_binding_sha256',
  'issuer_appointment_artifact_body_sha256',
];

const SOURCE_BINDING_KEYS = [
  'git_object_format',
  'installed_profile_preflight_artifact_body_sha256',
  'no_reexecution_call_graph_sha256',
  'repository_id',
  'service_artifact_schema_contract_sha256',
  'source_commit_oid',
  'source_precondition_artifact_body_sha256',
  'terminal_artifact_schema_contract_sha256',
];

export const PROTECTED_RECORDS_REPLACEMENT_CROSSING_PROJECTION_KEYS_V2 =
Object.freeze([
  'action_class',
  'activation_confirmation_artifact_body_sha256',
  'authority_grant_contract_sha256',
  'authority_status_at_effect_artifact_body_sha256',
  'authorized_effect_detail_sha256',
  'binding_schema_version',
  'binding_type',
  'confirmation_confirmed_at_epoch',
  'consequence_path',
  'control_tower_confirmation_relay_delay_seconds',
  'control_tower_confirmation_relay_max_seconds',
  'effect_decision_sha256',
  'execution_trace_sha256',
  'installed_profile_preflight_artifact_body_sha256',
  'holder_observed_confirmation_epoch',
  'issuer_appointment_artifact_body_sha256',
  'issuance_decision_sha256',
  'receipt_envelope_body_sha256',
  'recognition_contract_sha256',
  'record_update_sha256',
  'runtime_profile_sha256',
  'runtime_transition_sha256',
  'source_precondition_artifact_body_sha256',
  'target_binding_sha256',
  'target_contract_sha256',
  'target_effect_sha256',
]);

const CROSSING_PROJECTION_KEYS =
  PROTECTED_RECORDS_REPLACEMENT_CROSSING_PROJECTION_KEYS_V2;

const SERVICE_SCHEMA_CONTRACT = Object.freeze({
  schema_contract_type:
    'zlar.protected-records.replacement-service-artifact-schema-contract.v2',
  schema_version: SCHEMA_VERSION,
  action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
  consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
  artifact_type: PROTECTED_RECORDS_REPLACEMENT_SERVICE_ARTIFACT_TYPE_V2,
  canonicalization: CANONICALIZATION,
  hash_scope: HASH_SCOPE,
  artifact_required_keys: [
    'action_class',
    'artifact_type',
    'canonicalization',
    'composition_mode',
    'consequence_path',
    'hash_scope',
    'integrity',
    'payload',
    'schema_version',
  ],
  payload_required_keys: [
    'authority_binding',
    'crossing_evidence',
    'schema_binding',
    'source_binding',
  ],
  authority_binding_required_keys: AUTHORITY_BINDING_KEYS,
  source_binding_required_keys: SOURCE_BINDING_KEYS,
  crossing_binding_projection_required_keys: CROSSING_PROJECTION_KEYS,
  confirmation_relay_policy: {
    direction:
      'holder_observed_confirmation_epoch-minus-confirmation_confirmed_at_epoch',
    inclusive_maximum_seconds:
      PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2,
    inclusive_minimum_seconds: 0,
    future_dated_confirmation_allowed: false,
  },
  output_identity_policy: 'computed by builder; caller nomination forbidden',
  verifier_policy:
    'canonical raw bytes plus independently expected artifact and crossing-boundary identities required',
  prohibited_capabilities: [
    'consequence execution',
    'grant issuance',
    'key generation',
    'receipt signing',
    'runtime installation',
    'filesystem write',
  ],
});

const TERMINAL_SCHEMA_CONTRACT = Object.freeze({
  schema_contract_type:
    'zlar.protected-records.replacement-terminal-artifact-schema-contract.v2',
  schema_version: SCHEMA_VERSION,
  action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
  consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
  artifact_type: PROTECTED_RECORDS_REPLACEMENT_TERMINAL_ARTIFACT_TYPE_V2,
  canonicalization: CANONICALIZATION,
  hash_scope: HASH_SCOPE,
  artifact_required_keys: [
    'action_class',
    'artifact_type',
    'canonicalization',
    'composition_mode',
    'consequence_path',
    'hash_scope',
    'integrity',
    'payload',
    'schema_version',
  ],
  payload_required_keys: [
    'authority_binding',
    'schema_binding',
    'service_artifact_binding',
    'source_binding',
    'verification_projection',
  ],
  authority_binding_required_keys: AUTHORITY_BINDING_KEYS,
  source_binding_required_keys: SOURCE_BINDING_KEYS,
  crossing_binding_projection_required_keys: CROSSING_PROJECTION_KEYS,
  confirmation_relay_policy: {
    direction:
      'holder_observed_confirmation_epoch-minus-confirmation_confirmed_at_epoch',
    inclusive_maximum_seconds:
      PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2,
    inclusive_minimum_seconds: 0,
    future_dated_confirmation_allowed: false,
  },
  output_identity_policy: 'computed by builder; caller nomination forbidden',
  verifier_policy:
    'canonical raw bytes plus independently expected service, terminal, and crossing-boundary identities required',
  prohibited_capabilities: [
    'consequence execution',
    'grant issuance',
    'key generation',
    'receipt signing',
    'runtime installation',
    'filesystem write',
  ],
});

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function isObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function assertProtectedRecordsReplacementExactKeysV2(label, value, keys) {
  if (!isObject(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} keys must be exactly ${expected.join(', ')}`);
  }
}

export function assertProtectedRecordsReplacementSha256V2(label, value) {
  if (!SHA256_RE.test(value || '')) {
    throw new Error(`${label} must be a 64-character lowercase SHA-256 digest`);
  }
}

function assertEqual(label, expected, actual) {
  if (expected !== actual) throw new Error(`${label} mismatch`);
}

function assertShaFields(label, value, keys) {
  for (const key of keys) {
    assertProtectedRecordsReplacementSha256V2(`${label} ${key}`, value[key]);
  }
}

export function assertProtectedRecordsReplacementSourceBindingV2(binding) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement source binding',
    binding,
    SOURCE_BINDING_KEYS
  );
  if (binding.repository_id !== 'ZLAR_Repo' || binding.git_object_format !== 'sha1') {
    throw new Error('Protected records replacement source repository binding drifted');
  }
  if (!GIT_SHA1_RE.test(binding.source_commit_oid || '')) {
    throw new Error(
      'Protected records replacement source_commit_oid must be a 40-character lowercase Git SHA-1 object id'
    );
  }
  assertShaFields('Protected records replacement source binding', binding, [
    'installed_profile_preflight_artifact_body_sha256',
    'no_reexecution_call_graph_sha256',
    'service_artifact_schema_contract_sha256',
    'source_precondition_artifact_body_sha256',
    'terminal_artifact_schema_contract_sha256',
  ]);
  return true;
}

export function protectedRecordsReplacementSourceBindingEqualsV2(left, right) {
  try {
    assertProtectedRecordsReplacementSourceBindingV2(left);
    assertProtectedRecordsReplacementSourceBindingV2(right);
  } catch {
    return false;
  }
  return canonicalize(left) === canonicalize(right);
}

export function protectedRecordsReplacementServiceArtifactSchemaContractV2() {
  return cloneJson(SERVICE_SCHEMA_CONTRACT);
}

export function protectedRecordsReplacementServiceArtifactSchemaContractSha256V2() {
  return sha256hex(canonicalize(SERVICE_SCHEMA_CONTRACT));
}

export function protectedRecordsReplacementTerminalArtifactSchemaContractV2() {
  return cloneJson(TERMINAL_SCHEMA_CONTRACT);
}

export function protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2() {
  return sha256hex(canonicalize(TERMINAL_SCHEMA_CONTRACT));
}

export function assertProtectedRecordsReplacementConfirmationRelayV2(relay) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement confirmation relay',
    relay,
    CONFIRMATION_RELAY_INPUT_KEYS
  );
  for (const field of CONFIRMATION_RELAY_INPUT_KEYS) {
    if (!Number.isSafeInteger(relay[field]) || relay[field] < 0) {
      throw new Error(
        `Protected records replacement confirmation relay ${field} must be a nonnegative safe integer`
      );
    }
  }
  const computedDelay =
    relay.holderObservedConfirmationEpoch - relay.confirmationConfirmedAtEpoch;
  if (
    relay.controlTowerConfirmationRelayMaxSeconds !==
      PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2 ||
    relay.controlTowerConfirmationRelayDelaySeconds !== computedDelay ||
    computedDelay < 0 ||
    computedDelay >
      PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2
  ) {
    throw new Error(
      'Protected records replacement confirmation relay is outside the directional inclusive bound'
    );
  }
  return true;
}

export function protectedRecordsReplacementConfirmationRelayInputsV2({
  confirmationConfirmedAtEpoch,
  holderObservedConfirmationEpoch,
}) {
  const relay = Object.freeze({
    confirmationConfirmedAtEpoch,
    controlTowerConfirmationRelayDelaySeconds:
      holderObservedConfirmationEpoch - confirmationConfirmedAtEpoch,
    controlTowerConfirmationRelayMaxSeconds:
      PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2,
    holderObservedConfirmationEpoch,
  });
  assertProtectedRecordsReplacementConfirmationRelayV2(relay);
  return relay;
}

function assertCrossingInputs(params) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement crossing binding input',
    params,
    CROSSING_INPUT_KEYS
  );
  assertShaFields(
    'Protected records replacement crossing binding input',
    params,
    CROSSING_SHA256_INPUT_KEYS
  );
  assertProtectedRecordsReplacementConfirmationRelayV2(
    Object.fromEntries(
      CONFIRMATION_RELAY_INPUT_KEYS.map((key) => [key, params[key]])
    )
  );
}

export function protectedRecordsReplacementCrossingBindingProjectionV2(params) {
  assertCrossingInputs(params);
  return {
    action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
    activation_confirmation_artifact_body_sha256:
      params.activationConfirmationArtifactBodySha256,
    authority_grant_contract_sha256: params.authorityGrantContractSha256,
    authority_status_at_effect_artifact_body_sha256:
      params.authorityStatusAtEffectArtifactBodySha256,
    authorized_effect_detail_sha256: params.authorizedEffectDetailSha256,
    binding_schema_version: SCHEMA_VERSION,
    binding_type: PROTECTED_RECORDS_REPLACEMENT_CROSSING_BINDING_TYPE_V2,
    confirmation_confirmed_at_epoch: params.confirmationConfirmedAtEpoch,
    consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
    control_tower_confirmation_relay_delay_seconds:
      params.controlTowerConfirmationRelayDelaySeconds,
    control_tower_confirmation_relay_max_seconds:
      params.controlTowerConfirmationRelayMaxSeconds,
    effect_decision_sha256: params.effectDecisionSha256,
    execution_trace_sha256: params.executionTraceSha256,
    installed_profile_preflight_artifact_body_sha256:
      params.installedProfilePreflightArtifactBodySha256,
    holder_observed_confirmation_epoch:
      params.holderObservedConfirmationEpoch,
    issuer_appointment_artifact_body_sha256:
      params.issuerAppointmentArtifactBodySha256,
    issuance_decision_sha256: params.issuanceDecisionSha256,
    receipt_envelope_body_sha256: params.receiptEnvelopeBodySha256,
    recognition_contract_sha256: params.recognitionContractSha256,
    record_update_sha256: params.recordUpdateSha256,
    runtime_profile_sha256: params.runtimeProfileSha256,
    runtime_transition_sha256: params.runtimeTransitionSha256,
    source_precondition_artifact_body_sha256:
      params.sourcePreconditionArtifactBodySha256,
    target_binding_sha256: params.targetBindingSha256,
    target_contract_sha256: params.targetContractSha256,
    target_effect_sha256: params.targetEffectSha256,
  };
}

export function buildProtectedRecordsReplacementCrossingEvidenceV2(params) {
  const projection = protectedRecordsReplacementCrossingBindingProjectionV2(params);
  return {
    evidence_schema_version: SCHEMA_VERSION,
    evidence_type: PROTECTED_RECORDS_REPLACEMENT_CROSSING_EVIDENCE_TYPE_V2,
    crossing_binding_projection: projection,
    crossing_binding_sha256: sha256hex(canonicalize(projection)),
  };
}

function crossingInputsFromExpectedOptions(options) {
  const input = {};
  for (const key of CROSSING_INPUT_KEYS) {
    input[key] = options[`expected${key[0].toUpperCase()}${key.slice(1)}`];
  }
  return input;
}

function assertExpectedCrossingOptions(label, options) {
  const expectedShaKeys = CROSSING_SHA256_INPUT_KEYS.map(
    (key) => `expected${key[0].toUpperCase()}${key.slice(1)}`
  );
  assertShaFields(label, options, expectedShaKeys);
  assertProtectedRecordsReplacementConfirmationRelayV2(
    Object.fromEntries(
      CONFIRMATION_RELAY_INPUT_KEYS.map((key) => [
        key,
        options[`expected${key[0].toUpperCase()}${key.slice(1)}`],
      ])
    )
  );
}

function assertCrossingEvidenceMatchesExpected(evidence, expectedInputs) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement crossing evidence',
    evidence,
    [
      'crossing_binding_projection',
      'crossing_binding_sha256',
      'evidence_schema_version',
      'evidence_type',
    ]
  );
  if (
    evidence.evidence_schema_version !== SCHEMA_VERSION ||
    evidence.evidence_type !== PROTECTED_RECORDS_REPLACEMENT_CROSSING_EVIDENCE_TYPE_V2
  ) {
    throw new Error('Protected records replacement crossing evidence schema drifted');
  }
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement crossing binding projection',
    evidence.crossing_binding_projection,
    CROSSING_PROJECTION_KEYS
  );
  assertProtectedRecordsReplacementSha256V2(
    'Protected records replacement crossing binding SHA-256',
    evidence.crossing_binding_sha256
  );
  const computed = sha256hex(canonicalize(evidence.crossing_binding_projection));
  if (evidence.crossing_binding_sha256 !== computed) {
    throw new Error('Protected records replacement crossing binding recomputation mismatch');
  }
  const expectedEvidence = buildProtectedRecordsReplacementCrossingEvidenceV2(expectedInputs);
  if (canonicalize(evidence) !== canonicalize(expectedEvidence)) {
    throw new Error('Protected records replacement crossing evidence expected boundary mismatch');
  }
  return expectedEvidence;
}

function authorityBindingFromEvidence(evidence) {
  const projection = evidence.crossing_binding_projection;
  return {
    activation_confirmation_artifact_body_sha256:
      projection.activation_confirmation_artifact_body_sha256,
    authority_grant_contract_sha256: projection.authority_grant_contract_sha256,
    authority_status_at_effect_artifact_body_sha256:
      projection.authority_status_at_effect_artifact_body_sha256,
    crossing_binding_sha256: evidence.crossing_binding_sha256,
    issuer_appointment_artifact_body_sha256:
      projection.issuer_appointment_artifact_body_sha256,
  };
}

function assertAuthorityBinding(binding) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement authority binding',
    binding,
    AUTHORITY_BINDING_KEYS
  );
  assertShaFields('Protected records replacement authority binding', binding, AUTHORITY_BINDING_KEYS);
}

function buildIntegrity(body) {
  return { algorithm: 'SHA-256', body_sha256: sha256hex(canonicalize(body)) };
}

function assertIntegrity(label, artifact) {
  assertProtectedRecordsReplacementExactKeysV2(`${label} integrity`, artifact.integrity, [
    'algorithm',
    'body_sha256',
  ]);
  if (artifact.integrity.algorithm !== 'SHA-256') {
    throw new Error(`${label} integrity algorithm drifted`);
  }
  assertProtectedRecordsReplacementSha256V2(`${label} body SHA-256`, artifact.integrity.body_sha256);
  const { integrity, ...body } = artifact;
  if (artifact.integrity.body_sha256 !== sha256hex(canonicalize(body))) {
    throw new Error(`${label} structural self-integrity mismatch`);
  }
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

export function canonicalProtectedRecordsReplacementArtifactBytesV2(artifact) {
  if (artifact?.artifact_type === PROTECTED_RECORDS_REPLACEMENT_SERVICE_ARTIFACT_TYPE_V2) {
    assertProtectedRecordsReplacementServiceArtifactV2(artifact);
  } else if (artifact?.artifact_type === PROTECTED_RECORDS_REPLACEMENT_TERMINAL_ARTIFACT_TYPE_V2) {
    assertProtectedRecordsReplacementTerminalArtifactV2(artifact);
  } else {
    throw new Error('Unknown protected records replacement artifact type');
  }
  return Buffer.from(canonicalize(artifact), 'utf8');
}

export function buildProtectedRecordsReplacementServiceArtifactV2(params) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement service artifact builder input',
    params,
    [
      'crossingEvidence',
      'expectedServiceArtifactSchemaContractSha256',
      'sourceBinding',
      ...EXPECTED_CROSSING_KEYS,
    ]
  );
  assertProtectedRecordsReplacementSourceBindingV2(params.sourceBinding);
  assertExpectedCrossingOptions('Protected records replacement service builder expected crossing', params);
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement service schema contract SHA-256',
    params.expectedServiceArtifactSchemaContractSha256
  );
  assertEqual(
    'Protected records replacement service builder loaded schema contract',
    params.expectedServiceArtifactSchemaContractSha256,
    protectedRecordsReplacementServiceArtifactSchemaContractSha256V2()
  );
  assertEqual(
    'Protected records replacement service builder source schema contract',
    params.expectedServiceArtifactSchemaContractSha256,
    params.sourceBinding.service_artifact_schema_contract_sha256
  );
  const expectedInputs = crossingInputsFromExpectedOptions(params);
  if (
    expectedInputs.installedProfilePreflightArtifactBodySha256 !==
      params.sourceBinding.installed_profile_preflight_artifact_body_sha256 ||
    expectedInputs.sourcePreconditionArtifactBodySha256 !==
      params.sourceBinding.source_precondition_artifact_body_sha256
  ) {
    throw new Error('Protected records replacement service builder source preflight distinction mismatch');
  }
  const evidence = assertCrossingEvidenceMatchesExpected(params.crossingEvidence, expectedInputs);
  const body = {
    action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
    artifact_type: PROTECTED_RECORDS_REPLACEMENT_SERVICE_ARTIFACT_TYPE_V2,
    canonicalization: CANONICALIZATION,
    composition_mode: 'pure post-crossing composition; no consequence execution',
    consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
    hash_scope: HASH_SCOPE,
    payload: {
      authority_binding: authorityBindingFromEvidence(evidence),
      crossing_evidence: {
        evidence: cloneJson(evidence),
        evidence_body_sha256: sha256hex(canonicalize(evidence)),
      },
      schema_binding: {
        service_artifact_schema_contract_sha256:
          params.expectedServiceArtifactSchemaContractSha256,
      },
      source_binding: cloneJson(params.sourceBinding),
    },
    schema_version: SCHEMA_VERSION,
  };
  const artifact = { ...body, integrity: buildIntegrity(body) };
  assertProtectedRecordsReplacementServiceArtifactV2(artifact);
  return artifact;
}

export function assertProtectedRecordsReplacementServiceArtifactV2(artifact) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement service artifact',
    artifact,
    SERVICE_SCHEMA_CONTRACT.artifact_required_keys
  );
  if (
    artifact.action_class !== PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS ||
    artifact.consequence_path !== PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH ||
    artifact.artifact_type !== PROTECTED_RECORDS_REPLACEMENT_SERVICE_ARTIFACT_TYPE_V2 ||
    artifact.canonicalization !== CANONICALIZATION ||
    artifact.composition_mode !== 'pure post-crossing composition; no consequence execution' ||
    artifact.hash_scope !== HASH_SCOPE ||
    artifact.schema_version !== SCHEMA_VERSION
  ) {
    throw new Error('Protected records replacement service artifact boundary drifted');
  }
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement service artifact payload',
    artifact.payload,
    SERVICE_SCHEMA_CONTRACT.payload_required_keys
  );
  assertAuthorityBinding(artifact.payload.authority_binding);
  assertProtectedRecordsReplacementSourceBindingV2(artifact.payload.source_binding);
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement service schema binding',
    artifact.payload.schema_binding,
    ['service_artifact_schema_contract_sha256']
  );
  assertEqual(
    'Protected records replacement service schema contract',
    protectedRecordsReplacementServiceArtifactSchemaContractSha256V2(),
    artifact.payload.schema_binding.service_artifact_schema_contract_sha256
  );
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement service crossing evidence binding',
    artifact.payload.crossing_evidence,
    ['evidence', 'evidence_body_sha256']
  );
  assertProtectedRecordsReplacementSha256V2(
    'Protected records replacement service crossing evidence body SHA-256',
    artifact.payload.crossing_evidence.evidence_body_sha256
  );
  if (
    artifact.payload.crossing_evidence.evidence_body_sha256 !==
    sha256hex(canonicalize(artifact.payload.crossing_evidence.evidence))
  ) {
    throw new Error('Protected records replacement service crossing evidence hash mismatch');
  }
  const projection = artifact.payload.crossing_evidence.evidence.crossing_binding_projection;
  const expectedInputs = protectedRecordsReplacementCrossingInputsFromProjectionV2(projection);
  const evidence = assertCrossingEvidenceMatchesExpected(
    artifact.payload.crossing_evidence.evidence,
    expectedInputs
  );
  if (
    canonicalize(authorityBindingFromEvidence(evidence)) !==
    canonicalize(artifact.payload.authority_binding)
  ) {
    throw new Error('Protected records replacement service authority binding mismatch');
  }
  if (
    projection.installed_profile_preflight_artifact_body_sha256 !==
      artifact.payload.source_binding.installed_profile_preflight_artifact_body_sha256 ||
    projection.source_precondition_artifact_body_sha256 !==
      artifact.payload.source_binding.source_precondition_artifact_body_sha256
  ) {
    throw new Error('Protected records replacement service source preflight distinction mismatch');
  }
  assertIntegrity('Protected records replacement service artifact', artifact);
  return true;
}

export function protectedRecordsReplacementCrossingInputsFromProjectionV2(projection) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement crossing binding projection',
    projection,
    CROSSING_PROJECTION_KEYS
  );
  return {
    activationConfirmationArtifactBodySha256: projection.activation_confirmation_artifact_body_sha256,
    authorityGrantContractSha256: projection.authority_grant_contract_sha256,
    authorityStatusAtEffectArtifactBodySha256: projection.authority_status_at_effect_artifact_body_sha256,
    authorizedEffectDetailSha256: projection.authorized_effect_detail_sha256,
    confirmationConfirmedAtEpoch: projection.confirmation_confirmed_at_epoch,
    controlTowerConfirmationRelayDelaySeconds:
      projection.control_tower_confirmation_relay_delay_seconds,
    controlTowerConfirmationRelayMaxSeconds:
      projection.control_tower_confirmation_relay_max_seconds,
    effectDecisionSha256: projection.effect_decision_sha256,
    executionTraceSha256: projection.execution_trace_sha256,
    installedProfilePreflightArtifactBodySha256: projection.installed_profile_preflight_artifact_body_sha256,
    holderObservedConfirmationEpoch:
      projection.holder_observed_confirmation_epoch,
    issuerAppointmentArtifactBodySha256: projection.issuer_appointment_artifact_body_sha256,
    issuanceDecisionSha256: projection.issuance_decision_sha256,
    receiptEnvelopeBodySha256: projection.receipt_envelope_body_sha256,
    recognitionContractSha256: projection.recognition_contract_sha256,
    recordUpdateSha256: projection.record_update_sha256,
    runtimeProfileSha256: projection.runtime_profile_sha256,
    runtimeTransitionSha256: projection.runtime_transition_sha256,
    sourcePreconditionArtifactBodySha256: projection.source_precondition_artifact_body_sha256,
    targetBindingSha256: projection.target_binding_sha256,
    targetContractSha256: projection.target_contract_sha256,
    targetEffectSha256: projection.target_effect_sha256,
  };
}

function assertServiceVerifierOptions(options) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement service verifier options',
    options,
    [
      'expectedArtifactBodySha256',
      'expectedServiceArtifactSchemaContractSha256',
      'expectedSourceBinding',
      ...EXPECTED_CROSSING_KEYS,
    ]
  );
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement service artifact body SHA-256',
    options.expectedArtifactBodySha256
  );
  assertProtectedRecordsReplacementSourceBindingV2(options.expectedSourceBinding);
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement service schema contract SHA-256',
    options.expectedServiceArtifactSchemaContractSha256
  );
  assertExpectedCrossingOptions('Protected records replacement service verifier expected crossing', options);
}

export function verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(rawBytes, options) {
  assertServiceVerifierOptions(options);
  const artifact = parseCanonicalRawBytes(rawBytes, 'Protected records replacement service artifact');
  assertProtectedRecordsReplacementServiceArtifactV2(artifact);
  assertEqual(
    'Protected records replacement service artifact body identity',
    options.expectedArtifactBodySha256,
    artifact.integrity.body_sha256
  );
  assertEqual(
    'Protected records replacement service expected schema contract',
    options.expectedServiceArtifactSchemaContractSha256,
    artifact.payload.schema_binding.service_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement service source schema contract',
    options.expectedServiceArtifactSchemaContractSha256,
    artifact.payload.source_binding.service_artifact_schema_contract_sha256
  );
  if (!protectedRecordsReplacementSourceBindingEqualsV2(options.expectedSourceBinding, artifact.payload.source_binding)) {
    throw new Error('Protected records replacement service source binding mismatch');
  }
  const expectedInputs = crossingInputsFromExpectedOptions(options);
  const evidence = assertCrossingEvidenceMatchesExpected(
    artifact.payload.crossing_evidence.evidence,
    expectedInputs
  );
  return serviceVerificationProjection(artifact, evidence);
}

function serviceVerificationProjection(artifact, evidence) {
  const projection = evidence.crossing_binding_projection;
  return {
    verification_type: 'zlar.protected-records.replacement-service-artifact-verification.v2',
    verified: true,
    verification_mode: 'verification-only',
    consequence_reexecution_performed: false,
    artifact_body_sha256: artifact.integrity.body_sha256,
    authority_binding: cloneJson(artifact.payload.authority_binding),
    crossing_binding_projection: cloneJson(projection),
    crossing_evidence_body_sha256: artifact.payload.crossing_evidence.evidence_body_sha256,
    service_artifact_schema_contract_sha256:
      artifact.payload.schema_binding.service_artifact_schema_contract_sha256,
    source_binding: cloneJson(artifact.payload.source_binding),
    authority_status_evaluated: false,
    rightful_issuance_projected: false,
  };
}

export function buildProtectedRecordsReplacementTerminalArtifactV2(params) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement terminal artifact builder input',
    params,
    [
      'expectedServiceArtifactBodySha256',
      'expectedServiceArtifactSchemaContractSha256',
      'expectedSourceBinding',
      'expectedTerminalArtifactSchemaContractSha256',
      'serviceArtifactRawBytes',
      ...EXPECTED_CROSSING_KEYS,
    ]
  );
  const serviceVerification = verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
    params.serviceArtifactRawBytes,
    {
      expectedArtifactBodySha256: params.expectedServiceArtifactBodySha256,
      expectedServiceArtifactSchemaContractSha256:
        params.expectedServiceArtifactSchemaContractSha256,
      expectedSourceBinding: params.expectedSourceBinding,
      ...Object.fromEntries(EXPECTED_CROSSING_KEYS.map((key) => [key, params[key]])),
    }
  );
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement terminal schema contract SHA-256',
    params.expectedTerminalArtifactSchemaContractSha256
  );
  assertEqual(
    'Protected records replacement terminal builder loaded schema contract',
    params.expectedTerminalArtifactSchemaContractSha256,
    protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2()
  );
  assertEqual(
    'Protected records replacement terminal builder source schema contract',
    params.expectedTerminalArtifactSchemaContractSha256,
    params.expectedSourceBinding.terminal_artifact_schema_contract_sha256
  );
  const body = {
    action_class: PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
    artifact_type: PROTECTED_RECORDS_REPLACEMENT_TERMINAL_ARTIFACT_TYPE_V2,
    canonicalization: CANONICALIZATION,
    composition_mode: 'verification-only composition; no consequence re-execution',
    consequence_path: PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
    hash_scope: HASH_SCOPE,
    payload: {
      authority_binding: cloneJson(serviceVerification.authority_binding),
      schema_binding: {
        terminal_artifact_schema_contract_sha256:
          params.expectedTerminalArtifactSchemaContractSha256,
      },
      service_artifact_binding: {
        service_artifact_body_sha256: serviceVerification.artifact_body_sha256,
        service_artifact_schema_contract_sha256:
          serviceVerification.service_artifact_schema_contract_sha256,
      },
      source_binding: cloneJson(serviceVerification.source_binding),
      verification_projection: {
        consequence_reexecution_performed: false,
        crossing_binding_projection: cloneJson(serviceVerification.crossing_binding_projection),
        crossing_evidence_body_sha256: serviceVerification.crossing_evidence_body_sha256,
        service_artifact_verified_from_canonical_raw_bytes: true,
      },
    },
    schema_version: SCHEMA_VERSION,
  };
  const artifact = { ...body, integrity: buildIntegrity(body) };
  assertProtectedRecordsReplacementTerminalArtifactV2(artifact);
  return artifact;
}

export function assertProtectedRecordsReplacementTerminalArtifactV2(artifact) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement terminal artifact',
    artifact,
    TERMINAL_SCHEMA_CONTRACT.artifact_required_keys
  );
  if (
    artifact.action_class !== PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS ||
    artifact.consequence_path !== PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH ||
    artifact.artifact_type !== PROTECTED_RECORDS_REPLACEMENT_TERMINAL_ARTIFACT_TYPE_V2 ||
    artifact.canonicalization !== CANONICALIZATION ||
    artifact.composition_mode !== 'verification-only composition; no consequence re-execution' ||
    artifact.hash_scope !== HASH_SCOPE ||
    artifact.schema_version !== SCHEMA_VERSION
  ) {
    throw new Error('Protected records replacement terminal artifact boundary drifted');
  }
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement terminal artifact payload',
    artifact.payload,
    TERMINAL_SCHEMA_CONTRACT.payload_required_keys
  );
  assertAuthorityBinding(artifact.payload.authority_binding);
  assertProtectedRecordsReplacementSourceBindingV2(artifact.payload.source_binding);
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement terminal schema binding',
    artifact.payload.schema_binding,
    ['terminal_artifact_schema_contract_sha256']
  );
  assertEqual(
    'Protected records replacement terminal schema contract',
    protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2(),
    artifact.payload.schema_binding.terminal_artifact_schema_contract_sha256
  );
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement terminal service binding',
    artifact.payload.service_artifact_binding,
    ['service_artifact_body_sha256', 'service_artifact_schema_contract_sha256']
  );
  assertShaFields('Protected records replacement terminal service binding', artifact.payload.service_artifact_binding, [
    'service_artifact_body_sha256',
    'service_artifact_schema_contract_sha256',
  ]);
  assertEqual(
    'Protected records replacement terminal service schema contract',
    protectedRecordsReplacementServiceArtifactSchemaContractSha256V2(),
    artifact.payload.service_artifact_binding.service_artifact_schema_contract_sha256
  );
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement terminal verification projection',
    artifact.payload.verification_projection,
    [
      'consequence_reexecution_performed',
      'crossing_binding_projection',
      'crossing_evidence_body_sha256',
      'service_artifact_verified_from_canonical_raw_bytes',
    ]
  );
  if (
    artifact.payload.verification_projection.consequence_reexecution_performed !== false ||
    artifact.payload.verification_projection.service_artifact_verified_from_canonical_raw_bytes !== true
  ) {
    throw new Error('Protected records replacement terminal no-reexecution projection drifted');
  }
  assertProtectedRecordsReplacementSha256V2(
    'Protected records replacement terminal crossing evidence body SHA-256',
    artifact.payload.verification_projection.crossing_evidence_body_sha256
  );
  const projection = artifact.payload.verification_projection.crossing_binding_projection;
  const evidence = buildProtectedRecordsReplacementCrossingEvidenceV2(
    protectedRecordsReplacementCrossingInputsFromProjectionV2(projection)
  );
  if (
    canonicalize(projection) !==
    canonicalize(evidence.crossing_binding_projection)
  ) {
    throw new Error('Protected records replacement terminal crossing projection schema drifted');
  }
  if (
    artifact.payload.verification_projection.crossing_evidence_body_sha256 !==
    sha256hex(canonicalize(evidence))
  ) {
    throw new Error('Protected records replacement terminal crossing evidence hash mismatch');
  }
  if (
    canonicalize(authorityBindingFromEvidence(evidence)) !==
    canonicalize(artifact.payload.authority_binding)
  ) {
    throw new Error('Protected records replacement terminal authority projection mismatch');
  }
  if (
    projection.installed_profile_preflight_artifact_body_sha256 !==
      artifact.payload.source_binding.installed_profile_preflight_artifact_body_sha256 ||
    projection.source_precondition_artifact_body_sha256 !==
      artifact.payload.source_binding.source_precondition_artifact_body_sha256
  ) {
    throw new Error('Protected records replacement terminal source preflight distinction mismatch');
  }
  assertIntegrity('Protected records replacement terminal artifact', artifact);
  return true;
}

function assertTerminalVerifierOptions(options) {
  assertProtectedRecordsReplacementExactKeysV2(
    'Protected records replacement terminal verifier options',
    options,
    [
      'expectedArtifactBodySha256',
      'expectedServiceArtifactBodySha256',
      'expectedServiceArtifactSchemaContractSha256',
      'expectedSourceBinding',
      'expectedTerminalArtifactSchemaContractSha256',
      ...EXPECTED_CROSSING_KEYS,
    ]
  );
  assertShaFields('Protected records replacement terminal verifier expected artifact', options, [
    'expectedArtifactBodySha256',
    'expectedServiceArtifactBodySha256',
    'expectedServiceArtifactSchemaContractSha256',
    'expectedTerminalArtifactSchemaContractSha256',
  ]);
  assertProtectedRecordsReplacementSourceBindingV2(options.expectedSourceBinding);
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement service schema contract SHA-256',
    options.expectedServiceArtifactSchemaContractSha256
  );
  assertProtectedRecordsReplacementSha256V2(
    'Expected protected records replacement terminal schema contract SHA-256',
    options.expectedTerminalArtifactSchemaContractSha256
  );
  assertExpectedCrossingOptions('Protected records replacement terminal verifier expected crossing', options);
}

export function verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes(rawBytes, options) {
  assertTerminalVerifierOptions(options);
  const artifact = parseCanonicalRawBytes(rawBytes, 'Protected records replacement terminal artifact');
  assertProtectedRecordsReplacementTerminalArtifactV2(artifact);
  assertEqual(
    'Protected records replacement terminal artifact body identity',
    options.expectedArtifactBodySha256,
    artifact.integrity.body_sha256
  );
  assertEqual(
    'Protected records replacement terminal expected service schema contract',
    options.expectedServiceArtifactSchemaContractSha256,
    artifact.payload.service_artifact_binding.service_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement terminal expected terminal schema contract',
    options.expectedTerminalArtifactSchemaContractSha256,
    artifact.payload.schema_binding.terminal_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement terminal source service schema contract',
    options.expectedServiceArtifactSchemaContractSha256,
    artifact.payload.source_binding.service_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement terminal source terminal schema contract',
    options.expectedTerminalArtifactSchemaContractSha256,
    artifact.payload.source_binding.terminal_artifact_schema_contract_sha256
  );
  assertEqual(
    'Protected records replacement terminal service artifact identity',
    options.expectedServiceArtifactBodySha256,
    artifact.payload.service_artifact_binding.service_artifact_body_sha256
  );
  if (!protectedRecordsReplacementSourceBindingEqualsV2(options.expectedSourceBinding, artifact.payload.source_binding)) {
    throw new Error('Protected records replacement terminal source binding mismatch');
  }
  const expectedEvidence = buildProtectedRecordsReplacementCrossingEvidenceV2(
    crossingInputsFromExpectedOptions(options)
  );
  const projection = artifact.payload.verification_projection.crossing_binding_projection;
  if (canonicalize(projection) !== canonicalize(expectedEvidence.crossing_binding_projection)) {
    throw new Error('Protected records replacement terminal crossing projection mismatch');
  }
  assertEqual(
    'Protected records replacement terminal crossing binding',
    expectedEvidence.crossing_binding_sha256,
    artifact.payload.authority_binding.crossing_binding_sha256
  );
  return {
    verification_type: 'zlar.protected-records.replacement-terminal-artifact-verification.v2',
    verified: true,
    verification_mode: 'verification-only',
    consequence_reexecution_performed: false,
    artifact_body_sha256: artifact.integrity.body_sha256,
    authority_binding: cloneJson(artifact.payload.authority_binding),
    crossing_binding_projection: cloneJson(projection),
    crossing_evidence_body_sha256:
      artifact.payload.verification_projection.crossing_evidence_body_sha256,
    service_artifact_body_sha256:
      artifact.payload.service_artifact_binding.service_artifact_body_sha256,
    service_artifact_schema_contract_sha256:
      artifact.payload.service_artifact_binding.service_artifact_schema_contract_sha256,
    source_binding: cloneJson(artifact.payload.source_binding),
    terminal_artifact_schema_contract_sha256:
      artifact.payload.schema_binding.terminal_artifact_schema_contract_sha256,
    authority_status_evaluated: false,
    rightful_issuance_projected: false,
  };
}
