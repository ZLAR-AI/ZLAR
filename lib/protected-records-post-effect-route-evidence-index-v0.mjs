import { canonicalize } from './canonicalize.mjs';
import {
  verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes,
} from './protected-records-replacement-artifact-set-v2.mjs';
import { sha256hex } from './sha256.mjs';

export const PROTECTED_RECORDS_POST_EFFECT_ROUTE_EVIDENCE_INDEX_TYPE_V0 =
  'zlar.protected-records.post-effect-route-evidence-index.v0';
export const PROTECTED_RECORDS_POST_EFFECT_ROUTE_EVIDENCE_INDEX_VERSION_V0 = 0;

const ACTION_CLASS = 'records.write';
const CONSEQUENCE_PATH =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
const AUTHORITY_DOMAIN = 'protected-records.local-disposable-fixture';
const RUNTIME_RESULT_TYPE = 'protected-records-runtime-service-result-v2';
const VERIFICATION_TYPE =
  'zlar.protected-records.replacement-artifact-set-verification.v2';
const STATUS_TYPE = 'zlar-protected-records-fixture-authority-status-v2';
const CLOSEOUT_TYPE = 'zlar.protected-records.replacement-crossing-closeout.v2';
const CANONICALIZATION = 'ZLAR canonical JSON v1';
const HASH_SCOPE = 'canonical index body without integrity';
const MAX_RAW_BYTES = 8 * 1024 * 1024;
const SHA256_RE = /^[a-f0-9]{64}$/;
const GIT_SHA1_RE = /^[a-f0-9]{40}$/;

const PARAM_KEYS = Object.freeze([
  'closeoutRawBytes',
  'exhaustedStatusRawBytes',
  'expectedCloseoutFileSha256',
  'expectedCrossingBindingSha256',
  'expectedCrossingSourceCommitOid',
  'expectedExhaustedStatusBodySha256',
  'expectedExhaustedStatusFileSha256',
  'expectedGrantContractSha256',
  'expectedManifestArtifactBodySha256',
  'expectedManifestFileSha256',
  'expectedManifestSchemaContractSha256',
  'expectedRuntimeResultFileSha256',
  'expectedServiceArtifactBodySha256',
  'expectedServiceFileSha256',
  'expectedTerminalArtifactBodySha256',
  'expectedTerminalFileSha256',
  'expectedVerificationFileSha256',
  'manifestRawBytes',
  'runtimeResultRawBytes',
  'serviceArtifactRawBytes',
  'terminalArtifactRawBytes',
  'verificationRawBytes',
]);

const STATUS_KEYS = Object.freeze([
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
]);

const CLOSEOUT_KEYS = Object.freeze([
  'accepted_result_persisted',
  'artifact_manifest_pinned',
  'authority_status_exhausted',
  'automatic_retry_allowed',
  'consequence_executed',
  'crash_atomic_effect_plus_pin_proven',
  'downstream_verification_without_reexecution',
  'exactly_once_effect_proven',
  'grant_consumed',
  'lifecycle_closed',
  'route_type',
  'runtime_invocations_completed',
  'runtime_result_persisted',
]);

const INDEXED_ROLES = Object.freeze([
  'runtime_result_v2',
  'service_artifact_v2',
  'terminal_artifact_v2',
  'artifact_set_manifest_v2',
  'persisted_artifact_set_verification_v2',
  'exhausted_authority_status_v2',
  'route_closeout_v2',
]);

const NON_CLAIMS = Object.freeze([
  'The index binds caller-pinned post-effect bytes; it does not extend the central manifest or modify the completed crossing output.',
  'The stored artifact-set verification is source-recomputed from raw artifact bytes; this is not independent actor, process, implementation, or external attestation evidence.',
  'The runtime result is an opaque caller-pinned root with selected fields validated; its full schema and claim strings are not evaluated or reprojected.',
  'The closeout has no embedded crossing, grant, manifest, source, receipt, or artifact identity; exact-SHA co-indexing does not prove that it originated from the same route.',
  'The recorded target state was process-private memory and is not re-observed by this index.',
  'The CLI emits stdout only; parent-process redirection destinations are outside coverage, so existing_crossing_output_mutated=false describes the verifier itself.',
  'The index does not prove authority or effect occurrence, current authority, rightful issuance, exactly-once effect, crash atomicity, lifecycle closure, side-door closure, immutable custody, current-machine governance, production, enterprise readiness, public attestation, sovereign recognition, or all-surface governance.',
]);

function assertObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactKeys(label, value, expectedKeys) {
  assertObject(label, value);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} fields must be exactly: ${expected.join(', ')}`);
  }
}

function assertSha256(label, value) {
  if (typeof value !== 'string' || !SHA256_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertGitSha1(label, value) {
  if (typeof value !== 'string' || !GIT_SHA1_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-1 Git object ID`);
  }
}

function rawBuffer(value, label) {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (raw.length < 2 || raw.length > MAX_RAW_BYTES) {
    throw new Error(`${label} size is outside the accepted boundary`);
  }
  return raw;
}

function parsePinnedCanonicalJson(value, expectedFileSha256, label) {
  assertSha256(`${label} file`, expectedFileSha256);
  const raw = rawBuffer(value, label);
  if (sha256hex(raw) !== expectedFileSha256) {
    throw new Error(`${label} file identity mismatch`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (!raw.equals(Buffer.from(canonicalize(parsed), 'utf8'))) {
    throw new Error(`${label} must be exact canonical JSON`);
  }
  return {
    byteLength: raw.length,
    fileSha256: expectedFileSha256,
    parsed,
    raw,
  };
}

function memberProjection(member) {
  return {
    byte_length: member.byteLength,
    canonical_json_validated: true,
    file_sha256: member.fileSha256,
  };
}

function assertCanonicalObjectHash(label, value, expectedSha256) {
  assertObject(label, value);
  assertSha256(`${label} expected identity`, expectedSha256);
  if (sha256hex(canonicalize(value)) !== expectedSha256) {
    throw new Error(`${label} internal identity mismatch`);
  }
}

function verifyArtifactSet(params, members) {
  for (const [label, value] of [
    ['Service artifact body', params.expectedServiceArtifactBodySha256],
    ['Terminal artifact body', params.expectedTerminalArtifactBodySha256],
    ['Manifest artifact body', params.expectedManifestArtifactBodySha256],
    ['Manifest schema contract', params.expectedManifestSchemaContractSha256],
    ['Authority grant contract', params.expectedGrantContractSha256],
    ['Crossing binding', params.expectedCrossingBindingSha256],
  ]) {
    assertSha256(label, value);
  }
  assertGitSha1(
    'Historical crossing source commit',
    params.expectedCrossingSourceCommitOid,
  );

  const recomputed =
    verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes({
      expectedManifestArtifactBodySha256:
        params.expectedManifestArtifactBodySha256,
      manifestRawBytes: members.manifest.raw,
      serviceArtifactRawBytes: members.service.raw,
      terminalArtifactRawBytes: members.terminal.raw,
    });

  if (
    recomputed.verification_type !== VERIFICATION_TYPE ||
    recomputed.verified !== true ||
    recomputed.verification_mode !== 'verification-only' ||
    recomputed.central_manifest_required !== true ||
    recomputed.consequence_reexecution_performed !== false ||
    recomputed.downstream_consequence_reexecution_forbidden !== true ||
    recomputed.authority_status_evaluated !== false ||
    recomputed.rightful_issuance_projected !== false
  ) {
    throw new Error('Recomputed artifact-set verification posture mismatch');
  }
  if (
    canonicalize(recomputed) !== canonicalize(members.verification.parsed) ||
    !members.verification.raw.equals(
      Buffer.from(canonicalize(recomputed), 'utf8'),
    )
  ) {
    throw new Error(
      'Persisted artifact-set verification does not exactly match the source-recomputed verification',
    );
  }

  const manifest = members.manifest.parsed;
  const authority = recomputed.authority_binding;
  const crossing = recomputed.crossing_binding_projection;
  const source = recomputed.source_binding;
  if (
    recomputed.manifest_artifact_body_sha256 !==
      params.expectedManifestArtifactBodySha256 ||
    recomputed.service_artifact_body_sha256 !==
      params.expectedServiceArtifactBodySha256 ||
    recomputed.terminal_artifact_body_sha256 !==
      params.expectedTerminalArtifactBodySha256 ||
    manifest.payload?.schema_binding
      ?.artifact_set_manifest_schema_contract_sha256 !==
      params.expectedManifestSchemaContractSha256 ||
    authority.authority_grant_contract_sha256 !==
      params.expectedGrantContractSha256 ||
    crossing.authority_grant_contract_sha256 !==
      params.expectedGrantContractSha256 ||
    authority.crossing_binding_sha256 !==
      params.expectedCrossingBindingSha256 ||
    source.repository_id !== 'ZLAR_Repo' ||
    source.git_object_format !== 'sha1' ||
    source.source_commit_oid !== params.expectedCrossingSourceCommitOid
  ) {
    throw new Error('Artifact-set expected identity or source binding mismatch');
  }

  return {
    authority,
    crossing,
    manifest,
    recomputed,
    source,
  };
}

function verifyRuntimeResult(runtimeMember, artifactSet) {
  const result = runtimeMember.parsed;
  assertObject('Runtime result', result);
  const { authority, crossing, source } = artifactSet;
  if (
    result.result_type !== RUNTIME_RESULT_TYPE ||
    result.action_class !== ACTION_CLASS ||
    result.consequence_path !== CONSEQUENCE_PATH ||
    result.request_mode !== 'recognized_runtime_write' ||
    result.decision?.decision !== 'accept' ||
    result.decision?.phase !== 'effect' ||
    result.service_write_accepted !== true ||
    result.service_state_changed !== true ||
    result.state_entry_written !== true ||
    result.state_entry_count_before !== 0 ||
    result.state_entry_count_after !== 1 ||
    result.state_entry_count_delta !== 1 ||
    result.authority_grant_satisfied !== true ||
    result.consumed_authority_grant_count !== 1 ||
    result.state_storage !== 'process-private-memory' ||
    result.live_probing !== false ||
    result.runtime_profile_active !== true
  ) {
    throw new Error('Runtime result selected posture mismatch');
  }

  const expectedPairs = [
    [result.authority_grant_contract_sha256, authority.authority_grant_contract_sha256],
    [result.authority_grant_appointment_sha256, authority.issuer_appointment_artifact_body_sha256],
    [result.authority_grant_confirmation_sha256, authority.activation_confirmation_artifact_body_sha256],
    [result.authority_grant_status_at_effect_sha256, authority.authority_status_at_effect_artifact_body_sha256],
    [result.signed_receipt_sha256, crossing.receipt_envelope_body_sha256],
    [result.authority_grant_issuance_decision_sha256, crossing.issuance_decision_sha256],
    [result.authority_grant_effect_decision_sha256, crossing.effect_decision_sha256],
    [result.authorized_effect_detail_sha256, crossing.authorized_effect_detail_sha256],
    [result.execution_trace_sha256, crossing.execution_trace_sha256],
    [result.runtime_transition_binding_sha256, crossing.runtime_transition_sha256],
    [result.recognition_contract_sha256, crossing.recognition_contract_sha256],
    [result.profile_sha256, crossing.runtime_profile_sha256],
    [result.target_contract_sha256, crossing.target_contract_sha256],
    [result.target_binding_sha256, crossing.target_binding_sha256],
    [result.target_effect_sha256, crossing.target_effect_sha256],
    [result.record_update_sha256, crossing.record_update_sha256],
    [result.source_precondition_artifact_body_sha256, crossing.source_precondition_artifact_body_sha256],
    [result.installed_profile_preflight_artifact_body_sha256, crossing.installed_profile_preflight_artifact_body_sha256],
  ];
  if (expectedPairs.some(([actual, expected]) => actual !== expected)) {
    throw new Error('Runtime result selected artifact-set cross-binding mismatch');
  }

  const sourcePrecondition = result.authority_source_precondition;
  if (
    sourcePrecondition?.repository_id !== source.repository_id ||
    sourcePrecondition?.git_object_format !== source.git_object_format ||
    sourcePrecondition?.source_commit_oid !== source.source_commit_oid ||
    sourcePrecondition?.no_reexecution_call_graph_sha256 !==
      source.no_reexecution_call_graph_sha256 ||
    sourcePrecondition?.service_artifact_schema_contract_sha256 !==
      source.service_artifact_schema_contract_sha256 ||
    sourcePrecondition?.terminal_artifact_schema_contract_sha256 !==
      source.terminal_artifact_schema_contract_sha256 ||
    result.source_precondition_artifact_body_sha256 !==
      source.source_precondition_artifact_body_sha256 ||
    result.installed_profile_preflight_artifact_body_sha256 !==
      source.installed_profile_preflight_artifact_body_sha256
  ) {
    throw new Error('Runtime result selected source binding mismatch');
  }

  assertCanonicalObjectHash(
    'Runtime authority effect-gate binding',
    result.authority_effect_gate_binding,
    result.authority_effect_gate_binding_sha256,
  );
  assertCanonicalObjectHash(
    'Runtime transition binding',
    result.runtime_transition_binding,
    result.runtime_transition_binding_sha256,
  );
  assertCanonicalObjectHash(
    'Runtime execution trace',
    result.execution_trace,
    result.execution_trace_sha256,
  );

  const transition = result.runtime_transition_binding;
  const gate = result.authority_effect_gate_binding;
  if (
    transition.authority_effect_gate_binding_sha256 !==
      result.authority_effect_gate_binding_sha256 ||
    transition.state_entry_count_before !== 0 ||
    transition.state_entry_count_after !== 1 ||
    transition.authority_grant_consumption_count_before !== 0 ||
    transition.authority_grant_consumption_count_after !== 1 ||
    transition.authority_grant_contract_sha256 !==
      authority.authority_grant_contract_sha256 ||
    transition.authority_grant_effect_decision_sha256 !==
      crossing.effect_decision_sha256 ||
    transition.authority_grant_issuance_decision_sha256 !==
      crossing.issuance_decision_sha256 ||
    transition.execution_trace_sha256 !== crossing.execution_trace_sha256 ||
    transition.signed_receipt_sha256 !== crossing.receipt_envelope_body_sha256 ||
    transition.target_effect_sha256 !== crossing.target_effect_sha256 ||
    gate.authority_grant_contract_sha256 !==
      authority.authority_grant_contract_sha256 ||
    gate.appointment_sha256 !==
      authority.issuer_appointment_artifact_body_sha256 ||
    gate.confirmation_sha256 !==
      authority.activation_confirmation_artifact_body_sha256 ||
    gate.authority_status_at_effect_sha256 !==
      authority.authority_status_at_effect_artifact_body_sha256 ||
    gate.effect_decision_sha256 !== crossing.effect_decision_sha256 ||
    gate.target_effect_sha256 !== crossing.target_effect_sha256 ||
    gate.caller_supplied_consequence_time_accepted !== false ||
    gate.consequence_clock_source !== 'runtime-process-wall-clock-at-effect' ||
    !Number.isSafeInteger(gate.authority_effect_evaluation_epoch)
  ) {
    throw new Error('Runtime result selected internal transition mismatch');
  }

  return {
    authorityEffectEvaluationEpoch: gate.authority_effect_evaluation_epoch,
    projection: {
      projection_semantics: 'source-recorded-selected-fields-only',
      runtime_result_schema_fully_validated: false,
      runtime_result_selected_fields_validated: true,
      runtime_result_claim_strings_evaluated: false,
      artifact_set_cross_binding_matched: true,
      source_binding_cross_match: true,
      internal_transition_binding_matched: true,
      source_recorded_selected_fields: {
        request_mode: result.request_mode,
        decision: result.decision.decision,
        decision_phase: result.decision.phase,
        service_write_accepted: result.service_write_accepted,
        service_state_changed: result.service_state_changed,
        state_entry_written: result.state_entry_written,
        state_entry_count_before: result.state_entry_count_before,
        state_entry_count_after: result.state_entry_count_after,
        state_entry_count_delta: result.state_entry_count_delta,
        authority_grant_satisfied: result.authority_grant_satisfied,
        consumed_authority_grant_count:
          result.consumed_authority_grant_count,
        state_storage: result.state_storage,
        live_probing: result.live_probing,
      },
      source_recorded_crossing_binding_fields: {
        authority_grant_contract_sha256:
          result.authority_grant_contract_sha256,
        authority_grant_appointment_sha256:
          result.authority_grant_appointment_sha256,
        authority_grant_confirmation_sha256:
          result.authority_grant_confirmation_sha256,
        authority_grant_status_at_effect_sha256:
          result.authority_grant_status_at_effect_sha256,
        signed_receipt_sha256: result.signed_receipt_sha256,
        effect_decision_sha256:
          result.authority_grant_effect_decision_sha256,
        execution_trace_sha256: result.execution_trace_sha256,
        runtime_transition_sha256:
          result.runtime_transition_binding_sha256,
        target_binding_sha256: result.target_binding_sha256,
        target_effect_sha256: result.target_effect_sha256,
        record_update_sha256: result.record_update_sha256,
      },
    },
  };
}

function verifyExhaustedStatus(
  statusMember,
  artifactSet,
  runtime,
  expectedExhaustedStatusBodySha256,
) {
  assertSha256(
    'Exhausted-status body',
    expectedExhaustedStatusBodySha256,
  );
  const wrapper = statusMember.parsed;
  assertExactKeys('Exhausted-status wrapper', wrapper, [
    'authority_status',
    'authority_status_sha256',
  ]);
  assertExactKeys('Exhausted authority status', wrapper.authority_status, STATUS_KEYS);
  const status = wrapper.authority_status;
  if (
    wrapper.authority_status_sha256 !==
      expectedExhaustedStatusBodySha256 ||
    sha256hex(canonicalize(status)) !==
      expectedExhaustedStatusBodySha256
  ) {
    throw new Error('Exhausted-status body identity mismatch');
  }
  const { authority, crossing } = artifactSet;
  if (
    status.status_type !== STATUS_TYPE ||
    status.status_version !== 2 ||
    status.status !== 'exhausted' ||
    status.status_source !== 'source-recorded-single-use-consumption' ||
    status.maximum_effect_uses !== 1 ||
    status.recorded_effect_uses !== 1 ||
    status.fresh_effect_allowed !== false ||
    status.repeated_use_provenance_valid !== false ||
    status.historical_fixture_authority_at_effect_projection_allowed !== true ||
    status.revoked_at_epoch !== null ||
    status.revocation_reason_code !== null ||
    !Number.isSafeInteger(status.status_updated_at_epoch) ||
    status.status_updated_at_epoch !== runtime.authorityEffectEvaluationEpoch ||
    status.status_updated_at_epoch < crossing.confirmation_confirmed_at_epoch ||
    status.status_updated_at_epoch < crossing.holder_observed_confirmation_epoch
  ) {
    throw new Error('Exhausted-status posture or chronology mismatch');
  }
  if (
    status.authority_grant_contract_sha256 !==
      authority.authority_grant_contract_sha256 ||
    status.appointment_sha256 !==
      authority.issuer_appointment_artifact_body_sha256 ||
    status.confirmation_sha256 !==
      authority.activation_confirmation_artifact_body_sha256 ||
    status.consumed_crossing_binding_sha256 !==
      authority.crossing_binding_sha256
  ) {
    throw new Error('Exhausted-status crossing binding mismatch');
  }
  return {
    source_recorded_exhausted_posture_validated: true,
    status_body_sha256: wrapper.authority_status_sha256,
    status_cross_binding_matched: true,
    status_chronology_validated: true,
    source_recorded_selected_fields: {
      status: status.status,
      recorded_effect_uses: status.recorded_effect_uses,
      maximum_effect_uses: status.maximum_effect_uses,
      fresh_effect_allowed: status.fresh_effect_allowed,
      repeated_use_provenance_valid: status.repeated_use_provenance_valid,
      historical_fixture_authority_at_effect_projection_allowed:
        status.historical_fixture_authority_at_effect_projection_allowed,
      status_updated_at_epoch: status.status_updated_at_epoch,
    },
  };
}

function verifyCloseout(closeoutMember) {
  const closeout = closeoutMember.parsed;
  assertExactKeys('Route closeout', closeout, CLOSEOUT_KEYS);
  if (
    closeout.route_type !== CLOSEOUT_TYPE ||
    closeout.runtime_invocations_completed !== 1 ||
    closeout.automatic_retry_allowed !== false ||
    closeout.consequence_executed !== true ||
    closeout.grant_consumed !== true ||
    closeout.runtime_result_persisted !== true ||
    closeout.accepted_result_persisted !== true ||
    closeout.artifact_manifest_pinned !== true ||
    closeout.authority_status_exhausted !== true ||
    closeout.downstream_verification_without_reexecution !== true ||
    closeout.exactly_once_effect_proven !== false ||
    closeout.crash_atomic_effect_plus_pin_proven !== false ||
    closeout.lifecycle_closed !== false
  ) {
    throw new Error('Route closeout source-recorded posture mismatch');
  }
  return {
    exact_key_set_validated: true,
    source_recorded_closeout_posture_validated: true,
    closeout_crossing_identity_embedded: false,
    closeout_same_route_proven: false,
    source_recorded_selected_fields: {
      runtime_invocations_completed: closeout.runtime_invocations_completed,
      automatic_retry_allowed: closeout.automatic_retry_allowed,
      consequence_executed: closeout.consequence_executed,
      grant_consumed: closeout.grant_consumed,
      runtime_result_persisted: closeout.runtime_result_persisted,
      accepted_result_persisted: closeout.accepted_result_persisted,
      artifact_manifest_pinned: closeout.artifact_manifest_pinned,
      authority_status_exhausted: closeout.authority_status_exhausted,
      downstream_verification_without_reexecution:
        closeout.downstream_verification_without_reexecution,
      exactly_once_effect_proven: closeout.exactly_once_effect_proven,
      crash_atomic_effect_plus_pin_proven:
        closeout.crash_atomic_effect_plus_pin_proven,
      lifecycle_closed: closeout.lifecycle_closed,
    },
  };
}

function buildIndexBody(params) {
  assertExactKeys('Post-effect route-evidence index input', params, PARAM_KEYS);
  const members = {
    runtime: parsePinnedCanonicalJson(
      params.runtimeResultRawBytes,
      params.expectedRuntimeResultFileSha256,
      'Runtime result',
    ),
    service: parsePinnedCanonicalJson(
      params.serviceArtifactRawBytes,
      params.expectedServiceFileSha256,
      'Service artifact',
    ),
    terminal: parsePinnedCanonicalJson(
      params.terminalArtifactRawBytes,
      params.expectedTerminalFileSha256,
      'Terminal artifact',
    ),
    manifest: parsePinnedCanonicalJson(
      params.manifestRawBytes,
      params.expectedManifestFileSha256,
      'Artifact-set manifest',
    ),
    verification: parsePinnedCanonicalJson(
      params.verificationRawBytes,
      params.expectedVerificationFileSha256,
      'Persisted artifact-set verification',
    ),
    status: parsePinnedCanonicalJson(
      params.exhaustedStatusRawBytes,
      params.expectedExhaustedStatusFileSha256,
      'Exhausted-status wrapper',
    ),
    closeout: parsePinnedCanonicalJson(
      params.closeoutRawBytes,
      params.expectedCloseoutFileSha256,
      'Route closeout',
    ),
  };
  const artifactSet = verifyArtifactSet(params, members);
  const runtime = verifyRuntimeResult(members.runtime, artifactSet);
  const exhaustedStatus = verifyExhaustedStatus(
    members.status,
    artifactSet,
    runtime,
    params.expectedExhaustedStatusBodySha256,
  );
  const closeout = verifyCloseout(members.closeout);
  const recomputedVerificationSha256 = sha256hex(
    canonicalize(artifactSet.recomputed),
  );

  return {
    artifact_type:
      PROTECTED_RECORDS_POST_EFFECT_ROUTE_EVIDENCE_INDEX_TYPE_V0,
    schema_version:
      PROTECTED_RECORDS_POST_EFFECT_ROUTE_EVIDENCE_INDEX_VERSION_V0,
    action_class: ACTION_CLASS,
    consequence_path: CONSEQUENCE_PATH,
    authority_domain_context: AUTHORITY_DOMAIN,
    authority_domain_evaluated: false,
    verification_mode: 'verification-only',
    canonicalization: CANONICALIZATION,
    hash_scope: HASH_SCOPE,
    safe_claim_ceiling:
      'One exact caller-pinned canonical local/private post-effect file set is co-indexed; raw service, terminal, and manifest bytes source-recompute the stored artifact-set verification exactly; selected source-recorded runtime, exhaustion, and closeout fields are cross-checked without consequence execution. Authority and effect occurrence are not re-established, and the closeout is not proven to originate from the same crossing.',
    membership_policy: {
      identity_basis:
        'caller-supplied exact file SHA plus semantic cross-binding; filenames and directory adjacency are not identity',
      indexed_roles: [...INDEXED_ROLES],
      derived_downstream_projection_indexed: false,
      pre_effect_route_inputs_indexed: false,
      mutable_runtime_control_indexed: false,
      source_snapshot_indexed: false,
      historical_source_commit_reference_only: true,
      lifecycle_overlay_indexed: false,
      all_retained_route_files_covered: false,
    },
    members: {
      runtime_result_v2: memberProjection(members.runtime),
      service_artifact_v2: memberProjection(members.service),
      terminal_artifact_v2: memberProjection(members.terminal),
      artifact_set_manifest_v2: memberProjection(members.manifest),
      persisted_artifact_set_verification_v2:
        memberProjection(members.verification),
      exhausted_authority_status_v2: memberProjection(members.status),
      route_closeout_v2: memberProjection(members.closeout),
    },
    artifact_set_verification: {
      recomputed_from_raw_artifacts: true,
      persisted_exact_canonical_match: true,
      recomputed_verification_sha256: recomputedVerificationSha256,
      persisted_verification_file_sha256:
        members.verification.fileSha256,
      manifest_artifact_body_sha256:
        artifactSet.recomputed.manifest_artifact_body_sha256,
      service_artifact_body_sha256:
        artifactSet.recomputed.service_artifact_body_sha256,
      terminal_artifact_body_sha256:
        artifactSet.recomputed.terminal_artifact_body_sha256,
      structural_artifact_lineage_verified: true,
      authority_status_evaluated: false,
      rightful_issuance_projected: false,
      consequence_reexecution_performed: false,
    },
    runtime_result_selected_projection: runtime.projection,
    exhausted_status_projection: exhaustedStatus,
    closeout_projection: closeout,
    source_reference: {
      repository_id: artifactSet.source.repository_id,
      git_object_format: artifactSet.source.git_object_format,
      historical_source_commit_oid: artifactSet.source.source_commit_oid,
      source_commit_cross_binding_matched: true,
      source_commit_object_presence_evaluated: false,
    },
    boundaries: {
      post_effect_index_separate_from_central_manifest: true,
      central_manifest_extended: false,
      existing_crossing_output_mutated: false,
      artifact_set_verification_recomputed: true,
      persisted_verification_exact_match: true,
      consequence_reexecution_performed: false,
      authority_effect_occurrence_reevaluated: false,
      surviving_effect_state_reobserved: false,
      external_effect_occurrence_proven: false,
      current_authority_projected: false,
      rightful_issuance_projected: false,
      lifecycle_status_change_authorized: false,
      lifecycle_closed: false,
      exactly_once_effect_proven: false,
      crash_atomic_effect_plus_pin_proven: false,
      side_door_closure_proven: false,
    },
    claim_boundary: {
      current_authority: false,
      rightful_issuance: false,
      exactly_once_effect: false,
      crash_atomicity: false,
      lifecycle_closure: false,
      side_door_closure: false,
      immutable_custody: false,
      current_machine_governance: false,
      production_governance: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      all_surface_governance: false,
    },
    non_claims: [...NON_CLAIMS],
  };
}

export function buildProtectedRecordsPostEffectRouteEvidenceIndexV0(params) {
  const body = buildIndexBody(params);
  return {
    ...body,
    integrity: {
      body_sha256: sha256hex(canonicalize(body)),
    },
  };
}

export function assertProtectedRecordsPostEffectRouteEvidenceIndexV0(
  report,
  params,
) {
  assertObject('Post-effect route-evidence index', report);
  assertExactKeys('Post-effect route-evidence index integrity', report.integrity, [
    'body_sha256',
  ]);
  const expected = buildProtectedRecordsPostEffectRouteEvidenceIndexV0(params);
  if (canonicalize(report) !== canonicalize(expected)) {
    throw new Error(
      'Post-effect route-evidence index does not match the exact verified projection',
    );
  }
  return true;
}

export function canonicalProtectedRecordsPostEffectRouteEvidenceIndexBytesV0(
  report,
  params,
) {
  assertProtectedRecordsPostEffectRouteEvidenceIndexV0(report, params);
  return Buffer.from(canonicalize(report), 'utf8');
}

export function formatProtectedRecordsPostEffectRouteEvidenceIndexSummaryV0(
  report,
  params,
) {
  assertProtectedRecordsPostEffectRouteEvidenceIndexV0(report, params);
  return [
    'Post-effect route-evidence index: verified',
    `Path: ${report.consequence_path}`,
    `Index body SHA-256: ${report.integrity.body_sha256}`,
    `Historical crossing source: ${report.source_reference.historical_source_commit_oid}`,
    `Indexed roles: ${report.membership_policy.indexed_roles.length}`,
    `Artifact verification source-recomputed: ${report.artifact_set_verification.recomputed_from_raw_artifacts}`,
    `Persisted verification exact match: ${report.artifact_set_verification.persisted_exact_canonical_match}`,
    `Runtime full schema validated: ${report.runtime_result_selected_projection.runtime_result_schema_fully_validated}`,
    `Closeout crossing identity embedded: ${report.closeout_projection.closeout_crossing_identity_embedded}`,
    `Closeout same route proven: ${report.closeout_projection.closeout_same_route_proven}`,
    `Consequence reexecution performed: ${report.boundaries.consequence_reexecution_performed}`,
    `Lifecycle closed: ${report.boundaries.lifecycle_closed}`,
  ].join('\n');
}
