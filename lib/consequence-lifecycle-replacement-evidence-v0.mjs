import { canonicalize } from './canonicalize.mjs';
import {
  buildProtectedRecordsReplacementDownstreamProjectionV2,
} from './protected-records-replacement-artifact-set-v2.mjs';
import { sha256hex } from './sha256.mjs';

export const CONSEQUENCE_LIFECYCLE_REPLACEMENT_OVERLAY_TYPE_V0 =
  'zlar-consequence-lifecycle-map-v0-replacement-artifact-lineage-overlay';
export const CONSEQUENCE_LIFECYCLE_REPLACEMENT_OVERLAY_VERSION_V0 = 0;

const ACTION_CLASS = 'records.write';
const CONSEQUENCE_PATH =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
const AUTHORITY_DOMAIN = 'protected-records.local-disposable-fixture';
const SHA256_RE = /^[a-f0-9]{64}$/;
const GIT_SHA1_RE = /^[a-f0-9]{40}$/;
const MAX_RAW_BYTES = 8 * 1024 * 1024;

const BASE_MAP_KEYS = Object.freeze([
  'authority_domain',
  'authority_topology',
  'claim_boundary',
  'closure',
  'consequence_path',
  'effect_boundary',
  'equivalent_route_inventory',
  'evidence_ref_resolution',
  'learning_boundary',
  'lifecycle_obligations',
  'map_status',
  'map_version',
  'non_claims',
  'observed_traces',
  'path_definition',
  'receipt_integrity',
  'report_type',
  'revocation_powers',
  'safe_claim_ceiling',
  'side_doors',
  'source_evidence',
]);

const REQUIRED_BASE_BLOCKERS = Object.freeze([
  'local_fixture_rightful_issuance_not_evidenced',
  'current_fixture_authority_grant_exhausted',
  'repeated_use_fixture_provenance_invalid',
]);

const BASE_MAP_FALSE_CLAIM_BOUNDARY_FIELDS = Object.freeze([
  'local_fixture_rightful_issuance_path',
  'generic_rightful_issuance',
  'portable_rightful_issuance',
  'live_rightful_issuance',
  'production_rightful_issuance',
  'current_machine_rightful_issuance',
  'production_governance',
  'enterprise_readiness',
  'general_current_machine_governance',
  'public_external_attestation',
  'all_surface_governance',
  'revocation_truth',
  'side_door_closure',
  'sovereign_recognition',
]);

const EXHAUSTED_STATUS_KEYS = Object.freeze([
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

const NON_CLAIMS = Object.freeze([
  'The replacement overlay verifies one exact caller-pinned local fixture artifact lineage and validates source-recorded exhausted-status fields; it does not evaluate authority or effect occurrence and does not project rightful issuance.',
  'The central manifest covers the replacement service and terminal artifacts only, not the complete consequence lifecycle.',
  'The replacement source commit binds the exact crossing lineage, not the current lifecycle-map graph source.',
  'The overlay performs no consequence re-execution and does not create fresh authority.',
  'The base-map object and its unevaluated claim strings remain opaque; only its identity and selected validated open-boundary fields are reprojected.',
  'The committed static import graph does not cover NODE_OPTIONS, custom loaders or preloads, interpreter or PATH substitution, same-user source mutation, or code loaded before the entrypoint.',
  'The overlay does not prove exactly-once effect, crash atomicity, lifecycle closure, rollback-resistant custody, side-door closure, current-machine governance, production, enterprise readiness, public attestation, sovereign recognition, or all-surface governance.',
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

function rawBuffer(value, label) {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (raw.length < 2 || raw.length > MAX_RAW_BYTES) {
    throw new Error(`${label} size is outside the accepted boundary`);
  }
  return raw;
}

function parseCanonicalJson(value, label) {
  const raw = rawBuffer(value, label);
  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (!raw.equals(Buffer.from(canonicalize(parsed), 'utf8'))) {
    throw new Error(`${label} must be exact canonical JSON`);
  }
  return { parsed, raw };
}

function verifyBaseMap(baseMapRawBytes, expectedBaseMapSha256) {
  const raw = rawBuffer(baseMapRawBytes, 'Base consequence lifecycle map');
  let baseMap;
  try {
    baseMap = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new Error('Base consequence lifecycle map is not valid JSON');
  }
  assertExactKeys('Base consequence lifecycle map', baseMap, BASE_MAP_KEYS);
  assertExactKeys(
    'Base consequence lifecycle map claim boundary',
    baseMap.claim_boundary,
    ['safe_claim', ...BASE_MAP_FALSE_CLAIM_BOUNDARY_FIELDS],
  );
  const computedBaseMapSha256 = sha256hex(JSON.stringify(baseMap));
  if (computedBaseMapSha256 !== expectedBaseMapSha256) {
    throw new Error('Base consequence lifecycle map identity mismatch');
  }
  if (
    baseMap.report_type !== 'zlar-consequence-lifecycle-map-v0' ||
    baseMap.map_version !== 0 ||
    baseMap.map_status !== 'mapped_open' ||
    baseMap.authority_domain?.domain_id !== AUTHORITY_DOMAIN ||
    baseMap.authority_domain?.named !== true ||
    baseMap.authority_domain?.fixture_rightful_issuance_path_evidenced !== false ||
    baseMap.consequence_path?.path_id !== CONSEQUENCE_PATH ||
    baseMap.consequence_path?.action_class !== ACTION_CLASS ||
    baseMap.consequence_path?.fixture_rightful_issuance_path_evidenced !== false ||
    baseMap.path_definition?.source_commit_bound !== false ||
    baseMap.receipt_integrity?.fixture_rightful_issuance_path_evidenced !== false ||
    baseMap.receipt_integrity?.generic_rightful_issuance_proven !== false ||
    baseMap.closure?.closure_status !== 'mapped_open' ||
    baseMap.closure?.lifecycle_closed !== false ||
    baseMap.closure?.lifecycle_governance_proven !== false ||
    typeof baseMap.claim_boundary.safe_claim !== 'string' ||
    baseMap.claim_boundary.safe_claim.trim().length === 0 ||
    BASE_MAP_FALSE_CLAIM_BOUNDARY_FIELDS.some(
      (field) => baseMap.claim_boundary[field] !== false,
    ) ||
    baseMap.evidence_ref_resolution?.all_references_resolved !== true ||
    !Array.isArray(baseMap.closure?.closure_blockers) ||
    REQUIRED_BASE_BLOCKERS.some(
      (blocker) => !baseMap.closure.closure_blockers.includes(blocker),
    )
  ) {
    throw new Error('Base consequence lifecycle map claim boundary mismatch');
  }
  const text = raw.toString('utf8');
  if (
    /\/Users\/[A-Za-z0-9._-]+\//.test(text) ||
    /\/home\/[A-Za-z0-9._-]+\//.test(text) ||
    /"lifecycle_closed"\s*:\s*true/i.test(text) ||
    /\bZLAR governs all (?:AI|actions|agents)\b/i.test(text)
  ) {
    throw new Error('Base consequence lifecycle map contains unsafe claim text');
  }
  return {
    baseMapReference: {
      report_type: 'zlar-consequence-lifecycle-map-v0',
      map_version: 0,
      map_status: 'mapped_open',
      authority_domain_id: AUTHORITY_DOMAIN,
      consequence_path: CONSEQUENCE_PATH,
      action_class: ACTION_CLASS,
      path_source_commit_bound: false,
      closure_status: 'mapped_open',
      lifecycle_closed: false,
      lifecycle_governance_proven: false,
      required_open_blockers_verified: [...REQUIRED_BASE_BLOCKERS],
      full_object_reprojected: false,
      claim_strings_evaluated: false,
    },
    baseMapFileSha256: sha256hex(raw),
    baseMapSha256: computedBaseMapSha256,
  };
}

function verifyExhaustedStatus({
  exhaustedStatusRawBytes,
  expectedExhaustedStatusBodySha256,
  projection,
}) {
  const { parsed: wrapper, raw } = parseCanonicalJson(
    exhaustedStatusRawBytes,
    'Replacement exhausted-status wrapper',
  );
  assertExactKeys('Replacement exhausted-status wrapper', wrapper, [
    'authority_status',
    'authority_status_sha256',
  ]);
  assertExactKeys(
    'Replacement exhausted authority status',
    wrapper.authority_status,
    EXHAUSTED_STATUS_KEYS,
  );
  const status = wrapper.authority_status;
  const computedStatusSha256 = sha256hex(canonicalize(status));
  if (
    wrapper.authority_status_sha256 !== expectedExhaustedStatusBodySha256 ||
    computedStatusSha256 !== expectedExhaustedStatusBodySha256
  ) {
    throw new Error('Replacement exhausted-status identity mismatch');
  }
  const authority = projection.authority_binding;
  const crossing = projection.crossing_binding_projection;
  if (
    status.status_type !==
      'zlar-protected-records-fixture-authority-status-v2' ||
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
    status.status_updated_at_epoch < crossing.confirmation_confirmed_at_epoch ||
    status.status_updated_at_epoch < crossing.holder_observed_confirmation_epoch
  ) {
    throw new Error('Replacement exhausted-status posture mismatch');
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
    throw new Error('Replacement exhausted-status crossing binding mismatch');
  }
  return {
    wrapper,
    wrapper_file_sha256: sha256hex(raw),
  };
}

function replacementEvidence(params) {
  for (const [label, value] of [
    ['Replacement manifest', params.expectedManifestArtifactBodySha256],
    ['Replacement grant', params.expectedGrantContractSha256],
    ['Replacement manifest schema', params.expectedManifestSchemaContractSha256],
    ['Replacement exhausted status', params.expectedExhaustedStatusBodySha256],
  ]) {
    assertSha256(label, value);
  }
  const manifestRaw = rawBuffer(
    params.manifestRawBytes,
    'Replacement artifact-set manifest',
  );
  const serviceRaw = rawBuffer(
    params.serviceArtifactRawBytes,
    'Replacement service artifact',
  );
  const terminalRaw = rawBuffer(
    params.terminalArtifactRawBytes,
    'Replacement terminal artifact',
  );
  const projection = buildProtectedRecordsReplacementDownstreamProjectionV2(
    'consequence-lifecycle-map',
    {
      expectedManifestArtifactBodySha256:
        params.expectedManifestArtifactBodySha256,
      manifestRawBytes: manifestRaw,
      serviceArtifactRawBytes: serviceRaw,
      terminalArtifactRawBytes: terminalRaw,
    },
  );
  const { parsed: manifest } = parseCanonicalJson(
    manifestRaw,
    'Replacement artifact-set manifest',
  );
  if (
    projection.consumer_id !== 'consequence-lifecycle-map' ||
    projection.action_class !== ACTION_CLASS ||
    projection.consequence_path !== CONSEQUENCE_PATH ||
    projection.verification_mode !== 'verification-only' ||
    projection.central_manifest_required !== true ||
    projection.consequence_reexecution_performed !== false ||
    projection.downstream_consequence_reexecution_forbidden !== true ||
    projection.authority_status_evaluated !== false ||
    projection.rightful_issuance_projected !== false
  ) {
    throw new Error('Replacement consequence-lifecycle projection posture mismatch');
  }
  if (
    manifest.payload?.schema_binding
      ?.artifact_set_manifest_schema_contract_sha256 !==
      params.expectedManifestSchemaContractSha256 ||
    projection.authority_binding.authority_grant_contract_sha256 !==
      params.expectedGrantContractSha256 ||
    projection.crossing_binding_projection.authority_grant_contract_sha256 !==
      params.expectedGrantContractSha256
  ) {
    throw new Error('Replacement manifest grant or schema binding mismatch');
  }
  const source = projection.source_binding;
  if (
    source.repository_id !== 'ZLAR_Repo' ||
    source.git_object_format !== 'sha1' ||
    !GIT_SHA1_RE.test(source.source_commit_oid) ||
    !SHA256_RE.test(source.no_reexecution_call_graph_sha256)
  ) {
    throw new Error('Replacement crossing source binding mismatch');
  }
  const exhausted = verifyExhaustedStatus({
    exhaustedStatusRawBytes: params.exhaustedStatusRawBytes,
    expectedExhaustedStatusBodySha256:
      params.expectedExhaustedStatusBodySha256,
    projection,
  });
  const crossing = projection.crossing_binding_projection;
  return {
    evidence_type:
      'zlar-consequence-lifecycle-replacement-artifact-lineage-evidence-v0',
    evidence_version: 0,
    authority_domain_context: AUTHORITY_DOMAIN,
    authority_domain_evaluated: false,
    action_class: ACTION_CLASS,
    consequence_path: CONSEQUENCE_PATH,
    consumer_id: 'consequence-lifecycle-map',
    verification_mode: 'verification-only',
    structural_artifact_lineage_verified: true,
    central_manifest_required: true,
    manifest_covers_complete_lifecycle: false,
    consequence_reexecution_performed: false,
    downstream_consequence_reexecution_forbidden: true,
    manifest_artifact_body_sha256:
      projection.manifest_artifact_body_sha256,
    service_artifact_body_sha256:
      projection.service_artifact_body_sha256,
    terminal_artifact_body_sha256:
      projection.terminal_artifact_body_sha256,
    artifact_set_manifest_schema_contract_sha256:
      params.expectedManifestSchemaContractSha256,
    authority_grant_contract_sha256:
      params.expectedGrantContractSha256,
    activation_confirmation_artifact_body_sha256:
      projection.authority_binding
        .activation_confirmation_artifact_body_sha256,
    authority_status_at_effect_artifact_body_sha256:
      projection.authority_binding
        .authority_status_at_effect_artifact_body_sha256,
    issuer_appointment_artifact_body_sha256:
      projection.authority_binding
        .issuer_appointment_artifact_body_sha256,
    crossing_binding_sha256:
      projection.authority_binding.crossing_binding_sha256,
    receipt_envelope_body_sha256: crossing.receipt_envelope_body_sha256,
    effect_decision_sha256: crossing.effect_decision_sha256,
    execution_trace_sha256: crossing.execution_trace_sha256,
    target_binding_sha256: crossing.target_binding_sha256,
    target_effect_sha256: crossing.target_effect_sha256,
    record_update_sha256: crossing.record_update_sha256,
    replacement_crossing_source_commit_oid: source.source_commit_oid,
    replacement_crossing_source_commit_bound: true,
    no_reexecution_call_graph_sha256:
      source.no_reexecution_call_graph_sha256,
    base_lifecycle_graph_source_commit_bound: false,
    artifact_set_authority_status_evaluated: false,
    authority_effect_occurrence_evaluated: false,
    replacement_exhausted_status_evaluated: true,
    exhausted_status_body_sha256:
      exhausted.wrapper.authority_status_sha256,
    exhausted_status_wrapper_file_sha256:
      exhausted.wrapper_file_sha256,
    source_recorded_grant_status: exhausted.wrapper.authority_status.status,
    source_recorded_effect_uses:
      exhausted.wrapper.authority_status.recorded_effect_uses,
    source_recorded_maximum_effect_uses:
      exhausted.wrapper.authority_status.maximum_effect_uses,
    source_recorded_fresh_effect_allowed:
      exhausted.wrapper.authority_status.fresh_effect_allowed,
    source_recorded_repeated_use_provenance_valid:
      exhausted.wrapper.authority_status.repeated_use_provenance_valid,
    source_recorded_historical_fixture_authority_at_effect_projection_allowed:
      exhausted.wrapper.authority_status
        .historical_fixture_authority_at_effect_projection_allowed,
    rightful_issuance_projected: false,
    claim_boundary:
      'one exact caller-pinned local replacement artifact lineage plus source-recorded exhaustion fields; authority/effect occurrence, current authority, rightful issuance, lifecycle closure, exactly-once, production, and public claims are not evaluated',
  };
}

export function buildConsequenceLifecycleReplacementOverlayV0(params) {
  assertExactKeys('Consequence lifecycle replacement overlay input', params, [
    'baseMapRawBytes',
    'expectedBaseMapSha256',
    'expectedExhaustedStatusBodySha256',
    'expectedGrantContractSha256',
    'expectedManifestArtifactBodySha256',
    'expectedManifestSchemaContractSha256',
    'exhaustedStatusRawBytes',
    'manifestRawBytes',
    'serviceArtifactRawBytes',
    'terminalArtifactRawBytes',
  ]);
  assertSha256('Base consequence lifecycle map', params.expectedBaseMapSha256);
  const base = verifyBaseMap(
    params.baseMapRawBytes,
    params.expectedBaseMapSha256,
  );
  const replacement = replacementEvidence(params);
  return {
    report_type: CONSEQUENCE_LIFECYCLE_REPLACEMENT_OVERLAY_TYPE_V0,
    overlay_version: CONSEQUENCE_LIFECYCLE_REPLACEMENT_OVERLAY_VERSION_V0,
    map_status: 'mapped_open',
    safe_claim_ceiling:
      'ZLAR can bind one exact caller-pinned verification-only replacement artifact lineage and its source-recorded exhausted-status fields to an opaque SHA-pinned open local-fixture lifecycle-map root through a consequence-incapable committed static import graph; authority, effect occurrence, base-map claim strings, and runtime loader or preload state remain unevaluated.',
    base_map_sha256: base.baseMapSha256,
    base_map_file_sha256: base.baseMapFileSha256,
    base_map_boundary_fields_validated: true,
    base_map_schema_fully_validated: false,
    base_map_claim_strings_evaluated: false,
    base_map_reference: base.baseMapReference,
    replacement_artifact_lineage_v2: replacement,
    evidence_namespaces: {
      base_map: ['source', 'report'],
      replacement_artifact_lineage: ['replacement'],
      cross_namespace_authority_inference_allowed: false,
    },
    consequence_reexecution_performed: false,
    manifest_covers_complete_lifecycle: false,
    rightful_issuance_projected: false,
    closure: {
      closure_status: 'mapped_open',
      lifecycle_closed: false,
      lifecycle_governance_proven: false,
      overlay_changes_path_wide_closure: false,
      complete_base_map_blocker_set_reprojected: false,
      verified_base_map_blockers: [...REQUIRED_BASE_BLOCKERS],
    },
    claim_boundary: {
      local_fixture_rightful_issuance_path: false,
      current_fresh_authority: false,
      exactly_once_effect: false,
      crash_atomic_effect_plus_pin: false,
      lifecycle_closure: false,
      side_door_closure: false,
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

export function assertConsequenceLifecycleReplacementOverlayV0(
  report,
  params,
) {
  assertObject('Consequence lifecycle replacement overlay', report);
  const expected = buildConsequenceLifecycleReplacementOverlayV0(params);
  if (canonicalize(report) !== canonicalize(expected)) {
    throw new Error(
      'Consequence lifecycle replacement overlay does not match the exact verified projection',
    );
  }
  return true;
}

export function consequenceLifecycleReplacementOverlaySha256V0(report) {
  assertObject('Consequence lifecycle replacement overlay hash input', report);
  return sha256hex(canonicalize(report));
}

export function formatConsequenceLifecycleReplacementOverlaySummaryV0(
  report,
  params,
) {
  assertConsequenceLifecycleReplacementOverlayV0(report, params);
  const baseMap = report.base_map_reference;
  return [
    `Consequence lifecycle map: ${baseMap.map_status}`,
    `Path: ${baseMap.consequence_path}`,
    `Base map: sha256=${report.base_map_sha256}; boundary_fields_validated=${report.base_map_boundary_fields_validated}; schema_fully_validated=${report.base_map_schema_fully_validated}; full_object_reprojected=${baseMap.full_object_reprojected}; claim_strings_evaluated=${report.base_map_claim_strings_evaluated}`,
    `Base lifecycle closed: ${baseMap.lifecycle_closed}`,
    'Replacement artifact lineage overlay: verified',
    `Replacement manifest: ${report.replacement_artifact_lineage_v2.manifest_artifact_body_sha256}`,
    `Replacement source commit: ${report.replacement_artifact_lineage_v2.replacement_crossing_source_commit_oid}; crossing_bound=${report.replacement_artifact_lineage_v2.replacement_crossing_source_commit_bound}; lifecycle_graph_bound=${report.replacement_artifact_lineage_v2.base_lifecycle_graph_source_commit_bound}`,
    `Replacement authority fields: source_recorded_status=${report.replacement_artifact_lineage_v2.source_recorded_grant_status}; uses=${report.replacement_artifact_lineage_v2.source_recorded_effect_uses}/${report.replacement_artifact_lineage_v2.source_recorded_maximum_effect_uses}; source_recorded_fresh_effect_allowed=${report.replacement_artifact_lineage_v2.source_recorded_fresh_effect_allowed}; authority_effect_occurrence_evaluated=${report.replacement_artifact_lineage_v2.authority_effect_occurrence_evaluated}; rightful_issuance_projected=${report.rightful_issuance_projected}`,
    `Replacement verification: consequence_reexecution_performed=${report.consequence_reexecution_performed}; manifest_covers_complete_lifecycle=${report.manifest_covers_complete_lifecycle}`,
    `Overlay lifecycle closed: ${report.closure.lifecycle_closed}`,
    `Overlay SHA-256: ${consequenceLifecycleReplacementOverlaySha256V0(report)}`,
  ].join('\n');
}
