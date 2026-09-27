import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './sha256.mjs';

export const CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_TYPE_V0 =
  'zlar.consequence-path-coverage-dependency-map.v0';
export const CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_VERSION_V0 = 0;

const ACTION_CLASS = 'records.write';
const SELECTED_PATH =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
const AUTHORITY_DOMAIN = 'protected-records.local-disposable-fixture';
const CANONICALIZATION = 'ZLAR canonical JSON v1';
const HASH_SCOPE = 'canonical map body without integrity';
const MAX_RAW_BYTES = 8 * 1024 * 1024;
const SHA256_RE = /^[a-f0-9]{64}$/;
const GIT_SHA1_RE = /^[a-f0-9]{40}$/;

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

const OVERLAY_KEYS = Object.freeze([
  'base_map_boundary_fields_validated',
  'base_map_claim_strings_evaluated',
  'base_map_file_sha256',
  'base_map_reference',
  'base_map_schema_fully_validated',
  'base_map_sha256',
  'claim_boundary',
  'closure',
  'consequence_reexecution_performed',
  'evidence_namespaces',
  'manifest_covers_complete_lifecycle',
  'map_status',
  'non_claims',
  'overlay_version',
  'replacement_artifact_lineage_v2',
  'report_type',
  'rightful_issuance_projected',
  'safe_claim_ceiling',
]);

const INDEX_KEYS = Object.freeze([
  'action_class',
  'artifact_set_verification',
  'artifact_type',
  'authority_domain_context',
  'authority_domain_evaluated',
  'boundaries',
  'canonicalization',
  'claim_boundary',
  'closeout_projection',
  'consequence_path',
  'exhausted_status_projection',
  'hash_scope',
  'integrity',
  'members',
  'membership_policy',
  'non_claims',
  'runtime_result_selected_projection',
  'safe_claim_ceiling',
  'schema_version',
  'source_reference',
  'verification_mode',
]);

const REQUIRED_BASE_CANDIDATES = Object.freeze([
  'protected-records.private-operator.records-terminal.records.write',
  'protected-records.runtime.profile-installation.records.write',
  'protected-records.runtime.records.write',
  'protected-records.service-profile.records.write',
]);

const REQUIRED_BASE_OPEN_OBLIGATIONS = Object.freeze([
  'local_fixture_rightful_issuance',
  'path_closeout',
  'consequence_recovery',
  'hardening_proposal',
  'hardening_authorization',
  'hardening_application',
  'regression_verification',
  'equivalent_route_closure',
]);

const KNOWN_STATIC_WRAPPERS_NOT_CATALOGUED = Object.freeze([
  'bin/zlar-protected-records-runtime-profile-proof',
  'bin/zlar-protected-records-runtime-profile-preflight',
  'bin/zlar-protected-records-runtime-activation-preflight',
  'bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
  'bin/zlar-protected-records-installed-runtime-profile-service-proof',
  'bin/zlar-protected-records-active-persistent-profile-lifecycle',
]);

const SOURCE_SPECS = Object.freeze({
  main_dispatch: Object.freeze({
    relative_path: 'bin/zlar',
    markers: Object.freeze([
      'protected-records-write) ZLAR_PROJECT_DIR=',
      'protected-records-service-request) ZLAR_PROJECT_DIR=',
      'protected-records-replacement-crossing-v2) exec ',
      'local-proof-pack) ZLAR_PROJECT_DIR=',
    ]),
  }),
  adapter: Object.freeze({
    relative_path: 'lib/protected-records-adapter.mjs',
    markers: Object.freeze([
      'export function applyProtectedRecordsWrite(input = {})',
      'writeConsumedStore(consumedPath, [...store.receipt_ids, receiptId]);',
      'writeFileSync(ledgerPath, `${JSON.stringify(ledgerEntry)}\\n`, { flag: \'a\' });',
    ]),
  }),
  adapter_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-write',
    markers: Object.freeze([
      'applyProtectedRecordsWrite',
      '--require-written',
      'live protected-records writes are not implemented in this slice',
    ]),
  }),
  service: Object.freeze({
    relative_path: 'lib/protected-records-service.mjs',
    markers: Object.freeze([
      'export function applyProtectedRecordsServiceRequest(input = {}, options = {})',
      'function suppliedInputFields(request)',
      "writeFileSync(statePath, stateEntryLine, { flag: 'a' });",
    ]),
  }),
  service_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-service-request',
    markers: Object.freeze([
      'applyProtectedRecordsServiceRequest',
      'Without --config, input JSON supplies fixture_mode=true',
      'With --config, launcher-owned config supplies fixture_mode',
    ]),
  }),
  service_profile: Object.freeze({
    relative_path: 'lib/protected-records-service-profile.mjs',
    markers: Object.freeze([
      'PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_TYPE',
      'zlar protected-records-service-request --config <file|-> --input <file|->',
      'recognized_write_accepted',
    ]),
  }),
  terminal_proof: Object.freeze({
    relative_path: 'lib/protected-records-terminal-proof.mjs',
    markers: Object.freeze([
      'export function runProtectedRecordsTerminalProof({',
      'const result = applyProtectedRecordsWrite({',
      "authoritative_route: 'receipt-recognition-before-ledger-append'",
    ]),
  }),
  terminal_proof_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-proof',
    markers: Object.freeze([
      'runProtectedRecordsTerminalProof',
      'Runs a local hermetic protected records terminal proof.',
    ]),
  }),
  adapter_conformance: Object.freeze({
    relative_path: 'lib/protected-records-adapter-conformance.mjs',
    markers: Object.freeze([
      'export function runProtectedRecordsAdapterConformanceProof({',
      "mutation_authoritative_route: 'receipt-recognition-before-ledger-append'",
      'ledger_entry_count_delta',
    ]),
  }),
  adapter_conformance_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-adapter-conformance',
    markers: Object.freeze([
      'runProtectedRecordsAdapterConformanceProof',
      'Runs a local disposable CLI-process conformance proof',
    ]),
  }),
  service_proof: Object.freeze({
    relative_path: 'lib/protected-records-service-proof.mjs',
    markers: Object.freeze([
      'export function runProtectedRecordsServiceProof({',
      "mutation_authoritative_route: 'receipt-recognition-before-service-state-append'",
      "runZlar(['protected-records-service-request', '--input', acceptedPath, '--require-written'])",
    ]),
  }),
  service_proof_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-service-proof',
    markers: Object.freeze([
      'runProtectedRecordsServiceProof',
      'Runs a local disposable protected-records downstream service proof.',
    ]),
  }),
  service_preflight_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-service-preflight',
    markers: Object.freeze([
      'runProtectedRecordsServiceProfilePreflight',
      'Preflights a sample protected-records service profile',
      'Use verify --input <file|-> to verify a supplied service-profile preflight artifact',
    ]),
  }),
  runtime_profile: Object.freeze({
    relative_path: 'lib/protected-records-runtime-profile.mjs',
    markers: Object.freeze([
      'export const PROTECTED_RECORDS_CONSEQUENCE_PATH',
      'export function createProtectedRecordsRuntimeService(config = {})',
      'export function createProtectedRecordsRuntimeServiceV2(config = {})',
      'stateEntries.push(stateEntry);',
    ]),
  }),
  runtime_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-runtime-service',
    markers: Object.freeze([
      'Direct v2 positive configs are refused',
      'createProtectedRecordsRuntimeService(config)',
      'if (isProtectedRecordsRuntimeServiceConfigV2(config))',
    ]),
  }),
  runtime_local_activation: Object.freeze({
    relative_path: 'lib/protected-records-runtime-local-activation.mjs',
    markers: Object.freeze([
      'assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed',
      'runProtectedRecordsRuntimeProfileProof',
      'PROTECTED_RECORDS_RUNTIME_LOCAL_ACTIVATION_ARTIFACT_TYPE',
    ]),
  }),
  runtime_local_activation_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-runtime-local-activation',
    markers: Object.freeze([
      'runProtectedRecordsRuntimeLocalActivationProof',
      'Positive local-activation generation refuses under the exhausted one-use grant',
      'verify remains read-only historical artifact inspection',
    ]),
  }),
  runtime_profile_installation: Object.freeze({
    relative_path: 'lib/protected-records-runtime-profile-installation.mjs',
    markers: Object.freeze([
      'assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed',
      'runProtectedRecordsRuntimeProfileProof',
      'PROTECTED_RECORDS_RUNTIME_PROFILE_INSTALLATION_ARTIFACT_TYPE',
    ]),
  }),
  runtime_profile_installation_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-runtime-profile-installation',
    markers: Object.freeze([
      'runProtectedRecordsRuntimeProfileInstallationProof',
      'Positive installation-proof generation refuses before install-root creation under the exhausted one-use grant',
      'verify remains read-only historical artifact inspection',
    ]),
  }),
  installed_terminal_chain: Object.freeze({
    relative_path:
      'lib/protected-records-installed-runtime-profile-terminal-chain.mjs',
    markers: Object.freeze([
      'PROTECTED_RECORDS_CONSEQUENCE_PATH',
      'assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed',
      'PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_ARTIFACT_TYPE',
    ]),
  }),
  installed_terminal_chain_cli: Object.freeze({
    relative_path:
      'bin/zlar-protected-records-installed-runtime-profile-terminal-chain',
    markers: Object.freeze([
      'runProtectedRecordsInstalledRuntimeProfileTerminalChain',
      'Fresh chain generation refuses while the exact one-use fixture authority grant is exhausted',
      'verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact',
    ]),
  }),
  replacement_crossing_cli: Object.freeze({
    relative_path: 'lib/protected-records-replacement-crossing-cli-v2.mjs',
    markers: Object.freeze([
      'runtime_invocation_limit: 1',
      'automatic_retry_allowed: false',
      'sourceSnapshot.runtimeServicePath',
    ]),
  }),
  replacement_crossing_entrypoint: Object.freeze({
    relative_path: 'bin/zlar-protected-records-replacement-crossing-v2',
    markers: Object.freeze([
      'protected-records-replacement-crossing-cli-v2.mjs',
      'exec /usr/bin/env -i',
      'inherited loader/search-path authority',
    ]),
  }),
  replacement_runtime_child: Object.freeze({
    relative_path: 'lib/protected-records-replacement-runtime-child-v2.mjs',
    markers: Object.freeze([
      'ZLAR_REPLACEMENT_INTERNAL_CHILD',
      'createProtectedRecordsRuntimeServiceV2(config)',
      'if (lines.length !== 1)',
    ]),
  }),
  replacement_source_snapshot: Object.freeze({
    relative_path: 'lib/protected-records-replacement-source-snapshot-v2.mjs',
    markers: Object.freeze([
      'protected-records-replacement-runtime-child-v2.mjs',
      'freezeProtectedRecordsReplacementSnapshotReadOnlyV2',
      'materializeProtectedRecordsReplacementSourceSnapshotV2',
    ]),
  }),
  private_operator_target_shape: Object.freeze({
    relative_path: 'lib/recognized-effect-target-shape.mjs',
    markers: Object.freeze([
      'RECOGNIZED_EFFECT_ACTION_CLASS',
      'RECOGNIZED_EFFECT_SELECTED_CONSEQUENCE',
      'ledger.push(result.effect);',
    ]),
  }),
  private_operator_target_shape_cli: Object.freeze({
    relative_path: 'bin/zlar-recognized-effect-target-shape',
    markers: Object.freeze([
      'verifyRecognizedEffectTargetShapeArtifact',
      'buildRecognizedEffectTargetShapeSampleArtifact',
      'verify requires --input <file|-> or --sample.',
    ]),
  }),
  active_persistent_action_crossing: Object.freeze({
    relative_path:
      'lib/protected-records-active-persistent-profile-action-crossing.mjs',
    markers: Object.freeze([
      'function writeProofTargetMarker({',
      'assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed',
      'writeFileSync(proofTarget, output, { mode: 0o600 });',
    ]),
  }),
  active_persistent_action_crossing_cli: Object.freeze({
    relative_path:
      'bin/zlar-protected-records-active-persistent-profile-action-crossing',
    markers: Object.freeze([
      'runProtectedRecordsActivePersistentProfileActionCrossing',
      'records.write action crosses',
    ]),
  }),
  fixture_authority_status: Object.freeze({
    relative_path: 'lib/protected-records-fixture-authority-status.mjs',
    markers: Object.freeze([
      'export function assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(',
      "status: 'exhausted'",
      'fresh_effect_allowed: false',
    ]),
  }),
  local_proof_pack: Object.freeze({
    relative_path: 'lib/local-proof-pack.mjs',
    markers: Object.freeze([
      'export function runLocalProofPack()',
      'runProtectedRecordsTerminalProof()',
      'runProtectedRecordsAdapterConformanceProof()',
      'runProtectedRecordsServiceProof()',
      'assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(',
    ]),
  }),
  local_proof_pack_cli: Object.freeze({
    relative_path: 'bin/zlar-local-proof-pack',
    markers: Object.freeze([
      'runLocalProofPack',
      'Fresh proof-pack generation refuses before any proof execution.',
    ]),
  }),
  local_boarding_proof: Object.freeze({
    relative_path: 'lib/protected-records-local-boarding-proof.mjs',
    markers: Object.freeze([
      'PROTECTED_RECORDS_LOCAL_BOARDING_EVIDENCE_MODEL',
      'local-in-memory-fixture',
      'consequence_present_exactly_once_on_acceptance',
    ]),
  }),
  boarding_decision: Object.freeze({
    relative_path: 'lib/protected-records-boarding-decision.mjs',
    markers: Object.freeze([
      'export function evaluateProtectedRecordsBoardingDecision',
      'state.effects.push({',
      'recognized_receipt_boarded',
    ]),
  }),
  downstream_refusal_proof: Object.freeze({
    relative_path: 'lib/downstream-refusal-proof.mjs',
    markers: Object.freeze([
      'DOWNSTREAM_REFUSAL_PROOF_TYPE',
      'fake-downstream-effect.jsonl',
      'writeFileSync(markerFile',
    ]),
  }),
});

export const CONSEQUENCE_PATH_COVERAGE_SOURCE_PATHS_V0 = Object.freeze(
  Object.fromEntries(
    Object.entries(SOURCE_SPECS).map(([role, spec]) => [
      role,
      spec.relative_path,
    ]),
  ),
);

const PARAM_KEYS = Object.freeze([
  'baseMapRawBytes',
  'expectedBaseMapFileSha256',
  'expectedBaseMapSha256',
  'expectedDependencyMapSourceCommitOid',
  'expectedHistoricalCrossingSourceCommitOid',
  'expectedIndexBodySha256',
  'expectedIndexFileSha256',
  'expectedOverlayFileSha256',
  'expectedOverlaySha256',
  'expectedSourceInventorySha256',
  'indexRawBytes',
  'overlayRawBytes',
  'sourceFiles',
]);

const NON_CLAIMS = Object.freeze([
  'The map is a caller-pinned source-marker catalogue and dependency projection, not an exhaustive JavaScript control-flow or dynamic reachability proof.',
  'Mutation markers identify review candidates; they do not prove effect capability, executable route existence, runtime reachability, current authority, governed coverage, effect occurrence, or authorization to execute.',
  'Observed uncovered is not authorized outside coverage; no outside-coverage authority artifact was supplied or inferred.',
  'The post-effect index adds no new lifecycle-obligation status and no overlay consumer was built.',
  'The historical crossing source commit does not bind the dependency-map implementation source, and the pure verifier does not invoke Git.',
  'The direct internal v2 child marker is a software routing precondition, not human authority.',
  'Source-recorded exhaustion and fresh-effect-gate markers do not prove call order or current refusal behavior for any wrapper.',
  'The map does not prove domain inventory completeness, equivalent-route closure, lifecycle closure, same-route closeout, rightful issuance, current authority, exactly-once, crash atomicity, recovery, side-door closure, immutable custody, current-machine governance, production, enterprise readiness, public attestation, sovereign recognition, or all-surface governance.',
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
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
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
    throw new Error(`${label} must be a lowercase Git SHA-1 object id`);
  }
}

function rawBuffer(value, label) {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (raw.length < 2 || raw.length > MAX_RAW_BYTES) {
    throw new Error(`${label} size is outside the accepted boundary`);
  }
  return raw;
}

function parseJson(value, label) {
  const raw = rawBuffer(value, label);
  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  return { parsed, raw };
}

function parseCanonicalJson(value, label) {
  const result = parseJson(value, label);
  if (!result.raw.equals(Buffer.from(canonicalize(result.parsed), 'utf8'))) {
    throw new Error(`${label} must be exact canonical JSON`);
  }
  return result;
}

function exactSortedStrings(label, actual, expected) {
  if (!Array.isArray(actual) || actual.some((item) => typeof item !== 'string')) {
    throw new Error(`${label} must be an array of strings`);
  }
  const sorted = [...actual].sort();
  const wanted = [...expected].sort();
  if (
    sorted.length !== wanted.length ||
    sorted.some((item, index) => item !== wanted[index])
  ) {
    throw new Error(`${label} mismatch`);
  }
}

function verifyBaseMap(params) {
  const { parsed: baseMap, raw } = parseJson(
    params.baseMapRawBytes,
    'Base consequence lifecycle map',
  );
  assertExactKeys('Base consequence lifecycle map', baseMap, BASE_MAP_KEYS);
  if (sha256hex(raw) !== params.expectedBaseMapFileSha256) {
    throw new Error('Base consequence lifecycle map file identity mismatch');
  }
  const semanticSha256 = sha256hex(JSON.stringify(baseMap));
  if (semanticSha256 !== params.expectedBaseMapSha256) {
    throw new Error('Base consequence lifecycle map semantic identity mismatch');
  }
  if (
    baseMap.report_type !== 'zlar-consequence-lifecycle-map-v0' ||
    baseMap.map_version !== 0 ||
    baseMap.map_status !== 'mapped_open' ||
    baseMap.authority_domain?.domain_id !== AUTHORITY_DOMAIN ||
    baseMap.authority_domain?.named !== true ||
    baseMap.consequence_path?.path_id !== SELECTED_PATH ||
    baseMap.consequence_path?.action_class !== ACTION_CLASS ||
    baseMap.closure?.closure_status !== 'mapped_open' ||
    baseMap.closure?.lifecycle_closed !== false ||
    baseMap.closure?.lifecycle_governance_proven !== false ||
    baseMap.equivalent_route_inventory?.inventory_status !== 'open' ||
    baseMap.equivalent_route_inventory?.selected_path_id !== SELECTED_PATH ||
    baseMap.equivalent_route_inventory?.live_mcp_coverage_proven !== false ||
    baseMap.equivalent_route_inventory?.unrouted_records_paths_checked !== false ||
    baseMap.equivalent_route_inventory?.closure_blocked !== true
  ) {
    throw new Error('Base consequence lifecycle map selected boundary mismatch');
  }
  const candidates = baseMap.equivalent_route_inventory.candidates;
  if (!Array.isArray(candidates)) {
    throw new Error('Base equivalent-route candidates must be an array');
  }
  const candidateIds = candidates.map((candidate) => {
    assertExactKeys('Base equivalent-route candidate', candidate, [
      'parity_proven',
      'relationship',
      'surface_id',
    ]);
    if (
      typeof candidate.surface_id !== 'string' ||
      candidate.surface_id === SELECTED_PATH ||
      candidate.relationship !== 'unknown' ||
      candidate.parity_proven !== false
    ) {
      throw new Error('Base equivalent-route candidate posture mismatch');
    }
    return candidate.surface_id;
  });
  if (new Set(candidateIds).size !== candidateIds.length) {
    throw new Error('Base equivalent-route candidates must be unique');
  }
  exactSortedStrings(
    'Base equivalent-route candidates',
    candidateIds,
    REQUIRED_BASE_CANDIDATES,
  );
  if (
    !Array.isArray(baseMap.closure.closure_blockers) ||
    !baseMap.closure.closure_blockers.includes(
      'equivalent_route_closure_not_evidenced',
    ) ||
    !baseMap.closure.closure_blockers.includes(
      'unrouted_records_paths_unchecked',
    )
  ) {
    throw new Error('Base equivalent-route closure blockers are missing');
  }
  if (!Array.isArray(baseMap.lifecycle_obligations)) {
    throw new Error('Base lifecycle obligations must be an array');
  }
  const obligationIds = baseMap.lifecycle_obligations.map(
    (item) => item?.obligation_id,
  );
  if (
    obligationIds.some((item) => typeof item !== 'string') ||
    new Set(obligationIds).size !== obligationIds.length
  ) {
    throw new Error('Base lifecycle obligation IDs must be unique strings');
  }
  const obligations = new Map(
    baseMap.lifecycle_obligations.map((item) => [
      item.obligation_id,
      item.status,
    ]),
  );
  for (const obligationId of REQUIRED_BASE_OPEN_OBLIGATIONS) {
    if (obligations.get(obligationId) !== 'not_evidenced') {
      throw new Error(`Base obligation ${obligationId} must remain not_evidenced`);
    }
  }
  return { baseMap, candidateIds: candidateIds.sort(), semanticSha256 };
}

function verifyOverlay(params, base) {
  const { parsed: overlay, raw } = parseJson(
    params.overlayRawBytes,
    'Replacement lifecycle overlay',
  );
  assertExactKeys('Replacement lifecycle overlay', overlay, OVERLAY_KEYS);
  if (sha256hex(raw) !== params.expectedOverlayFileSha256) {
    throw new Error('Replacement lifecycle overlay file identity mismatch');
  }
  const semanticSha256 = sha256hex(canonicalize(overlay));
  if (semanticSha256 !== params.expectedOverlaySha256) {
    throw new Error('Replacement lifecycle overlay semantic identity mismatch');
  }
  const replacement = overlay.replacement_artifact_lineage_v2;
  const baseReference = overlay.base_map_reference;
  if (
    overlay.report_type !==
      'zlar-consequence-lifecycle-map-v0-replacement-artifact-lineage-overlay' ||
    overlay.overlay_version !== 0 ||
    overlay.map_status !== 'mapped_open' ||
    overlay.base_map_sha256 !== base.semanticSha256 ||
    overlay.base_map_file_sha256 !== params.expectedBaseMapFileSha256 ||
    overlay.base_map_schema_fully_validated !== false ||
    overlay.base_map_claim_strings_evaluated !== false ||
    overlay.consequence_reexecution_performed !== false ||
    overlay.manifest_covers_complete_lifecycle !== false ||
    overlay.rightful_issuance_projected !== false ||
    overlay.closure?.closure_status !== 'mapped_open' ||
    overlay.closure?.lifecycle_closed !== false ||
    overlay.claim_boundary?.current_fresh_authority !== false ||
    overlay.claim_boundary?.lifecycle_closure !== false ||
    baseReference?.report_type !== 'zlar-consequence-lifecycle-map-v0' ||
    baseReference?.map_version !== 0 ||
    baseReference?.map_status !== 'mapped_open' ||
    baseReference?.authority_domain_id !== AUTHORITY_DOMAIN ||
    baseReference?.consequence_path !== SELECTED_PATH ||
    baseReference?.action_class !== ACTION_CLASS ||
    baseReference?.path_source_commit_bound !== false ||
    baseReference?.closure_status !== 'mapped_open' ||
    baseReference?.lifecycle_closed !== false ||
    baseReference?.lifecycle_governance_proven !== false ||
    baseReference?.full_object_reprojected !== false ||
    baseReference?.claim_strings_evaluated !== false ||
    replacement?.action_class !== ACTION_CLASS ||
    replacement?.consequence_path !== SELECTED_PATH ||
    replacement?.authority_domain_context !== AUTHORITY_DOMAIN ||
    replacement?.authority_domain_evaluated !== false ||
    replacement?.authority_effect_occurrence_evaluated !== false ||
    replacement?.rightful_issuance_projected !== false ||
    replacement?.consequence_reexecution_performed !== false ||
    replacement?.replacement_crossing_source_commit_oid !==
      params.expectedHistoricalCrossingSourceCommitOid
  ) {
    throw new Error('Replacement lifecycle overlay boundary mismatch');
  }
  return { overlay, replacement, semanticSha256 };
}

function verifyIndex(params, overlay) {
  const { parsed: index, raw } = parseCanonicalJson(
    params.indexRawBytes,
    'Post-effect route-evidence index',
  );
  assertExactKeys('Post-effect route-evidence index', index, INDEX_KEYS);
  if (sha256hex(raw) !== params.expectedIndexFileSha256) {
    throw new Error('Post-effect route-evidence index file identity mismatch');
  }
  assertExactKeys('Post-effect route-evidence index integrity', index.integrity, [
    'body_sha256',
  ]);
  const { integrity: _integrity, ...body } = index;
  const bodySha256 = sha256hex(canonicalize(body));
  if (
    bodySha256 !== params.expectedIndexBodySha256 ||
    index.integrity.body_sha256 !== params.expectedIndexBodySha256
  ) {
    throw new Error('Post-effect route-evidence index body identity mismatch');
  }
  if (
    index.artifact_type !==
      'zlar.protected-records.post-effect-route-evidence-index.v0' ||
    index.schema_version !== 0 ||
    index.action_class !== ACTION_CLASS ||
    index.consequence_path !== SELECTED_PATH ||
    index.authority_domain_context !== AUTHORITY_DOMAIN ||
    index.authority_domain_evaluated !== false ||
    index.verification_mode !== 'verification-only' ||
    index.source_reference?.historical_source_commit_oid !==
      params.expectedHistoricalCrossingSourceCommitOid ||
    index.source_reference?.source_commit_cross_binding_matched !== true ||
    index.source_reference?.source_commit_object_presence_evaluated !== false ||
    index.artifact_set_verification?.authority_status_evaluated !== false ||
    index.artifact_set_verification?.consequence_reexecution_performed !== false ||
    index.artifact_set_verification?.rightful_issuance_projected !== false ||
    index.membership_policy?.lifecycle_overlay_indexed !== false ||
    index.membership_policy?.all_retained_route_files_covered !== false ||
    index.boundaries?.central_manifest_extended !== false ||
    index.boundaries?.consequence_reexecution_performed !== false ||
    index.boundaries?.authority_effect_occurrence_reevaluated !== false ||
    index.boundaries?.current_authority_projected !== false ||
    index.boundaries?.rightful_issuance_projected !== false ||
    index.boundaries?.lifecycle_status_change_authorized !== false ||
    index.boundaries?.lifecycle_closed !== false ||
    index.boundaries?.external_effect_occurrence_proven !== false ||
    index.boundaries?.exactly_once_effect_proven !== false ||
    index.boundaries?.crash_atomic_effect_plus_pin_proven !== false ||
    index.runtime_result_selected_projection
      ?.runtime_result_schema_fully_validated !== false ||
    index.runtime_result_selected_projection
      ?.runtime_result_claim_strings_evaluated !== false ||
    index.runtime_result_selected_projection?.source_binding_cross_match !== true ||
    index.closeout_projection?.closeout_crossing_identity_embedded !== false ||
    index.closeout_projection?.closeout_same_route_proven !== false ||
    index.closeout_projection?.source_recorded_selected_fields
      ?.exactly_once_effect_proven !== false ||
    index.closeout_projection?.source_recorded_selected_fields
      ?.crash_atomic_effect_plus_pin_proven !== false ||
    index.boundaries?.surviving_effect_state_reobserved !== false
  ) {
    throw new Error('Post-effect route-evidence index boundary mismatch');
  }
  const replacement = overlay.replacement;
  if (
    index.artifact_set_verification?.manifest_artifact_body_sha256 !==
      replacement.manifest_artifact_body_sha256 ||
    index.artifact_set_verification?.service_artifact_body_sha256 !==
      replacement.service_artifact_body_sha256 ||
    index.artifact_set_verification?.terminal_artifact_body_sha256 !==
      replacement.terminal_artifact_body_sha256 ||
    index.runtime_result_selected_projection
      ?.source_recorded_crossing_binding_fields
      ?.authority_grant_contract_sha256 !==
      replacement.authority_grant_contract_sha256 ||
    index.exhausted_status_projection?.status_body_sha256 !==
      replacement.exhausted_status_body_sha256
  ) {
    throw new Error('Overlay and post-effect index reported lineage mismatch');
  }
  return { index, bodySha256 };
}

function verifySourceFiles(sourceFiles, expectedInventorySha256) {
  assertExactKeys('Coverage dependency source files', sourceFiles, Object.keys(SOURCE_SPECS));
  const files = [];
  for (const role of Object.keys(SOURCE_SPECS).sort()) {
    const spec = SOURCE_SPECS[role];
    const raw = rawBuffer(sourceFiles[role], `Coverage dependency source ${role}`);
    const text = raw.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(raw)) {
      throw new Error(`Coverage dependency source ${role} must be valid UTF-8`);
    }
    for (const marker of spec.markers) {
      if (!text.includes(marker)) {
        throw new Error(`Coverage dependency source ${role} marker mismatch`);
      }
    }
    files.push({
      role,
      relative_path: spec.relative_path,
      byte_length: raw.length,
      file_sha256: sha256hex(raw),
      required_markers_validated: true,
    });
  }
  const inventorySha256 = sha256hex(canonicalize(files));
  if (inventorySha256 !== expectedInventorySha256) {
    throw new Error('Coverage dependency source inventory identity mismatch');
  }
  return { files, inventorySha256 };
}

export function consequencePathCoverageSourceInventorySha256V0(sourceFiles) {
  assertExactKeys('Coverage dependency source files', sourceFiles, Object.keys(SOURCE_SPECS));
  const files = [];
  for (const role of Object.keys(SOURCE_SPECS).sort()) {
    const spec = SOURCE_SPECS[role];
    const raw = rawBuffer(sourceFiles[role], `Coverage dependency source ${role}`);
    const text = raw.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(raw)) {
      throw new Error(`Coverage dependency source ${role} must be valid UTF-8`);
    }
    for (const marker of spec.markers) {
      if (!text.includes(marker)) {
        throw new Error(`Coverage dependency source ${role} marker mismatch`);
      }
    }
    files.push({
      role,
      relative_path: spec.relative_path,
      byte_length: raw.length,
      file_sha256: sha256hex(raw),
      required_markers_validated: true,
    });
  }
  return sha256hex(canonicalize(files));
}

function effectNodes() {
  return [
    {
      effect_node_id: 'E1.adapter-ledger-append-v1',
      effect_capable: 'source_candidate_unproven',
      effect_primitive_marker_observed: true,
      effect_capability_proven: false,
      target_mutation_primitive: 'ledger-jsonl-append',
      governance_transition_primitive: 'consumed-receipt-json-store-write-before-target-append',
      partial_transition_side_door: 'consumed-receipt-can-burn-before-ledger-append',
      target_kind: 'derived-or-caller-selected-local-fixture-ledger-path',
      logical_target_binding_reported_for_selected_path: false,
      physical_target_identity_bound: false,
      surviving_target_reobserved: false,
      storage: 'local-file-backed-json-and-jsonl',
      primary_source_role: 'adapter',
      relationship_to_selected_path: 'distinct_effect',
      authority_domain_membership: 'unclassified',
      node_scope: 'protected-records-target-mutation-candidate',
    },
    {
      effect_node_id: 'E2.service-jsonl-state-append-v1',
      effect_capable: 'source_candidate_unproven',
      effect_primitive_marker_observed: true,
      effect_capability_proven: false,
      target_mutation_primitive: 'service-state-jsonl-append',
      governance_transition_primitive: 'consumed-receipt-json-store-commit-after-target-append',
      partial_transition_side_door: 'target-append-precedes-store-commit-with-best-effort-rollback',
      target_kind: 'local-fixture-service-state-path-derived-or-caller-selected',
      logical_target_binding_reported_for_selected_path: false,
      physical_target_identity_bound: false,
      surviving_target_reobserved: false,
      storage: 'local-file-backed-jsonl-and-json',
      primary_source_role: 'service',
      relationship_to_selected_path: 'distinct_effect',
      authority_domain_membership: 'unclassified',
      node_scope: 'protected-records-target-mutation-candidate',
    },
    {
      effect_node_id: 'E3.legacy-runtime-process-private-state-v1',
      effect_capable: 'source_candidate_unproven',
      effect_primitive_marker_observed: true,
      effect_capability_proven: false,
      target_mutation_primitive: 'process-private-state-array-append-v1',
      governance_transition_primitive: 'grant-store-anchor-witness-commit-before-target-append',
      partial_transition_side_door: 'grant-can-burn-before-process-private-state-append',
      target_kind: 'process-private-runtime-state-v1',
      logical_target_binding_reported_for_selected_path: false,
      physical_target_identity_bound: false,
      surviving_target_reobserved: false,
      storage: 'process-private-memory-plus-local-grant-store-anchor-witness',
      primary_source_role: 'runtime_profile',
      relationship_to_selected_path: 'distinct_effect',
      authority_domain_membership: 'unclassified',
      node_scope: 'protected-records-target-mutation-candidate',
    },
    {
      effect_node_id: 'E4.replacement-runtime-process-private-state-v2',
      effect_capable: 'historically_reported_source_candidate_unproven_live',
      effect_primitive_marker_observed: true,
      effect_capability_proven: false,
      target_mutation_primitive: 'process-private-state-array-append-v2',
      governance_transition_primitive: 'consumed-store-anchor-witness-commit-before-target-append',
      partial_transition_side_door: 'grant-can-burn-before-process-private-state-append',
      target_kind: 'process-private-recognized-effect-state',
      logical_target_binding_reported_for_selected_path: true,
      physical_target_identity_bound: false,
      surviving_target_reobserved: false,
      storage: 'process-private-memory-plus-local-consumed-store-anchor-witness',
      primary_source_role: 'runtime_profile',
      relationship_to_selected_path: 'authoritative_route',
      authority_domain_membership: 'context_only_not_evaluated',
      node_scope: 'protected-records-target-mutation-candidate',
    },
    {
      effect_node_id: 'E5.active-persistent-proof-target-marker-v1',
      effect_capable: 'source_candidate_unproven',
      effect_primitive_marker_observed: true,
      effect_capability_proven: false,
      target_mutation_primitive: 'proof-owned-filesystem-target-marker-write',
      governance_transition_primitive: null,
      partial_transition_side_door: 'proof-marker-is-not-protected-records-target-state',
      target_kind: 'proof-owned-action-crossing-target',
      logical_target_binding_reported_for_selected_path: false,
      physical_target_identity_bound: false,
      surviving_target_reobserved: false,
      storage: 'local-proof-owned-file',
      primary_source_role: 'active_persistent_action_crossing',
      relationship_to_selected_path: 'distinct_effect',
      authority_domain_membership: 'unclassified',
      node_scope: 'proof-marker-mutation-candidate',
    },
  ];
}

function surface({
  surfaceId,
  surfaceRole,
  entrypointReference,
  entrypointKind,
  sourceModule,
  effectNodeId,
  dependencyEffectNodeIds = [],
  effectNodeEdgeKind,
  relationship,
  sharesSelectedEffectNode,
  consequencePath,
  authorityDomainMembership,
  coverageDisposition,
  effectCapable = 'source_candidate_unproven',
  modeScope,
  historicalRouteEvidenceBound = false,
  freshEffectGateMarkerObserved = false,
  unresolvedSideDoors,
}) {
  return {
    surface_id: surfaceId,
    surface_role: surfaceRole,
    entrypoint_reference: entrypointReference,
    entrypoint_kind: entrypointKind,
    source_module: sourceModule,
    required_source_markers_observed: true,
    effect_or_dependency_markers_observed:
      effectNodeId !== null || dependencyEffectNodeIds.length > 0,
    verification_markers_observed: surfaceRole === 'verification_only',
    effect_capable: effectCapable,
    effect_capability_proven: false,
    effect_node_id: effectNodeId,
    dependency_effect_node_ids: [...dependencyEffectNodeIds],
    effect_node_edge_kind: effectNodeEdgeKind,
    relationship_to_selected_path: relationship,
    shares_selected_effect_node: sharesSelectedEffectNode,
    consequence_path: surfaceId === SELECTED_PATH ? consequencePath : null,
    source_reported_consequence_path_marker: consequencePath,
    authority_domain_context: AUTHORITY_DOMAIN,
    authority_domain_membership: authorityDomainMembership,
    route_existence_proven: false,
    runtime_reachability_proven: false,
    current_refusal_behavior_proven: false,
    fresh_effect_gate_marker_observed: freshEffectGateMarkerObserved,
    historical_route_evidence_bound: historicalRouteEvidenceBound,
    governed_lifecycle_proven: false,
    current_authority_projected: false,
    coverage_disposition: coverageDisposition,
    mode_scope: modeScope,
    authorized_outside_coverage: false,
    outside_coverage_authority_artifact_present: false,
    evidence_freshness: 'caller-pinned-source-marker-observation',
    unresolved_side_doors: [...unresolvedSideDoors],
  };
}

function verificationModeSurface({
  surfaceId,
  entrypointReference,
  sourceModule,
  consequencePath = null,
  authorityDomainMembership = 'unclassified',
  unresolvedSideDoors = [],
}) {
  return surface({
    surfaceId,
    surfaceRole: 'verification_only',
    entrypointReference,
    entrypointKind: 'cli_mode',
    modeScope: 'verification-mode-only',
    sourceModule,
    effectNodeId: null,
    effectNodeEdgeKind: 'no_effect_node_candidate',
    relationship: 'unclassified',
    sharesSelectedEffectNode: false,
    consequencePath,
    authorityDomainMembership,
    coverageDisposition: 'verification_only',
    effectCapable: 'not_evidenced',
    unresolvedSideDoors: [
      'claim-strings-and-transitive-imports-not-fully-evaluated',
      ...unresolvedSideDoors,
    ],
  });
}

function surfaces() {
  const commonUncovered = [
    'current-authority-not-evaluated',
    'route-reachability-and-control-flow-unproven',
    'direct-import-and-custom-loader-reachability-open',
  ];
  return [
    surface({
      surfaceId: 'source-discovered:bin/zlar-command-dispatch',
      surfaceRole: 'multi_command_dispatch_wrapper',
      entrypointReference: 'bin/zlar',
      entrypointKind: 'shell_dispatch',
      modeScope: 'all-dispatched-command-modes',
      sourceModule: 'bin/zlar',
      effectNodeId: null,
      dependencyEffectNodeIds: [
        'E1.adapter-ledger-append-v1',
        'E2.service-jsonl-state-append-v1',
        'E3.legacy-runtime-process-private-state-v1',
        'E4.replacement-runtime-process-private-state-v2',
        'E5.active-persistent-proof-target-marker-v1',
      ],
      effectNodeEdgeKind: 'multi_command_dispatch_candidates',
      relationship: 'unclassified',
      sharesSelectedEffectNode: true,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'one-shell-dispatch-wrapper-routes-multiple-distinct-mutation-candidates',
        'environment-and-path-handling-differ-across-dispatched-commands',
      ],
    }),
    surface({
      surfaceId: SELECTED_PATH,
      surfaceRole: 'selected_entrypoint',
      entrypointReference: 'bin/zlar-protected-records-replacement-crossing-v2',
      entrypointKind: 'cli',
      modeScope: 'crossing-execution-mode',
      sourceModule: 'lib/protected-records-replacement-crossing-cli-v2.mjs',
      effectNodeId: 'E4.replacement-runtime-process-private-state-v2',
      effectNodeEdgeKind: 'historical_selected_route_candidate',
      relationship: 'authoritative_route',
      sharesSelectedEffectNode: true,
      consequencePath: SELECTED_PATH,
      authorityDomainMembership: 'context_only_not_evaluated',
      coverageDisposition: 'historical_effect_evidence_bound_current_authority_not_projected',
      effectCapable:
        'historically_reported_source_candidate_unproven_live',
      historicalRouteEvidenceBound: true,
      unresolvedSideDoors: [
        'direct-internal-v2-child-or-module-invocation',
        'process-private-effect-state-not-reobservable',
        'same-route-closeout-proven-false',
      ],
    }),
    surface({
      surfaceId: 'protected-records.service-profile.records.write',
      surfaceRole: 'wrapper',
      entrypointReference: 'export:runProtectedRecordsServiceProfilePreflight',
      entrypointKind: 'exported_function',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-service-profile.mjs',
      effectNodeId: 'E2.service-jsonl-state-append-v1',
      effectNodeEdgeKind: 'invocation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'preflight-manufactures-fixture-issuer-and-receipt',
        'wrapper-derives-scratch-local-state-paths',
      ],
    }),
    surface({
      surfaceId: 'protected-records.runtime.records.write',
      surfaceRole: 'wrapper',
      entrypointReference: 'bin/zlar-protected-records-runtime-local-activation',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-runtime-local-activation.mjs',
      effectNodeId: 'E3.legacy-runtime-process-private-state-v1',
      effectNodeEdgeKind: 'artifact_generation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: SELECTED_PATH,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'fresh_effect_gate_marker_observed_refusal_unproven',
      effectCapable: 'not_evidenced',
      freshEffectGateMarkerObserved: true,
      unresolvedSideDoors: [
        'underlying-direct-legacy-runtime-source-candidate-remains-open',
        'current-gate-call-order-and-behavior-unproven',
      ],
    }),
    verificationModeSurface({
      surfaceId:
        'source-discovered:bin/zlar-protected-records-runtime-local-activation:verify-mode',
      entrypointReference:
        'bin/zlar-protected-records-runtime-local-activation verify',
      sourceModule: 'lib/protected-records-runtime-local-activation.mjs',
      consequencePath: SELECTED_PATH,
      unresolvedSideDoors: [
        'verification-mode-shares-cli-with-gated-generation-mode',
      ],
    }),
    surface({
      surfaceId: 'protected-records.runtime.profile-installation.records.write',
      surfaceRole: 'wrapper',
      entrypointReference: 'bin/zlar-protected-records-runtime-profile-installation',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-runtime-profile-installation.mjs',
      effectNodeId: 'E3.legacy-runtime-process-private-state-v1',
      effectNodeEdgeKind: 'artifact_generation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: SELECTED_PATH,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'fresh_effect_gate_marker_observed_refusal_unproven',
      effectCapable: 'not_evidenced',
      freshEffectGateMarkerObserved: true,
      unresolvedSideDoors: [
        'installation-writes-are-not-records-consequence',
        'current-gate-call-order-and-behavior-unproven',
      ],
    }),
    verificationModeSurface({
      surfaceId:
        'source-discovered:bin/zlar-protected-records-runtime-profile-installation:verify-mode',
      entrypointReference:
        'bin/zlar-protected-records-runtime-profile-installation verify',
      sourceModule: 'lib/protected-records-runtime-profile-installation.mjs',
      consequencePath: SELECTED_PATH,
      unresolvedSideDoors: [
        'verification-mode-shares-cli-with-gated-generation-mode',
      ],
    }),
    surface({
      surfaceId: 'protected-records.private-operator.records-terminal.records.write',
      surfaceRole: 'verification_only',
      entrypointReference: 'bin/zlar-recognized-effect-target-shape verify',
      entrypointKind: 'cli_mode',
      modeScope: 'verification-mode-only',
      sourceModule: 'lib/recognized-effect-target-shape.mjs',
      effectNodeId: null,
      effectNodeEdgeKind: 'no_effect_node_candidate',
      relationship: 'unclassified',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'verification_only',
      effectCapable: 'not_evidenced',
      unresolvedSideDoors: [
        'relationship-to-active-persistent-proof-marker-unclassified',
        'optional-artifact-output-is-evidence-write-not-target-effect',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-recognized-effect-target-shape:sample-generation',
      surfaceRole: 'proof_generator_wrapper',
      entrypointReference: 'bin/zlar-recognized-effect-target-shape --sample',
      entrypointKind: 'cli_mode',
      modeScope: 'sample-generation-mode-only',
      sourceModule: 'lib/recognized-effect-target-shape.mjs',
      effectNodeId: null,
      effectNodeEdgeKind: 'no_effect_node_candidate',
      relationship: 'unclassified',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'verification_only',
      effectCapable: 'not_evidenced',
      unresolvedSideDoors: [
        'sample-model-in-memory-ledger-is-not-a-protected-records-target-effect',
        'optional-artifact-output-is-evidence-write-not-target-effect',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-write',
      surfaceRole: 'direct_entrypoint',
      entrypointReference: 'bin/zlar-protected-records-write',
      entrypointKind: 'cli',
      modeScope: 'write-execution-mode',
      sourceModule: 'lib/protected-records-adapter.mjs',
      effectNodeId: 'E1.adapter-ledger-append-v1',
      effectNodeEdgeKind: 'mutation_primitive_entry_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'caller-selected-ledger-and-consumed-store-paths',
        'consumed-receipt-can-burn-before-ledger-append',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-proof',
      surfaceRole: 'proof_generator_wrapper',
      entrypointReference: 'bin/zlar-protected-records-proof',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-terminal-proof.mjs',
      effectNodeId: 'E1.adapter-ledger-append-v1',
      effectNodeEdgeKind: 'invocation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'proof-generator-runs-a-disposable-adapter-mutation-candidate',
        'consumed-receipt-can-burn-before-ledger-append',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-adapter-conformance',
      surfaceRole: 'proof_generator_wrapper',
      entrypointReference: 'bin/zlar-protected-records-adapter-conformance',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-adapter-conformance.mjs',
      effectNodeId: 'E1.adapter-ledger-append-v1',
      effectNodeEdgeKind: 'invocation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'conformance-generator-runs-a-disposable-adapter-mutation-candidate',
        'consumed-receipt-can-burn-before-ledger-append',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-service-request:config-mode',
      surfaceRole: 'direct_entrypoint',
      entrypointReference: 'bin/zlar-protected-records-service-request --config',
      entrypointKind: 'cli_mode',
      modeScope: 'config-mode-only',
      sourceModule: 'lib/protected-records-service.mjs',
      effectNodeId: 'E2.service-jsonl-state-append-v1',
      effectNodeEdgeKind: 'mutation_primitive_entry_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'caller-selects-config-file-without-authenticated-launcher-provenance',
        'target-append-precedes-store-commit-with-best-effort-rollback',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-service-request:no-config-mode',
      surfaceRole: 'direct_entrypoint',
      entrypointReference: 'bin/zlar-protected-records-service-request --input',
      entrypointKind: 'cli_mode',
      modeScope: 'no-config-mode-only',
      sourceModule: 'lib/protected-records-service.mjs',
      effectNodeId: 'E2.service-jsonl-state-append-v1',
      effectNodeEdgeKind: 'mutation_primitive_entry_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'no-config-mode-accepts-caller-recognition-rule-time-and-paths',
        'target-append-precedes-store-commit-with-best-effort-rollback',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-service-proof',
      surfaceRole: 'proof_generator_wrapper',
      entrypointReference: 'bin/zlar-protected-records-service-proof',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-service-proof.mjs',
      effectNodeId: 'E2.service-jsonl-state-append-v1',
      effectNodeEdgeKind: 'invocation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'service-proof-generator-runs-disposable-service-mutation-candidates',
        'target-append-precedes-store-commit-with-best-effort-rollback',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-service-preflight',
      surfaceRole: 'proof_generator_wrapper',
      entrypointReference: 'bin/zlar-protected-records-service-preflight',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-service-profile.mjs',
      effectNodeId: 'E2.service-jsonl-state-append-v1',
      effectNodeEdgeKind: 'invocation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'preflight-generation-and-read-only-verify-modes-share-one-cli',
        'target-append-precedes-store-commit-with-best-effort-rollback',
      ],
    }),
    verificationModeSurface({
      surfaceId:
        'source-discovered:bin/zlar-protected-records-service-preflight:verify-mode',
      entrypointReference: 'bin/zlar-protected-records-service-preflight verify',
      sourceModule: 'lib/protected-records-service-profile.mjs',
      unresolvedSideDoors: [
        'verification-mode-shares-cli-with-preflight-generation-mode',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-runtime-service-v1',
      surfaceRole: 'direct_entrypoint',
      entrypointReference: 'bin/zlar-protected-records-runtime-service',
      entrypointKind: 'cli',
      modeScope: 'legacy-v1-execution-mode',
      sourceModule: 'lib/protected-records-runtime-profile.mjs',
      effectNodeId: 'E3.legacy-runtime-process-private-state-v1',
      effectNodeEdgeKind: 'mutation_primitive_entry_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: SELECTED_PATH,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        ...commonUncovered,
        'caller-configured-time-grant-and-store-inputs',
        'current-authority-status-source-gate-absent',
        'grant-can-burn-before-process-private-state-append',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:internal-replacement-runtime-child-v2',
      surfaceRole: 'internal_entrypoint',
      entrypointReference: 'lib/protected-records-replacement-runtime-child-v2.mjs',
      entrypointKind: 'internal_module',
      modeScope: 'internal-child-execution-mode',
      sourceModule: 'lib/protected-records-replacement-runtime-child-v2.mjs',
      effectNodeId: 'E4.replacement-runtime-process-private-state-v2',
      effectNodeEdgeKind: 'internal_invocation_candidate',
      relationship: 'unclassified',
      sharesSelectedEffectNode: true,
      consequencePath: SELECTED_PATH,
      authorityDomainMembership: 'context_only_not_evaluated',
      coverageDisposition: 'observed_uncovered',
      unresolvedSideDoors: [
        'software-routing-marker-is-not-human-authority',
        'direct-module-import-or-reproduced-child-preconditions',
        'grant-can-burn-before-process-private-state-append',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:active-persistent-profile-action-crossing',
      surfaceRole: 'composite_wrapper',
      entrypointReference: 'bin/zlar-protected-records-active-persistent-profile-action-crossing',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-active-persistent-profile-action-crossing.mjs',
      effectNodeId: null,
      dependencyEffectNodeIds: [
        'E3.legacy-runtime-process-private-state-v1',
        'E5.active-persistent-proof-target-marker-v1',
      ],
      effectNodeEdgeKind: 'composite_dependency_candidates',
      relationship: 'unclassified',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'fresh_effect_gate_marker_observed_refusal_unproven',
      effectCapable: 'not_evidenced',
      freshEffectGateMarkerObserved: true,
      unresolvedSideDoors: [
        'proof-marker-is-not-protected-runtime-target',
        'private-operator-relationship-unclassified',
        'current-gate-call-order-and-behavior-unproven',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-local-proof-pack',
      surfaceRole: 'composite_proof_generator_wrapper',
      entrypointReference: 'bin/zlar-local-proof-pack',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/local-proof-pack.mjs',
      effectNodeId: null,
      dependencyEffectNodeIds: [
        'E1.adapter-ledger-append-v1',
        'E2.service-jsonl-state-append-v1',
      ],
      effectNodeEdgeKind: 'composite_dependency_candidates',
      relationship: 'unclassified',
      sharesSelectedEffectNode: false,
      consequencePath: null,
      authorityDomainMembership: 'unclassified',
      coverageDisposition: 'fresh_effect_gate_marker_observed_refusal_unproven',
      effectCapable: 'not_evidenced',
      freshEffectGateMarkerObserved: true,
      unresolvedSideDoors: [
        'current-gate-call-order-and-behavior-unproven',
        'composite-pack-depends-on-multiple-disposable-mutation-candidates',
        'read-only-verify-mode-shares-one-cli',
      ],
    }),
    verificationModeSurface({
      surfaceId: 'source-discovered:bin/zlar-local-proof-pack:verify-mode',
      entrypointReference: 'bin/zlar-local-proof-pack verify',
      sourceModule: 'lib/local-proof-pack.mjs',
      unresolvedSideDoors: [
        'verification-mode-shares-cli-with-gated-proof-generation-mode',
      ],
    }),
    surface({
      surfaceId: 'source-discovered:bin/zlar-protected-records-installed-runtime-profile-terminal-chain',
      surfaceRole: 'wrapper',
      entrypointReference: 'bin/zlar-protected-records-installed-runtime-profile-terminal-chain',
      entrypointKind: 'cli',
      modeScope: 'generation-mode-only',
      sourceModule: 'lib/protected-records-installed-runtime-profile-terminal-chain.mjs',
      effectNodeId: 'E3.legacy-runtime-process-private-state-v1',
      effectNodeEdgeKind: 'artifact_generation_dependency_candidate',
      relationship: 'distinct_effect',
      sharesSelectedEffectNode: false,
      consequencePath: SELECTED_PATH,
      authorityDomainMembership: 'context_only_not_evaluated',
      coverageDisposition: 'fresh_effect_gate_marker_observed_refusal_unproven',
      effectCapable: 'not_evidenced',
      freshEffectGateMarkerObserved: true,
      unresolvedSideDoors: [
        'legacy-terminal-generator-is-not-the-replacement-v2-authoritative-route',
        'current-gate-call-order-and-behavior-unproven',
      ],
    }),
    verificationModeSurface({
      surfaceId:
        'source-discovered:bin/zlar-protected-records-installed-runtime-profile-terminal-chain:verify-mode',
      entrypointReference:
        'bin/zlar-protected-records-installed-runtime-profile-terminal-chain verify',
      sourceModule:
        'lib/protected-records-installed-runtime-profile-terminal-chain.mjs',
      consequencePath: SELECTED_PATH,
      authorityDomainMembership: 'context_only_not_evaluated',
      unresolvedSideDoors: [
        'verification-mode-shares-cli-with-gated-generation-mode',
      ],
    }),
  ];
}

const ALLOWED_RELATIONSHIPS = Object.freeze([
  'authoritative_route',
  'distinct_effect',
  'unclassified',
]);

const ALLOWED_SURFACE_ROLES = Object.freeze([
  'selected_entrypoint',
  'wrapper',
  'verification_only',
  'direct_entrypoint',
  'internal_entrypoint',
  'composite_wrapper',
  'multi_command_dispatch_wrapper',
  'proof_generator_wrapper',
  'composite_proof_generator_wrapper',
]);

const ALLOWED_COVERAGE_DISPOSITIONS = Object.freeze([
  'historical_effect_evidence_bound_current_authority_not_projected',
  'observed_uncovered',
  'fresh_effect_gate_marker_observed_refusal_unproven',
  'verification_only',
  'unclassified',
]);

const ALLOWED_ENTRYPOINT_KINDS = Object.freeze([
  'shell_dispatch',
  'cli',
  'cli_mode',
  'exported_function',
  'internal_module',
]);

const ALLOWED_MODE_SCOPES = Object.freeze([
  'all-dispatched-command-modes',
  'crossing-execution-mode',
  'generation-mode-only',
  'verification-mode-only',
  'write-execution-mode',
  'sample-generation-mode-only',
  'config-mode-only',
  'no-config-mode-only',
  'legacy-v1-execution-mode',
  'internal-child-execution-mode',
]);

const ALLOWED_EFFECT_CAPABLE_POSTURES = Object.freeze([
  'historically_reported_source_candidate_unproven_live',
  'source_candidate_unproven',
  'not_evidenced',
]);

const ALLOWED_EFFECT_NODE_EDGE_KINDS = Object.freeze([
  'historical_selected_route_candidate',
  'mutation_primitive_entry_candidate',
  'invocation_dependency_candidate',
  'artifact_generation_dependency_candidate',
  'internal_invocation_candidate',
  'composite_dependency_candidates',
  'multi_command_dispatch_candidates',
  'no_effect_node_candidate',
]);

function materializeSurfaceTopology(item, nodesById, sourceCommitOid) {
  const associatedNodeIds = item.effect_node_id === null
    ? [...item.dependency_effect_node_ids]
    : [item.effect_node_id];
  const associatedNodes = associatedNodeIds.map((nodeId) => nodesById.get(nodeId));
  const oneNode = associatedNodes.length === 1 ? associatedNodes[0] : null;
  const targetIdentity = oneNode
    ? oneNode.logical_target_binding_reported_for_selected_path === true
      ? 'logical-selected-target-binding-reported-physical-identity-unproven'
      : 'unproven'
    : associatedNodes.length > 1
      ? 'multiple-candidate-target-identities-unproven'
      : null;
  const evidenceLocations = [item.source_module];
  if (!item.entrypoint_reference.startsWith('export:')) {
    evidenceLocations.push(item.entrypoint_reference.split(' ')[0]);
  }
  return {
    ...item,
    effect_node_binding_kind:
      item.effect_node_id !== null
        ? 'single-associated-effect-node-candidate'
        : item.dependency_effect_node_ids.length > 0
          ? 'dependency-effect-node-candidates'
          : 'no-effect-node-candidate',
    mutation_primitive: oneNode
      ? oneNode.target_mutation_primitive
      : associatedNodes.length > 1
        ? 'multiple-dependency-effect-node-candidates'
        : null,
    target_kind: oneNode
      ? oneNode.target_kind
      : associatedNodes.length > 1
        ? 'multiple-candidate-target-kinds'
        : null,
    target_identity: targetIdentity,
    target_storage: oneNode
      ? oneNode.storage
      : associatedNodes.length > 1
        ? 'multiple-candidate-storage-kinds'
        : null,
    upstream_dependencies: item.historical_route_evidence_bound
      ? [
          'caller-pinned-source-inventory',
          'caller-pinned-replacement-lifecycle-overlay',
          'caller-pinned-post-effect-route-evidence-index',
        ]
      : ['caller-pinned-source-inventory'],
    downstream_dependencies: associatedNodeIds,
    evidence_locations: [...new Set(evidenceLocations)].sort(),
    caller_pinned_source_commit_oid_unverified: sourceCommitOid,
  };
}

function knownStaticWrapperObservations(sourceCommitOid) {
  return KNOWN_STATIC_WRAPPERS_NOT_CATALOGUED.map((entrypoint) => ({
    surface_id: `known-static-uncatalogued:${entrypoint}`,
    surface_role: 'wrapper',
    executable_entrypoint: entrypoint,
    source_module: null,
    required_source_markers_observed: false,
    effect_capable: 'not_evidenced',
    effect_capability_proven: false,
    effect_node_id: null,
    mutation_primitive: null,
    target_kind: null,
    target_identity: null,
    target_storage: null,
    consequence_path: null,
    source_reported_consequence_path_marker: null,
    authority_domain_context: AUTHORITY_DOMAIN,
    authority_domain_membership: 'unclassified',
    upstream_dependencies: [],
    downstream_dependencies: [],
    relationship_to_selected_path: 'unclassified',
    evidence_locations: [entrypoint],
    caller_pinned_source_commit_oid_unverified: sourceCommitOid,
    evidence_freshness: 'known-static-path-observation-not-source-pinned',
    coverage_disposition: 'unclassified',
    unresolved_side_doors: [
      'not-in-v0-pinned-source-inventory',
      'effect-node-and-mode-relationship-unclassified',
    ],
  }));
}

function validateTopology(nodes, mappedSurfaces) {
  const nodeIds = nodes.map((item) => item.effect_node_id);
  if (new Set(nodeIds).size !== nodeIds.length) {
    throw new Error('Effect-node IDs must be unique');
  }
  const surfaceIds = mappedSurfaces.map((item) => item.surface_id);
  if (new Set(surfaceIds).size !== surfaceIds.length) {
    throw new Error('Surface IDs must be unique');
  }
  const nodeIdSet = new Set(nodeIds);
  for (const node of nodes) {
    if (!ALLOWED_RELATIONSHIPS.includes(node.relationship_to_selected_path)) {
      throw new Error(`Effect node ${node.effect_node_id} relationship is unsupported`);
    }
    if (!ALLOWED_EFFECT_CAPABLE_POSTURES.includes(node.effect_capable)) {
      throw new Error(`Effect node ${node.effect_node_id} capability posture is unsupported`);
    }
    if (
      node.effect_capability_proven !== false ||
      node.effect_primitive_marker_observed !== true ||
      !['context_only_not_evaluated', 'unclassified'].includes(
        node.authority_domain_membership,
      )
    ) {
      throw new Error(`Effect node ${node.effect_node_id} proof boundary drifted`);
    }
  }
  const authoritativeNodes = nodes.filter(
    (item) => item.relationship_to_selected_path === 'authoritative_route',
  );
  if (
    authoritativeNodes.length !== 1 ||
    authoritativeNodes[0].effect_node_id !==
      'E4.replacement-runtime-process-private-state-v2'
  ) {
    throw new Error('Exactly E4 must be the sole authoritative-route node');
  }
  for (const item of mappedSurfaces) {
    if (!ALLOWED_RELATIONSHIPS.includes(item.relationship_to_selected_path)) {
      throw new Error(`Surface ${item.surface_id} relationship is unsupported`);
    }
    if (!ALLOWED_EFFECT_CAPABLE_POSTURES.includes(item.effect_capable)) {
      throw new Error(`Surface ${item.surface_id} capability posture is unsupported`);
    }
    if (!ALLOWED_SURFACE_ROLES.includes(item.surface_role)) {
      throw new Error(`Surface ${item.surface_id} role is unsupported`);
    }
    if (!ALLOWED_ENTRYPOINT_KINDS.includes(item.entrypoint_kind)) {
      throw new Error(`Surface ${item.surface_id} entrypoint kind is unsupported`);
    }
    if (!ALLOWED_COVERAGE_DISPOSITIONS.includes(item.coverage_disposition)) {
      throw new Error(`Surface ${item.surface_id} coverage disposition is unsupported`);
    }
    if (!ALLOWED_EFFECT_NODE_EDGE_KINDS.includes(item.effect_node_edge_kind)) {
      throw new Error(`Surface ${item.surface_id} effect-node edge is unsupported`);
    }
    if (!ALLOWED_MODE_SCOPES.includes(item.mode_scope)) {
      throw new Error(`Surface ${item.surface_id} mode scope is required`);
    }
    if (item.effect_node_id !== null && !nodeIdSet.has(item.effect_node_id)) {
      throw new Error(`Surface ${item.surface_id} references an unknown effect node`);
    }
    if (
      item.effect_node_id !== null &&
      item.dependency_effect_node_ids.length !== 0
    ) {
      throw new Error(`Surface ${item.surface_id} mixes single and multi-node bindings`);
    }
    if (
      item.effect_node_id === null &&
      item.dependency_effect_node_ids.length === 1
    ) {
      throw new Error(`Surface ${item.surface_id} must use its unique effect_node_id`);
    }
    const noEffectNode =
      item.effect_node_id === null && item.dependency_effect_node_ids.length === 0;
    if (
      (item.effect_node_edge_kind === 'no_effect_node_candidate') !==
      noEffectNode
    ) {
      throw new Error(`Surface ${item.surface_id} no-node edge posture drifted`);
    }
    if (
      (item.effect_or_dependency_markers_observed === true) !== !noEffectNode ||
      item.verification_markers_observed !==
        (item.surface_role === 'verification_only')
    ) {
      throw new Error(`Surface ${item.surface_id} marker posture drifted`);
    }
    if (
      item.effect_node_edge_kind === 'historical_selected_route_candidate' &&
      (item.surface_id !== SELECTED_PATH ||
        item.effect_node_id !==
          'E4.replacement-runtime-process-private-state-v2')
    ) {
      throw new Error('Historical selected edge must bind only selected E4');
    }
    if (
      item.effect_node_edge_kind === 'mutation_primitive_entry_candidate' &&
      (item.surface_role !== 'direct_entrypoint' || item.effect_node_id === null)
    ) {
      throw new Error(`Surface ${item.surface_id} mutation-entry edge drifted`);
    }
    if (
      item.effect_node_edge_kind === 'internal_invocation_candidate' &&
      (item.surface_role !== 'internal_entrypoint' ||
        item.effect_node_id !==
          'E4.replacement-runtime-process-private-state-v2')
    ) {
      throw new Error(`Surface ${item.surface_id} internal edge drifted`);
    }
    if (
      item.effect_node_edge_kind === 'composite_dependency_candidates' &&
      (!['composite_wrapper', 'composite_proof_generator_wrapper'].includes(
        item.surface_role,
      ) || item.dependency_effect_node_ids.length < 2)
    ) {
      throw new Error(`Surface ${item.surface_id} composite edge drifted`);
    }
    if (
      item.effect_node_edge_kind === 'multi_command_dispatch_candidates' &&
      (item.surface_role !== 'multi_command_dispatch_wrapper' ||
        item.dependency_effect_node_ids.length < 2)
    ) {
      throw new Error(`Surface ${item.surface_id} dispatch edge drifted`);
    }
    if (
      item.effect_node_edge_kind === 'artifact_generation_dependency_candidate' &&
      (item.surface_role !== 'wrapper' || item.effect_node_id === null)
    ) {
      throw new Error(`Surface ${item.surface_id} artifact edge drifted`);
    }
    if (
      item.effect_node_edge_kind === 'invocation_dependency_candidate' &&
      (!['wrapper', 'proof_generator_wrapper'].includes(item.surface_role) ||
        item.effect_node_id === null)
    ) {
      throw new Error(`Surface ${item.surface_id} invocation edge drifted`);
    }
    if (
      new Set(item.dependency_effect_node_ids).size !==
      item.dependency_effect_node_ids.length
    ) {
      throw new Error(`Surface ${item.surface_id} has duplicate dependency nodes`);
    }
    for (const nodeId of item.dependency_effect_node_ids) {
      if (!nodeIdSet.has(nodeId)) {
        throw new Error(`Surface ${item.surface_id} dependency effect node is unknown`);
      }
    }
    const allAssociatedNodes = new Set([
      ...(item.effect_node_id === null ? [] : [item.effect_node_id]),
      ...item.dependency_effect_node_ids,
    ]);
    const sharesSelected = allAssociatedNodes.has(
      'E4.replacement-runtime-process-private-state-v2',
    );
    if (item.shares_selected_effect_node !== sharesSelected) {
      throw new Error(`Surface ${item.surface_id} selected-node relation drifted`);
    }
    if (
      item.route_existence_proven !== false ||
      item.runtime_reachability_proven !== false ||
      item.effect_capability_proven !== false ||
      item.current_refusal_behavior_proven !== false ||
      item.authorized_outside_coverage !== false ||
      item.outside_coverage_authority_artifact_present !== false ||
      !['context_only_not_evaluated', 'unclassified'].includes(
        item.authority_domain_membership,
      )
    ) {
      throw new Error(`Surface ${item.surface_id} proof boundary drifted`);
    }
    if (
      (item.surface_id === SELECTED_PATH && item.consequence_path !== SELECTED_PATH) ||
      (item.surface_id !== SELECTED_PATH && item.consequence_path !== null)
    ) {
      throw new Error(`Surface ${item.surface_id} consequence-path assignment drifted`);
    }
    if (
      (item.surface_role === 'verification_only' ||
        item.fresh_effect_gate_marker_observed === true) &&
      item.effect_capable !== 'not_evidenced'
    ) {
      throw new Error(`Surface ${item.surface_id} cannot be labeled effect-capable`);
    }
    if (
      item.surface_role === 'verification_only' &&
      (item.effect_node_id !== null || item.dependency_effect_node_ids.length !== 0)
    ) {
      throw new Error(`Verification-only surface ${item.surface_id} cannot bind an effect node`);
    }
  }
  const selected = mappedSurfaces.find((item) => item.surface_id === SELECTED_PATH);
  if (
    selected?.relationship_to_selected_path !== 'authoritative_route' ||
    selected?.effect_node_id !== 'E4.replacement-runtime-process-private-state-v2' ||
    selected?.effect_node_edge_kind !== 'historical_selected_route_candidate' ||
    selected?.mode_scope !== 'crossing-execution-mode' ||
    selected?.historical_route_evidence_bound !== true ||
    selected?.shares_selected_effect_node !== true
  ) {
    throw new Error('Selected surface topology drifted');
  }
  if (
    mappedSurfaces.some(
      (item) =>
        item.surface_id !== SELECTED_PATH &&
        item.relationship_to_selected_path === 'authoritative_route',
    )
  ) {
    throw new Error('Only the selected surface may be the authoritative route');
  }
}

function buildBody(params) {
  assertExactKeys('Coverage dependency map input', params, PARAM_KEYS);
  for (const [label, value] of [
    ['Base map file', params.expectedBaseMapFileSha256],
    ['Base map semantic', params.expectedBaseMapSha256],
    ['Overlay file', params.expectedOverlayFileSha256],
    ['Overlay semantic', params.expectedOverlaySha256],
    ['Index file', params.expectedIndexFileSha256],
    ['Index body', params.expectedIndexBodySha256],
    ['Source inventory', params.expectedSourceInventorySha256],
  ]) {
    assertSha256(label, value);
  }
  assertGitSha1(
    'Historical crossing source commit',
    params.expectedHistoricalCrossingSourceCommitOid,
  );
  assertGitSha1(
    'Dependency map source commit',
    params.expectedDependencyMapSourceCommitOid,
  );
  const base = verifyBaseMap(params);
  const overlay = verifyOverlay(params, base);
  const index = verifyIndex(params, overlay);
  const source = verifySourceFiles(
    params.sourceFiles,
    params.expectedSourceInventorySha256,
  );
  const nodes = effectNodes().map((item) => ({
    ...item,
    authority_domain_context: AUTHORITY_DOMAIN,
    source_module: SOURCE_SPECS[item.primary_source_role].relative_path,
    caller_pinned_source_commit_oid_unverified:
      params.expectedDependencyMapSourceCommitOid,
    evidence_locations: [SOURCE_SPECS[item.primary_source_role].relative_path],
    evidence_freshness: 'caller-pinned-source-marker-observation',
  }));
  const nodesById = new Map(nodes.map((item) => [item.effect_node_id, item]));
  const mappedSurfaces = surfaces().map((item) =>
    materializeSurfaceTopology(
      item,
      nodesById,
      params.expectedDependencyMapSourceCommitOid,
    ),
  ).sort((a, b) =>
    a.surface_id.localeCompare(b.surface_id),
  );
  const knownUncataloguedWrappers = knownStaticWrapperObservations(
    params.expectedDependencyMapSourceCommitOid,
  );
  validateTopology(nodes, mappedSurfaces);
  const observedUncoveredCount = mappedSurfaces.filter(
    (item) => item.coverage_disposition === 'observed_uncovered',
  ).length;
  const unresolvedSurfaceCount = mappedSurfaces.filter(
    (item) =>
      item.unresolved_side_doors.length > 0 ||
      item.coverage_disposition === 'observed_uncovered' ||
      item.relationship_to_selected_path === 'unclassified' ||
      item.authority_domain_membership === 'unclassified' ||
      (item.fresh_effect_gate_marker_observed === true &&
        item.current_refusal_behavior_proven === false),
  ).length + knownUncataloguedWrappers.length;

  return {
    artifact_type: CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_TYPE_V0,
    schema_version: CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_VERSION_V0,
    map_status: 'mapped_open',
    action_class: ACTION_CLASS,
    consequence_path: SELECTED_PATH,
    authority_domain_context: AUTHORITY_DOMAIN,
    authority_domain_evaluated: false,
    verification_mode:
      'verification-only-source-marker-catalogue-and-dependency-projection',
    canonicalization: CANONICALIZATION,
    hash_scope: HASH_SCOPE,
    safe_claim_ceiling:
      'One exact caller-pinned source-marker checkpoint catalogues four protected-records target-mutation candidates plus one proof-marker mutation candidate, separates surface role from relationship to the selected v2 candidate, and records observed-uncovered or unclassified surfaces without proving executable reachability, authority-domain membership, effect capability, or domain completeness.',
    overlay_consumer_decision: {
      decision: 'no_go_no_new_lifecycle_evidence',
      question_answer:
        'The index co-binds and verifies already recorded evidence; it does not add a new underlying lifecycle fact.',
      named_obligation_candidate: null,
      genuinely_new_underlying_fact: null,
      same_route_provenance_newly_proven: false,
      exact_before_after_claim_delta: 'none',
      consumer_built: false,
      consumer_execution_performed: false,
      new_underlying_lifecycle_facts: 0,
      new_evidence_refs_added: 0,
      obligation_status_changes: [],
      new_claims_allowed: [],
      consumer_justified: false,
      wrapper_creation_authorized: false,
      map_status_before: 'mapped_open',
      map_status_after: 'mapped_open',
    },
    source_binding: {
      repository_id: 'ZLAR_Repo',
      git_object_format: 'sha1',
      dependency_map_source_commit_oid:
        params.expectedDependencyMapSourceCommitOid,
      dependency_map_source_commit_caller_pinned: true,
      dependency_map_source_commit_object_presence_evaluated: false,
      loaded_source_matches_commit_evaluated: false,
      source_inventory_sha256: source.inventorySha256,
      source_inventory_files: source.files,
      required_source_markers_observed: true,
      source_ast_or_control_flow_proven: false,
      dynamic_reachability_proven: false,
      historical_crossing_source_commit_oid:
        params.expectedHistoricalCrossingSourceCommitOid,
      historical_crossing_source_cross_bound: true,
    },
    caller_pinned_dependencies: {
      base_lifecycle_map: {
        report_type: 'zlar-consequence-lifecycle-map-v0',
        map_version: 0,
        file_sha256: params.expectedBaseMapFileSha256,
        semantic_sha256: base.semanticSha256,
        selected_boundary_fields_validated: true,
        schema_fully_validated: false,
        claim_strings_evaluated: false,
      },
      replacement_lifecycle_overlay: {
        report_type:
          'zlar-consequence-lifecycle-map-v0-replacement-artifact-lineage-overlay',
        overlay_version: 0,
        file_sha256: params.expectedOverlayFileSha256,
        semantic_sha256: overlay.semanticSha256,
        selected_boundary_fields_validated: true,
        schema_fully_validated: false,
        claim_strings_evaluated: false,
      },
      post_effect_route_evidence_index: {
        artifact_type:
          'zlar.protected-records.post-effect-route-evidence-index.v0',
        schema_version: 0,
        file_sha256: params.expectedIndexFileSha256,
        body_sha256: index.bodySha256,
        self_integrity_validated: true,
        selected_boundary_fields_validated: true,
        schema_fully_validated: false,
        underlying_member_bytes_revalidated: false,
        claim_strings_evaluated: false,
      },
    },
    dependency_cross_bindings: {
      selected_dependency_fields_cross_matched: true,
      base_map_identity_matches_overlay: true,
      selected_path_matches_across_dependencies: true,
      authority_domain_context_matches_across_dependencies: true,
      historical_crossing_source_matches_overlay_and_index: true,
      reported_artifact_lineage_matches_overlay_and_index: true,
      reported_exhausted_status_matches_overlay_and_index: true,
      reported_grant_matches_overlay_and_index: true,
      underlying_post_effect_member_bytes_revalidated: false,
      authority_effect_occurrence_reevaluated: false,
    },
    coverage_classification_contract: {
      observation_creates_authority: false,
      observed_uncovered_is_authorized_outside_coverage: false,
      authorized_outside_coverage_requires_separate_exact_authority_artifact:
        true,
      separate_outside_coverage_authority_artifact_supplied: false,
      authorized_outside_coverage_inferred: false,
      base_lifecycle_obligation_outside_coverage_is_route_authorization: false,
      human_authority_substitutes_for_missing_topology_evidence: false,
    },
    topology_model: {
      surface_role_and_effect_relationship_separated: true,
      source_marker_catalogue_validated: true,
      source_markers_prove_effect_capability: false,
      source_markers_prove_route_existence: false,
      source_markers_prove_runtime_reachability: false,
      exact_javascript_control_flow_proven: false,
      surface_count_does_not_equal_effect_exit_count: true,
      wrappers_counted_as_distinct_effect_exits: false,
      verification_only_surfaces_counted_as_effect_exits: false,
      refusal_marker_surfaces_counted_as_effect_exits: false,
      source_projected_mutation_node_candidate_count: nodes.length,
      protected_records_target_mutation_candidate_count: nodes.filter(
        (item) => item.node_scope === 'protected-records-target-mutation-candidate',
      ).length,
      proof_marker_mutation_candidate_count: nodes.filter(
        (item) => item.node_scope === 'proof-marker-mutation-candidate',
      ).length,
      node_inclusion_rule:
        'Include exact caller-pinned protected-records target-mutation markers plus the separately labeled active-persistent proof-target marker; exclude unscoped local-boarding and generic downstream marker observations from the named-domain candidate count.',
      surface_count: mappedSurfaces.length,
      known_static_uncatalogued_wrapper_count:
        knownUncataloguedWrappers.length,
      selected_effect_node_id:
        'E4.replacement-runtime-process-private-state-v2',
      effect_nodes: nodes,
      surfaces: mappedSurfaces,
      known_static_wrappers_not_catalogued: knownUncataloguedWrappers,
      excluded_nonconsequence_mutations: [
        'artifact-evidence-and-report-writes',
        'disposable-profile-and-index-installation-writes',
        'consumed-grant-status-anchor-and-witness-governance-state-writes',
      ],
      unscoped_effect_observations: [
        {
          observation_id: 'local-boarding-simulated-in-memory-effect',
          source_roles: ['local_boarding_proof', 'boarding_decision'],
          relationship_to_named_domain: 'unclassified',
          counted_as_domain_effect_node: false,
        },
        {
          observation_id: 'generic-downstream-refusal-temporary-marker',
          source_roles: ['downstream_refusal_proof'],
          relationship_to_named_domain: 'unclassified',
          counted_as_domain_effect_node: false,
        },
      ],
    },
    base_candidate_disposition: base.candidateIds.map((candidatePathId) => {
      const item = mappedSurfaces.find(
        (candidate) => candidate.surface_id === candidatePathId,
      );
      if (!item) {
        throw new Error(`Base candidate ${candidatePathId} lacks a source disposition`);
      }
      return {
        candidate_path_id: candidatePathId,
        base_relationship: 'unknown',
        base_parity_proven: false,
        source_projected_surface_role: item.surface_role,
        source_projected_relationship_to_selected:
          item.relationship_to_selected_path,
        source_projected_effect_node_id: item.effect_node_id,
        source_projected_dependency_effect_node_ids:
          item.dependency_effect_node_ids,
        shares_selected_effect_node: item.shares_selected_effect_node,
        route_existence_proven: item.route_existence_proven,
        required_source_markers_observed:
          item.required_source_markers_observed,
        effect_capable: item.effect_capable,
        effect_capability_proven: item.effect_capability_proven,
        coverage_disposition: item.coverage_disposition,
        authorized_outside_coverage: false,
        blocks_equivalent_route_closure: true,
        governed_lifecycle_proven: false,
      };
    }),
    domain_inventory: {
      inventory_basis:
        'caller-pinned-base-map-plus-exact-source-marker-observations',
      selected_path_count: 1,
      observed_base_candidate_count: base.candidateIds.length,
      source_observed_surface_count: mappedSurfaces.length,
      known_static_uncatalogued_wrapper_count:
        knownUncataloguedWrappers.length,
      source_projected_mutation_node_candidate_count: nodes.length,
      protected_records_target_mutation_candidate_count: nodes.filter(
        (item) => item.node_scope === 'protected-records-target-mutation-candidate',
      ).length,
      proof_marker_mutation_candidate_count: nodes.filter(
        (item) => item.node_scope === 'proof-marker-mutation-candidate',
      ).length,
      observed_uncovered_count: observedUncoveredCount,
      authorized_outside_coverage_count: 0,
      governed_equivalent_route_count: 0,
      unresolved_surface_count: unresolvedSurfaceCount,
      unresolved_surface_count_predicate:
        'surface has an unresolved side door, observed_uncovered disposition, unclassified relationship or domain membership, or a fresh-effect-gate marker with unproven current-refusal behavior',
      all_catalogued_surfaces_status_recorded: true,
      all_known_static_uncatalogued_wrappers_visible: true,
      all_observed_candidates_status_recorded: false,
      unrouted_records_paths_checked: false,
      additional_unobserved_routes_ruled_out: false,
      domain_inventory_complete: false,
    },
    domain_inventory_complete: false,
    equivalent_route_closure: false,
    closure: {
      map_status: 'mapped_open',
      coverage_dependency_closure: false,
      equivalent_route_closure: false,
      lifecycle_closed: false,
      base_equivalent_route_blocker_preserved: true,
      outside_coverage_authorization_inferred: false,
      unresolved_surface_count: unresolvedSurfaceCount,
    },
    claim_boundary: {
      current_authority: false,
      rightful_issuance: false,
      same_route_closeout: false,
      exactly_once_effect: false,
      crash_atomicity: false,
      recovery: false,
      domain_inventory_completeness: false,
      equivalent_route_closure: false,
      lifecycle_closure: false,
      side_door_closure: false,
      current_machine_governance: false,
      production_governance: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      all_surface_governance: false,
    },
    side_doors: [
      'direct-adapter-caller-selected-ledger-and-store-paths',
      'direct-service-no-config-caller-rule-time-and-paths',
      'direct-service-config-caller-selected-config-without-authenticated-launcher-provenance',
      'direct-legacy-runtime-v1-caller-configured-time-grant-and-stores',
      'direct-internal-v2-child-or-module-invocation',
      'proof-and-conformance-wrappers-can-reach-disposable-e1-or-e2-mutation-candidates',
      'consumed-receipt-can-burn-before-adapter-ledger-append',
      'service-target-append-can-precede-consumed-store-commit',
      'runtime-grant-can-burn-before-process-private-state-append',
      'raw-filesystem-writes-around-fixture-storage',
      'dynamic-or-generated-entrypoints-absent-from-static-inventory',
      'node-options-loaders-preloads-interpreter-path-and-same-user-source-mutation',
      'shell-mcp-browser-app-control-filesystem-and-network-routes-not-bound-to-an-effect-node',
      'source-drift-after-the-caller-pinned-checkpoint',
      'unbound-process-private-target-identity-and-vanished-effect-state',
      'parent-process-stdout-destination',
      'main-zlar-shell-dispatch-routes-multiple-candidate-nodes-and-command-modes',
      'required-markers-can-survive-only-in-comments-or-unreachable-text',
      'transitive-imported-modules-outside-the-pinned-source-spec-set',
      'repo-root-intermediate-directory-symlinks-not-covered-by-final-component-no-follow',
      'dual-mode-generation-and-verification-clis-require-mode-specific-classification',
    ],
    non_claims: [...NON_CLAIMS],
  };
}

export function buildConsequencePathCoverageDependencyMapV0(params) {
  const body = buildBody(params);
  return {
    ...body,
    integrity: {
      body_sha256: sha256hex(canonicalize(body)),
    },
  };
}

export function assertConsequencePathCoverageDependencyMapV0(report, params) {
  assertObject('Coverage dependency map', report);
  assertExactKeys('Coverage dependency map integrity', report.integrity, [
    'body_sha256',
  ]);
  const expected = buildConsequencePathCoverageDependencyMapV0(params);
  if (canonicalize(report) !== canonicalize(expected)) {
    throw new Error('Coverage dependency map does not match the exact verified projection');
  }
  return true;
}

export function canonicalConsequencePathCoverageDependencyMapBytesV0(
  report,
  params,
) {
  assertConsequencePathCoverageDependencyMapV0(report, params);
  return Buffer.from(canonicalize(report), 'utf8');
}

export function formatConsequencePathCoverageDependencyMapSummaryV0(
  report,
  params,
) {
  assertConsequencePathCoverageDependencyMapV0(report, params);
  return [
    `Coverage dependency map: ${report.map_status}`,
    `Overlay consumer: ${report.overlay_consumer_decision.decision}`,
    `Selected path: ${report.consequence_path}`,
    `Mutation-node candidates: ${report.topology_model.source_projected_mutation_node_candidate_count}`,
    `Surfaces: ${report.topology_model.surface_count}`,
    `Observed uncovered: ${report.domain_inventory.observed_uncovered_count}`,
    `Domain inventory complete: ${report.domain_inventory_complete}`,
    `Equivalent-route closure: ${report.equivalent_route_closure}`,
    `Lifecycle closed: ${report.closure.lifecycle_closed}`,
    `Map body SHA-256: ${report.integrity.body_sha256}`,
  ].join('\n');
}
