#!/usr/bin/env node
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { canonicalize } from '../lib/canonicalize.mjs';
import { sha256hex } from '../lib/sha256.mjs';
import {
  CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_TYPE_V0,
  CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_VERSION_V0,
  CONSEQUENCE_PATH_COVERAGE_SOURCE_PATHS_V0,
  assertConsequencePathCoverageDependencyMapV0,
  buildConsequencePathCoverageDependencyMapV0,
  canonicalConsequencePathCoverageDependencyMapBytesV0,
  consequencePathCoverageSourceInventorySha256V0,
  formatConsequencePathCoverageDependencyMapSummaryV0,
} from '../lib/consequence-path-coverage-dependency-map-v0.mjs';
import {
  sourceBoundHistoricalSourceFilesV0,
  writeSourceBoundHistoricalRootV0,
} from './source-bound-historical-source-v0.mjs';

const PROJECT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(PROJECT_DIR, 'bin/zlar-consequence-path-coverage-dependency-map-v0');
const SELECTED_PATH =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
const AUTHORITY_DOMAIN = 'protected-records.local-disposable-fixture';
const HISTORICAL_COMMIT = '9'.repeat(40);
const MAP_SOURCE_COMMIT = '8'.repeat(40);
const HASHES = Object.freeze({
  manifest: '1'.repeat(64),
  service: '2'.repeat(64),
  terminal: '3'.repeat(64),
  grant: '4'.repeat(64),
  exhausted: '5'.repeat(64),
});

let assertions = 0;
function assert(label, condition) {
  assertions += 1;
  if (!condition) throw new Error(`FAIL: ${label}`);
}

function equal(label, expected, actual) {
  assert(label, Object.is(expected, actual));
}

function deepEqual(label, expected, actual) {
  assert(label, canonicalize(expected) === canonicalize(actual));
}

function throws(label, fn, pattern) {
  assertions += 1;
  try {
    fn();
  } catch (error) {
    if (pattern && !pattern.test(error?.message || '')) {
      throw new Error(`FAIL: ${label}: wrong error ${error?.message}`);
    }
    return;
  }
  throw new Error(`FAIL: ${label}: did not throw`);
}

function section(name) {
  process.stdout.write(`\n## ${name}\n`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function baseMap() {
  const obligations = [
    'local_fixture_rightful_issuance',
    'path_closeout',
    'consequence_recovery',
    'hardening_proposal',
    'hardening_authorization',
    'hardening_application',
    'regression_verification',
    'equivalent_route_closure',
  ].map((obligationId) => ({
    obligation_id: obligationId,
    status: 'not_evidenced',
  }));
  return {
    authority_domain: { domain_id: AUTHORITY_DOMAIN, named: true },
    authority_topology: {},
    claim_boundary: { lifecycle_closure: false },
    closure: {
      closure_status: 'mapped_open',
      lifecycle_closed: false,
      lifecycle_governance_proven: false,
      closure_blockers: [
        'equivalent_route_closure_not_evidenced',
        'unrouted_records_paths_unchecked',
      ],
    },
    consequence_path: { path_id: SELECTED_PATH, action_class: 'records.write' },
    effect_boundary: {},
    equivalent_route_inventory: {
      inventory_status: 'open',
      selected_path_id: SELECTED_PATH,
      candidates: [
        'protected-records.service-profile.records.write',
        'protected-records.runtime.records.write',
        'protected-records.runtime.profile-installation.records.write',
        'protected-records.private-operator.records-terminal.records.write',
      ].map((surfaceId) => ({
        surface_id: surfaceId,
        relationship: 'unknown',
        parity_proven: false,
      })),
      live_mcp_coverage_proven: false,
      unrouted_records_paths_checked: false,
      closure_blocked: true,
    },
    evidence_ref_resolution: {},
    learning_boundary: {},
    lifecycle_obligations: obligations,
    map_status: 'mapped_open',
    map_version: 0,
    non_claims: ['synthetic-base-claim-string-remains-opaque'],
    observed_traces: [],
    path_definition: {},
    receipt_integrity: {},
    report_type: 'zlar-consequence-lifecycle-map-v0',
    revocation_powers: {},
    safe_claim_ceiling: 'synthetic base safe claim',
    side_doors: {},
    source_evidence: {},
  };
}

function overlay(baseSemanticSha256, baseFileSha256) {
  return {
    base_map_boundary_fields_validated: true,
    base_map_claim_strings_evaluated: false,
    base_map_file_sha256: baseFileSha256,
    base_map_reference: {
      report_type: 'zlar-consequence-lifecycle-map-v0',
      map_version: 0,
      map_status: 'mapped_open',
      authority_domain_id: AUTHORITY_DOMAIN,
      consequence_path: SELECTED_PATH,
      action_class: 'records.write',
      path_source_commit_bound: false,
      closure_status: 'mapped_open',
      lifecycle_closed: false,
      lifecycle_governance_proven: false,
      full_object_reprojected: false,
      claim_strings_evaluated: false,
    },
    base_map_schema_fully_validated: false,
    base_map_sha256: baseSemanticSha256,
    claim_boundary: {
      current_fresh_authority: false,
      lifecycle_closure: false,
    },
    closure: { closure_status: 'mapped_open', lifecycle_closed: false },
    consequence_reexecution_performed: false,
    evidence_namespaces: {},
    manifest_covers_complete_lifecycle: false,
    map_status: 'mapped_open',
    non_claims: ['synthetic-overlay-claim-string-remains-opaque'],
    overlay_version: 0,
    replacement_artifact_lineage_v2: {
      action_class: 'records.write',
      consequence_path: SELECTED_PATH,
      authority_domain_context: AUTHORITY_DOMAIN,
      authority_domain_evaluated: false,
      authority_effect_occurrence_evaluated: false,
      rightful_issuance_projected: false,
      consequence_reexecution_performed: false,
      replacement_crossing_source_commit_oid: HISTORICAL_COMMIT,
      manifest_artifact_body_sha256: HASHES.manifest,
      service_artifact_body_sha256: HASHES.service,
      terminal_artifact_body_sha256: HASHES.terminal,
      authority_grant_contract_sha256: HASHES.grant,
      exhausted_status_body_sha256: HASHES.exhausted,
    },
    report_type:
      'zlar-consequence-lifecycle-map-v0-replacement-artifact-lineage-overlay',
    rightful_issuance_projected: false,
    safe_claim_ceiling: 'synthetic overlay safe claim',
  };
}

function packedIndex() {
  const body = {
    action_class: 'records.write',
    artifact_set_verification: {
      manifest_artifact_body_sha256: HASHES.manifest,
      service_artifact_body_sha256: HASHES.service,
      terminal_artifact_body_sha256: HASHES.terminal,
      authority_status_evaluated: false,
      consequence_reexecution_performed: false,
      rightful_issuance_projected: false,
    },
    artifact_type: 'zlar.protected-records.post-effect-route-evidence-index.v0',
    authority_domain_context: AUTHORITY_DOMAIN,
    authority_domain_evaluated: false,
    boundaries: {
      central_manifest_extended: false,
      consequence_reexecution_performed: false,
      authority_effect_occurrence_reevaluated: false,
      current_authority_projected: false,
      rightful_issuance_projected: false,
      lifecycle_status_change_authorized: false,
      lifecycle_closed: false,
      external_effect_occurrence_proven: false,
      exactly_once_effect_proven: false,
      crash_atomic_effect_plus_pin_proven: false,
      surviving_effect_state_reobserved: false,
    },
    canonicalization: 'ZLAR canonical JSON v1',
    claim_boundary: { lifecycle_closure: false },
    closeout_projection: {
      closeout_crossing_identity_embedded: false,
      closeout_same_route_proven: false,
      source_recorded_selected_fields: {
        exactly_once_effect_proven: false,
        crash_atomic_effect_plus_pin_proven: false,
      },
    },
    consequence_path: SELECTED_PATH,
    exhausted_status_projection: { status_body_sha256: HASHES.exhausted },
    hash_scope: 'canonical index body without integrity',
    members: {},
    membership_policy: {
      lifecycle_overlay_indexed: false,
      all_retained_route_files_covered: false,
    },
    non_claims: ['synthetic-index-claim-string-remains-opaque'],
    runtime_result_selected_projection: {
      runtime_result_schema_fully_validated: false,
      runtime_result_claim_strings_evaluated: false,
      source_binding_cross_match: true,
      source_recorded_crossing_binding_fields: {
        authority_grant_contract_sha256: HASHES.grant,
      },
    },
    safe_claim_ceiling: 'synthetic index safe claim',
    schema_version: 0,
    source_reference: {
      historical_source_commit_oid: HISTORICAL_COMMIT,
      source_commit_cross_binding_matched: true,
      source_commit_object_presence_evaluated: false,
    },
    verification_mode: 'verification-only',
  };
  return {
    ...body,
    integrity: { body_sha256: sha256hex(canonicalize(body)) },
  };
}

function sourceFiles() {
  return sourceBoundHistoricalSourceFilesV0(
    PROJECT_DIR,
    CONSEQUENCE_PATH_COVERAGE_SOURCE_PATHS_V0,
  );
}

function currentSourceFiles() {
  return Object.fromEntries(
    Object.entries(CONSEQUENCE_PATH_COVERAGE_SOURCE_PATHS_V0).map(
      ([role, relativePath]) => [role, readFileSync(join(PROJECT_DIR, relativePath))],
    ),
  );
}

function fixture() {
  const base = baseMap();
  const baseRaw = Buffer.from(`${JSON.stringify(base, null, 2)}\n`);
  const baseFileSha = sha256hex(baseRaw);
  const baseSemanticSha = sha256hex(JSON.stringify(base));
  const over = overlay(baseSemanticSha, baseFileSha);
  const overlayRaw = Buffer.from(`${JSON.stringify(over, null, 2)}\n`);
  const index = packedIndex();
  const indexRaw = Buffer.from(canonicalize(index));
  const sources = sourceFiles();
  return {
    params: {
      baseMapRawBytes: baseRaw,
      overlayRawBytes: overlayRaw,
      indexRawBytes: indexRaw,
      expectedBaseMapFileSha256: baseFileSha,
      expectedBaseMapSha256: baseSemanticSha,
      expectedOverlayFileSha256: sha256hex(overlayRaw),
      expectedOverlaySha256: sha256hex(canonicalize(over)),
      expectedIndexFileSha256: sha256hex(indexRaw),
      expectedIndexBodySha256: index.integrity.body_sha256,
      expectedHistoricalCrossingSourceCommitOid: HISTORICAL_COMMIT,
      expectedDependencyMapSourceCommitOid: MAP_SOURCE_COMMIT,
      expectedSourceInventorySha256:
        consequencePathCoverageSourceInventorySha256V0(sources),
      sourceFiles: sources,
    },
    base,
    overlay: over,
    index,
  };
}

function repackBase(f, mutate) {
  const next = clone(f.base);
  mutate(next);
  const raw = Buffer.from(`${JSON.stringify(next, null, 2)}\n`);
  const params = {
    ...f.params,
    baseMapRawBytes: raw,
    expectedBaseMapFileSha256: sha256hex(raw),
    expectedBaseMapSha256: sha256hex(JSON.stringify(next)),
  };
  const nextOverlay = overlay(
    params.expectedBaseMapSha256,
    params.expectedBaseMapFileSha256,
  );
  const overlayRaw = Buffer.from(`${JSON.stringify(nextOverlay, null, 2)}\n`);
  params.overlayRawBytes = overlayRaw;
  params.expectedOverlayFileSha256 = sha256hex(overlayRaw);
  params.expectedOverlaySha256 = sha256hex(canonicalize(nextOverlay));
  return params;
}

function repackOverlay(f, mutate) {
  const next = clone(f.overlay);
  mutate(next);
  const raw = Buffer.from(`${JSON.stringify(next, null, 2)}\n`);
  return {
    ...f.params,
    overlayRawBytes: raw,
    expectedOverlayFileSha256: sha256hex(raw),
    expectedOverlaySha256: sha256hex(canonicalize(next)),
  };
}

function repackIndex(f, mutate) {
  const next = clone(f.index);
  mutate(next);
  delete next.integrity;
  next.integrity = {
    body_sha256: sha256hex(canonicalize(next)),
  };
  const raw = Buffer.from(canonicalize(next));
  return {
    ...f.params,
    indexRawBytes: raw,
    expectedIndexFileSha256: sha256hex(raw),
    expectedIndexBodySha256: next.integrity.body_sha256,
  };
}

section('deterministic source topology');
const f = fixture();
const report = buildConsequencePathCoverageDependencyMapV0(f.params);
equal('artifact type', CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_TYPE_V0, report.artifact_type);
equal('schema version', CONSEQUENCE_PATH_COVERAGE_DEPENDENCY_MAP_VERSION_V0, report.schema_version);
equal('map remains open', 'mapped_open', report.map_status);
equal('action class exact', 'records.write', report.action_class);
equal('selected path exact', SELECTED_PATH, report.consequence_path);
equal('authority domain context exact', AUTHORITY_DOMAIN, report.authority_domain_context);
equal('authority domain not evaluated', false, report.authority_domain_evaluated);
equal('overlay consumer no-go', 'no_go_no_new_lifecycle_evidence', report.overlay_consumer_decision.decision);
equal('overlay consumer absent', false, report.overlay_consumer_decision.consumer_built);
equal('new lifecycle fact count zero', 0, report.overlay_consumer_decision.new_underlying_lifecycle_facts);
deepEqual('no obligation changes', [], report.overlay_consumer_decision.obligation_status_changes);
deepEqual('no new claims', [], report.overlay_consumer_decision.new_claims_allowed);
equal(
  'mutation-node candidate count',
  5,
  report.topology_model.source_projected_mutation_node_candidate_count,
);
equal(
  'protected-records mutation candidate count',
  4,
  report.topology_model.protected_records_target_mutation_candidate_count,
);
equal(
  'proof-marker mutation candidate count',
  1,
  report.topology_model.proof_marker_mutation_candidate_count,
);
equal('surface count', 24, report.topology_model.surface_count);
equal('surface and node relations separate', true, report.topology_model.surface_role_and_effect_relationship_separated);
equal('domain inventory incomplete', false, report.domain_inventory_complete);
equal('equivalent route closure false', false, report.equivalent_route_closure);
equal('lifecycle closure false', false, report.closure.lifecycle_closed);
equal('authorized outside count zero', 0, report.domain_inventory.authorized_outside_coverage_count);
equal('outside authority absent', false, report.coverage_classification_contract.separate_outside_coverage_authority_artifact_supplied);
equal('observation not authority', false, report.coverage_classification_contract.observation_creates_authority);
equal('source AST proof false', false, report.source_binding.source_ast_or_control_flow_proven);
equal('dynamic reachability false', false, report.source_binding.dynamic_reachability_proven);
equal('source commit caller pinned', true, report.source_binding.dependency_map_source_commit_caller_pinned);
equal('Git object presence not evaluated', false, report.source_binding.dependency_map_source_commit_object_presence_evaluated);
equal('loaded source commit equality not evaluated', false, report.source_binding.loaded_source_matches_commit_evaluated);
equal('underlying index members not revalidated', false, report.dependency_cross_bindings.underlying_post_effect_member_bytes_revalidated);

const expectedNodePostures = new Map([
  ['E1.adapter-ledger-append-v1', 'source_candidate_unproven'],
  ['E2.service-jsonl-state-append-v1', 'source_candidate_unproven'],
  ['E3.legacy-runtime-process-private-state-v1', 'source_candidate_unproven'],
  [
    'E4.replacement-runtime-process-private-state-v2',
    'historically_reported_source_candidate_unproven_live',
  ],
  ['E5.active-persistent-proof-target-marker-v1', 'source_candidate_unproven'],
]);
const nodes = new Map(
  report.topology_model.effect_nodes.map((item) => [item.effect_node_id, item]),
);
for (const [nodeId, effectCapable] of expectedNodePostures) {
  assert(`effect node present ${nodeId}`, nodes.has(nodeId));
  equal(`effect node posture ${nodeId}`, effectCapable, nodes.get(nodeId).effect_capable);
  equal(
    `effect primitive marker observed ${nodeId}`,
    true,
    nodes.get(nodeId).effect_primitive_marker_observed,
  );
  equal(
    `effect capability unproven ${nodeId}`,
    false,
    nodes.get(nodeId).effect_capability_proven,
  );
}
equal('five exact mutation-node candidates', 5, nodes.size);
equal('selected node domain context only', 'context_only_not_evaluated', nodes.get('E4.replacement-runtime-process-private-state-v2').authority_domain_membership);
equal('adapter node domain unclassified', 'unclassified', nodes.get('E1.adapter-ledger-append-v1').authority_domain_membership);

const surfaces = new Map(report.topology_model.surfaces.map((item) => [item.surface_id, item]));
deepEqual(
  'exact source-projected surface inventory',
  [
    SELECTED_PATH,
    'protected-records.private-operator.records-terminal.records.write',
    'protected-records.runtime.profile-installation.records.write',
    'protected-records.runtime.records.write',
    'protected-records.service-profile.records.write',
    'source-discovered:active-persistent-profile-action-crossing',
    'source-discovered:bin/zlar-command-dispatch',
    'source-discovered:bin/zlar-local-proof-pack',
    'source-discovered:bin/zlar-local-proof-pack:verify-mode',
    'source-discovered:bin/zlar-protected-records-adapter-conformance',
    'source-discovered:bin/zlar-protected-records-installed-runtime-profile-terminal-chain',
    'source-discovered:bin/zlar-protected-records-installed-runtime-profile-terminal-chain:verify-mode',
    'source-discovered:bin/zlar-protected-records-proof',
    'source-discovered:bin/zlar-protected-records-runtime-local-activation:verify-mode',
    'source-discovered:bin/zlar-protected-records-runtime-profile-installation:verify-mode',
    'source-discovered:bin/zlar-protected-records-runtime-service-v1',
    'source-discovered:bin/zlar-protected-records-service-preflight',
    'source-discovered:bin/zlar-protected-records-service-preflight:verify-mode',
    'source-discovered:bin/zlar-protected-records-service-proof',
    'source-discovered:bin/zlar-protected-records-service-request:config-mode',
    'source-discovered:bin/zlar-protected-records-service-request:no-config-mode',
    'source-discovered:bin/zlar-protected-records-write',
    'source-discovered:bin/zlar-recognized-effect-target-shape:sample-generation',
    'source-discovered:internal-replacement-runtime-child-v2',
  ].sort(),
  [...surfaces.keys()].sort(),
);
assert(
  'all surfaces retain source-only proof ceiling',
  [...surfaces.values()].every(
    (item) =>
      item.required_source_markers_observed === true &&
      item.effect_or_dependency_markers_observed ===
        (item.effect_node_id !== null ||
          item.dependency_effect_node_ids.length > 0) &&
      item.verification_markers_observed ===
        (item.surface_role === 'verification_only') &&
      item.effect_capability_proven === false &&
      item.route_existence_proven === false &&
      item.runtime_reachability_proven === false &&
      item.current_refusal_behavior_proven === false &&
      item.authorized_outside_coverage === false &&
      !Object.hasOwn(item, 'authority_domain'),
  ),
);

for (const surfaceId of [
  'source-discovered:bin/zlar-local-proof-pack:verify-mode',
  'source-discovered:bin/zlar-protected-records-installed-runtime-profile-terminal-chain:verify-mode',
  'source-discovered:bin/zlar-protected-records-runtime-local-activation:verify-mode',
  'source-discovered:bin/zlar-protected-records-runtime-profile-installation:verify-mode',
  'source-discovered:bin/zlar-protected-records-service-preflight:verify-mode',
]) {
  const item = surfaces.get(surfaceId);
  equal(`${surfaceId} verification role`, 'verification_only', item.surface_role);
  equal(`${surfaceId} verification mode`, 'verification-mode-only', item.mode_scope);
  equal(`${surfaceId} no-node edge`, 'no_effect_node_candidate', item.effect_node_edge_kind);
  equal(`${surfaceId} relation unclassified`, 'unclassified', item.relationship_to_selected_path);
  equal(`${surfaceId} effect not evidenced`, 'not_evidenced', item.effect_capable);
  equal(`${surfaceId} verification disposition`, 'verification_only', item.coverage_disposition);
  equal(`${surfaceId} no direct node`, null, item.effect_node_id);
  deepEqual(`${surfaceId} no dependency nodes`, [], item.dependency_effect_node_ids);
}

const shapeSample = surfaces.get(
  'source-discovered:bin/zlar-recognized-effect-target-shape:sample-generation',
);
equal('shape sample proof-generator role', 'proof_generator_wrapper', shapeSample.surface_role);
equal('shape sample generation mode', 'sample-generation-mode-only', shapeSample.mode_scope);
equal('shape sample no-node edge', 'no_effect_node_candidate', shapeSample.effect_node_edge_kind);
equal('shape sample relation unclassified', 'unclassified', shapeSample.relationship_to_selected_path);
equal('shape sample effect not evidenced', 'not_evidenced', shapeSample.effect_capable);
equal('shape sample verification disposition', 'verification_only', shapeSample.coverage_disposition);

equal(
  'known static uncatalogued wrapper count',
  6,
  report.topology_model.known_static_uncatalogued_wrapper_count,
);
const uncataloguedWrappers = report.topology_model.known_static_wrappers_not_catalogued;
deepEqual(
  'known static uncatalogued wrapper IDs exact',
  [
    'bin/zlar-protected-records-active-persistent-profile-lifecycle',
    'bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
    'bin/zlar-protected-records-installed-runtime-profile-service-proof',
    'bin/zlar-protected-records-runtime-activation-preflight',
    'bin/zlar-protected-records-runtime-profile-preflight',
    'bin/zlar-protected-records-runtime-profile-proof',
  ],
  uncataloguedWrappers.map((item) => item.executable_entrypoint).sort(),
);
assert(
  'known static uncatalogued wrappers stay unclassified and unproven',
  uncataloguedWrappers.every(
    (item) =>
      item.required_source_markers_observed === false &&
      item.effect_capable === 'not_evidenced' &&
      item.effect_capability_proven === false &&
      item.effect_node_id === null &&
      item.relationship_to_selected_path === 'unclassified' &&
      item.authority_domain_membership === 'unclassified' &&
      item.coverage_disposition === 'unclassified' &&
      !Object.hasOwn(item, 'authority_domain'),
  ),
);
const selected = surfaces.get(SELECTED_PATH);
equal('selected surface role', 'selected_entrypoint', selected.surface_role);
equal('selected mode scope', 'crossing-execution-mode', selected.mode_scope);
equal('selected edge kind', 'historical_selected_route_candidate', selected.effect_node_edge_kind);
equal('selected route authoritative', 'authoritative_route', selected.relationship_to_selected_path);
equal('selected effect node v2', 'E4.replacement-runtime-process-private-state-v2', selected.effect_node_id);
equal('selected shares selected node', true, selected.shares_selected_effect_node);
equal('selected effect posture remains unproven', 'historically_reported_source_candidate_unproven_live', selected.effect_capable);
equal('selected current authority false', false, selected.current_authority_projected);
equal('selected historical disposition', 'historical_effect_evidence_bound_current_authority_not_projected', selected.coverage_disposition);

const serviceProfile = surfaces.get('protected-records.service-profile.records.write');
equal('service profile wrapper role', 'wrapper', serviceProfile.surface_role);
equal('service profile generation mode', 'generation-mode-only', serviceProfile.mode_scope);
equal('service profile invocation edge', 'invocation_dependency_candidate', serviceProfile.effect_node_edge_kind);
equal('service profile distinct effect', 'distinct_effect', serviceProfile.relationship_to_selected_path);
equal('service profile uncovered', 'observed_uncovered', serviceProfile.coverage_disposition);
equal('service profile node E2', 'E2.service-jsonl-state-append-v1', serviceProfile.effect_node_id);
equal('service profile effect posture', 'source_candidate_unproven', serviceProfile.effect_capable);

const runtime = surfaces.get('protected-records.runtime.records.write');
equal('runtime wrapper role', 'wrapper', runtime.surface_role);
equal('runtime generation mode', 'generation-mode-only', runtime.mode_scope);
equal('runtime relation is distinct effect', 'distinct_effect', runtime.relationship_to_selected_path);
equal('runtime effect posture not evidenced', 'not_evidenced', runtime.effect_capable);
equal('runtime associated node E3', 'E3.legacy-runtime-process-private-state-v1', runtime.effect_node_id);
deepEqual('runtime has no parallel dependencies', [], runtime.dependency_effect_node_ids);
equal('runtime artifact-generation edge', 'artifact_generation_dependency_candidate', runtime.effect_node_edge_kind);

const installation = surfaces.get('protected-records.runtime.profile-installation.records.write');
equal('installation wrapper role', 'wrapper', installation.surface_role);
equal('installation generation mode', 'generation-mode-only', installation.mode_scope);
equal('installation distinct effect', 'distinct_effect', installation.relationship_to_selected_path);
equal('installation effect posture not evidenced', 'not_evidenced', installation.effect_capable);
equal('installation associated node E3', 'E3.legacy-runtime-process-private-state-v1', installation.effect_node_id);
equal('installation artifact-generation edge', 'artifact_generation_dependency_candidate', installation.effect_node_edge_kind);
equal('installation current refusal disposition', 'fresh_effect_gate_marker_observed_refusal_unproven', installation.coverage_disposition);

const privateOperator = surfaces.get('protected-records.private-operator.records-terminal.records.write');
equal('private operator verification-only role', 'verification_only', privateOperator.surface_role);
equal('private operator verification mode', 'verification-mode-only', privateOperator.mode_scope);
equal('private operator no-node edge', 'no_effect_node_candidate', privateOperator.effect_node_edge_kind);
equal('private operator relationship unclassified', 'unclassified', privateOperator.relationship_to_selected_path);
equal('private operator effect posture not evidenced', 'not_evidenced', privateOperator.effect_capable);
equal('private operator no effect node', null, privateOperator.effect_node_id);
equal('private operator route unproven', false, privateOperator.route_existence_proven);

const directAdapter = surfaces.get('source-discovered:bin/zlar-protected-records-write');
equal('direct adapter role', 'direct_entrypoint', directAdapter.surface_role);
equal('direct adapter execution mode', 'write-execution-mode', directAdapter.mode_scope);
equal('direct adapter mutation edge', 'mutation_primitive_entry_candidate', directAdapter.effect_node_edge_kind);
equal('direct adapter distinct effect', 'distinct_effect', directAdapter.relationship_to_selected_path);
equal('direct adapter uncovered', 'observed_uncovered', directAdapter.coverage_disposition);
equal('direct adapter node E1', 'E1.adapter-ledger-append-v1', directAdapter.effect_node_id);
for (const mode of ['config-mode', 'no-config-mode']) {
  const directService = surfaces.get(
    `source-discovered:bin/zlar-protected-records-service-request:${mode}`,
  );
  equal(`direct service ${mode} role`, 'direct_entrypoint', directService.surface_role);
  equal(`direct service ${mode} scope`, `${mode}-only`, directService.mode_scope);
  equal(`direct service ${mode} mutation edge`, 'mutation_primitive_entry_candidate', directService.effect_node_edge_kind);
  equal(`direct service ${mode} distinct effect`, 'distinct_effect', directService.relationship_to_selected_path);
  equal(`direct service ${mode} uncovered`, 'observed_uncovered', directService.coverage_disposition);
  equal(`direct service ${mode} node E2`, 'E2.service-jsonl-state-append-v1', directService.effect_node_id);
}
const directRuntime = surfaces.get('source-discovered:bin/zlar-protected-records-runtime-service-v1');
equal('direct legacy runtime role', 'direct_entrypoint', directRuntime.surface_role);
equal('direct legacy runtime mode', 'legacy-v1-execution-mode', directRuntime.mode_scope);
equal('direct legacy runtime mutation edge', 'mutation_primitive_entry_candidate', directRuntime.effect_node_edge_kind);
equal('direct legacy runtime distinct effect', 'distinct_effect', directRuntime.relationship_to_selected_path);
equal('direct legacy runtime uncovered', 'observed_uncovered', directRuntime.coverage_disposition);
equal('direct legacy runtime node E3', 'E3.legacy-runtime-process-private-state-v1', directRuntime.effect_node_id);
assert('direct legacy runtime current status gap named', directRuntime.unresolved_side_doors.includes('current-authority-status-source-gate-absent'));
const internalV2 = surfaces.get('source-discovered:internal-replacement-runtime-child-v2');
equal('internal v2 role', 'internal_entrypoint', internalV2.surface_role);
equal('internal v2 mode', 'internal-child-execution-mode', internalV2.mode_scope);
equal('internal v2 invocation edge', 'internal_invocation_candidate', internalV2.effect_node_edge_kind);
equal('internal v2 relationship unclassified', 'unclassified', internalV2.relationship_to_selected_path);
equal('internal v2 uncovered', 'observed_uncovered', internalV2.coverage_disposition);
equal('internal v2 shares selected node', true, internalV2.shares_selected_effect_node);
assert('internal marker not authority named', internalV2.unresolved_side_doors.includes('software-routing-marker-is-not-human-authority'));

const mainDispatch = surfaces.get('source-discovered:bin/zlar-command-dispatch');
equal('main dispatch wrapper role', 'multi_command_dispatch_wrapper', mainDispatch.surface_role);
equal('main dispatch all-mode scope', 'all-dispatched-command-modes', mainDispatch.mode_scope);
equal('main dispatch multi-command edge', 'multi_command_dispatch_candidates', mainDispatch.effect_node_edge_kind);
equal('main dispatch relation unclassified', 'unclassified', mainDispatch.relationship_to_selected_path);
equal('main dispatch direct effect node absent', null, mainDispatch.effect_node_id);
deepEqual(
  'main dispatch binds all mutation-node candidates',
  [...expectedNodePostures.keys()],
  mainDispatch.dependency_effect_node_ids,
);
equal('main dispatch shares selected node', true, mainDispatch.shares_selected_effect_node);
equal('main dispatch uncovered', 'observed_uncovered', mainDispatch.coverage_disposition);

for (const [surfaceId, role, edgeKind] of [
  [
    'source-discovered:bin/zlar-protected-records-proof',
    'proof_generator_wrapper',
    'invocation_dependency_candidate',
  ],
  [
    'source-discovered:bin/zlar-protected-records-adapter-conformance',
    'proof_generator_wrapper',
    'invocation_dependency_candidate',
  ],
  [
    'source-discovered:bin/zlar-protected-records-service-proof',
    'proof_generator_wrapper',
    'invocation_dependency_candidate',
  ],
  [
    'source-discovered:bin/zlar-protected-records-service-preflight',
    'proof_generator_wrapper',
    'invocation_dependency_candidate',
  ],
  [
    'source-discovered:active-persistent-profile-action-crossing',
    'composite_wrapper',
    'composite_dependency_candidates',
  ],
  [
    'source-discovered:bin/zlar-local-proof-pack',
    'composite_proof_generator_wrapper',
    'composite_dependency_candidates',
  ],
  [
    'source-discovered:bin/zlar-protected-records-installed-runtime-profile-terminal-chain',
    'wrapper',
    'artifact_generation_dependency_candidate',
  ],
]) {
  equal(`${surfaceId} role`, role, surfaces.get(surfaceId).surface_role);
  equal(`${surfaceId} generation mode`, 'generation-mode-only', surfaces.get(surfaceId).mode_scope);
  equal(`${surfaceId} edge kind`, edgeKind, surfaces.get(surfaceId).effect_node_edge_kind);
}

deepEqual(
  'surfaces sorted lexically',
  [...report.topology_model.surfaces].map((item) => item.surface_id).sort(),
  report.topology_model.surfaces.map((item) => item.surface_id),
);
equal('base candidate count', 4, report.base_candidate_disposition.length);
assert('all base candidates keep closure blocked', report.base_candidate_disposition.every((item) => item.blocks_equivalent_route_closure === true));
assert('no base candidate authorized outside', report.base_candidate_disposition.every((item) => item.authorized_outside_coverage === false));
assert('safe claim bounded to source-marker checkpoint', report.safe_claim_ceiling.includes('caller-pinned source-marker checkpoint'));
assert('non-claims reject domain completeness', report.non_claims.some((item) => item.includes('domain inventory completeness')));
assert('side doors name legacy v1', report.side_doors.includes('direct-legacy-runtime-v1-caller-configured-time-grant-and-stores'));
assert('self assertion passes', assertConsequencePathCoverageDependencyMapV0(report, f.params));
const canonicalBytes = canonicalConsequencePathCoverageDependencyMapBytesV0(report, f.params);
equal('canonical output exact', canonicalize(report), canonicalBytes.toString('utf8'));
assert('canonical output no newline', !canonicalBytes.toString('utf8').endsWith('\n'));
const second = buildConsequencePathCoverageDependencyMapV0(f.params);
deepEqual('deterministic rebuild', report, second);
const summary = formatConsequencePathCoverageDependencyMapSummaryV0(report, f.params);
assert('summary names no-go', summary.includes('no_go_no_new_lifecycle_evidence'));
assert('summary names open inventory', summary.includes('Domain inventory complete: false'));

section('identity and boundary refusals');
for (const [label, key] of [
  ['base file SHA', 'expectedBaseMapFileSha256'],
  ['base semantic SHA', 'expectedBaseMapSha256'],
  ['overlay file SHA', 'expectedOverlayFileSha256'],
  ['overlay semantic SHA', 'expectedOverlaySha256'],
  ['index file SHA', 'expectedIndexFileSha256'],
  ['index body SHA', 'expectedIndexBodySha256'],
  ['source inventory SHA', 'expectedSourceInventorySha256'],
]) {
  throws(`${label} mismatch refuses`, () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, [key]: '0'.repeat(64) }), /mismatch/);
}
throws('malformed historical Git SHA refuses', () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, expectedHistoricalCrossingSourceCommitOid: 'x' }), /Git SHA-1/);
throws('malformed map Git SHA refuses', () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, expectedDependencyMapSourceCommitOid: 'x' }), /Git SHA-1/);
throws('invalid base JSON refuses', () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, baseMapRawBytes: Buffer.from('{bad') }), /valid JSON/);
throws('noncanonical index refuses', () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, indexRawBytes: Buffer.from(`${JSON.stringify(f.index, null, 2)}\n`), expectedIndexFileSha256: sha256hex(Buffer.from(`${JSON.stringify(f.index, null, 2)}\n`)) }), /canonical JSON/);

for (const [label, mutate, pattern] of [
  ['base map closed', (item) => { item.map_status = 'closed'; }, /boundary mismatch/],
  ['base authority domain unnamed', (item) => { item.authority_domain.named = false; }, /boundary mismatch/],
  ['base lifecycle closed', (item) => { item.closure.lifecycle_closed = true; }, /boundary mismatch/],
  ['base inventory closed', (item) => { item.equivalent_route_inventory.inventory_status = 'closed'; }, /boundary mismatch/],
  ['base live MCP coverage laundered', (item) => { item.equivalent_route_inventory.live_mcp_coverage_proven = true; }, /boundary mismatch/],
  ['base unrouted checked', (item) => { item.equivalent_route_inventory.unrouted_records_paths_checked = true; }, /boundary mismatch/],
  ['candidate relationship drift', (item) => { item.equivalent_route_inventory.candidates[0].relationship = 'equivalent'; }, /candidate posture/],
  ['candidate parity laundering', (item) => { item.equivalent_route_inventory.candidates[0].parity_proven = true; }, /candidate posture/],
  ['candidate duplicate', (item) => { item.equivalent_route_inventory.candidates[1].surface_id = item.equivalent_route_inventory.candidates[0].surface_id; }, /unique|mismatch/],
  ['selected path candidate collision', (item) => { item.equivalent_route_inventory.candidates[0].surface_id = SELECTED_PATH; }, /candidate posture/],
  ['equivalent blocker missing', (item) => { item.closure.closure_blockers = item.closure.closure_blockers.filter((value) => !value.startsWith('equivalent_route')); }, /blockers/],
  ['open obligation changed', (item) => { item.lifecycle_obligations[0].status = 'evidenced'; }, /must remain not_evidenced/],
  ['open obligation marked outside coverage', (item) => { item.lifecycle_obligations[0].status = 'outside_coverage'; }, /must remain not_evidenced/],
  ['open obligation duplicated', (item) => { item.lifecycle_obligations[1].obligation_id = item.lifecycle_obligations[0].obligation_id; }, /unique strings/],
]) {
  throws(label, () => buildConsequencePathCoverageDependencyMapV0(repackBase(f, mutate)), pattern);
}

for (const [label, mutate, pattern] of [
  ['overlay closes', (item) => { item.map_status = 'closed'; }, /boundary mismatch/],
  ['overlay rightful issuance', (item) => { item.rightful_issuance_projected = true; }, /boundary mismatch/],
  ['overlay consequence reexecution', (item) => { item.consequence_reexecution_performed = true; }, /boundary mismatch/],
  ['overlay base identity drift', (item) => { item.base_map_sha256 = '0'.repeat(64); }, /boundary mismatch/],
  ['overlay base reference report drift', (item) => { item.base_map_reference.report_type = 'other'; }, /boundary mismatch/],
  ['overlay base reference domain drift', (item) => { item.base_map_reference.authority_domain_id = 'other'; }, /boundary mismatch/],
  ['overlay base reference path drift', (item) => { item.base_map_reference.consequence_path = 'other'; }, /boundary mismatch/],
  ['overlay base reference path binding laundering', (item) => { item.base_map_reference.path_source_commit_bound = true; }, /boundary mismatch/],
  ['overlay base reference closure laundering', (item) => { item.base_map_reference.lifecycle_closed = true; }, /boundary mismatch/],
  ['overlay base reference full projection laundering', (item) => { item.base_map_reference.full_object_reprojected = true; }, /boundary mismatch/],
  ['overlay base reference claim evaluation laundering', (item) => { item.base_map_reference.claim_strings_evaluated = true; }, /boundary mismatch/],
  ['overlay historical source drift', (item) => { item.replacement_artifact_lineage_v2.replacement_crossing_source_commit_oid = '7'.repeat(40); }, /boundary mismatch/],
  ['overlay authority effect laundering', (item) => { item.replacement_artifact_lineage_v2.authority_effect_occurrence_evaluated = true; }, /boundary mismatch/],
]) {
  throws(label, () => buildConsequencePathCoverageDependencyMapV0(repackOverlay(f, mutate)), pattern);
}

for (const [label, mutate, pattern] of [
  ['index central manifest extended', (item) => { item.boundaries.central_manifest_extended = true; }, /boundary mismatch/],
  ['index lifecycle closed', (item) => { item.boundaries.lifecycle_closed = true; }, /boundary mismatch/],
  ['index current authority', (item) => { item.boundaries.current_authority_projected = true; }, /boundary mismatch/],
  ['index rightful issuance', (item) => { item.boundaries.rightful_issuance_projected = true; }, /boundary mismatch/],
  ['index authority status evaluation', (item) => { item.artifact_set_verification.authority_status_evaluated = true; }, /boundary mismatch/],
  ['index artifact verification reexecution', (item) => { item.artifact_set_verification.consequence_reexecution_performed = true; }, /boundary mismatch/],
  ['index artifact verification rightful issuance', (item) => { item.artifact_set_verification.rightful_issuance_projected = true; }, /boundary mismatch/],
  ['index source cross-binding false', (item) => { item.source_reference.source_commit_cross_binding_matched = false; }, /boundary mismatch/],
  ['index source object presence laundering', (item) => { item.source_reference.source_commit_object_presence_evaluated = true; }, /boundary mismatch/],
  ['index external effect occurrence laundering', (item) => { item.boundaries.external_effect_occurrence_proven = true; }, /boundary mismatch/],
  ['index exactly-once laundering', (item) => { item.boundaries.exactly_once_effect_proven = true; }, /boundary mismatch/],
  ['index crash-atomic laundering', (item) => { item.boundaries.crash_atomic_effect_plus_pin_proven = true; }, /boundary mismatch/],
  ['index runtime schema validation laundering', (item) => { item.runtime_result_selected_projection.runtime_result_schema_fully_validated = true; }, /boundary mismatch/],
  ['index runtime claim evaluation laundering', (item) => { item.runtime_result_selected_projection.runtime_result_claim_strings_evaluated = true; }, /boundary mismatch/],
  ['index runtime source cross-match false', (item) => { item.runtime_result_selected_projection.source_binding_cross_match = false; }, /boundary mismatch/],
  ['index closeout identity laundering', (item) => { item.closeout_projection.closeout_crossing_identity_embedded = true; }, /boundary mismatch/],
  ['index closeout same route', (item) => { item.closeout_projection.closeout_same_route_proven = true; }, /boundary mismatch/],
  ['index closeout exactly-once laundering', (item) => { item.closeout_projection.source_recorded_selected_fields.exactly_once_effect_proven = true; }, /boundary mismatch/],
  ['index closeout crash-atomic laundering', (item) => { item.closeout_projection.source_recorded_selected_fields.crash_atomic_effect_plus_pin_proven = true; }, /boundary mismatch/],
  ['index surviving effect', (item) => { item.boundaries.surviving_effect_state_reobserved = true; }, /boundary mismatch/],
  ['index all files covered', (item) => { item.membership_policy.all_retained_route_files_covered = true; }, /boundary mismatch/],
  ['index grant cross-binding drift', (item) => { item.runtime_result_selected_projection.source_recorded_crossing_binding_fields.authority_grant_contract_sha256 = '0'.repeat(64); }, /lineage mismatch/],
  ['index exhausted status drift', (item) => { item.exhausted_status_projection.status_body_sha256 = '0'.repeat(64); }, /lineage mismatch/],
]) {
  throws(label, () => buildConsequencePathCoverageDependencyMapV0(repackIndex(f, mutate)), pattern);
}

const missingSource = { ...f.params.sourceFiles };
delete missingSource.adapter;
throws('missing source role refuses', () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, sourceFiles: missingSource }), /fields must be exactly/);
const extraSource = { ...f.params.sourceFiles, surprise: Buffer.from('x') };
throws('extra source role refuses', () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, sourceFiles: extraSource }), /fields must be exactly/);
const markerDriftSources = { ...f.params.sourceFiles, runtime_cli: Buffer.from('safe but unrelated source') };
throws('source inventory helper refuses marker drift', () => consequencePathCoverageSourceInventorySha256V0(markerDriftSources), /marker mismatch/);
throws('source marker drift refuses map build', () => buildConsequencePathCoverageDependencyMapV0({ ...f.params, sourceFiles: markerDriftSources }), /marker mismatch/);
throws(
  'current post-retirement source refuses immutable parent reconstruction',
  () => consequencePathCoverageSourceInventorySha256V0(currentSourceFiles()),
  /SHA-256|marker mismatch/,
);

const mutatedReport = clone(report);
mutatedReport.domain_inventory_complete = true;
throws('mutated report domain closure refuses', () => assertConsequencePathCoverageDependencyMapV0(mutatedReport, f.params), /does not match/);
const authorizedReport = clone(report);
authorizedReport.topology_model.surfaces[0].authorized_outside_coverage = true;
throws('mutated outside authority refuses', () => assertConsequencePathCoverageDependencyMapV0(authorizedReport, f.params), /does not match/);
const formattedMutation = clone(report);
formattedMutation.overlay_consumer_decision.consumer_built = true;
throws('formatter mutation refuses', () => formatConsequencePathCoverageDependencyMapSummaryV0(formattedMutation, f.params), /does not match/);

section('direct CLI and file boundary');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-coverage-dependency-map-'));
process.once('exit', () => {
  rmSync(scratch, { recursive: true, force: true });
});
const historicalSourceRoot = writeSourceBoundHistoricalRootV0({
  projectDir: PROJECT_DIR,
  rootDir: join(scratch, 'historical-source-root'),
  sourcePaths: CONSEQUENCE_PATH_COVERAGE_SOURCE_PATHS_V0,
});
const paths = {
  base: join(scratch, 'base.json'),
  overlay: join(scratch, 'overlay.json'),
  index: join(scratch, 'index.json'),
};
writeFileSync(paths.base, f.params.baseMapRawBytes);
writeFileSync(paths.overlay, f.params.overlayRawBytes);
writeFileSync(paths.index, f.params.indexRawBytes);

const cliArgs = [
  '--repo-root', historicalSourceRoot,
  '--base-map', paths.base,
  '--overlay', paths.overlay,
  '--index', paths.index,
  '--require-base-map-file-sha', f.params.expectedBaseMapFileSha256,
  '--require-base-map-sha', f.params.expectedBaseMapSha256,
  '--require-overlay-file-sha', f.params.expectedOverlayFileSha256,
  '--require-overlay-sha', f.params.expectedOverlaySha256,
  '--require-index-file-sha', f.params.expectedIndexFileSha256,
  '--require-index-body-sha', f.params.expectedIndexBodySha256,
  '--require-historical-crossing-source-commit', HISTORICAL_COMMIT,
  '--require-dependency-map-source-commit', MAP_SOURCE_COMMIT,
  '--require-source-inventory-sha', f.params.expectedSourceInventorySha256,
];

function runCli(extra = [], override = null) {
  return spawnSync(process.execPath, [CLI, ...(override || cliArgs), ...extra], {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
}

const cliSummary = runCli();
equal('CLI summary exits zero', 0, cliSummary.status);
assert('CLI summary names no-go', cliSummary.stdout.includes('no_go_no_new_lifecycle_evidence'));
assert('CLI summary names lifecycle open', cliSummary.stdout.includes('Lifecycle closed: false'));
const cliJson = runCli(['--json']);
equal('CLI JSON exits zero', 0, cliJson.status);
equal('CLI JSON exact canonical report', canonicalize(report), cliJson.stdout);
assert('CLI JSON has no trailing newline', !cliJson.stdout.endsWith('\n'));

for (const flag of [
  '--require-closed',
  '--require-domain-inventory-complete',
  '--require-equivalent-route-closure',
]) {
  const result = runCli([flag]);
  equal(`${flag} refuses`, 1, result.status);
  assert(`${flag} emits no report`, result.stdout === '');
  assert(`${flag} names unsupported open map`, result.stderr.includes('unsupported'));
}

const unknown = runCli(['--surprise']);
equal('unknown flag refuses', 2, unknown.status);
const duplicate = runCli(['--json', '--json']);
equal('duplicate flag refuses', 2, duplicate.status);
assert('duplicate flag named', duplicate.stderr.includes('Duplicate flag'));
const missing = runCli([], cliArgs.slice(2));
equal('missing repo root refuses', 2, missing.status);

const symlinkPath = join(scratch, 'base-link.json');
symlinkSync(paths.base, symlinkPath);
const symlinkArgs = [...cliArgs];
symlinkArgs[symlinkArgs.indexOf(paths.base)] = symlinkPath;
const symlinkResult = runCli([], symlinkArgs);
equal('symlink input refuses', 1, symlinkResult.status);
assert('symlink refusal names no-follow', symlinkResult.stderr.includes('no-follow'));

const aliasArgs = [...cliArgs];
aliasArgs[aliasArgs.indexOf(paths.overlay)] = paths.base;
const aliasResult = runCli([], aliasArgs);
equal('aliased input refuses', 1, aliasResult.status);
assert('alias refusal explicit', aliasResult.stderr.includes('aliases another'));

const directoryPath = join(scratch, 'directory-input');
mkdirSync(directoryPath);
const directoryArgs = [...cliArgs];
directoryArgs[directoryArgs.indexOf(paths.index)] = directoryPath;
const directoryResult = runCli([], directoryArgs);
equal('directory input refuses', 1, directoryResult.status);

const oversized = join(scratch, 'oversized.json');
writeFileSync(oversized, Buffer.alloc(8 * 1024 * 1024 + 1, 0x20));
const oversizedArgs = [...cliArgs];
oversizedArgs[oversizedArgs.indexOf(paths.index)] = oversized;
const oversizedResult = runCli([], oversizedArgs);
equal('oversized input refuses', 1, oversizedResult.status);
assert('oversized refusal names boundary', oversizedResult.stderr.includes('size is outside'));

section('static capability graph and privacy');
const newLibraryPath = join(PROJECT_DIR, 'lib/consequence-path-coverage-dependency-map-v0.mjs');
const newTestPath = join(PROJECT_DIR, 'tests/test-consequence-path-coverage-dependency-map-v0.mjs');
function staticImportSpecifiers(source) {
  const specifiers = new Set();
  const fromImports =
    /(?:^|\n)\s*(?:import|export)\s+[^;]*?\sfrom\s*(['"])([^'"]+)\1\s*;?/g;
  const sideEffectImports =
    /(?:^|\n)\s*import\s*(['"])([^'"]+)\1\s*;?/g;
  for (const pattern of [fromImports, sideEffectImports]) {
    for (const match of source.matchAll(pattern)) specifiers.add(match[2]);
  }
  return [...specifiers].sort();
}

function resolvedStaticImportGraph(entryPaths) {
  const pending = entryPaths.map((filePath) => resolve(filePath));
  const files = new Set();
  const externalImports = new Set();
  const sourceByPath = new Map();
  while (pending.length > 0) {
    const filePath = pending.pop();
    if (files.has(filePath)) continue;
    if (
      filePath !== PROJECT_DIR &&
      !filePath.startsWith(`${PROJECT_DIR}/`)
    ) {
      throw new Error(`Static production import escaped repository: ${filePath}`);
    }
    const source = readFileSync(filePath, 'utf8');
    files.add(filePath);
    sourceByPath.set(filePath, source);
    for (const specifier of staticImportSpecifiers(source)) {
      if (specifier.startsWith('.') || specifier.startsWith('/')) {
        pending.push(
          specifier.startsWith('/')
            ? resolve(specifier)
            : resolve(dirname(filePath), specifier),
        );
      } else {
        externalImports.add(specifier);
      }
    }
  }
  return {
    externalImports: [...externalImports].sort(),
    files: [...files].sort(),
    sourceByPath,
  };
}

function namedImportsForSpecifier(source, expectedSpecifier) {
  const bindings = [];
  const namedImports =
    /(?:^|\n)\s*import\s*\{([^}]*)\}\s*from\s*(['"])([^'"]+)\2\s*;?/g;
  for (const match of source.matchAll(namedImports)) {
    if (match[3] !== expectedSpecifier) continue;
    for (const rawBinding of match[1].split(',')) {
      const binding = rawBinding.trim();
      if (binding) bindings.push(binding.split(/\s+as\s+/)[0]);
    }
  }
  return bindings;
}

deepEqual(
  'static import parser supports from and side-effect forms',
  ['./side-effect.mjs', 'node:fs'],
  staticImportSpecifiers(
    "import './side-effect.mjs';\nimport { readFileSync } from 'node:fs';\n",
  ),
);

const productionGraph = resolvedStaticImportGraph([CLI]);
deepEqual(
  'resolved production repository import set exact',
  [
    'bin/zlar-consequence-path-coverage-dependency-map-v0',
    'lib/canonicalize.mjs',
    'lib/consequence-path-coverage-dependency-map-v0.mjs',
    'lib/sha256.mjs',
  ],
  productionGraph.files.map((filePath) => filePath.slice(PROJECT_DIR.length + 1)),
);
deepEqual(
  'resolved production external import set exact',
  ['node:crypto', 'node:fs', 'node:path'],
  productionGraph.externalImports,
);
const graphText = productionGraph.files
  .map((filePath) => productionGraph.sourceByPath.get(filePath))
  .join('\n');
const importSpecifiers = productionGraph.files.flatMap((filePath) =>
  staticImportSpecifiers(productionGraph.sourceByPath.get(filePath)),
);
assert('no child process import in production graph', !importSpecifiers.includes('node:child_process'));
assert('no runtime profile import in production graph', !importSpecifiers.some((value) => value.includes('runtime-profile')));
assert('no crossing import in production graph', !importSpecifiers.some((value) => value.includes('crossing')));
assert('no receipt import in production graph', !importSpecifiers.some((value) => value.includes('receipt')));
assert('no dynamic import syntax', !/\bimport\s*\(/.test(graphText));
assert('no require call', !/\brequire\s*\(/.test(graphText));
assert('no eval call', !/\beval\s*\(/.test(graphText));
assert('no Git process execution', !/exec(?:File|Sync)?\s*\([^)]*git|spawn(?:Sync)?\s*\([^)]*git/i.test(graphText));

const cliSource = readFileSync(CLI, 'utf8');
const fsBindings = productionGraph.files
  .flatMap((filePath) =>
    namedImportsForSpecifier(
      productionGraph.sourceByPath.get(filePath),
      'node:fs',
    ),
  )
  .sort();
deepEqual(
  'all production node fs named imports are exact and read-only',
  ['closeSync', 'constants', 'fstatSync', 'lstatSync', 'openSync', 'readFileSync'].sort(),
  fsBindings,
);
assert('CLI has no output-file option', !cliSource.includes('--output'));

for (const path of [newLibraryPath, CLI, newTestPath]) {
  const text = readFileSync(path, 'utf8');
  assert(`${path} has no private absolute path`, !/\/Users\/|\/home\/|\/private\/|\/tmp\//.test(text));
  const privateIndexSha =
    '29e10ad2fc559a4028630f344d226c14' +
    'e501f30fe970da45afff4117e42abc8e';
  const privateCeremonyIdentity =
    '46e40faaa64aa11d4f6843b56df9e6a1' +
    'aa652c91e5d403d7c0fbc9b2eea90997';
  assert(`${path} has no real post-effect index SHA`, !text.includes(privateIndexSha));
  assert(`${path} has no historical ceremony identity`, !text.includes(privateCeremonyIdentity));
}

process.stdout.write(`\nconsequence path coverage dependency map v0: ${assertions}/${assertions} assertions passed\n`);
