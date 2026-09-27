#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC_PATH = join(ROOT, 'spec/legacy-runtime-v1-e3-source-disposition-overlay-v0.json');
const EXPECTED_BODY_SHA = '5acaedb62413361c14389e270207d9b2c6ca60982559ec187cbdbcba611b9525';
let assertions = 0;

function assert(label, value) {
  assertions += 1;
  if (!value) throw new Error(`FAIL: ${label}`);
}

function equal(label, expected, actual) {
  assert(label, Object.is(expected, actual));
}

function deepEqual(label, expected, actual) {
  assert(label, JSON.stringify(expected) === JSON.stringify(actual));
}

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function read(relativePath) {
  return readFileSync(join(ROOT, relativePath), 'utf8');
}

function readGitBytes(commitOid, relativePath) {
  const result = spawnSync('git', ['show', `${commitOid}:${relativePath}`], {
    cwd: ROOT,
  });
  if (result.status !== 0) {
    throw new Error(
      `FAIL: cannot read ${relativePath} at ${commitOid}: ${String(result.stderr).trim()}`,
    );
  }
  return result.stdout;
}

function section(label) {
  process.stdout.write(`\n## ${label}\n`);
}

const spec = JSON.parse(readFileSync(SPEC_PATH, 'utf8'));
const { integrity, ...body } = spec;
const ANALYZED_SOURCE_COMMIT = spec.source_checkpoint.analyzed_source_commit_oid;

section('artifact and architecture decision');
equal('artifact type', 'zlar.legacy-runtime-v1-e3-source-disposition-overlay.v0', spec.artifact_type);
equal('schema version', 0, spec.schema_version);
equal('verification mode', 'source-only-static-overlay', spec.verification_mode);
equal('decision', 'add_temporal_source_disposition_without_parent_reclassification', spec.decision);
equal('analyzed source commit', '9f726e6e14b423af60e45d647573a4f4838b170c', ANALYZED_SOURCE_COMMIT);
equal('runtime observation absent', false, spec.source_checkpoint.runtime_observation_performed);
equal('dynamic reachability unproven', false, spec.source_checkpoint.dynamic_reachability_proven);
equal('accepted architecture', 'additive_temporal_overlay', spec.architecture_decision.accepted_option);
deepEqual('rejected architecture options exact', [
  'mutate_parent_dependency_map_or_reachability_delta',
  'delete_or_split_verifier_bearing_wrappers',
  'claim_e3_elimination_or_runtime_unreachability',
], spec.architecture_decision.rejected_options.map((item) => item.option));
equal('integrity algorithm', 'SHA-256', integrity.algorithm);
equal('integrity scope', 'canonical artifact body without integrity', integrity.scope);
equal('body SHA pin', EXPECTED_BODY_SHA, integrity.body_sha256);
equal('body SHA validates', EXPECTED_BODY_SHA, sha(canonicalize(body)));

section('immutable dependency identities');
equal('parent map file pin', 'a275b74cb7e468bed6a8376c8ccc0aab81937d945e240d69090293ae9b38a4de', spec.immutable_dependencies.consequence_path_coverage_dependency_map_v0.file_sha256);
equal('parent map body pin', 'b39767ba79435bede70784d416b25ad52c47a6fb1c22df195a32b4af115f6b9b', spec.immutable_dependencies.consequence_path_coverage_dependency_map_v0.body_sha256);
equal('parent map unchanged', false, spec.immutable_dependencies.consequence_path_coverage_dependency_map_v0.mutated);
equal('reachability file pin', '15d84e7b569b9fef928d2d7fe619efbca6047de135379b7e50bbfec6c7abf973', spec.immutable_dependencies.source_bound_static_reachability_delta_v0.file_sha256);
equal('reachability body pin', '219d36fa18b01de5477ff2bebf0e00892868c65fead36446227a86838db23f89', spec.immutable_dependencies.source_bound_static_reachability_delta_v0.body_sha256);
equal('reachability inventory pin', '20451df27fb00b5e11e0c6f25dceb6c3f26a71f55a452c2f6a7e6d092cb41642', spec.immutable_dependencies.source_bound_static_reachability_delta_v0.source_inventory_sha256);
equal('reachability unchanged', false, spec.immutable_dependencies.source_bound_static_reachability_delta_v0.mutated);
for (const key of ['direct_entry_disposition_v0', 'direct_factory_disposition_v0']) {
  const dependency = spec.immutable_dependencies[key];
  equal(`${key} exact file hash`, dependency.file_sha256, sha(read(dependency.path)));
  equal(`${key} unchanged`, false, dependency.mutated);
  const value = JSON.parse(read(dependency.path));
  const { integrity: dependencyIntegrity, ...dependencyBody } = value;
  equal(`${key} body pin`, dependency.body_sha256, dependencyIntegrity.body_sha256);
  equal(`${key} body validates`, dependency.body_sha256, sha(canonicalize(dependencyBody)));
}

section('exact checkpoint source inventory');
equal('source inventory count', 17, spec.source_inventory.length);
equal('source inventory paths unique', spec.source_inventory.length, new Set(spec.source_inventory.map((item) => item.path)).size);
for (const item of spec.source_inventory) {
  equal(
    `${item.path} exact SHA at analyzed source checkpoint`,
    item.file_sha256,
    sha(readGitBytes(ANALYZED_SOURCE_COMMIT, item.path)),
  );
}

section('current fixed refusal endpoints');
equal('endpoint count', 2, spec.fixed_refusal_endpoints.length);
const directCli = read('bin/zlar-protected-records-runtime-service');
equal('direct CLI source exact', `#!/usr/bin/env node\n\n// This committed script body is permanently retired. It reads no argv,\n// process environment, config, stdin, caller identity, or authority status.\n// Interpreter selection and pre-script loader execution remain outside this\n// source-level refusal.\nprocess.stderr.write(\n  'ERROR: protected-records runtime-service direct entry refused: legacy_runtime_v1_direct_entry_surface_retired\\n',\n);\nprocess.exitCode = 1;\n`, directCli);
const runtimeProfile = read('lib/protected-records-runtime-profile.mjs');
const v1Start = runtimeProfile.indexOf('export function createProtectedRecordsRuntimeService');
const v1End = runtimeProfile.indexOf('export const PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2', v1Start);
assert('v1 factory slice boundaries exist', v1Start >= 0 && v1End > v1Start);
equal('v1 factory source exact', `export function createProtectedRecordsRuntimeService() {\n  throw new Error('legacy_runtime_v1_exported_factory_retired');\n}\n\n`, runtimeProfile.slice(v1Start, v1End));
for (const endpoint of spec.fixed_refusal_endpoints) {
  equal(`${endpoint.endpoint_id} source hash`, endpoint.file_sha256, sha(read(endpoint.source_path)));
  equal(`${endpoint.endpoint_id} input independent`, true, endpoint.input_independent);
  equal(`${endpoint.endpoint_id} creates no service`, false, endpoint.creates_service_or_apply_request);
  assert(`${endpoint.endpoint_id} reason present`, read(endpoint.source_path).includes(endpoint.reason_code));
}

section('current static E3 projection chains');
const sources = Object.fromEntries(spec.source_inventory.map((item) => [item.path, read(item.path)]));
assert('runtime proof helper spawns retired CLI route', sources['lib/protected-records-runtime-profile.mjs'].includes("spawnSync(ZLAR_BIN, ['protected-records-runtime-service', '--config', configPath]"));
assert('runtime profile preflight calls runtime proof', sources['lib/protected-records-runtime-profile-preflight.mjs'].includes('const proof = runProtectedRecordsRuntimeProfileProof();'));
assert('runtime activation calls profile preflight', sources['lib/protected-records-runtime-activation-preflight.mjs'].includes('const runtimePreflight = runProtectedRecordsRuntimeProfilePreflight(profile);'));
assert('installed recognition calls retired factory', sources['lib/protected-records-installed-runtime-profile-recognition-proof.mjs'].includes('const service = createProtectedRecordsRuntimeService({'));
assert('installed recognition old apply remains downstream of factory', sources['lib/protected-records-installed-runtime-profile-recognition-proof.mjs'].includes('const result = service.applyRequest({'));
assert('installed service helper spawns retired CLI route', sources['lib/protected-records-installed-runtime-profile-service-proof.mjs'].includes("spawnSync(ZLAR_BIN, ['protected-records-runtime-service', '--config', configPath]"));
assert('active lifecycle calls installed service proof', sources['lib/protected-records-active-persistent-profile-lifecycle.mjs'].includes('const serviceProof = runProtectedRecordsInstalledRuntimeProfileServiceProof('));
assert('installation calls retired factory', sources['lib/protected-records-runtime-profile-installation.mjs'].includes('const service = createProtectedRecordsRuntimeService({'));
assert('installation also calls runtime proof route', sources['lib/protected-records-runtime-profile-installation.mjs'].includes('const runtimeProof = runProtectedRecordsRuntimeProfileProof();'));
assert('runtime local activation calls runtime proof route', sources['lib/protected-records-runtime-local-activation.mjs'].includes('const runtimeProof = runProtectedRecordsRuntimeProfileProof();'));
assert('installed terminal chain reads committed service proof artifact', sources['lib/protected-records-installed-runtime-profile-terminal-chain.mjs'].includes('readCommittedProtectedRecordsInstalledRuntimeProfileServiceProofArtifact()'));
assert('installed terminal chain does not invoke service proof generator', !sources['lib/protected-records-installed-runtime-profile-terminal-chain.mjs'].includes('runProtectedRecordsInstalledRuntimeProfileServiceProof('));
equal('overlayed surface count', 10, spec.surface_disposition_delta.length);
equal('overlayed surface ids unique', spec.surface_disposition_delta.length, new Set(spec.surface_disposition_delta.map((item) => item.surface_id)).size);
for (const surface of spec.surface_disposition_delta) {
  assert(`${surface.surface_id} has current E3 disposition`, ['refusal_only', 'wrapper_to_refusal', 'ancestor_to_refusal', 'wrapper_to_both_fixed_refusals', 'historical_evidence_view'].includes(surface.current_e3_projection));
  if (surface.current_e3_projection === 'historical_evidence_view') {
    equal(`${surface.surface_id} has no live terminating endpoint`, null, surface.terminating_endpoint_id);
  } else {
    assert(`${surface.surface_id} names terminating endpoint`, typeof surface.terminating_endpoint_id === 'string' && surface.terminating_endpoint_id.length > 0);
  }
  assert(`${surface.surface_id} retains historical relationship`, ['distinct_effect', 'wrapper'].includes(surface.historical_relationship));
}
const lifecycle = spec.surface_disposition_delta.find((item) => item.surface_id.includes('active-persistent-profile-lifecycle'));
deepEqual('mixed lifecycle surface keeps E5 visible', ['E5.active-persistent-proof-target-marker-v1'], lifecycle.other_effect_node_projections);

section('temporal disposition and non-claims');
equal('E3 identity retained', true, spec.e3_disposition.historical_node_identity_retained);
equal('historical relation remains distinct', 'distinct_effect', spec.e3_disposition.historical_relationship_to_selected_e4);
equal('positive current-source v1 route absent in overlay', false, spec.e3_disposition.identified_static_v1_route_positive_source_available);
equal('historical positive factory body absent', false, spec.e3_disposition.historical_positive_factory_body_present_in_current_module);
equal('current factory returns no applyRequest', false, spec.e3_disposition.current_factory_returns_apply_request);
equal('runtime unreachability unproven', false, spec.e3_disposition.runtime_unreachability_proven);
equal('E3 elimination false', false, spec.e3_disposition.e3_eliminated);
equal('installed-copy elimination false', false, spec.e3_disposition.installed_copy_eliminated);
equal('outside coverage false', false, spec.e3_disposition.authorized_outside_coverage);
deepEqual('no lifecycle obligation changes', [], spec.lifecycle_delta.obligation_status_changes);
equal('map remains open', 'mapped_open', spec.lifecycle_delta.map_status_after);
equal('new lifecycle evidence false', false, spec.lifecycle_delta.new_lifecycle_evidence_added);
equal('coverage disposition unchanged', false, spec.claim_delta.coverage_disposition_changed);
equal('historical distinct effect not removed', false, spec.claim_delta.historical_distinct_effect_claim_removed);

section('authority, claims, and side doors');
equal('source authority present', true, spec.authority_status.route_and_source_authority_present);
equal('consequence authority absent', false, spec.authority_status.consequence_authority_present);
equal('domain assignment absent', false, spec.authority_status.authority_domain_assignment_present);
equal('outside coverage authority absent', false, spec.authority_status.outside_coverage_authority_present);
equal('active authority absent', false, spec.authority_status.active_authority_present);
equal('exact source fixed-refusal boundary true', true, spec.claim_boundary.exact_checkpoint_static_e3_fixed_refusal_boundary);
equal('historical E3 identity true', true, spec.claim_boundary.historical_e3_identity_retained);
for (const [claim, value] of Object.entries(spec.claim_boundary)) {
  if (claim === 'exact_checkpoint_static_e3_fixed_refusal_boundary' || claim === 'historical_e3_identity_retained') continue;
  equal(`${claim} remains false`, false, value);
}
for (const sideDoor of [
  'old-installed-or-copied-positive-v1-source',
  'historical-git-objects-and-checkouts',
  'custom-import-of-old-or-mutated-source',
  'NODE_OPTIONS-loaders-preloads-and-interpreter-substitution',
  'other-effect-projections-on-mixed-surfaces-including-E5',
  'source-drift-after-checkpoint',
]) assert(`side door visible: ${sideDoor}`, spec.side_doors.includes(sideDoor));

process.stdout.write(`\nResults: ${assertions}/${assertions} passed — legacy runtime v1 E3 source-disposition overlay\n`);
