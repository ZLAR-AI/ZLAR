#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';
import { createProtectedRecordsRuntimeService } from '../lib/protected-records-runtime-profile.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC_PATH = join(ROOT, 'spec/legacy-runtime-v1-direct-factory-disposition-v0.json');
const EXPECTED_BODY_SHA = '82ae2feb5378753074e865f0236e779d3092bea5b53dbb792579a2fb177f6a35';
const FIXED_REASON = 'legacy_runtime_v1_exported_factory_retired';
let assertions = 0;

function assert(label, value) {
  assertions += 1;
  if (!value) throw new Error(`FAIL: ${label}`);
}

function equal(label, expected, actual) {
  assert(label, Object.is(expected, actual));
}

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function read(path) {
  return readFileSync(join(ROOT, path), 'utf8');
}

function slice(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  assert(`${startMarker} starts`, start >= 0);
  assert(`${endMarker} follows`, end > start);
  return source.slice(start, end);
}

function section(label) {
  process.stdout.write(`\n## ${label}\n`);
}

const specText = readFileSync(SPEC_PATH, 'utf8');
const spec = JSON.parse(specText);
const { integrity, ...body } = spec;
const runtimeSource = read('lib/protected-records-runtime-profile.mjs');

section('artifact and immutable inputs');
equal('artifact type', 'zlar.legacy-runtime-v1-direct-factory-disposition.v0', spec.artifact_type);
equal('schema version', 0, spec.schema_version);
equal('source-only mode', 'source-only', spec.verification_mode);
equal('exact disposition', 'retire_and_refuse_exported_v1_factory', spec.decision);
equal('body algorithm', 'SHA-256', integrity.algorithm);
equal('body scope', 'canonical artifact body without integrity', integrity.scope);
equal('body SHA pinned', EXPECTED_BODY_SHA, integrity.body_sha256);
equal('body SHA validates', EXPECTED_BODY_SHA, sha(canonicalize(body)));
equal('prior disposition file unchanged', spec.immutable_dependencies.prior_direct_entry_disposition.file_sha256, sha(read('spec/legacy-runtime-v1-governed-disposition-v0.json')));
equal('prior disposition body pin', 'ec322d0bdc43c889c409ac17685bce2c47970cdf326d09e5602fd4826e609d8a', spec.immutable_dependencies.prior_direct_entry_disposition.body_sha256);
equal('prior disposition mutation false', false, spec.immutable_dependencies.prior_direct_entry_disposition.mutated);
equal('starting commit pinned', 'abff0002460e61cb411dfe6a4b7a253c4cdcdde9', spec.source_checkpoint.starting_commit_oid);
equal('pre-change module pinned', 'a99ad56f2b2b96944b266b51296b7d68cddb3d3ea849ec8f9b94b8e34a5ad5d2', spec.source_checkpoint.pre_change_module_sha256);
equal('current module exact', spec.source_checkpoint.post_change_module_sha256, sha(runtimeSource));

section('fixed input-independent refusal');
const v1Slice = slice(
  runtimeSource,
  'export function createProtectedRecordsRuntimeService',
  'export const PROTECTED_RECORDS_RUNTIME_STATUS_REFRESH_TRANSPORT_V2',
);
equal('v1 factory exact slice', `export function createProtectedRecordsRuntimeService() {\n  throw new Error('${FIXED_REASON}');\n}\n\n`, v1Slice);
equal('v1 factory slice hash', spec.source_checkpoint.post_change_v1_factory_slice_sha256, sha(v1Slice));
equal('factory has zero declared parameters', 0, createProtectedRecordsRuntimeService.length);
let getterReads = 0;
const hostileConfig = new Proxy({}, {
  get() {
    getterReads += 1;
    throw new Error('hostile getter reached');
  },
  ownKeys() {
    getterReads += 1;
    throw new Error('hostile ownKeys reached');
  },
});
let returned = Symbol('not-returned');
let observedError = null;
try {
  returned = createProtectedRecordsRuntimeService(hostileConfig);
} catch (error) {
  observedError = error;
}
equal('no config trap read', 0, getterReads);
equal('fixed error observed', FIXED_REASON, observedError?.message);
equal('no service object returned', 'symbol', typeof returned);
assert('slice contains no config token', !/\bconfig\b/.test(v1Slice));
assert('slice contains no environment or argv', !/process\.(?:env|argv)/.test(v1Slice));
assert('slice contains no time read', !/Date\.|now_epoch|nowEpoch/.test(v1Slice));
assert('slice contains no authority status', !/authority|grant|receipt|status/i.test(v1Slice));
assert('slice contains no filesystem, stdin, network, or child API', !/readFile|writeFile|stdin|fetch|http|spawn|exec|fork/.test(v1Slice));
assert('slice contains no internal mode or capability', !/internal|token|capability|delegate/i.test(v1Slice));
assert('slice exposes no applyRequest', !/applyRequest/.test(v1Slice));

section('consumer linkage and disposition');
const recognition = await import('../lib/protected-records-installed-runtime-profile-recognition-proof.mjs');
const installation = await import('../lib/protected-records-runtime-profile-installation.mjs');
equal('recognition verifier-bearing module links', 'function', typeof recognition.verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact);
equal('recognition generator module links', 'function', typeof recognition.runProtectedRecordsInstalledRuntimeProfileRecognitionProof);
equal('installation verifier-bearing module links', 'function', typeof installation.verifyProtectedRecordsRuntimeProfileInstallationArtifact);
equal('installation generator module links', 'function', typeof installation.runProtectedRecordsRuntimeProfileInstallationProof);
const recognitionSource = read('lib/protected-records-installed-runtime-profile-recognition-proof.mjs');
const recognitionRun = recognitionSource.slice(recognitionSource.indexOf('export function runProtectedRecordsInstalledRuntimeProfileRecognitionProof'));
assert('recognition positive call remains visible only as historical generator source', recognitionRun.includes('createProtectedRecordsRuntimeService({') && recognitionRun.includes('service.applyRequest({'));
assert('recognition outer guard precedes positive call', recognitionRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < recognitionRun.indexOf('createProtectedRecordsRuntimeService({'));
const installationSource = read('lib/protected-records-runtime-profile-installation.mjs');
const installationRun = installationSource.slice(installationSource.indexOf('export function runProtectedRecordsRuntimeProfileInstallationProof'));
assert('installation negative probe remains visible', installationSource.includes('const service = createProtectedRecordsRuntimeService({') && installationSource.includes('const result = service.applyRequest({'));
assert('installation outer guard precedes probe invocation', installationRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < installationRun.indexOf('runRequestAuthorityGuardSummary()'));
equal('exact static v1 importer count', 4, spec.import_search.exact_static_v1_importers.length);
equal('no pinned namespace or dynamic v1 import found', false, spec.import_search.namespace_or_dynamic_v1_import_found_in_pinned_source);
equal('custom imports remain open', false, spec.import_search.custom_external_import_closed);
for (const item of spec.consumer_inventory) {
  assert(`${item.id} classification allowed`, ['positive_generator', 'refusal_probe', 'verification_only', 'historical_test', 'evidence_only', 'packaging_copy', 'distinct_e4', 'unclassified'].includes(item.classification));
  assert(`${item.id} edge chain present`, Array.isArray(item.edge_chain) && item.edge_chain.length > 0);
  equal(`${item.id} current successful invocation not required`, false, item.current_success_required);
  assert(`${item.id} retirement impact named`, typeof item.retirement_impact === 'string' && item.retirement_impact.length > 0);
}

section('historical mutation and test routing');
equal('historical ordering has six stages', 6, spec.historical_mutation_order.length);
equal('persistent store precedes anchor', true, spec.historical_mutation_order.indexOf('write_consumed_store_temp_fsync_rename_and_directory_fsync') < spec.historical_mutation_order.indexOf('write_anchor_temp_fsync_rename_and_directory_fsync'));
equal('anchor precedes witness', true, spec.historical_mutation_order.indexOf('write_anchor_temp_fsync_rename_and_directory_fsync') < spec.historical_mutation_order.indexOf('write_witness_temp_fsync_rename_and_directory_fsync'));
equal('witness precedes E3 append', true, spec.historical_mutation_order.indexOf('write_witness_temp_fsync_rename_and_directory_fsync') < spec.historical_mutation_order.indexOf('stateEntries.push'));
const superseded = read('tests/superseded-source-bound-test-suites.txt').trim().split('\n');
assert('prior disposition suite routed historical', superseded.includes('test-legacy-runtime-v1-governed-disposition-v0.mjs'));
assert('new suite remains current', !superseded.includes('test-legacy-runtime-v1-direct-factory-disposition-v0.mjs'));
const inactive = read('tests/authority-inactive-test-suites.txt').trim().split('\n');
assert('historical effect-capable v1 suite remains inactive', inactive.includes('test-protected-records-runtime-profile.mjs'));

section('E4 separation and identity effect');
const v2Slice = slice(
  runtimeSource,
  'export function createProtectedRecordsRuntimeServiceV2',
  'export function assertProtectedRecordsRuntimeServiceResultV2',
);
equal('v2 behavioral slice unchanged', spec.source_checkpoint.unchanged_v2_factory_slice_sha256, sha(v2Slice));
equal('E4 driver unchanged', spec.immutable_dependencies.replacement_e4.driver_sha256, sha(read(spec.immutable_dependencies.replacement_e4.driver_path)));
equal('E4 child unchanged', spec.immutable_dependencies.replacement_e4.child_sha256, sha(read(spec.immutable_dependencies.replacement_e4.child_path)));
equal('E4 behavioral slice changed false', false, spec.immutable_dependencies.replacement_e4.behavioral_slice_changed);
equal('shared module identity changed', true, spec.historical_identity_effect.shared_module_whole_file_identity_changed);
equal('historical E4 preconditions further superseded', true, spec.historical_identity_effect.historical_e4_source_preconditions_further_superseded);
equal('historical artifacts not rewritten', false, spec.historical_identity_effect.historical_artifacts_rewritten);
equal('historical authority not reusable', false, spec.historical_identity_effect.historical_authority_reusable);

section('authority, claims, and side doors');
equal('route/source authority present', true, spec.authority_status.route_and_source_authority_present);
equal('consequence authority absent', false, spec.authority_status.consequence_authority_present);
equal('active authority absent', false, spec.authority_status.active_authority_present);
equal('outside-coverage authority absent', false, spec.authority_status.outside_coverage_authority_present);
equal('checked-out source refusal true', true, spec.claim_boundary.checked_out_source_exported_v1_factory_refusal);
equal('applyRequest non-creation true', true, spec.claim_boundary.returned_apply_request_non_creation);
for (const [claim, value] of Object.entries(spec.claim_boundary)) {
  if (claim === 'checked_out_source_exported_v1_factory_refusal' || claim === 'returned_apply_request_non_creation') continue;
  equal(`${claim} remains false`, false, value);
}
for (const sideDoor of [
  'existing-installed-or-copied-positive-v1-module',
  'custom-import-of-old-or-mutated-source',
  'NODE_OPTIONS-loaders-preloads-and-interpreter-substitution',
  'same-user-source-mutation',
  'source-drift-after-checkpoint',
]) assert(`side door visible: ${sideDoor}`, spec.side_doors.includes(sideDoor));

process.stdout.write(`\nResults: ${assertions}/${assertions} passed — legacy runtime v1 direct-factory disposition\n`);
