#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  CONSEQUENCE_PATH_COVERAGE_SOURCE_PATHS_V0,
  consequencePathCoverageSourceInventorySha256V0,
} from '../lib/consequence-path-coverage-dependency-map-v0.mjs';
import {
  SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0,
  sourceBoundStaticReachabilitySourceInventorySha256V0,
} from '../lib/source-bound-static-reachability-delta-v0.mjs';
import { canonicalize } from '../lib/canonicalize.mjs';

const PROJECT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = join(PROJECT_DIR, 'bin/zlar-protected-records-runtime-service');
const MAIN = join(PROJECT_DIR, 'bin/zlar');
const SPEC = join(PROJECT_DIR, 'spec/legacy-runtime-v1-governed-disposition-v0.json');
const FIXED_REASON = 'legacy_runtime_v1_direct_entry_surface_retired';
const FIXED_STDERR =
  `ERROR: protected-records runtime-service direct entry refused: ${FIXED_REASON}\n`;
const EXPECTED_SPEC_BODY_SHA256 =
  'ec322d0bdc43c889c409ac17685bce2c47970cdf326d09e5602fd4826e609d8a';

let assertions = 0;
function assert(label, condition) {
  assertions += 1;
  if (!condition) throw new Error(`FAIL: ${label}`);
}

function equal(label, expected, actual) {
  assert(label, Object.is(expected, actual));
}

function deepEqual(label, expected, actual) {
  assert(label, JSON.stringify(expected) === JSON.stringify(actual));
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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function read(relativePath) {
  return readFileSync(join(PROJECT_DIR, relativePath), 'utf8');
}

function count(source, pattern) {
  return [...source.matchAll(pattern)].length;
}

function sourceFiles(paths) {
  return Object.fromEntries(
    Object.entries(paths).map(([role, relativePath]) => [
      role,
      readFileSync(join(PROJECT_DIR, relativePath)),
    ]),
  );
}

function section(name) {
  process.stdout.write(`\n## ${name}\n`);
}

function assertExactSpecIntegrity(value) {
  const { integrity, ...body } = value;
  if (
    integrity?.algorithm !== 'SHA-256' ||
    integrity?.scope !== 'canonical artifact body without integrity' ||
    integrity?.body_sha256 !== EXPECTED_SPEC_BODY_SHA256 ||
    sha256(canonicalize(body)) !== EXPECTED_SPEC_BODY_SHA256
  ) {
    throw new Error('Legacy runtime v1 disposition exact semantic integrity mismatch');
  }
  return true;
}

const specText = readFileSync(SPEC, 'utf8');
const spec = JSON.parse(specText);
const entrySource = readFileSync(ENTRY, 'utf8');
const executableEntrySource = entrySource
  .split('\n')
  .filter((line) => !line.trimStart().startsWith('//'))
  .join('\n');

section('decision and immutable input identities');
equal('artifact type', 'zlar.legacy-runtime-v1-governed-disposition.v0', spec.artifact_type);
equal('schema version', 0, spec.schema_version);
equal('source-only verification mode', 'source-only', spec.verification_mode);
equal('exact disposition', 'retire_and_refuse_direct_entry_surface', spec.decision);
equal('exact selected consequence path', 'protected-records.installed-runtime-profile.terminal-chain.records.write', spec.selected_consequence_path);
equal('exact selected E4 effect node', 'E4.replacement-runtime-process-private-state-v2', spec.selected_e4_effect_node_id);
equal('North Star 1 remains historical boarding/effect evidence', 'historical_boarding_and_effect_evidence', spec.north_star_posture.north_star_1);
equal('North Star 2 remains mapped open', 'mapped_open', spec.north_star_posture.north_star_2);
equal('lifecycle status is unchanged', false, spec.north_star_posture.lifecycle_status_changed);
assert('spec exact semantic integrity validates', assertExactSpecIntegrity(spec));
equal('spec exact body SHA', EXPECTED_SPEC_BODY_SHA256, spec.integrity.body_sha256);
equal('North Star 2 context stays unmoved', false, spec.claim_boundary.lifecycle_closure);
equal('domain membership remains unproven', false, spec.authority_domain_membership_proven);
equal('starting commit exact', '765767f92ed32a64aa498244a63ea4b8a6b2c5fb', spec.source_checkpoint.starting_commit_oid);
equal(
  'entry pre-retirement SHA exact',
  '8aec7c8eed3a3e0072818c6a8d5110fcf66707ad4b48073308d8679af4370493',
  spec.source_checkpoint.pre_retirement_entry_file_sha256,
);
equal(
  'entry post-retirement SHA exact',
  spec.source_checkpoint.post_retirement_entry_file_sha256,
  sha256(entrySource),
);
equal('entry git mode exact', 0o755, lstatSync(ENTRY).mode & 0o777);
equal('parent file SHA pin exact', 'a275b74cb7e468bed6a8376c8ccc0aab81937d945e240d69090293ae9b38a4de', spec.immutable_dependencies.parent_dependency_map.file_sha256);
equal('parent body SHA pin exact', 'b39767ba79435bede70784d416b25ad52c47a6fb1c22df195a32b4af115f6b9b', spec.immutable_dependencies.parent_dependency_map.body_sha256);
equal('parent not mutated', false, spec.immutable_dependencies.parent_dependency_map.mutated);
equal('delta file SHA pin exact', '15d84e7b569b9fef928d2d7fe619efbca6047de135379b7e50bbfec6c7abf973', spec.immutable_dependencies.source_bound_static_reachability_delta.file_sha256);
equal('delta body SHA pin exact', '219d36fa18b01de5477ff2bebf0e00892868c65fead36446227a86838db23f89', spec.immutable_dependencies.source_bound_static_reachability_delta.body_sha256);
equal('delta inventory SHA pin exact', '20451df27fb00b5e11e0c6f25dceb6c3f26a71f55a452c2f6a7e6d092cb41642', spec.immutable_dependencies.source_bound_static_reachability_delta.analyzed_source_inventory_sha256);
equal('delta not mutated', false, spec.immutable_dependencies.source_bound_static_reachability_delta.mutated);

for (const [label, mutate] of [
  ['E3 elimination laundering', (value) => { value.selected_surface.e3_eliminated = true; }],
  ['lifecycle closure laundering', (value) => { value.claim_boundary.lifecycle_closure = true; }],
  ['extra contradictory claim', (value) => { value.claim_boundary.secret_closure = true; }],
]) {
  const changed = JSON.parse(JSON.stringify(spec));
  mutate(changed);
  throws(label, () => assertExactSpecIntegrity(changed), /exact semantic integrity mismatch/);
}

for (const [label, relativePath, expected] of [
  ['dependency map library', 'lib/consequence-path-coverage-dependency-map-v0.mjs', spec.immutable_dependencies.frozen_source_evidence_implementations.dependency_map_library_sha256],
  ['reachability delta library', 'lib/source-bound-static-reachability-delta-v0.mjs', spec.immutable_dependencies.frozen_source_evidence_implementations.reachability_delta_library_sha256],
]) {
  equal(`${label} remains byte frozen`, expected, sha256(readFileSync(join(PROJECT_DIR, relativePath))));
}
equal('historical analyzed commit exact', 'e7c621927df35eb31cf3f0dfc1ea2a42df6d5dd5', spec.historical_source_reconstruction.analyzed_source_commit_oid);
equal('historical reconstruction helper exact', spec.historical_source_reconstruction.helper_sha256, sha256(readFileSync(join(PROJECT_DIR, spec.historical_source_reconstruction.helper_path))));
equal('historical helper reads exact Git blobs only', true, spec.historical_source_reconstruction.reads_only_git_blobs_from_exact_historical_commit);
equal('no durable positive source copy added', false, spec.historical_source_reconstruction.durable_positive_source_copy_added);
equal('historical source normal cleanup uses try/finally', true, spec.historical_source_reconstruction.normal_cleanup_uses_try_finally);
equal('abnormal termination cleanup is not guaranteed', false, spec.historical_source_reconstruction.abnormal_termination_cleanup_guaranteed);
equal('historical object required only for local baseline suites', true, spec.historical_source_reconstruction.historical_git_object_required_for_local_baseline_suites);
equal('current checkout must refuse old source identity', true, spec.historical_source_reconstruction.current_checkout_required_to_refuse_as_source_drift);

section('freshness gate is not durable governance');
const statusSource = read('lib/protected-records-fixture-authority-status.mjs');
assert('status source pins one exact current contract', statusSource.includes('PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256'));
assert('status source records exhaustion', statusSource.includes("status: 'exhausted'"));
assert('status source can return true when no refusal reason remains', statusSource.includes('if (reason) {') && statusSource.includes('return true;'));
equal('freshness-only option rejected', 'no_go_refusal_theater', spec.freshness_gate_decision.decision);
equal('freshness gate not implemented', false, spec.freshness_gate_decision.implemented);
equal('freshness gate would reopen', true, spec.freshness_gate_decision.would_reopen_if_source_status_changed);
equal('freshness gate proves no durable disposition', false, spec.freshness_gate_decision.durable_governed_disposition_established);
equal('retirement claim is lexical source control flow', true, spec.retirement_contract.committed_script_body_contains_one_unconditional_refusal_path);
equal('pre-script loader closure remains false', false, spec.retirement_contract.pre_script_loader_execution_closed);

section('import-free unconditional retirement source');
equal('entry exact fixed source', `#!/usr/bin/env node\n\n// This committed script body is permanently retired. It reads no argv,\n// process environment, config, stdin, caller identity, or authority status.\n// Interpreter selection and pre-script loader execution remain outside this\n// source-level refusal.\nprocess.stderr.write(\n  'ERROR: protected-records runtime-service direct entry refused: legacy_runtime_v1_direct_entry_surface_retired\\n',\n);\nprocess.exitCode = 1;\n`, entrySource);
equal('fixed reason occurs once in executable code', 1, count(executableEntrySource, /legacy_runtime_v1_direct_entry_surface_retired/g));
equal('one stderr write', 1, count(executableEntrySource, /process\.stderr\.write\(/g));
equal('one flush-safe nonzero exit code', 1, count(executableEntrySource, /process\.exitCode = 1/g));
for (const [label, pattern] of [
  ['static import', /^\s*import\s/m],
  ['require', /\brequire\s*\(/],
  ['dynamic import', /\bimport\s*\(/],
  ['eval', /\beval\s*\(/],
  ['Function constructor', /\bFunction\s*\(/],
  ['argv read', /process\.argv/],
  ['environment read', /process\.env/],
  ['stdin read', /process\.stdin|readFileSync\s*\(\s*0/],
  ['filesystem API', /readFileSync|writeFileSync|openSync|node:fs/],
  ['child process API', /spawn|exec|fork|node:child_process/],
  ['network API', /fetch\s*\(|node:(?:net|http|https)|WebSocket/],
  ['legacy factory', /createProtectedRecordsRuntimeService/],
  ['returned apply method', /applyRequest/],
  ['freshness assertion', /assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed/],
  ['conditional branch', /\bif\s*\(|\bswitch\s*\(/],
]) {
  assert(`entry has no ${label}`, !pattern.test(executableEntrySource));
}

section('refusal-only runtime observations');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-legacy-runtime-retirement-'));
try {
  const missingConfig = join(scratch, 'must-not-be-read.json');
  const cases = [
    ['no args', [], ''],
    ['help cannot reopen route', ['--help'], ''],
    ['nonexistent config cannot alter refusal', ['--config', missingConfig], ''],
    ['inert stdin cannot alter refusal', ['--config', '-'], '{}\n'],
  ];
  const before = readdirSync(scratch);
  for (const [label, args, input] of cases) {
    const run = spawnSync(process.execPath, [ENTRY, ...args], {
      cwd: scratch,
      encoding: 'utf8',
      env: { PATH: `${dirname(process.execPath)}:/usr/bin:/bin` },
      input,
    });
    equal(`${label} exits one`, 1, run.status);
    equal(`${label} emits no stdout`, '', run.stdout);
    equal(`${label} emits exact fixed refusal`, FIXED_STDERR, run.stderr);
    equal(`${label} has no signal`, null, run.signal);
  }
  deepEqual('direct refusal creates no files', before, readdirSync(scratch));

  const dispatch = spawnSync(MAIN, ['protected-records-runtime-service', '--config', missingConfig], {
    cwd: scratch,
    encoding: 'utf8',
    env: { PATH: `${dirname(process.execPath)}:/usr/bin:/bin` },
    input: '{}\n',
  });
  equal('main dispatcher reaches refusal', 1, dispatch.status);
  equal('main dispatcher emits no stdout', '', dispatch.stdout);
  equal('main dispatcher emits exact refusal', FIXED_STDERR, dispatch.stderr);
  deepEqual('dispatcher refusal creates no files', before, readdirSync(scratch));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
equal('bounded direct refusal observation recorded', true, spec.bounded_verification_observation.exact_local_refusal_probe_observed);
equal('bounded observation interpreter exact', 'process.execPath', spec.bounded_verification_observation.exact_interpreter);
equal('bounded observation sanitized environment', true, spec.bounded_verification_observation.sanitized_environment);
equal('bounded direct probe count exact', 4, spec.bounded_verification_observation.direct_script_probe_count);
equal('bounded dispatcher probe count exact', 1, spec.bounded_verification_observation.main_dispatch_probe_count);
equal('bounded probes supplied no effect-capable config', false, spec.bounded_verification_observation.config_or_target_effect_input_supplied);
equal('bounded observation is not generalized current-machine refusal', false, spec.bounded_verification_observation.generalized_current_machine_refusal_proven);

section('exact executable consumer and guard inventory');
const mainSource = read('bin/zlar');
assert('main dispatcher targets only retired file', mainSource.includes('protected-records-runtime-service) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-runtime-service" "$@" ;;'));
assert('main help names retirement', mainSource.includes('Refuse the permanently retired legacy runtime-service direct entry surface'));

const runtimeProfileSource = read('lib/protected-records-runtime-profile.mjs');
equal('runtime profile child helper plus exact 25 calls', 26, count(runtimeProfileSource, /runRuntimeService\(/g));
equal('runtime profile has one exact child spawn', 1, count(runtimeProfileSource, /spawnSync\(ZLAR_BIN, \['protected-records-runtime-service', '--config', configPath\]/g));
const runtimeProofStart = runtimeProfileSource.indexOf('export function runProtectedRecordsRuntimeProfileProof');
const runtimeProof = runtimeProfileSource.slice(runtimeProofStart);
assert('runtime proof guard precedes scratch creation', runtimeProof.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < runtimeProof.indexOf('mkdtempSync'));
assert('runtime proof guard precedes first child call', runtimeProof.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < runtimeProof.indexOf('runRuntimeService('));

const installedServiceSource = read('lib/protected-records-installed-runtime-profile-service-proof.mjs');
equal('installed service helper plus exact 9 calls', 10, count(installedServiceSource, /runRuntimeService\(/g));
equal('installed service has one exact child spawn', 1, count(installedServiceSource, /spawnSync\(ZLAR_BIN, \['protected-records-runtime-service', '--config', configPath\]/g));
const installedServiceRunStart = installedServiceSource.indexOf('export function runProtectedRecordsInstalledRuntimeProfileServiceProof');
const installedServiceRun = installedServiceSource.slice(installedServiceRunStart);
assert('installed service guard precedes scratch', installedServiceRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < installedServiceRun.indexOf('mkdtempSync'));
assert('installed service guard precedes child call', installedServiceRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < installedServiceRun.indexOf('runRuntimeService('));

const namedBoundarySource = read('lib/protected-records-named-deployment-profile-real-boundary.mjs');
equal('named boundary helper plus exact 2 dormant calls', 3, count(namedBoundarySource, /runRuntimeChild\(/g));
const namedRunStart = namedBoundarySource.indexOf('export function runProtectedRecordsNamedDeploymentProfileRealBoundaryProof');
const namedRun = namedBoundarySource.slice(namedRunStart);
assert('named boundary refusal precedes activation inspection', namedRun.indexOf('throw refusal;') < namedRun.indexOf('ensureActivationRootShape'));
assert('named boundary refusal precedes first child call', namedRun.indexOf('throw refusal;') < namedRun.indexOf('runRuntimeChild('));

const recognitionSource = read('lib/protected-records-installed-runtime-profile-recognition-proof.mjs');
const recognitionStart = recognitionSource.indexOf('export function runProtectedRecordsInstalledRuntimeProfileRecognitionProof');
const recognitionRun = recognitionSource.slice(recognitionStart);
assert('recognition direct factory remains visible', recognitionRun.includes('createProtectedRecordsRuntimeService({'));
assert('recognition returned apply remains visible', recognitionRun.includes('service.applyRequest({'));
assert('recognition guard precedes scratch and direct factory', recognitionRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < recognitionRun.indexOf('mkdtempSync') && recognitionRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < recognitionRun.indexOf('createProtectedRecordsRuntimeService({'));

const installationSource = read('lib/protected-records-runtime-profile-installation.mjs');
assert('installation direct factory negative probe remains visible', installationSource.includes('const service = createProtectedRecordsRuntimeService({'));
const installationRunStart = installationSource.indexOf('export function runProtectedRecordsRuntimeProfileInstallationProof');
const installationRun = installationSource.slice(installationRunStart);
assert('installation guard precedes negative-probe invocation', installationRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < installationRun.indexOf('runRequestAuthorityGuardSummary()'));
assert('installation guard precedes nested child proof', installationRun.indexOf('assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed') < installationRun.indexOf('runProtectedRecordsRuntimeProfileProof()'));

const recordsTerminalSource = read('lib/records-write-terminal-proof.mjs');
const recordsTerminalCliSource = read('bin/zlar-records-write-terminal-proof');
assert('records terminal library reaches runtime local activation', recordsTerminalSource.includes('const localActivation = runProtectedRecordsRuntimeLocalActivationProof(plan, profile);'));
assert('records terminal CLI exposes terminal builder', recordsTerminalCliSource.includes('const proof = buildRecordsWriteTerminalProof(plan, profile);'));
const productProofSource = read('lib/product-proof-path.mjs');
const productProofCliSource = read('bin/zlar-product-proof-path');
equal('product proof has two explicit local-pack generation calls', 2, count(productProofSource, /buildLocalProofPackArtifact\(runLocalProofPack\(\)\)/g));
assert('product proof CLI exposes Product Proof Path generation', productProofCliSource.includes('const report = runProductProofPath();'));
assert('product proof CLI has no standalone verify mode', !productProofCliSource.includes("args[0] === 'verify'"));

const installSource = read('install.sh');
assert('installer inventory globs every zlar wrapper', installSource.includes('for wrapper in "${_INSTALL_SELF_DIR}/bin"/zlar-*; do'));
assert('installer copy path globs every zlar wrapper', installSource.includes('for wrapper in "${SCRIPT_SOURCE_DIR}/bin"/zlar-*; do'));
assert('installer copies wrapper into install bin', installSource.includes('cp "${wrapper}" "${INSTALL_DIR}/bin/${wrapper_name}"'));

const v2GrantSource = read('lib/protected-records-fixture-authority-grant-v2.mjs');
const v2ArtifactSetSource = read('lib/protected-records-replacement-artifact-set-v2.mjs');
const noReexecutionGraphSource = read('spec/protected-records-no-reexecution-call-graph-v2.json');
assert('v2 source completeness names retired CLI path', v2GrantSource.includes("'bin/zlar-protected-records-runtime-service'"));
assert('v2 artifact graph names general runtime CLI node', v2ArtifactSetSource.includes("source_symbol: 'zlar-protected-records-runtime-service'"));
assert('v2 no-reexecution spec names retired CLI symbol', noReexecutionGraphSource.includes('"source_symbol": "zlar-protected-records-runtime-service"'));

section('verification preservation and E4 separation');
equal('verify branch ordering is the proven boundary', true, spec.preserved_verification_boundary.verify_branch_precedes_named_generation_markers);
equal('verification branches intend no consequence reexecution', true, spec.preserved_verification_boundary.intended_no_consequence_reexecution);
equal('filesystem read-only is not claimed for every preserved mode', false, spec.preserved_verification_boundary.filesystem_read_only_for_all_modes);
equal('verification import-time side-effect closure remains false', false, spec.preserved_verification_boundary.import_time_side_effect_closure_proven);
equal('verification runtime no-write behavior is not generalized', false, spec.preserved_verification_boundary.runtime_no_write_behavior_generalized);
for (const verificationMode of spec.preserved_verification_modes) {
  const source = read(verificationMode.entrypoint);
  if (verificationMode.selector_type === 'non-run-supplied-report-composition') {
    const runSelector = source.indexOf(verificationMode.run_selector_marker);
    const runGeneration = source.indexOf(verificationMode.run_generation_marker, runSelector);
    const runExit = source.indexOf(verificationMode.run_exit_marker, runGeneration);
    const suppliedReportBuilder = source.indexOf(verificationMode.supplied_report_builder_marker, runExit);
    assert(`${verificationMode.mode_id} run selector exists`, runSelector >= 0);
    assert(`${verificationMode.mode_id} run generation stays inside the earlier run branch`, runGeneration > runSelector);
    assert(`${verificationMode.mode_id} run branch exits after generation`, runExit > runGeneration);
    assert(`${verificationMode.mode_id} supplied-report builder remains after the run exit`, suppliedReportBuilder > runExit);
    continue;
  }
  const verifyBranch = source.indexOf("if (args[0] === 'verify')");
  const verifyExit = source.indexOf('process.exit(0);', verifyBranch);
  assert(`${verificationMode.mode_id} verify branch exists`, verifyBranch >= 0);
  assert(`${verificationMode.mode_id} verify exit exists`, verifyExit > verifyBranch);
  for (const marker of verificationMode.generation_boundary_markers) {
    const markerIndex = source.indexOf(marker, verifyExit + 1);
    assert(`${verificationMode.mode_id} generation marker exists after verify: ${marker}`, markerIndex > verifyExit);
  }
}
const replacementSnapshotSource = read('lib/protected-records-replacement-source-snapshot-v2.mjs');
const replacementDriverSource = read('lib/protected-records-replacement-crossing-driver-v2.mjs');
const replacementChildSource = read('lib/protected-records-replacement-runtime-child-v2.mjs');
equal('E4 driver exact source remains unchanged', spec.immutable_dependencies.replacement_e4_unchanged_source.driver_file_sha256, sha256(replacementDriverSource));
equal('E4 child exact source remains unchanged', spec.immutable_dependencies.replacement_e4_unchanged_source.child_file_sha256, sha256(replacementChildSource));
assert('E4 snapshot uses dedicated replacement child', replacementSnapshotSource.includes("'lib/protected-records-replacement-runtime-child-v2.mjs'"));
assert('E4 driver binds dedicated replacement child', replacementDriverSource.includes("'lib/protected-records-replacement-runtime-child-v2.mjs'"));
assert('E4 driver does not invoke retired public runtime service', !replacementDriverSource.includes("['protected-records-runtime-service'"));
equal('replacement E4 driver and child unchanged by contract', false, spec.retirement_contract.replacement_e4_driver_or_child_changed);
equal('retired entry remains in v2 completeness contract', true, spec.retirement_contract.retired_entry_remains_in_v2_source_completeness_contract);
equal('old E4 source precondition does not match current checkout', false, spec.retirement_contract.prior_e4_source_precondition_matches_current_checkout);
equal('historical E4 authority not reusable', false, spec.retirement_contract.historical_e4_authority_reusable);

section('complete disposition inventory and historical test routing');
const expectedConsumerIds = [
  'active-persistent-action-crossing',
  'active-persistent-lifecycle',
  'declarative-command-contracts',
  'immutable-source-evidence-validators',
  'installed-recognition-direct-factory',
  'installed-service-proof-child-helper',
  'installed-service-proof-cli',
  'installer-copy-glob',
  'local-proof-pack',
  'main-shell-dispatch',
  'named-deployment-real-boundary',
  'north-star-readiness-dynamic-wrapper',
  'product-proof-path',
  'proof-smoke-dynamic-wrapper',
  'records-write-terminal-proof',
  'runtime-activation-preflight',
  'runtime-authority-v2-direct-cli-refusal-test',
  'runtime-local-activation',
  'runtime-profile-direct-factory-test',
  'runtime-profile-installation',
  'runtime-profile-positive-cli-test',
  'runtime-profile-preflight',
  'runtime-profile-proof-child-helper',
  'runtime-profile-proof-cli',
  'v2-no-reexecution-graph',
  'v2-source-completeness-contract',
  'v2-source-completeness-test',
].sort();
deepEqual('consumer id set exact', expectedConsumerIds, spec.consumers.map((item) => item.consumer_id).sort());
equal('consumer ids unique', spec.consumers.length, new Set(spec.consumers.map((item) => item.consumer_id)).size);
for (const consumer of spec.consumers) {
  assert(`${consumer.consumer_id} names caller`, typeof consumer.caller === 'string' && consumer.caller.length > 0);
  assert(`${consumer.consumer_id} names mode`, typeof consumer.mode === 'string' && consumer.mode.length > 0);
  assert(`${consumer.consumer_id} names entrypoint kind`, typeof consumer.entrypoint_kind === 'string' && consumer.entrypoint_kind.length > 0);
  assert(`${consumer.consumer_id} carries source-bound edge chain`, Array.isArray(consumer.source_bound_edge_chain));
  assert(`${consumer.consumer_id} carries legitimate dependency disposition`, consumer.legitimate_fixture_or_proof_dependency === null || (typeof consumer.legitimate_fixture_or_proof_dependency === 'string' && consumer.legitimate_fixture_or_proof_dependency.length > 0));
  assert(`${consumer.consumer_id} names E3 projection`, typeof consumer.e3_projection === 'string' && consumer.e3_projection.length > 0);
  assert(`${consumer.consumer_id} names guard posture`, typeof consumer.guard_or_refusal_posture === 'string' && consumer.guard_or_refusal_posture.length > 0);
  assert(`${consumer.consumer_id} carries imported environment and interpreter dependencies`, Array.isArray(consumer.imported_environment_and_interpreter_dependencies));
  assert(`${consumer.consumer_id} keeps alternate paths and side doors visible`, Array.isArray(consumer.unresolved_alternate_paths_and_side_doors) && consumer.unresolved_alternate_paths_and_side_doors.length > 0);
  assert(`${consumer.consumer_id} names retirement impact`, typeof consumer.retirement_impact === 'string' && consumer.retirement_impact.length > 0);
  assert(`${consumer.consumer_id} names disposition`, typeof consumer.disposition === 'string' && consumer.disposition.length > 0);
}

const inactive = read('tests/authority-inactive-test-suites.txt').trim().split('\n');
equal('authority-inactive test consumer count exact', spec.test_consumer_inventory.authority_inactive_positive_suite_count, inactive.length);
equal('authority-inactive inventory path exact', 'tests/authority-inactive-test-suites.txt', spec.test_consumer_inventory.authority_inactive_positive_suite_inventory_path);
for (const basename of [
  'test-protected-records-runtime-profile-cli.mjs',
  'test-protected-records-runtime-profile.mjs',
  'test-protected-records-installed-runtime-profile-service-proof-cli.mjs',
  'test-protected-records-installed-runtime-profile-service-proof.mjs',
  'test-protected-records-runtime-profile-installation.mjs',
]) {
  assert(`${basename} remains authority inactive`, inactive.includes(basename));
}
for (const relativePath of spec.test_consumer_inventory.active_refusal_and_source_test_paths) {
  assert(`${relativePath} exists as an active refusal or source consumer`, lstatSync(join(PROJECT_DIR, relativePath)).isFile());
}
deepEqual(
  'superseded exact-source suite inventory exact',
  [
    'test-consequence-path-coverage-dependency-map-v0.mjs',
    'test-source-bound-static-reachability-delta-v0.mjs',
  ],
  read('tests/superseded-source-bound-test-suites.txt').trim().split('\n'),
);
const assertionHarness = read('tests/count-assertions.sh');
assert('assertion harness loads superseded inventory', assertionHarness.includes('SUPERSEDED_SOURCE_BOUND_TEST_SUITES='));
assert('assertion harness exact-matches superseded basenames', assertionHarness.includes('grep -Fqx "${base}" "${SUPERSEDED_SOURCE_BOUND_TEST_SUITES}"'));
assert('assertion harness reports source-snapshot reason', assertionHarness.includes('(superseded source snapshot)'));
assert('current disposition suite is not superseded', !read('tests/superseded-source-bound-test-suites.txt').includes('test-legacy-runtime-v1-governed-disposition-v0.mjs'));
assert('superseded suites are not mislabeled authority inactive', !inactive.includes('test-consequence-path-coverage-dependency-map-v0.mjs') && !inactive.includes('test-source-bound-static-reachability-delta-v0.mjs'));

for (const relativePath of spec.declarative_command_contract_paths) {
  const source = read(relativePath);
  assert(`${relativePath} remains an explicit declarative legacy reference`, source.includes('protected-records-runtime-service'));
}

section('old live-source reconstruction fails closed');
throws(
  'immutable parent source inventory rejects current checkout drift',
  () => consequencePathCoverageSourceInventorySha256V0(
    sourceFiles(CONSEQUENCE_PATH_COVERAGE_SOURCE_PATHS_V0),
  ),
  /SHA-256|marker|mismatch|drift/i,
);
throws(
  'immutable reachability source inventory rejects current checkout drift',
  () => sourceBoundStaticReachabilitySourceInventorySha256V0(
    sourceFiles(SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0),
  ),
  /SHA-256|witness|mismatch|drift/i,
);

section('authority, claim ceiling, side doors, and privacy');
equal('source authority present', true, spec.authority_status.route_and_source_authority_present);
equal('source authority is active-turn observation only', 'control_tower_active_turn_user_message', spec.source_authority_evidence.observation_surface);
equal('source authority exact scope', 'route_and_source_only', spec.source_authority_evidence.scope);
equal('no embedded portable authority record', false, spec.source_authority_evidence.embedded_authority_record);
equal('source authority is not portable', false, spec.source_authority_evidence.portable);
equal('source authority is not reusable', false, spec.source_authority_evidence.reusable);
equal('source authority carries no consequence authority', false, spec.source_authority_evidence.consequence_authority);
equal('consequence authority absent', false, spec.authority_status.consequence_authority_present);
equal('outside-coverage authority absent', false, spec.authority_status.outside_coverage_authority_present);
equal('active authority absent', false, spec.authority_status.active_authority_present);
equal('rightful issuance remains false', false, spec.claim_boundary.rightful_issuance);
equal('equivalent-route closure remains false', false, spec.claim_boundary.equivalent_route_closure);
equal('same-route closeout remains false', false, spec.claim_boundary.same_route_closeout);
equal('one narrow source claim true', true, spec.claim_boundary.source_level_named_entry_refusal);
for (const [claim, value] of Object.entries(spec.claim_boundary)) {
  if (claim === 'source_level_named_entry_refusal') continue;
  equal(`${claim} remains false`, false, value);
}
for (const requiredSideDoor of [
  'direct-esm-import-of-createProtectedRecordsRuntimeService',
  'direct-internal-e4-child-or-module-invocation',
  'custom-loaders-and-preloads-before-stub-execution',
  'BASH_ENV',
  'exported-shell-functions',
  'direct-shebang-/usr/bin/env-node-PATH-resolution',
  'unqualified-node-and-PATH-substitution-in-bin-zlar',
  'old-commit-or-copied-positive-executable',
  'existing-installed-or-machine-local-copy-not-inspected',
  'raw-filesystem-writes-around-fixture-storage',
  'same-user-source-mutation',
  'verification-branch-transitive-import-time-side-effects-unproven',
  'abnormal-termination-historical-source-temp-residue',
]) {
  assert(`${requiredSideDoor} remains visible`, spec.side_doors.includes(requiredSideDoor));
}
equal('future internal route is not authorized', false, spec.future_reactivation_boundary.authorized_in_this_lane);
equal('retired direct surface cannot reopen', false, spec.future_reactivation_boundary.retired_direct_surface_reopen_allowed);
equal('hidden direct CLI mode is forbidden', false, spec.future_reactivation_boundary.hidden_direct_cli_mode_allowed);
equal('future E3 route requires a new versioned non-dispatched capability', true, spec.future_reactivation_boundary.requires_new_versioned_non_dispatched_internal_capability);
equal('future E3 route requires consumer migration', true, spec.future_reactivation_boundary.requires_consumer_migration);
equal('future internal route needs separate authority', true, spec.future_reactivation_boundary.requires_separate_authority_before_implementation);

for (const [label, source] of [
  ['entry', entrySource],
  ['spec', specText],
  ['superseded routing doc', read('tests/SUPERSEDED-SOURCE-BOUND-SUITES.md')],
]) {
  assert(`${label} has no private absolute path`, !/\/Users\/|\/home\/|\/private\/|\/tmp\//.test(source));
  assert(`${label} has no PEM block`, !/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/.test(source));
  assert(`${label} has no credential material vocabulary`, !/telegram.*(?:token|credential)|hmac.*secret/i.test(source));
}

process.stdout.write(`\nResults: ${assertions}/${assertions} passed\n`);
