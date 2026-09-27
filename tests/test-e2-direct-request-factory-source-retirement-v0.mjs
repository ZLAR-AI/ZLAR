#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC_PATH = join(
  ROOT,
  'spec/e2-direct-request-factory-source-retirement-v0.json',
);
const BASELINE_COMMIT = '530683fc61f85e5b0c8882f8b65a3bcd8ef9199d';
const EXPECTED_SPEC_BODY_SHA =
  '6c27a0be8f447a96c369388d6c67d0795060fcf88a93c5855881beb0ced38b11';
const RETIREMENT_REASON = 'e2_direct_request_factory_source_retired';
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

function fileSha(relativePath) {
  return sha(readFileSync(join(ROOT, relativePath)));
}

function section(label) {
  process.stdout.write(`\n## ${label}\n`);
}

function gitShow(commit, path) {
  const result = spawnSync('/usr/bin/git', ['show', `${commit}:${path}`], {
    cwd: ROOT,
    encoding: null,
    env: {
      NO_COLOR: '1',
      PATH: '/usr/bin:/bin',
    },
  });
  equal(`git show succeeds: ${commit}:${path}`, 0, result.status);
  equal(`git show stderr empty: ${commit}:${path}`, '', result.stderr.toString());
  return result.stdout;
}

function collectSourceFiles(startRelativePath) {
  const found = [];
  const visit = (relativePath) => {
    const absolutePath = join(ROOT, relativePath);
    for (const entry of readdirSync(absolutePath, { withFileTypes: true })) {
      const child = join(relativePath, entry.name);
      if (entry.isDirectory()) {
        if (child === 'tests/fixtures') continue;
        visit(child);
      } else if (entry.isFile()) {
        found.push(child);
      }
    }
  };
  visit(startRelativePath);
  return found;
}

function hostileProxy() {
  let reads = 0;
  const proxy = new Proxy({}, {
    get() {
      reads += 1;
      throw new Error('hostile getter reached');
    },
    ownKeys() {
      reads += 1;
      throw new Error('hostile ownKeys reached');
    },
    getOwnPropertyDescriptor() {
      reads += 1;
      throw new Error('hostile descriptor reached');
    },
  });
  return { proxy, reads: () => reads };
}

function runWrapper(relativePath, args, input) {
  return spawnSync(
    process.execPath,
    [join(ROOT, relativePath), ...args],
    {
      cwd: ROOT,
      encoding: 'utf8',
      input,
      env: {
        NO_COLOR: '1',
        PATH: '/usr/bin:/bin',
      },
    },
  );
}

function runNodeWrapper(args) {
  return runWrapper('bin/zlar-protected-records-service-request', args);
}

const spec = JSON.parse(readFileSync(SPEC_PATH, 'utf8'));
const { integrity, ...body } = spec;

section('artifact and current source inventory');
equal(
  'artifact type',
  'zlar.e2-direct-request-factory-source-retirement.v0',
  spec.artifact_type,
);
equal('schema version', 0, spec.schema_version);
equal(
  'decision exact',
  'retire_direct_e2_request_factory_and_future_copy_preserve_historical_verification',
  spec.decision,
);
equal('baseline commit exact', BASELINE_COMMIT, spec.source_checkpoint.baseline_commit_oid);
equal('baseline remote exact', BASELINE_COMMIT, spec.source_checkpoint.baseline_private_remote_oid);
equal('positive E2 execution absent', false, spec.source_checkpoint.positive_e2_execution_performed);
equal('runtime observation absent', false, spec.source_checkpoint.runtime_observation_performed);
equal('installation absent', false, spec.source_checkpoint.installation_performed);
equal('integrity algorithm', 'SHA-256', integrity.algorithm);
equal('integrity scope', 'canonical artifact body without integrity', integrity.scope);
equal('spec body pin exact', EXPECTED_SPEC_BODY_SHA, integrity.body_sha256);
equal('spec body SHA validates', EXPECTED_SPEC_BODY_SHA, sha(canonicalize(body)));
equal(
  'current source inventory paths unique',
  spec.source_inventory.length,
  new Set(spec.source_inventory.map((item) => item.path)).size,
);
for (const item of spec.source_inventory) {
  equal(`${item.path} current SHA exact`, item.file_sha256, fileSha(item.path));
}
equal('canonical E2 identity preserved', 'E2.service-jsonl-state-append-v1', spec.effect_node_id);

section('Stage 2 source-bound preservation');
const stage2SpecPath = 'spec/e2-positive-proof-generator-retirement-v0.json';
equal(
  'Stage 2 overlay bytes unchanged',
  spec.historical_verification.stage_2_overlay.file_sha256,
  fileSha(stage2SpecPath),
);
const stage2Spec = JSON.parse(read(stage2SpecPath));
equal('Stage 2 baseline exact', 'f369b6779dff1f1cb339ffb6e58f0a0f67f0832b', stage2Spec.source_checkpoint.baseline_commit_oid);
for (const item of stage2Spec.source_inventory) {
  equal(
    `Stage 2 source identity at ${BASELINE_COMMIT}: ${item.path}`,
    item.file_sha256,
    sha(gitShow(BASELINE_COMMIT, item.path)),
  );
}
const stage2Inventory = new Map(
  stage2Spec.source_inventory.map((item) => [item.path, item.file_sha256]),
);
for (const path of [
  'bin/zlar-protected-records-service-proof',
  'bin/zlar-protected-records-service-preflight',
  'lib/local-proof-pack.mjs',
  'bin/zlar-local-proof-pack',
  'lib/product-proof-path.mjs',
  'bin/zlar-product-proof-path',
  'lib/north-star-readiness.mjs',
  'bin/zlar-north-star-readiness',
  'tests/retired-positive-generator-test-suites.txt',
]) {
  equal(
    `Stage 2 unchanged source remains live: ${path}`,
    stage2Inventory.get(path),
    fileSha(path),
  );
}
equal(
  'Stage 2 direct-positive suite bytes preserved under retired classification',
  stage2Inventory.get('tests/current-positive-e2-test-suites.txt'),
  fileSha('tests/retired-direct-e2-test-suites.txt'),
);
for (const item of [
  stage2Spec.unchanged_stage_3_and_e4_boundaries.direct_e2_factory,
  stage2Spec.unchanged_stage_3_and_e4_boundaries.direct_e2_request_cli,
  stage2Spec.unchanged_stage_3_and_e4_boundaries.future_install_copy_path,
]) {
  equal(
    `Stage 2 boundary identity at ${BASELINE_COMMIT}: ${item.path}`,
    item.file_sha256,
    sha(gitShow(BASELINE_COMMIT, item.path)),
  );
}

section('static fixed-refusal precondition');
const factorySource = read('lib/protected-records-service.mjs');
const verificationSource = read('lib/protected-records-service-verification.mjs');
const requestWrapperSource = read('bin/zlar-protected-records-service-request');
const mainCliSource = read('bin/zlar');
const installerSource = read('install.sh');
const profileSource = read('lib/protected-records-service-profile.mjs');
const proofSource = read('lib/protected-records-service-proof.mjs');
const localProofPackSource = read('lib/local-proof-pack.mjs');
const productProofSource = read('lib/product-proof-path.mjs');

assert(
  'Stage 2 service-proof fixed refusal remains live',
  proofSource.includes(
    'export function runProtectedRecordsServiceProof() {\n' +
      '  throw new Error(PROTECTED_RECORDS_SERVICE_PROOF_GENERATION_RETIREMENT_REASON);\n' +
      '}',
  ),
);
assert(
  'Stage 2 service-preflight fixed refusal remains live',
  profileSource.includes(
    'export function runProtectedRecordsServiceProfilePreflight() {\n' +
      '  throw new Error(\n' +
      '    PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_GENERATION_RETIREMENT_REASON,\n' +
      '  );\n' +
      '}',
  ),
);
assert(
  'Stage 2 service-preflight default artifact fallback remains retired',
  profileSource.includes(
    "if (report === undefined) {\n" +
      "    throw new Error(\n" +
      "      'e2_positive_service_preflight_default_artifact_generation_retired',\n" +
      '    );\n' +
      '  }',
  ),
);
assert(
  'Stage 2 local-proof-pack fixed refusal remains live',
  localProofPackSource.includes(
    'export function runLocalProofPack() {\n' +
      '  throw new Error(LOCAL_PROOF_PACK_GENERATION_RETIREMENT_REASON);\n' +
      '}',
  ),
);
assert(
  'Stage 2 local-proof-pack default artifact fallback remains retired',
  localProofPackSource.includes(
    "if (report === undefined) {\n" +
      "    throw new Error('local_proof_pack_default_artifact_generation_retired');\n" +
      '  }',
  ),
);
assert(
  'Stage 2 product-proof builder fixed refusal remains live',
  productProofSource.includes(
    'export function buildProductProofPathReport() {\n' +
      '  throw new Error(PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON);\n' +
      '}',
  ),
);
assert(
  'Stage 2 product-proof runner fixed refusal remains live',
  productProofSource.includes(
    'export function runProductProofPath() {\n' +
      '  throw new Error(PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON);\n' +
      '}',
  ),
);

const exactFactoryBody =
  `export function applyProtectedRecordsServiceRequest() {\n` +
  `  throw new Error(PROTECTED_RECORDS_SERVICE_REQUEST_RETIREMENT_REASON);\n` +
  `}\n`;
assert('factory exact zero-parameter refusal body', factorySource.includes(exactFactoryBody));
assert('factory source declares exact reason', factorySource.includes(`'${RETIREMENT_REASON}'`));
for (const forbidden of [
  'node:fs',
  'canonicalize',
  'evaluateDownstreamRecognition',
  'protected-records-adapter',
  'writeFileSync',
  'unlinkSync',
  'writeConsumedStoreForTest',
  "flag: 'a'",
  'arguments',
]) {
  assert(`factory stub excludes ${forbidden}`, !factorySource.includes(forbidden));
}
assert('verification module has no imports', !/^import\s/m.test(verificationSource));
assert(
  'verification module exposes no positive factory',
  !verificationSource.includes('applyProtectedRecordsServiceRequest'),
);
for (const forbidden of [
  'node:fs',
  'evaluateDownstreamRecognition',
  'writeFileSync',
  'unlinkSync',
  'spawnSync',
  'execSync',
  "flag: 'a'",
]) {
  assert(`verification module excludes ${forbidden}`, !verificationSource.includes(forbidden));
}
assert(
  'profile verification imports split module',
  profileSource.includes("from './protected-records-service-verification.mjs';"),
);
assert(
  'profile verification does not import retired factory module',
  !profileSource.includes("from './protected-records-service.mjs';"),
);
assert(
  'proof verification imports split module',
  proofSource.includes("from './protected-records-service-verification.mjs';"),
);
assert(
  'proof verification does not import retired factory module',
  !proofSource.includes("from './protected-records-service.mjs';"),
);
equal(
  'request wrapper exact fixed-refusal source',
  `#!/usr/bin/env node\n\nconsole.error('ERROR: ${RETIREMENT_REASON}');\nprocess.exit(1);\n`,
  requestWrapperSource,
);
assert('request wrapper has no module import', !/^import\s/m.test(requestWrapperSource));
assert('request wrapper has no argv read', !requestWrapperSource.includes('process.argv'));
assert('request wrapper has no stdin or JSON read', !/stdin|readFile|JSON\./.test(requestWrapperSource));
assert('main help removes direct request', !mainCliSource.includes('    protected-records-service-request\\n'));
assert(
  'main dispatcher removes direct request',
  !mainCliSource.includes('protected-records-service-request)'),
);

const scannedFiles = [
  ...collectSourceFiles('lib'),
  ...collectSourceFiles('bin'),
  ...collectSourceFiles('tests'),
];
const retiredModuleImportPattern =
  /(?:from\s*|import\s*\()\s*['"][^'"]*\/protected-records-service\.mjs['"]/;
const retiredModuleImporters = scannedFiles
  .filter((path) => retiredModuleImportPattern.test(read(path)))
  .map((path) => relative('.', path).replace(/^\.\//, ''))
  .sort();
deepEqual(
  'retired module importers are historical/refusal tests only',
  [
    'tests/test-claude-code-receipt-bridge-proof.mjs',
    'tests/test-e2-direct-request-factory-source-retirement-v0.mjs',
    'tests/test-protected-records-service-proof.mjs',
    'tests/test-protected-records-service.mjs',
  ],
  retiredModuleImporters,
);

section('future installer source exclusion');
for (const marker of [
  'zlar-protected-records-service-request) return 0',
  'protected-records-service.mjs) return 0',
  'is_retired_installed_bin_wrapper "${wrapper_name}" && continue',
  'is_retired_installed_library "${library_name}" && continue',
  'copy_installed_libraries',
]) {
  assert(`installer contains exact exclusion marker: ${marker}`, installerSource.includes(marker));
}
assert(
  'installer no longer glob-copies every library',
  !installerSource.includes('cp "${SCRIPT_SOURCE_DIR}/lib/"* "${INSTALL_DIR}/lib/"'),
);
equal('installer was not executed', false, spec.future_install_copy_disposition.installer_executed);
equal('existing installed files not deleted', false, spec.future_install_copy_disposition.existing_installed_files_deleted);
equal('installed-copy retirement unproven', false, spec.future_install_copy_disposition.installed_copy_retirement_proven);

section('dynamic hostile-input refusal after static proof');
const factoryModule = await import('../lib/protected-records-service.mjs');
const verificationModule = await import('../lib/protected-records-service-verification.mjs');
equal('factory reason export exact', RETIREMENT_REASON, factoryModule.PROTECTED_RECORDS_SERVICE_REQUEST_RETIREMENT_REASON);
equal('factory metadata length zero', 0, factoryModule.applyProtectedRecordsServiceRequest.length);
const hostileInput = hostileProxy();
const hostileOptions = hostileProxy();
let observedError = null;
try {
  factoryModule.applyProtectedRecordsServiceRequest(
    hostileInput.proxy,
    hostileOptions.proxy,
  );
} catch (error) {
  observedError = error;
}
equal('factory fixed error exact', RETIREMENT_REASON, observedError?.message);
equal('factory reads no hostile input', 0, hostileInput.reads());
equal('factory reads no hostile options', 0, hostileOptions.reads());
equal('historical result validator remains exported', 'function', typeof verificationModule.assertProtectedRecordsServiceResult);
equal('historical privacy guard remains exported', 'function', typeof verificationModule.assertNoUnsafeProtectedRecordsServiceText);
equal('verification module exposes no factory', undefined, verificationModule.applyProtectedRecordsServiceRequest);
equal('validator hostile-object safety remains explicitly false', false, spec.verification_split.hostile_object_safe);
equal('validator fresh-effect verification remains false', false, spec.verification_split.fresh_effect_verification);

section('standalone CLI fixed refusal and no writes');
const prohibitedOutput = join(
  tmpdir(),
  `zlar-stage3-direct-e2-prohibited-${process.pid}.json`,
);
equal('prohibited output precondition absent', false, existsSync(prohibitedOutput));
for (const args of [
  [],
  ['--help'],
  ['--config', '/nonexistent/config.json', '--input', '/nonexistent/input.json'],
  ['--input', '-', '--require-refused'],
  ['--artifact', prohibitedOutput, '--require-written'],
]) {
  const result = runNodeWrapper(args);
  equal(`wrapper exits one: ${args.join(' ')}`, 1, result.status);
  equal(`wrapper stdout empty: ${args.join(' ')}`, '', result.stdout);
  equal(
    `wrapper stderr exact: ${args.join(' ')}`,
    `ERROR: ${RETIREMENT_REASON}\n`,
    result.stderr,
  );
}
equal('wrapper creates no prohibited output', false, existsSync(prohibitedOutput));
assert(
  'wrapper remains executable',
  (statSync(join(ROOT, 'bin/zlar-protected-records-service-request')).mode & 0o111) !== 0,
);

section('exact historical verification and tamper refusal');
const servicePreflightBodySha =
  spec.historical_verification.service_preflight.body_sha256;
const serviceVerificationRun = runWrapper(
  'bin/zlar-protected-records-service-preflight',
  ['verify', '--sample', '--require-sha', servicePreflightBodySha, '--json'],
);
equal('service-preflight historical verification exits zero', 0, serviceVerificationRun.status);
equal('service-preflight historical verification stderr empty', '', serviceVerificationRun.stderr);
const serviceVerification = JSON.parse(serviceVerificationRun.stdout);
equal('service-preflight historical verification true', true, serviceVerification.verified);
equal('service-preflight historical body exact', servicePreflightBodySha, serviceVerification.body_sha256);

const localProofPackBodySha =
  spec.historical_verification.local_proof_pack.body_sha256;
const localVerificationRun = runWrapper(
  'bin/zlar-local-proof-pack',
  ['verify', '--sample', '--require-sha', localProofPackBodySha, '--json'],
);
equal('local-proof-pack historical verification exits zero', 0, localVerificationRun.status);
equal('local-proof-pack historical verification stderr empty', '', localVerificationRun.stderr);
const localVerification = JSON.parse(localVerificationRun.stdout);
equal('local-proof-pack historical verification true', true, localVerification.verified);
equal('local-proof-pack historical body exact', localProofPackBodySha, localVerification.body_sha256);
equal('local-proof-pack fresh generation false', false, localVerification.fresh_proof_pack_run_performed);

const tamperedService = JSON.parse(
  read('tests/fixtures/protected-records-service-preflight-artifact-v1.json'),
);
tamperedService.payload.preflight.live_probing = true;
const tamperedServiceRun = runWrapper(
  'bin/zlar-protected-records-service-preflight',
  ['verify', '--input', '-', '--require-sha', servicePreflightBodySha, '--json'],
  `${JSON.stringify(tamperedService)}\n`,
);
equal('tampered service-preflight artifact refuses', 1, tamperedServiceRun.status);

const tamperedLocal = JSON.parse(
  read('tests/fixtures/local-proof-pack-artifact-v1.json'),
);
tamperedLocal.payload.live_probing = true;
const tamperedLocalRun = runWrapper(
  'bin/zlar-local-proof-pack',
  ['verify', '--input', '-', '--require-sha', localProofPackBodySha, '--json'],
  `${JSON.stringify(tamperedLocal)}\n`,
);
equal('tampered local-proof-pack artifact refuses', 1, tamperedLocalRun.status);

section('test routing and current-source consumer disposition');
deepEqual(
  'retired direct E2 suites exact',
  [
    'test-claude-code-receipt-bridge-proof.mjs',
    'test-protected-records-service-request-cli.mjs',
    'test-protected-records-service.mjs',
  ],
  read('tests/retired-direct-e2-test-suites.txt').trim().split('\n'),
);
equal(
  'contradictory current-positive inventory removed',
  false,
  existsSync(join(ROOT, 'tests/current-positive-e2-test-suites.txt')),
);
const superseded = read('tests/superseded-source-bound-test-suites.txt').trim().split('\n');
assert('Stage 2 live-tree suite routed as source-bound historical', superseded.includes('test-e2-positive-proof-generator-retirement-v0.mjs'));
assert('Stage 3 suite remains active', !superseded.includes('test-e2-direct-request-factory-source-retirement-v0.mjs'));
equal('three direct suites retired', 3, spec.test_routing.retired_direct_e2_suite_count);
equal('four generator suites remain retired', 4, spec.test_routing.retired_positive_generator_suite_count);
for (const item of spec.consumer_inventory) {
  assert(`${item.id} has an edge chain`, Array.isArray(item.edge_chain) && item.edge_chain.length > 0);
  assert(
    `${item.id} classification allowed`,
    [
      'fixed-refusal',
      'dispatch-removed',
      'verification-only-import',
      'historical-effect-capable-test-source',
      'immutable-prior-source-overlay',
      'historical-evidence-text',
      'source-only-copy-exclusion',
      'historical-source-bound-evidence',
      'unknown-open',
    ].includes(item.classification),
  );
}

section('historical bytes and unchanged source boundaries');
for (const item of [
  spec.historical_verification.proof_smoke,
  spec.historical_verification.local_proof_pack,
  spec.historical_verification.service_preflight,
  spec.historical_verification.service_profile_command_fixture,
]) {
  equal(`${item.file_path} immutable SHA`, item.file_sha256, fileSha(item.file_path));
}
for (const item of [
  spec.unchanged_source_boundaries.consequence_lifecycle_map_library,
  spec.unchanged_source_boundaries.source_bound_reachability_library,
  spec.unchanged_source_boundaries.prior_dependency_map_library,
]) {
  equal(`${item.path} unchanged SHA`, item.file_sha256, fileSha(item.path));
  equal(`${item.path} mutation false`, false, item.mutated);
}
const e4 = spec.unchanged_source_boundaries.replacement_e4;
equal('E4 driver unchanged', e4.driver_file_sha256, fileSha(e4.driver_path));
equal('E4 child unchanged', e4.child_file_sha256, fileSha(e4.child_path));
equal('E4 changed false', false, e4.changed);

section('topology, reachability, lifecycle, and claim ceiling');
equal('North Star 1 remains historical', 'historical', spec.north_star_1_status);
equal('North Star 2 remains mapped open', 'mapped_open', spec.north_star_2_status);
equal('lifecycle remains mapped open', 'mapped_open', spec.lifecycle_refresh.map_status_after);
deepEqual('no lifecycle obligation status changed', [], spec.lifecycle_refresh.lifecycle_obligation_status_changes);
equal('canonical E2 identity preserved', true, spec.effect_node_topology_refresh.canonical_e2_identity_preserved);
equal('named static current-source positive route absent', false, spec.effect_node_topology_refresh.named_static_current_source_positive_e2_route_found_after);
equal('dynamic/external inventory incomplete', false, spec.effect_node_topology_refresh.inventory_complete_for_dynamic_external_old_or_mutated_paths);
equal('E2 elimination remains false', false, spec.effect_node_topology_refresh.e2_effect_node_eliminated);
equal('runtime reachability remains unproven', false, spec.reachability_delta_refresh.runtime_reachability_proven);
equal('equivalent-route closure remains unproven', false, spec.reachability_delta_refresh.equivalent_route_closure_proven);
for (const [claim, value] of Object.entries(spec.claim_boundary)) {
  if ([
    'exact_checked_out_source_direct_e2_request_factory_retirement',
    'exact_historical_verification_preserved',
    'future_installer_source_copy_exclusion',
  ].includes(claim)) {
    equal(`${claim} exact true`, true, value);
  } else {
    equal(`${claim} remains false`, false, value);
  }
}
for (const sideDoor of [
  'old-installed-copied-historical-or-mutated-positive-source',
  'upgrade-or-reinstall-stale-installed-wrapper-and-module-residue',
  'already-loaded-positive-function-object',
  'explicit-report-artifact-packaging-and-write-exports',
  'raw-filesystem-writes',
  'NODE_OPTIONS-loaders-preloads-and-interpreter-substitution',
  'dynamic-generated-or-external-entrypoints',
  'source-drift-after-checkpoint',
]) {
  assert(`side door visible: ${sideDoor}`, spec.side_doors.includes(sideDoor));
}

process.stdout.write(
  `\nResults: ${assertions}/${assertions} passed — E2 direct request/factory source retirement v0\n`,
);
