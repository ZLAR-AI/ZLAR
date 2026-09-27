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
const NODE_BIN_DIR = dirname(process.execPath);
const SPEC_PATH = join(
  ROOT,
  'spec/e1-direct-adapter-factory-source-retirement-v0.json',
);
const BASELINE_COMMIT = 'd8c10149b2f0333b65f751e57920ee1ca28c6ab3';
const EXPECTED_SPEC_BODY_SHA =
  'b1c3bbcd0cd6d5ce448f337e7a243a415b89e0f601697bda87a82ce353fa2b1d';
const RETIREMENT_REASON = 'e1_direct_adapter_factory_source_retired';
const TERMINAL_REASON = 'e1_positive_terminal_proof_generation_retired';
const CONFORMANCE_REASON = 'e1_positive_adapter_conformance_generation_retired';
const LOCAL_PROOF_PACK_BODY_SHA =
  '777f66be5c4c5d9dcf5c5555c4e80653231815db22a82adf056c0908cf890ac0';
const PROOF_SMOKE_FILE_SHA =
  '69d567c4708642393c470f3cffca015d1c39096a99191d720252aaf5a33b0635';
const PROOF_SMOKE_REPORT_SHA =
  '4e700bfeb3061589baa68071f534e1a74221a1b26e38100afdee62bbe6938c6f';
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
    env: { NO_COLOR: '1', PATH: '/usr/bin:/bin' },
  });
  equal(`git show succeeds: ${commit}:${path}`, 0, result.status);
  equal(`git show stderr empty: ${commit}:${path}`, '', result.stderr.toString());
  return result.stdout;
}

function runWrapper(relativePath, args = [], input) {
  return spawnSync(process.execPath, [join(ROOT, relativePath), ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    input,
    env: { NO_COLOR: '1', PATH: '/usr/bin:/bin' },
  });
}

function runMain(args = [], input) {
  return spawnSync(join(ROOT, 'bin/zlar'), args, {
    cwd: ROOT,
    encoding: 'utf8',
    input,
    env: { NO_COLOR: '1', PATH: `${NODE_BIN_DIR}:/usr/bin:/bin` },
  });
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

function assertThrowsExact(label, fn, expectedMessage) {
  assertions += 1;
  try {
    fn();
  } catch (error) {
    if (error instanceof Error && error.message === expectedMessage) return;
    throw new Error(
      `FAIL: ${label}: expected ${expectedMessage}, got ${error?.message || String(error)}`,
    );
  }
  throw new Error(`FAIL: ${label}: expected throw`);
}

function collectFiles(startRelativePath) {
  const found = [];
  const visit = (relativePath) => {
    for (const entry of readdirSync(join(ROOT, relativePath), { withFileTypes: true })) {
      const child = join(relativePath, entry.name);
      if (entry.isDirectory()) visit(child);
      if (entry.isFile()) found.push(relative('.', child).replace(/^\.\//, ''));
    }
  };
  visit(startRelativePath);
  return found;
}

const spec = JSON.parse(readFileSync(SPEC_PATH, 'utf8'));
const { integrity, ...body } = spec;

section('overlay and exact current source inventory');
equal(
  'artifact type exact',
  'zlar.e1-direct-adapter-factory-source-retirement.v0',
  spec.artifact_type,
);
equal('schema version exact', 0, spec.schema_version);
equal(
  'decision exact',
  'retire_direct_e1_adapter_factory_cli_and_future_copy_preserve_historical_verification',
  spec.decision,
);
equal('baseline commit exact', BASELINE_COMMIT, spec.source_checkpoint.baseline_commit_oid);
equal('baseline private remote exact', BASELINE_COMMIT, spec.source_checkpoint.baseline_private_remote_oid);
equal('runtime observation absent', false, spec.source_checkpoint.runtime_observation_performed);
equal('positive E1 execution absent', false, spec.source_checkpoint.positive_e1_execution_performed);
equal('installation absent', false, spec.source_checkpoint.installation_performed);
equal('integrity algorithm exact', 'SHA-256', integrity.algorithm);
equal('integrity scope exact', 'canonical artifact body without integrity', integrity.scope);
equal('integrity pin exact', EXPECTED_SPEC_BODY_SHA, integrity.body_sha256);
equal('integrity recomputes', EXPECTED_SPEC_BODY_SHA, sha(canonicalize(body)));
equal(
  'source inventory paths unique',
  spec.source_inventory.length,
  new Set(spec.source_inventory.map((item) => item.path)).size,
);
for (const item of spec.source_inventory) {
  equal(`${item.path} current source SHA exact`, item.file_sha256, fileSha(item.path));
}
equal('canonical E1 identity exact', 'E1.adapter-ledger-append-v1', spec.effect_node_id);

section('Stage 4 exact-source and live refusal preservation');
equal(
  'Stage 4 overlay file SHA unchanged',
  spec.historical_verification.stage_4_overlay.file_sha256,
  fileSha(spec.historical_verification.stage_4_overlay.file_path),
);
const stage4 = JSON.parse(read(spec.historical_verification.stage_4_overlay.file_path));
equal(
  'Stage 4 overlay body identity exact',
  spec.historical_verification.stage_4_overlay.body_sha256,
  stage4.integrity.body_sha256,
);
for (const item of stage4.source_inventory) {
  equal(
    `Stage 4 source identity at baseline: ${item.path}`,
    item.file_sha256,
    sha(gitShow(BASELINE_COMMIT, item.path)),
  );
}
equal(
  'Stage 4 current-positive E1 inventory bytes preserved under retired name',
  sha(gitShow(BASELINE_COMMIT, 'tests/current-positive-e1-direct-test-suites.txt')),
  fileSha('tests/retired-direct-e1-test-suites.txt'),
);
for (const item of spec.unchanged_stage_4_generator_refusals) {
  equal(`${item.path} Stage 4 live SHA unchanged`, item.file_sha256, fileSha(item.path));
}
const terminalSource = read('lib/protected-records-terminal-proof.mjs');
const conformanceSource = read('lib/protected-records-adapter-conformance.mjs');
const terminalWrapperSource = read('bin/zlar-protected-records-proof');
const conformanceWrapperSource = read('bin/zlar-protected-records-adapter-conformance');
assert(
  'Stage 4 terminal library refusal remains live',
  terminalSource.includes(
    'export function runProtectedRecordsTerminalProof() {\n' +
      '  throw new Error(PROTECTED_RECORDS_TERMINAL_PROOF_GENERATION_RETIREMENT_REASON);\n' +
      '}',
  ),
);
assert(
  'Stage 4 conformance library refusal remains live',
  conformanceSource.includes(
    'export function runProtectedRecordsAdapterConformanceProof() {\n' +
      '  throw new Error(\n' +
      '    PROTECTED_RECORDS_ADAPTER_CONFORMANCE_GENERATION_RETIREMENT_REASON,\n' +
      '  );\n' +
      '}',
  ),
);
equal(
  'Stage 4 terminal wrapper refusal remains exact',
  `#!/usr/bin/env node\n\nconsole.error('ERROR: ${TERMINAL_REASON}');\nprocess.exit(1);\n`,
  terminalWrapperSource,
);
equal(
  'Stage 4 conformance wrapper refusal remains exact',
  `#!/usr/bin/env node\n\nconsole.error('ERROR: ${CONFORMANCE_REASON}');\nprocess.exit(1);\n`,
  conformanceWrapperSource,
);

section('direct E1 fixed-refusal source disposition');
const adapterSource = read('lib/protected-records-adapter.mjs');
const verificationSource = read('lib/protected-records-adapter-verification.mjs');
const wrapperSource = read('bin/zlar-protected-records-write');
const mainSource = read('bin/zlar');
const installerSource = read('install.sh');
const expectedAdapterSource =
  "export {\n" +
  "  NON_CLAIMS,\n" +
  "  PROTECTED_RECORDS_ADAPTER_TYPE,\n" +
  "  PROTECTED_RECORDS_CONSUMED_STORE_TYPE,\n" +
  "  PROTECTED_RECORDS_WRITE_RESULT_TYPE,\n" +
  "  SAFE_CLAIM_CEILING,\n" +
  "  assertNoUnsafeProtectedRecordsAdapterText,\n" +
  "  assertProtectedRecordsWriteResult,\n" +
  "} from './protected-records-adapter-verification.mjs';\n\n" +
  "export const PROTECTED_RECORDS_ADAPTER_RETIREMENT_REASON =\n" +
  "  'e1_direct_adapter_factory_source_retired';\n\n" +
  "export function applyProtectedRecordsWrite() {\n" +
  "  throw new Error(PROTECTED_RECORDS_ADAPTER_RETIREMENT_REASON);\n" +
  "}\n";
equal('retired adapter module exact source', expectedAdapterSource, adapterSource);
assert('retired adapter module has no imports', !/^import\s/m.test(adapterSource));
for (const forbidden of [
  'node:fs',
  'canonicalize',
  'evaluateDownstreamRecognition',
  'sha256hex',
  'writeFileSync',
  'readFileSync',
  'receipt_ids',
  'ledger_path',
  "flag: 'a'",
  'arguments',
]) {
  assert(`retired adapter excludes ${forbidden}`, !adapterSource.includes(forbidden));
}
assert('verification module has no imports', !/^import\s/m.test(verificationSource));
assert('verification module exports no positive factory', !verificationSource.includes('applyProtectedRecordsWrite'));
for (const forbidden of ['node:fs', 'writeFileSync', 'evaluateDownstreamRecognition', "flag: 'a'"]) {
  assert(`verification module excludes ${forbidden}`, !verificationSource.includes(forbidden));
}
equal(
  'standalone wrapper exact fixed refusal',
  `#!/usr/bin/env node\n\nconsole.error('ERROR: ${RETIREMENT_REASON}');\nprocess.exit(1);\n`,
  wrapperSource,
);
assert('standalone wrapper has no import', !/^import\s/m.test(wrapperSource));
assert('standalone wrapper has no argv read', !wrapperSource.includes('process.argv'));
assert('standalone wrapper has no stdin or JSON handling', !/stdin|readFile|JSON\./.test(wrapperSource));
assert('main help removes direct E1 command', !mainSource.includes('    protected-records-write\\n'));
assert('main dispatcher removes direct E1 command', !mainSource.includes('protected-records-write)'));

const positiveAdapterImportPattern =
  /(?:from\s*|import\s*\()\s*['"][^'"]*\/protected-records-adapter\.mjs['"]/;
const liveImporters = [...collectFiles('lib'), ...collectFiles('bin')]
  .filter((path) => positiveAdapterImportPattern.test(read(path)))
  .sort();
deepEqual('no live lib/bin importer of retired positive adapter module', [], liveImporters);

section('future installer source exclusion');
for (const marker of [
  'zlar-protected-records-write) return 0',
  'protected-records-adapter.mjs) return 0',
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
equal('installed files were not inspected', false, spec.future_install_copy_disposition.existing_installed_files_inspected);
equal('installed files were not deleted', false, spec.future_install_copy_disposition.existing_installed_files_deleted);
equal('installed-copy retirement unproven', false, spec.future_install_copy_disposition.installed_copy_retirement_proven);

section('input-independent library and wrapper refusals');
const [adapterModule, verificationModule, terminalModule, conformanceModule] = await Promise.all([
  import('../lib/protected-records-adapter.mjs'),
  import('../lib/protected-records-adapter-verification.mjs'),
  import('../lib/protected-records-terminal-proof.mjs'),
  import('../lib/protected-records-adapter-conformance.mjs'),
]);
equal('adapter retirement reason exact', RETIREMENT_REASON, adapterModule.PROTECTED_RECORDS_ADAPTER_RETIREMENT_REASON);
equal('adapter factory metadata length zero', 0, adapterModule.applyProtectedRecordsWrite.length);
const hostileInput = hostileProxy();
const hostileOptions = hostileProxy();
assertThrowsExact(
  'adapter factory refuses exact',
  () => adapterModule.applyProtectedRecordsWrite(hostileInput.proxy, hostileOptions.proxy),
  RETIREMENT_REASON,
);
equal('adapter factory reads no hostile input', 0, hostileInput.reads());
equal('adapter factory reads no hostile options', 0, hostileOptions.reads());
equal('historical result validator remains exported', 'function', typeof verificationModule.assertProtectedRecordsWriteResult);
equal('historical privacy guard remains exported', 'function', typeof verificationModule.assertNoUnsafeProtectedRecordsAdapterText);
equal('verification module exposes no factory', undefined, verificationModule.applyProtectedRecordsWrite);
equal('Stage 4 terminal export remains fixed', TERMINAL_REASON, terminalModule.PROTECTED_RECORDS_TERMINAL_PROOF_GENERATION_RETIREMENT_REASON);
equal('Stage 4 conformance export remains fixed', CONFORMANCE_REASON, conformanceModule.PROTECTED_RECORDS_ADAPTER_CONFORMANCE_GENERATION_RETIREMENT_REASON);

const prohibitedOutput = join(tmpdir(), `zlar-retired-direct-e1-${process.pid}.json`);
equal('prohibited output precondition absent', false, existsSync(prohibitedOutput));
for (const args of [
  [],
  ['--help'],
  ['--input', '/nonexistent/e1.json'],
  ['--input', '-', '--require-refused'],
  ['--artifact', prohibitedOutput, '--require-written'],
]) {
  const result = runWrapper('bin/zlar-protected-records-write', args, '{"hostile":true}\n');
  equal(`wrapper exits one: ${args.join(' ')}`, 1, result.status);
  equal(`wrapper stdout empty: ${args.join(' ')}`, '', result.stdout);
  equal(`wrapper stderr exact: ${args.join(' ')}`, `ERROR: ${RETIREMENT_REASON}\n`, result.stderr);
}
equal('retired wrapper creates no prohibited output', false, existsSync(prohibitedOutput));
assert('retired wrapper remains executable', (statSync(join(ROOT, 'bin/zlar-protected-records-write')).mode & 0o111) !== 0);

section('exact historical verification and tamper refusal');
const localVerificationRun = runWrapper('bin/zlar-local-proof-pack', [
  'verify',
  '--sample',
  '--require-sha',
  LOCAL_PROOF_PACK_BODY_SHA,
  '--json',
]);
equal('local historical verification exits zero', 0, localVerificationRun.status);
equal('local historical verification stderr empty', '', localVerificationRun.stderr);
const localVerification = JSON.parse(localVerificationRun.stdout);
equal('local historical verification true', true, localVerification.verified);
equal('local historical body SHA exact', LOCAL_PROOF_PACK_BODY_SHA, localVerification.body_sha256);
equal('local historical fresh generation false', false, localVerification.fresh_proof_pack_run_performed);

const proofSmokeRun = runMain([
  'proof-smoke',
  'verify',
  '--historical',
  '--sample',
  '--require-file-sha',
  PROOF_SMOKE_FILE_SHA,
  '--require-sha',
  PROOF_SMOKE_REPORT_SHA,
  '--json',
]);
equal('proof-smoke historical verification exits zero', 0, proofSmokeRun.status);
equal('proof-smoke historical verification stderr empty', '', proofSmokeRun.stderr);
const proofSmokeVerification = JSON.parse(proofSmokeRun.stdout);
equal('proof-smoke file SHA exact', PROOF_SMOKE_FILE_SHA, proofSmokeVerification.file_sha256);
equal('proof-smoke report SHA exact', PROOF_SMOKE_REPORT_SHA, proofSmokeVerification.report_sha256);
equal('proof-smoke historical only exact', true, proofSmokeVerification.historical_only);

const localArtifact = JSON.parse(read('tests/fixtures/local-proof-pack-artifact-v1.json'));
equal(
  'local artifact file SHA immutable',
  spec.historical_verification.local_proof_pack.file_sha256,
  fileSha(spec.historical_verification.local_proof_pack.file_path),
);
const manifest = new Map(
  localArtifact.component_manifest.map((item) => [item.component, item.component_sha256]),
);
equal(
  'terminal component identity exact',
  spec.historical_verification.local_proof_pack.terminal_component_sha256,
  manifest.get('protected_records_terminal'),
);
equal(
  'conformance component identity exact',
  spec.historical_verification.local_proof_pack.adapter_conformance_component_sha256,
  manifest.get('protected_records_adapter_conformance'),
);
const tampered = structuredClone(localArtifact);
tampered.payload.live_probing = true;
const tamperRun = runWrapper(
  'bin/zlar-local-proof-pack',
  ['verify', '--input', '-', '--require-sha', LOCAL_PROOF_PACK_BODY_SHA, '--json'],
  `${JSON.stringify(tampered)}\n`,
);
equal('tampered local artifact refuses', 1, tamperRun.status);
equal('tampered local artifact emits no success output', '', tamperRun.stdout);

section('test routing and current consumer disposition');
deepEqual(
  'retired direct E1 suites exact',
  ['test-protected-records-adapter.mjs', 'test-protected-records-write-cli.mjs'],
  read('tests/retired-direct-e1-test-suites.txt').trim().split('\n'),
);
equal(
  'contradictory current-positive E1 inventory removed',
  false,
  existsSync(join(ROOT, 'tests/current-positive-e1-direct-test-suites.txt')),
);
const superseded = read('tests/superseded-source-bound-test-suites.txt').trim().split('\n');
assert('Stage 4 live-tree suite routed historical', superseded.includes('test-e1-positive-proof-generator-retirement-v0.mjs'));
assert('current direct E1 suite remains active', !superseded.includes('test-e1-direct-adapter-factory-source-retirement-v0.mjs'));
equal('eight generator suites remain retired', 8, spec.test_routing.retired_positive_generator_suite_count);
equal('three direct E2 suites remain retired', 3, spec.test_routing.retired_direct_e2_suite_count);
equal('two direct E1 suites retired', 2, spec.test_routing.retired_direct_e1_suite_count);
equal('broad harness was not executed', false, spec.test_routing.broad_harness_executed);
const harnessSource = read('tests/count-assertions.sh');
assert('harness loads retired direct E1 inventory', harnessSource.includes('RETIRED_DIRECT_E1_TEST_SUITES='));
assert('harness exact-matches retired direct E1 basenames', harnessSource.includes('grep -Fqx "${base}" "${RETIRED_DIRECT_E1_TEST_SUITES}"'));
assert('harness names retired direct E1 skip reason', harnessSource.includes('(retired direct E1 suite)'));

section('E4 preservation, docs, topology, lifecycle, and claim ceiling');
for (const item of [
  [spec.unchanged_e4_boundary.driver_path, spec.unchanged_e4_boundary.driver_file_sha256],
  [spec.unchanged_e4_boundary.child_path, spec.unchanged_e4_boundary.child_file_sha256],
]) {
  equal(`${item[0]} unchanged E4 SHA`, item[1], fileSha(item[0]));
}
for (const [path, tokens] of [
  ['docs/technical-reference.md', [RETIREMENT_REASON, 'main dispatcher no longer routes', 'runtime unreachability']],
  ['docs/cli-reference.md', [RETIREMENT_REASON, 'retired current-source surface', 'Existing installed']],
  ['docs/governed-surface-coverage-map.md', [RETIREMENT_REASON, 'does not establish', 'E4']],
  ['docs/trusted-receipt-issuer.md', ['direct factory remain historical', 'current source surfaces fixed-refuse']],
]) {
  const source = read(path);
  for (const token of tokens) assert(`${path} names ${token}`, source.includes(token));
}

equal('North Star 1 remains historical', 'historical', spec.north_star_1_status);
equal('North Star 2 remains mapped open', 'mapped_open', spec.north_star_2_status);
equal('named current-source positive E1 route absent', false, spec.effect_node_topology_refresh.named_static_current_source_positive_e1_route_found_after);
equal('E1 elimination remains false', false, spec.effect_node_topology_refresh.e1_effect_node_eliminated);
equal('runtime reachability remains unproven', false, spec.reachability_delta_refresh.runtime_reachability_proven);
equal('equivalent-route closure remains unproven', false, spec.reachability_delta_refresh.equivalent_route_closure_proven);
equal('lifecycle remains mapped open', 'mapped_open', spec.lifecycle_refresh.map_status_after);
deepEqual('no lifecycle obligation status changed', [], spec.lifecycle_refresh.lifecycle_obligation_status_changes);
equal('coverage disposition unchanged', false, spec.lifecycle_refresh.coverage_disposition_changed);
for (const [claim, value] of Object.entries(spec.claim_boundary)) {
  if ([
    'exact_checked_out_source_direct_e1_adapter_factory_retirement',
    'future_installer_source_copy_exclusion',
    'exact_historical_verification_preserved',
  ].includes(claim)) {
    equal(`${claim} exact true`, true, value);
  } else {
    equal(`${claim} remains false`, false, value);
  }
}
for (const sideDoor of [
  'old-installed-copied-historical-or-mutated-positive-source',
  'stale-installed-wrapper-or-module-across-upgrade-or-reinstall',
  'already-loaded-positive-function-object',
  'selected-positive-e4-replacement-route',
  'raw-filesystem-writes',
  'NODE_OPTIONS-loaders-preloads-and-interpreter-substitution',
  'PATH-selected-or-alternate-interpreters',
  'dynamic-generated-external-or-non-node-entrypoints',
]) {
  assert(`side door remains visible: ${sideDoor}`, spec.side_doors.includes(sideDoor));
}

process.stdout.write(
  `\nResults: ${assertions}/${assertions} passed — E1 direct adapter/factory source retirement v0\n`,
);
