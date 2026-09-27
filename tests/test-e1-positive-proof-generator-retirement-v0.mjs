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
const SPEC_PATH = join(ROOT, 'spec/e1-positive-proof-generator-retirement-v0.json');
const BASELINE_COMMIT = 'e66748f5047ecb86e45a17f93cba861b50c962fd';
const EXPECTED_SPEC_BODY_SHA =
  '87e6918de9e5fe18ba1cffd5cb602fff30bba27680bfe682e17f801350ddc0d2';
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
    env: { NO_COLOR: '1', PATH: `${NODE_BIN_DIR}:/usr/bin:/bin` },
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

function extractDirectFactory(source) {
  const match = source.match(/export function applyProtectedRecordsWrite\([\s\S]*?\n}\n/);
  assert('direct E1 factory body is statically extractable', Boolean(match));
  return match[0];
}

const spec = JSON.parse(readFileSync(SPEC_PATH, 'utf8'));
const { integrity, ...body } = spec;

section('overlay and exact current source inventory');
equal(
  'artifact type exact',
  'zlar.e1-positive-proof-generator-retirement.v0',
  spec.artifact_type,
);
equal('schema version exact', 0, spec.schema_version);
equal(
  'decision exact',
  'retire_positive_e1_terminal_and_conformance_generation_preserve_pinned_historical_verification',
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

section('Stage 3 exact-source history remains independently pinned');
equal(
  'Stage 3 overlay file SHA unchanged',
  spec.historical_verification.stage_3_overlay.file_sha256,
  fileSha(spec.historical_verification.stage_3_overlay.file_path),
);
const stage3 = JSON.parse(read(spec.historical_verification.stage_3_overlay.file_path));
equal(
  'Stage 3 overlay body identity exact',
  spec.historical_verification.stage_3_overlay.body_sha256,
  stage3.integrity.body_sha256,
);
for (const item of stage3.source_inventory) {
  equal(
    `Stage 3 source identity at baseline: ${item.path}`,
    item.file_sha256,
    sha(gitShow(BASELINE_COMMIT, item.path)),
  );
}

section('positive generator machinery removed before execution');
const terminalSource = read('lib/protected-records-terminal-proof.mjs');
const conformanceSource = read('lib/protected-records-adapter-conformance.mjs');
const adapterSource = read('lib/protected-records-adapter.mjs');
const adapterVerificationSource = read('lib/protected-records-adapter-verification.mjs');
const terminalWrapperSource = read('bin/zlar-protected-records-proof');
const conformanceWrapperSource = read('bin/zlar-protected-records-adapter-conformance');
const localProofPackSource = read('lib/local-proof-pack.mjs');
const mainSource = read('bin/zlar');

assert(
  'terminal export is exact zero-parameter fixed refusal',
  terminalSource.includes(
    'export function runProtectedRecordsTerminalProof() {\n' +
      '  throw new Error(PROTECTED_RECORDS_TERMINAL_PROOF_GENERATION_RETIREMENT_REASON);\n' +
      '}',
  ),
);
assert(
  'conformance export is exact zero-parameter fixed refusal',
  conformanceSource.includes(
    'export function runProtectedRecordsAdapterConformanceProof() {\n' +
      '  throw new Error(\n' +
      '    PROTECTED_RECORDS_ADAPTER_CONFORMANCE_GENERATION_RETIREMENT_REASON,\n' +
      '  );\n' +
      '}',
  ),
);
for (const [label, source] of [
  ['terminal generator', terminalSource],
  ['adapter conformance generator', conformanceSource],
]) {
  for (const forbidden of [
    'generateKeyPairSync',
    'signReceiptV1',
    'createReceiptV1FromEvent',
    'mkdtempSync',
    'writeFileSync',
    'spawnSync',
    'applyProtectedRecordsWrite',
    "from './protected-records-adapter.mjs'",
  ]) {
    assert(`${label} excludes ${forbidden}`, !source.includes(forbidden));
  }
  assert(
    `${label} imports only inert adapter verification dependency`,
    source.includes("from './protected-records-adapter-verification.mjs';"),
  );
}
assert('adapter verification module has no imports', !/^import\s/m.test(adapterVerificationSource));
assert(
  'adapter verification module exposes no positive factory',
  !adapterVerificationSource.includes('applyProtectedRecordsWrite'),
);
for (const forbidden of [
  'node:fs',
  'canonicalize',
  'evaluateDownstreamRecognition',
  'writeFileSync',
  "flag: 'a'",
]) {
  assert(`adapter verification module excludes ${forbidden}`, !adapterVerificationSource.includes(forbidden));
}
assert(
  'positive adapter imports inert verification constants',
  adapterSource.includes("from './protected-records-adapter-verification.mjs';"),
);
assert(
  'positive adapter reexports inert validators',
  adapterSource.includes('assertProtectedRecordsWriteResult,') &&
    adapterSource.includes('assertNoUnsafeProtectedRecordsAdapterText,'),
);
assert('local proof pack retains terminal validator', localProofPackSource.includes('assertProtectedRecordsTerminalProof'));
assert('local proof pack retains conformance validator', localProofPackSource.includes('assertProtectedRecordsAdapterConformanceProof'));
assert('local proof pack removes terminal runner import/call', !localProofPackSource.includes('runProtectedRecordsTerminalProof'));
assert('local proof pack removes conformance runner import/call', !localProofPackSource.includes('runProtectedRecordsAdapterConformanceProof'));

equal(
  'terminal wrapper exact input-independent refusal',
  `#!/usr/bin/env node\n\nconsole.error('ERROR: ${TERMINAL_REASON}');\nprocess.exit(1);\n`,
  terminalWrapperSource,
);
equal(
  'conformance wrapper exact input-independent refusal',
  `#!/usr/bin/env node\n\nconsole.error('ERROR: ${CONFORMANCE_REASON}');\nprocess.exit(1);\n`,
  conformanceWrapperSource,
);
for (const [label, source] of [
  ['terminal wrapper', terminalWrapperSource],
  ['conformance wrapper', conformanceWrapperSource],
]) {
  assert(`${label} has no import`, !/^import\s/m.test(source));
  assert(`${label} has no argv read`, !source.includes('process.argv'));
  assert(`${label} has no stdin or JSON handling`, !/stdin|readFile|JSON\./.test(source));
}
for (const [command, wrapper] of [
  ['protected-records-proof', 'bin/zlar-protected-records-proof'],
  ['protected-records-adapter-conformance', 'bin/zlar-protected-records-adapter-conformance'],
]) {
  assert(
    `main dispatcher retains ${command} only through fixed wrapper`,
    mainSource.includes(
      `${command}) ZLAR_PROJECT_DIR="\${PROJECT_DIR}" node "\${PROJECT_DIR}/${wrapper}" "$@" ;;`,
    ),
  );
}
assert(
  'main help names terminal generation retirement',
  mainSource.includes('Refuse permanently retired fresh E1 terminal-proof generation'),
);
assert(
  'main source inventory names terminal generation retirement',
  mainSource.includes('— refuse retired fresh E1 terminal-proof generation'),
);
assert(
  'main source inventory removes stale terminal run claim',
  !mainSource.includes('— run hermetic protected records terminal proof'),
);
assert(
  'main help names conformance generation retirement',
  mainSource.includes('Refuse permanently retired fresh E1 adapter-conformance generation'),
);

const positiveAdapterImportPattern =
  /(?:from\s*|import\s*\()\s*['"][^'"]*\/protected-records-adapter\.mjs['"]/;
const liveImporters = [...collectFiles('lib'), ...collectFiles('bin')]
  .filter((path) => positiveAdapterImportPattern.test(read(path)))
  .sort();
deepEqual(
  'only direct E1 wrapper imports the positive adapter module in live lib/bin source',
  ['bin/zlar-protected-records-write'],
  liveImporters,
);

section('input-independent library and CLI refusals');
const [terminalModule, conformanceModule, adapterVerificationModule] = await Promise.all([
  import('../lib/protected-records-terminal-proof.mjs'),
  import('../lib/protected-records-adapter-conformance.mjs'),
  import('../lib/protected-records-adapter-verification.mjs'),
]);
equal(
  'terminal reason export exact',
  TERMINAL_REASON,
  terminalModule.PROTECTED_RECORDS_TERMINAL_PROOF_GENERATION_RETIREMENT_REASON,
);
equal(
  'conformance reason export exact',
  CONFORMANCE_REASON,
  conformanceModule.PROTECTED_RECORDS_ADAPTER_CONFORMANCE_GENERATION_RETIREMENT_REASON,
);
for (const [label, fn, reason] of [
  ['terminal export', terminalModule.runProtectedRecordsTerminalProof, TERMINAL_REASON],
  ['conformance export', conformanceModule.runProtectedRecordsAdapterConformanceProof, CONFORMANCE_REASON],
]) {
  equal(`${label} metadata length zero`, 0, fn.length);
  const hostileInput = hostileProxy();
  const hostileOptions = hostileProxy();
  assertThrowsExact(
    `${label} refuses exact`,
    () => fn(hostileInput.proxy, hostileOptions.proxy),
    reason,
  );
  equal(`${label} reads no hostile input`, 0, hostileInput.reads());
  equal(`${label} reads no hostile options`, 0, hostileOptions.reads());
}
equal(
  'historical write-result validator remains exported',
  'function',
  typeof adapterVerificationModule.assertProtectedRecordsWriteResult,
);
equal(
  'historical adapter privacy guard remains exported',
  'function',
  typeof adapterVerificationModule.assertNoUnsafeProtectedRecordsAdapterText,
);
equal(
  'verification module exports no positive factory',
  undefined,
  adapterVerificationModule.applyProtectedRecordsWrite,
);

const prohibitedOutput = join(tmpdir(), `zlar-retired-e1-generator-${process.pid}.json`);
equal('prohibited output precondition absent', false, existsSync(prohibitedOutput));
for (const [label, wrapper, reason] of [
  ['terminal CLI', 'bin/zlar-protected-records-proof', TERMINAL_REASON],
  ['conformance CLI', 'bin/zlar-protected-records-adapter-conformance', CONFORMANCE_REASON],
]) {
  for (const args of [
    [],
    ['--help'],
    ['--json'],
    ['--input', '/nonexistent/e1.json', '--artifact', prohibitedOutput],
  ]) {
    const result = runWrapper(wrapper, args, '{"hostile":true}\n');
    equal(`${label} exits one: ${args.join(' ')}`, 1, result.status);
    equal(`${label} stdout empty: ${args.join(' ')}`, '', result.stdout);
    equal(`${label} stderr exact: ${args.join(' ')}`, `ERROR: ${reason}\n`, result.stderr);
  }
  assert(`${label} wrapper remains executable`, (statSync(join(ROOT, wrapper)).mode & 0o111) !== 0);
}
equal('retired wrappers create no prohibited output', false, existsSync(prohibitedOutput));

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
equal('proof-smoke historical mode exact', true, proofSmokeVerification.historical_only);

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

section('test routing and open direct E1 boundary');
deepEqual(
  'retired positive generator inventory exact',
  [
    'test-protected-records-adapter-conformance-cli.mjs',
    'test-protected-records-adapter-conformance.mjs',
    'test-protected-records-proof-cli.mjs',
    'test-protected-records-service-preflight-cli.mjs',
    'test-protected-records-service-profile.mjs',
    'test-protected-records-service-proof-cli.mjs',
    'test-protected-records-service-proof.mjs',
    'test-protected-records-terminal-proof.mjs',
  ],
  read('tests/retired-positive-generator-test-suites.txt').trim().split('\n'),
);
deepEqual(
  'current positive direct E1 inventory exact',
  [
    'test-protected-records-adapter.mjs',
    'test-protected-records-write-cli.mjs',
  ],
  read('tests/current-positive-e1-direct-test-suites.txt').trim().split('\n'),
);
const harnessSource = read('tests/count-assertions.sh');
assert('harness loads current positive E1 inventory', harnessSource.includes('CURRENT_POSITIVE_E1_DIRECT_TEST_SUITES='));
assert('harness exact-matches current positive E1 basenames', harnessSource.includes('grep -Fqx "${base}" "${CURRENT_POSITIVE_E1_DIRECT_TEST_SUITES}"'));
assert('harness names open direct E1 skip reason', harnessSource.includes('(current positive direct E1 suite)'));
const superseded = read('tests/superseded-source-bound-test-suites.txt').trim().split('\n');
assert('Stage 3 live-tree suite routed historical', superseded.includes('test-e2-direct-request-factory-source-retirement-v0.mjs'));
assert('current E1 suite remains active', !superseded.includes('test-e1-positive-proof-generator-retirement-v0.mjs'));
equal('eight generator suites routed retired', 8, spec.test_routing.retired_positive_generator_suite_count);
equal('four E1 generator suites routed retired', 4, spec.test_routing.retired_e1_generator_suite_count);
equal('two direct E1 suites remain current positive', 2, spec.test_routing.current_positive_direct_e1_suite_count);
equal('broad harness was not executed', false, spec.test_routing.broad_harness_executed);

const priorAdapterSource = gitShow(BASELINE_COMMIT, 'lib/protected-records-adapter.mjs').toString();
const currentFactory = extractDirectFactory(adapterSource);
const priorFactory = extractDirectFactory(priorAdapterSource);
equal('direct E1 positive factory body unchanged', priorFactory, currentFactory);
equal(
  'direct E1 positive factory slice SHA exact',
  spec.unchanged_direct_e1_boundary.positive_factory_body_sha256,
  sha(currentFactory),
);
equal(
  'direct E1 wrapper unchanged',
  spec.unchanged_direct_e1_boundary.standalone_wrapper_sha256,
  fileSha(spec.unchanged_direct_e1_boundary.standalone_wrapper_path),
);
equal(
  'installer unchanged',
  spec.unchanged_direct_e1_boundary.future_installer_sha256,
  fileSha(spec.unchanged_direct_e1_boundary.future_installer_path),
);
equal('direct factory retirement remains false', false, spec.unchanged_direct_e1_boundary.direct_factory_retired);
equal('direct CLI retirement remains false', false, spec.unchanged_direct_e1_boundary.direct_cli_retired);
equal('future install copy exclusion remains false', false, spec.unchanged_direct_e1_boundary.future_install_copy_excluded);
for (const item of [
  [spec.unchanged_e4_boundary.driver_path, spec.unchanged_e4_boundary.driver_file_sha256],
  [spec.unchanged_e4_boundary.child_path, spec.unchanged_e4_boundary.child_file_sha256],
]) {
  equal(`${item[0]} unchanged E4 SHA`, item[1], fileSha(item[0]));
}

section('topology, lifecycle, docs, and claim ceiling');
equal('North Star 1 remains historical', 'historical', spec.north_star_1_status);
equal('North Star 2 remains mapped open', 'mapped_open', spec.north_star_2_status);
equal('two positive generator routes found before', 2, spec.effect_node_topology_refresh.named_positive_e1_generator_routes_found_before);
equal('zero positive generator routes found after', 0, spec.effect_node_topology_refresh.named_positive_e1_generator_routes_found_after);
equal('direct E1 route remains positive', true, spec.effect_node_topology_refresh.named_static_current_source_positive_direct_e1_route_found_after);
equal('E1 elimination remains false', false, spec.effect_node_topology_refresh.e1_effect_node_eliminated);
equal('lifecycle remains mapped open', 'mapped_open', spec.lifecycle_refresh.map_status_after);
deepEqual('no lifecycle obligation status changed', [], spec.lifecycle_refresh.lifecycle_obligation_status_changes);
equal('coverage disposition unchanged', false, spec.lifecycle_refresh.coverage_disposition_changed);

for (const [path, tokens] of [
  ['docs/technical-reference.md', [TERMINAL_REASON, CONFORMANCE_REASON, 'not E1 retirement']],
  ['docs/cli-reference.md', [TERMINAL_REASON, CONFORMANCE_REASON, 'direct adapter remains positive']],
  ['docs/governed-surface-coverage-map.md', [TERMINAL_REASON, CONFORMANCE_REASON, 'does not establish E1 retirement']],
  ['docs/trusted-receipt-issuer.md', ['Fresh `zlar protected-records-adapter-conformance`', 'historical evidence only']],
]) {
  const source = read(path);
  for (const token of tokens) assert(`${path} names ${token}`, source.includes(token));
}

for (const [claim, value] of Object.entries(spec.claim_boundary)) {
  if ([
    'exact_checked_out_source_e1_generator_retirement',
    'historical_verification_decoupled_from_positive_adapter_module',
    'exact_historical_verification_preserved',
  ].includes(claim)) {
    equal(`${claim} exact true`, true, value);
  } else {
    equal(`${claim} remains false`, false, value);
  }
}
for (const sideDoor of [
  'current-positive-direct-e1-adapter-cli',
  'current-positive-exported-e1-factory',
  'future-installer-copy-of-direct-e1-surfaces',
  'selected-positive-e4-replacement-route',
  'old-installed-copied-historical-or-mutated-positive-source',
  'already-loaded-positive-function-object',
  'raw-filesystem-writes',
  'NODE_OPTIONS-loaders-preloads-and-interpreter-substitution',
  'dynamic-generated-external-or-non-node-entrypoints',
]) {
  assert(`side door remains visible: ${sideDoor}`, spec.side_doors.includes(sideDoor));
}

process.stdout.write(
  `\nResults: ${assertions}/${assertions} passed — E1 positive proof-generator retirement v0\n`,
);
