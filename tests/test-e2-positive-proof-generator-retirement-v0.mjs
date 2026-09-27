#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC_PATH = join(ROOT, 'spec/e2-positive-proof-generator-retirement-v0.json');
const EXPECTED_SPEC_BODY_SHA = '5e40dccf5aa6989c9d9941a0eb61227c041cf4375f09ece6018a764eb9d101c4';
const LOCAL_PROOF_PACK_BODY_SHA =
  '777f66be5c4c5d9dcf5c5555c4e80653231815db22a82adf056c0908cf890ac0';
const SERVICE_PREFLIGHT_BODY_SHA =
  '36a3aadfa920ea3da2ac3199b5af79f937e783e42604bfa3318d6ac8824b190c';
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

function assertThrows(label, fn, expectedMessage) {
  assertions += 1;
  try {
    fn();
  } catch (err) {
    if (err instanceof Error && err.message === expectedMessage) return;
    throw new Error(
      `FAIL: ${label}: expected ${expectedMessage}, got ${err?.message || String(err)}`,
    );
  }
  throw new Error(`FAIL: ${label}: expected throw`);
}

function runWrapper(relativePath, args, input) {
  return spawnSync(process.execPath, [join(ROOT, relativePath), ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    input,
    env: {
      NO_COLOR: '1',
      PATH: '/usr/bin:/bin',
    },
  });
}

function hostileProxy() {
  let reads = 0;
  const proxy = new Proxy({}, {
    get() {
      reads += 1;
      throw new Error('hostile input read');
    },
    ownKeys() {
      reads += 1;
      throw new Error('hostile input keys read');
    },
    getOwnPropertyDescriptor() {
      reads += 1;
      throw new Error('hostile input descriptor read');
    },
  });
  return { proxy, reads: () => reads };
}

function section(label) {
  process.stdout.write(`\n## ${label}\n`);
}

const spec = JSON.parse(readFileSync(SPEC_PATH, 'utf8'));
const { integrity, ...body } = spec;

section('artifact and exact source inventory');
equal(
  'artifact type',
  'zlar.e2-positive-proof-generator-retirement.v0',
  spec.artifact_type,
);
equal('schema version', 0, spec.schema_version);
equal(
  'decision',
  'retire_positive_e2_generation_preserve_pinned_historical_verification',
  spec.decision,
);
equal('baseline commit', 'f369b6779dff1f1cb339ffb6e58f0a0f67f0832b', spec.source_checkpoint.baseline_commit_oid);
equal('runtime observation absent', false, spec.source_checkpoint.runtime_observation_performed);
equal('positive E2 execution absent', false, spec.source_checkpoint.positive_e2_execution_performed);
equal('integrity algorithm', 'SHA-256', integrity.algorithm);
equal('integrity scope', 'canonical artifact body without integrity', integrity.scope);
equal('spec body SHA pin', EXPECTED_SPEC_BODY_SHA, integrity.body_sha256);
equal('spec body SHA validates', EXPECTED_SPEC_BODY_SHA, sha(canonicalize(body)));
equal('source inventory paths unique', spec.source_inventory.length, new Set(spec.source_inventory.map((item) => item.path)).size);
for (const item of spec.source_inventory) {
  equal(`${item.path} exact source SHA`, item.file_sha256, fileSha(item.path));
}
equal(
  'canonical E2 identity',
  'E2.service-jsonl-state-append-v1',
  spec.effect_node_id,
);

section('static refusal precondition before module or CLI execution');
const serviceProofSource = read('lib/protected-records-service-proof.mjs');
const serviceProfileSource = read('lib/protected-records-service-profile.mjs');
const localProofPackSource = read('lib/local-proof-pack.mjs');
const productProofSource = read('lib/product-proof-path.mjs');
const readinessSource = read('lib/north-star-readiness.mjs');
const readinessCliSource = read('bin/zlar-north-star-readiness');
const mainCliSource = read('bin/zlar');
const serviceProofCliSource = read('bin/zlar-protected-records-service-proof');
const servicePreflightCliSource = read('bin/zlar-protected-records-service-preflight');
const localProofPackCliSource = read('bin/zlar-local-proof-pack');
const productProofCliSource = read('bin/zlar-product-proof-path');

for (const token of [
  'generateKeyPairSync',
  'signReceiptV1',
  'spawnSync',
  'mkdtempSync',
]) {
  assert(`service proof removes ${token}`, !serviceProofSource.includes(token));
  assert(`service preflight removes ${token}`, !serviceProfileSource.includes(token));
}
assert(
  'service proof export is exact zero-parameter fixed refusal',
  serviceProofSource.includes(
    "export function runProtectedRecordsServiceProof() {\n  throw new Error(PROTECTED_RECORDS_SERVICE_PROOF_GENERATION_RETIREMENT_REASON);\n}",
  ),
);
assert(
  'service preflight export is exact zero-parameter fixed refusal',
  serviceProfileSource.includes(
    "export function runProtectedRecordsServiceProfilePreflight() {\n  throw new Error(\n    PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_GENERATION_RETIREMENT_REASON,\n  );\n}",
  ),
);
assert(
  'local proof-pack export is exact zero-parameter fixed refusal',
  localProofPackSource.includes(
    "export function runLocalProofPack() {\n  throw new Error(LOCAL_PROOF_PACK_GENERATION_RETIREMENT_REASON);\n}",
  ),
);
assert(
  'local proof-pack no-argument artifact fallback has exact refusal',
  localProofPackSource.includes(
    "if (report === undefined) {\n    throw new Error('local_proof_pack_default_artifact_generation_retired');\n  }",
  ),
);
assert(
  'product proof builder is exact zero-parameter fixed refusal',
  productProofSource.includes(
    "export function buildProductProofPathReport() {\n  throw new Error(PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON);\n}",
  ),
);
assert(
  'product proof runner is exact zero-parameter fixed refusal',
  productProofSource.includes(
    "export function runProductProofPath() {\n  throw new Error(PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON);\n}",
  ),
);
assert(
  'service preflight no-report artifact fallback has exact refusal',
  serviceProfileSource.includes(
    "if (report === undefined) {\n    throw new Error(\n      'e2_positive_service_preflight_default_artifact_generation_retired',\n    );\n  }",
  ),
);
assert(
  'service-proof wrapper has no positive module import',
  !serviceProofCliSource.includes("from '../lib/"),
);
assert(
  'service-preflight wrapper has no generator import',
  !servicePreflightCliSource.includes('runProtectedRecordsServiceProfilePreflight'),
);
assert(
  'local proof-pack wrapper has no generator import',
  !localProofPackCliSource.includes('runLocalProofPack') &&
    !localProofPackCliSource.includes('buildLocalProofPackArtifact'),
);
assert(
  'product proof wrapper has no module import',
  !productProofCliSource.includes("from '../lib/"),
);
for (const [command, wrapper] of [
  ['protected-records-service-proof', 'bin/zlar-protected-records-service-proof'],
  ['protected-records-service-preflight', 'bin/zlar-protected-records-service-preflight'],
  ['local-proof-pack', 'bin/zlar-local-proof-pack'],
  ['product-proof-path', 'bin/zlar-product-proof-path'],
]) {
  assert(
    `main dispatcher maps ${command} to exact wrapper`,
    mainCliSource.includes(
      `${command}) ZLAR_PROJECT_DIR="\${PROJECT_DIR}" node "\${PROJECT_DIR}/${wrapper}" "$@" ;;`,
    ),
  );
}
assert(
  'local proof pack removes service-proof generator import/call',
  !localProofPackSource.includes('runProtectedRecordsServiceProof'),
);
assert(
  'local proof pack removes service-preflight generator import/call',
  !localProofPackSource.includes('runProtectedRecordsServiceProfilePreflight'),
);
assert(
  'product proof removes local proof-pack run import/call',
  !productProofSource.includes('runLocalProofPack'),
);
assert(
  'product proof removes local proof-pack artifact generation import/call',
  !productProofSource.includes('buildLocalProofPackArtifact'),
);
assert(
  'readiness removes product proof run import/call',
  !readinessSource.includes('runProductProofPath'),
);
assert(
  'readiness sample removes product proof CLI execution',
  !readinessCliSource.includes("runZlarJson(['product-proof-path'"),
);

const [
  serviceProofModule,
  serviceProfileModule,
  localProofPackModule,
  productProofModule,
] = await Promise.all([
  import('../lib/protected-records-service-proof.mjs'),
  import('../lib/protected-records-service-profile.mjs'),
  import('../lib/local-proof-pack.mjs'),
  import('../lib/product-proof-path.mjs'),
]);
const {
  PROTECTED_RECORDS_SERVICE_PROOF_GENERATION_RETIREMENT_REASON,
  runProtectedRecordsServiceProof,
} = serviceProofModule;
const {
  PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_GENERATION_RETIREMENT_REASON,
  buildProtectedRecordsServiceProfilePreflightArtifact,
  runProtectedRecordsServiceProfilePreflight,
} = serviceProfileModule;
const {
  LOCAL_PROOF_PACK_GENERATION_RETIREMENT_REASON,
  buildLocalProofPackArtifact,
  runLocalProofPack,
} = localProofPackModule;
const {
  PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON,
  buildProductProofPathReport,
  historicalProductProofPathClaudeHookReplaySummary,
  runProductProofPath,
} = productProofModule;

section('input-independent fixed refusals');
for (const [label, fn, reason] of [
  ['service proof export', runProtectedRecordsServiceProof, PROTECTED_RECORDS_SERVICE_PROOF_GENERATION_RETIREMENT_REASON],
  ['service preflight export', runProtectedRecordsServiceProfilePreflight, PROTECTED_RECORDS_SERVICE_PROFILE_PREFLIGHT_GENERATION_RETIREMENT_REASON],
  ['local proof pack export', runLocalProofPack, LOCAL_PROOF_PACK_GENERATION_RETIREMENT_REASON],
  ['product proof builder', buildProductProofPathReport, PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON],
  ['product proof runner', runProductProofPath, PRODUCT_PROOF_PATH_GENERATION_RETIREMENT_REASON],
]) {
  equal(`${label} declares zero parameters`, 0, fn.length);
  const hostile = hostileProxy();
  assertThrows(label, () => fn(hostile.proxy, hostile.proxy), reason);
  equal(`${label} reads no hostile input`, 0, hostile.reads());
}
assertThrows(
  'local proof-pack default artifact fallback retired',
  () => buildLocalProofPackArtifact(),
  'local_proof_pack_default_artifact_generation_retired',
);
const preflightArtifactHostile = hostileProxy();
assertThrows(
  'service preflight default artifact fallback retired',
  () => buildProtectedRecordsServiceProfilePreflightArtifact(
    preflightArtifactHostile.proxy,
  ),
  'e2_positive_service_preflight_default_artifact_generation_retired',
);
equal(
  'service preflight default artifact fallback reads no hostile input',
  0,
  preflightArtifactHostile.reads(),
);

section('CLI fixed refusals and no artifact writes');
const noWritePaths = {
  preflight: join(tmpdir(), `zlar-retired-e2-preflight-${process.pid}.json`),
  local: join(tmpdir(), `zlar-retired-local-proof-pack-${process.pid}.json`),
  product: join(tmpdir(), `zlar-retired-product-proof-${process.pid}.json`),
};
for (const path of Object.values(noWritePaths)) {
  equal(`precondition output absent: ${path}`, false, existsSync(path));
}
for (const [label, wrapper, args, reason] of [
  ['service proof CLI', 'bin/zlar-protected-records-service-proof', ['--json'], 'e2_positive_service_proof_generation_retired'],
  ['service preflight CLI', 'bin/zlar-protected-records-service-preflight', ['--profile', '/nonexistent/e2-profile.json', '--artifact', noWritePaths.preflight], 'e2_positive_service_preflight_generation_retired'],
  ['local proof-pack CLI', 'bin/zlar-local-proof-pack', ['--artifact', noWritePaths.local], 'local_proof_pack_fresh_generation_retired'],
  ['product proof CLI', 'bin/zlar-product-proof-path', ['--json-out', noWritePaths.product], 'product_proof_path_fresh_generation_retired'],
]) {
  const result = runWrapper(wrapper, args);
  equal(`${label} exits one`, 1, result.status);
  equal(`${label} emits no stdout`, '', result.stdout);
  assert(`${label} reason exact`, result.stderr.includes(reason));
}
for (const path of Object.values(noWritePaths)) {
  equal(`retired CLI wrote no artifact: ${path}`, false, existsSync(path));
}
for (const path of [
  'bin/zlar-protected-records-service-proof',
  'bin/zlar-protected-records-service-preflight',
  'bin/zlar-local-proof-pack',
  'bin/zlar-product-proof-path',
]) {
  assert(`${path} remains executable`, (statSync(join(ROOT, path)).mode & 0o111) !== 0);
}

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
equal(
  'local historical body SHA exact',
  LOCAL_PROOF_PACK_BODY_SHA,
  localVerification.body_sha256,
);
equal(
  'local historical fresh generation false',
  false,
  localVerification.fresh_proof_pack_run_performed,
);

const preflightVerificationRun = runWrapper(
  'bin/zlar-protected-records-service-preflight',
  [
  'verify',
  '--sample',
  '--require-sha',
  SERVICE_PREFLIGHT_BODY_SHA,
  '--json',
  ],
);
equal('preflight historical verification exits zero', 0, preflightVerificationRun.status);
equal('preflight historical verification stderr empty', '', preflightVerificationRun.stderr);
const preflightVerification = JSON.parse(preflightVerificationRun.stdout);
equal('preflight historical verification true', true, preflightVerification.verified);
equal(
  'preflight historical body SHA exact',
  SERVICE_PREFLIGHT_BODY_SHA,
  preflightVerification.body_sha256,
);

const tamperedLocal = JSON.parse(
  read('tests/fixtures/local-proof-pack-artifact-v1.json'),
);
tamperedLocal.payload.live_probing = true;
const tamperedLocalRun = runWrapper('bin/zlar-local-proof-pack', [
  'verify',
  '--input',
  '-',
  '--require-sha',
  LOCAL_PROOF_PACK_BODY_SHA,
  '--json',
], `${JSON.stringify(tamperedLocal)}\n`);
equal('tampered local artifact refuses', 1, tamperedLocalRun.status);

const tamperedPreflight = JSON.parse(
  read('tests/fixtures/protected-records-service-preflight-artifact-v1.json'),
);
tamperedPreflight.payload.preflight.live_probing = true;
const tamperedPreflightRun = runWrapper(
  'bin/zlar-protected-records-service-preflight',
  [
  'verify',
  '--input',
  '-',
  '--require-sha',
  SERVICE_PREFLIGHT_BODY_SHA,
  '--json',
  ],
  `${JSON.stringify(tamperedPreflight)}\n`,
);
equal('tampered preflight artifact refuses', 1, tamperedPreflightRun.status);

const historicalHookSummary =
  historicalProductProofPathClaudeHookReplaySummary();
equal(
  'historical product-proof hook contract SHA',
  '452d1245cc3cc81c3588c4842f0eef02f3636c8fed42a2c29082448945b87b78',
  historicalHookSummary.hook_replay_contract_sha256,
);
equal(
  'historical product-proof hook component SHA',
  '6321be8c8e904e3365dd404bee542bb10ef34000af677ddc2eedfc90ab09ea7b',
  historicalHookSummary.component_sha256,
);
equal(
  'historical product-proof hook case evidence SHA',
  'a40e37992f26befe379bb81c53740458bcf3a6406a4ff392e2f204075ff099cc',
  historicalHookSummary.case_evidence_sha256,
);

section('test routing keeps active side doors visible');
deepEqual(
  'retired generator suites exact',
  [
    'test-protected-records-service-preflight-cli.mjs',
    'test-protected-records-service-profile.mjs',
    'test-protected-records-service-proof-cli.mjs',
    'test-protected-records-service-proof.mjs',
  ],
  read('tests/retired-positive-generator-test-suites.txt').trim().split('\n'),
);
deepEqual(
  'current positive E2 suites exact',
  [
    'test-claude-code-receipt-bridge-proof.mjs',
    'test-protected-records-service-request-cli.mjs',
    'test-protected-records-service.mjs',
  ],
  read('tests/current-positive-e2-test-suites.txt').trim().split('\n'),
);
equal('current direct E2 factory remains unretired', false, spec.unchanged_stage_3_and_e4_boundaries.direct_e2_factory.retired);
equal('current direct E2 CLI remains unretired', false, spec.unchanged_stage_3_and_e4_boundaries.direct_e2_request_cli.retired);
equal('skip does not prove retirement', false, spec.test_routing.skip_status_proves_retirement);
equal('skip does not prove governance', false, spec.test_routing.skip_status_proves_governance);

section('immutable fixtures and out-of-scope source unchanged');
for (const item of [
  spec.historical_verification.proof_smoke,
  spec.historical_verification.local_proof_pack,
  spec.historical_verification.service_preflight,
  spec.unchanged_stage_3_and_e4_boundaries.direct_e2_factory,
  spec.unchanged_stage_3_and_e4_boundaries.direct_e2_request_cli,
  spec.unchanged_stage_3_and_e4_boundaries.future_install_copy_path,
]) {
  equal(`${item.path || item.file_path} exact unchanged SHA`, item.file_sha256, fileSha(item.path || item.file_path));
}
const e4 = spec.unchanged_stage_3_and_e4_boundaries.replacement_e4;
equal('E4 driver unchanged', e4.driver_file_sha256, fileSha(e4.driver_path));
equal('E4 child unchanged', e4.child_file_sha256, fileSha(e4.child_path));

section('claim and lifecycle boundary');
equal('North Star 1 remains historical', 'historical', spec.north_star_1_status);
equal('North Star 2 remains mapped open', 'mapped_open', spec.north_star_2_status);
equal('lifecycle map remains open', 'mapped_open', spec.lifecycle_delta.map_status_after);
deepEqual('no lifecycle obligations changed', [], spec.lifecycle_delta.lifecycle_obligation_status_changes);
equal('generator retirement exact true', true, spec.claim_boundary.exact_checked_out_source_generator_retirement);
equal('historical verification preserved true', true, spec.claim_boundary.exact_historical_verification_preserved);
for (const [claim, value] of Object.entries(spec.claim_boundary)) {
  if (
    claim === 'exact_checked_out_source_generator_retirement' ||
    claim === 'exact_historical_verification_preserved'
  ) continue;
  equal(`${claim} remains false`, false, value);
}
for (const required of [
  'current-positive-direct-e2-request-cli',
  'current-positive-exported-e2-factory',
  'future-installer-copy-of-direct-e2-surfaces',
  'old-installed-copied-or-historical-positive-source',
  'explicit-report-artifact-packaging-and-write-exports',
  'raw-filesystem-writes',
  'source-drift-after-checkpoint',
]) {
  assert(`side door visible: ${required}`, spec.side_doors.includes(required));
}

process.stdout.write(
  `\nResults: ${assertions}/${assertions} passed — E2 positive proof-generator retirement v0\n`,
);
