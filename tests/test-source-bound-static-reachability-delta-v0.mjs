#!/usr/bin/env node
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { canonicalize } from '../lib/canonicalize.mjs';
import { sha256hex } from '../lib/sha256.mjs';
import {
  SOURCE_BOUND_STATIC_REACHABILITY_DELTA_TYPE_V0,
  SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0,
  assertSourceBoundStaticReachabilityDeltaV0,
  buildSourceBoundStaticReachabilityDeltaV0,
  canonicalSourceBoundStaticReachabilityDeltaBytesV0,
  maskJavaScriptNonCodeV0,
  sourceBoundStaticReachabilitySourceInventorySha256V0,
  validateExactSourceWitnessesV0,
} from '../lib/source-bound-static-reachability-delta-v0.mjs';
import {
  sourceBoundHistoricalSourceFilesV0,
  writeSourceBoundHistoricalRootV0,
} from './source-bound-historical-source-v0.mjs';

const PROJECT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(PROJECT_DIR, 'bin/zlar-source-bound-static-reachability-delta-v0');
const PARENT = join(
  resolve(PROJECT_DIR, '..'),
  'ZLAR-Draft/build/north-star-2-consequence-path-coverage-dependency-map-20260711T204128Z/NORTH-STAR-2-CONSEQUENCE-PATH-COVERAGE-DEPENDENCY-MAP-V0.json',
);
const PARENT_FILE_SHA =
  'a275b74cb7e468bed6a8376c8ccc0aab81937d945e240d69090293ae9b38a4de';
const PARENT_BODY_SHA =
  'b39767ba79435bede70784d416b25ad52c47a6fb1c22df195a32b4af115f6b9b';
const SOURCE_COMMIT = 'e7c621927df35eb31cf3f0dfc1ea2a42df6d5dd5';
const SOURCE_INVENTORY_SHA =
  '20451df27fb00b5e11e0c6f25dceb6c3f26a71f55a452c2f6a7e6d092cb41642';

if (!existsSync(PARENT)) {
  throw new Error(
    'Exact private workspace parent map is required for this fail-closed integration test; do not substitute or copy Draft evidence into repository source.',
  );
}

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

function section(label) {
  process.stdout.write(`\n## ${label}\n`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function rehashArtifact(value) {
  const { integrity: _discarded, ...body } = value;
  value.integrity = { body_sha256: sha256hex(canonicalize(body)) };
  return value;
}

function sourceFiles() {
  return sourceBoundHistoricalSourceFilesV0(
    PROJECT_DIR,
    SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0,
  );
}

function currentSourceFiles() {
  return Object.fromEntries(
    Object.entries(SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0).map(
      ([role, relativePath]) => [role, readFileSync(join(PROJECT_DIR, relativePath))],
    ),
  );
}

function build(overrides = {}) {
  return buildSourceBoundStaticReachabilityDeltaV0({
    parentRawBytes: readFileSync(PARENT),
    sourceFiles: sourceFiles(),
    expectedParentFileSha256: PARENT_FILE_SHA,
    expectedParentBodySha256: PARENT_BODY_SHA,
    expectedAnalyzedSourceCommitOid: SOURCE_COMMIT,
    expectedSourceInventorySha256: SOURCE_INVENTORY_SHA,
    ...overrides,
  });
}

function mode(artifact, id) {
  return artifact.mode_results.find((item) => item.surface_mode_id === id);
}

function cliArgs(extra = [], repoRoot = PROJECT_DIR) {
  return [
    '--repo-root',
    repoRoot,
    '--parent-map',
    PARENT,
    '--require-parent-file-sha',
    PARENT_FILE_SHA,
    '--require-parent-body-sha',
    PARENT_BODY_SHA,
    '--require-analyzed-source-commit',
    SOURCE_COMMIT,
    '--require-source-inventory-sha',
    SOURCE_INVENTORY_SHA,
    ...extra,
  ];
}

function staticImportSpecifiers(source) {
  return [
    ...[...source.matchAll(/\bfrom\s+['"]([^'"]+)['"]\s*;/g)].map(
      (match) => match[1],
    ),
    ...[
      ...source.matchAll(/^\s*import\s+['"]([^'"]+)['"]\s*;/gm),
    ].map((match) => match[1]),
  ].sort();
}

function executableImportTokenCount(source) {
  return (maskJavaScriptNonCodeV0(source).match(/\bimport\b/g) || []).length;
}

function exactImportEnvelope(source, expectedPrefix, expectedImportCount) {
  return (
    source.startsWith(expectedPrefix) &&
    executableImportTokenCount(source) === expectedImportCount
  );
}

section('exact parent and source identities');
const parentBefore = sha256hex(readFileSync(PARENT));
const sources = sourceFiles();
equal('exact source inventory role count', 16, Object.keys(sources).length);
equal(
  'source inventory SHA is deterministic',
  SOURCE_INVENTORY_SHA,
  sourceBoundStaticReachabilitySourceInventorySha256V0(sources),
);
equal('parent exact file identity', PARENT_FILE_SHA, parentBefore);

section('build and exact mode delta');
const artifact = build();
assert('artifact validates', assertSourceBoundStaticReachabilityDeltaV0(artifact));
equal('artifact type', SOURCE_BOUND_STATIC_REACHABILITY_DELTA_TYPE_V0, artifact.artifact_type);
equal('lifecycle remains mapped open', 'mapped_open', artifact.map_status);
equal('exact mode count', 11, artifact.mode_results.length);
equal('resolved mutation candidate mode count', 3, artifact.inventory_posture_after.delta_source_resolved_mutation_candidate_mode_count);
equal('unresolved mutation candidate mode count', 5, artifact.inventory_posture_after.delta_unresolved_mutation_candidate_mode_count);
equal('verifier sink mode count', 4, artifact.inventory_posture_after.delta_resolved_verifier_sink_mode_count);
equal('parent unresolved count preserved', 30, artifact.inventory_posture_after.parent_unresolved_surface_count_preserved);
equal('domain inventory not recomputed', false, artifact.inventory_posture_after.domain_inventory_recomputed);
equal('domain inventory open', false, artifact.inventory_posture_after.domain_inventory_complete);
equal('equivalent route closure false', false, artifact.inventory_posture_after.equivalent_route_closure);
deepEqual('no new effect nodes', [], artifact.dependency_map_delta.new_effect_node_ids);
equal('selected E4 not reached', false, artifact.dependency_map_delta.selected_node_e4_reached_by_any_analyzed_mode);
equal('parent not mutated', false, artifact.immutable_parent_binding.parent_mutated);
equal('parent not regenerated', false, artifact.immutable_parent_binding.parent_regenerated);
equal('underlying dependency bytes not reloaded', false, artifact.immutable_parent_binding.underlying_parent_dependency_bytes_reloaded);
equal('regex lexical closure remains false', false, artifact.analysis_contract.regex_lexical_closure_complete);
equal('edge semantics are not machine-derived CFG', false, artifact.analysis_contract.edge_semantics_machine_derived_from_general_ast_or_cfg);

const exactModeIds = [
  'protected-records-active-persistent-profile-lifecycle.run',
  'protected-records-active-persistent-profile-lifecycle.verify-supplied-reports',
  'protected-records-installed-runtime-profile-recognition-proof.generate',
  'protected-records-installed-runtime-profile-recognition-proof.verify',
  'protected-records-installed-runtime-profile-service-proof.generate',
  'protected-records-installed-runtime-profile-service-proof.verify',
  'protected-records-runtime-activation-preflight.generate',
  'protected-records-runtime-activation-preflight.verify',
  'protected-records-runtime-profile-preflight.generate',
  'protected-records-runtime-profile-proof.generate',
  'protected-records-runtime-service.legacy-v1-execution',
].sort();
deepEqual(
  'mode set exact',
  exactModeIds,
  artifact.mode_results.map((item) => item.surface_mode_id).sort(),
);

section('positive paths and strict unresolved children');
const direct = mode(artifact, 'protected-records-runtime-service.legacy-v1-execution');
equal('direct legacy path source-resolved', true, direct.source_resolved_call_path);
deepEqual('direct legacy resolves E3 candidate', ['E3.legacy-runtime-process-private-state-v1'], direct.source_resolved_existing_node_candidate_ids);
equal('direct legacy has no freshness edge', 0, direct.source_guard_edge_ids.length);
equal('direct legacy remains uncovered', 'observed_uncovered', direct.coverage_disposition);
equal('direct legacy keeps parent surface id', 'source-discovered:bin/zlar-protected-records-runtime-service-v1', direct.surface_id);
equal('direct legacy is a distinct direct surface', 'distinct_effect', direct.relationship_to_selected_path);

const recognition = mode(
  artifact,
  'protected-records-installed-runtime-profile-recognition-proof.generate',
);
equal('recognition generation source-resolved', true, recognition.source_resolved_call_path);
deepEqual('recognition generation resolves E3 candidate', ['E3.legacy-runtime-process-private-state-v1'], recognition.source_resolved_existing_node_candidate_ids);
equal('recognition guard dominance remains unproven', 'not_proven_import_time_closure_open', recognition.source_refusal_dominance.status);
equal('recognition current refusal remains false', false, recognition.current_refusal_behavior_proven);
equal('recognition surface remains wrapper', 'wrapper', recognition.relationship_to_selected_path);
equal('recognition reached node is distinct', 'distinct_effect', recognition.reached_node_relationship_to_selected_path);
equal(
  'recognition parent wrapper id exact',
  'known-static-uncatalogued:bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
  recognition.parent_surface_reference.surface_id,
);

const lifecycle = mode(
  artifact,
  'protected-records-active-persistent-profile-lifecycle.run',
);
equal('lifecycle has a source-resolved path', true, lifecycle.source_resolved_call_path);
deepEqual('lifecycle resolves E5 candidate only', ['E5.active-persistent-proof-target-marker-v1'], lifecycle.source_resolved_existing_node_candidate_ids);
deepEqual('lifecycle E3 remains unresolved expected', ['E3.legacy-runtime-process-private-state-v1'], lifecycle.unresolved_expected_node_candidate_ids);
deepEqual('lifecycle child edge unresolved', ['S5'], lifecycle.unresolved_edge_ids);
equal('lifecycle does not create effect exit', false, lifecycle.adds_new_effect_exit);
equal('lifecycle surface remains wrapper', 'wrapper', lifecycle.relationship_to_selected_path);
assert('lifecycle guard inventory includes red-path LR2', lifecycle.source_guard_edge_ids.includes('LR2'));
deepEqual(
  'lifecycle exact branch set',
  [
    'green-action-crossing',
    'post-closeout-expected-refusal-probe',
    'red-path-evidence',
  ],
  lifecycle.source_path_branches.map((item) => item.branch_id).sort(),
);
const greenBranch = lifecycle.source_path_branches.find(
  (item) => item.branch_id === 'green-action-crossing',
);
deepEqual(
  'green branch preserves service-before-proof-target order',
  ['L5', 'S3', 'S4', 'S5', 'L6', 'L7'],
  greenBranch.ordered_edge_steps.slice(-6).map((item) => item.edge_id),
);
const redBranch = lifecycle.source_path_branches.find(
  (item) => item.branch_id === 'red-path-evidence',
);
assert('red branch exposes LR1', redBranch.ordered_edge_steps.some((item) => item.edge_id === 'LR1'));
assert('red branch exposes unresolved S5', redBranch.ordered_edge_steps.some((item) => item.edge_id === 'S5' && item.expected_status === 'unresolved'));
const closeoutBranch = lifecycle.source_path_branches.find(
  (item) => item.branch_id === 'post-closeout-expected-refusal-probe',
);
assert('closeout branch exposes LC2', closeoutBranch.ordered_edge_steps.some((item) => item.edge_id === 'LC2'));
equal('closeout current refusal remains false', false, closeoutBranch.current_refusal_behavior_proven);

for (const id of [
  'protected-records-runtime-profile-proof.generate',
  'protected-records-runtime-profile-preflight.generate',
  'protected-records-runtime-activation-preflight.generate',
  'protected-records-installed-runtime-profile-service-proof.generate',
]) {
  const item = mode(artifact, id);
  equal(`${id} not source-resolved through child`, false, item.source_resolved_call_path);
  deepEqual(`${id} strict projection empty`, [], item.source_resolved_existing_node_candidate_ids);
  deepEqual(`${id} expected E3 visible`, ['E3.legacy-runtime-process-private-state-v1'], item.unresolved_expected_node_candidate_ids);
  assert(`${id} has one unresolved child edge`, item.unresolved_edge_ids.length === 1);
  equal(`${id} wrapper relationship preserved`, 'wrapper', item.relationship_to_selected_path);
  equal(
    `${id} exact parent surface join`,
    `known-static-uncatalogued:${item.entrypoint}`,
    item.parent_surface_reference.surface_id,
  );
}

const p4 = artifact.edge_certificates.find((item) => item.edge_id === 'P4');
const s5 = artifact.edge_certificates.find((item) => item.edge_id === 'S5');
equal('profile child unresolved', 'unresolved', p4.resolution_status);
equal('service child unresolved', 'unresolved', s5.resolution_status);
assert('profile child reason names inherited env', p4.unresolved_reason.includes('inherits-process-env'));
assert('service child reason names inherited env', s5.unresolved_reason.includes('inherits-process-env'));

section('verification candidates stay below absence proof');
for (const id of [
  'protected-records-runtime-activation-preflight.verify',
  'protected-records-installed-runtime-profile-recognition-proof.verify',
  'protected-records-installed-runtime-profile-service-proof.verify',
  'protected-records-active-persistent-profile-lifecycle.verify-supplied-reports',
]) {
  const item = mode(artifact, id);
  equal(`${id} call path resolves to verifier`, true, item.source_resolved_call_path);
  assert(`${id} role preserves import-time caveat`, item.surface_role.startsWith('verification_candidate'));
  equal(`${id} import-time closure open`, false, item.import_time_side_effect_closure_complete);
  deepEqual(`${id} target projection empty`, [], item.source_resolved_existing_node_candidate_ids);
  equal(`${id} effect capability false`, false, item.effect_capability_proven);
  equal(
    `${id} exact parent surface join`,
    `known-static-uncatalogued:${item.entrypoint}`,
    item.parent_surface_reference.surface_id,
  );
}

section('claim ceiling invariants');
for (const [key, value] of Object.entries(artifact.claim_boundary)) {
  equal(`claim ${key} false`, false, value);
}
for (const item of artifact.mode_results) {
  equal(`${item.surface_mode_id} runtime false`, false, item.runtime_reachability_proven);
  equal(`${item.surface_mode_id} effect capability false`, false, item.effect_capability_proven);
  equal(`${item.surface_mode_id} effect occurrence false`, false, item.effect_occurrence_proven);
  equal(`${item.surface_mode_id} refusal false`, false, item.current_refusal_behavior_proven);
  equal(`${item.surface_mode_id} domain membership false`, false, item.authority_domain_membership_proven);
  equal(`${item.surface_mode_id} outside coverage false`, false, item.authorized_outside_coverage);
  equal(`${item.surface_mode_id} new exit false`, false, item.adds_new_effect_exit);
}

section('canonical integrity and parent immutability');
const artifactAgain = build();
equal('deterministic body sha', artifact.integrity.body_sha256, artifactAgain.integrity.body_sha256);
equal('deterministic canonical bytes', canonicalSourceBoundStaticReachabilityDeltaBytesV0(artifact), canonicalSourceBoundStaticReachabilityDeltaBytesV0(artifactAgain));
equal('parent bytes unchanged after build', parentBefore, sha256hex(readFileSync(PARENT)));
const brokenIntegrity = clone(artifact);
brokenIntegrity.map_status = 'closed';
throws('self-integrity drift refused', () => assertSourceBoundStaticReachabilityDeltaV0(brokenIntegrity), /mapped_open|integrity/);
const promotedRuntime = clone(artifact);
promotedRuntime.mode_results[0].runtime_reachability_proven = true;
throws('runtime claim promotion refused', () => assertSourceBoundStaticReachabilityDeltaV0(promotedRuntime), /runtime reachability/);
const inventedNode = clone(artifact);
inventedNode.dependency_map_delta.new_effect_node_ids.push('E6.wrapper-laundering');
throws('wrapper node laundering refused', () => assertSourceBoundStaticReachabilityDeltaV0(inventedNode), /add an effect node/);
const wrongParentNodeProjection = clone(artifact);
wrongParentNodeProjection.mode_results[0].source_resolved_existing_node_candidate_ids = [
  'E5.wrong-parent-node-id',
];
throws(
  'wrong parent node identity refused',
  () => assertSourceBoundStaticReachabilityDeltaV0(wrongParentNodeProjection),
  /unsupported parent node candidate/,
);
const forgedSemanticBody = clone(artifact);
forgedSemanticBody.source_binding.analyzed_source_commit_oid = '0'.repeat(40);
forgedSemanticBody.safe_claim_ceiling =
  'This forged body claims runtime reachability and lifecycle closure.';
forgedSemanticBody.side_doors = [];
forgedSemanticBody.edge_certificates = [];
forgedSemanticBody.mode_results[0].resolved_edge_ids = [];
rehashArtifact(forgedSemanticBody);
throws(
  'recomputed-integrity semantic forgery refused',
  () => assertSourceBoundStaticReachabilityDeltaV0(forgedSemanticBody),
  /exact v0 semantic body identity mismatch/,
);

section('parent and source drift refusals');
throws(
  'wrong parent file pin refused',
  () => build({ expectedParentFileSha256: '0'.repeat(64) }),
  /parent file SHA-256 pin mismatch/,
);
throws(
  'wrong parent body pin refused',
  () => build({ expectedParentBodySha256: '0'.repeat(64) }),
  /parent body SHA-256 pin mismatch/,
);
throws(
  'wrong source commit refused',
  () => build({ expectedAnalyzedSourceCommitOid: '0'.repeat(40) }),
  /source commit pin mismatch/,
);
throws(
  'wrong source inventory pin refused',
  () => build({ expectedSourceInventorySha256: '0'.repeat(64) }),
  /source inventory SHA-256 mismatch/,
);
const alteredParent = Buffer.from(readFileSync(PARENT));
alteredParent[alteredParent.length - 2] = alteredParent[alteredParent.length - 2] === 32 ? 33 : 32;
throws(
  'parent byte drift refused',
  () => build({ parentRawBytes: alteredParent }),
  /parent map file SHA-256 mismatch/,
);
const changedSources = sourceFiles();
changedSources.runtime_service_cli = Buffer.concat([
  changedSources.runtime_service_cli,
  Buffer.from('\n// drift\n'),
]);
throws(
  'source byte drift refused',
  () => build({ sourceFiles: changedSources }),
  /full-file SHA-256 mismatch/,
);
throws(
  'current post-retirement source refuses immutable delta reconstruction',
  () => sourceBoundStaticReachabilitySourceInventorySha256V0(currentSourceFiles()),
  /full-file SHA-256 mismatch|witness/,
);
const missingSources = sourceFiles();
delete missingSources.runtime_service_cli;
throws(
  'missing source refused',
  () => build({ sourceFiles: missingSources }),
  /exact source inventory/,
);
const extraSources = sourceFiles();
extraSources.unexpected = Buffer.from('unexpected');
throws(
  'unexpected source refused',
  () => build({ sourceFiles: extraSources }),
  /exact source inventory/,
);

section('lexical witness laundering refusals');
const lexicalCases = [
  ['line comment', '// dangerousCall();\nconst safe = true;'],
  ['block comment', '/* dangerousCall(); */\nconst safe = true;'],
  ['single string', "const x = 'dangerousCall();';"],
  ['double string', 'const x = "dangerousCall();";'],
  ['template', 'const x = `dangerousCall();`;'],
  ['regex', 'const x = /dangerousCall\(\)/;'],
];
for (const [label, source] of lexicalCases) {
  const raw = Buffer.from(source);
  throws(
    `${label} cannot satisfy executable anchor`,
    () =>
      validateExactSourceWitnessesV0({
        relativePath: `${label}.mjs`,
        rawBytes: raw,
        expectedFileSha256: sha256hex(raw),
        witnesses: [
          { id: 'candidate', needle: 'dangerousCall()', code_anchors: ['dangerousCall'] },
        ],
      }),
    /not executable lexical code/,
  );
}
const returnRegex = Buffer.from('function f() { return /dangerousCall\\(\\)/; }\n');
throws(
  'return regex cannot satisfy executable anchor',
  () =>
    validateExactSourceWitnessesV0({
      relativePath: 'return-regex.mjs',
      rawBytes: returnRegex,
      expectedFileSha256: sha256hex(returnRegex),
      witnesses: [
        { id: 'candidate', needle: 'dangerousCall\\(\\)', code_anchors: ['dangerousCall'] },
      ],
    }),
  /not executable lexical code/,
);
const realCall = Buffer.from('const result = dangerousCall();\n');
const realWitness = validateExactSourceWitnessesV0({
  relativePath: 'real.mjs',
  rawBytes: realCall,
  expectedFileSha256: sha256hex(realCall),
  witnesses: [
    { id: 'candidate', needle: 'dangerousCall()', code_anchors: ['dangerousCall'] },
  ],
});
equal('real executable call validates', 1, realWitness.length);
const duplicateCall = Buffer.from('dangerousCall();\ndangerousCall();\n');
throws(
  'duplicate witness refused',
  () =>
    validateExactSourceWitnessesV0({
      relativePath: 'duplicate.mjs',
      rawBytes: duplicateCall,
      expectedFileSha256: sha256hex(duplicateCall),
      witnesses: [
        { id: 'candidate', needle: 'dangerousCall()', code_anchors: ['dangerousCall'] },
      ],
    }),
  /exactly once/,
);
const invalidUtf8 = Buffer.from([0xff, 0xfe, 0xfd]);
throws(
  'invalid UTF-8 refused',
  () =>
    validateExactSourceWitnessesV0({
      relativePath: 'invalid.mjs',
      rawBytes: invalidUtf8,
      expectedFileSha256: sha256hex(invalidUtf8),
      witnesses: [],
    }),
  /canonical UTF-8/,
);
const nulSource = Buffer.from('const value = true;\0\n');
throws(
  'NUL byte refused',
  () =>
    validateExactSourceWitnessesV0({
      relativePath: 'nul.mjs',
      rawBytes: nulSource,
      expectedFileSha256: sha256hex(nulSource),
      witnesses: [],
    }),
  /NUL byte/,
);
const masked = maskJavaScriptNonCodeV0(
  "// hiddenCall()\nconst shown = realCall(); const hidden = 'stringCall()';\n",
);
assert('mask preserves real code', masked.includes('realCall'));
assert('mask removes comment code', !masked.includes('hiddenCall'));
assert('mask removes string code', !masked.includes('stringCall'));

section('production capability graph');
const libraryText = readFileSync(
  join(PROJECT_DIR, 'lib/source-bound-static-reachability-delta-v0.mjs'),
  'utf8',
);
const cliText = readFileSync(CLI, 'utf8');
const canonicalizeText = readFileSync(join(PROJECT_DIR, 'lib/canonicalize.mjs'), 'utf8');
const shaText = readFileSync(join(PROJECT_DIR, 'lib/sha256.mjs'), 'utf8');
const libraryImportPrefix =
  "import { canonicalize } from './canonicalize.mjs';\n" +
  "import { sha256hex } from './sha256.mjs';\n";
const cliImportPrefix = `#!/usr/bin/env node
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import {
  SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0,
  buildSourceBoundStaticReachabilityDeltaV0,
  canonicalSourceBoundStaticReachabilityDeltaBytesV0,
  formatSourceBoundStaticReachabilityDeltaSummaryV0,
} from '../lib/source-bound-static-reachability-delta-v0.mjs';
`;
assert(
  'library exact import declaration envelope',
  exactImportEnvelope(libraryText, libraryImportPrefix, 2),
);
assert(
  'CLI exact import declaration envelope',
  exactImportEnvelope(cliText, cliImportPrefix, 3),
);
deepEqual(
  'library exact import allowlist',
  ['./canonicalize.mjs', './sha256.mjs'],
  staticImportSpecifiers(libraryText),
);
deepEqual(
  'CLI exact import allowlist',
  [
    '../lib/source-bound-static-reachability-delta-v0.mjs',
    'node:fs',
    'node:path',
  ].sort(),
  staticImportSpecifiers(cliText),
);
deepEqual('canonicalizer has no imports', [], staticImportSpecifiers(canonicalizeText));
deepEqual('SHA helper exact import allowlist', ['node:crypto'], staticImportSpecifiers(shaText));
equal(
  'canonicalizer transitive source pin',
  '44293ad4383fbe0026c200a9771ab3cc15b460984b7641e55bb103f128004f4f',
  sha256hex(canonicalizeText),
);
equal(
  'SHA helper transitive source pin',
  '90b7459845347501a9e3a074b3ccb5606c17ee865599ff2944e49bea8b64f06c',
  sha256hex(shaText),
);
equal('library exact import declaration count', 2, executableImportTokenCount(libraryText));
equal('CLI exact import declaration count', 3, executableImportTokenCount(cliText));
equal('canonicalizer exact import declaration count', 0, executableImportTokenCount(canonicalizeText));
equal('SHA helper exact import declaration count', 1, executableImportTokenCount(shaText));
deepEqual(
  'bare static import parser is load-bearing',
  ['node:net'],
  staticImportSpecifiers("import 'node:net';\n"),
);
equal(
  'comment-separated bare import remains visible to coverage count',
  1,
  executableImportTokenCount("import/*comment*/'node:net';\n"),
);
deepEqual(
  'comment-separated bare import is not silently allowlisted',
  [],
  staticImportSpecifiers("import/*comment*/'node:net';\n"),
);
const decoyImportBypass =
  "import { writeFileSync } from/*comment*/'node:fs';\n" +
  "import/*comment*/'node:net';\n" +
  "const decoy = \"from './canonicalize.mjs'; from './sha256.mjs';\";\n";
equal(
  'comment-separated imports plus string decoys fail exact envelope',
  false,
  exactImportEnvelope(decoyImportBypass, libraryImportPrefix, 2),
);
assert(
  'CLI exact read-only fs binding block',
  cliText.includes(
    "import {\n  closeSync,\n  constants,\n  fstatSync,\n  lstatSync,\n  openSync,\n  readFileSync,\n  realpathSync,\n} from 'node:fs';",
  ),
);
for (const [label, text] of [
  ['library', libraryText],
  ['cli', cliText],
]) {
  assert(`${label} has no child-process import`, !/from ['"]node:child_process['"]/.test(text));
  assert(`${label} has no vm import`, !/from ['"]node:vm['"]/.test(text));
  assert(`${label} has no dynamic import`, !/\bimport\s*\(/.test(maskJavaScriptNonCodeV0(text)));
  assert(`${label} has no require call`, !/\brequire\s*\(/.test(maskJavaScriptNonCodeV0(text)));
  assert(`${label} has no eval call`, !/\beval\s*\(/.test(maskJavaScriptNonCodeV0(text)));
}
for (const targetPath of Object.values(SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0)) {
  assert(
    `library does not import target ${targetPath}`,
    !new RegExp(`from ['"][^'"]*${targetPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`).test(libraryText),
  );
}
assert('CLI has no output file flag implementation', !cliText.includes("['--output',"));

section('CLI success and refusal surface');
const scratch = mkdtempSync(join(realpathSync(tmpdir()), 'zlar-reachability-delta-test-'));
process.once('exit', () => rmSync(scratch, { recursive: true, force: true }));
const historicalSourceRoot = writeSourceBoundHistoricalRootV0({
  projectDir: PROJECT_DIR,
  rootDir: join(scratch, 'historical-source-root'),
  sourcePaths: SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0,
});
const summaryRun = spawnSync(CLI, cliArgs([], historicalSourceRoot), {
  cwd: PROJECT_DIR,
  encoding: 'utf8',
  env: { PATH: process.env.PATH },
});
equal('CLI summary exit', 0, summaryRun.status);
assert('CLI summary reports GO', summaryRun.stdout.includes('decision=go_new_source_resolved_call_path_evidence'));
assert('CLI summary preserves false runtime', summaryRun.stdout.includes('runtime_reachability_proven=false'));
const jsonRun = spawnSync(CLI, cliArgs(['--json'], historicalSourceRoot), {
  cwd: PROJECT_DIR,
  encoding: 'utf8',
  env: { PATH: process.env.PATH },
});
equal('CLI JSON exit', 0, jsonRun.status);
const cliArtifact = JSON.parse(jsonRun.stdout);
equal('CLI JSON deterministic body', artifact.integrity.body_sha256, cliArtifact.integrity.body_sha256);
const unsupportedOutput = spawnSync(CLI, cliArgs(['--output', '/tmp/no'], historicalSourceRoot), {
  cwd: PROJECT_DIR,
  encoding: 'utf8',
  env: { PATH: process.env.PATH },
});
equal('CLI output flag refused', 2, unsupportedOutput.status);
assert('CLI output refusal explicit', unsupportedOutput.stderr.includes('unsupported'));
const runtimeClaim = spawnSync(CLI, cliArgs(['--require-runtime-reachable'], historicalSourceRoot), {
  cwd: PROJECT_DIR,
  encoding: 'utf8',
  env: { PATH: process.env.PATH },
});
equal('CLI runtime promotion refused', 2, runtimeClaim.status);
const duplicateFlag = spawnSync(
  CLI,
  cliArgs(['--require-parent-file-sha', PARENT_FILE_SHA], historicalSourceRoot),
  {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    env: { PATH: process.env.PATH },
  },
);
equal('CLI duplicate flag refused', 2, duplicateFlag.status);
assert('CLI duplicate refusal explicit', duplicateFlag.stderr.includes('Duplicate flag'));

try {
  const parentLink = join(scratch, 'parent-link.json');
  symlinkSync(PARENT, parentLink);
  const symlinkArgs = cliArgs([], historicalSourceRoot);
  symlinkArgs[symlinkArgs.indexOf(PARENT)] = parentLink;
  const symlinkRun = spawnSync(CLI, symlinkArgs, {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    env: { PATH: process.env.PATH },
  });
  equal('CLI parent symlink refused', 1, symlinkRun.status);
  assert('CLI parent symlink refusal explicit', symlinkRun.stderr.includes('symlinks'));
  const repoRootLink = join(scratch, 'repo-root-link');
  symlinkSync(historicalSourceRoot, repoRootLink);
  const rootSymlinkArgs = cliArgs([], historicalSourceRoot);
  rootSymlinkArgs[1] = repoRootLink;
  const rootSymlinkRun = spawnSync(CLI, rootSymlinkArgs, {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    env: { PATH: process.env.PATH },
  });
  equal('CLI repository-root symlink refused', 1, rootSymlinkRun.status);
  assert('CLI repository-root symlink refusal explicit', rootSymlinkRun.stderr.includes('non-symlink'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

section('privacy');
const rendered = canonicalSourceBoundStaticReachabilityDeltaBytesV0(artifact);
assert('artifact has no user-home path', !rendered.includes('/Users/'));
assert('artifact has no Telegram credential vocabulary', !/telegram.*(token|credential)/i.test(rendered));
assert('artifact has no PEM block', !rendered.includes('BEGIN PRIVATE KEY'));
assert('artifact has no authority-capable secret material', !/private[_-]?key|hmac[_-]?secret/i.test(rendered));
assert('artifact uses relative analyzed paths', artifact.source_binding.source_files.every((item) => !item.relative_path.startsWith('/')));

process.stdout.write(`\nPASS: ${assertions} assertions\n`);
