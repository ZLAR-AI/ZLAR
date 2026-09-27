#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC_PATH = join(
  ROOT,
  'spec/future-installer-retired-source-residue-cleanup-v0.json',
);
const BASELINE_COMMIT = 'dca5edbf7311c9af9c3152a33d9b810e52410850';
const CLEANUP_RESULT_COMMIT = 'b6c16a216d8b6ca9c6f66b552b72d1f609f2d307';
const EXPECTED_SPEC_BODY_SHA =
  'f9ae31f2e3c1e50ed843ac351b9b7c6f00aa94de38e51a1f9d272edb55cf433e';
const RETIRED_PATHS = [
  'bin/zlar-protected-records-write',
  'bin/zlar-protected-records-service-request',
  'lib/protected-records-adapter.mjs',
  'lib/protected-records-service.mjs',
];
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

function snapshot(root) {
  const records = [];
  const visit = (path) => {
    const names = readdirSync(path).sort();
    for (const name of names) {
      const child = join(path, name);
      const rel = relative(root, child);
      const stat = lstatSync(child);
      if (stat.isDirectory()) {
        records.push(`d ${rel}`);
        visit(child);
      } else if (stat.isSymbolicLink()) {
        records.push(`l ${rel}`);
      } else {
        records.push(`f ${rel} ${sha(readFileSync(child))}`);
      }
    }
  };
  visit(root);
  return records;
}

function runDryPlan(home, args = []) {
  const result = spawnSync(
    '/bin/bash',
    [join(ROOT, 'install.sh'), '--dry-run', '--json', ...args],
    {
      cwd: ROOT,
      encoding: 'utf8',
      env: {
        HOME: home,
        NO_COLOR: '1',
        PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
      },
    },
  );
  equal('dry-run status zero', 0, result.status);
  equal('dry-run stderr empty', '', result.stderr);
  return JSON.parse(result.stdout);
}

const spec = JSON.parse(readFileSync(SPEC_PATH, 'utf8'));
const { integrity, ...body } = spec;

section('overlay and exact source checkpoints');
equal(
  'artifact type exact',
  'zlar.future-installer-retired-source-residue-cleanup.v0',
  spec.artifact_type,
);
equal('schema version exact', 0, spec.schema_version);
equal(
  'decision exact',
  'remove_only_exact_retired_e1_e2_installed_source_residue_on_future_accepted_existing_install_modes',
  spec.decision,
);
equal('baseline commit exact', BASELINE_COMMIT, spec.source_checkpoint.baseline_commit_oid);
equal('baseline remote exact', BASELINE_COMMIT, spec.source_checkpoint.baseline_private_remote_oid);
equal(
  'source inventory verification uses exact cleanup result checkpoint',
  'b6c16a216d8b6ca9c6f66b552b72d1f609f2d307',
  CLEANUP_RESULT_COMMIT,
);
equal('installer execution absent', false, spec.source_checkpoint.installer_executed);
equal('machine inspection absent', false, spec.source_checkpoint.current_machine_installation_inspected);
equal('positive effect execution absent', false, spec.source_checkpoint.positive_effect_execution_performed);
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
  equal(
    `${item.path} source SHA exact at cleanup result checkpoint`,
    item.file_sha256,
    sha(readGitBytes(CLEANUP_RESULT_COMMIT, item.path)),
  );
}

section('prior retirement and sole E4 route preserved');
equal(
  'Stage 5 overlay file exact',
  spec.prior_retirement_overlay.file_sha256,
  fileSha(spec.prior_retirement_overlay.path),
);
const stage5 = JSON.parse(read(spec.prior_retirement_overlay.path));
equal(
  'Stage 5 body identity exact',
  spec.prior_retirement_overlay.body_sha256,
  stage5.integrity.body_sha256,
);
for (const item of spec.unchanged_e4_source_boundary) {
  equal(`${item.path} E4 SHA unchanged`, item.file_sha256, fileSha(item.path));
}
equal('E4 retirement route decision NO-GO', 'NO-GO', spec.route_decisions.e4_source_retirement);
equal('E5 latent retirement route decision NO-GO', 'NO-GO', spec.route_decisions.e5_latent_body_retirement);
equal('installer residue lane route decision GO', 'GO', spec.route_decisions.installer_stale_residue_cleanup);
equal('North Star 1 remains historical', 'historical', spec.north_star_1_status);
equal('North Star 2 remains mapped open', 'mapped_open', spec.north_star_2_status);

section('exact cleanup source boundary');
deepEqual('retired paths exact and ordered', RETIRED_PATHS, spec.cleanup_contract.exact_paths);
deepEqual(
  'accepted operations exact',
  ['repair', 'upgrade', 'reinstall'],
  spec.cleanup_contract.accepted_existing_install_operations,
);
deepEqual(
  'excluded operations exact',
  ['fresh_install', 'no_op', 'refusal'],
  spec.cleanup_contract.excluded_operations,
);
equal('validation before writes required', true, spec.cleanup_contract.validates_before_installer_writes);
equal('regular files removable', true, spec.cleanup_contract.regular_files_removable);
equal('symlinks removable as links', true, spec.cleanup_contract.symlinks_removable_as_links);
equal('unexpected types refused', true, spec.cleanup_contract.unexpected_file_types_refused);
equal('install-root and bin/lib parents must be real directories', true, spec.cleanup_contract.real_directory_parents_required);
equal('symlinked parents refused', true, spec.cleanup_contract.symlinked_parents_refused);
equal('non-directory parents refused', true, spec.cleanup_contract.non_directory_parents_refused);
equal('recursive delete forbidden', true, spec.cleanup_contract.recursive_delete_forbidden);
equal('quiescent filesystem required', true, spec.cleanup_contract.quiescent_filesystem_required_for_exact_path_claim);
equal('concurrent substitution remains open', false, spec.cleanup_contract.concurrent_parent_or_leaf_substitution_closed);

const installer = read('install.sh');
const removalStart = installer.indexOf('remove_retired_installed_positive_source_surfaces() {');
const removalEnd = installer.indexOf('\n}\n', removalStart);
const removalBody = installer.slice(removalStart, removalEnd + 3);
assert('removal function found', removalStart >= 0 && removalEnd > removalStart);
assert('removal uses exact non-recursive rm', removalBody.includes('rm -f --'));
assert('removal excludes recursive rm', !removalBody.includes('rm -rf'));
assert('removal excludes install-path globs', !removalBody.includes('${INSTALL_DIR}/*'));
assert('removal revalidates immediately before delete', removalBody.includes('validate_retired_installed_positive_source_surfaces'));
for (const relativePath of RETIRED_PATHS) {
  assert(
    `removal function names exact path: ${relativePath}`,
    removalBody.includes(`\${INSTALL_DIR}/${relativePath}`),
  );
}
equal(
  'removal function has four exact install-root paths',
  4,
  [...removalBody.matchAll(/\$\{INSTALL_DIR\}\//g)].length,
);
const earlyValidation = installer.indexOf('# Validate the four exact retirement paths before any installer-managed write.');
const frameworkProbe = installer.indexOf('# Check if any framework already has ZLAR hooks');
assert('early validation is before framework and later install phases', earlyValidation >= 0 && earlyValidation < frameworkProbe);
const cleanupCall = installer.lastIndexOf('\nremove_retired_installed_positive_source_surfaces\n');
const copyCall = installer.indexOf('\ncopy_installed_bin_wrappers\n', cleanupCall);
assert('cleanup call precedes replacement copies', cleanupCall >= 0 && cleanupCall < copyCall);
assert(
  'parent validator refuses symlinked parent',
  installer.includes("if [ -L \"${path}\" ]; then\n        printf 'symlinked_parent'"),
);
assert(
  'parent validator refuses non-directory parent',
  installer.includes("elif [ -e \"${path}\" ] && [ ! -d \"${path}\" ]; then\n        printf 'non_directory_parent'"),
);

section('no-write plan evidence for exact files and operation gates');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-retired-residue-v0-'));
try {
  const regularHome = join(scratch, 'regular');
  mkdirSync(join(regularHome, '.zlar/bin'), { recursive: true });
  mkdirSync(join(regularHome, '.zlar/lib'), { recursive: true });
  writeFileSync(join(regularHome, '.zlar/VERSION'), '0.0.0-stale\n');
  for (const path of RETIRED_PATHS) {
    writeFileSync(join(regularHome, '.zlar', path), 'stale-retired-source\n');
  }
  const regularBefore = snapshot(regularHome);
  const upgrade = runDryPlan(regularHome, [
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--existing-install',
    'upgrade',
  ]);
  equal('upgrade decision accepted', 'upgrade_existing_install', upgrade.existing_install.decision);
  equal('four exact removals planned', 4, upgrade.planned_retired_source_removals.length);
  deepEqual(
    'planned removal paths exact',
    RETIRED_PATHS.map((path) => `~/.zlar/${path}`),
    upgrade.planned_retired_source_removals.map((item) => item.path),
  );
  assert(
    'all planned actions exact',
    upgrade.planned_retired_source_removals.every(
      (item) => item.action === 'remove_retired_positive_source_residue',
    ),
  );
  equal('regular cleanup has no refusal', 0, upgrade.planned_retired_source_cleanup_refusals.length);
  equal('regular cleanup not blocked', false, upgrade.write_effects_if_real_install_runs.blocked_by_retired_source_cleanup);
  deepEqual('upgrade dry-run changes no bytes', regularBefore, snapshot(regularHome));

  const refusedDefault = runDryPlan(regularHome);
  equal('default existing-install mode refuses', 'refuse_existing_install', refusedDefault.existing_install.decision);
  equal('default refusal plans no removal', 0, refusedDefault.planned_retired_source_removals.length);
  deepEqual('default refusal changes no bytes', regularBefore, snapshot(regularHome));

  const targetVersion = read('VERSION').trim();
  writeFileSync(join(regularHome, '.zlar/VERSION'), `${targetVersion}\n`);
  const noOpBefore = snapshot(regularHome);
  const noOp = runDryPlan(regularHome, [
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--existing-install',
    'no-op',
  ]);
  equal('no-op decision exact', 'no_op_existing_install', noOp.existing_install.decision);
  equal('no-op plans no removal', 0, noOp.planned_retired_source_removals.length);
  deepEqual('no-op changes no bytes', noOpBefore, snapshot(regularHome));

  const unexpectedHome = join(scratch, 'unexpected');
  mkdirSync(
    join(unexpectedHome, '.zlar/bin/zlar-protected-records-write'),
    { recursive: true },
  );
  writeFileSync(join(unexpectedHome, '.zlar/VERSION'), '0.0.0-stale\n');
  const unexpectedBefore = snapshot(unexpectedHome);
  const unexpected = runDryPlan(unexpectedHome, [
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--existing-install',
    'upgrade',
  ]);
  equal('unexpected type keeps route decision visible', 'upgrade_existing_install', unexpected.existing_install.decision);
  equal('unexpected type plans no removal', 0, unexpected.planned_retired_source_removals.length);
  equal('unexpected type emits one refusal', 1, unexpected.planned_retired_source_cleanup_refusals.length);
  equal(
    'unexpected refusal path exact',
    '~/.zlar/bin/zlar-protected-records-write',
    unexpected.planned_retired_source_cleanup_refusals[0].path,
  );
  equal(
    'unexpected refusal reason exact',
    'unexpected_file_type',
    unexpected.planned_retired_source_cleanup_refusals[0].reason,
  );
  equal(
    'unexpected type marks pre-write refusal',
    true,
    unexpected.existing_install.retired_source_cleanup_would_refuse_before_writes,
  );
  equal(
    'unexpected type sets generic pre-write exit',
    true,
    unexpected.existing_install.real_install_would_exit_before_writes,
  );
  equal(
    'unexpected type blocks file effects',
    false,
    unexpected.write_effects_if_real_install_runs.would_create_or_modify_files,
  );
  deepEqual('unexpected-type dry-run changes no bytes', unexpectedBefore, snapshot(unexpectedHome));

  const rootSymlinkHome = join(scratch, 'root-symlink-home');
  const rootSymlinkOutside = join(scratch, 'root-symlink-outside');
  mkdirSync(rootSymlinkHome, { recursive: true });
  mkdirSync(join(rootSymlinkOutside, 'bin'), { recursive: true });
  mkdirSync(join(rootSymlinkOutside, 'lib'), { recursive: true });
  writeFileSync(join(rootSymlinkOutside, 'VERSION'), '0.0.0-stale\n');
  writeFileSync(
    join(rootSymlinkOutside, 'bin/zlar-protected-records-write'),
    'outside-must-remain\n',
  );
  symlinkSync(rootSymlinkOutside, join(rootSymlinkHome, '.zlar'));
  const rootSymlinkHomeBefore = snapshot(rootSymlinkHome);
  const rootSymlinkOutsideBefore = snapshot(rootSymlinkOutside);
  const rootSymlink = runDryPlan(rootSymlinkHome, [
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--existing-install',
    'upgrade',
  ]);
  equal('symlinked install root plans no removals', 0, rootSymlink.planned_retired_source_removals.length);
  deepEqual(
    'symlinked install root refusal exact',
    [{ path: '~/.zlar', reason: 'symlinked_parent' }],
    rootSymlink.planned_retired_source_parent_refusals,
  );
  equal('symlinked install root blocks cleanup', true, rootSymlink.write_effects_if_real_install_runs.blocked_by_retired_source_cleanup);
  equal('symlinked install root sets generic pre-write exit', true, rootSymlink.existing_install.real_install_would_exit_before_writes);
  deepEqual('symlinked install root leaves home intact', rootSymlinkHomeBefore, snapshot(rootSymlinkHome));
  deepEqual('symlinked install root leaves outside intact', rootSymlinkOutsideBefore, snapshot(rootSymlinkOutside));

  const binSymlinkHome = join(scratch, 'bin-symlink-home');
  const binSymlinkOutside = join(scratch, 'bin-symlink-outside');
  mkdirSync(join(binSymlinkHome, '.zlar/lib'), { recursive: true });
  mkdirSync(binSymlinkOutside, { recursive: true });
  writeFileSync(join(binSymlinkHome, '.zlar/VERSION'), '0.0.0-stale\n');
  writeFileSync(
    join(binSymlinkOutside, 'zlar-protected-records-write'),
    'outside-must-remain\n',
  );
  symlinkSync(binSymlinkOutside, join(binSymlinkHome, '.zlar/bin'));
  const binSymlinkHomeBefore = snapshot(binSymlinkHome);
  const binSymlinkOutsideBefore = snapshot(binSymlinkOutside);
  const binSymlink = runDryPlan(binSymlinkHome, [
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--existing-install',
    'upgrade',
  ]);
  equal('symlinked bin parent plans no removals', 0, binSymlink.planned_retired_source_removals.length);
  deepEqual(
    'symlinked bin parent refusal exact',
    [{ path: '~/.zlar/bin', reason: 'symlinked_parent' }],
    binSymlink.planned_retired_source_parent_refusals,
  );
  equal('symlinked bin parent blocks cleanup', true, binSymlink.write_effects_if_real_install_runs.blocked_by_retired_source_cleanup);
  deepEqual('symlinked bin parent leaves home intact', binSymlinkHomeBefore, snapshot(binSymlinkHome));
  deepEqual('symlinked bin parent leaves outside intact', binSymlinkOutsideBefore, snapshot(binSymlinkOutside));

  const libNonDirectoryHome = join(scratch, 'lib-nondirectory-home');
  mkdirSync(join(libNonDirectoryHome, '.zlar/bin'), { recursive: true });
  writeFileSync(join(libNonDirectoryHome, '.zlar/VERSION'), '0.0.0-stale\n');
  writeFileSync(join(libNonDirectoryHome, '.zlar/lib'), 'not-a-directory\n');
  const libNonDirectoryBefore = snapshot(libNonDirectoryHome);
  const libNonDirectory = runDryPlan(libNonDirectoryHome, [
    '--surface',
    'claude-code',
    '--no-machine-helpers',
    '--existing-install',
    'upgrade',
  ]);
  equal('non-directory lib parent plans no removals', 0, libNonDirectory.planned_retired_source_removals.length);
  deepEqual(
    'non-directory lib parent refusal exact',
    [{ path: '~/.zlar/lib', reason: 'non_directory_parent' }],
    libNonDirectory.planned_retired_source_parent_refusals,
  );
  equal('non-directory lib parent blocks cleanup', true, libNonDirectory.write_effects_if_real_install_runs.blocked_by_retired_source_cleanup);
  equal('non-directory lib parent sets generic pre-write exit', true, libNonDirectory.existing_install.real_install_would_exit_before_writes);
  deepEqual('non-directory lib parent remains byte-identical', libNonDirectoryBefore, snapshot(libNonDirectoryHome));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

section('routing, history, and claim ceiling');
const superseded = read('tests/superseded-source-bound-test-suites.txt')
  .trim()
  .split('\n');
assert(
  'Stage 5 source snapshot is superseded, not rerun as live evidence',
  superseded.includes('test-e1-direct-adapter-factory-source-retirement-v0.mjs'),
);
assert(
  'current cleanup suite is active',
  !superseded.includes('test-future-installer-retired-source-residue-cleanup-v0.mjs'),
);
for (const item of spec.unchanged_historical_fixtures) {
  equal(
    `${item.path} immutable fixture SHA exact at cleanup result checkpoint`,
    item.file_sha256,
    sha(readGitBytes(CLEANUP_RESULT_COMMIT, item.path)),
  );
}
for (const [claim, value] of Object.entries(spec.claim_ceiling)) {
  equal(`claim ceiling remains false: ${claim}`, false, value);
}
equal('side doors remain named', true, spec.side_doors.length >= 8);
equal('integrity does not project closure', false, integrity.projects_lifecycle_closure);
equal('integrity does not project installed retirement', false, integrity.projects_installed_copy_retirement);

process.stdout.write(`\n${assertions} passed, 0 failed out of ${assertions} tests\n`);
