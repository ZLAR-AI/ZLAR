import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  realpathSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PROJECT_DIR = realpathSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '..'),
);

export function protectedRecordsReplacementMinimalChildEnvironmentV2() {
  return {
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    HOME: '/var/empty',
    LANG: 'C',
    LC_ALL: 'C',
    NO_COLOR: '1',
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    TZ: 'UTC',
  };
}

export function protectedRecordsReplacementGitSourceStateV2(
  projectDir = PROJECT_DIR,
) {
  const sourceRepositoryRealpath = realpathSync(projectDir);
  const env = protectedRecordsReplacementMinimalChildEnvironmentV2();
  const head = spawnSync('/usr/bin/git', ['rev-parse', 'HEAD'], {
    cwd: sourceRepositoryRealpath,
    encoding: 'utf8',
    env,
  });
  const status = spawnSync(
    '/usr/bin/git',
    ['--no-optional-locks', 'status', '--porcelain'],
    { cwd: sourceRepositoryRealpath, encoding: 'utf8', env },
  );
  const indexFlags = spawnSync('/usr/bin/git', ['ls-files', '-v', '-z'], {
    cwd: sourceRepositoryRealpath,
    encoding: 'utf8',
    env,
  });
  if (head.status !== 0 || status.status !== 0 || indexFlags.status !== 0) {
    throw new Error('Could not establish the exact local source state');
  }
  const hiddenIndexFlagPresent =
    typeof indexFlags.stdout !== 'string' ||
    indexFlags.stdout
      .split('\0')
      .filter(Boolean)
      .some((entry) => entry[0] !== 'H' || entry[1] !== ' ');
  if (hiddenIndexFlagPresent) {
    throw new Error(
      'Replacement crossing refuses assume-unchanged, skip-worktree, or nonstandard Git index flags',
    );
  }
  return Object.freeze({
    sourceCommitOid: head.stdout.trim(),
    sourceRepositoryRealpath,
    sourceWorktreeClean: status.stdout === '',
  });
}

export function materializeProtectedRecordsReplacementSourceSnapshotV2(
  parentDir,
  sourceCommitOid,
) {
  if (!/^[a-f0-9]{40}$/.test(sourceCommitOid || '')) {
    throw new Error('Exact source snapshot commit must be a Git SHA-1 object id');
  }
  const snapshotDir = join(parentDir, 'source-snapshot');
  const emptyTemplateDir = join(parentDir, 'empty-git-template');
  mkdirSync(emptyTemplateDir, { mode: 0o700, recursive: false });
  const clone = spawnSync(
    '/usr/bin/git',
    [
      '-c',
      'core.hooksPath=/dev/null',
      'clone',
      '--no-local',
      '--no-checkout',
      '--quiet',
      '--template',
      emptyTemplateDir,
      PROJECT_DIR,
      snapshotDir,
    ],
    {
      encoding: 'utf8',
      env: protectedRecordsReplacementMinimalChildEnvironmentV2(),
    },
  );
  if (clone.status !== 0) {
    throw new Error('Could not materialize the exact source repository');
  }
  const checkout = spawnSync(
    '/usr/bin/git',
    [
      '-c',
      'core.hooksPath=/dev/null',
      'checkout',
      '--detach',
      '--quiet',
      sourceCommitOid,
    ],
    {
      cwd: snapshotDir,
      encoding: 'utf8',
      env: protectedRecordsReplacementMinimalChildEnvironmentV2(),
    },
  );
  if (checkout.status !== 0) {
    throw new Error('Could not check out the exact source commit');
  }
  const state = protectedRecordsReplacementGitSourceStateV2(snapshotDir);
  if (
    state.sourceWorktreeClean !== true ||
    state.sourceCommitOid !== sourceCommitOid
  ) {
    throw new Error('Materialized source snapshot does not match the exact commit');
  }
  const runtimeServicePath = realpathSync(
    join(snapshotDir, 'lib/protected-records-replacement-runtime-child-v2.mjs'),
  );
  return Object.freeze({
    snapshotDir: realpathSync(snapshotDir),
    runtimeServicePath,
  });
}

export function freezeProtectedRecordsReplacementSnapshotReadOnlyV2(path) {
  const status = lstatSync(path);
  if (status.isSymbolicLink()) {
    throw new Error('Materialized source snapshot contains an unsupported symlink');
  }
  if (status.isDirectory()) {
    for (const entry of readdirSync(path)) {
      freezeProtectedRecordsReplacementSnapshotReadOnlyV2(join(path, entry));
    }
    chmodSync(path, 0o500);
    return;
  }
  if (!status.isFile()) {
    throw new Error('Materialized source snapshot contains a non-file entry');
  }
  chmodSync(path, status.mode & 0o111 ? 0o500 : 0o400);
}
