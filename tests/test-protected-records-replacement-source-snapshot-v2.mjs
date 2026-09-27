import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  freezeProtectedRecordsReplacementSnapshotReadOnlyV2,
  materializeProtectedRecordsReplacementSourceSnapshotV2,
  protectedRecordsReplacementGitSourceStateV2,
  protectedRecordsReplacementMinimalChildEnvironmentV2,
} from '../lib/protected-records-replacement-source-snapshot-v2.mjs';

let assertions = 0;

function equal(label, expected, actual) {
  assertions += 1;
  if (expected !== actual) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function thawForRemoval(path) {
  const status = lstatSync(path);
  if (status.isDirectory()) {
    chmodSync(path, 0o700);
    for (const entry of readdirSync(path)) {
      thawForRemoval(join(path, entry));
    }
  } else if (status.isFile()) {
    chmodSync(path, 0o600);
  }
}

const parentState = protectedRecordsReplacementGitSourceStateV2();
equal('parent source commit is exact Git SHA-1', true, /^[a-f0-9]{40}$/.test(parentState.sourceCommitOid));
equal('parent source worktree is clean', true, parentState.sourceWorktreeClean);

const scratch = mkdtempSync(
  join(tmpdir(), 'zlar-replacement-source-snapshot-v2-'),
);
let snapshotDir = '';
try {
  const snapshot = materializeProtectedRecordsReplacementSourceSnapshotV2(
    scratch,
    parentState.sourceCommitOid,
  );
  snapshotDir = snapshot.snapshotDir;
  const materializedState = protectedRecordsReplacementGitSourceStateV2(
    snapshot.snapshotDir,
  );
  equal('materialized snapshot commit matches', parentState.sourceCommitOid, materializedState.sourceCommitOid);
  equal('materialized snapshot is clean', true, materializedState.sourceWorktreeClean);

  freezeProtectedRecordsReplacementSnapshotReadOnlyV2(snapshot.snapshotDir);
  equal('snapshot root has no write bits', 0, statSync(snapshot.snapshotDir).mode & 0o222);
  equal('runtime child has no write bits', 0, statSync(snapshot.runtimeServicePath).mode & 0o222);

  const rehearsal = spawnSync(
    process.execPath,
    [
      snapshot.runtimeServicePath,
      '--source-rehearsal',
      parentState.sourceCommitOid,
    ],
    {
      cwd: snapshot.snapshotDir,
      encoding: 'utf8',
      env: {
        ...protectedRecordsReplacementMinimalChildEnvironmentV2(),
        ZLAR_REPLACEMENT_INTERNAL_CHILD: 'exact-source-rehearsal-v2',
      },
    },
  );
  equal('read-only internal-child source rehearsal exits zero', 0, rehearsal.status);
  const evidence = JSON.parse(rehearsal.stdout);
  equal('rehearsal exact source verified', true, evidence.exact_source_state_verified);
  equal('rehearsal generated no key', false, evidence.key_generation_performed);
  equal('rehearsal signed no receipt', false, evidence.receipt_signing_performed);
  equal('rehearsal executed no positive consequence', false, evidence.positive_consequence_executed);

  const missingMarker = spawnSync(
    process.execPath,
    [snapshot.runtimeServicePath, '--source-rehearsal', parentState.sourceCommitOid],
    {
      cwd: snapshot.snapshotDir,
      encoding: 'utf8',
      env: protectedRecordsReplacementMinimalChildEnvironmentV2(),
    },
  );
  equal('source rehearsal without routing marker refuses', 2, missingMarker.status);
  equal('source rehearsal refusal emits no success body', '', missingMarker.stdout);
} finally {
  if (snapshotDir) thawForRemoval(snapshotDir);
  rmSync(scratch, { recursive: true, force: true });
}

console.log(
  `protected records replacement source snapshot v2: ${assertions}/${assertions} assertions passed`,
);
