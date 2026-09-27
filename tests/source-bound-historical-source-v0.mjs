import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const SOURCE_BOUND_HISTORICAL_ANALYZED_COMMIT_V0 =
  'e7c621927df35eb31cf3f0dfc1ea2a42df6d5dd5';

function readHistoricalGitBlob(projectDir, relativePath) {
  const run = spawnSync(
    'git',
    [
      'show',
      `${SOURCE_BOUND_HISTORICAL_ANALYZED_COMMIT_V0}:${relativePath}`,
    ],
    {
      cwd: projectDir,
      encoding: null,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (run.error || run.status !== 0 || !Buffer.isBuffer(run.stdout)) {
    throw new Error(
      `Historical source blob is unavailable for ${relativePath}`,
    );
  }
  return run.stdout;
}

export function sourceBoundHistoricalSourceFilesV0(projectDir, sourcePaths) {
  return Object.fromEntries(
    Object.entries(sourcePaths).map(([role, relativePath]) => [
      role,
      readHistoricalGitBlob(projectDir, relativePath),
    ]),
  );
}

export function writeSourceBoundHistoricalRootV0({
  projectDir,
  rootDir,
  sourcePaths,
}) {
  const sourceFiles = sourceBoundHistoricalSourceFilesV0(projectDir, sourcePaths);
  for (const [role, relativePath] of Object.entries(sourcePaths)) {
    const outputPath = join(rootDir, relativePath);
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, sourceFiles[role], { mode: 0o600 });
  }
  return rootDir;
}
