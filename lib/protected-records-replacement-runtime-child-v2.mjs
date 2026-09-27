import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeServiceConfigV2,
  assertProtectedRecordsRuntimeServiceResultV2,
  createProtectedRecordsRuntimeServiceV2,
} from './protected-records-runtime-profile.mjs';

const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const PROJECT_DIR = realpathSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '..'),
);

function die(message, code = 1) {
  let safe = message;
  try {
    assertNoUnsafeProtectedRecordsRuntimeProfileText(safe);
  } catch {
    safe = 'Internal protected-records replacement runtime child failed closed.';
  }
  console.error(`ERROR: ${safe}`);
  process.exit(code);
}

function readBoundedRegularFile(path, label) {
  const status = lstatSync(path);
  if (status.isSymbolicLink() || !status.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file`);
  }
  if (status.size < 2 || status.size > MAX_INPUT_BYTES) {
    throw new Error(`${label} size is outside the accepted boundary`);
  }
  return readFileSync(path, 'utf8');
}

function exactSourceState(expectedCommit) {
  if (!/^[a-f0-9]{40}$/.test(expectedCommit || '')) {
    throw new Error('Internal v2 source commit binding is invalid');
  }
  const env = {
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    HOME: '/var/empty',
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    TZ: 'UTC',
  };
  const head = spawnSync('/usr/bin/git', ['rev-parse', 'HEAD'], {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    env,
  });
  const status = spawnSync(
    '/usr/bin/git',
    ['--no-optional-locks', 'status', '--porcelain'],
    { cwd: PROJECT_DIR, encoding: 'utf8', env },
  );
  const indexFlags = spawnSync('/usr/bin/git', ['ls-files', '-v', '-z'], {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    env,
  });
  const hiddenIndexFlagPresent =
    typeof indexFlags.stdout !== 'string' ||
    indexFlags.stdout
      .split('\0')
      .filter(Boolean)
      .some((entry) => entry[0] !== 'H' || entry[1] !== ' ');
  if (
    head.status !== 0 ||
    status.status !== 0 ||
    indexFlags.status !== 0 ||
    head.stdout.trim() !== expectedCommit ||
    status.stdout !== '' ||
    hiddenIndexFlagPresent
  ) {
    throw new Error('Internal v2 exact source commit is unavailable or dirty');
  }
}

const args = process.argv.slice(2);
const routingMarker = process.env.ZLAR_REPLACEMENT_INTERNAL_CHILD;
if (routingMarker === 'exact-source-rehearsal-v2') {
  if (
    args.length !== 2 ||
    args[0] !== '--source-rehearsal' ||
    !/^[a-f0-9]{40}$/.test(args[1] || '')
  ) {
    die('Internal v2 source rehearsal requires one exact source commit.', 2);
  }
  try {
    exactSourceState(args[1]);
    process.stdout.write(`${JSON.stringify({
      rehearsal_type:
        'zlar.protected-records.replacement-source-snapshot-rehearsal.v2',
      source_commit_oid: args[1],
      exact_source_state_verified: true,
      source_snapshot_read_only: true,
      key_generation_performed: false,
      receipt_signing_performed: false,
      positive_consequence_executed: false,
    })}\n`);
    process.exit(0);
  } catch (error) {
    die(error.message);
  }
}
if (routingMarker !== 'exact-source-single-attempt-v2') {
  die('Internal v2 runtime child is unsupported without the crossing routing marker.', 2);
}

if (args.length !== 2 || args[0] !== '--config' || !args[1]) {
  die('Internal v2 runtime child requires exactly --config <file>.', 2);
}

try {
  const config = JSON.parse(
    readBoundedRegularFile(args[1], 'Internal v2 runtime config'),
  );
  assertProtectedRecordsRuntimeServiceConfigV2(config);
  exactSourceState(config.authority_source_precondition.source_commit_oid);
  const rawInput = readFileSync(0, 'utf8');
  if (Buffer.byteLength(rawInput, 'utf8') > MAX_INPUT_BYTES) {
    throw new Error('Internal v2 request exceeds the accepted boundary');
  }
  const lines = rawInput.split(/\n/).filter((line) => line.trim());
  if (lines.length !== 1) {
    throw new Error('Internal v2 runtime child requires exactly one request');
  }
  const request = JSON.parse(lines[0]);
  const result = createProtectedRecordsRuntimeServiceV2(config)
    .applyRequest(request);
  assertProtectedRecordsRuntimeServiceResultV2(result);
  const output = `${JSON.stringify(result)}\n`;
  assertNoUnsafeProtectedRecordsRuntimeProfileText(output);
  process.stdout.write(output);
} catch (error) {
  die(error.message);
}
