#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

function fixtureSha256(path) {
  return JSON.parse(readFileSync(path, 'utf8')).integrity.body_sha256;
}

function runZlar(args) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const GENERIC_REQUIRED_SHA_MISMATCH_FRAGMENT =
  'does not match required --require-sha value';
const GENERIC_REQUIRED_SHA_MALFORMED_FRAGMENT =
  '--require-sha must be a 64-character lowercase SHA-256 hex digest';

const verifierCases = [
  {
    name: 'service preflight',
    args: ['protected-records-service-preflight', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-service-preflight-artifact-v1.json'),
  },
  {
    name: 'runtime activation preflight',
    args: ['protected-records-runtime-activation-preflight', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json'),
  },
  {
    name: 'runtime local activation',
    args: ['protected-records-runtime-local-activation', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-runtime-local-activation-artifact-v1.json'),
  },
  {
    name: 'runtime profile installation',
    args: ['protected-records-runtime-profile-installation', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-runtime-profile-installation-artifact-v1.json'),
  },
  {
    name: 'installed runtime profile preflight',
    args: ['protected-records-installed-runtime-profile-preflight', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json'),
  },
  {
    name: 'installed runtime profile service proof',
    args: ['protected-records-installed-runtime-profile-service-proof', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-installed-runtime-profile-service-proof-artifact-v1.json'),
    mismatchFragment:
      'Installed service proof artifact does not match the caller-supplied expected SHA-256 identity',
    malformedFragment:
      'Installed service proof artifact expected identity must be SHA-256 hex',
  },
  {
    name: 'installed runtime profile recognition proof',
    args: ['protected-records-installed-runtime-profile-recognition-proof', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-installed-runtime-profile-recognition-proof-artifact-v1.json'),
    mismatchFragment:
      'Installed recognition proof artifact does not match the caller-supplied expected SHA-256 identity',
    malformedFragment:
      'Installed recognition proof artifact expected identity must be SHA-256 hex',
  },
  {
    name: 'installed runtime profile terminal chain',
    args: ['protected-records-installed-runtime-profile-terminal-chain', 'verify', '--sample'],
    sha256: fixtureSha256('tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json'),
    mismatchFragment:
      'Protected records installed runtime profile terminal chain artifact does not match the caller-supplied expected SHA-256 identity',
    malformedFragment:
      'Protected records installed runtime profile terminal chain artifact expected identity must be SHA-256 hex',
  },
];

section('matching required artifact sha');
for (const verifier of verifierCases) {
  const textRun = runZlar([...verifier.args, '--require-sha', verifier.sha256]);
  assertEqual(`${verifier.name} text exits zero`, 0, textRun.status);
  assertEqual(`${verifier.name} text emits no stderr`, '', textRun.stderr);
  assert(`${verifier.name} text reports required sha`, textRun.stdout.includes(`required_body_sha256=${verifier.sha256}`));
  assert(`${verifier.name} text reports required sha match`, textRun.stdout.includes('required_body_sha256_matched=true'));
  assert(`${verifier.name} text output is privacy safe`, !unsafeOutputPattern.test(textRun.stdout));

  const jsonRun = runZlar([...verifier.args, '--require-sha', verifier.sha256, '--json']);
  assertEqual(`${verifier.name} json exits zero`, 0, jsonRun.status);
  assertEqual(`${verifier.name} json emits no stderr`, '', jsonRun.stderr);
  assert(`${verifier.name} json output is privacy safe`, !unsafeOutputPattern.test(jsonRun.stdout));
  const verification = JSON.parse(jsonRun.stdout);
  assertEqual(`${verifier.name} json body sha`, verifier.sha256, verification.body_sha256);
  assertEqual(`${verifier.name} json required sha`, verifier.sha256, verification.required_body_sha256);
  assertEqual(`${verifier.name} json required sha matched`, true, verification.required_body_sha256_matched);
}

section('mismatched required artifact sha refuses before stdout');
const mismatchedSha = '0'.repeat(64);
for (const verifier of verifierCases) {
  const mismatchRun = runZlar([...verifier.args, '--require-sha', mismatchedSha, '--json']);
  assert(`${verifier.name} mismatch exits nonzero`, mismatchRun.status !== 0);
  assertEqual(`${verifier.name} mismatch emits no stdout`, '', mismatchRun.stdout);
  assert(
    `${verifier.name} mismatch names required sha`,
    mismatchRun.stderr.includes(
      verifier.mismatchFragment ?? GENERIC_REQUIRED_SHA_MISMATCH_FRAGMENT,
    ),
  );
  assert(`${verifier.name} mismatch stderr is privacy safe`, !unsafeOutputPattern.test(mismatchRun.stderr));
}

section('malformed required artifact sha refuses before stdout');
for (const verifier of verifierCases) {
  const malformedRun = runZlar([...verifier.args, '--require-sha', 'abc', '--json']);
  assert(`${verifier.name} malformed exits nonzero`, malformedRun.status !== 0);
  assertEqual(`${verifier.name} malformed emits no stdout`, '', malformedRun.stdout);
  assert(
    `${verifier.name} malformed names required sha format`,
    malformedRun.stderr.includes(
      verifier.malformedFragment ?? GENERIC_REQUIRED_SHA_MALFORMED_FRAGMENT,
    ),
  );
  assert(`${verifier.name} malformed stderr is privacy safe`, !unsafeOutputPattern.test(malformedRun.stderr));
}

section('missing required artifact sha value refuses');
const missingValueRun = runZlar([
  'protected-records-service-preflight',
  'verify',
  '--sample',
  '--require-sha',
]);
assert('missing value exits nonzero', missingValueRun.status !== 0);
assertEqual('missing value emits no stdout', '', missingValueRun.stdout);
assert('missing value names missing value', missingValueRun.stderr.includes('Missing value for --require-sha'));
assert('missing value stderr is privacy safe', !unsafeOutputPattern.test(missingValueRun.stderr));

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
