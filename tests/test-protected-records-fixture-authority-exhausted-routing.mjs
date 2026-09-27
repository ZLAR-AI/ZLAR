#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  runProtectedRecordsActivePersistentProfileActionCrossing,
} from '../lib/protected-records-active-persistent-profile-action-crossing.mjs';
import {
  runActivePersistentProfileLifecycleEvidence,
  runActivePersistentProfileRedPathRefusal,
} from '../lib/protected-records-active-persistent-profile-lifecycle.mjs';
import {
  PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MUTATION_AUTHORITY_ABSENT_REASON_CODE,
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_EXHAUSTED_REASON_CODE,
  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed,
} from '../lib/protected-records-fixture-authority-status.mjs';
import {
  closeActivePersistentProfileLiveInstallation,
  runActivePersistentProfileLiveInstallation,
} from '../lib/protected-records-active-persistent-profile-live-installation.mjs';
import {
  runProtectedRecordsInstalledRuntimeProfileRecognitionProof,
} from '../lib/protected-records-installed-runtime-profile-recognition-proof.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256,
  runProtectedRecordsInstalledRuntimeProfileServiceProof,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  runProtectedRecordsInstalledRuntimeProfileTerminalChain,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  buildProtectedRecordsNamedDeploymentProfileReadiness,
} from '../lib/protected-records-named-deployment-profile-readiness.mjs';
import {
  runProtectedRecordsOneTerminalDeploymentProfileProof,
} from '../lib/protected-records-one-terminal-deployment-profile.mjs';
import {
  runProtectedRecordsRuntimeProfileProof,
} from '../lib/protected-records-runtime-profile.mjs';
import {
  runProtectedRecordsRuntimeProfilePreflight,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  runProtectedRecordsRuntimeActivationPreflight,
} from '../lib/protected-records-runtime-activation-preflight.mjs';
import {
  runProtectedRecordsRuntimeLocalActivationProof,
} from '../lib/protected-records-runtime-local-activation.mjs';
import {
  runProtectedRecordsRuntimeProfileInstallationProof,
} from '../lib/protected-records-runtime-profile-installation.mjs';
import {
  buildRecordsWriteTerminalProof,
} from '../lib/records-write-terminal-proof.mjs';
import {
  readProtectedRecordsInstalledSamplePlan,
  readProtectedRecordsInstalledSampleProfile,
} from '../lib/protected-records-installed-proof-samples.mjs';

let pass = 0;
let fail = 0;
let total = 0;

function assert(label, condition, detail = '') {
  total += 1;
  if (condition) {
    pass += 1;
    console.log(`  PASS: ${label}`);
  } else {
    fail += 1;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(
    label,
    expected === actual,
    `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`,
  );
}

function assertExhausted(label, fn) {
  total += 1;
  try {
    fn();
    fail += 1;
    console.log(`  FAIL: ${label} -- expected exhaustion refusal`);
  } catch (error) {
    if (String(error?.message).includes(PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_EXHAUSTED_REASON_CODE)) {
      pass += 1;
      console.log(`  PASS: ${label}`);
    } else {
      fail += 1;
      console.log(`  FAIL: ${label} -- ${error?.message}`);
    }
  }
}

function assertRefusedWith(label, fn, reasonCode) {
  total += 1;
  try {
    fn();
    fail += 1;
    console.log(`  FAIL: ${label} -- expected refusal`);
  } catch (error) {
    if (String(error?.message).includes(reasonCode)) {
      pass += 1;
      console.log(`  PASS: ${label}`);
    } else {
      fail += 1;
      console.log(`  FAIL: ${label} -- ${error?.message}`);
    }
  }
}

function runZlar(args) {
  return spawnSync('bin/zlar', args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

const recognitionArtifact = JSON.parse(readFileSync(
  'tests/fixtures/protected-records-installed-runtime-profile-recognition-proof-artifact-v1.json',
  'utf8',
));
const recognitionSourcePreflightSha256 =
  recognitionArtifact.payload.proof.source_preflight.body_sha256;
const recognitionArtifactBodySha256 =
  '502f303f094bc213a03208ae7edcb490edddd3b7f2e20698915b6010a2ec26c3';

console.log('\n-- source-recorded authority exhaustion --');
assertEqual(
  'current contract SHA is exact',
  '0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba',
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
);
assertExhausted(
  'central fresh-effect assertion refuses',
  () => assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed('test'),
);

console.log('\n-- fresh generation CLI refusals --');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-exhausted-routing-'));
try {
  const commands = [
    'protected-records-installed-runtime-profile-recognition-proof',
    'protected-records-installed-runtime-profile-service-proof',
    'protected-records-installed-runtime-profile-terminal-chain',
    'protected-records-one-terminal-deployment-profile',
  ];
  for (const command of commands) {
    const result = runZlar([command, '--sample']);
    assert(`${command} refuses`, result.status !== 0);
    assertEqual(`${command} emits no stdout`, '', result.stdout);
    assert(
      `${command} names exact exhaustion code`,
      result.stderr.includes(PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_EXHAUSTED_REASON_CODE),
    );
  }

  for (const command of commands.slice(0, 3)) {
    const artifactPath = join(scratch, `${command}.json`);
    const result = runZlar([command, '--sample', '--artifact', artifactPath]);
    assert(`${command} artifact request refuses`, result.status !== 0);
    assert(`${command} artifact is not written`, existsSync(artifactPath) === false);
  }

  console.log('\n-- pinned historical verification remains read-only --');
  const recognitionVerify = runZlar([
    'protected-records-installed-runtime-profile-recognition-proof',
    'verify',
    '--sample',
    '--require-sha',
    recognitionArtifactBodySha256,
    '--require-source-preflight-sha',
    recognitionSourcePreflightSha256,
    '--json',
  ]);
  assertEqual('recognition historical verification exits zero', 0, recognitionVerify.status);
  assertEqual('recognition historical verification emits no stderr', '', recognitionVerify.stderr);
  assertEqual(
    'recognition historical identity matched',
    true,
    JSON.parse(recognitionVerify.stdout).artifact_identity_sha256_matched,
  );

  const serviceVerify = runZlar([
    'protected-records-installed-runtime-profile-service-proof',
    'verify',
    '--sample',
    '--require-sha',
    PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_SERVICE_PROOF_SAMPLE_ARTIFACT_BODY_SHA256,
    '--json',
  ]);
  assertEqual('service historical verification exits zero', 0, serviceVerify.status);
  assertEqual('service historical verification emits no stderr', '', serviceVerify.stderr);
  assertEqual(
    'service historical identity matched',
    true,
    JSON.parse(serviceVerify.stdout).artifact_identity_sha256_matched,
  );

  const terminalVerify = runZlar([
    'protected-records-installed-runtime-profile-terminal-chain',
    'verify',
    '--sample',
    '--require-sha',
    PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
    '--json',
  ]);
  assertEqual('terminal historical verification exits zero', 0, terminalVerify.status);
  assertEqual('terminal historical verification emits no stderr', '', terminalVerify.stderr);
  assertEqual(
    'terminal historical identity matched',
    true,
    JSON.parse(terminalVerify.stdout).artifact_identity_sha256_matched,
  );

  const readiness = buildProtectedRecordsNamedDeploymentProfileReadiness();
  assertEqual(
    'named readiness uses pinned historical artifact',
    'pinned-committed-historical-artifact-verification',
    readiness.source_terminal_chain.source_mode,
  );
  assertEqual(
    'named readiness terminal artifact identity matched',
    true,
    readiness.source_terminal_chain.terminal_artifact_identity_sha256_matched,
  );
  assertEqual(
    'named readiness exact terminal artifact SHA',
    PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
    readiness.source_terminal_chain.terminal_artifact_body_sha256,
  );

  console.log('\n-- active and recursive library routes refuse before writes --');
  const activationRoot = join(scratch, 'active-root');
  const outputDir = join(scratch, 'lifecycle-output');
  const proofTarget = join(scratch, 'proof-target.jsonl');
  const liveInstallReport = join(scratch, 'active-persistent-live-installation.json');
  assertRefusedWith(
    'active persistent live installation refuses before root inspection or creation',
    () => runActivePersistentProfileLiveInstallation({ activationRoot }),
    PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MUTATION_AUTHORITY_ABSENT_REASON_CODE,
  );
  assertRefusedWith(
    'active persistent closeout refuses before root inspection or mutation',
    () => closeActivePersistentProfileLiveInstallation({ activationRoot }),
    PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MUTATION_AUTHORITY_ABSENT_REASON_CODE,
  );
  const liveInstallCli = runZlar([
    'protected-records-active-persistent-profile-live-installation',
    'install',
    '--activation-root', activationRoot,
    '--profile', 'profiles/protected-records-runtime-fixture.profile.json',
    '--runtime-profile-id', 'protected-records-disposable-runtime-profile',
    '--runtime-profile-sha256', 'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469',
    '--expires-at', '2030-01-01T00:00:00.000Z',
    '--now-epoch', '1700000000',
    '--report', liveInstallReport,
    '--json',
  ]);
  assert('active persistent live installation CLI refuses', liveInstallCli.status !== 0);
  assertEqual('active persistent live installation CLI emits no stdout', '', liveInstallCli.stdout);
  assert(
    'active persistent live installation CLI names mutation-authority refusal',
    liveInstallCli.stderr.includes(
      PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MUTATION_AUTHORITY_ABSENT_REASON_CODE,
    ),
  );
  assert('active persistent live installation CLI leaves root absent', existsSync(activationRoot) === false);
  assert('active persistent live installation CLI leaves report absent', existsSync(liveInstallReport) === false);
  assertExhausted(
    'active action crossing refuses before argument or target handling',
    () => runProtectedRecordsActivePersistentProfileActionCrossing({ proofTarget }),
  );
  assertExhausted(
    'active red path refuses before active-root inspection',
    () => runActivePersistentProfileRedPathRefusal({ activationRoot }),
  );
  assertExhausted(
    'active lifecycle refuses before output/root creation',
    () => runActivePersistentProfileLifecycleEvidence({ activationRoot, outputDir }),
  );
  assertExhausted(
    'recognition generator refuses before input validation or scratch setup',
    () => runProtectedRecordsInstalledRuntimeProfileRecognitionProof(),
  );
  assertExhausted(
    'service generator refuses before input validation or scratch setup',
    () => runProtectedRecordsInstalledRuntimeProfileServiceProof(),
  );
  assertExhausted(
    'terminal chain refuses before disposable install-root creation',
    () => runProtectedRecordsInstalledRuntimeProfileTerminalChain(
      readProtectedRecordsInstalledSamplePlan(),
      readProtectedRecordsInstalledSampleProfile(),
    ),
  );
  assertExhausted(
    'one-terminal generator refuses before bridge input validation',
    () => runProtectedRecordsOneTerminalDeploymentProfileProof(),
  );
  assertExhausted(
    'runtime-profile generator refuses before scratch creation',
    () => runProtectedRecordsRuntimeProfileProof(),
  );
  assertExhausted(
    'runtime-profile preflight generator refuses before nested proof execution',
    () => runProtectedRecordsRuntimeProfilePreflight(),
  );
  assertExhausted(
    'runtime activation-preflight generator refuses before nested proof execution',
    () => runProtectedRecordsRuntimeActivationPreflight(),
  );
  assertExhausted(
    'runtime local-activation generator refuses before nested proof execution',
    () => runProtectedRecordsRuntimeLocalActivationProof(),
  );
  assertExhausted(
    'runtime profile-installation generator refuses before install-root creation',
    () => runProtectedRecordsRuntimeProfileInstallationProof(),
  );
  assertExhausted(
    'records-write terminal generator refuses before nested proof execution',
    () => buildRecordsWriteTerminalProof(),
  );
  assert('active root remains absent', existsSync(activationRoot) === false);
  assert('lifecycle output remains absent', existsSync(outputDir) === false);
  assert('proof target remains absent', existsSync(proofTarget) === false);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${pass}/${total} passed${fail ? `, ${fail} failed` : ' ✓'}`);
if (fail) process.exit(1);
