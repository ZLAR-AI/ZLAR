#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_EVIDENCE_MODEL,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_SOURCE_STATE_BOUNDARY,
  CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE,
  assertClaudeCodeHookContractReplayProof,
} from '../lib/claude-code-hook-contract-replay-proof.mjs';
import {
  SAMPLE_DEPLOYMENT_PROFILE_DISPLAY_PATH,
  SAMPLE_DEPLOYMENT_PROFILE_TEXT_SHA256,
  SAMPLE_PLAN_DISPLAY_PATH,
  SAMPLE_PLAN_TEXT_SHA256,
  SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256,
  SAMPLE_PREFLIGHT_ARTIFACT_DISPLAY_PATH,
  SAMPLE_PROFILE_DISPLAY_PATH,
  SAMPLE_PROFILE_TEXT_SHA256,
  buildCanonicalProtectedRecordsInstalledPreflightSampleArtifact,
  protectedRecordsInstalledProofSampleContext,
  readProtectedRecordsInstalledSamplePlan,
  readProtectedRecordsInstalledSampleProfile,
  readProtectedRecordsOneTerminalDeploymentProfileSampleText,
} from '../lib/protected-records-installed-proof-samples.mjs';
import {
  parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText,
} from '../lib/protected-records-installed-runtime-profile-preflight.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileRecognitionProof,
} from '../lib/protected-records-installed-runtime-profile-recognition-proof.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileServiceProof,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  assertProtectedRecordsInstalledRuntimeProfileTerminalChain,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  assertProtectedRecordsOneTerminalDeploymentProfile,
} from '../lib/protected-records-one-terminal-deployment-profile.mjs';

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

function sha256FileWithShasum(path) {
  const run = spawnSync('shasum', ['-a', '256', path], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
  if (run.status !== 0) {
    throw new Error(`shasum failed for ${path}`);
  }
  return run.stdout.trim().split(/\s+/)[0];
}

function runInstalledZlar(root, args) {
  return spawnSync(join(root, 'bin', 'zlar'), args, {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

function parseJsonStdout(run) {
  try {
    return JSON.parse(run.stdout);
  } catch (err) {
    throw new Error(`could not parse JSON stdout: ${err.message}\n${run.stdout.slice(0, 200)}`);
  }
}

const unsafeOutputPattern =
  /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

section('static installed proof context boundary');
const installedSampleModuleSource = readFileSync('lib/protected-records-installed-proof-samples.mjs', 'utf8');
for (const forbidden of [
  'local-proof-pack',
  'proof-smoke',
  'product-proof-path',
  'north-star',
  'release-forward',
  'github',
]) {
  assert(`installed sample context does not import ${forbidden}`, !installedSampleModuleSource.includes(forbidden));
}

const installedSafeFileForbiddenFragments = {
  'bin/zlar-protected-records-installed-runtime-profile-preflight': [
    'fileURLToPath',
    'SAMPLE_ARTIFACT_PATH',
    '../tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json',
  ],
  'bin/zlar-protected-records-installed-runtime-profile-service-proof': [
    'const SAMPLE_ARTIFACT_PATH',
    'new URL(`../${SAMPLE_ARTIFACT_DISPLAY_PATH}`',
    '../tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json',
  ],
  'bin/zlar-protected-records-installed-runtime-profile-recognition-proof': [
    'const SAMPLE_ARTIFACT_PATH',
    'new URL(`../${SAMPLE_ARTIFACT_DISPLAY_PATH}`',
    '../tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json',
  ],
  'bin/zlar-protected-records-installed-runtime-profile-terminal-chain': [
    'const SAMPLE_PLAN_PATH',
    'const SAMPLE_PROFILE_PATH',
    'new URL(`../${SAMPLE_PLAN_DISPLAY_PATH}`',
    'new URL(`../${SAMPLE_PROFILE_DISPLAY_PATH}`',
    'readJsonInput(SAMPLE_PLAN_PATH',
    'readJsonInput(SAMPLE_PROFILE_PATH',
  ],
  'lib/protected-records-one-terminal-deployment-profile.mjs': [
    'SAMPLE_DEPLOYMENT_PROFILE_PATH',
    'SAMPLE_RUNTIME_PROFILE_PATH',
    'SAMPLE_PREFLIGHT_ARTIFACT_PATH',
    'fileURLToPath',
    'readFileSync',
  ],
};
for (const [path, fragments] of Object.entries(installedSafeFileForbiddenFragments)) {
  const source = readFileSync(path, 'utf8');
  for (const fragment of fragments) {
    assert(`${path} avoids installed-unsafe fixture fragment: ${fragment}`, !source.includes(fragment));
  }
}

section('canonical installed proof sample context');
const context = protectedRecordsInstalledProofSampleContext();
assertEqual('sample context type', 'zlar-protected-records-installed-proof-sample-context-v1', context.sample_context_type);
assertEqual('sample context repo paths not required', false, context.repo_paths_required_at_runtime);
assertEqual('sample context no source freshness', false, context.source_freshness_claimed);
assertEqual('sample context no current-machine governance', false, context.current_machine_governance_proven);
assertEqual('deployment fixture sha matches committed file', sha256FileWithShasum(SAMPLE_DEPLOYMENT_PROFILE_DISPLAY_PATH), SAMPLE_DEPLOYMENT_PROFILE_TEXT_SHA256);
assertEqual('plan fixture sha matches committed file', sha256FileWithShasum(SAMPLE_PLAN_DISPLAY_PATH), SAMPLE_PLAN_TEXT_SHA256);
assertEqual('profile fixture sha matches committed file', sha256FileWithShasum(SAMPLE_PROFILE_DISPLAY_PATH), SAMPLE_PROFILE_TEXT_SHA256);
const committedPreflightArtifact = parseProtectedRecordsInstalledRuntimeProfilePreflightArtifactText(
  readFileSync(SAMPLE_PREFLIGHT_ARTIFACT_DISPLAY_PATH, 'utf8')
);
assertEqual('generated preflight body sha matches committed fixture', committedPreflightArtifact.integrity.body_sha256, SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256);
const generatedPreflightArtifact = buildCanonicalProtectedRecordsInstalledPreflightSampleArtifact();
assertEqual('canonical preflight body sha stable', SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256, generatedPreflightArtifact.integrity.body_sha256);
assertEqual(
  'canonical preflight matches committed fixture body',
  JSON.stringify(committedPreflightArtifact.payload),
  JSON.stringify(generatedPreflightArtifact.payload)
);
const plan = readProtectedRecordsInstalledSamplePlan();
const profile = readProtectedRecordsInstalledSampleProfile();
assertEqual('canonical plan runtime profile id', 'protected-records-disposable-runtime-profile', plan.runtime_profile_id);
assertEqual('canonical profile runtime profile id', 'protected-records-disposable-runtime-profile', profile.runtime_profile_id);
const deploymentProfile = JSON.parse(readProtectedRecordsOneTerminalDeploymentProfileSampleText());
assert('deployment profile validates', assertProtectedRecordsOneTerminalDeploymentProfile(deploymentProfile));

section('temp installed layout without repo fixture paths');
const root = mkdtempSync(join(tmpdir(), 'zlar-installed-proof-context-'));
try {
  cpSync('bin', join(root, 'bin'), { recursive: true });
  cpSync('lib', join(root, 'lib'), { recursive: true });
  cpSync('adapters/claude-code', join(root, 'adapters', 'claude-code'), { recursive: true });
  assertEqual('temp layout has no profiles directory', false, existsSync(join(root, 'profiles')));
  assertEqual('temp layout has no tests directory', false, existsSync(join(root, 'tests')));

  const hookRun = runInstalledZlar(root, ['claude-code-hook-contract-replay-proof', '--json']);
  assertEqual('installed hook replay exits zero', 0, hookRun.status);
  assertEqual('installed hook replay emits no stderr', '', hookRun.stderr);
  assert('installed hook replay output privacy safe', !unsafeOutputPattern.test(hookRun.stdout));
  const hookReport = parseJsonStdout(hookRun);
  assert('installed hook replay validates', assertClaudeCodeHookContractReplayProof(hookReport));
  assertEqual('installed hook replay proof type', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE, hookReport.proof_type);
  assertEqual('installed hook replay adapter source', 'installed', hookReport.adapter_source);
  assertEqual('installed hook replay evidence model', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_EVIDENCE_MODEL, hookReport.evidence_model);
  assertEqual('installed hook replay source state unavailable', false, hookReport.source_state.status_known);
  assertEqual('installed hook replay source boundary', CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_SOURCE_STATE_BOUNDARY, hookReport.source_state_boundary);
  assertEqual('installed hook replay no source freshness', true, hookReport.non_claims.some((item) => item.includes('source freshness')));

  const explicitInstalledRun = runInstalledZlar(root, [
    'claude-code-hook-contract-replay-proof',
    '--adapter-source',
    'installed',
    '--json',
  ]);
  assertEqual('explicit installed hook replay exits zero', 0, explicitInstalledRun.status);
  assertEqual('explicit installed hook replay emits no stderr', '', explicitInstalledRun.stderr);
  const explicitInstalledReport = parseJsonStdout(explicitInstalledRun);
  assertEqual('explicit installed adapter source', 'installed', explicitInstalledReport.adapter_source);

  const repoSourceRun = runInstalledZlar(root, [
    'claude-code-hook-contract-replay-proof',
    '--adapter-source',
    'repo',
    '--json',
  ]);
  assert('repo-source hook replay refuses unknown source state', repoSourceRun.status !== 0);
  assertEqual('repo-source refusal emits no stdout', '', repoSourceRun.stdout);
  assert('repo-source refusal names source status', repoSourceRun.stderr.includes('source status must be known'));
  assert('repo-source refusal privacy safe', !unsafeOutputPattern.test(repoSourceRun.stderr));

  const preflightRun = runInstalledZlar(root, [
    'protected-records-installed-runtime-profile-preflight',
    'verify',
    '--sample',
    '--json',
  ]);
  assertEqual('installed preflight sample exits zero', 0, preflightRun.status);
  assertEqual('installed preflight sample emits no stderr', '', preflightRun.stderr);
  const preflightVerification = parseJsonStdout(preflightRun);
  assertEqual('installed preflight sample body sha', SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256, preflightVerification.body_sha256);
  assertEqual('installed preflight sample no current-machine governance', false, preflightVerification.current_machine_governance_proven);

  const serviceRun = runInstalledZlar(root, [
    'protected-records-installed-runtime-profile-service-proof',
    '--sample',
    '--json',
  ]);
  assertEqual('installed service sample exits zero', 0, serviceRun.status);
  assertEqual('installed service sample emits no stderr', '', serviceRun.stderr);
  const serviceReport = parseJsonStdout(serviceRun);
  assert('installed service sample validates', assertProtectedRecordsInstalledRuntimeProfileServiceProof(serviceReport));
  assertEqual('installed service sample source preflight sha', SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256, serviceReport.source_preflight.body_sha256);
  assertEqual('installed service sample no production downstream', false, serviceReport.proof_boundary.production_downstream_recognition);

  const recognitionRun = runInstalledZlar(root, [
    'protected-records-installed-runtime-profile-recognition-proof',
    '--sample',
    '--json',
  ]);
  assertEqual('installed recognition sample exits zero', 0, recognitionRun.status);
  assertEqual('installed recognition sample emits no stderr', '', recognitionRun.stderr);
  const recognitionReport = parseJsonStdout(recognitionRun);
  assert('installed recognition sample validates', assertProtectedRecordsInstalledRuntimeProfileRecognitionProof(recognitionReport));
  assertEqual('installed recognition sample source preflight sha', SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256, recognitionReport.source_preflight.body_sha256);
  assertEqual('installed recognition sample no current-machine governance', false, recognitionReport.proof_boundary.current_machine_governance_proven);

  const terminalRun = runInstalledZlar(root, [
    'protected-records-installed-runtime-profile-terminal-chain',
    '--sample',
    '--json',
  ]);
  assertEqual('installed terminal-chain sample exits zero', 0, terminalRun.status);
  assertEqual('installed terminal-chain sample emits no stderr', '', terminalRun.stderr);
  const terminalReport = parseJsonStdout(terminalRun);
  assert('installed terminal-chain sample validates', assertProtectedRecordsInstalledRuntimeProfileTerminalChain(terminalReport));
  assertEqual('installed terminal-chain generated preflight sha', SAMPLE_PREFLIGHT_ARTIFACT_BODY_SHA256, terminalReport.generated_preflight.artifact_body_sha256);
  assertEqual('installed terminal-chain no current-machine governance', false, terminalReport.side_door_report.current_machine_governance_proven);
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
