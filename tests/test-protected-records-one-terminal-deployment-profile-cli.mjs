#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertProtectedRecordsOneTerminalDeploymentProfileProof,
} from '../lib/protected-records-one-terminal-deployment-profile.mjs';
import {
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
} from '../lib/protected-records-runtime-profile.mjs';

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
const PROFILE_PATH = 'profiles/protected-records-one-terminal-deployment-profile.fixture.json';
const RUNTIME_PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const PREFLIGHT_ARTIFACT_PATH =
  'tests/fixtures/protected-records-installed-runtime-profile-preflight-artifact-v1.json';

function runZlar(args, options = {}) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

console.log('\n-- protected records one-terminal deployment profile cli --');

section('text summary');
const textRun = runZlar(['protected-records-one-terminal-deployment-profile', '--sample']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records One-Terminal Deployment Profile Proof v1'));
assert('text summary includes sample input mode', textRun.stdout.includes('input_mode=sample'));
assert('text summary includes source hash binding', textRun.stdout.includes('source_text_hashes_bound=true'));
assert('text summary includes explicit id+sha', textRun.stdout.includes('selected_by_explicit_id_and_sha=true'));
assert('text summary includes no latest', textRun.stdout.includes('selects_latest_profile=false'));
assert('text summary includes preflight verified', textRun.stdout.includes('preflight_artifact_verified=true'));
assert('text summary includes recognized mutation', textRun.stdout.includes('recognized_receipt_mutates_once=true'));
assert('text summary includes authority refusal', textRun.stdout.includes('agent_supplied_authority_refused_before_mutation=true'));
assert('text summary includes deployment authority refusals', textRun.stdout.includes('deployment_profile_authority_refusals_before_service_proof=true'));
assert('text summary includes stale artifact refusal', textRun.stdout.includes('stale_deployment_profile_artifact_refused_before_service_proof=true'));
assert('text summary includes profile mismatch refusal', textRun.stdout.includes('profile_recognition_mismatch_refused_before_service_proof=true'));
assert('text summary includes direct API refusal', textRun.stdout.includes('direct_api_refused_before_mutation=true'));
assert('text summary includes production non-claim', textRun.stdout.includes('production_downstream_recognition=false'));
assert('text summary privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(textRun.stdout));

section('json summary');
const jsonRun = runZlar(['protected-records-one-terminal-deployment-profile', '--sample', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report validates', assertProtectedRecordsOneTerminalDeploymentProfileProof(report));
assertEqual('json proof type', 'zlar-protected-records-one-terminal-deployment-profile-proof-v1', report.proof_type);
assertEqual('json input mode sample', 'sample', report.input_provenance.input_mode);
assertEqual('json source paths safe', true, report.input_provenance.source_paths_public_safe);
assertEqual('json absolute paths not emitted', false, report.input_provenance.absolute_paths_emitted);
assertEqual('json selected by explicit id and sha', true, report.selected_runtime_profile.selected_by_explicit_id_and_sha);
assertEqual('json no latest selection', false, report.selected_runtime_profile.selects_latest_profile);
assertEqual('json preflight verified', true, report.preflight_bridge.verified);
assertEqual('json recognized mutates once', true, report.service_proof_bridge.recognized_receipt_mutates_once);
assertEqual('json all refusals before mutation', true, report.service_proof_bridge.all_refusals_before_mutation);
assertEqual('json agent authority refused before mutation', true, report.service_proof_bridge.agent_supplied_authority_refused_before_mutation);
assertEqual('json deployment authority refusals before service proof', true, report.deployment_profile_authority_refusals.all_refused_before_service_proof);
assertEqual('json stale artifact refused before service proof', true, report.deployment_profile_authority_refusals.stale_deployment_profile_artifact_refused_before_service_proof);
assertEqual('json profile mismatch refused before service proof', true, report.deployment_profile_authority_refusals.profile_recognition_mismatch_refused_before_service_proof);
assertEqual('json latest selection refused before service proof', true, report.deployment_profile_authority_refusals.latest_profile_selection_refused_before_service_proof);
assertEqual('json request authority refused before service proof', true, report.deployment_profile_authority_refusals.request_stream_authority_material_refused_before_service_proof);
assertEqual('json current machine false', false, report.proof_boundary.current_machine_governance);
assertEqual('json production authority false', false, report.proof_boundary.production_authority);

section('explicit file inputs');
const explicitRun = runZlar([
  'protected-records-one-terminal-deployment-profile',
  '--profile',
  PROFILE_PATH,
  '--runtime-profile',
  RUNTIME_PROFILE_PATH,
  '--preflight-artifact',
  PREFLIGHT_ARTIFACT_PATH,
  '--json',
]);
assertEqual('explicit command exits zero', 0, explicitRun.status);
assertEqual('explicit command emits no stderr', '', explicitRun.stderr);
const explicitReport = JSON.parse(explicitRun.stdout);
assert('explicit report validates', assertProtectedRecordsOneTerminalDeploymentProfileProof(explicitReport));
assertEqual('explicit report input mode', 'explicit-files', explicitReport.input_provenance.input_mode);
assertEqual('explicit deployment profile source', 'explicit-file', explicitReport.input_provenance.deployment_profile.source);
assertEqual('explicit deployment profile display path', PROFILE_PATH, explicitReport.input_provenance.deployment_profile.display_path);
assertEqual('explicit runtime profile display path', RUNTIME_PROFILE_PATH, explicitReport.input_provenance.runtime_profile.display_path);
assertEqual('explicit preflight artifact display path', PREFLIGHT_ARTIFACT_PATH, explicitReport.input_provenance.preflight_artifact.display_path);
assertEqual('explicit absolute paths not emitted', false, explicitReport.input_provenance.absolute_paths_emitted);
assertEqual('explicit report deployment profile sha stable', report.deployment_profile.profile_sha256, explicitReport.deployment_profile.profile_sha256);
assertEqual('explicit report runtime profile sha stable', report.selected_runtime_profile.profile_sha256, explicitReport.selected_runtime_profile.profile_sha256);

section('stdin deployment profile input');
const profileText = readFileSync(PROFILE_PATH, 'utf8');
const stdinRun = runZlar([
  'protected-records-one-terminal-deployment-profile',
  '--profile',
  '-',
  '--runtime-profile',
  RUNTIME_PROFILE_PATH,
  '--preflight-artifact',
  PREFLIGHT_ARTIFACT_PATH,
  '--json',
], { input: profileText });
assertEqual('stdin command exits zero', 0, stdinRun.status);
assertEqual('stdin command emits no stderr', '', stdinRun.stderr);
const stdinReport = JSON.parse(stdinRun.stdout);
assert('stdin report validates', assertProtectedRecordsOneTerminalDeploymentProfileProof(stdinReport));
assertEqual('stdin input mode', 'explicit-files', stdinReport.input_provenance.input_mode);
assertEqual('stdin deployment profile source', 'stdin-redacted', stdinReport.input_provenance.deployment_profile.source);
assertEqual('stdin deployment profile path redacted', '<stdin>', stdinReport.input_provenance.deployment_profile.display_path);
assertEqual('stdin deployment profile hash stable', explicitReport.input_provenance.deployment_profile.text_sha256, stdinReport.input_provenance.deployment_profile.text_sha256);

section('fail closed CLI boundaries');
const conflictRun = runZlar([
  'protected-records-one-terminal-deployment-profile',
  '--sample',
  '--profile',
  PROFILE_PATH,
  '--runtime-profile',
  RUNTIME_PROFILE_PATH,
  '--preflight-artifact',
  PREFLIGHT_ARTIFACT_PATH,
]);
assertEqual('sample plus explicit inputs exits two', 2, conflictRun.status);
assert('sample plus explicit names conflict', conflictRun.stderr.includes('Cannot combine --sample'));
assert('sample plus explicit privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(conflictRun.stderr));

const missingRun = runZlar(['protected-records-one-terminal-deployment-profile', '--profile', PROFILE_PATH]);
assertEqual('missing inputs exits two', 2, missingRun.status);
assert('missing inputs names requirement', missingRun.stderr.includes('Missing required'));

const unsupportedRun = runZlar(['protected-records-one-terminal-deployment-profile', '--latest']);
assertEqual('unsupported option exits two', 2, unsupportedRun.status);

const scratch = mkdtempSync(join(tmpdir(), 'zlar-one-terminal-deployment-profile-cli-'));
try {
  const drifted = JSON.parse(profileText);
  drifted.selected_runtime_profile.selects_latest_profile = true;
  const driftedPath = join(scratch, 'drifted-profile.json');
  writeFileSync(driftedPath, `${JSON.stringify(drifted, null, 2)}\n`);
  const driftRun = runZlar([
    'protected-records-one-terminal-deployment-profile',
    '--profile',
    driftedPath,
    '--runtime-profile',
    RUNTIME_PROFILE_PATH,
    '--preflight-artifact',
    PREFLIGHT_ARTIFACT_PATH,
    '--json',
  ]);
  assert('latest-selection profile exits nonzero', driftRun.status !== 0);
  assertEqual('latest-selection profile emits no stdout', '', driftRun.stdout);
  assert('latest-selection profile names drift', driftRun.stderr.includes('runtime-profile selection drifted'));
  assert('latest-selection stderr privacy safe', assertNoUnsafeProtectedRecordsRuntimeProfileText(driftRun.stderr));
  assert('latest-selection stderr does not leak scratch path', !driftRun.stderr.includes(scratch));

  const outsideRuntimePath = join(scratch, 'runtime-profile.json');
  writeFileSync(outsideRuntimePath, readFileSync(RUNTIME_PROFILE_PATH, 'utf8'));
  const outsideRuntimeRun = runZlar([
    'protected-records-one-terminal-deployment-profile',
    '--profile',
    PROFILE_PATH,
    '--runtime-profile',
    outsideRuntimePath,
    '--preflight-artifact',
    PREFLIGHT_ARTIFACT_PATH,
    '--json',
  ]);
  assertEqual('outside runtime input exits zero', 0, outsideRuntimeRun.status);
  const outsideRuntimeReport = JSON.parse(outsideRuntimeRun.stdout);
  assert('outside runtime report validates', assertProtectedRecordsOneTerminalDeploymentProfileProof(outsideRuntimeReport));
  assertEqual('outside runtime source redacted', 'outside-repo-redacted', outsideRuntimeReport.input_provenance.runtime_profile.source);
  assertEqual('outside runtime path redacted', '<outside-repo-redacted>', outsideRuntimeReport.input_provenance.runtime_profile.display_path);
  assert('outside runtime report does not leak scratch path', !outsideRuntimeRun.stdout.includes(scratch));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

const helpRun = runZlar(['protected-records-one-terminal-deployment-profile', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-one-terminal-deployment-profile'));
assert('help names non-claim', helpRun.stderr.includes('does not install'));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists command', mainHelp.stdout.includes('protected-records-one-terminal-deployment-profile'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed${FAIL ? ` (${FAIL} FAILED)` : ' ✓'}`);
if (FAIL > 0) process.exit(1);
