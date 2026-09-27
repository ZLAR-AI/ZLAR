#!/usr/bin/env node

import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE,
  RECOGNIZED_EFFECT_TARGET_SHAPE_VERIFICATION_TYPE,
  assertNoUnsafeRecognizedEffectTargetShapeText,
  buildRecognizedEffectTargetShapeSampleArtifact,
  parseRecognizedEffectTargetShapeArtifactText,
  verifyRecognizedEffectTargetShapeArtifact,
} from '../lib/recognized-effect-target-shape.mjs';

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

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-recognized-effect-target-shape-'));

function runZlar(args, input = '') {
  return spawnSync('./bin/zlar', args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

try {
  section('library sample verification');
  const artifact = buildRecognizedEffectTargetShapeSampleArtifact();
  assertEqual('artifact type', RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE, artifact.artifact_type);
  const report = verifyRecognizedEffectTargetShapeArtifact(artifact);
  assertEqual('verification type', RECOGNIZED_EFFECT_TARGET_SHAPE_VERIFICATION_TYPE, report.report_type);
  assertEqual('verification passes', true, report.verified);
  assertEqual('recognized effect delta is one', 1, report.recognized_effect_delta);
  assertEqual('current-machine governance false', false, report.current_machine_governance_proven);
  assertEqual('side-door closure false', false, report.side_door_closure_proven);
  assertEqual('public claim movement false', false, report.public_claim_movement);
  assertEqual('coherent rewrite authenticity false', false, report.coherent_state_manifest_rewrite_authenticity_proven);
  assert('safe claim mentions raw JSONL not consequence', report.safe_claim.includes('raw JSONL bytes'));
  assert('forbidden claims include side-door closure', report.forbidden_claims.includes('side-door closure'));
  assert('report is privacy safe', assertNoUnsafeRecognizedEffectTargetShapeText(JSON.stringify(report)));

  const direct = report.side_door_matrix.find((item) => item.route === 'direct_filesystem_append_to_untrusted_ingress_fixture');
  const shell = report.side_door_matrix.find((item) => item.route === 'shell_helper_append_to_untrusted_ingress_fixture');
  assertEqual('direct ingress not accepted', false, direct.accepted);
  assertEqual('direct ingress delta zero', 0, direct.recognized_effect_delta);
  assertEqual('direct ingress does not prove OS blocking', false, direct.os_filesystem_blocking_proven);
  assertEqual('shell ingress not accepted', false, shell.accepted);
  assertEqual('shell ingress delta zero', 0, shell.recognized_effect_delta);
  assertEqual('shell ingress does not prove OS blocking', false, shell.os_filesystem_blocking_proven);

  const negativeById = Object.fromEntries(report.negative_case_results.map((item) => [item.case_id, item]));
  for (const [caseId, reason] of [
    ['missing_receipt', 'receipt_missing'],
    ['invalid_receipt_hash', 'receipt_hash_mismatch'],
    ['stale_receipt', 'receipt_stale'],
    ['same_process_replay', 'receipt_replay'],
    ['wrong_policy', 'policy_not_recognized'],
    ['wrong_action_class', 'action_class_mismatch'],
    ['wrong_domain', 'domain_mismatch'],
    ['wrong_tool', 'tool_mismatch'],
    ['wrong_detail', 'detail_hash_mismatch'],
    ['wrong_audit_event', 'audit_event_mismatch'],
    ['wrong_target', 'target_mismatch'],
    ['wrong_runtime_profile_id', 'runtime_profile_id_mismatch'],
    ['wrong_runtime_profile_sha256', 'runtime_profile_sha256_mismatch'],
    ['non_boarding_receipt', 'non_boarding_receipt'],
    ['unknown_issuer', 'unknown_issuer'],
    ['missing_issuer_status', 'missing_issuer_status'],
    ['retired_issuer', 'retired_issuer'],
    ['compromised_issuer', 'compromised_issuer'],
    ['receipt_contract_mismatch', 'receipt_contract_mismatch'],
    ['request_stream_authority_material', 'request_stream_authority_material'],
    ['restart_replay_refused_through_persisted_store_fixture', 'receipt_replay_after_restart'],
    ['malformed_jsonl_partial_write_ingress', 'malformed_jsonl_quarantined'],
    ['materialized_state_tamper', 'state_manifest_mismatch'],
    ['manifest_state_hash_mismatch', 'manifest_state_hash_mismatch'],
  ]) {
    assertEqual(`${caseId} refused`, false, negativeById[caseId]?.accepted);
    assertEqual(`${caseId} reason`, reason, negativeById[caseId]?.reason_code);
    assertEqual(`${caseId} delta zero`, 0, negativeById[caseId]?.recognized_effect_delta);
  }
  assertEqual('same-process replay refused flag', true, report.same_process_replay_refused);
  assertEqual('persisted restart replay refused flag', true, report.persisted_replay_store_duplicate_refused);
  assertEqual('malformed ingress fails closed flag', true, report.malformed_ingress_fail_closed);
  assertEqual('state tamper refused flag', true, report.materialized_state_tamper_refused);
  assertEqual('manifest mismatch refused flag', true, report.manifest_state_hash_mismatch_refused);
  assertEqual('coherent rewrite consistency can pass', true, report.coherent_state_manifest_rewrite_consistency_passes);
  assertEqual('coherent rewrite authenticity still false', false, report.coherent_state_manifest_rewrite_authenticity_proven);

  section('artifact parser and fail-closed mutations');
  const artifactText = `${JSON.stringify(artifact, null, 2)}\n`;
  const parsed = parseRecognizedEffectTargetShapeArtifactText(artifactText);
  assertEqual('parsed artifact type', RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE, parsed.artifact_type);
  assertThrows('malformed JSON is refused', () => parseRecognizedEffectTargetShapeArtifactText('{'), 'not valid JSON');

  const manifestMismatch = clone(artifact);
  manifestMismatch.materialized.state_manifest.recognized_effect_state_sha256 = '0'.repeat(64);
  assertThrows('tampered state manifest is refused', () => verifyRecognizedEffectTargetShapeArtifact(manifestMismatch), 'state_manifest mismatch');

  const stateTamper = clone(artifact);
  stateTamper.materialized.recognized_effect_state.recognized_effect_delta = 2;
  assertThrows('tampered materialized state is refused', () => verifyRecognizedEffectTargetShapeArtifact(stateTamper), 'recognized_effect_state mismatch');

  const diffPacket = clone(artifact);
  diffPacket.source_design_packet_sha256 = '1'.repeat(64);
  assertThrows('wrong source packet hash is refused', () => verifyRecognizedEffectTargetShapeArtifact(diffPacket), 'source_design_packet_sha256');

  const claimInflation = clone(artifact);
  claimInflation.claim_boundary.side_door_closure_proven = true;
  assertThrows('side-door claim inflation is refused', () => verifyRecognizedEffectTargetShapeArtifact(claimInflation), 'side_door_closure_proven');

  section('CLI sample and verify');
  const sampleTextRun = runZlar(['recognized-effect-target-shape', '--sample']);
  assertEqual('sample text exits zero', 0, sampleTextRun.status);
  assertEqual('sample text emits no stderr', '', sampleTextRun.stderr);
  assert('sample text names verifier', sampleTextRun.stdout.includes('ZLAR Recognized-Effect Target-Shape Verification v1'));
  assert('sample text says delta one', sampleTextRun.stdout.includes('recognized_effect_delta=1'));
  assert('sample text says direct delta zero', sampleTextRun.stdout.includes('direct_ingress_delta=0'));
  assert('sample text says shell delta zero', sampleTextRun.stdout.includes('shell_ingress_delta=0'));
  assert('sample text says persisted replay refused', sampleTextRun.stdout.includes('persisted_restart_replay_refused=true'));
  assert('sample text says coherent rewrite authenticity false', sampleTextRun.stdout.includes('coherent_rewrite_authenticity_proven=false'));
  assert('sample text privacy safe', assertNoUnsafeRecognizedEffectTargetShapeText(sampleTextRun.stdout));

  const sampleJsonRun = runZlar(['recognized-effect-target-shape', '--sample', '--json']);
  assertEqual('sample json exits zero', 0, sampleJsonRun.status);
  assertEqual('sample json emits no stderr', '', sampleJsonRun.stderr);
  const sampleJson = JSON.parse(sampleJsonRun.stdout);
  assertEqual('sample json report type', RECOGNIZED_EFFECT_TARGET_SHAPE_VERIFICATION_TYPE, sampleJson.report_type);
  assertEqual('sample json verified', true, sampleJson.verified);
  assertEqual('sample json public claim false', false, sampleJson.public_claim_movement);
  assert('sample json privacy safe', assertNoUnsafeRecognizedEffectTargetShapeText(sampleJsonRun.stdout));

  const artifactPath = join(scratch, 'recognized-effect-target-shape-artifact.json');
  const artifactRun = runZlar(['recognized-effect-target-shape', '--sample', '--artifact', artifactPath]);
  assertEqual('artifact command exits zero', 0, artifactRun.status);
  assertEqual('artifact command emits no stderr', '', artifactRun.stderr);
  const writtenArtifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  assertEqual('written artifact type', RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE, writtenArtifact.artifact_type);
  assert('written artifact verifies', verifyRecognizedEffectTargetShapeArtifact(writtenArtifact).verified);

  const artifactStdoutRun = runZlar(['recognized-effect-target-shape', '--sample', '--artifact', '-']);
  assertEqual('artifact stdout exits zero', 0, artifactStdoutRun.status);
  assertEqual('artifact stdout emits no stderr', '', artifactStdoutRun.stderr);
  const stdoutArtifact = JSON.parse(artifactStdoutRun.stdout);
  assertEqual('stdout artifact type', RECOGNIZED_EFFECT_TARGET_SHAPE_ARTIFACT_TYPE, stdoutArtifact.artifact_type);

  const verifyRun = runZlar(['recognized-effect-target-shape', 'verify', '--input', artifactPath]);
  assertEqual('verify command exits zero', 0, verifyRun.status);
  assertEqual('verify command emits no stderr', '', verifyRun.stderr);
  assert('verify text says verified', verifyRun.stdout.includes('verified=true'));
  assert('verify text privacy safe', assertNoUnsafeRecognizedEffectTargetShapeText(verifyRun.stdout));

  const verifyJsonRun = runZlar(['recognized-effect-target-shape', 'verify', '--input', artifactPath, '--json']);
  assertEqual('verify json exits zero', 0, verifyJsonRun.status);
  assertEqual('verify json emits no stderr', '', verifyJsonRun.stderr);
  const verifyJson = JSON.parse(verifyJsonRun.stdout);
  assertEqual('verify json type', RECOGNIZED_EFFECT_TARGET_SHAPE_VERIFICATION_TYPE, verifyJson.report_type);
  assertEqual('verify json recognized effect delta one', 1, verifyJson.recognized_effect_delta);

  const verifyStdinRun = runZlar(['recognized-effect-target-shape', 'verify', '--input', '-'], artifactText);
  assertEqual('verify stdin exits zero', 0, verifyStdinRun.status);
  assertEqual('verify stdin emits no stderr', '', verifyStdinRun.stderr);
  assert('verify stdin says verified', verifyStdinRun.stdout.includes('verified=true'));

  const verifySampleRun = runZlar(['recognized-effect-target-shape', 'verify', '--sample', '--json']);
  assertEqual('verify sample exits zero', 0, verifySampleRun.status);
  assertEqual('verify sample emits no stderr', '', verifySampleRun.stderr);
  const verifySampleJson = JSON.parse(verifySampleRun.stdout);
  assertEqual('verify sample report type', RECOGNIZED_EFFECT_TARGET_SHAPE_VERIFICATION_TYPE, verifySampleJson.report_type);
  assertEqual('verify sample replay flag', true, verifySampleJson.persisted_replay_store_duplicate_refused);

  section('CLI fail closed handling');
  const helpRun = runZlar(['recognized-effect-target-shape', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar recognized-effect-target-shape --sample'));
  assert('help names non-claims', helpRun.stderr.includes('does not live probe'));
  assertEqual('help emits no stdout', '', helpRun.stdout);

  const missingSample = runZlar(['recognized-effect-target-shape']);
  assert('missing sample exits nonzero', missingSample.status !== 0);
  assert('missing sample prints usage', missingSample.stderr.includes('Usage: zlar recognized-effect-target-shape --sample'));
  assertEqual('missing sample emits no stdout', '', missingSample.stdout);

  const missingSampleWithJson = runZlar(['recognized-effect-target-shape', '--json']);
  assert('missing sample with json exits nonzero', missingSampleWithJson.status !== 0);
  assert('missing sample with json says sample required', missingSampleWithJson.stderr.includes('--sample is required'));
  assertEqual('missing sample with json emits no stdout', '', missingSampleWithJson.stdout);

  const latestRun = runZlar(['recognized-effect-target-shape', '--latest']);
  assert('latest option exits nonzero', latestRun.status !== 0);
  assert('latest option rejected', latestRun.stderr.includes('Unsupported option: --latest'));
  assertEqual('latest emits no stdout', '', latestRun.stdout);

  const artifactJsonConflict = runZlar(['recognized-effect-target-shape', '--sample', '--json', '--artifact', '-']);
  assert('artifact stdout json conflict exits nonzero', artifactJsonConflict.status !== 0);
  assert('artifact stdout json conflict named', artifactJsonConflict.stderr.includes('Cannot combine --json with --artifact -'));

  const missingVerifyInput = runZlar(['recognized-effect-target-shape', 'verify']);
  assert('missing verify input exits nonzero', missingVerifyInput.status !== 0);
  assert('missing verify input named', missingVerifyInput.stderr.includes('verify requires --input'));

  const verifyInputSampleConflict = runZlar(['recognized-effect-target-shape', 'verify', '--input', artifactPath, '--sample']);
  assert('verify input sample conflict exits nonzero', verifyInputSampleConflict.status !== 0);
  assert('verify input sample conflict named', verifyInputSampleConflict.stderr.includes('Cannot combine --input with --sample'));

  const malformedPath = join(scratch, 'malformed.json');
  writeFileSync(malformedPath, '{', 'utf8');
  const malformedRun = runZlar(['recognized-effect-target-shape', 'verify', '--input', malformedPath]);
  assert('malformed verify exits nonzero', malformedRun.status !== 0);
  assert('malformed verify names invalid json', malformedRun.stderr.includes('not valid JSON'));
  assertEqual('malformed verify emits no stdout', '', malformedRun.stdout);

  const tamperedPath = join(scratch, 'tampered.json');
  writeFileSync(tamperedPath, JSON.stringify(manifestMismatch, null, 2), 'utf8');
  const tamperedRun = runZlar(['recognized-effect-target-shape', 'verify', '--input', tamperedPath]);
  assert('tampered verify exits nonzero', tamperedRun.status !== 0);
  assert('tampered verify refuses manifest', tamperedRun.stderr.includes('state_manifest mismatch'));
  assertEqual('tampered verify emits no stdout', '', tamperedRun.stdout);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\n${PASS} passed, ${FAIL} failed (${TOTAL} total)`);
if (FAIL > 0) {
  process.exit(1);
}
