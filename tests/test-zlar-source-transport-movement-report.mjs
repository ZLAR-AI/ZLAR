#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  BUILD_ROOT,
  EXPECTED_NEW_REMOTE_SHA,
  EXPECTED_OLD_REMOTE_SHA,
  REQUESTED_REF,
  buildExampleMockReport,
  buildExampleSourceMovementReport,
  ensureSourceMovementReportIsSafe,
  validateSourceMovementReport,
  writeSourceMovementReportReview,
} from '../lib/zlar-source-transport-movement-report.mjs';
import { scanUnsafeTokenLifecycleText } from '../lib/zlar-github-app-token-lifecycle-wrapper.mjs';

const repoRoot = process.cwd();
const cliPath = join(repoRoot, 'bin', 'zlar-source-transport-proof');
const modulePath = join(repoRoot, 'lib', 'zlar-source-transport-movement-report.mjs');
const zlarPath = join(repoRoot, 'bin', 'zlar');
const tempRoot = mkdtempSync(`${BUILD_ROOT}/zlar-source-transport-proof-tests-${process.pid}-`);

function clone(value) {
  return structuredClone(value);
}

function assertFailure(name, report, code) {
  const review = validateSourceMovementReport(report);
  assert.equal(review.proof_status, 'failed', name);
  assert.equal(review.refusal_reason_code, code, name);
}

function writeFixture(name, value) {
  const path = `${tempRoot}/${name}.json`;
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  return path;
}

{
  const report = buildExampleSourceMovementReport();
  ensureSourceMovementReportIsSafe(report);
  const review = validateSourceMovementReport(report);
  assert.equal(review.proof_status, 'passed');
  assert.equal(review.selected_repo, 'ZLAR-AI/ZLAR');
  assert.equal(review.requested_ref, REQUESTED_REF);
  assert.equal(review.expected_old_remote_sha, EXPECTED_OLD_REMOTE_SHA);
  assert.equal(review.expected_new_remote_sha, EXPECTED_NEW_REMOTE_SHA);
  assert.equal(review.source_movement, true);
  assert.equal(review.remote_ref_write, true);
  assert.equal(review.cleanup.revocation_proven, true);
}

{
  const report = buildExampleSourceMovementReport();
  report.post_ref_read_attempted = false;
  report.post_read_returned_sha = null;
  assertFailure('missing post-read fails', report, 'operation_evidence_missing');
}

{
  const report = buildExampleSourceMovementReport();
  report.post_read_returned_ref = 'refs/heads/other';
  assertFailure('wrong post-read ref fails', report, 'post_ref_mismatch');
}

{
  const report = buildExampleSourceMovementReport();
  report.post_read_returned_sha = EXPECTED_OLD_REMOTE_SHA;
  assertFailure('wrong post-read sha fails', report, 'post_sha_mismatch');
}

{
  const report = buildExampleSourceMovementReport();
  report.post_read_returned_sha = null;
  assertFailure('movement true without post-read proof fails', report, 'operation_evidence_missing');
}

{
  const report = buildExampleMockReport();
  const review = validateSourceMovementReport(report);
  assert.equal(review.proof_status, 'failed');
  assert.equal(review.refusal_reason_code, 'report_is_not_success_proof');
  assert.equal(review.source_movement, false);
}

{
  const report = buildExampleSourceMovementReport();
  report.movement_status = 'failed';
  report.failure_stage = 'git_transport_push';
  report.failure_reason_code = 'git_transport_push_failed';
  report.source_movement = false;
  report.remote_ref_write = false;
  const review = validateSourceMovementReport(report);
  assert.equal(review.proof_status, 'failed');
  assert.equal(review.refusal_reason_code, 'report_is_not_success_proof');
}

{
  const report = buildExampleSourceMovementReport();
  report.pre_ref_read_count = 1;
  report.pre_ref_read_attempted = false;
  assertFailure('positive pre-read counter requires evidence', report, 'operation_evidence_missing');
}

{
  const report = buildExampleSourceMovementReport();
  report.installation_token_minted = true;
  report.token_cleanup_required = false;
  report.token_cleanup_proven = false;
  report.token_cleanup_proof_type = 'none';
  report.revocation_attempted = false;
  report.revocation_status_class = null;
  report.revocation_request_count = 0;
  report.token_lifecycle_request_count = 2;
  report.request_count = 5;
  assertFailure('token cleanup required after token mint', report, 'token_cleanup_required_missing');
}

{
  const report = buildExampleSourceMovementReport();
  const review = validateSourceMovementReport(report);
  assert.equal(review.cleanup.token_cleanup_proof_type, 'revocation_2xx');
  assert.equal(review.cleanup.revocation_proven, true);
}

{
  const report = buildExampleSourceMovementReport();
  report.revocation_attempted = false;
  report.revocation_status_class = null;
  report.revocation_request_count = 0;
  report.token_lifecycle_request_count = 2;
  report.request_count = 5;
  report.installation_token_expires_at = '2026-07-05T03:00:00Z';
  report.installation_token_expiry_class = 'recorded';
  report.token_cleanup_proof_type = 'expiry_timestamp';
  const review = validateSourceMovementReport(report);
  assert.equal(review.proof_status, 'passed');
  assert.equal(review.cleanup.revocation_proven, false);
  assert.equal(review.cleanup.expiry_recorded, true);
  assert.equal(review.cleanup.cleanup_claim, 'expiry_recorded_not_revocation');
}

for (const [label, key, code] of [
  ['credential helper nonzero rejects', 'credential_helper_count', 'counter_mismatch'],
  ['rest ref update nonzero rejects', 'rest_ref_update_count', 'counter_mismatch'],
]) {
  const report = buildExampleSourceMovementReport();
  report[key] = 1;
  assertFailure(label, report, code);
}

for (const [label, key] of [
  ['force push rejects', 'force_push'],
  ['plus refspec rejects', 'plus_refspec_used'],
  ['actions marker rejects', 'actions_used'],
  ['tag marker rejects', 'tag_or_release_used'],
  ['website marker rejects', 'website_touched'],
  ['deploy-key marker rejects', 'deploy_key_policy_touched'],
  ['github settings marker rejects', 'github_settings_touched'],
  ['production issuer marker rejects', 'production_issuer_path_used'],
]) {
  const report = buildExampleSourceMovementReport();
  report[key] = true;
  assertFailure(label, report, 'forbidden_marker_true');
}

{
  const report = buildExampleSourceMovementReport();
  report.requested_ref = 'Authorization: Bearer SHOULD_NOT_ECHO';
  const review = validateSourceMovementReport(report);
  assert.equal(review.proof_status, 'failed');
  assert.equal(review.refusal_reason_code, 'report_redaction_failed');
  assert.equal(JSON.stringify(review).includes('SHOULD_NOT_ECHO'), false);
  assert.deepEqual(scanUnsafeTokenLifecycleText(JSON.stringify(review)), []);
}

{
  const report = buildExampleSourceMovementReport();
  const outputPath = `${tempRoot}/review.json`;
  const written = writeSourceMovementReportReview(report, outputPath);
  assert.equal(written, outputPath);
  assert.equal(existsSync(outputPath), true);
  assert.deepEqual(scanUnsafeTokenLifecycleText(readFileSync(outputPath, 'utf8')), []);
  assert.throws(
    () => writeSourceMovementReportReview(report, outputPath),
    (error) => error?.safeCode === 'output_exists',
  );
}

{
  const forgedReview = {
    report_type: 'zlar-source-transport-movement-report-review-v1',
    proof_status: 'passed',
    source_movement: true,
    remote_ref_write: true,
    no_secret_verifier: true,
  };
  assert.throws(
    () => writeSourceMovementReportReview(forgedReview, `${tempRoot}/forged-review.json`),
    (error) => error?.safeCode === 'forged_review_input_refused',
  );
  assert.equal(existsSync(`${tempRoot}/forged-review.json`), false);
}

{
  const report = buildExampleSourceMovementReport();
  const outside = `/tmp/zlar-source-transport-proof-${process.pid}.json`;
  rmSync(outside, { force: true });
  assert.throws(
    () => writeSourceMovementReportReview(report, outside),
    (error) => error?.safeCode === 'unsafe_output_path',
  );
  assert.equal(existsSync(outside), false);
}

{
  const reportPath = writeFixture('success-report', buildExampleSourceMovementReport());
  const result = spawnSync(process.execPath, [cliPath, '--report', reportPath, '--json'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const review = JSON.parse(result.stdout);
  assert.equal(review.proof_status, 'passed');
}

{
  const outsideInput = `/tmp/zlar-source-transport-input-${process.pid}.json`;
  rmSync(outsideInput, { force: true });
  writeFileSync(outsideInput, `${JSON.stringify(buildExampleSourceMovementReport())}\n`, { mode: 0o600 });
  const result = spawnSync(process.execPath, [cliPath, '--report', outsideInput, '--json'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /build scratch root/);
  rmSync(outsideInput, { force: true });
}

{
  const unsafePath = '/operator-private-config/source-transport/github-app/fake-private-key.pem';
  const result = spawnSync(process.execPath, [cliPath, '--report', unsafePath, '--json'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.equal(`${result.stdout}${result.stderr}`.includes('fake-private-key.pem'), false);
}

{
  const unsafeAuthorityPath = `${BUILD_ROOT}/fake-custody-token-authority.json`;
  const result = spawnSync(process.execPath, [cliPath, '--authority-packet', unsafeAuthorityPath, '--json'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.equal(`${result.stdout}${result.stderr}`.includes('fake-custody-token-authority'), false);
}

{
  const result = spawnSync(process.execPath, [cliPath, '--report', '-', '--json'], {
    input: 'Authorization: Bearer SHOULD_NOT_ECHO',
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.equal(`${result.stdout}${result.stderr}`.includes('SHOULD_NOT_ECHO'), false);
}

{
  const result = spawnSync(
    process.execPath,
    [cliPath, '--live', 'Authorization: Bearer SHOULD_NOT_ECHO', '--json'],
    { encoding: 'utf8' },
  );
  assert.notEqual(result.status, 0);
  assert.equal(`${result.stdout}${result.stderr}`.includes('SHOULD_NOT_ECHO'), false);
}

{
  const zlarResult = spawnSync(zlarPath, ['source-transport-proof', '--live', '--json'], { encoding: 'utf8' });
  assert.equal(zlarResult.status, 2);
  assert.equal(JSON.parse(zlarResult.stdout).refusal_reason_code, 'live_mode_disabled_in_no_secret_build');
}

{
  const moduleText = readFileSync(modulePath, 'utf8');
  const cliText = readFileSync(cliPath, 'utf8');
  assert.equal(/node:child_process/.test(`${moduleText}\n${cliText}`), false);
  assert.equal(/\bfetch\s*\(/.test(`${moduleText}\n${cliText}`), false);
  assert.equal(/api\.github\.com/.test(`${moduleText}\n${cliText}`), false);
  assert.equal(/git\s+push|git\s+fetch|git\s+ls-remote/.test(`${moduleText}\n${cliText}`), false);
}

console.log('zlar source transport movement report: 81/81 assertions passed');
