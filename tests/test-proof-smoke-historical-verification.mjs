#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  PROOF_SMOKE_HISTORICAL_REPORT_VERIFICATION_TYPE,
  PROOF_SMOKE_HISTORICAL_V1_DOWNSTREAM_SERVICE_COMPONENT_SHA256,
  PROOF_SMOKE_HISTORICAL_V1_LOCAL_PROOF_PACK_FILE_SHA256,
  PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256,
  PROOF_SMOKE_HISTORICAL_V1_SAMPLE_REPORT_SHA256,
  PROOF_SMOKE_HISTORICAL_V1_SERVICE_PREFLIGHT_FILE_SHA256,
  PROOF_SMOKE_SAMPLE_REPORT_PATH,
  verifyHistoricalProofSmokeReportText,
} from '../lib/proof-smoke-report.mjs';

let passed = 0;
let failed = 0;

function assert(label, condition) {
  if (condition) {
    passed += 1;
    console.log(`  PASS: ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL: ${label}`);
  }
}

function throws(label, fn, fragment) {
  try {
    fn();
    assert(label, false);
  } catch (err) {
    assert(label, String(err.message).includes(fragment));
  }
}

function runCli(args) {
  return spawnSync(process.execPath, ['bin/zlar-proof-smoke', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
}

const text = readFileSync(PROOF_SMOKE_SAMPLE_REPORT_PATH, 'utf8');
const expectedOptions = {
  expectedFileSha256: PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256,
  expectedReportSha256: PROOF_SMOKE_HISTORICAL_V1_SAMPLE_REPORT_SHA256,
};

console.log('\n-- exact-pinned historical library verification --');
const verification = verifyHistoricalProofSmokeReportText(text, expectedOptions);
assert('verification type exact', verification.verification_type === PROOF_SMOKE_HISTORICAL_REPORT_VERIFICATION_TYPE);
assert('historical verification passes', verification.verified === true);
assert('historical only true', verification.historical_only === true);
assert('exact file identity matched', verification.required_file_sha256_matched === true);
assert('exact report identity matched', verification.required_report_sha256_matched === true);
assert('ordered steps verified', verification.ordered_step_contract_verified === true);
assert('embedded identities verified', verification.embedded_verification_identities_verified === true);
assert('local proof pack file identity preserved without claiming a file read', verification.immutable_historical_inputs.local_proof_pack.file_sha256 === PROOF_SMOKE_HISTORICAL_V1_LOCAL_PROOF_PACK_FILE_SHA256 && verification.immutable_historical_inputs.local_proof_pack.external_file_bytes_read_by_this_verifier === false);
assert('downstream service component identity verified', verification.immutable_historical_inputs.local_proof_pack.embedded_downstream_service_component_sha256 === PROOF_SMOKE_HISTORICAL_V1_DOWNSTREAM_SERVICE_COMPONENT_SHA256 && verification.immutable_historical_inputs.local_proof_pack.embedded_component_identity_verified === true);
assert('service preflight file identity preserved without claiming a file read', verification.immutable_historical_inputs.service_preflight.file_sha256 === PROOF_SMOKE_HISTORICAL_V1_SERVICE_PREFLIGHT_FILE_SHA256 && verification.immutable_historical_inputs.service_preflight.external_file_bytes_read_by_this_verifier === false);
assert('fresh proof false', verification.fresh_proof_execution_performed === false);
assert('source freshness false', verification.source_freshness_proven === false);
assert('current coverage false', verification.current_coverage_projected === false);
assert('current authority false', verification.current_authority_proven === false);
assert('current rightful false', verification.current_fixture_rightful_issuance_projected === false);
assert('current effect false', verification.current_effect_projected === false);
assert('lifecycle closure false', verification.consequence_lifecycle_closed === false);
assert('current projection refused', verification.current_projection_allowed === false);
assert('historical counts non-scoring', verification.historical_counts_evidence_class === 'historical-non-scoring-artifact-content');
assert('no current counts field', !Object.prototype.hasOwnProperty.call(verification, 'counts'));

console.log('\n-- identity and tamper refusals --');
throws(
  'missing file identity refused',
  () => verifyHistoricalProofSmokeReportText(text),
  'must be a 64-character',
);
throws(
  'wrong expected file identity refused',
  () => verifyHistoricalProofSmokeReportText(text, {
    ...expectedOptions,
    expectedFileSha256: '0'.repeat(64),
  }),
  'is not the pinned v1 sample',
);
throws(
  'wrong expected report identity refused',
  () => verifyHistoricalProofSmokeReportText(text, {
    ...expectedOptions,
    expectedReportSha256: '0'.repeat(64),
  }),
  'is not the pinned v1 sample',
);
throws(
  'tampered bytes refused',
  () => verifyHistoricalProofSmokeReportText(`${text} `, expectedOptions),
  'file SHA-256 does not match',
);

console.log('\n-- verification-only CLI --');
const cliArgs = [
  'verify',
  '--historical',
  '--sample',
  '--require-file-sha',
  PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256,
  '--require-sha',
  PROOF_SMOKE_HISTORICAL_V1_SAMPLE_REPORT_SHA256,
  '--json',
];
const cli = runCli(cliArgs);
assert('historical CLI exits zero', cli.status === 0);
assert('historical CLI emits no stderr', cli.stderr === '');
const cliVerification = JSON.parse(cli.stdout);
assert('historical CLI type exact', cliVerification.verification_type === PROOF_SMOKE_HISTORICAL_REPORT_VERIFICATION_TYPE);
assert('historical CLI current projection false', cliVerification.current_projection_allowed === false);

const missingPin = runCli(['verify', '--historical', '--sample', '--json']);
assert('historical CLI missing pin refuses', missingPin.status !== 0 && missingPin.stdout === '');
assert('historical CLI missing pin reason exact', missingPin.stderr.includes('requires --require-file-sha'));

const missingReportPin = runCli([
  'verify',
  '--historical',
  '--sample',
  '--require-file-sha',
  PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256,
  '--json',
]);
assert('historical CLI missing report pin refuses', missingReportPin.status !== 0 && missingReportPin.stdout === '');
assert('historical CLI missing report pin reason exact', missingReportPin.stderr.includes('requires --require-sha'));

const currentPath = runCli(['verify', '--sample', '--json']);
assert('current v1 acceptance remains refused', currentPath.status !== 0 && currentPath.stdout === '');
assert('current v1 refusal names exhausted grant', currentPath.stderr.includes('authority_grant_contract_exhausted'));

const scratch = mkdtempSync(join(tmpdir(), 'zlar-proof-smoke-historical-'));
try {
  const tamperedPath = join(scratch, 'tampered.json');
  writeFileSync(tamperedPath, text.replace('"result": "passed"', '"result": "failed"'));
  const tampered = runCli([
    'verify',
    '--historical',
    '--input',
    tamperedPath,
    '--require-file-sha',
    PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256,
    '--require-sha',
    PROOF_SMOKE_HISTORICAL_V1_SAMPLE_REPORT_SHA256,
    '--json',
  ]);
  assert('historical CLI tamper refuses', tampered.status !== 0 && tampered.stdout === '');
  assert('historical CLI tamper reason is identity', tampered.stderr.includes('file SHA-256 does not match'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log('\n-- verification consumer cutover --');
const readinessCliSource = readFileSync('bin/zlar-north-star-readiness', 'utf8');
const readinessSource = readFileSync('lib/north-star-readiness.mjs', 'utf8');
const historicalCommand = `proof-smoke verify --historical --sample --require-file-sha ${PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256}`;
assert('readiness CLI consumes historical verifier', readinessCliSource.includes("'--historical'") && readinessCliSource.includes('PROOF_SMOKE_HISTORICAL_V1_SAMPLE_FILE_SHA256'));
assert('readiness evidence labels historical non-scoring', readinessSource.includes('historical_verified_non_scoring') && readinessSource.includes(historicalCommand));

console.log(`\nproof smoke historical verification: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
