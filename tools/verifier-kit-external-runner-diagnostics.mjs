#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function usage() {
  console.log(`Usage:
  node tools/verifier-kit-external-runner-diagnostics.mjs --json-out <file> [--kit-dir <dir>] [--issuer-status-json <file>]

Inspects the built verifier-kit external-runner dry-run helper, its manifest
entry, and the repo-side regression harness for diagnostic hardening.

This is source/build inspection plus local dry-run artifact intake. It sends no
verifier request and creates no public external attestation.`);
}

function parseArgs(argv) {
  const args = {
    jsonOut: '',
    kitDir: 'dist/zlar-verifier-kit-v0.1.0',
    issuerStatusJson: 'zlar-verifier-kit-issuer-status-fixture.json',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json-out') {
      args.jsonOut = argv[++i] || '';
    } else if (arg === '--kit-dir') {
      args.kitDir = argv[++i] || '';
    } else if (arg === '--issuer-status-json') {
      args.issuerStatusJson = argv[++i] || '';
    } else if (arg === '-h' || arg === '--help') {
      usage();
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.jsonOut) {
    throw new Error('--json-out is required');
  }
  return args;
}

function readBytes(path) {
  return readFileSync(path);
}

function readText(path) {
  return readFileSync(path, 'utf8');
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256File(path) {
  return sha256Bytes(readBytes(path));
}

const args = parseArgs(process.argv.slice(2));
const kitDir = args.kitDir.replace(/\/+$/, '');
const sourceRunnerPath = 'tools/verifier-kit-src/external-runner-dry-run.sh';
const builtRunnerPath = `${kitDir}/external-runner-dry-run.sh`;
const testHarnessPath = 'tests/test-verifier-kit.sh';
const manifestPath = `${kitDir}/MANIFEST.json`;
const manifestSigPath = `${kitDir}/MANIFEST.sig`;
const tarballPath = 'dist/zlar-verifier-kit-v0.1.0.tar.gz';

const sourceRunner = readText(sourceRunnerPath);
const builtRunner = readText(builtRunnerPath);
const testHarness = readText(testHarnessPath);
const manifest = readJson(manifestPath);
const issuerStatus = readJson(args.issuerStatusJson);
const manifestEntry = (manifest.files || []).find((entry) => entry.path === 'external-runner-dry-run.sh') || {};

const sourceRunnerSha = sha256File(sourceRunnerPath);
const builtRunnerSha = sha256File(builtRunnerPath);
const issuerStatusSha = sha256File(args.issuerStatusJson);

const requiredLiteral = '[[ "${LAST_OUTPUT}" != *"${expected}"* ]]';
const forbiddenLiterals = ['grep -q', 'grep -qF'];

const diagnosticContract = {
  pipefail_safe_last_output_check_present: sourceRunner.includes(requiredLiteral) && builtRunner.includes(requiredLiteral),
  grep_q_absent_from_external_runner:
    !forbiddenLiterals.some((literal) => sourceRunner.includes(literal) || builtRunner.includes(literal)),
  required_literals_present: [requiredLiteral],
  forbidden_literals_absent: forbiddenLiterals,
};

const repoRegressionContract = {
  test_file_sha256: sha256File(testHarnessPath),
  t_kit_23_fixture_copy_assertions_present:
    testHarness.includes('T-KIT-23.engagement-receipt-copied') &&
    testHarness.includes('T-KIT-23.engagement-pubkey-copied') &&
    testHarness.includes('T-KIT-23.engagement-chain-copied'),
  t_kit_23_failure_tail_diagnostic_present:
    testHarness.includes('T-KIT-23 dry-run failed; last 40 lines:'),
  assert_match_tail_context_present:
    testHarness.includes('first lines:') && testHarness.includes('last lines:'),
  included_in_built_kit: false,
};

const builtKit = {
  kit_version: readText(`${kitDir}/VERSION`).trim(),
  tarball_sha256: sha256File(tarballPath),
  manifest_json_sha256: sha256File(manifestPath),
  manifest_sig_sha256: sha256File(manifestSigPath),
  external_runner_manifest_entry_sha256: manifestEntry.sha256 || '',
  external_runner_built_sha256: builtRunnerSha,
  external_runner_source_sha256: sourceRunnerSha,
  manifest_entry_matches_built_file: manifestEntry.sha256 === builtRunnerSha,
  source_matches_built_file: sourceRunnerSha === builtRunnerSha,
};

const executionEvidence = {
  evidence_model: 'release-forward-helper-generated-external-runner-issuer-status-json',
  issuer_status_json_artifact_verified: issuerStatus.verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED',
  external_runner_dry_run_executed_by_this_command: false,
  issuer_status_json_artifact: args.issuerStatusJson,
  issuer_status_json_sha256: issuerStatusSha,
  issuer_status_verdict: issuerStatus.verdict || '',
  live_probing: issuerStatus.live_probing,
};

const target = {
  release_tag: process.env.ZLAR_RELEASE_FORWARD_TARGET_TAG || '',
  expected_commit_sha: process.env.ZLAR_RELEASE_FORWARD_EXPECTED_SHA || '',
  observed_commit_sha: process.env.ZLAR_RELEASE_FORWARD_OBSERVED_SHA || '',
  moving_target_selected: false,
};

const report = {
  report_type: 'zlar-verifier-kit-external-runner-diagnostics-v1',
  schema_version: 1,
  result: 'PASS',
  minimum_hardening_release_tag: 'v3.4.20',
  artifact_preservation_minimum_release_tag: 'v3.4.21',
  target,
  built_kit: builtKit,
  diagnostic_contract: diagnosticContract,
  execution_evidence: executionEvidence,
  repo_regression_contract: repoRegressionContract,
  claim_boundary: {
    creates_external_attestation: false,
    proves_non_operator_review: false,
    proves_production_downstream_recognition: false,
    proves_enterprise_readiness: false,
    changes_v3_4_19_recognition_contract_digest_claim: false,
  },
};

const pass =
  diagnosticContract.pipefail_safe_last_output_check_present === true &&
  diagnosticContract.grep_q_absent_from_external_runner === true &&
  builtKit.manifest_entry_matches_built_file === true &&
  builtKit.source_matches_built_file === true &&
  executionEvidence.issuer_status_json_artifact_verified === true &&
  executionEvidence.issuer_status_verdict === 'ISSUER-STATUS-FIXTURE-VERIFIED' &&
  executionEvidence.live_probing === false &&
  repoRegressionContract.t_kit_23_fixture_copy_assertions_present === true &&
  repoRegressionContract.t_kit_23_failure_tail_diagnostic_present === true &&
  repoRegressionContract.assert_match_tail_context_present === true &&
  repoRegressionContract.included_in_built_kit === false;

report.result = pass ? 'PASS' : 'FAIL';

writeFileSync(resolve(args.jsonOut), `${JSON.stringify(report, null, 2)}\n`);

if (!pass) {
  console.error(JSON.stringify(report, null, 2));
  process.exit(1);
}
