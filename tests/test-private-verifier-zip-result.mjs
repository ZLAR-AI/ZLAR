#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  PRIVATE_VERIFIER_ZIP_RELATIONSHIP,
  PRIVATE_VERIFIER_ZIP_RESULT_TYPE,
  REQUIRED_ZIP_RESULT_STEPS,
  assertPrivateVerifierZipResult,
  buildPrivateVerifierZipResultVerification,
} from '../lib/private-verifier-zip-result.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;
const TEMP_DIRS = [];

process.on('exit', () => {
  for (const dir of TEMP_DIRS) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function ok(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function equal(label, actual, expected) {
  ok(label, actual === expected, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function throws(label, fn, expectedMessage) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessage || String(err.message).includes(expectedMessage)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256Text(text) {
  return sha256Bytes(Buffer.from(text));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

const TARGET_COMMIT = '5a12a2e39d67091fb96ae35d016d3e49efeaa05b';
const SOURCE_ZIP_SHA = '05b18ab9053ba05ee8d58ee62b8de8619fdeadee8e908869a3929d59e062b439';
const PROOF_SMOKE_SHA = 'fdbe2983ecc0bd8f2b86c9193379a2166734095c7b7293d5a089097db3d8f2c6';
const EMPTY_SHA = sha256Text('');

function baseReport() {
  return {
    report_type: PRIVATE_VERIFIER_ZIP_RESULT_TYPE,
    schema_version: 1,
    generated_at: '2026-07-06T13:45:00Z',
    intake_class: 'zip-snapshot-private-verifier-reply',
    target: {
      repo: 'ZLAR-AI/ZLAR',
      expected_commit_sha: TARGET_COMMIT,
      commit_sha: TARGET_COMMIT,
      source_route: 'browser-downloaded-zip-snapshot',
      moving_target_used: false,
    },
    verifier: {
      public_label: 'private-personally-connected-outside-machine-verifier-1',
      relationship_to_zlar: PRIVATE_VERIFIER_ZIP_RELATIONSHIP,
      identity_public: false,
      contact_public: false,
    },
    custody: {
      source_channel_recorded_privately: true,
      received_timestamp_recorded_privately: true,
      raw_reply_publicly_committed: false,
      private_storage_required: true,
      public_repo_material_contains_private_identity: false,
      returned_attachment_locally_reviewed: true,
    },
    evidence: {
      evidence_model: 'zip-snapshot-returned-artifact-set',
      returned_results_zip_name: 'zlar-private-verifier-zip-results.zip',
      returned_results_zip_sha256: '0'.repeat(64),
      source_snapshot_zip_sha256: SOURCE_ZIP_SHA,
      sha256sums_entry_count: 24,
      required_steps: REQUIRED_ZIP_RESULT_STEPS.map((id) => ({
        id,
        exit_code: 0,
        stdout_sha256: EMPTY_SHA,
        stderr_sha256: EMPTY_SHA,
      })),
    },
    privacy: {
      private_by_default: true,
      public_attribution_approved: false,
      public_external_attestation_approved: false,
      verifier_identity_public: false,
      verifier_contact_public: false,
      private_contact_included: false,
      private_paths_included: false,
      credentials_included: false,
    },
    claim_boundary: {
      private_intake_only: true,
      private_personally_connected_outside_machine_signal: true,
      artifact_custody_reviewed: true,
      public_external_attestation: false,
      independent_review: false,
      arms_length_review: false,
      public_attribution: false,
      git_clone_source_access: false,
      source_transport_credentials: false,
      tag_or_release_proof: false,
      website_public_alignment: false,
      production_trust: false,
      current_machine_governance: false,
      all_surface_governance: false,
      north_star_readiness: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    non_claims: [
      'This result is private/internal intake only unless separate public disclosure is approved.',
      "This result is not independent, third-party, public, or arm's-length attestation.",
      'This result does not prove git clone source access or source-transport credential proof.',
      'This result does not prove production trust, current-machine governance, all-surface governance, or side-door closure.',
      'This result does not prove North Star readiness, website/public alignment, tag/release proof, or absolute human intention.',
    ],
  };
}

function step(report, id) {
  return report.evidence.required_steps.find((entry) => entry.id === id);
}

function writeEvidence(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'zlar-private-verifier-zip-result-test-'));
  TEMP_DIRS.push(root);
  const unpacked = join(root, 'unpacked');
  mkdirSync(unpacked, { recursive: true });

  const returnedZipBytes = Buffer.from('private verifier ZIP result archive bytes\n');
  writeFileSync(join(root, 'zlar-private-verifier-zip-results.zip'), returnedZipBytes);

  const files = new Map([
    ['environment.txt', `ZLAR private verifier ZIP fallback\nexpected_sha=${TARGET_COMMIT}\nnode v22.22.0\n`],
    ['zip-source.txt', `zip=ZLAR-${TARGET_COMMIT}.zip\n`],
    ['zip-sha256.txt', `${SOURCE_ZIP_SHA}  ZLAR-${TARGET_COMMIT}.zip\n`],
    ['SHA256SUMS.err', 'shasum: unpacked: Is a directory\n'],
  ]);

  const sourceBridge = {
    report_type: 'zlar-time-boxed-source-bridge-window-report-v1',
    authority_status: 'accepted',
    safe_for_control_tower_use: true,
    can_push_under_window: true,
    no_secret_boundary: {
      reads_private_key_material: false,
      reads_token_material: false,
      mints_credentials: false,
      calls_github: false,
      reads_remote_refs: false,
      pushes_source: false,
      changes_configuration: false,
    },
  };
  const proofSmoke = {
    verification_type: 'zlar-proof-smoke-report-verification-v1',
    verified: true,
    report_sha256: PROOF_SMOKE_SHA,
    evidence_model: 'committed-local-fixtures',
    live_probing: false,
  };
  const northStar = {
    report_type: 'zlar-north-star-readiness-v1',
    result: options.ready ? 'READY_FOR_V3_4_0' : 'NOT_READY_FOR_V3_4_0',
    evidence_model: 'committed-local-fixtures',
    claim_boundary: {
      public_external_attestation: false,
      non_operator_review_proven: false,
      production_authority: false,
      enterprise_readiness: false,
      sovereign_recognition: false,
      current_machine_governance: false,
      production_downstream_recognition: false,
      all_mcp_governance: false,
      unrouted_surface_coverage: false,
    },
  };

  const stdoutByStep = {
    'node-check-proof-smoke': '',
    'source-bridge-window': `${JSON.stringify(sourceBridge, null, 2)}\n`,
    'proof-smoke-verify': `${JSON.stringify(proofSmoke, null, 2)}\n`,
    'north-star-readiness': `${JSON.stringify(northStar, null, 2)}\n`,
    'test-proof-smoke-cli': 'proof smoke CLI tests passed\n',
    'test-proof-smoke-report': 'proof smoke report tests passed\n',
    'public-privacy': '=== Public Privacy Hygiene ===\n\nResults: 59/59 passed\n',
  };

  const report = baseReport();
  report.evidence.returned_results_zip_sha256 = sha256Bytes(returnedZipBytes);

  for (const id of REQUIRED_ZIP_RESULT_STEPS) {
    const exitCode = options.nonzeroStep === id ? 2 : 0;
    files.set(`${id}.exit`, `${exitCode}\n`);
    files.set(`${id}.out`, stdoutByStep[id]);
    files.set(`${id}.err`, options.stderrStep === id ? 'unexpected stderr\n' : '');
    const entry = step(report, id);
    entry.exit_code = 0;
    entry.stdout_sha256 = sha256Text(stdoutByStep[id]);
    entry.stderr_sha256 = sha256Text(options.stderrStep === id ? 'unexpected stderr\n' : '');
  }

  const sumNames = [...files.keys()]
    .filter((name) => !['SHA256SUMS.txt', 'SHA256SUMS.err'].includes(name))
    .sort();
  const shaLines = sumNames.map((name) => `${sha256Text(files.get(name))}  ${name}`);
  if (!options.omitShaEntry) {
    files.set('SHA256SUMS.txt', `${shaLines.join('\n')}\n`);
  } else {
    files.set('SHA256SUMS.txt', `${shaLines.slice(1).join('\n')}\n`);
  }
  if (options.extraUnlistedFile) {
    files.set('unlisted-extra.txt', 'unlisted evidence should fail closed\n');
  }
  report.evidence.sha256sums_entry_count = sumNames.length;

  for (const [name, text] of files.entries()) {
    writeFileSync(join(unpacked, name), text);
  }

  return { root, report };
}

console.log('\n-- private verifier ZIP result schema --');
{
  const fixture = JSON.parse(readFileSync('tests/fixtures/private-verifier-zip-result-v1.json', 'utf8'));
  equal('fixture validates', assertPrivateVerifierZipResult(fixture), true);
  const verification = buildPrivateVerifierZipResultVerification(fixture);
  equal('fixture verification type', verification.verification_type, 'zlar-private-verifier-zip-result-verification-v1');
  equal('fixture not recomputed', verification.recomputed_evidence, false);
  equal('fixture allowed claim true', verification.allowed_claim.private_personally_connected_outside_machine_signal, true);
  equal('fixture public attestation false', verification.claim_boundary.public_external_attestation, false);
}

console.log('\n-- private verifier ZIP result evidence recompute --');
{
  const { root, report } = writeEvidence();
  const verification = buildPrivateVerifierZipResultVerification(report, {
    evidenceDir: root,
    requireTarget: `ZLAR-AI/ZLAR@${TARGET_COMMIT}`,
    requireReturnedZipSha: report.evidence.returned_results_zip_sha256,
    requireSourceZipSha: SOURCE_ZIP_SHA,
    requireRecomputedEvidence: true,
  });
  equal('recomputed evidence true', verification.recomputed_evidence, true);
  equal('all checksum entries matched', verification.all_sha256sums_entries_matched, true);
  equal('all required steps zero', verification.all_required_steps_exit_zero, true);
  equal('known stderr only', verification.only_known_stderr_issue, true);
  equal('proof smoke verified', verification.proof_smoke_verified, true);
  equal('north star remains not ready', verification.north_star_result, 'NOT_READY_FOR_V3_4_0');
  equal('public privacy passed', verification.public_privacy_passed, true);
}

console.log('\n-- private verifier ZIP result refusals --');
{
  const bad = baseReport();
  bad.claim_boundary.public_external_attestation = true;
  throws('public attestation overclaim refused', () => assertPrivateVerifierZipResult(bad), 'public_external_attestation');
}
{
  const bad = baseReport();
  bad.verifier.public_label = 'named-person';
  throws('named verifier label refused', () => assertPrivateVerifierZipResult(bad), 'pseudonymous');
}
{
  const bad = baseReport();
  bad.evidence.returned_results_zip_name = '/Users/private/file.zip';
  throws('private path in envelope refused', () => assertPrivateVerifierZipResult(bad), 'safe relative path');
}
{
  const { root, report } = writeEvidence({ nonzeroStep: 'proof-smoke-verify' });
  throws('nonzero exit file refused', () => buildPrivateVerifierZipResultVerification(report, { evidenceDir: root }), 'proof-smoke-verify.exit');
}
{
  const { root, report } = writeEvidence({ stderrStep: 'test-proof-smoke-cli' });
  throws('unexpected stderr refused', () => buildPrivateVerifierZipResultVerification(report, { evidenceDir: root }), 'test-proof-smoke-cli.err');
}
{
  const { root, report } = writeEvidence({ omitShaEntry: true });
  throws('missing checksum entry refused', () => buildPrivateVerifierZipResultVerification(report, { evidenceDir: root }), 'entry count');
}
{
  const { root, report } = writeEvidence({ extraUnlistedFile: true });
  throws('unlisted unpacked file refused', () => buildPrivateVerifierZipResultVerification(report, { evidenceDir: root }), 'unlisted file');
}
{
  const { root, report } = writeEvidence({ ready: true });
  throws('readiness upgrade refused', () => buildPrivateVerifierZipResultVerification(report, { evidenceDir: root }), 'NOT_READY_FOR_V3_4_0');
}
throws('required recompute needs evidence dir', () => buildPrivateVerifierZipResultVerification(baseReport(), { requireRecomputedEvidence: true }), 'requires --evidence-dir');

console.log('\n-- private verifier ZIP result CLI --');
{
  const sample = spawnSync('node', ['bin/zlar-private-verifier-zip-result', 'verify', '--sample', '--json'], {
    encoding: 'utf8',
  });
  equal('sample CLI exits zero', sample.status, 0);
  equal('sample CLI emits no stderr', sample.stderr, '');
  equal('sample CLI verification type', JSON.parse(sample.stdout).verification_type, 'zlar-private-verifier-zip-result-verification-v1');
}
{
  const { root, report } = writeEvidence();
  const inputPath = join(root, 'zlar-private-verifier-zip-result-v1.json');
  writeJson(inputPath, report);
  const cli = spawnSync('node', [
    'bin/zlar-private-verifier-zip-result',
    'verify',
    '--input',
    inputPath,
    '--evidence-dir',
    root,
    '--require-recomputed-evidence',
    '--json',
  ], {
    encoding: 'utf8',
  });
  equal('evidence CLI exits zero', cli.status, 0);
  equal('evidence CLI emits no stderr', cli.stderr, '');
  equal('evidence CLI recomputes', JSON.parse(cli.stdout).recomputed_evidence, true);
}
{
  const dispatch = spawnSync('bash', ['bin/zlar', 'private-verifier-zip-result', 'verify', '--sample', '--json'], {
    encoding: 'utf8',
  });
  equal('main zlar dispatch exits zero', dispatch.status, 0);
  equal('main zlar dispatch emits no stderr', dispatch.stderr, '');
}

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
