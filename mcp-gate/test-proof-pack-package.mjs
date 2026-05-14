#!/usr/bin/env node
// Hermetic tests for Proof Pack Packaging v0.

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { projectWorkerReceipt } from '../lib/worker-receipt.mjs';
import {
  SERVER_NAME,
  buildProfileReport,
} from './smoke-codex-cli.mjs';
import {
  buildGovernedProfileCoverageReport,
  formatGovernedProfileCoverageSummary,
  stableStringify,
} from './governed-profile-coverage-report.mjs';
import {
  assertNoUnsafeProofPackText,
  assertProofPackBundleSafe,
  packageProofPackBundle,
} from './proof-pack-package.mjs';

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

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function mcpEvent({ id, action, outcome, rule, authorizer = 'policy', prev = 'genesis' }) {
  return {
    id,
    ts: '2026-05-14T12:00:00Z',
    seq: Number(id.replace(/\D/g, '')) || 1,
    source: 'mcp-gate',
    host: 'test-host',
    user: 'tester',
    agent_id: 'codex-cli',
    session_id: 'proof-pack-session',
    transport: 'stdio',
    domain: 'mcp',
    action,
    outcome,
    risk_score: outcome === 'allow' ? 0 : 80,
    detail: { tool: action, marker_hash: sha256Hex(action) },
    rule,
    rule_description: `Rule for ${action}`,
    policy_version: 'proof-pack-policy-v0',
    policy_key_id: 'policy-key-test',
    severity: outcome === 'allow' ? 'info' : 'critical',
    prev_hash: prev,
    authorizer,
    signature_algorithm: 'Ed25519',
    hash_algorithm: 'SHA-256',
    public_key_id: 'audit-key-test',
    signature: 'test',
  };
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-proof-pack-test-'));
const outputDir = join(scratch, 'proof-pack');
const cliOutputDir = join(scratch, 'proof-pack-cli');
const inputDir = join(scratch, 'inputs');
mkdirSync(inputDir, { recursive: true });

try {
  const wrapperPath = join(scratch, 'zlar-wrapper.sh');
  const upstreamPort = 18181;
  const safeMcpGet = {
    name: SERVER_NAME,
    enabled: true,
    transport: {
      type: 'stdio',
      command: wrapperPath,
      args: [],
      env: null,
      cwd: null,
    },
  };
  const safeMcpList = `Name            Command                         Args  Env  Cwd  Status   Auth
${SERVER_NAME}  ${wrapperPath}                  -     -    -    enabled  Unsupported
`;

  const profileReport = buildProfileReport({
    mcpGetAfterAdd: safeMcpGet,
    mcpListAfterAdd: safeMcpList,
    upstreamPort,
    sessionId: 'proof-pack-test',
  });

  const allowEvent = mcpEvent({ id: 'pack-allow-001', action: 'proof.allow', outcome: 'allow', rule: 'P1_ALLOW' });
  const denyEvent = mcpEvent({ id: 'pack-deny-001', action: 'proof.deny', outcome: 'deny', rule: 'P1_DENY', prev: 'a'.repeat(64) });
  const authorizedEvent = mcpEvent({
    id: 'pack-authorized-001',
    action: 'proof.ask_approve',
    outcome: 'authorized',
    rule: 'P2_ASK_APPROVE',
    authorizer: 'human:operator-1',
    prev: 'b'.repeat(64),
  });
  const deniedEvent = mcpEvent({
    id: 'pack-denied-001',
    action: 'proof.ask_deny',
    outcome: 'denied',
    rule: 'P2_ASK_DENY',
    authorizer: 'human:operator-1',
    prev: 'c'.repeat(64),
  });

  const proofReport = {
    report_type: 'routed-mcp-client-proof',
    governed_routed_mcp_calls: [
      { expected_decision: 'allow', upstream_observed: true, auditEvent: allowEvent },
      { expected_decision: 'deny', upstream_observed: false, auditEvent: denyEvent },
      { expected_decision: 'authorized', upstream_observed: true, auditEvent: authorizedEvent },
      { expected_decision: 'denied', upstream_observed: false, auditEvent: deniedEvent },
    ],
  };
  const workerReceipts = [allowEvent, denyEvent, authorizedEvent, deniedEvent]
    .map((event) => projectWorkerReceipt(event));
  const whyByEventId = {
    [allowEvent.id]: 'available',
    [denyEvent.id]: 'missing',
    [authorizedEvent.id]: true,
    [deniedEvent.id]: { status: 'not_checked' },
  };
  const coverageReport = buildGovernedProfileCoverageReport({
    profileReport,
    routedMcpProofReport: proofReport,
    workerReceipts,
    whyByEventId,
    generatedAt: '2026-05-14T12:34:56Z',
  });
  const coverageSummary = formatGovernedProfileCoverageSummary(coverageReport);

  section('bundle packaging');
  const result = packageProofPackBundle({
    outputDir,
    coverageReport,
    coverageSummary,
    routedMcpProofReport: proofReport,
    workerReceipts,
    whyByEventId,
    verifierKitRunnerStatus: {
      status: 'prepared_pending',
      external_attestation: 'not_attested',
      dry_run: 'not_checked',
    },
    generatedAt: '2026-05-14T13:00:00Z',
  });

  assert('manifest exists', existsSync(result.manifestPath));
  assert('README exists', existsSync(result.readmePath));
  assert('coverage JSON exists', existsSync(result.coverageJsonPath));
  assert('coverage text exists', existsSync(result.coverageTextPath));
  assert('bundle safety scan passes', assertProofPackBundleSafe(result.bundleDir));
  assertEqual('pack type', 'zlar-proof-pack-v0', result.manifest.pack_type);
  assertEqual('coverage report included', true, result.manifest.evidence.governed_profile_coverage_report.included);
  assertEqual('routed proof referenced only', false, result.manifest.evidence.routed_mcp_proof_report.included);
  assertEqual('worker raw store omitted', false, result.manifest.evidence.worker_receipts.included_raw_store);
  assertEqual('worker receipt summary count', workerReceipts.length, result.manifest.evidence.worker_receipts.receipt_summaries.length);
  assertEqual('why allow available', 'available', result.manifest.evidence.why_lookup.status_by_event_id[allowEvent.id]);
  assertEqual('why deny missing', 'missing', result.manifest.evidence.why_lookup.status_by_event_id[denyEvent.id]);
  assertEqual('external attestation remains not attested', 'not_attested', result.manifest.evidence.verifier_kit.packet.external_attestation);
  assert('manifest lists residual ungoverned surfaces', result.manifest.residual_ungoverned_surfaces.length >= 4);
  assert('privacy checks all true', Object.values(result.manifest.privacy_validation.checks).every(Boolean));

  const bundleText = result.files
    .map((file) => readFileSync(join(result.bundleDir, file), 'utf8'))
    .join('\n');
  assert('bundle omits raw proof marker details', !bundleText.includes('marker_hash'));
  assert('bundle omits scratch path', !bundleText.includes(scratch));
  assert('bundle omits unredacted worker store body', !bundleText.includes('Rule for proof.allow'));

  section('CLI packaging');
  const coverageJsonPath = join(inputDir, 'coverage.json');
  const coverageTextPath = join(inputDir, 'coverage.txt');
  const proofPath = join(inputDir, 'proof.json');
  const workerReceiptPath = join(inputDir, 'worker-receipts.jsonl');
  const whyPath = join(inputDir, 'why.json');
  writeFileSync(coverageJsonPath, `${JSON.stringify(coverageReport, null, 2)}\n`);
  writeFileSync(coverageTextPath, coverageSummary);
  writeFileSync(proofPath, `${JSON.stringify(proofReport, null, 2)}\n`);
  writeFileSync(workerReceiptPath, `${workerReceipts.map((receipt) => JSON.stringify(receipt)).join('\n')}\n`);
  writeFileSync(whyPath, `${JSON.stringify(whyByEventId, null, 2)}\n`);

  const cli = spawnSync(process.execPath, [
    join(process.cwd(), 'mcp-gate', 'proof-pack-package.mjs'),
    '--coverage-json', coverageJsonPath,
    '--coverage-text', coverageTextPath,
    '--routed-proof-json', proofPath,
    '--worker-receipts-jsonl', workerReceiptPath,
    '--why-json', whyPath,
    '--out-dir', cliOutputDir,
  ], { cwd: join(process.cwd()), encoding: 'utf8' });
  assertEqual('CLI exits zero', 0, cli.status);
  assert('CLI writes manifest', existsSync(join(cliOutputDir, 'proof-pack-manifest.json')));
  assert('CLI bundle scan passes', assertProofPackBundleSafe(cliOutputDir));

  section('privacy guard');
  const numericHumanFixture = ['human:', '123456'].join('');
  const credentialFixture = [['sk', 'proofpack', 'credential000000'].join('-')].join('');
  const privatePathFixture = ['/', 'Users', 'tester', 'private'].join('/');
  assertThrows('numeric human id rejected', () => {
    assertNoUnsafeProofPackText(`authorizer ${numericHumanFixture}`);
  }, 'numeric human identifier');
  assertThrows('credential rejected', () => {
    assertNoUnsafeProofPackText(`credential ${credentialFixture}`);
  }, 'OpenAI-style key');
  assertThrows('private path rejected', () => {
    assertNoUnsafeProofPackText(`path ${privatePathFixture}`);
  }, 'private operator path');
  assertThrows('raw args key rejected', () => {
    assertNoUnsafeProofPackText(['args_', 'preview'].join(''));
  }, 'raw MCP args key');
  const broadCodexPhrase = ['governs', 'Codex'].join(' ');
  assertThrows('broad Codex claim rejected', () => {
    assertNoUnsafeProofPackText(broadCodexPhrase);
  }, 'broad Codex claim');

  const manifestText = JSON.stringify(result.manifest);
  assertEqual('manifest coverage json hash', sha256Hex(stableStringify(coverageReport)), result.manifest.evidence.governed_profile_coverage_report.json_sha256);
  assert('manifest does not contain broad Codex phrase', !manifestText.includes(broadCodexPhrase));

  console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
  if (FAIL > 0) process.exit(1);
  console.log('ALL PASS');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
