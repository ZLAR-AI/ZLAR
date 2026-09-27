#!/usr/bin/env node

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { projectWorkerReceipt } from '../lib/worker-receipt.mjs';

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
const FIXTURE_PATH = join(
  process.cwd(),
  'tests',
  'fixtures',
  'downstream-recognition-v1-input.json'
);
const COVERAGE_FIXTURE_PATH = join(
  process.cwd(),
  'tests',
  'fixtures',
  'governed-surface-coverage-map-v1-input.json'
);

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

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-downstream-recognition-cli-'));

try {
  const fixtureText = readFileSync(FIXTURE_PATH, 'utf8');
  const fixture = JSON.parse(fixtureText);

  section('committed fixture');
  assertEqual('fixture type', 'downstream-recognition-input-v1', fixture.fixture_type);
  assertEqual('fixture expected refusal reason', 'policy_not_recognized', fixture.expected_decision.reason_code);
  assert('fixture includes public key only as input trust anchor', fixtureText.includes('BEGIN PUBLIC KEY'));
  assert('fixture omits private key material', !/BEGIN [A-Z ]*PRIVATE KEY/.test(fixtureText));
  assert('fixture omits private paths and fake credentials', !/\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]/i.test(fixtureText));

  section('refused decision from supplied receipt and rule');
  const refusedRun = runZlar(['downstream-recognition', '--input', FIXTURE_PATH, '--require-refused']);
  assertEqual('refused fixture exits zero', 0, refusedRun.status);
  assertEqual('refused fixture emits no stderr', '', refusedRun.stderr);
  const refusedDecision = JSON.parse(refusedRun.stdout);
  assertEqual('refused result type', 'downstream-recognition-rule-v1', refusedDecision.result_type);
  assertEqual('refused decision', 'refuse', refusedDecision.decision);
  assertEqual('refused recognized false', false, refusedDecision.recognized);
  assertEqual('refused reason', 'policy_not_recognized', refusedDecision.reason_code);
  assertEqual('refused signature valid', true, refusedDecision.evidence.signature_valid);
  assertEqual('refused policy evidence', 'recognition-policy-old', refusedDecision.evidence.payload.policy_version);
  assert('refused output omits key material and private data', !unsafeOutputPattern.test(refusedRun.stdout));
  assert('refused output states non-claim boundary', refusedRun.stdout.includes('does not prove production deployment'));

  const refusedStdin = runZlar(['downstream-recognition', '--input', '-', '--require-refused'], {
    input: fixtureText,
  });
  assertEqual('stdin refused fixture exits zero', 0, refusedStdin.status);
  assertEqual('stdin refused reason preserved', 'policy_not_recognized', JSON.parse(refusedStdin.stdout).reason_code);

  const requireRecognizedFailure = runZlar(['downstream-recognition', '--input', FIXTURE_PATH, '--require-recognized']);
  assert('require-recognized fails refused fixture', requireRecognizedFailure.status !== 0);
  assertEqual('require-recognized failure emits no JSON', '', requireRecognizedFailure.stdout);
  assert('require-recognized failure names refusal', requireRecognizedFailure.stderr.includes('policy_not_recognized'));

  section('recognized decision from supplied receipt and widened test rule');
  const recognizedInput = structuredClone(fixture);
  recognizedInput.recognition_rule.accepted_policy_versions = ['recognition-policy-old'];
  recognizedInput.expected_decision = {
    decision: 'accept',
    reason_code: 'recognized',
  };
  const recognizedPath = join(scratch, 'recognized.json');
  writeFileSync(recognizedPath, `${JSON.stringify(recognizedInput, null, 2)}\n`);

  const recognizedRun = runZlar(['downstream-recognition', '--input', recognizedPath, '--require-recognized']);
  assertEqual('recognized fixture exits zero', 0, recognizedRun.status);
  assertEqual('recognized fixture emits no stderr', '', recognizedRun.stderr);
  const recognizedDecision = JSON.parse(recognizedRun.stdout);
  assertEqual('recognized decision', 'accept', recognizedDecision.decision);
  assertEqual('recognized true', true, recognizedDecision.recognized);
  assertEqual('recognized reason', 'recognized', recognizedDecision.reason_code);
  assert('recognized output omits key material and private data', !unsafeOutputPattern.test(recognizedRun.stdout));

  const requireRefusedFailure = runZlar(['downstream-recognition', '--input', recognizedPath, '--require-refused']);
  assert('require-refused fails recognized fixture', requireRefusedFailure.status !== 0);
  assertEqual('require-refused failure emits no JSON', '', requireRefusedFailure.stdout);

  section('coverage map binds emitted refused decision to lane');
  const unrelatedCoverageInput = JSON.parse(readFileSync(COVERAGE_FIXTURE_PATH, 'utf8'));
  unrelatedCoverageInput.bashGateLane.downstream_refusal = {
    recognition_decision: refusedDecision,
  };
  const unrelatedCoverageRun = runZlar(['coverage', '--input', '-', '--require-governed'], {
    input: `${JSON.stringify(unrelatedCoverageInput, null, 2)}\n`,
  });
  assert('coverage rejects refused decision for different lane', unrelatedCoverageRun.status !== 0);
  assertEqual('unrelated coverage emits no summary', '', unrelatedCoverageRun.stdout);
  assert('unrelated coverage names downstream refusal missing', unrelatedCoverageRun.stderr.includes('downstream_refusal_missing'));

  const coverageInput = JSON.parse(readFileSync(COVERAGE_FIXTURE_PATH, 'utf8'));
  const matchingPolicyVersion = refusedDecision.evidence.payload.policy_version;
  const matchingAuditEvent = {
    ...coverageInput.bashGateLane.audit_event,
    id: refusedDecision.evidence.payload.audit_event_id,
    ts: refusedDecision.evidence.payload.ts,
    domain: refusedDecision.evidence.payload.domain,
    action: refusedDecision.evidence.payload.tool,
    outcome: refusedDecision.evidence.payload.outcome,
    detail: {
      record_type: 'fixture-record',
      operation: 'update_status',
    },
    rule: refusedDecision.evidence.payload.rule,
    rule_description: 'Fixture records write rule for downstream recognition coverage.',
    policy_version: matchingPolicyVersion,
  };
  coverageInput.bashGateLane.audit_event = matchingAuditEvent;
  coverageInput.bashGateLane.policy = {
    ...coverageInput.bashGateLane.policy,
    active_version: matchingPolicyVersion,
    evidence_version: matchingPolicyVersion,
    expected_version: matchingPolicyVersion,
  };
  coverageInput.bashGateLane.worker_receipt = projectWorkerReceipt(matchingAuditEvent);
  coverageInput.bashGateLane.downstream_refusal = {
    recognition_decision: refusedDecision,
  };
  const currentCoverageInputText = `${JSON.stringify(coverageInput, null, 2)}\n`;
  const coverageRun = runZlar(['coverage', '--input', '-'], {
    input: currentCoverageInputText,
  });
  assert(
    'coverage consumes lane-bound refused recognition decision',
    coverageRun.status === 0,
    coverageRun.stderr.trim(),
  );
  assert('coverage remains fixture-only', coverageRun.stdout.includes('Evidence model: fixtures; live probing=false'));
  assert('coverage reports current governed lanes', coverageRun.stdout.includes('Counts: governed=4/6'));
  const requireCurrentGovernedRun = runZlar(['coverage', '--input', '-', '--require-governed'], {
    input: currentCoverageInputText,
  });
  assert('current coverage require-governed refuses two demoted lanes', requireCurrentGovernedRun.status !== 0);
  assertEqual('current coverage require-governed emits no summary', '', requireCurrentGovernedRun.stdout);
  assert('current coverage refusal names runtime profile-installation', requireCurrentGovernedRun.stderr.includes('protected-records.runtime.profile-installation.records.write:receipt_not_capable'));
  assert('current coverage refusal names installed terminal-chain', requireCurrentGovernedRun.stderr.includes('protected-records.installed-runtime-profile.terminal-chain.records.write:receipt_not_capable'));

  section('fail closed command handling');
  const missingInput = runZlar(['downstream-recognition']);
  assert('missing input exits usage error', missingInput.status !== 0);
  assert('missing input refuses live probing', missingInput.stderr.includes('live probing is not implemented'));
  assertEqual('missing input emits no JSON', '', missingInput.stdout);

  const unsupported = runZlar(['downstream-recognition', '--input', FIXTURE_PATH, '--latest']);
  assert('unsupported option exits usage error', unsupported.status !== 0);
  assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));
  assertEqual('unsupported option emits no JSON', '', unsupported.stdout);

  const bothRequire = runZlar([
    'downstream-recognition',
    '--input',
    FIXTURE_PATH,
    '--require-refused',
    '--require-recognized',
  ]);
  assert('mutually exclusive require flags fail', bothRequire.status !== 0);
  assert('mutually exclusive error is explicit', bothRequire.stderr.includes('mutually exclusive'));
  assertEqual('mutually exclusive emits no JSON', '', bothRequire.stdout);

  const unsafeInput = structuredClone(fixture);
  unsafeInput.recognition_rule.deployment_scope = '/Users/tester/private-terminal';
  const unsafePath = join(scratch, 'unsafe.json');
  writeFileSync(unsafePath, `${JSON.stringify(unsafeInput, null, 2)}\n`);
  const unsafeRun = runZlar(['downstream-recognition', '--input', unsafePath]);
  assert('unsafe output exits nonzero', unsafeRun.status !== 0);
  assert('unsafe output rejected by scanner', unsafeRun.stderr.includes('private operator path'));
  assertEqual('unsafe output emits no JSON', '', unsafeRun.stdout);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
