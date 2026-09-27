#!/usr/bin/env node
// Fixture/read-only tests for MCP gate coverage evidence assembly.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { projectWorkerReceipt } from '../lib/worker-receipt.mjs';
import {
  assertGovernedSurfaceCoverageMap,
  assertNoUnsafeCoverageMapText,
  buildGovernedSurfaceCoverageMap,
} from '../lib/governed-surface-coverage-map.mjs';
import {
  assertNoUnsafeMcpGateCoverageEvidenceInput,
  buildMcpGateCoverageEvidenceInput,
} from '../lib/mcp-gate-coverage-evidence.mjs';

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

function surface(report, id = 'mcp.tools_call') {
  return report.surfaces.find((item) => item.surface_id === id);
}

const EVENT_ID = 'mcp-evidence-001';
const FIXTURE_EVENT_ID = 'mcp-fixture-event-001';
const POLICY_VERSION = 'coverage-policy-v1';
const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const FIXTURE_PATH = join(process.cwd(), 'tests', 'fixtures', 'mcp-gate-coverage-evidence-v1-input.json');

function mcpAuditEvent(overrides = {}) {
  const hasToolOverride = Object.prototype.hasOwnProperty.call(overrides, 'tool');
  const hasActionOverride = Object.prototype.hasOwnProperty.call(overrides, 'action');
  return {
    id: overrides.id || EVENT_ID,
    ts: '2026-06-18T03:10:00Z',
    seq: 20,
    source: overrides.source || 'mcp-gate',
    host: 'fixture-host',
    user: 'fixture-user',
    agent_id: 'fixture-agent',
    session_id: 'fixture-session',
    transport: 'stdio',
    domain: overrides.domain || 'mcp',
    action: hasActionOverride ? overrides.action : 'fixture.write_record',
    outcome: overrides.outcome || 'deny',
    risk_score: 90,
    detail: {
      tool: hasToolOverride ? overrides.tool : 'fixture.write_record',
      arguments: {
        private_path: '/Users/tester/private-project/record.json',
        token: 'sk-live-mcp-evidence-000000',
      },
    },
    rule: overrides.rule || 'RTEST_MCP_EVIDENCE',
    rule_description: 'Fixture MCP coverage evidence rule.',
    policy_version: overrides.policy_version || POLICY_VERSION,
    policy_key_id: 'fixture-policy-key',
    severity: 'critical',
    prev_hash: overrides.prev_hash || 'd'.repeat(64),
    authorizer: overrides.authorizer || 'policy',
    signature_algorithm: 'Ed25519',
    hash_algorithm: 'SHA-256',
    public_key_id: 'fixture-audit-key',
    signature: 'fixture-signature',
  };
}

function evidenceInput(overrides = {}) {
  const event = overrides.audit_event || overrides.auditEvent || mcpAuditEvent(overrides.eventOverrides || {});
  return {
    generatedAt: '2026-06-18T03:11:00Z',
    event_id: overrides.event_id || EVENT_ID,
    surface_id: 'mcp.tools_call',
    boarding_lane: 'Routed MCP tools/call boarding lane',
    checkpoint_path: 'mcp-gate:tools/call->fixture-upstream',
    mcp_registration: {
      configured: true,
      routed: true,
      zlar_routed: true,
      configured_server_count: 1,
      server_name: 'zlar-routed-fixture',
      transport: 'stdio',
      direct_upstream_observed: false,
      extra_registration_observed: false,
      gate_target: '/Users/tester/Documents/ZLAR/ZLAR_Repo/mcp-gate/gate.mjs token=sk-live-route-000000',
      ...(overrides.mcp_registration || {}),
    },
    heartbeat: {
      state: 'on',
      last_heartbeat_epoch: 6000,
      now_epoch: 6030,
      freshness_seconds: 120,
      ...(overrides.heartbeat || {}),
    },
    policy: {
      active_version: POLICY_VERSION,
      evidence_version: event.policy_version || POLICY_VERSION,
      expected_version: POLICY_VERSION,
      signature_valid: true,
      acknowledged: true,
      key_id: 'fixture-policy-key',
      active_policy_sha256: 'e'.repeat(64),
      policy_pubkey_sha256: 'f'.repeat(64),
      verification_source: 'fixture-policy-verification',
      ...(overrides.policy || {}),
    },
    audit_event: event,
    worker_receipt: Object.prototype.hasOwnProperty.call(overrides, 'worker_receipt')
      ? overrides.worker_receipt
      : projectWorkerReceipt(event),
    downstream_refusal: {
      proved: true,
      applicable: true,
      upstream_observed_on_deny: false,
      mechanism: 'Fixture deny decision did not reach the upstream effect server.',
      ...(overrides.downstream_refusal || {}),
    },
    ...(overrides.root || {}),
  };
}

function coverageReportFromEvidence(input, options = {}) {
  const coverageInput = buildMcpGateCoverageEvidenceInput(input);
  const report = buildGovernedSurfaceCoverageMap(coverageInput);
  if (options.validate !== false) assertGovernedSurfaceCoverageMap(report);
  return { coverageInput, report };
}

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

section('happy path event-scoped MCP evidence');
const happy = coverageReportFromEvidence(evidenceInput());
const happySurface = surface(happy.report);
assertEqual('one counted lane', 1, happy.report.counts.counted_lanes);
assertEqual('MCP evidence governed', true, happySurface.governed);
assertEqual('MCP evidence configured', true, happySurface.configured);
assertEqual('MCP evidence routed', true, happySurface.routed);
assertEqual('MCP evidence alive', true, happySurface.alive);
assertEqual('MCP evidence policy current', true, happySurface.policy_current);
assertEqual('MCP evidence receipt capable', true, happySurface.receipt_capable);
assertEqual('MCP evidence downstream refusal', true, happySurface.downstream_refusal);
assertEqual('MCP evidence status', 'governed', happySurface.verification_status);
assert('route target path redacted', String(happySurface.evidence.route.gate_target).includes('[REDACTED_PATH]'));
assert('route target credential redacted', String(happySurface.evidence.route.gate_target).includes('[REDACTED_CREDENTIAL]'));
assert('route target omits raw path/token', !String(happySurface.evidence.route.gate_target).includes('/Users/tester') && !String(happySurface.evidence.route.gate_target).includes('sk-live-route'));
assertEqual('MCP route has one server', 1, happySurface.evidence.route.configured_server_count);
assertEqual('direct upstream absent', false, happySurface.evidence.route.direct_upstream_observed);
assertEqual('extra registration absent', false, happySurface.evidence.route.extra_registration_observed);
assertEqual('audit event id carried', EVENT_ID, happySurface.evidence.audit_event.id);
assertEqual('audit event source carried', 'mcp-gate', happySurface.evidence.audit_event.source);
assertEqual('receipt surface evidence', 'mcp-gate', happySurface.evidence.receipt.surface);
assert('raw Worker Receipt is emitted for validation', Boolean(happy.coverageInput.mcpGateLane.worker_receipt));
assertEqual('receipt ref is not emitted for happy path', undefined, happy.coverageInput.mcpGateLane.worker_receipt_ref);
assert('coverage input is scanner-safe', assertNoUnsafeMcpGateCoverageEvidenceInput(happy.coverageInput));
assert('coverage report is scanner-safe', assertNoUnsafeCoverageMapText(happy.report));

const serializedHappyInput = JSON.stringify(happy.coverageInput);
assert('coverage input omits raw arguments key', !serializedHappyInput.includes('"arguments"'));
assert('coverage input omits raw params key', !serializedHappyInput.includes('"params"'));
assert('coverage input omits private path', !serializedHappyInput.includes('/Users/tester'));
assert('coverage input omits raw token', !serializedHappyInput.includes('sk-live-mcp-evidence'));
assert('coverage input carries tool name only', serializedHappyInput.includes('fixture.write_record'));

section('fail closed evidence cases');
const stale = coverageReportFromEvidence(evidenceInput({
  heartbeat: {
    state: 'on',
    last_heartbeat_epoch: 6000,
    now_epoch: 6300,
    freshness_seconds: 120,
  },
}));
assertEqual('stale heartbeat downgrades alive', false, surface(stale.report).alive);
assertEqual('stale heartbeat downgrades governed', false, surface(stale.report).governed);
assertEqual('stale heartbeat status', 'stale_or_missing_heartbeat', surface(stale.report).verification_status);

const policyMismatch = coverageReportFromEvidence(evidenceInput({
  policy: { evidence_version: 'coverage-policy-old' },
}));
assertEqual('policy mismatch downgrades policy current', false, surface(policyMismatch.report).policy_current);
assertEqual('policy mismatch downgrades governed', false, surface(policyMismatch.report).governed);
assertEqual('policy mismatch status', 'policy_not_current', surface(policyMismatch.report).verification_status);

const invalidPolicy = coverageReportFromEvidence(evidenceInput({
  policy: { signature_valid: false },
}));
assertEqual('invalid policy downgrades policy current', false, surface(invalidPolicy.report).policy_current);
assertEqual('invalid policy downgrades governed', false, surface(invalidPolicy.report).governed);

const missingReceipt = coverageReportFromEvidence(evidenceInput({ worker_receipt: null }));
assertEqual('missing receipt downgrades receipt capable', false, surface(missingReceipt.report).receipt_capable);
assertEqual('missing receipt downgrades governed', false, surface(missingReceipt.report).governed);
assertEqual('missing receipt status', 'receipt_not_capable', surface(missingReceipt.report).verification_status);

const hash = 'a'.repeat(64);
const detailHash = 'b'.repeat(64);
const forgedRefInput = {
  generatedAt: '2026-06-18T03:12:00Z',
  mcpGateLane: {
    surface_id: 'mcp.tools_call',
    boarding_lane: 'Routed MCP tools/call boarding lane',
    checkpoint_path: 'mcp-gate:tools/call->fixture-upstream',
    mcp_registration: {
      configured: true,
      routed: true,
      zlar_routed: true,
      configured_server_count: 1,
      direct_upstream_observed: false,
      extra_registration_observed: false,
    },
    heartbeat: { state: 'on', last_heartbeat_epoch: 6000, now_epoch: 6030, freshness_seconds: 120 },
    policy: {
      active_version: POLICY_VERSION,
      evidence_version: POLICY_VERSION,
      expected_version: POLICY_VERSION,
      signature_valid: true,
      acknowledged: true,
    },
    audit_event_ref: {
      id: EVENT_ID,
      source: 'mcp-gate',
      domain: 'mcp',
      outcome: 'deny',
      rule: 'RTEST_MCP_EVIDENCE',
      policy_version: POLICY_VERSION,
      audit_hash: hash,
      tool: 'fixture.write_record',
    },
    worker_receipt_ref: {
      present: true,
      valid: true,
      event_id: EVENT_ID,
      surface: 'mcp-gate',
      policy_version: POLICY_VERSION,
      audit_hash: hash,
      detail_hash: detailHash,
      decision_outcome: 'deny',
    },
    downstream_refusal: {
      proved: true,
      applicable: true,
      upstream_observed_on_deny: false,
      mechanism: 'Fixture deny decision did not reach upstream.',
    },
  },
};
const forgedRefReport = buildGovernedSurfaceCoverageMap(forgedRefInput);
assertGovernedSurfaceCoverageMap(forgedRefReport);
assertEqual('forged direct receipt ref is not trusted', false, surface(forgedRefReport).evidence.receipt.validation_trusted);
assertEqual('forged direct receipt ref downgrades receipt capable', false, surface(forgedRefReport).receipt_capable);
assertEqual('forged direct receipt ref downgrades governed', false, surface(forgedRefReport).governed);
assertEqual('forged direct receipt ref status', 'receipt_not_capable', surface(forgedRefReport).verification_status);

const suppliedRefThroughAssembler = coverageReportFromEvidence(evidenceInput({
  worker_receipt: null,
  root: {
    worker_receipt_ref: forgedRefInput.mcpGateLane.worker_receipt_ref,
  },
}));
assertEqual('supplied receipt ref through assembler is not trusted', false, surface(suppliedRefThroughAssembler.report).evidence.receipt.validation_trusted);
assertEqual('supplied receipt ref through assembler is reference-only', true, surface(suppliedRefThroughAssembler.report).evidence.receipt.reference_only);
assertEqual('supplied receipt ref through assembler downgrades receipt capable', false, surface(suppliedRefThroughAssembler.report).receipt_capable);
assertEqual('supplied receipt ref through assembler downgrades governed', false, surface(suppliedRefThroughAssembler.report).governed);

const invalidRawReceipt = coverageReportFromEvidence(evidenceInput({
  worker_receipt: {
    worker_receipt_version: '0.1.0',
    type: 'worker-receipt',
  },
}));
assert('invalid raw receipt records validation error', String(surface(invalidRawReceipt.report).evidence.receipt.validation_error || '').length > 0);
assertEqual('invalid raw receipt downgrades receipt capable', false, surface(invalidRawReceipt.report).receipt_capable);
assertEqual('invalid raw receipt downgrades governed', false, surface(invalidRawReceipt.report).governed);

const otherEvent = mcpAuditEvent({ id: 'mcp-evidence-other' });
const mismatchedReceipt = coverageReportFromEvidence(evidenceInput({
  worker_receipt: projectWorkerReceipt(otherEvent),
}));
assertEqual('mismatched receipt downgrades receipt capable', false, surface(mismatchedReceipt.report).receipt_capable);
assertEqual('mismatched receipt id mismatch named', false, surface(mismatchedReceipt.report).evidence.receipt.id_matches_audit);
assertEqual('mismatched receipt governed false', false, surface(mismatchedReceipt.report).governed);

const missingDownstreamRefusal = coverageReportFromEvidence(evidenceInput({
  downstream_refusal: {
    proved: false,
    upstream_observed_on_deny: true,
    mechanism: 'Fixture intentionally withholds downstream refusal proof.',
  },
}));
assertEqual('missing downstream refusal downgrades refusal', false, surface(missingDownstreamRefusal.report).downstream_refusal);
assertEqual('missing downstream refusal downgrades governed', false, surface(missingDownstreamRefusal.report).governed);
assertEqual('missing downstream refusal status', 'downstream_refusal_missing', surface(missingDownstreamRefusal.report).verification_status);

section('fail closed MCP bypass evidence');
const directUpstream = coverageReportFromEvidence(evidenceInput({
  mcp_registration: { direct_upstream_observed: true },
}), { validate: false });
assertEqual('direct upstream evidence downgrades routed', false, surface(directUpstream.report).routed);
assertEqual('direct upstream evidence downgrades governed', false, surface(directUpstream.report).governed);
assertEqual('direct upstream evidence status', 'rejected_mcp_bypass', surface(directUpstream.report).verification_status);
assertThrows('direct upstream evidence rejected by validator', () => {
  assertGovernedSurfaceCoverageMap(directUpstream.report);
}, 'direct MCP upstream');

const extraRegistration = coverageReportFromEvidence(evidenceInput({
  mcp_registration: {
    configured_server_count: 2,
    extra_registration_observed: true,
  },
}), { validate: false });
assertEqual('extra registration evidence downgrades routed', false, surface(extraRegistration.report).routed);
assertEqual('extra registration evidence downgrades governed', false, surface(extraRegistration.report).governed);
assertEqual('extra registration evidence status', 'rejected_mcp_bypass', surface(extraRegistration.report).verification_status);
assertThrows('extra registration evidence rejected by validator', () => {
  assertGovernedSurfaceCoverageMap(extraRegistration.report);
}, 'extra MCP registration');

section('reject non-MCP surfaces');
assertThrows('bash event rejected', () => {
  buildMcpGateCoverageEvidenceInput(evidenceInput({
    audit_event: mcpAuditEvent({ source: 'gate', domain: 'bash' }),
  }));
}, 'mcp-gate-sourced MCP');
assertThrows('SDK event rejected', () => {
  buildMcpGateCoverageEvidenceInput(evidenceInput({
    audit_event: mcpAuditEvent({ source: 'sdk-daemon', domain: 'mcp' }),
  }));
}, 'mcp-gate-sourced MCP');
assertThrows('subagent event rejected', () => {
  buildMcpGateCoverageEvidenceInput(evidenceInput({
    audit_event: mcpAuditEvent({ source: 'mcp-gate', domain: 'subagent' }),
  }));
}, 'mcp-gate-sourced MCP');
assertThrows('MCP event without tool rejected', () => {
  buildMcpGateCoverageEvidenceInput(evidenceInput({
    audit_event: mcpAuditEvent({ action: '', tool: '' }),
  }));
}, 'tool name');

section('privacy and claim scanner');
assertThrows('broad claim rejected', () => {
  buildMcpGateCoverageEvidenceInput(evidenceInput({
    root: { non_claims: ['ZLAR governs all actions'] },
  }));
}, 'broad action claim');
assertThrows('chat id rejected', () => {
  buildMcpGateCoverageEvidenceInput(evidenceInput({
    root: { non_claims: ['chat_id=123456'] },
  }));
}, 'chat id');
assertThrows('production authority claim rejected', () => {
  buildMcpGateCoverageEvidenceInput(evidenceInput({
    root: { non_claims: ['production authority'] },
  }));
}, 'production authority');
assertThrows('raw MCP args field rejected if reintroduced', () => {
  assertNoUnsafeMcpGateCoverageEvidenceInput({
    mcpGateLane: {
      arguments: { secret: 'nope' },
    },
  });
}, 'raw MCP args');

section('CLI wiring');
const fixtureText = readFileSync(FIXTURE_PATH, 'utf8');
assert('committed fixture omits private paths', !fixtureText.includes('/Users/') && !fixtureText.includes('/home/') && !fixtureText.includes('/private/') && !fixtureText.includes('/tmp/'));
assert('committed fixture omits obvious secrets', !/sk-[A-Za-z0-9_-]{6,}|ghp_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{12,}|bot[0-9]{6,}:/i.test(fixtureText));
assert('committed fixture omits chat ids and numeric human ids', !/\bchat_id\b/i.test(fixtureText) && !/\bhuman:[0-9]/.test(fixtureText));
assert('committed fixture omits raw args fields', !/"(?:args|arguments|params|payload|request|raw_args|mcp_args)"\s*:/i.test(fixtureText));

const fixtureCli = runZlar(['coverage-evidence', 'mcp', '--input', FIXTURE_PATH, '--event-id', FIXTURE_EVENT_ID]);
assertEqual('committed fixture MCP coverage-evidence exits zero', 0, fixtureCli.status);
assertEqual('committed fixture MCP coverage-evidence emits no stderr', '', fixtureCli.stderr);
const fixtureCoverageInput = JSON.parse(fixtureCli.stdout);
assertEqual('committed fixture event id carried', FIXTURE_EVENT_ID, fixtureCoverageInput.mcpGateLane.audit_event_id);
assertEqual('committed fixture emits MCP lane', 'mcp.tools_call', fixtureCoverageInput.mcpGateLane.surface_id);
assert('committed fixture output omits raw args fields', !/"(?:args|arguments|params|payload|request|raw_args|mcp_args)"\s*:/i.test(fixtureCli.stdout));
assert('committed fixture output omits raw sensitive paths', !fixtureCli.stdout.includes('/Users/') && !fixtureCli.stdout.includes('/home/') && !fixtureCli.stdout.includes('/tmp/'));
assert('committed fixture output scanner-safe', assertNoUnsafeMcpGateCoverageEvidenceInput(fixtureCoverageInput));

const fixtureCoverage = runZlar(['coverage', '--input', '-', '--require-governed'], {
  input: fixtureCli.stdout,
});
assertEqual('coverage consumes committed MCP fixture evidence', 0, fixtureCoverage.status);
assert('committed MCP fixture coverage reports one governed lane', fixtureCoverage.stdout.includes('Counts: governed=1/1'));
assert('committed MCP fixture coverage preserves no live probing', fixtureCoverage.stdout.includes('live probing=false'));

const scratch = mkdtempSync(join(tmpdir(), 'zlar-mcp-coverage-evidence-'));
try {
  const evidencePath = join(scratch, 'mcp-evidence.json');
  writeFileSync(evidencePath, `${JSON.stringify(evidenceInput(), null, 2)}\n`);

  const cli = runZlar(['coverage-evidence', 'mcp', '--input', evidencePath, '--event-id', EVENT_ID]);
  assertEqual('MCP coverage-evidence CLI exits zero', 0, cli.status);
  const cliInput = JSON.parse(cli.stdout);
  assertEqual('MCP coverage-evidence CLI emits MCP lane', 'mcp.tools_call', cliInput.mcpGateLane.surface_id);
  assert('MCP coverage-evidence CLI omits scratch path', !cli.stdout.includes(scratch) && !cli.stderr.includes(scratch));
  assert('MCP coverage-evidence CLI omits private path', !cli.stdout.includes('/Users/tester'));
  assert('MCP coverage-evidence CLI omits raw token', !cli.stdout.includes('sk-live-mcp-evidence'));
  assert('MCP coverage-evidence CLI omits raw args fields', !/"(?:args|arguments|params|payload|request|raw_args|mcp_args)"\s*:/i.test(cli.stdout));

  const coverage = runZlar(['coverage', '--input', '-', '--require-governed'], {
    input: cli.stdout,
  });
  assertEqual('coverage consumes emitted MCP evidence', 0, coverage.status);
  assert('coverage summary reports one governed MCP lane', coverage.stdout.includes('Counts: governed=1/1'));
  assert('coverage summary preserves no live probing', coverage.stdout.includes('live probing=false'));

  const missingEventId = runZlar(['coverage-evidence', 'mcp', '--input', evidencePath]);
  assertEqual('missing event id exits usage error', 2, missingEventId.status);
  assert('missing event id refuses latest selection', missingEventId.stderr.includes('latest-event selection is not implemented'));
  assertEqual('missing event id emits no JSON', '', missingEventId.stdout);

  const missingInput = runZlar(['coverage-evidence', 'mcp', '--input', join(scratch, 'missing.json'), '--event-id', EVENT_ID]);
  assertEqual('missing input exits read error', 1, missingInput.status);
  assert('missing input error is privacy safe', !missingInput.stderr.includes(scratch) && missingInput.stderr.includes('Could not read mcp coverage evidence input.'));
  assertEqual('missing input emits no JSON', '', missingInput.stdout);

  const fakePrivateOption = `/Users/tester/${['sk', 'live', 'option', '000000'].join('-')}`;
  const unsupported = runZlar(['coverage-evidence', 'mcp', `--${fakePrivateOption}`, '--input', evidencePath, '--event-id', EVENT_ID]);
  assertEqual('unsupported option exits usage error', 2, unsupported.status);
  assert('unsupported option is privacy safe', !unsupported.stderr.includes(fakePrivateOption) && !unsupported.stderr.includes('sk-live-option'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
