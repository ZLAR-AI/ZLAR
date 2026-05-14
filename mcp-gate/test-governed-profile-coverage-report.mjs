#!/usr/bin/env node
// Hermetic tests for Governed Profile Coverage Report v0.

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { projectWorkerReceipt } from '../lib/worker-receipt.mjs';
import {
  SERVER_NAME,
  buildProfileReport,
} from './smoke-codex-cli.mjs';
import {
  SAFE_CLAIM_CEILING,
  assertGovernedProfileCoverageReport,
  assertNoUnsafeCoverageText,
  buildGovernedProfileCoverageReport,
  formatGovernedProfileCoverageSummary,
} from './governed-profile-coverage-report.mjs';

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

function surface(report, id) {
  return report.surfaces.find((item) => item.id === id);
}

function stableStringifyLocal(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringifyLocal).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringifyLocal(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256HexLocal(value) {
  return createHash('sha256').update(value).digest('hex');
}

const scratch = join(tmpdir(), 'zlar-codex-cli-mcp-smoke');
const wrapperPath = join(scratch, 'zlar-smoke-cli-wrapper.sh');
const upstreamPort = 18181;
const fakeCredentialPrefix = ['to', 'ken'].join('');
const fakeCredentialValue = ['sk', 'live', 'test', 'fixture', '000000'].join('-');
const fakeMcpCredentialValue = ['sk', 'live', 'mcp', '000000'].join('-');

const safeMcpGet = {
  name: SERVER_NAME,
  enabled: true,
  transport: {
    type: 'stdio',
    command: wrapperPath,
    args: [],
    env: {
      HOME: join(scratch, 'home'),
      SHOULD_NOT_LEAK: `${fakeCredentialPrefix}=${fakeCredentialValue}`,
    },
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
  sessionId: 'coverage-report-test',
});

function mcpEvent({ id, action, outcome, rule, authorizer = 'policy', prev = 'genesis' }) {
  return {
    id,
    ts: '2026-05-14T12:00:00Z',
    seq: Number(id.replace(/\D/g, '')) || 1,
    source: 'mcp-gate',
    host: 'test-host',
    user: 'tester',
    agent_id: 'codex-cli',
    session_id: 'coverage-session',
    transport: 'stdio',
    domain: 'mcp',
    action,
    outcome,
    risk_score: outcome === 'allow' ? 0 : 80,
    detail: {
      tool: action,
      args_preview: JSON.stringify({
        marker: 'marker_deny',
        path: '/Users/tester/private',
        [fakeCredentialPrefix]: fakeMcpCredentialValue,
      }),
    },
    rule,
    rule_description: `Rule for ${action}`,
    policy_version: 'coverage-policy-v0',
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

const allowEvent = mcpEvent({ id: 'cov-allow-001', action: 'proof.allow', outcome: 'allow', rule: 'P1_ALLOW' });
const denyEvent = mcpEvent({ id: 'cov-deny-001', action: 'proof.deny', outcome: 'deny', rule: 'P1_DENY', prev: 'a'.repeat(64) });
const authorizedEvent = mcpEvent({
  id: 'cov-authorized-001',
  action: 'proof.ask_approve',
  outcome: 'authorized',
  rule: 'P2_ASK_APPROVE',
  authorizer: 'human:operator-1',
  prev: 'b'.repeat(64),
});
const deniedEvent = mcpEvent({
  id: 'cov-denied-001',
  action: 'proof.ask_deny',
  outcome: 'denied',
  rule: 'P2_ASK_DENY',
  authorizer: 'human:operator-1',
  prev: 'c'.repeat(64),
});

const proofReport = {
  governed_routed_mcp_calls: [
    { expected_decision: 'allow', upstream_observed: true, auditEvent: allowEvent },
    { expected_decision: 'deny', upstream_observed: false, auditEvent: denyEvent },
    { expected_decision: 'authorized', upstream_observed: true, auditEvent: authorizedEvent },
    { expected_decision: 'denied', upstream_observed: false, auditEvent: deniedEvent },
  ],
};

const workerReceipts = [allowEvent, denyEvent, authorizedEvent, deniedEvent].map((event) => projectWorkerReceipt(event));
const whyByEventId = {
  [allowEvent.id]: true,
  [denyEvent.id]: false,
  [authorizedEvent.id]: 'available',
  [deniedEvent.id]: { status: 'not_checked' },
};

section('happy path report');
const report = buildGovernedProfileCoverageReport({
  profileReport,
  routedMcpProofReport: proofReport,
  workerReceipts,
  whyByEventId,
  generatedAt: '2026-05-14T12:34:56Z',
});

assert('valid report passes validation', assertGovernedProfileCoverageReport(report));
assertEqual('uses exact safe claim ceiling', SAFE_CLAIM_CEILING, report.safe_claim_ceiling);
assertEqual('profile client', 'Codex CLI', report.profile.client);
assert('profile is isolated', report.profile.isolated_config);
assertEqual('routed tools/call surface is routed', 'routed', surface(report, 'codex.mcp.tools_call.routed_profile').status);
assertEqual('direct upstream sentinel blocked in happy path', 'blocked', surface(report, 'codex.mcp.registration.direct_upstream_bypass').status);
assertEqual('extra registration sentinel blocked in happy path', 'blocked', surface(report, 'codex.mcp.registration.extra_server_bypass').status);
assertEqual('non-tools/call is out of scope', 'out_of_scope', surface(report, 'codex.mcp.protocol.non_tools_call').status);
assertEqual('shell is out of scope', 'out_of_scope', surface(report, 'codex.shell').status);
assertEqual('/contest is disclosed', 'disclosed', surface(report, 'zlar.contest').status);
assertEqual('external verifier attestation disclosed', 'disclosed', surface(report, 'external.verifier_attestation').status);
assertEqual('verifier kit prepared pending', 'prepared_pending', report.verifier_kit_packet.status);
assertEqual('verifier kit not externally attested', 'not_attested', report.verifier_kit_packet.external_attestation);

section('decision evidence');
const denySurface = surface(report, 'codex.mcp.decision.deny');
assertEqual('deny surface is blocked', 'blocked', denySurface.status);
assertEqual('deny audit id represented', denyEvent.id, denySurface.evidence.audit_event_ids[0]);
assertEqual('deny /why status missing', 'missing', denySurface.why.status);
assertEqual('allow /why status available', 'available', surface(report, 'codex.mcp.decision.allow').why.status);
assertEqual('denied /why status not checked', 'not_checked', surface(report, 'codex.mcp.decision.denied').why.status);

const allowReceipt = surface(report, 'codex.mcp.decision.allow').worker_receipts[0];
assertEqual('Worker Receipt event id captured', allowEvent.id, allowReceipt.event_id);
assertEqual('Worker Receipt hash computed', sha256HexLocal(stableStringifyLocal(workerReceipts[0])), allowReceipt.receipt_sha256);
assert('Worker Receipt detail hash present', /^[a-f0-9]{64}$/.test(allowReceipt.detail_hash));

const reportText = JSON.stringify(report);
assert('deny evidence omits raw marker args', !reportText.includes('marker_deny'));
assert('deny evidence omits raw secret', !reportText.includes(fakeMcpCredentialValue));
assert('deny evidence omits private path', !reportText.includes('/Users/tester'));

section('missing evidence stays unknown');
const missingEvidenceReport = buildGovernedProfileCoverageReport({
  profileReport,
  generatedAt: '2026-05-14T12:40:00Z',
});
assertGovernedProfileCoverageReport(missingEvidenceReport);
assertEqual('missing allow audit is unknown', 'unknown', surface(missingEvidenceReport, 'codex.mcp.decision.allow').status);
assertEqual('missing deny audit is unknown', 'unknown', surface(missingEvidenceReport, 'codex.mcp.decision.deny').status);
assertEqual('missing receipt leaves why not checked', 'not_checked', surface(missingEvidenceReport, 'codex.mcp.decision.allow').why.status);

section('schema guards');
const badStatusReport = JSON.parse(JSON.stringify(report));
badStatusReport.surfaces[0].status = 'governed';
assertThrows('status enum rejects unknown value', () => {
  assertGovernedProfileCoverageReport(badStatusReport);
}, 'status is invalid');

const unsafeExternalReport = JSON.parse(JSON.stringify(report));
unsafeExternalReport.verifier_kit_packet.external_attestation = 'externally_attested';
assertThrows('external attestation completion is rejected', () => {
  assertGovernedProfileCoverageReport(unsafeExternalReport);
}, 'external attestation');

section('bypass sentinels reject unsafe profile evidence');
for (const [label, transport] of [
  ['direct command', {
    type: 'stdio',
    command: 'zlar-smoke-upstream',
    args: [String(upstreamPort)],
    env: null,
    cwd: null,
  }],
  ['direct args', {
    type: 'stdio',
    command: wrapperPath,
    args: ['zlar-smoke-upstream', '--port', String(upstreamPort)],
    env: null,
    cwd: null,
  }],
  ['direct env', {
    type: 'stdio',
    command: wrapperPath,
    args: [],
    env: { MCP_UPSTREAM_PORT: String(upstreamPort) },
    cwd: null,
  }],
  ['direct nested config', {
    type: 'stdio',
    command: wrapperPath,
    args: [],
    config: { upstream: { command: 'zlar-smoke-upstream', port: upstreamPort } },
    env: null,
    cwd: null,
  }],
]) {
  const unsafeProfile = buildProfileReport({
    mcpGetAfterAdd: {
      name: SERVER_NAME,
      enabled: true,
      transport,
    },
    mcpListAfterAdd: safeMcpList,
    upstreamPort,
    sessionId: 'coverage-report-test',
  });
  const unsafeReport = buildGovernedProfileCoverageReport({ profileReport: unsafeProfile });
  assertThrows(`direct upstream ${label} rejected`, () => {
    assertGovernedProfileCoverageReport(unsafeReport);
  }, 'direct upstream MCP registration bypass observed');
}

const extraServerProfile = buildProfileReport({
  mcpGetAfterAdd: safeMcpGet,
  mcpListAfterAdd: `${safeMcpList}direct-upstream  node  fake-upstream  -  -  enabled  Unsupported\n`,
  upstreamPort,
  sessionId: 'coverage-report-test',
});
const extraServerReport = buildGovernedProfileCoverageReport({ profileReport: extraServerProfile });
assertThrows('extra MCP registration rejected', () => {
  assertGovernedProfileCoverageReport(extraServerReport);
}, 'extra MCP registration bypass observed');

section('privacy and claim scans');
const summary = formatGovernedProfileCoverageSummary(report);
assert('summary validates against privacy scan', (() => {
  try {
    assertNoUnsafeCoverageText(summary);
    return true;
  } catch {
    return false;
  }
})());
assert('summary omits raw marker args', !summary.includes('marker_deny'));
const broadCodexPhrase = ['governs', 'Codex'].join(' ');
assert('summary omits broad Codex claim phrase', !summary.includes(broadCodexPhrase));
assert('summary does not claim external attestation', !summary.includes('externally attested'));
assert('summary states contest boundary', summary.includes('/contest is not implemented.'));

const numericHumanFixture = ['human:', '123', '456', '789'].join('');
const leakCredential = ['sk', 'live', 'fixture', '000000'].join('-');
const leakBearer = ['fake', 'Bearer', '000000'].join('');
const leakFixture = `${fakeCredentialPrefix}=${leakCredential} /Users/tester/.zlar ${numericHumanFixture} authorization: Bearer ${leakBearer}`;
const redactedReport = buildGovernedProfileCoverageReport({
  profileReport,
  profile: {
    id: `leaky ${leakFixture}`,
    name: `leaky profile ${leakFixture}`,
    client: `Codex CLI ${leakFixture}`,
    isolated_config: true,
  },
});
const redactedText = JSON.stringify(redactedReport);
assert('synthetic leak fixture redacted from generated report', !redactedText.includes(leakCredential) && !redactedText.includes('/Users/tester') && !redactedText.includes(numericHumanFixture));
assert('generated report includes redaction markers', redactedText.includes('[REDACTED_CREDENTIAL]') && redactedText.includes('[REDACTED_PATH]'));
assertThrows('unsafe raw fixture rejected by scan', () => {
  assertNoUnsafeCoverageText({ leak: leakFixture });
}, 'coverage report contains');
assertThrows('broad Hermes claim rejected by scan', () => {
  assertNoUnsafeCoverageText(['ZLAR', 'governs', 'Hermes'].join(' '));
}, 'broad Hermes claim');

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
