#!/usr/bin/env node
// Hermetic checks for the Codex isolated-profile report/guard helpers.
// This does not invoke the Codex CLI or touch operator MCP configuration.

import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  assertGovernedProfileCoverageReport,
  assertNoUnsafeCoverageText,
} from './governed-profile-coverage-report.mjs';
import {
  CLAIM_CEILING,
  SERVER_NAME,
  assertIsolatedProfileReport,
  buildProfileReport,
  buildScratchState,
  configuredServersFromCodex,
  extractCodexMcpServerNames,
  sanitizeMcpTransport,
  transportCommandKind,
  transportLooksDirectFakeUpstream,
} from './smoke-codex-cli.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..');

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

function assertDoesNotThrow(label, fn) {
  TOTAL++;
  try {
    fn();
    PASS++;
    console.log(`  PASS: ${label}`);
  } catch (err) {
    FAIL++;
    console.log(`  FAIL: ${label} -- ${err.message}`);
  }
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const scratch = join(tmpdir(), 'zlar-codex-cli-mcp-smoke');
const wrapperPath = join(scratch, 'zlar-smoke-cli-wrapper.sh');
const upstreamPort = 18181;

const safeMcpGet = {
  name: SERVER_NAME,
  enabled: true,
  transport: {
    type: 'stdio',
    command: wrapperPath,
    args: [],
    env: {
      HOME: join(scratch, 'home'),
      SENSITIVE_ENV: 'SHOULD_NOT_APPEAR',
    },
    cwd: null,
  },
};

const safeMcpList = `Name            Command                         Args  Env  Cwd  Status   Auth
${SERVER_NAME}  ${wrapperPath}                  -     -    -    enabled  Unsupported
`;

section('Codex MCP list parsing');
assertEqual('extracts one server name from table output', SERVER_NAME, extractCodexMcpServerNames(safeMcpList)[0]);
assertEqual('ignores empty MCP list message', 0, extractCodexMcpServerNames('No MCP servers configured.').length);

section('Transport sanitization');
const sanitized = sanitizeMcpTransport(safeMcpGet.transport);
assert('keeps transport type', sanitized.type === 'stdio');
assert('keeps env keys', sanitized.env_keys.includes('SENSITIVE_ENV'));
assert('redacts env values', !JSON.stringify(sanitized).includes('SHOULD_NOT_APPEAR'));
assertEqual('classifies wrapper command as ZLAR wrapper', 'zlar-wrapper', transportCommandKind(safeMcpGet.transport));
assert('safe transport is not direct fake upstream', !transportLooksDirectFakeUpstream(safeMcpGet.transport, upstreamPort));

const gateTransport = {
  type: 'stdio',
  command: process.execPath,
  args: [
    join(scratch, 'project', 'mcp-gate', 'gate.mjs'),
    '--stdio',
    '--config',
    join(scratch, 'upstreams.json'),
  ],
  env: {},
  cwd: null,
};
assertEqual('classifies direct gate command as ZLAR gate', 'zlar-gate', transportCommandKind(gateTransport));

section('Profile report');
const report = buildProfileReport({
  mcpGetAfterAdd: safeMcpGet,
  mcpListAfterAdd: safeMcpList,
  upstreamPort,
  sessionId: 'profile-harness-test',
});

assertDoesNotThrow('valid profile report does not throw', () => {
  assertIsolatedProfileReport(report);
});
assertEqual('uses exact claim ceiling', CLAIM_CEILING, report.claim_ceiling);
assertEqual('reports one configured MCP server', 1, report.configured_mcp_servers.length);
assert('marks proof server as ZLAR-routed', report.configured_mcp_servers[0].zlar_routed);
assertEqual('records structured transport command kind', 'zlar-wrapper', report.configured_mcp_servers[0].transport_command_kind);
assert('does not mark proof server as direct fake upstream', !report.configured_mcp_servers[0].direct_fake_upstream_registration);
assert('records scratch cleanup command', report.scratch.cleanup_command.includes('cleanup --isolated-profile'));
assert('lists intentionally ungoverned surfaces', report.intentionally_ungoverned_surfaces.length >= 4);

const reportText = JSON.stringify(report);
const broadCodexPhrase = ['governs', 'Codex'].join(' ');
assert('profile report omits private user path', !reportText.includes('/Users/'));
assert('profile report omits env values', !reportText.includes('SHOULD_NOT_APPEAR'));
assert('profile report avoids broad Codex claim phrase', !reportText.includes(broadCodexPhrase));
assert('profile report avoids numeric human identifiers', !/human:[0-9]/.test(reportText));

section('Scratch state safety');
const state = buildScratchState({
  ready: {
    pid: 12345,
    upstreamPort,
    telegramUrl: 'http://127.0.0.1:19090',
  },
  isolatedProfile: true,
  codexRegistration: { listStdout: safeMcpList },
  mcpGetAfterAdd: safeMcpGet,
  preflight: {
    ok: true,
    stdout: '{"id":900,"result":{"field":"SHOULD_NOT_APPEAR"}}',
    stderr: 'Policy signature verified with marker SHOULD_NOT_APPEAR',
  },
});
const stateText = JSON.stringify(state);
assertEqual('records early-cleanup pid context', 12345, state.serverPid);
assert('state records sanitized MCP server summary', state.codexMcpRegistration.configuredMcpServers[0].zlar_routed);
assert('state redacts raw MCP env values and preflight text', !stateText.includes('SHOULD_NOT_APPEAR'));
assert('state stores preflight booleans', state.preflight.ok && state.preflight.policy_signature_verified);

function reportSurface(report, id) {
  return report.surfaces.find((item) => item.id === id);
}

function writeJson(path, value) {
  writeFileSync(path, JSON.stringify(value, null, 2));
}

function mcpCoverageEvent({ id, action, outcome, rule, authorizer = 'policy', detail = {} }) {
  return {
    id,
    ts: '2026-05-14T12:00:00Z',
    seq: Number(id.replace(/\D/g, '')) || 1,
    source: 'mcp-gate',
    host: 'test-host',
    user: 'tester',
    agent_id: 'codex-live-smoke',
    session_id: 'coverage-command-test',
    transport: 'stdio',
    domain: 'mcp',
    action,
    outcome,
    risk_score: outcome === 'allow' || outcome === 'authorized' ? 0 : 80,
    detail,
    rule,
    rule_description: `Rule for ${action}`,
    policy_version: 'coverage-policy-v0',
    policy_key_id: 'policy-key-test',
    severity: outcome === 'allow' || outcome === 'authorized' ? 'info' : 'critical',
    prev_hash: 'genesis',
    authorizer,
    signature_algorithm: 'Ed25519',
    hash_algorithm: 'SHA-256',
    public_key_id: 'audit-key-test',
    signature: 'test',
  };
}

section('Coverage report command');
const coverageScratch = mkdtempSync(join(tmpdir(), 'zlar-codex-smoke-coverage-command-'));
try {
  const fakeBin = join(coverageScratch, 'fake-bin');
  const fakeHome = join(coverageScratch, 'operator-home');
  const fakeCodexProbe = join(coverageScratch, 'codex-probe.txt');
  mkdirSync(fakeBin, { recursive: true });
  mkdirSync(fakeHome, { recursive: true });
  const fakeCodex = join(fakeBin, 'codex');
  writeFileSync(fakeCodex, `#!/bin/sh
echo touched >> "${fakeCodexProbe}"
exit 99
`);
  chmodSync(fakeCodex, 0o755);

  function runCoverageCommandWithScratch(scratchOverride) {
    return spawnSync(process.execPath, [join(REPO_ROOT, 'mcp-gate', 'smoke-codex-cli.mjs'), 'coverage-report'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        ZLAR_CODEX_SMOKE_SCRATCH: scratchOverride,
        PATH: `${fakeBin}:${process.env.PATH || ''}`,
        HOME: fakeHome,
        CODEX_HOME: join(fakeHome, '.codex'),
      },
    });
  }

  const badOverrides = [
    ['root path', '/'],
    ['repo path', REPO_ROOT],
    ['temp directory itself', tmpdir()],
    ['arbitrary temp path', join(tmpdir(), 'not-zlar-codex-smoke-coverage-command')],
    ['home-like temp path', fakeHome],
  ];
  for (const [label, scratchOverride] of badOverrides) {
    const badResult = runCoverageCommandWithScratch(scratchOverride);
    assert(`unsafe scratch override rejected for ${label}`, badResult.status !== 0);
    assert(`unsafe scratch override names env var for ${label}`,
      `${badResult.stderr}\n${badResult.stdout}`.includes('ZLAR_CODEX_SMOKE_SCRATCH'));
  }

  const symlinkScratch = join(coverageScratch, 'zlar-codex-smoke-symlink');
  symlinkSync(fakeHome, symlinkScratch, 'dir');
  const symlinkResult = runCoverageCommandWithScratch(symlinkScratch);
  assert('symlink scratch override rejected', symlinkResult.status !== 0);
  assert('symlink scratch override names symlink rejection',
    `${symlinkResult.stderr}\n${symlinkResult.stdout}`.includes('symlink'));

  const profilePath = join(coverageScratch, 'profile-report.json');
  const auditPath = join(coverageScratch, 'codex-live-smoke.audit.jsonl');
  const upstreamExecutionsPath = join(coverageScratch, 'upstream-executions.jsonl');
  const coverageJsonPath = join(coverageScratch, 'governed-profile-coverage-report.json');
  const coverageTextPath = join(coverageScratch, 'governed-profile-coverage-report.txt');
  const wrapperPathForChild = join(coverageScratch, 'zlar-smoke-cli-wrapper.sh');
  const codexHomeForChild = join(coverageScratch, 'codex-home');
  const codexDotdirForChild = join(codexHomeForChild, '.codex');
  mkdirSync(codexDotdirForChild, { recursive: true });

  const profileFixture = {
    generated_at: '2026-05-14T12:00:00Z',
    mode: 'isolated-codex-profile',
    claim_ceiling: CLAIM_CEILING,
    configured_mcp_servers: [
      {
        name: SERVER_NAME,
        enabled: true,
        transport: {
          type: 'stdio',
          command: wrapperPathForChild,
          args: [],
          env_keys: ['HOME', 'ZLAR_FAKE_ENV'],
          cwd: null,
          additional_keys: [],
        },
        transport_command_kind: 'zlar-wrapper',
        zlar_routed: true,
        direct_fake_upstream_registration: false,
      },
    ],
    zlar_route: {
      server_name: SERVER_NAME,
      transport: 'stdio',
      fake_telegram: true,
      live_telegram: false,
    },
    scratch: {
      root: coverageScratch,
      codex_home: codexHomeForChild,
      codex_dotdir: codexDotdirForChild,
      cleanup_command: 'node mcp-gate/smoke-codex-cli.mjs cleanup --isolated-profile',
    },
    privacy: {
      env_values_redacted: true,
      live_telegram_credential: false,
      real_chat_id: false,
      real_human_state_id: false,
    },
    intentionally_ungoverned_surfaces: [],
    limitations: {
      contest: '/contest is not implemented.',
      external_verifier: 'External non-Vincent verifier attestation has not completed.',
    },
  };
  writeJson(profilePath, profileFixture);
  writeJson(join(coverageScratch, 'state.json'), {
    scratch: coverageScratch,
    isolatedProfile: true,
    serverName: SERVER_NAME,
    profileReportPath: profilePath,
    coverageReportJsonPath: coverageJsonPath,
    coverageReportTextPath: coverageTextPath,
  });

  const fakeCredentialKey = ['to', 'ken'].join('');
  const fakeCredentialValue = ['sk', 'live', 'test', 'fixture', '000000'].join('-');
  const unsafeFixture = {
    args_preview: JSON.stringify({
      marker: 'marker_deny',
      path: '/Users/tester/private',
      [fakeCredentialKey]: fakeCredentialValue,
    }),
  };
  const auditEvents = [
    mcpCoverageEvent({ id: 'cov-allow-001', action: 'test.marker_allow', outcome: 'allow', rule: 'P1_ALLOW' }),
    mcpCoverageEvent({ id: 'cov-deny-001', action: 'test.marker_deny', outcome: 'deny', rule: 'P1_DENY', detail: unsafeFixture }),
    mcpCoverageEvent({ id: 'cov-authorized-001', action: 'test.marker_ask_approve', outcome: 'authorized', rule: 'P2_ASK_APPROVE', authorizer: 'human:operator-1' }),
    mcpCoverageEvent({ id: 'cov-denied-001', action: 'test.marker_ask_deny', outcome: 'denied', rule: 'P2_ASK_DENY', authorizer: 'human:operator-1' }),
  ];
  writeFileSync(auditPath, `${auditEvents.map((event) => JSON.stringify(event)).join('\n')}\n`);
  writeFileSync(upstreamExecutionsPath, [
    JSON.stringify({ name: 'test.marker_allow', marker: 'marker_allow' }),
    JSON.stringify({ name: 'test.marker_ask_approve', marker: 'marker_ask_approve' }),
  ].join('\n') + '\n');

  const result = runCoverageCommandWithScratch(coverageScratch);
  assertEqual('coverage-report command exits 0', 0, result.status);
  assert('safe temp-prefix scratch override works', coverageScratch.split('/').pop().startsWith('zlar-codex-smoke-'));
  assert('coverage-report command prints JSON path', result.stdout.includes(coverageJsonPath));
  assert('coverage-report command prints text path', result.stdout.includes(coverageTextPath));
  assert('coverage-report writes JSON under scratch', existsSync(coverageJsonPath) && coverageJsonPath.startsWith(coverageScratch));
  assert('coverage-report writes text under scratch', existsSync(coverageTextPath) && coverageTextPath.startsWith(coverageScratch));
  assert('coverage-report does not invoke Codex CLI', !existsSync(fakeCodexProbe));
  assert('coverage-report does not touch operator CODEX_HOME', !existsSync(join(fakeHome, '.codex', 'config.toml')));

  const coverageReport = JSON.parse(readFileSync(coverageJsonPath, 'utf8'));
  assertDoesNotThrow('coverage JSON validates', () => assertGovernedProfileCoverageReport(coverageReport));
  const coverageText = readFileSync(coverageTextPath, 'utf8');
  assert('coverage text summary is generated', coverageText.includes('Governed Profile Coverage Report v0'));
  assertEqual('coverage report type', 'governed-profile-coverage-v0', coverageReport.report_type);
  assertEqual('coverage safe claim ceiling', CLAIM_CEILING, coverageReport.safe_claim_ceiling);
  assertEqual('direct upstream registration remains blocked', 'blocked', reportSurface(coverageReport, 'codex.mcp.registration.direct_upstream_bypass').status);
  assertEqual('extra MCP registration remains blocked', 'blocked', reportSurface(coverageReport, 'codex.mcp.registration.extra_server_bypass').status);
  assertEqual('missing optional Worker Receipt why stays not checked', 'not_checked', reportSurface(coverageReport, 'codex.mcp.decision.allow').why.status);
  assertEqual('missing optional Worker Receipt evidence stays empty', 0, reportSurface(coverageReport, 'codex.mcp.decision.allow').worker_receipts.length);
  assertEqual('/contest is disclosed only', 'disclosed', reportSurface(coverageReport, 'zlar.contest').status);
  assertEqual('external attestation is disclosed only', 'disclosed', reportSurface(coverageReport, 'external.verifier_attestation').status);
  assertEqual('verifier kit packet status prepared pending', 'prepared_pending', coverageReport.verifier_kit_packet.status);
  assertDoesNotThrow('coverage JSON privacy/claim scan passes', () => assertNoUnsafeCoverageText(coverageReport));
  assertDoesNotThrow('coverage text privacy/claim scan passes', () => assertNoUnsafeCoverageText(coverageText));
  assert('coverage JSON omits raw MCP args', !JSON.stringify(coverageReport).includes('marker_deny'));
  assert('coverage text omits raw MCP args', !coverageText.includes('marker_deny'));
  assert('coverage outputs omit private fixture path', !JSON.stringify(coverageReport).includes('/Users/tester') && !coverageText.includes('/Users/tester'));
  assert('coverage outputs omit fake credential fixture', !JSON.stringify(coverageReport).includes(fakeCredentialValue) && !coverageText.includes(fakeCredentialValue));
} finally {
  rmSync(coverageScratch, { recursive: true, force: true });
}

section('Guard failures');
const directServers = configuredServersFromCodex({
  mcpGetAfterAdd: {
    name: SERVER_NAME,
    enabled: true,
    transport: {
      type: 'stdio',
      command: 'zlar-smoke-upstream',
      args: [String(upstreamPort)],
      env: null,
      cwd: null,
    },
  },
  mcpListAfterAdd: `Name            Command              Args  Env  Cwd  Status   Auth
${SERVER_NAME}  zlar-smoke-upstream  ${upstreamPort}  -    -    enabled  Unsupported
`,
  upstreamPort,
});
assert('flags direct fake-upstream registration', directServers[0].direct_fake_upstream_registration);
assert('does not mark direct upstream as ZLAR-routed', !directServers[0].zlar_routed);
assertEqual('classifies direct upstream command as other', 'other', directServers[0].transport_command_kind);

for (const [label, transport] of [
  ['args', {
    type: 'stdio',
    command: wrapperPath,
    args: ['zlar-smoke-upstream', '--port', String(upstreamPort)],
    env: null,
    cwd: null,
  }],
  ['env', {
    type: 'stdio',
    command: wrapperPath,
    args: [],
    env: { MCP_UPSTREAM_PORT: String(upstreamPort) },
    cwd: null,
  }],
  ['nested config', {
    type: 'stdio',
    command: wrapperPath,
    args: [],
    config: { upstream: { command: 'zlar-smoke-upstream', port: upstreamPort } },
    env: null,
    cwd: null,
  }],
]) {
  const variantReport = buildProfileReport({
    mcpGetAfterAdd: {
      name: SERVER_NAME,
      enabled: true,
      transport,
    },
    mcpListAfterAdd: safeMcpList,
    upstreamPort,
    sessionId: 'profile-harness-test',
  });
  assertThrows(`guard rejects direct fake-upstream encoded through ${label}`, () => {
    assertIsolatedProfileReport(variantReport);
  }, 'must not directly register the fake upstream');
}

const extraServerReport = buildProfileReport({
  mcpGetAfterAdd: safeMcpGet,
  mcpListAfterAdd: `${safeMcpList}direct-upstream  node  fake-upstream  -  -  enabled  Unsupported\n`,
  upstreamPort,
  sessionId: 'profile-harness-test',
});
assertThrows('guard rejects additional MCP registration', () => {
  assertIsolatedProfileReport(extraServerReport);
}, 'exactly one MCP server');

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
