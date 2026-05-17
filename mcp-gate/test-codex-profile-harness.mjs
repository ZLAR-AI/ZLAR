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
  LIVE_TELEGRAM_CHAT_ID_ENV,
  LIVE_TELEGRAM_TOKEN_ENV,
  SERVER_NAME,
  assertIsolatedProfileReport,
  buildProfileReport,
  buildScratchState,
  liveTelegramRuntimeFromEnv,
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

section('Live Telegram profile guards');
const liveRuntime = liveTelegramRuntimeFromEnv({
  [LIVE_TELEGRAM_TOKEN_ENV]: 'fixture-live-telegram-token',
  [LIVE_TELEGRAM_CHAT_ID_ENV]: '123456789',
});
const liveMcpGet = {
  name: SERVER_NAME,
  enabled: true,
  transport: {
    type: 'stdio',
    command: wrapperPath,
    args: [],
    env: {
      HOME: join(scratch, 'home'),
      ZLAR_TELEGRAM_TOKEN: 'SHOULD_NOT_APPEAR',
    },
    cwd: null,
  },
};
const liveReport = buildProfileReport({
  mcpGetAfterAdd: liveMcpGet,
  mcpListAfterAdd: safeMcpList,
  upstreamPort,
  sessionId: 'profile-harness-live-test',
  telegramRuntime: liveRuntime,
});
assertDoesNotThrow('live profile with isolated server does not throw', () => {
  assertIsolatedProfileReport(liveReport);
});
assert('live profile records live Telegram mode', liveReport.zlar_route.live_telegram && !liveReport.zlar_route.fake_telegram);
assert('live profile redacts numeric chat id from gate args', !JSON.stringify(liveReport.zlar_route.gate_args).includes('123456789'));
assert('live profile redacts token value from transport', !JSON.stringify(liveReport).includes('SHOULD_NOT_APPEAR'));

const liveWithFakeApiReport = buildProfileReport({
  mcpGetAfterAdd: {
    ...liveMcpGet,
    transport: {
      ...liveMcpGet.transport,
      env: {
        ZLAR_TELEGRAM_TOKEN: 'fixture',
        ZLAR_TELEGRAM_API_BASE: 'http://127.0.0.1:19999',
      },
    },
  },
  mcpListAfterAdd: safeMcpList,
  upstreamPort,
  sessionId: 'profile-harness-live-test',
  telegramRuntime: liveRuntime,
});
assertThrows('live profile rejects fake Telegram API override', () => {
  assertIsolatedProfileReport(liveWithFakeApiReport);
}, 'fake Telegram API');

assertThrows('live Telegram mode requires numeric chat id', () => {
  liveTelegramRuntimeFromEnv({
    [LIVE_TELEGRAM_TOKEN_ENV]: 'fixture-live-telegram-token',
    [LIVE_TELEGRAM_CHAT_ID_ENV]: '@ZLAR_00_bot',
  });
}, 'numeric Telegram chat ID');

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

function readJsonl(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
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

section('Live isolated setup command');
const liveTestRoot = mkdtempSync(join(tmpdir(), 'zlar-codex-smoke-live-test-'));
const liveScratch = join(liveTestRoot, 'zlar-codex-smoke-live-setup');
const liveFakeBin = join(liveTestRoot, 'fake-bin');
const liveOperatorHome = join(liveTestRoot, 'operator-home');
const liveOperatorCodexHome = join(liveOperatorHome, '.codex');
const liveFakeCodexLog = join(liveTestRoot, 'fake-codex-log.jsonl');
const liveFakeCodex = join(liveFakeBin, 'codex');
mkdirSync(liveFakeBin, { recursive: true });
mkdirSync(liveOperatorCodexHome, { recursive: true });
writeJson(join(liveOperatorCodexHome, 'fake-mcp-config.json'), {
  servers: {
    inherited_extra: {
      name: 'inherited_extra',
      enabled: true,
      transport: { type: 'stdio', command: 'direct-upstream', args: [], env: {}, cwd: null },
    },
  },
});
writeFileSync(liveFakeCodex, `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
const logPath = process.env.FAKE_CODEX_LOG;
if (logPath) {
  fs.appendFileSync(logPath, JSON.stringify({
    argv,
    env: {
      HOME: process.env.HOME || '',
      CODEX_HOME: process.env.CODEX_HOME || '',
      ZLAR_TELEGRAM_API_BASE: process.env.ZLAR_TELEGRAM_API_BASE || '',
    },
  }) + '\\n');
}

function codexHome() {
  return process.env.CODEX_HOME || path.join(process.env.HOME || process.cwd(), '.codex');
}

function configPath() {
  const home = codexHome();
  fs.mkdirSync(home, { recursive: true });
  return path.join(home, 'fake-mcp-config.json');
}

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(configPath(), 'utf8'));
  } catch {
    return { servers: {} };
  }
}

function saveConfig(config) {
  fs.writeFileSync(configPath(), JSON.stringify(config, null, 2));
}

if (argv[0] === '--version') {
  console.log('codex fake 0.0.0');
  process.exit(0);
}

if (argv[0] !== 'mcp') {
  process.exit(99);
}

const sub = argv[1];
const config = loadConfig();
if (sub === 'remove') {
  delete config.servers[argv[2]];
  saveConfig(config);
  process.exit(0);
}

if (sub === 'add') {
  const name = argv[2];
  const env = {};
  let command = '';
  let args = [];
  for (let i = 3; i < argv.length; i += 1) {
    if (argv[i] === '--env') {
      const raw = argv[i + 1] || '';
      const eq = raw.indexOf('=');
      env[raw.slice(0, eq)] = raw.slice(eq + 1);
      i += 1;
    } else if (argv[i] === '--') {
      command = argv[i + 1] || '';
      args = argv.slice(i + 2);
      break;
    }
  }
  config.servers[name] = {
    name,
    enabled: true,
    transport: { type: 'stdio', command, args, env, cwd: null },
  };
  saveConfig(config);
  process.exit(0);
}

if (sub === 'get') {
  const server = config.servers[argv[2]];
  if (!server) process.exit(1);
  if (argv.includes('--json')) {
    console.log(JSON.stringify(server));
  } else {
    console.log(server.name);
  }
  process.exit(0);
}

if (sub === 'list') {
  const servers = Object.values(config.servers);
  if (servers.length === 0) {
    console.log('No MCP servers configured.');
  } else {
    console.log('Name            Command                         Args  Env  Cwd  Status   Auth');
    for (const server of servers) {
      console.log(String(server.name) + '  ' + String(server.transport.command || '-') + '  -  -  -  enabled  Unsupported');
    }
  }
  process.exit(0);
}

process.exit(98);
`);
chmodSync(liveFakeCodex, 0o755);

let cleanupResult = null;
try {
  const liveEnv = {
    ...process.env,
    ZLAR_CODEX_SMOKE_SCRATCH: liveScratch,
    PATH: `${liveFakeBin}:${process.env.PATH || ''}`,
    HOME: liveOperatorHome,
    CODEX_HOME: liveOperatorCodexHome,
    FAKE_CODEX_LOG: liveFakeCodexLog,
    [LIVE_TELEGRAM_TOKEN_ENV]: 'fixture-live-telegram-token',
    [LIVE_TELEGRAM_CHAT_ID_ENV]: '123456789',
    ZLAR_TELEGRAM_API_BASE: 'http://127.0.0.1:19999',
  };
  const setupResult = spawnSync(process.execPath, [
    join(REPO_ROOT, 'mcp-gate', 'smoke-codex-cli.mjs'),
    'setup',
    '--isolated-profile',
    '--live-telegram',
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: liveEnv,
    timeout: 15000,
  });
  assert('live isolated setup exits 0', setupResult.status === 0, setupResult.stderr || setupResult.stdout);
  assert('live isolated setup names live mode', setupResult.stdout.includes('Live Telegram: enabled'));

  const liveProfilePath = join(liveScratch, 'profile-report.json');
  assert('live isolated setup writes profile report', existsSync(liveProfilePath));
  if (existsSync(liveProfilePath)) {
    const setupProfile = JSON.parse(readFileSync(liveProfilePath, 'utf8'));
    assertEqual('live isolated setup has one MCP server', 1, setupProfile.configured_mcp_servers.length);
    assertEqual('live isolated setup registers only smoke server', SERVER_NAME, setupProfile.configured_mcp_servers[0].name);
    assert('live isolated setup does not inherit operator MCP server',
      !JSON.stringify(setupProfile.configured_mcp_servers).includes('inherited_extra'));
    assert('live isolated setup records live Telegram mode',
      setupProfile.zlar_route.live_telegram === true && setupProfile.zlar_route.fake_telegram === false);
    assert('live isolated setup does not register fake Telegram API env',
      !setupProfile.configured_mcp_servers[0].transport.env_keys.includes('ZLAR_TELEGRAM_API_BASE'));
  }

  const liveWrapperText = existsSync(join(liveScratch, 'zlar-smoke-cli-wrapper.sh'))
    ? readFileSync(join(liveScratch, 'zlar-smoke-cli-wrapper.sh'), 'utf8')
    : '';
  assert('live wrapper unsets fake Telegram API override', liveWrapperText.includes('unset ZLAR_TELEGRAM_API_BASE'));
  assert('live setup does not start fake Telegram API server', !existsSync(join(liveScratch, 'telegram-requests.jsonl')));
  assert('live setup does not run proof tool executions', !existsSync(join(liveScratch, 'upstream-executions.jsonl')));
  const upstreamCalls = readJsonl(join(liveScratch, 'upstream-calls.jsonl'));
  assert('live setup preflight never sends tools/call', upstreamCalls.every((entry) => entry.method !== 'tools/call'));

  cleanupResult = spawnSync(process.execPath, [
    join(REPO_ROOT, 'mcp-gate', 'smoke-codex-cli.mjs'),
    'cleanup',
    '--isolated-profile',
  ], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: liveEnv,
    timeout: 15000,
  });
  assert('live isolated cleanup exits 0', cleanupResult.status === 0, cleanupResult.stderr || cleanupResult.stdout);
  assert('live isolated cleanup removes scratch files', !existsSync(liveScratch));
  const codexLog = readJsonl(liveFakeCodexLog);
  assert('cleanup removes temporary MCP registration in isolated profile',
    codexLog.some((entry) =>
      entry.argv[0] === 'mcp' &&
      entry.argv[1] === 'remove' &&
      entry.argv[2] === SERVER_NAME &&
      String(entry.env.CODEX_HOME || '').startsWith(join(liveScratch, 'codex-home'))));
  assert('all MCP registration commands used scratch CODEX_HOME',
    codexLog
      .filter((entry) => entry.argv[0] === 'mcp')
      .every((entry) => String(entry.env.CODEX_HOME || '').startsWith(join(liveScratch, 'codex-home'))));
} finally {
  if (cleanupResult === null && existsSync(liveScratch)) {
    spawnSync(process.execPath, [
      join(REPO_ROOT, 'mcp-gate', 'smoke-codex-cli.mjs'),
      'cleanup',
      '--isolated-profile',
    ], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        ZLAR_CODEX_SMOKE_SCRATCH: liveScratch,
        PATH: `${liveFakeBin}:${process.env.PATH || ''}`,
        HOME: liveOperatorHome,
        CODEX_HOME: liveOperatorCodexHome,
        FAKE_CODEX_LOG: liveFakeCodexLog,
      },
      timeout: 15000,
    });
  }
  rmSync(liveTestRoot, { recursive: true, force: true });
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
