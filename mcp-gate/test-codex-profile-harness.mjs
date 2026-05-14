#!/usr/bin/env node
// Hermetic checks for the Codex isolated-profile report/guard helpers.
// This does not invoke the Codex CLI or touch operator MCP configuration.

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CLAIM_CEILING,
  SERVER_NAME,
  assertIsolatedProfileReport,
  buildProfileReport,
  configuredServersFromCodex,
  extractCodexMcpServerNames,
  sanitizeMcpTransport,
} from './smoke-codex-cli.mjs';

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
assert('does not mark proof server as direct fake upstream', !report.configured_mcp_servers[0].direct_fake_upstream_registration);
assert('records scratch cleanup command', report.scratch.cleanup_command.includes('cleanup --isolated-profile'));
assert('lists intentionally ungoverned surfaces', report.intentionally_ungoverned_surfaces.length >= 4);

const reportText = JSON.stringify(report);
const broadCodexPhrase = ['governs', 'Codex'].join(' ');
assert('profile report omits private user path', !reportText.includes('/Users/'));
assert('profile report omits env values', !reportText.includes('SHOULD_NOT_APPEAR'));
assert('profile report avoids broad Codex claim phrase', !reportText.includes(broadCodexPhrase));
assert('profile report avoids numeric human identifiers', !/human:[0-9]/.test(reportText));

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
