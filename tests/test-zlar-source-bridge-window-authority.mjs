#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DEFAULT_BRANCH,
  DEFAULT_REMOTE_REF,
  DEFAULT_REPO,
  REQUIRED_ALLOWED_SOURCE_MOVEMENT,
  REQUIRED_FORBIDDEN_CONSEQUENCES,
  REQUIRED_STOP_CONDITIONS,
  SOURCE_BRIDGE_WINDOW_PACKET_TYPE,
  assertSourceBridgeWindowAuthorityReport,
  runSourceBridgeWindowAuthority,
  runSourceBridgeWindowSampleAuthority,
} from '../lib/zlar-source-bridge-window-authority.mjs';

const NOW = Date.parse('2026-07-06T00:30:00Z');
const repoRoot = process.cwd();
const cliPath = join(repoRoot, 'bin', 'zlar-source-bridge-window');
const zlarPath = join(repoRoot, 'bin', 'zlar');

function packet(overrides = {}) {
  return merge({
    packet_type: SOURCE_BRIDGE_WINDOW_PACKET_TYPE,
    human_grant: {
      human: 'Vincent Nijjar',
      grant_timestamp: '2026-07-06T00:28:59Z',
      action: 'overnight source bridge window',
    },
    window: {
      expires_at: '2026-07-06T13:00:00Z',
      timezone: 'America/Winnipeg',
    },
    source_target: {
      repo: DEFAULT_REPO,
      branch: DEFAULT_BRANCH,
      remote_ref: DEFAULT_REMOTE_REF,
    },
    allowed_source_movement: Object.fromEntries(REQUIRED_ALLOWED_SOURCE_MOVEMENT.map((key) => [key, true])),
    forbidden_consequences: [...REQUIRED_FORBIDDEN_CONSEQUENCES],
    stop_conditions: [...REQUIRED_STOP_CONDITIONS],
  }, overrides);
}

function cliFreshPacket(overrides = {}) {
  const nowMs = Date.now();
  const base = packet({
    human_grant: {
      grant_timestamp: new Date(nowMs - 60_000).toISOString(),
    },
    window: {
      expires_at: new Date(nowMs + 45_000_000).toISOString(),
    },
  });
  return merge(base, overrides);
}

function merge(base, overrides) {
  const next = structuredClone(base);
  for (const [key, value] of Object.entries(overrides)) {
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      next[key] &&
      typeof next[key] === 'object' &&
      !Array.isArray(next[key])
    ) {
      next[key] = merge(next[key], value);
    } else {
      next[key] = value;
    }
  }
  return next;
}

function run(input) {
  return runSourceBridgeWindowAuthority(input, { nowMs: NOW });
}

function refused(name, expectedCode, candidate) {
  const report = run(candidate);
  assert.equal(report.authority_status, 'refused', name);
  assert.equal(report.refusal_reason_code, expectedCode, name);
  assert.equal(report.can_push_under_window, false, name);
  assert.equal(JSON.stringify(report).includes('BEGIN PRIVATE KEY'), false, name);
}

{
  const report = run(packet());
  assert.equal(assertSourceBridgeWindowAuthorityReport(report), true);
  assert.equal(report.authority_status, 'accepted');
  assert.equal(report.safe_for_control_tower_use, true);
  assert.equal(report.can_push_under_window, true);
  assert.equal(report.source_target.repo, DEFAULT_REPO);
  assert.equal(report.source_target.remote_ref, DEFAULT_REMOTE_REF);
  assert.equal(report.no_secret_boundary.pushes_source, false);
  assert.equal(report.no_secret_boundary.calls_github, false);
  assert.equal(report.required_forbidden_consequences_present, true);
  assert.equal(report.required_stop_conditions_present, true);
  assert.match(report.packet_sha256, /^[a-f0-9]{64}$/);
}

{
  const report = runSourceBridgeWindowSampleAuthority();
  assert.equal(assertSourceBridgeWindowAuthorityReport(report), true);
  assert.equal(report.authority_status, 'accepted');
  assert.equal(report.window.expires_in_seconds, 45000);
}

refused('bad packet type', 'packet_type_mismatch', packet({ packet_type: 'other' }));
refused('unknown top field refuses', 'unknown_field', packet({ extra: true }));
refused('future grant refuses', 'grant_from_future', packet({ human_grant: { grant_timestamp: '2026-07-06T01:00:01Z' } }));
refused('expired window refuses', 'window_expired', packet({ window: { expires_at: '2026-07-06T00:00:00Z' } }));
refused('too-long window refuses', 'window_too_long', packet({ window: { expires_at: '2026-07-08T00:00:00Z' } }));
refused('wrong repo refuses', 'repo_not_selected', packet({ source_target: { repo: 'ZLAR-AI/Other' } }));
refused('wrong branch refuses', 'branch_not_selected', packet({ source_target: { branch: 'main' } }));
refused('wrong remote ref refuses', 'remote_ref_not_selected', packet({ source_target: { remote_ref: 'refs/heads/main' } }));
refused('missing required push guard refuses', 'required_guard_not_true', packet({ allowed_source_movement: { non_force_push: false } }));
refused(
  'missing forbidden consequence refuses',
  'required_boundary_missing',
  packet({ forbidden_consequences: REQUIRED_FORBIDDEN_CONSEQUENCES.filter((entry) => entry !== 'actions') }),
);
refused(
  'missing stop condition refuses',
  'required_boundary_missing',
  packet({ stop_conditions: REQUIRED_STOP_CONDITIONS.filter((entry) => entry !== 'branch_divergence') }),
);
refused(
  'secret-shaped material refuses',
  'unsafe_secret_shaped_material',
  JSON.stringify(packet({ human_grant: { action: 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz' } })),
);
refused('malformed json refuses', 'malformed_json', '{not json');

const tempRoot = mkdtempSync(join(tmpdir(), 'zlar-source-bridge-window-test-'));
const inputPath = join(tempRoot, 'packet.json');
writeFileSync(inputPath, `${JSON.stringify(cliFreshPacket())}\n`);
const cli = spawnSync(process.execPath, [cliPath, '--input', inputPath, '--json'], { encoding: 'utf8' });
assert.equal(cli.status, 0, cli.stderr);
assert.equal(JSON.parse(cli.stdout).authority_status, 'accepted');

const refusedCli = spawnSync(process.execPath, [cliPath, '--input', '-', '--json'], {
  input: JSON.stringify(cliFreshPacket({ source_target: { repo: 'ZLAR-AI/Other' } })),
  encoding: 'utf8',
});
assert.equal(refusedCli.status, 2);
assert.equal(JSON.parse(refusedCli.stdout).refusal_reason_code, 'repo_not_selected');

const zlarHelp = spawnSync(zlarPath, ['help'], { encoding: 'utf8' });
assert.equal(zlarHelp.status, 0);
assert.equal(zlarHelp.stdout.includes('source-bridge-window'), true);

const zlarDispatch = spawnSync(zlarPath, ['source-bridge-window', '--input', inputPath, '--json'], { encoding: 'utf8' });
assert.equal(zlarDispatch.status, 0, zlarDispatch.stderr);
assert.equal(JSON.parse(zlarDispatch.stdout).authority_status, 'accepted');

const sampleCli = spawnSync(process.execPath, [cliPath, '--sample', '--json'], { encoding: 'utf8' });
assert.equal(sampleCli.status, 0, sampleCli.stderr);
assert.equal(JSON.parse(sampleCli.stdout).authority_status, 'accepted');

const zlarSampleDispatch = spawnSync(zlarPath, ['source-bridge-window', '--sample', '--json'], { encoding: 'utf8' });
assert.equal(zlarSampleDispatch.status, 0, zlarSampleDispatch.stderr);
assert.equal(JSON.parse(zlarSampleDispatch.stdout).window.expires_in_seconds, 45000);

const unsafeArg = spawnSync(process.execPath, [cliPath, '--input', 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'], {
  encoding: 'utf8',
});
assert.equal(unsafeArg.status, 1);
assert.equal(`${unsafeArg.stdout}${unsafeArg.stderr}`.includes('abcdefghijklmnopqrstuvwxyz'), false);

const outside = join(tmpdir(), `zlar-source-bridge-window-out-${process.pid}.json`);
rmSync(outside, { force: true });
const outsideOut = spawnSync(process.execPath, [cliPath, '--input', inputPath, '--json-out', outside, '--json'], {
  encoding: 'utf8',
});
assert.equal(outsideOut.status, 1);
assert.equal(existsSync(outside), false);

const reportOut = join(tempRoot, 'report.json');
const reportCli = spawnSync(process.execPath, [cliPath, '--input', inputPath, '--json-out', reportOut, '--json'], {
  encoding: 'utf8',
});
assert.equal(reportCli.status, 1);
assert.equal(existsSync(reportOut), false);
assert.equal(`${reportCli.stdout}${reportCli.stderr}`.includes(tempRoot), false);

assert.equal(readFileSync(cliPath, 'utf8').includes('git push'), false);

console.log('zlar source bridge window authority: 86/86 assertions passed');
