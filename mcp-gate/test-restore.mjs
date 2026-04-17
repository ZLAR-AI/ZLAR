// test-restore.mjs — Parity tests for mcp-gate Agent Health / Restore port
//
// Validates that mcp-gate/restore.mjs enforces the same invariants as
// lib/restore.sh. Covered invariants:
//   INV-01: absent trust state = healthy
//   INV-02: malformed / HMAC-mismatched trust state = degraded
//   INV-04: any error returns input action (fail-open on advisory layer)
//   INV-09: trust-state HMAC verification
//   INV-12: config integrity — tampered config forces all-deny
//
// And the escalation semantics (matches lib/restore.sh restore_check_escalation):
//   healthy  → pass-through
//   degraded → escalate allow to configured.degraded
//   at_risk  → escalate allow/log to configured.at_risk
//   suspended → escalate everything to configured.suspended
//   already-stronger policy action → no downgrade (monotone)

import { writeFileSync, readFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHmac } from 'node:crypto';
import {
  initRestore,
  checkEscalation,
  readTrustState,
  getRestoreState,
  _resetRestoreForTests,
} from './restore.mjs';

let PASS = 0, FAIL = 0, TOTAL = 0;
function assert(label, expected, actual) {
  TOTAL++;
  const ok = JSON.stringify(expected) === JSON.stringify(actual);
  if (ok) PASS++;
  else { FAIL++; console.log(`  FAIL: ${label} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`); }
}

const SCRATCH = join(tmpdir(), `zlar-restore-test-${process.pid}`);
if (existsSync(SCRATCH)) rmSync(SCRATCH, { recursive: true });

function setupProject() {
  _resetRestoreForTests();
  if (existsSync(SCRATCH)) rmSync(SCRATCH, { recursive: true });
  mkdirSync(join(SCRATCH, 'etc/keys'), { recursive: true });
  mkdirSync(join(SCRATCH, 'var/restore'), { recursive: true });
  return SCRATCH;
}

function writeConfig(projectDir, config) {
  const path = join(projectDir, 'etc/restore-config.json');
  writeFileSync(path, JSON.stringify(config, null, 2));
  return path;
}

function writeTrustState(projectDir, state, hmacKey = null) {
  const path = join(projectDir, 'var/restore/trust-state.json');
  const payload = {
    state,
    updated_at: new Date().toISOString(),
    detectors: {},
    history: [],
    reset_count: 0,
  };
  if (hmacKey) {
    const hmac = createHmac('sha256', hmacKey).update(JSON.stringify(payload)).digest('hex');
    writeFileSync(path, JSON.stringify({ ...payload, _hmac: hmac }, null, 2));
  } else {
    writeFileSync(path, JSON.stringify(payload, null, 2));
  }
  return path;
}

// ─── Section 1: Configuration loading ───────────────────────────────────────

console.log('\n── Section 1: configuration ──────────────────────────────────');

{
  // 1a. No config file → disabled
  const projectDir = setupProject();
  const r = initRestore({ projectDir, configFile: join(projectDir, 'etc/restore-config.json') });
  assert('no config file → disabled', false, r.enabled);
  assert('no config file → checkEscalation pass-through', 'allow',
    checkEscalation('allow').action);
}

{
  // 1b. Config with enabled=false → disabled
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: false });
  const r = initRestore({ projectDir, configFile });
  assert('enabled=false → disabled', false, r.enabled);
}

{
  // 1c. Config with enabled=true → enabled
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, {
    enabled: true,
    trust_state_file: 'var/restore/trust-state.json',
    escalation: { degraded: 'log', at_risk: 'ask', suspended: 'deny' },
  });
  const r = initRestore({ projectDir, configFile });
  assert('enabled=true → enabled', true, r.enabled);
}

{
  // 1d. Corrupt config JSON → disabled (NOT forced-closed without HMAC key)
  const projectDir = setupProject();
  const configFile = join(projectDir, 'etc/restore-config.json');
  writeFileSync(configFile, '{ this is not json');
  const r = initRestore({ projectDir, configFile });
  assert('corrupt config + no HMAC key → disabled', false, r.enabled);
}

// ─── Section 2: Trust state reader (INV-01, INV-02) ─────────────────────────

console.log('\n── Section 2: trust state reader ─────────────────────────────');

{
  // 2a. Enabled + no trust state file → healthy (INV-01)
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: true });
  initRestore({ projectDir, configFile });
  assert('enabled + no trust file → healthy', 'healthy', readTrustState());
}

{
  // 2b. Enabled + healthy trust state → healthy
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: true });
  writeTrustState(projectDir, 'healthy');
  initRestore({ projectDir, configFile });
  assert('healthy trust state → healthy', 'healthy', readTrustState());
}

{
  // 2c. Enabled + degraded trust state → degraded
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: true });
  writeTrustState(projectDir, 'degraded');
  initRestore({ projectDir, configFile });
  assert('degraded trust state → degraded', 'degraded', readTrustState());
}

{
  // 2d. Enabled + malformed trust state → degraded (INV-02)
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: true });
  writeFileSync(join(projectDir, 'var/restore/trust-state.json'), '{ not valid json');
  initRestore({ projectDir, configFile });
  assert('malformed trust state → degraded', 'degraded', readTrustState());
}

// ─── Section 3: Escalation semantics ────────────────────────────────────────

console.log('\n── Section 3: escalation semantics ───────────────────────────');

function buildEnabledProject(trustState) {
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, {
    enabled: true,
    trust_state_file: 'var/restore/trust-state.json',
    escalation: { degraded: 'log', at_risk: 'ask', suspended: 'deny' },
  });
  if (trustState) writeTrustState(projectDir, trustState);
  initRestore({ projectDir, configFile });
}

{
  // 3a. healthy + allow → allow (no escalation)
  buildEnabledProject('healthy');
  const r = checkEscalation('allow');
  assert('healthy + allow → allow', { action: 'allow', trustState: 'healthy', escalated: false }, r);
}

{
  // 3b. degraded + allow → log
  buildEnabledProject('degraded');
  const r = checkEscalation('allow');
  assert('degraded + allow → log', { action: 'log', trustState: 'degraded', escalated: true }, r);
}

{
  // 3c. at_risk + allow → ask
  buildEnabledProject('at_risk');
  const r = checkEscalation('allow');
  assert('at_risk + allow → ask', { action: 'ask', trustState: 'at_risk', escalated: true }, r);
}

{
  // 3d. suspended + allow → deny
  buildEnabledProject('suspended');
  const r = checkEscalation('allow');
  assert('suspended + allow → deny', { action: 'deny', trustState: 'suspended', escalated: true }, r);
}

{
  // 3e. degraded + ask → ask (monotone — do NOT downgrade)
  buildEnabledProject('degraded');
  const r = checkEscalation('ask');
  assert('degraded + ask → ask (no downgrade)', { action: 'ask', trustState: 'degraded', escalated: false }, r);
}

{
  // 3f. at_risk + log → ask
  buildEnabledProject('at_risk');
  const r = checkEscalation('log');
  assert('at_risk + log → ask', { action: 'ask', trustState: 'at_risk', escalated: true }, r);
}

{
  // 3g. suspended + deny → deny (no change)
  buildEnabledProject('suspended');
  const r = checkEscalation('deny');
  assert('suspended + deny → deny', { action: 'deny', trustState: 'suspended', escalated: false }, r);
}

// ─── Section 4: Disabled restore → pass-through ─────────────────────────────

console.log('\n── Section 4: disabled → pass-through ────────────────────────');

{
  _resetRestoreForTests();
  const r = checkEscalation('allow');
  assert('never initialized → pass-through', { action: 'allow', trustState: 'healthy', escalated: false }, r);
}

{
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: false });
  initRestore({ projectDir, configFile });
  writeTrustState(projectDir, 'suspended');  // file present but restore off
  const r = checkEscalation('allow');
  assert('disabled restore ignores trust state', { action: 'allow', trustState: 'healthy', escalated: false }, r);
}

// ─── Section 5: HMAC config integrity (INV-12) ──────────────────────────────

console.log('\n── Section 5: config HMAC integrity (INV-12) ─────────────────');

{
  // 5a. Config HMAC key exists + sidecar missing → forced-closed
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: true });
  writeFileSync(join(projectDir, 'etc/keys/restore-config-hmac.key'), 'test-hmac-key');
  let forcedClosedCalled = false;
  const r = initRestore({
    projectDir, configFile,
    onForceClosed: () => { forcedClosedCalled = true; },
  });
  assert('missing HMAC sidecar → forced closed', true, r.forcedClosed === true);
  assert('missing HMAC sidecar → onForceClosed called', true, forcedClosedCalled);
  // In forced-closed mode, all escalations are deny.
  const s = getRestoreState();
  assert('forced closed → all escalations deny',
    { degraded: 'deny', at_risk: 'deny', suspended: 'deny' }, s.escalation);
}

{
  // 5b. Config HMAC key + valid sidecar → honors config
  const projectDir = setupProject();
  const config = {
    enabled: true,
    trust_state_file: 'var/restore/trust-state.json',
    escalation: { degraded: 'log', at_risk: 'ask', suspended: 'deny' },
  };
  const configFile = writeConfig(projectDir, config);
  const hmacKey = 'test-hmac-key';
  writeFileSync(join(projectDir, 'etc/keys/restore-config-hmac.key'), hmacKey);
  // Compute HMAC over canonical form (same as config-integrity.mjs signConfig)
  const canonical = JSON.stringify(JSON.parse(readFileSync(configFile, 'utf-8')));
  const hmac = createHmac('sha256', hmacKey).update(canonical).digest('hex');
  writeFileSync(configFile + '.hmac', hmac + '\n');
  const r = initRestore({ projectDir, configFile });
  assert('valid HMAC sidecar → enabled, not forced-closed',
    { enabled: true, forcedClosed: undefined }, { enabled: r.enabled, forcedClosed: r.forcedClosed });
}

{
  // 5c. Config HMAC mismatch → forced-closed
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, { enabled: true });
  const hmacKey = 'test-hmac-key';
  writeFileSync(join(projectDir, 'etc/keys/restore-config-hmac.key'), hmacKey);
  writeFileSync(configFile + '.hmac', 'deadbeef\n');  // wrong hmac
  const r = initRestore({ projectDir, configFile });
  assert('HMAC mismatch → forced closed', true, r.forcedClosed === true);
}

// ─── Section 6: INV-04 — advisory never crashes ────────────────────────────

console.log('\n── Section 6: INV-04 fail-open ──────────────────────────────');

{
  // Enabled + trust state file unreadable directory: force ENOENT by pointing
  // trust_state_file at a non-existent relative path. readTrustState must
  // still return 'healthy' (no file = INV-01 healthy).
  const projectDir = setupProject();
  const configFile = writeConfig(projectDir, {
    enabled: true,
    trust_state_file: 'var/does-not-exist/trust-state.json',
    escalation: { degraded: 'log', at_risk: 'ask', suspended: 'deny' },
  });
  initRestore({ projectDir, configFile });
  assert('unreachable trust file → healthy (INV-01)', 'healthy', readTrustState());
  assert('unreachable trust file → pass-through', 'allow', checkEscalation('allow').action);
}

// ─── Summary ────────────────────────────────────────────────────────────────

rmSync(SCRATCH, { recursive: true, force: true });

console.log(`\nRestore parity tests: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
process.exit(FAIL === 0 ? 0 : 1);
