#!/usr/bin/env node

import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
  signReceiptV1,
} from '../lib/receipt.mjs';
import {
  PROTECTED_RECORDS_SERVICE_LAUNCHER_CONFIG_TYPE,
  applyProtectedRecordsServiceRequest,
  assertNoUnsafeProtectedRecordsServiceText,
  assertProtectedRecordsServiceResult,
} from '../lib/protected-records-service.mjs';

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

function isoFromEpoch(epoch) {
  return new Date(epoch * 1000).toISOString();
}

function base64urlEncode(value) {
  return Buffer.from(value, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function readIfExists(path) {
  return existsSync(path) ? readFileSync(path, 'utf8') : null;
}

function clone(value) {
  return structuredClone(value);
}

const scratch = mkdtempSync(join(tmpdir(), 'zlar-claude-bridge-proof-'));
const nowEpoch = Math.floor(Date.now() / 1000);

function keyFixture(label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(scratch, `${label}.pub`);
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPem,
    kid: pubkeyFingerprint(publicPath),
  };
}

const trusted = keyFixture('trusted-hook-issuer');
const unknown = keyFixture('unknown-hook-issuer');
const policyVersion = 'claude-code-bridge-profile-v1';
const auditEventId = 'claude-code-hook-bridge-001';
const ruleId = 'R_CLAUDE_CODE_SCRATCH_RECORDS_WRITE';

function recordUpdate(overrides = {}) {
  return {
    request_id: 'scratch-bridge-request-001',
    operation: 'append_scratch_status',
    protected_record: {
      alias: 'scratch-protected-record',
      classification: 'fixture_only',
    },
    bridge: {
      client_surface: 'claude-code',
      gate_surface: 'claude-code-pretooluse-fixture',
      profile_id: 'claude-code-first-lane-profile-v1',
      terminal_id: 'protected-records.scratch.records.write',
      command_hash: 'b'.repeat(64),
      receipt_handoff: 'fixture-hook-gate-to-downstream-verifier',
    },
    ...overrides,
  };
}

const validRecordUpdate = recordUpdate();

function hookEvent(overrides = {}) {
  return {
    id: overrides.id || auditEventId,
    source: 'gate',
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || validRecordUpdate,
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || ruleId,
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || policyVersion,
    ts: overrides.ts || isoFromEpoch(nowEpoch - 5),
    prev_hash: overrides.prev_hash || '0'.repeat(64),
    manifest_agent_id: 'zlar:agent:claude-code',
    agent_config_hash: 'a'.repeat(64),
    agent_config_source: 'project_claude_md',
    agent_fingerprint: '0123456789abcdef',
  };
}

function signedReceipt(key = trusted, overrides = {}) {
  return signReceiptV1(
    createReceiptV1FromEvent(hookEvent(overrides)),
    key.privatePem,
    key.kid
  );
}

function recognitionRule() {
  return {
    deployment_scope: 'claude-code-scratch-protected-records-bridge-fixture',
    accepted_issuers: [
      {
        kid: trusted.kid,
        public_key_pem: trusted.publicPem,
        status: 'active',
      },
    ],
    accepted_policy_versions: [policyVersion],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: auditEventId,
  };
}

function paths(label) {
  return {
    state_path: join(scratch, `${label}.jsonl`),
    consumed_receipts_path: join(scratch, `${label}-consumed.json`),
  };
}

function launcherConfig(label) {
  const fixturePaths = paths(label);
  return {
    config_type: PROTECTED_RECORDS_SERVICE_LAUNCHER_CONFIG_TYPE,
    fixture_mode: true,
    recognition_rule: recognitionRule(),
    state_path: fixturePaths.state_path,
    consumed_receipts_path: fixturePaths.consumed_receipts_path,
    now_epoch: nowEpoch,
    request_stream_allowed_fields: ['receipt', 'record_update'],
    request_stream_authority_material_allowed: false,
  };
}

function request(receipt = signedReceipt(), update = validRecordUpdate, extra = {}) {
  return {
    receipt,
    record_update: update,
    ...extra,
  };
}

function seededConfig(label) {
  const config = launcherConfig(label);
  const initialState = `${JSON.stringify({
    entry_type: 'seed-state-entry-v1',
    marker: label,
  })}\n`;
  const initialConsumed = `${JSON.stringify({
    store_type: 'protected-records-consumed-receipts-v1',
    receipt_ids: ['seed-receipt'],
  }, null, 2)}\n`;
  writeFileSync(config.state_path, initialState);
  writeFileSync(config.consumed_receipts_path, initialConsumed);
  return { config, initialState, initialConsumed };
}

function assertSafeResult(label, result) {
  assert(`${label} result validates`, assertProtectedRecordsServiceResult(result));
  assert(`${label} result output is privacy safe`, assertNoUnsafeProtectedRecordsServiceText(JSON.stringify(result, null, 2)));
}

function runRefusalCase({
  label,
  receipt = signedReceipt(),
  update = validRecordUpdate,
  extraRequest = {},
  expectedReason,
}) {
  const { config, initialState, initialConsumed } = seededConfig(label);
  const result = applyProtectedRecordsServiceRequest(
    request(receipt, update, extraRequest),
    { launcherConfig: config }
  );
  assertSafeResult(label, result);
  assertEqual(`${label} refuses`, false, result.service_write_accepted);
  assertEqual(`${label} reason`, expectedReason, result.decision.reason_code);
  assertEqual(`${label} state delta`, 0, result.state_entry_count_delta);
  assertEqual(`${label} state unchanged`, initialState, readIfExists(config.state_path));
  assertEqual(`${label} consumed store unchanged`, initialConsumed, readIfExists(config.consumed_receipts_path));
  return result;
}

function tamperedPayloadReceipt() {
  const receipt = clone(signedReceipt());
  const payload = decodePayloadV1(receipt);
  payload.detail_hash = 'c'.repeat(64);
  return {
    ...receipt,
    payload: base64urlEncode(JSON.stringify(payload)),
  };
}

try {
  section('simulated Claude Code hook/gate handoff accepts one scratch write');
  const acceptedConfig = launcherConfig('accepted');
  const acceptedRequest = request();
  const accepted = applyProtectedRecordsServiceRequest(acceptedRequest, {
    launcherConfig: acceptedConfig,
  });
  assertSafeResult('accepted bridge', accepted);
  assertEqual('accepted bridge evidence model', 'local-fixture-launcher-owned-config', accepted.evidence_model);
  assertEqual('accepted bridge has no live probing', false, accepted.live_probing);
  assertEqual('accepted bridge accepts exactly one write', true, accepted.service_write_accepted);
  assertEqual('accepted bridge state delta', 1, accepted.state_entry_count_delta);
  assertEqual('accepted bridge reason', 'recognized', accepted.decision.reason_code);
  assertEqual('accepted bridge binds Claude Code action', 'records.write', accepted.decision.evidence.payload.tool);
  assertEqual('accepted bridge binds records domain', 'records', accepted.decision.evidence.payload.domain);
  assertEqual('accepted bridge binds policy profile', policyVersion, accepted.decision.evidence.payload.policy_version);
  assertEqual('accepted bridge binds hook event id', auditEventId, accepted.decision.evidence.payload.audit_event_id);

  const acceptedStateText = readIfExists(acceptedConfig.state_path);
  assert('accepted state exists', typeof acceptedStateText === 'string' && acceptedStateText.length > 0);
  assert('accepted state omits raw record alias', !acceptedStateText.includes('scratch-protected-record'));
  assert('accepted state omits private key material', !acceptedStateText.includes('BEGIN PRIVATE KEY'));
  assert('accepted state omits public key material', !acceptedStateText.includes('BEGIN PUBLIC KEY'));
  const acceptedStateEntry = JSON.parse(acceptedStateText.trim());
  assertEqual('accepted state entry type', 'protected-records-service-state-entry-v1', acceptedStateEntry.entry_type);
  assertEqual('accepted state entry binds receipt id', accepted.decision.evidence.receipt_id, acceptedStateEntry.receipt_id);
  assertEqual('accepted state entry binds detail hash', accepted.record_update_hash, acceptedStateEntry.detail_hash);

  section('replay refuses before scratch state mutation');
  const replayStateBefore = readIfExists(acceptedConfig.state_path);
  const replayConsumedBefore = readIfExists(acceptedConfig.consumed_receipts_path);
  const replay = applyProtectedRecordsServiceRequest(acceptedRequest, {
    launcherConfig: acceptedConfig,
  });
  assertSafeResult('replay bridge', replay);
  assertEqual('replay refuses', false, replay.service_write_accepted);
  assertEqual('replay reason', 'receipt_replay', replay.decision.reason_code);
  assertEqual('replay state unchanged', replayStateBefore, readIfExists(acceptedConfig.state_path));
  assertEqual('replay consumed store unchanged', replayConsumedBefore, readIfExists(acceptedConfig.consumed_receipts_path));

  section('receipt and recognition refusal matrix leaves scratch state unchanged');
  runRefusalCase({
    label: 'missing-receipt',
    receipt: null,
    expectedReason: 'receipt_missing',
  });
  const invalidReceipt = { ...signedReceipt(), sig: '' };
  runRefusalCase({
    label: 'invalid-receipt',
    receipt: invalidReceipt,
    expectedReason: 'receipt_invalid',
  });
  runRefusalCase({
    label: 'stale-or-expired-receipt',
    receipt: signedReceipt(trusted, { ts: isoFromEpoch(nowEpoch - 121) }),
    expectedReason: 'receipt_stale',
  });
  runRefusalCase({
    label: 'future-skew-receipt',
    receipt: signedReceipt(trusted, { ts: isoFromEpoch(nowEpoch + 30) }),
    expectedReason: 'receipt_stale',
  });
  runRefusalCase({
    label: 'wrong-request',
    update: recordUpdate({ request_id: 'scratch-bridge-request-002' }),
    expectedReason: 'detail_hash_mismatch',
  });
  runRefusalCase({
    label: 'wrong-policy',
    receipt: signedReceipt(trusted, { policy_version: 'other-policy-v1' }),
    expectedReason: 'policy_not_recognized',
  });
  runRefusalCase({
    label: 'wrong-profile',
    update: recordUpdate({
      bridge: {
        ...validRecordUpdate.bridge,
        profile_id: 'other-profile-v1',
      },
    }),
    expectedReason: 'detail_hash_mismatch',
  });
  runRefusalCase({
    label: 'wrong-surface',
    update: recordUpdate({
      bridge: {
        ...validRecordUpdate.bridge,
        client_surface: 'cursor',
      },
    }),
    expectedReason: 'detail_hash_mismatch',
  });
  runRefusalCase({
    label: 'wrong-terminal',
    update: recordUpdate({
      bridge: {
        ...validRecordUpdate.bridge,
        terminal_id: 'protected-records.other.records.write',
      },
    }),
    expectedReason: 'detail_hash_mismatch',
  });
  runRefusalCase({
    label: 'unrecognized-issuer',
    receipt: signedReceipt(unknown),
    expectedReason: 'unknown_issuer',
  });
  runRefusalCase({
    label: 'summary-only-recognition',
    receipt: {
      recognized: true,
      receipt_id: 'summary-only',
      issuer_known: true,
      signature_valid: true,
    },
    expectedReason: 'unsupported_receipt_format',
  });
  runRefusalCase({
    label: 'tampered-receipt-evidence',
    receipt: tamperedPayloadReceipt(),
    expectedReason: 'receipt_invalid',
  });
  runRefusalCase({
    label: 'request-stream-authority-material',
    extraRequest: {
      state_path: 'attacker-supplied-state.jsonl',
    },
    expectedReason: 'request_stream_authority_material',
  });

  section('claim boundary');
  assert('bridge proof did not write machine hook paths', !existsSync(join(scratch, '.claude')));
  assert('bridge proof remains fixture evidence', accepted.non_claims.includes('This service is a local fixture downstream service.'));
  assert('bridge proof does not claim production deployment', accepted.non_claims.includes('This service does not prove production deployment.'));
  assert('bridge proof does not close direct filesystem side doors', accepted.non_claims.includes('This service does not close direct filesystem writes to fixture paths.'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
console.log(`Claude Code receipt bridge proof tests: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
