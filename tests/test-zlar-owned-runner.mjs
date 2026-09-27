#!/usr/bin/env node

import {
  generateKeyPairSync,
} from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  ZLAR_OWNED_RUNNER_CONTRACT,
  evidenceText,
  runCli,
  runZlarOwnedRunner,
  sha256Text,
} from '../lib/zlar-owned-runner.mjs';
import {
  decodePayloadV1,
  pubkeyFingerprint,
  verifyReceiptV1FromFile,
} from '../lib/receipt.mjs';

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

const PROJECT_DIR = process.cwd();
const baseScratch = process.env.ZLAR_RUNNER_TEST_ROOT ||
  join(tmpdir(), `zlar-owned-runner-${process.pid}`);
const scratch = join(baseScratch, 'node');
rmSync(scratch, { recursive: true, force: true });
mkdirSync(scratch, { recursive: true });

const fakeGate = join(scratch, 'fake-gate.mjs');
const auditFile = join(scratch, 'audit.jsonl');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const proofPrivateKeyPath = join(scratch, 'proof-receipt.key');
const proofPublicKeyPath = join(scratch, 'proof-receipt.pub');
writeFileSync(proofPrivateKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
writeFileSync(proofPublicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
const proofKeyId = pubkeyFingerprint(proofPublicKeyPath);

writeFileSync(fakeGate, `#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';

const input = JSON.parse(readFileSync(0, 'utf8'));
const cmd = input.tool_input?.command || '';
const auditedCmd = cmd + ' ';
const cwd = input.tool_input?.cwd || '';
const auditFile = process.env.ZLAR_AUDIT_FILE;

function appendEvent(overrides = {}) {
  if (!auditFile) return;
  const event = {
    id: overrides.id || 'fixture-' + Math.random().toString(16).slice(2),
    ts: new Date().toISOString(),
    seq: 1,
    source: 'gate',
    host: 'fixture',
    user: 'fixture',
    agent_id: input.agent_id || 'zlar-owned-runner',
    session_id: overrides.session_id || input.session_id,
    domain: 'bash',
    action: auditedCmd.slice(0, 200),
    outcome: overrides.outcome || 'allow',
    risk_score: 0,
    detail: {
      command: overrides.command || auditedCmd,
      cwd: overrides.cwd === undefined ? cwd : overrides.cwd,
    },
    rule: overrides.rule || 'fixture:allow',
    policy_version: 'fixture',
    severity: 'info',
    prev_hash: 'fixture',
    authorizer: overrides.authorizer || 'policy',
    signature: 'fixture',
  };
  appendFileSync(auditFile, JSON.stringify(event) + '\\n');
}

if (cmd.includes('deny-fixture')) {
  appendEvent({ outcome: 'deny', rule: 'fixture:deny' });
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: '[policy] fixture deny' } }));
  process.exit(2);
}
if (cmd.includes('malformed-fixture')) {
  appendEvent();
  console.log('not-json');
  process.exit(0);
}
if (cmd.includes('empty-fixture')) {
  appendEvent();
  process.exit(0);
}
if (cmd.includes('nonzero-fixture')) {
  appendEvent();
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }));
  process.exit(9);
}
if (cmd.includes('missing-audit-fixture')) {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }));
  process.exit(0);
}
if (cmd.includes('mismatch-session-fixture')) {
  appendEvent({ session_id: 'wrong-session' });
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }));
  process.exit(0);
}
if (cmd.includes('mismatch-command-fixture')) {
  appendEvent({ command: cmd + ' drift' });
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }));
  process.exit(0);
}
if (cmd.includes('extra-space-mismatch-fixture')) {
  appendEvent({ command: auditedCmd + ' ' });
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }));
  process.exit(0);
}
if (cmd.includes('ambiguous-audit-fixture')) {
  appendEvent({ id: 'fixture-ambiguous-a' });
  appendEvent({ id: 'fixture-ambiguous-b' });
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }));
  process.exit(0);
}
if (cmd.includes('updated-fixture')) {
  appendEvent();
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow', updatedInput: { command: process.env.ZLAR_UPDATED_COMMAND || cmd } } }));
  process.exit(0);
}

appendEvent();
console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' } }));
process.exit(0);
`);
chmodSync(fakeGate, 0o755);

function runFixture(command, extra = {}) {
  const result = runZlarOwnedRunner({
    command,
    cwd: extra.cwd || scratch,
    reason: extra.reason || 'fixture',
    session_id: extra.session_id || `fixture-${Math.random().toString(16).slice(2)}`,
    ...(extra.request || {}),
  }, {
    projectDir: PROJECT_DIR,
    gatePath: fakeGate,
    auditFile,
    env: {
      ZLAR_AUDIT_FILE: auditFile,
      ZLAR_RUNNER_EVIDENCE_ROOT: scratch,
      ...(extra.env || {}),
    },
    now: () => '2026-07-04T00:00:00Z',
  });
  return result;
}

console.log('ZLAR-Owned Runner Tests');
console.log('=======================');

section('fake gate allow executes once');
const allowMarker = join(scratch, 'allow-marker.txt');
const allowCommand = `printf allow-fixture > ${allowMarker}`;
const allow = runFixture(allowCommand);
assertEqual('allow exits zero', 0, allow.exitCode);
assertEqual('allow evidence contract', ZLAR_OWNED_RUNNER_CONTRACT, allow.evidence.runner_contract);
assertEqual('allow executed true', true, allow.evidence.execution.executed);
assert('allow marker written', existsSync(allowMarker));
assertEqual('allow marker content', 'allow-fixture', readFileSync(allowMarker, 'utf8'));
assertEqual('allow audit matched', 'matched', allow.evidence.audit.match_status);
assertEqual('allow audit outcome', 'allow', allow.evidence.audit.outcome);
assertEqual('allow audit is not receipt grade', false, allow.evidence.audit.receipt_grade);
assertEqual('allow audit freshness is local', 'local_line_count_window', allow.evidence.audit.freshness_scope);
assertEqual(
  'allow matches gate-normalized audit command hash',
  sha256Text(`${allowCommand} `),
  allow.evidence.audit.detail_command_sha256
);
assertEqual(
  'allow evidence records expected gate-normalized command hash',
  sha256Text(`${allowCommand} `),
  allow.evidence.audit.expected_detail_command_sha256
);
assertEqual('allow transformation no updatedInput', false, allow.evidence.gate_transformation.updated_input_used);
assertEqual('allow transformation request hash', sha256Text(allowCommand), allow.evidence.gate_transformation.requested_command_sha256);
assertEqual('allow transformation effective hash', sha256Text(allowCommand), allow.evidence.gate_transformation.effective_command_sha256);
assertEqual('allow effective command audit match true', true, allow.evidence.gate_transformation.effective_command_audit_match);

section('receipt binding allow executes after verified receipt');
const receiptAllowMarker = join(scratch, 'receipt-allow-marker.txt');
const receiptAllowOut = join(scratch, 'receipt-allow.json');
const receiptAllowCommand = `printf receipt-allow > ${receiptAllowMarker}`;
const receiptAllow = runFixture(receiptAllowCommand, {
  request: {
    receipt_out: receiptAllowOut,
    receipt_key: proofPrivateKeyPath,
    receipt_pubkey: proofPublicKeyPath,
  },
});
assertEqual('receipt allow exits zero', 0, receiptAllow.exitCode);
assertEqual('receipt allow executed true', true, receiptAllow.evidence.execution.executed);
assert('receipt allow marker written', existsSync(receiptAllowMarker));
assert('receipt allow file written', existsSync(receiptAllowOut));
assertEqual('receipt allow grade true', true, receiptAllow.evidence.receipt_binding.receipt_grade);
assertEqual('receipt allow claim true', true, receiptAllow.evidence.receipt_claim);
assertEqual('receipt allow claim scope', 'proof-key v1 receipt binding for this zlar-run invocation only', receiptAllow.evidence.receipt_claim_scope);
assertEqual('receipt allow verification valid', true, receiptAllow.evidence.receipt_binding.verification.valid);
assertEqual('receipt allow kid matches proof key', proofKeyId, receiptAllow.evidence.receipt_binding.receipt.kid);
const receiptAllowJson = JSON.parse(readFileSync(receiptAllowOut, 'utf8'));
const receiptAllowVerify = verifyReceiptV1FromFile(receiptAllowJson, proofPublicKeyPath);
const receiptAllowPayload = decodePayloadV1(receiptAllowJson);
assertEqual('receipt allow verifies from file', true, receiptAllowVerify.valid);
assertEqual('receipt allow payload outcome', 'allow', receiptAllowPayload.outcome);
assertEqual('receipt allow payload event id binds audit', receiptAllow.evidence.audit.id, receiptAllowPayload.audit_event_id);
assertEqual('receipt allow payload prev hash binds audit', receiptAllow.evidence.audit.prev_hash, receiptAllowPayload.audit_prev_hash);
assertEqual('receipt allow payload detail hash binds audit', receiptAllow.evidence.audit.detail_hash, receiptAllowPayload.detail_hash);

section('fake gate deny blocks effect');
const denyMarker = join(scratch, 'deny-marker.txt');
const deny = runFixture(`printf deny-fixture > ${denyMarker} # deny-fixture`);
assertEqual('deny exits two', 2, deny.exitCode);
assertEqual('deny executed false', false, deny.evidence.execution.executed);
assert('deny marker absent', !existsSync(denyMarker));
assert('deny block names gate nonzero', deny.evidence.execution.block_reasons.includes('gate_nonzero_exit'));
assert('deny block names decision', deny.evidence.execution.block_reasons.includes('gate_decision_deny'));
assertEqual('deny audit matched', 'matched', deny.evidence.audit.match_status);
assertEqual('deny audit outcome', 'deny', deny.evidence.audit.outcome);
assertEqual('deny audit is not receipt grade', false, deny.evidence.audit.receipt_grade);

section('receipt binding deny blocks child and preserves sentinel');
const receiptDenyMarker = join(scratch, 'receipt-deny-marker.txt');
const receiptDenyOut = join(scratch, 'receipt-deny.json');
const receiptDenyCommand = `printf deny-fixture > ${receiptDenyMarker} # deny-fixture`;
const receiptDeny = runFixture(receiptDenyCommand, {
  request: {
    receipt_out: receiptDenyOut,
    receipt_key: proofPrivateKeyPath,
    receipt_pubkey: proofPublicKeyPath,
  },
});
assertEqual('receipt deny exits two', 2, receiptDeny.exitCode);
assertEqual('receipt deny executed false', false, receiptDeny.evidence.execution.executed);
assert('receipt deny marker absent', !existsSync(receiptDenyMarker));
assert('receipt deny file written', existsSync(receiptDenyOut));
assertEqual('receipt deny grade true', true, receiptDeny.evidence.receipt_binding.receipt_grade);
assertEqual('receipt deny claim true', true, receiptDeny.evidence.receipt_claim);
assertEqual('receipt deny verification valid', true, receiptDeny.evidence.receipt_binding.verification.valid);
const receiptDenyJson = JSON.parse(readFileSync(receiptDenyOut, 'utf8'));
const receiptDenyVerify = verifyReceiptV1FromFile(receiptDenyJson, proofPublicKeyPath);
const receiptDenyPayload = decodePayloadV1(receiptDenyJson);
assertEqual('receipt deny verifies from file', true, receiptDenyVerify.valid);
assertEqual('receipt deny payload outcome', 'deny', receiptDenyPayload.outcome);
assertEqual('receipt deny payload event id binds audit', receiptDeny.evidence.audit.id, receiptDenyPayload.audit_event_id);
assertEqual('receipt deny payload prev hash binds audit', receiptDeny.evidence.audit.prev_hash, receiptDenyPayload.audit_prev_hash);
assertEqual('receipt deny payload detail hash binds audit', receiptDeny.evidence.audit.detail_hash, receiptDenyPayload.detail_hash);

section('malformed and empty gate output block');
const malformedMarker = join(scratch, 'malformed-marker.txt');
const malformed = runFixture(`printf malformed > ${malformedMarker} # malformed-fixture`);
assertEqual('malformed exits two', 2, malformed.exitCode);
assertEqual('malformed executed false', false, malformed.evidence.execution.executed);
assert('malformed marker absent', !existsSync(malformedMarker));
assert('malformed block reason present', malformed.evidence.execution.block_reasons.includes('gate_stdout_invalid_json'));

const emptyMarker = join(scratch, 'empty-marker.txt');
const empty = runFixture(`printf empty > ${emptyMarker} # empty-fixture`);
assertEqual('empty exits two', 2, empty.exitCode);
assertEqual('empty executed false', false, empty.evidence.execution.executed);
assert('empty marker absent', !existsSync(emptyMarker));
assert('empty block reason present', empty.evidence.execution.block_reasons.includes('gate_stdout_empty_stdout'));

section('nonzero allow blocks');
const nonzeroMarker = join(scratch, 'nonzero-marker.txt');
const nonzero = runFixture(`printf nonzero > ${nonzeroMarker} # nonzero-fixture`);
assertEqual('nonzero exits two', 2, nonzero.exitCode);
assertEqual('nonzero executed false', false, nonzero.evidence.execution.executed);
assert('nonzero marker absent', !existsSync(nonzeroMarker));
assert('nonzero block reason present', nonzero.evidence.execution.block_reasons.includes('gate_nonzero_exit'));

section('missing and mismatched audit block');
const missingAuditMarker = join(scratch, 'missing-audit-marker.txt');
const missingAudit = runFixture(`printf missing > ${missingAuditMarker} # missing-audit-fixture`);
assertEqual('missing audit exits two', 2, missingAudit.exitCode);
assertEqual('missing audit executed false', false, missingAudit.evidence.execution.executed);
assert('missing audit marker absent', !existsSync(missingAuditMarker));
assert('missing audit block reason present', missingAudit.evidence.execution.block_reasons.includes('audit_missing'));

const mismatchSessionMarker = join(scratch, 'mismatch-session-marker.txt');
const mismatchSession = runFixture(`printf mismatch > ${mismatchSessionMarker} # mismatch-session-fixture`);
assertEqual('mismatch session exits two', 2, mismatchSession.exitCode);
assertEqual('mismatch session executed false', false, mismatchSession.evidence.execution.executed);
assert('mismatch session marker absent', !existsSync(mismatchSessionMarker));
assert('mismatch session block reason present', mismatchSession.evidence.execution.block_reasons.includes('audit_missing'));

const mismatchCommandMarker = join(scratch, 'mismatch-command-marker.txt');
const mismatchCommand = runFixture(`printf mismatch > ${mismatchCommandMarker} # mismatch-command-fixture`);
assertEqual('mismatch command exits two', 2, mismatchCommand.exitCode);
assertEqual('mismatch command executed false', false, mismatchCommand.evidence.execution.executed);
assert('mismatch command marker absent', !existsSync(mismatchCommandMarker));
assert('mismatch command block reason present', mismatchCommand.evidence.execution.block_reasons.includes('audit_missing'));

const extraSpaceMarker = join(scratch, 'extra-space-marker.txt');
const extraSpace = runFixture(`printf extra > ${extraSpaceMarker} # extra-space-mismatch-fixture`);
assertEqual('extra space mismatch exits two', 2, extraSpace.exitCode);
assertEqual('extra space mismatch executed false', false, extraSpace.evidence.execution.executed);
assert('extra space mismatch marker absent', !existsSync(extraSpaceMarker));
assert('extra space mismatch block reason present', extraSpace.evidence.execution.block_reasons.includes('audit_missing'));

const ambiguousMarker = join(scratch, 'ambiguous-marker.txt');
const ambiguous = runFixture(`printf ambiguous > ${ambiguousMarker} # ambiguous-audit-fixture`);
assertEqual('ambiguous audit exits two', 2, ambiguous.exitCode);
assertEqual('ambiguous audit executed false', false, ambiguous.evidence.execution.executed);
assert('ambiguous marker absent', !existsSync(ambiguousMarker));
assert('ambiguous block reason present', ambiguous.evidence.execution.block_reasons.includes('audit_ambiguous'));

section('updatedInput behavior explicit');
const originalMarker = join(scratch, 'original-updated-marker.txt');
const updatedMarker = join(scratch, 'updated-marker.txt');
const updated = runFixture(`printf original > ${originalMarker} # updated-fixture`, {
  env: {
    ZLAR_UPDATED_COMMAND: `printf updated > ${updatedMarker}`,
  },
});
const updatedRequestedCommand = `printf original > ${originalMarker} # updated-fixture`;
const updatedEffectiveCommand = `printf updated > ${updatedMarker}`;
assertEqual('updated exits zero', 0, updated.exitCode);
assertEqual('updated executed true', true, updated.evidence.execution.executed);
assertEqual('updatedInput used true', true, updated.evidence.execution.updated_input_used);
assert('original marker absent', !existsSync(originalMarker));
assert('updated marker written', existsSync(updatedMarker));
assertEqual('updated marker content', 'updated', readFileSync(updatedMarker, 'utf8'));
assertEqual('updated transformation used true', true, updated.evidence.gate_transformation.updated_input_used);
assertEqual('updated requested command hash', sha256Text(updatedRequestedCommand), updated.evidence.gate_transformation.requested_command_sha256);
assertEqual('updated effective command hash', sha256Text(updatedEffectiveCommand), updated.evidence.gate_transformation.effective_command_sha256);
assertEqual('updated effective command audit match false', false, updated.evidence.gate_transformation.effective_command_audit_match);
assertEqual(
  'updated audit still binds requested command',
  sha256Text(`${updatedRequestedCommand} `),
  updated.evidence.audit.detail_command_sha256
);

section('cwd lexical and filesystem canonical binding');
const realCwd = join(scratch, 'real-cwd');
mkdirSync(realCwd, { recursive: true });
const symlinkCwd = join(scratch, 'linked-cwd');
symlinkSync(realCwd, symlinkCwd);
const cwdMarker = join(scratch, 'cwd-marker.txt');
const cwdResult = runFixture(`pwd -P > ${cwdMarker}`, { cwd: symlinkCwd });
assertEqual('cwd fixture exits zero', 0, cwdResult.exitCode);
assertEqual('cwd fixture executed', true, cwdResult.evidence.execution.executed);
assertEqual('cwd lexical recorded', symlinkCwd, cwdResult.evidence.request.cwd);
assertEqual('cwd canonical recorded', realpathSync(realCwd), cwdResult.evidence.request.cwd_canonical);
assertEqual('cwd execution uses canonical', realpathSync(realCwd), cwdResult.evidence.execution.effective_cwd);
assertEqual('cwd child saw canonical cwd', `${realpathSync(realCwd)}\n`, readFileSync(cwdMarker, 'utf8'));

section('unsafe evidence redaction and preflight blocking');
const unsafeMarker = join(scratch, 'unsafe-marker.txt');
const unsafe = runFixture(`printf token=sk-testsecret123456 > ${unsafeMarker}`);
assertEqual('unsafe exits two', 2, unsafe.exitCode);
assertEqual('unsafe executed false', false, unsafe.evidence.execution.executed);
assert('unsafe marker absent', !existsSync(unsafeMarker));
assert('unsafe block names material', unsafe.evidence.execution.block_reasons.some((item) => item.startsWith('unsafe_command_material')));
assertEqual('unsafe command redacted', true, unsafe.evidence.request.command.redacted);
assert('unsafe command has sha', /^[a-f0-9]{64}$/.test(unsafe.evidence.request.command.sha256));
const redacted = evidenceText('Authorization: Bearer abcdefghijk12345');
assertEqual('standalone evidence redacts auth', true, redacted.redacted);

section('evidence output path hardening');
function makeIo() {
  return {
    stdoutText: '',
    stderrText: '',
    stdout: { write(chunk) { this.owner.stdoutText += String(chunk); } },
    stderr: { write(chunk) { this.owner.stderrText += String(chunk); } },
  };
}

function runCliFixture(args, extra = {}) {
  const io = makeIo();
  io.stdout.owner = io;
  io.stderr.owner = io;
  const rc = runCli(args, {
    stdout: io.stdout,
    stderr: io.stderr,
    runnerOptions: {
      projectDir: PROJECT_DIR,
      gatePath: fakeGate,
      auditFile,
      env: {
        ZLAR_AUDIT_FILE: auditFile,
        ZLAR_RUNNER_EVIDENCE_ROOT: scratch,
        ...(extra.env || {}),
      },
      now: () => '2026-07-04T00:00:00Z',
    },
  });
  return { rc, stdout: io.stdoutText, stderr: io.stderrText };
}

const cliEvidence = join(scratch, 'cli-evidence.json');
const cliResult = runCliFixture([
  '--cmd',
  `printf cli-evidence > ${join(scratch, 'cli-evidence-marker.txt')}`,
  '--cwd',
  scratch,
  '--evidence-out',
  cliEvidence,
]);
assertEqual('cli evidence run exits zero', 0, cliResult.rc);
assert('cli evidence file created', existsSync(cliEvidence));
assertEqual('cli evidence contract', ZLAR_OWNED_RUNNER_CONTRACT, JSON.parse(readFileSync(cliEvidence, 'utf8')).runner_contract);

const existingEvidence = join(scratch, 'existing-evidence.json');
writeFileSync(existingEvidence, 'already here\n');
const existingResult = runCliFixture([
  '--cmd',
  `printf existing > ${join(scratch, 'existing-marker.txt')}`,
  '--cwd',
  scratch,
  '--evidence-out',
  existingEvidence,
]);
assertEqual('existing evidence path exits two', 2, existingResult.rc);
assert('existing evidence path rejected', existingResult.stderr.includes('evidence_path_exists'));
assertEqual('existing evidence not overwritten', 'already here\n', readFileSync(existingEvidence, 'utf8'));

const outsideEvidence = join(tmpdir(), `zlar-owned-runner-outside-${process.pid}.json`);
rmSync(outsideEvidence, { force: true });
const outsideResult = runCliFixture([
  '--cmd',
  `printf outside > ${join(scratch, 'outside-marker.txt')}`,
  '--cwd',
  scratch,
  '--evidence-out',
  outsideEvidence,
]);
assertEqual('outside evidence path exits two', 2, outsideResult.rc);
assert('outside evidence path rejected', outsideResult.stderr.includes('evidence_path_outside_root'));
assert('outside evidence file absent', !existsSync(outsideEvidence));

const traversalResult = runCliFixture([
  '--cmd',
  `printf traversal > ${join(scratch, 'traversal-marker.txt')}`,
  '--cwd',
  scratch,
  '--evidence-out',
  '../traversal-evidence.json',
]);
assertEqual('traversal evidence path exits two', 2, traversalResult.rc);
assert('traversal evidence path rejected', traversalResult.stderr.includes('evidence_path_traversal'));

const symlinkParent = join(scratch, 'evidence-link');
symlinkSync(scratch, symlinkParent);
const symlinkResult = runCliFixture([
  '--cmd',
  `printf symlink > ${join(scratch, 'symlink-marker.txt')}`,
  '--cwd',
  scratch,
  '--evidence-out',
  join(symlinkParent, 'via-symlink.json'),
]);
assertEqual('symlink parent evidence path exits two', 2, symlinkResult.rc);
assert('symlink parent evidence path rejected', symlinkResult.stderr.includes('evidence_path_symlink_parent'));

console.log('');
console.log(`Results: ${PASS} passed, ${FAIL} failed out of ${TOTAL}`);

if (FAIL > 0) {
  process.exit(1);
}
