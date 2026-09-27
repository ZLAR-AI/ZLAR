import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  receiptHashV1,
  signablePayloadV1,
  signReceiptV1FromFiles,
  verifyReceiptV1FromFile,
} from './receipt.mjs';

export const ZLAR_OWNED_RUNNER_CONTRACT = 'zlar-owned-enforceable-runner-v1';

const ALLOW_OUTCOMES = new Set([
  'allow',
  'logged',
  'authorized',
  'away_auto_allow',
]);

const SECRET_PATTERNS = Object.freeze([
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'hmac material', pattern: /\bhmac\b\s*[:=]\s*[^&\s"'`,;})\]]+/i },
  { label: 'token material', pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i },
  { label: 'authorization credential', pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/i },
  { label: 'GitHub token', pattern: /\bghp_[A-Za-z0-9_]{10,}\b/ },
  { label: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/ },
  { label: 'Slack token', pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{12,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
]);

const REDACTION_PATTERNS = Object.freeze([
  ...SECRET_PATTERNS,
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
]);

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256Text(value) {
  return sha256Bytes(String(value));
}

function stableSort(value) {
  if (Array.isArray(value)) {
    return value.map(stableSort);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, stableSort(value[key])])
    );
  }
  return value;
}

export function stableJson(value) {
  return JSON.stringify(stableSort(value));
}

export function defaultProjectDir() {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..');
}

function defaultGatePath(projectDir) {
  return resolve(projectDir, 'bin', 'zlar-gate');
}

function defaultAuditFile(projectDir, env = process.env) {
  return env.ZLAR_AUDIT_FILE || resolve(projectDir, 'var', 'log', 'audit.jsonl');
}

function defaultEvidenceRoot(projectDir, env = process.env) {
  return env.ZLAR_RUNNER_EVIDENCE_ROOT || resolve(projectDir, '..', 'ZLAR-Draft', 'build');
}

function isoNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function makeSessionId() {
  return `zlar-run-${Date.now()}-${randomBytes(6).toString('hex')}`;
}

function normalizeCommand(command) {
  return String(command ?? '');
}

function gateAuditedBashCommand(command) {
  // Mirrors bin/zlar-gate Bash translation:
  // jq -r emits a trailing newline, then tr maps newlines/carriage returns to spaces.
  return `${normalizeCommand(command)} `;
}

function realpathOrNull(path) {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

function findSecretPattern(text) {
  const value = String(text ?? '');
  return SECRET_PATTERNS.find((item) => item.pattern.test(value)) || null;
}

function redactionReason(text) {
  const value = String(text ?? '');
  return REDACTION_PATTERNS.find((item) => item.pattern.test(value))?.label || null;
}

export function evidenceText(value, maxLength = 160) {
  const text = String(value ?? '');
  const reason = redactionReason(text);
  if (reason) {
    return {
      redacted: true,
      redaction_reason: reason,
      snippet: `[redacted:${reason}]`,
      sha256: sha256Text(text),
    };
  }
  return {
    redacted: text.length > maxLength,
    redaction_reason: text.length > maxLength ? 'length' : null,
    snippet: text.length > maxLength ? `${text.slice(0, maxLength)}...` : text,
    sha256: sha256Text(text),
  };
}

function stdoutEvidence(buffer) {
  const text = Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer ?? '');
  return {
    sha256: sha256Bytes(Buffer.isBuffer(buffer) ? buffer : Buffer.from(text)),
    bytes: Buffer.byteLength(text),
    snippet: evidenceText(text, 240),
  };
}

function readLineCount(path) {
  if (!existsSync(path)) {
    return 0;
  }
  const text = readFileSync(path, 'utf8');
  if (!text) {
    return 0;
  }
  return text.split('\n').filter((line) => line.length > 0).length;
}

function readAuditEventsSince(path, startLineCount) {
  if (!existsSync(path)) {
    return {
      end_line_count: 0,
      events: [],
      parse_errors: [],
    };
  }

  const lines = readFileSync(path, 'utf8').split('\n').filter((line) => line.length > 0);
  const events = [];
  const parseErrors = [];

  lines.slice(startLineCount).forEach((line, index) => {
    const lineNumber = startLineCount + index + 1;
    try {
      const parsed = JSON.parse(line);
      events.push({
        line_number: lineNumber,
        entry_sha256: sha256Text(line),
        event: parsed,
      });
    } catch {
      parseErrors.push({
        line_number: lineNumber,
        entry_sha256: sha256Text(line),
      });
    }
  });

  return {
    end_line_count: lines.length,
    events,
    parse_errors: parseErrors,
  };
}

function validateRequest(request, cwd) {
  const errors = [];
  const command = normalizeCommand(request.command);

  if (!command.trim()) {
    errors.push('missing_command');
  }
  if (/[\r\n]/.test(command)) {
    errors.push('command_contains_newline');
  }
  const secret = findSecretPattern(command);
  if (secret) {
    errors.push(`unsafe_command_material:${secret.label}`);
  }
  const reasonSecret = findSecretPattern(request.reason || '');
  if (reasonSecret) {
    errors.push(`unsafe_reason_material:${reasonSecret.label}`);
  }
  try {
    const stats = statSync(cwd);
    if (!stats.isDirectory()) {
      errors.push('cwd_not_directory');
    }
  } catch {
    errors.push('cwd_missing');
  }
  return errors;
}

function hasTraversalSegment(path) {
  return String(path ?? '').split(/[\\/]+/).includes('..');
}

function pathInsideRoot(path, root) {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

function hasSymlinkParent(root, target) {
  const rel = relative(root, dirname(target));
  if (rel === '') {
    return false;
  }
  if (rel.startsWith('..') || isAbsolute(rel)) {
    return true;
  }
  let current = root;
  for (const part of rel.split(sep).filter(Boolean)) {
    current = resolve(current, part);
    if (!existsSync(current)) {
      break;
    }
    if (lstatSync(current).isSymbolicLink()) {
      return true;
    }
  }
  return false;
}

function validateEvidenceOutPath(evidenceOut, options = {}) {
  if (!evidenceOut) {
    return {
      ok: true,
      path: '',
      root: '',
      error: null,
    };
  }

  const projectDir = resolve(options.projectDir || defaultProjectDir());
  const rootLexical = resolve(options.evidenceRoot || defaultEvidenceRoot(projectDir, options.env || process.env));
  mkdirSync(rootLexical, { recursive: true });
  const rootReal = realpathSync(rootLexical);
  const requested = String(evidenceOut);

  if (hasTraversalSegment(requested)) {
    return {
      ok: false,
      path: '',
      root: rootReal,
      error: 'evidence_path_traversal',
    };
  }

  const requestedResolved = isAbsolute(requested)
    ? resolve(requested)
    : resolve(rootLexical, requested);

  let target = '';
  if (pathInsideRoot(requestedResolved, rootLexical)) {
    target = resolve(rootReal, relative(rootLexical, requestedResolved));
  } else if (pathInsideRoot(requestedResolved, rootReal)) {
    target = requestedResolved;
  }

  if (!target || !pathInsideRoot(target, rootReal)) {
    return {
      ok: false,
      path: '',
      root: rootReal,
      error: 'evidence_path_outside_root',
    };
  }
  if (existsSync(target)) {
    return {
      ok: false,
      path: '',
      root: rootReal,
      error: 'evidence_path_exists',
    };
  }
  if (hasSymlinkParent(rootReal, target)) {
    return {
      ok: false,
      path: '',
      root: rootReal,
      error: 'evidence_path_symlink_parent',
    };
  }

  return {
    ok: true,
    path: target,
    root: rootReal,
    error: null,
  };
}

function validateReceiptKeyPath(keyPath, rootReal, label) {
  const requested = String(keyPath || '');
  if (!requested) {
    return {
      ok: false,
      path: '',
      error: `${label}_missing`,
    };
  }
  if (hasTraversalSegment(requested)) {
    return {
      ok: false,
      path: '',
      error: `${label}_path_traversal`,
    };
  }
  const resolved = resolve(requested);
  let real = '';
  try {
    real = realpathSync(resolved);
  } catch {
    return {
      ok: false,
      path: '',
      error: `${label}_missing`,
    };
  }
  if (!pathInsideRoot(real, rootReal)) {
    return {
      ok: false,
      path: '',
      error: `${label}_outside_evidence_root`,
    };
  }
  try {
    if (lstatSync(resolved).isSymbolicLink()) {
      return {
        ok: false,
        path: '',
        error: `${label}_symlink`,
      };
    }
    if (!statSync(real).isFile()) {
      return {
        ok: false,
        path: '',
        error: `${label}_not_file`,
      };
    }
  } catch {
    return {
      ok: false,
      path: '',
      error: `${label}_unreadable`,
    };
  }
  return {
    ok: true,
    path: real,
    error: null,
  };
}

function receiptRequestFrom(request) {
  const receipt = request.receipt && typeof request.receipt === 'object'
    ? request.receipt
    : {};
  return {
    out: request.receipt_out || request.receiptOut || receipt.out || receipt.path || '',
    key: request.receipt_key || request.receiptKey || receipt.key || receipt.private_key || '',
    pubkey: request.receipt_pubkey || request.receiptPubkey || receipt.pubkey || receipt.public_key || '',
  };
}

function validateReceiptBindingRequest(request, options = {}) {
  const receipt = receiptRequestFrom(request);
  const enabled = Boolean(receipt.out || receipt.key || receipt.pubkey);
  const projectDir = resolve(options.projectDir || defaultProjectDir());
  const output = enabled
    ? validateEvidenceOutPath(receipt.out, {
        projectDir,
        evidenceRoot: options.evidenceRoot,
        env: options.env || process.env,
      })
    : {
        ok: true,
        path: '',
        root: '',
        error: null,
      };

  if (!enabled) {
    return {
      enabled: false,
      ok: true,
      output,
      key: { ok: true, path: '', error: null },
      pubkey: { ok: true, path: '', error: null },
      error: null,
    };
  }

  if (!output.ok) {
    return {
      enabled: true,
      ok: false,
      output,
      key: { ok: true, path: '', error: null },
      pubkey: { ok: true, path: '', error: null },
      error: output.error,
    };
  }

  const key = validateReceiptKeyPath(receipt.key, output.root, 'receipt_key');
  if (!key.ok) {
    return {
      enabled: true,
      ok: false,
      output,
      key,
      pubkey: { ok: true, path: '', error: null },
      error: key.error,
    };
  }

  const pubkey = validateReceiptKeyPath(receipt.pubkey, output.root, 'receipt_pubkey');
  if (!pubkey.ok) {
    return {
      enabled: true,
      ok: false,
      output,
      key,
      pubkey,
      error: pubkey.error,
    };
  }

  return {
    enabled: true,
    ok: true,
    output,
    key,
    pubkey,
    error: null,
  };
}

function parseGateDecision(stdout) {
  const text = stdout.toString('utf8').trim();
  if (!text) {
    return {
      stdout_json_valid: false,
      parse_error: 'empty_stdout',
      hookSpecificOutput: null,
    };
  }
  try {
    const parsed = JSON.parse(text);
    return {
      stdout_json_valid: true,
      parse_error: null,
      hookSpecificOutput: parsed?.hookSpecificOutput ?? null,
      parsed,
    };
  } catch {
    return {
      stdout_json_valid: false,
      parse_error: 'invalid_json',
      hookSpecificOutput: null,
    };
  }
}

function buildPayload({ command, cwd, reason, sessionId }) {
  return {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    session_id: sessionId,
    agent_id: 'zlar-owned-runner',
    tool_input: {
      command,
      cwd,
      description: reason || 'zlar-owned-runner',
    },
  };
}

function findMatchingAudit({ auditFile, startLineCount, sessionId, command, cwd }) {
  const audit = readAuditEventsSince(auditFile, startLineCount);
  const expectedCommand = gateAuditedBashCommand(command);
  const matches = audit.events.filter(({ event }) => (
    event?.session_id === sessionId &&
    event?.domain === 'bash' &&
    event?.detail?.command === expectedCommand &&
    (event?.detail?.cwd ?? '') === (cwd ?? '')
  ));

  let status = 'missing';
  if (matches.length === 1) {
    status = 'matched';
  } else if (matches.length > 1) {
    status = 'ambiguous';
  }

  return {
    file: auditFile,
    start_line_count: startLineCount,
    end_line_count: audit.end_line_count,
    expected_detail_command_sha256: sha256Text(expectedCommand),
    parse_errors: audit.parse_errors,
    match_status: status,
    match_count: matches.length,
    matched: matches[0] || null,
  };
}

function summarizeAuditMatch(match) {
  const boundary = {
    freshness_scope: 'local_line_count_window',
    receipt_grade: false,
    receipt_boundary: 'Local audit freshness does not verify audit signature, issuer identity, or hash-chain continuity.',
  };
  if (!match.matched) {
    return {
      file: match.file,
      start_line_count: match.start_line_count,
      end_line_count: match.end_line_count,
      expected_detail_command_sha256: match.expected_detail_command_sha256,
      ...boundary,
      parse_error_count: match.parse_errors.length,
      match_status: match.match_status,
      match_count: match.match_count,
    };
  }

  const { event, line_number, entry_sha256 } = match.matched;
  return {
    file: match.file,
    start_line_count: match.start_line_count,
    end_line_count: match.end_line_count,
    expected_detail_command_sha256: match.expected_detail_command_sha256,
    ...boundary,
    parse_error_count: match.parse_errors.length,
    match_status: match.match_status,
    match_count: match.match_count,
    line_number,
    entry_sha256,
    id: event.id ?? null,
    ts: event.ts ?? null,
    session_id: event.session_id ?? null,
    domain: event.domain ?? null,
    action: event.action ?? null,
    outcome: event.outcome ?? null,
    rule: event.rule ?? null,
    authorizer: event.authorizer ?? null,
    detail_command_sha256: sha256Text(event?.detail?.command ?? ''),
    detail_hash: sha256Text(stableJson(event?.detail ?? {})),
    detail_cwd: event?.detail?.cwd ?? null,
    policy_version: event.policy_version ?? null,
    prev_hash: event.prev_hash ?? null,
  };
}

function effectiveCommandFromDecision(decision, originalCommand) {
  const updated = decision?.hookSpecificOutput?.updatedInput?.command;
  if (updated === undefined || updated === null) {
    return {
      command: originalCommand,
      updatedInputUsed: false,
      error: null,
    };
  }
  if (typeof updated !== 'string' || updated.trim() === '' || /[\r\n]/.test(updated)) {
    return {
      command: null,
      updatedInputUsed: true,
      error: 'invalid_updated_input_command',
    };
  }
  const secret = findSecretPattern(updated);
  if (secret) {
    return {
      command: null,
      updatedInputUsed: true,
      error: `unsafe_updated_input_command:${secret.label}`,
    };
  }
  return {
    command: updated,
    updatedInputUsed: true,
    error: null,
  };
}

function buildBaseEvidence({
  request,
  command,
  cwd,
  cwdCanonical,
  sessionId,
  projectDir,
  gatePath,
  auditFile,
  startedAt,
}) {
  const requestForHash = {
    command,
    cwd,
    cwd_canonical: cwdCanonical,
    reason: request.reason || '',
    session_id: sessionId,
  };
  return {
    runner_contract: ZLAR_OWNED_RUNNER_CONTRACT,
    generated_at: startedAt,
    project_dir: projectDir,
    gate_path: gatePath,
    receipt_claim: false,
    receipt_claim_scope: null,
    request: {
      sha256: sha256Text(stableJson(requestForHash)),
      session_id: sessionId,
      command: evidenceText(command),
      cwd,
      cwd_canonical: cwdCanonical,
      reason_sha256: sha256Text(request.reason || ''),
    },
    gate: null,
    gate_transformation: {
      updated_input_used: false,
      requested_command_sha256: sha256Text(command),
      effective_command_sha256: null,
      audit_binds: 'requested_command',
      effective_command_audit_match: false,
      note: 'A matching audit event binds the requested command. If updatedInput.command is used, the child command is a gate transformation and is recorded separately.',
    },
    audit: {
      file: auditFile,
      match_status: 'not_checked',
      freshness_scope: 'local_line_count_window',
      receipt_grade: false,
      receipt_boundary: 'Local audit freshness does not verify audit signature, issuer identity, or hash-chain continuity.',
    },
    receipt_binding: {
      enabled: false,
      receipt_grade: false,
      format: 'governed-action-receipt-v1',
      production_trust: false,
      issuer_recognition: false,
      verification: null,
      receipt: null,
      output: null,
      block_reason: null,
      boundary: 'A signed v1 receipt proves content integrity under the supplied public key. It does not prove production issuer recognition, custody, revocation status, downstream acceptance, or human intent.',
    },
    execution: {
      executed: false,
      block_reasons: [],
      effective_command_sha256: null,
      effective_cwd: cwdCanonical || cwd,
      updated_input_used: false,
      stdout_sha256: null,
      stderr_sha256: null,
      exit_code: null,
      signal: null,
    },
    non_claims: [
      'no raw Codex desktop developer-tool governance claim',
      'no all-surface governance claim',
      'no downstream recognition/refusal claim',
      'no production trust claim',
      'no live receipt emission claim',
      'no side-door closure claim',
    ],
  };
}

function buildReceiptBinding({
  auditMatch,
  receiptValidation,
  requestedCommand,
  effectiveCommand,
  updatedInputUsed,
}) {
  if (!receiptValidation.enabled) {
    return {
      ok: true,
      blockReason: null,
      evidence: {
        enabled: false,
        receipt_grade: false,
        format: 'governed-action-receipt-v1',
        production_trust: false,
        issuer_recognition: false,
        verification: null,
        receipt: null,
        output: null,
        block_reason: null,
        boundary: 'Receipt binding was not requested for this runner invocation.',
      },
    };
  }

  const baseEvidence = {
    enabled: true,
    receipt_grade: false,
    format: 'governed-action-receipt-v1',
    production_trust: false,
    issuer_recognition: false,
    verification: null,
    receipt: null,
    output: {
      path: receiptValidation.output.path,
      root: receiptValidation.output.root,
      sha256: null,
      create_new_only: true,
    },
    key: {
      public_key_path_sha256: receiptValidation.pubkey.path
        ? sha256Text(receiptValidation.pubkey.path)
        : null,
      private_key_path_sha256: receiptValidation.key.path
        ? sha256Text(receiptValidation.key.path)
        : null,
      raw_private_material_reported: false,
    },
    audit_binding: null,
    command_binding: {
      requested_command_sha256: sha256Text(requestedCommand),
      effective_command_sha256: effectiveCommand ? sha256Text(effectiveCommand) : null,
      updated_input_used: updatedInputUsed,
      receipt_detail_binds: 'matched_audit_event_detail',
      note: updatedInputUsed
        ? 'Receipt payload binds the matched audit event detail. The audit event names the requested command; the effective child command is separately hashed in runner evidence.'
        : 'Requested command and effective child command are identical; the receipt payload binds the matched audit event detail for that command.',
    },
    boundary: 'A signed v1 receipt proves content integrity under the supplied public key. It does not prove production issuer recognition, custody, revocation status, downstream acceptance, or human intent.',
    block_reason: null,
  };

  if (!receiptValidation.ok) {
    return {
      ok: false,
      blockReason: `receipt_${receiptValidation.error || 'configuration_invalid'}`,
      evidence: {
        ...baseEvidence,
        block_reason: `receipt_${receiptValidation.error || 'configuration_invalid'}`,
      },
    };
  }

  if (auditMatch.match_status !== 'matched' || !auditMatch.matched?.event) {
    return {
      ok: false,
      blockReason: `receipt_audit_${auditMatch.match_status}`,
      evidence: {
        ...baseEvidence,
        block_reason: `receipt_audit_${auditMatch.match_status}`,
      },
    };
  }

  const { event, line_number: lineNumber, entry_sha256: entrySha256 } = auditMatch.matched;
  try {
    const unsigned = createReceiptV1FromEvent(event);
    const signed = signReceiptV1FromFiles(
      unsigned,
      receiptValidation.key.path,
      receiptValidation.pubkey.path
    );
    const verified = verifyReceiptV1FromFile(signed, receiptValidation.pubkey.path);
    const payload = decodePayloadV1(signed);
    const expectedDetailHash = sha256Text(stableJson(event?.detail ?? {}));
    const bindingErrors = [];

    for (const [field, expected] of [
      ['audit_event_id', event.id],
      ['audit_prev_hash', event.prev_hash],
      ['outcome', event.outcome],
      ['rule', event.rule],
      ['authorizer', event.authorizer],
      ['policy_version', event.policy_version],
      ['detail_hash', expectedDetailHash],
    ]) {
      if (payload[field] !== expected) {
        bindingErrors.push(`payload_${field}_mismatch`);
      }
    }
    if (!verified.valid) {
      bindingErrors.push('receipt_verification_failed');
    }

    if (bindingErrors.length === 0) {
      const receiptText = `${JSON.stringify(signed, null, 2)}\n`;
      writeFileSync(receiptValidation.output.path, receiptText, { flag: 'wx', mode: 0o600 });
      return {
        ok: true,
        blockReason: null,
        evidence: {
          ...baseEvidence,
          receipt_grade: true,
          verification: {
            valid: true,
            reason: verified.reason,
          },
          receipt: {
            id: signed.id,
            kid: signed.kid,
            payload_sha256: signablePayloadV1(signed),
            detail_hash: payload.detail_hash,
            envelope_hash: receiptHashV1(signed),
            prev: signed.prev,
            iat: signed.iat,
          },
          output: {
            ...baseEvidence.output,
            sha256: sha256Text(receiptText),
          },
          audit_binding: {
            line_number: lineNumber,
            entry_sha256: entrySha256,
            audit_event_id: event.id,
            audit_prev_hash: event.prev_hash,
            outcome: event.outcome,
            rule: event.rule,
            authorizer: event.authorizer,
            policy_version: event.policy_version,
            detail_hash: expectedDetailHash,
          },
          decoded_payload: {
            audit_event_id: payload.audit_event_id,
            audit_prev_hash: payload.audit_prev_hash,
            outcome: payload.outcome,
            rule: payload.rule,
            authorizer: payload.authorizer,
            policy_version: payload.policy_version,
            detail_hash: payload.detail_hash,
          },
          block_reason: null,
        },
      };
    }

    return {
      ok: false,
      blockReason: bindingErrors[0],
      evidence: {
        ...baseEvidence,
        verification: {
          valid: Boolean(verified.valid),
          reason: verified.reason,
        },
        audit_binding: {
          line_number: lineNumber,
          entry_sha256: entrySha256,
          audit_event_id: event.id ?? null,
        },
        decoded_payload: {
          audit_event_id: payload.audit_event_id,
          audit_prev_hash: payload.audit_prev_hash,
          outcome: payload.outcome,
          rule: payload.rule,
          authorizer: payload.authorizer,
          policy_version: payload.policy_version,
          detail_hash: payload.detail_hash,
        },
        block_reason: bindingErrors[0],
      },
    };
  } catch (error) {
    return {
      ok: false,
      blockReason: 'receipt_binding_error',
      evidence: {
        ...baseEvidence,
        block_reason: 'receipt_binding_error',
        error: String(error.message || error),
      },
    };
  }
}

function writeEvidence(path, evidence) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' });
}

export function runZlarOwnedRunner(request, options = {}) {
  const projectDir = resolve(options.projectDir || defaultProjectDir());
  const gatePath = resolve(options.gatePath || defaultGatePath(projectDir));
  const auditFile = resolve(options.auditFile || defaultAuditFile(projectDir, options.env || process.env));
  const cwd = resolve(request.cwd || process.cwd());
  const cwdCanonical = realpathOrNull(cwd);
  const command = normalizeCommand(request.command);
  const sessionId = request.session_id || request.sessionId || makeSessionId();
  const startedAt = options.now ? options.now() : isoNow();
  const evidence = buildBaseEvidence({
    request,
    command,
    cwd,
    cwdCanonical,
    sessionId,
    projectDir,
    gatePath,
    auditFile,
    startedAt,
  });

  const receiptValidation = validateReceiptBindingRequest(request, {
    projectDir,
    env: options.env || process.env,
    evidenceRoot: options.evidenceRoot,
  });
  if (receiptValidation.enabled) {
    evidence.receipt_binding.enabled = true;
    evidence.receipt_binding.output = {
      path: receiptValidation.output.path || null,
      root: receiptValidation.output.root || null,
      sha256: null,
      create_new_only: true,
    };
  }
  if (receiptValidation.enabled && !receiptValidation.ok) {
    evidence.execution.block_reasons.push(`receipt_${receiptValidation.error || 'configuration_invalid'}`);
    evidence.receipt_binding.block_reason = `receipt_${receiptValidation.error || 'configuration_invalid'}`;
    return {
      exitCode: 2,
      evidence,
      stdout: Buffer.alloc(0),
      stderr: Buffer.from(`ZLAR runner blocked before gate: receipt_${receiptValidation.error || 'configuration_invalid'}\n`),
    };
  }

  const validationErrors = validateRequest(request, cwd);
  if (validationErrors.length > 0) {
    evidence.execution.block_reasons.push(...validationErrors);
    return {
      exitCode: 2,
      evidence,
      stdout: Buffer.alloc(0),
      stderr: Buffer.from(`ZLAR runner blocked before gate: ${validationErrors.join(', ')}\n`),
    };
  }

  if (!existsSync(gatePath)) {
    evidence.execution.block_reasons.push('gate_missing');
    return {
      exitCode: 2,
      evidence,
      stdout: Buffer.alloc(0),
      stderr: Buffer.from('ZLAR runner blocked: gate executable is missing\n'),
    };
  }

  const payload = buildPayload({
    command,
    cwd,
    reason: request.reason,
    sessionId,
  });
  evidence.gate_payload_sha256 = sha256Text(stableJson(payload));

  const startLineCount = readLineCount(auditFile);
  const gateRun = spawnSync(gatePath, [], {
    cwd: projectDir,
    input: `${JSON.stringify(payload)}\n`,
    env: {
      ...process.env,
      ...(options.env || {}),
      ZLAR_AUDIT_FILE: auditFile,
    },
    maxBuffer: options.maxBuffer || 10 * 1024 * 1024,
  });

  const gateStdout = gateRun.stdout || Buffer.alloc(0);
  const gateStderr = gateRun.stderr || Buffer.alloc(0);
  const decision = parseGateDecision(gateStdout);
  const hook = decision.hookSpecificOutput;
  const permissionDecision = hook?.permissionDecision ?? null;
  const permissionReason = hook?.permissionDecisionReason ?? '';

  evidence.gate = {
    stdout: stdoutEvidence(gateStdout),
    stderr: stdoutEvidence(gateStderr),
    exit_code: typeof gateRun.status === 'number' ? gateRun.status : null,
    signal: gateRun.signal || null,
    error: gateRun.error ? String(gateRun.error.message || gateRun.error) : null,
    stdout_json_valid: decision.stdout_json_valid,
    parse_error: decision.parse_error,
    hook_event_name: hook?.hookEventName ?? null,
    permission_decision: permissionDecision,
    permission_decision_reason_present: permissionReason.length > 0,
    permission_decision_reason: permissionReason ? evidenceText(permissionReason) : null,
    updated_input_present: typeof hook?.updatedInput?.command === 'string',
    updated_input_command_sha256: typeof hook?.updatedInput?.command === 'string'
      ? sha256Text(hook.updatedInput.command)
      : null,
  };

  const auditMatch = findMatchingAudit({
    auditFile,
    startLineCount,
    sessionId,
    command,
    cwd,
  });
  evidence.audit = summarizeAuditMatch(auditMatch);

  const blockReasons = evidence.execution.block_reasons;
  if (gateRun.error) {
    blockReasons.push('gate_spawn_error');
  }
  if (gateRun.status !== 0) {
    blockReasons.push('gate_nonzero_exit');
  }
  if (!decision.stdout_json_valid) {
    blockReasons.push(`gate_stdout_${decision.parse_error}`);
  }
  if (hook?.hookEventName !== 'PreToolUse') {
    blockReasons.push('gate_hook_event_not_pretooluse');
  }
  if (permissionDecision !== 'allow') {
    blockReasons.push(`gate_decision_${permissionDecision || 'missing'}`);
  }
  if (auditMatch.match_status !== 'matched') {
    blockReasons.push(`audit_${auditMatch.match_status}`);
  }

  const matchedOutcome = auditMatch.matched?.event?.outcome ?? null;
  if (auditMatch.match_status === 'matched' && !ALLOW_OUTCOMES.has(matchedOutcome)) {
    blockReasons.push(`audit_outcome_${matchedOutcome || 'missing'}`);
  }

  const effective = effectiveCommandFromDecision(decision, command);
  evidence.execution.updated_input_used = effective.updatedInputUsed;
  evidence.gate_transformation.updated_input_used = effective.updatedInputUsed;
  evidence.gate_transformation.effective_command_sha256 = effective.command
    ? sha256Text(effective.command)
    : null;
  evidence.gate_transformation.effective_command_audit_match = (
    auditMatch.match_status === 'matched' &&
    !effective.updatedInputUsed &&
    effective.command === command
  );
  if (effective.error) {
    blockReasons.push(effective.error);
  }

  const receiptBinding = buildReceiptBinding({
    auditMatch,
    receiptValidation,
    requestedCommand: command,
    effectiveCommand: effective.command,
    updatedInputUsed: effective.updatedInputUsed,
  });
  evidence.receipt_binding = receiptBinding.evidence;
  if (receiptBinding.evidence.receipt_grade === true) {
    evidence.receipt_claim = true;
    evidence.receipt_claim_scope = 'proof-key v1 receipt binding for this zlar-run invocation only';
  }
  if (!receiptBinding.ok) {
    blockReasons.push(receiptBinding.blockReason);
  }

  if (blockReasons.length > 0) {
    return {
      exitCode: 2,
      evidence,
      stdout: Buffer.alloc(0),
      stderr: Buffer.from(`ZLAR runner blocked: ${blockReasons.join(', ')}\n`),
    };
  }

  const effectiveCommand = effective.command;
  evidence.execution.effective_command_sha256 = sha256Text(effectiveCommand);

  const child = spawnSync('/bin/bash', ['-lc', effectiveCommand], {
    cwd: cwdCanonical || cwd,
    maxBuffer: options.maxBuffer || 10 * 1024 * 1024,
    env: {
      ...process.env,
      ...(options.childEnv || {}),
    },
  });

  evidence.execution.executed = true;
  evidence.execution.stdout = stdoutEvidence(child.stdout || Buffer.alloc(0));
  evidence.execution.stderr = stdoutEvidence(child.stderr || Buffer.alloc(0));
  evidence.execution.exit_code = typeof child.status === 'number' ? child.status : 1;
  evidence.execution.signal = child.signal || null;
  if (child.error) {
    evidence.execution.error = String(child.error.message || child.error);
  }

  return {
    exitCode: evidence.execution.exit_code,
    evidence,
    stdout: child.stdout || Buffer.alloc(0),
    stderr: child.stderr || Buffer.alloc(0),
  };
}

export function usageText() {
  return [
    'Usage:',
    "  zlar run --cmd '<bash command>' [--cwd <dir>] [--reason <text>] [--evidence-out <file>]",
    '  zlar run --json <request.json> [--evidence-out <file>]',
    '  zlar run ... --receipt-out <file> --receipt-key <private.pem> --receipt-pubkey <public.pem>',
    '',
    'Runs one intentionally supplied Bash command through the ZLAR-owned runner surface.',
    'The command executes only after bin/zlar-gate returns allow and a matching audit event exists.',
    'Evidence output is create-new-only and constrained to the runner evidence root.',
    'Receipt output is opt-in, create-new-only, and constrained to the same evidence root as proof-owned key material.',
    'This command does not prove raw Codex desktop governance, all-surface governance, production trust, issuer recognition, or side-door closure.',
  ].join('\n');
}

export function parseRunnerArgs(args, io = {}) {
  const request = {};
  let evidenceOut = '';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      return { help: true, request, evidenceOut };
    }
    if (arg === '--cmd') {
      request.command = args[++i] || '';
    } else if (arg === '--cwd') {
      request.cwd = args[++i] || '';
    } else if (arg === '--reason') {
      request.reason = args[++i] || '';
    } else if (arg === '--session-id') {
      request.session_id = args[++i] || '';
    } else if (arg === '--evidence-out') {
      evidenceOut = args[++i] || '';
    } else if (arg === '--receipt-out') {
      request.receipt_out = args[++i] || '';
    } else if (arg === '--receipt-key') {
      request.receipt_key = args[++i] || '';
    } else if (arg === '--receipt-pubkey') {
      request.receipt_pubkey = args[++i] || '';
    } else if (arg === '--json') {
      const inputPath = args[++i] || '';
      if (!inputPath) {
        throw new Error('missing value for --json');
      }
      const raw = inputPath === '-'
        ? readFileSync(io.stdinFd ?? 0, 'utf8')
        : readFileSync(inputPath, 'utf8');
      Object.assign(request, JSON.parse(raw));
    } else {
      throw new Error(`unsupported option: ${arg}`);
    }
  }

  return { help: false, request, evidenceOut };
}

export function runCli(argv = process.argv.slice(2), options = {}) {
  let parsed;
  try {
    parsed = parseRunnerArgs(argv);
  } catch (error) {
    const message = `ERROR: ${error.message}\n\n${usageText()}\n`;
    (options.stderr || process.stderr).write(message);
    return 2;
  }

  if (parsed.help) {
    (options.stdout || process.stdout).write(`${usageText()}\n`);
    return 0;
  }

  let evidencePath = '';
  if (parsed.evidenceOut) {
    const runnerOptions = options.runnerOptions || {};
    const evidenceValidation = validateEvidenceOutPath(parsed.evidenceOut, {
      projectDir: runnerOptions.projectDir || defaultProjectDir(),
      evidenceRoot: runnerOptions.evidenceRoot,
      env: runnerOptions.env || process.env,
    });
    if (!evidenceValidation.ok) {
      (options.stderr || process.stderr).write(`ERROR: unsafe evidence output: ${evidenceValidation.error}\n`);
      return 2;
    }
    evidencePath = evidenceValidation.path;
  }

  const result = runZlarOwnedRunner(parsed.request, options.runnerOptions || {});
  if (evidencePath) {
    writeEvidence(evidencePath, result.evidence);
  }

  if (result.stdout.length > 0) {
    (options.stdout || process.stdout).write(result.stdout);
  }
  if (result.stderr.length > 0) {
    (options.stderr || process.stderr).write(result.stderr);
  }

  return result.exitCode;
}

export function writeRunnerEvidence(path, evidence, options = {}) {
  const validation = validateEvidenceOutPath(path, options);
  if (!validation.ok) {
    throw new Error(validation.error);
  }
  writeEvidence(validation.path, evidence);
}
