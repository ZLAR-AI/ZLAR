import { spawnSync, execFileSync } from 'node:child_process';
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE,
  assertProtectedRecordsLocalBoardingProof,
  runProtectedRecordsLocalBoardingProof,
} from './protected-records-local-boarding-proof.mjs';

export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE =
  'zlar-claude-code-hook-contract-replay-proof-v1';
export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_COMMAND =
  'zlar claude-code-hook-contract-replay-proof';
export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL =
  'local-fixture-hook-contract-replay';
export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_EVIDENCE_MODEL =
  'installed-local-fixture-hook-contract-replay';
export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_ADAPTER_RELATIVE_PATH =
  'adapters/claude-code/hook.sh';
export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY =
  'standalone hook replay source_state must match current HEAD plus a git status fingerprint during validation; local proof-pack artifacts bind hook replay identity by contract and adapter hashes, not full source freshness';
export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_SOURCE_STATE_BOUNDARY =
  'installed hook replay binds installed adapter file identity and fixture case evidence only; source_state is unavailable and no source freshness, remote-green, release, install authority, live Claude passage, current-machine governance, or production downstream recognition claim is made';
export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_PACK_SOURCE_STATE_BOUNDARY =
  'source_state is not carried in the local proof-pack artifact; hook replay identity and case evidence are bound by hook_replay_contract_sha256, adapter_sha256, and case_evidence_sha256';

export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING =
  'ZLAR can locally replay Claude-shaped PreToolUse hook payloads through a selected Claude Code adapter copy in a proof-owned fixture root, observe valid allow and deny Claude hook JSON, prove the local replay harness did not execute the denied effect, and rerun local protected-records boarding proof.';

export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS = Object.freeze([
  'This proof is local hook-contract replay evidence, not live Claude Code application passage.',
  'This proof does not invoke the claude CLI, run a live prompt, contact Claude or Anthropic, run login, or repair Claude authentication.',
  'This proof does not read or write ~/.claude, ~/.zlar, ~/.claude.json, installed/live Claude or ZLAR hooks, profiles, services, user config, or machine config; it reads the repo adapter and writes only disposable fixture files.',
  'This proof does not install, activate, repair, upgrade, reinstall, uninstall, tag, release, publish website changes, change GitHub settings, use Telegram, or contact external verifiers.',
  'This proof does not emit a live receipt.',
  'This proof does not prove current-machine governance.',
  'This proof does not prove app-originated hook crossing.',
  'This proof does not prove production downstream recognition.',
  'This proof does not prove all-surface governance, enterprise readiness, external attestation, sovereign recognition, or side-door closure.',
]);

export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_NON_CLAIMS = Object.freeze([
  'This proof is installed-local hook-contract replay evidence, not live Claude Code application passage.',
  'This proof does not invoke the claude CLI, run a live prompt, contact Claude or Anthropic, run login, or repair Claude authentication.',
  'This proof does not write ~/.claude, ~/.zlar, ~/.claude.json, live Claude or ZLAR hooks, profiles, services, user config, or machine config; it reads only the selected installed adapter/program files needed for local hook-contract replay and writes only disposable fixture files.',
  'This proof does not install, activate, repair, upgrade, reinstall, uninstall, tag, release, publish website changes, change GitHub settings, use Telegram, or contact external verifiers.',
  'This proof does not emit a live receipt.',
  'This proof does not prove current-machine governance.',
  'This proof does not prove app-originated hook crossing.',
  'This proof does not prove production downstream recognition.',
  'This proof does not prove source freshness, remote-green state, release identity, all-surface governance, enterprise readiness, external attestation, sovereign recognition, or side-door closure.',
]);

export const REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES = Object.freeze([
  Object.freeze({
    case_id: 'allow_pwd_hook_json',
    expected_case_result: 'passed',
    expected_permission_decision: 'allow',
    expected_adapter_exit: 0,
  }),
  Object.freeze({
    case_id: 'deny_destructive_sentinel_hook_json',
    expected_case_result: 'passed',
    expected_permission_decision: 'deny',
    expected_adapter_exit: 0,
  }),
  Object.freeze({
    case_id: 'adapter_does_not_execute_tool_input',
    expected_case_result: 'passed',
    expected_permission_decision: 'allow',
    expected_adapter_exit: 0,
  }),
  Object.freeze({
    case_id: 'missing_gate_fails_closed',
    expected_case_result: 'passed',
    expected_permission_decision: 'deny',
    expected_adapter_exit: 0,
  }),
  Object.freeze({
    case_id: 'blank_gate_response_fails_closed',
    expected_case_result: 'passed',
    expected_permission_decision: 'deny',
    expected_adapter_exit: 0,
  }),
  Object.freeze({
    case_id: 'malformed_output_refused',
    expected_case_result: 'refused',
    expected_permission_decision: null,
    expected_adapter_exit: 0,
  }),
  Object.freeze({
    case_id: 'non_pretooluse_payload_denied_by_fixture_gate',
    expected_case_result: 'refused',
    expected_permission_decision: 'deny',
    expected_adapter_exit: 0,
  }),
]);

export const REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS = Object.freeze([
  'live Claude Code app-originated hook passage',
  'Claude service/auth/runtime boundary',
  'direct shell/filesystem outside Claude Code',
  'Browser/computer-use tools',
  'Cursor, Windsurf, Codex, and other AI client surfaces',
  'direct MCP registrations bypassing the Claude Code hook',
  'network/external tools',
  'manual Claude or ZLAR config edits',
  'legacy Claude gate script file on disk',
  'Claude Stop hook and non-PreToolUse surfaces',
  'host/debugger/operator bypass',
  'sub-runtimes launched outside the routed adapter',
  'unrouted records paths and production downstream systems',
]);

const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_KEYS = Object.freeze([
  'adapter_exit_code',
  'case_id',
  'case_result',
  'denied_effect_executed',
  'gate_mode',
  'hook_event_name',
  'input_contract_sha256',
  'input_sha256',
  'permission_decision',
  'permission_decision_reason_present',
  'proof_refusal_reason',
  'refused_before_effect',
  'sentinel_unchanged',
  'stderr_empty',
  'stderr_sha256',
  'stdout_json_valid',
  'stdout_sha256',
  'valid_claude_hook_json',
]);

export const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INPUT_CONTRACTS = Object.freeze({
  allow_pwd_hook_json: Object.freeze({
    command_contract: 'pwd # zlar-hook-replay-allow',
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    session_id: 'zlar-hook-replay-allow',
  }),
  deny_destructive_sentinel_hook_json: Object.freeze({
    command_contract: 'rm -rf <proof-owned-sentinel-dir> # zlar-hook-replay-deny',
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    session_id: 'zlar-hook-replay-deny',
  }),
  adapter_does_not_execute_tool_input: Object.freeze({
    command_contract: 'touch <proof-owned-marker-path> # zlar-hook-replay-no-exec',
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    session_id: 'zlar-hook-replay-no-exec',
  }),
  missing_gate_fails_closed: Object.freeze({
    command_contract: 'pwd # zlar-hook-replay-allow',
    gate_mode: 'missing-fixture-gate',
    hook_event_name: 'PreToolUse',
    session_id: 'zlar-hook-replay-missing-gate',
  }),
  blank_gate_response_fails_closed: Object.freeze({
    command_contract: 'pwd # zlar-hook-replay-blank',
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    session_id: 'zlar-hook-replay-blank',
  }),
  malformed_output_refused: Object.freeze({
    command_contract: 'pwd # zlar-hook-replay-malformed',
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    session_id: 'zlar-hook-replay-malformed',
  }),
  non_pretooluse_payload_denied_by_fixture_gate: Object.freeze({
    command_contract: 'pwd # zlar-hook-replay-non-pretooluse',
    gate_mode: 'fixture-gate',
    hook_event_name: 'Stop',
    session_id: 'zlar-hook-replay-non-pretooluse',
  }),
});

const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_SEMANTICS = Object.freeze({
  allow_pwd_hook_json: Object.freeze({
    denied_effect_executed: null,
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    permission_decision_reason_present: false,
    proof_refusal_reason: null,
    refused_before_effect: false,
    sentinel_unchanged: null,
    stderr_empty: true,
    stdout_json_valid: true,
    valid_claude_hook_json: true,
  }),
  deny_destructive_sentinel_hook_json: Object.freeze({
    denied_effect_executed: false,
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    permission_decision_reason_present: true,
    proof_refusal_reason: null,
    refused_before_effect: true,
    sentinel_unchanged: true,
    stderr_empty: true,
    stdout_json_valid: true,
    valid_claude_hook_json: true,
  }),
  adapter_does_not_execute_tool_input: Object.freeze({
    denied_effect_executed: false,
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    permission_decision_reason_present: false,
    proof_refusal_reason: null,
    refused_before_effect: false,
    sentinel_unchanged: true,
    stderr_empty: true,
    stdout_json_valid: true,
    valid_claude_hook_json: true,
  }),
  missing_gate_fails_closed: Object.freeze({
    denied_effect_executed: null,
    gate_mode: 'missing-fixture-gate',
    hook_event_name: 'PreToolUse',
    permission_decision_reason_present: true,
    proof_refusal_reason: null,
    refused_before_effect: true,
    sentinel_unchanged: null,
    stderr_empty: true,
    stdout_json_valid: true,
    valid_claude_hook_json: true,
  }),
  blank_gate_response_fails_closed: Object.freeze({
    denied_effect_executed: null,
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    permission_decision_reason_present: true,
    proof_refusal_reason: null,
    refused_before_effect: true,
    sentinel_unchanged: null,
    stderr_empty: true,
    stdout_json_valid: true,
    valid_claude_hook_json: true,
  }),
  malformed_output_refused: Object.freeze({
    denied_effect_executed: null,
    gate_mode: 'fixture-gate',
    hook_event_name: null,
    permission_decision_reason_present: false,
    proof_refusal_reason: 'adapter_stdout_not_valid_claude_hook_json',
    refused_before_effect: true,
    sentinel_unchanged: null,
    stderr_empty: true,
    stdout_json_valid: false,
    valid_claude_hook_json: false,
  }),
  non_pretooluse_payload_denied_by_fixture_gate: Object.freeze({
    denied_effect_executed: null,
    gate_mode: 'fixture-gate',
    hook_event_name: 'PreToolUse',
    permission_decision_reason_present: true,
    proof_refusal_reason: 'fixture_gate_denied_non_pretooluse_payload',
    refused_before_effect: true,
    sentinel_unchanged: null,
    stderr_empty: true,
    stdout_json_valid: true,
    valid_claude_hook_json: true,
  }),
});

export function claudeCodeHookContractReplayExpectedCaseSemantics(caseId) {
  const semantics = CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_SEMANTICS[caseId];
  if (!semantics) {
    throw new Error(`Unknown Claude Code hook-contract replay case semantics: ${caseId}`);
  }
  return { ...semantics };
}

export function claudeCodeHookContractReplayInputContract(caseId) {
  const contract = CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INPUT_CONTRACTS[caseId];
  if (!contract) {
    throw new Error(`Unknown Claude Code hook-contract replay input contract: ${caseId}`);
  }
  return {
    contract_type: 'zlar-local-proof-pack-claude-hook-contract-replay-input-contract-v1',
    case_id: caseId,
    command_contract: contract.command_contract,
    gate_mode: contract.gate_mode,
    hook_event_name: contract.hook_event_name,
    session_id: contract.session_id,
    tool_name: 'Bash',
    path_policy: 'proof-owned temporary filesystem paths normalized before proof-pack hashing',
  };
}

export function claudeCodeHookContractReplayInputContractSha256(caseId) {
  return sha256(canonicalize(claudeCodeHookContractReplayInputContract(caseId)));
}

function normalizePayloadCommandContract(caseId, command) {
  if (caseId === 'deny_destructive_sentinel_hook_json') {
    return String(command || '').replace(
      /^rm -rf .+ # zlar-hook-replay-deny$/,
      'rm -rf <proof-owned-sentinel-dir> # zlar-hook-replay-deny'
    );
  }
  if (caseId === 'adapter_does_not_execute_tool_input') {
    return String(command || '').replace(
      /^touch .+ # zlar-hook-replay-no-exec$/,
      'touch <proof-owned-marker-path> # zlar-hook-replay-no-exec'
    );
  }
  return String(command || '');
}

function claudeCodeHookContractReplayInputContractFromPayload(caseId, payload, gateMode) {
  return {
    contract_type: 'zlar-local-proof-pack-claude-hook-contract-replay-input-contract-v1',
    case_id: caseId,
    command_contract: normalizePayloadCommandContract(
      caseId,
      payload?.tool_input?.command
    ),
    gate_mode: gateMode,
    hook_event_name: payload?.hook_event_name ?? null,
    session_id: payload?.session_id ?? null,
    tool_name: payload?.tool_name ?? null,
    path_policy: 'proof-owned temporary filesystem paths normalized before proof-pack hashing',
  };
}

function claudeCodeHookContractReplayInputContractSha256FromPayload(caseId, payload, gateMode) {
  return sha256(
    canonicalize(
      claudeCodeHookContractReplayInputContractFromPayload(caseId, payload, gateMode)
    )
  );
}

const CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SUMMARY_KEYS = Object.freeze([
  'adapter_did_not_execute_tool_input',
  'all_adapter_exits_zero',
  'all_required_cases_present',
  'allow_json_observed',
  'app_originated_hook_crossing_proven',
  'blank_gate_response_failed_closed',
  'current_machine_governance_proven',
  'denied_effect_not_executed',
  'deny_json_observed',
  'live_claude_app_passage_proven',
  'live_receipt_emission_proven',
  'malformed_output_refused',
  'missing_gate_failed_closed',
  'non_pretooluse_payload_denied_by_fixture_gate',
  'production_downstream_recognition_proven',
  'side_door_closure_proven',
]);

const UNSAFE_OUTPUT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'chat id field', pattern: /\bchat_id\b/i },
  { label: 'numeric human identifier', pattern: /\bhuman:[0-9]/ },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'public key material', pattern: /BEGIN PUBLIC KEY/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key|hmac)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/i,
  },
  { label: 'GitHub token', pattern: /\bghp_[A-Za-z0-9_]{10,}\b/ },
  { label: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/ },
  { label: 'Slack token', pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{12,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function projectDir() {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..');
}

function sourceState() {
  const dir = projectDir();
  let commit = null;
  let status = null;
  try {
    const value = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    commit = /^[a-f0-9]{40}$/.test(value) ? value : null;
  } catch {
    commit = null;
  }
  try {
    status = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal'], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    status = null;
  }
  const statusKnown = typeof status === 'string';
  const worktreeClean = statusKnown ? status.trim().length === 0 : false;
  return {
    commit,
    provenance: worktreeClean ? 'clean-commit' : 'commit-plus-uncommitted-worktree',
    status_sha256: statusKnown ? sha256(status) : null,
    status_known: statusKnown,
    uncommitted_changes: !worktreeClean,
    worktree_clean: worktreeClean,
  };
}

export function claudeCodeHookContractReplayRepoAdapterPath() {
  return resolve(projectDir(), CLAUDE_CODE_HOOK_CONTRACT_REPLAY_ADAPTER_RELATIVE_PATH);
}

export function claudeCodeHookContractReplayRepoAdapterSha256() {
  return sha256File(claudeCodeHookContractReplayRepoAdapterPath());
}

export function claudeCodeHookContractReplayContractSha256(options = {}) {
  const adapterSource = options.adapterSource || 'repo';
  const adapterSha256 = options.adapterSha256 || (
    adapterSource === 'repo' ? claudeCodeHookContractReplayRepoAdapterSha256() : ''
  );
  if (!['repo', 'installed'].includes(adapterSource)) {
    throw new Error('Claude Code hook-contract replay adapter source is unsupported');
  }
  if (!/^[a-f0-9]{64}$/.test(adapterSha256)) {
    throw new Error('Claude Code hook-contract replay adapter SHA-256 is malformed');
  }
  const contract = {
    contract_type: 'zlar-claude-code-hook-contract-replay-contract-v1',
    proof_module_sha256: sha256File(fileURLToPath(import.meta.url)),
    adapter_relative_path: CLAUDE_CODE_HOOK_CONTRACT_REPLAY_ADAPTER_RELATIVE_PATH,
    adapter_source: adapterSource,
    adapter_sha256: adapterSha256,
    required_cases: REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES,
    required_side_doors: REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS,
    non_claims: adapterSource === 'installed'
      ? CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_NON_CLAIMS
      : CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS,
  };
  return sha256(JSON.stringify(contract));
}

function installedSourceState() {
  return {
    commit: null,
    provenance: 'installed-file-identity-no-source-state',
    status_sha256: null,
    status_known: false,
    uncommitted_changes: false,
    worktree_clean: false,
  };
}

function fixtureGateScript() {
  return `#!/bin/bash
set -u
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INPUT="$(cat)"
mkdir -p "$PROJECT_DIR/var/log" 2>/dev/null || true
printf '%s' "$INPUT" > "$PROJECT_DIR/var/log/fixture-gate-stdin.json"
case "$INPUT" in
  *zlar-hook-replay-allow*)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}\\n'
    exit 0
    ;;
  *zlar-hook-replay-deny*)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[policy] local hook-contract replay deny fixture"}}\\n'
    exit 2
    ;;
  *zlar-hook-replay-no-exec*)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}\\n'
    exit 0
    ;;
  *zlar-hook-replay-blank*)
    exit 99
    ;;
  *zlar-hook-replay-malformed*)
    printf 'not-json\\n'
    exit 0
    ;;
  *'"hook_event_name":"Stop"'*zlar-hook-replay-non-pretooluse*)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[policy] local hook-contract replay non-PreToolUse payload fixture"}}\\n'
    exit 2
    ;;
  *)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[policy] unrecognized local replay fixture"}}\\n'
    exit 2
    ;;
esac
`;
}

function setupFixture(adapterPath) {
  const root = mkdtempSync(join(tmpdir(), 'zlar-claude-hook-replay-'));
  const fixtureRoot = join(root, 'fixture-root');
  const adapterDir = join(fixtureRoot, 'adapters', 'claude-code');
  const binDir = join(fixtureRoot, 'bin');
  const logDir = join(fixtureRoot, 'var', 'log');
  mkdirSync(adapterDir, { recursive: true, mode: 0o700 });
  mkdirSync(binDir, { recursive: true, mode: 0o700 });
  mkdirSync(logDir, { recursive: true, mode: 0o700 });
  const fixtureAdapter = join(adapterDir, 'hook.sh');
  cpSync(adapterPath, fixtureAdapter);
  chmodSync(fixtureAdapter, 0o700);
  const fixtureGate = join(binDir, 'zlar-gate');
  writeFileSync(fixtureGate, fixtureGateScript(), { mode: 0o700 });
  return { root, fixtureRoot, fixtureAdapter, fixtureGate };
}

function parseHookJson(value) {
  try {
    const parsed = JSON.parse(value);
    return { parsed, parse_error: null };
  } catch (err) {
    return { parsed: null, parse_error: err.message };
  }
}

function payloadFor(caseId, command, hookEventName = 'PreToolUse') {
  return {
    hook_event_name: hookEventName,
    tool_name: 'Bash',
    tool_input: { command },
    session_id: `zlar-hook-replay-${caseId}`,
  };
}

function runAdapterCase({ fixtureAdapter, payload, expectedHookEvent = 'PreToolUse' }) {
  const input = `${JSON.stringify(payload)}\n`;
  const run = spawnSync(fixtureAdapter, {
    input,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
  const stdout = run.stdout || '';
  const stderr = run.stderr || '';
  const parsed = parseHookJson(stdout);
  const hookSpecificOutput = parsed.parsed?.hookSpecificOutput || null;
  const hookEventName = hookSpecificOutput?.hookEventName ?? null;
  const permissionDecision = hookSpecificOutput?.permissionDecision ?? null;
  const permissionDecisionReason = hookSpecificOutput?.permissionDecisionReason ?? null;
  const validHookJson = Boolean(parsed.parsed) &&
    hookEventName === expectedHookEvent &&
    (permissionDecision === 'allow' || permissionDecision === 'deny');
  return {
    adapter_exit_code: run.status,
    adapter_signal: run.signal ?? null,
    stdout_sha256: sha256(stdout),
    stderr_sha256: sha256(stderr),
    stderr_empty: stderr.length === 0,
    stdout_json_valid: Boolean(parsed.parsed),
    stdout_parse_error_hash: parsed.parse_error ? sha256(parsed.parse_error) : null,
    hook_event_name: hookEventName,
    permission_decision: permissionDecision,
    permission_decision_reason_hash: permissionDecisionReason ? sha256(permissionDecisionReason) : null,
    permission_decision_reason_present: typeof permissionDecisionReason === 'string' && permissionDecisionReason.length > 0,
    valid_claude_hook_json: validHookJson,
  };
}

function sentinelState(path) {
  if (!existsSync(path)) {
    return {
      exists: false,
      sha256: null,
      size: null,
      mode: null,
    };
  }
  const stat = statSync(path);
  return {
    exists: true,
    sha256: sha256File(path),
    size: stat.size,
    mode: (stat.mode & 0o777).toString(8),
  };
}

function buildCase(caseId, result, extra = {}) {
  if (!extra.payload) {
    throw new Error(`case ${caseId} missing input payload binding`);
  }
  const gateMode = extra.gate_mode || 'fixture-gate';
  return {
    case_id: caseId,
    case_result: extra.case_result || 'passed',
    adapter_exit_code: result.adapter_exit_code,
    stdout_json_valid: result.stdout_json_valid,
    valid_claude_hook_json: result.valid_claude_hook_json,
    hook_event_name: result.hook_event_name,
    permission_decision: result.permission_decision,
    permission_decision_reason_present: result.permission_decision_reason_present,
    stdout_sha256: result.stdout_sha256,
    stderr_sha256: result.stderr_sha256,
    stderr_empty: result.stderr_empty,
    input_sha256: sha256(JSON.stringify(extra.payload)),
    input_contract_sha256: claudeCodeHookContractReplayInputContractSha256FromPayload(
      caseId,
      extra.payload,
      gateMode
    ),
    gate_mode: gateMode,
    refused_before_effect: extra.refused_before_effect ?? null,
    denied_effect_executed: extra.denied_effect_executed ?? null,
    sentinel_unchanged: extra.sentinel_unchanged ?? null,
    proof_refusal_reason: extra.proof_refusal_reason || null,
  };
}

export function runClaudeCodeHookContractReplayProof(options = {}) {
  const requestedAdapterSource = options.adapterSource || 'auto';
  if (!['auto', 'repo', 'installed'].includes(requestedAdapterSource)) {
    throw new Error('Unsupported adapter source for v1: use repo or installed.');
  }

  const dir = projectDir();
  const currentSourceState = sourceState();
  const adapterSource = requestedAdapterSource === 'auto'
    ? (currentSourceState.status_known ? 'repo' : 'installed')
    : requestedAdapterSource;
  if (adapterSource === 'repo' && currentSourceState.status_known !== true) {
    throw new Error('source status must be known');
  }
  if (adapterSource === 'installed' && currentSourceState.status_known === true) {
    throw new Error('installed adapter source must not be selected from a repo source checkout');
  }
  const adapterPath = join(dir, CLAUDE_CODE_HOOK_CONTRACT_REPLAY_ADAPTER_RELATIVE_PATH);
  if (!existsSync(adapterPath)) {
    throw new Error('Claude Code adapter source is missing.');
  }
  if (!(statSync(adapterPath).mode & 0o111)) {
    throw new Error('Claude Code adapter source is not executable.');
  }

  const source_state = adapterSource === 'installed'
    ? installedSourceState()
    : currentSourceState;
  const adapterSha256 = sha256File(adapterPath);
  const evidenceModel = adapterSource === 'installed'
    ? CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_EVIDENCE_MODEL
    : CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL;
  const sourceStateBoundary = adapterSource === 'installed'
    ? CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_SOURCE_STATE_BOUNDARY
    : CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY;
  const nonClaims = adapterSource === 'installed'
    ? CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_NON_CLAIMS
    : CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS;
  const fixture = setupFixture(adapterPath);
  const caseSummaries = [];
  let sentinel = null;
  let marker = null;
  let localBoardingProof = null;

  try {
    const allowPayload = payloadFor('allow', 'pwd # zlar-hook-replay-allow');
    const allowRun = runAdapterCase({ fixtureAdapter: fixture.fixtureAdapter, payload: allowPayload });
    caseSummaries.push(buildCase('allow_pwd_hook_json', allowRun, {
      payload: allowPayload,
      refused_before_effect: false,
    }));

    const sentinelDir = join(fixture.root, 'sentinel-target');
    mkdirSync(sentinelDir, { recursive: true, mode: 0o700 });
    const sentinelPath = join(sentinelDir, 'sentinel.txt');
    writeFileSync(sentinelPath, 'zlar local hook replay sentinel\n', { mode: 0o600 });
    const sentinelBefore = sentinelState(sentinelPath);
    const denyPayload = payloadFor('deny', `rm -rf ${sentinelDir} # zlar-hook-replay-deny`);
    const denyRun = runAdapterCase({ fixtureAdapter: fixture.fixtureAdapter, payload: denyPayload });
    const sentinelAfter = sentinelState(sentinelPath);
    const sentinelUnchanged = sentinelBefore.exists &&
      sentinelAfter.exists &&
      sentinelBefore.sha256 === sentinelAfter.sha256 &&
      sentinelBefore.size === sentinelAfter.size;
    sentinel = {
      before_sha256: sentinelBefore.sha256,
      after_sha256: sentinelAfter.sha256,
      before_exists: sentinelBefore.exists,
      after_exists: sentinelAfter.exists,
      unchanged: sentinelUnchanged,
      denied_effect_executed: !sentinelUnchanged,
    };
    caseSummaries.push(buildCase('deny_destructive_sentinel_hook_json', denyRun, {
      payload: denyPayload,
      refused_before_effect: true,
      denied_effect_executed: !sentinelUnchanged,
      sentinel_unchanged: sentinelUnchanged,
    }));

    const markerPath = join(fixture.root, 'marker-created-by-tool-input');
    const noExecPayload = payloadFor('no-exec', `touch ${markerPath} # zlar-hook-replay-no-exec`);
    const noExecRun = runAdapterCase({ fixtureAdapter: fixture.fixtureAdapter, payload: noExecPayload });
    marker = {
      before_exists: false,
      after_exists: existsSync(markerPath),
      tool_input_command_executed: existsSync(markerPath),
    };
    caseSummaries.push(buildCase('adapter_does_not_execute_tool_input', noExecRun, {
      payload: noExecPayload,
      refused_before_effect: false,
      denied_effect_executed: false,
      sentinel_unchanged: !marker.after_exists,
    }));

    const movedGate = `${fixture.fixtureGate}.moved`;
    cpSync(fixture.fixtureGate, movedGate);
    unlinkSync(fixture.fixtureGate);
    const missingPayload = payloadFor('missing-gate', 'pwd # zlar-hook-replay-allow');
    const missingRun = runAdapterCase({ fixtureAdapter: fixture.fixtureAdapter, payload: missingPayload });
    cpSync(movedGate, fixture.fixtureGate);
    chmodSync(fixture.fixtureGate, 0o700);
    unlinkSync(movedGate);
    caseSummaries.push(buildCase('missing_gate_fails_closed', missingRun, {
      payload: missingPayload,
      gate_mode: 'missing-fixture-gate',
      refused_before_effect: true,
    }));

    const blankPayload = payloadFor('blank', 'pwd # zlar-hook-replay-blank');
    const blankRun = runAdapterCase({ fixtureAdapter: fixture.fixtureAdapter, payload: blankPayload });
    caseSummaries.push(buildCase('blank_gate_response_fails_closed', blankRun, {
      payload: blankPayload,
      refused_before_effect: true,
    }));

    const malformedPayload = payloadFor('malformed', 'pwd # zlar-hook-replay-malformed');
    const malformedRun = runAdapterCase({ fixtureAdapter: fixture.fixtureAdapter, payload: malformedPayload });
    caseSummaries.push(buildCase('malformed_output_refused', malformedRun, {
      payload: malformedPayload,
      case_result: 'refused',
      refused_before_effect: true,
      proof_refusal_reason: 'adapter_stdout_not_valid_claude_hook_json',
    }));

    const nonPreToolUsePayload = payloadFor('non-pretooluse', 'pwd # zlar-hook-replay-non-pretooluse', 'Stop');
    const nonPreToolUseRun = runAdapterCase({ fixtureAdapter: fixture.fixtureAdapter, payload: nonPreToolUsePayload });
    caseSummaries.push(buildCase('non_pretooluse_payload_denied_by_fixture_gate', nonPreToolUseRun, {
      payload: nonPreToolUsePayload,
      case_result: 'refused',
      refused_before_effect: true,
      proof_refusal_reason: 'fixture_gate_denied_non_pretooluse_payload',
    }));

    const localBoarding = runProtectedRecordsLocalBoardingProof();
    assertProtectedRecordsLocalBoardingProof(localBoarding);
    localBoardingProof = {
      run: true,
      passed: true,
      proof_type: PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE,
      evidence_model: localBoarding.evidence_model,
      final_effect_count: localBoarding.summary.final_effect_count,
      required_cases_present: localBoarding.summary.all_required_cases_present,
      v1_receipt_identity_verified: localBoarding.summary.v1_receipt_identity_verified,
      consequence_absent_on_every_refusal: localBoarding.summary.consequence_absent_on_every_refusal,
      consequence_present_exactly_once_on_acceptance:
        localBoarding.summary.consequence_present_exactly_once_on_acceptance,
      legacy_v0_recognized_boarding_identity:
        localBoarding.summary.legacy_v0_recognized_boarding_identity,
      replay_refused_after_acceptance: localBoarding.summary.replay_refused_after_acceptance,
      current_machine_governance_proven: localBoarding.summary.current_machine_governance_proven,
      production_downstream_recognition_proven: localBoarding.summary.production_downstream_recognition_proven,
    };
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }

  const summary = summarizeCases(caseSummaries, sentinel, marker);
  const report = {
    proof_type: CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE,
    command: CLAUDE_CODE_HOOK_CONTRACT_REPLAY_COMMAND,
    generated_at: new Date().toISOString(),
    evidence_model: evidenceModel,
    hook_replay_contract_sha256: claudeCodeHookContractReplayContractSha256({
      adapterSource,
      adapterSha256,
    }),
    adapter_source: adapterSource,
    adapter_path_claimed: `${adapterSource}:${CLAUDE_CODE_HOOK_CONTRACT_REPLAY_ADAPTER_RELATIVE_PATH}`,
    adapter_sha256: adapterSha256,
    source_commit: source_state.commit,
    source_state,
    source_state_boundary: sourceStateBoundary,
    live_claude_invoked: false,
    live_claude_app_passage_proven: false,
    app_originated_hook_crossing_proven: false,
    installed_hook_configuration_written: false,
    current_machine_governance_proven: false,
    live_receipt_emission_proven: false,
    production_downstream_recognition_proven: false,
    all_surface_governance_proven: false,
    side_door_closure_proven: false,
    fixture_contract: {
      fixture_contract_type: 'zlar-claude-code-hook-contract-replay-fixture-v1',
      adapter_invocation_model: 'copied-adapter-in-proof-owned-install-shaped-fixture-root',
      input_contract: 'claude-code-pretooluse-hook-json',
      output_contract: 'hookSpecificOutput.permissionDecision-json',
      arbitrary_external_fixture_paths_allowed: false,
      live_claude_contact_allowed: false,
      denied_effect_execution_model: 'harness-never-executes-tool-input-command',
      real_zlar_audit_paths_written: false,
      real_zlar_worker_receipt_paths_written: false,
    },
    cases: caseSummaries,
    sentinel,
    marker,
    audit_session_worker_receipt_deltas: {
      mode: 'fixture-gate',
      real_zlar_audit_delta: 'not_applicable',
      real_zlar_session_delta: 'not_applicable',
      real_zlar_worker_receipt_delta: 'not_applicable',
      fixture_gate_stdin_captured: true,
    },
    supporting_local_boarding_proof: localBoardingProof,
    summary,
    safe_claim_ceiling: CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING,
    non_claims: [...nonClaims],
    side_doors: [...REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS],
  };

  assertClaudeCodeHookContractReplayProof(report);
  return report;
}

function summarizeCases(cases, sentinel, marker) {
  return {
    all_required_cases_present: REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.every((required) =>
      cases.some((item) => item.case_id === required.case_id)
    ),
    all_adapter_exits_zero: cases.every((item) => item.adapter_exit_code === 0),
    allow_json_observed: cases.some((item) =>
      item.case_id === 'allow_pwd_hook_json' &&
      item.valid_claude_hook_json &&
      item.permission_decision === 'allow'
    ),
    deny_json_observed: cases.some((item) =>
      item.case_id === 'deny_destructive_sentinel_hook_json' &&
      item.valid_claude_hook_json &&
      item.permission_decision === 'deny'
    ),
    denied_effect_not_executed: sentinel?.unchanged === true && sentinel?.denied_effect_executed === false,
    adapter_did_not_execute_tool_input: marker?.tool_input_command_executed === false,
    missing_gate_failed_closed: cases.some((item) =>
      item.case_id === 'missing_gate_fails_closed' &&
      item.permission_decision === 'deny' &&
      item.valid_claude_hook_json
    ),
    blank_gate_response_failed_closed: cases.some((item) =>
      item.case_id === 'blank_gate_response_fails_closed' &&
      item.permission_decision === 'deny' &&
      item.valid_claude_hook_json
    ),
    malformed_output_refused: cases.some((item) =>
      item.case_id === 'malformed_output_refused' &&
      item.case_result === 'refused' &&
      item.stdout_json_valid === false
    ),
    non_pretooluse_payload_denied_by_fixture_gate: cases.some((item) =>
      item.case_id === 'non_pretooluse_payload_denied_by_fixture_gate' &&
      item.case_result === 'refused' &&
      item.proof_refusal_reason === 'fixture_gate_denied_non_pretooluse_payload'
    ),
    live_claude_app_passage_proven: false,
    app_originated_hook_crossing_proven: false,
    live_receipt_emission_proven: false,
    current_machine_governance_proven: false,
    production_downstream_recognition_proven: false,
    side_door_closure_proven: false,
  };
}

function assertExactKeys(label, value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
  return true;
}

function assertExactArray(label, value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`${label} drifted`);
  }
  for (let i = 0; i < expected.length; i++) {
    if (value[i] !== expected[i]) {
      throw new Error(`${label} drifted`);
    }
  }
  return true;
}

function assertBooleanFalse(label, value) {
  if (value !== false) {
    throw new Error(`${label} must be false`);
  }
}

export function assertClaudeCodeHookContractReplayProof(report) {
  assertExactKeys('report', report, [
    'adapter_path_claimed',
    'adapter_sha256',
    'adapter_source',
    'all_surface_governance_proven',
    'app_originated_hook_crossing_proven',
    'audit_session_worker_receipt_deltas',
    'cases',
    'command',
    'current_machine_governance_proven',
    'evidence_model',
    'fixture_contract',
    'generated_at',
    'hook_replay_contract_sha256',
    'installed_hook_configuration_written',
    'live_claude_app_passage_proven',
    'live_claude_invoked',
    'live_receipt_emission_proven',
    'marker',
    'non_claims',
    'production_downstream_recognition_proven',
    'proof_type',
    'safe_claim_ceiling',
    'sentinel',
    'side_door_closure_proven',
    'side_doors',
    'source_commit',
    'source_state',
    'source_state_boundary',
    'summary',
    'supporting_local_boarding_proof',
  ]);
  if (report.proof_type !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_PROOF_TYPE) {
    throw new Error('proof type drifted');
  }
  if (report.command !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_COMMAND) {
    throw new Error('command drifted');
  }
  if (!['repo', 'installed'].includes(report.adapter_source)) {
    throw new Error('adapter source drifted');
  }
  const installedMode = report.adapter_source === 'installed';
  const expectedEvidenceModel = installedMode
    ? CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_EVIDENCE_MODEL
    : CLAUDE_CODE_HOOK_CONTRACT_REPLAY_EVIDENCE_MODEL;
  const expectedSourceBoundary = installedMode
    ? CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_SOURCE_STATE_BOUNDARY
    : CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SOURCE_STATE_BOUNDARY;
  const expectedNonClaims = installedMode
    ? CLAUDE_CODE_HOOK_CONTRACT_REPLAY_INSTALLED_NON_CLAIMS
    : CLAUDE_CODE_HOOK_CONTRACT_REPLAY_NON_CLAIMS;
  if (report.evidence_model !== expectedEvidenceModel) {
    throw new Error('evidence model drifted');
  }
  if (!/^[a-f0-9]{64}$/.test(report.adapter_sha256 || '')) {
    throw new Error('adapter hash invalid');
  }
  if (
    report.hook_replay_contract_sha256 !==
      claudeCodeHookContractReplayContractSha256({
        adapterSource: report.adapter_source,
        adapterSha256: report.adapter_sha256,
      })
  ) {
    throw new Error('hook replay contract hash drifted');
  }
  if (report.adapter_path_claimed !== `${report.adapter_source}:${CLAUDE_CODE_HOOK_CONTRACT_REPLAY_ADAPTER_RELATIVE_PATH}`) {
    throw new Error('adapter path claim drifted');
  }
  if (!installedMode && report.adapter_sha256 !== claudeCodeHookContractReplayRepoAdapterSha256()) {
    throw new Error('adapter hash drifted');
  }
  if (report.source_state_boundary !== expectedSourceBoundary) {
    throw new Error('source state boundary drifted');
  }
  assertExactKeys('source_state', report.source_state, [
    'commit',
    'provenance',
    'status_sha256',
    'status_known',
    'uncommitted_changes',
    'worktree_clean',
  ]);
  if (report.source_commit !== report.source_state.commit) {
    throw new Error('source commit does not match source state');
  }
  if (report.source_commit !== null && !/^[a-f0-9]{40}$/.test(report.source_commit)) {
    throw new Error('source commit invalid');
  }
  if (installedMode) {
    if (
      report.source_commit !== null ||
      report.source_state.commit !== null ||
      report.source_state.provenance !== 'installed-file-identity-no-source-state' ||
      report.source_state.status_sha256 !== null ||
      report.source_state.status_known !== false ||
      report.source_state.uncommitted_changes !== false ||
      report.source_state.worktree_clean !== false
    ) {
      throw new Error('installed source-state boundary drifted');
    }
  } else {
    if (!['clean-commit', 'commit-plus-uncommitted-worktree'].includes(report.source_state.provenance)) {
      throw new Error('source provenance drifted');
    }
    if (report.source_state.status_known !== true) {
      throw new Error('source status must be known');
    }
    if (!/^[a-f0-9]{64}$/.test(report.source_state.status_sha256 || '')) {
      throw new Error('source status fingerprint invalid');
    }
    if (typeof report.source_state.uncommitted_changes !== 'boolean' ||
        typeof report.source_state.worktree_clean !== 'boolean' ||
        report.source_state.uncommitted_changes === report.source_state.worktree_clean) {
      throw new Error('source worktree boundary drifted');
    }
    if (
      report.source_state.provenance === 'clean-commit' &&
      (report.source_state.uncommitted_changes !== false || report.source_state.worktree_clean !== true)
    ) {
      throw new Error('clean source state drifted');
    }
    if (
      report.source_state.provenance === 'commit-plus-uncommitted-worktree' &&
      (report.source_state.uncommitted_changes !== true || report.source_state.worktree_clean !== false)
    ) {
      throw new Error('dirty source state drifted');
    }
    const currentSourceState = sourceState();
    if (
      report.source_commit !== currentSourceState.commit ||
      JSON.stringify(report.source_state) !== JSON.stringify(currentSourceState)
    ) {
      throw new Error('source state drifted from current local HEAD/status fingerprint');
    }
  }
  for (const field of [
    'live_claude_invoked',
    'live_claude_app_passage_proven',
    'app_originated_hook_crossing_proven',
    'installed_hook_configuration_written',
    'current_machine_governance_proven',
    'live_receipt_emission_proven',
    'production_downstream_recognition_proven',
    'all_surface_governance_proven',
    'side_door_closure_proven',
  ]) {
    assertBooleanFalse(field, report[field]);
  }

  assertExactKeys('fixture_contract', report.fixture_contract, [
    'adapter_invocation_model',
    'arbitrary_external_fixture_paths_allowed',
    'denied_effect_execution_model',
    'fixture_contract_type',
    'input_contract',
    'live_claude_contact_allowed',
    'output_contract',
    'real_zlar_audit_paths_written',
    'real_zlar_worker_receipt_paths_written',
  ]);
  if (report.fixture_contract.adapter_invocation_model !== 'copied-adapter-in-proof-owned-install-shaped-fixture-root') {
    throw new Error('fixture adapter model drifted');
  }
  for (const field of [
    'arbitrary_external_fixture_paths_allowed',
    'live_claude_contact_allowed',
    'real_zlar_audit_paths_written',
    'real_zlar_worker_receipt_paths_written',
  ]) {
    assertBooleanFalse(`fixture_contract.${field}`, report.fixture_contract[field]);
  }

  if (!Array.isArray(report.cases) ||
      report.cases.length !== REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES.length) {
    throw new Error('case count drifted');
  }
  for (const required of REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASES) {
    const item = report.cases.find((candidate) => candidate.case_id === required.case_id);
    if (!item) {
      throw new Error(`missing case ${required.case_id}`);
    }
    assertExactKeys(`case ${required.case_id}`, item, CLAUDE_CODE_HOOK_CONTRACT_REPLAY_CASE_KEYS);
    if (item.case_result !== required.expected_case_result) {
      throw new Error(`case ${required.case_id} result drifted`);
    }
    if (item.adapter_exit_code !== required.expected_adapter_exit) {
      throw new Error(`case ${required.case_id} adapter exit drifted`);
    }
    if (item.permission_decision !== required.expected_permission_decision) {
      throw new Error(`case ${required.case_id} decision drifted`);
    }
    if (!/^[a-f0-9]{64}$/.test(item.stdout_sha256) ||
        !/^[a-f0-9]{64}$/.test(item.stderr_sha256) ||
        !/^[a-f0-9]{64}$/.test(item.input_sha256) ||
        !/^[a-f0-9]{64}$/.test(item.input_contract_sha256)) {
      throw new Error(`case ${required.case_id} hash invalid`);
    }
    if (
      item.input_contract_sha256 !==
        claudeCodeHookContractReplayInputContractSha256(required.case_id)
    ) {
      throw new Error(`case ${required.case_id} input contract drifted`);
    }
    const expectedSemantics = claudeCodeHookContractReplayExpectedCaseSemantics(
      required.case_id
    );
    for (const [field, expectedValue] of Object.entries(expectedSemantics)) {
      if (item[field] !== expectedValue) {
        throw new Error(`case ${required.case_id} ${field} drifted`);
      }
    }
  }

  const allow = report.cases.find((item) => item.case_id === 'allow_pwd_hook_json');
  if (!allow.valid_claude_hook_json || allow.hook_event_name !== 'PreToolUse') {
    throw new Error('allow hook JSON invalid');
  }
  const deny = report.cases.find((item) => item.case_id === 'deny_destructive_sentinel_hook_json');
  if (!deny.valid_claude_hook_json || deny.permission_decision_reason_present !== true ||
      deny.refused_before_effect !== true || deny.denied_effect_executed !== false ||
      deny.sentinel_unchanged !== true) {
    throw new Error('deny hook JSON or sentinel proof invalid');
  }
  const missing = report.cases.find((item) => item.case_id === 'missing_gate_fails_closed');
  if (!missing.valid_claude_hook_json || missing.permission_decision !== 'deny' ||
      missing.refused_before_effect !== true) {
    throw new Error('missing gate did not fail closed');
  }
  const blank = report.cases.find((item) => item.case_id === 'blank_gate_response_fails_closed');
  if (!blank.valid_claude_hook_json || blank.permission_decision !== 'deny' ||
      blank.refused_before_effect !== true) {
    throw new Error('blank gate response did not fail closed');
  }
  const malformed = report.cases.find((item) => item.case_id === 'malformed_output_refused');
  if (malformed.stdout_json_valid !== false ||
      malformed.refused_before_effect !== true ||
      malformed.proof_refusal_reason !== 'adapter_stdout_not_valid_claude_hook_json') {
    throw new Error('malformed output refusal drifted');
  }
  const nonPreToolUse = report.cases.find((item) => item.case_id === 'non_pretooluse_payload_denied_by_fixture_gate');
  if (nonPreToolUse.proof_refusal_reason !== 'fixture_gate_denied_non_pretooluse_payload') {
    throw new Error('non-PreToolUse fixture denial drifted');
  }
  if (nonPreToolUse.permission_decision !== 'deny' ||
      nonPreToolUse.valid_claude_hook_json !== true ||
      nonPreToolUse.refused_before_effect !== true) {
    throw new Error('non-PreToolUse payload was not denied by fixture gate');
  }
  if (!report.sentinel?.unchanged || report.sentinel.denied_effect_executed !== false) {
    throw new Error('sentinel proof drifted');
  }
  if (report.marker?.tool_input_command_executed !== false) {
    throw new Error('tool_input command was executed');
  }

  assertExactKeys('audit_session_worker_receipt_deltas', report.audit_session_worker_receipt_deltas, [
    'fixture_gate_stdin_captured',
    'mode',
    'real_zlar_audit_delta',
    'real_zlar_session_delta',
    'real_zlar_worker_receipt_delta',
  ]);
  if (report.audit_session_worker_receipt_deltas.mode !== 'fixture-gate' ||
      report.audit_session_worker_receipt_deltas.real_zlar_audit_delta !== 'not_applicable' ||
      report.audit_session_worker_receipt_deltas.real_zlar_session_delta !== 'not_applicable' ||
      report.audit_session_worker_receipt_deltas.real_zlar_worker_receipt_delta !== 'not_applicable' ||
      report.audit_session_worker_receipt_deltas.fixture_gate_stdin_captured !== true) {
    throw new Error('audit/session/worker receipt boundary drifted');
  }

  assertExactKeys('supporting_local_boarding_proof', report.supporting_local_boarding_proof, [
    'current_machine_governance_proven',
    'consequence_absent_on_every_refusal',
    'consequence_present_exactly_once_on_acceptance',
    'evidence_model',
    'final_effect_count',
    'legacy_v0_recognized_boarding_identity',
    'passed',
    'production_downstream_recognition_proven',
    'proof_type',
    'replay_refused_after_acceptance',
    'required_cases_present',
    'run',
    'v1_receipt_identity_verified',
  ]);
  if (report.supporting_local_boarding_proof.run !== true ||
      report.supporting_local_boarding_proof.passed !== true ||
      report.supporting_local_boarding_proof.proof_type !== PROTECTED_RECORDS_LOCAL_BOARDING_PROOF_TYPE ||
      report.supporting_local_boarding_proof.v1_receipt_identity_verified !== true ||
      report.supporting_local_boarding_proof.consequence_absent_on_every_refusal !== true ||
      report.supporting_local_boarding_proof.consequence_present_exactly_once_on_acceptance !== true ||
      report.supporting_local_boarding_proof.legacy_v0_recognized_boarding_identity !== false ||
      report.supporting_local_boarding_proof.current_machine_governance_proven !== false ||
      report.supporting_local_boarding_proof.production_downstream_recognition_proven !== false) {
    throw new Error('supporting local boarding proof boundary drifted');
  }

  assertExactKeys('summary', report.summary, CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SUMMARY_KEYS);
  for (const [key, value] of Object.entries(report.summary)) {
    if (key.endsWith('_proven') || key === 'side_door_closure_proven') {
      assertBooleanFalse(`summary.${key}`, value);
    }
  }
  for (const requiredTrue of [
    'all_required_cases_present',
    'all_adapter_exits_zero',
    'allow_json_observed',
    'deny_json_observed',
    'denied_effect_not_executed',
    'adapter_did_not_execute_tool_input',
    'missing_gate_failed_closed',
    'blank_gate_response_failed_closed',
    'malformed_output_refused',
    'non_pretooluse_payload_denied_by_fixture_gate',
  ]) {
    if (report.summary[requiredTrue] !== true) {
      throw new Error(`summary.${requiredTrue} must be true`);
    }
  }
  if (report.safe_claim_ceiling !== CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SAFE_CLAIM_CEILING) {
    throw new Error('safe claim ceiling drifted');
  }
  assertExactArray('non_claims', report.non_claims, expectedNonClaims);
  assertExactArray('side_doors', report.side_doors, REQUIRED_CLAUDE_CODE_HOOK_CONTRACT_REPLAY_SIDE_DOORS);
  assertNoUnsafeClaudeCodeHookContractReplayProofText(JSON.stringify(report));
  return true;
}

export function formatClaudeCodeHookContractReplayProofSummary(report) {
  assertClaudeCodeHookContractReplayProof(report);
  const lines = [
    'Claude Code Hook-Contract Replay Proof v1',
    `Command: ${CLAUDE_CODE_HOOK_CONTRACT_REPLAY_COMMAND}`,
    `Evidence model: ${report.evidence_model}; live_claude_invoked=false; live_app_passage=false`,
    `Adapter: ${report.adapter_path_claimed}; sha256=${report.adapter_sha256}`,
    `Hook replay contract: sha256=${report.hook_replay_contract_sha256}`,
    `Source: commit=${report.source_commit || 'unknown'}; provenance=${report.source_state.provenance}`,
    `Source boundary: ${report.source_state_boundary}`,
    'Layer: local Claude-shaped PreToolUse replay through copied adapter fixture',
    `Cases: allow_json=${report.summary.allow_json_observed}; deny_json=${report.summary.deny_json_observed}; denied_effect_not_executed=${report.summary.denied_effect_not_executed}`,
    `Fail-closed: missing_gate=${report.summary.missing_gate_failed_closed}; blank_gate=${report.summary.blank_gate_response_failed_closed}; malformed_refused=${report.summary.malformed_output_refused}; non_pretooluse_payload_denied_by_fixture_gate=${report.summary.non_pretooluse_payload_denied_by_fixture_gate}`,
    `Supporting local boarding proof: passed=${report.supporting_local_boarding_proof.passed}; proof_type=${report.supporting_local_boarding_proof.proof_type}; v1_receipt_identity_verified=${report.supporting_local_boarding_proof.v1_receipt_identity_verified}; consequence_absent_on_every_refusal=${report.supporting_local_boarding_proof.consequence_absent_on_every_refusal}; consequence_present_exactly_once_on_acceptance=${report.supporting_local_boarding_proof.consequence_present_exactly_once_on_acceptance}; legacy_v0_recognized_boarding_identity=${report.supporting_local_boarding_proof.legacy_v0_recognized_boarding_identity}`,
    'Non-claims: not live Claude app passage, not app-originated hook crossing, not current-machine governance, not live receipt emission, not production downstream recognition, not all-surface governance, not side-door closure',
  ];
  for (const item of report.cases) {
    lines.push(`  - ${item.case_id}: result=${item.case_result}; decision=${item.permission_decision || 'none'}; adapter_exit=${item.adapter_exit_code}`);
  }
  const output = `${lines.join('\n')}\n`;
  assertNoUnsafeClaudeCodeHookContractReplayProofText(output);
  return output;
}

export function assertNoUnsafeClaudeCodeHookContractReplayProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`Unsafe ${label} in Claude Code hook-contract replay proof output`);
    }
  }
  return true;
}
