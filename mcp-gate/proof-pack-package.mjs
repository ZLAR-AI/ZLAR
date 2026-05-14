#!/usr/bin/env node
// Proof Pack Packaging v0.
//
// This helper packages already-produced routed-MCP evidence into a local,
// privacy-scanned bundle. It does not create new proof evidence.

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateWorkerReceipt } from '../lib/worker-receipt.mjs';
import {
  assertGovernedProfileCoverageReport,
  assertNoUnsafeCoverageText,
  formatGovernedProfileCoverageSummary,
  sha256Hex,
  stableStringify,
} from './governed-profile-coverage-report.mjs';

const __filename = fileURLToPath(import.meta.url);
const SCRIPT_PATH = resolve(__filename);

const PACK_TYPE = 'zlar-proof-pack-v0';
const MANIFEST_FILE = 'proof-pack-manifest.json';
const README_FILE = 'README.md';
const EVIDENCE_DIR = 'evidence';
const COVERAGE_JSON_FILE = `${EVIDENCE_DIR}/governed-profile-coverage-report.json`;
const COVERAGE_TEXT_FILE = `${EVIDENCE_DIR}/governed-profile-coverage-report.txt`;

const PRIVACY_CHECKS = Object.freeze([
  'raw_args_absent',
  'env_values_absent',
  'prompt_text_absent',
  'final_text_absent',
  'private_paths_absent',
  'numeric_human_ids_absent',
  'approval_channel_ids_absent',
  'live_approval_channel_details_absent',
  'credentials_absent',
  'operator_config_values_absent',
]);

const UNSAFE_BUNDLE_PATTERNS = Object.freeze([
  { label: 'raw MCP args key', pattern: /\b(?:args_preview|raw_args|tool_args|mcp_args)\b/i },
  { label: 'raw args object', pattern: /"args"\s*:\s*[\[{"]/i },
  { label: 'env object', pattern: /"env"\s*:\s*\{/i },
  { label: 'prompt text value', pattern: /"(?:prompt|prompt_text)"\s*:\s*"[^"]+"/i },
  { label: 'final text value', pattern: /"(?:final|final_text|final_client_text)"\s*:\s*"[^"]+"/i },
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'numeric human identifier', pattern: /\bhuman:[0-9]/ },
  { label: 'chat id field', pattern: new RegExp(`\\b${['chat', 'id'].join('_')}\\b`, 'i') },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
  { label: 'GitHub token', pattern: new RegExp(`\\b${['ghp', ''].join('_')}[A-Za-z0-9_]{10,}\\b`) },
  { label: 'GitHub fine-grained token', pattern: new RegExp(`\\b${['github', 'pat', ''].join('_')}[A-Za-z0-9_]{10,}\\b`) },
  { label: 'Slack token', pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key', pattern: new RegExp(`\\b${['AK', 'IA'].join('')}[0-9A-Z]{12,}\\b`) },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*(?!\[REDACTED_(?:CREDENTIAL|SECRET)\])[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+(?!\[REDACTED_CREDENTIAL\])[A-Za-z0-9._~+/=-]{6,}/i,
  },
  {
    label: 'broad action claim',
    pattern: new RegExp(`\\b${['all', 'actions'].join('\\s+')}\\b`, 'i'),
  },
  {
    label: 'broad tool claim',
    pattern: new RegExp(`\\b${['every', 'tool', 'call'].join('[-\\s]+')}\\b`, 'i'),
  },
  {
    label: 'broad Codex claim',
    pattern: new RegExp(`\\b${['governs', 'Codex'].join('\\s+')}\\b`),
  },
  {
    label: 'broad Hermes claim',
    pattern: new RegExp(`\\b(?:govern|governs|governed)\\s+${'Hermes'}\\b`),
  },
  {
    label: 'external attestation completion claim',
    pattern: new RegExp(`\\b(?:${['externally', 'attested'].join('\\s+')}|${['independently', 'attested'].join('\\s+')})\\b`, 'i'),
  },
  {
    label: 'contest implementation claim',
    pattern: /\/contest\s+(?:is\s+)?implemented\b/i,
  },
]);

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function readText(path) {
  return readFileSync(path, 'utf8');
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function readJsonl(path) {
  if (!path || !existsSync(path)) return [];
  return readText(path)
    .split(/\n/)
    .filter((line) => line.trim())
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (err) {
        throw new Error(`${basename(path)} line ${index + 1} is not JSON: ${err.message}`);
      }
    });
}

function relativeBundlePath(bundleDir, path) {
  return relative(bundleDir, path).replace(/\\/g, '/');
}

function safeGeneratedAt(value) {
  return value || new Date().toISOString();
}

function surfaceCounts(report) {
  const counts = {};
  for (const surface of report.surfaces || []) {
    counts[surface.status] = (counts[surface.status] || 0) + 1;
  }
  return counts;
}

function decisionSurfaceSummaries(report) {
  return (report.surfaces || [])
    .filter((surface) => String(surface.id || '').startsWith('codex.mcp.decision.'))
    .map((surface) => ({
      id: surface.id,
      status: surface.status,
      audit_event_ids: Array.isArray(surface.evidence?.audit_event_ids)
        ? surface.evidence.audit_event_ids
        : [],
      worker_receipt_count: Array.isArray(surface.worker_receipts)
        ? surface.worker_receipts.length
        : 0,
      why_status: surface.why?.status || 'not_checked',
    }));
}

function coverageWorkerReceiptSummaries(report) {
  const summaries = [];
  for (const surface of report.surfaces || []) {
    for (const receipt of surface.worker_receipts || []) {
      summaries.push({
        event_id: receipt.event_id || null,
        receipt_sha256: receipt.receipt_sha256 || null,
        audit_hash: receipt.audit_hash || null,
        detail_hash: receipt.detail_hash || null,
        decision: receipt.decision || null,
        why_status: receipt.why_status || surface.why?.status || 'not_checked',
      });
    }
  }
  return summaries;
}

function storeWorkerReceiptSummaries(workerReceipts) {
  return workerReceipts.map((receipt) => {
    validateWorkerReceipt(receipt);
    return {
      event_id: receipt.event.id,
      surface: receipt.event.surface,
      receipt_sha256: sha256Hex(stableStringify(receipt)),
      audit_hash: receipt.event.audit_hash,
      detail_hash: receipt.action.detail_hash,
      decision: receipt.decision.outcome,
    };
  });
}

function whySummary(report, extraWhyByEventId = null) {
  const byEventId = {};
  for (const surface of report.surfaces || []) {
    const ids = Array.isArray(surface.evidence?.audit_event_ids)
      ? surface.evidence.audit_event_ids
      : [];
    for (const id of ids) {
      if (!id) continue;
      byEventId[id] = surface.why?.status || 'not_checked';
    }
    for (const receipt of surface.worker_receipts || []) {
      if (receipt.event_id) {
        byEventId[receipt.event_id] = receipt.why_status || surface.why?.status || 'not_checked';
      }
    }
  }
  if (extraWhyByEventId && typeof extraWhyByEventId === 'object') {
    for (const [eventId, value] of Object.entries(extraWhyByEventId)) {
      if (typeof value === 'string') byEventId[eventId] = value;
      else if (value && typeof value === 'object' && typeof value.status === 'string') byEventId[eventId] = value.status;
      else if (value === true) byEventId[eventId] = 'available';
      else if (value === false || value === null) byEventId[eventId] = 'missing';
    }
  }
  return byEventId;
}

function routedMcpProofSummary(report) {
  if (!report) {
    return {
      available: false,
      included: false,
      reason: 'not supplied',
    };
  }
  const calls = Array.isArray(report.governed_routed_mcp_calls)
    ? report.governed_routed_mcp_calls
    : [];
  return {
    available: true,
    included: false,
    reason: 'referenced by hash and sanitized call summary only',
    report_type: report.report_type || 'unknown',
    report_sha256: sha256Hex(stableStringify(report)),
    call_count: calls.length,
    calls: calls.map((call) => ({
      expected_decision: call.expected_decision || call.expectedDecision || null,
      upstream_observed: call.upstream_observed ?? call.upstreamObserved ?? null,
      audit_event_id: call.audit?.id || call.auditEvent?.id || null,
      audit_source: call.audit?.source || call.auditEvent?.source || null,
      audit_outcome: call.audit?.outcome || call.auditEvent?.outcome || null,
      worker_receipt_emitted: Boolean(call.worker_receipt?.emitted || call.workerReceipt),
    })),
  };
}

function verifierKitSummary(coverageReport, verifierKitRunnerStatus = null) {
  return {
    packet: coverageReport.verifier_kit_packet || {
      status: 'prepared_pending',
      external_attestation: 'not_attested',
    },
    runner: verifierKitRunnerStatus || {
      status: 'not_checked',
      external_attestation: 'not_attested',
    },
  };
}

function privacyValidationBlock() {
  return {
    passed: true,
    checks: Object.fromEntries(PRIVACY_CHECKS.map((check) => [check, true])),
  };
}

function buildManifest({
  coverageReport,
  coverageSummary,
  routedMcpProofReport = null,
  workerReceipts = [],
  whyByEventId = null,
  verifierKitRunnerStatus = null,
  generatedAt = null,
} = {}) {
  assertGovernedProfileCoverageReport(coverageReport);
  assertNoUnsafeCoverageText(coverageReport);
  assertNoUnsafeCoverageText(coverageSummary);
  const storeSummaries = storeWorkerReceiptSummaries(workerReceipts);
  const coverageReceiptSummaries = coverageWorkerReceiptSummaries(coverageReport);
  const manifest = {
    generated_at: safeGeneratedAt(generatedAt),
    pack_type: PACK_TYPE,
    pack_version: 0,
    claim_ceiling: coverageReport.safe_claim_ceiling,
    included_files: {
      manifest: MANIFEST_FILE,
      readme: README_FILE,
      governed_profile_coverage_json: COVERAGE_JSON_FILE,
      governed_profile_coverage_text: COVERAGE_TEXT_FILE,
    },
    evidence: {
      governed_profile_coverage_report: {
        included: true,
        report_type: coverageReport.report_type,
        profile: coverageReport.profile,
        json_file: COVERAGE_JSON_FILE,
        text_file: COVERAGE_TEXT_FILE,
        json_sha256: sha256Hex(stableStringify(coverageReport)),
        text_sha256: sha256Hex(coverageSummary),
        surface_counts: surfaceCounts(coverageReport),
        decision_surfaces: decisionSurfaceSummaries(coverageReport),
      },
      routed_mcp_proof_report: routedMcpProofSummary(routedMcpProofReport),
      worker_receipts: {
        included_raw_store: false,
        coverage_report_receipt_count: coverageReceiptSummaries.length,
        store_receipt_count: storeSummaries.length,
        receipt_summaries: storeSummaries.length > 0 ? storeSummaries : coverageReceiptSummaries,
      },
      why_lookup: {
        status_by_event_id: whySummary(coverageReport, whyByEventId),
      },
      verifier_kit: verifierKitSummary(coverageReport, verifierKitRunnerStatus),
    },
    non_claims: coverageReport.non_claims || [],
    residual_ungoverned_surfaces: coverageReport.residual_ungoverned_surfaces || [],
    privacy_validation: privacyValidationBlock(),
  };
  assertNoUnsafeProofPackText(manifest);
  return manifest;
}

function formatReadme(manifest) {
  const coverage = manifest.evidence.governed_profile_coverage_report;
  const routedProof = manifest.evidence.routed_mcp_proof_report;
  const receiptInfo = manifest.evidence.worker_receipts;
  const lines = [
    '# ZLAR Proof Pack v0',
    '',
    'This local bundle packages existing routed-MCP evidence for review.',
    '',
    `Claim ceiling: ${manifest.claim_ceiling}`,
    '',
    'Included evidence:',
    `- ${coverage.json_file} (${coverage.report_type}, sha256=${coverage.json_sha256})`,
    `- ${coverage.text_file} (sha256=${coverage.text_sha256})`,
    `- Routed-MCP proof report: ${routedProof.available ? `referenced by hash ${routedProof.report_sha256}` : 'not supplied'}`,
    `- Worker Receipt summaries: ${receiptInfo.receipt_summaries.length}`,
    `- Verifier Kit packet status: ${manifest.evidence.verifier_kit.packet.status}`,
    '',
    'Not included:',
    '- Raw MCP argument objects, environment values, prompt text, final client text, private paths, approval-channel identifiers, credentials, or operator config values.',
    '- Raw Worker Receipt store contents.',
    '- Any external attestation claim.',
    '',
    'Non-claims:',
    ...manifest.non_claims.map((claim) => `- ${claim}`),
    '',
    'Residual ungoverned surfaces:',
    ...manifest.residual_ungoverned_surfaces.map((surface) => `- ${surface}`),
  ];
  const readme = `${lines.join('\n')}\n`;
  assertNoUnsafeProofPackText(readme);
  return readme;
}

function assertNoUnsafeProofPackText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_BUNDLE_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`proof pack contains ${label}`);
    }
  }
  assertNoUnsafeCoverageText(text);
}

function listFiles(dir) {
  const results = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const st = statSync(path);
    if (st.isDirectory()) {
      results.push(...listFiles(path));
    } else if (st.isFile()) {
      results.push(path);
    }
  }
  return results;
}

function assertProofPackBundleSafe(bundleDir) {
  for (const path of listFiles(bundleDir)) {
    assertNoUnsafeProofPackText(readText(path));
  }
  return true;
}

function packageProofPackBundle({
  outputDir,
  coverageReport,
  coverageSummary = null,
  routedMcpProofReport = null,
  workerReceipts = [],
  whyByEventId = null,
  verifierKitRunnerStatus = null,
  generatedAt = null,
} = {}) {
  if (!outputDir) throw new Error('outputDir is required');
  const bundleDir = resolve(outputDir);
  const evidenceDir = join(bundleDir, EVIDENCE_DIR);
  mkdirSync(evidenceDir, { recursive: true });

  const summary = coverageSummary || formatGovernedProfileCoverageSummary(coverageReport);
  const manifest = buildManifest({
    coverageReport,
    coverageSummary: summary,
    routedMcpProofReport,
    workerReceipts,
    whyByEventId,
    verifierKitRunnerStatus,
    generatedAt,
  });
  const readme = formatReadme(manifest);

  writeJson(join(bundleDir, MANIFEST_FILE), manifest);
  writeFileSync(join(bundleDir, README_FILE), readme);
  writeJson(join(bundleDir, COVERAGE_JSON_FILE), coverageReport);
  writeFileSync(join(bundleDir, COVERAGE_TEXT_FILE), summary.endsWith('\n') ? summary : `${summary}\n`);

  assertProofPackBundleSafe(bundleDir);

  return {
    bundleDir,
    manifest,
    manifestPath: join(bundleDir, MANIFEST_FILE),
    readmePath: join(bundleDir, README_FILE),
    coverageJsonPath: join(bundleDir, COVERAGE_JSON_FILE),
    coverageTextPath: join(bundleDir, COVERAGE_TEXT_FILE),
    files: listFiles(bundleDir).map((path) => relativeBundlePath(bundleDir, path)).sort(),
  };
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (!item.startsWith('--')) throw new Error(`unexpected argument: ${item}`);
    const key = item.slice(2);
    if (key === 'help' || key === 'h') {
      args.help = true;
      continue;
    }
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) throw new Error(`--${key} requires a value`);
    args[key] = value;
    i += 1;
  }
  return args;
}

function usage() {
  console.log(`Usage:
  node mcp-gate/proof-pack-package.mjs \\
    --coverage-json <path> \\
    --out-dir <bundle-dir> \\
    [--coverage-text <path>] \\
    [--routed-proof-json <path>] \\
    [--worker-receipts-jsonl <path>] \\
    [--why-json <path>] \\
    [--verifier-status-json <path>]

Packages existing evidence into a local Proof Pack v0 bundle. The helper
copies only governed-profile coverage JSON/text and summarizes or hashes
optional routed proof and Worker Receipt inputs.`);
}

function runCli(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    usage();
    return 0;
  }
  if (!args['coverage-json']) throw new Error('--coverage-json is required');
  if (!args['out-dir']) throw new Error('--out-dir is required');
  const coverageReport = readJson(args['coverage-json']);
  const coverageSummary = args['coverage-text']
    ? readText(args['coverage-text'])
    : formatGovernedProfileCoverageSummary(coverageReport);
  const routedMcpProofReport = args['routed-proof-json']
    ? readJson(args['routed-proof-json'])
    : null;
  const workerReceipts = args['worker-receipts-jsonl']
    ? readJsonl(args['worker-receipts-jsonl'])
    : [];
  const whyByEventId = args['why-json']
    ? readJson(args['why-json'])
    : null;
  const verifierKitRunnerStatus = args['verifier-status-json']
    ? readJson(args['verifier-status-json'])
    : null;
  const result = packageProofPackBundle({
    outputDir: args['out-dir'],
    coverageReport,
    coverageSummary,
    routedMcpProofReport,
    workerReceipts,
    whyByEventId,
    verifierKitRunnerStatus,
  });
  console.log(`Proof Pack v0 bundle: ${result.bundleDir}`);
  console.log(`Manifest: ${result.manifestPath}`);
  console.log(`README: ${result.readmePath}`);
  return 0;
}

export {
  MANIFEST_FILE,
  PACK_TYPE,
  README_FILE,
  assertNoUnsafeProofPackText,
  assertProofPackBundleSafe,
  buildManifest,
  formatReadme,
  packageProofPackBundle,
};

if (process.argv[1] && resolve(process.argv[1]) === SCRIPT_PATH) {
  try {
    process.exit(runCli(process.argv.slice(2)));
  } catch (err) {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  }
}
