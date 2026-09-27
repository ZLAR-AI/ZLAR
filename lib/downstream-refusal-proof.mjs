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
} from './receipt.mjs';
import { evaluateDownstreamRecognition } from './downstream-recognition-rule.mjs';

export const DOWNSTREAM_REFUSAL_PROOF_TYPE = 'downstream-refusal-proof-v1';

export const SAFE_CLAIM_CEILING =
  'ZLAR can demonstrate, in a local hermetic fixture, that one downstream recognition rule accepts one matching signed receipt and refuses missing, invalid, stale, unknown-issuer, retired-issuer, wrong-policy, out-of-scope, wrong-audit-event, wrong-detail, and non-boarding receipts before a fake effect marker is written.';

export const NON_CLAIMS = Object.freeze([
  'This proof does not inspect live downstream systems.',
  'This proof does not prove production deployment.',
  'This proof does not prove external attestation or sovereign recognition.',
  'This proof does not prove coverage of unrouted paths.',
]);

export const REQUIRED_REFUSAL_REASONS = Object.freeze([
  'receipt_missing',
  'receipt_invalid',
  'issuer_not_active',
  'unknown_issuer',
  'outcome_not_boarding',
  'policy_not_recognized',
  'domain_out_of_scope',
  'tool_out_of_scope',
  'audit_event_mismatch',
  'detail_hash_mismatch',
  'receipt_stale',
]);

const UNSAFE_OUTPUT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'numeric human identifier', pattern: /\bhuman:[0-9]/ },
  { label: 'chat id field', pattern: /\bchat_id\b/i },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'public key material', pattern: /BEGIN PUBLIC KEY/ },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*[^&\s"'`,;})\]]+/i,
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

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

function fixtureEvent(nowEpoch, overrides = {}) {
  return {
    id: overrides.id || 'fake-effect-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || {
      record_id: 'fixture-record-001',
      operation: 'update_status',
    },
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RRECORDS_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function markerCount(markerFile) {
  if (!existsSync(markerFile)) return 0;
  return readFileSync(markerFile, 'utf8').trim().split(/\n/).filter(Boolean).length;
}

function markerText(markerFile) {
  if (!existsSync(markerFile)) return '';
  return readFileSync(markerFile, 'utf8');
}

function caseReport({ caseId, result, before, after }) {
  return {
    case_id: caseId,
    boarded: result.boarded,
    decision: result.decision.decision,
    reason_code: result.decision.reason_code,
    marker_count_delta: after - before,
  };
}

export function runHermeticDownstreamRefusalProof({
  nowEpoch = Math.floor(Date.now() / 1000),
} = {}) {
  const scratch = mkdtempSync(join(tmpdir(), 'zlar-downstream-refusal-'));
  try {
    const markerFile = join(scratch, 'fake-downstream-effect.jsonl');
    function keyMaterial(label) {
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

    const activeIssuer = keyMaterial('active-issuer');
    const retiredIssuer = keyMaterial('retired-issuer');
    const unknownIssuer = keyMaterial('unknown-issuer');

    function signedReceipt(overrides = {}, issuer = activeIssuer) {
      return signReceiptV1(
        createReceiptV1FromEvent(fixtureEvent(nowEpoch, overrides)),
        issuer.privatePem,
        issuer.kid
      );
    }

    const recognizedReceipt = signedReceipt();
    const recognizedPayload = decodePayloadV1(recognizedReceipt);
    const recognitionRule = {
      deployment_scope: 'fixture-records-terminal',
      accepted_issuers: [
        {
          kid: activeIssuer.kid,
          public_key_pem: activeIssuer.publicPem,
          status: 'active',
        },
        {
          kid: retiredIssuer.kid,
          public_key_pem: retiredIssuer.publicPem,
          status: 'retired',
        },
      ],
      accepted_policy_versions: ['recognition-policy-v1'],
      accepted_domains: ['records'],
      accepted_tools: ['records.write'],
      accepted_outcomes: ['allow', 'authorized'],
      max_age_seconds: 120,
      required_audit_event_id: 'fake-effect-001',
      required_detail_hash: recognizedPayload.detail_hash,
    };

    function fakeDownstreamEffect({ receipt, label }) {
      const decision = evaluateDownstreamRecognition({
        receipt,
        recognition_rule: recognitionRule,
        now_epoch: nowEpoch,
      });
      if (!decision.recognized) {
        return { boarded: false, decision };
      }
      writeFileSync(markerFile, `${JSON.stringify({
        label,
        receipt_id: decision.evidence.receipt_id,
        audit_event_id: decision.evidence.payload.audit_event_id,
        detail_hash: decision.evidence.payload.detail_hash,
      })}\n`, { flag: 'a' });
      return { boarded: true, decision };
    }

    const beforeRecognized = markerCount(markerFile);
    const recognizedResult = fakeDownstreamEffect({
      receipt: recognizedReceipt,
      label: 'recognized',
    });
    const recognized = caseReport({
      caseId: 'recognized',
      result: recognizedResult,
      before: beforeRecognized,
      after: markerCount(markerFile),
    });

    const refusalInputs = [
      {
        caseId: 'missing',
        receipt: null,
        label: 'missing',
      },
      {
        caseId: 'tampered',
        receipt: { ...recognizedReceipt, sig: `${recognizedReceipt.sig.slice(0, -4)}xxxx` },
        label: 'tampered',
      },
      {
        caseId: 'retired_issuer',
        receipt: signedReceipt({}, retiredIssuer),
        label: 'retired-issuer',
      },
      {
        caseId: 'unknown_issuer',
        receipt: signedReceipt({}, unknownIssuer),
        label: 'unknown-issuer',
      },
      {
        caseId: 'non_boarding',
        receipt: signedReceipt({ outcome: 'deny' }),
        label: 'deny',
      },
      {
        caseId: 'wrong_policy',
        receipt: signedReceipt({ policy_version: 'recognition-policy-old' }),
        label: 'wrong-policy',
      },
      {
        caseId: 'wrong_domain',
        receipt: signedReceipt({ domain: 'finance' }),
        label: 'wrong-domain',
      },
      {
        caseId: 'wrong_tool',
        receipt: signedReceipt({ action: 'records.delete' }),
        label: 'wrong-tool',
      },
      {
        caseId: 'wrong_audit_event',
        receipt: signedReceipt({ id: 'fake-effect-999' }),
        label: 'wrong-audit-event',
      },
      {
        caseId: 'wrong_detail',
        receipt: signedReceipt({
          detail: {
            record_id: 'fixture-record-002',
            operation: 'update_status',
          },
        }),
        label: 'wrong-detail',
      },
      {
        caseId: 'stale',
        receipt: signedReceipt({ ts: isoSecondsAgo(nowEpoch, 600) }),
        label: 'stale',
      },
    ];

    const refusals = refusalInputs.map((input) => {
      const before = markerCount(markerFile);
      const result = fakeDownstreamEffect(input);
      const after = markerCount(markerFile);
      return caseReport({
        caseId: input.caseId,
        result,
        before,
        after,
      });
    });

    const markers = markerText(markerFile);
    return {
      proof_type: DOWNSTREAM_REFUSAL_PROOF_TYPE,
      evidence_model: 'local-hermetic-fixture',
      live_probing: false,
      action_class: 'records.write',
      deployment_scope: 'fixture-records-terminal',
      recognized_boarding: recognized,
      refusals,
      marker: {
        final_count: markerCount(markerFile),
        receipt_id_present: markers.includes(recognizedReceipt.id),
        raw_record_id_present: markers.includes('fixture-record-001'),
        public_key_present: markers.includes('BEGIN PUBLIC KEY'),
      },
      safe_claim_ceiling: SAFE_CLAIM_CEILING,
      non_claims: [...NON_CLAIMS],
    };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

export function assertDownstreamRefusalProof(report) {
  if (!report || report.proof_type !== DOWNSTREAM_REFUSAL_PROOF_TYPE) {
    throw new Error('Downstream refusal proof has the wrong proof type');
  }
  if (report.evidence_model !== 'local-hermetic-fixture') {
    throw new Error('Downstream refusal proof must be local hermetic fixture evidence');
  }
  if (report.live_probing !== false) {
    throw new Error('Downstream refusal proof must not perform live probing');
  }
  const recognized = report.recognized_boarding || {};
  if (
    recognized.case_id !== 'recognized' ||
    recognized.boarded !== true ||
    recognized.decision !== 'accept' ||
    recognized.reason_code !== 'recognized' ||
    recognized.marker_count_delta !== 1
  ) {
    throw new Error('Recognized downstream receipt did not board exactly once');
  }
  const refusals = Array.isArray(report.refusals) ? report.refusals : [];
  const reasons = new Set(refusals.map((item) => item.reason_code));
  for (const reason of REQUIRED_REFUSAL_REASONS) {
    if (!reasons.has(reason)) {
      throw new Error(`Missing required downstream refusal reason: ${reason}`);
    }
  }
  for (const refusal of refusals) {
    if (
      refusal.boarded !== false ||
      refusal.decision !== 'refuse' ||
      refusal.marker_count_delta !== 0
    ) {
      throw new Error(`Downstream refusal case boarded unexpectedly: ${refusal.case_id || 'unknown'}`);
    }
  }
  if (report.marker?.final_count !== 1) {
    throw new Error('Downstream refusal proof must end with exactly one marker');
  }
  if (report.marker?.receipt_id_present !== true) {
    throw new Error('Downstream refusal proof marker must retain bounded receipt linkage');
  }
  if (report.marker?.raw_record_id_present !== false) {
    throw new Error('Downstream refusal proof marker leaked raw record id');
  }
  if (report.marker?.public_key_present !== false) {
    throw new Error('Downstream refusal proof marker leaked public key material');
  }
  assertNoUnsafeDownstreamRefusalProofText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeDownstreamRefusalProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`downstream refusal proof output contains ${label}`);
    }
  }
  return true;
}

export function formatDownstreamRefusalProofSummary(report) {
  const lines = [
    'Downstream Refusal Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Action class: ${report.action_class}`,
    `Downstream scope: ${report.deployment_scope}`,
    'Boarded:',
    `- ${report.recognized_boarding.case_id}: ${report.recognized_boarding.decision}; marker_delta=${report.recognized_boarding.marker_count_delta}`,
    'Refused:',
  ];
  for (const refusal of report.refusals) {
    lines.push(`- ${refusal.case_id}: ${refusal.reason_code}; marker_delta=${refusal.marker_count_delta}`);
  }
  lines.push(
    `Marker: final_count=${report.marker.final_count}; receipt_id_present=${report.marker.receipt_id_present}; raw_record_id_present=${report.marker.raw_record_id_present}; public_key_present=${report.marker.public_key_present}`,
    'Non-claims:'
  );
  for (const nonClaim of report.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  return `${lines.join('\n')}\n`;
}
