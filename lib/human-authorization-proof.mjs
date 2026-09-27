import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
  signReceiptV1,
} from './receipt.mjs';
import { evaluateDownstreamRecognition } from './downstream-recognition-rule.mjs';

export const HUMAN_AUTHORIZATION_PROOF_TYPE = 'human-authorization-proof-v1';

export const SAFE_CLAIM_CEILING =
  'ZLAR can demonstrate, in a local hermetic fixture, that an ask-class action does not board until a simulated human authorization produces a signed receipt, and that simulated human denial does not board.';

export const NON_CLAIMS = Object.freeze([
  'This proof uses a simulated human decision fixture, not live Telegram or a real operator approval.',
  'This proof does not inspect live hooks, live audit stores, or live approval channels.',
  'This proof does not prove production deployment.',
  'This proof does not prove external attestation or sovereign recognition.',
  'This proof does not prove coverage of unrouted paths.',
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
    id: overrides.id || 'human-authorized-record-write-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || {
      record_alias: 'authorized-fixture-record',
      operation: 'update_status',
    },
    outcome: overrides.outcome || 'authorized',
    rule: overrides.rule || 'RASK_RECORDS_WRITE',
    authorizer: overrides.authorizer || 'human:fixture-operator',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function keyMaterial(scratch) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(scratch, 'issuer.pub');
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPem,
    kid: pubkeyFingerprint(publicPath),
  };
}

function caseReport({ caseId, receipt, decision, expectedReceiptId = null }) {
  return {
    case_id: caseId,
    receipt_present: Boolean(receipt),
    receipt_id_matches_expected: receipt ? receipt.id === expectedReceiptId : false,
    boarded: decision.recognized,
    decision: decision.decision,
    reason_code: decision.reason_code,
    authorizer: receipt ? decodePayloadV1(receipt).authorizer : null,
    outcome: receipt ? decodePayloadV1(receipt).outcome : null,
  };
}

export function runHumanAuthorizationProof({
  nowEpoch = Math.floor(Date.now() / 1000),
} = {}) {
  const scratch = mkdtempSync(join(tmpdir(), 'zlar-human-authorization-'));
  try {
    const issuer = keyMaterial(scratch);

    function signedReceipt(overrides = {}) {
      return signReceiptV1(
        createReceiptV1FromEvent(fixtureEvent(nowEpoch, overrides)),
        issuer.privatePem,
        issuer.kid
      );
    }

    const authorizedReceipt = signedReceipt();
    const authorizedPayload = decodePayloadV1(authorizedReceipt);
    const recognitionRule = {
      deployment_scope: 'human-authorization-fixture',
      accepted_issuers: [{
        kid: issuer.kid,
        public_key_pem: issuer.publicPem,
        status: 'active',
      }],
      accepted_policy_versions: ['recognition-policy-v1'],
      accepted_domains: ['records'],
      accepted_tools: ['records.write'],
      accepted_outcomes: ['authorized'],
      max_age_seconds: 120,
      required_audit_event_id: 'human-authorized-record-write-001',
      required_detail_hash: authorizedPayload.detail_hash,
    };

    function recognize(receipt) {
      return evaluateDownstreamRecognition({
        receipt,
        recognition_rule: recognitionRule,
        now_epoch: nowEpoch,
      });
    }

    const pending = caseReport({
      caseId: 'ask_pending_without_human_decision',
      receipt: null,
      decision: recognize(null),
      expectedReceiptId: authorizedReceipt.id,
    });
    const authorized = caseReport({
      caseId: 'simulated_human_approved',
      receipt: authorizedReceipt,
      decision: recognize(authorizedReceipt),
      expectedReceiptId: authorizedReceipt.id,
    });
    const deniedReceipt = signedReceipt({
      id: 'human-denied-record-write-001',
      outcome: 'denied',
      rule: 'RASK_RECORDS_WRITE',
      authorizer: 'human:fixture-operator',
    });
    const denied = caseReport({
      caseId: 'simulated_human_denied',
      receipt: deniedReceipt,
      decision: recognize(deniedReceipt),
      expectedReceiptId: deniedReceipt.id,
    });

    return {
      proof_type: HUMAN_AUTHORIZATION_PROOF_TYPE,
      evidence_model: 'local-hermetic-fixture',
      live_probing: false,
      approval_channel: 'simulated-human-fixture',
      action_class: 'records.write',
      checkpoint_rule: 'RASK_RECORDS_WRITE',
      pending_without_decision: pending,
      authorized_boarding: authorized,
      denied_boarding: denied,
      receipt: {
        authorized_receipt_present: Boolean(authorizedReceipt.id),
        authorizer: authorizedPayload.authorizer,
        outcome: authorizedPayload.outcome,
        policy_version: authorizedPayload.policy_version,
        raw_detail_present: JSON.stringify(authorizedReceipt).includes('authorized-fixture-record'),
        public_key_present: JSON.stringify(authorizedReceipt).includes('BEGIN PUBLIC KEY'),
        private_key_present: JSON.stringify(authorizedReceipt).includes('BEGIN PRIVATE KEY'),
      },
      safe_claim_ceiling: SAFE_CLAIM_CEILING,
      non_claims: [...NON_CLAIMS],
    };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

export function assertHumanAuthorizationProof(report) {
  if (!report || report.proof_type !== HUMAN_AUTHORIZATION_PROOF_TYPE) {
    throw new Error('Human authorization proof has the wrong proof type');
  }
  if (report.evidence_model !== 'local-hermetic-fixture') {
    throw new Error('Human authorization proof must be local hermetic fixture evidence');
  }
  if (report.live_probing !== false) {
    throw new Error('Human authorization proof must not perform live probing');
  }
  if (report.approval_channel !== 'simulated-human-fixture') {
    throw new Error('Human authorization proof must use simulated human approval channel');
  }
  const pending = report.pending_without_decision || {};
  if (
    pending.case_id !== 'ask_pending_without_human_decision' ||
    pending.receipt_present !== false ||
    pending.boarded !== false ||
    pending.decision !== 'refuse' ||
    pending.reason_code !== 'receipt_missing'
  ) {
    throw new Error('Pending ask without human decision boarded unexpectedly');
  }
  const authorized = report.authorized_boarding || {};
  if (
    authorized.case_id !== 'simulated_human_approved' ||
    authorized.receipt_present !== true ||
    authorized.receipt_id_matches_expected !== true ||
    authorized.boarded !== true ||
    authorized.decision !== 'accept' ||
    authorized.reason_code !== 'recognized' ||
    authorized.authorizer !== 'human:fixture-operator' ||
    authorized.outcome !== 'authorized'
  ) {
    throw new Error('Simulated human authorization did not produce recognized boarding');
  }
  const denied = report.denied_boarding || {};
  if (
    denied.case_id !== 'simulated_human_denied' ||
    denied.receipt_present !== true ||
    denied.boarded !== false ||
    denied.decision !== 'refuse' ||
    denied.reason_code !== 'outcome_not_boarding' ||
    denied.authorizer !== 'human:fixture-operator' ||
    denied.outcome !== 'denied'
  ) {
    throw new Error('Simulated human denial boarded unexpectedly');
  }
  if (report.receipt?.authorized_receipt_present !== true) {
    throw new Error('Human authorization proof must include an authorized receipt');
  }
  if (report.receipt?.authorizer !== 'human:fixture-operator') {
    throw new Error('Human authorization proof receipt authorizer drifted');
  }
  if (report.receipt?.outcome !== 'authorized') {
    throw new Error('Human authorization proof receipt outcome drifted');
  }
  if (report.receipt?.raw_detail_present !== false) {
    throw new Error('Human authorization proof leaked raw detail');
  }
  if (report.receipt?.public_key_present !== false) {
    throw new Error('Human authorization proof leaked public key material');
  }
  if (report.receipt?.private_key_present !== false) {
    throw new Error('Human authorization proof leaked private key material');
  }
  if (!Array.isArray(report.non_claims) || report.non_claims.length !== NON_CLAIMS.length) {
    throw new Error('Human authorization proof non-claims drifted');
  }
  assertNoUnsafeHumanAuthorizationProofText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeHumanAuthorizationProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`human authorization proof output contains ${label}`);
    }
  }
  return true;
}

export function formatHumanAuthorizationProofSummary(report) {
  const lines = [
    'Human Authorization Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Approval channel: ${report.approval_channel}`,
    `Action class: ${report.action_class}`,
    `Checkpoint rule: ${report.checkpoint_rule}`,
    'Boarding cases:',
    `- ${report.pending_without_decision.case_id}: ${report.pending_without_decision.decision}; reason=${report.pending_without_decision.reason_code}`,
    `- ${report.authorized_boarding.case_id}: ${report.authorized_boarding.decision}; authorizer=${report.authorized_boarding.authorizer}`,
    `- ${report.denied_boarding.case_id}: ${report.denied_boarding.decision}; reason=${report.denied_boarding.reason_code}`,
    `Receipt: authorized_receipt_present=${report.receipt.authorized_receipt_present}; authorizer=${report.receipt.authorizer}; outcome=${report.receipt.outcome}; raw_detail_present=${report.receipt.raw_detail_present}`,
    'Non-claims:',
  ];
  for (const nonClaim of report.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  return `${lines.join('\n')}\n`;
}
