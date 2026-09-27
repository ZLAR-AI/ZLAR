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

export const APPROVAL_TRANSPORT_PROOF_TYPE = 'approval-transport-proof-v1';

export const SAFE_CLAIM_CEILING =
  'ZLAR can model human approval delivery as a replaceable local fixture transport boundary: unavailable transports fail closed, Telegram is not required by the proof path, and boarding still requires a signed human decision receipt.';

export const NON_CLAIMS = Object.freeze([
  'This proof uses local fixture transports only; it does not send Telegram, Slack, Teams, email, web, or hardware approval messages.',
  'This proof does not inspect live approval-channel configuration, live hooks, live audit stores, or runtime state.',
  'This proof does not prove any production approval transport is configured, healthy, or secure.',
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
    id: overrides.id || 'approval-transport-record-write-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || {
      record_alias: 'approval-transport-fixture-record',
      operation: 'update_status',
      approval_transport: 'reference-fixture-transport',
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

function caseReport({
  caseId,
  transportId,
  transportHealthy,
  deliveryAttempted,
  deliveryAccepted,
  receipt,
  decision,
  expectedReceiptId = null,
}) {
  return {
    case_id: caseId,
    transport_id: transportId,
    transport_healthy: transportHealthy,
    delivery_attempted: deliveryAttempted,
    delivery_accepted: deliveryAccepted,
    receipt_present: Boolean(receipt),
    receipt_id_matches_expected: receipt ? receipt.id === expectedReceiptId : false,
    boarded: decision.recognized,
    decision: decision.decision,
    reason_code: decision.reason_code,
    authorizer: receipt ? decodePayloadV1(receipt).authorizer : null,
    outcome: receipt ? decodePayloadV1(receipt).outcome : null,
  };
}

function transportEntries() {
  return [
    {
      transport_id: 'reference-fixture-transport',
      role: 'local proof reference transport',
      configured: true,
      healthy: true,
      live_delivery: false,
      sends_real_notification: false,
      required_for_fixture: true,
      status: 'healthy_fixture',
    },
    {
      transport_id: 'telegram-adapter',
      role: 'optional operator transport adapter',
      configured: false,
      healthy: false,
      live_delivery: false,
      sends_real_notification: false,
      required_for_fixture: false,
      status: 'not_configured_not_required_for_fixture',
    },
  ];
}

export function runApprovalTransportProof({
  nowEpoch = Math.floor(Date.now() / 1000),
} = {}) {
  const scratch = mkdtempSync(join(tmpdir(), 'zlar-approval-transport-'));
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
      deployment_scope: 'approval-transport-fixture',
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
      required_audit_event_id: 'approval-transport-record-write-001',
      required_detail_hash: authorizedPayload.detail_hash,
    };

    function recognize(receipt) {
      return evaluateDownstreamRecognition({
        receipt,
        recognition_rule: recognitionRule,
        now_epoch: nowEpoch,
      });
    }

    const unavailable = caseReport({
      caseId: 'transport_unavailable_without_receipt',
      transportId: 'reference-fixture-transport',
      transportHealthy: false,
      deliveryAttempted: false,
      deliveryAccepted: false,
      receipt: null,
      decision: recognize(null),
      expectedReceiptId: authorizedReceipt.id,
    });
    const pending = caseReport({
      caseId: 'transport_delivered_no_human_decision',
      transportId: 'reference-fixture-transport',
      transportHealthy: true,
      deliveryAttempted: true,
      deliveryAccepted: true,
      receipt: null,
      decision: recognize(null),
      expectedReceiptId: authorizedReceipt.id,
    });
    const authorized = caseReport({
      caseId: 'transport_delivered_signed_human_decision',
      transportId: 'reference-fixture-transport',
      transportHealthy: true,
      deliveryAttempted: true,
      deliveryAccepted: true,
      receipt: authorizedReceipt,
      decision: recognize(authorizedReceipt),
      expectedReceiptId: authorizedReceipt.id,
    });
    const telegramNotRequired = {
      case_id: 'telegram_adapter_not_configured_nonessential',
      transport_id: 'telegram-adapter',
      configured: false,
      required_for_fixture: false,
      live_probed: false,
      blocks_reference_fixture: false,
      status: 'not_configured_not_required_for_fixture',
    };

    return {
      proof_type: APPROVAL_TRANSPORT_PROOF_TYPE,
      evidence_model: 'local-hermetic-fixture',
      transport_model: 'channel-neutral-approval-transport-v1',
      live_probing: false,
      action_class: 'records.write',
      checkpoint_rule: 'RASK_RECORDS_WRITE',
      transports: transportEntries(),
      cases: {
        transport_unavailable: unavailable,
        delivered_without_decision: pending,
        signed_human_decision: authorized,
        telegram_not_required: telegramNotRequired,
      },
      receipt: {
        signed_human_decision_receipt_present: Boolean(authorizedReceipt.id),
        authorizer: authorizedPayload.authorizer,
        outcome: authorizedPayload.outcome,
        policy_version: authorizedPayload.policy_version,
        raw_detail_present: JSON.stringify(authorizedReceipt).includes('approval-transport-fixture-record'),
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

export function assertApprovalTransportProof(report) {
  if (!report || report.proof_type !== APPROVAL_TRANSPORT_PROOF_TYPE) {
    throw new Error('Approval transport proof has the wrong proof type');
  }
  if (report.evidence_model !== 'local-hermetic-fixture') {
    throw new Error('Approval transport proof must be local hermetic fixture evidence');
  }
  if (report.transport_model !== 'channel-neutral-approval-transport-v1') {
    throw new Error('Approval transport proof transport model drifted');
  }
  if (report.live_probing !== false) {
    throw new Error('Approval transport proof must not perform live probing');
  }
  if (report.safe_claim_ceiling !== SAFE_CLAIM_CEILING) {
    throw new Error('Approval transport proof safe claim ceiling drifted');
  }
  if (!Array.isArray(report.transports) || report.transports.length !== 2) {
    throw new Error('Approval transport proof must name exactly two fixture transports');
  }
  const reference = report.transports.find((item) => item.transport_id === 'reference-fixture-transport');
  if (
    !reference ||
    reference.configured !== true ||
    reference.healthy !== true ||
    reference.live_delivery !== false ||
    reference.sends_real_notification !== false ||
    reference.required_for_fixture !== true ||
    reference.status !== 'healthy_fixture'
  ) {
    throw new Error('Reference approval transport fixture drifted');
  }
  const telegram = report.transports.find((item) => item.transport_id === 'telegram-adapter');
  if (
    !telegram ||
    telegram.configured !== false ||
    telegram.healthy !== false ||
    telegram.live_delivery !== false ||
    telegram.sends_real_notification !== false ||
    telegram.required_for_fixture !== false ||
    telegram.status !== 'not_configured_not_required_for_fixture'
  ) {
    throw new Error('Telegram adapter nonessential fixture drifted');
  }

  const unavailable = report.cases?.transport_unavailable || {};
  if (
    unavailable.case_id !== 'transport_unavailable_without_receipt' ||
    unavailable.transport_healthy !== false ||
    unavailable.delivery_attempted !== false ||
    unavailable.delivery_accepted !== false ||
    unavailable.receipt_present !== false ||
    unavailable.boarded !== false ||
    unavailable.decision !== 'refuse' ||
    unavailable.reason_code !== 'receipt_missing'
  ) {
    throw new Error('Unavailable approval transport did not fail closed');
  }
  const pending = report.cases?.delivered_without_decision || {};
  if (
    pending.case_id !== 'transport_delivered_no_human_decision' ||
    pending.transport_healthy !== true ||
    pending.delivery_attempted !== true ||
    pending.delivery_accepted !== true ||
    pending.receipt_present !== false ||
    pending.boarded !== false ||
    pending.decision !== 'refuse' ||
    pending.reason_code !== 'receipt_missing'
  ) {
    throw new Error('Delivered ask without human decision boarded unexpectedly');
  }
  const authorized = report.cases?.signed_human_decision || {};
  if (
    authorized.case_id !== 'transport_delivered_signed_human_decision' ||
    authorized.transport_healthy !== true ||
    authorized.delivery_attempted !== true ||
    authorized.delivery_accepted !== true ||
    authorized.receipt_present !== true ||
    authorized.receipt_id_matches_expected !== true ||
    authorized.boarded !== true ||
    authorized.decision !== 'accept' ||
    authorized.reason_code !== 'recognized' ||
    authorized.authorizer !== 'human:fixture-operator' ||
    authorized.outcome !== 'authorized'
  ) {
    throw new Error('Signed human decision did not board through the reference transport fixture');
  }
  const telegramCase = report.cases?.telegram_not_required || {};
  if (
    telegramCase.case_id !== 'telegram_adapter_not_configured_nonessential' ||
    telegramCase.configured !== false ||
    telegramCase.required_for_fixture !== false ||
    telegramCase.live_probed !== false ||
    telegramCase.blocks_reference_fixture !== false ||
    telegramCase.status !== 'not_configured_not_required_for_fixture'
  ) {
    throw new Error('Telegram adapter nonessential case drifted');
  }
  if (report.receipt?.signed_human_decision_receipt_present !== true) {
    throw new Error('Approval transport proof must include a signed human decision receipt');
  }
  if (report.receipt?.authorizer !== 'human:fixture-operator') {
    throw new Error('Approval transport proof receipt authorizer drifted');
  }
  if (report.receipt?.outcome !== 'authorized') {
    throw new Error('Approval transport proof receipt outcome drifted');
  }
  if (report.receipt?.raw_detail_present !== false) {
    throw new Error('Approval transport proof leaked raw detail');
  }
  if (report.receipt?.public_key_present !== false) {
    throw new Error('Approval transport proof leaked public key material');
  }
  if (report.receipt?.private_key_present !== false) {
    throw new Error('Approval transport proof leaked private key material');
  }
  if (!Array.isArray(report.non_claims) || report.non_claims.length !== NON_CLAIMS.length) {
    throw new Error('Approval transport proof non-claims drifted');
  }
  assertNoUnsafeApprovalTransportProofText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeApprovalTransportProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`approval transport proof output contains ${label}`);
    }
  }
  return true;
}

export function formatApprovalTransportProofSummary(report) {
  const lines = [
    'Approval Transport Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Transport model: ${report.transport_model}`,
    'Transports:',
  ];
  for (const transport of report.transports) {
    lines.push(
      `- ${transport.transport_id}: configured=${transport.configured}; healthy=${transport.healthy}; live_delivery=${transport.live_delivery}; required_for_fixture=${transport.required_for_fixture}; status=${transport.status}`
    );
  }
  lines.push('Boarding cases:');
  lines.push(
    `- ${report.cases.transport_unavailable.case_id}: ${report.cases.transport_unavailable.decision}; reason=${report.cases.transport_unavailable.reason_code}`
  );
  lines.push(
    `- ${report.cases.delivered_without_decision.case_id}: ${report.cases.delivered_without_decision.decision}; reason=${report.cases.delivered_without_decision.reason_code}`
  );
  lines.push(
    `- ${report.cases.signed_human_decision.case_id}: ${report.cases.signed_human_decision.decision}; authorizer=${report.cases.signed_human_decision.authorizer}`
  );
  lines.push(
    `- ${report.cases.telegram_not_required.case_id}: status=${report.cases.telegram_not_required.status}; blocks_reference_fixture=${report.cases.telegram_not_required.blocks_reference_fixture}`
  );
  lines.push(
    `Receipt: signed_human_decision_receipt_present=${report.receipt.signed_human_decision_receipt_present}; authorizer=${report.receipt.authorizer}; outcome=${report.receipt.outcome}; raw_detail_present=${report.receipt.raw_detail_present}`
  );
  lines.push('Non-claims:');
  for (const nonClaim of report.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeApprovalTransportProofText(summary);
  return summary;
}
