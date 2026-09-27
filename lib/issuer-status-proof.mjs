import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createReceiptV1FromEvent,
  pubkeyFingerprint,
  signReceiptV1,
  verifyReceiptV1,
} from './receipt.mjs';
import { evaluateDownstreamRecognition } from './downstream-recognition-rule.mjs';

export const ISSUER_STATUS_PROOF_TYPE = 'issuer-status-proof-v1';

export const SAFE_CLAIM_CEILING =
  'ZLAR can demonstrate, in a local hermetic fixture, that one downstream recognition rule distinguishes active, retired, compromised, missing-status, unknown, and key-missing receipt issuers before accepting boarding.';

export const NON_CLAIMS = Object.freeze([
  'This proof uses ephemeral local fixture issuer keys, not live or production signing authority.',
  'This proof does not inspect live hooks, live audit stores, live trust registries, or runtime state.',
  'This proof does not prove key custody, key rotation operations, revocation infrastructure, or compromise response.',
  'This proof distinguishes cryptographic signature validity from issuer status recognition and downstream boarding.',
  'This proof does not prove production deployment.',
  'This proof does not prove external attestation or sovereign recognition.',
  'This proof does not prove coverage of unrouted paths.',
]);

export const REQUIRED_REFUSAL_REASONS = Object.freeze([
  'issuer_not_active',
  'issuer_compromised',
  'issuer_status_missing',
  'unknown_issuer',
  'issuer_key_missing',
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
    id: overrides.id || 'issuer-status-record-write-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || {
      record_alias: 'issuer-status-fixture-record',
      operation: 'update_status',
    },
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RISSUER_STATUS_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function keyMaterial(scratch, label) {
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

function diagnosticSignatureValid(receipt, publicKeyPem) {
  if (!receipt || !publicKeyPem) return null;
  try {
    return verifyReceiptV1(receipt, publicKeyPem).valid === true;
  } catch {
    return false;
  }
}

function caseReport({ caseId, receipt, decision, diagnosticPublicKeyPem = null }) {
  const evidence = decision.evidence || {};
  const signatureValid =
    typeof evidence.signature_valid === 'boolean'
      ? evidence.signature_valid
      : diagnosticSignatureValid(receipt, diagnosticPublicKeyPem);
  const issuerLifecycleStatusRecognized =
    evidence.issuer_known === true &&
    evidence.issuer_status === 'active' &&
    signatureValid === true;
  const issuerPublicKeyRecognizedForDownstream =
    issuerLifecycleStatusRecognized === true &&
    decision.reason_code !== 'issuer_key_missing';
  return {
    case_id: caseId,
    receipt_present: Boolean(receipt),
    issuer_key_id_present: Boolean(receipt?.kid),
    issuer_known: evidence.issuer_known ?? false,
    issuer_status: evidence.issuer_status ?? null,
    signature_valid: signatureValid,
    issuer_lifecycle_status_recognized: issuerLifecycleStatusRecognized,
    issuer_public_key_recognized_for_downstream: issuerPublicKeyRecognizedForDownstream,
    receipt_recognized_for_downstream: decision.recognized === true,
    boarded: decision.recognized,
    decision: decision.decision,
    reason_code: decision.reason_code,
    receipt_id_present: Boolean(evidence.receipt_id),
  };
}

export function runIssuerStatusProof({
  nowEpoch = Math.floor(Date.now() / 1000),
} = {}) {
  const scratch = mkdtempSync(join(tmpdir(), 'zlar-issuer-status-'));
  try {
    const active = keyMaterial(scratch, 'active-issuer');
    const retired = keyMaterial(scratch, 'retired-issuer');
    const compromised = keyMaterial(scratch, 'compromised-issuer');
    const missingStatus = keyMaterial(scratch, 'missing-status-issuer');
    const unknown = keyMaterial(scratch, 'unknown-issuer');
    const missingKey = keyMaterial(scratch, 'missing-key-issuer');

    function signedReceipt(key) {
      return signReceiptV1(
        createReceiptV1FromEvent(fixtureEvent(nowEpoch)),
        key.privatePem,
        key.kid
      );
    }

    const recognitionRule = {
      deployment_scope: 'issuer-status-fixture',
      accepted_issuers: [
        {
          kid: active.kid,
          public_key_pem: active.publicPem,
          status: 'active',
        },
        {
          kid: retired.kid,
          public_key_pem: retired.publicPem,
          status: 'retired',
        },
        {
          kid: compromised.kid,
          public_key_pem: compromised.publicPem,
          status: 'compromised',
        },
        {
          kid: missingStatus.kid,
          public_key_pem: missingStatus.publicPem,
        },
        {
          kid: missingKey.kid,
          status: 'active',
        },
      ],
      accepted_policy_versions: ['recognition-policy-v1'],
      accepted_domains: ['records'],
      accepted_tools: ['records.write'],
      accepted_outcomes: ['allow'],
      max_age_seconds: 120,
      required_audit_event_id: 'issuer-status-record-write-001',
    };

    function recognize(receipt) {
      return evaluateDownstreamRecognition({
        receipt,
        recognition_rule: recognitionRule,
        now_epoch: nowEpoch,
      });
    }

    const activeReceipt = signedReceipt(active);
    const retiredReceipt = signedReceipt(retired);
    const compromisedReceipt = signedReceipt(compromised);
    const missingStatusReceipt = signedReceipt(missingStatus);
    const unknownReceipt = signedReceipt(unknown);
    const missingKeyReceipt = signedReceipt(missingKey);

    const activeIssuer = caseReport({
      caseId: 'active_issuer_recognized',
      receipt: activeReceipt,
      decision: recognize(activeReceipt),
      diagnosticPublicKeyPem: active.publicPem,
    });
    const retiredIssuer = caseReport({
      caseId: 'retired_issuer_refused',
      receipt: retiredReceipt,
      decision: recognize(retiredReceipt),
      diagnosticPublicKeyPem: retired.publicPem,
    });
    const compromisedIssuer = caseReport({
      caseId: 'compromised_issuer_refused',
      receipt: compromisedReceipt,
      decision: recognize(compromisedReceipt),
      diagnosticPublicKeyPem: compromised.publicPem,
    });
    const missingStatusIssuer = caseReport({
      caseId: 'missing_status_issuer_refused',
      receipt: missingStatusReceipt,
      decision: recognize(missingStatusReceipt),
      diagnosticPublicKeyPem: missingStatus.publicPem,
    });
    const unknownIssuer = caseReport({
      caseId: 'unknown_issuer_refused',
      receipt: unknownReceipt,
      decision: recognize(unknownReceipt),
      diagnosticPublicKeyPem: unknown.publicPem,
    });
    const missingKeyIssuer = caseReport({
      caseId: 'missing_key_issuer_refused',
      receipt: missingKeyReceipt,
      decision: recognize(missingKeyReceipt),
      diagnosticPublicKeyPem: missingKey.publicPem,
    });

    const report = {
      proof_type: ISSUER_STATUS_PROOF_TYPE,
      evidence_model: 'local-hermetic-fixture',
      live_probing: false,
      trust_anchor_model: 'local-fixture-recognition-rule',
      action_class: 'records.write',
      active_issuer: activeIssuer,
      retired_issuer: retiredIssuer,
      compromised_issuer: compromisedIssuer,
      missing_status_issuer: missingStatusIssuer,
      unknown_issuer: unknownIssuer,
      missing_key_issuer: missingKeyIssuer,
      issuer_boundary: {
        active_issuer_boards: activeIssuer.boarded === true,
        retired_issuer_refuses: retiredIssuer.reason_code === 'issuer_not_active',
        compromised_issuer_refuses: compromisedIssuer.reason_code === 'issuer_compromised',
        missing_status_issuer_refuses: missingStatusIssuer.reason_code === 'issuer_status_missing',
        unknown_issuer_refuses: unknownIssuer.reason_code === 'unknown_issuer',
        missing_key_issuer_refuses: missingKeyIssuer.reason_code === 'issuer_key_missing',
        valid_retired_signature_refuses:
          retiredIssuer.signature_valid === true &&
          retiredIssuer.issuer_lifecycle_status_recognized === false &&
          retiredIssuer.receipt_recognized_for_downstream === false,
        valid_compromised_signature_refuses:
          compromisedIssuer.signature_valid === true &&
          compromisedIssuer.issuer_lifecycle_status_recognized === false &&
          compromisedIssuer.receipt_recognized_for_downstream === false,
        valid_unknown_signature_refuses:
          unknownIssuer.signature_valid === true &&
          unknownIssuer.issuer_lifecycle_status_recognized === false &&
          unknownIssuer.receipt_recognized_for_downstream === false,
        active_lifecycle_without_public_key_refuses:
          missingKeyIssuer.signature_valid === true &&
          missingKeyIssuer.issuer_lifecycle_status_recognized === true &&
          missingKeyIssuer.issuer_public_key_recognized_for_downstream === false &&
          missingKeyIssuer.receipt_recognized_for_downstream === false,
        raw_public_key_material_included: false,
        raw_private_key_material_included: false,
      },
      safe_claim_ceiling: SAFE_CLAIM_CEILING,
      non_claims: [...NON_CLAIMS],
    };
    assertIssuerStatusProof(report);
    return report;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

export function assertIssuerStatusProof(report) {
  if (!report || report.proof_type !== ISSUER_STATUS_PROOF_TYPE) {
    throw new Error('Issuer status proof has the wrong proof type');
  }
  if (report.evidence_model !== 'local-hermetic-fixture') {
    throw new Error('Issuer status proof must be local hermetic fixture evidence');
  }
  if (report.live_probing !== false) {
    throw new Error('Issuer status proof must not perform live probing');
  }
  if (report.trust_anchor_model !== 'local-fixture-recognition-rule') {
    throw new Error('Issuer status proof has the wrong trust anchor model');
  }

  const activeIssuer = report.active_issuer || {};
  if (
    activeIssuer.case_id !== 'active_issuer_recognized' ||
    activeIssuer.receipt_present !== true ||
    activeIssuer.issuer_key_id_present !== true ||
    activeIssuer.issuer_known !== true ||
    activeIssuer.issuer_status !== 'active' ||
    activeIssuer.signature_valid !== true ||
    activeIssuer.issuer_lifecycle_status_recognized !== true ||
    activeIssuer.issuer_public_key_recognized_for_downstream !== true ||
    activeIssuer.receipt_recognized_for_downstream !== true ||
    activeIssuer.boarded !== true ||
    activeIssuer.decision !== 'accept' ||
    activeIssuer.reason_code !== 'recognized' ||
    activeIssuer.receipt_id_present !== true
  ) {
    throw new Error('Active issuer was not recognized');
  }

  const retiredIssuer = report.retired_issuer || {};
  if (
    retiredIssuer.case_id !== 'retired_issuer_refused' ||
    retiredIssuer.receipt_present !== true ||
    retiredIssuer.issuer_key_id_present !== true ||
    retiredIssuer.issuer_known !== true ||
    retiredIssuer.issuer_status !== 'retired' ||
    retiredIssuer.signature_valid !== true ||
    retiredIssuer.issuer_lifecycle_status_recognized !== false ||
    retiredIssuer.issuer_public_key_recognized_for_downstream !== false ||
    retiredIssuer.receipt_recognized_for_downstream !== false ||
    retiredIssuer.boarded !== false ||
    retiredIssuer.decision !== 'refuse' ||
    retiredIssuer.reason_code !== 'issuer_not_active' ||
    retiredIssuer.receipt_id_present !== false
  ) {
    throw new Error('Retired issuer did not refuse before boarding');
  }

  const compromisedIssuer = report.compromised_issuer || {};
  if (
    compromisedIssuer.case_id !== 'compromised_issuer_refused' ||
    compromisedIssuer.receipt_present !== true ||
    compromisedIssuer.issuer_key_id_present !== true ||
    compromisedIssuer.issuer_known !== true ||
    compromisedIssuer.issuer_status !== 'compromised' ||
    compromisedIssuer.signature_valid !== true ||
    compromisedIssuer.issuer_lifecycle_status_recognized !== false ||
    compromisedIssuer.issuer_public_key_recognized_for_downstream !== false ||
    compromisedIssuer.receipt_recognized_for_downstream !== false ||
    compromisedIssuer.boarded !== false ||
    compromisedIssuer.decision !== 'refuse' ||
    compromisedIssuer.reason_code !== 'issuer_compromised' ||
    compromisedIssuer.receipt_id_present !== false
  ) {
    throw new Error('Compromised issuer did not refuse before boarding');
  }

  const missingStatusIssuer = report.missing_status_issuer || {};
  if (
    missingStatusIssuer.case_id !== 'missing_status_issuer_refused' ||
    missingStatusIssuer.receipt_present !== true ||
    missingStatusIssuer.issuer_key_id_present !== true ||
    missingStatusIssuer.issuer_known !== true ||
    missingStatusIssuer.issuer_status !== null ||
    missingStatusIssuer.signature_valid !== true ||
    missingStatusIssuer.issuer_lifecycle_status_recognized !== false ||
    missingStatusIssuer.issuer_public_key_recognized_for_downstream !== false ||
    missingStatusIssuer.receipt_recognized_for_downstream !== false ||
    missingStatusIssuer.boarded !== false ||
    missingStatusIssuer.decision !== 'refuse' ||
    missingStatusIssuer.reason_code !== 'issuer_status_missing' ||
    missingStatusIssuer.receipt_id_present !== false
  ) {
    throw new Error('Missing-status issuer did not refuse before boarding');
  }

  const unknownIssuer = report.unknown_issuer || {};
  if (
    unknownIssuer.case_id !== 'unknown_issuer_refused' ||
    unknownIssuer.receipt_present !== true ||
    unknownIssuer.issuer_key_id_present !== true ||
    unknownIssuer.issuer_known !== false ||
    unknownIssuer.issuer_status !== null ||
    unknownIssuer.signature_valid !== true ||
    unknownIssuer.issuer_lifecycle_status_recognized !== false ||
    unknownIssuer.issuer_public_key_recognized_for_downstream !== false ||
    unknownIssuer.receipt_recognized_for_downstream !== false ||
    unknownIssuer.boarded !== false ||
    unknownIssuer.decision !== 'refuse' ||
    unknownIssuer.reason_code !== 'unknown_issuer' ||
    unknownIssuer.receipt_id_present !== false
  ) {
    throw new Error('Unknown issuer did not refuse before boarding');
  }

  const missingKeyIssuer = report.missing_key_issuer || {};
  if (
    missingKeyIssuer.case_id !== 'missing_key_issuer_refused' ||
    missingKeyIssuer.receipt_present !== true ||
    missingKeyIssuer.issuer_key_id_present !== true ||
    missingKeyIssuer.issuer_known !== true ||
    missingKeyIssuer.issuer_status !== 'active' ||
    missingKeyIssuer.signature_valid !== true ||
    missingKeyIssuer.issuer_lifecycle_status_recognized !== true ||
    missingKeyIssuer.issuer_public_key_recognized_for_downstream !== false ||
    missingKeyIssuer.receipt_recognized_for_downstream !== false ||
    missingKeyIssuer.boarded !== false ||
    missingKeyIssuer.decision !== 'refuse' ||
    missingKeyIssuer.reason_code !== 'issuer_key_missing' ||
    missingKeyIssuer.receipt_id_present !== false
  ) {
    throw new Error('Missing-key issuer did not refuse before boarding');
  }

  const boundary = report.issuer_boundary || {};
  if (
    boundary.active_issuer_boards !== true ||
    boundary.retired_issuer_refuses !== true ||
    boundary.compromised_issuer_refuses !== true ||
    boundary.missing_status_issuer_refuses !== true ||
    boundary.unknown_issuer_refuses !== true ||
    boundary.missing_key_issuer_refuses !== true ||
    boundary.valid_retired_signature_refuses !== true ||
    boundary.valid_compromised_signature_refuses !== true ||
    boundary.valid_unknown_signature_refuses !== true ||
    boundary.active_lifecycle_without_public_key_refuses !== true ||
    boundary.raw_public_key_material_included !== false ||
    boundary.raw_private_key_material_included !== false
  ) {
    throw new Error('Issuer status boundary drifted');
  }

  if (!Array.isArray(report.non_claims) || report.non_claims.length !== NON_CLAIMS.length) {
    throw new Error('Issuer status proof non-claims drifted');
  }
  assertNoUnsafeIssuerStatusProofText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeIssuerStatusProofText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_OUTPUT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`issuer status proof output contains ${label}`);
    }
  }
  return true;
}

export function formatIssuerStatusProofSummary(report) {
  const lines = [
    'Issuer Status Proof v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model}; live probing=${report.live_probing}`,
    `Trust anchor model: ${report.trust_anchor_model}`,
    `Action class: ${report.action_class}`,
    'Recognition split: signature_valid is distinct from issuer_lifecycle_status_recognized, issuer_public_key_recognized_for_downstream, and receipt_recognized_for_downstream.',
    'Issuer cases:',
    `- ${report.active_issuer.case_id}: ${report.active_issuer.decision}; issuer_status=${report.active_issuer.issuer_status}; signature_valid=${report.active_issuer.signature_valid}`,
    `- ${report.retired_issuer.case_id}: ${report.retired_issuer.decision}; reason=${report.retired_issuer.reason_code}; issuer_status=${report.retired_issuer.issuer_status}; signature_valid=${report.retired_issuer.signature_valid}; downstream_key_recognized=${report.retired_issuer.issuer_public_key_recognized_for_downstream}; downstream_recognized=${report.retired_issuer.receipt_recognized_for_downstream}`,
    `- ${report.compromised_issuer.case_id}: ${report.compromised_issuer.decision}; reason=${report.compromised_issuer.reason_code}; issuer_status=${report.compromised_issuer.issuer_status}; signature_valid=${report.compromised_issuer.signature_valid}; downstream_key_recognized=${report.compromised_issuer.issuer_public_key_recognized_for_downstream}; downstream_recognized=${report.compromised_issuer.receipt_recognized_for_downstream}`,
    `- ${report.missing_status_issuer.case_id}: ${report.missing_status_issuer.decision}; reason=${report.missing_status_issuer.reason_code}; issuer_status=${report.missing_status_issuer.issuer_status}; signature_valid=${report.missing_status_issuer.signature_valid}; downstream_key_recognized=${report.missing_status_issuer.issuer_public_key_recognized_for_downstream}; downstream_recognized=${report.missing_status_issuer.receipt_recognized_for_downstream}`,
    `- ${report.unknown_issuer.case_id}: ${report.unknown_issuer.decision}; reason=${report.unknown_issuer.reason_code}; issuer_known=${report.unknown_issuer.issuer_known}; signature_valid=${report.unknown_issuer.signature_valid}; downstream_key_recognized=${report.unknown_issuer.issuer_public_key_recognized_for_downstream}; downstream_recognized=${report.unknown_issuer.receipt_recognized_for_downstream}`,
    `- ${report.missing_key_issuer.case_id}: ${report.missing_key_issuer.decision}; reason=${report.missing_key_issuer.reason_code}; issuer_status=${report.missing_key_issuer.issuer_status}; signature_valid=${report.missing_key_issuer.signature_valid}; downstream_key_recognized=${report.missing_key_issuer.issuer_public_key_recognized_for_downstream}; downstream_recognized=${report.missing_key_issuer.receipt_recognized_for_downstream}`,
    'Non-claims:',
  ];
  for (const nonClaim of report.non_claims) {
    lines.push(`- ${nonClaim}`);
  }
  const summary = `${lines.join('\n')}\n`;
  assertNoUnsafeIssuerStatusProofText(summary);
  return summary;
}
