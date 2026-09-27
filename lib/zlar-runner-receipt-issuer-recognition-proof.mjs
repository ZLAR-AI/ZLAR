#!/usr/bin/env node
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
  signReceiptV1,
  verifyReceiptV1
} from './receipt.mjs';
import { evaluateDownstreamRecognition } from './downstream-recognition-rule.mjs';

export const PROOF_TYPE = 'zlar-runner-receipt-issuer-recognition-proof-v1';
export const EVIDENCE_MODEL = 'local-hermetic-runner-receipt-issuer-recognition-fixture';
export const RECEIPT_FORMAT = 'governed-action-v1';
export const RUNNER_SCOPE = 'zlar-run-owned-runner-surface';
export const RUNNER_TOOL = 'Bash';
export const RUNNER_DOMAIN = 'bash';
export const RUNNER_POLICY_VERSION = 'runner-receipt-binding-v1';

export const SAFE_CLAIM =
  'ZLAR can locally demonstrate that signed v1 zlar run proof receipts are distinct from fixture issuer recognition, and both remain distinct from production issuer authority.';

export const FORBIDDEN_CLAIMS = [
  'production issuer trust',
  'production issuer custody',
  'downstream production recognition',
  'raw Codex desktop/developer-tool governance',
  'arbitrary current-machine governance',
  'all-surface governance',
  'side-door closure',
  'absolute human intention'
];

const REQUIRED_CASE_IDS = [
  'active_allow_recognized',
  'active_deny_recognized_not_boarding',
  'retired_issuer_refused',
  'compromised_issuer_refused',
  'missing_status_refused',
  'unknown_issuer_refused',
  'missing_public_key_refused',
  'wrong_policy_refused',
  'wrong_domain_refused',
  'wrong_tool_refused',
  'wrong_audit_event_id_refused',
  'wrong_detail_hash_refused',
  'stale_receipt_refused',
  'valid_proof_key_receipt_not_recognized'
];

const EXPECTED_REFUSAL_REASONS = new Map([
  ['retired_issuer_refused', 'issuer_not_active'],
  ['compromised_issuer_refused', 'issuer_compromised'],
  ['missing_status_refused', 'issuer_status_missing'],
  ['unknown_issuer_refused', 'unknown_issuer'],
  ['missing_public_key_refused', 'issuer_key_missing'],
  ['wrong_policy_refused', 'policy_not_recognized'],
  ['wrong_domain_refused', 'domain_out_of_scope'],
  ['wrong_tool_refused', 'tool_out_of_scope'],
  ['wrong_audit_event_id_refused', 'audit_event_mismatch'],
  ['wrong_detail_hash_refused', 'detail_hash_mismatch'],
  ['stale_receipt_refused', 'receipt_stale'],
  ['valid_proof_key_receipt_not_recognized', 'unknown_issuer']
]);

function sha256(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}

function isoFromEpoch(epochSeconds) {
  return new Date(epochSeconds * 1000).toISOString();
}

function runnerDetail(label) {
  return {
    runner_contract: 'zlar-owned-enforceable-runner-v1',
    command_material_model: 'sha256-redacted',
    requested_command_sha256: sha256(`${label}:requested-command`),
    effective_command_sha256: sha256(`${label}:effective-command`),
    lexical_cwd_sha256: sha256(`${label}:lexical-cwd`),
    canonical_cwd_sha256: sha256(`${label}:canonical-cwd`)
  };
}

function eventFromParts({
  id,
  ts,
  outcome,
  rule = 'runner.fixture.rule',
  authorizer = 'zlar-runner-fixture',
  policyVersion = RUNNER_POLICY_VERSION,
  action = RUNNER_TOOL,
  domain = RUNNER_DOMAIN,
  detail = runnerDetail(outcome)
}) {
  return {
    id,
    ts,
    action,
    domain,
    detail,
    outcome,
    rule,
    authorizer,
    policy_version: policyVersion,
    prev_hash: sha256(`${id}:previous-audit-entry`)
  };
}

function makeKeyMaterial(scratchDir, label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pair = {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' })
  };
  const publicKeyPath = join(scratchDir, `${label}.public.pem`);
  writeFileSync(publicKeyPath, pair.publicKeyPem, { mode: 0o600 });
  const kid = pubkeyFingerprint(publicKeyPath);
  return {
    kid,
    publicKeyPem: pair.publicKeyPem,
    privateKeyPem: pair.privateKeyPem
  };
}

function signEventWithIssuer(event, issuer) {
  const receipt = createReceiptV1FromEvent(event, {
    kid: issuer.kid,
    actor: 'zlar-runner-fixture',
    reason: 'local hermetic runner issuer-recognition proof'
  });
  return signReceiptV1(receipt, issuer.privateKeyPem, issuer.kid);
}

function publicIssuerRecord(issuer, status = 'active', options = {}) {
  const record = {
    kid: issuer.kid,
    status
  };
  if (options.includePublicKey !== false) {
    record.public_key_pem = issuer.publicKeyPem;
  }
  return record;
}

function recognitionRule({
  issuers,
  requiredAuditEventId,
  requiredDetailHash,
  acceptedPolicyVersions = [RUNNER_POLICY_VERSION],
  acceptedDomains = [RUNNER_DOMAIN],
  acceptedTools = [RUNNER_TOOL],
  acceptedOutcomes = ['allow', 'deny'],
  maxAgeSeconds = 120
}) {
  return {
    rule_id: 'zlar-runner-fixture-recognition-rule',
    deployment_scope: RUNNER_SCOPE,
    accepted_issuers: issuers,
    accepted_policy_versions: acceptedPolicyVersions,
    accepted_domains: acceptedDomains,
    accepted_tools: acceptedTools,
    accepted_outcomes: acceptedOutcomes,
    required_audit_event_id: requiredAuditEventId,
    required_detail_hash: requiredDetailHash,
    max_age_seconds: maxAgeSeconds
  };
}

function verifiedPayload(receipt, publicKeyPem) {
  const verified = verifyReceiptV1(receipt, publicKeyPem);
  let payload = null;
  try {
    payload = decodePayloadV1(receipt);
  } catch {
    payload = null;
  }
  return { verified, payload };
}

function classifyBoardingEffect({ recognized, payload }) {
  if (!recognized) return 'refused';
  if (payload?.outcome === 'allow') return 'allow_can_board';
  if (payload?.outcome === 'deny') return 'deny_decision_record_not_boarding';
  return 'recognized_non_boarding';
}

function caseResult({ id, description, receipt, publicKeyPem, rule, nowEpoch }) {
  const { verified, payload } = verifiedPayload(receipt, publicKeyPem);
  const decision = evaluateDownstreamRecognition({
    receipt,
    recognition_rule: rule,
    now_epoch: nowEpoch
  });
  const recognized = decision.recognized === true;
  const boardingEffect = classifyBoardingEffect({ recognized, payload });

  return {
    id,
    description,
    receipt_valid: verified.valid === true,
    issuer_known: decision.evidence?.issuer_known === true,
    issuer_status: decision.evidence?.issuer_status ?? null,
    recognized_for_runner_scope: recognized,
    decision: decision.decision,
    reason_code: decision.reason_code,
    receipt_id: receipt.id,
    receipt_kid: receipt.kid,
    receipt_outcome: payload?.outcome ?? null,
    audit_event_id: payload?.audit_event_id ?? null,
    audit_prev_hash: payload?.audit_prev_hash ?? null,
    policy_version: payload?.policy_version ?? null,
    detail_hash: payload?.detail_hash ?? null,
    rule: payload?.rule ?? null,
    authorizer: payload?.authorizer ?? null,
    boarding_effect: boardingEffect,
    boards: boardingEffect === 'allow_can_board',
    production_trust: false,
    custody_proven: false,
    downstream_production_recognition: false,
    all_surface_governance: false
  };
}

function assertReportShape(report) {
  const caseIds = report.cases.map((item) => item.id);
  if (caseIds.length !== REQUIRED_CASE_IDS.length) {
    throw new Error(`expected ${REQUIRED_CASE_IDS.length} cases, got ${caseIds.length}`);
  }
  for (const id of REQUIRED_CASE_IDS) {
    if (!caseIds.includes(id)) {
      throw new Error(`missing proof case: ${id}`);
    }
  }

  const byId = new Map(report.cases.map((item) => [item.id, item]));
  const activeAllow = byId.get('active_allow_recognized');
  if (!activeAllow.receipt_valid || !activeAllow.recognized_for_runner_scope || activeAllow.boarding_effect !== 'allow_can_board') {
    throw new Error('active allow fixture was not recognized as boarding-capable for the runner scope');
  }

  const activeDeny = byId.get('active_deny_recognized_not_boarding');
  if (!activeDeny.receipt_valid || !activeDeny.recognized_for_runner_scope || activeDeny.boards !== false || activeDeny.boarding_effect !== 'deny_decision_record_not_boarding') {
    throw new Error('active deny fixture did not remain a recognized non-boarding decision record');
  }

  for (const [id, reason] of EXPECTED_REFUSAL_REASONS.entries()) {
    const item = byId.get(id);
    if (!item) throw new Error(`missing refusal case ${id}`);
    if (item.recognized_for_runner_scope !== false || item.decision !== 'refuse' || item.reason_code !== reason) {
      throw new Error(`${id} expected refusal ${reason}, got ${item.reason_code}`);
    }
    if (item.receipt_valid !== true) {
      throw new Error(`${id} should keep receipt byte validity separate from recognition refusal`);
    }
  }

  for (const item of report.cases) {
    if (item.production_trust || item.custody_proven || item.downstream_production_recognition || item.all_surface_governance) {
      throw new Error(`${item.id} leaked a forbidden production/all-surface claim`);
    }
  }

  if (report.production_trust || report.custody_proven || report.downstream_production_recognition || report.all_surface_governance) {
    throw new Error('top-level report leaked a forbidden production/all-surface claim');
  }
}

export function assertNoUnsafeProofText(text) {
  const forbidden = [
    'BEGIN PRIVATE KEY',
    'BEGIN PUBLIC KEY',
    'PRIVATE KEY',
    'public_key_pem',
    'privateKeyPem',
    '/Users/',
    '/tmp/',
    'Documents/ZLAR'
  ];
  for (const needle of forbidden) {
    if (text.includes(needle)) {
      throw new Error(`unsafe proof output includes ${needle}`);
    }
  }
  return true;
}

export function runZlarRunnerReceiptIssuerRecognitionProof(options = {}) {
  const nowEpoch = Number.isInteger(options.nowEpoch)
    ? options.nowEpoch
    : Math.floor(Date.now() / 1000);
  const scratchDir = mkdtempSync(join(tmpdir(), 'zlar-runner-issuer-proof-'));

  try {
    const activeIssuer = makeKeyMaterial(scratchDir, 'active');
    const retiredIssuer = makeKeyMaterial(scratchDir, 'retired');
    const compromisedIssuer = makeKeyMaterial(scratchDir, 'compromised');
    const missingStatusIssuer = makeKeyMaterial(scratchDir, 'missing-status');
    const missingPublicKeyIssuer = makeKeyMaterial(scratchDir, 'missing-public-key');
    const unknownIssuer = makeKeyMaterial(scratchDir, 'unknown');
    const proofOnlyIssuer = makeKeyMaterial(scratchDir, 'proof-only');

    const allowEvent = eventFromParts({
      id: 'runner-fixture-audit-allow-001',
      ts: isoFromEpoch(nowEpoch - 10),
      outcome: 'allow',
      rule: 'runner.fixture.allow',
      authorizer: 'policy'
    });
    const denyEvent = eventFromParts({
      id: 'runner-fixture-audit-deny-001',
      ts: isoFromEpoch(nowEpoch - 10),
      outcome: 'deny',
      rule: 'runner.fixture.deny',
      authorizer: 'policy',
      detail: runnerDetail('deny')
    });

    const allowReceipt = signEventWithIssuer(allowEvent, activeIssuer);
    const denyReceipt = signEventWithIssuer(denyEvent, activeIssuer);
    const allowPayload = decodePayloadV1(allowReceipt);
    const denyPayload = decodePayloadV1(denyReceipt);

    const activeIssuerRecord = publicIssuerRecord(activeIssuer, 'active');
    const baseAllowRule = recognitionRule({
      issuers: [activeIssuerRecord],
      requiredAuditEventId: allowPayload.audit_event_id,
      requiredDetailHash: allowPayload.detail_hash
    });
    const baseDenyRule = recognitionRule({
      issuers: [activeIssuerRecord],
      requiredAuditEventId: denyPayload.audit_event_id,
      requiredDetailHash: denyPayload.detail_hash
    });

    const staleReceipt = signEventWithIssuer(
      eventFromParts({
        id: allowPayload.audit_event_id,
        ts: isoFromEpoch(nowEpoch - 600),
        outcome: 'allow',
        rule: 'runner.fixture.allow',
        authorizer: 'policy',
        detail: runnerDetail('allow')
      }),
      activeIssuer
    );

    const wrongDetailReceipt = signEventWithIssuer(
      eventFromParts({
        id: allowPayload.audit_event_id,
        ts: isoFromEpoch(nowEpoch - 10),
        outcome: 'allow',
        rule: 'runner.fixture.allow',
        authorizer: 'policy',
        detail: runnerDetail('wrong-detail')
      }),
      activeIssuer
    );

    const cases = [
      caseResult({
        id: 'active_allow_recognized',
        description: 'active fixture issuer recognized for a runner allow receipt',
        receipt: allowReceipt,
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'active_deny_recognized_not_boarding',
        description: 'active fixture issuer recognized for deny as a decision record, not boarding',
        receipt: denyReceipt,
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseDenyRule,
        nowEpoch
      }),
      caseResult({
        id: 'retired_issuer_refused',
        description: 'retired issuer is refused despite valid receipt bytes',
        receipt: signEventWithIssuer(allowEvent, retiredIssuer),
        publicKeyPem: retiredIssuer.publicKeyPem,
        rule: recognitionRule({
          issuers: [publicIssuerRecord(retiredIssuer, 'retired')],
          requiredAuditEventId: allowPayload.audit_event_id,
          requiredDetailHash: allowPayload.detail_hash
        }),
        nowEpoch
      }),
      caseResult({
        id: 'compromised_issuer_refused',
        description: 'compromised issuer is refused despite valid receipt bytes',
        receipt: signEventWithIssuer(allowEvent, compromisedIssuer),
        publicKeyPem: compromisedIssuer.publicKeyPem,
        rule: recognitionRule({
          issuers: [publicIssuerRecord(compromisedIssuer, 'compromised')],
          requiredAuditEventId: allowPayload.audit_event_id,
          requiredDetailHash: allowPayload.detail_hash
        }),
        nowEpoch
      }),
      caseResult({
        id: 'missing_status_refused',
        description: 'issuer record without status is refused',
        receipt: signEventWithIssuer(allowEvent, missingStatusIssuer),
        publicKeyPem: missingStatusIssuer.publicKeyPem,
        rule: recognitionRule({
          issuers: [{ kid: missingStatusIssuer.kid, public_key_pem: missingStatusIssuer.publicKeyPem }],
          requiredAuditEventId: allowPayload.audit_event_id,
          requiredDetailHash: allowPayload.detail_hash
        }),
        nowEpoch
      }),
      caseResult({
        id: 'unknown_issuer_refused',
        description: 'issuer not listed in the fixture recognition rule is refused',
        receipt: signEventWithIssuer(allowEvent, unknownIssuer),
        publicKeyPem: unknownIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'missing_public_key_refused',
        description: 'recognized kid without public key is refused',
        receipt: signEventWithIssuer(allowEvent, missingPublicKeyIssuer),
        publicKeyPem: missingPublicKeyIssuer.publicKeyPem,
        rule: recognitionRule({
          issuers: [publicIssuerRecord(missingPublicKeyIssuer, 'active', { includePublicKey: false })],
          requiredAuditEventId: allowPayload.audit_event_id,
          requiredDetailHash: allowPayload.detail_hash
        }),
        nowEpoch
      }),
      caseResult({
        id: 'wrong_policy_refused',
        description: 'wrong policy version is refused',
        receipt: signEventWithIssuer(
          eventFromParts({
            id: allowPayload.audit_event_id,
            ts: isoFromEpoch(nowEpoch - 10),
            outcome: 'allow',
            rule: 'runner.fixture.allow',
            authorizer: 'policy',
            policyVersion: 'wrong-policy-version'
          }),
          activeIssuer
        ),
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'wrong_domain_refused',
        description: 'wrong domain is refused',
        receipt: signEventWithIssuer(
          eventFromParts({
            id: allowPayload.audit_event_id,
            ts: isoFromEpoch(nowEpoch - 10),
            outcome: 'allow',
            rule: 'runner.fixture.allow',
            authorizer: 'policy',
            domain: 'wrong-domain'
          }),
          activeIssuer
        ),
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'wrong_tool_refused',
        description: 'wrong tool is refused',
        receipt: signEventWithIssuer(
          eventFromParts({
            id: allowPayload.audit_event_id,
            ts: isoFromEpoch(nowEpoch - 10),
            outcome: 'allow',
            rule: 'runner.fixture.allow',
            authorizer: 'policy',
            action: 'Write'
          }),
          activeIssuer
        ),
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'wrong_audit_event_id_refused',
        description: 'wrong audit event id is refused',
        receipt: signEventWithIssuer(
          eventFromParts({
            id: 'runner-fixture-audit-allow-other',
            ts: isoFromEpoch(nowEpoch - 10),
            outcome: 'allow',
            rule: 'runner.fixture.allow',
            authorizer: 'policy'
          }),
          activeIssuer
        ),
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'wrong_detail_hash_refused',
        description: 'wrong detail hash is refused',
        receipt: wrongDetailReceipt,
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'stale_receipt_refused',
        description: 'locally stale receipt is refused by the recognition rule freshness window',
        receipt: staleReceipt,
        publicKeyPem: activeIssuer.publicKeyPem,
        rule: baseAllowRule,
        nowEpoch
      }),
      caseResult({
        id: 'valid_proof_key_receipt_not_recognized',
        description: 'valid proof-key receipt is not recognized when no rule accepts its kid',
        receipt: signEventWithIssuer(allowEvent, proofOnlyIssuer),
        publicKeyPem: proofOnlyIssuer.publicKeyPem,
        rule: recognitionRule({
          issuers: [],
          requiredAuditEventId: allowPayload.audit_event_id,
          requiredDetailHash: allowPayload.detail_hash
        }),
        nowEpoch
      })
    ];

    const report = {
      proof_type: PROOF_TYPE,
      evidence_model: EVIDENCE_MODEL,
      receipt_format: RECEIPT_FORMAT,
      runner_scope: RUNNER_SCOPE,
      live_probing: false,
      fixture_keys: 'ephemeral proof-owned Ed25519 keys; raw key material omitted',
      production_trust: false,
      custody_proven: false,
      downstream_production_recognition: false,
      all_surface_governance: false,
      deny_recognition_is_boarding: false,
      safe_claim: SAFE_CLAIM,
      forbidden_claims: FORBIDDEN_CLAIMS,
      case_count: cases.length,
      recognized_for_runner_scope_count: cases.filter((item) => item.recognized_for_runner_scope).length,
      refused_count: cases.filter((item) => item.decision === 'refuse').length,
      cases
    };

    assertReportShape(report);
    assertNoUnsafeProofText(JSON.stringify(report));
    return report;
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

export function formatZlarRunnerReceiptIssuerRecognitionProof(report) {
  const lines = [
    `Proof: ${report.proof_type}`,
    `Evidence model: ${report.evidence_model}`,
    `Runner scope: ${report.runner_scope}`,
    `Receipt format: ${report.receipt_format}`,
    `Recognized fixture cases: ${report.recognized_for_runner_scope_count}/${report.case_count}`,
    `Production trust: ${report.production_trust}`,
    `Custody proven: ${report.custody_proven}`,
    `Downstream production recognition: ${report.downstream_production_recognition}`,
    `All-surface governance: ${report.all_surface_governance}`,
    '',
    'Cases:'
  ];
  for (const item of report.cases) {
    lines.push(
      `- ${item.id}: receipt_valid=${item.receipt_valid}; recognized=${item.recognized_for_runner_scope}; reason=${item.reason_code}; boarding_effect=${item.boarding_effect}`
    );
  }
  lines.push('', `Safe claim: ${report.safe_claim}`);
  lines.push('Forbidden claims:');
  for (const claim of report.forbidden_claims) lines.push(`- ${claim}`);
  const text = `${lines.join('\n')}\n`;
  assertNoUnsafeProofText(text);
  return text;
}
