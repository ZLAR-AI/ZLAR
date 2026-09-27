#!/usr/bin/env node

import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  pubkeyFingerprint,
  sha256hex,
  signReceiptV1,
} from '../lib/receipt.mjs';
import {
  TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE,
  assertNoUnsafeTrustedReceiptIssuerRegistryV2SummaryText,
  assertTrustedReceiptIssuerRegistryV1Contract,
  assertTrustedReceiptIssuerRegistryV2Contract,
  evaluateTrustedReceiptIssuerRegistryV2Recognition,
  publicSafeTrustedReceiptIssuerRegistryV2Summary,
} from '../lib/trusted-receipt-issuer-registry.mjs';
import {
  assertRecognized,
  assertRefused,
} from '../lib/downstream-recognition-rule.mjs';

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

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function assertRegistryRefused(label, decision, expectedCode) {
  assertEqual(`${label} decision`, 'refuse', decision.decision);
  assertEqual(`${label} recognized`, false, decision.recognized);
  assertEqual(`${label} reason`, expectedCode, decision.reason_code);
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const tempDir = mkdtempSync(join(tmpdir(), 'zlar-trusted-registry-'));
process.on('exit', () => {
  try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
});

function keyFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(tempDir, `key-${sha256hex(publicPem).slice(0, 12)}.pub`);
  writeFileSync(publicPath, publicPem);
  return {
    kid: pubkeyFingerprint(publicPath),
    privatePem,
    publicPem,
  };
}

const primaryKey = keyFixture();
const otherKey = keyFixture();
const nowEpoch = Math.floor(Date.now() / 1000);
function isoFromNow(offsetSeconds) {
  return new Date((nowEpoch + offsetSeconds) * 1000).toISOString();
}
const effectiveAt = isoFromNow(-3600);
const expiresAt = isoFromNow(3600);

function eventFixture(overrides = {}) {
  return {
    id: overrides.id || 'trusted-registry-action-001',
    ts: overrides.ts || isoFromNow(-10),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || {
      action_class: 'records.write',
      registry_contract_case: 'recognized',
    },
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RTRUSTED_REGISTRY_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'trusted-registry-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function signedReceipt(overrides = {}, key = primaryKey) {
  return signReceiptV1(
    createReceiptV1FromEvent(eventFixture(overrides)),
    key.privatePem,
    key.kid
  );
}

const acceptedReceipt = signedReceipt();
const acceptedPayload = decodePayloadV1(acceptedReceipt);

function claimBoundary() {
  return {
    current_machine_governance_proven: false,
    enterprise_readiness: false,
    hardware_custody_proven: false,
    key_custody_proven: false,
    live_issuer_status_proven: false,
    live_trust_registry_state: false,
    production_authority: false,
    production_downstream_recognition_proven: false,
    production_trust_registry_proven: false,
    public_external_attestation: false,
    revocation_truth_proven: false,
    sovereign_recognition: false,
  };
}

function v2Issuer(overrides = {}) {
  return {
    kid: primaryKey.kid,
    public_key_pem: primaryKey.publicPem,
    trust_anchor_sha256: null,
    status: 'active',
    status_reason: 'local fixture issuer recognized for no-secret contract validation only',
    effective_at: effectiveAt,
    expires_at: expiresAt,
    status_transition: {
      transition_type: 'fixture_activation',
      transition_at: effectiveAt,
      previous_status: null,
      reason: 'local fixture activation for contract validation',
    },
    custody_posture: {
      declaration: 'ephemeral local fixture key; no custody proof',
      private_key_material_included: false,
      hardware_custody_proven: false,
      custody_proof_provided: false,
    },
    ...overrides,
  };
}

function v2Registry(overrides = {}) {
  return {
    registry_type: 'trusted-receipt-issuers-v2',
    registry_id: 'local-no-secret-trusted-issuer-registry-fixture',
    version: 2,
    evidence_model: 'local-no-secret-registry-contract-fixture',
    live_probing: false,
    deployment_scope: 'fixture-records-terminal',
    effective_at: effectiveAt,
    expires_at: expiresAt,
    trusted_issuers: [v2Issuer()],
    accepted_policy_versions: ['trusted-registry-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow'],
    freshness_requirements: {
      max_age_seconds: 120,
      future_tolerance_seconds: 0,
    },
    replay_protection: {
      receipt_id_required: true,
      replay_cache_required: true,
      atomic_consume_required: true,
    },
    required_audit_event_id: acceptedPayload.audit_event_id,
    required_detail_hash: acceptedPayload.detail_hash,
    claim_boundary: claimBoundary(),
    non_claims: [
      'This registry artifact is a no-secret local contract fixture, not live registry truth.',
      'This registry artifact does not prove key custody, hardware custody, revocation truth, production authority, production downstream recognition, public external attestation, sovereign recognition, enterprise readiness, or current-machine governance.',
    ],
    ...overrides,
  };
}

function v1Registry(overrides = {}) {
  return {
    registry_type: 'trusted-receipt-issuers-v1',
    version: 1,
    evidence_model: 'local-v1-registry-contract-fixture',
    live_probing: false,
    deployment_scope: 'fixture-records-terminal',
    trusted_issuers: [
      {
        kid: primaryKey.kid,
        public_key_pem: primaryKey.publicPem,
        status: 'active',
      },
    ],
    accepted_policy_versions: ['trusted-registry-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow'],
    required_audit_event_id: acceptedPayload.audit_event_id,
    required_detail_hash: acceptedPayload.detail_hash,
    non_claims: [
      'This V1 registry is a supplied local fixture, not live registry truth.',
    ],
    ...overrides,
  };
}

function decisionFor(receipt, registryOverride = {}, scope = 'fixture-records-terminal') {
  return evaluateTrustedReceiptIssuerRegistryV2Recognition({
    receipt,
    registry: v2Registry(registryOverride),
    deployment_scope: scope,
    now_epoch: nowEpoch,
  });
}

section('versioned schema and runtime contracts');
const v1SchemaBytes = readFileSync(new URL('../spec/trusted-receipt-issuers-v1.schema.json', import.meta.url));
const v2SchemaBytes = readFileSync(new URL('../spec/trusted-receipt-issuers-v2.schema.json', import.meta.url));
const v1Schema = JSON.parse(v1SchemaBytes.toString('utf8'));
const v2Schema = JSON.parse(v2SchemaBytes.toString('utf8'));
const v1Required = [
  'registry_type',
  'version',
  'evidence_model',
  'live_probing',
  'deployment_scope',
  'trusted_issuers',
  'accepted_policy_versions',
  'accepted_domains',
  'accepted_tools',
  'accepted_outcomes',
  'non_claims',
];
const v2Required = [
  'registry_type',
  'registry_id',
  'version',
  'evidence_model',
  'live_probing',
  'deployment_scope',
  'effective_at',
  'expires_at',
  'trusted_issuers',
  'accepted_policy_versions',
  'accepted_domains',
  'accepted_tools',
  'accepted_outcomes',
  'freshness_requirements',
  'replay_protection',
  'required_audit_event_id',
  'required_detail_hash',
  'claim_boundary',
  'non_claims',
];
const v2IssuerRequired = [
  'kid',
  'public_key_pem',
  'trust_anchor_sha256',
  'status',
  'status_reason',
  'effective_at',
  'expires_at',
  'status_transition',
  'custody_posture',
];
assertEqual(
  'frozen V1 schema exact SHA-256',
  '67defefa4f36894ca378c11c6d468f00232898c2489346f450739e3d6ee96a93',
  sha256hex(v1SchemaBytes)
);
assertEqual('V1 schema id', 'https://zlar.ai/spec/trusted-receipt-issuers-v1.schema.json', v1Schema.$id);
assertEqual('V1 schema registry type', 'trusted-receipt-issuers-v1', v1Schema.properties.registry_type.const);
assertEqual('V1 schema numeric version', 1, v1Schema.properties.version.const);
assertEqual('V1 schema required fields', JSON.stringify(v1Required), JSON.stringify(v1Schema.required));
assertEqual('V1 schema accepted top-level key count', 13, Object.keys(v1Schema.properties).length);
assertEqual('V1 schema issuer required field count', 3, v1Schema.properties.trusted_issuers.items.required.length);
assertEqual('V2 schema id', 'https://zlar.ai/spec/trusted-receipt-issuers-v2.schema.json', v2Schema.$id);
assertEqual('V2 schema title', 'ZLAR Trusted Receipt Issuers v2', v2Schema.title);
assertEqual('V2 schema registry type', 'trusted-receipt-issuers-v2', v2Schema.properties.registry_type.const);
assertEqual('V2 schema numeric version', 2, v2Schema.properties.version.const);
assertEqual('V2 schema required fields', JSON.stringify(v2Required), JSON.stringify(v2Schema.required));
assertEqual('V2 schema accepted top-level key count', 19, Object.keys(v2Schema.properties).length);
assertEqual('V2 schema issuer required fields', JSON.stringify(v2IssuerRequired), JSON.stringify(v2Schema.properties.trusted_issuers.items.required));
assertEqual('V2 schema issuer exact-object uniqueness signal', true, v2Schema.properties.trusted_issuers.uniqueItems);
for (const field of ['accepted_policy_versions', 'accepted_domains', 'accepted_tools', 'accepted_outcomes']) {
  assertEqual(`V2 schema ${field} requires one item`, 1, v2Schema.properties[field].minItems);
}
assert(
  'V2 schema active issuer requires public key or trust anchor',
  Array.isArray(v2Schema.properties.trusted_issuers.items.allOf) &&
    v2Schema.properties.trusted_issuers.items.allOf[0]?.if?.properties?.status?.const === 'active' &&
    v2Schema.properties.trusted_issuers.items.allOf[0]?.then?.anyOf?.length === 2
);

const validV1 = v1Registry();
assert('old V1 accepted by V1 runtime contract', assertTrustedReceiptIssuerRegistryV1Contract(validV1));
const optionalBindingV1 = v1Registry();
delete optionalBindingV1.required_audit_event_id;
delete optionalBindingV1.required_detail_hash;
assert('V1 optional bindings may be absent', assertTrustedReceiptIssuerRegistryV1Contract(optionalBindingV1));
assert(
  'V1 preserves empty accepted-list semantics',
  assertTrustedReceiptIssuerRegistryV1Contract(v1Registry({
    accepted_policy_versions: [],
    accepted_domains: [],
    accepted_tools: [],
    accepted_outcomes: [],
  }))
);
assertThrows(
  'old V1 rejected by V2 runtime contract',
  () => assertTrustedReceiptIssuerRegistryV2Contract(validV1),
  'unexpected fields'
);
assertThrows(
  'expanded V2 rejected by V1 runtime contract',
  () => assertTrustedReceiptIssuerRegistryV1Contract(v2Registry()),
  'unexpected fields'
);
assertThrows(
  'mixed V2 shape with V1 type rejected by V2',
  () => assertTrustedReceiptIssuerRegistryV2Contract(v2Registry({ registry_type: 'trusted-receipt-issuers-v1' })),
  'identity'
);
assertThrows(
  'mixed V2 shape with V1 version rejected by V2',
  () => assertTrustedReceiptIssuerRegistryV2Contract(v2Registry({ version: 1 })),
  'identity'
);
assertThrows(
  'V1 shape with V2-only field rejected by V1',
  () => assertTrustedReceiptIssuerRegistryV1Contract(v1Registry({ registry_id: 'not-a-v1-field' })),
  'unexpected fields'
);
assertThrows(
  'old V1 fails before V2 recognition verdict',
  () => evaluateTrustedReceiptIssuerRegistryV2Recognition({
    receipt: acceptedReceipt,
    registry: validV1,
    deployment_scope: 'fixture-records-terminal',
    now_epoch: nowEpoch,
  }),
  'unexpected fields'
);
assertThrows(
  'mixed V1 type and V2 fields fail before recognition verdict',
  () => evaluateTrustedReceiptIssuerRegistryV2Recognition({
    receipt: acceptedReceipt,
    registry: v2Registry({ registry_type: 'trusted-receipt-issuers-v1' }),
    deployment_scope: 'fixture-records-terminal',
    now_epoch: nowEpoch,
  }),
  'identity'
);
assertThrows(
  'mixed V1 version and V2 fields fail before recognition verdict',
  () => evaluateTrustedReceiptIssuerRegistryV2Recognition({
    receipt: acceptedReceipt,
    registry: v2Registry({ version: 1 }),
    deployment_scope: 'fixture-records-terminal',
    now_epoch: nowEpoch,
  }),
  'identity'
);
const missingAuditBindingV2 = v2Registry();
delete missingAuditBindingV2.required_audit_event_id;
assertThrows(
  'V2 required audit binding cannot be omitted',
  () => assertTrustedReceiptIssuerRegistryV2Contract(missingAuditBindingV2),
  'unexpected fields'
);
const missingDetailBindingV2 = v2Registry();
delete missingDetailBindingV2.required_detail_hash;
assertThrows(
  'V2 required detail binding cannot be omitted',
  () => assertTrustedReceiptIssuerRegistryV2Contract(missingDetailBindingV2),
  'unexpected fields'
);
assertThrows(
  'revoked status is not valid V1 input',
  () => assertTrustedReceiptIssuerRegistryV1Contract(v1Registry({
    trusted_issuers: [{ ...validV1.trusted_issuers[0], status: 'revoked' }],
  })),
  'unsupported'
);

section('valid no-secret V2 registry contract');
const validRegistry = v2Registry();
assert('valid V2 registry contract passes', assertTrustedReceiptIssuerRegistryV2Contract(validRegistry));
const recognizedDecision = decisionFor(acceptedReceipt);
assert('active recognized issuer boards through downstream evaluator', assertRecognized(recognizedDecision));
assertEqual('registry-driven evaluator type is downstream recognition', 'downstream-recognition-rule-v1', recognizedDecision.result_type);
assertEqual('recognized issuer status active', 'active', recognizedDecision.evidence.issuer_status);
assertEqual('recognized audit event bound', acceptedPayload.audit_event_id, recognizedDecision.evidence.payload.audit_event_id);
assertEqual('recognized detail hash bound', acceptedPayload.detail_hash, recognizedDecision.evidence.payload.detail_hash);

section('public-safe hash-bound summary');
const summary = publicSafeTrustedReceiptIssuerRegistryV2Summary(validRegistry);
assertEqual('summary type', 'trusted-receipt-issuer-registry-public-safe-summary-v2', summary.summary_type);
assertEqual('summary evidence class', TRUSTED_RECEIPT_ISSUER_REGISTRY_V2_CONTRACT_EVIDENCE, summary.contract_evidence);
assert('registry contract sha present', /^[a-f0-9]{64}$/.test(summary.registry_contract_sha256));
assert('summary sha present', /^[a-f0-9]{64}$/.test(summary.summary_sha256));
assertEqual('summary has no raw public key material', false, summary.raw_public_key_material_included);
assertEqual('summary has no raw private key material', false, summary.raw_private_key_material_included);
assertEqual('summary makes no live registry truth claim', false, summary.live_registry_truth_claimed);
assert('summary text is safe', assertNoUnsafeTrustedReceiptIssuerRegistryV2SummaryText(JSON.stringify(summary)));
assert('summary omits raw public key', !JSON.stringify(summary).includes('BEGIN PUBLIC KEY'));

section('required refusal coverage');
assertThrows('missing status fails registry validation', () => {
  const broken = v2Registry({ trusted_issuers: [v2Issuer()] });
  delete broken.trusted_issuers[0].status;
  assertTrustedReceiptIssuerRegistryV2Contract(broken);
}, 'unexpected fields');

assert('unknown issuer refused', assertRefused(decisionFor(signedReceipt({}, otherKey)), 'unknown_issuer'));

assertThrows('active issuer without public key or trust anchor fails', () => {
  assertTrustedReceiptIssuerRegistryV2Contract(
    v2Registry({
      trusted_issuers: [
        v2Issuer({ public_key_pem: null, trust_anchor_sha256: null }),
      ],
    })
  );
}, 'requires a public key or trust anchor');

assert('retired issuer refused', assertRefused(decisionFor(acceptedReceipt, {
  trusted_issuers: [v2Issuer({ status: 'retired', status_reason: 'fixture retirement', status_transition: {
    transition_type: 'fixture_retirement',
    transition_at: effectiveAt,
    previous_status: 'active',
    reason: 'fixture retirement metadata',
  } })],
}), 'issuer_not_active'));

assert('revoked issuer refused', assertRefused(decisionFor(acceptedReceipt, {
  trusted_issuers: [v2Issuer({ status: 'revoked', status_reason: 'fixture revocation', status_transition: {
    transition_type: 'fixture_revocation',
    transition_at: effectiveAt,
    previous_status: 'active',
    reason: 'fixture revocation metadata',
  } })],
}), 'issuer_revoked'));

assert('compromised issuer refused', assertRefused(decisionFor(acceptedReceipt, {
  trusted_issuers: [v2Issuer({ status: 'compromised', status_reason: 'fixture compromise', status_transition: {
    transition_type: 'fixture_compromise',
    transition_at: effectiveAt,
    previous_status: 'active',
    reason: 'fixture compromise metadata',
  } })],
}), 'issuer_compromised'));

assert('stale receipt refused', assertRefused(decisionFor(signedReceipt({ ts: isoFromNow(-600) })), 'receipt_stale'));
assert('future receipt refused', assertRefused(decisionFor(signedReceipt({ ts: isoFromNow(60) })), 'receipt_stale'));
assert('wrong policy refused', assertRefused(decisionFor(signedReceipt({ policy_version: 'old-policy' })), 'policy_not_recognized'));
assert('wrong domain refused', assertRefused(decisionFor(signedReceipt({ domain: 'other', action: 'records.write' })), 'domain_out_of_scope'));
assert('wrong tool refused', assertRefused(decisionFor(signedReceipt({ action: 'records.delete' })), 'tool_out_of_scope'));
assert('wrong outcome refused', assertRefused(decisionFor(signedReceipt({ outcome: 'deny' })), 'outcome_not_boarding'));
assert('wrong audit event refused', assertRefused(decisionFor(signedReceipt({ id: 'other-audit-event' })), 'audit_event_mismatch'));
assert('wrong detail hash refused', assertRefused(decisionFor(signedReceipt({ detail: { action_class: 'records.write', registry_contract_case: 'mismatch' } })), 'detail_hash_mismatch'));
assertRegistryRefused('wrong deployment scope refused before downstream verdict', decisionFor(acceptedReceipt, {}, 'other-scope'), 'scope_not_found');

section('malformed and overclaiming registry refusal');
const malformed = v2Registry({ production_authority: true });
assertThrows('unsupported top-level claim field fails', () => assertTrustedReceiptIssuerRegistryV2Contract(malformed), 'unexpected fields');

const liveClaim = v2Registry({ claim_boundary: { ...claimBoundary(), live_trust_registry_state: true } });
assertThrows('live registry claim flag fails', () => assertTrustedReceiptIssuerRegistryV2Contract(liveClaim), 'must be false');

const rawPrivateMaterial = v2Registry({
  trusted_issuers: [
    v2Issuer({
      status_reason: '-----BEGIN PRIVATE KEY----- unsafe fixture -----END PRIVATE KEY-----',
    }),
  ],
});
assertThrows('raw private material fails', () => assertTrustedReceiptIssuerRegistryV2Contract(rawPrivateMaterial), 'private key material');

const defaultActive = v2Registry({ trusted_issuers: [v2Issuer({ status: undefined })] });
assertThrows('default-active behavior fails validation', () => assertTrustedReceiptIssuerRegistryV2Contract(defaultActive), 'unsupported');

const trustAnchorOnly = v2Registry({
  trusted_issuers: [
    v2Issuer({
      public_key_pem: null,
      trust_anchor_sha256: 'a'.repeat(64),
    }),
  ],
});
assert('trust-anchor-only registry can be described', assertTrustedReceiptIssuerRegistryV2Contract(trustAnchorOnly));
const trustAnchorDecision = evaluateTrustedReceiptIssuerRegistryV2Recognition({
  receipt: acceptedReceipt,
  registry: trustAnchorOnly,
  deployment_scope: 'fixture-records-terminal',
  now_epoch: nowEpoch,
});
assert('trust-anchor-only registry does not board without public key', assertRefused(trustAnchorDecision, 'issuer_key_missing'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
