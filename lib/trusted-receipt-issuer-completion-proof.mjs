import { createHash } from 'node:crypto';
import { canonicalize } from './canonicalize.mjs';

export const TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE =
  'zlar-trusted-receipt-issuer-completion-proof-v1';
export const TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE =
  'zlar-trusted-receipt-issuer-completion-proof-verification-v1';
export const TRUSTED_RECEIPT_ISSUER_COMPLETION_CANONICAL_SURFACE_ID =
  'protected-records.runtime.profile-installation.records.write';
export const TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID =
  'protected-records.private-operator.records-terminal.records.write';
export const TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID =
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CANONICAL_SURFACE_ID;
export const TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_IDS = Object.freeze([
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CANONICAL_SURFACE_ID,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
]);
export const TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_PRIMITIVE =
  'recognized_authority_event';
export const TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE =
  'Receipts prove recognized authority events, not absolute human intention.';

export const TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_EVENT_TYPES =
  Object.freeze([
    'direct_human_approval',
    'delegated_policy_approval',
    'standing_mandate',
    'quorum_approval',
    'emergency_override',
    'system_control_approval_under_pre_approved_policy',
    'blocked',
    'escalated',
    'timed_out',
    'refused_due_to_missing_authority',
    'refused_due_to_invalid_receipt',
    'refused_due_to_stale_or_unrecognized_registry_state',
  ]);

export const TRUSTED_RECEIPT_ISSUER_COMPLETION_REQUIRED_REFUSAL_CASES =
  Object.freeze([
    'missing_authority_refused',
    'invalid_receipt_refused',
    'unknown_issuer_refused',
    'inactive_issuer_refused',
    'stale_registry_state_refused',
    'unrecognized_registry_state_refused',
    'summary_only_evidence_refused',
    'fixture_only_evidence_refused',
    'overclaim_flags_refused',
  ]);

export const TRUSTED_RECEIPT_ISSUER_COMPLETION_NON_CLAIMS = Object.freeze([
  'This proof verifies a bounded recognized-authority-event evidence contract for the selected surface only.',
  'This proof does not prove moral blameworthiness, metaphysical consent, absolute human intention, or a legal conclusion.',
  'This proof does not prove customer production relying-party trust, production downstream recognition, or current-machine governance.',
  'This proof does not prove hardware-backed custody when custody posture is software-rooted.',
  'This proof does not prove global certainty about compromise, revocation, or all possible registry state.',
  'This proof does not prove external attestation, public release alignment, all-surface governance, or side-door closure.',
]);

const HEX64 = /^[a-f0-9]{64}$/;
const KID16 = /^[a-f0-9]{16}$/;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireObject(label, value) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireString(label, value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requireBool(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
}

function requireHex(label, value) {
  requireString(label, value);
  if (!HEX64.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 hex string`);
  }
  return value;
}

function requireKid(label, value) {
  requireString(label, value);
  if (!KID16.test(value)) {
    throw new Error(`${label} must be a 16-hex key id`);
  }
  return value;
}

function requireArray(label, value) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function exactArray(label, actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} drifted`);
  }
}

function deterministicHash(label) {
  return createHash('sha256').update(label, 'utf8').digest('hex');
}

export function isTrustedReceiptIssuerCompletionSurfaceId(value) {
  return TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_IDS.includes(value);
}

export function trustedReceiptIssuerCompletionProofBodySha256(proof) {
  return createHash('sha256').update(canonicalize(proof), 'utf8').digest('hex');
}

export function buildTrustedReceiptIssuerCompletionProofTestVector(overrides = {}) {
  const selectedSurfaceId =
    overrides.selected_surface_id || TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID;
  const base = {
    proof_type: TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE,
    schema_version: 1,
    evidence_model: 'operator-owned-private-core-recognized-authority-event-contract',
    selected_surface_id: selectedSurfaceId,
    authority_primitive: TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_PRIMITIVE,
    core_sentence: TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
    authority_event_contract: {
      observed_event_type: 'delegated_policy_approval',
      allowed_event_types: [...TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_EVENT_TYPES],
      collapsed_authorized_category: false,
      human_yes_claimed: false,
      legal_consent_claimed: false,
      moral_blameworthiness_claimed: false,
      metaphysical_consent_claimed: false,
      absolute_human_intention_claimed: false,
    },
    issuer_identity: {
      kid: '0123456789abcdef',
      public_key_sha256: deterministicHash('trusted-receipt-issuer-public-key'),
      receipt_format: 'v1',
      receipt_signature_valid: true,
      receipt_validity_distinct_from_issuer_recognition: true,
      receipt_validity_distinct_from_human_intention: true,
      raw_public_key_material_included: false,
      raw_private_key_material_included: false,
    },
    registry_identity: {
      registry_type: 'trusted-receipt-issuers-v1',
      registry_sha256: deterministicHash('trusted-receipt-issuer-registry'),
      operator_owned_private_core_registry: true,
      customer_production_trust: false,
      production_relying_party_trust: false,
      issuer_status: 'active',
      issuer_recognized: true,
      recognition_decision: 'accept',
      recognition_reason_code: 'recognized',
      live_registry_global_truth_claimed: false,
    },
    recognition_contract_identity: {
      recognition_contract_sha256: deterministicHash('trusted-receipt-issuer-recognition-contract'),
      surface_id: selectedSurfaceId,
      policy_version: 'protected-records-runtime-profile-installation-v1',
      action_class: 'records.write',
      audit_event_id_bound: true,
      detail_hash_bound: true,
      downstream_refusal_distinct_from_receipt_validity: true,
    },
    revocation_status_evidence_identity: {
      status_source_sha256: deterministicHash('trusted-receipt-issuer-status-source'),
      issuer_status: 'active',
      revocation_status: 'not_revoked_for_selected_scope',
      revocation_truth_scope: 'selected-private-core-registry',
      global_compromise_certainty_claimed: false,
      global_revocation_certainty_claimed: false,
      status_truth_distinct_from_external_attestation: true,
    },
    custody_posture_identity: {
      custody_posture: 'software-rooted-current',
      custody_posture_sha256: deterministicHash('trusted-receipt-issuer-custody-posture'),
      key_state_sha256: deterministicHash('trusted-receipt-issuer-key-state'),
      custody_evidence_bound: true,
      software_rooted_custody: true,
      hardware_backed_custody_claimed: false,
      hardware_backed_custody_proven: false,
      raw_private_key_material_included: false,
      signing_operation_performed: false,
    },
    command_posture: {
      verifier_command: 'zlar trusted-receipt-issuer-completion-proof verify --input <file> --json',
      requires_identity_binding: true,
      requires_nonclaim_boundary: true,
      requires_distinct_authority_event_type: true,
      summary_only_evidence_accepted: false,
      fixture_only_evidence_accepted: false,
      overclaim_flags_accepted: false,
    },
    refusal_contract: {
      refusal_case_count: TRUSTED_RECEIPT_ISSUER_COMPLETION_REQUIRED_REFUSAL_CASES.length,
      refusal_case_ids: [...TRUSTED_RECEIPT_ISSUER_COMPLETION_REQUIRED_REFUSAL_CASES],
      all_refusals_before_consequence: true,
      consequence_absent_on_refusal: true,
      recognized_authority_event_accepts_selected_surface: true,
    },
    claim_boundary: {
      receipt_validity_is_human_intention: false,
      issuer_recognition_is_human_yes: false,
      authority_event_is_legal_consent: false,
      operator_registry_is_customer_production_trust: false,
      software_custody_is_hardware_backed: false,
      revocation_status_is_global_certainty: false,
      authorized_is_undifferentiated: false,
      fixture_only_evidence: false,
      summary_only_evidence: false,
      moral_blameworthiness: false,
      metaphysical_consent: false,
      absolute_human_intention: false,
      legal_conclusion: false,
      production_relying_party_trust: false,
      hardware_backed_custody_without_proof: false,
      global_compromise_or_revocation_certainty: false,
      external_attestation: false,
      public_release_alignment: false,
      current_machine_governance: false,
      live_receipt_emission: false,
      production_downstream_recognition: false,
      all_surface_governance: false,
      side_door_closure: false,
    },
    completion_claim: {
      completed_for_selected_surface: true,
      star_one_piece: 'Trusted Receipt Issuer',
      completion_scope: 'operator-owned-private-core-recognized-authority-event-contract',
      fixture_only_completion: false,
      customer_production_trust_completed: false,
      external_attestation_completed: false,
      production_deployment_completed: false,
    },
    non_claims: [...TRUSTED_RECEIPT_ISSUER_COMPLETION_NON_CLAIMS],
  };
  return {
    ...base,
    ...overrides,
    recognition_contract_identity: {
      ...base.recognition_contract_identity,
      ...(overrides.recognition_contract_identity || {}),
    },
  };
}

export function assertTrustedReceiptIssuerCompletionProof(proof) {
  requireObject('Trusted Receipt Issuer completion proof', proof);
  if (proof.proof_type !== TRUSTED_RECEIPT_ISSUER_COMPLETION_PROOF_TYPE) {
    throw new Error('Trusted Receipt Issuer completion proof has the wrong proof type');
  }
  if (proof.schema_version !== 1) {
    throw new Error('Trusted Receipt Issuer completion proof schema version drifted');
  }
  if (proof.evidence_model !== 'operator-owned-private-core-recognized-authority-event-contract') {
    throw new Error('Trusted Receipt Issuer completion proof evidence model drifted');
  }
  if (!isTrustedReceiptIssuerCompletionSurfaceId(proof.selected_surface_id)) {
    throw new Error('Trusted Receipt Issuer completion proof selected surface drifted');
  }
  if (proof.authority_primitive !== TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_PRIMITIVE) {
    throw new Error('Trusted Receipt Issuer completion proof authority primitive drifted');
  }
  if (proof.core_sentence !== TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE) {
    throw new Error('Trusted Receipt Issuer completion proof core sentence drifted');
  }

  const event = requireObject('authority_event_contract', proof.authority_event_contract);
  if (!TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_EVENT_TYPES.includes(event.observed_event_type)) {
    throw new Error('Trusted Receipt Issuer completion proof authority event type drifted');
  }
  exactArray(
    'Trusted Receipt Issuer completion proof authority event type list',
    requireArray('authority_event_contract.allowed_event_types', event.allowed_event_types),
    TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_EVENT_TYPES
  );
  for (const key of [
    'collapsed_authorized_category',
    'human_yes_claimed',
    'legal_consent_claimed',
    'moral_blameworthiness_claimed',
    'metaphysical_consent_claimed',
    'absolute_human_intention_claimed',
  ]) {
    requireBool(`authority_event_contract.${key}`, event[key], false);
  }

  const issuer = requireObject('issuer_identity', proof.issuer_identity);
  requireKid('issuer_identity.kid', issuer.kid);
  requireHex('issuer_identity.public_key_sha256', issuer.public_key_sha256);
  if (issuer.receipt_format !== 'v1') {
    throw new Error('Trusted Receipt Issuer completion proof must be v1 receipt identity');
  }
  for (const key of [
    'receipt_signature_valid',
    'receipt_validity_distinct_from_issuer_recognition',
    'receipt_validity_distinct_from_human_intention',
  ]) {
    requireBool(`issuer_identity.${key}`, issuer[key], true);
  }
  requireBool('issuer_identity.raw_public_key_material_included', issuer.raw_public_key_material_included, false);
  requireBool('issuer_identity.raw_private_key_material_included', issuer.raw_private_key_material_included, false);

  const registry = requireObject('registry_identity', proof.registry_identity);
  if (registry.registry_type !== 'trusted-receipt-issuers-v1') {
    throw new Error('Trusted Receipt Issuer completion proof registry type drifted');
  }
  requireHex('registry_identity.registry_sha256', registry.registry_sha256);
  requireBool('registry_identity.operator_owned_private_core_registry', registry.operator_owned_private_core_registry, true);
  requireBool('registry_identity.customer_production_trust', registry.customer_production_trust, false);
  requireBool('registry_identity.production_relying_party_trust', registry.production_relying_party_trust, false);
  if (
    registry.issuer_status !== 'active' ||
    registry.issuer_recognized !== true ||
    registry.recognition_decision !== 'accept' ||
    registry.recognition_reason_code !== 'recognized'
  ) {
    throw new Error('Trusted Receipt Issuer completion proof registry recognition did not accept active issuer');
  }
  requireBool('registry_identity.live_registry_global_truth_claimed', registry.live_registry_global_truth_claimed, false);

  const recognition = requireObject('recognition_contract_identity', proof.recognition_contract_identity);
  requireHex('recognition_contract_identity.recognition_contract_sha256', recognition.recognition_contract_sha256);
  if (recognition.surface_id !== proof.selected_surface_id) {
    throw new Error('Trusted Receipt Issuer completion proof recognition contract surface drifted');
  }
  requireString('recognition_contract_identity.policy_version', recognition.policy_version);
  if (recognition.action_class !== 'records.write') {
    throw new Error('Trusted Receipt Issuer completion proof recognition contract action drifted');
  }
  for (const key of [
    'audit_event_id_bound',
    'detail_hash_bound',
    'downstream_refusal_distinct_from_receipt_validity',
  ]) {
    requireBool(`recognition_contract_identity.${key}`, recognition[key], true);
  }

  const revocation = requireObject('revocation_status_evidence_identity', proof.revocation_status_evidence_identity);
  requireHex('revocation_status_evidence_identity.status_source_sha256', revocation.status_source_sha256);
  if (
    revocation.issuer_status !== 'active' ||
    revocation.revocation_status !== 'not_revoked_for_selected_scope' ||
    revocation.revocation_truth_scope !== 'selected-private-core-registry'
  ) {
    throw new Error('Trusted Receipt Issuer completion proof revocation/status evidence drifted');
  }
  requireBool('revocation_status_evidence_identity.global_compromise_certainty_claimed', revocation.global_compromise_certainty_claimed, false);
  requireBool('revocation_status_evidence_identity.global_revocation_certainty_claimed', revocation.global_revocation_certainty_claimed, false);
  requireBool('revocation_status_evidence_identity.status_truth_distinct_from_external_attestation', revocation.status_truth_distinct_from_external_attestation, true);

  const custody = requireObject('custody_posture_identity', proof.custody_posture_identity);
  if (!['software-rooted-current', 'hardware-backed-current'].includes(custody.custody_posture)) {
    throw new Error('Trusted Receipt Issuer completion proof custody posture drifted');
  }
  requireHex('custody_posture_identity.custody_posture_sha256', custody.custody_posture_sha256);
  requireHex('custody_posture_identity.key_state_sha256', custody.key_state_sha256);
  requireBool('custody_posture_identity.custody_evidence_bound', custody.custody_evidence_bound, true);
  requireBool('custody_posture_identity.raw_private_key_material_included', custody.raw_private_key_material_included, false);
  requireBool('custody_posture_identity.signing_operation_performed', custody.signing_operation_performed, false);
  if (custody.custody_posture === 'software-rooted-current') {
    requireBool('custody_posture_identity.software_rooted_custody', custody.software_rooted_custody, true);
    requireBool('custody_posture_identity.hardware_backed_custody_claimed', custody.hardware_backed_custody_claimed, false);
    requireBool('custody_posture_identity.hardware_backed_custody_proven', custody.hardware_backed_custody_proven, false);
  }
  if (custody.hardware_backed_custody_claimed === true && custody.hardware_backed_custody_proven !== true) {
    throw new Error('Trusted Receipt Issuer completion proof claims hardware custody without proof');
  }

  const command = requireObject('command_posture', proof.command_posture);
  requireString('command_posture.verifier_command', command.verifier_command);
  for (const key of [
    'requires_identity_binding',
    'requires_nonclaim_boundary',
    'requires_distinct_authority_event_type',
  ]) {
    requireBool(`command_posture.${key}`, command[key], true);
  }
  for (const key of [
    'summary_only_evidence_accepted',
    'fixture_only_evidence_accepted',
    'overclaim_flags_accepted',
  ]) {
    requireBool(`command_posture.${key}`, command[key], false);
  }

  const refusal = requireObject('refusal_contract', proof.refusal_contract);
  if (refusal.refusal_case_count !== TRUSTED_RECEIPT_ISSUER_COMPLETION_REQUIRED_REFUSAL_CASES.length) {
    throw new Error('Trusted Receipt Issuer completion proof refusal case count drifted');
  }
  exactArray(
    'Trusted Receipt Issuer completion proof refusal case ids',
    requireArray('refusal_contract.refusal_case_ids', refusal.refusal_case_ids),
    TRUSTED_RECEIPT_ISSUER_COMPLETION_REQUIRED_REFUSAL_CASES
  );
  for (const key of [
    'all_refusals_before_consequence',
    'consequence_absent_on_refusal',
    'recognized_authority_event_accepts_selected_surface',
  ]) {
    requireBool(`refusal_contract.${key}`, refusal[key], true);
  }

  const boundary = requireObject('claim_boundary', proof.claim_boundary);
  for (const [key, value] of Object.entries(boundary)) {
    requireBool(`claim_boundary.${key}`, value, false);
  }
  for (const required of [
    'receipt_validity_is_human_intention',
    'issuer_recognition_is_human_yes',
    'authority_event_is_legal_consent',
    'operator_registry_is_customer_production_trust',
    'software_custody_is_hardware_backed',
    'revocation_status_is_global_certainty',
    'authorized_is_undifferentiated',
    'fixture_only_evidence',
    'summary_only_evidence',
  ]) {
    if (!Object.prototype.hasOwnProperty.call(boundary, required)) {
      throw new Error(`Trusted Receipt Issuer completion proof missing claim boundary ${required}`);
    }
  }

  const completion = requireObject('completion_claim', proof.completion_claim);
  requireBool('completion_claim.completed_for_selected_surface', completion.completed_for_selected_surface, true);
  if (completion.star_one_piece !== 'Trusted Receipt Issuer') {
    throw new Error('Trusted Receipt Issuer completion proof Star One piece drifted');
  }
  if (completion.completion_scope !== 'operator-owned-private-core-recognized-authority-event-contract') {
    throw new Error('Trusted Receipt Issuer completion proof completion scope drifted');
  }
  for (const key of [
    'fixture_only_completion',
    'customer_production_trust_completed',
    'external_attestation_completed',
    'production_deployment_completed',
  ]) {
    requireBool(`completion_claim.${key}`, completion[key], false);
  }

  exactArray(
    'Trusted Receipt Issuer completion proof non-claims',
    requireArray('non_claims', proof.non_claims),
    TRUSTED_RECEIPT_ISSUER_COMPLETION_NON_CLAIMS
  );

  return true;
}

export function buildTrustedReceiptIssuerCompletionVerification(proof) {
  assertTrustedReceiptIssuerCompletionProof(proof);
  return {
    verification_type: TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE,
    verified: true,
    proof_type: proof.proof_type,
    proof_sha256: trustedReceiptIssuerCompletionProofBodySha256(proof),
    selected_surface_id: proof.selected_surface_id,
    authority_primitive: proof.authority_primitive,
    core_sentence: proof.core_sentence,
    authority_event_type: proof.authority_event_contract.observed_event_type,
    issuer_kid: proof.issuer_identity.kid,
    issuer_public_key_sha256: proof.issuer_identity.public_key_sha256,
    registry_sha256: proof.registry_identity.registry_sha256,
    recognition_contract_sha256: proof.recognition_contract_identity.recognition_contract_sha256,
    status_source_sha256: proof.revocation_status_evidence_identity.status_source_sha256,
    custody_posture: proof.custody_posture_identity.custody_posture,
    custody_posture_sha256: proof.custody_posture_identity.custody_posture_sha256,
    key_state_sha256: proof.custody_posture_identity.key_state_sha256,
    completed_for_selected_surface: true,
    receipt_validity_distinct_from_human_intention: true,
    issuer_recognition_distinct_from_human_yes: true,
    authority_event_distinct_from_legal_consent: true,
    operator_registry_distinct_from_customer_production_trust: true,
    software_custody_not_hardware_backed: proof.custody_posture_identity.custody_posture === 'software-rooted-current',
    revocation_status_not_global_certainty: true,
    summary_only_evidence_accepted: false,
    fixture_only_evidence_accepted: false,
    overclaim_flags_accepted: false,
    claim_boundary: { ...proof.claim_boundary },
    non_claims: [...proof.non_claims],
  };
}

export function readinessSummaryFromTrustedReceiptIssuerCompletionVerification(verification) {
  if (
    !isObject(verification) ||
    verification.verification_type !== TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE ||
    verification.verified !== true
  ) {
    return {
      provided: false,
      verified: false,
      verification_type: 'not-provided',
      proof_type: 'not-provided',
      proof_sha256: 'not-provided',
      selected_surface_id: TRUSTED_RECEIPT_ISSUER_COMPLETION_SURFACE_ID,
      authority_primitive: TRUSTED_RECEIPT_ISSUER_COMPLETION_AUTHORITY_PRIMITIVE,
      core_sentence: TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
      authority_event_type: 'not-provided',
      issuer_kid: 'not-provided',
      issuer_public_key_sha256: 'not-provided',
      registry_sha256: 'not-provided',
      recognition_contract_sha256: 'not-provided',
      status_source_sha256: 'not-provided',
      custody_posture: 'not-provided',
      custody_posture_sha256: 'not-provided',
      key_state_sha256: 'not-provided',
      completed_for_selected_surface: false,
      receipt_validity_distinct_from_human_intention: false,
      issuer_recognition_distinct_from_human_yes: false,
      authority_event_distinct_from_legal_consent: false,
      operator_registry_distinct_from_customer_production_trust: false,
      software_custody_not_hardware_backed: false,
      revocation_status_not_global_certainty: false,
      summary_only_evidence_accepted: false,
      fixture_only_evidence_accepted: false,
      overclaim_flags_accepted: false,
      claim_boundary: {},
      non_claims: [],
    };
  }
  return {
    provided: true,
    verified: true,
    verification_type: verification.verification_type,
    proof_type: verification.proof_type,
    proof_sha256: verification.proof_sha256,
    selected_surface_id: verification.selected_surface_id,
    authority_primitive: verification.authority_primitive,
    core_sentence: verification.core_sentence,
    authority_event_type: verification.authority_event_type,
    issuer_kid: verification.issuer_kid,
    issuer_public_key_sha256: verification.issuer_public_key_sha256,
    registry_sha256: verification.registry_sha256,
    recognition_contract_sha256: verification.recognition_contract_sha256,
    status_source_sha256: verification.status_source_sha256,
    custody_posture: verification.custody_posture,
    custody_posture_sha256: verification.custody_posture_sha256,
    key_state_sha256: verification.key_state_sha256,
    completed_for_selected_surface: verification.completed_for_selected_surface === true,
    receipt_validity_distinct_from_human_intention:
      verification.receipt_validity_distinct_from_human_intention === true,
    issuer_recognition_distinct_from_human_yes:
      verification.issuer_recognition_distinct_from_human_yes === true,
    authority_event_distinct_from_legal_consent:
      verification.authority_event_distinct_from_legal_consent === true,
    operator_registry_distinct_from_customer_production_trust:
      verification.operator_registry_distinct_from_customer_production_trust === true,
    software_custody_not_hardware_backed:
      verification.software_custody_not_hardware_backed === true,
    revocation_status_not_global_certainty:
      verification.revocation_status_not_global_certainty === true,
    summary_only_evidence_accepted: verification.summary_only_evidence_accepted === true,
    fixture_only_evidence_accepted: verification.fixture_only_evidence_accepted === true,
    overclaim_flags_accepted: verification.overclaim_flags_accepted === true,
    claim_boundary: { ...(verification.claim_boundary || {}) },
    non_claims: Array.isArray(verification.non_claims) ? [...verification.non_claims] : [],
  };
}

export function formatTrustedReceiptIssuerCompletionVerification(verification) {
  const lines = [
    'Trusted Receipt Issuer Completion Proof v1',
    `Verified: ${verification.verified}`,
    `Selected surface: ${verification.selected_surface_id}`,
    `Authority primitive: ${verification.authority_primitive}`,
    `Core sentence: ${verification.core_sentence}`,
    `Authority event type: ${verification.authority_event_type}`,
    `Issuer kid: ${verification.issuer_kid}`,
    `Proof SHA-256: ${verification.proof_sha256}`,
    'Claim boundary: local recognized-authority-event contract only; not human intention, legal consent, production trust, hardware custody, global revocation truth, or external attestation.',
    'Non-claims:',
    ...verification.non_claims.map((claim) => `- ${claim}`),
  ];
  return `${lines.join('\n')}\n`;
}
