import { createHash } from 'node:crypto';
import {
  canonicalize,
  validateWorkerReceipt,
} from './worker-receipt.mjs';
import {
  DOWNSTREAM_RECOGNITION_RULE_TYPE,
} from './downstream-recognition-rule.mjs';
import {
  assertProtectedRecordsServiceProfilePreflightArtifact,
} from './protected-records-service-profile.mjs';
import {
  assertProtectedRecordsRuntimeLocalActivationArtifact,
} from './protected-records-runtime-local-activation.mjs';
import {
  assertProtectedRecordsRuntimeProfileInstallationArtifact,
} from './protected-records-runtime-profile-installation.mjs';
import {
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS,
  REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS,
  PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
  assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
} from './protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
  protectedRecordsFixtureAuthorityGrantStatus,
} from './protected-records-fixture-authority-status.mjs';

export const REPORT_TYPE = 'governed-surface-coverage-map-v1';
export const SAFE_CLAIM_CEILING =
  'ZLAR can show whether supplied defined routed action-surface lanes have current routing, liveness, policy, receipt, and refusal evidence.';

const VERIFICATION_STATUS_VALUES = Object.freeze([
  'governed',
  'missing_configuration',
  'not_routed',
  'stale_or_missing_heartbeat',
  'policy_not_current',
  'receipt_not_capable',
  'downstream_refusal_missing',
  'rejected_mcp_bypass',
  'deferred',
  'audit_only',
  'not_receipt_capable',
  'unrouted',
  'boundary',
]);

const REQUIRED_SURFACE_FIELDS = Object.freeze([
  'surface_id',
  'boarding_lane',
  'checkpoint_path',
  'configured',
  'routed',
  'alive',
  'policy_current',
  'receipt_capable',
  'downstream_refusal',
  'governed',
  'verification_status',
  'coverage_summary',
  'last_decision',
  'last_receipt',
  'issuer_identity',
  'known_boundaries',
  'evidence',
  'non_claims',
]);

const NON_CLAIMS = Object.freeze([
  'Coverage is limited to lanes this report marks governed.',
  'Unrouted surfaces are boundaries, not governed lanes.',
  'A receipt proves one bounded checkpoint event, not wisdom or global authorization.',
  'This report does not create outside attestation, deployment authority, or recognition-boundary claims.',
  '/contest is not implemented.',
]);

const SURFACE_NON_CLAIMS = Object.freeze([
  'This lane does not claim adjacent clients, tools, or paths.',
  'This lane does not claim unrouted side doors.',
  'This lane does not claim authority beyond its supplied fixture evidence.',
]);

const BOUNDARY_NON_CLAIMS = Object.freeze([
  'Boundary entry only; not counted as governed coverage.',
  'No checkpoint, receipt, or downstream refusal claim is made for this boundary.',
]);

const RUNTIME_LOCAL_ACTIVATION_KIND = 'protected-records-runtime-local-activation';
const RUNTIME_PROFILE_INSTALLATION_KIND = 'protected-records-runtime-profile-installation';
const SERVICE_PROFILE_PREFLIGHT_KIND = 'protected-records-service-profile-preflight';
const INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_KIND =
  'protected-records-installed-runtime-profile-terminal-chain';
const SERVICE_PROFILE_PREFLIGHT_REQUIRED_REFUSALS = Object.freeze([
  'replay_refused',
  'missing_receipt_refused',
  'unrecognized_receipt_refused',
  'invalid_receipt_refused',
  'unknown_issuer_refused',
  'wrong_policy_refused',
  'stale_receipt_refused',
  'request_stream_authority_material_refused',
  'request_stream_forbidden_fields_refused',
  'direct_api_without_receipt_refused',
  'direct_api_with_receipt_refused',
]);
const EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE =
  'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation';
const RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASE_IDS = Object.freeze([
  'missing_receipt_refused_before_runtime_mutation',
  'invalid_receipt_refused_before_runtime_mutation',
  'unknown_issuer_refused_before_runtime_mutation',
  'retired_issuer_refused_before_runtime_mutation',
  'missing_issuer_status_refused_before_runtime_mutation',
  'wrong_policy_refused_before_runtime_mutation',
  'wrong_domain_refused_before_runtime_mutation',
  'wrong_tool_refused_before_runtime_mutation',
  'wrong_runtime_profile_id_refused_before_runtime_mutation',
  'wrong_audit_event_refused_before_runtime_mutation',
  'wrong_detail_refused_before_runtime_mutation',
  'non_boarding_outcome_refused_before_runtime_mutation',
  'stale_receipt_refused_before_runtime_mutation',
  'direct_api_without_receipt_refused_before_runtime_mutation',
  'direct_api_with_receipt_refused_before_runtime_mutation',
  'agent_supplied_recognition_rule_refused_before_runtime_mutation',
  'agent_supplied_fixture_mode_refused_before_runtime_mutation',
  'unsupported_request_field_refused_before_runtime_mutation',
]);
const RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASE_IDS = Object.freeze([
  'missing_authority_grant_appointment_refused_before_consumption',
  'mismatched_authority_grant_appointment_refused_before_consumption',
  'expired_authority_grant_refused_before_consumption',
  'revoked_authority_grant_refused_before_consumption',
  'agent_supplied_authority_grant_refused_before_runtime_mutation',
]);

const DEFAULT_BOUNDARIES = Object.freeze([
  {
    surface_id: 'sdk.daemon_membrane_authzen',
    boarding_lane: 'SDK daemon, membrane, and AuthZEN lane',
    checkpoint_path: 'deferred SDK/membrane/AuthZEN coverage path',
    verification_status: 'deferred',
    evidence: {
      boundary_kind: 'deferred',
      reason: 'Deferred unless current routed, alive, policy-current, receipt-capable, and refusal evidence is supplied.',
    },
  },
  {
    surface_id: 'hook.subagent_start',
    boarding_lane: 'SubagentStart hook lane',
    checkpoint_path: 'hook:SubagentStart',
    verification_status: 'not_receipt_capable',
    evidence: {
      boundary_kind: 'subagent',
      reason: 'SubagentStart is not receipt-capable in this map without actual current receipt evidence.',
    },
  },
  {
    surface_id: 'cursor.afterFileEdit',
    boarding_lane: 'Cursor afterFileEdit event',
    checkpoint_path: 'cursor:afterFileEdit',
    verification_status: 'audit_only',
    evidence: {
      boundary_kind: 'after_effect',
      reason: 'afterFileEdit is post-effect audit evidence and cannot prove pre-effect boarding governance.',
    },
  },
  {
    surface_id: 'windsurf.post_events',
    boarding_lane: 'Windsurf post_* events',
    checkpoint_path: 'windsurf:post_*',
    verification_status: 'audit_only',
    evidence: {
      boundary_kind: 'after_effect',
      reason: 'post_* events are after-effect audit evidence and cannot prove pre-effect boarding governance.',
    },
  },
  {
    surface_id: 'mcp.direct_registration',
    boarding_lane: 'Direct MCP registration',
    checkpoint_path: 'mcp:direct-registration',
    verification_status: 'rejected_mcp_bypass',
    evidence: {
      boundary_kind: 'direct_mcp_bypass',
      reason: 'MCP servers registered directly with a client instead of the ZLAR route are not coverage evidence.',
    },
  },
  {
    surface_id: 'unrouted.shell',
    boarding_lane: 'Unrouted shell surface',
    checkpoint_path: 'unrouted:shell',
    verification_status: 'unrouted',
    evidence: { boundary_kind: 'unrouted' },
  },
  {
    surface_id: 'unrouted.filesystem',
    boarding_lane: 'Unrouted filesystem surface',
    checkpoint_path: 'unrouted:filesystem',
    verification_status: 'unrouted',
    evidence: { boundary_kind: 'unrouted' },
  },
  {
    surface_id: 'unrouted.browser',
    boarding_lane: 'Unrouted browser surface',
    checkpoint_path: 'unrouted:browser',
    verification_status: 'unrouted',
    evidence: { boundary_kind: 'unrouted' },
  },
  {
    surface_id: 'unrouted.app_control',
    boarding_lane: 'Unrouted app-control surface',
    checkpoint_path: 'unrouted:app-control',
    verification_status: 'unrouted',
    evidence: { boundary_kind: 'unrouted' },
  },
  {
    surface_id: 'unrouted.network',
    boarding_lane: 'Unrouted network surface',
    checkpoint_path: 'unrouted:network',
    verification_status: 'unrouted',
    evidence: { boundary_kind: 'unrouted' },
  },
  {
    surface_id: 'unrouted.model',
    boarding_lane: 'Unrouted model reasoning surface',
    checkpoint_path: 'unrouted:model-reasoning',
    verification_status: 'unrouted',
    evidence: { boundary_kind: 'unrouted' },
  },
  {
    surface_id: 'unrouted.final_text',
    boarding_lane: 'Unrouted final-text surface',
    checkpoint_path: 'unrouted:final-text',
    verification_status: 'unrouted',
    evidence: { boundary_kind: 'unrouted' },
  },
]);

const REQUIRED_BOUNDARY_IDS = Object.freeze(DEFAULT_BOUNDARIES.map((item) => item.surface_id));

const CREDENTIAL_REDACTION_PATTERNS = Object.freeze([
  {
    pattern: /\b((?:token|secret|password|api[_-]?key)\s*[:=]\s*)([^&\s"'`,;})\]]+)/gi,
    replacement: '$1[REDACTED_CREDENTIAL]',
  },
  {
    pattern: /\b(authorization\s*[:=]\s*(?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]{6,})/gi,
    replacement: '$1[REDACTED_CREDENTIAL]',
  },
  {
    pattern: /\b((?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{6,})/g,
    replacement: '$1[REDACTED_CREDENTIAL]',
  },
  { pattern: /\bghp_[A-Za-z0-9_]{10,}\b/g, replacement: '[REDACTED_CREDENTIAL]' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/g, replacement: '[REDACTED_CREDENTIAL]' },
  { pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g, replacement: '[REDACTED_CREDENTIAL]' },
  { pattern: /\bAKIA[0-9A-Z]{12,}\b/g, replacement: '[REDACTED_CREDENTIAL]' },
  { pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/g, replacement: '[REDACTED_CREDENTIAL]' },
  { pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/g, replacement: '[REDACTED_CREDENTIAL]' },
]);

const UNSAFE_REPORT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'numeric human identifier', pattern: /\bhuman:[0-9]/ },
  { label: 'chat id field', pattern: /\bchat_id\b/i },
  {
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key)\s*[:=]\s*(?!\[REDACTED_CREDENTIAL\])[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization credential',
    pattern: /\bauthorization\s*[:=]\s*(?:bearer|basic)\s+(?!\[REDACTED_CREDENTIAL\])[A-Za-z0-9._~+/=-]{6,}/i,
  },
  {
    label: 'bearer/basic credential',
    pattern: /\b(?:Bearer|Basic)\s+(?!\[REDACTED_CREDENTIAL\])[A-Za-z0-9._~+/=-]{6,}/,
  },
  { label: 'GitHub token', pattern: /\bghp_[A-Za-z0-9_]{10,}\b/ },
  { label: 'GitHub fine-grained token', pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/ },
  { label: 'Slack token', pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/ },
  { label: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{12,}\b/ },
  { label: 'OpenAI-style key', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'bot token', pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/ },
  { label: 'broad action claim', pattern: /\bZLAR\s+governs\s+all\s+actions\b/i },
  { label: 'broad action claim', pattern: /\bgoverns\s+all\s+actions\b/i },
  { label: 'broad Codex claim', pattern: /\bgoverns\s+Codex\b/i },
  { label: 'enterprise readiness claim', pattern: /\benterprise(?:[- ]deployment)?[- ]ready\b|\benterprise deployment readiness\b/i },
  { label: 'sovereign claim', pattern: /\bsovereign\b/i },
  { label: 'external attestation claim', pattern: /\bexternally attested\b|\bexternal attestation\b/i },
  { label: 'production authority claim', pattern: /\bproduction authority\b/i },
]);

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function redactString(value) {
  let redacted = String(value)
    .replace(/(?:~|\/Users\/[^\s"'`;&|,)}\]]+|\/home\/[^\s"'`;&|,)}\]]+|\/private\/[^\s"'`;&|,)}\]]+|\/tmp\/[^\s"'`;&|,)}\]]+|\/var\/[^\s"'`;&|,)}\]]+)/g, '[REDACTED_PATH]')
    .replace(/\bhuman:[0-9][A-Za-z0-9_.:-]*/g, 'human:[REDACTED_ID]');
  for (const { pattern, replacement } of CREDENTIAL_REDACTION_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

function redactValue(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactString(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, redactValue(nested)]));
  }
  return redactString(String(value));
}

function cleanString(value, fallback = '') {
  if (value === null || value === undefined || value === '') return fallback;
  return redactString(value);
}

function cleanArray(values, fallback = []) {
  if (!Array.isArray(values)) return [...fallback];
  return values.map((value) => cleanString(value)).filter(Boolean);
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function boolFrom(...values) {
  for (const value of values) {
    if (value === true || value === false) return value;
  }
  return false;
}

function laneKind(lane) {
  return cleanString(lane?.kind || lane?.surface_type || lane?.surface || lane?.type || 'unknown');
}

function runtimeLocalActivationArtifact(lane) {
  const artifact =
    lane.runtime_local_activation_artifact ||
    lane.runtimeLocalActivationArtifact ||
    lane.artifact ||
    null;
  return artifact && typeof artifact === 'object' && !Array.isArray(artifact)
    ? artifact
    : null;
}

function serviceProfilePreflightArtifact(lane) {
  const artifact =
    lane.service_profile_preflight_artifact ||
    lane.serviceProfilePreflightArtifact ||
    lane.artifact ||
    null;
  return artifact && typeof artifact === 'object' && !Array.isArray(artifact)
    ? artifact
    : null;
}

function runtimeProfileInstallationArtifact(lane) {
  const artifact =
    lane.runtime_profile_installation_artifact ||
    lane.runtimeProfileInstallationArtifact ||
    lane.artifact ||
    null;
  return artifact && typeof artifact === 'object' && !Array.isArray(artifact)
    ? artifact
    : null;
}

function installedRuntimeProfileTerminalChainArtifact(lane) {
  const artifact =
    lane.installed_runtime_profile_terminal_chain_artifact ||
    lane.installedRuntimeProfileTerminalChainArtifact ||
    lane.terminal_chain_artifact ||
    lane.terminalChainArtifact ||
    lane.artifact ||
    null;
  return artifact && typeof artifact === 'object' && !Array.isArray(artifact)
    ? artifact
    : null;
}

function falseRuntimeLocalActivationEvidence(message) {
  return {
    configured: false,
    routed: false,
    alive: false,
    policy_current: false,
    receipt_capable: false,
    downstream_refusal: false,
    evidence: {
      validation: {
        artifact_present: false,
        valid: false,
        validation_error: cleanString(message || 'runtime local activation artifact missing', null),
      },
    },
  };
}

function falseServiceProfilePreflightEvidence(message) {
  return {
    configured: false,
    routed: false,
    alive: false,
    policy_current: false,
    receipt_capable: false,
    downstream_refusal: false,
    evidence: {
      validation: {
        artifact_present: false,
        valid: false,
        validation_error: cleanString(message || 'service profile preflight artifact missing', null),
      },
    },
  };
}

function falseRuntimeProfileInstallationEvidence(message) {
  return {
    configured: false,
    routed: false,
    alive: false,
    policy_current: false,
    receipt_capable: false,
    downstream_refusal: false,
    evidence: {
      validation: {
        artifact_present: false,
        valid: false,
        validation_error: cleanString(message || 'runtime profile installation artifact missing', null),
      },
    },
  };
}

function falseInstalledRuntimeProfileTerminalChainEvidence(message) {
  return {
    configured: false,
    routed: false,
    alive: false,
    policy_current: false,
    receipt_capable: false,
    downstream_refusal: false,
    evidence: {
      validation: {
        artifact_present: false,
        valid: false,
        validation_error: cleanString(message || 'installed runtime profile terminal chain artifact missing', null),
      },
    },
  };
}

function caseById(cases, caseId) {
  return Array.isArray(cases)
    ? cases.find((item) => item && item.case_id === caseId)
    : null;
}

function runtimeRefusalProjection(cases, requiredCaseIds, {
  authority = false,
} = {}) {
  const observedCases = requiredCaseIds.map((caseId) => {
    const item = caseById(cases, caseId);
    const refused = Boolean(
      item &&
      item.service_write_accepted === false &&
      item.state_entry_count_delta === 0
    );
    return {
      case_id: caseId,
      reason_code: cleanString(item?.reason_code || null, null),
      ...(authority
        ? { refused_before_consumption_and_mutation: refused }
        : { refused_before_mutation: refused }),
    };
  });
  const allRefused = observedCases.every((item) => authority
    ? item.refused_before_consumption_and_mutation === true
    : item.refused_before_mutation === true);
  return {
    required_case_count: requiredCaseIds.length,
    observed_case_count: observedCases.filter((item) => item.reason_code).length,
    required_case_ids: [...requiredCaseIds],
    observed_cases: observedCases,
    taxonomy_sha256: sha256Hex(stableStringify(observedCases)),
    ...(authority
      ? { all_refused_before_consumption_and_mutation: allRefused }
      : { all_refused_before_mutation: allRefused }),
  };
}

function runtimeContractEvidence(runtimeProfile, summary, contract, sideDoor) {
  return {
    mutation_authoritative_route:
      cleanString(summary.mutation_authoritative_route || runtimeProfile.mutation_authoritative_route || null, null),
    consumed_authority_grant_store:
      cleanString(summary.consumed_authority_grant_store || runtimeProfile.consumed_authority_grant_store || null, null),
    consumption_identity:
      cleanString(summary.consumption_identity || runtimeProfile.consumption_identity || null, null),
    signed_payload_replay_identity:
      cleanString(summary.signed_payload_replay_identity || runtimeProfile.signed_payload_replay_identity || null, null),
    consumed_store_witness:
      cleanString(summary.consumed_store_witness || runtimeProfile.consumed_store_witness || null, null),
    consumed_store_write_model:
      cleanString(summary.consumed_store_write_model || runtimeProfile.consumed_store_write_model || null, null),
    authority_grant_contract_required_from_launcher:
      contract.authority_grant_contract_required_from_launcher === true ||
      contract.launcher_supplies_authority_grant_contract === true,
    authority_grant_appointment_required_from_launcher:
      contract.authority_grant_appointment_required_from_launcher === true ||
      contract.launcher_supplies_authority_grant_appointment === true,
    authority_grant_issuance_decision_required_from_launcher:
      contract.authority_grant_issuance_decision_required_from_launcher === true ||
      contract.launcher_supplies_authority_grant_issuance_decision === true,
    authorized_record_update_required_from_launcher:
      contract.authorized_record_update_required_from_launcher === true ||
      contract.launcher_supplies_authorized_record_update === true,
    request_supplied_authority_grant_refused:
      contract.request_supplied_authority_grant_refused === true ||
      (
        contract.authority_grant_material_agent_supplied === false &&
        contract.missing_mismatched_expired_revoked_or_consumed_grant_refused === true
      ),
    persistent_consumed_authority_grant_store:
      sideDoor.persistent_consumed_authority_grant_store === true ||
      runtimeProfile.storage_boundary?.persistent_consumed_authority_grant_store === true,
    consumed_store_anchor_present:
      sideDoor.consumed_store_anchor_present === true ||
      runtimeProfile.storage_boundary?.local_anchor_owned_by_launcher === true,
    consumed_store_witness_present:
      sideDoor.consumed_store_witness_present === true ||
      runtimeProfile.storage_boundary?.local_witness_owned_by_launcher === true,
  };
}

function fixtureAuthorityStatusEvidence({
  artifactContractSha256 = null,
} = {}) {
  const statusContractSha256 = artifactContractSha256 ||
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256;
  const status = protectedRecordsFixtureAuthorityGrantStatus(
    statusContractSha256
  );
  const artifactContractBoundToStatus =
    artifactContractSha256 === status.authority_grant_contract_sha256;
  const freshFixtureRightfulProjectionAllowed = Boolean(
    artifactContractBoundToStatus &&
      status.fresh_effect_allowed === true &&
      status.repeated_use_provenance_valid === true &&
      status.fresh_fixture_rightful_projection_allowed === true
  );
  return {
    status_type: cleanString(status.status_type, null),
    authority_grant_contract_sha256: cleanString(
      status.authority_grant_contract_sha256,
      null
    ),
    artifact_authority_grant_contract_sha256:
      cleanString(artifactContractSha256, null),
    artifact_contract_bound_to_status: artifactContractBoundToStatus,
    status: cleanString(status.status, null),
    status_source: cleanString(status.status_source, null),
    maximum_effect_uses: status.maximum_effect_uses,
    recorded_effect_uses: status.recorded_effect_uses,
    fresh_effect_allowed: status.fresh_effect_allowed === true,
    repeated_use_provenance_valid:
      status.repeated_use_provenance_valid === true,
    source_fresh_fixture_rightful_projection_allowed:
      status.fresh_fixture_rightful_projection_allowed === true,
    fresh_fixture_rightful_projection_allowed:
      freshFixtureRightfulProjectionAllowed,
    replacement_authority_grant_present:
      status.replacement_authority_grant_present === true,
  };
}

function terminalChainNamedReceiptRefusals(namedRefusals) {
  return Object.fromEntries(
    Object.entries(REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_NAMED_RECEIPT_REFUSALS)
      .map(([key, expected]) => [
        key,
        namedRefusals?.[key]?.case_id === expected.case_id &&
          namedRefusals?.[key]?.reason_code === expected.reason_code &&
          namedRefusals?.[key]?.refused_before_mutation === true,
      ])
  );
}

function terminalChainTrustedIssuerRegistryRefusalCases(localRefusals) {
  const cases = Array.isArray(localRefusals?.cases)
    ? localRefusals.cases.map((item) => ({
        case_id: cleanString(item?.case_id || null, null),
        reason_code: cleanString(item?.reason_code || null, null),
        refused: item?.decision === 'refuse' && item?.recognized === false,
      }))
    : [];
  const caseIds = cases.map((item) => item.case_id).filter(Boolean);
  const reasonCodes = cases.map((item) => item.reason_code).filter(Boolean);
  const preserved = Boolean(
    cases.length ===
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS.length &&
      REQUIRED_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_TRUSTED_ISSUER_REGISTRY_RECOGNITION_REFUSALS
        .every((expected, index) => (
          cases[index]?.case_id === expected.case_id &&
          cases[index]?.reason_code === expected.reason_code &&
          cases[index]?.refused === true
        ))
  );
  return {
    cases,
    case_ids: caseIds,
    reason_codes: reasonCodes,
    preserved,
  };
}

function terminalChainTrustedIssuerRegistryEvidence(terminal) {
  const binding = terminal?.trusted_issuer_registry_recognition_binding &&
    typeof terminal.trusted_issuer_registry_recognition_binding === 'object'
    ? terminal.trusted_issuer_registry_recognition_binding
    : {};
  const localRefusals = binding.trusted_issuer_registry_recognition_refusals &&
    typeof binding.trusted_issuer_registry_recognition_refusals === 'object'
    ? binding.trusted_issuer_registry_recognition_refusals
    : {};
  const bindingSha = terminal?.trusted_issuer_registry_recognition_binding_sha256;
  const refusalCases =
    terminalChainTrustedIssuerRegistryRefusalCases(localRefusals);

  return {
    verdict: cleanString(binding.verdict || null, null),
    recognized: binding.recognized === true,
    decision: cleanString(binding.decision || null, null),
    reason_code: cleanString(binding.reason_code || null, null),
    issuer_status: cleanString(binding.issuer_status || null, null),
    signature_valid: binding.signature_valid === true,
    registry_fixture_validated: binding.registry_fixture_validated === true,
    registry_fixture_evaluated: binding.registry_fixture_evaluated === true,
    registry_to_recognition_rule_evaluated:
      binding.registry_to_recognition_rule_evaluated === true,
    registry_evaluation_result_type:
      cleanString(binding.registry_evaluation_result_type || null, null),
    registry_trusted_issuer_count:
      Number.isInteger(binding.registry_trusted_issuer_count)
        ? binding.registry_trusted_issuer_count
        : null,
    required_audit_event_id_bound:
      binding.required_audit_event_id_bound === true,
    required_detail_hash_bound:
      binding.required_detail_hash_bound === true,
    recognition_contract_hash_bound:
      binding.recognition_contract_hash_bound === true,
    registry_receipt_contract_hash_bound:
      binding.registry_receipt_contract_hash_bound === true,
    selected_profile_hash_bound:
      binding.selected_profile_hash_bound === true,
    service_artifact_hash_bound:
      binding.service_artifact_hash_bound === true,
    binding_sha256: cleanString(bindingSha || binding.binding_sha256 || null, null),
    binding_sha_matches_summary: Boolean(
      bindingSha &&
        binding.binding_sha256 &&
        bindingSha === binding.binding_sha256
    ),
    registry_fixture_contract_sha256:
      cleanString(binding.registry_fixture_contract_sha256 || null, null),
    receipt_payload_contract_sha256:
      cleanString(binding.receipt_payload_contract_sha256 || null, null),
    local_refusals_all_refused: localRefusals.all_refused === true,
    local_refusal_case_count: Number.isInteger(localRefusals.case_count)
      ? localRefusals.case_count
      : null,
    local_refusal_case_ids: refusalCases.case_ids,
    local_refusal_reason_codes: refusalCases.reason_codes,
    local_refusal_cases: refusalCases.cases,
    local_refusal_case_ids_preserved: refusalCases.preserved,
    local_refusals_sha256:
      cleanString(binding.trusted_issuer_registry_recognition_refusals_sha256 || null, null),
    registry_public_key_material_included:
      binding.registry_public_key_material_included === true,
    receipt_envelope_included: binding.receipt_envelope_included === true,
    cryptographic_evidence_reproducible_from_artifact:
      binding.cryptographic_evidence_reproducible_from_artifact === true,
    live_trust_registry_state: binding.live_trust_registry_state === true,
    live_issuer_status_proven: binding.live_issuer_status_proven === true,
    key_custody_proven: binding.key_custody_proven === true,
    revocation_truth_proven: binding.revocation_truth_proven === true,
    production_trust_registry_proven:
      binding.production_trust_registry_proven === true,
    production_downstream_recognition_proven:
      binding.production_downstream_recognition_proven === true,
    production_authority: binding.production_authority === true,
    public_external_attestation: binding.public_external_attestation === true,
    sovereign_recognition: binding.sovereign_recognition === true,
    real_non_operator_review: binding.real_non_operator_review === true,
    current_machine_governance_proven:
      binding.current_machine_governance_proven === true,
  };
}

function terminalChainTrustedIssuerRegistryRecognized(evidence) {
  return Boolean(
    evidence.verdict === 'RECOGNIZED' &&
      evidence.recognized === true &&
      evidence.signature_valid === true &&
      evidence.registry_fixture_validated === true &&
      evidence.registry_fixture_evaluated === true &&
      evidence.registry_to_recognition_rule_evaluated === true &&
      evidence.registry_evaluation_result_type === 'downstream-recognition-rule-v1' &&
      evidence.registry_trusted_issuer_count === 1 &&
      evidence.required_audit_event_id_bound === true &&
      evidence.required_detail_hash_bound === true &&
      evidence.recognition_contract_hash_bound === true &&
      evidence.registry_receipt_contract_hash_bound === true &&
      evidence.selected_profile_hash_bound === true &&
      evidence.service_artifact_hash_bound === true &&
      evidence.binding_sha_matches_summary === true &&
      /^[a-f0-9]{64}$/.test(evidence.binding_sha256 || '') &&
      /^[a-f0-9]{64}$/.test(evidence.registry_fixture_contract_sha256 || '') &&
      /^[a-f0-9]{64}$/.test(evidence.receipt_payload_contract_sha256 || '') &&
      /^[a-f0-9]{64}$/.test(evidence.local_refusals_sha256 || '') &&
      evidence.local_refusals_all_refused === true &&
      evidence.local_refusal_case_ids_preserved === true &&
      evidence.registry_public_key_material_included === false &&
      evidence.receipt_envelope_included === false &&
      evidence.cryptographic_evidence_reproducible_from_artifact === false &&
      evidence.live_trust_registry_state === false &&
      evidence.live_issuer_status_proven === false &&
      evidence.key_custody_proven === false &&
      evidence.revocation_truth_proven === false &&
      evidence.production_trust_registry_proven === false &&
      evidence.production_downstream_recognition_proven === false &&
      evidence.production_authority === false &&
      evidence.public_external_attestation === false &&
      evidence.sovereign_recognition === false &&
      evidence.real_non_operator_review === false &&
      evidence.current_machine_governance_proven === false
  );
}

function installedRuntimeProfileTerminalChainRouteEvidence(chain) {
  const preflight =
    chain.nested_artifacts?.generated_preflight_artifact?.payload?.preflight || null;
  const serviceProof =
    chain.nested_artifacts?.generated_service_proof_artifact?.payload?.proof || null;
  const preflightActionClass = preflight?.recognition_contract?.action_class || null;
  const preflightInstalledProfileActionClass =
    preflight?.installed_profile?.action_class || null;
  const serviceSelectedProfileActionClass =
    serviceProof?.selected_profile?.action_class || null;
  const serviceConfigActionClass =
    serviceProof?.service_config_provenance?.config_action_class || null;
  const serviceRecognitionContractActionClass =
    serviceProof?.recognition_contract?.action_class || null;
  const actionClasses = [
    preflightActionClass,
    preflightInstalledProfileActionClass,
    serviceSelectedProfileActionClass,
    serviceConfigActionClass,
    serviceRecognitionContractActionClass,
  ];
  const preflightMutationRoute =
    preflight?.recognition_contract?.mutation_authoritative_route || null;
  const serviceBoundaryMutationRoute =
    serviceProof?.service_boundary?.mutation_authoritative_route || null;
  const serviceRecognitionMutationRoute =
    serviceProof?.recognition_contract?.mutation_authoritative_route || null;
  const mutationRoutes = [
    preflightMutationRoute,
    serviceBoundaryMutationRoute,
    serviceRecognitionMutationRoute,
  ];
  const presentActionClasses = actionClasses.filter(Boolean);
  const presentMutationRoutes = mutationRoutes.filter(Boolean);

  return {
    action_class: actionClasses.find(Boolean) || null,
    action_class_consistent:
      presentActionClasses.length >= 3 &&
      presentActionClasses.every((value) => value === 'records.write'),
    preflight_action_class: preflightActionClass,
    preflight_installed_profile_action_class: preflightInstalledProfileActionClass,
    service_selected_profile_action_class: serviceSelectedProfileActionClass,
    service_config_action_class: serviceConfigActionClass,
    service_recognition_contract_action_class: serviceRecognitionContractActionClass,
    mutation_authoritative_route: mutationRoutes.find(Boolean) || null,
    mutation_authoritative_route_consistent:
      presentMutationRoutes.length >= 2 &&
      presentMutationRoutes.every((value) =>
        value === EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE
      ),
    preflight_mutation_authoritative_route: preflightMutationRoute,
    service_boundary_mutation_authoritative_route: serviceBoundaryMutationRoute,
    service_recognition_mutation_authoritative_route: serviceRecognitionMutationRoute,
    consumed_authority_grant_store:
      serviceProof?.service_boundary?.consumed_authority_grant_store || null,
    consumption_identity:
      serviceProof?.service_boundary?.consumption_identity || null,
    signed_payload_replay_identity:
      serviceProof?.service_boundary?.signed_payload_replay_identity || null,
    consumed_store_write_model:
      serviceProof?.service_boundary?.consumed_store_write_model || null,
    consumed_grant_store_witness_source:
      serviceProof?.service_config_provenance?.consumed_grant_store_witness_source || null,
  };
}

function installedRuntimeProfileTerminalChainEvidence(lane) {
  const artifact = installedRuntimeProfileTerminalChainArtifact(lane);
  if (!artifact) {
    return falseInstalledRuntimeProfileTerminalChainEvidence(
      'installed runtime profile terminal chain artifact missing'
    );
  }

  let artifactVerification;
  try {
    assertProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact);
    artifactVerification =
      verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(artifact, {
        expectedArtifactBodySha256:
          PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
      });
  } catch (err) {
    return {
      ...falseInstalledRuntimeProfileTerminalChainEvidence(err.message),
      evidence: {
        validation: {
          artifact_present: true,
          valid: false,
          validation_error: cleanString(err.message, null),
        },
      },
    };
  }

  const { chain } = artifact.payload;
  const terminal = chain.terminal_chain;
  const install = chain.disposable_installation;
  const service = chain.generated_service_proof;
  const sideDoor = chain.side_door_report;
  const route = installedRuntimeProfileTerminalChainRouteEvidence(chain);
  const grantSummary = terminal.public_safe_grant_summary || service.public_safe_grant_summary || {};
  const authorityStatus = fixtureAuthorityStatusEvidence({
    artifactContractSha256:
      cleanString(grantSummary.authority_grant_contract_sha256, null),
  });
  const namedRefusals = terminalChainNamedReceiptRefusals(terminal.named_receipt_refusals);
  const allNamedRefusals = Object.values(namedRefusals).every(Boolean);
  const trustedIssuerRegistry =
    terminalChainTrustedIssuerRegistryEvidence(terminal);
  const trustedIssuerRegistryRecognized =
    terminalChainTrustedIssuerRegistryRecognized(trustedIssuerRegistry);
  const configured = Boolean(
    artifactVerification.artifact_identity_sha256_matched === true &&
      artifactVerification.outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256 === true &&
      chain.evidence_model === 'fresh-local-disposable-installed-runtime-profile-terminal-chain' &&
      chain.live_probing === false &&
      install.install_root_kind === 'launcher-owned-disposable-proof-root'
  );
  const routed = Boolean(
    route.action_class === 'records.write' &&
      route.action_class_consistent === true &&
      route.mutation_authoritative_route ===
        EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE &&
      route.mutation_authoritative_route_consistent === true &&
      route.consumed_authority_grant_store ===
        'persistent-single-use-authority-grant-contract-sha256-store' &&
      route.consumption_identity === 'authority-grant-contract-sha256' &&
      route.signed_payload_replay_identity === 'verified-signed-payload-sha256' &&
      route.consumed_store_write_model ===
        'per-file-temp-fsync-rename-non-atomic-across-store-anchor-witness' &&
      route.consumed_grant_store_witness_source ===
        'launcher-owned-local-proof-witness' &&
      terminal.generated_installed_root_preflighted === true &&
      terminal.generated_preflight_artifact_consumed_by_service_proof === true &&
      terminal.generated_service_proof_artifact_verified === true &&
      terminal.service_proof_bound_to_generated_preflight === true &&
      terminal.service_artifact_verification_bound_to_service_proof === true
  );
  const alive = Boolean(
    chain.live_probing === false &&
      install.install_root_created === true &&
      install.profile_copy_written === true &&
      install.active_profile_index_written === true &&
      install.profile_selected_from_install_root === true &&
      install.selected_by_explicit_id_and_sha === true &&
      install.selects_latest_profile === false &&
      install.disposable_root_removed_after_run === true &&
      service.runtime_service_started === true
  );
  const policyCurrent = Boolean(
    chain.runtime_profile.profile_sha256 === install.selected_profile_sha256 &&
      chain.runtime_profile.profile_sha256 ===
        'e632931d5ab89c5b01a63a85b5bf0273c729e14c78b58929f39ac4ff6f131469' &&
      terminal.recognition_contract_sha256 === service.recognition_contract_sha256
  );
  const receiptCapable = Boolean(
    artifactVerification.recognized_write_boarded === true &&
      artifactVerification.fixture_rightful_issuance_path_evidenced === true &&
      authorityStatus.fresh_fixture_rightful_projection_allowed === true &&
      artifactVerification
        .trusted_issuer_registry_signature_identity_bound_to_expected_terminal_artifact_sha256 === true &&
      artifactVerification
        .recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256 === true &&
      trustedIssuerRegistryRecognized &&
      /^[a-f0-9]{64}$/.test(terminal.recognition_contract_sha256 || '') &&
      /^[a-f0-9]{64}$/.test(terminal.named_receipt_refusals_sha256 || '')
  );
  const downstreamRefusal = Boolean(
    terminal.all_required_recognition_refusals_before_mutation === true &&
      terminal.all_required_authority_refusals_before_consumption_and_mutation === true &&
      terminal.required_recognition_refusal_case_count === 18 &&
      terminal.observed_recognition_refusal_case_count === 18 &&
      terminal.required_authority_refusal_case_count === 5 &&
      terminal.observed_authority_refusal_case_count === 5 &&
      terminal.same_process_signed_payload_replay_refused === true &&
      terminal.restart_consumed_authority_grant_refused === true &&
      terminal.missing_receipt_refused_before_mutation === true &&
      terminal.invalid_receipt_refused_before_mutation === true &&
      allNamedRefusals &&
      sideDoor.persistent_runtime_profile_installed === false &&
      sideDoor.runtime_profile_activation_performed === false &&
      sideDoor.hook_configuration_written === false &&
      sideDoor.user_config_written === false &&
      sideDoor.machine_config_written === false &&
      sideDoor.live_runtime_profile_checked === false &&
      sideDoor.live_records_system_checked === false &&
      sideDoor.production_records_service_checked === false
  );

  return {
    configured,
    routed,
    alive,
    policy_current: policyCurrent,
    receipt_capable: receiptCapable,
    downstream_refusal: downstreamRefusal,
    evidence: {
      validation: {
        artifact_present: true,
        valid: true,
        artifact_type: cleanString(artifact.artifact_type || null, null),
        body_sha256: cleanString(artifact.integrity?.body_sha256 || null, null),
        expected_body_sha256:
          PROTECTED_RECORDS_INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_SAMPLE_ARTIFACT_BODY_SHA256,
        artifact_identity_sha256_matched:
          artifactVerification.artifact_identity_sha256_matched === true,
        outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256:
          artifactVerification
            .outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256 === true,
      },
      route: {
        action_class: cleanString(route.action_class, null),
        action_class_consistent: route.action_class_consistent === true,
        preflight_action_class:
          cleanString(route.preflight_action_class, null),
        preflight_installed_profile_action_class:
          cleanString(route.preflight_installed_profile_action_class, null),
        service_selected_profile_action_class:
          cleanString(route.service_selected_profile_action_class, null),
        service_config_action_class:
          cleanString(route.service_config_action_class, null),
        service_recognition_contract_action_class:
          cleanString(route.service_recognition_contract_action_class, null),
        mutation_authoritative_route:
          cleanString(route.mutation_authoritative_route, null),
        mutation_authoritative_route_consistent:
          route.mutation_authoritative_route_consistent === true,
        preflight_mutation_authoritative_route:
          cleanString(route.preflight_mutation_authoritative_route, null),
        service_boundary_mutation_authoritative_route:
          cleanString(route.service_boundary_mutation_authoritative_route, null),
        service_recognition_mutation_authoritative_route:
          cleanString(route.service_recognition_mutation_authoritative_route, null),
        consumed_authority_grant_store:
          cleanString(route.consumed_authority_grant_store, null),
        consumption_identity: cleanString(route.consumption_identity, null),
        signed_payload_replay_identity:
          cleanString(route.signed_payload_replay_identity, null),
        consumed_store_write_model:
          cleanString(route.consumed_store_write_model, null),
        consumed_grant_store_witness_source:
          cleanString(route.consumed_grant_store_witness_source, null),
        runtime_profile_id: cleanString(chain.runtime_profile.runtime_profile_id || null, null),
        generated_installed_root_preflighted:
          terminal.generated_installed_root_preflighted === true,
        service_proof_bound_to_generated_preflight:
          terminal.service_proof_bound_to_generated_preflight === true,
        service_artifact_verification_bound_to_service_proof:
          terminal.service_artifact_verification_bound_to_service_proof === true,
      },
      heartbeat: {
        terminal_chain_run: true,
        local_disposable_install_root_created: install.install_root_created === true,
        profile_selected_from_install_root:
          install.profile_selected_from_install_root === true,
        runtime_service_started: service.runtime_service_started === true,
        disposable_root_removed_after_run:
          install.disposable_root_removed_after_run === true,
        live_probing: chain.live_probing === true,
      },
      policy: {
        plan_id: cleanString(chain.plan.plan_id || null, null),
        runtime_profile_id: cleanString(chain.runtime_profile.runtime_profile_id || null, null),
        runtime_profile_sha256: cleanString(chain.runtime_profile.profile_sha256 || null, null),
        selected_profile_sha256: cleanString(install.selected_profile_sha256 || null, null),
        selected_by_explicit_id_and_sha: install.selected_by_explicit_id_and_sha === true,
        selects_latest_profile: install.selects_latest_profile === true,
        recognition_contract_sha256: cleanString(terminal.recognition_contract_sha256 || null, null),
      },
      receipt: {
        recognized_write_boarded:
          artifactVerification.recognized_write_boarded === true,
        recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256:
          artifactVerification
            .recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256 === true,
        receipt_recognition_required: true,
        missing_or_unrecognized_receipt_refused:
          terminal.missing_receipt_refused_before_mutation === true &&
          terminal.invalid_receipt_refused_before_mutation === true &&
          terminal.named_receipt_refusals?.unknown_issuer?.refused_before_mutation === true,
        named_receipt_refusals_sha256:
          cleanString(terminal.named_receipt_refusals_sha256 || null, null),
      },
      trusted_issuer_registry: trustedIssuerRegistry,
      downstream_refusal: {
        named_receipt_refusals: namedRefusals,
        all_named_receipt_refusals: allNamedRefusals,
        recognition_refusals: {
          required_case_count: terminal.required_recognition_refusal_case_count,
          observed_case_count: terminal.observed_recognition_refusal_case_count,
          all_refused_before_mutation:
            terminal.all_required_recognition_refusals_before_mutation === true,
          taxonomy_sha256:
            cleanString(terminal.recognition_refusal_taxonomy_sha256 || null, null),
        },
        authority_refusals: {
          required_case_count: terminal.required_authority_refusal_case_count,
          observed_case_count: terminal.observed_authority_refusal_case_count,
          all_refused_before_consumption_and_mutation:
            terminal.all_required_authority_refusals_before_consumption_and_mutation === true,
          taxonomy_sha256:
            cleanString(terminal.authority_refusal_taxonomy_sha256 || null, null),
        },
        same_process_signed_payload_replay_refused:
          terminal.same_process_signed_payload_replay_refused === true,
        restart_consumed_authority_grant_refused:
          terminal.restart_consumed_authority_grant_refused === true,
        recognition_refusal_groups_sha256:
          cleanString(terminal.recognition_refusal_groups_sha256 || null, null),
        state_mutation_refused_before_runtime_effect:
          terminal.all_required_recognition_refusals_before_mutation === true &&
          terminal.all_required_authority_refusals_before_consumption_and_mutation === true &&
          allNamedRefusals,
      },
      authority_status: authorityStatus,
      rightful_issuance: {
        authority_domain_id: cleanString(grantSummary.authority_domain_id || null, null),
        grantor_role_id: cleanString(grantSummary.grantor_role_id || null, null),
        authority_grant_contract_sha256:
          cleanString(grantSummary.authority_grant_contract_sha256 || null, null),
        one_use_effect_grant: grantSummary.one_use_effect_grant === true,
        fixture_authority_grant_satisfied_at_evaluation_time:
          grantSummary.fixture_authority_grant_satisfied_at_evaluation_time === true &&
          authorityStatus.fresh_effect_allowed === true,
        historical_artifact_fixture_authority_grant_satisfied_at_evaluation_time:
          grantSummary.fixture_authority_grant_satisfied_at_evaluation_time === true,
        historical_artifact_fixture_rightful_issuance_path_evidenced:
          terminal.fixture_rightful_issuance_path_evidenced === true,
        fixture_rightful_issuance_path_evidenced:
          authorityStatus.fresh_fixture_rightful_projection_allowed === true,
        rightful_issuance_proven: terminal.rightful_issuance_proven === true,
        portable_rightful_issuance_proven:
          terminal.portable_rightful_issuance_proven === true,
        production_rightful_issuance_proven:
          terminal.production_rightful_issuance_proven === true,
        live_authority_proven: terminal.live_authority_proven === true,
        current_machine_governance_proven:
          terminal.current_machine_governance_proven === true,
        consequence_lifecycle_closed:
          terminal.consequence_lifecycle_closed === true,
      },
      boundaries: {
        disposable_install_only: sideDoor.disposable_install_only === true,
        persistent_runtime_profile_installed:
          sideDoor.persistent_runtime_profile_installed === true,
        runtime_profile_activation_performed:
          sideDoor.runtime_profile_activation_performed === true,
        hook_configuration_written: sideDoor.hook_configuration_written === true,
        user_config_written: sideDoor.user_config_written === true,
        machine_config_written: sideDoor.machine_config_written === true,
        live_runtime_profile_checked: sideDoor.live_runtime_profile_checked === true,
        live_records_system_checked: sideDoor.live_records_system_checked === true,
        production_records_service_checked:
          sideDoor.production_records_service_checked === true,
        current_machine_governance_proven:
          sideDoor.current_machine_governance_proven === true,
        live_mcp_coverage_checked: sideDoor.live_mcp_coverage_checked === true,
        live_approval_channel_health_checked:
          sideDoor.live_approval_channel_health_checked === true,
        exactly_once_effect_semantics:
          sideDoor.exactly_once_effect_semantics === true,
        atomic_store_anchor_witness_commit:
          sideDoor.atomic_store_anchor_witness_commit === true,
        state_append_after_grant_commit_burn_observed:
          sideDoor.state_append_after_grant_commit_burn_observed === true,
        metadata_partial_commit_burn_observed:
          sideDoor.metadata_partial_commit_burn_observed === true,
        store_and_anchor_rollback_refused_while_witness_ahead:
          sideDoor.store_and_anchor_rollback_refused_while_witness_ahead === true,
        store_anchor_and_witness_joint_rollback_detection:
          sideDoor.store_anchor_and_witness_joint_rollback_detection === true,
        joint_rollback_reopened_authority_grant_reuse:
          sideDoor.joint_rollback_reopened_authority_grant_reuse === true,
        host_filesystem_path_toctou_closed:
          sideDoor.host_filesystem_path_toctou_closed === true,
        historical_artifact_fixture_rightful_issuance_path_evidenced:
          sideDoor.fixture_rightful_issuance_path_evidenced === true,
        fixture_rightful_issuance_path_evidenced:
          authorityStatus.fresh_fixture_rightful_projection_allowed === true,
        rightful_issuance_proven: sideDoor.rightful_issuance_proven === true,
        portable_rightful_issuance_proven:
          sideDoor.portable_rightful_issuance_proven === true,
        production_rightful_issuance_proven:
          sideDoor.production_rightful_issuance_proven === true,
        live_authority_proven: sideDoor.live_authority_proven === true,
        consequence_lifecycle_closed:
          sideDoor.consequence_lifecycle_closed === true,
        external_attestation: sideDoor.external_attestation === true,
        sovereign_recognition: sideDoor.sovereign_recognition === true,
        unrouted_records_paths_checked: sideDoor.unrouted_records_paths_checked === true,
        known_open_boundaries: cleanArray(chain.known_open_boundaries),
      },
    },
  };
}

function serviceProfilePreflightEvidence(lane) {
  const artifact = serviceProfilePreflightArtifact(lane);
  if (!artifact) {
    return falseServiceProfilePreflightEvidence('service profile preflight artifact missing');
  }

  try {
    assertProtectedRecordsServiceProfilePreflightArtifact(artifact);
  } catch (err) {
    return {
      ...falseServiceProfilePreflightEvidence(err.message),
      evidence: {
        validation: {
          artifact_present: true,
          valid: false,
          validation_error: cleanString(err.message, null),
        },
      },
    };
  }

  const { profile, preflight } = artifact.payload;
  const boundary = preflight.environment_boundary;
  const contract = preflight.recognition_rule_contract;
  const sideDoor = preflight.side_door_report;
  const accepted = caseById(preflight.cases, 'recognized_profile_service_write_first_process');
  const replay = caseById(preflight.cases, 'replay_profile_refused_after_service_restart');
  const missing = caseById(preflight.cases, 'missing_receipt_profile_refused_before_service_mutation');
  const unrecognized = caseById(preflight.cases, 'unrecognized_receipt_profile_refused_before_service_mutation');
  const invalid = caseById(preflight.cases, 'invalid_receipt_profile_refused_before_service_mutation');
  const unknownIssuer = caseById(preflight.cases, 'unknown_issuer_profile_refused_before_service_mutation');
  const wrongPolicy = caseById(preflight.cases, 'wrong_policy_profile_refused_before_service_mutation');
  const stale = caseById(preflight.cases, 'stale_receipt_profile_refused_before_service_mutation');
  const requestStreamAuthority = caseById(
    preflight.cases,
    'request_stream_authority_material_profile_refused_before_service_mutation'
  );
  const directApiWithoutReceipt = caseById(preflight.cases, 'direct_api_profile_without_receipt_refused_before_service_mutation');
  const directApiWithReceipt = caseById(preflight.cases, 'direct_api_profile_receipt_present_refused_before_service_mutation');
  const requiredRefusals = {
    replay_refused: replay?.service_write_accepted === false && replay.state_entry_count_delta === 0,
    missing_receipt_refused: missing?.service_write_accepted === false && missing.state_entry_count_delta === 0,
    unrecognized_receipt_refused:
      unrecognized?.service_write_accepted === false && unrecognized.state_entry_count_delta === 0,
    invalid_receipt_refused: invalid?.service_write_accepted === false && invalid.state_entry_count_delta === 0,
    unknown_issuer_refused:
      unknownIssuer?.service_write_accepted === false && unknownIssuer.state_entry_count_delta === 0,
    wrong_policy_refused:
      wrongPolicy?.service_write_accepted === false &&
      wrongPolicy.state_entry_count_delta === 0 &&
      wrongPolicy.reason_code === 'policy_not_recognized',
    stale_receipt_refused: stale?.service_write_accepted === false && stale.state_entry_count_delta === 0,
    request_stream_authority_material_refused:
      requestStreamAuthority?.service_write_accepted === false &&
      requestStreamAuthority.state_entry_count_delta === 0 &&
      requestStreamAuthority.reason_code === 'request_stream_authority_material',
    request_stream_forbidden_fields_refused:
      sideDoor.request_stream_forbidden_fields_refused === true,
    direct_api_without_receipt_refused:
      directApiWithoutReceipt?.service_write_accepted === false &&
      directApiWithoutReceipt.state_entry_count_delta === 0 &&
      directApiWithoutReceipt.direct_api_attempted === true,
    direct_api_with_receipt_refused:
      directApiWithReceipt?.service_write_accepted === false &&
      directApiWithReceipt.state_entry_count_delta === 0 &&
      directApiWithReceipt.direct_api_attempted === true,
  };
  const allRequiredRefusals = SERVICE_PROFILE_PREFLIGHT_REQUIRED_REFUSALS
    .every((key) => requiredRefusals[key] === true);
  const configured = Boolean(
    profile.service_command &&
      preflight.evidence_model === 'local-disposable-config-backed-profile-preflight-fixture' &&
      preflight.live_probing === false &&
      preflight.deployment_posture === 'deployable_profile_preflight_only'
  );
  const routed = Boolean(
    profile.action_class === 'records.write' &&
      profile.recognition_boundary === 'downstream-recognition-before-service-mutation' &&
      profile.mutation_authoritative_route === 'receipt-recognition-before-service-state-append' &&
      boundary.authoritative_route === 'receipt-recognition-before-service-state-append' &&
      boundary.service_process_boundary === 'separate-cli-process' &&
      boundary.launcher_owned_config_required === true &&
      boundary.request_stream_authority_material_allowed === false
  );
  const alive = Boolean(
    preflight.live_probing === false &&
      accepted?.process_invocation === 1 &&
      accepted.service_write_accepted === true &&
      accepted.state_entry_count_delta === 1 &&
      replay?.separate_process_from_accepted === true &&
      sideDoor.live_profile_installed === false &&
      sideDoor.live_records_system_checked === false &&
      sideDoor.production_records_service_checked === false
  );
  const policyCurrent = Boolean(
    preflight.profile.profile_sha256 === artifact.payload.preflight.profile.profile_sha256 &&
      preflight.profile.profile_id === profile.profile_id &&
      preflight.profile.profile_status === profile.profile_status
  );
  const receiptCapable = Boolean(
    accepted?.service_write_accepted === true &&
      contract.deployment_scope &&
      contract.required_detail_binding === 'receipt.payload.detail_hash == sha256(canonical(record_update))'
  );
  const downstreamRefusal = Boolean(
    allRequiredRefusals &&
      sideDoor.launcher_owned_config_required === true &&
      sideDoor.request_stream_authority_material_allowed === false &&
      sideDoor.request_stream_authority_material_refused === true &&
      sideDoor.direct_api_without_receipt_refused === true &&
      sideDoor.direct_api_with_receipt_refused === true &&
      sideDoor.direct_filesystem_write_to_fixture_paths_closed === false &&
      sideDoor.live_profile_installed === false &&
      sideDoor.live_records_system_checked === false &&
      sideDoor.production_records_service_checked === false &&
      sideDoor.live_mcp_coverage_checked === false &&
      sideDoor.live_approval_channel_health_checked === false
  );

  return {
    configured,
    routed,
    alive,
    policy_current: policyCurrent,
    receipt_capable: receiptCapable,
    downstream_refusal: downstreamRefusal,
    evidence: {
      validation: {
        artifact_present: true,
        valid: true,
        artifact_type: cleanString(artifact.artifact_type || null, null),
        body_sha256: cleanString(artifact.integrity?.body_sha256 || null, null),
      },
      route: {
        action_class: cleanString(profile.action_class || null, null),
        service_type: cleanString(profile.service_type || null, null),
        service_command: cleanString(profile.service_command || null, null),
        service_process_boundary: cleanString(boundary.service_process_boundary || null, null),
        recognition_boundary: cleanString(profile.recognition_boundary || null, null),
        mutation_authoritative_route: cleanString(profile.mutation_authoritative_route || null, null),
        launcher_owned_config_required: boundary.launcher_owned_config_required === true,
        request_stream_authority_material_allowed:
          boundary.request_stream_authority_material_allowed === true,
      },
      heartbeat: {
        preflight_run: true,
        process_case_count: preflight.cases.length,
        accepted_process_invocation: accepted?.process_invocation ?? null,
        replay_separate_process: replay?.separate_process_from_accepted === true,
        live_probing: preflight.live_probing === true,
      },
      policy: {
        profile_id: cleanString(profile.profile_id || null, null),
        profile_status: cleanString(profile.profile_status || null, null),
        deployment_posture: cleanString(profile.deployment_posture || null, null),
        profile_sha256: cleanString(preflight.profile.profile_sha256 || null, null),
        deployment_scope: cleanString(contract.deployment_scope || null, null),
        accepted_policy_versions: cleanArray(contract.accepted_policy_versions),
        required_issuer_status: cleanString(contract.required_issuer_status || null, null),
        required_detail_binding: cleanString(contract.required_detail_binding || null, null),
      },
      receipt: {
        recognized_write_accepted: accepted?.service_write_accepted === true,
        receipt_recognition_required: Boolean(contract.deployment_scope),
        missing_or_unrecognized_receipt_refused:
          requiredRefusals.missing_receipt_refused === true &&
          requiredRefusals.unrecognized_receipt_refused === true,
      },
      downstream_refusal: {
        required_refusals: requiredRefusals,
        all_required_refusals: allRequiredRefusals,
        request_stream_authority_material_refused:
          requiredRefusals.request_stream_authority_material_refused === true,
        request_stream_forbidden_fields_refused:
          requiredRefusals.request_stream_forbidden_fields_refused === true,
        state_mutation_refused_before_service_effect: allRequiredRefusals,
      },
      boundaries: {
        direct_filesystem_write_to_fixture_paths_closed:
          sideDoor.direct_filesystem_write_to_fixture_paths_closed === true,
        runtime_profile_activation_checked:
          sideDoor.runtime_profile_activation_checked === true,
        live_profile_installed: sideDoor.live_profile_installed === true,
        live_records_system_checked: sideDoor.live_records_system_checked === true,
        production_records_service_checked:
          sideDoor.production_records_service_checked === true,
        live_mcp_coverage_checked: sideDoor.live_mcp_coverage_checked === true,
        live_approval_channel_health_checked:
          sideDoor.live_approval_channel_health_checked === true,
        external_attestation: sideDoor.external_attestation === true,
        sovereign_recognition: sideDoor.sovereign_recognition === true,
        unrouted_records_paths_checked: sideDoor.unrouted_records_paths_checked === true,
        known_open_boundaries: cleanArray(preflight.known_open_boundaries),
      },
    },
  };
}

function runtimeLocalActivationEvidence(lane) {
  const artifact = runtimeLocalActivationArtifact(lane);
  if (!artifact) {
    return falseRuntimeLocalActivationEvidence('runtime local activation artifact missing');
  }

  try {
    assertProtectedRecordsRuntimeLocalActivationArtifact(artifact);
  } catch (err) {
    return {
      ...falseRuntimeLocalActivationEvidence(err.message),
      evidence: {
        validation: {
          artifact_present: true,
          valid: false,
          validation_error: cleanString(err.message, null),
        },
      },
    };
  }

  const { plan, runtime_profile: runtimeProfile, proof } = artifact.payload;
  const summary = proof.runtime_proof_summary;
  const sideDoor = proof.side_door_report;
  const contract = proof.activation_contract;
  const recognitionRefusals = runtimeRefusalProjection(
    proof.case_summaries,
    RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASE_IDS
  );
  const authorityRefusals = runtimeRefusalProjection(
    proof.case_summaries,
    RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASE_IDS,
    { authority: true }
  );
  const runtimeContract = runtimeContractEvidence(
    runtimeProfile,
    summary,
    contract,
    sideDoor
  );
  const configured = Boolean(
    plan.local_activation_command &&
      plan.runtime_profile_source &&
      proof.evidence_model === 'local-disposable-runtime-activation-fixture' &&
      proof.live_probing === false
  );
  const routed = Boolean(
    plan.action_class === 'records.write' &&
      runtimeProfile.action_class === 'records.write' &&
      runtimeContract.mutation_authoritative_route === EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE &&
      runtimeContract.consumed_authority_grant_store ===
        'persistent-single-use-authority-grant-contract-sha256-store' &&
      runtimeContract.consumption_identity === 'authority-grant-contract-sha256' &&
      runtimeContract.signed_payload_replay_identity === 'verified-signed-payload-sha256' &&
      runtimeContract.consumed_store_witness === 'launcher-owned-local-store-hash-witness' &&
      runtimeContract.authority_grant_contract_required_from_launcher === true &&
      runtimeContract.authority_grant_appointment_required_from_launcher === true &&
      runtimeContract.authority_grant_issuance_decision_required_from_launcher === true &&
      runtimeContract.authorized_record_update_required_from_launcher === true &&
      runtimeContract.request_supplied_authority_grant_refused === true &&
      contract.downstream_recognition_required === true &&
      contract.launcher_supplies_config === true &&
      contract.config_path_agent_supplied === false &&
      contract.state_path_agent_supplied === false &&
      contract.recognition_rule_agent_supplied === false &&
      contract.issuer_registry_agent_supplied === false
  );
  const alive = Boolean(
    proof.live_probing === false &&
      summary.proof_run === true &&
      sideDoor.local_activation_applied === true &&
      sideDoor.disposable_runtime_config_written === true &&
      sideDoor.runtime_service_started === true &&
      sideDoor.persistent_runtime_config_written === false &&
      sideDoor.hook_configuration_written === false
  );
  const policyCurrent = Boolean(
    proof.runtime_profile.profile_sha_matches_plan === true &&
      proof.runtime_profile.profile_sha256 === plan.runtime_profile_sha256
  );
  const receiptCapable = Boolean(
    summary.recognized_write_accepted === true &&
      contract.downstream_recognition_required === true &&
      contract.missing_or_unrecognized_receipt_refused === true
  );
  const downstreamRefusal = Boolean(
    recognitionRefusals.all_refused_before_mutation === true &&
      authorityRefusals.all_refused_before_consumption_and_mutation === true &&
      summary.same_process_signed_payload_replay_refused === true &&
      summary.restart_consumed_authority_grant_refused === true &&
      sideDoor.request_stream_authority_material_accepted === false &&
      sideDoor.live_records_system_checked === false &&
      sideDoor.production_records_service_checked === false &&
      sideDoor.live_mcp_coverage_checked === false &&
      sideDoor.live_approval_channel_health_checked === false
  );

  return {
    configured,
    routed,
    alive,
    policy_current: policyCurrent,
    receipt_capable: receiptCapable,
    downstream_refusal: downstreamRefusal,
    evidence: {
      validation: {
        artifact_present: true,
        valid: true,
        artifact_type: cleanString(artifact.artifact_type || null, null),
        body_sha256: cleanString(artifact.integrity?.body_sha256 || null, null),
      },
      route: {
        action_class: cleanString(plan.action_class || runtimeProfile.action_class || null, null),
        mutation_authoritative_route: cleanString(runtimeProfile.mutation_authoritative_route || null, null),
        runtime_environment: cleanString(runtimeProfile.runtime_environment || null, null),
        service_command: cleanString(proof.runtime_proof_summary.service_command || null, null),
        local_activation_command: cleanString(plan.local_activation_command || null, null),
        downstream_recognition_required: contract.downstream_recognition_required === true,
        runtime_contract: runtimeContract,
      },
      heartbeat: {
        proof_run: summary.proof_run === true,
        local_activation_applied: sideDoor.local_activation_applied === true,
        disposable_runtime_config_written: sideDoor.disposable_runtime_config_written === true,
        runtime_service_started: sideDoor.runtime_service_started === true,
        live_probing: proof.live_probing === true,
      },
      policy: {
        plan_id: cleanString(plan.plan_id || null, null),
        plan_sha256: cleanString(proof.plan?.plan_sha256 || null, null),
        runtime_profile_id: cleanString(runtimeProfile.runtime_profile_id || null, null),
        runtime_profile_sha256: cleanString(proof.runtime_profile?.profile_sha256 || null, null),
        runtime_profile_sha_matches_plan: proof.runtime_profile?.profile_sha_matches_plan === true,
      },
      receipt: {
        recognized_write_accepted: summary.recognized_write_accepted === true,
        receipt_recognition_required: contract.downstream_recognition_required === true,
        missing_or_unrecognized_receipt_refused:
          contract.missing_or_unrecognized_receipt_refused === true,
      },
      downstream_refusal: {
        recognition_refusals: recognitionRefusals,
        authority_refusals: authorityRefusals,
        same_process_signed_payload_replay_refused:
          summary.same_process_signed_payload_replay_refused === true,
        restart_consumed_authority_grant_refused:
          summary.restart_consumed_authority_grant_refused === true,
        state_mutation_refused_before_runtime_effect:
          recognitionRefusals.all_refused_before_mutation === true &&
          authorityRefusals.all_refused_before_consumption_and_mutation === true,
      },
      boundaries: {
        persistent_runtime_profile_installed:
          sideDoor.persistent_runtime_profile_installed === true,
        hook_configuration_written: sideDoor.hook_configuration_written === true,
        live_records_system_checked: sideDoor.live_records_system_checked === true,
        production_records_service_checked: sideDoor.production_records_service_checked === true,
        live_mcp_coverage_checked: sideDoor.live_mcp_coverage_checked === true,
        live_approval_channel_health_checked:
          sideDoor.live_approval_channel_health_checked === true,
        exactly_once_effect_semantics:
          sideDoor.exactly_once_effect_semantics === true,
        atomic_store_anchor_witness_commit:
          sideDoor.atomic_store_anchor_witness_commit === true,
        partial_grant_commit_burn_window_named:
          sideDoor.partial_grant_commit_burn_window_named === true,
        partial_commit_witness_missing_observed:
          sideDoor.partial_commit_witness_missing_observed === true,
        store_and_anchor_joint_rollback_refused_while_witness_ahead:
          sideDoor.store_and_anchor_joint_rollback_refused_while_witness_ahead === true,
        store_anchor_and_witness_joint_rollback_detection:
          sideDoor.store_anchor_and_witness_joint_rollback_detection === true,
        joint_rollback_reopened_authority_grant_reuse:
          sideDoor.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse === true,
        host_filesystem_path_toctou_closed:
          sideDoor.host_filesystem_path_toctou_closed === true,
        fixture_authority_grant_effect_satisfied:
          summary.omitted_runtime_profile_id_reason_code ===
            'fixture_authority_grant_effect_satisfied',
        fixture_rightful_issuance_path_evidenced: false,
        rightful_issuance_proven: false,
        portable_rightful_issuance_proven: false,
        production_rightful_issuance_proven: false,
        live_authority_proven: false,
        current_machine_governance_proven: false,
        consequence_lifecycle_closed: false,
        external_attestation: sideDoor.external_attestation === true,
        sovereign_recognition: sideDoor.sovereign_recognition === true,
        unrouted_records_paths_checked: sideDoor.unrouted_records_paths_checked === true,
        known_open_boundaries: cleanArray(proof.known_open_boundaries),
      },
    },
  };
}

function runtimeProfileInstallationEvidence(lane) {
  const artifact = runtimeProfileInstallationArtifact(lane);
  if (!artifact) {
    return falseRuntimeProfileInstallationEvidence('runtime profile installation artifact missing');
  }

  try {
    assertProtectedRecordsRuntimeProfileInstallationArtifact(artifact);
  } catch (err) {
    return {
      ...falseRuntimeProfileInstallationEvidence(err.message),
      evidence: {
        validation: {
          artifact_present: true,
          valid: false,
          validation_error: cleanString(err.message, null),
        },
      },
    };
  }

  const { plan, runtime_profile: runtimeProfile, proof } = artifact.payload;
  const summary = proof.runtime_proof_summary;
  const sideDoor = proof.side_door_report;
  const contract = proof.activation_contract;
  const installation = proof.installation;
  const guard = proof.request_authority_guard_summary;
  const recognitionRefusals = runtimeRefusalProjection(
    proof.case_summaries,
    RUNTIME_PROFILE_RECOGNITION_REFUSAL_CASE_IDS
  );
  const authorityRefusals = runtimeRefusalProjection(
    proof.case_summaries,
    RUNTIME_PROFILE_AUTHORITY_REFUSAL_CASE_IDS,
    { authority: true }
  );
  const runtimeContract = runtimeContractEvidence(
    runtimeProfile,
    summary,
    contract,
    sideDoor
  );
  const authorityStatus = fixtureAuthorityStatusEvidence({
    artifactContractSha256:
      cleanString(summary.authority_grant_contract_sha256, null),
  });
  const configured = Boolean(
    plan.installation_command &&
      plan.runtime_profile_source &&
      proof.evidence_model === 'local-disposable-runtime-profile-installation-fixture' &&
      proof.live_probing === false
  );
  const routed = Boolean(
    plan.action_class === 'records.write' &&
      runtimeProfile.action_class === 'records.write' &&
      runtimeContract.mutation_authoritative_route === EXACT_RUNTIME_MUTATION_AUTHORITATIVE_ROUTE &&
      runtimeContract.consumed_authority_grant_store ===
        'persistent-single-use-authority-grant-contract-sha256-store' &&
      runtimeContract.consumption_identity === 'authority-grant-contract-sha256' &&
      runtimeContract.signed_payload_replay_identity === 'verified-signed-payload-sha256' &&
      runtimeContract.consumed_store_witness === 'launcher-owned-local-store-hash-witness' &&
      runtimeContract.authority_grant_contract_required_from_launcher === true &&
      runtimeContract.authority_grant_appointment_required_from_launcher === true &&
      runtimeContract.authority_grant_issuance_decision_required_from_launcher === true &&
      runtimeContract.authorized_record_update_required_from_launcher === true &&
      runtimeContract.request_supplied_authority_grant_refused === true &&
      installation.selected_by_explicit_id_and_sha === true &&
      installation.selects_latest_profile === false &&
      contract.downstream_recognition_required === true &&
      contract.launcher_supplies_config === true &&
      contract.config_path_agent_supplied === false &&
      contract.state_path_agent_supplied === false &&
      contract.recognition_rule_agent_supplied === false &&
      contract.issuer_registry_agent_supplied === false
  );
  const alive = Boolean(
    proof.live_probing === false &&
      summary.proof_run === true &&
      sideDoor.disposable_profile_installation_applied === true &&
      sideDoor.local_disposable_install_root_created === true &&
      sideDoor.profile_copied_to_install_root === true &&
      sideDoor.active_profile_index_written === true &&
      sideDoor.profile_selected_from_install_root === true &&
      sideDoor.disposable_runtime_config_written === true &&
      sideDoor.runtime_service_started === true &&
      sideDoor.persistent_runtime_config_written === false &&
      sideDoor.persistent_runtime_profile_installed === false &&
      sideDoor.hook_configuration_written === false &&
      sideDoor.user_config_written === false &&
      sideDoor.machine_config_written === false
  );
  const policyCurrent = Boolean(
    proof.runtime_profile.profile_sha_matches_plan === true &&
      proof.runtime_profile.profile_sha256 === plan.runtime_profile_sha256 &&
      installation.selected_profile_sha256 === plan.runtime_profile_sha256
  );
  const receiptCapable = Boolean(
    summary.recognized_write_accepted === true &&
      authorityStatus.fresh_fixture_rightful_projection_allowed === true &&
      contract.downstream_recognition_required === true &&
      contract.missing_or_unrecognized_receipt_refused === true
  );
  const requestGuardRefused = Boolean(
    guard.all_refused_before_mutation === true &&
      guard.installed_profile_state_refused === true &&
      guard.runtime_config_refused === true &&
      guard.runtime_profile_refused === true &&
      guard.recognition_rule_refused === true &&
      guard.state_entry_count_delta_total === 0
  );
  const downstreamRefusal = Boolean(
    recognitionRefusals.all_refused_before_mutation === true &&
      authorityRefusals.all_refused_before_consumption_and_mutation === true &&
      summary.same_process_signed_payload_replay_refused === true &&
      summary.restart_consumed_authority_grant_refused === true &&
      requestGuardRefused &&
      sideDoor.request_stream_authority_material_accepted === false &&
      sideDoor.live_runtime_profile_checked === false &&
      sideDoor.live_records_system_checked === false &&
      sideDoor.production_records_service_checked === false &&
      sideDoor.live_mcp_coverage_checked === false &&
      sideDoor.live_approval_channel_health_checked === false
  );

  return {
    configured,
    routed,
    alive,
    policy_current: policyCurrent,
    receipt_capable: receiptCapable,
    downstream_refusal: downstreamRefusal,
    evidence: {
      validation: {
        artifact_present: true,
        valid: true,
        artifact_type: cleanString(artifact.artifact_type || null, null),
        body_sha256: cleanString(artifact.integrity?.body_sha256 || null, null),
      },
      route: {
        action_class: cleanString(plan.action_class || runtimeProfile.action_class || null, null),
        mutation_authoritative_route: cleanString(runtimeProfile.mutation_authoritative_route || null, null),
        runtime_environment: cleanString(runtimeProfile.runtime_environment || null, null),
        service_command: cleanString(summary.service_command || null, null),
        installation_command: cleanString(plan.installation_command || null, null),
        downstream_recognition_required: contract.downstream_recognition_required === true,
        installed_profile_status: cleanString(installation.installed_profile_status || null, null),
        runtime_contract: runtimeContract,
      },
      heartbeat: {
        proof_run: summary.proof_run === true,
        disposable_profile_installation_applied:
          sideDoor.disposable_profile_installation_applied === true,
        local_disposable_install_root_created:
          sideDoor.local_disposable_install_root_created === true,
        profile_copied_to_install_root: sideDoor.profile_copied_to_install_root === true,
        active_profile_index_written: sideDoor.active_profile_index_written === true,
        profile_selected_from_install_root:
          sideDoor.profile_selected_from_install_root === true,
        runtime_service_started: sideDoor.runtime_service_started === true,
        live_probing: proof.live_probing === true,
      },
      policy: {
        plan_id: cleanString(plan.plan_id || null, null),
        plan_sha256: cleanString(proof.plan?.plan_sha256 || null, null),
        runtime_profile_id: cleanString(runtimeProfile.runtime_profile_id || null, null),
        runtime_profile_sha256: cleanString(proof.runtime_profile?.profile_sha256 || null, null),
        runtime_profile_sha_matches_plan: proof.runtime_profile?.profile_sha_matches_plan === true,
        selected_profile_sha256: cleanString(installation.selected_profile_sha256 || null, null),
        selected_by_explicit_id_and_sha: installation.selected_by_explicit_id_and_sha === true,
        selects_latest_profile: installation.selects_latest_profile === true,
      },
      receipt: {
        recognized_write_accepted: summary.recognized_write_accepted === true,
        receipt_recognition_required: contract.downstream_recognition_required === true,
        missing_or_unrecognized_receipt_refused:
          contract.missing_or_unrecognized_receipt_refused === true,
      },
      downstream_refusal: {
        recognition_refusals: recognitionRefusals,
        authority_refusals: authorityRefusals,
        same_process_signed_payload_replay_refused:
          summary.same_process_signed_payload_replay_refused === true,
        restart_consumed_authority_grant_refused:
          summary.restart_consumed_authority_grant_refused === true,
        request_authority_guard_refused: requestGuardRefused,
        request_authority_guard_reason_codes: cleanArray(guard.reason_codes),
        state_mutation_refused_before_runtime_effect:
          recognitionRefusals.all_refused_before_mutation === true &&
          authorityRefusals.all_refused_before_consumption_and_mutation === true &&
          requestGuardRefused,
      },
      authority_status: authorityStatus,
      boundaries: {
        persistent_runtime_profile_installed:
          sideDoor.persistent_runtime_profile_installed === true,
        hook_configuration_written: sideDoor.hook_configuration_written === true,
        user_config_written: sideDoor.user_config_written === true,
        machine_config_written: sideDoor.machine_config_written === true,
        live_runtime_profile_checked: sideDoor.live_runtime_profile_checked === true,
        live_records_system_checked: sideDoor.live_records_system_checked === true,
        production_records_service_checked: sideDoor.production_records_service_checked === true,
        live_mcp_coverage_checked: sideDoor.live_mcp_coverage_checked === true,
        live_approval_channel_health_checked:
          sideDoor.live_approval_channel_health_checked === true,
        exactly_once_effect_semantics:
          sideDoor.exactly_once_effect_semantics === true,
        atomic_store_anchor_witness_commit:
          sideDoor.atomic_store_anchor_witness_commit === true,
        partial_grant_commit_burn_window_named:
          sideDoor.partial_grant_commit_burn_window_named === true,
        store_anchor_and_witness_joint_rollback_detection:
          sideDoor.store_anchor_and_witness_joint_rollback_detection === true,
        host_filesystem_path_toctou_closed:
          sideDoor.host_filesystem_path_toctou_closed === true,
        historical_artifact_fixture_rightful_issuance_path_evidenced:
          summary.fixture_rightful_issuance_path_evidenced === true,
        fixture_rightful_issuance_path_evidenced:
          authorityStatus.fresh_fixture_rightful_projection_allowed === true,
        rightful_issuance_proven: false,
        portable_rightful_issuance_proven: false,
        production_rightful_issuance_proven: false,
        live_authority_proven: false,
        current_machine_governance_proven: false,
        consequence_lifecycle_closed: false,
        external_attestation: sideDoor.external_attestation === true,
        sovereign_recognition: sideDoor.sovereign_recognition === true,
        unrouted_records_paths_checked: sideDoor.unrouted_records_paths_checked === true,
        known_open_boundaries: cleanArray(proof.known_open_boundaries),
      },
    },
  };
}

function auditSummary(event) {
  if (!event || typeof event !== 'object') return null;
  const detail = event.detail && typeof event.detail === 'object' ? event.detail : {};
  return redactValue({
    id: event.id || null,
    ts: event.ts || null,
    source: event.source || null,
    domain: event.domain || null,
    action: event.action || null,
    outcome: event.outcome || null,
    rule: event.rule || event.rule_id || null,
    authorizer: event.authorizer || null,
    policy_version: event.policy_version || null,
    policy_key_id: event.policy_key_id || null,
    public_key_id: event.public_key_id || null,
    audit_hash_present: Boolean(event.audit_hash || event.auditHash || event.hash || event.audit_event_hash),
    tool: detail.tool || event.tool_name || null,
  });
}

function routeStatus(surface) {
  if (surface.configured !== true) return 'missing_configuration';
  if (surface.routed !== true) return 'not_routed';
  return 'routed';
}

function freshnessStatus(alive) {
  return alive === true ? 'fresh' : 'stale_or_missing';
}

function receiptStatus(receiptCapable) {
  return receiptCapable === true ? 'receipt_capable' : 'receipt_not_capable';
}

function downstreamRefusalStatus(downstreamRefusal) {
  return downstreamRefusal === true ? 'refusal_evidence_present' : 'refusal_evidence_missing';
}

function lastDecisionSummary(auditRef, receiptEvidence, fallback = {}) {
  const event = auditRef && typeof auditRef === 'object' ? auditRef : {};
  const detail = event.detail && typeof event.detail === 'object' ? event.detail : {};
  return redactValue({
    evidence_source: cleanString(fallback.evidence_source || 'audit_event', null),
    audit_event_id: cleanString(event.id || receiptEvidence?.audit_event_id || fallback.audit_event_id || null, null),
    observed_at: cleanString(event.ts || fallback.observed_at || null, null),
    domain: cleanString(event.domain || fallback.domain || null, null),
    action: cleanString(event.action || fallback.action || null, null),
    tool: cleanString(detail.tool || event.tool_name || fallback.tool || null, null),
    outcome: cleanString(event.outcome || receiptEvidence?.decision || fallback.outcome || null, null),
    rule: cleanString(event.rule || event.rule_id || fallback.rule || null, null),
    policy_version: cleanString(event.policy_version || receiptEvidence?.policy_version || fallback.policy_version || null, null),
    authorizer: cleanString(event.authorizer || fallback.authorizer || null, null),
  });
}

function lastReceiptSummary(receiptEvidence, fallback = {}) {
  const receipt = receiptEvidence && typeof receiptEvidence === 'object' ? receiptEvidence : {};
  return redactValue({
    evidence_source: cleanString(fallback.evidence_source || 'worker_receipt', null),
    present: receipt.present === undefined ? fallback.present === true : receipt.present === true,
    valid: receipt.valid === undefined ? fallback.valid === true : receipt.valid === true,
    verification_status: cleanString(
      fallback.verification_status ||
        (receipt.valid === true ? 'valid' : 'not_validated'),
      null
    ),
    event_id: cleanString(receipt.event_id || fallback.event_id || null, null),
    surface: cleanString(receipt.surface || fallback.surface || null, null),
    policy_version: cleanString(receipt.policy_version || fallback.policy_version || null, null),
    receipt_sha256: cleanString(receipt.receipt_sha256 || fallback.receipt_sha256 || null, null),
    detail_hash: cleanString(receipt.detail_hash || fallback.detail_hash || null, null),
    id_matches_audit: receipt.id_matches_audit ?? fallback.id_matches_audit ?? null,
    policy_matches_lane: receipt.policy_matches_lane ?? fallback.policy_matches_lane ?? null,
    audit_hash_matches: receipt.audit_hash_matches ?? fallback.audit_hash_matches ?? null,
  });
}

function issuerIdentitySummary(auditRef, policyEvidence, receiptEvidence, fallback = {}) {
  const event = auditRef && typeof auditRef === 'object' ? auditRef : {};
  const policy = policyEvidence && typeof policyEvidence === 'object' ? policyEvidence : {};
  return redactValue({
    evidence_source: cleanString(fallback.evidence_source || 'supplied_fixture_metadata', null),
    policy_key_id: cleanString(policy.key_id || event.policy_key_id || fallback.policy_key_id || null, null),
    audit_public_key_id: cleanString(event.public_key_id || fallback.audit_public_key_id || null, null),
    recognition_anchor_id: cleanString(fallback.recognition_anchor_id || null, null),
    receipt_surface: cleanString(receiptEvidence?.surface || fallback.receipt_surface || null, null),
    issuer_status_proven: fallback.issuer_status_proven === true,
    key_custody_proven: false,
    revocation_state_proven: false,
    production_trust_registry_proven: false,
    external_attestation: false,
    sovereign_recognition: false,
  });
}

function coverageSummary({
  configured,
  routed,
  alive,
  policy_current,
  receipt_capable,
  downstream_refusal,
  governed,
  verification_status,
  policy_version,
  known_boundaries,
}) {
  return {
    route_status: routeStatus({ configured, routed }),
    freshness_status: freshnessStatus(alive),
    policy_version: cleanString(policy_version || null, null),
    policy_status: policy_current === true ? 'current' : 'not_current',
    receipt_status: receiptStatus(receipt_capable),
    downstream_refusal_status: downstreamRefusalStatus(downstream_refusal),
    verification_status,
    governed,
    known_boundary_count: Array.isArray(known_boundaries) ? known_boundaries.length : 0,
  };
}

function auditReference(lane, auditEvent) {
  if (auditEvent && typeof auditEvent === 'object') return auditEvent;
  const ref = lane.audit_event_ref || lane.auditEventRef || null;
  if (ref && typeof ref === 'object') return ref;
  const id = lane.audit_event_id || lane.auditEventId || null;
  if (!id) return null;
  return {
    id,
    source: lane.audit_event_source || lane.auditEventSource || null,
    domain: lane.audit_event_domain || lane.auditEventDomain || null,
    outcome: lane.audit_event_outcome || lane.auditEventOutcome || null,
    rule: lane.audit_event_rule || lane.auditEventRule || null,
    policy_version: lane.audit_event_policy_version || lane.auditEventPolicyVersion || null,
    audit_hash: lane.audit_event_hash || lane.auditEventHash || null,
  };
}

function auditEventIdFor(lane, auditEvent) {
  return cleanString(
    auditEvent?.id ||
      lane.audit_event_id ||
      lane.auditEventId ||
      lane.audit_event_ref?.id ||
      lane.auditEventRef?.id ||
      null,
    null
  );
}

function auditEventHashFor(lane, auditEvent) {
  if (auditEvent && typeof auditEvent === 'object') {
    return sha256Hex(canonicalize(auditEvent));
  }
  return cleanString(
    lane.audit_event_hash ||
      lane.auditEventHash ||
      lane.audit_event_ref?.audit_hash ||
      lane.audit_event_ref?.auditHash ||
      lane.auditEventRef?.audit_hash ||
      lane.auditEventRef?.auditHash ||
      null,
    null
  );
}

function heartbeatEvidence(raw = {}) {
  const heartbeat = raw && typeof raw === 'object' ? raw : {};
  const state = cleanString(heartbeat.state || '');
  const lastHeartbeatEpoch = numberOrNull(heartbeat.last_heartbeat_epoch ?? heartbeat.lastHeartbeatEpoch);
  const nowEpoch = numberOrNull(heartbeat.now_epoch ?? heartbeat.nowEpoch);
  const freshnessSeconds = numberOrNull(heartbeat.freshness_seconds ?? heartbeat.freshnessSeconds ?? heartbeat.max_age_seconds ?? heartbeat.maxAgeSeconds) ?? 60;
  const ageSeconds = lastHeartbeatEpoch !== null && nowEpoch !== null ? nowEpoch - lastHeartbeatEpoch : null;
  const computedFresh = state === 'on' &&
    lastHeartbeatEpoch !== null &&
    nowEpoch !== null &&
    ageSeconds !== null &&
    ageSeconds >= 0 &&
    ageSeconds <= freshnessSeconds;
  const fresh = heartbeat.fresh === true ? computedFresh : computedFresh && heartbeat.fresh !== false;
  return {
    alive: fresh,
    evidence: {
      state: state || null,
      last_heartbeat_epoch: lastHeartbeatEpoch,
      now_epoch: nowEpoch,
      max_age_seconds: freshnessSeconds,
      age_seconds: ageSeconds,
      fresh,
    },
  };
}

function routeEvidence(lane, kind) {
  const route = lane.route && typeof lane.route === 'object' ? lane.route : {};
  const hook = lane.hook && typeof lane.hook === 'object' ? lane.hook : {};
  const mcp = lane.mcp_registration || lane.mcpRegistration || lane.profile || {};
  const configuredServerCount = numberOrNull(mcp.configured_server_count ?? mcp.configuredServerCount ?? route.configured_server_count ?? route.configuredServerCount);
  const directUpstreamObserved = boolFrom(
    mcp.direct_upstream_observed,
    mcp.directUpstreamObserved,
    mcp.direct_fake_upstream_registration,
    route.direct_upstream_observed,
    route.directUpstreamObserved
  );
  const extraRegistrationObserved = boolFrom(
    mcp.extra_registration_observed,
    mcp.extraRegistrationObserved,
    route.extra_registration_observed,
    route.extraRegistrationObserved,
    configuredServerCount !== null && configuredServerCount > 1
  );
  const malformed = boolFrom(lane.malformed, hook.malformed, route.malformed, mcp.malformed);
  const checkpointPresent = typeof lane.checkpoint_path === 'string' && lane.checkpoint_path.trim().length > 0;
  const configured = boolFrom(
    lane.configured,
    route.configured,
    hook.configured,
    mcp.configured,
    kind === 'mcp-gate' && configuredServerCount === 1
  );
  const requestedRouted = boolFrom(
    lane.routed,
    route.routed,
    hook.routed,
    mcp.routed,
    mcp.zlar_routed,
    mcp.zlarRouted
  );
  const bypassDetected = kind === 'mcp-gate' && (directUpstreamObserved || extraRegistrationObserved);
  const routed = configured && requestedRouted && checkpointPresent && !malformed && !bypassDetected;

  return {
    configured,
    routed,
    bypass_detected: bypassDetected,
    direct_upstream_observed: directUpstreamObserved,
    extra_registration_observed: extraRegistrationObserved,
    evidence: {
      checkpoint_present: checkpointPresent,
      configured_evidence_present: configured,
      routed_evidence_present: requestedRouted,
      malformed_evidence: malformed,
      configured_server_count: configuredServerCount,
      direct_upstream_observed: directUpstreamObserved,
      extra_registration_observed: extraRegistrationObserved,
      hook_name: cleanString(hook.name || hook.hook_name || route.hook_name || null, null),
      route_name: cleanString(route.name || route.route_name || mcp.server_name || null, null),
      gate_target: cleanString(hook.gate_target || hook.gateTarget || hook.command || route.gate_target || route.gateTarget || mcp.gate_target || mcp.gateTarget || null, null),
    },
  };
}

function policyEvidence(lane, auditEvent) {
  const policy = lane.policy && typeof lane.policy === 'object' ? lane.policy : {};
  const activeVersion = cleanString(policy.active_version || policy.activeVersion || policy.version || policy.expected_version || policy.expectedVersion || null, null);
  const evidenceVersion = cleanString(
    policy.evidence_version ||
      policy.evidenceVersion ||
      policy.observed_version ||
      policy.observedVersion ||
      policy.audit_policy_version ||
      policy.auditPolicyVersion ||
      auditEvent?.policy_version ||
      null,
    null
  );
  const expectedVersion = cleanString(policy.expected_version || policy.expectedVersion || activeVersion || null, null);
  const signatureValid = boolFrom(
    policy.signature_valid,
    policy.signatureValid,
    policy.valid_signature,
    policy.validSignature
  );
  const acknowledged = policy.acknowledged === undefined && policy.ack === undefined
    ? true
    : boolFrom(policy.acknowledged, policy.ack);
  const versionMatches = Boolean(activeVersion && evidenceVersion && activeVersion === evidenceVersion);
  const expectedMatches = !expectedVersion || expectedVersion === activeVersion;
  const policyCurrent = signatureValid && acknowledged && versionMatches && expectedMatches && policy.invalid !== true;

  return {
    policy_current: policyCurrent,
    active_version: activeVersion,
    evidence: {
      active_version: activeVersion,
      evidence_version: evidenceVersion,
      expected_version: expectedVersion,
      signature_valid: signatureValid,
      acknowledged,
      version_matches: versionMatches,
      expected_matches: expectedMatches,
      key_id: cleanString(policy.key_id || policy.keyId || auditEvent?.policy_key_id || null, null),
      active_policy_sha256: cleanString(policy.active_policy_sha256 || policy.activePolicySha256 || null, null),
      policy_pubkey_sha256: cleanString(policy.policy_pubkey_sha256 || policy.policyPubkeySha256 || null, null),
      verification_source: cleanString(policy.verification_source || policy.verificationSource || null, null),
    },
  };
}

function receiptEvidence(lane, kind, auditEvent, activePolicyVersion) {
  const receipt = lane.worker_receipt || lane.workerReceipt || null;
  const receiptRef = lane.worker_receipt_ref || lane.workerReceiptRef || null;
  if (!receipt) {
    if (receiptRef && typeof receiptRef === 'object') {
      const expectedSurface = kind === 'mcp-gate' ? 'mcp-gate' : 'bash-gate';
      const receiptEvent = receiptRef.event && typeof receiptRef.event === 'object' ? receiptRef.event : {};
      const present = receiptRef.present === undefined ? true : receiptRef.present === true;
      const validationSource = cleanString(receiptRef.validation_source || receiptRef.validationSource || null, null);
      const validationContract = cleanString(receiptRef.validation_contract || receiptRef.validationContract || null, null);
      const valid = false;
      const receiptEventId = cleanString(receiptRef.event_id || receiptRef.eventId || receiptEvent.id || null, null);
      const auditEventId = auditEventIdFor(lane, auditEvent);
      const receiptSurface = cleanString(receiptRef.surface || receiptEvent.surface || null, null);
      const receiptPolicyVersion = cleanString(receiptRef.policy_version || receiptRef.policyVersion || receiptRef.decision?.policy_version || null, null);
      const receiptAuditHash = cleanString(receiptRef.audit_hash || receiptRef.auditHash || receiptEvent.audit_hash || receiptEvent.auditHash || null, null);
      const expectedAuditHash = auditEventHashFor(lane, auditEvent);
      const detailHash = cleanString(receiptRef.detail_hash || receiptRef.detailHash || receiptRef.action?.detail_hash || null, null);
      const idMatchesAudit = Boolean(auditEventId && receiptEventId === auditEventId);
      const surfaceMatchesLane = receiptSurface === expectedSurface;
      const policyMatchesLane = Boolean(activePolicyVersion && receiptPolicyVersion === activePolicyVersion);
      const auditHashMatches = Boolean(expectedAuditHash && receiptAuditHash === expectedAuditHash);
      const receiptCapable = false;

      return {
        receipt_capable: receiptCapable,
        evidence: {
          present,
          valid,
          validation_source: validationSource || 'untrusted_worker_receipt_ref',
          validation_contract: validationContract,
          validation_trusted: false,
          reference_only: true,
          validation_error: cleanString(
            receiptRef.validation_error ||
              receiptRef.validationError ||
              'worker_receipt_ref is reference-only; supply worker_receipt for validation',
            null
          ),
          event_id: receiptEventId,
          audit_event_id: auditEventId,
          receipt_sha256: cleanString(receiptRef.receipt_sha256 || receiptRef.receiptSha256 || null, null),
          surface: receiptSurface,
          expected_surface: expectedSurface,
          decision: cleanString(receiptRef.decision_outcome || receiptRef.decisionOutcome || receiptRef.decision?.outcome || null, null),
          policy_version: receiptPolicyVersion,
          detail_hash: detailHash,
          id_matches_audit: idMatchesAudit,
          surface_matches_lane: surfaceMatchesLane,
          policy_matches_lane: policyMatchesLane,
          audit_hash_matches: auditHashMatches,
        },
      };
    }
    return {
      receipt_capable: false,
      evidence: {
        present: false,
        valid: false,
        id_matches_audit: false,
        surface_matches_lane: false,
        policy_matches_lane: false,
        audit_hash_matches: false,
      },
    };
  }

  const expectedSurface = kind === 'mcp-gate' ? 'mcp-gate' : 'bash-gate';
  let valid = false;
  let validationError = null;
  try {
    valid = validateWorkerReceipt(receipt);
  } catch (err) {
    validationError = err.message;
  }

  const receiptEventId = cleanString(receipt?.event?.id || null, null);
  const auditEventId = auditEventIdFor(lane, auditEvent);
  const receiptSurface = cleanString(receipt?.event?.surface || null, null);
  const receiptPolicyVersion = cleanString(receipt?.decision?.policy_version || null, null);
  const idMatchesAudit = Boolean(auditEventId && receiptEventId === auditEventId);
  const surfaceMatchesLane = receiptSurface === expectedSurface;
  const policyMatchesLane = Boolean(activePolicyVersion && receiptPolicyVersion === activePolicyVersion);
  const expectedAuditHash = auditEventHashFor(lane, auditEvent);
  const auditHashMatches = Boolean(expectedAuditHash && receipt?.event?.audit_hash === expectedAuditHash);
  const receiptCapable = valid &&
    idMatchesAudit &&
    surfaceMatchesLane &&
    policyMatchesLane &&
    auditHashMatches &&
    /^[a-f0-9]{64}$/.test(String(receipt?.action?.detail_hash || ''));

  return {
    receipt_capable: receiptCapable,
    evidence: {
      present: true,
      valid,
      validation_error: cleanString(validationError || null, null),
      event_id: receiptEventId,
      audit_event_id: auditEventId,
      receipt_sha256: valid ? sha256Hex(stableStringify(receipt)) : null,
      surface: receiptSurface,
      expected_surface: expectedSurface,
      decision: cleanString(receipt?.decision?.outcome || null, null),
      policy_version: receiptPolicyVersion,
      detail_hash: cleanString(receipt?.action?.detail_hash || null, null),
      id_matches_audit: idMatchesAudit,
      surface_matches_lane: surfaceMatchesLane,
      policy_matches_lane: policyMatchesLane,
      audit_hash_matches: auditHashMatches,
    },
  };
}

function downstreamRecognitionDecisionEvidence(decision, context = {}) {
  if (!decision || typeof decision !== 'object' || Array.isArray(decision)) {
    return { present: false, refused: false, evidence: null };
  }

  const resultType = cleanString(decision.result_type || decision.resultType || null, null);
  const outcome = cleanString(decision.decision || null, null);
  const reasonCode = cleanString(decision.reason_code || decision.reasonCode || null, null);
  const recognized = decision.recognized === true
    ? true
    : decision.recognized === false
      ? false
      : null;
  const reasonCodes = Array.isArray(decision.reasons)
    ? decision.reasons
      .map((reason) => cleanString(reason?.code || null, null))
      .filter(Boolean)
    : [];
  const payload = decision.evidence && typeof decision.evidence === 'object'
    ? decision.evidence.payload || {}
    : {};
  const rule = decision.evidence && typeof decision.evidence === 'object'
    ? decision.evidence.rule || {}
    : {};
  const payloadAuditEventId = cleanString(payload.audit_event_id || null, null);
  const payloadDetailHash = cleanString(payload.detail_hash || null, null);
  const laneAuditEventId = cleanString(context.audit_event_id || context.auditEventId || null, null);
  const laneDetailHash = cleanString(context.detail_hash || context.detailHash || null, null);
  const auditEventMatchesLane = Boolean(laneAuditEventId && payloadAuditEventId === laneAuditEventId);
  const detailHashMatchesLane = Boolean(laneDetailHash && payloadDetailHash === laneDetailHash);
  const refused = resultType === DOWNSTREAM_RECOGNITION_RULE_TYPE &&
    recognized === false &&
    outcome === 'refuse' &&
    reasonCode !== 'recognized' &&
    auditEventMatchesLane &&
    detailHashMatchesLane;

  return {
    present: true,
    refused,
    evidence: {
      present: true,
      result_type: resultType,
      recognized,
      decision: outcome,
      reason_code: reasonCode,
      reason_codes: reasonCodes,
      receipt_present: decision.evidence?.receipt_present ?? null,
      kid: cleanString(decision.evidence?.kid || null, null),
      signature_valid: decision.evidence?.signature_valid ?? null,
      receipt_id: cleanString(decision.evidence?.receipt_id || null, null),
      payload: {
        tool: cleanString(payload.tool || null, null),
        domain: cleanString(payload.domain || null, null),
        outcome: cleanString(payload.outcome || null, null),
        policy_version: cleanString(payload.policy_version || null, null),
        audit_event_id: payloadAuditEventId,
        detail_hash: payloadDetailHash,
      },
      lane_match: {
        audit_event_id: laneAuditEventId,
        detail_hash: laneDetailHash,
        audit_event_matches_lane: auditEventMatchesLane,
        detail_hash_matches_lane: detailHashMatchesLane,
      },
      rule: {
        deployment_scope: cleanString(rule.deployment_scope || null, null),
      },
    },
  };
}

function downstreamRefusalEvidence(lane, kind, auditEvent, receipt) {
  const downstream = lane.downstream_refusal || lane.downstreamRefusal || {};
  const recognition = downstreamRecognitionDecisionEvidence(
    downstream.recognition_decision || downstream.recognitionDecision || null,
    {
      audit_event_id: auditEventIdFor(lane, auditEvent),
      detail_hash: receipt?.evidence?.detail_hash || null,
    }
  );
  const applicable = downstream.applicable === undefined ? true : downstream.applicable !== false;
  const proved = downstream.proved === true ||
    recognition.refused ||
    (kind === 'mcp-gate' && downstream.upstream_observed_on_deny === false) ||
    (kind === 'mcp-gate' && downstream.upstreamObservedOnDeny === false);
  return {
    downstream_refusal: applicable && proved,
    evidence: {
      applicable,
      proved,
      mechanism: cleanString(
        downstream.mechanism ||
          downstream.reason ||
          (recognition.refused ? 'Supplied downstream recognition decision refused an unrecognized boarding credential.' : null),
        null
      ),
      upstream_observed_on_deny: downstream.upstream_observed_on_deny ?? downstream.upstreamObservedOnDeny ?? null,
      recognition_decision: recognition.evidence,
    },
  };
}

function verificationStatus({
  route,
  heartbeat,
  policy,
  receipt,
  downstream,
}) {
  if (route.bypass_detected) return 'rejected_mcp_bypass';
  if (!route.configured) return 'missing_configuration';
  if (!route.routed) return 'not_routed';
  if (!heartbeat.alive) return 'stale_or_missing_heartbeat';
  if (!policy.policy_current) return 'policy_not_current';
  if (!receipt.receipt_capable) return 'receipt_not_capable';
  if (!downstream.downstream_refusal) return 'downstream_refusal_missing';
  return 'governed';
}

function buildLaneSurface(lane) {
  const kind = laneKind(lane);
  const auditEvent = lane.audit_event || lane.auditEvent || null;
  const auditRef = auditReference(lane, auditEvent);
  const route = routeEvidence(lane, kind);
  const heartbeat = heartbeatEvidence(lane.heartbeat || lane.liveness || {});
  const policy = policyEvidence(lane, auditEvent);
  const receipt = receiptEvidence(lane, kind, auditEvent, policy.active_version);
  const downstream = downstreamRefusalEvidence(lane, kind, auditEvent, receipt);
  const governed = route.configured &&
    route.routed &&
    heartbeat.alive &&
    policy.policy_current &&
    receipt.receipt_capable &&
    downstream.downstream_refusal;
  const verification_status = governed
    ? 'governed'
    : verificationStatus({ route, heartbeat, policy, receipt, downstream });
  const knownBoundaries = cleanArray(lane.known_boundaries || lane.knownBoundaries, [
    'adjacent_clients_tools_or_paths',
    'unrouted_side_doors',
  ]);
  const lastDecision = lastDecisionSummary(auditRef, receipt.evidence);
  const lastReceipt = lastReceiptSummary(receipt.evidence);
  const issuerIdentity = issuerIdentitySummary(auditRef, policy.evidence, receipt.evidence);

  return {
    surface_id: cleanString(lane.surface_id || lane.surfaceId || lane.id || `${kind}.lane`),
    boarding_lane: cleanString(lane.boarding_lane || lane.boardingLane || `${kind} boarding lane`),
    checkpoint_path: cleanString(lane.checkpoint_path || lane.checkpointPath || ''),
    surface_type: kind,
    counted: true,
    configured: route.configured,
    routed: route.routed,
    alive: heartbeat.alive,
    policy_current: policy.policy_current,
    receipt_capable: receipt.receipt_capable,
    downstream_refusal: downstream.downstream_refusal,
    governed,
    verification_status,
    coverage_summary: coverageSummary({
      configured: route.configured,
      routed: route.routed,
      alive: heartbeat.alive,
      policy_current: policy.policy_current,
      receipt_capable: receipt.receipt_capable,
      downstream_refusal: downstream.downstream_refusal,
      governed,
      verification_status,
      policy_version: policy.active_version,
      known_boundaries: knownBoundaries,
    }),
    last_decision: lastDecision,
    last_receipt: lastReceipt,
    issuer_identity: issuerIdentity,
    known_boundaries: knownBoundaries,
    evidence: redactValue({
      route: route.evidence,
      heartbeat: heartbeat.evidence,
      policy: policy.evidence,
      receipt: receipt.evidence,
      downstream_refusal: downstream.evidence,
      audit_event: auditSummary(auditRef),
    }),
    non_claims: cleanArray(lane.non_claims, SURFACE_NON_CLAIMS),
  };
}

function buildServiceProfilePreflightSurface(lane) {
  const preflight = serviceProfilePreflightEvidence(lane);
  const governed = preflight.configured &&
    preflight.routed &&
    preflight.alive &&
    preflight.policy_current &&
    preflight.receipt_capable &&
    preflight.downstream_refusal;
  const verification_status = governed
    ? 'governed'
    : verificationStatus({
      route: {
        bypass_detected: false,
        configured: preflight.configured,
        routed: preflight.routed,
      },
      heartbeat: { alive: preflight.alive },
      policy: { policy_current: preflight.policy_current },
      receipt: { receipt_capable: preflight.receipt_capable },
      downstream: { downstream_refusal: preflight.downstream_refusal },
    });
  const policyVersion = preflight.evidence?.policy?.deployment_scope || null;
  const knownBoundaries = cleanArray(
    preflight.evidence?.boundaries?.known_open_boundaries,
    ['direct_filesystem_write_to_configured_fixture_paths', 'runtime_profile_not_installed', 'unrouted_records_paths']
  );
  const lastDecision = lastDecisionSummary(null, null, {
    evidence_source: 'service_profile_preflight_artifact',
    domain: 'protected-records',
    action: preflight.evidence?.route?.action_class || 'records.write',
    tool: preflight.evidence?.route?.service_command || null,
    outcome: preflight.evidence?.receipt?.recognized_write_accepted
      ? 'recognized_write_accepted'
      : 'not_accepted',
    rule: preflight.evidence?.route?.mutation_authoritative_route || null,
    policy_version: policyVersion,
    authorizer: 'fixture-recognition-rule',
  });
  const lastReceipt = lastReceiptSummary(null, {
    evidence_source: 'service_profile_preflight_artifact',
    present: preflight.evidence?.receipt?.receipt_recognition_required === true,
    valid: preflight.evidence?.receipt?.recognized_write_accepted === true,
    verification_status: preflight.evidence?.receipt?.recognized_write_accepted
      ? 'recognized_receipt_accepted'
      : 'receipt_not_accepted',
    surface: SERVICE_PROFILE_PREFLIGHT_KIND,
    policy_version: policyVersion,
  });
  const issuerIdentity = issuerIdentitySummary(null, preflight.evidence?.policy, null, {
    evidence_source: 'service_profile_preflight_artifact',
    policy_key_id: preflight.evidence?.policy?.deployment_scope || null,
    recognition_anchor_id: preflight.evidence?.policy?.profile_sha256 || null,
    receipt_surface: SERVICE_PROFILE_PREFLIGHT_KIND,
  });

  return {
    surface_id: cleanString(
      lane.surface_id ||
        lane.surfaceId ||
        lane.id ||
        'protected-records.service-profile.records.write'
    ),
    boarding_lane: cleanString(
      lane.boarding_lane ||
        lane.boardingLane ||
        'Protected records service-profile preflight records.write lane'
    ),
    checkpoint_path: cleanString(
      lane.checkpoint_path ||
        lane.checkpointPath ||
        'protected-records-service-profile-preflight:receipt-recognition-before-service-state-append'
    ),
    surface_type: SERVICE_PROFILE_PREFLIGHT_KIND,
    counted: true,
    configured: preflight.configured,
    routed: preflight.routed,
    alive: preflight.alive,
    policy_current: preflight.policy_current,
    receipt_capable: preflight.receipt_capable,
    downstream_refusal: preflight.downstream_refusal,
    governed,
    verification_status,
    coverage_summary: coverageSummary({
      configured: preflight.configured,
      routed: preflight.routed,
      alive: preflight.alive,
      policy_current: preflight.policy_current,
      receipt_capable: preflight.receipt_capable,
      downstream_refusal: preflight.downstream_refusal,
      governed,
      verification_status,
      policy_version: policyVersion,
      known_boundaries: knownBoundaries,
    }),
    last_decision: lastDecision,
    last_receipt: lastReceipt,
    issuer_identity: issuerIdentity,
    known_boundaries: knownBoundaries,
    evidence: redactValue(preflight.evidence),
    non_claims: cleanArray(lane.non_claims, [
      'This lane counts only the committed local disposable service-profile preflight artifact.',
      'This lane does not claim runtime activation, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ]),
  };
}

function buildRuntimeLocalActivationSurface(lane) {
  const runtime = runtimeLocalActivationEvidence(lane);
  const governed = runtime.configured &&
    runtime.routed &&
    runtime.alive &&
    runtime.policy_current &&
    runtime.receipt_capable &&
    runtime.downstream_refusal;
  const verification_status = governed
    ? 'governed'
    : verificationStatus({
      route: {
        bypass_detected: false,
        configured: runtime.configured,
        routed: runtime.routed,
      },
      heartbeat: { alive: runtime.alive },
      policy: { policy_current: runtime.policy_current },
      receipt: { receipt_capable: runtime.receipt_capable },
      downstream: { downstream_refusal: runtime.downstream_refusal },
    });
  const policyVersion = runtime.evidence?.policy?.runtime_profile_id || null;
  const knownBoundaries = cleanArray(
    runtime.evidence?.boundaries?.known_open_boundaries,
    ['local_activation_only', 'persistent_runtime_profile_installation', 'unrouted_records_paths']
  );
  const lastDecision = lastDecisionSummary(null, null, {
    evidence_source: 'runtime_local_activation_artifact',
    domain: 'protected-records',
    action: runtime.evidence?.route?.action_class || 'records.write',
    tool: runtime.evidence?.route?.service_command || null,
    outcome: runtime.evidence?.receipt?.recognized_write_accepted
      ? 'recognized_write_accepted'
      : 'not_accepted',
    rule: runtime.evidence?.route?.mutation_authoritative_route || null,
    policy_version: policyVersion,
    authorizer: 'fixture-recognition-rule',
  });
  const lastReceipt = lastReceiptSummary(null, {
    evidence_source: 'runtime_local_activation_artifact',
    present: runtime.evidence?.receipt?.receipt_recognition_required === true,
    valid: runtime.evidence?.receipt?.recognized_write_accepted === true,
    verification_status: runtime.evidence?.receipt?.recognized_write_accepted
      ? 'recognized_receipt_accepted'
      : 'receipt_not_accepted',
    surface: 'protected-records-runtime-local-activation',
    policy_version: policyVersion,
  });
  const issuerIdentity = issuerIdentitySummary(null, runtime.evidence?.policy, null, {
    evidence_source: 'runtime_local_activation_artifact',
    policy_key_id: runtime.evidence?.policy?.runtime_profile_id || null,
    recognition_anchor_id: runtime.evidence?.policy?.runtime_profile_sha256 || null,
    receipt_surface: 'protected-records-runtime-local-activation',
  });

  return {
    surface_id: cleanString(
      lane.surface_id ||
        lane.surfaceId ||
        lane.id ||
        'protected-records.runtime.records.write'
    ),
    boarding_lane: cleanString(
      lane.boarding_lane ||
        lane.boardingLane ||
        'Protected records runtime local activation records.write lane'
    ),
    checkpoint_path: cleanString(
      lane.checkpoint_path ||
        lane.checkpointPath ||
        'protected-records-runtime-local-activation:receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation'
    ),
    surface_type: RUNTIME_LOCAL_ACTIVATION_KIND,
    counted: true,
    configured: runtime.configured,
    routed: runtime.routed,
    alive: runtime.alive,
    policy_current: runtime.policy_current,
    receipt_capable: runtime.receipt_capable,
    downstream_refusal: runtime.downstream_refusal,
    governed,
    verification_status,
    coverage_summary: coverageSummary({
      configured: runtime.configured,
      routed: runtime.routed,
      alive: runtime.alive,
      policy_current: runtime.policy_current,
      receipt_capable: runtime.receipt_capable,
      downstream_refusal: runtime.downstream_refusal,
      governed,
      verification_status,
      policy_version: policyVersion,
      known_boundaries: knownBoundaries,
    }),
    last_decision: lastDecision,
    last_receipt: lastReceipt,
    issuer_identity: issuerIdentity,
    known_boundaries: knownBoundaries,
    evidence: redactValue(runtime.evidence),
    non_claims: cleanArray(lane.non_claims, [
      'This lane counts only the committed local disposable runtime activation artifact.',
      'This lane does not claim persistent install, hook configuration, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ]),
  };
}

function buildRuntimeProfileInstallationSurface(lane) {
  const runtime = runtimeProfileInstallationEvidence(lane);
  const governed = runtime.configured &&
    runtime.routed &&
    runtime.alive &&
    runtime.policy_current &&
    runtime.receipt_capable &&
    runtime.downstream_refusal;
  const verification_status = governed
    ? 'governed'
    : verificationStatus({
      route: {
        bypass_detected: false,
        configured: runtime.configured,
        routed: runtime.routed,
      },
      heartbeat: { alive: runtime.alive },
      policy: { policy_current: runtime.policy_current },
      receipt: { receipt_capable: runtime.receipt_capable },
      downstream: { downstream_refusal: runtime.downstream_refusal },
    });
  const policyVersion = runtime.evidence?.policy?.runtime_profile_id || null;
  const knownBoundaries = cleanArray(
    runtime.evidence?.boundaries?.known_open_boundaries,
    ['disposable_install_only', 'persistent_runtime_profile_installation', 'unrouted_records_paths']
  );
  const lastDecision = lastDecisionSummary(null, null, {
    evidence_source: 'runtime_profile_installation_artifact',
    domain: 'protected-records',
    action: runtime.evidence?.route?.action_class || 'records.write',
    tool: runtime.evidence?.route?.service_command || null,
    outcome: runtime.evidence?.receipt?.recognized_write_accepted
      ? 'recognized_write_accepted'
      : 'not_accepted',
    rule: runtime.evidence?.route?.mutation_authoritative_route || null,
    policy_version: policyVersion,
    authorizer: 'fixture-recognition-rule',
  });
  const lastReceipt = lastReceiptSummary(null, {
    evidence_source: 'runtime_profile_installation_artifact',
    present: runtime.evidence?.receipt?.receipt_recognition_required === true,
    valid: runtime.evidence?.receipt?.recognized_write_accepted === true,
    verification_status: runtime.evidence?.receipt?.recognized_write_accepted
      ? 'recognized_receipt_accepted'
      : 'receipt_not_accepted',
    surface: RUNTIME_PROFILE_INSTALLATION_KIND,
    policy_version: policyVersion,
  });
  const issuerIdentity = issuerIdentitySummary(null, runtime.evidence?.policy, null, {
    evidence_source: 'runtime_profile_installation_artifact',
    policy_key_id: runtime.evidence?.policy?.runtime_profile_id || null,
    recognition_anchor_id: runtime.evidence?.policy?.runtime_profile_sha256 || null,
    receipt_surface: RUNTIME_PROFILE_INSTALLATION_KIND,
  });

  return {
    surface_id: cleanString(
      lane.surface_id ||
        lane.surfaceId ||
        lane.id ||
        'protected-records.runtime.profile-installation.records.write'
    ),
    boarding_lane: cleanString(
      lane.boarding_lane ||
        lane.boardingLane ||
        'Protected records runtime profile installation records.write lane'
    ),
    checkpoint_path: cleanString(
      lane.checkpoint_path ||
        lane.checkpointPath ||
        'protected-records-runtime-profile-installation:installed-profile-selection-then-receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation'
    ),
    surface_type: RUNTIME_PROFILE_INSTALLATION_KIND,
    counted: true,
    configured: runtime.configured,
    routed: runtime.routed,
    alive: runtime.alive,
    policy_current: runtime.policy_current,
    receipt_capable: runtime.receipt_capable,
    downstream_refusal: runtime.downstream_refusal,
    governed,
    verification_status,
    coverage_summary: coverageSummary({
      configured: runtime.configured,
      routed: runtime.routed,
      alive: runtime.alive,
      policy_current: runtime.policy_current,
      receipt_capable: runtime.receipt_capable,
      downstream_refusal: runtime.downstream_refusal,
      governed,
      verification_status,
      policy_version: policyVersion,
      known_boundaries: knownBoundaries,
    }),
    last_decision: lastDecision,
    last_receipt: lastReceipt,
    issuer_identity: issuerIdentity,
    known_boundaries: knownBoundaries,
    evidence: redactValue(runtime.evidence),
    non_claims: cleanArray(lane.non_claims, [
      'This lane counts only the committed local disposable runtime profile installation artifact.',
      'This lane does not claim persistent install, hook configuration, user or machine configuration, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ]),
  };
}

function buildInstalledRuntimeProfileTerminalChainSurface(lane) {
  const terminal = installedRuntimeProfileTerminalChainEvidence(lane);
  const governed = terminal.configured &&
    terminal.routed &&
    terminal.alive &&
    terminal.policy_current &&
    terminal.receipt_capable &&
    terminal.downstream_refusal;
  const verification_status = governed
    ? 'governed'
    : verificationStatus({
      route: {
        bypass_detected: false,
        configured: terminal.configured,
        routed: terminal.routed,
      },
      heartbeat: { alive: terminal.alive },
      policy: { policy_current: terminal.policy_current },
      receipt: { receipt_capable: terminal.receipt_capable },
      downstream: { downstream_refusal: terminal.downstream_refusal },
    });
  const policyVersion = terminal.evidence?.policy?.runtime_profile_id || null;
  const knownBoundaries = cleanArray(
    terminal.evidence?.boundaries?.known_open_boundaries,
    ['disposable_install_only', 'persistent_runtime_profile_installation', 'unrouted_records_paths']
  );
  const lastDecision = lastDecisionSummary(null, null, {
    evidence_source: 'installed_runtime_profile_terminal_chain_artifact',
    domain: 'protected-records',
    action: terminal.evidence?.route?.action_class || 'records.write',
    tool: 'protected-records-installed-runtime-profile-terminal-chain',
    outcome: terminal.evidence?.receipt?.recognized_write_boarded
      ? 'recognized_write_boarded'
      : 'not_boarded',
    rule: terminal.evidence?.route?.mutation_authoritative_route || null,
    policy_version: policyVersion,
    authorizer: 'fixture-recognition-rule',
  });
  const lastReceipt = lastReceiptSummary(null, {
    evidence_source: 'installed_runtime_profile_terminal_chain_artifact',
    present: terminal.evidence?.receipt?.receipt_recognition_required === true,
    valid: terminal.evidence?.receipt?.recognized_write_boarded === true,
    verification_status: terminal.evidence?.receipt?.recognized_write_boarded
      ? 'recognized_receipt_boarded'
      : 'receipt_not_boarded',
    surface: INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_KIND,
    policy_version: policyVersion,
  });
  const issuerIdentity = issuerIdentitySummary(null, terminal.evidence?.policy, null, {
    evidence_source: 'installed_runtime_profile_terminal_chain_artifact',
    policy_key_id: terminal.evidence?.policy?.runtime_profile_id || null,
    recognition_anchor_id: terminal.evidence?.policy?.runtime_profile_sha256 || null,
    receipt_surface: INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_KIND,
  });

  return {
    surface_id: cleanString(
      lane.surface_id ||
        lane.surfaceId ||
        lane.id ||
        'protected-records.installed-runtime-profile.terminal-chain.records.write'
    ),
    boarding_lane: cleanString(
      lane.boarding_lane ||
        lane.boardingLane ||
        'Protected records installed-runtime-profile terminal-chain records.write lane'
    ),
    checkpoint_path: cleanString(
      lane.checkpoint_path ||
        lane.checkpointPath ||
        'protected-records-installed-runtime-profile-terminal-chain:receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation'
    ),
    surface_type: INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_KIND,
    counted: true,
    configured: terminal.configured,
    routed: terminal.routed,
    alive: terminal.alive,
    policy_current: terminal.policy_current,
    receipt_capable: terminal.receipt_capable,
    downstream_refusal: terminal.downstream_refusal,
    governed,
    verification_status,
    coverage_summary: coverageSummary({
      configured: terminal.configured,
      routed: terminal.routed,
      alive: terminal.alive,
      policy_current: terminal.policy_current,
      receipt_capable: terminal.receipt_capable,
      downstream_refusal: terminal.downstream_refusal,
      governed,
      verification_status,
      policy_version: policyVersion,
      known_boundaries: knownBoundaries,
    }),
    last_decision: lastDecision,
    last_receipt: lastReceipt,
    issuer_identity: issuerIdentity,
    known_boundaries: knownBoundaries,
    evidence: redactValue(terminal.evidence),
    non_claims: cleanArray(lane.non_claims, [
      'This lane counts only the committed local disposable installed-runtime-profile terminal-chain artifact.',
      'This lane does not claim persistent install, activation, hook/user/machine configuration, production service deployment, live current-machine governance, or unrouted records paths.',
      'This lane does not claim authority beyond the supplied fixture artifact.',
    ]),
  };
}

function buildSurfaceForLane(lane) {
  const kind = laneKind(lane);
  if (kind === SERVICE_PROFILE_PREFLIGHT_KIND || kind === 'service-profile-preflight') {
    return buildServiceProfilePreflightSurface(lane);
  }
  if (kind === RUNTIME_LOCAL_ACTIVATION_KIND || kind === 'runtime-local-activation') {
    return buildRuntimeLocalActivationSurface(lane);
  }
  if (kind === RUNTIME_PROFILE_INSTALLATION_KIND || kind === 'runtime-profile-installation') {
    return buildRuntimeProfileInstallationSurface(lane);
  }
  if (
    kind === INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_KIND ||
    kind === 'installed-runtime-profile-terminal-chain'
  ) {
    return buildInstalledRuntimeProfileTerminalChainSurface(lane);
  }
  return buildLaneSurface(lane);
}

function buildBoundarySurface(boundary) {
  const verificationStatusValue = cleanString(boundary.verification_status || boundary.verificationStatus || 'boundary');
  const knownBoundaries = cleanArray(boundary.known_boundaries || boundary.knownBoundaries, [
    cleanString(boundary.evidence?.boundary_kind || verificationStatusValue || 'boundary'),
  ]);
  return {
    surface_id: cleanString(boundary.surface_id || boundary.surfaceId || boundary.id),
    boarding_lane: cleanString(boundary.boarding_lane || boundary.boardingLane || 'Boundary lane'),
    checkpoint_path: cleanString(boundary.checkpoint_path || boundary.checkpointPath || 'boundary'),
    surface_type: cleanString(boundary.surface_type || boundary.surfaceType || 'boundary'),
    counted: false,
    configured: false,
    routed: false,
    alive: false,
    policy_current: false,
    receipt_capable: false,
    downstream_refusal: false,
    governed: false,
    verification_status: verificationStatusValue,
    coverage_summary: coverageSummary({
      configured: false,
      routed: false,
      alive: false,
      policy_current: false,
      receipt_capable: false,
      downstream_refusal: false,
      governed: false,
      verification_status: verificationStatusValue,
      policy_version: null,
      known_boundaries: knownBoundaries,
    }),
    last_decision: lastDecisionSummary(null, null, {
      evidence_source: 'boundary_entry',
      outcome: 'not_governed',
    }),
    last_receipt: lastReceiptSummary(null, {
      evidence_source: 'boundary_entry',
      present: false,
      valid: false,
      verification_status: 'not_receipt_capable',
    }),
    issuer_identity: issuerIdentitySummary(null, null, null, {
      evidence_source: 'boundary_entry',
    }),
    known_boundaries: knownBoundaries,
    evidence: redactValue(boundary.evidence || {}),
    non_claims: cleanArray(boundary.non_claims, BOUNDARY_NON_CLAIMS),
  };
}

function inputLanes(input) {
  const lanes = [];
  if (input.bashGateLane) lanes.push({ kind: 'bash-gate', ...input.bashGateLane });
  if (input.mcpGateLane) lanes.push({ kind: 'mcp-gate', ...input.mcpGateLane });
  if (input.serviceProfilePreflightLane) {
    lanes.push({ kind: SERVICE_PROFILE_PREFLIGHT_KIND, ...input.serviceProfilePreflightLane });
  }
  if (input.service_profile_preflight_lane) {
    lanes.push({ kind: SERVICE_PROFILE_PREFLIGHT_KIND, ...input.service_profile_preflight_lane });
  }
  if (input.runtimeLocalActivationLane) {
    lanes.push({ kind: RUNTIME_LOCAL_ACTIVATION_KIND, ...input.runtimeLocalActivationLane });
  }
  if (input.runtime_local_activation_lane) {
    lanes.push({ kind: RUNTIME_LOCAL_ACTIVATION_KIND, ...input.runtime_local_activation_lane });
  }
  if (input.runtimeProfileInstallationLane) {
    lanes.push({ kind: RUNTIME_PROFILE_INSTALLATION_KIND, ...input.runtimeProfileInstallationLane });
  }
  if (input.runtime_profile_installation_lane) {
    lanes.push({ kind: RUNTIME_PROFILE_INSTALLATION_KIND, ...input.runtime_profile_installation_lane });
  }
  if (input.installedRuntimeProfileTerminalChainLane) {
    lanes.push({
      kind: INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_KIND,
      ...input.installedRuntimeProfileTerminalChainLane,
    });
  }
  if (input.installed_runtime_profile_terminal_chain_lane) {
    lanes.push({
      kind: INSTALLED_RUNTIME_PROFILE_TERMINAL_CHAIN_KIND,
      ...input.installed_runtime_profile_terminal_chain_lane,
    });
  }
  if (Array.isArray(input.lanes)) lanes.push(...input.lanes);
  return lanes;
}

function buildPrivacyFlags() {
  return {
    live_probing_performed: false,
    raw_command_args_included: false,
    raw_mcp_args_included: false,
    private_paths_included: false,
    numeric_human_ids_included: false,
    real_chat_ids_included: false,
    credentials_included: false,
    prompt_text_included: false,
    final_text_included: false,
  };
}

function countsFor(surfaces) {
  const counted = surfaces.filter((surface) => surface.counted === true);
  return {
    total_surfaces: surfaces.length,
    counted_lanes: counted.length,
    governed_lanes: counted.filter((surface) => surface.governed).length,
    boundary_entries: surfaces.length - counted.length,
  };
}

export function buildGovernedSurfaceCoverageMap(input = {}) {
  const lanes = inputLanes(input);
  const boundaryInputs = [
    ...DEFAULT_BOUNDARIES,
    ...(Array.isArray(input.boundaries) ? input.boundaries : []),
    ...(Array.isArray(input.boundary_entries) ? input.boundary_entries : []),
  ];
  const surfaces = [
    ...lanes.map(buildSurfaceForLane),
    ...boundaryInputs.map(buildBoundarySurface),
  ];
  const report = {
    generated_at: cleanString(input.generatedAt || input.generated_at || new Date().toISOString()),
    report_type: REPORT_TYPE,
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    evidence_model: {
      source: 'fixtures',
      live_probing_performed: false,
      live_state_claimed: false,
    },
    surfaces,
    counts: countsFor(surfaces),
    non_claims: cleanArray(input.non_claims, NON_CLAIMS),
    privacy: buildPrivacyFlags(),
  };
  assertNoUnsafeCoverageMapText(report);
  return report;
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function assertBoolean(value, label) {
  if (typeof value !== 'boolean') {
    throw new Error(`${label} must be boolean`);
  }
}

function assertSurfaceShape(surface, index) {
  assertObject(surface, `surface[${index}]`);
  for (const key of REQUIRED_SURFACE_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(surface, key)) {
      throw new Error(`surface[${index}] missing ${key}`);
    }
  }
  for (const key of [
    'surface_id',
    'boarding_lane',
    'checkpoint_path',
    'surface_type',
    'verification_status',
  ]) {
    assertString(surface[key], `surface[${index}].${key}`);
  }
  for (const key of [
    'counted',
    'configured',
    'routed',
    'alive',
    'policy_current',
    'receipt_capable',
    'downstream_refusal',
    'governed',
  ]) {
    assertBoolean(surface[key], `surface[${index}].${key}`);
  }
  if (!VERIFICATION_STATUS_VALUES.includes(surface.verification_status)) {
    throw new Error(`surface[${index}].verification_status is invalid: ${surface.verification_status}`);
  }
  assertObject(surface.coverage_summary, `surface[${index}].coverage_summary`);
  for (const key of [
    'route_status',
    'freshness_status',
    'policy_status',
    'receipt_status',
    'downstream_refusal_status',
    'verification_status',
  ]) {
    assertString(surface.coverage_summary[key], `surface[${index}].coverage_summary.${key}`);
  }
  assertBoolean(surface.coverage_summary.governed, `surface[${index}].coverage_summary.governed`);
  if (typeof surface.coverage_summary.known_boundary_count !== 'number') {
    throw new Error(`surface[${index}].coverage_summary.known_boundary_count must be a number`);
  }
  assertObject(surface.last_decision, `surface[${index}].last_decision`);
  assertString(surface.last_decision.evidence_source, `surface[${index}].last_decision.evidence_source`);
  assertObject(surface.last_receipt, `surface[${index}].last_receipt`);
  assertString(surface.last_receipt.evidence_source, `surface[${index}].last_receipt.evidence_source`);
  assertString(surface.last_receipt.verification_status, `surface[${index}].last_receipt.verification_status`);
  assertObject(surface.issuer_identity, `surface[${index}].issuer_identity`);
  assertString(surface.issuer_identity.evidence_source, `surface[${index}].issuer_identity.evidence_source`);
  for (const key of [
    'issuer_status_proven',
    'key_custody_proven',
    'revocation_state_proven',
    'production_trust_registry_proven',
    'external_attestation',
    'sovereign_recognition',
  ]) {
    assertBoolean(surface.issuer_identity[key], `surface[${index}].issuer_identity.${key}`);
  }
  if (!Array.isArray(surface.known_boundaries)) {
    throw new Error(`surface[${index}].known_boundaries must be an array`);
  }
  if (surface.coverage_summary.verification_status !== surface.verification_status) {
    throw new Error(`surface[${index}].coverage_summary verification_status drifted`);
  }
  assertObject(surface.evidence, `surface[${index}].evidence`);
  if (!Array.isArray(surface.non_claims) || surface.non_claims.length === 0) {
    throw new Error(`surface[${index}].non_claims must be a non-empty array`);
  }
  if (surface.governed && !(
    surface.configured &&
    surface.routed &&
    surface.alive &&
    surface.policy_current &&
    surface.receipt_capable &&
    surface.downstream_refusal &&
    surface.verification_status === 'governed'
  )) {
    throw new Error(`surface[${index}] is governed without all required evidence gates`);
  }
  if (!surface.governed && surface.verification_status === 'governed') {
    throw new Error(`surface[${index}] has governed verification_status while governed=false`);
  }
}

function surfaceById(report, id) {
  return report.surfaces.find((surface) => surface.surface_id === id);
}

export function assertGovernedSurfaceCoverageMap(report) {
  assertObject(report, 'report');
  if (report.report_type !== REPORT_TYPE) throw new Error(`report_type must be ${REPORT_TYPE}`);
  if (report.safe_claim_ceiling !== SAFE_CLAIM_CEILING) throw new Error('safe claim ceiling drifted');
  assertString(report.generated_at, 'generated_at');
  assertObject(report.evidence_model, 'evidence_model');
  if (report.evidence_model.source !== 'fixtures') throw new Error('evidence_model.source must be fixtures');
  if (report.evidence_model.live_probing_performed !== false) throw new Error('live probing must remain false');
  if (!Array.isArray(report.surfaces) || report.surfaces.length === 0) throw new Error('surfaces must be a non-empty array');
  report.surfaces.forEach(assertSurfaceShape);
  const ids = new Set(report.surfaces.map((surface) => surface.surface_id));
  if (ids.size !== report.surfaces.length) throw new Error('surface ids must be unique');
  for (const id of REQUIRED_BOUNDARY_IDS) {
    if (!ids.has(id)) throw new Error(`missing boundary surface: ${id}`);
  }

  for (const surface of report.surfaces) {
    if (surface.counted && surface.surface_type === 'mcp-gate') {
      if (surface.evidence?.route?.direct_upstream_observed) {
        throw new Error('direct MCP upstream registration rejected as coverage evidence');
      }
      if (surface.evidence?.route?.extra_registration_observed) {
        throw new Error('extra MCP registration rejected as coverage evidence');
      }
    }
  }

  const cursor = surfaceById(report, 'cursor.afterFileEdit');
  if (cursor?.verification_status !== 'audit_only' || cursor.governed !== false) {
    throw new Error('Cursor afterFileEdit must remain audit-only');
  }
  const windsurf = surfaceById(report, 'windsurf.post_events');
  if (windsurf?.verification_status !== 'audit_only' || windsurf.governed !== false) {
    throw new Error('Windsurf post_* must remain audit-only');
  }
  const subagent = surfaceById(report, 'hook.subagent_start');
  if (subagent?.receipt_capable !== false || subagent.governed !== false) {
    throw new Error('SubagentStart must remain non-governed without receipt evidence');
  }
  if (!Array.isArray(report.non_claims) || !report.non_claims.includes('/contest is not implemented.')) {
    throw new Error('explicit non-claims must include /contest boundary');
  }
  assertObject(report.privacy, 'privacy');
  for (const [key, value] of Object.entries(report.privacy)) {
    if (value !== false) throw new Error(`privacy.${key} must be false`);
  }
  assertNoUnsafeCoverageMapText(report);
  return true;
}

function evidenceSummary(surface) {
  if (surface.counted) {
    return [
      `configured=${surface.configured}`,
      `routed=${surface.routed}`,
      `alive=${surface.alive}`,
      `policy_current=${surface.policy_current}`,
      `receipt_capable=${surface.receipt_capable}`,
      `downstream_refusal=${surface.downstream_refusal}`,
      `last_decision=${surface.last_decision?.outcome || 'unknown'}`,
      `last_receipt=${surface.last_receipt?.verification_status || 'unknown'}`,
      `issuer=${surface.issuer_identity?.policy_key_id || surface.issuer_identity?.audit_public_key_id || 'none'}`,
    ].join(' ');
  }
  return `boundary=${surface.verification_status}`;
}

export function formatGovernedSurfaceCoverageMapSummary(report) {
  assertGovernedSurfaceCoverageMap(report);
  const lines = [
    'Governed Surface Coverage Map v1',
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Evidence model: ${report.evidence_model.source}; live probing=${report.evidence_model.live_probing_performed}`,
    `Counts: governed=${report.counts.governed_lanes}/${report.counts.counted_lanes}; boundaries=${report.counts.boundary_entries}`,
    '',
    'Surfaces:',
    ...report.surfaces.map((surface) => `- ${surface.surface_id}: ${surface.verification_status}; ${evidenceSummary(surface)}`),
    '',
    'Non-claims:',
    ...report.non_claims.map((claim) => `- ${claim}`),
  ];
  const summary = lines.join('\n');
  assertNoUnsafeCoverageMapText(summary);
  return summary;
}

export function assertNoUnsafeCoverageMapText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_REPORT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`coverage map contains ${label}`);
    }
  }
  return true;
}
