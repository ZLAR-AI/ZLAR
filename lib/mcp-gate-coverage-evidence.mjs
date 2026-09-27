import { createHash } from 'node:crypto';
import {
  canonicalize,
  validateWorkerReceipt,
} from './worker-receipt.mjs';
import { assertNoUnsafeCoverageMapText } from './governed-surface-coverage-map.mjs';

export const MCP_GATE_COVERAGE_EVIDENCE_TYPE = 'mcp-gate-coverage-evidence-input-v1';
export const WORKER_RECEIPT_REF_VALIDATION_SOURCE = 'internal_worker_receipt_object_validation';
export const WORKER_RECEIPT_REF_CONTRACT = 'zlar-supplied-evidence-worker-receipt-ref-v1';

const DEFAULT_NON_CLAIMS = Object.freeze([
  'This is event-scoped supplied evidence for one MCP tools/call lane.',
  'No live probing is performed by this evidence assembler.',
  'This evidence does not prove live MCP coverage, live machine coverage, or coverage of unrouted surfaces.',
  'This evidence does not create outside attestation, deployment authority, or recognition-boundary claims.',
  '/contest is not implemented.',
]);

const DEFAULT_SURFACE_NON_CLAIMS = Object.freeze([
  'This lane describes one MCP tools/call event routed through the ZLAR MCP gate.',
  'This lane does not claim direct MCP registrations, extra MCP servers, adjacent clients, or non-MCP tools.',
  'This lane does not claim current-machine governance unless all supplied evidence gates pass.',
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
  return String(value ?? '')
    .replace(/(?:~|\/Users\/[^\s"'`;&|,)}\]]+|\/home\/[^\s"'`;&|,)}\]]+|\/private\/[^\s"'`;&|,)}\]]+|\/tmp\/[^\s"'`;&|,)}\]]+|\/var\/[^\s"'`;&|,)}\]]+)/g, '[REDACTED_PATH]')
    .replace(/\bhuman:[0-9][A-Za-z0-9_.:-]*/g, 'human:[REDACTED_ID]')
    .replace(/\b((?:token|secret|password|api[_-]?key)\s*[:=]\s*)([^&\s"'`,;})\]]+)/gi, '$1[REDACTED_CREDENTIAL]')
    .replace(/\b(authorization\s*[:=]\s*(?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]{6,})/gi, '$1[REDACTED_CREDENTIAL]')
    .replace(/\b((?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{6,})/g, '$1[REDACTED_CREDENTIAL]')
    .replace(/\bghp_[A-Za-z0-9_]{10,}\b/g, '[REDACTED_CREDENTIAL]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{10,}\b/g, '[REDACTED_CREDENTIAL]')
    .replace(/\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g, '[REDACTED_CREDENTIAL]')
    .replace(/\bAKIA[0-9A-Z]{12,}\b/g, '[REDACTED_CREDENTIAL]')
    .replace(/\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED_CREDENTIAL]')
    .replace(/\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/g, '[REDACTED_CREDENTIAL]');
}

function cleanString(value, fallback = '') {
  if (value === null || value === undefined || value === '') return fallback;
  return redactString(value);
}

function cleanArray(value, fallback) {
  if (!Array.isArray(value)) return [...fallback];
  return value.map((item) => cleanString(item)).filter(Boolean);
}

function bool(value) {
  return value === true;
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function requireEventId(input) {
  const eventId = cleanString(input.event_id || input.eventId || '');
  if (!eventId) throw new Error('event_id is required for MCP coverage evidence');
  return eventId;
}

function mcpToolName(event) {
  const detail = event?.detail && typeof event.detail === 'object' ? event.detail : {};
  return cleanString(detail.tool || event?.tool_name || event?.tool || null, null);
}

function rejectNonMcpEvent(event, eventId) {
  const source = String(event.source || '');
  const domain = String(event.domain || '');
  if (String(event.id || '') !== eventId) {
    throw new Error('audit event id does not match requested event_id');
  }
  if (source !== 'mcp-gate' || domain !== 'mcp') {
    throw new Error('MCP coverage evidence only accepts mcp-gate-sourced MCP events');
  }
  if (!mcpToolName(event)) {
    throw new Error('MCP coverage evidence requires a tools/call tool name');
  }
}

function auditReferenceFrom(input, eventId) {
  const rawEvent = input.audit_event || input.auditEvent || null;
  const ref = input.audit_event_ref || input.auditEventRef || null;

  if (rawEvent) {
    assertObject(rawEvent, 'audit_event');
    rejectNonMcpEvent(rawEvent, eventId);
    return {
      id: cleanString(rawEvent.id),
      source: 'mcp-gate',
      domain: 'mcp',
      outcome: cleanString(rawEvent.outcome || null, null),
      rule: cleanString(rawEvent.rule || rawEvent.rule_id || null, null),
      policy_version: cleanString(rawEvent.policy_version || null, null),
      audit_hash: sha256Hex(canonicalize(rawEvent)),
      transport: cleanString(rawEvent.transport || rawEvent.detail?.transport || rawEvent.detail?.mcp_transport || null, null),
      tool: mcpToolName(rawEvent),
    };
  }

  if (ref) {
    assertObject(ref, 'audit_event_ref');
    rejectNonMcpEvent({
      id: ref.id,
      source: ref.source,
      domain: ref.domain,
      detail: { tool: ref.tool || ref.tool_name },
    }, eventId);
    return {
      id: cleanString(ref.id),
      source: 'mcp-gate',
      domain: 'mcp',
      outcome: cleanString(ref.outcome || null, null),
      rule: cleanString(ref.rule || ref.rule_id || null, null),
      policy_version: cleanString(ref.policy_version || ref.policyVersion || null, null),
      audit_hash: cleanString(ref.audit_hash || ref.auditHash || ref.hash || null, null),
      transport: cleanString(ref.transport || null, null),
      tool: cleanString(ref.tool || ref.tool_name || null, null),
    };
  }

  throw new Error('audit_event or audit_event_ref is required for MCP coverage evidence');
}

function workerReceiptReferenceFrom(input) {
  const receipt = input.worker_receipt || input.workerReceipt || null;
  const ref = input.worker_receipt_ref || input.workerReceiptRef || null;

  if (receipt) {
    let valid = false;
    let validationError = null;
    try {
      valid = validateWorkerReceipt(receipt);
    } catch (err) {
      validationError = err.message;
    }
    return {
      present: true,
      valid,
      validation_source: WORKER_RECEIPT_REF_VALIDATION_SOURCE,
      validation_contract: WORKER_RECEIPT_REF_CONTRACT,
      validation_error: cleanString(validationError || null, null),
      event_id: cleanString(receipt?.event?.id || null, null),
      source: cleanString(receipt?.event?.source || null, null),
      surface: cleanString(receipt?.event?.surface || null, null),
      audit_hash: cleanString(receipt?.event?.audit_hash || null, null),
      receipt_sha256: sha256Hex(stableStringify(receipt)),
      decision_outcome: cleanString(receipt?.decision?.outcome || null, null),
      policy_version: cleanString(receipt?.decision?.policy_version || null, null),
      detail_hash: cleanString(receipt?.action?.detail_hash || null, null),
    };
  }

  if (!ref) return null;
  assertObject(ref, 'worker_receipt_ref');
  return {
    present: ref.present === undefined ? true : bool(ref.present),
    valid: false,
    validation_source: 'untrusted_supplied_worker_receipt_ref',
    validation_contract: null,
    validation_error: cleanString(ref.validation_error || ref.validationError || 'worker_receipt_ref is not self-validating; supply worker_receipt for internal validation.'),
    event_id: cleanString(ref.event_id || ref.eventId || null, null),
    source: cleanString(ref.source || null, null),
    surface: cleanString(ref.surface || null, null),
    audit_hash: cleanString(ref.audit_hash || ref.auditHash || null, null),
    receipt_sha256: cleanString(ref.receipt_sha256 || ref.receiptSha256 || null, null),
    decision_outcome: cleanString(ref.decision_outcome || ref.decisionOutcome || null, null),
    policy_version: cleanString(ref.policy_version || ref.policyVersion || null, null),
    detail_hash: cleanString(ref.detail_hash || ref.detailHash || null, null),
  };
}

function mcpRegistrationEvidence(input) {
  const registration = input.mcp_registration && typeof input.mcp_registration === 'object'
    ? input.mcp_registration
    : input.mcpRegistration && typeof input.mcpRegistration === 'object'
      ? input.mcpRegistration
      : input.profile && typeof input.profile === 'object'
        ? input.profile
        : {};
  const configuredServerCount = numberOrNull(registration.configured_server_count ?? registration.configuredServerCount);
  return {
    configured: bool(registration.configured),
    routed: bool(registration.routed),
    zlar_routed: bool(registration.zlar_routed ?? registration.zlarRouted),
    configured_server_count: configuredServerCount,
    server_name: cleanString(registration.server_name || registration.serverName || 'zlar-routed-mcp-gate'),
    transport: cleanString(registration.transport || 'stdio'),
    direct_upstream_observed: bool(registration.direct_upstream_observed ?? registration.directUpstreamObserved ?? registration.direct_fake_upstream_registration),
    extra_registration_observed: bool(registration.extra_registration_observed ?? registration.extraRegistrationObserved) ||
      (configuredServerCount !== null && configuredServerCount > 1),
    gate_target: cleanString(registration.gate_target || registration.gateTarget || 'mcp-gate'),
  };
}

function heartbeatEvidence(input) {
  const heartbeat = input.heartbeat && typeof input.heartbeat === 'object' ? input.heartbeat : {};
  return {
    state: cleanString(heartbeat.state || null, null),
    last_heartbeat_epoch: numberOrNull(heartbeat.last_heartbeat_epoch ?? heartbeat.lastHeartbeatEpoch),
    now_epoch: numberOrNull(heartbeat.now_epoch ?? heartbeat.nowEpoch),
    freshness_seconds: numberOrNull(heartbeat.freshness_seconds ?? heartbeat.freshnessSeconds ?? heartbeat.max_age_seconds ?? heartbeat.maxAgeSeconds),
  };
}

function policyEvidence(input, auditRef) {
  const policy = input.policy && typeof input.policy === 'object' ? input.policy : {};
  const activeVersion = cleanString(policy.active_version || policy.activeVersion || policy.version || null, null);
  const evidenceVersion = cleanString(policy.evidence_version || policy.evidenceVersion || auditRef.policy_version || null, null);
  return {
    active_version: activeVersion,
    evidence_version: evidenceVersion,
    expected_version: cleanString(policy.expected_version || policy.expectedVersion || activeVersion || null, null),
    signature_valid: bool(policy.signature_valid ?? policy.signatureValid),
    acknowledged: policy.acknowledged === undefined && policy.ack === undefined ? true : bool(policy.acknowledged || policy.ack),
    key_id: cleanString(policy.key_id || policy.keyId || null, null),
    active_policy_sha256: cleanString(policy.active_policy_sha256 || policy.activePolicySha256 || null, null),
    policy_pubkey_sha256: cleanString(policy.policy_pubkey_sha256 || policy.policyPubkeySha256 || null, null),
    verification_source: cleanString(policy.verification_source || policy.verificationSource || 'supplied-evidence'),
  };
}

function downstreamRefusalEvidence(input) {
  const downstream = input.downstream_refusal && typeof input.downstream_refusal === 'object'
    ? input.downstream_refusal
    : input.downstreamRefusal && typeof input.downstreamRefusal === 'object'
      ? input.downstreamRefusal
      : {};
  return {
    proved: bool(downstream.proved),
    applicable: downstream.applicable === undefined ? true : downstream.applicable !== false,
    upstream_observed_on_deny: downstream.upstream_observed_on_deny ?? downstream.upstreamObservedOnDeny ?? null,
    mechanism: cleanString(downstream.mechanism || downstream.reason || 'No downstream refusal proof was supplied for this event-scoped MCP lane.'),
  };
}

export function buildMcpGateCoverageEvidenceInput(input = {}) {
  assertObject(input, 'input');
  const eventId = requireEventId(input);
  const auditRef = auditReferenceFrom(input, eventId);
  const receiptRef = workerReceiptReferenceFrom(input);
  const rawWorkerReceipt = input.worker_receipt || input.workerReceipt || null;
  const generatedAt = cleanString(input.generatedAt || input.generated_at || new Date().toISOString());

  const coverageInput = {
    generatedAt,
    evidence_type: MCP_GATE_COVERAGE_EVIDENCE_TYPE,
    mcpGateLane: {
      surface_id: cleanString(input.surface_id || input.surfaceId || 'mcp.tools_call'),
      boarding_lane: cleanString(input.boarding_lane || input.boardingLane || 'Routed MCP tools/call boarding lane'),
      checkpoint_path: cleanString(input.checkpoint_path || input.checkpointPath || 'mcp-gate:tools/call->routed-upstream'),
      mcp_registration: mcpRegistrationEvidence(input),
      heartbeat: heartbeatEvidence(input),
      policy: policyEvidence(input, auditRef),
      audit_event_id: eventId,
      audit_event_hash: auditRef.audit_hash,
      audit_event_ref: auditRef,
      downstream_refusal: downstreamRefusalEvidence(input),
      non_claims: cleanArray(input.surface_non_claims || input.surfaceNonClaims, DEFAULT_SURFACE_NON_CLAIMS),
    },
    non_claims: cleanArray(input.non_claims || input.nonClaims, DEFAULT_NON_CLAIMS),
  };

  if (rawWorkerReceipt) {
    coverageInput.mcpGateLane.worker_receipt = rawWorkerReceipt;
  } else if (receiptRef) {
    coverageInput.mcpGateLane.worker_receipt_ref = receiptRef;
  }

  assertNoUnsafeMcpGateCoverageEvidenceInput(coverageInput);
  return coverageInput;
}

export function assertNoUnsafeMcpGateCoverageEvidenceInput(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  assertNoUnsafeCoverageMapText(text);
  for (const { label, pattern } of [
    { label: 'raw command field', pattern: /"command"\s*:/i },
    { label: 'raw MCP args field', pattern: /"(?:args|arguments|params|payload|request|raw_args|mcp_args)"\s*:/i },
    { label: 'raw cwd field', pattern: /"cwd"\s*:/i },
    { label: 'raw path field', pattern: /"path"\s*:/i },
    { label: 'raw prompt field', pattern: /"prompt"\s*:/i },
  ]) {
    if (pattern.test(text)) {
      throw new Error(`MCP coverage evidence contains ${label}`);
    }
  }
  return true;
}
