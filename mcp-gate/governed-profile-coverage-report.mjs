import { createHash } from 'node:crypto';

const REPORT_TYPE = 'governed-profile-coverage-v0';
const SAFE_CLAIM_CEILING =
  'ZLAR can govern Codex CLI-invoked MCP tool calls when those MCP servers are routed through ZLAR.';

const STATUS_VALUES = Object.freeze(['routed', 'blocked', 'disclosed', 'unknown', 'out_of_scope']);
const WHY_STATUS_VALUES = Object.freeze(['available', 'missing', 'not_checked']);

const NON_CLAIMS = Object.freeze([
  'This report covers routed or intercepted action surfaces only.',
  'This report does not assert coverage for Codex shell, filesystem, browser, app-control, direct network, model reasoning, or final text surfaces.',
  'MCP servers registered directly with a client instead of through the ZLAR MCP gate are outside this report.',
  '/contest is not implemented.',
  'External non-operator verifier attestation is not present in v0.',
]);

const RESIDUAL_UNGOVERNED_SURFACES = Object.freeze([
  'Codex shell commands outside routed MCP tools/call decisions',
  'Codex filesystem changes outside routed MCP tools/call decisions',
  'Codex browser actions outside routed MCP tools/call decisions',
  'Codex desktop app-control actions outside routed MCP tools/call decisions',
  'Codex direct network calls outside routed MCP tools/call decisions',
  'Codex model reasoning and final text',
  'MCP protocol messages other than tools/call decisions',
  'MCP servers registered directly with the client instead of through the ZLAR MCP gate',
]);

const CREDENTIAL_REDACTION_PATTERNS = Object.freeze([
  {
    label: 'key-value credential',
    pattern: /\b((?:token|secret|password|api[_-]?key)\s*[:=]\s*)([^&\s"'`,;})\]]+)/gi,
    replacement: '$1[REDACTED_CREDENTIAL]',
  },
  {
    label: 'authorization credential',
    pattern: /\b(authorization\s*[:=]\s*(?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]{6,})/gi,
    replacement: '$1[REDACTED_CREDENTIAL]',
  },
  {
    label: 'bearer/basic credential',
    pattern: /\b((?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{6,})/g,
    replacement: '$1[REDACTED_CREDENTIAL]',
  },
  {
    label: 'GitHub token',
    pattern: /\bghp_[A-Za-z0-9_]{10,}\b/g,
    replacement: '[REDACTED_CREDENTIAL]',
  },
  {
    label: 'GitHub fine-grained token',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{10,}\b/g,
    replacement: '[REDACTED_CREDENTIAL]',
  },
  {
    label: 'Slack token',
    pattern: /\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b/g,
    replacement: '[REDACTED_CREDENTIAL]',
  },
  {
    label: 'AWS access key',
    pattern: /\bAKIA[0-9A-Z]{12,}\b/g,
    replacement: '[REDACTED_CREDENTIAL]',
  },
  {
    label: 'OpenAI-style key',
    pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/g,
    replacement: '[REDACTED_CREDENTIAL]',
  },
  {
    label: 'bot token',
    pattern: /\bbot[0-9]{6,}:[A-Za-z0-9_-]{6,}\b/g,
    replacement: '[REDACTED_CREDENTIAL]',
  },
]);

const UNSAFE_REPORT_PATTERNS = Object.freeze([
  {
    label: 'private operator path',
    pattern: /\/Users\/[^\s"'`]+/,
  },
  {
    label: 'home path',
    pattern: /\/home\/[^\s"'`]+/,
  },
  {
    label: 'numeric human identifier',
    pattern: /\bhuman:[0-9]/,
  },
  {
    label: 'chat id field',
    pattern: /\bchat_id\b/i,
  },
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
  { label: 'broad action claim', pattern: new RegExp(`\\b${['all', 'actions'].join(' ')}\\b`, 'i') },
  { label: 'broad tool claim', pattern: /\bevery[- ]tool\b/i },
  { label: 'broad agent claim', pattern: /\ball[- ]agent\b/i },
  { label: 'broad Codex claim', pattern: new RegExp(`\\b${['governs', 'Codex'].join(' ')}\\b`) },
  { label: 'broad Hermes claim', pattern: new RegExp(`\\b(?:govern|governs|governed) ${'Hermes'}\\b`) },
  { label: 'external attestation completion claim', pattern: /\bexternally attested\b(?! yet)/i },
  { label: 'contest implementation claim', pattern: /\/contest\s+(?:is\s+)?implemented\b/i },
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
    .replace(/\/Users\/[^\s"'`;&|]+/g, '[REDACTED_PATH]')
    .replace(/\/home\/[^\s"'`;&|]+/g, '[REDACTED_PATH]')
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

function surface({
  id,
  label,
  status,
  boundary,
  closureMechanism,
  evidence = {},
  workerReceipts = [],
  why = { status: 'not_checked' },
}) {
  return {
    id,
    label: cleanString(label),
    status,
    boundary: cleanString(boundary),
    closure_mechanism: cleanString(closureMechanism),
    evidence: redactValue(evidence),
    worker_receipts: redactValue(workerReceipts),
    why,
  };
}

function configuredServers(profileReport) {
  return Array.isArray(profileReport?.configured_mcp_servers)
    ? profileReport.configured_mcp_servers
    : [];
}

function analyzeProfile(profileReport) {
  const servers = configuredServers(profileReport);
  const routedServers = servers.filter((server) => server?.zlar_routed === true);
  const directUpstreamServers = servers.filter((server) => server?.direct_fake_upstream_registration === true);
  const serverName = cleanString(
    profileReport?.zlar_route?.server_name ||
      routedServers[0]?.name ||
      servers[0]?.name ||
      'unknown'
  );
  const hasServerEvidence = servers.length > 0;
  const exactlyOneRouted = servers.length === 1 && routedServers.length === 1 && directUpstreamServers.length === 0;
  return {
    servers,
    serverName,
    hasServerEvidence,
    exactlyOneRouted,
    directUpstreamObserved: directUpstreamServers.length > 0,
    extraRegistrationObserved: servers.length > 1,
    serverNames: servers.map((server) => cleanString(server?.name || 'unknown')),
  };
}

function auditSummary(event) {
  if (!event) return null;
  return {
    id: cleanString(event.id || null, null),
    source: cleanString(event.source || null, null),
    outcome: cleanString(event.outcome || null, null),
    rule: cleanString(event.rule || event.rule_id || null, null),
    transport: cleanString(event.transport || event.detail?.transport || event.detail?.mcp_transport || null, null),
  };
}

function expectedOutcomesFor(decision) {
  if (decision === 'allow') return ['allow'];
  if (decision === 'deny') return ['deny'];
  if (decision === 'authorized') return ['authorized'];
  if (decision === 'denied') return ['denied'];
  return [decision];
}

function normalizedDecision(call) {
  return String(call?.expected_decision || call?.expectedDecision || call?.audit?.outcome || call?.auditEvent?.outcome || '').trim();
}

function callAudit(call) {
  return call?.auditEvent || call?.audit || null;
}

function callsFromProof(routedMcpProofReport) {
  return Array.isArray(routedMcpProofReport?.governed_routed_mcp_calls)
    ? routedMcpProofReport.governed_routed_mcp_calls
    : [];
}

function findDecisionCall(calls, decision) {
  const expected = expectedOutcomesFor(decision);
  return calls.find((call) => {
    const audit = callAudit(call);
    const expectedDecision = normalizedDecision(call);
    return expected.includes(expectedDecision) || expected.includes(String(audit?.outcome || ''));
  }) || null;
}

function workerReceiptMap(workerReceipts = []) {
  const map = new Map();
  for (const receipt of workerReceipts || []) {
    const eventId = receipt?.event?.id;
    if (!eventId) continue;
    map.set(String(eventId), receipt);
  }
  return map;
}

function whyStatusForEvent(eventId, whyByEventId) {
  if (!eventId || !whyByEventId) return 'not_checked';
  const value = whyByEventId[eventId];
  if (value === true) return 'available';
  if (value === false || value === null) return 'missing';
  if (typeof value === 'string' && WHY_STATUS_VALUES.includes(value)) return value;
  if (value && typeof value === 'object' && WHY_STATUS_VALUES.includes(value.status)) return value.status;
  return 'not_checked';
}

function combinedWhyStatus(eventIds, whyByEventId) {
  if (!eventIds.length || !whyByEventId) return { status: 'not_checked' };
  const statuses = eventIds.map((id) => whyStatusForEvent(id, whyByEventId));
  if (statuses.includes('missing')) return { status: 'missing' };
  if (statuses.every((status) => status === 'available')) return { status: 'available' };
  return { status: 'not_checked' };
}

function receiptEvidenceForEvent(eventId, receiptsByEventId, whyByEventId) {
  if (!eventId) return [];
  const receipt = receiptsByEventId.get(String(eventId));
  if (!receipt) return [];
  return [{
    event_id: cleanString(receipt.event?.id || eventId),
    receipt_sha256: sha256Hex(stableStringify(receipt)),
    audit_hash: cleanString(receipt.event?.audit_hash || null, null),
    detail_hash: cleanString(receipt.action?.detail_hash || null, null),
    decision: cleanString(receipt.decision?.outcome || null, null),
    why_status: whyStatusForEvent(String(eventId), whyByEventId),
  }];
}

function decisionSurface({ decision, calls, receiptsByEventId, whyByEventId }) {
  const call = findDecisionCall(calls, decision);
  const audit = auditSummary(callAudit(call));
  const eventIds = audit?.id ? [audit.id] : [];
  const evidenceAvailable = Boolean(audit?.id && audit.source === 'mcp-gate');
  const upstreamObserved = call?.upstream_observed ?? call?.upstreamObserved;
  const status = !evidenceAvailable
    ? 'unknown'
    : (decision === 'deny' || decision === 'denied')
      ? 'blocked'
      : 'routed';
  const boundary = !evidenceAvailable
    ? `${decision} MCP decision evidence is not present in the supplied inputs.`
    : `${decision} decision evidence is limited to the supplied routed MCP tools/call audit event.`;
  const closureMechanism = decision === 'deny' || decision === 'denied'
    ? 'Blocked decisions must have mcp-gate audit evidence and no upstream execution evidence when the proof records that check.'
    : 'Routed decisions must have mcp-gate audit evidence and remain limited to the configured routed MCP server.';
  return surface({
    id: `codex.mcp.decision.${decision}`,
    label: `Routed MCP ${decision} decision evidence`,
    status,
    boundary,
    closureMechanism,
    evidence: {
      audit_event_ids: eventIds,
      audit,
      upstream_observed: upstreamObserved === undefined ? null : Boolean(upstreamObserved),
    },
    workerReceipts: eventIds.flatMap((eventId) => receiptEvidenceForEvent(eventId, receiptsByEventId, whyByEventId)),
    why: combinedWhyStatus(eventIds, whyByEventId),
  });
}

function buildProfileSurfaces(profileReport) {
  const profile = analyzeProfile(profileReport);
  const routeEvidence = profile.exactlyOneRouted ? 'routed' : (profile.hasServerEvidence ? 'unknown' : 'unknown');
  return [
    surface({
      id: 'codex.mcp.tools_call.routed_profile',
      label: 'Codex CLI MCP tools/call through isolated routed profile',
      status: profile.exactlyOneRouted ? 'routed' : routeEvidence,
      boundary: profile.exactlyOneRouted
        ? 'Coverage is limited to Codex CLI MCP tools/call requests for the single configured server routed through the ZLAR MCP gate.'
        : 'The supplied profile evidence does not prove a single ZLAR-routed MCP server.',
      closureMechanism: 'The isolated profile must contain exactly one MCP server and that server must launch the ZLAR wrapper or MCP gate route.',
      evidence: {
        server_name: profile.serverName,
        configured_server_count: profile.servers.length,
        configured_server_names: profile.serverNames,
        isolated_profile_report_present: Boolean(profileReport),
      },
    }),
    surface({
      id: 'codex.mcp.registration.direct_upstream_bypass',
      label: 'Direct upstream MCP registration bypass sentinel',
      status: profile.directUpstreamObserved ? 'disclosed' : (profile.hasServerEvidence ? 'blocked' : 'unknown'),
      boundary: profile.directUpstreamObserved
        ? 'Disclosure only: a direct upstream registration was observed and this report must be rejected as a coverage claim.'
        : 'A direct upstream MCP server registration would bypass the routed MCP gate and is not accepted as coverage evidence.',
      closureMechanism: 'Reject registrations that reference the fake upstream command, upstream port, or upstream markers instead of the ZLAR route.',
      evidence: {
        direct_upstream_observed: profile.directUpstreamObserved,
        configured_server_count: profile.servers.length,
      },
    }),
    surface({
      id: 'codex.mcp.registration.extra_server_bypass',
      label: 'Extra MCP registration bypass sentinel',
      status: profile.extraRegistrationObserved ? 'disclosed' : (profile.hasServerEvidence ? 'blocked' : 'unknown'),
      boundary: profile.extraRegistrationObserved
        ? 'Disclosure only: more than one MCP server was observed in the isolated profile and this report must be rejected as a coverage claim.'
        : 'A second MCP server registration could bypass the routed proof surface and is not accepted in v0.',
      closureMechanism: 'Reject isolated-profile evidence unless the configured MCP server set has exactly one server: the ZLAR-routed proof server.',
      evidence: {
        extra_registration_observed: profile.extraRegistrationObserved,
        configured_server_count: profile.servers.length,
        configured_server_names: profile.serverNames,
      },
    }),
  ];
}

function outOfScopeSurface(id, label, boundary) {
  return surface({
    id,
    label,
    status: 'out_of_scope',
    boundary,
    closureMechanism: 'Requires a separate interception surface or deployment-layer control; it is not claimed by this routed MCP profile report.',
  });
}

function disclosureSurface(id, label, boundary) {
  return surface({
    id,
    label,
    status: 'disclosed',
    boundary: `Disclosure only: ${boundary}`,
    closureMechanism: 'No closure mechanism is claimed in v0.',
  });
}

function buildBoundarySurfaces() {
  return [
    outOfScopeSurface(
      'codex.mcp.protocol.non_tools_call',
      'MCP protocol traffic other than tools/call',
      'MCP initialize, listing, and other protocol traffic can traverse the route, but v0 action coverage is limited to tools/call decisions.'
    ),
    outOfScopeSurface('codex.shell', 'Codex shell surface', 'Codex shell commands are outside this routed MCP profile report.'),
    outOfScopeSurface('codex.filesystem', 'Codex filesystem surface', 'Codex filesystem operations outside routed MCP tools/call decisions are outside this report.'),
    outOfScopeSurface('codex.browser', 'Codex browser surface', 'Codex browser actions outside routed MCP tools/call decisions are outside this report.'),
    outOfScopeSurface('codex.app_control', 'Codex desktop app-control surface', 'Codex desktop app-control actions outside routed MCP tools/call decisions are outside this report.'),
    outOfScopeSurface('codex.network', 'Codex direct network surface', 'Codex direct network calls outside routed MCP tools/call decisions are outside this report.'),
    outOfScopeSurface('codex.model_reasoning_final_text', 'Codex model reasoning and final text', 'Model reasoning, planning, memory, and final text are not an MCP tools/call action surface.'),
    disclosureSurface('zlar.contest', '/contest status', '/contest is not implemented.'),
    disclosureSurface('external.verifier_attestation', 'External verifier attestation status', 'no non-operator verifier attestation is present in v0.'),
  ];
}

function buildVerifierKitPacket(verifierKit = {}) {
  return redactValue({
    status: verifierKit.status || 'prepared_pending',
    kit_version: verifierKit.kit_version || 'v0.1.0',
    packet_status: verifierKit.packet_status || 'prepared_pending',
    external_attestation: 'not_attested',
    worker_receipt_verification: 'not_supported_by_verifier_kit_v0_1',
  });
}

function buildPrivacyFlags() {
  return {
    raw_mcp_args_included: false,
    env_values_included: false,
    prompt_text_included: false,
    final_client_text_included: false,
    private_paths_included: false,
    numeric_human_ids_included: false,
    real_chat_ids_included: false,
    telegram_details_included: false,
    credentials_included: false,
    operator_config_values_included: false,
  };
}

function buildGovernedProfileCoverageReport({
  profileReport = null,
  routedMcpProofReport = null,
  workerReceipts = [],
  whyByEventId = null,
  verifierKit = {},
  profile = {},
  generatedAt = new Date().toISOString(),
} = {}) {
  const profileAnalysis = analyzeProfile(profileReport);
  const calls = callsFromProof(routedMcpProofReport);
  const receiptsByEventId = workerReceiptMap(workerReceipts);
  const profileId = cleanString(profile.id || `codex:${profileAnalysis.serverName}:isolated-routed-mcp`);
  const report = {
    generated_at: cleanString(generatedAt),
    report_type: REPORT_TYPE,
    profile: {
      id: profileId,
      name: cleanString(profile.name || 'isolated Codex routed-MCP profile'),
      client: cleanString(profile.client || 'Codex CLI'),
      isolated_config: Boolean(profile.isolated_config ?? (profileReport?.mode === 'isolated-codex-profile')),
    },
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    surfaces: [
      ...buildProfileSurfaces(profileReport),
      ...['allow', 'deny', 'authorized', 'denied'].map((decision) => decisionSurface({
        decision,
        calls,
        receiptsByEventId,
        whyByEventId,
      })),
      ...buildBoundarySurfaces(),
    ],
    verifier_kit_packet: buildVerifierKitPacket(verifierKit),
    non_claims: [...NON_CLAIMS],
    residual_ungoverned_surfaces: [...RESIDUAL_UNGOVERNED_SURFACES],
    privacy: buildPrivacyFlags(),
  };
  assertNoUnsafeCoverageText(report);
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

function assertSurfaceShape(item, index) {
  assertObject(item, `surface[${index}]`);
  for (const key of ['id', 'label', 'status', 'boundary', 'closure_mechanism']) {
    assertString(item[key], `surface[${index}].${key}`);
  }
  if (!STATUS_VALUES.includes(item.status)) {
    throw new Error(`surface[${index}].status is invalid: ${item.status}`);
  }
  assertObject(item.evidence, `surface[${index}].evidence`);
  if (!Array.isArray(item.worker_receipts)) {
    throw new Error(`surface[${index}].worker_receipts must be an array`);
  }
  assertObject(item.why, `surface[${index}].why`);
  if (!WHY_STATUS_VALUES.includes(item.why.status)) {
    throw new Error(`surface[${index}].why.status is invalid: ${item.why.status}`);
  }
  if (item.status === 'disclosed') {
    const text = `${item.label} ${item.boundary} ${item.closure_mechanism}`;
    if (/\bcoverage evidence\b/i.test(text) || /\bgoverned\b/i.test(text)) {
      throw new Error(`surface[${index}] disclosed text reads like coverage evidence`);
    }
  }
}

function surfaceById(report, id) {
  return report.surfaces.find((item) => item.id === id);
}

function assertGovernedProfileCoverageReport(report) {
  assertObject(report, 'report');
  if (report.report_type !== REPORT_TYPE) throw new Error(`report_type must be ${REPORT_TYPE}`);
  if (report.safe_claim_ceiling !== SAFE_CLAIM_CEILING) throw new Error('safe claim ceiling drifted');
  assertString(report.generated_at, 'generated_at');
  assertObject(report.profile, 'profile');
  for (const key of ['id', 'name', 'client']) assertString(report.profile[key], `profile.${key}`);
  if (typeof report.profile.isolated_config !== 'boolean') throw new Error('profile.isolated_config must be boolean');
  if (!Array.isArray(report.surfaces) || report.surfaces.length === 0) throw new Error('surfaces must be a non-empty array');
  report.surfaces.forEach(assertSurfaceShape);
  const ids = new Set(report.surfaces.map((item) => item.id));
  if (ids.size !== report.surfaces.length) throw new Error('surface ids must be unique');

  for (const requiredId of [
    'codex.mcp.tools_call.routed_profile',
    'codex.mcp.decision.allow',
    'codex.mcp.decision.deny',
    'codex.mcp.decision.authorized',
    'codex.mcp.decision.denied',
    'codex.mcp.registration.direct_upstream_bypass',
    'codex.mcp.registration.extra_server_bypass',
    'codex.mcp.protocol.non_tools_call',
    'codex.shell',
    'codex.filesystem',
    'codex.browser',
    'codex.app_control',
    'codex.network',
    'codex.model_reasoning_final_text',
    'zlar.contest',
    'external.verifier_attestation',
  ]) {
    if (!ids.has(requiredId)) throw new Error(`missing surface: ${requiredId}`);
  }

  const direct = surfaceById(report, 'codex.mcp.registration.direct_upstream_bypass');
  if (direct?.evidence?.direct_upstream_observed) {
    throw new Error('direct upstream MCP registration bypass observed');
  }
  const extra = surfaceById(report, 'codex.mcp.registration.extra_server_bypass');
  if (extra?.evidence?.extra_registration_observed) {
    throw new Error('extra MCP registration bypass observed');
  }
  if (surfaceById(report, 'zlar.contest')?.status !== 'disclosed') {
    throw new Error('/contest status must be disclosed');
  }
  if (surfaceById(report, 'external.verifier_attestation')?.status !== 'disclosed') {
    throw new Error('external verifier attestation status must be disclosed');
  }
  if (report.verifier_kit_packet?.external_attestation !== 'not_attested') {
    throw new Error('external attestation must remain not_attested');
  }
  if (!Array.isArray(report.non_claims) || !report.non_claims.includes('/contest is not implemented.')) {
    throw new Error('explicit non-claims must include /contest boundary');
  }
  if (!Array.isArray(report.residual_ungoverned_surfaces) || report.residual_ungoverned_surfaces.length < 4) {
    throw new Error('residual ungoverned surfaces must be explicit');
  }
  assertObject(report.privacy, 'privacy');
  for (const [key, value] of Object.entries(report.privacy)) {
    if (value !== false) throw new Error(`privacy.${key} must be false`);
  }
  assertNoUnsafeCoverageText(report);
  return true;
}

function evidenceSummary(item) {
  const ids = Array.isArray(item.evidence?.audit_event_ids) ? item.evidence.audit_event_ids.filter(Boolean) : [];
  if (ids.length > 0) return `audit=${ids.join(',')}`;
  if (typeof item.evidence?.configured_server_count === 'number') return `servers=${item.evidence.configured_server_count}`;
  return 'evidence=none';
}

function formatGovernedProfileCoverageSummary(report) {
  assertGovernedProfileCoverageReport(report);
  const lines = [
    'Governed Profile Coverage Report v0',
    `Profile: ${report.profile.name} (${report.profile.client}; isolated=${report.profile.isolated_config})`,
    `Claim ceiling: ${report.safe_claim_ceiling}`,
    `Verifier kit packet: ${report.verifier_kit_packet.status}; external attestation=${report.verifier_kit_packet.external_attestation}`,
    '',
    'Surfaces:',
    ...report.surfaces.map((item) => `- ${item.id}: ${item.status}; ${evidenceSummary(item)}; ${item.boundary}`),
    '',
    'Non-claims:',
    ...report.non_claims.map((claim) => `- ${claim}`),
    '',
    'Residual ungoverned surfaces:',
    ...report.residual_ungoverned_surfaces.map((item) => `- ${item}`),
  ];
  const summary = lines.join('\n');
  assertNoUnsafeCoverageText(summary);
  return summary;
}

function assertNoUnsafeCoverageText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { label, pattern } of UNSAFE_REPORT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`coverage report contains ${label}`);
    }
  }
}

export {
  REPORT_TYPE,
  SAFE_CLAIM_CEILING,
  STATUS_VALUES,
  WHY_STATUS_VALUES,
  assertGovernedProfileCoverageReport,
  assertNoUnsafeCoverageText,
  buildGovernedProfileCoverageReport,
  formatGovernedProfileCoverageSummary,
  sha256Hex,
  stableStringify,
};
