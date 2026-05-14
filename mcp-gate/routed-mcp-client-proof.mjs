// Client-neutral report helpers for routed MCP proof harnesses.
// The report shape is intentionally narrow: it covers only MCP tools/call
// requests that pass through the ZLAR MCP gate route exercised by a harness.

const ROUTED_MCP_CLIENT_CLAIM_CEILING =
  'A routed-MCP proof can show ZLAR governance for client-initiated MCP tools/call requests only when the configured MCP server route passes through the ZLAR MCP gate.';

const INTENTIONALLY_UNGOVERNED_SURFACES = Object.freeze([
  'client shell, filesystem, browser, app-control, and network surfaces outside this routed MCP proof',
  'MCP servers registered directly with the client instead of through the ZLAR MCP gate',
  'client model reasoning, planning, memory, and final text outside routed MCP tools/call decisions',
  'other clients, routes, or MCP servers not exercised by this harness',
]);

const BROAD_CLAIM_FRAGMENTS = Object.freeze([
  ['all', 'actions'].join(' '),
  ['every', 'tool call'].join(' '),
  ['governs', 'Codex'].join(' '),
  ['governs', 'Hermes'].join(' '),
  ['ZLAR', 'governs', 'Codex'].join(' '),
  ['ZLAR', 'governs', 'Hermes'].join(' '),
]);

const CREDENTIAL_REDACTION_PATTERNS = Object.freeze([
  {
    label: 'key-value credential',
    pattern: /\b((?:token|secret|password|api[_-]?key)\s*=\s*)([^&\s"'`,;})\]]+)/gi,
    replacement: '$1[REDACTED_CREDENTIAL]',
  },
  {
    label: 'authorization header credential',
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
    label: 'key-value credential',
    pattern: /\b(?:token|secret|password|api[_-]?key)\s*=\s*(?!\[REDACTED_CREDENTIAL\])[^&\s"'`,;})\]]+/i,
  },
  {
    label: 'authorization header credential',
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
]);

function redactString(value) {
  let redacted = String(value).replace(/\/Users\/[^\s"'`]+/g, '[REDACTED_PATH]');
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
  return String(value);
}

function redactOptionalString(value) {
  return value === null || value === undefined ? null : redactString(value);
}

function auditSummary(event) {
  if (!event) return null;
  return {
    id: redactOptionalString(event.id),
    source: redactOptionalString(event.source),
    action: redactOptionalString(event.action),
    outcome: redactOptionalString(event.outcome),
    rule: redactOptionalString(event.rule),
    authorizer: redactOptionalString(event.authorizer),
    agent_id: redactOptionalString(event.agent_id),
    session_id: redactOptionalString(event.session_id),
    transport: redactOptionalString(event.transport || event.detail?.transport || event.detail?.mcp_transport),
    args_hash: redactOptionalString(event.detail?.args_hash),
  };
}

function workerReceiptSummary(receipt, auditEvent) {
  if (!receipt) return { emitted: false };
  return {
    emitted: true,
    event_id: redactOptionalString(receipt.event?.id),
    matches_audit_event: Boolean(auditEvent?.id && receipt.event?.id === auditEvent.id),
    decision: redactOptionalString(receipt.decision?.label),
    action_summary: redactOptionalString(receipt.action?.summary),
  };
}

function callSummary(call) {
  const audit = auditSummary(call.auditEvent);
  return {
    tool_name: redactString(call.toolName),
    expected_decision: call.expectedDecision,
    client_observed: redactValue(call.clientObserved || null),
    upstream_observed: Boolean(call.upstreamObserved),
    audit,
    worker_receipt: workerReceiptSummary(call.workerReceipt, audit),
  };
}

function buildRoutedMcpClientProofReport({
  clientName,
  clientInvocation,
  route,
  calls,
  generatedAt = new Date().toISOString(),
}) {
  return {
    generated_at: generatedAt,
    report_type: 'routed-mcp-client-proof',
    claim_ceiling: ROUTED_MCP_CLIENT_CLAIM_CEILING,
    topology: 'client -> ZLAR-routed MCP gate -> fake upstream MCP server',
    client: {
      name: redactString(clientName || 'synthetic local MCP client'),
      invocation: redactString(clientInvocation || 'synthetic local MCP client'),
      isolated_config: true,
      live_credentials: false,
      direct_fake_upstream_registration: false,
    },
    route: {
      transport: redactString(route?.transport || 'stdio'),
      zlar_gate: true,
      fake_upstream: true,
      live_telegram: false,
      external_services: false,
      description: redactString(route?.description || 'local scratch route through ZLAR MCP gate'),
    },
    governed_routed_mcp_calls: calls.map(callSummary),
    intentionally_ungoverned_surfaces: [...INTENTIONALLY_UNGOVERNED_SURFACES],
    limitations: {
      scope: 'Only the routed MCP tools/call decisions exercised by this harness are covered.',
      contest: '/contest is not implemented.',
      external_verifier: 'External non-Vincent verifier attestation has not completed.',
    },
  };
}

function assertNoUnsafeReportText(report) {
  const text = JSON.stringify(report);
  const privateOperatorPath = ['', 'Users', 'vincentnijjar'].join('/');
  if (text.includes(privateOperatorPath)) {
    throw new Error('proof report contains a private operator path');
  }
  if (/human:[0-9]/.test(text)) {
    throw new Error('proof report contains a numeric human identifier');
  }
  for (const { label, pattern } of UNSAFE_REPORT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`proof report contains ${label}`);
    }
  }
  for (const phrase of BROAD_CLAIM_FRAGMENTS) {
    if (text.includes(phrase)) {
      throw new Error(`proof report contains broad claim phrase: ${phrase}`);
    }
  }
}

function assertAudit(call, expectedOutcomes) {
  const audit = call.audit;
  if (!audit) throw new Error(`${call.tool_name} is missing audit evidence`);
  if (audit.source !== 'mcp-gate') throw new Error(`${call.tool_name} audit source must be mcp-gate`);
  if (!expectedOutcomes.includes(audit.outcome)) {
    throw new Error(`${call.tool_name} audit outcome ${audit.outcome || '<none>'} was not expected`);
  }
  if (!['stdio', 'tcp'].includes(audit.transport)) {
    throw new Error(`${call.tool_name} audit must identify the MCP transport`);
  }
}

function assertWorkerReceiptEvidence(call) {
  if (call.worker_receipt?.emitted && call.worker_receipt.matches_audit_event !== true) {
    throw new Error(`${call.tool_name} Worker Receipt must match its audit event id`);
  }
}

function assertRoutedMcpClientProofReport(report) {
  if (report.claim_ceiling !== ROUTED_MCP_CLIENT_CLAIM_CEILING) {
    throw new Error('routed MCP proof claim ceiling drifted');
  }
  if (report.client?.isolated_config !== true) {
    throw new Error('routed MCP proof must use isolated client config');
  }
  if (report.client?.live_credentials !== false) {
    throw new Error('routed MCP proof must not use live credentials');
  }
  if (report.client?.direct_fake_upstream_registration !== false) {
    throw new Error('routed MCP proof must not register the fake upstream directly');
  }
  if (report.route?.zlar_gate !== true || report.route?.fake_upstream !== true) {
    throw new Error('routed MCP proof route must go through ZLAR to a fake upstream');
  }
  if (report.route?.external_services !== false || report.route?.live_telegram !== false) {
    throw new Error('routed MCP proof must not require external services');
  }

  const calls = report.governed_routed_mcp_calls || [];
  const allow = calls.find((call) => call.expected_decision === 'allow');
  const deny = calls.find((call) => call.expected_decision === 'deny');
  if (!allow || !deny) throw new Error('routed MCP proof must include allow and deny calls');
  if (allow.upstream_observed !== true) throw new Error('allow proof must reach fake upstream');
  if (deny.upstream_observed !== false) throw new Error('deny proof must stop before fake upstream');
  assertAudit(allow, ['allow', 'authorized']);
  assertAudit(deny, ['deny', 'denied']);
  for (const call of calls) assertWorkerReceiptEvidence(call);

  if (!Array.isArray(report.intentionally_ungoverned_surfaces) ||
      report.intentionally_ungoverned_surfaces.length < 4) {
    throw new Error('routed MCP proof must list intentionally ungoverned surfaces');
  }
  assertNoUnsafeReportText(report);
}

export {
  INTENTIONALLY_UNGOVERNED_SURFACES,
  ROUTED_MCP_CLIENT_CLAIM_CEILING,
  assertNoUnsafeReportText,
  assertRoutedMcpClientProofReport,
  buildRoutedMcpClientProofReport,
};
