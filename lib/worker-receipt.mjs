import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const WORKER_RECEIPT_VERSION = '0.1.0';

const TOP_LEVEL_KEYS = [
  'worker_receipt_version',
  'type',
  'event',
  'time',
  'action',
  'decision',
  'limitations',
  'contest'
];

const FINAL_OUTCOMES = new Set(['allow', 'deny', 'authorized', 'denied', 'timeout']);
const SECRET_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{6,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{10,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{12,}\b/g,
  /\b(?:token|secret|password|api[_-]?key)=\S+/gi
];

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    return Object.keys(value).sort().reduce((acc, key) => {
      acc[key] = sortValue(value[key]);
      return acc;
    }, {});
  }
  return value;
}

export function canonicalize(value) {
  return JSON.stringify(sortValue(value));
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function collapseWhitespace(value) {
  return String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/ {2,}/g, ' ').trim();
}

export function redactText(value) {
  let redacted = collapseWhitespace(value);
  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, '[REDACTED_SECRET]');
  }
  redacted = redacted.replace(/(?:~|\/Users\/[^\s'"`;&|]+|\/home\/[^\s'"`;&|]+|\/private\/[^\s'"`;&|]+|\/tmp\/[^\s'"`;&|]+|\/var\/[^\s'"`;&|]+)/g, '[REDACTED_PATH]');
  return redacted.slice(0, 220);
}

function actionSummary(event) {
  const action = collapseWhitespace(event.action || event.tool_name || event.domain || 'action');
  const detail = event.detail && typeof event.detail === 'object' ? event.detail : {};
  if (event.domain === 'bash' || action === 'Bash') {
    return `Bash: ${redactText(detail.command || '')}`.trim();
  }
  if (detail.path) return `${action}: ${redactText(detail.path)}`;
  if (detail.url) return `${action}: ${redactText(detail.url)}`;
  if (detail.query) return `${action}: ${redactText(detail.query)}`;
  return redactText(action);
}

function decisionLabel(outcome, authorizer) {
  if (outcome === 'allow') return 'Allowed by policy';
  if (outcome === 'deny') return 'Denied by policy';
  if (outcome === 'authorized') return 'Authorized by human';
  if (outcome === 'denied' && String(authorizer).startsWith('human:')) return 'Denied by human';
  if (outcome === 'denied' && String(authorizer).startsWith('gate:timeout')) return 'Denied after approval timeout';
  if (outcome === 'timeout') return 'Timed out';
  if (outcome === 'denied') return 'Denied by gate';
  return outcome;
}

function authorizerSummary(authorizer) {
  const value = String(authorizer || 'gate');
  if (value === 'policy') return 'Policy rule decided this action.';
  if (value.startsWith('human:')) return 'Human approval channel decided this action.';
  if (value.startsWith('gate:timeout') || value === 'timeout') return 'ZLAR gate denied this action after approval timeout.';
  if (value.startsWith('gate:')) return 'ZLAR gate decided this action.';
  return 'Recorded authorizer decided this action.';
}

function approvalChannel(event) {
  if (event.approval_channel) return String(event.approval_channel);
  if (String(event.authorizer || '').startsWith('human:')) return 'telegram';
  return 'none';
}

export function isWorkerReceiptEligible(event) {
  if (!event || typeof event !== 'object') return false;
  if (!event.id) return false;
  if (event.source && event.source !== 'gate') return false;
  if (event.domain === 'mcp' || event.domain === 'internal') return false;
  if (!FINAL_OUTCOMES.has(event.outcome)) return false;
  return true;
}

export function projectWorkerReceipt(event) {
  if (!isWorkerReceiptEligible(event)) return null;

  const detail = event.detail && typeof event.detail === 'object' ? event.detail : {};
  const auditHash = sha256Hex(canonicalize(event));
  const detailHash = sha256Hex(canonicalize(detail));
  const authorizer = String(event.authorizer || 'gate');

  return {
    worker_receipt_version: WORKER_RECEIPT_VERSION,
    type: 'worker-receipt',
    event: {
      id: String(event.id),
      source: String(event.source || 'gate'),
      surface: 'bash-gate',
      audit_prev_hash: String(event.prev_hash || 'genesis'),
      audit_hash: auditHash
    },
    time: {
      observed_at: String(event.ts || event.timestamp || ''),
      source: 'local_clock',
      statement: 'Timestamp was recorded by the local ZLAR host clock.'
    },
    action: {
      class: String(event.action || event.tool_name || ''),
      domain: String(event.domain || ''),
      summary: actionSummary(event),
      detail_hash: detailHash
    },
    decision: {
      outcome: String(event.outcome),
      label: decisionLabel(String(event.outcome), authorizer),
      rule_id: String(event.rule || event.rule_id || 'unknown'),
      rule_description: String(event.rule_description || event.policy_rule_description || 'Unavailable in audit event.'),
      policy_version: String(event.policy_version || 'unknown'),
      policy_key_id: event.policy_key_id ? String(event.policy_key_id) : null,
      authorizer: authorizer.startsWith('human:') ? 'human' : authorizer,
      authorizer_summary: authorizerSummary(authorizer),
      approval_channel: approvalChannel(event)
    },
    limitations: {
      scope: 'This Worker Receipt only describes a single action routed through the ZLAR bash gate.',
      non_claims: [
        'It does not prove agent intent.',
        'It does not prove operator understanding.',
        'It does not prove ZLAR governed actions outside this gate.'
      ]
    },
    contest: {
      status: 'not_implemented',
      handle: null,
      statement: '/contest is not implemented in Worker Receipt v0.1.'
    }
  };
}

export function validateWorkerReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw new Error('Worker Receipt must be a JSON object');
  }
  const keys = Object.keys(receipt).sort();
  const expected = [...TOP_LEVEL_KEYS].sort();
  if (JSON.stringify(keys) !== JSON.stringify(expected)) {
    throw new Error(`Worker Receipt has invalid top-level fields: ${keys.join(',')}`);
  }
  if (receipt.worker_receipt_version !== WORKER_RECEIPT_VERSION) {
    throw new Error(`Unsupported Worker Receipt version: ${receipt.worker_receipt_version}`);
  }
  if (receipt.type !== 'worker-receipt') {
    throw new Error(`Unsupported Worker Receipt type: ${receipt.type}`);
  }
  if (!receipt.event?.id) throw new Error('Worker Receipt missing event.id');
  if (receipt.event.surface !== 'bash-gate') throw new Error('Worker Receipt surface is not bash-gate');
  if (receipt.time?.source !== 'local_clock') throw new Error('Worker Receipt missing local_clock declaration');
  if (receipt.contest?.status !== 'not_implemented') throw new Error('Worker Receipt contest status must be not_implemented');
  return true;
}

export function findWorkerReceiptByEventId(filePath, eventId) {
  const text = readFileSync(filePath, 'utf8');
  const lines = text.split(/\n/);
  let found = null;

  lines.forEach((line, index) => {
    if (!line.trim()) return;
    let receipt;
    try {
      receipt = JSON.parse(line);
    } catch {
      throw new Error(`Malformed Worker Receipt store at line ${index + 1}`);
    }
    validateWorkerReceipt(receipt);
    if (receipt.event.id === eventId) {
      found = receipt;
    }
  });

  return found;
}

export function formatWorkerReceiptHuman(receipt) {
  validateWorkerReceipt(receipt);
  return [
    `ZLAR Worker Receipt v${receipt.worker_receipt_version}`,
    '',
    `Event: ${receipt.event.id}`,
    `Surface: ${receipt.event.surface}`,
    `Time: ${receipt.time.observed_at} (${receipt.time.source})`,
    `Action: ${receipt.action.summary}`,
    `Decision: ${receipt.decision.label}`,
    `Rule: ${receipt.decision.rule_id} - ${receipt.decision.rule_description}`,
    `Policy: ${receipt.decision.policy_version}${receipt.decision.policy_key_id ? ` (${receipt.decision.policy_key_id})` : ''}`,
    `Authority: ${receipt.decision.authorizer_summary}`,
    `Approval channel: ${receipt.decision.approval_channel}`,
    `Audit pointer: prev=${receipt.event.audit_prev_hash} hash=${receipt.event.audit_hash}`,
    '',
    'Limitations:',
    `- ${receipt.limitations.scope}`,
    ...receipt.limitations.non_claims.map((claim) => `- ${claim}`),
    '',
    `Contest: ${receipt.contest.status} - ${receipt.contest.statement}`
  ].join('\n');
}
