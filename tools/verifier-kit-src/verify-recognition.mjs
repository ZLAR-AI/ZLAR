#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Verifier Kit v0.1 — Trusted Receipt Issuer Recognition
//
// Evaluates one Governed Action Receipt v1 envelope against one supplied
// trusted-receipt-issuers-v1 registry fixture.
//
// This is issuer-recognition fixture evaluation. It does not inspect live trust
// registries, prove key custody, prove revocation truth, prove production
// downstream recognition, or create external attestation.
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runSelfTest, selfTestReport } from './selftest.mjs';
import { PUBLISHER_PUBKEY_PEM, KIT_VERSION, SPEC_VERSION } from './lib/kit-publisher.mjs';
import { evaluateDownstreamRecognition } from './lib/downstream-recognition-rule.mjs';

const TRUSTED_ISSUERS_REGISTRY_TYPE = 'trusted-receipt-issuers-v1';
const SAFE_CLAIM_CEILING =
  'ZLAR can evaluate whether one supplied v1 receipt is recognized by one supplied trusted-receipt-issuers-v1 registry fixture.';
const NON_CLAIMS = Object.freeze([
  'This command evaluates a supplied registry fixture; it does not inspect a live or production trust registry.',
  'This command does not prove key custody, hardware possession, revocation truth, compromise response, or production signing identity.',
  'This command does not prove routed coverage, live downstream deployment recognition, production authority, external attestation, sovereign recognition, or coverage of unrouted surfaces.',
]);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Self-test FIRST ─────────────────────────────────────────────────────────

const selfTest = runSelfTest({ kitRoot: __dirname, publisherPubkeyPem: PUBLISHER_PUBKEY_PEM });
if (!selfTest.ok) {
  process.stderr.write(`BUNDLE-INTEGRITY-FAIL: ${selfTest.reason}\n`);
  if (selfTest.detail) {
    process.stderr.write(`${selfTest.detail}\n`);
  }
  process.exit(4);
}

// ─── Argument parsing ────────────────────────────────────────────────────────

const args = process.argv.slice(2);
let receiptPath = null;
let registryPath = null;
let scope = null;
let jsonOutput = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--receipt' && i + 1 < args.length) {
    receiptPath = args[++i];
  } else if (a === '--registry' && i + 1 < args.length) {
    registryPath = args[++i];
  } else if (a === '--scope' && i + 1 < args.length) {
    scope = args[++i];
  } else if (a === '--json') {
    jsonOutput = true;
  } else if (a === '--help' || a === '-h') {
    printUsage();
    process.exit(0);
  } else if (a === '--self-test-report') {
    process.stdout.write(selfTestReport(selfTest) + '\n');
    process.exit(0);
  } else {
    process.stderr.write(`ERROR: unsupported argument: ${a}\n`);
    process.stderr.write('Usage: node verify-recognition.mjs --receipt <receipt.json> --registry <trusted-receipt-issuers-v1.json> [--scope <deployment-scope>] [--json]\n');
    process.exit(2);
  }
}

function printUsage() {
  process.stdout.write(`
ZLAR Verifier Kit v0.1 — Trusted Receipt Issuer Recognition  (kit ${KIT_VERSION}, spec ${SPEC_VERSION})

USAGE
  node verify-recognition.mjs --receipt <receipt.json> --registry <trusted-receipt-issuers-v1.json> [--scope <deployment-scope>]
  node verify-recognition.mjs --receipt <receipt.json> --registry <trusted-receipt-issuers-v1.json> [--scope <deployment-scope>] --json

OPTIONS
  --receipt <path>       Governed Action Receipt v1 envelope [REQUIRED]
  --registry <path>      trusted-receipt-issuers-v1 registry [REQUIRED]
  --scope <scope>        Optional deployment scope; must match registry scope
  --json                 Machine-readable output
  --self-test-report     Print self-test detail and exit 0
  --help, -h             Show this help

EXIT CODES
  0   RECOGNIZED              receipt recognized by supplied registry fixture
  1   RECOGNITION-REFUSED     receipt not recognized by supplied registry fixture
  2   ERROR                   bad args, missing file, bad JSON, bad registry
  4   BUNDLE-INTEGRITY-FAIL   kit self-test failed; recognition NOT attempted

WHAT THIS PROVES
  One supplied local registry fixture recognized or refused one supplied v1
  receipt by issuer status, public key, policy, scope, action, outcome, and
  action-binding fields.

WHAT THIS DOES NOT PROVE
  This does not prove live active issuer status, key custody, revocation truth,
  production trust-registry state, production downstream recognition, production
  authority, external attestation, sovereign recognition, or coverage of
  unrouted surfaces.
`.trimEnd() + '\n');
}

if (!receiptPath || !registryPath) {
  process.stderr.write('ERROR: --receipt and --registry are required\n');
  process.stderr.write('Usage: node verify-recognition.mjs --receipt <receipt.json> --registry <trusted-receipt-issuers-v1.json> [--scope <deployment-scope>] [--json]\n');
  process.exit(2);
}

let receipt;
let registry;
try {
  receipt = JSON.parse(readFileSync(resolve(receiptPath), 'utf8'));
} catch (err) {
  process.stderr.write(`ERROR: Cannot read receipt JSON.\n  ${err.message}\n`);
  process.exit(2);
}
try {
  registry = JSON.parse(readFileSync(resolve(registryPath), 'utf8'));
} catch (err) {
  process.stderr.write(`ERROR: Cannot read registry JSON.\n  ${err.message}\n`);
  process.exit(2);
}

let decision;
try {
  decision = evaluateRegistryRecognition({ receipt, registry, scope });
} catch (err) {
  process.stderr.write(`ERROR: ${err && err.message ? err.message : String(err)}\n`);
  process.exit(2);
}

if (jsonOutput) {
  process.stdout.write(JSON.stringify(formatJson(decision, registry, scope), null, 2) + '\n');
} else {
  process.stdout.write(formatText(decision, registry, scope));
}
process.exit(decision.recognized === true ? 0 : 1);

function evaluateRegistryRecognition({ receipt, registry, scope }) {
  assertRegistry(registry);
  const deploymentScope = registry.deployment_scope;
  if (scope && scope !== deploymentScope) {
    return {
      recognized: false,
      decision: 'refuse',
      reason_code: 'scope_not_found',
      reasons: [
        {
          code: 'scope_not_found',
          message: 'Requested deployment scope does not match the supplied registry.',
        },
      ],
      evidence: {
        receipt_present: Boolean(receipt),
        registry_type: registry.registry_type,
        requested_scope: scope,
        registry_scope: deploymentScope,
      },
      safe_claim_ceiling: SAFE_CLAIM_CEILING,
      non_claims: [...NON_CLAIMS],
    };
  }

  const recognitionRule = {
    deployment_scope: deploymentScope,
    accepted_issuers: registry.trusted_issuers,
    accepted_policy_versions: registry.accepted_policy_versions,
    accepted_domains: registry.accepted_domains,
    accepted_tools: registry.accepted_tools,
    accepted_outcomes: registry.accepted_outcomes,
    required_audit_event_id: registry.required_audit_event_id,
    required_detail_hash: registry.required_detail_hash,
  };
  const result = evaluateDownstreamRecognition({
    receipt,
    recognition_rule: recognitionRule,
  });
  return {
    ...result,
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    non_claims: [...NON_CLAIMS],
  };
}

function assertRegistry(registry) {
  if (!registry || typeof registry !== 'object' || Array.isArray(registry)) {
    throw new Error('Registry must be a JSON object');
  }
  assertOnlyKeys('Registry', registry, [
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
    'required_audit_event_id',
    'required_detail_hash',
    'non_claims',
  ]);
  if (registry.registry_type !== TRUSTED_ISSUERS_REGISTRY_TYPE) {
    throw new Error('Registry must have registry_type=trusted-receipt-issuers-v1');
  }
  if (registry.version !== 1) {
    throw new Error('Registry version must be 1');
  }
  if (typeof registry.evidence_model !== 'string' || !registry.evidence_model) {
    throw new Error('Registry must declare evidence_model');
  }
  if (registry.live_probing !== false) {
    throw new Error('Registry must declare live_probing=false');
  }
  if (typeof registry.deployment_scope !== 'string' || !registry.deployment_scope) {
    throw new Error('Registry must declare deployment_scope');
  }
  if (!Array.isArray(registry.trusted_issuers) || registry.trusted_issuers.length === 0) {
    throw new Error('Registry must include at least one trusted issuer');
  }
  for (const issuer of registry.trusted_issuers) {
    if (!issuer || typeof issuer !== 'object') {
      throw new Error('Trusted issuer entries must be objects');
    }
    assertOnlyKeys('Trusted issuer', issuer, ['kid', 'public_key_pem', 'status']);
    if (typeof issuer.kid !== 'string' || !/^[0-9a-f]{16}$/.test(issuer.kid)) {
      throw new Error('Trusted issuer kid must be 16 lowercase hex characters');
    }
    if (typeof issuer.public_key_pem !== 'string' || !issuer.public_key_pem.startsWith('-----BEGIN PUBLIC KEY-----')) {
      throw new Error('Trusted issuer public_key_pem must be a public key PEM string');
    }
    if (!['active', 'retired', 'compromised'].includes(issuer.status)) {
      throw new Error('Trusted issuer status must be active, retired, or compromised');
    }
  }
  for (const field of [
    'accepted_policy_versions',
    'accepted_domains',
    'accepted_tools',
    'accepted_outcomes',
  ]) {
    if (!Array.isArray(registry[field]) || registry[field].some((item) => typeof item !== 'string' || !item)) {
      throw new Error(`Registry ${field} must be a string array`);
    }
  }
  if (!Array.isArray(registry.non_claims) || registry.non_claims.length === 0) {
    throw new Error('Registry must include non_claims');
  }
  if (registry.non_claims.some((item) => typeof item !== 'string' || !item)) {
    throw new Error('Registry non_claims must be a non-empty string array');
  }
  if ('required_audit_event_id' in registry && (typeof registry.required_audit_event_id !== 'string' || !registry.required_audit_event_id)) {
    throw new Error('Registry required_audit_event_id must be a string when present');
  }
  if ('required_detail_hash' in registry && (typeof registry.required_detail_hash !== 'string' || !/^[0-9a-f]{64}$/.test(registry.required_detail_hash))) {
    throw new Error('Registry required_detail_hash must be 64 lowercase hex characters when present');
  }
}

function assertOnlyKeys(label, object, allowedKeys) {
  const allowed = new Set(allowedKeys);
  const extras = Object.keys(object).filter((key) => !allowed.has(key));
  if (extras.length > 0) {
    throw new Error(`${label} contains unsupported field: ${extras.sort()[0]}`);
  }
}

function formatJson(decision, registry, requestedScope) {
  const evidence = decision.evidence || {};
  return {
    verdict: decision.recognized === true ? 'RECOGNIZED' : 'RECOGNITION-REFUSED',
    self_test_passed: true,
    kit_version: KIT_VERSION,
    spec_version: SPEC_VERSION,
    command: 'verify-recognition.mjs',
    registry_type: TRUSTED_ISSUERS_REGISTRY_TYPE,
    registry_evidence_model: registry.evidence_model || null,
    live_probing: false,
    requested_scope: requestedScope || null,
    registry_scope: registry.deployment_scope,
    recognized: decision.recognized === true,
    decision: decision.decision,
    reason_code: decision.reason_code,
    reasons: decision.reasons || [],
    receipt_id: evidence.receipt_id || null,
    kid: evidence.kid || null,
    issuer_status: evidence.issuer_status ?? null,
    signature_valid: evidence.signature_valid ?? null,
    payload: evidence.payload || null,
    safe_claim_ceiling: SAFE_CLAIM_CEILING,
    non_claims: [...NON_CLAIMS],
  };
}

function formatText(decision, registry, requestedScope) {
  const evidence = decision.evidence || {};
  const lines = [];
  lines.push(decision.recognized === true ? 'RECOGNIZED' : 'RECOGNITION-REFUSED');
  lines.push('');
  lines.push('Trusted Receipt Issuer Recognition v1');
  lines.push(`registry_type=${TRUSTED_ISSUERS_REGISTRY_TYPE}`);
  lines.push(`evidence_model=${registry.evidence_model || 'unspecified'}; live_probing=false`);
  lines.push(`requested_scope=${requestedScope || 'default'}; registry_scope=${registry.deployment_scope}`);
  lines.push(`decision=${decision.decision}; reason=${decision.reason_code}`);
  lines.push(`receipt_id=${evidence.receipt_id || 'null'}; kid=${evidence.kid || 'null'}; issuer_status=${evidence.issuer_status ?? 'null'}; signature_valid=${evidence.signature_valid ?? 'null'}`);
  lines.push('Non-claims:');
  for (const claim of NON_CLAIMS) {
    lines.push(`- ${claim}`);
  }
  return lines.join('\n') + '\n';
}
