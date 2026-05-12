#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Verifier Kit v0.1 — Receipt Verifier
//
// Verifies a Governed Action Receipt v1 envelope against a public key.
// Refuses to start if its own bundle integrity does not check out.
//
// Usage:
//   node verify.mjs <receipt.json> --pubkey <key.pub>
//   cat receipt.json | node verify.mjs --pubkey <key.pub>
//
// Exit codes:
//   0 = VALID                  signature OK, semantic OK, kid matches
//   1 = INVALID                signature OR semantic OR bound failure
//   2 = ERROR                  bad args, missing file, bad JSON, bad PEM
//   3 = UNKNOWN-SIGNER         receipt kid does not match provided pubkey
//   4 = BUNDLE-INTEGRITY-FAIL  kit self-test failed; verification NOT attempted
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import { runSelfTest, selfTestReport } from './selftest.mjs';
import { PUBLISHER_PUBKEY_PEM, KIT_VERSION, SPEC_VERSION } from './lib/kit-publisher.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Self-test FIRST ─────────────────────────────────────────────────────────
// Cannot be silenced. Cannot be skipped. Broken kit refuses to verify.

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
let pubkeyPath = null;
let jsonOutput = false;
let verbose = false;
let allowV0 = false;
let strictCanonical = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--pubkey' && i + 1 < args.length) {
    pubkeyPath = args[++i];
  } else if (a === '--json') {
    jsonOutput = true;
  } else if (a === '--verbose' || a === '-v') {
    verbose = true;
  } else if (a === '--allow-v0') {
    allowV0 = true;
  } else if (a === '--strict-canonical') {
    strictCanonical = true;
  } else if (a === '--help' || a === '-h') {
    printUsage();
    process.exit(0);
  } else if (a === '--self-test-report') {
    process.stdout.write(selfTestReport(selfTest) + '\n');
    process.exit(0);
  } else if (!a.startsWith('-') && !receiptPath) {
    receiptPath = a;
  }
}

function printUsage() {
  process.stdout.write(`
ZLAR Verifier Kit v0.1 — Receipt Verifier  (kit ${KIT_VERSION}, spec ${SPEC_VERSION})

USAGE
  node verify.mjs <receipt.json> --pubkey <key.pub>
  cat receipt.json | node verify.mjs --pubkey <key.pub>

OPTIONS
  --pubkey <path>      Ed25519 public key (PEM)            [REQUIRED]
  --json               Machine-readable output
  --verbose, -v        Show receipt details alongside verdict
  --allow-v0           Accept legacy v0 receipts (off by default)
  --strict-canonical   Reject non-spec canonical forms (DEC-5)
  --self-test-report   Print self-test detail and exit 0
  --help, -h           Show this help

EXIT CODES
  0   VALID                  signature OK, semantic OK, kid matches
  1   INVALID                signature OR semantic OR bound failure
  2   ERROR                  bad args, missing file, bad JSON, bad PEM
  3   UNKNOWN-SIGNER         receipt kid does not match provided pubkey
  4   BUNDLE-INTEGRITY-FAIL  kit self-test failed; verification NOT attempted

WHAT THIS PROVES
  A VALID verdict proves: the receipt was produced by the holder of the
  named signing key, the canonical form was honored at signing time, the
  payload fields are internally coherent (semantic invariants hold), and
  no bit has changed since signing.

WHAT THIS DOES NOT PROVE
  See README.md "Limits — what this kit does not prove" for the eight
  named limits (L1-L8). In particular this kit DOES NOT prove the agent
  was routed through ZLAR, a human actually attended, the timestamp is
  externally anchored, cross-gate canonicalization byte-parity holds,
  hardware-rooted signing, external attestation, or policy replay.
`.trimEnd() + '\n');
}

// ─── Input validation ────────────────────────────────────────────────────────

if (!pubkeyPath) {
  process.stderr.write('ERROR: --pubkey is required\n');
  process.stderr.write('Usage: node verify.mjs <receipt.json> --pubkey <key.pub>\n');
  process.exit(2);
}

let receiptJson;
if (receiptPath) {
  try {
    receiptJson = readFileSync(resolve(receiptPath), 'utf8');
  } catch (err) {
    process.stderr.write(`ERROR: Cannot read receipt file: ${receiptPath}\n  ${err.message}\n`);
    process.exit(2);
  }
} else if (!process.stdin.isTTY) {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  receiptJson = Buffer.concat(chunks).toString('utf8');
} else {
  process.stderr.write('ERROR: No receipt provided. Pass a file path or pipe to stdin.\n');
  process.exit(2);
}

let publicKeyPem;
try {
  publicKeyPem = readFileSync(resolve(pubkeyPath), 'utf8');
} catch (err) {
  process.stderr.write(`ERROR: Cannot read public key: ${pubkeyPath}\n  ${err.message}\n`);
  process.exit(2);
}

let receipt;
try {
  receipt = JSON.parse(receiptJson);
} catch (err) {
  process.stderr.write(`ERROR: Receipt is not valid JSON.\n  ${err.message}\n`);
  process.exit(2);
}

// ─── kid pre-check (UNKNOWN-SIGNER discrimination) ───────────────────────────
// Per CONFORMANCE.md §1.1 item 9: unknown-signer is distinct from invalid.
// Today's bin/zlar-verify collapses the two. The kit separates them so an
// operator can tell "wrong key" from "bad signature."

const providedKid = createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 16);
const receiptKid = receipt && typeof receipt === 'object' ? receipt.kid : null;
const isV1 = receipt && typeof receipt.v === 'number' && receipt.v === 1;

if (isV1 && typeof receiptKid === 'string' && receiptKid.length === 16 && receiptKid !== providedKid) {
  emitUnknownSigner(receiptKid, providedKid);
  process.exit(3);
}

// ─── Verification (delegated to bundled lib/receipt.mjs) ─────────────────────

const libPath = join(__dirname, 'lib', 'receipt.mjs');
const { verifyReceiptAny } = await import(libPath);

const result = verifyReceiptAny(receipt, publicKeyPem, { allowV0 });
const warnings = [];

// strictCanonical: today's lib/sig-verify.mjs accepts three canonical forms
// for v0 receipts (spec / bash-pipeline / bash-pretty). v1 receipts use the
// envelope form and re-canonicalization is not performed. Surface the v0
// multi-canonical path as a warning candidate.
if (strictCanonical && result.version === 'v0' && result.valid) {
  warnings.push({
    code: 'STRICT_CANONICAL_VIOLATION',
    detail: 'v0 receipts may have been accepted via multi-canonical fallback; --strict-canonical forbids non-spec forms.'
  });
}

emitVerdict(result, warnings, strictCanonical);
process.exit(result.valid && warnings.length === 0 ? 0 : 1);

// ─── Output ──────────────────────────────────────────────────────────────────

function emitUnknownSigner(rkid, pkid) {
  if (jsonOutput) {
    process.stdout.write(JSON.stringify({
      verdict: 'UNKNOWN-SIGNER',
      reason: 'Receipt kid does not match provided public key.',
      receipt_id: receipt && receipt.id ? receipt.id : null,
      receipt_kid: rkid,
      provided_kid: pkid,
      kid_match: false,
      self_test_passed: true,
      kit_version: KIT_VERSION,
      spec_version: SPEC_VERSION
    }, null, 2) + '\n');
    return;
  }
  process.stdout.write('UNKNOWN-SIGNER\n');
  process.stdout.write(`Receipt kid:      ${rkid}\n`);
  process.stdout.write(`Provided key kid: ${pkid}\n`);
  process.stdout.write('These do not match.\n');
}

function emitVerdict(r, warns, strict) {
  const isV1 = r.version === 'v1';
  const p = isV1 ? r.payload : null;
  const displayId = receipt.id;
  const displayVersion = isV1 ? `v${receipt.v}` : (receipt.receipt_version ? receipt.receipt_version : null);
  const displayTool = isV1 ? (p && p.tool) : (receipt.governed_action && receipt.governed_action.tool);
  const displayDomain = isV1 ? (p && p.domain) : (receipt.governed_action && receipt.governed_action.domain);
  const displayOutcome = isV1 ? (p && p.outcome) : (receipt.decision && receipt.decision.outcome);
  const displayRule = isV1 ? (p && p.rule) : (receipt.decision && receipt.decision.rule);
  const displayAuthorizer = isV1 ? (p && p.authorizer) : (receipt.decision && receipt.decision.authorizer);
  const displayTimestamp = isV1 ? (p && p.ts) : (receipt.decision && receipt.decision.timestamp);
  const displayPolicy = isV1 ? (p && p.policy_version) : (receipt.evidence && receipt.evidence.policy_version);
  const displayAgent = isV1 ? (p && p.manifest_agent_id) : (receipt.evidence && receipt.evidence.manifest_agent_id);
  const displayAuditId = isV1 ? (p && p.audit_event_id) : (receipt.evidence && receipt.evidence.audit_event_id);
  const displayKid = isV1 ? receipt.kid : (receipt.signature && receipt.signature.key_id);

  const effectiveValid = r.valid && (warns.length === 0);
  const verdict = effectiveValid ? 'VALID' : 'INVALID';

  if (jsonOutput) {
    const out = {
      verdict,
      reason: r.reason,
      receipt_id: displayId,
      receipt_version: displayVersion,
      format: r.version,
      kid_match: isV1 ? (receipt.kid === providedKid) : null,
      self_test_passed: true,
      kit_version: KIT_VERSION,
      spec_version: SPEC_VERSION,
      strict_canonical: strict,
      warnings: warns,
      canonicalization_caveat: 'v1 envelope: signature covers SHA-256(decoded payload bytes); no re-canonicalization at verify time. v0 multi-canonical fallback accepts spec/bash-pipeline/bash-pretty forms (ADR-011).'
    };
    if (verbose && displayTool) {
      out.tool = displayTool;
      out.domain = displayDomain;
      out.outcome = displayOutcome;
      out.rule = displayRule;
      out.authorizer = displayAuthorizer;
      out.timestamp = displayTimestamp;
      out.policy_version = displayPolicy;
      out.manifest_agent_id = displayAgent;
      out.audit_event_id = displayAuditId;
      out.signed_by = displayKid;
      out.algorithm = 'Ed25519';
    }
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    return;
  }

  process.stdout.write(verdict + '\n');
  process.stdout.write('\n');
  process.stdout.write(r.reason + '\n');
  if (warns.length > 0) {
    process.stdout.write('\n');
    for (const w of warns) {
      process.stdout.write(`WARNING [${w.code}]: ${w.detail}\n`);
    }
  }
  if (verbose && displayTool) {
    process.stdout.write('\n--- Receipt Details ---\n');
    process.stdout.write(`  ID:         ${displayId}\n`);
    process.stdout.write(`  Version:    ${displayVersion} (${r.version})\n`);
    process.stdout.write(`  Tool:       ${displayTool}\n`);
    process.stdout.write(`  Domain:     ${displayDomain}\n`);
    process.stdout.write(`  Outcome:    ${displayOutcome}\n`);
    process.stdout.write(`  Rule:       ${displayRule}\n`);
    process.stdout.write(`  Authorizer: ${displayAuthorizer}\n`);
    process.stdout.write(`  Timestamp:  ${displayTimestamp}\n`);
    process.stdout.write(`  Policy:     ${displayPolicy}\n`);
    if (displayAgent) process.stdout.write(`  Agent:      ${displayAgent}\n`);
    process.stdout.write(`  Audit ID:   ${displayAuditId}\n`);
    process.stdout.write(`  Signed by:  ${displayKid} (Ed25519)\n`);
  }
}
