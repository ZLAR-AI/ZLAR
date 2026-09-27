#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Verifier Kit v0.1 — Issuer Status Fixture Verifier
//
// Runs a bundled hermetic fixture that proves one recognition rule can
// distinguish active, retired, compromised, missing-status, unknown, and
// missing-key issuers before boarding.
//
// This does not inspect live issuer registries, production keys, custody,
// revocation truth, downstream deployment recognition, or external attestation.
// ═══════════════════════════════════════════════════════════════════════════════

import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runSelfTest, selfTestReport } from './selftest.mjs';
import { PUBLISHER_PUBKEY_PEM, KIT_VERSION, SPEC_VERSION } from './lib/kit-publisher.mjs';
import {
  assertIssuerStatusProof,
  assertNoUnsafeIssuerStatusProofText,
  formatIssuerStatusProofSummary,
  runIssuerStatusProof,
} from './lib/issuer-status-proof.mjs';

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
let jsonOutput = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--json') {
    jsonOutput = true;
  } else if (a === '--help' || a === '-h') {
    printUsage();
    process.exit(0);
  } else if (a === '--self-test-report') {
    process.stdout.write(selfTestReport(selfTest) + '\n');
    process.exit(0);
  } else {
    process.stderr.write(`ERROR: unsupported argument: ${a}\n`);
    process.stderr.write('Usage: node verify-issuer-status.mjs [--json]\n');
    process.exit(2);
  }
}

function printUsage() {
  process.stdout.write(`
ZLAR Verifier Kit v0.1 — Issuer Status Fixture Verifier  (kit ${KIT_VERSION}, spec ${SPEC_VERSION})

USAGE
  node verify-issuer-status.mjs
  node verify-issuer-status.mjs --json

OPTIONS
  --json               Machine-readable output
  --self-test-report   Print self-test detail and exit 0
  --help, -h           Show this help

EXIT CODES
  0   ISSUER-STATUS-FIXTURE-VERIFIED  fixture boundary verified
  1   ISSUER-STATUS-FIXTURE-FAIL      fixture boundary failed
  2   ERROR                           bad args
  4   BUNDLE-INTEGRITY-FAIL           kit self-test failed; verification NOT attempted

WHAT THIS PROVES
  A local hermetic fixture recognition rule accepts one active issuer and
  refuses retired, compromised, missing-status, unknown, and missing-key
  issuers before boarding.

WHAT THIS DOES NOT PROVE
  This does not prove live active issuer status, key custody, revocation truth,
  production trust-registry state, downstream recognition for a real
  deployment, external attestation, production authority, sovereign recognition,
  or coverage of unrouted surfaces.
`.trimEnd() + '\n');
}

// ─── Fixture verification ────────────────────────────────────────────────────

let report;
try {
  report = runIssuerStatusProof();
  assertIssuerStatusProof(report);
  const outputProbe = JSON.stringify(report);
  assertNoUnsafeIssuerStatusProofText(outputProbe);
} catch (err) {
  if (jsonOutput) {
    process.stdout.write(JSON.stringify({
      verdict: 'ISSUER-STATUS-FIXTURE-FAIL',
      reason: err && err.message ? err.message : String(err),
      self_test_passed: true,
      kit_version: KIT_VERSION,
      spec_version: SPEC_VERSION,
    }, null, 2) + '\n');
  } else {
    process.stdout.write('ISSUER-STATUS-FIXTURE-FAIL\n');
    process.stdout.write(`${err && err.message ? err.message : String(err)}\n`);
  }
  process.exit(1);
}

if (jsonOutput) {
  process.stdout.write(JSON.stringify({
    verdict: 'ISSUER-STATUS-FIXTURE-VERIFIED',
    self_test_passed: true,
    kit_version: KIT_VERSION,
    spec_version: SPEC_VERSION,
    command: 'verify-issuer-status.mjs',
    ...report,
  }, null, 2) + '\n');
} else {
  process.stdout.write('ISSUER-STATUS-FIXTURE-VERIFIED\n\n');
  process.stdout.write(formatIssuerStatusProofSummary(report));
}
