#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  LIVE_TRUST_REGISTRY_STATE_FALSE_FLAGS,
  assertLiveTrustRegistryStateContract,
  buildLiveTrustRegistryStateVerification,
  formatLiveTrustRegistryStateVerification,
} from '../lib/live-trust-registry-state-contract.mjs';

let pass = 0;
let fail = 0;
let total = 0;

function assert(label, condition, detail = '') {
  total++;
  if (condition) {
    pass++;
    console.log(`  PASS: ${label}`);
  } else {
    fail++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, expectedMessageFragment) {
  total++;
  try {
    fn();
    fail++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      pass++;
      console.log(`  PASS: ${label}`);
    } else {
      fail++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function falseBoundary() {
  return Object.fromEntries(LIVE_TRUST_REGISTRY_STATE_FALSE_FLAGS.map((key) => [key, false]));
}

function sampleContract(overrides = {}) {
  const snapshotSha = '2'.repeat(64);
  const previousSnapshotSha = '1'.repeat(64);
  const claimBoundary = falseBoundary();
  const contract = {
    contract_type: 'zlar-live-trust-registry-state-contract-v1',
    schema_version: 1,
    registry_snapshot: {
      snapshot_type: 'zlar-live-trust-registry-snapshot-contract-v1',
      registry_id: 'private-operator-terminal-registry',
      registry_sequence: 4,
      evidence_model: 'no-secret-live-shaped-contract',
      live_probing: false,
      deployment_scope: 'protected-records.private-operator.records-terminal',
      effective_at: '2026-07-08T21:00:00.000Z',
      expires_at: '2026-07-08T22:00:00.000Z',
      previous_snapshot_sha256: previousSnapshotSha,
      snapshot_sha256: snapshotSha,
      trusted_issuer_count: 3,
      issuer_status_counts: {
        active: 1,
        retired: 0,
        revoked: 1,
        compromised: 0,
        unknown: 1,
      },
      private_key_material_included: false,
      raw_public_key_material_included: false,
      claim_boundary: { ...claimBoundary },
      non_claims: [
        'This contract is no-secret and live-shaped only.',
        'This contract does not prove live trust-registry state, key custody, revocation truth, or production downstream recognition.',
      ],
    },
    issuer_state: {
      issuer_kid: '88aaeeaca05eba4d',
      issuer_status: 'revoked',
      status_reason_code: 'operator_revocation_rehearsal',
      status_effective_at: '2026-07-08T21:05:00.000Z',
      status_expires_at: '2026-07-08T22:00:00.000Z',
      status_sequence: 7,
      registry_snapshot_sha256: snapshotSha,
      public_key_sha256: '3'.repeat(64),
      trust_anchor_sha256: null,
      scope_binding: {
        policy_version: 'recognition-policy-v1',
        domain: 'records',
        tool: 'records.write',
        outcome: 'allow',
      },
      claim_boundary: { ...claimBoundary },
    },
    custody_posture: {
      custody_class: 'software_local_declared',
      custody_evidence_id: 'declared-no-secret-custody-posture',
      custody_evidence_sha256: '4'.repeat(64),
      private_key_material_included: false,
      key_custody_proven: false,
      hardware_custody_proven: false,
      claim_boundary: { ...claimBoundary },
    },
    revocation_closure: {
      revocation_event_id: 'issuer-revocation-rehearsal-001',
      issuer_kid: '88aaeeaca05eba4d',
      previous_status: 'active',
      new_status: 'revoked',
      revoked_at: '2026-07-08T21:06:00.000Z',
      registry_sequence: 4,
      previous_snapshot_sha256: previousSnapshotSha,
      new_snapshot_sha256: snapshotSha,
      affected_scope: 'protected-records.private-operator.records-terminal',
      freshness_window_seconds: 120,
      recognized_before_revocation: true,
      recognized_after_revocation: false,
      claim_boundary: { ...claimBoundary },
    },
    claim_boundary: { ...claimBoundary },
    non_claims: [
      'This verifies a no-secret live-shaped registry contract only.',
      'This does not prove live registry state, key custody, revocation truth, production downstream recognition, public external attestation, or current-machine governance.',
    ],
  };
  return {
    ...contract,
    ...overrides,
  };
}

function runZlar(args, input = '') {
  return spawnSync('./bin/zlar', args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

console.log('\n-- live trust registry state contract --');

const valid = sampleContract();
assert('valid contract verifies', assertLiveTrustRegistryStateContract(valid));
const validText = `${JSON.stringify(valid, null, 2)}\n`;
const verification = buildLiveTrustRegistryStateVerification(valid, { inputText: validText });
assertEqual('verification type', 'zlar-live-trust-registry-state-contract-verification-v1', verification.verification_type);
assertEqual('verification verified', true, verification.verified);
assertEqual('verification live truth false', false, verification.live_truth_claimed);
assertEqual('verification key custody false', false, verification.key_custody_claimed);
assertEqual('verification revocation truth false', false, verification.revocation_truth_claimed);
assertEqual('verification production false', false, verification.production_recognition_claimed);
assert('formatted verification privacy safe', !formatLiveTrustRegistryStateVerification(verification).includes('/Users/'));

const liveProbe = clone(valid);
liveProbe.registry_snapshot.live_probing = true;
assertThrows('live probing true refused', () => assertLiveTrustRegistryStateContract(liveProbe), 'live_probing');

const liveClaim = clone(valid);
liveClaim.claim_boundary.live_trust_registry_state = true;
assertThrows('live registry claim refused', () => assertLiveTrustRegistryStateContract(liveClaim), 'live trust registry claim_boundary.live_trust_registry_state');

const keyCustodyClaim = clone(valid);
keyCustodyClaim.custody_posture.key_custody_proven = true;
assertThrows('key custody claim refused', () => assertLiveTrustRegistryStateContract(keyCustodyClaim), 'key or hardware custody');

const provenCustodyClass = clone(valid);
provenCustodyClass.custody_posture.custody_class = 'hardware_proven';
assertThrows('proven custody class refused', () => assertLiveTrustRegistryStateContract(provenCustodyClass), 'proven custody classes');

const rawPublicMaterial = clone(valid);
rawPublicMaterial.registry_snapshot.raw_public_key_material_included = true;
assertThrows('raw public key material flag refused', () => assertLiveTrustRegistryStateContract(rawPublicMaterial), 'raw_public_key_material_included');

const privateMaterial = clone(valid);
privateMaterial.non_claims.push('-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----');
assertThrows('private key material refused', () => assertLiveTrustRegistryStateContract(privateMaterial), 'private key material');

const issuerSnapshotMismatch = clone(valid);
issuerSnapshotMismatch.issuer_state.registry_snapshot_sha256 = '5'.repeat(64);
assertThrows('issuer snapshot mismatch refused', () => assertLiveTrustRegistryStateContract(issuerSnapshotMismatch), 'issuer registry snapshot sha mismatch');

const revocationSnapshotMismatch = clone(valid);
revocationSnapshotMismatch.revocation_closure.new_snapshot_sha256 = '6'.repeat(64);
assertThrows('revocation snapshot mismatch refused', () => assertLiveTrustRegistryStateContract(revocationSnapshotMismatch), 'revocation new snapshot');

const revocationStillRecognized = clone(valid);
revocationStillRecognized.revocation_closure.recognized_after_revocation = true;
assertThrows('revocation still recognized refused', () => assertLiveTrustRegistryStateContract(revocationStillRecognized), 'recognized_after_revocation');

const vagueCounts = clone(valid);
vagueCounts.registry_snapshot.issuer_status_counts.revoked = 0;
assertThrows('issuer status count drift refused', () => assertLiveTrustRegistryStateContract(vagueCounts), 'issuer status counts');

console.log('\n-- live trust registry state CLI --');

const scratch = mkdtempSync(join(tmpdir(), 'zlar-live-trust-registry-state-'));
const inputPath = join(scratch, 'contract.json');
writeFileSync(inputPath, validText);

const jsonRun = runZlar(['live-trust-registry-state', 'verify', '--input', inputPath, '--json']);
assertEqual('CLI json exits zero', 0, jsonRun.status);
assertEqual('CLI json stderr empty', '', jsonRun.stderr);
assert('CLI json verification true', JSON.parse(jsonRun.stdout).verified === true);

const stdinRun = runZlar(['live-trust-registry-state', 'verify', '--input', '-'], validText);
assertEqual('CLI stdin exits zero', 0, stdinRun.status);
assert('CLI stdin output names claim ceiling', stdinRun.stdout.includes('no live registry'));

const badInput = clone(valid);
badInput.claim_boundary.public_external_attestation = true;
const badRun = runZlar(['live-trust-registry-state', 'verify', '--input', '-'], `${JSON.stringify(badInput)}\n`);
assertEqual('CLI bad claim exits nonzero', 1, badRun.status);
assertEqual('CLI bad claim emits no stdout', '', badRun.stdout);
assert('CLI bad claim names boundary', badRun.stderr.includes('public_external_attestation'));

console.log(`\nResults: ${pass}/${total} passed`);
if (fail > 0) {
  process.exit(1);
}
