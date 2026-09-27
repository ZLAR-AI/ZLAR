import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  createReceipt,
  createReceiptV1FromEvent,
  pubkeyFingerprint,
  signReceipt,
  signReceiptV1,
} from './receipt.mjs';

export const RECEIPT_VERIFIER_BOUNDARY_PROOF_TYPE =
  'zlar-receipt-verifier-boundary-proof-v1';

export const RECEIPT_VERIFIER_BOUNDARY_SAFE_CLAIM_CEILING =
  'ZLAR can run a local ephemeral receipt-verifier fixture that proves zlar-verify distinguishes VALID signed-byte/semantic integrity, UNKNOWN-SIGNER public-key mismatch, and INVALID tampering without proving active issuer status, key custody, revocation state, downstream recognition, production deployment, current-machine governance, external attestation, sovereign recognition, or unrouted-path coverage.';

export const RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS = Object.freeze([
  'This proof verifies a local ephemeral v1 receipt under supplied local ephemeral public keys only.',
  'This proof does not prove active issuer status, key custody, or revocation state.',
  'This proof does not prove downstream recognition or production relying-party acceptance.',
  'This proof does not prove current-machine governance, production deployment, external attestation, sovereign recognition, or coverage of unrouted paths.',
]);

const PROJECT_DIR = fileURLToPath(new URL('..', import.meta.url));
const VERIFY_BIN = join(PROJECT_DIR, 'bin', 'zlar-verify');
const KID_PATTERN = /^[a-f0-9]{16}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

function keyPair(tmpDir, prefix) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privatePath = join(tmpDir, `${prefix}.key`);
  const publicPath = join(tmpDir, `${prefix}.pub`);
  writeFileSync(privatePath, privatePem);
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPath,
    kid: pubkeyFingerprint(publicPath),
  };
}

function runVerifier(args) {
  return spawnSync(process.execPath, [VERIFY_BIN, ...args], {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
  });
}

function parseJsonRun(label, run) {
  if (run.stderr !== '') {
    throw new Error(`${label} emitted unexpected stderr`);
  }
  try {
    return JSON.parse(run.stdout);
  } catch (err) {
    throw new Error(`${label} emitted invalid JSON: ${err.message}`);
  }
}

function hasKid(value) {
  return typeof value === 'string' && KID_PATTERN.test(value);
}

function hasSha256(value) {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

export function runReceiptVerifierBoundaryProof() {
  const tmpDir = mkdtempSync(join(tmpdir(), 'zlar-receipt-verifier-boundary-'));
  try {
    const goodKey = keyPair(tmpDir, 'good');
    const wrongKey = keyPair(tmpDir, 'wrong');
    const receipt = signReceiptV1(
      createReceiptV1FromEvent({
        id: 'zlar-receipt-verifier-boundary-event-001',
        ts: '2026-06-20T00:00:00.000Z',
        action: 'Bash',
        domain: 'file',
        detail: { command: 'printf safe' },
        outcome: 'deny',
        rule: 'R002',
        authorizer: 'policy',
        policy_version: 'receipt-verifier-boundary-fixture',
        prev_hash: '0'.repeat(64),
      }),
      goodKey.privatePem,
      goodKey.kid
    );
    const receiptPath = join(tmpDir, 'receipt.json');
    writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

    const validRun = runVerifier([receiptPath, '--pubkey', goodKey.publicPath, '--json']);
    const validJson = parseJsonRun('valid verifier case', validRun);

    const requiredIdentityRun = runVerifier([
      receiptPath,
      '--pubkey',
      goodKey.publicPath,
      '--json',
      '--require-receipt-id',
      receipt.id,
      '--require-receipt-sha',
      validJson.receipt_sha256,
      '--require-kid',
      goodKey.kid,
      '--require-pubkey-sha',
      validJson.provided_pubkey_sha256,
      '--require-format',
      'v1',
      '--require-v1-only',
    ]);
    const requiredIdentityJson = parseJsonRun(
      'required identity verifier case',
      requiredIdentityRun
    );

    const unknownRun = runVerifier([receiptPath, '--pubkey', wrongKey.publicPath, '--json']);
    const unknownJson = parseJsonRun('unknown-signer verifier case', unknownRun);

    const tampered = { ...receipt, sig: `${receipt.sig.slice(0, -2)}xx` };
    const tamperedPath = join(tmpDir, 'tampered.json');
    writeFileSync(tamperedPath, JSON.stringify(tampered, null, 2));
    const invalidRun = runVerifier([tamperedPath, '--pubkey', goodKey.publicPath, '--json']);
    const invalidJson = parseJsonRun('invalid verifier case', invalidRun);

    const legacyV0Receipt = signReceipt(
      createReceipt({
        id: 'zlar-receipt-verifier-boundary-v0-event-001',
        tool: 'Bash',
        domain: 'file',
        detail: { command: 'printf legacy-safe' },
        outcome: 'deny',
        rule: 'R002',
        authorizer: 'policy',
        timestamp: '2026-06-20T00:00:00.000Z',
        policy_version: 'receipt-verifier-boundary-v0-fixture',
        audit_event_id: 'zlar-receipt-verifier-boundary-v0-event-001',
        audit_prev_hash: '0'.repeat(64),
      }),
      goodKey.privatePem,
      goodKey.kid
    );
    const legacyV0Path = join(tmpDir, 'legacy-v0-receipt.json');
    writeFileSync(legacyV0Path, JSON.stringify(legacyV0Receipt, null, 2));
    const legacyV0RequiredIdentityRun = runVerifier([
      legacyV0Path,
      '--pubkey',
      goodKey.publicPath,
      '--allow-v0',
      '--require-receipt-id',
      legacyV0Receipt.id,
    ]);

    const helpRun = runVerifier(['--help']);

    const report = {
      proof_type: RECEIPT_VERIFIER_BOUNDARY_PROOF_TYPE,
      evidence_model: 'local-ephemeral-receipt-verifier-fixture',
      live_probing: false,
      safe_claim_ceiling: RECEIPT_VERIFIER_BOUNDARY_SAFE_CLAIM_CEILING,
      command: 'zlar-verify <receipt.json> --pubkey <key.pub> --json',
      receipt_version: 'v1',
      receipt_type: 'governed-action',
      signed_byte_integrity_checked: true,
      semantic_checks_checked: true,
      valid_exit_code: validRun.status,
      valid_verdict: validJson.verdict,
      valid_format: validJson.format,
      valid_receipt_version: validJson.receipt_version,
      valid_kid_match: validJson.kid_match,
      valid_receipt_sha256_present: hasSha256(validJson.receipt_sha256),
      valid_provided_pubkey_sha256_present:
        hasSha256(validJson.provided_pubkey_sha256),
      valid_command_posture_allow_v0: validJson.command_posture?.allow_v0,
      valid_command_posture_detected_format:
        validJson.command_posture?.detected_format,
      valid_required_identity_command_posture:
        validJson.required_identity?.command_posture,
      valid_receipt_id_present: typeof validJson.receipt_id === 'string' && validJson.receipt_id.length > 0,
      valid_receipt_kid_present: hasKid(validJson.receipt_kid),
      valid_provided_kid_present: hasKid(validJson.provided_kid),
      required_identity_exit_code: requiredIdentityRun.status,
      required_identity_verdict: requiredIdentityJson.verdict,
      required_identity_receipt_id_matched:
        requiredIdentityJson.required_identity?.receipt_id_matched,
      required_identity_receipt_sha256_matched:
        requiredIdentityJson.required_identity?.receipt_sha256_matched,
      required_identity_kid_matched:
        requiredIdentityJson.required_identity?.kid_matched,
      required_identity_pubkey_sha256_matched:
        requiredIdentityJson.required_identity?.pubkey_sha256_matched,
      required_identity_format_matched:
        requiredIdentityJson.required_identity?.format_matched,
      required_identity_v1_only_matched:
        requiredIdentityJson.required_identity?.v1_only_matched,
      required_identity_command_posture:
        requiredIdentityJson.required_identity?.command_posture,
      required_identity_command_posture_allow_v0:
        requiredIdentityJson.command_posture?.allow_v0,
      required_identity_command_posture_detected_format:
        requiredIdentityJson.command_posture?.detected_format,
      required_identity_command_posture_v1_only_required:
        requiredIdentityJson.command_posture?.v1_only_required,
      unknown_signer_exit_code: unknownRun.status,
      unknown_signer_verdict: unknownJson.verdict,
      unknown_signer_reason: unknownJson.reason,
      unknown_signer_kid_match: unknownJson.kid_match,
      unknown_signer_receipt_sha256_matches_valid:
        unknownJson.receipt_sha256 === validJson.receipt_sha256,
      unknown_signer_provided_pubkey_sha256_differs:
        unknownJson.provided_pubkey_sha256 !== validJson.provided_pubkey_sha256,
      unknown_signer_receipt_id_present:
        typeof unknownJson.receipt_id === 'string' && unknownJson.receipt_id.length > 0,
      unknown_signer_receipt_kid_present: hasKid(unknownJson.receipt_kid),
      unknown_signer_provided_kid_present: hasKid(unknownJson.provided_kid),
      invalid_exit_code: invalidRun.status,
      invalid_verdict: invalidJson.verdict,
      invalid_format: invalidJson.format,
      invalid_receipt_version: invalidJson.receipt_version,
      invalid_kid_match: invalidJson.kid_match,
      invalid_receipt_sha256_differs_from_valid:
        invalidJson.receipt_sha256 !== validJson.receipt_sha256,
      invalid_provided_pubkey_sha256_matches_valid:
        invalidJson.provided_pubkey_sha256 === validJson.provided_pubkey_sha256,
      invalid_receipt_id_present:
        typeof invalidJson.receipt_id === 'string' && invalidJson.receipt_id.length > 0,
      invalid_receipt_kid_present: hasKid(invalidJson.receipt_kid),
      invalid_provided_kid_present: hasKid(invalidJson.provided_kid),
      legacy_v0_required_identity_refused:
        legacyV0RequiredIdentityRun.status === 1 &&
        legacyV0RequiredIdentityRun.stdout === '' &&
        legacyV0RequiredIdentityRun.stderr.includes(
          'required identity is v1-only in this verifier stage'
        ),
      legacy_v0_required_identity_exit_code: legacyV0RequiredIdentityRun.status,
      help_exit_code: helpRun.status,
      help_names_unknown_signer: helpRun.stdout.includes('UNKNOWN-SIGNER'),
      help_names_non_claims:
        helpRun.stdout.includes('WHAT THIS DOES NOT PROVE') &&
        helpRun.stdout.includes('active issuer status') &&
        helpRun.stdout.includes('downstream recognition'),
      distinguishes_unknown_signer_from_invalid:
        unknownRun.status === 3 &&
        unknownJson.verdict === 'UNKNOWN-SIGNER' &&
        invalidRun.status === 1 &&
        invalidJson.verdict === 'INVALID',
      issuer_recognition_proven: false,
      key_custody_proven: false,
      revocation_state_proven: false,
      downstream_recognition_proven: false,
      production_deployment_proven: false,
      current_machine_governance_proven: false,
      external_attestation: false,
      sovereign_recognition: false,
      unrouted_paths_coverage_proven: false,
      non_claims: [...RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS],
    };
    assertReceiptVerifierBoundaryProof(report);
    return report;
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertExactObjectKeys(label, value, expectedKeys) {
  assertObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} has unexpected fields`);
  }
}

export function assertReceiptVerifierBoundaryProof(report) {
  assertExactObjectKeys('Receipt verifier boundary proof', report, [
    'command',
    'current_machine_governance_proven',
    'distinguishes_unknown_signer_from_invalid',
    'downstream_recognition_proven',
    'evidence_model',
    'external_attestation',
    'help_exit_code',
    'help_names_non_claims',
    'help_names_unknown_signer',
    'invalid_exit_code',
    'invalid_format',
    'invalid_kid_match',
    'invalid_provided_pubkey_sha256_matches_valid',
    'invalid_provided_kid_present',
    'invalid_receipt_id_present',
    'invalid_receipt_kid_present',
    'invalid_receipt_sha256_differs_from_valid',
    'invalid_receipt_version',
    'invalid_verdict',
    'issuer_recognition_proven',
    'key_custody_proven',
    'legacy_v0_required_identity_exit_code',
    'legacy_v0_required_identity_refused',
    'live_probing',
    'non_claims',
    'production_deployment_proven',
    'proof_type',
    'receipt_type',
    'receipt_version',
    'revocation_state_proven',
    'safe_claim_ceiling',
    'semantic_checks_checked',
    'signed_byte_integrity_checked',
    'sovereign_recognition',
    'required_identity_command_posture',
    'required_identity_command_posture_allow_v0',
    'required_identity_command_posture_detected_format',
    'required_identity_command_posture_v1_only_required',
    'required_identity_exit_code',
    'required_identity_format_matched',
    'required_identity_kid_matched',
    'required_identity_pubkey_sha256_matched',
    'required_identity_receipt_id_matched',
    'required_identity_receipt_sha256_matched',
    'required_identity_v1_only_matched',
    'required_identity_verdict',
    'unknown_signer_exit_code',
    'unknown_signer_kid_match',
    'unknown_signer_provided_pubkey_sha256_differs',
    'unknown_signer_provided_kid_present',
    'unknown_signer_reason',
    'unknown_signer_receipt_id_present',
    'unknown_signer_receipt_kid_present',
    'unknown_signer_receipt_sha256_matches_valid',
    'unknown_signer_verdict',
    'unrouted_paths_coverage_proven',
    'valid_command_posture_allow_v0',
    'valid_command_posture_detected_format',
    'valid_exit_code',
    'valid_format',
    'valid_kid_match',
    'valid_provided_pubkey_sha256_present',
    'valid_provided_kid_present',
    'valid_receipt_id_present',
    'valid_receipt_kid_present',
    'valid_receipt_sha256_present',
    'valid_receipt_version',
    'valid_required_identity_command_posture',
    'valid_verdict',
  ]);
  if (report.proof_type !== RECEIPT_VERIFIER_BOUNDARY_PROOF_TYPE) {
    throw new Error('Receipt verifier boundary proof type drifted');
  }
  if (report.evidence_model !== 'local-ephemeral-receipt-verifier-fixture') {
    throw new Error('Receipt verifier boundary proof evidence model drifted');
  }
  if (report.live_probing !== false) {
    throw new Error('Receipt verifier boundary proof must not perform live probing');
  }
  if (report.safe_claim_ceiling !== RECEIPT_VERIFIER_BOUNDARY_SAFE_CLAIM_CEILING) {
    throw new Error('Receipt verifier boundary safe claim ceiling drifted');
  }
  if (report.command !== 'zlar-verify <receipt.json> --pubkey <key.pub> --json') {
    throw new Error('Receipt verifier boundary command drifted');
  }
  if (report.receipt_version !== 'v1' || report.receipt_type !== 'governed-action') {
    throw new Error('Receipt verifier boundary receipt identity drifted');
  }
  if (report.signed_byte_integrity_checked !== true || report.semantic_checks_checked !== true) {
    throw new Error('Receipt verifier boundary integrity checks drifted');
  }
  if (
    report.valid_exit_code !== 0 ||
    report.valid_verdict !== 'VALID' ||
    report.valid_format !== 'v1' ||
    report.valid_receipt_version !== 'v1' ||
    report.valid_kid_match !== true ||
    report.valid_receipt_sha256_present !== true ||
    report.valid_provided_pubkey_sha256_present !== true ||
    report.valid_command_posture_allow_v0 !== false ||
    report.valid_command_posture_detected_format !== 'v1' ||
    report.valid_required_identity_command_posture !== 'receipt-verifier-v1-default' ||
    report.valid_receipt_id_present !== true ||
    report.valid_receipt_kid_present !== true ||
    report.valid_provided_kid_present !== true
  ) {
    throw new Error('Receipt verifier boundary VALID case failed');
  }
  if (
    report.required_identity_exit_code !== 0 ||
    report.required_identity_verdict !== 'VALID' ||
    report.required_identity_receipt_id_matched !== true ||
    report.required_identity_receipt_sha256_matched !== true ||
    report.required_identity_kid_matched !== true ||
    report.required_identity_pubkey_sha256_matched !== true ||
    report.required_identity_format_matched !== true ||
    report.required_identity_v1_only_matched !== true ||
    report.required_identity_command_posture !== 'receipt-verifier-v1-only-required' ||
    report.required_identity_command_posture_allow_v0 !== false ||
    report.required_identity_command_posture_detected_format !== 'v1' ||
    report.required_identity_command_posture_v1_only_required !== true
  ) {
    throw new Error('Receipt verifier boundary required identity case failed');
  }
  if (
    report.unknown_signer_exit_code !== 3 ||
    report.unknown_signer_verdict !== 'UNKNOWN-SIGNER' ||
    report.unknown_signer_reason !== 'Receipt kid does not match provided public key.' ||
    report.unknown_signer_kid_match !== false ||
    report.unknown_signer_receipt_sha256_matches_valid !== true ||
    report.unknown_signer_provided_pubkey_sha256_differs !== true ||
    report.unknown_signer_receipt_id_present !== true ||
    report.unknown_signer_receipt_kid_present !== true ||
    report.unknown_signer_provided_kid_present !== true
  ) {
    throw new Error('Receipt verifier boundary UNKNOWN-SIGNER case failed');
  }
  if (
    report.invalid_exit_code !== 1 ||
    report.invalid_verdict !== 'INVALID' ||
    report.invalid_format !== 'v1' ||
    report.invalid_receipt_version !== 'v1' ||
    report.invalid_kid_match !== true ||
    report.invalid_receipt_sha256_differs_from_valid !== true ||
    report.invalid_provided_pubkey_sha256_matches_valid !== true ||
    report.invalid_receipt_id_present !== true ||
    report.invalid_receipt_kid_present !== true ||
    report.invalid_provided_kid_present !== true
  ) {
    throw new Error('Receipt verifier boundary INVALID case failed');
  }
  if (
    report.legacy_v0_required_identity_refused !== true ||
    report.legacy_v0_required_identity_exit_code !== 1
  ) {
    throw new Error('Receipt verifier boundary legacy v0 required identity refusal failed');
  }
  if (
    report.help_exit_code !== 0 ||
    report.help_names_unknown_signer !== true ||
    report.help_names_non_claims !== true
  ) {
    throw new Error('Receipt verifier boundary help boundary failed');
  }
  if (report.distinguishes_unknown_signer_from_invalid !== true) {
    throw new Error('Receipt verifier boundary must distinguish UNKNOWN-SIGNER from INVALID');
  }
  for (const field of [
    'issuer_recognition_proven',
    'key_custody_proven',
    'revocation_state_proven',
    'downstream_recognition_proven',
    'production_deployment_proven',
    'current_machine_governance_proven',
    'external_attestation',
    'sovereign_recognition',
    'unrouted_paths_coverage_proven',
  ]) {
    if (report[field] !== false) {
      throw new Error(`Receipt verifier boundary ${field} must remain false`);
    }
  }
  if (
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS.length
  ) {
    throw new Error('Receipt verifier boundary non-claims drifted');
  }
  for (let i = 0; i < RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS.length; i++) {
    if (report.non_claims[i] !== RECEIPT_VERIFIER_BOUNDARY_NON_CLAIMS[i]) {
      throw new Error('Receipt verifier boundary non-claims drifted');
    }
  }
  return true;
}
