import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

export const KEY_STATE_REPORT_TYPE = 'zlar-key-state-report-v1';
export const KEY_STATE_NON_CLAIMS = Object.freeze([
  'This report does not read private key bytes or request PINs.',
  'This report does not sign, rotate, revoke, or migrate keys.',
  'This report does not prove key custody or hardware possession.',
  'This report does not prove active issuer status, revocation state, production trust registry truth, downstream recognition, production authority, external attestation, sovereign recognition, or current-machine governance.',
]);

const NO_VALUE = null;

function sha256First16(buffer) {
  return createHash('sha256').update(buffer).digest('hex').slice(0, 16);
}

function fpOfPemFile(file) {
  if (!existsSync(file)) return NO_VALUE;
  return sha256First16(readFileSync(file));
}

function fpOfEmbeddedB64(b64) {
  if (!b64 || b64 === 'null') return NO_VALUE;
  return sha256First16(Buffer.from(`-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`));
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: 'utf8',
    ...options,
  });
}

function commandAvailable(command) {
  const result = run(command, ['--version']);
  return result.error?.code !== 'ENOENT';
}

function listYubiKeys() {
  const result = run('ykman', ['list']);
  if (result.error?.code === 'ENOENT') {
    return {
      ykman_available: false,
      devices: [],
    };
  }
  const devices = [];
  for (const line of result.stdout.split(/\r?\n/)) {
    const match = line.match(/Serial:\s*([0-9]+)/);
    if (match) devices.push({ serial: match[1] });
  }
  return {
    ykman_available: true,
    devices,
  };
}

function fpOfYubiKeySlot(serial, slot) {
  if (!commandAvailable('openssl')) return { fingerprint: NO_VALUE, status: 'openssl_missing' };

  const scratch = mkdtempSync(join(tmpdir(), 'zlar-key-state-'));
  const derPath = join(scratch, 'slot.der');
  const pemPath = join(scratch, 'slot.pem');
  try {
    const exportRun = run('ykman', ['--device', serial, 'piv', 'keys', 'export', slot, derPath, '--format', 'DER']);
    if (exportRun.status !== 0) return { fingerprint: NO_VALUE, status: 'empty_or_unavailable' };

    const opensslRun = run('openssl', ['pkey', '-pubin', '-inform', 'DER', '-in', derPath, '-outform', 'PEM'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (opensslRun.status !== 0 || !opensslRun.stdout) {
      return { fingerprint: NO_VALUE, status: 'format_error' };
    }
    return {
      fingerprint: sha256First16(Buffer.from(opensslRun.stdout)),
      status: 'present',
    };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function allPresentAndEqual(values) {
  return values.every(Boolean) && values.every((value) => value === values[0]);
}

function hardwareSlot(devices, deviceIndex, slot) {
  const device = devices[deviceIndex];
  if (!device) {
    return {
      observed: false,
      slot,
      fingerprint: NO_VALUE,
      status: 'no_device',
    };
  }
  const result = fpOfYubiKeySlot(device.serial, slot);
  return {
    observed: result.status === 'present',
    slot,
    fingerprint: result.fingerprint,
    status: result.status,
  };
}

export function buildKeyStateReport({
  projectDir = process.cwd(),
  homeDir = process.env.HOME || '',
  generatedAt = new Date().toISOString(),
  hardwareObservation = null,
  toolAvailability = null,
} = {}) {
  const diskPolicy = fpOfPemFile(join(projectDir, 'etc', 'keys', 'policy-signing.pub'));
  const diskConstitution = fpOfPemFile(join(projectDir, 'etc', 'keys', 'constitution-signing.pub'));
  const diskPolicyOc = fpOfPemFile(join(projectDir, 'etc', 'keys', 'policy-signing-oc.pub'));
  const diskSpec = fpOfPemFile(join(projectDir, 'spec', 'test-key.pub'));
  const diskLegacySoftware = fpOfPemFile(join(homeDir, '.zlar-signing.pub'));
  const legacySoftwarePrivateKeyPresent = existsSync(join(homeDir, '.zlar-signing.key'));

  const manifest = readJson(join(projectDir, 'etc', 'manifest.json'));
  const activePolicy = readJson(join(projectDir, 'etc', 'policies', 'active.policy.json'));
  const constitution = readJson(join(projectDir, 'etc', 'constitution.json'));

  const manifestKeyId = manifest?.signature?.key_id || NO_VALUE;
  const activePolicyFp = fpOfEmbeddedB64(activePolicy?.signature?.public_key || '');
  const constitutionFp = fpOfEmbeddedB64(constitution?.signature?.public_key || '');

  const yubiKeys = hardwareObservation || listYubiKeys();
  const policyHardware = hardwareSlot(yubiKeys.devices, 0, '9c');
  const constitutionHardware = hardwareSlot(yubiKeys.devices, 0, '9d');
  const specHardware = hardwareSlot(yubiKeys.devices, 1, '9a');

  const policySoftwarePinsAligned = allPresentAndEqual([diskPolicy, manifestKeyId, activePolicyFp]);
  const constitutionSoftwarePinsAligned = allPresentAndEqual([diskConstitution, constitutionFp]);
  const specHardwareAligned = specHardware.observed && specHardware.fingerprint === diskSpec;

  return {
    report_type: KEY_STATE_REPORT_TYPE,
    generated_at: generatedAt,
    evidence_model: 'local-read-only-key-state',
    live_probing: false,
    read_only: true,
    claim_boundary: 'local verifier/pin alignment snapshot only; no signing, private-key read, key custody proof, revocation truth, production trust registry, or external attestation',
    fingerprint_convention: 'first 16 hex of SHA-256(public-key PEM bytes including trailing newline)',
    operational_posture: {
      policy_manifest_constitution: 'software-rooted-current',
      hardware_policy_constitution: 'provisioned-target-not-current-custody-proof',
      spec_test_vectors: 'hardware-backed-target',
    },
    privacy: {
      private_key_material_read: false,
      private_key_material_included: false,
      private_key_paths_included: false,
      yubi_key_serial_numbers_included: false,
    },
    tools: {
      ykman_available: yubiKeys.ykman_available,
      openssl_available: toolAvailability?.openssl_available ?? commandAvailable('openssl'),
    },
    public_verifiers: {
      policy_signing_pub: diskPolicy,
      constitution_signing_pub: diskConstitution,
      policy_signing_oc_pub: diskPolicyOc,
      spec_test_key_pub: diskSpec,
      legacy_software_signing_pub: diskLegacySoftware,
    },
    local_private_key_presence: {
      legacy_software_signing_key_present: legacySoftwarePrivateKeyPresent,
      private_key_bytes_read: false,
    },
    operational_pins: {
      manifest_key_id: manifestKeyId,
      active_policy_embedded_pubkey_fp: activePolicyFp,
      constitution_embedded_pubkey_fp: constitutionFp,
    },
    hardware_observation: {
      yubi_key_count: yubiKeys.devices.length,
      primary_policy_slot_9c: policyHardware,
      primary_constitution_slot_9d: constitutionHardware,
      spare_spec_slot_9a: specHardware,
    },
    concerns: {
      policy_signing: {
        current_posture: 'software-rooted',
        verifier_fingerprint: diskPolicy,
        manifest_key_id: manifestKeyId,
        active_policy_embedded_pubkey_fp: activePolicyFp,
        software_pins_aligned: policySoftwarePinsAligned,
        hardware_target_observed: policyHardware.observed,
        hardware_target_aligned: policyHardware.observed ? policyHardware.fingerprint === diskPolicy : null,
        current_ceremony_ready: policySoftwarePinsAligned,
        custody_claim: 'software-rooted-current; no hardware custody proof',
      },
      constitution_signing: {
        current_posture: 'software-rooted',
        verifier_fingerprint: diskConstitution,
        constitution_embedded_pubkey_fp: constitutionFp,
        software_pins_aligned: constitutionSoftwarePinsAligned,
        hardware_target_observed: constitutionHardware.observed,
        hardware_target_aligned: constitutionHardware.observed ? constitutionHardware.fingerprint === diskConstitution : null,
        current_ceremony_ready: constitutionSoftwarePinsAligned,
        custody_claim: 'software-rooted-current; no hardware custody proof',
      },
      spec_test_vector_signing: {
        current_posture: 'hardware-backed-target',
        verifier_fingerprint: diskSpec,
        hardware_target_observed: specHardware.observed,
        hardware_target_aligned: specHardware.observed ? specHardwareAligned : null,
        current_ceremony_ready: specHardwareAligned,
        custody_claim: specHardwareAligned ? 'hardware target observed and aligned for spec test-vector signing only' : 'no current hardware observation in this report',
      },
    },
    non_claims: [...KEY_STATE_NON_CLAIMS],
  };
}

export function buildSampleKeyStateReport({ projectDir = process.cwd() } = {}) {
  return buildKeyStateReport({
    projectDir,
    homeDir: join(projectDir, 'tests', 'fixtures', 'key-state-empty-home'),
    generatedAt: '1970-01-01T00:00:00.000Z',
    hardwareObservation: {
      ykman_available: false,
      devices: [],
    },
    toolAvailability: {
      openssl_available: false,
    },
  });
}

export function assertKeyStateReport(report) {
  if (!report || typeof report !== 'object') throw new Error('Key-state report must be an object');
  if (report.report_type !== KEY_STATE_REPORT_TYPE) throw new Error('Unexpected key-state report type');
  if (report.evidence_model !== 'local-read-only-key-state') throw new Error('Unexpected key-state evidence model');
  if (report.live_probing !== false) throw new Error('Key-state report must not claim live probing');
  if (report.read_only !== true) throw new Error('Key-state report must be read-only');
  if (report.privacy?.private_key_material_read !== false) throw new Error('Key-state report must not read private key material');
  if (report.privacy?.private_key_material_included !== false) throw new Error('Key-state report must not include private key material');
  if (report.privacy?.private_key_paths_included !== false) throw new Error('Key-state report must not include private key paths');
  if (report.privacy?.yubi_key_serial_numbers_included !== false) throw new Error('Key-state report must not include YubiKey serial numbers');
  if (report.operational_posture?.policy_manifest_constitution !== 'software-rooted-current') {
    throw new Error('Policy/manifest/constitution posture must remain software-rooted-current');
  }
  for (const field of ['policy_signing', 'constitution_signing', 'spec_test_vector_signing']) {
    if (!report.concerns?.[field]) throw new Error(`Missing key-state concern: ${field}`);
  }
  if (!Array.isArray(report.non_claims) || report.non_claims.length < 3) {
    throw new Error('Key-state report must carry non-claims');
  }
  return true;
}
