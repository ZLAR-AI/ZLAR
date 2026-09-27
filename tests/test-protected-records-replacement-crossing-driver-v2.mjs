import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  PROTECTED_RECORDS_REPLACEMENT_HOLDER_BOUND_KEYS_V2,
  PROTECTED_RECORDS_REPLACEMENT_HOLDER_SIGNED_ONCE_KEYS_V2,
  PROTECTED_RECORDS_REPLACEMENT_PACKET_KEYS_V2,
  assertProtectedRecordsReplacementSignedReceiptEnvelopeProjectionV2,
  deriveProtectedRecordsReplacementRuntimeConfigV2,
  deriveProtectedRecordsReplacementRuntimeRequestV2,
  validateProtectedRecordsReplacementCrossingAuthorityV2,
} from '../lib/protected-records-replacement-crossing-driver-v2.mjs';
import {
  protectedRecordsReplacementConfirmationRelayInputsV2,
} from '../lib/protected-records-replacement-artifacts-v2.mjs';
import { sha256hex } from '../lib/receipt.mjs';

let assertions = 0;

function equal(label, expected, actual) {
  assertions += 1;
  if (expected !== actual) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function ok(label, value) {
  equal(label, true, Boolean(value));
}

function refuses(label, fn, expectedText) {
  assertions += 1;
  try {
    fn();
  } catch (error) {
    if (String(error?.message).includes(expectedText)) return;
    throw new Error(
      `${label}: expected ${JSON.stringify(expectedText)}, got ${JSON.stringify(error?.message)}`,
    );
  }
  throw new Error(`${label}: expected refusal`);
}

const PACKET_KEYS = PROTECTED_RECORDS_REPLACEMENT_PACKET_KEYS_V2;
const HOLDER_SIGNED_ONCE_KEYS =
  PROTECTED_RECORDS_REPLACEMENT_HOLDER_SIGNED_ONCE_KEYS_V2;
const HOLDER_BOUND_KEYS = PROTECTED_RECORDS_REPLACEMENT_HOLDER_BOUND_KEYS_V2;

equal('replacement packet schema has 33 exact keys', 33, PACKET_KEYS.length);
equal('replacement holder-bound schema has 59 exact keys', 59, HOLDER_BOUND_KEYS.length);
equal(
  'replacement holder-signed-once schema has 25 exact keys',
  25,
  HOLDER_SIGNED_ONCE_KEYS.length,
);
for (const [label, keys, required] of [
  [
    'packet checkpoint parity fields',
    PACKET_KEYS,
    ['source_repository_checkpoint', 'source_repository_checkpoint_body_sha256'],
  ],
  [
    'holder permission and activation parity fields',
    HOLDER_BOUND_KEYS,
    [
      'activation_record_body_sha256',
      'holder_claim_capability_sha256',
      'source_repository_checkpoint_body_sha256',
      'transport_descriptor_shape',
    ],
  ],
  [
    'holder timer parity fields',
    HOLDER_SIGNED_ONCE_KEYS,
    [
      'holder_observed_signing_milliseconds',
      'signing_window_early_wakeup_count',
      'signing_window_early_wakeup_limit',
      'signing_window_timer_guard_milliseconds',
    ],
  ],
]) {
  ok(label, required.every((key) => keys.includes(key)));
}

function exactNullObject(keys) {
  return Object.fromEntries(keys.map((key) => [key, null]));
}

const H = 'a'.repeat(64);
const unsignedEnvelope = {
  iat: 100,
  id: 'receipt-fixture',
  kid: '',
  payload: 'e30',
  prev: null,
  sig: '',
  type: 'governed-action',
  v: 1,
};
const signedEnvelope = {
  ...unsignedEnvelope,
  kid: 'fixture-kid',
  sig: 'fixture-signature',
};
const unsignedEnvelopeSha = sha256hex(canonicalize(unsignedEnvelope));
ok(
  'exact unsigned-to-signed envelope projection validates without signing',
  assertProtectedRecordsReplacementSignedReceiptEnvelopeProjectionV2({
    appointedIssuerKid: 'fixture-kid',
    signedReceipt: signedEnvelope,
    unsignedReceipt: unsignedEnvelope,
    unsignedReceiptEnvelopeSha256: unsignedEnvelopeSha,
  }),
);
for (const [label, changes, expectedText] of [
  ['changed signed id', { signedReceipt: { ...signedEnvelope, id: 'other' } }, 'unsigned-envelope projection mismatch'],
  ['changed signed previous hash', { signedReceipt: { ...signedEnvelope, prev: H } }, 'unsigned-envelope projection mismatch'],
  ['wrong appointed kid', { appointedIssuerKid: 'other-kid' }, 'unsigned-envelope projection mismatch'],
  ['wrong unsigned envelope hash', { unsignedReceiptEnvelopeSha256: H }, 'unsigned-envelope projection mismatch'],
  ['extra signed field', { signedReceipt: { ...signedEnvelope, hidden: true } }, 'unexpected or missing fields'],
]) {
  refuses(
    `${label} refuses`,
    () => assertProtectedRecordsReplacementSignedReceiptEnvelopeProjectionV2({
      appointedIssuerKid: 'fixture-kid',
      signedReceipt: signedEnvelope,
      unsignedReceipt: unsignedEnvelope,
      unsignedReceiptEnvelopeSha256: unsignedEnvelopeSha,
      ...changes,
    }),
    expectedText,
  );
}
const basePacket = exactNullObject(PACKET_KEYS);
const baseSigned = exactNullObject(HOLDER_SIGNED_ONCE_KEYS);
const baseHolderBound = exactNullObject(HOLDER_BOUND_KEYS);
const BASE_SIGNED_SHA = sha256hex(canonicalize(baseSigned));
const baseParams = {
  packet: basePacket,
  holderBound: baseHolderBound,
  holderSignedOnce: baseSigned,
  requiredPacketSha256: H,
  requiredHolderBoundSha256: H,
  requiredHolderSignedOnceSha256: BASE_SIGNED_SHA,
  requiredGrantSha256: H,
  requiredManifestSchemaSha256: H,
  observedEpoch: 1,
  sourceCommitOid: 'a'.repeat(40),
  sourceRepositoryRealpath: '/fixture/ZLAR_Repo',
  sourceWorktreeClean: true,
};

for (const [label, key] of [
  ['packet', 'packet'],
  ['holder-bound', 'holderBound'],
  ['holder-signed-once', 'holderSignedOnce'],
]) {
  const missing = structuredClone(baseParams);
  delete missing[key][Object.keys(missing[key])[0]];
  refuses(
    `${label} missing field refuses`,
    () => validateProtectedRecordsReplacementCrossingAuthorityV2(missing),
    'unexpected or missing fields',
  );
  const extra = structuredClone(baseParams);
  extra[key].hidden = true;
  refuses(
    `${label} extra field refuses`,
    () => validateProtectedRecordsReplacementCrossingAuthorityV2(extra),
    'unexpected or missing fields',
  );
}

for (const key of [
  'requiredPacketSha256',
  'requiredHolderBoundSha256',
  'requiredHolderSignedOnceSha256',
  'requiredGrantSha256',
  'requiredManifestSchemaSha256',
]) {
  refuses(
    `${key} malformed refuses`,
    () => validateProtectedRecordsReplacementCrossingAuthorityV2({
      ...structuredClone(baseParams),
      [key]: 'bad',
    }),
    'must be lowercase SHA-256 hex',
  );
}

refuses(
  'invalid observed epoch refuses',
  () => validateProtectedRecordsReplacementCrossingAuthorityV2({
    ...structuredClone(baseParams),
    observedEpoch: Number.NaN,
  }),
  'observed epoch is invalid',
);

equal(
  'confirmation relay accepts zero-second delivery',
  0,
  protectedRecordsReplacementConfirmationRelayInputsV2({
    confirmationConfirmedAtEpoch: 1_000,
    holderObservedConfirmationEpoch: 1_000,
  }).controlTowerConfirmationRelayDelaySeconds,
);
equal(
  'confirmation relay accepts exact 300-second boundary',
  300,
  protectedRecordsReplacementConfirmationRelayInputsV2({
    confirmationConfirmedAtEpoch: 1_000,
    holderObservedConfirmationEpoch: 1_300,
  }).controlTowerConfirmationRelayDelaySeconds,
);
refuses(
  'confirmation relay refuses future-dated confirmation',
  () => protectedRecordsReplacementConfirmationRelayInputsV2({
    confirmationConfirmedAtEpoch: 1_001,
    holderObservedConfirmationEpoch: 1_000,
  }),
  'nonnegative safe integer',
);
refuses(
  'confirmation relay refuses 301-second delivery',
  () => protectedRecordsReplacementConfirmationRelayInputsV2({
    confirmationConfirmedAtEpoch: 1_000,
    holderObservedConfirmationEpoch: 1_301,
  }),
  'directional inclusive bound',
);
equal(
  'crossing CLI forwards validated relay to composition and exhausted closeout',
  2,
  (readFileSync(
    'lib/protected-records-replacement-crossing-cli-v2.mjs',
    'utf8',
  ).match(/authorityValidation\.confirmation_relay_inputs/g) || []).length,
);
ok(
  'crossing authority refuses confirmation received at or after valid-from',
  readFileSync(
    'lib/protected-records-replacement-crossing-driver-v2.mjs',
    'utf8',
  ).includes(
    'holderSignedOnce.confirmation.confirmed_at_epoch >=\n' +
      '      packet.grant_contract.time_policy.valid_from_epoch',
  ),
);

const holderHashPacket = exactNullObject(PACKET_KEYS);
holderHashPacket.packet_type =
  'zlar.protected-records.replacement-post-hardening-authorization-packet.v2';
holderHashPacket.packet_version = 2;
const holderHashPacketSha = sha256hex(canonicalize(holderHashPacket));
const mismatchedHolderBound = exactNullObject(HOLDER_BOUND_KEYS);
mismatchedHolderBound.holder_bound_body_sha256 = H;
mismatchedHolderBound.event = 'holder_bound';
mismatchedHolderBound.holder_protocol = 'zlar-ephemeral-issuer-holder-v1';
mismatchedHolderBound.key_generation_count = 1;
mismatchedHolderBound.private_key_exported = false;
mismatchedHolderBound.private_key_extractable = false;
mismatchedHolderBound.packet_body_sha256 = holderHashPacketSha;
mismatchedHolderBound.grant_contract_sha256 = H;
const holderHashSigned = exactNullObject(HOLDER_SIGNED_ONCE_KEYS);
holderHashSigned.packet_body_sha256 = holderHashPacketSha;
refuses(
  'holder-bound body mismatch refuses',
  () => validateProtectedRecordsReplacementCrossingAuthorityV2({
    ...structuredClone(baseParams),
    packet: holderHashPacket,
    holderBound: mismatchedHolderBound,
    holderSignedOnce: holderHashSigned,
    requiredHolderSignedOnceSha256:
      sha256hex(canonicalize(holderHashSigned)),
    requiredPacketSha256: holderHashPacketSha,
  }),
  'holder-bound identity mismatch',
);

const derivedPacket = {
  grant_contract: {
    scope: {
      action_class: 'records.write',
      runtime_profile_id: 'protected-records-disposable-runtime-profile',
    },
  },
  grant_contract_sha256: H,
  record_update: { operation: 'set_status', record_alias: 'driver-shape-only' },
  appointment: { appointment: 'shape-only' },
  source_precondition: { source: 'shape-only' },
  recognition_rule: { rule: 'shape-only' },
  target_binding: { target_handle: `zlar-target:v1:logical-fixture:${H}` },
};
const derivedSigned = {
  confirmation: { confirmation: 'shape-only' },
  issuance_decision: { decision: 'shape-only' },
  authority_status: { status: 'shape-only' },
  signed_receipt: { receipt: 'shape-only' },
};
const derivedConfig = deriveProtectedRecordsReplacementRuntimeConfigV2({
  packet: derivedPacket,
  holderSignedOnce: derivedSigned,
  authorityStatusRefreshPath: '/tmp/status.json',
  consumedGrantsPath: '/tmp/consumed.json',
  consumedGrantStoreAnchorPath: '/tmp/anchor.json',
  consumedGrantStoreWitnessPath: '/tmp/witness.json',
});
equal('derived v2 config has no now_epoch', false, 'now_epoch' in derivedConfig);
equal('derived v2 config has 16 exact fields', 16, Object.keys(derivedConfig).length);
const derivedRequest = deriveProtectedRecordsReplacementRuntimeRequestV2({
  packet: derivedPacket,
  holderSignedOnce: derivedSigned,
});
equal('derived request has five fields', 5, Object.keys(derivedRequest).length);
equal('derived request has no now_epoch', false, 'now_epoch' in derivedRequest);
equal('derived request has no authority status', false, 'authority_grant_status' in derivedRequest);

const crossingBootstrapSource = readFileSync(
  'bin/zlar-protected-records-replacement-crossing-v2',
  'utf8',
);
const crossingSource = readFileSync(
  'lib/protected-records-replacement-crossing-cli-v2.mjs',
  'utf8',
);
const crossingDriverLibrarySource = readFileSync(
  'lib/protected-records-replacement-crossing-driver-v2.mjs',
  'utf8',
);
const sourceSnapshotBoundarySource = readFileSync(
  'lib/protected-records-replacement-source-snapshot-v2.mjs',
  'utf8',
);
ok(
  'bootstrap clears inherited Node loader and search-path variables',
  crossingBootstrapSource.includes('exec /usr/bin/env -i') &&
    !crossingBootstrapSource.includes('NODE_OPTIONS=') &&
    !crossingBootstrapSource.includes('NODE_PATH='),
);
ok('driver requires holder-bound file', crossingSource.includes("'--holder-bound'"));
ok('driver requires holder-bound SHA', crossingSource.includes("'--require-holder-bound-sha'"));
ok('driver requires holder-signed-once SHA', crossingSource.includes("'--require-holder-signed-once-sha'"));
ok(
  'driver pins unsigned-to-signed receipt envelope projection',
  crossingDriverLibrarySource.includes(
    'assertProtectedRecordsReplacementSignedReceiptEnvelopeProjectionV2',
  ),
);
ok('driver ignores redirectable ZLAR_PROJECT_DIR', !crossingSource.includes('process.env.ZLAR_PROJECT_DIR'));
ok('driver uses physical checkout path', sourceSnapshotBoundarySource.includes('const PROJECT_DIR = realpathSync'));
ok('driver uses absolute Git binary', sourceSnapshotBoundarySource.includes("spawnSync('/usr/bin/git'"));
ok(
  'driver uses minimal child environment',
  crossingSource.includes('protectedRecordsReplacementMinimalChildEnvironmentV2()'),
);
ok(
  'driver materializes exact detached source snapshot',
    crossingSource.includes('materializeProtectedRecordsReplacementSourceSnapshotV2') &&
    sourceSnapshotBoundarySource.includes("'clone',") &&
    sourceSnapshotBoundarySource.includes("'--no-local'") &&
    sourceSnapshotBoundarySource.includes("'checkout',") &&
    sourceSnapshotBoundarySource.includes("'--detach'")
);
ok(
  'driver disables clone and checkout hooks',
  (sourceSnapshotBoundarySource.match(/core\.hooksPath=\/dev\/null/g) || []).length === 2 &&
    sourceSnapshotBoundarySource.includes("'--template'"),
);
ok(
  'driver refuses hidden Git index flags',
  sourceSnapshotBoundarySource.includes("['ls-files', '-v', '-z']") &&
    sourceSnapshotBoundarySource.includes('hiddenIndexFlagPresent'),
);
ok(
  'driver rechecks and freezes exact source before runtime import',
  crossingSource.includes(
    'const preSpawnSourceState = protectedRecordsReplacementGitSourceStateV2',
  ) &&
    crossingSource.indexOf(
      'freezeProtectedRecordsReplacementSnapshotReadOnlyV2(',
    ) <
      crossingSource.indexOf('const run = spawnSync('),
);
ok(
  'runtime child executes from exact source snapshot',
  crossingSource.includes('[sourceSnapshot.runtimeServicePath,') &&
    crossingSource.includes('cwd: sourceSnapshot.snapshotDir')
);
ok(
  'driver re-reads persisted result before composition',
  crossingSource.indexOf('const persistedRuntimeResultRaw = readFileSync(runtimeResultPath)') <
    crossingSource.indexOf(
      'const artifacts = composeProtectedRecordsReplacementArtifactSetFromResultV2',
    ),
);
ok(
  'driver compares persisted runtime result raw bytes before parsing',
  crossingSource.indexOf('persistedRuntimeResultRaw.equals(runtimeResultBytes)') <
    crossingSource.indexOf("persistedRuntimeResultRaw.toString('utf8')"),
);
ok('composition receives persisted result', crossingSource.includes('runtimeResult: persistedRuntimeResult'));
ok(
  'live exhausted status precedes immutable exhausted evidence',
  crossingSource.indexOf('replaceCanonical(\n    authorityStatusRefreshPath') <
    crossingSource.indexOf("'80-authority-status-exhausted-v2.json'"),
);
ok(
  'exhausted closeout uses verified crossing binding',
  crossingSource.includes('persistedVerification.authority_binding'),
);

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
for (const [label, args] of [
  ['crossing help', ['protected-records-replacement-crossing-v2', '--help']],
  ['verifier help', ['protected-records-replacement-artifact-set-v2', '--help']],
]) {
  const run = spawnSync(join(repoRoot, 'bin/zlar'), args, {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  equal(`${label} exits zero`, 0, run.status);
}
const mainHelp = spawnSync(join(repoRoot, 'bin/zlar'), ['help'], {
  cwd: repoRoot,
  encoding: 'utf8',
});
equal('main help exits zero', 0, mainHelp.status);
ok(
  'main help lists crossing driver',
  mainHelp.stdout.includes('protected-records-replacement-crossing-v2'),
);
ok(
  'main help lists independent verifier',
  mainHelp.stdout.includes('protected-records-replacement-artifact-set-v2'),
);
const loaderSanitizedHelp = spawnSync(
  join(repoRoot, 'bin/zlar'),
  ['protected-records-replacement-crossing-v2', '--help'],
  {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NODE_OPTIONS: '--require=/definitely-missing-zlar-preload.cjs',
      NODE_PATH: '/definitely-missing-zlar-node-path',
    },
  },
);
equal('crossing bootstrap neutralizes inherited NODE_OPTIONS', 0, loaderSanitizedHelp.status);

const scratch = mkdtempSync(join(tmpdir(), 'zlar-crossing-driver-refusal-'));
try {
  const forbiddenOutput = join(scratch, 'forbidden-output');
  const run = spawnSync(
    join(repoRoot, 'bin/zlar'),
    [
      'protected-records-replacement-crossing-v2',
      'cross-and-pin',
      '--now-epoch', '1',
      '--output-dir', forbiddenOutput,
    ],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  equal('main dispatch caller clock refuses', 2, run.status);
  equal('main dispatch caller clock creates no output', false, existsSync(forbiddenOutput));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(
  `protected records replacement crossing driver v2: ${assertions}/${assertions} assertions passed`,
);
