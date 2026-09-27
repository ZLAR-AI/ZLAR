import { spawnSync } from 'node:child_process';
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  assertDerivedProtectedRecordsReplacementRuntimeConfigV2,
  buildProtectedRecordsReplacementExhaustedStatusV2,
  composeProtectedRecordsReplacementArtifactSetFromResultV2,
  deriveProtectedRecordsReplacementRuntimeConfigV2,
  deriveProtectedRecordsReplacementRuntimeRequestV2,
  protectedRecordsReplacementRuntimeResultCanonicalBytesV2,
  validateProtectedRecordsReplacementCrossingAuthorityV2,
} from './protected-records-replacement-crossing-driver-v2.mjs';
import {
  verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes,
} from './protected-records-replacement-artifact-set-v2.mjs';
import {
  assertProtectedRecordsRuntimeServiceResultV2,
} from './protected-records-runtime-profile.mjs';
import { sha256hex } from './receipt.mjs';
import {
  freezeProtectedRecordsReplacementSnapshotReadOnlyV2,
  materializeProtectedRecordsReplacementSourceSnapshotV2,
  protectedRecordsReplacementGitSourceStateV2,
  protectedRecordsReplacementMinimalChildEnvironmentV2,
} from './protected-records-replacement-source-snapshot-v2.mjs';

const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const PROJECT_DIR = realpathSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '..'),
);

function usage() {
  console.error(
    'Usage: zlar protected-records-replacement-crossing-v2 cross-and-pin --packet <file> --holder-bound <file> --holder-signed-once <file> --output-dir <new-dir> --require-packet-sha <sha256> --require-holder-bound-sha <sha256> --require-holder-signed-once-sha <sha256> --require-grant-sha <sha256> --require-manifest-schema-sha <sha256> --json',
  );
  console.error(
    'Executes at most one v2 runtime-service request, never retries, writes the accepted result first, and pins the central manifest after the service and terminal artifacts.',
  );
  console.error(
    'There is no caller-supplied consequence clock. Crash-atomic effect-plus-artifact pin and exactly-once semantics are not claimed.',
  );
}

function die(message, code = 1) {
  console.error(`ERROR: ${message}`);
  process.exit(code);
}

function parseArgs(argv) {
  const args = [...argv];
  if (args[0] === '--help' || args[0] === '-h') {
    usage();
    process.exit(0);
  }
  const command = args.shift();
  if (command !== 'cross-and-pin') {
    usage();
    die('cross-and-pin is required.', 2);
  }
  const options = {
    packetPath: '',
    holderBoundPath: '',
    holderSignedOncePath: '',
    outputDir: '',
    requiredPacketSha256: '',
    requiredHolderBoundSha256: '',
    requiredHolderSignedOnceSha256: '',
    requiredGrantSha256: '',
    requiredManifestSchemaSha256: '',
    json: false,
  };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--packet') options.packetPath = args[++index] || '';
    else if (arg === '--holder-bound') {
      options.holderBoundPath = args[++index] || '';
    }
    else if (arg === '--holder-signed-once') {
      options.holderSignedOncePath = args[++index] || '';
    } else if (arg === '--output-dir') options.outputDir = args[++index] || '';
    else if (arg === '--require-packet-sha') {
      options.requiredPacketSha256 = args[++index] || '';
    } else if (arg === '--require-holder-bound-sha') {
      options.requiredHolderBoundSha256 = args[++index] || '';
    } else if (arg === '--require-holder-signed-once-sha') {
      options.requiredHolderSignedOnceSha256 = args[++index] || '';
    } else if (arg === '--require-grant-sha') {
      options.requiredGrantSha256 = args[++index] || '';
    } else if (arg === '--require-manifest-schema-sha') {
      options.requiredManifestSchemaSha256 = args[++index] || '';
    } else if (arg === '--json') options.json = true;
    else if (arg === '--help' || arg === '-h') {
      usage();
      process.exit(0);
    } else {
      usage();
      die(`Unsupported option: ${arg}`, 2);
    }
  }
  for (const [label, value] of [
    ['--packet', options.packetPath],
    ['--holder-bound', options.holderBoundPath],
    ['--holder-signed-once', options.holderSignedOncePath],
    ['--output-dir', options.outputDir],
    ['--require-packet-sha', options.requiredPacketSha256],
    ['--require-holder-bound-sha', options.requiredHolderBoundSha256],
    ['--require-holder-signed-once-sha', options.requiredHolderSignedOnceSha256],
    ['--require-grant-sha', options.requiredGrantSha256],
    ['--require-manifest-schema-sha', options.requiredManifestSchemaSha256],
  ]) {
    if (!value) die(`${label} is required.`, 2);
  }
  if (!options.json) die('--json is required for the exact crossing route.', 2);
  return options;
}

function readJsonRegularFile(path, label) {
  const resolved = resolve(path);
  const status = lstatSync(resolved);
  if (status.isSymbolicLink() || !status.isFile()) {
    throw new Error(`${label} must be a regular non-symlink file`);
  }
  const raw = readFileSync(realpathSync(resolved));
  if (raw.length < 2 || raw.length > MAX_INPUT_BYTES) {
    throw new Error(`${label} size is outside the accepted boundary`);
  }
  return JSON.parse(raw.toString('utf8'));
}

function fsyncDirectory(path) {
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writeOnce(path, bytes) {
  const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8');
  const temporary = `${path}.${process.pid}.${Date.now()}.pending`;
  let fd;
  try {
    fd = openSync(temporary, 'wx', 0o400);
    writeFileSync(fd, body);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    linkSync(temporary, path);
    try {
      fsyncDirectory(dirname(path));
    } catch (error) {
      try {
        unlinkSync(path);
        fsyncDirectory(dirname(path));
      } catch {
        // A visible uncommitted residue remains fail-closed and must not retry.
      }
      throw error;
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
    try {
      unlinkSync(temporary);
    } catch {
      // The final hard link, when present, remains the write-once artifact.
    }
  }
}

function writeCanonical(path, value) {
  writeOnce(path, Buffer.from(canonicalize(value), 'utf8'));
}

function replaceCanonical(path, value) {
  const temporary = `${path}.${process.pid}.${Date.now()}.replacement`;
  let fd;
  try {
    fd = openSync(temporary, 'wx', 0o400);
    writeFileSync(fd, Buffer.from(canonicalize(value), 'utf8'));
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  } finally {
    if (fd !== undefined) closeSync(fd);
    try {
      unlinkSync(temporary);
    } catch {
      // A successful rename removes the temporary name.
    }
  }
}

function parseOneRuntimeResult(run) {
  if (run.error || run.status !== 0 || run.signal) {
    throw new Error('The one runtime-service invocation failed or was ambiguous');
  }
  const lines = run.stdout.toString('utf8').split(/\n/).filter((line) => line.trim());
  if (lines.length !== 1) {
    throw new Error('The one runtime-service invocation did not emit exactly one result');
  }
  const result = JSON.parse(lines[0]);
  assertProtectedRecordsRuntimeServiceResultV2(result);
  return result;
}

const options = parseArgs(process.argv.slice(2));
let outputDir = '';
let authorityStatusRefreshPath = '';
let routeInitialized = false;
let runtimeInvocationsCompleted = 0;
let runtimeResultPersisted = false;
let acceptedResultPersisted = false;
let consequenceExecuted = false;
let manifestPinned = false;
let authorityStatusExhausted = false;

try {
  const packet = readJsonRegularFile(options.packetPath, 'Packet');
  const holderBound = readJsonRegularFile(
    options.holderBoundPath,
    'Holder-bound event',
  );
  const holderSignedOnce = readJsonRegularFile(
    options.holderSignedOncePath,
    'Holder-signed-once event',
  );
  const sourceState = protectedRecordsReplacementGitSourceStateV2();
  const observedEpoch = Math.floor(Date.now() / 1000);
  const authorityValidation =
    validateProtectedRecordsReplacementCrossingAuthorityV2({
      packet,
      holderBound,
      holderSignedOnce,
      requiredPacketSha256: options.requiredPacketSha256,
      requiredHolderBoundSha256: options.requiredHolderBoundSha256,
      requiredHolderSignedOnceSha256:
        options.requiredHolderSignedOnceSha256,
      requiredGrantSha256: options.requiredGrantSha256,
      requiredManifestSchemaSha256:
        options.requiredManifestSchemaSha256,
      observedEpoch,
      ...sourceState,
    });

  outputDir = resolve(options.outputDir);
  const outputRelativeToSource = relative(PROJECT_DIR, outputDir);
  if (
    outputRelativeToSource === '' ||
    (!outputRelativeToSource.startsWith('..') &&
      !isAbsolute(outputRelativeToSource))
  ) {
    throw new Error('Replacement crossing output must remain outside the source repository');
  }
  const outputParent = dirname(outputDir);
  const outputParentStatus = lstatSync(outputParent);
  if (
    outputParentStatus.isSymbolicLink() ||
    !outputParentStatus.isDirectory() ||
    realpathSync(outputParent) !== resolve(outputParent)
  ) {
    throw new Error('Replacement crossing output parent must be a real non-symlink directory');
  }
  const runtimeDir = join(outputDir, 'runtime-control');
  authorityStatusRefreshPath = join(
    runtimeDir,
    'authority-status.json',
  );
  if (
    resolve(packet.revocation_boundary.planned_status_refresh_path) !==
      authorityStatusRefreshPath
  ) {
    throw new Error('Packet status-refresh path does not match the exact output route');
  }
  mkdirSync(outputDir, { mode: 0o700, recursive: false });
  if (realpathSync(outputDir) !== outputDir) {
    throw new Error('Replacement crossing output directory identity drifted');
  }
  routeInitialized = true;
  const sourceSnapshot = materializeProtectedRecordsReplacementSourceSnapshotV2(
    outputDir,
    sourceState.sourceCommitOid,
  );
  mkdirSync(runtimeDir, { mode: 0o700, recursive: false });

  const paths = {
    authorityStatusRefreshPath,
    consumedGrantsPath: join(runtimeDir, 'consumed-grants.json'),
    consumedGrantStoreAnchorPath: join(
      runtimeDir,
      'consumed-grants.anchor.json',
    ),
    consumedGrantStoreWitnessPath: join(
      runtimeDir,
      'consumed-grants.witness.json',
    ),
  };
  const intent = {
    route_type: 'zlar.protected-records.replacement-crossing-intent.v2',
    route_version: 2,
    required_packet_sha256: options.requiredPacketSha256,
    required_holder_bound_sha256: options.requiredHolderBoundSha256,
    required_holder_signed_once_sha256:
      options.requiredHolderSignedOnceSha256,
    required_grant_sha256: options.requiredGrantSha256,
    required_manifest_schema_sha256:
      options.requiredManifestSchemaSha256,
    source_commit_oid: sourceState.sourceCommitOid,
    source_execution_snapshot: {
      mode: 'private-local-git-clone-detached-exact-commit',
      pre_spawn_source_recheck_required: true,
      read_only_before_runtime_import: true,
      source_commit_oid: sourceState.sourceCommitOid,
      runtime_service_path_source: 'materialized-exact-commit',
    },
    authority_validation: authorityValidation,
    runtime_invocation_limit: 1,
    runtime_invocations_completed: 0,
    automatic_retry_allowed: false,
    caller_supplied_consequence_time_accepted: false,
    consequence_executed: false,
    runtime_result_persisted: false,
    accepted_result_persisted: false,
    artifact_manifest_pinned: false,
  };
  writeCanonical(join(outputDir, '00-route-intent-v2.json'), intent);
  writeCanonical(authorityStatusRefreshPath, holderSignedOnce.authority_status);

  const runtimeConfig = deriveProtectedRecordsReplacementRuntimeConfigV2({
    packet,
    holderSignedOnce,
    ...paths,
  });
  assertDerivedProtectedRecordsReplacementRuntimeConfigV2(runtimeConfig);
  const runtimeRequest = deriveProtectedRecordsReplacementRuntimeRequestV2({
    packet,
    holderSignedOnce,
  });
  const runtimeConfigPath = join(
    outputDir,
    '10-runtime-service-config-v2.json',
  );
  writeCanonical(runtimeConfigPath, runtimeConfig);
  writeCanonical(join(outputDir, '11-runtime-request-v2.json'), runtimeRequest);

  const preSpawnSourceState = protectedRecordsReplacementGitSourceStateV2(
    sourceSnapshot.snapshotDir,
  );
  if (
    preSpawnSourceState.sourceWorktreeClean !== true ||
    preSpawnSourceState.sourceCommitOid !== sourceState.sourceCommitOid
  ) {
    throw new Error('Exact source snapshot drifted before runtime import');
  }
  freezeProtectedRecordsReplacementSnapshotReadOnlyV2(
    sourceSnapshot.snapshotDir,
  );

  const run = spawnSync(
    process.execPath,
    [sourceSnapshot.runtimeServicePath, '--config', runtimeConfigPath],
    {
      cwd: sourceSnapshot.snapshotDir,
      input: `${canonicalize(runtimeRequest)}\n`,
      encoding: null,
      timeout: 15_000,
      killSignal: 'SIGKILL',
      maxBuffer: MAX_INPUT_BYTES,
      env: {
        ...protectedRecordsReplacementMinimalChildEnvironmentV2(),
        ZLAR_REPLACEMENT_INTERNAL_CHILD: 'exact-source-single-attempt-v2',
      },
    },
  );
  runtimeInvocationsCompleted = 1;
  const runtimeResult = parseOneRuntimeResult(run);
  consequenceExecuted =
    runtimeResult.service_write_accepted === true &&
    runtimeResult.authority_grant_satisfied === true;
  const runtimeResultBytes =
    protectedRecordsReplacementRuntimeResultCanonicalBytesV2(runtimeResult);
  const runtimeResultPath = join(
    outputDir,
    '20-runtime-service-result-v2.canonical.json',
  );
  writeOnce(
    runtimeResultPath,
    runtimeResultBytes,
  );
  runtimeResultPersisted = true;
  acceptedResultPersisted = consequenceExecuted;
  const persistedRuntimeResultRaw = readFileSync(runtimeResultPath);
  if (!persistedRuntimeResultRaw.equals(runtimeResultBytes)) {
    throw new Error('Persisted runtime result raw bytes drifted before composition');
  }
  const persistedRuntimeResult = JSON.parse(
    persistedRuntimeResultRaw.toString('utf8'),
  );
  assertProtectedRecordsRuntimeServiceResultV2(persistedRuntimeResult);
  if (
    !Buffer.from(canonicalize(persistedRuntimeResult), 'utf8').equals(
      runtimeResultBytes,
    )
  ) {
    throw new Error('Persisted runtime result bytes drifted before composition');
  }
  if (
    persistedRuntimeResult.service_write_accepted !== true ||
    persistedRuntimeResult.authority_grant_satisfied !== true
  ) {
    writeCanonical(join(outputDir, '99-route-failed-closed-v2.json'), {
      route_type: 'zlar.protected-records.replacement-crossing-failure.v2',
      reason_code: persistedRuntimeResult.decision.reason_code,
      runtime_invocations_completed: 1,
      automatic_retry_allowed: false,
      consequence_executed: false,
      runtime_result_persisted: true,
      accepted_result_persisted: false,
      artifact_manifest_pinned: false,
    });
    die('The one runtime request refused; automatic retry is forbidden.', 3);
  }

  const artifacts = composeProtectedRecordsReplacementArtifactSetFromResultV2({
    confirmationRelayInputs:
      authorityValidation.confirmation_relay_inputs,
    runtimeResult: persistedRuntimeResult,
    requiredGrantSha256: options.requiredGrantSha256,
    requiredManifestSchemaSha256:
      options.requiredManifestSchemaSha256,
  });
  const servicePath = join(
    outputDir,
    '30-replacement-service-artifact-v2.canonical.json',
  );
  const terminalPath = join(
    outputDir,
    '40-replacement-terminal-artifact-v2.canonical.json',
  );
  const manifestPath = join(
    outputDir,
    '50-replacement-artifact-set-manifest-v2.canonical.json',
  );
  writeOnce(servicePath, artifacts.serviceArtifactRawBytes);
  writeOnce(terminalPath, artifacts.terminalArtifactRawBytes);
  writeOnce(manifestPath, artifacts.manifestRawBytes);
  manifestPinned = true;

  const persistedVerification =
    verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes({
      expectedManifestArtifactBodySha256:
        artifacts.manifest.integrity.body_sha256,
      manifestRawBytes: readFileSync(manifestPath),
      serviceArtifactRawBytes: readFileSync(servicePath),
      terminalArtifactRawBytes: readFileSync(terminalPath),
    });
  writeCanonical(
    join(outputDir, '60-replacement-artifact-set-verification-v2.json'),
    persistedVerification,
  );
  writeCanonical(
    join(outputDir, '70-replacement-downstream-projections-v2.json'),
    artifacts.downstreamProjections,
  );
  const exhaustedStatus = buildProtectedRecordsReplacementExhaustedStatusV2({
    confirmationRelayInputs:
      authorityValidation.confirmation_relay_inputs,
    runtimeResult: persistedRuntimeResult,
    crossingBindingSha256:
      persistedVerification.authority_binding
        .crossing_binding_sha256,
  });
  replaceCanonical(
    authorityStatusRefreshPath,
    exhaustedStatus.authority_status,
  );
  authorityStatusExhausted = true;
  writeCanonical(
    join(outputDir, '80-authority-status-exhausted-v2.json'),
    exhaustedStatus,
  );
  writeCanonical(join(outputDir, '90-route-closeout-v2.json'), {
    route_type: 'zlar.protected-records.replacement-crossing-closeout.v2',
    runtime_invocations_completed: runtimeInvocationsCompleted,
    automatic_retry_allowed: false,
    consequence_executed: true,
    grant_consumed: true,
    runtime_result_persisted: true,
    accepted_result_persisted: true,
    artifact_manifest_pinned: true,
    authority_status_exhausted: true,
    downstream_verification_without_reexecution: true,
    exactly_once_effect_proven: false,
    crash_atomic_effect_plus_pin_proven: false,
    lifecycle_closed: false,
  });

  process.stdout.write(`${JSON.stringify({
    route_type: 'zlar.protected-records.replacement-crossing-complete.v2',
    consequence_class: 'records.write',
    consequence_path:
      'protected-records.installed-runtime-profile.terminal-chain.records.write',
    runtime_invocations_completed: 1,
    automatic_retry_allowed: false,
    consequence_executed: true,
    grant_consumed: true,
    runtime_result_persisted: true,
    accepted_result_persisted: true,
    manifest_pinned_after_service_and_terminal: true,
    authority_status_exhausted: true,
    manifest_artifact_body_sha256:
      artifacts.manifest.integrity.body_sha256,
    service_artifact_body_sha256:
      artifacts.serviceArtifact.integrity.body_sha256,
    terminal_artifact_body_sha256:
      artifacts.terminalArtifact.integrity.body_sha256,
    downstream_verification_without_reexecution: true,
    exactly_once_effect_proven: false,
    crash_atomic_effect_plus_pin_proven: false,
    lifecycle_closed: false,
  })}\n`);
} catch (error) {
  if (routeInitialized) {
    if (
      !authorityStatusExhausted &&
      authorityStatusRefreshPath &&
      existsSync(authorityStatusRefreshPath)
    ) {
      try {
        const observedStatus = JSON.parse(
          readFileSync(authorityStatusRefreshPath, 'utf8'),
        );
        authorityStatusExhausted =
          observedStatus.status === 'exhausted' &&
          observedStatus.fresh_effect_allowed === false &&
          observedStatus.recorded_effect_uses === 1;
      } catch {
        // Leave the status posture unknown and fail closed.
      }
    }
    try {
      writeCanonical(join(outputDir, '99-route-failed-closed-v2.json'), {
        route_type: 'zlar.protected-records.replacement-crossing-failure.v2',
        reason_code: 'crossing_or_pin_failed',
        error_message_sha256: sha256hex(String(error?.message || error)),
        runtime_invocations_completed: runtimeInvocationsCompleted,
        automatic_retry_allowed: false,
        consequence_executed: consequenceExecuted,
        consequence_state_ambiguous:
          runtimeInvocationsCompleted === 1 && !runtimeResultPersisted,
        runtime_result_persisted: runtimeResultPersisted,
        accepted_result_persisted: acceptedResultPersisted,
        artifact_manifest_pinned: manifestPinned,
        artifact_manifest_visible_residue:
          outputDir !== '' &&
          existsSync(join(
            outputDir,
            '50-replacement-artifact-set-manifest-v2.canonical.json',
          )),
        authority_status_exhausted: authorityStatusExhausted,
        exactly_once_effect_proven: false,
      });
    } catch {
      // The route directory itself is residue and must never trigger retry.
    }
  }
  die(error?.message || 'Replacement crossing failed closed.');
}
