import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalize } from './canonicalize.mjs';
import {
  createReceiptV1FromEvent,
  decodePayloadV1,
  sha256hex,
  signReceiptV1,
  verifyReceiptV1,
} from './receipt.mjs';
import {
  PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
  PROTECTED_RECORDS_TARGET_HANDLE,
  assertNoUnsafeProtectedRecordsRuntimeProfileText,
  assertProtectedRecordsRuntimeServiceConfig,
  assertProtectedRecordsRuntimeServiceResult,
  createProtectedRecordsRuntimeAuthorityReceiptEvidence,
  createProtectedRecordsRuntimeFixtureAuthorityGrantContract,
  createProtectedRecordsRuntimeLauncherScopeEvidence,
  createProtectedRecordsRuntimeTargetBinding,
  protectedRecordsTargetEffect,
} from './protected-records-runtime-profile.mjs';
import {
  PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH,
  PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  assertProtectedRecordsFixtureAuthorityGrantDecision,
  createProtectedRecordsFixtureAuthorityGrantAppointment,
  evaluateProtectedRecordsFixtureAuthorityGrantIssuance,
  protectedRecordsAuthorizedEffectDetail,
  protectedRecordsFixtureAuthorityGrantContractSha256,
} from './protected-records-fixture-authority-grant.mjs';
import {
  readProtectedRecordsInstalledSampleProfile,
} from './protected-records-installed-proof-samples.mjs';
import {
  runtimeProfileSha256,
} from './protected-records-runtime-profile-preflight.mjs';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REPORT_TYPE =
  'zlar-protected-records-named-deployment-profile-real-boundary-proof-v1';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_ACTIVATION_TYPE =
  'zlar-protected-records-named-deployment-profile-real-boundary-activation-v1';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_CODE =
  'machine_local_named_route_outside_authorized_scope';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_MESSAGE =
  'Protected records machine-local named deployment is outside the authorized fixture-only terminal proof scope; authority is required before activation, proof-target writes, or child-process execution.';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID =
  'protected-records-private-operator-records-terminal';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_SAFE_CLAIM =
  'ZLAR can activate one bounded machine-local named protected-records deployment profile for records.write, route proof-owned requests through the selected runtime-service child-process boundary, mutate the proof-owned records target only after a recognized receipt, refuse missing, unrecognized, out-of-scope, request-authority, replay, and closed-profile attempts before target mutation, and close the activation as inert evidence.';

export const PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_NON_CLAIMS = Object.freeze([
  'This proof activates one bounded machine-local named deployment profile only inside the named ZLAR-owned activation root.',
  'This proof uses proof-owned records target files under the build scratch root; it does not touch real personal, business, customer, or production records.',
  'This proof writes public recognition fixture material only inside the named activation root; no private key, token, HMAC, secret, or credential material is persisted or emitted.',
  'This proof does not write hooks, Codex config, user config, machine config, production config, GitHub settings, website files, tags, releases, Actions, or external services.',
  'This proof does not prove generic current-machine governance, raw Codex/developer-tool governance, browser governance, Computer Use governance, MCP governance, shell governance, all-surface governance, production downstream recognition, production authority, enterprise readiness, public external attestation, sovereign recognition, side-door closure, or absolute human intention.',
]);

const ZLAR_BIN = fileURLToPath(new URL('../bin/zlar', import.meta.url));

function repoRootFromModule() {
  return fileURLToPath(new URL('..', import.meta.url));
}

export function defaultNamedDeploymentProfileActivationRoot() {
  return join(
    homedir(),
    '.zlar',
    'protected-records',
    'deployments',
    PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID
  );
}

export function defaultNamedDeploymentProfileProofRoot() {
  const repoRoot = process.env.ZLAR_PROJECT_DIR || repoRootFromModule();
  return join(dirname(repoRoot), 'ZLAR-Draft', 'build');
}

function requireObject(label, value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function exactKeys(label, value, keys) {
  requireObject(label, value);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} keys drifted`);
  }
  return true;
}

function expectBool(label, value, expected) {
  if (value !== expected) {
    throw new Error(`${label} must be ${expected}`);
  }
  return true;
}

function expectString(label, value) {
  if (typeof value !== 'string' || value.length < 1) {
    throw new Error(`${label} must be a non-empty string`);
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(value);
  return true;
}

function expectSha(label, value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${label} must be a SHA-256 hex string`);
  }
  return true;
}

function writeJson(path, value, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode });
  return path;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function publicKeyFingerprint(publicPem) {
  return createHash('sha256').update(publicPem).digest('hex').slice(0, 16);
}

function ephemeralTestIssuer() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    privatePem,
    publicPem,
    kid: publicKeyFingerprint(publicPem),
  };
}

function isoFromEpoch(epoch) {
  return new Date(epoch * 1000).toISOString();
}

function safeRunId(nowEpoch) {
  return isoFromEpoch(nowEpoch).replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
}

function targetLabel(runId) {
  return `<ZLAR-Draft/build>/named-deployment-profile-real-boundary-${runId}/records-target.jsonl`;
}

function activationRootLabel() {
  return `~/.zlar/protected-records/deployments/${PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID}`;
}

function ensureActivationRootShape(activationRoot) {
  if (basename(activationRoot) !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID) {
    throw new Error('Named deployment profile activation root must end with the deployment profile id');
  }
  mkdirSync(activationRoot, { recursive: true, mode: 0o700 });
  return true;
}

function proofRecordUpdate() {
  return {
    ...PROTECTED_RECORDS_FIXTURE_AUTHORIZED_RECORD_UPDATE,
  };
}

function eventFixture({ nowEpoch, detail, id, overrides = {} }) {
  return {
    id,
    ts: overrides.ts || isoFromEpoch(nowEpoch - 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: Object.prototype.hasOwnProperty.call(overrides, 'detail')
      ? overrides.detail
      : detail,
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RRECORDS_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function signedReceipt({ issuer, nowEpoch, detail, id, overrides = {} }) {
  return signReceiptV1(
    createReceiptV1FromEvent(eventFixture({
      nowEpoch,
      detail,
      id,
      overrides,
    })),
    issuer.privatePem,
    issuer.kid
  );
}

function recognitionRule({
  activeIssuer,
  requiredAuditEventId,
  requiredDetailHash = null,
}) {
  const rule = {
    deployment_scope: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    accepted_issuers: [
      {
        kid: activeIssuer.kid,
        public_key_pem: activeIssuer.publicPem,
        status: 'active',
      },
    ],
    accepted_policy_versions: ['recognition-policy-v1'],
    accepted_domains: ['records'],
    accepted_tools: ['records.write'],
    accepted_outcomes: ['allow', 'authorized'],
    max_age_seconds: 120,
    required_audit_event_id: requiredAuditEventId,
  };
  if (requiredDetailHash) rule.required_detail_hash = requiredDetailHash;
  return rule;
}

function fixtureAuthorityCrossing({
  activeIssuer,
  nowEpoch,
  recordUpdate,
  targetBinding,
}) {
  const auditEventId = 'protected-records-private-operator-records-terminal-001';
  const launcherRecognitionRule = recognitionRule({
    activeIssuer,
    requiredAuditEventId: auditEventId,
  });
  const scopeEvidence = createProtectedRecordsRuntimeLauncherScopeEvidence({
    actionClass: 'records.write',
    authorizedRecordUpdate: recordUpdate,
    profileId: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    recognitionRuleSnapshot: launcherRecognitionRule,
    targetBinding,
  });
  const contract = createProtectedRecordsRuntimeFixtureAuthorityGrantContract({
    scopeEvidence,
    validFromEpoch: nowEpoch - 30,
    expiresAtEpoch: nowEpoch + 120,
  });
  const appointment = createProtectedRecordsFixtureAuthorityGrantAppointment({
    contract,
    granteeIssuerKid: activeIssuer.kid,
    granteePublicKeySha256: sha256hex(activeIssuer.publicPem),
  });
  const targetEffect = protectedRecordsTargetEffect({
    targetHandle: targetBinding.target_handle,
    recordUpdate,
  });
  const authorizedEffectDetail = protectedRecordsAuthorizedEffectDetail({
    contract,
    targetEffect,
  });
  const unsignedReceipt = createReceiptV1FromEvent(eventFixture({
    nowEpoch,
    detail: authorizedEffectDetail,
    id: auditEventId,
  }));
  const unsignedPayload = decodePayloadV1(unsignedReceipt);
  const issuanceReceiptEvidence = createProtectedRecordsRuntimeAuthorityReceiptEvidence({
    envelope: unsignedReceipt,
    issuerKid: activeIssuer.kid,
    issuerStatus: null,
    payload: unsignedPayload,
    publicKeySha256: sha256hex(activeIssuer.publicPem),
    source: 'unsigned-receipt-payload-before-signing',
    signatureVerified: false,
    downstreamRecognitionAccepted: false,
    verifiedSignedPayloadSha256: null,
  });
  const issuanceDecision = evaluateProtectedRecordsFixtureAuthorityGrantIssuance({
    contract,
    appointment,
    scopeEvidence,
    receiptEvidence: issuanceReceiptEvidence,
    authorizedEffectDetail,
    evaluationEpoch: issuanceReceiptEvidence.issued_at_epoch,
    grantPreviouslyConsumed: false,
  });
  assertProtectedRecordsFixtureAuthorityGrantDecision(
    issuanceDecision,
    contract,
    'issuance',
    { requireAccepted: true }
  );
  const receipt = signReceiptV1(unsignedReceipt, activeIssuer.privatePem, activeIssuer.kid);
  const verified = verifyReceiptV1(receipt, activeIssuer.publicPem);
  if (!verified.valid || !verified.payload || !verified.verified_signed_payload_sha256) {
    throw new Error('Named deployment profile could not verify its just-signed fixture receipt');
  }
  return {
    appointment,
    authorizedEffectDetail,
    contract,
    issuanceDecision,
    receipt,
    recognitionRule: recognitionRule({
      activeIssuer,
      requiredAuditEventId: auditEventId,
      requiredDetailHash: verified.payload.detail_hash,
    }),
  };
}

function runtimeConfig({
  crossing,
  nowEpoch,
  recordUpdate,
  runDir,
  targetBinding,
}) {
  return {
    profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    action_class: 'records.write',
    now_epoch: nowEpoch,
    consumed_grants_path: join(runDir, 'state', 'consumed-grants.json'),
    consumed_grant_store_anchor_path:
      join(runDir, 'state', 'consumed-grants.anchor.json'),
    consumed_grant_store_witness_path:
      join(runDir, 'state', 'consumed-grants.witness.json'),
    authorized_record_update: recordUpdate,
    authority_grant_contract: crossing.contract,
    authority_grant_appointment: crossing.appointment,
    authority_grant_issuance_decision: crossing.issuanceDecision,
    recognition_rule: crossing.recognitionRule,
    target_binding: targetBinding,
  };
}

function serviceRequest({ receipt = null, recordUpdate, requestMode, overrides = {} }) {
  const request = {
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    target_handle: PROTECTED_RECORDS_TARGET_HANDLE,
    record_update: recordUpdate,
    request_mode: requestMode,
    ...overrides,
  };
  if (receipt) {
    request.receipt = receipt;
  }
  return request;
}

function targetEntryCount(targetPath) {
  if (!existsSync(targetPath)) return 0;
  const text = readFileSync(targetPath, 'utf8').trim();
  return text ? text.split(/\n/).length : 0;
}

function appendTargetEntry(targetPath, result, requestMode) {
  const entry = {
    entry_type: 'zlar-proof-owned-records-target-entry-v1',
    deployment_profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
    runtime_profile_id: result.runtime_profile_id,
    action_class: result.action_class,
    request_mode: requestMode,
    record_update_hash: result.record_update_hash,
    decision_reason_code: result.decision.reason_code,
    service_write_accepted: result.service_write_accepted,
  };
  mkdirSync(dirname(targetPath), { recursive: true, mode: 0o700 });
  writeFileSync(targetPath, `${JSON.stringify(entry)}\n`, { flag: 'a', mode: 0o600 });
}

function runRuntimeChild(configPath, requests) {
  const input = `${requests.map((request) => JSON.stringify(request)).join('\n')}\n`;
  const run = spawnSync(ZLAR_BIN, ['protected-records-runtime-service', '--config', configPath], {
    cwd: repoRootFromModule(),
    encoding: 'utf8',
    input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
  if (run.error) {
    throw new Error('Named deployment profile runtime child process failed');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(run.stdout);
  assertNoUnsafeProtectedRecordsRuntimeProfileText(run.stderr);
  if (run.status !== 0 || run.stderr !== '') {
    throw new Error('Named deployment profile runtime child process returned nonzero');
  }
  const results = run.stdout.trim().split(/\n/).filter(Boolean).map((line) => {
    const result = JSON.parse(line);
    assertProtectedRecordsRuntimeServiceResult(result);
    return result;
  });
  if (results.length !== requests.length) {
    throw new Error('Named deployment profile runtime child process result count drifted');
  }
  return {
    child_process_spawned: true,
    stdout_line_count: results.length,
    stderr_empty: run.stderr === '',
    exit_code: run.status,
    results,
  };
}

function writeChildResultEvidence(runDir, label, run) {
  const evidence = {
    evidence_type: 'zlar-named-deployment-profile-runtime-child-result-evidence-v1',
    label,
    child_process_spawned: run.child_process_spawned,
    stdout_line_count: run.stdout_line_count,
    stderr_empty: run.stderr_empty,
    exit_code: run.exit_code,
    results: run.results,
  };
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(evidence));
  writeJson(join(runDir, 'evidence', `${label}.json`), evidence);
  return sha256hex(canonicalize(evidence));
}

function activeManifest({
  runId,
  nowEpoch,
  profileSha256,
  configSha256,
  publicRecognitionSha256,
}) {
  return {
    activation_type: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_ACTIVATION_TYPE,
    schema_version: 1,
    deployment_profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
    activation_status: 'active_for_proof',
    evidence_model: 'bounded-machine-local-named-deployment-profile',
    run_id: runId,
    issued_at: isoFromEpoch(nowEpoch),
    expires_at: isoFromEpoch(nowEpoch + 3600),
    activation_root_label: activationRootLabel(),
    selected_profile: {
      source: 'committed-canonical-installed-runtime-profile-sample',
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      profile_sha256: profileSha256,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
    },
    runtime_service: {
      boundary: 'protected-records-runtime-service:local-jsonl-child-process',
      config_sha256: configSha256,
      public_recognition_material_sha256: publicRecognitionSha256,
      private_key_material_persisted: false,
      private_key_material_emitted: false,
      request_stream_authority_material_accepted: false,
    },
    claim_boundary: {
      named_profile_active_for_proof: true,
      real_personal_files_touched: false,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      public_external_attestation: false,
      all_surface_governance: false,
    },
  };
}

function closedManifest(manifest, nowEpoch) {
  return {
    ...manifest,
    activation_status: 'closed_inert_evidence',
    closed_at: isoFromEpoch(nowEpoch),
    claim_boundary: {
      ...manifest.claim_boundary,
      named_profile_active_for_proof: false,
    },
  };
}

function assertManifestOpen(manifest, nowEpoch) {
  if (
    manifest.activation_type !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_ACTIVATION_TYPE ||
    manifest.deployment_profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    manifest.activation_status !== 'active_for_proof' ||
    Date.parse(manifest.expires_at) <= nowEpoch * 1000 ||
    manifest.selected_profile?.selected_by_explicit_id_and_sha !== true ||
    manifest.selected_profile?.selects_latest_profile !== false
  ) {
    return {
      allowed: false,
      reason_code: 'named_deployment_profile_not_active',
      child_process_spawned: false,
      target_mutated: false,
    };
  }
  return {
    allowed: true,
    reason_code: 'named_deployment_profile_active',
    child_process_spawned: null,
    target_mutated: null,
  };
}

function caseSummary({ caseId, result, before, after, childProcessSpawned }) {
  return {
    case_id: caseId,
    child_process_spawned: childProcessSpawned,
    service_write_accepted: result.service_write_accepted,
    reason_code: result.decision.reason_code,
    target_entry_count_before: before,
    target_entry_count_after: after,
    target_entry_count_delta: after - before,
    refused_before_target_mutation:
      result.service_write_accepted === false && after - before === 0,
  };
}

function closedCaseSummary({ before, after, guard }) {
  return {
    case_id: 'closed_profile_refused_before_target_mutation',
    child_process_spawned: false,
    service_write_accepted: false,
    reason_code: guard.reason_code,
    target_entry_count_before: before,
    target_entry_count_after: after,
    target_entry_count_delta: after - before,
    refused_before_target_mutation: after - before === 0,
  };
}

export function runProtectedRecordsNamedDeploymentProfileRealBoundaryProof({
  activationRoot = defaultNamedDeploymentProfileActivationRoot(),
  proofRoot = defaultNamedDeploymentProfileProofRoot(),
  nowEpoch = PROTECTED_RECORDS_FIXTURE_AUTHORITY_EVALUATION_EPOCH,
  resetActivationRoot = false,
} = {}) {
  const refusal = new Error(
    PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_MESSAGE
  );
  refusal.code = PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REFUSAL_CODE;
  throw refusal;

  ensureActivationRootShape(activationRoot);
  if (resetActivationRoot) {
    rmSync(activationRoot, { recursive: true, force: true });
    mkdirSync(activationRoot, { recursive: true, mode: 0o700 });
  }

  const runId = safeRunId(nowEpoch);
  const runDir = join(activationRoot, 'runs', runId);
  const proofDir = join(proofRoot, `named-deployment-profile-real-boundary-${runId}`);
  const targetPath = join(proofDir, 'records-target.jsonl');
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  mkdirSync(join(runDir, 'state'), { recursive: true, mode: 0o700 });
  mkdirSync(proofDir, { recursive: true, mode: 0o700 });

  const runtimeProfile = readProtectedRecordsInstalledSampleProfile();
  const profileSha256 = runtimeProfileSha256(runtimeProfile);
  const activeIssuer = ephemeralTestIssuer();
  const unknownIssuer = ephemeralTestIssuer();
  const recordUpdate = proofRecordUpdate();
  const targetBinding = createProtectedRecordsRuntimeTargetBinding({
    sourceProfileId: runtimeProfile.profile_id,
    sourceRuntimeProfileId: runtimeProfile.runtime_profile_id,
    sourceProfileSha256: profileSha256,
  });
  const crossing = fixtureAuthorityCrossing({
    activeIssuer,
    nowEpoch,
    recordUpdate,
    targetBinding,
  });
  const recognizedReceipt = crossing.receipt;
  const unrecognizedReceipt = signedReceipt({
    issuer: unknownIssuer,
    nowEpoch,
    detail: crossing.authorizedEffectDetail,
    id: 'protected-records-private-operator-records-terminal-unknown',
  });
  const outOfScopeReceipt = signedReceipt({
    issuer: activeIssuer,
    nowEpoch,
    detail: crossing.authorizedEffectDetail,
    id: 'protected-records-private-operator-records-terminal-out-of-scope',
    overrides: { action: 'records.delete' },
  });

  const publicRecognitionMaterial = {
    material_type: 'zlar-public-recognition-fixture-material-v1',
    deployment_profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
    runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
    issuer_kid: activeIssuer.kid,
    public_key_pem: activeIssuer.publicPem,
    private_key_material_persisted: false,
    production_issuer: false,
  };
  const publicRecognitionPath = join(runDir, 'public-recognition-material.json');
  writeJson(publicRecognitionPath, publicRecognitionMaterial);

  const config = runtimeConfig({
    crossing,
    nowEpoch,
    recordUpdate,
    runDir,
    targetBinding,
  });
  assertProtectedRecordsRuntimeServiceConfig(config);
  const configPath = join(runDir, 'runtime-service-config.json');
  writeJson(configPath, config);

  const configSha256 = sha256hex(canonicalize(config));
  const publicRecognitionSha256 = sha256hex(canonicalize(publicRecognitionMaterial));
  const manifest = activeManifest({
    runId,
    nowEpoch,
    profileSha256,
    configSha256,
    publicRecognitionSha256,
  });
  const manifestPath = join(activationRoot, 'activation-manifest.json');
  const runManifestPath = join(runDir, 'activation-manifest.json');
  writeJson(manifestPath, manifest);
  writeJson(runManifestPath, manifest);

  const openGuard = assertManifestOpen(readJson(manifestPath), nowEpoch);
  if (!openGuard.allowed) {
    throw new Error('Named deployment profile activation guard refused before proof start');
  }

  const acceptedBefore = targetEntryCount(targetPath);
  const acceptedRun = runRuntimeChild(configPath, [
    serviceRequest({
      receipt: recognizedReceipt,
      recordUpdate,
      requestMode: 'recognized_named_deployment_profile_write',
    }),
    serviceRequest({
      receipt: recognizedReceipt,
      recordUpdate,
      requestMode: 'same_process_replay_named_deployment_profile_write',
    }),
  ]);
  const acceptedRunEvidenceSha256 = writeChildResultEvidence(runDir, 'accepted-and-same-process-replay', acceptedRun);
  if (acceptedRun.results[0].service_write_accepted === true) {
    appendTargetEntry(targetPath, acceptedRun.results[0], 'recognized_named_deployment_profile_write');
  }
  if (acceptedRun.results[1].service_write_accepted === true) {
    appendTargetEntry(targetPath, acceptedRun.results[1], 'same_process_replay_named_deployment_profile_write');
  }
  const sameProcessAfter = targetEntryCount(targetPath);

  const cases = [
    caseSummary({
      caseId: 'recognized_receipt_mutates_proof_target_once',
      result: acceptedRun.results[0],
      before: acceptedBefore,
      after: acceptedBefore + (acceptedRun.results[0].service_write_accepted ? 1 : 0),
      childProcessSpawned: acceptedRun.child_process_spawned,
    }),
    caseSummary({
      caseId: 'same_process_replay_refused_before_target_mutation',
      result: acceptedRun.results[1],
      before: acceptedBefore + (acceptedRun.results[0].service_write_accepted ? 1 : 0),
      after: sameProcessAfter,
      childProcessSpawned: acceptedRun.child_process_spawned,
    }),
  ];

  const refusalSpecs = [
    {
      caseId: 'restart_replay_refused_before_target_mutation',
      request: serviceRequest({
        receipt: recognizedReceipt,
        recordUpdate,
        requestMode: 'restart_replay_named_deployment_profile_write',
      }),
    },
    {
      caseId: 'missing_receipt_refused_before_target_mutation',
      request: serviceRequest({
        recordUpdate,
        requestMode: 'missing_receipt_named_deployment_profile_write',
      }),
    },
    {
      caseId: 'unrecognized_receipt_refused_before_target_mutation',
      request: serviceRequest({
        receipt: unrecognizedReceipt,
        recordUpdate,
        requestMode: 'unrecognized_receipt_named_deployment_profile_write',
      }),
    },
    {
      caseId: 'out_of_scope_receipt_refused_before_target_mutation',
      request: serviceRequest({
        receipt: outOfScopeReceipt,
        recordUpdate,
        requestMode: 'out_of_scope_receipt_named_deployment_profile_write',
      }),
    },
    {
      caseId: 'request_authority_material_refused_before_target_mutation',
      request: serviceRequest({
        receipt: recognizedReceipt,
        recordUpdate,
        requestMode: 'request_authority_material_named_deployment_profile_write',
        overrides: {
          authority_grant_contract: crossing.contract,
        },
      }),
    },
  ];

  for (const spec of refusalSpecs) {
    const before = targetEntryCount(targetPath);
    const run = runRuntimeChild(configPath, [spec.request]);
    writeChildResultEvidence(runDir, spec.caseId, run);
    if (run.results[0].service_write_accepted === true) {
      appendTargetEntry(targetPath, run.results[0], spec.request.request_mode);
    }
    const after = targetEntryCount(targetPath);
    cases.push(caseSummary({
      caseId: spec.caseId,
      result: run.results[0],
      before,
      after,
      childProcessSpawned: run.child_process_spawned,
    }));
  }

  const closed = closedManifest(manifest, nowEpoch);
  writeJson(manifestPath, closed);
  writeJson(join(runDir, 'activation-closeout.json'), closed);
  const closedBefore = targetEntryCount(targetPath);
  const closedGuard = assertManifestOpen(readJson(manifestPath), nowEpoch);
  const closedAfter = targetEntryCount(targetPath);
  cases.push(closedCaseSummary({
    before: closedBefore,
    after: closedAfter,
    guard: closedGuard,
  }));

  const targetText = existsSync(targetPath) ? readFileSync(targetPath, 'utf8') : '';
  const report = {
    report_type: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REPORT_TYPE,
    schema_version: 1,
    evidence_model: 'bounded-machine-local-named-deployment-profile-real-boundary',
    live_probing: false,
    safe_claim: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_SAFE_CLAIM,
    activation: {
      activation_type: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_ACTIVATION_TYPE,
      deployment_profile_id: PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID,
      activation_root_label: activationRootLabel(),
      run_id: runId,
      status_before_proof: 'active_for_proof',
      status_after_proof: 'closed_inert_evidence',
      expires_at: manifest.expires_at,
      activation_manifest_sha256_before_close: sha256hex(canonicalize(manifest)),
      activation_manifest_sha256_after_close: sha256hex(canonicalize(closed)),
      activation_root_written: true,
      activation_root_only_machine_local_write_surface: true,
    },
    selected_profile: {
      runtime_profile_id: PROTECTED_RECORDS_RUNTIME_PROFILE_ID,
      runtime_profile_sha256: profileSha256,
      selected_by_explicit_id_and_sha: true,
      selects_latest_profile: false,
    },
    public_recognition_fixture: {
      public_recognition_material_written_inside_activation_root: true,
      public_recognition_material_sha256: publicRecognitionSha256,
      private_key_generated_in_memory_only: true,
      private_key_persisted: false,
      private_key_emitted: false,
      production_issuer: false,
    },
    proof_target: {
      target_label: targetLabel(runId),
      proof_owned_build_target: true,
      final_entry_count: targetEntryCount(targetPath),
      target_sha256: sha256hex(targetText),
      real_personal_files_touched: false,
    },
    service_boundary: {
      downstream_boundary: 'protected-records-runtime-service:local-jsonl-child-process',
      config_sha256: configSha256,
      accepted_run_evidence_sha256: acceptedRunEvidenceSha256,
      config_written_inside_activation_root: true,
      launcher_owned_authority_grant_contract_supplied: true,
      launcher_owned_authority_grant_appointment_supplied: true,
      launcher_owned_authority_grant_issuance_decision_supplied: true,
      launcher_owned_authorized_record_update_supplied: true,
      launcher_owned_consumed_grant_store_paths_supplied: true,
      launcher_owned_target_binding_supplied: true,
      pre_sign_issuance_decision_accepted:
        crossing.issuanceDecision.decision === 'accept',
      authority_grant_contract_sha256:
        protectedRecordsFixtureAuthorityGrantContractSha256(crossing.contract),
      request_stream_authority_material_accepted: false,
      runtime_service_child_process_used: true,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      production_config_written: false,
    },
    cases,
    acceptance_gates: {
      named_profile_selected_by_exact_id_and_sha: true,
      activation_root_is_only_machine_local_config_surface: true,
      proof_target_is_proof_owned_scratch: true,
      no_latest_selection: true,
      missing_receipt_refused_before_target_mutation:
        cases.find((item) => item.case_id === 'missing_receipt_refused_before_target_mutation')?.refused_before_target_mutation === true,
      unrecognized_receipt_refused_before_target_mutation:
        cases.find((item) => item.case_id === 'unrecognized_receipt_refused_before_target_mutation')?.refused_before_target_mutation === true,
      out_of_scope_receipt_refused_before_target_mutation:
        cases.find((item) => item.case_id === 'out_of_scope_receipt_refused_before_target_mutation')?.refused_before_target_mutation === true,
      request_authority_material_refused_before_target_mutation:
        cases.find((item) => item.case_id === 'request_authority_material_refused_before_target_mutation')?.refused_before_target_mutation === true,
      recognized_receipt_mutated_once:
        cases.find((item) => item.case_id === 'recognized_receipt_mutates_proof_target_once')?.target_entry_count_delta === 1,
      same_process_replay_refused_before_target_mutation:
        cases.find((item) => item.case_id === 'same_process_replay_refused_before_target_mutation')?.refused_before_target_mutation === true,
      restart_replay_refused_before_target_mutation:
        cases.find((item) => item.case_id === 'restart_replay_refused_before_target_mutation')?.refused_before_target_mutation === true,
      closure_refused_before_target_mutation:
        cases.find((item) => item.case_id === 'closed_profile_refused_before_target_mutation')?.refused_before_target_mutation === true,
      no_private_key_persistence: true,
      no_real_personal_files_touched: true,
      no_public_or_external_claim: true,
    },
    claim_boundary: {
      bounded_named_machine_local_profile_proven: true,
      active_after_proof: false,
      proof_owned_records_target_only: true,
      real_personal_files_touched: false,
      hook_configuration_written: false,
      user_config_written: false,
      machine_config_written: false,
      production_downstream_recognition: false,
      production_authority: false,
      enterprise_readiness: false,
      current_machine_governance_general: false,
      public_external_attestation: false,
      sovereign_recognition: false,
      all_surface_governance: false,
      side_door_closure: false,
      absolute_human_intention: false,
    },
    non_claims: [...PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_NON_CLAIMS],
  };
  assertProtectedRecordsNamedDeploymentProfileRealBoundaryProof(report);
  return report;
}

export function assertProtectedRecordsNamedDeploymentProfileRealBoundaryProof(report) {
  exactKeys('named deployment profile real-boundary report', report, [
    'acceptance_gates',
    'activation',
    'cases',
    'claim_boundary',
    'evidence_model',
    'live_probing',
    'non_claims',
    'proof_target',
    'public_recognition_fixture',
    'report_type',
    'safe_claim',
    'schema_version',
    'selected_profile',
    'service_boundary',
  ]);
  if (
    report.report_type !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_REPORT_TYPE ||
    report.schema_version !== 1 ||
    report.evidence_model !== 'bounded-machine-local-named-deployment-profile-real-boundary' ||
    report.live_probing !== false ||
    report.safe_claim !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_SAFE_CLAIM
  ) {
    throw new Error('named deployment profile real-boundary top-level contract drifted');
  }

  exactKeys('named deployment profile real-boundary activation', report.activation, [
    'activation_manifest_sha256_after_close',
    'activation_manifest_sha256_before_close',
    'activation_root_label',
    'activation_root_only_machine_local_write_surface',
    'activation_root_written',
    'activation_type',
    'deployment_profile_id',
    'expires_at',
    'run_id',
    'status_after_proof',
    'status_before_proof',
  ]);
  if (
    report.activation.activation_type !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_ACTIVATION_TYPE ||
    report.activation.deployment_profile_id !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_ID ||
    report.activation.activation_root_label !== activationRootLabel() ||
    report.activation.status_before_proof !== 'active_for_proof' ||
    report.activation.status_after_proof !== 'closed_inert_evidence' ||
    report.activation.activation_root_written !== true ||
    report.activation.activation_root_only_machine_local_write_surface !== true
  ) {
    throw new Error('named deployment profile real-boundary activation drifted');
  }
  expectSha('activation manifest before close hash', report.activation.activation_manifest_sha256_before_close);
  expectSha('activation manifest after close hash', report.activation.activation_manifest_sha256_after_close);
  expectString('activation expiry', report.activation.expires_at);
  expectString('activation run id', report.activation.run_id);

  exactKeys('named deployment profile real-boundary selected profile', report.selected_profile, [
    'runtime_profile_id',
    'runtime_profile_sha256',
    'selected_by_explicit_id_and_sha',
    'selects_latest_profile',
  ]);
  if (report.selected_profile.runtime_profile_id !== PROTECTED_RECORDS_RUNTIME_PROFILE_ID) {
    throw new Error('named deployment profile real-boundary runtime profile id drifted');
  }
  expectSha('runtime profile SHA-256', report.selected_profile.runtime_profile_sha256);
  expectBool('selected by explicit id and SHA', report.selected_profile.selected_by_explicit_id_and_sha, true);
  expectBool('selects latest profile', report.selected_profile.selects_latest_profile, false);

  exactKeys('named deployment profile real-boundary public recognition fixture', report.public_recognition_fixture, [
    'private_key_emitted',
    'private_key_generated_in_memory_only',
    'private_key_persisted',
    'production_issuer',
    'public_recognition_material_sha256',
    'public_recognition_material_written_inside_activation_root',
  ]);
  expectSha('public recognition material hash', report.public_recognition_fixture.public_recognition_material_sha256);
  for (const key of [
    'public_recognition_material_written_inside_activation_root',
    'private_key_generated_in_memory_only',
  ]) {
    expectBool(`public recognition fixture ${key}`, report.public_recognition_fixture[key], true);
  }
  for (const key of ['private_key_persisted', 'private_key_emitted', 'production_issuer']) {
    expectBool(`public recognition fixture ${key}`, report.public_recognition_fixture[key], false);
  }

  exactKeys('named deployment profile real-boundary proof target', report.proof_target, [
    'final_entry_count',
    'proof_owned_build_target',
    'real_personal_files_touched',
    'target_label',
    'target_sha256',
  ]);
  expectString('proof target label', report.proof_target.target_label);
  expectSha('proof target hash', report.proof_target.target_sha256);
  expectBool('proof target proof owned', report.proof_target.proof_owned_build_target, true);
  expectBool('proof target real personal files touched', report.proof_target.real_personal_files_touched, false);
  if (report.proof_target.final_entry_count !== 1) {
    throw new Error('named deployment profile real-boundary target did not mutate exactly once');
  }

  exactKeys('named deployment profile real-boundary service boundary', report.service_boundary, [
    'accepted_run_evidence_sha256',
    'authority_grant_contract_sha256',
    'config_sha256',
    'config_written_inside_activation_root',
    'downstream_boundary',
    'hook_configuration_written',
    'launcher_owned_authority_grant_appointment_supplied',
    'launcher_owned_authority_grant_contract_supplied',
    'launcher_owned_authority_grant_issuance_decision_supplied',
    'launcher_owned_authorized_record_update_supplied',
    'launcher_owned_consumed_grant_store_paths_supplied',
    'launcher_owned_target_binding_supplied',
    'machine_config_written',
    'pre_sign_issuance_decision_accepted',
    'production_config_written',
    'request_stream_authority_material_accepted',
    'runtime_service_child_process_used',
    'user_config_written',
  ]);
  expectSha('accepted run evidence hash', report.service_boundary.accepted_run_evidence_sha256);
  expectSha('authority grant contract hash', report.service_boundary.authority_grant_contract_sha256);
  expectSha('service config hash', report.service_boundary.config_sha256);
  if (report.service_boundary.downstream_boundary !== 'protected-records-runtime-service:local-jsonl-child-process') {
    throw new Error('named deployment profile real-boundary downstream boundary drifted');
  }
  for (const key of [
    'config_written_inside_activation_root',
    'launcher_owned_authority_grant_contract_supplied',
    'launcher_owned_authority_grant_appointment_supplied',
    'launcher_owned_authority_grant_issuance_decision_supplied',
    'launcher_owned_authorized_record_update_supplied',
    'launcher_owned_consumed_grant_store_paths_supplied',
    'launcher_owned_target_binding_supplied',
    'pre_sign_issuance_decision_accepted',
    'runtime_service_child_process_used',
  ]) {
    expectBool(`service boundary ${key}`, report.service_boundary[key], true);
  }
  for (const key of [
    'request_stream_authority_material_accepted',
    'hook_configuration_written',
    'user_config_written',
    'machine_config_written',
    'production_config_written',
  ]) {
    expectBool(`service boundary ${key}`, report.service_boundary[key], false);
  }

  if (!Array.isArray(report.cases) || report.cases.length !== 8) {
    throw new Error('named deployment profile real-boundary cases drifted');
  }
  const expectedCases = [
    'recognized_receipt_mutates_proof_target_once',
    'same_process_replay_refused_before_target_mutation',
    'restart_replay_refused_before_target_mutation',
    'missing_receipt_refused_before_target_mutation',
    'unrecognized_receipt_refused_before_target_mutation',
    'out_of_scope_receipt_refused_before_target_mutation',
    'request_authority_material_refused_before_target_mutation',
    'closed_profile_refused_before_target_mutation',
  ];
  for (const caseId of expectedCases) {
    const proofCase = report.cases.find((item) => item.case_id === caseId);
    if (!proofCase) {
      throw new Error(`named deployment profile real-boundary case missing: ${caseId}`);
    }
    exactKeys(`named deployment profile real-boundary case ${caseId}`, proofCase, [
      'case_id',
      'child_process_spawned',
      'reason_code',
      'refused_before_target_mutation',
      'service_write_accepted',
      'target_entry_count_after',
      'target_entry_count_before',
      'target_entry_count_delta',
    ]);
    if (caseId === 'recognized_receipt_mutates_proof_target_once') {
      if (
        proofCase.service_write_accepted !== true ||
        proofCase.target_entry_count_delta !== 1 ||
        proofCase.reason_code !== 'fixture_authority_grant_effect_satisfied'
      ) {
        throw new Error('named deployment profile real-boundary recognized case failed');
      }
    } else if (
      proofCase.service_write_accepted !== false ||
      proofCase.target_entry_count_delta !== 0 ||
      proofCase.refused_before_target_mutation !== true
    ) {
      throw new Error(`named deployment profile real-boundary refusal failed: ${caseId}`);
    }
  }

  exactKeys('named deployment profile real-boundary acceptance gates', report.acceptance_gates, [
    'activation_root_is_only_machine_local_config_surface',
    'closure_refused_before_target_mutation',
    'missing_receipt_refused_before_target_mutation',
    'named_profile_selected_by_exact_id_and_sha',
    'no_latest_selection',
    'no_private_key_persistence',
    'no_public_or_external_claim',
    'no_real_personal_files_touched',
    'out_of_scope_receipt_refused_before_target_mutation',
    'proof_target_is_proof_owned_scratch',
    'recognized_receipt_mutated_once',
    'request_authority_material_refused_before_target_mutation',
    'restart_replay_refused_before_target_mutation',
    'same_process_replay_refused_before_target_mutation',
    'unrecognized_receipt_refused_before_target_mutation',
  ]);
  for (const [key, value] of Object.entries(report.acceptance_gates)) {
    expectBool(`acceptance gate ${key}`, value, true);
  }

  exactKeys('named deployment profile real-boundary claim boundary', report.claim_boundary, [
    'absolute_human_intention',
    'active_after_proof',
    'all_surface_governance',
    'bounded_named_machine_local_profile_proven',
    'current_machine_governance_general',
    'enterprise_readiness',
    'hook_configuration_written',
    'machine_config_written',
    'production_authority',
    'production_downstream_recognition',
    'proof_owned_records_target_only',
    'public_external_attestation',
    'real_personal_files_touched',
    'side_door_closure',
    'sovereign_recognition',
    'user_config_written',
  ]);
  expectBool('bounded named machine local profile proven', report.claim_boundary.bounded_named_machine_local_profile_proven, true);
  expectBool('proof owned records target only', report.claim_boundary.proof_owned_records_target_only, true);
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    if (!['bounded_named_machine_local_profile_proven', 'proof_owned_records_target_only'].includes(key)) {
      expectBool(`claim boundary ${key}`, value, false);
    }
  }

  if (
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_NON_CLAIMS.length ||
    report.non_claims.some((claim, index) => claim !== PROTECTED_RECORDS_NAMED_DEPLOYMENT_PROFILE_REAL_BOUNDARY_NON_CLAIMS[index])
  ) {
    throw new Error('named deployment profile real-boundary non-claims drifted');
  }
  assertNoUnsafeProtectedRecordsRuntimeProfileText(JSON.stringify(report));
  return true;
}

export function formatProtectedRecordsNamedDeploymentProfileRealBoundaryProof(report) {
  assertProtectedRecordsNamedDeploymentProfileRealBoundaryProof(report);
  return [
    'ZLAR Protected Records Named Deployment Profile Real Boundary Proof v1',
    `report_type=${report.report_type}`,
    `evidence_model=${report.evidence_model}`,
    `deployment_profile_id=${report.activation.deployment_profile_id}`,
    `activation_root=${report.activation.activation_root_label}`,
    `status_after_proof=${report.activation.status_after_proof}`,
    `runtime_profile_id=${report.selected_profile.runtime_profile_id}`,
    `selected_by_explicit_id_and_sha=${report.selected_profile.selected_by_explicit_id_and_sha}`,
    `selects_latest_profile=${report.selected_profile.selects_latest_profile}`,
    `proof_target=${report.proof_target.target_label}`,
    `final_target_entries=${report.proof_target.final_entry_count}`,
    `recognized_receipt_mutated_once=${report.acceptance_gates.recognized_receipt_mutated_once}`,
    `missing_receipt_refused=${report.acceptance_gates.missing_receipt_refused_before_target_mutation}`,
    `unrecognized_receipt_refused=${report.acceptance_gates.unrecognized_receipt_refused_before_target_mutation}`,
    `out_of_scope_receipt_refused=${report.acceptance_gates.out_of_scope_receipt_refused_before_target_mutation}`,
    `request_authority_material_refused=${report.acceptance_gates.request_authority_material_refused_before_target_mutation}`,
    `launcher_owned_fixture_authority_supplied=${report.service_boundary.launcher_owned_authority_grant_contract_supplied}`,
    `pre_sign_issuance_decision_accepted=${report.service_boundary.pre_sign_issuance_decision_accepted}`,
    `request_stream_authority_material_accepted=${report.service_boundary.request_stream_authority_material_accepted}`,
    `same_process_replay_refused=${report.acceptance_gates.same_process_replay_refused_before_target_mutation}`,
    `restart_replay_refused=${report.acceptance_gates.restart_replay_refused_before_target_mutation}`,
    `closure_refused=${report.acceptance_gates.closure_refused_before_target_mutation}`,
    `private_key_persisted=${report.public_recognition_fixture.private_key_persisted}`,
    `current_machine_governance_general=${report.claim_boundary.current_machine_governance_general}`,
    `production_downstream_recognition=${report.claim_boundary.production_downstream_recognition}`,
    `enterprise_readiness=${report.claim_boundary.enterprise_readiness}`,
  ].join('\n') + '\n';
}
