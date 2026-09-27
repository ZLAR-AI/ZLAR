import { spawnSync } from 'node:child_process';
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  PROTECTED_RECORDS_POST_EFFECT_ROUTE_EVIDENCE_INDEX_TYPE_V0,
  assertProtectedRecordsPostEffectRouteEvidenceIndexV0,
  buildProtectedRecordsPostEffectRouteEvidenceIndexV0,
  canonicalProtectedRecordsPostEffectRouteEvidenceIndexBytesV0,
  formatProtectedRecordsPostEffectRouteEvidenceIndexSummaryV0,
} from '../lib/protected-records-post-effect-route-evidence-index-v0.mjs';
import {
  buildProtectedRecordsReplacementCrossingEvidenceV2,
  buildProtectedRecordsReplacementServiceArtifactV2,
  buildProtectedRecordsReplacementTerminalArtifactV2,
  canonicalProtectedRecordsReplacementArtifactBytesV2,
  protectedRecordsReplacementServiceArtifactSchemaContractSha256V2,
  protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2,
} from '../lib/protected-records-replacement-artifacts-v2.mjs';
import {
  buildProtectedRecordsReplacementArtifactSetManifestV2,
  canonicalProtectedRecordsReplacementArtifactSetManifestBytesV2,
  protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2,
  protectedRecordsReplacementNoReexecutionCallGraphSha256V2,
  verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes,
} from '../lib/protected-records-replacement-artifact-set-v2.mjs';
import { sha256hex } from '../lib/sha256.mjs';

let assertions = 0;

function equal(label, expected, actual) {
  assertions += 1;
  if (actual !== expected) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}

function ok(label, value) {
  assertions += 1;
  if (!value) throw new Error(`${label}: expected truthy value`);
}

function throws(label, fn, expectedText) {
  assertions += 1;
  try {
    fn();
  } catch (error) {
    if (!String(error.message).includes(expectedText)) {
      throw new Error(
        `${label}: expected ${JSON.stringify(expectedText)}, got ${JSON.stringify(error.message)}`,
      );
    }
    return;
  }
  throw new Error(`${label}: expected refusal`);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function digest(label) {
  return sha256hex(`synthetic-route-index:${label}`);
}

function canonicalBytes(value) {
  return Buffer.from(canonicalize(value), 'utf8');
}

function expectedCrossingOptions(inputs) {
  return Object.fromEntries(
    Object.entries(inputs).map(([key, value]) => [
      `expected${key[0].toUpperCase()}${key.slice(1)}`,
      value,
    ]),
  );
}

const callGraph = JSON.parse(
  readFileSync('spec/protected-records-no-reexecution-call-graph-v2.json', 'utf8'),
);
const serviceSchemaSha256 =
  protectedRecordsReplacementServiceArtifactSchemaContractSha256V2();
const terminalSchemaSha256 =
  protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2();
const manifestSchemaSha256 =
  protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2();
const historicalSourceCommitOid = 'a'.repeat(40);
const sourceBinding = {
  git_object_format: 'sha1',
  installed_profile_preflight_artifact_body_sha256:
    digest('installed-profile-preflight'),
  no_reexecution_call_graph_sha256:
    protectedRecordsReplacementNoReexecutionCallGraphSha256V2(callGraph),
  repository_id: 'ZLAR_Repo',
  service_artifact_schema_contract_sha256: serviceSchemaSha256,
  source_commit_oid: historicalSourceCommitOid,
  source_precondition_artifact_body_sha256: digest('source-precondition'),
  terminal_artifact_schema_contract_sha256: terminalSchemaSha256,
};

const effectEpoch = 2_000_000_100;
const effectDecisionSha256 = digest('effect-decision');
const issuanceDecisionSha256 = digest('issuance-decision');
const grantSha256 = digest('grant');
const appointmentSha256 = digest('appointment');
const confirmationSha256 = digest('confirmation');
const statusAtEffectSha256 = digest('status-at-effect');
const authorizedEffectDetailSha256 = digest('authorized-effect');
const receiptSha256 = digest('receipt-envelope');
const targetBindingSha256 = digest('target-binding');
const targetEffectSha256 = digest('target-effect');

const effectGateBinding = {
  appointment_sha256: appointmentSha256,
  authority_effect_evaluation_epoch: effectEpoch,
  authority_grant_contract_sha256: grantSha256,
  authority_status_at_effect_sha256: statusAtEffectSha256,
  caller_supplied_consequence_time_accepted: false,
  confirmation_sha256: confirmationSha256,
  consequence_clock_source: 'runtime-process-wall-clock-at-effect',
  effect_decision_sha256: effectDecisionSha256,
  target_effect_sha256: targetEffectSha256,
};
const effectGateBindingSha256 = sha256hex(canonicalize(effectGateBinding));
const executionTrace = {
  trace_type: 'synthetic-source-recorded-runtime-trace',
  transition_count: 1,
};
const executionTraceSha256 = sha256hex(canonicalize(executionTrace));
const runtimeTransitionBinding = {
  authority_effect_gate_binding_sha256: effectGateBindingSha256,
  authority_grant_consumption_count_after: 1,
  authority_grant_consumption_count_before: 0,
  authority_grant_contract_sha256: grantSha256,
  authority_grant_effect_decision_sha256: effectDecisionSha256,
  authority_grant_issuance_decision_sha256: issuanceDecisionSha256,
  execution_trace_sha256: executionTraceSha256,
  signed_receipt_sha256: receiptSha256,
  state_entry_count_after: 1,
  state_entry_count_before: 0,
  target_effect_sha256: targetEffectSha256,
};
const runtimeTransitionSha256 = sha256hex(
  canonicalize(runtimeTransitionBinding),
);

const crossingInputs = {
  activationConfirmationArtifactBodySha256: confirmationSha256,
  authorityGrantContractSha256: grantSha256,
  authorityStatusAtEffectArtifactBodySha256: statusAtEffectSha256,
  authorizedEffectDetailSha256,
  confirmationConfirmedAtEpoch: 2_000_000_000,
  controlTowerConfirmationRelayDelaySeconds: 30,
  controlTowerConfirmationRelayMaxSeconds: 300,
  effectDecisionSha256,
  executionTraceSha256,
  installedProfilePreflightArtifactBodySha256:
    sourceBinding.installed_profile_preflight_artifact_body_sha256,
  holderObservedConfirmationEpoch: 2_000_000_030,
  issuerAppointmentArtifactBodySha256: appointmentSha256,
  issuanceDecisionSha256,
  receiptEnvelopeBodySha256: receiptSha256,
  recognitionContractSha256: digest('recognition-contract'),
  recordUpdateSha256: digest('record-update'),
  runtimeProfileSha256: digest('runtime-profile'),
  runtimeTransitionSha256,
  sourcePreconditionArtifactBodySha256:
    sourceBinding.source_precondition_artifact_body_sha256,
  targetBindingSha256,
  targetContractSha256: digest('target-contract'),
  targetEffectSha256,
};
const expectedCrossing = expectedCrossingOptions(crossingInputs);
const crossingEvidence =
  buildProtectedRecordsReplacementCrossingEvidenceV2(crossingInputs);
const serviceArtifact = buildProtectedRecordsReplacementServiceArtifactV2({
  crossingEvidence,
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  sourceBinding,
  ...expectedCrossing,
});
const serviceRawBytes =
  canonicalProtectedRecordsReplacementArtifactBytesV2(serviceArtifact);
const terminalArtifact = buildProtectedRecordsReplacementTerminalArtifactV2({
  expectedServiceArtifactBodySha256: serviceArtifact.integrity.body_sha256,
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  expectedSourceBinding: sourceBinding,
  expectedTerminalArtifactSchemaContractSha256: terminalSchemaSha256,
  serviceArtifactRawBytes: serviceRawBytes,
  ...expectedCrossing,
});
const terminalRawBytes =
  canonicalProtectedRecordsReplacementArtifactBytesV2(terminalArtifact);
const manifest = buildProtectedRecordsReplacementArtifactSetManifestV2({
  expectedServiceArtifactBodySha256: serviceArtifact.integrity.body_sha256,
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  expectedSourceBinding: sourceBinding,
  expectedTerminalArtifactBodySha256: terminalArtifact.integrity.body_sha256,
  expectedTerminalArtifactSchemaContractSha256: terminalSchemaSha256,
  serviceArtifactRawBytes: serviceRawBytes,
  terminalArtifactRawBytes: terminalRawBytes,
  ...expectedCrossing,
});
const manifestRawBytes =
  canonicalProtectedRecordsReplacementArtifactSetManifestBytesV2(manifest);
const verification = verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes({
  expectedManifestArtifactBodySha256: manifest.integrity.body_sha256,
  manifestRawBytes,
  serviceArtifactRawBytes: serviceRawBytes,
  terminalArtifactRawBytes: terminalRawBytes,
});
const verificationRawBytes = canonicalBytes(verification);

const runtimeResult = {
  action_class: 'records.write',
  authority_effect_gate_binding: effectGateBinding,
  authority_effect_gate_binding_sha256: effectGateBindingSha256,
  authority_grant_appointment_sha256: appointmentSha256,
  authority_grant_confirmation_sha256: confirmationSha256,
  authority_grant_contract_sha256: grantSha256,
  authority_grant_effect_decision_sha256: effectDecisionSha256,
  authority_grant_issuance_decision_sha256: issuanceDecisionSha256,
  authority_grant_satisfied: true,
  authority_grant_status_at_effect_sha256: statusAtEffectSha256,
  authority_source_precondition: {
    git_object_format: sourceBinding.git_object_format,
    no_reexecution_call_graph_sha256:
      sourceBinding.no_reexecution_call_graph_sha256,
    repository_id: sourceBinding.repository_id,
    service_artifact_schema_contract_sha256:
      sourceBinding.service_artifact_schema_contract_sha256,
    source_commit_oid: sourceBinding.source_commit_oid,
    terminal_artifact_schema_contract_sha256:
      sourceBinding.terminal_artifact_schema_contract_sha256,
  },
  authorized_effect_detail_sha256: authorizedEffectDetailSha256,
  consequence_path:
    'protected-records.installed-runtime-profile.terminal-chain.records.write',
  consumed_authority_grant_count: 1,
  decision: { decision: 'accept', phase: 'effect' },
  execution_trace: executionTrace,
  execution_trace_sha256: executionTraceSha256,
  installed_profile_preflight_artifact_body_sha256:
    sourceBinding.installed_profile_preflight_artifact_body_sha256,
  live_probing: false,
  profile_sha256: crossingInputs.runtimeProfileSha256,
  recognition_contract_sha256: crossingInputs.recognitionContractSha256,
  record_update_sha256: crossingInputs.recordUpdateSha256,
  request_mode: 'recognized_runtime_write',
  result_type: 'protected-records-runtime-service-result-v2',
  runtime_profile_active: true,
  runtime_transition_binding: runtimeTransitionBinding,
  runtime_transition_binding_sha256: runtimeTransitionSha256,
  service_state_changed: true,
  service_write_accepted: true,
  signed_receipt_sha256: receiptSha256,
  source_precondition_artifact_body_sha256:
    sourceBinding.source_precondition_artifact_body_sha256,
  state_entry_count_after: 1,
  state_entry_count_before: 0,
  state_entry_count_delta: 1,
  state_entry_written: true,
  state_storage: 'process-private-memory',
  target_binding_sha256: targetBindingSha256,
  target_contract_sha256: crossingInputs.targetContractSha256,
  target_effect_sha256: targetEffectSha256,
};
const runtimeResultRawBytes = canonicalBytes(runtimeResult);

const exhaustedStatus = {
  appointment_sha256: appointmentSha256,
  authority_grant_contract_sha256: grantSha256,
  confirmation_sha256: confirmationSha256,
  consumed_crossing_binding_sha256: crossingEvidence.crossing_binding_sha256,
  fresh_effect_allowed: false,
  historical_fixture_authority_at_effect_projection_allowed: true,
  maximum_effect_uses: 1,
  recorded_effect_uses: 1,
  repeated_use_provenance_valid: false,
  revocation_reason_code: null,
  revoked_at_epoch: null,
  status: 'exhausted',
  status_source: 'source-recorded-single-use-consumption',
  status_type: 'zlar-protected-records-fixture-authority-status-v2',
  status_updated_at_epoch: effectEpoch,
  status_version: 2,
};
const exhaustedStatusBodySha256 = sha256hex(canonicalize(exhaustedStatus));
const exhaustedStatusWrapper = {
  authority_status: exhaustedStatus,
  authority_status_sha256: exhaustedStatusBodySha256,
};
const exhaustedStatusRawBytes = canonicalBytes(exhaustedStatusWrapper);

const closeout = {
  accepted_result_persisted: true,
  artifact_manifest_pinned: true,
  authority_status_exhausted: true,
  automatic_retry_allowed: false,
  consequence_executed: true,
  crash_atomic_effect_plus_pin_proven: false,
  downstream_verification_without_reexecution: true,
  exactly_once_effect_proven: false,
  grant_consumed: true,
  lifecycle_closed: false,
  route_type: 'zlar.protected-records.replacement-crossing-closeout.v2',
  runtime_invocations_completed: 1,
  runtime_result_persisted: true,
};
const closeoutRawBytes = canonicalBytes(closeout);

const params = {
  closeoutRawBytes,
  exhaustedStatusRawBytes,
  expectedCloseoutFileSha256: sha256hex(closeoutRawBytes),
  expectedCrossingBindingSha256: crossingEvidence.crossing_binding_sha256,
  expectedCrossingSourceCommitOid: historicalSourceCommitOid,
  expectedExhaustedStatusBodySha256: exhaustedStatusBodySha256,
  expectedExhaustedStatusFileSha256: sha256hex(exhaustedStatusRawBytes),
  expectedGrantContractSha256: grantSha256,
  expectedManifestArtifactBodySha256: manifest.integrity.body_sha256,
  expectedManifestFileSha256: sha256hex(manifestRawBytes),
  expectedManifestSchemaContractSha256: manifestSchemaSha256,
  expectedRuntimeResultFileSha256: sha256hex(runtimeResultRawBytes),
  expectedServiceArtifactBodySha256: serviceArtifact.integrity.body_sha256,
  expectedServiceFileSha256: sha256hex(serviceRawBytes),
  expectedTerminalArtifactBodySha256: terminalArtifact.integrity.body_sha256,
  expectedTerminalFileSha256: sha256hex(terminalRawBytes),
  expectedVerificationFileSha256: sha256hex(verificationRawBytes),
  manifestRawBytes,
  runtimeResultRawBytes,
  serviceArtifactRawBytes: serviceRawBytes,
  terminalArtifactRawBytes: terminalRawBytes,
  verificationRawBytes,
};

const report = buildProtectedRecordsPostEffectRouteEvidenceIndexV0(params);
equal(
  'index type is exact',
  PROTECTED_RECORDS_POST_EFFECT_ROUTE_EVIDENCE_INDEX_TYPE_V0,
  report.artifact_type,
);
equal('index has seven roles', 7, report.membership_policy.indexed_roles.length);
equal(
  'artifact-set verification is source-recomputed',
  true,
  report.artifact_set_verification.recomputed_from_raw_artifacts,
);
equal(
  'persisted verification exactly matches',
  true,
  report.artifact_set_verification.persisted_exact_canonical_match,
);
equal(
  'runtime full schema remains false',
  false,
  report.runtime_result_selected_projection.runtime_result_schema_fully_validated,
);
equal(
  'runtime selected fields are validated',
  true,
  report.runtime_result_selected_projection.runtime_result_selected_fields_validated,
);
equal(
  'closeout crossing identity remains absent',
  false,
  report.closeout_projection.closeout_crossing_identity_embedded,
);
equal(
  'closeout same-route provenance remains false',
  false,
  report.closeout_projection.closeout_same_route_proven,
);
equal(
  'effect state is not reobserved',
  false,
  report.boundaries.surviving_effect_state_reobserved,
);
equal(
  'consequence is not reexecuted',
  false,
  report.boundaries.consequence_reexecution_performed,
);
equal('lifecycle remains open', false, report.boundaries.lifecycle_closed);
ok(
  'index assertion accepts exact report',
  assertProtectedRecordsPostEffectRouteEvidenceIndexV0(report, params),
);
equal(
  'canonical bytes are exact',
  canonicalize(report),
  canonicalProtectedRecordsPostEffectRouteEvidenceIndexBytesV0(
    report,
    params,
  ).toString('utf8'),
);
ok(
  'summary names closeout provenance refusal',
  formatProtectedRecordsPostEffectRouteEvidenceIndexSummaryV0(report, params)
    .includes('Closeout same route proven: false'),
);

const tamperedReport = clone(report);
tamperedReport.boundaries.rightful_issuance_projected = true;
throws(
  'report mutation refuses',
  () => assertProtectedRecordsPostEffectRouteEvidenceIndexV0(
    tamperedReport,
    params,
  ),
  'exact verified projection',
);
throws(
  'formatter mutation refuses',
  () => formatProtectedRecordsPostEffectRouteEvidenceIndexSummaryV0(
    tamperedReport,
    params,
  ),
  'exact verified projection',
);

const maliciousClaim = 'Production and enterprise governance are proven.';
const runtimeWithMaliciousClaim = {
  ...runtimeResult,
  non_claims: [maliciousClaim],
  safe_claim_ceiling: maliciousClaim,
};
const runtimeWithMaliciousClaimBytes = canonicalBytes(runtimeWithMaliciousClaim);
const opaqueReport = buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
  ...params,
  expectedRuntimeResultFileSha256: sha256hex(runtimeWithMaliciousClaimBytes),
  runtimeResultRawBytes: runtimeWithMaliciousClaimBytes,
});
equal(
  'runtime claim strings remain opaque',
  false,
  JSON.stringify(opaqueReport).includes(maliciousClaim),
);

for (const [rawKey, expectedShaKey, parsed] of [
  ['runtimeResultRawBytes', 'expectedRuntimeResultFileSha256', runtimeResult],
  ['serviceArtifactRawBytes', 'expectedServiceFileSha256', serviceArtifact],
  ['terminalArtifactRawBytes', 'expectedTerminalFileSha256', terminalArtifact],
  ['manifestRawBytes', 'expectedManifestFileSha256', manifest],
  ['verificationRawBytes', 'expectedVerificationFileSha256', verification],
  ['exhaustedStatusRawBytes', 'expectedExhaustedStatusFileSha256', exhaustedStatusWrapper],
  ['closeoutRawBytes', 'expectedCloseoutFileSha256', closeout],
]) {
  throws(
    `wrong caller file identity refuses ${rawKey}`,
    () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
      ...params,
      [expectedShaKey]: 'f'.repeat(64),
    }),
    'file identity mismatch',
  );
  const pretty = Buffer.from(JSON.stringify(parsed, null, 2), 'utf8');
  throws(
    `noncanonical bytes refuse ${rawKey}`,
    () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
      ...params,
      [rawKey]: pretty,
      [expectedShaKey]: sha256hex(pretty),
    }),
    'must be exact canonical JSON',
  );
}

const refusedRuntime = { ...runtimeResult, service_write_accepted: false };
const refusedRuntimeBytes = canonicalBytes(refusedRuntime);
throws(
  'runtime selected posture drift refuses',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    expectedRuntimeResultFileSha256: sha256hex(refusedRuntimeBytes),
    runtimeResultRawBytes: refusedRuntimeBytes,
  }),
  'selected posture mismatch',
);
const detachedRuntime = {
  ...runtimeResult,
  target_effect_sha256: digest('detached-target-effect'),
};
const detachedRuntimeBytes = canonicalBytes(detachedRuntime);
throws(
  'runtime artifact-set detachment refuses',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    expectedRuntimeResultFileSha256: sha256hex(detachedRuntimeBytes),
    runtimeResultRawBytes: detachedRuntimeBytes,
  }),
  'selected artifact-set cross-binding mismatch',
);
const internallyDriftedRuntime = clone(runtimeResult);
internallyDriftedRuntime.runtime_transition_binding.state_entry_count_after = 2;
const internallyDriftedRuntimeBytes = canonicalBytes(internallyDriftedRuntime);
throws(
  'runtime internal transition hash drift refuses',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    expectedRuntimeResultFileSha256: sha256hex(internallyDriftedRuntimeBytes),
    runtimeResultRawBytes: internallyDriftedRuntimeBytes,
  }),
  'internal identity mismatch',
);
const detachedGateRuntime = clone(runtimeResult);
detachedGateRuntime.authority_effect_gate_binding
  .authority_effect_evaluation_epoch += 1;
detachedGateRuntime.authority_effect_gate_binding_sha256 = sha256hex(
  canonicalize(detachedGateRuntime.authority_effect_gate_binding),
);
const detachedGateRuntimeBytes = canonicalBytes(detachedGateRuntime);
const detachedGateStatus = {
  ...exhaustedStatus,
  status_updated_at_epoch: effectEpoch + 1,
};
const detachedGateStatusBodySha256 = sha256hex(
  canonicalize(detachedGateStatus),
);
const detachedGateStatusWrapper = {
  authority_status: detachedGateStatus,
  authority_status_sha256: detachedGateStatusBodySha256,
};
const detachedGateStatusRawBytes = canonicalBytes(
  detachedGateStatusWrapper,
);
throws(
  'detached effect gate refuses despite matched status chronology',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    exhaustedStatusRawBytes: detachedGateStatusRawBytes,
    expectedExhaustedStatusBodySha256: detachedGateStatusBodySha256,
    expectedExhaustedStatusFileSha256:
      sha256hex(detachedGateStatusRawBytes),
    expectedRuntimeResultFileSha256: sha256hex(detachedGateRuntimeBytes),
    runtimeResultRawBytes: detachedGateRuntimeBytes,
  }),
  'selected internal transition mismatch',
);

const driftedVerification = {
  ...verification,
  rightful_issuance_projected: true,
};
const driftedVerificationBytes = canonicalBytes(driftedVerification);
throws(
  'persisted verification drift refuses',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    expectedVerificationFileSha256: sha256hex(driftedVerificationBytes),
    verificationRawBytes: driftedVerificationBytes,
  }),
  'does not exactly match',
);

for (const overrides of [
  { fresh_effect_allowed: true },
  { recorded_effect_uses: 0 },
  { status_updated_at_epoch: effectEpoch + 1 },
  { consumed_crossing_binding_sha256: digest('wrong-crossing') },
]) {
  const status = { ...exhaustedStatus, ...overrides };
  const bodySha = sha256hex(canonicalize(status));
  const wrapper = {
    authority_status: status,
    authority_status_sha256: bodySha,
  };
  const raw = canonicalBytes(wrapper);
  throws(
    `exhausted-status drift refuses ${Object.keys(overrides)[0]}`,
    () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
      ...params,
      exhaustedStatusRawBytes: raw,
      expectedExhaustedStatusBodySha256: bodySha,
      expectedExhaustedStatusFileSha256: sha256hex(raw),
    }),
    Object.hasOwn(overrides, 'consumed_crossing_binding_sha256')
      ? 'crossing binding mismatch'
      : 'posture or chronology mismatch',
  );
}

for (const overrides of [
  { automatic_retry_allowed: true },
  { exactly_once_effect_proven: true },
  { crash_atomic_effect_plus_pin_proven: true },
  { lifecycle_closed: true },
]) {
  const changed = { ...closeout, ...overrides };
  const raw = canonicalBytes(changed);
  throws(
    `closeout overclaim refuses ${Object.keys(overrides)[0]}`,
    () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
      ...params,
      closeoutRawBytes: raw,
      expectedCloseoutFileSha256: sha256hex(raw),
    }),
    'source-recorded posture mismatch',
  );
}
const identityLaunderedCloseout = {
  ...closeout,
  crossing_binding_sha256: crossingEvidence.crossing_binding_sha256,
};
const identityLaunderedCloseoutBytes = canonicalBytes(identityLaunderedCloseout);
throws(
  'closeout identity laundering refuses added field',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    closeoutRawBytes: identityLaunderedCloseoutBytes,
    expectedCloseoutFileSha256: sha256hex(identityLaunderedCloseoutBytes),
  }),
  'fields must be exactly',
);

throws(
  'missing input field refuses',
  () => {
    const missing = { ...params };
    delete missing.closeoutRawBytes;
    buildProtectedRecordsPostEffectRouteEvidenceIndexV0(missing);
  },
  'fields must be exactly',
);
throws(
  'extra input field refuses',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    unsupported: true,
  }),
  'fields must be exactly',
);
throws(
  'wrong historical source pin refuses',
  () => buildProtectedRecordsPostEffectRouteEvidenceIndexV0({
    ...params,
    expectedCrossingSourceCommitOid: 'b'.repeat(40),
  }),
  'expected identity or source binding mismatch',
);

function resolvedStaticImportGraph(entryPaths) {
  const pending = entryPaths.map((path) => resolve(path));
  const visited = new Set();
  const externalSpecifiers = new Set();
  while (pending.length > 0) {
    const current = pending.pop();
    if (visited.has(current)) continue;
    visited.add(current);
    const source = readFileSync(current, 'utf8');
    for (const match of source.matchAll(
      /(?:\bfrom\s*|\bimport\s*)['"]([^'"]+)['"]/g,
    )) {
      if (match[1].startsWith('.')) {
        pending.push(resolve(dirname(current), match[1]));
      } else {
        externalSpecifiers.add(match[1]);
      }
    }
  }
  return {
    externalSpecifiers: [...externalSpecifiers].sort(),
    files: [...visited].sort(),
  };
}

const cliSourcePath =
  'bin/zlar-protected-records-post-effect-route-evidence-index-v0';
const moduleSourcePath =
  'lib/protected-records-post-effect-route-evidence-index-v0.mjs';
const imports = resolvedStaticImportGraph([cliSourcePath, moduleSourcePath]);
equal('resolved source graph has six files', 6, imports.files.length);
equal(
  'external imports are exactly allowlisted',
  JSON.stringify(['node:crypto', 'node:fs', 'node:path']),
  JSON.stringify(imports.externalSpecifiers),
);
for (const expectedPath of [
  cliSourcePath,
  moduleSourcePath,
  'lib/canonicalize.mjs',
  'lib/protected-records-replacement-artifact-set-v2.mjs',
  'lib/protected-records-replacement-artifacts-v2.mjs',
  'lib/sha256.mjs',
]) {
  ok(
    `source graph contains expected file ${expectedPath}`,
    imports.files.includes(resolve(expectedPath)),
  );
}
for (const sourcePath of imports.files) {
  const source = readFileSync(sourcePath, 'utf8');
  for (const forbidden of [
    'node:child_process',
    'protected-records-runtime-profile.mjs',
    'protected-records-replacement-crossing-driver-v2.mjs',
    "from './receipt.mjs'",
    'generateKeyPairSync',
    'spawnSync',
    'writeFileSync',
    'renameSync',
    'unlinkSync',
    'import(',
    'require(',
    'eval(',
  ]) {
    equal(
      `${sourcePath} excludes ${forbidden}`,
      false,
      source.includes(forbidden),
    );
  }
  equal(
    `${sourcePath} excludes whitespace/comment dynamic import`,
    false,
    /\bimport\s*(?:\/\*[\s\S]*?\*\/\s*)?\(/.test(source),
  );
  equal(
    `${sourcePath} excludes whitespace require call`,
    false,
    /\brequire\s*\(/.test(source),
  );
  equal(
    `${sourcePath} excludes whitespace eval call`,
    false,
    /\beval\s*\(/.test(source),
  );
}
const moduleSource = readFileSync(moduleSourcePath, 'utf8');
equal(
  'module embeds no fixed SHA-256 identity',
  false,
  /\b[a-f0-9]{64}\b/.test(moduleSource),
);
equal(
  'module embeds no private absolute path',
  false,
  moduleSource.includes('/Users/'),
);
const cliSource = readFileSync(cliSourcePath, 'utf8');
const fsImports = [...cliSource.matchAll(
  /import\s*{([\s\S]*?)}\s*from\s*['"]node:fs['"]/g,
)];
equal('CLI has exactly one node:fs named import', 1, fsImports.length);
equal(
  'CLI node:fs bindings are exactly read-only allowlisted',
  JSON.stringify([
    'closeSync',
    'constants',
    'fstatSync',
    'openSync',
    'readFileSync',
  ]),
  JSON.stringify(
    fsImports[0][1]
      .split(',')
      .map((name) => name.trim())
      .filter(Boolean)
      .sort(),
  ),
);
ok(
  'CLI opens no-follow',
  cliSource.includes('constants.O_NOFOLLOW'),
);
ok(
  'CLI checks size before read',
  cliSource.indexOf('before.size < 2') < cliSource.indexOf('readFileSync(descriptor)'),
);
ok(
  'CLI compares descriptor metadata after read',
  cliSource.includes('descriptorIdentity(before) !== descriptorIdentity(after)'),
);

const scratch = mkdtempSync(join(tmpdir(), 'zlar-post-effect-index-'));
try {
  const paths = {
    runtime: join(scratch, 'runtime.json'),
    service: join(scratch, 'service.json'),
    terminal: join(scratch, 'terminal.json'),
    manifest: join(scratch, 'manifest.json'),
    verification: join(scratch, 'verification.json'),
    status: join(scratch, 'status.json'),
    closeout: join(scratch, 'closeout.json'),
  };
  writeFileSync(paths.runtime, runtimeResultRawBytes);
  writeFileSync(paths.service, serviceRawBytes);
  writeFileSync(paths.terminal, terminalRawBytes);
  writeFileSync(paths.manifest, manifestRawBytes);
  writeFileSync(paths.verification, verificationRawBytes);
  writeFileSync(paths.status, exhaustedStatusRawBytes);
  writeFileSync(paths.closeout, closeoutRawBytes);

  const cliPath = fileURLToPath(
    new URL(
      '../bin/zlar-protected-records-post-effect-route-evidence-index-v0',
      import.meta.url,
    ),
  );
  const cliArgs = [
    cliPath,
    '--runtime-result', paths.runtime,
    '--service', paths.service,
    '--terminal', paths.terminal,
    '--manifest', paths.manifest,
    '--verification', paths.verification,
    '--exhausted-status', paths.status,
    '--closeout', paths.closeout,
    '--require-runtime-result-file-sha', params.expectedRuntimeResultFileSha256,
    '--require-service-file-sha', params.expectedServiceFileSha256,
    '--require-terminal-file-sha', params.expectedTerminalFileSha256,
    '--require-manifest-file-sha', params.expectedManifestFileSha256,
    '--require-verification-file-sha', params.expectedVerificationFileSha256,
    '--require-exhausted-status-file-sha', params.expectedExhaustedStatusFileSha256,
    '--require-closeout-file-sha', params.expectedCloseoutFileSha256,
    '--require-service-body-sha', params.expectedServiceArtifactBodySha256,
    '--require-terminal-body-sha', params.expectedTerminalArtifactBodySha256,
    '--require-manifest-body-sha', params.expectedManifestArtifactBodySha256,
    '--require-manifest-schema-sha', params.expectedManifestSchemaContractSha256,
    '--require-grant-sha', params.expectedGrantContractSha256,
    '--require-crossing-binding-sha', params.expectedCrossingBindingSha256,
    '--require-exhausted-status-body-sha', params.expectedExhaustedStatusBodySha256,
    '--require-crossing-source-commit', params.expectedCrossingSourceCommitOid,
    '--json',
  ];
  const cliRun = spawnSync(process.execPath, cliArgs, { encoding: 'utf8' });
  equal('CLI exits zero', 0, cliRun.status);
  equal('CLI stderr empty', '', cliRun.stderr);
  equal('CLI canonical JSON has no trailing newline', false, cliRun.stdout.endsWith('\n'));
  const cliReport = JSON.parse(cliRun.stdout);
  equal(
    'CLI emits exact index type',
    PROTECTED_RECORDS_POST_EFFECT_ROUTE_EVIDENCE_INDEX_TYPE_V0,
    cliReport.artifact_type,
  );
  equal('CLI output is exact canonical JSON', canonicalize(cliReport), cliRun.stdout);

  const summaryRun = spawnSync(
    process.execPath,
    cliArgs.slice(0, -1),
    { encoding: 'utf8' },
  );
  equal('CLI summary exits zero', 0, summaryRun.status);
  ok('CLI summary names lifecycle false', summaryRun.stdout.includes('Lifecycle closed: false'));

  const requireClosedRun = spawnSync(
    process.execPath,
    [...cliArgs.slice(0, -1), '--require-closed'],
    { encoding: 'utf8' },
  );
  equal('CLI require-closed refuses', 1, requireClosedRun.status);
  equal('CLI require-closed emits no report', '', requireClosedRun.stdout);
  ok(
    'CLI require-closed names unauthorized lifecycle status change',
    requireClosedRun.stderr.includes('lifecycle status change is not authorized'),
  );

  const missingRun = spawnSync(
    process.execPath,
    [cliPath, '--runtime-result', paths.runtime],
    { encoding: 'utf8' },
  );
  equal('CLI missing inputs refuse', 2, missingRun.status);
  equal('CLI missing inputs emit no report', '', missingRun.stdout);

  const duplicateArgs = [...cliArgs];
  duplicateArgs.push('--runtime-result', paths.runtime);
  const duplicateRun = spawnSync(process.execPath, duplicateArgs, {
    encoding: 'utf8',
  });
  equal('CLI duplicate flag refuses', 2, duplicateRun.status);
  equal('CLI duplicate flag emits no report', '', duplicateRun.stdout);

  const unknownRun = spawnSync(
    process.execPath,
    [...cliArgs, '--unsupported'],
    { encoding: 'utf8' },
  );
  equal('CLI unknown argument refuses', 2, unknownRun.status);
  equal('CLI unknown argument emits no report', '', unknownRun.stdout);

  const runtimeLink = join(scratch, 'runtime-link.json');
  symlinkSync(paths.runtime, runtimeLink);
  const symlinkArgs = [...cliArgs];
  symlinkArgs[symlinkArgs.indexOf('--runtime-result') + 1] = runtimeLink;
  const symlinkRun = spawnSync(process.execPath, symlinkArgs, {
    encoding: 'utf8',
  });
  equal('CLI symlink refuses', 1, symlinkRun.status);
  equal('CLI symlink emits no report', '', symlinkRun.stdout);

  const oversizedPath = join(scratch, 'oversized.json');
  writeFileSync(oversizedPath, '');
  truncateSync(oversizedPath, 8 * 1024 * 1024 + 1);
  const oversizedArgs = [...cliArgs];
  oversizedArgs[oversizedArgs.indexOf('--closeout') + 1] = oversizedPath;
  const oversizedRun = spawnSync(process.execPath, oversizedArgs, {
    encoding: 'utf8',
  });
  equal('CLI oversized input refuses', 1, oversizedRun.status);
  equal('CLI oversized input emits no report', '', oversizedRun.stdout);

  const directoryPath = join(scratch, 'directory');
  mkdirSync(directoryPath);
  const directoryArgs = [...cliArgs];
  directoryArgs[directoryArgs.indexOf('--closeout') + 1] = directoryPath;
  const directoryRun = spawnSync(process.execPath, directoryArgs, {
    encoding: 'utf8',
  });
  equal('CLI nonregular input refuses', 1, directoryRun.status);
  equal('CLI nonregular input emits no report', '', directoryRun.stdout);

  const serviceHardLink = join(scratch, 'service-hard-link.json');
  linkSync(paths.service, serviceHardLink);
  const duplicateObjectArgs = [...cliArgs];
  duplicateObjectArgs[duplicateObjectArgs.indexOf('--terminal') + 1] =
    serviceHardLink;
  const duplicateObjectRun = spawnSync(
    process.execPath,
    duplicateObjectArgs,
    { encoding: 'utf8' },
  );
  equal('CLI duplicate filesystem object refuses', 1, duplicateObjectRun.status);
  equal('CLI duplicate filesystem object emits no report', '', duplicateObjectRun.stdout);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(
  `protected records post-effect route-evidence index v0: ${assertions}/${assertions} assertions passed`,
);
