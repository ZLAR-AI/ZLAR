import { spawnSync } from 'node:child_process';
import {
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
  buildConsequenceLifecycleMap,
} from '../lib/consequence-lifecycle-map.mjs';
import {
  CONSEQUENCE_LIFECYCLE_REPLACEMENT_OVERLAY_TYPE_V0,
  assertConsequenceLifecycleReplacementOverlayV0,
  buildConsequenceLifecycleReplacementOverlayV0,
  consequenceLifecycleReplacementOverlaySha256V0,
  formatConsequenceLifecycleReplacementOverlaySummaryV0,
} from '../lib/consequence-lifecycle-replacement-evidence-v0.mjs';
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
  return sha256hex(`synthetic-overlay:${label}`);
}

function expectedCrossingOptions(inputs) {
  return Object.fromEntries(
    Object.entries(inputs).map(([key, value]) => [
      `expected${key[0].toUpperCase()}${key.slice(1)}`,
      value,
    ]),
  );
}

function exhaustedStatusEvidence(crossingEvidence, crossingInputs, overrides = {}) {
  const authorityStatus = {
    appointment_sha256: crossingInputs.issuerAppointmentArtifactBodySha256,
    authority_grant_contract_sha256:
      crossingInputs.authorityGrantContractSha256,
    confirmation_sha256:
      crossingInputs.activationConfirmationArtifactBodySha256,
    consumed_crossing_binding_sha256:
      crossingEvidence.crossing_binding_sha256,
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
    status_updated_at_epoch: 2_000_000_100,
    status_version: 2,
    ...overrides,
  };
  const authorityStatusSha256 = sha256hex(canonicalize(authorityStatus));
  const wrapper = {
    authority_status: authorityStatus,
    authority_status_sha256: authorityStatusSha256,
  };
  return {
    bodySha256: authorityStatusSha256,
    rawBytes: Buffer.from(canonicalize(wrapper), 'utf8'),
    wrapper,
  };
}

const sourceArtifact = JSON.parse(
  readFileSync(
    'tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json',
    'utf8',
  ),
);
const baseMap = buildConsequenceLifecycleMap(sourceArtifact);
const baseMapRawBytes = Buffer.from(JSON.stringify(baseMap, null, 2), 'utf8');
const baseMapSha256 = sha256hex(JSON.stringify(baseMap));
const callGraph = JSON.parse(
  readFileSync('spec/protected-records-no-reexecution-call-graph-v2.json', 'utf8'),
);
const serviceSchemaSha256 =
  protectedRecordsReplacementServiceArtifactSchemaContractSha256V2();
const terminalSchemaSha256 =
  protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2();
const manifestSchemaSha256 =
  protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2();
const sourceBinding = {
  git_object_format: 'sha1',
  installed_profile_preflight_artifact_body_sha256:
    digest('installed-profile-preflight'),
  no_reexecution_call_graph_sha256:
    protectedRecordsReplacementNoReexecutionCallGraphSha256V2(callGraph),
  repository_id: 'ZLAR_Repo',
  service_artifact_schema_contract_sha256: serviceSchemaSha256,
  source_commit_oid: 'a'.repeat(40),
  source_precondition_artifact_body_sha256: digest('source-precondition'),
  terminal_artifact_schema_contract_sha256: terminalSchemaSha256,
};
const crossingInputs = {
  activationConfirmationArtifactBodySha256: digest('confirmation'),
  authorityGrantContractSha256: digest('grant'),
  authorityStatusAtEffectArtifactBodySha256: digest('status-at-effect'),
  authorizedEffectDetailSha256: digest('authorized-effect'),
  confirmationConfirmedAtEpoch: 2_000_000_000,
  controlTowerConfirmationRelayDelaySeconds: 30,
  controlTowerConfirmationRelayMaxSeconds: 300,
  effectDecisionSha256: digest('effect-decision'),
  executionTraceSha256: digest('execution-trace'),
  installedProfilePreflightArtifactBodySha256:
    sourceBinding.installed_profile_preflight_artifact_body_sha256,
  holderObservedConfirmationEpoch: 2_000_000_030,
  issuerAppointmentArtifactBodySha256: digest('appointment'),
  issuanceDecisionSha256: digest('issuance-decision'),
  receiptEnvelopeBodySha256: digest('receipt-envelope'),
  recognitionContractSha256: digest('recognition-contract'),
  recordUpdateSha256: digest('record-update'),
  runtimeProfileSha256: digest('runtime-profile'),
  runtimeTransitionSha256: digest('runtime-transition'),
  sourcePreconditionArtifactBodySha256:
    sourceBinding.source_precondition_artifact_body_sha256,
  targetBindingSha256: digest('target-binding'),
  targetContractSha256: digest('target-contract'),
  targetEffectSha256: digest('target-effect'),
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
const exhausted = exhaustedStatusEvidence(crossingEvidence, crossingInputs);
const params = {
  baseMapRawBytes,
  expectedBaseMapSha256: baseMapSha256,
  expectedExhaustedStatusBodySha256: exhausted.bodySha256,
  expectedGrantContractSha256:
    crossingInputs.authorityGrantContractSha256,
  expectedManifestArtifactBodySha256: manifest.integrity.body_sha256,
  expectedManifestSchemaContractSha256: manifestSchemaSha256,
  exhaustedStatusRawBytes: exhausted.rawBytes,
  manifestRawBytes,
  serviceArtifactRawBytes: serviceRawBytes,
  terminalArtifactRawBytes: terminalRawBytes,
};

const report = buildConsequenceLifecycleReplacementOverlayV0(params);
equal(
  'overlay type is exact',
  CONSEQUENCE_LIFECYCLE_REPLACEMENT_OVERLAY_TYPE_V0,
  report.report_type,
);
equal('overlay remains mapped open', 'mapped_open', report.map_status);
equal('overlay lifecycle remains open', false, report.closure.lifecycle_closed);
equal(
  'overlay does not project rightful issuance',
  false,
  report.rightful_issuance_projected,
);
equal(
  'overlay performs no consequence reexecution',
  false,
  report.consequence_reexecution_performed,
);
equal(
  'overlay manifest is explicitly incomplete lifecycle evidence',
  false,
  report.manifest_covers_complete_lifecycle,
);
equal(
  'base map remains canonical v0',
  'zlar-consequence-lifecycle-map-v0',
  report.base_map_reference.report_type,
);
equal('overlay binds exact base map', baseMapSha256, report.base_map_sha256);
equal(
  'overlay does not reproject the unvalidated full base map',
  false,
  Object.hasOwn(report, 'base_map'),
);
equal(
  'overlay validates bounded base-map fields only',
  false,
  report.base_map_schema_fully_validated,
);
equal(
  'overlay does not evaluate base-map claim strings',
  false,
  report.base_map_claim_strings_evaluated,
);
equal(
  'base lifecycle graph remains source-unbound',
  false,
  report.base_map_reference.path_source_commit_bound,
);
equal(
  'replacement crossing source is bound',
  true,
  report.replacement_artifact_lineage_v2
    .replacement_crossing_source_commit_bound,
);
equal(
  'artifact-set verifier does not evaluate status',
  false,
  report.replacement_artifact_lineage_v2.artifact_set_authority_status_evaluated,
);
equal(
  'overlay does not evaluate authority or effect occurrence',
  false,
  report.replacement_artifact_lineage_v2.authority_effect_occurrence_evaluated,
);
equal(
  'canonical hash-pinned exhausted status is separately evaluated',
  true,
  report.replacement_artifact_lineage_v2
    .replacement_exhausted_status_evaluated,
);
equal(
  'replacement grant is exhausted',
  'exhausted',
  report.replacement_artifact_lineage_v2.source_recorded_grant_status,
);
equal(
  'replacement fresh effect is false',
  false,
  report.replacement_artifact_lineage_v2.source_recorded_fresh_effect_allowed,
);
equal(
  'replacement use count is one',
  1,
  report.replacement_artifact_lineage_v2.source_recorded_effect_uses,
);
equal(
  'replacement repeated-use provenance is false',
  false,
  report.replacement_artifact_lineage_v2
    .source_recorded_repeated_use_provenance_valid,
);
equal(
  'replacement evidence namespace cannot create cross-authority',
  false,
  report.evidence_namespaces.cross_namespace_authority_inference_allowed,
);
ok(
  'overlay assertion accepts exact report',
  assertConsequenceLifecycleReplacementOverlayV0(report, params),
);
ok(
  'overlay hash is exact SHA-256',
  /^[a-f0-9]{64}$/.test(
    consequenceLifecycleReplacementOverlaySha256V0(report),
  ),
);
ok(
  'overlay summary names rightful refusal',
  formatConsequenceLifecycleReplacementOverlaySummaryV0(report, params)
    .includes('rightful_issuance_projected=false'),
);

const tamperedReport = clone(report);
tamperedReport.rightful_issuance_projected = true;
throws(
  'overlay assertion refuses rightful projection',
  () => assertConsequenceLifecycleReplacementOverlayV0(tamperedReport, params),
  'exact verified projection',
);
throws(
  'overlay formatter refuses a mutated report',
  () => formatConsequenceLifecycleReplacementOverlaySummaryV0(
    tamperedReport,
    params,
  ),
  'exact verified projection',
);
const closedBaseMap = clone(baseMap);
closedBaseMap.closure.lifecycle_closed = true;
const closedBaseMapRawBytes = Buffer.from(
  JSON.stringify(closedBaseMap, null, 2),
  'utf8',
);
throws(
  'overlay refuses a caller-pinned closed base map',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    baseMapRawBytes: closedBaseMapRawBytes,
    expectedBaseMapSha256: sha256hex(JSON.stringify(closedBaseMap)),
  }),
  'claim boundary mismatch',
);
for (const claimField of [
  'local_fixture_rightful_issuance_path',
  'generic_rightful_issuance',
  'portable_rightful_issuance',
  'live_rightful_issuance',
  'production_rightful_issuance',
  'current_machine_rightful_issuance',
  'production_governance',
  'enterprise_readiness',
  'general_current_machine_governance',
  'public_external_attestation',
  'all_surface_governance',
  'revocation_truth',
  'side_door_closure',
  'sovereign_recognition',
]) {
  const unsafeBaseMap = clone(baseMap);
  unsafeBaseMap.claim_boundary[claimField] = true;
  throws(
    `overlay refuses caller-pinned base-map claim ${claimField}`,
    () => buildConsequenceLifecycleReplacementOverlayV0({
      ...params,
      baseMapRawBytes: Buffer.from(
        JSON.stringify(unsafeBaseMap, null, 2),
        'utf8',
      ),
      expectedBaseMapSha256: sha256hex(JSON.stringify(unsafeBaseMap)),
    }),
    'claim boundary mismatch',
  );
}
const hostileClaimString =
  'Enterprise and production governance are proven for every machine.';
const hostileStringBaseMap = clone(baseMap);
hostileStringBaseMap.safe_claim_ceiling = hostileClaimString;
hostileStringBaseMap.claim_boundary.safe_claim = hostileClaimString;
const hostileStringOverlay = buildConsequenceLifecycleReplacementOverlayV0({
  ...params,
  baseMapRawBytes: Buffer.from(
    JSON.stringify(hostileStringBaseMap, null, 2),
    'utf8',
  ),
  expectedBaseMapSha256: sha256hex(JSON.stringify(hostileStringBaseMap)),
});
equal(
  'overlay keeps unvalidated base-map claim strings opaque',
  false,
  JSON.stringify(hostileStringOverlay).includes(hostileClaimString),
);
equal(
  'opaque hostile-string base map remains explicitly unevaluated',
  false,
  hostileStringOverlay.base_map_claim_strings_evaluated,
);
throws(
  'overlay refuses wrong manifest identity',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    expectedManifestArtifactBodySha256: 'f'.repeat(64),
  }),
  'body identity mismatch',
);
throws(
  'overlay refuses wrong grant identity',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    expectedGrantContractSha256: 'f'.repeat(64),
  }),
  'grant or schema binding mismatch',
);
throws(
  'overlay refuses wrong manifest schema',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    expectedManifestSchemaContractSha256: 'f'.repeat(64),
  }),
  'grant or schema binding mismatch',
);
throws(
  'overlay refuses noncanonical status wrapper',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    exhaustedStatusRawBytes: Buffer.from(
      JSON.stringify(exhausted.wrapper, null, 2),
      'utf8',
    ),
  }),
  'must be exact canonical JSON',
);
const freshStatus = exhaustedStatusEvidence(
  crossingEvidence,
  crossingInputs,
  { fresh_effect_allowed: true },
);
throws(
  'overlay refuses fresh exhausted status',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    expectedExhaustedStatusBodySha256: freshStatus.bodySha256,
    exhaustedStatusRawBytes: freshStatus.rawBytes,
  }),
  'posture mismatch',
);
const wrongCrossingStatus = exhaustedStatusEvidence(
  crossingEvidence,
  crossingInputs,
  { consumed_crossing_binding_sha256: digest('wrong-crossing') },
);
throws(
  'overlay refuses detached exhausted crossing',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    expectedExhaustedStatusBodySha256: wrongCrossingStatus.bodySha256,
    exhaustedStatusRawBytes: wrongCrossingStatus.rawBytes,
  }),
  'crossing binding mismatch',
);
const earlyStatus = exhaustedStatusEvidence(
  crossingEvidence,
  crossingInputs,
  { status_updated_at_epoch: 2_000_000_029 },
);
throws(
  'overlay refuses status predating holder observation',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    expectedExhaustedStatusBodySha256: earlyStatus.bodySha256,
    exhaustedStatusRawBytes: earlyStatus.rawBytes,
  }),
  'posture mismatch',
);
const tamperedService = Buffer.from(serviceRawBytes);
tamperedService[tamperedService.length - 1] = 0x20;
throws(
  'overlay refuses tampered service bytes',
  () => buildConsequenceLifecycleReplacementOverlayV0({
    ...params,
    serviceArtifactRawBytes: tamperedService,
  }),
  'not valid JSON',
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
    for (const match of source.matchAll(/(?:\bfrom\s*|\bimport\s*)['"]([^'"]+)['"]/g)) {
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

const overlayCliPath =
  'bin/zlar-consequence-lifecycle-replacement-overlay-v0';
const overlayImports = resolvedStaticImportGraph([
  overlayCliPath,
  'lib/consequence-lifecycle-replacement-evidence-v0.mjs',
]);
const overlayGraph = overlayImports.files;
equal('overlay resolved import graph has six files', 6, overlayGraph.length);
equal(
  'overlay static external imports are exactly allowlisted',
  JSON.stringify(['node:crypto', 'node:fs', 'node:path']),
  JSON.stringify(overlayImports.externalSpecifiers),
);
for (const expectedPath of [
  'bin/zlar-consequence-lifecycle-replacement-overlay-v0',
  'lib/canonicalize.mjs',
  'lib/consequence-lifecycle-replacement-evidence-v0.mjs',
  'lib/protected-records-replacement-artifact-set-v2.mjs',
  'lib/protected-records-replacement-artifacts-v2.mjs',
  'lib/sha256.mjs',
]) {
  ok(
    `overlay import graph contains only expected file ${expectedPath}`,
    overlayGraph.includes(resolve(expectedPath)),
  );
}
for (const sourcePath of overlayGraph) {
  const source = readFileSync(sourcePath, 'utf8');
  for (const forbidden of [
    'node:child_process',
    "from './receipt.mjs'",
    'import(',
    'require(',
    'writeFileSync',
  ]) {
    equal(
      `${sourcePath} excludes ${forbidden}`,
      false,
      source.includes(forbidden),
    );
  }
}
const overlaySource = readFileSync(
  'lib/consequence-lifecycle-replacement-evidence-v0.mjs',
  'utf8',
);
equal('overlay source imports no base lifecycle generator', false, overlaySource.includes('consequence-lifecycle-map.mjs'));
equal('overlay source embeds no fixed SHA-256 identity', false, /\b[a-f0-9]{64}\b/.test(overlaySource));
const overlayCliSource = readFileSync(overlayCliPath, 'utf8');
ok(
  'overlay CLI checks descriptor size before reading bytes',
  overlayCliSource.indexOf('status.size < 2') <
    overlayCliSource.indexOf('readFileSync(descriptor)'),
);
ok(
  'overlay CLI opens with no-follow semantics',
  overlayCliSource.includes('constants.O_NOFOLLOW'),
);

const scratch = mkdtempSync(join(tmpdir(), 'zlar-lifecycle-overlay-'));
try {
  const manifestPath = join(scratch, 'manifest.json');
  const servicePath = join(scratch, 'service.json');
  const terminalPath = join(scratch, 'terminal.json');
  const exhaustedPath = join(scratch, 'exhausted.json');
  const baseMapPath = join(scratch, 'base-map.json');
  writeFileSync(baseMapPath, baseMapRawBytes);
  writeFileSync(manifestPath, manifestRawBytes);
  writeFileSync(servicePath, serviceRawBytes);
  writeFileSync(terminalPath, terminalRawBytes);
  writeFileSync(exhaustedPath, exhausted.rawBytes);
  const cliPath = fileURLToPath(
    new URL(
      '../bin/zlar-consequence-lifecycle-replacement-overlay-v0',
      import.meta.url,
    ),
  );
  const cliArgs = [
    cliPath,
    '--base-map', baseMapPath,
    '--replacement-manifest', manifestPath,
    '--replacement-service', servicePath,
    '--replacement-terminal', terminalPath,
    '--replacement-exhausted-status', exhaustedPath,
    '--require-base-map-sha', baseMapSha256,
    '--require-replacement-manifest-sha', manifest.integrity.body_sha256,
    '--require-replacement-grant-sha',
    crossingInputs.authorityGrantContractSha256,
    '--require-replacement-manifest-schema-sha', manifestSchemaSha256,
    '--require-replacement-exhausted-status-sha', exhausted.bodySha256,
    '--json',
  ];
  const cliRun = spawnSync(process.execPath, cliArgs, { encoding: 'utf8' });
  equal('overlay CLI exits zero', 0, cliRun.status);
  const cliReport = JSON.parse(cliRun.stdout);
  equal(
    'overlay CLI emits exact type',
    CONSEQUENCE_LIFECYCLE_REPLACEMENT_OVERLAY_TYPE_V0,
    cliReport.report_type,
  );
  equal(
    'overlay CLI keeps lifecycle open',
    false,
    cliReport.closure.lifecycle_closed,
  );

  const partialRun = spawnSync(
    process.execPath,
    [cliPath, '--base-map', baseMapPath],
    { encoding: 'utf8' },
  );
  equal('overlay CLI partial args exit usage refusal', 2, partialRun.status);
  equal('overlay CLI partial args emit no report', '', partialRun.stdout);

  const invalidShaArgs = [...cliArgs];
  invalidShaArgs[
    invalidShaArgs.indexOf('--require-base-map-sha') + 1
  ] = 'not-a-sha';
  const invalidShaRun = spawnSync(process.execPath, invalidShaArgs, {
    encoding: 'utf8',
  });
  equal('overlay CLI invalid SHA exits usage refusal', 2, invalidShaRun.status);
  equal('overlay CLI invalid SHA emits no report', '', invalidShaRun.stdout);

  const requireClosedRun = spawnSync(
    process.execPath,
    [...cliArgs, '--require-closed'],
    { encoding: 'utf8' },
  );
  equal('overlay CLI require-closed refuses', 1, requireClosedRun.status);
  equal('overlay CLI require-closed emits no report', '', requireClosedRun.stdout);

  const exhaustedLink = join(scratch, 'exhausted-link.json');
  symlinkSync(exhaustedPath, exhaustedLink);
  const symlinkArgs = [...cliArgs];
  symlinkArgs[symlinkArgs.indexOf('--replacement-exhausted-status') + 1] =
    exhaustedLink;
  const symlinkRun = spawnSync(process.execPath, symlinkArgs, {
    encoding: 'utf8',
  });
  equal('overlay CLI symlink refuses', 1, symlinkRun.status);
  equal('overlay CLI symlink emits no report', '', symlinkRun.stdout);

  const oversizedPath = join(scratch, 'oversized.json');
  writeFileSync(oversizedPath, '');
  truncateSync(oversizedPath, 8 * 1024 * 1024 + 1);
  const oversizedArgs = [...cliArgs];
  oversizedArgs[oversizedArgs.indexOf('--replacement-manifest') + 1] =
    oversizedPath;
  const oversizedRun = spawnSync(process.execPath, oversizedArgs, {
    encoding: 'utf8',
  });
  equal('overlay CLI oversized input refuses', 1, oversizedRun.status);
  equal('overlay CLI oversized input emits no report', '', oversizedRun.stdout);

} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log(
  `consequence lifecycle replacement overlay v0: ${assertions}/${assertions} assertions passed`,
);
