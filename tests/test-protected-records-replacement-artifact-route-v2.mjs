import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../lib/canonicalize.mjs';
import { sha256hex } from '../lib/receipt.mjs';
import {
  PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS,
  PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2,
  PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH,
  buildProtectedRecordsReplacementCrossingEvidenceV2,
  buildProtectedRecordsReplacementServiceArtifactV2,
  buildProtectedRecordsReplacementTerminalArtifactV2,
  canonicalProtectedRecordsReplacementArtifactBytesV2,
  protectedRecordsReplacementServiceArtifactSchemaContractSha256V2,
  protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2,
  verifyProtectedRecordsReplacementServiceArtifactV2RawBytes,
  verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes,
} from '../lib/protected-records-replacement-artifacts-v2.mjs';
import {
  PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2,
  assertProtectedRecordsReplacementNoReexecutionCallGraphDescriptorV2,
  buildProtectedRecordsReplacementArtifactSetManifestV2,
  buildProtectedRecordsReplacementDownstreamProjectionV2,
  canonicalProtectedRecordsReplacementArtifactSetManifestBytesV2,
  protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2,
  protectedRecordsReplacementNoReexecutionCallGraphSha256V2,
  verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes,
} from '../lib/protected-records-replacement-artifact-set-v2.mjs';

let assertions = 0;

function equal(label, expected, actual) {
  assertions += 1;
  if (actual !== expected) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
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
        `${label}: expected error containing ${JSON.stringify(expectedText)}, got ${JSON.stringify(error.message)}`
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
  return sha256hex(`synthetic-source-only:${label}`);
}

function expectedCrossingOptions(inputs) {
  return Object.fromEntries(
    Object.entries(inputs).map(([key, value]) => [
      `expected${key[0].toUpperCase()}${key.slice(1)}`,
      value,
    ])
  );
}

const callGraphDescriptor = JSON.parse(
  readFileSync('spec/protected-records-no-reexecution-call-graph-v2.json', 'utf8')
);
assertProtectedRecordsReplacementNoReexecutionCallGraphDescriptorV2(
  callGraphDescriptor
);
const callGraphSha256 =
  protectedRecordsReplacementNoReexecutionCallGraphSha256V2(callGraphDescriptor);
const serviceSchemaSha256 =
  protectedRecordsReplacementServiceArtifactSchemaContractSha256V2();
const terminalSchemaSha256 =
  protectedRecordsReplacementTerminalArtifactSchemaContractSha256V2();

const sourceBinding = {
  git_object_format: 'sha1',
  installed_profile_preflight_artifact_body_sha256: digest(
    'installed-profile-preflight'
  ),
  no_reexecution_call_graph_sha256: callGraphSha256,
  repository_id: 'ZLAR_Repo',
  service_artifact_schema_contract_sha256: serviceSchemaSha256,
  source_commit_oid: 'a'.repeat(40),
  source_precondition_artifact_body_sha256: digest('source-precondition'),
  terminal_artifact_schema_contract_sha256: terminalSchemaSha256,
};

const crossingInputs = {
  activationConfirmationArtifactBodySha256: digest('activation-confirmation'),
  authorityGrantContractSha256: digest('replacement-grant'),
  authorityStatusAtEffectArtifactBodySha256: digest('authority-status-at-effect'),
  authorizedEffectDetailSha256: digest('authorized-effect-detail'),
  confirmationConfirmedAtEpoch: 2_000_000_000,
  controlTowerConfirmationRelayDelaySeconds: 79,
  controlTowerConfirmationRelayMaxSeconds: 300,
  effectDecisionSha256: digest('effect-decision'),
  executionTraceSha256: digest('execution-trace'),
  installedProfilePreflightArtifactBodySha256:
    sourceBinding.installed_profile_preflight_artifact_body_sha256,
  holderObservedConfirmationEpoch: 2_000_000_079,
  issuerAppointmentArtifactBodySha256: digest('issuer-appointment'),
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
const expectedRelayProjection = {
  confirmation_confirmed_at_epoch: crossingInputs.confirmationConfirmedAtEpoch,
  control_tower_confirmation_relay_delay_seconds:
    crossingInputs.controlTowerConfirmationRelayDelaySeconds,
  control_tower_confirmation_relay_max_seconds:
    crossingInputs.controlTowerConfirmationRelayMaxSeconds,
  holder_observed_confirmation_epoch:
    crossingInputs.holderObservedConfirmationEpoch,
};
function relayProjection(projection) {
  return Object.fromEntries(
    Object.keys(expectedRelayProjection).map((key) => [key, projection[key]])
  );
}

equal('action class is narrow', 'records.write', PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS);
equal(
  'consequence path is exact',
  'protected-records.installed-runtime-profile.terminal-chain.records.write',
  PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH
);
ok(
  'action class and consequence path are not conflated',
  PROTECTED_RECORDS_REPLACEMENT_ACTION_CLASS !==
    PROTECTED_RECORDS_REPLACEMENT_CONSEQUENCE_PATH
);
ok('service schema identity is exact SHA-256', /^[a-f0-9]{64}$/.test(serviceSchemaSha256));
ok('terminal schema identity is exact SHA-256', /^[a-f0-9]{64}$/.test(terminalSchemaSha256));
ok('call graph identity is exact SHA-256', /^[a-f0-9]{64}$/.test(callGraphSha256));
equal(
  'confirmation relay maximum is exact',
  300,
  PROTECTED_RECORDS_REPLACEMENT_CONFIRMATION_RELAY_MAX_SECONDS_V2
);

const serviceBuilderInput = {
  crossingEvidence,
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  sourceBinding,
  ...expectedCrossing,
};
const serviceArtifact =
  buildProtectedRecordsReplacementServiceArtifactV2(serviceBuilderInput);
const serviceRawBytes =
  canonicalProtectedRecordsReplacementArtifactBytesV2(serviceArtifact);
const serviceArtifactSha256 = serviceArtifact.integrity.body_sha256;
const serviceVerifierOptions = {
  expectedArtifactBodySha256: serviceArtifactSha256,
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  expectedSourceBinding: sourceBinding,
  ...expectedCrossing,
};
const serviceVerification =
  verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
    serviceRawBytes,
    serviceVerifierOptions
  );

equal('service artifact verifies', true, serviceVerification.verified);
equal(
  'service verification does not execute consequence',
  false,
  serviceVerification.consequence_reexecution_performed
);
equal(
  'service artifact binds recomputed X',
  crossingEvidence.crossing_binding_sha256,
  serviceArtifact.payload.authority_binding.crossing_binding_sha256
);
equal(
  'service artifact binds activation confirmation A',
  crossingInputs.activationConfirmationArtifactBodySha256,
  serviceArtifact.payload.authority_binding
    .activation_confirmation_artifact_body_sha256
);
equal(
  'service artifact binds status at effect',
  crossingInputs.authorityStatusAtEffectArtifactBodySha256,
  serviceArtifact.payload.authority_binding
    .authority_status_at_effect_artifact_body_sha256
);
equal(
  'service artifact distinguishes installed-profile preflight',
  crossingInputs.installedProfilePreflightArtifactBodySha256,
  serviceArtifact.payload.source_binding
    .installed_profile_preflight_artifact_body_sha256
);
equal(
  'service artifact distinguishes source precondition',
  crossingInputs.sourcePreconditionArtifactBodySha256,
  serviceArtifact.payload.source_binding
    .source_precondition_artifact_body_sha256
);
ok(
  'installed-profile preflight and source precondition are distinct',
  sourceBinding.installed_profile_preflight_artifact_body_sha256 !==
    sourceBinding.source_precondition_artifact_body_sha256
);

const terminalBuilderInput = {
  expectedServiceArtifactBodySha256: serviceArtifactSha256,
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  expectedSourceBinding: sourceBinding,
  expectedTerminalArtifactSchemaContractSha256: terminalSchemaSha256,
  serviceArtifactRawBytes: serviceRawBytes,
  ...expectedCrossing,
};
const terminalArtifact =
  buildProtectedRecordsReplacementTerminalArtifactV2(terminalBuilderInput);
const terminalRawBytes =
  canonicalProtectedRecordsReplacementArtifactBytesV2(terminalArtifact);
const terminalArtifactSha256 = terminalArtifact.integrity.body_sha256;
const terminalVerification =
  verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes(
    terminalRawBytes,
    {
      expectedArtifactBodySha256: terminalArtifactSha256,
      expectedServiceArtifactBodySha256: serviceArtifactSha256,
      expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
      expectedSourceBinding: sourceBinding,
      expectedTerminalArtifactSchemaContractSha256: terminalSchemaSha256,
      ...expectedCrossing,
    }
  );

equal('terminal artifact verifies', true, terminalVerification.verified);
equal(
  'terminal artifact pins exact service HS',
  serviceArtifactSha256,
  terminalArtifact.payload.service_artifact_binding.service_artifact_body_sha256
);
equal(
  'terminal verification does not re-execute consequence',
  false,
  terminalVerification.consequence_reexecution_performed
);

const manifestBuilderInput = {
  expectedServiceArtifactBodySha256: serviceArtifactSha256,
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  expectedSourceBinding: sourceBinding,
  expectedTerminalArtifactBodySha256: terminalArtifactSha256,
  expectedTerminalArtifactSchemaContractSha256: terminalSchemaSha256,
  serviceArtifactRawBytes: serviceRawBytes,
  terminalArtifactRawBytes: terminalRawBytes,
  ...expectedCrossing,
};
const manifest =
  buildProtectedRecordsReplacementArtifactSetManifestV2(manifestBuilderInput);
const manifestRawBytes =
  canonicalProtectedRecordsReplacementArtifactSetManifestBytesV2(manifest);
const manifestSha256 = manifest.integrity.body_sha256;
const artifactSetVerification =
  verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes({
    expectedManifestArtifactBodySha256: manifestSha256,
    manifestRawBytes,
    serviceArtifactRawBytes: serviceRawBytes,
    terminalArtifactRawBytes: terminalRawBytes,
  });
const rawArtifactSet = {
  expectedManifestArtifactBodySha256: manifestSha256,
  manifestRawBytes,
  serviceArtifactRawBytes: serviceRawBytes,
  terminalArtifactRawBytes: terminalRawBytes,
};

equal('central artifact set verifies', true, artifactSetVerification.verified);
equal(
  'central artifact set pins service HS',
  serviceArtifactSha256,
  artifactSetVerification.service_artifact_body_sha256
);
equal(
  'central artifact set pins terminal HT',
  terminalArtifactSha256,
  artifactSetVerification.terminal_artifact_body_sha256
);
equal(
  'central artifact set performs no consequence reexecution',
  false,
  artifactSetVerification.consequence_reexecution_performed
);
equal(
  'service artifact carries exact confirmation relay tuple',
  canonicalize(expectedRelayProjection),
  canonicalize(relayProjection(
    serviceArtifact.payload.crossing_evidence.evidence
      .crossing_binding_projection
  ))
);
equal(
  'terminal artifact carries exact confirmation relay tuple',
  canonicalize(expectedRelayProjection),
  canonicalize(relayProjection(
    terminalArtifact.payload.verification_projection.crossing_binding_projection
  ))
);
equal(
  'central manifest carries exact confirmation relay tuple',
  canonicalize(expectedRelayProjection),
  canonicalize(relayProjection(manifest.payload.crossing_binding_projection))
);
equal(
  'artifact-set verification carries exact confirmation relay tuple',
  canonicalize(expectedRelayProjection),
  canonicalize(relayProjection(
    artifactSetVerification.crossing_binding_projection
  ))
);
equal(
  'downstream projection carries exact confirmation relay tuple',
  canonicalize(expectedRelayProjection),
  canonicalize(relayProjection(
    buildProtectedRecordsReplacementDownstreamProjectionV2(
      'local-proof-pack',
      rawArtifactSet
    ).crossing_binding_projection
  ))
);

for (const consumerId of PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2) {
  const projection = buildProtectedRecordsReplacementDownstreamProjectionV2(
    consumerId,
    rawArtifactSet
  );
  equal(`${consumerId} projection uses exact manifest`, manifestSha256, projection.manifest_artifact_body_sha256);
  equal(`${consumerId} projection uses exact service`, serviceArtifactSha256, projection.service_artifact_body_sha256);
  equal(`${consumerId} projection uses exact terminal`, terminalArtifactSha256, projection.terminal_artifact_body_sha256);
  equal(`${consumerId} projection does not reexecute`, false, projection.consequence_reexecution_performed);
}

throws(
  'service builder refuses caller-nominated output hash',
  () =>
    buildProtectedRecordsReplacementServiceArtifactV2({
      ...serviceBuilderInput,
      artifactBodySha256: digest('caller-nominated-service-output'),
    }),
  'keys must be exactly'
);
throws(
  'crossing evidence refuses future-dated confirmation',
  () => buildProtectedRecordsReplacementCrossingEvidenceV2({
    ...crossingInputs,
    confirmationConfirmedAtEpoch:
      crossingInputs.holderObservedConfirmationEpoch + 1,
    controlTowerConfirmationRelayDelaySeconds: 0,
  }),
  'directional inclusive bound'
);
throws(
  'crossing evidence refuses 301-second relay',
  () => buildProtectedRecordsReplacementCrossingEvidenceV2({
    ...crossingInputs,
    controlTowerConfirmationRelayDelaySeconds: 301,
    holderObservedConfirmationEpoch:
      crossingInputs.confirmationConfirmedAtEpoch + 301,
  }),
  'directional inclusive bound'
);

const relayTamperedService = clone(serviceArtifact);
relayTamperedService.payload.crossing_evidence.evidence
  .crossing_binding_projection.control_tower_confirmation_relay_delay_seconds =
    80;
relayTamperedService.payload.crossing_evidence.evidence.crossing_binding_sha256 =
  sha256hex(canonicalize(
    relayTamperedService.payload.crossing_evidence.evidence
      .crossing_binding_projection
  ));
relayTamperedService.payload.crossing_evidence.evidence_body_sha256 =
  sha256hex(canonicalize(
    relayTamperedService.payload.crossing_evidence.evidence
  ));
relayTamperedService.payload.authority_binding.crossing_binding_sha256 =
  relayTamperedService.payload.crossing_evidence.evidence
    .crossing_binding_sha256;
const { integrity: ignoredRelayIntegrity, ...relayTamperedServiceBody } =
  relayTamperedService;
void ignoredRelayIntegrity;
relayTamperedService.integrity = {
  algorithm: 'SHA-256',
  body_sha256: sha256hex(canonicalize(relayTamperedServiceBody)),
};
throws(
  'service verifier refuses integrity-recomputed relay drift',
  () => verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
    Buffer.from(canonicalize(relayTamperedService), 'utf8'),
    {
      ...serviceVerifierOptions,
      expectedArtifactBodySha256:
        relayTamperedService.integrity.body_sha256,
    }
  ),
  'directional inclusive bound'
);
throws(
  'terminal builder refuses caller-nominated output hash',
  () =>
    buildProtectedRecordsReplacementTerminalArtifactV2({
      ...terminalBuilderInput,
      artifactBodySha256: digest('caller-nominated-terminal-output'),
    }),
  'keys must be exactly'
);
throws(
  'manifest builder refuses caller-nominated output hash',
  () =>
    buildProtectedRecordsReplacementArtifactSetManifestV2({
      ...manifestBuilderInput,
      artifactBodySha256: digest('caller-nominated-manifest-output'),
    }),
  'keys must be exactly'
);

const forgedCrossingInputs = {
  ...crossingInputs,
  targetEffectSha256: digest('forged-target-effect'),
};
const selfConsistentButWrongCrossing =
  buildProtectedRecordsReplacementCrossingEvidenceV2(forgedCrossingInputs);
throws(
  'service builder refuses self-consistent X from wrong expected target effect',
  () =>
    buildProtectedRecordsReplacementServiceArtifactV2({
      ...serviceBuilderInput,
      crossingEvidence: selfConsistentButWrongCrossing,
    }),
  'expected boundary mismatch'
);

const arbitraryX = clone(crossingEvidence);
arbitraryX.crossing_binding_sha256 = digest('arbitrary-crossing-binding');
throws(
  'service builder recomputes and refuses arbitrary X',
  () =>
    buildProtectedRecordsReplacementServiceArtifactV2({
      ...serviceBuilderInput,
      crossingEvidence: arbitraryX,
    }),
  'recomputation mismatch'
);

const missingServiceSchema = { ...serviceVerifierOptions };
delete missingServiceSchema.expectedServiceArtifactSchemaContractSha256;
throws(
  'service verifier refuses missing expected SS',
  () =>
    verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
      serviceRawBytes,
      missingServiceSchema
    ),
  'keys must be exactly'
);
throws(
  'service verifier refuses mismatched expected SS',
  () =>
    verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
      serviceRawBytes,
      {
        ...serviceVerifierOptions,
        expectedServiceArtifactSchemaContractSha256: digest('wrong-service-schema'),
      }
    ),
  'expected schema contract mismatch'
);
throws(
  'service verifier refuses noncanonical raw JSON',
  () =>
    verifyProtectedRecordsReplacementServiceArtifactV2RawBytes(
      JSON.stringify(serviceArtifact, null, 2),
      serviceVerifierOptions
    ),
  'must be exact canonical JSON'
);
throws(
  'terminal verifier refuses mismatched expected TS',
  () =>
    verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes(
      terminalRawBytes,
      {
        expectedArtifactBodySha256: terminalArtifactSha256,
        expectedServiceArtifactBodySha256: serviceArtifactSha256,
        expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
        expectedSourceBinding: sourceBinding,
        expectedTerminalArtifactSchemaContractSha256: digest('wrong-terminal-schema'),
        ...expectedCrossing,
      }
    ),
  'expected terminal schema contract mismatch'
);

const tamperedTerminal = clone(terminalArtifact);
tamperedTerminal.payload.verification_projection.crossing_evidence_body_sha256 =
  digest('detached-crossing-evidence');
const { integrity: ignoredTerminalIntegrity, ...tamperedTerminalBody } =
  tamperedTerminal;
void ignoredTerminalIntegrity;
tamperedTerminal.integrity = {
  algorithm: 'SHA-256',
  body_sha256: sha256hex(canonicalize(tamperedTerminalBody)),
};
throws(
  'terminal verifier refuses detached crossing evidence identity',
  () =>
    verifyProtectedRecordsReplacementTerminalArtifactV2RawBytes(
      Buffer.from(canonicalize(tamperedTerminal), 'utf8'),
      {
        expectedArtifactBodySha256: tamperedTerminal.integrity.body_sha256,
        expectedServiceArtifactBodySha256: serviceArtifactSha256,
        expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
        expectedSourceBinding: sourceBinding,
        expectedTerminalArtifactSchemaContractSha256: terminalSchemaSha256,
        ...expectedCrossing,
      }
    ),
  'crossing evidence hash mismatch'
);

const alternateInputs = {
  ...crossingInputs,
  recordUpdateSha256: digest('alternate-record-update'),
};
const alternateExpected = expectedCrossingOptions(alternateInputs);
const alternateService = buildProtectedRecordsReplacementServiceArtifactV2({
  crossingEvidence: buildProtectedRecordsReplacementCrossingEvidenceV2(alternateInputs),
  expectedServiceArtifactSchemaContractSha256: serviceSchemaSha256,
  sourceBinding,
  ...alternateExpected,
});
const alternateServiceRawBytes =
  canonicalProtectedRecordsReplacementArtifactBytesV2(alternateService);
throws(
  'central artifact set refuses alternate service lineage',
  () =>
    verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes({
      expectedManifestArtifactBodySha256: manifestSha256,
      manifestRawBytes,
      serviceArtifactRawBytes: alternateServiceRawBytes,
      terminalArtifactRawBytes: terminalRawBytes,
    }),
  'body identity mismatch'
);

const tamperedManifest = clone(manifest);
tamperedManifest.payload.artifact_binding.service_artifact_body_sha256 =
  alternateService.integrity.body_sha256;
const { integrity: ignoredIntegrity, ...tamperedManifestBody } = tamperedManifest;
void ignoredIntegrity;
tamperedManifest.integrity = {
  algorithm: 'SHA-256',
  body_sha256: sha256hex(canonicalize(tamperedManifestBody)),
};
throws(
  'central artifact set refuses a self-consistent but unpinned manifest',
  () =>
    verifyProtectedRecordsReplacementArtifactSetV2FromRawBytes({
      expectedManifestArtifactBodySha256: manifestSha256,
      manifestRawBytes: Buffer.from(canonicalize(tamperedManifest), 'utf8'),
      serviceArtifactRawBytes: alternateServiceRawBytes,
      terminalArtifactRawBytes: terminalRawBytes,
    }),
  'body identity mismatch'
);

throws(
  'downstream projection refuses undeclared consumer',
  () =>
    buildProtectedRecordsReplacementDownstreamProjectionV2(
      'legacy-positive-runner',
      rawArtifactSet
    ),
  'not declared'
);
throws(
  'downstream projection refuses detached verification JSON',
  () =>
    buildProtectedRecordsReplacementDownstreamProjectionV2(
      'local-proof-pack',
      artifactSetVerification
    ),
  'downstream raw artifact set keys must be exactly'
);

const consequenceNode = callGraphDescriptor.consequence_node;
equal(
  'runtime v2 source function is the only consequence node',
  'runtime_service_v2',
  consequenceNode
);
equal(
  'runtime consequence node names the positive source boundary',
  'createProtectedRecordsRuntimeServiceV2',
  callGraphDescriptor.nodes.find((node) => node.id === consequenceNode)?.source_symbol
);
equal(
  'accepted runtime result has one pure crossing-input mapper',
  'pure-mapper',
  callGraphDescriptor.nodes.find((node) => node.id === 'runtime_crossing_inputs_mapper_v2')?.kind
);
equal(
  'accepted runtime result has one pure source-binding mapper',
  'pure-mapper',
  callGraphDescriptor.nodes.find((node) => node.id === 'runtime_source_binding_mapper_v2')?.kind
);
const forbiddenConsumerEdges = callGraphDescriptor.forbidden_edges.filter(
  (edge) => edge.from.startsWith('downstream_') && edge.to === consequenceNode
);
equal(
  'all named downstream consumers have forbidden consequence back-edges',
  PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2.length,
  forbiddenConsumerEdges.length
);
equal(
  'only the authorized executor has a permitted consequence-result edge',
  1,
  callGraphDescriptor.edges.filter(
    (edge) => edge.from === consequenceNode
  ).length
);
equal(
  'only the non-dispatched exact-source child may enter the consequence executor',
  1,
  callGraphDescriptor.edges.filter(
    (edge) =>
      edge.to === consequenceNode &&
      edge.from === 'replacement_runtime_child_v2'
  ).length
);
equal(
  'direct internal-child invocation is explicitly outside coverage',
  'outside-defined-governed-route',
  callGraphDescriptor.coverage_boundary.excluded_paths.find((item) =>
    item.path.includes('protected-records-replacement-runtime-child-v2.mjs')
  )?.mapping
);
equal(
  'call graph does not claim side-door closure',
  false,
  callGraphDescriptor.coverage_boundary.side_door_closure_proven
);
equal(
  'call graph binds directional 0-through-300 relay invariant',
  true,
  callGraphDescriptor.invariants.includes(
    'the crossing binding carries confirmation-confirmed and holder-observed epochs and independently enforces their directional inclusive relay delay from 0 through 300 seconds'
  )
);
equal(
  'consequence executor has exactly one permitted incoming edge total',
  1,
  callGraphDescriptor.edges.filter((edge) => edge.to === consequenceNode).length
);
equal(
  'accepted result must cross write-once persistence before mappers',
  1,
  callGraphDescriptor.edges.filter(
    (edge) =>
      edge.from === 'authorized_crossing_result' &&
      edge.to === 'accepted_result_persistence_v2'
  ).length
);
equal(
  'independent verifier has a forbidden consequence back-edge',
  1,
  callGraphDescriptor.forbidden_edges.filter(
    (edge) =>
      edge.from === 'independent_artifact_set_verifier_cli_v2' &&
      edge.to === consequenceNode
  ).length
);
const nodeIds = callGraphDescriptor.nodes.map((node) => node.id);
equal('call-graph node ids are unique', nodeIds.length, new Set(nodeIds).size);
const nodeIdSet = new Set(nodeIds);
for (const edge of [
  ...callGraphDescriptor.edges,
  ...callGraphDescriptor.forbidden_edges,
]) {
  ok(`call-graph edge source exists: ${edge.from}`, nodeIdSet.has(edge.from));
  ok(`call-graph edge target exists: ${edge.to}`, nodeIdSet.has(edge.to));
}
const remainingEdges = callGraphDescriptor.edges.map((edge) => ({ ...edge }));
const indegree = new Map(nodeIds.map((id) => [id, 0]));
for (const edge of remainingEdges) {
  indegree.set(edge.to, indegree.get(edge.to) + 1);
}
const ready = nodeIds.filter((id) => indegree.get(id) === 0);
let visited = 0;
while (ready.length > 0) {
  const id = ready.shift();
  visited += 1;
  for (const edge of remainingEdges.filter((item) => item.from === id)) {
    indegree.set(edge.to, indegree.get(edge.to) - 1);
    if (indegree.get(edge.to) === 0) ready.push(edge.to);
  }
}
equal('permitted no-reexecution graph is acyclic', nodeIds.length, visited);
for (const node of callGraphDescriptor.nodes.filter((item) =>
  [
    'pure-mapper',
    'pure-builder',
    'verification-only',
    'verification-only-builder',
    'verification-only-entrypoint',
    'declared-verification-only-consumer',
    'pure-post-effect-lifecycle-closeout-builder',
    'post-effect-lifecycle-state-write',
    'write-once-post-effect-evidence-boundary',
  ].includes(item.kind)
)) {
  equal(
    `${node.id} has one forbidden consequence back-edge`,
    1,
    callGraphDescriptor.forbidden_edges.filter(
      (edge) => edge.from === node.id && edge.to === consequenceNode
    ).length
  );
}

const sourceFiles = [
  'lib/protected-records-replacement-artifacts-v2.mjs',
  'lib/protected-records-replacement-artifact-set-v2.mjs',
  'lib/sha256.mjs',
];
const forbiddenSourcePattern =
  /runProtectedRecords|runLocalProofPack|generateKeyPair|signReceipt|writeFileSync|readFileSync|spawnSync|node:child_process|from ['"]node:fs['"]/;
for (const sourceFile of sourceFiles) {
  const source = readFileSync(sourceFile, 'utf8');
  ok(`${sourceFile} has no positive-runner or filesystem capability`, !forbiddenSourcePattern.test(source));
  ok(`${sourceFile} has no embedded sample SHA-256 identity`, !/[a-f0-9]{64}/.test(source));
}
equal(
  'replacement artifacts do not transitively import receipt signing module',
  false,
  readFileSync('lib/protected-records-replacement-artifacts-v2.mjs', 'utf8')
    .includes("from './receipt.mjs'")
);
equal(
  'artifact set does not transitively import receipt signing module',
  false,
  readFileSync('lib/protected-records-replacement-artifact-set-v2.mjs', 'utf8')
    .includes("from './receipt.mjs'")
);

const crossingDriverSource = readFileSync(
  'lib/protected-records-replacement-crossing-cli-v2.mjs',
  'utf8'
);
const crossingBootstrapSource = readFileSync(
  'bin/zlar-protected-records-replacement-crossing-v2',
  'utf8'
);
const independentVerifierSource = readFileSync(
  'bin/zlar-protected-records-replacement-artifact-set-v2',
  'utf8'
);
equal(
  'crossing driver exposes no caller consequence clock option',
  false,
  crossingDriverSource.includes('--now-epoch')
);
equal(
  'crossing driver has one runtime child invocation expression',
  1,
  (crossingDriverSource.match(/\[sourceSnapshot\.runtimeServicePath, '--config', runtimeConfigPath\]/g) || []).length
);
ok(
  'crossing driver persists accepted result before artifact composition',
  crossingDriverSource.indexOf("'20-runtime-service-result-v2.canonical.json'") <
    crossingDriverSource.indexOf(
      'const artifacts = composeProtectedRecordsReplacementArtifactSetFromResultV2'
    )
);
ok(
  'crossing driver pins central manifest after service and terminal artifacts',
  crossingDriverSource.indexOf('writeOnce(servicePath') <
    crossingDriverSource.indexOf('writeOnce(manifestPath') &&
    crossingDriverSource.indexOf('writeOnce(terminalPath') <
      crossingDriverSource.indexOf('writeOnce(manifestPath')
);
ok(
  'crossing driver forbids automatic retry in source',
  crossingDriverSource.includes('automatic_retry_allowed: false')
);
ok(
  'crossing bootstrap removes inherited Node loader authority',
  crossingBootstrapSource.includes("exec /usr/bin/env -i") &&
    !crossingBootstrapSource.includes('NODE_OPTIONS=') &&
    !crossingBootstrapSource.includes('NODE_PATH=')
);
for (const forbidden of [
  'protected-records-runtime-profile.mjs',
  'protected-records-replacement-crossing-driver-v2.mjs',
  'node:child_process',
  'spawnSync',
  'Date.now',
  'signReceipt',
  'generateKeyPair',
]) {
  equal(
    `independent verifier excludes ${forbidden}`,
    false,
    independentVerifierSource.includes(forbidden)
  );
}

const cliScratch = mkdtempSync(join(tmpdir(), 'zlar-replacement-v2-cli-'));
try {
  const manifestPath = join(cliScratch, 'manifest.json');
  const servicePath = join(cliScratch, 'service.json');
  const terminalPath = join(cliScratch, 'terminal.json');
  writeFileSync(manifestPath, manifestRawBytes);
  writeFileSync(servicePath, serviceRawBytes);
  writeFileSync(terminalPath, terminalRawBytes);
  const verifierPath = fileURLToPath(
    new URL('../bin/zlar-protected-records-replacement-artifact-set-v2', import.meta.url)
  );
  const verifierRun = spawnSync(
    process.execPath,
    [
      verifierPath,
      'verify',
      '--manifest', manifestPath,
      '--service', servicePath,
      '--terminal', terminalPath,
      '--require-manifest-sha', manifestSha256,
      '--require-grant-sha', crossingInputs.authorityGrantContractSha256,
      '--require-manifest-schema-sha',
      protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2(),
      '--consumer', 'all',
      '--json',
    ],
    { encoding: 'utf8' }
  );
  equal('independent verifier exits zero', 0, verifierRun.status);
  const verifierResult = JSON.parse(verifierRun.stdout);
  equal('independent verifier verifies', true, verifierResult.verified);
  equal(
    'independent verifier does not reexecute',
    false,
    verifierResult.consequence_reexecution_performed
  );
  equal(
    'independent verifier emits every declared projection',
    PROTECTED_RECORDS_REPLACEMENT_DOWNSTREAM_CONSUMER_IDS_V2.length,
    Object.keys(verifierResult.downstream_projections).length
  );

  const wrongGrantRun = spawnSync(
    process.execPath,
    [
      verifierPath,
      'verify',
      '--manifest', manifestPath,
      '--service', servicePath,
      '--terminal', terminalPath,
      '--require-manifest-sha', manifestSha256,
      '--require-grant-sha', 'f'.repeat(64),
      '--require-manifest-schema-sha',
      protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2(),
      '--consumer', 'all',
      '--json',
    ],
    { encoding: 'utf8' }
  );
  equal('independent verifier wrong G exits nonzero', 1, wrongGrantRun.status);
  equal('independent verifier wrong G emits no result', '', wrongGrantRun.stdout);

  for (const [label, flag, value, expectedStatus] of [
    ['wrong manifest SHA', '--require-manifest-sha', 'e'.repeat(64), 1],
    ['wrong manifest schema SHA', '--require-manifest-schema-sha', 'e'.repeat(64), 1],
    ['undeclared consumer', '--consumer', 'legacy-positive-runner', 2],
  ]) {
    const args = [
      verifierPath,
      'verify',
      '--manifest', manifestPath,
      '--service', servicePath,
      '--terminal', terminalPath,
      '--require-manifest-sha', manifestSha256,
      '--require-grant-sha', crossingInputs.authorityGrantContractSha256,
      '--require-manifest-schema-sha',
      protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2(),
      '--consumer', 'all',
      '--json',
    ];
    args[args.indexOf(flag) + 1] = value;
    const refusal = spawnSync(process.execPath, args, { encoding: 'utf8' });
    equal(`independent verifier ${label} exits refusal`, expectedStatus, refusal.status);
    equal(`independent verifier ${label} emits no result`, '', refusal.stdout);
  }

  const manifestSymlink = join(cliScratch, 'manifest-link.json');
  symlinkSync(manifestPath, manifestSymlink);
  const symlinkRun = spawnSync(
    process.execPath,
    [
      verifierPath,
      'verify',
      '--manifest', manifestSymlink,
      '--service', servicePath,
      '--terminal', terminalPath,
      '--require-manifest-sha', manifestSha256,
      '--require-grant-sha', crossingInputs.authorityGrantContractSha256,
      '--require-manifest-schema-sha',
      protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2(),
      '--consumer', 'all',
      '--json',
    ],
    { encoding: 'utf8' }
  );
  equal('independent verifier symlink refuses', 1, symlinkRun.status);

  const tamperedServicePath = join(cliScratch, 'service-tampered.json');
  const tamperedService = Buffer.from(serviceRawBytes);
  tamperedService[tamperedService.length - 1] = 0x20;
  writeFileSync(tamperedServicePath, tamperedService);
  const tamperRun = spawnSync(
    process.execPath,
    [
      verifierPath,
      'verify',
      '--manifest', manifestPath,
      '--service', tamperedServicePath,
      '--terminal', terminalPath,
      '--require-manifest-sha', manifestSha256,
      '--require-grant-sha', crossingInputs.authorityGrantContractSha256,
      '--require-manifest-schema-sha',
      protectedRecordsReplacementArtifactSetManifestSchemaContractSha256V2(),
      '--consumer', 'all',
      '--json',
    ],
    { encoding: 'utf8' }
  );
  equal('independent verifier tampered bytes refuse', 1, tamperRun.status);

  const crossingPath = fileURLToPath(
    new URL('../bin/zlar-protected-records-replacement-crossing-v2', import.meta.url)
  );
  const forbiddenOutput = join(cliScratch, 'forbidden-output');
  const callerClockRun = spawnSync(
    crossingPath,
    [
      'cross-and-pin',
      '--now-epoch', '1',
      '--output-dir', forbiddenOutput,
    ],
    { encoding: 'utf8' }
  );
  equal('crossing CLI caller clock exits usage refusal', 2, callerClockRun.status);
  equal('crossing CLI caller clock creates no output', false, existsSync(forbiddenOutput));
} finally {
  rmSync(cliScratch, { recursive: true, force: true });
}

console.log(
  `protected records replacement artifact route v2: ${assertions}/${assertions} assertions passed`
);
