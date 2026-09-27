#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  assertGovernedSurfaceCoverageMap,
  buildGovernedSurfaceCoverageMap,
} from '../lib/governed-surface-coverage-map.mjs';
import {
  LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256,
  NON_CLAIMS,
  SAFE_CLAIM_CEILING,
  assertLocalProofPack,
  assertLocalProofPackArtifact,
  parseLocalProofPackArtifactText,
  verifyLocalProofPackArtifact,
} from '../lib/local-proof-pack.mjs';
import {
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
} from '../lib/protected-records-fixture-authority-status.mjs';
let passed = 0;
let failed = 0;

function assert(label, condition, detail = '') {
  if (condition) {
    passed += 1;
    console.log(`  PASS: ${label}`);
    return;
  }
  failed += 1;
  console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
}

function assertEqual(label, expected, actual) {
  assert(
    label,
    expected === actual,
    `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`
  );
}

function assertThrows(label, fn, expectedMessageFragment) {
  try {
    fn();
    assert(label, false, 'expected throw');
  } catch (error) {
    assert(
      label,
      String(error.message).includes(expectedMessageFragment),
      String(error.message)
    );
  }
}

function currentStaticCoveragePayload(artifact, coverageReport) {
  const payload = structuredClone(artifact.payload);
  payload.safe_claim_ceiling = SAFE_CLAIM_CEILING;
  payload.non_claims = [...NON_CLAIMS];
  const coverageIndex = payload.components.findIndex(
    (item) => item.component === 'governed_surface_coverage_map'
  );
  const terminalSurface = coverageReport.surfaces.find(
    (item) =>
      item.surface_id ===
      'protected-records.installed-runtime-profile.terminal-chain.records.write'
  );
  payload.components[coverageIndex] = {
    ...payload.components[coverageIndex],
    report_type: coverageReport.report_type,
    evidence_model: coverageReport.evidence_model.source,
    live_probing: coverageReport.evidence_model.live_probing_performed,
    governed_lanes: coverageReport.counts.governed_lanes,
    counted_lanes: coverageReport.counts.counted_lanes,
    boundary_entries: coverageReport.counts.boundary_entries,
    terminal_artifact_body_sha256:
      terminalSurface.evidence.validation.body_sha256,
    terminal_artifact_expected_body_sha256:
      terminalSurface.evidence.validation.expected_body_sha256,
    terminal_artifact_identity_sha256_matched:
      terminalSurface.evidence.validation.artifact_identity_sha256_matched,
    terminal_outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256:
      terminalSurface.evidence.validation
        .outer_fixture_metadata_bound_to_expected_terminal_artifact_sha256,
    terminal_recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256:
      terminalSurface.evidence.receipt
        .recognized_receipt_source_identity_bound_to_expected_terminal_artifact_sha256,
    terminal_trusted_issuer_registry_signature_valid:
      terminalSurface.evidence.trusted_issuer_registry.signature_valid,
    terminal_fixture_rightful_issuance_path_evidenced:
      terminalSurface.evidence.rightful_issuance
        .fixture_rightful_issuance_path_evidenced,
  };
  return payload;
}

function coherentlyResealedLegacyCoverageArtifact(artifact) {
  const copy = structuredClone(artifact);
  const coverage = copy.payload.components.find(
    (item) => item.component === 'governed_surface_coverage_map'
  );
  coverage.boundary_entries = 11;
  const manifestItem = copy.component_manifest.find(
    (item) => item.component === 'governed_surface_coverage_map'
  );
  manifestItem.component_sha256 = createHash('sha256')
    .update(canonicalize(coverage), 'utf8')
    .digest('hex');
  const { integrity, ...body } = copy;
  copy.integrity = {
    ...integrity,
    body_sha256: createHash('sha256')
      .update(canonicalize(body), 'utf8')
      .digest('hex'),
  };
  return copy;
}

console.log('\n-- committed historical artifact --');
const sampleText = readFileSync(
  'tests/fixtures/local-proof-pack-artifact-v1.json',
  'utf8'
);
const artifact = parseLocalProofPackArtifactText(sampleText);
assert('exact committed historical artifact validates', assertLocalProofPackArtifact(artifact));
assertEqual(
  'exact committed historical artifact body identity is pinned',
  LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256,
  artifact.integrity.body_sha256
);

console.log('\n-- current static coverage schema --');
const coverageInput = JSON.parse(
  readFileSync('tests/fixtures/governed-surface-coverage-map-v1-input.json', 'utf8')
);
const coverageReport = buildGovernedSurfaceCoverageMap(coverageInput);
assert('current static coverage report validates', assertGovernedSurfaceCoverageMap(coverageReport));
const currentPayload = currentStaticCoveragePayload(artifact, coverageReport);
assert('current static 4/6 coverage payload validates', assertLocalProofPack(currentPayload));
const currentCoverage = currentPayload.components.find(
  (item) => item.component === 'governed_surface_coverage_map'
);
assertEqual('current static governed lanes', 4, currentCoverage.governed_lanes);
assertEqual('current static counted lanes', 6, currentCoverage.counted_lanes);
assertEqual(
  'current static terminal fixture rightful path is demoted',
  false,
  currentCoverage.terminal_fixture_rightful_issuance_path_evidenced
);
const overclaimingCurrentPayload = structuredClone(currentPayload);
overclaimingCurrentPayload.components.find(
  (item) => item.component === 'governed_surface_coverage_map'
).terminal_fixture_rightful_issuance_path_evidenced = true;
assertThrows(
  'current static coverage fixture-rightful overclaim is refused',
  () => assertLocalProofPack(overclaimingCurrentPayload),
  'coverage component drifted'
);
const unversionedGrantBindingPayload = structuredClone(currentPayload);
unversionedGrantBindingPayload.components.find(
  (item) => item.component === 'governed_surface_coverage_map'
).authority_grant_contract_sha256 =
  PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256;
assertThrows(
  'current schema cannot silently add a grant binding without a schema revision',
  () => assertLocalProofPack(unversionedGrantBindingPayload),
  'unexpected fields'
);
assertThrows(
  'coherently resealed legacy coverage schema is not accepted as the pinned historical artifact',
  () => assertLocalProofPackArtifact(coherentlyResealedLegacyCoverageArtifact(artifact)),
  'safe claim ceiling drifted'
);

console.log('\n-- unpinned read-only verification --');
const unpinned = verifyLocalProofPackArtifact(artifact);
assertEqual('unpinned verification performs no fresh proof run', false, unpinned.fresh_proof_pack_run_performed);
assertEqual('unpinned verification does not project artifact identity', false, unpinned.artifact_identity_sha256_matched);
assertEqual('authority grant is exhausted', 'exhausted', unpinned.authority_grant_status);
assertEqual('fresh effect is refused', false, unpinned.authority_grant_fresh_effect_allowed);
assertEqual('repeated-use provenance is invalid', false, unpinned.authority_grant_repeated_use_provenance_valid);
assertEqual('fixture-rightful projection is refused', false, unpinned.authority_grant_status_allows_fixture_rightful_projection);
assertEqual('historical artifact embeds no grant contract identity', null, unpinned.embedded_authority_grant_contract_sha256);
assertEqual('historical artifact grant identity is not bound', false, unpinned.authority_grant_contract_identity_bound_by_artifact);
assertEqual('historical artifact fixture-rightful projection is invariant false', false, unpinned.fixture_rightful_issuance_projection_allowed);
assertEqual('exhaustion reason is exact', 'authority_grant_contract_exhausted', unpinned.authority_grant_status_reason_code);
assertEqual('embedded coverage schema is historical', 'historical-pre-exhaustion-coverage-component-v1', unpinned.coverage.embedded_coverage_schema);
assertEqual('embedded 6/6 counts are named historical', true, unpinned.coverage.embedded_coverage_counts_historical);
assertEqual('current coverage counts are not claimed', false, unpinned.coverage.current_coverage_counts_claimed);
assertEqual('historical governed count preserved', 6, unpinned.coverage.governed_lanes);
assertEqual('historical counted count preserved', 6, unpinned.coverage.counted_lanes);
assertEqual('historical artifact lacks terminal identity projection', false, unpinned.coverage.terminal_claim_projection_allowed);
assertEqual('terminal fixture rightful projection withheld', false, unpinned.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assertEqual('runtime-local historical embedded field preserved', true, unpinned.runtime_local_activation.historical_embedded_fixture_rightful_issuance_path_evidenced);
assertEqual('runtime-local current fixture rightful projection withheld', false, unpinned.runtime_local_activation.fixture_rightful_issuance_path_evidenced);
assertEqual('runtime-install historical embedded field preserved', true, unpinned.runtime_profile_installation.historical_embedded_fixture_rightful_issuance_path_evidenced);
assertEqual('runtime-install current fixture rightful projection withheld', false, unpinned.runtime_profile_installation.fixture_rightful_issuance_path_evidenced);

console.log('\n-- exact-SHA read-only verification --');
const pinned = verifyLocalProofPackArtifact(artifact, {
  expectedArtifactBodySha256:
    LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256,
});
assertEqual('exact SHA preserves artifact identity', true, pinned.artifact_identity_sha256_matched);
assertEqual('exact SHA remains a historical coverage snapshot', true, pinned.coverage.embedded_coverage_counts_historical);
assertEqual('exact SHA does not make 6/6 current', false, pinned.coverage.current_coverage_counts_claimed);
assertEqual('exact SHA cannot restore terminal projection absent embedded binding', false, pinned.coverage.terminal_claim_projection_allowed);
assertEqual('exact SHA cannot restore fixture-rightful projection', false, pinned.coverage.terminal_fixture_rightful_issuance_path_evidenced);
assertEqual('exact SHA cannot create an absent grant identity binding', false, pinned.authority_grant_contract_identity_bound_by_artifact);
assertEqual('exact SHA leaves overall fixture-rightful projection false', false, pinned.fixture_rightful_issuance_projection_allowed);
assertEqual('exact SHA cannot restore runtime-local fixture-rightful projection', false, pinned.runtime_local_activation.fixture_rightful_issuance_path_evidenced);
assertEqual('exact SHA cannot restore runtime-install fixture-rightful projection', false, pinned.runtime_profile_installation.fixture_rightful_issuance_path_evidenced);
assertThrows(
  'wrong expected SHA is refused',
  () =>
    verifyLocalProofPackArtifact(artifact, {
      expectedArtifactBodySha256: '0'.repeat(64),
    }),
  'does not match required --require-sha value'
);

console.log('\n-- CLI read-only verification --');
const cli = spawnSync(
  process.execPath,
  [
    'bin/zlar-local-proof-pack',
    'verify',
    '--sample',
    '--require-sha',
    LOCAL_PROOF_PACK_HISTORICAL_SAMPLE_ARTIFACT_BODY_SHA256,
    '--json',
  ],
  { cwd: process.cwd(), encoding: 'utf8' }
);
assertEqual('CLI verification exits zero', 0, cli.status);
const cliVerification = cli.status === 0 ? JSON.parse(cli.stdout) : null;
assertEqual('CLI preserves exact artifact identity', true, cliVerification?.artifact_identity_sha256_matched);
assertEqual('CLI names historical 6/6 snapshot', true, cliVerification?.coverage.embedded_coverage_counts_historical);
assertEqual('CLI names exhausted authority grant', 'exhausted', cliVerification?.authority_grant_status);
assertEqual('CLI names absent grant identity binding', false, cliVerification?.authority_grant_contract_identity_bound_by_artifact);
assertEqual('CLI overall fixture-rightful projection remains false', false, cliVerification?.fixture_rightful_issuance_projection_allowed);
assertEqual('CLI withholds fixture-rightful projection', false, cliVerification?.coverage.terminal_fixture_rightful_issuance_path_evidenced);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
