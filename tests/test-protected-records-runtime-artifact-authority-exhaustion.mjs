import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  formatProtectedRecordsRuntimeActivationPreflightArtifactVerification,
  verifyProtectedRecordsRuntimeActivationPreflightArtifact,
} from '../lib/protected-records-runtime-activation-preflight.mjs';
import {
  formatProtectedRecordsRuntimeLocalActivationArtifactVerification,
  verifyProtectedRecordsRuntimeLocalActivationArtifact,
} from '../lib/protected-records-runtime-local-activation.mjs';
import {
  formatProtectedRecordsRuntimeProfileInstallationArtifactVerification,
  verifyProtectedRecordsRuntimeProfileInstallationArtifact,
} from '../lib/protected-records-runtime-profile-installation.mjs';

const CURRENT_GRANT_SHA256 =
  '0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba';
const EXHAUSTED_REASON_CODE = 'authority_grant_contract_exhausted';

const CASES = [
  {
    label: 'activation preflight',
    fixture:
      'tests/fixtures/protected-records-runtime-activation-preflight-artifact-v1.json',
    sha256: '1bc7b61e0b0f9e18d3a2bbdf8f7bfa9f1417e60cba027d20807ae893bce60c48',
    binary: 'bin/zlar-protected-records-runtime-activation-preflight',
    verify: verifyProtectedRecordsRuntimeActivationPreflightArtifact,
    format: formatProtectedRecordsRuntimeActivationPreflightArtifactVerification,
    assertHistorical(verification) {
      equal(
        'activation preflight historical proof run preserved',
        true,
        verification.historical_artifact_runtime_profile_proof_run
      );
      equal(
        'activation preflight proof run is not current authority',
        false,
        verification.runtime_profile_proof_run_is_current_authority_projection
      );
      equal(
        'activation preflight historical recognized effect preserved',
        true,
        verification.historical_artifact_recognized_write_accepted
      );
      equal(
        'activation preflight historical fixture effect preserved',
        true,
        verification.historical_artifact_fixture_authority_effect_observed
      );
    },
  },
  {
    label: 'runtime local activation',
    fixture:
      'tests/fixtures/protected-records-runtime-local-activation-artifact-v1.json',
    sha256: 'dbf2b182501a38c870377984d58c92ae28cfc857afa86fc9686dd90a64bd846b',
    binary: 'bin/zlar-protected-records-runtime-local-activation',
    verify: verifyProtectedRecordsRuntimeLocalActivationArtifact,
    format: formatProtectedRecordsRuntimeLocalActivationArtifactVerification,
    assertHistorical(verification) {
      equal(
        'runtime local activation historical recognized effect preserved',
        true,
        verification.historical_artifact_recognized_write_accepted
      );
      equal(
        'runtime local activation recognized effect is not current authority',
        false,
        verification.recognized_write_accepted_is_current_authority_projection
      );
      equal(
        'runtime local activation historical fixture effect preserved',
        true,
        verification.historical_artifact_fixture_authority_effect_observed
      );
    },
  },
  {
    label: 'runtime profile installation',
    fixture:
      'tests/fixtures/protected-records-runtime-profile-installation-artifact-v1.json',
    sha256: '5512d12a7320417f6499630557ec3c5993ffb88474ba2822891fb67e4f9bf88f',
    binary: 'bin/zlar-protected-records-runtime-profile-installation',
    verify: verifyProtectedRecordsRuntimeProfileInstallationArtifact,
    format: formatProtectedRecordsRuntimeProfileInstallationArtifactVerification,
    assertHistorical(verification) {
      equal(
        'runtime installation historical recognized effect preserved',
        true,
        verification.historical_artifact_recognized_write_accepted
      );
      equal(
        'runtime installation recognized effect is not current authority',
        false,
        verification.recognized_write_accepted_is_current_authority_projection
      );
      equal(
        'runtime installation historical fixture rightful assertion preserved',
        true,
        verification.historical_artifact_fixture_rightful_issuance_path_evidenced
      );
    },
  },
];

let assertions = 0;

function equal(label, expected, actual) {
  assertions += 1;
  if (actual !== expected) {
    throw new Error(
      `${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
    );
  }
}

function includes(label, text, expected) {
  assertions += 1;
  if (!text.includes(expected)) {
    throw new Error(`${label}: missing ${JSON.stringify(expected)}`);
  }
}

function readArtifact(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function verifyCli(testCase) {
  const result = spawnSync(
    process.execPath,
    [
      testCase.binary,
      'verify',
      '--sample',
      '--require-sha',
      testCase.sha256,
      '--json',
    ],
    { cwd: process.cwd(), encoding: 'utf8' }
  );
  equal(`${testCase.label} CLI exits zero`, 0, result.status);
  equal(`${testCase.label} CLI emits no stderr`, '', result.stderr);
  const verification = JSON.parse(result.stdout);
  equal(`${testCase.label} CLI exact identity`, testCase.sha256, verification.body_sha256);
  equal(
    `${testCase.label} CLI required identity matched`,
    true,
    verification.required_body_sha256_matched
  );
  return verification;
}

function assertHistoricalOnlyAuthorityProjection(testCase, verification) {
  equal(`${testCase.label} verified`, true, verification.verified);
  equal(`${testCase.label} exact artifact identity`, testCase.sha256, verification.body_sha256);
  equal(
    `${testCase.label} current status contract`,
    CURRENT_GRANT_SHA256,
    verification.authority_grant_status_contract_sha256
  );
  equal(`${testCase.label} artifact contract absent`, null, verification.artifact_authority_grant_contract_sha256);
  equal(`${testCase.label} artifact not bound to status`, false, verification.artifact_contract_bound_to_authority_status);
  equal(
    `${testCase.label} permanently historical without contract binding`,
    true,
    verification.historical_only_due_to_missing_artifact_grant_contract_binding
  );
  equal(`${testCase.label} current grant exhausted`, 'exhausted', verification.authority_grant_status);
  equal(`${testCase.label} fresh effect refused`, false, verification.authority_grant_fresh_effect_allowed);
  equal(
    `${testCase.label} repeated-use provenance invalid`,
    false,
    verification.authority_grant_repeated_use_provenance_valid
  );
  equal(
    `${testCase.label} fixture-rightful projection refused`,
    false,
    verification.authority_grant_status_allows_fixture_rightful_projection
  );
  equal(
    `${testCase.label} exhaustion reason`,
    EXHAUSTED_REASON_CODE,
    verification.authority_grant_status_reason_code
  );
  equal(
    `${testCase.label} current fixture-rightful false`,
    false,
    verification.fixture_rightful_issuance_path_evidenced
  );
  includes(
    `${testCase.label} claim is historical-only`,
    verification.claim_boundary,
    'historical embedded local'
  );
  testCase.assertHistorical(verification);
  const summary = testCase.format(verification);
  includes(`${testCase.label} summary names exhaustion`, summary, 'status=exhausted');
  includes(
    `${testCase.label} summary names missing artifact contract binding`,
    summary,
    'historical_only_missing_contract_binding=true'
  );
  includes(
    `${testCase.label} summary refuses current fixture rightful`,
    summary,
    'fixture_rightful_issuance_path_evidenced=false'
  );
}

for (const testCase of CASES) {
  const artifact = readArtifact(testCase.fixture);
  const directVerification = testCase.verify(artifact);
  assertHistoricalOnlyAuthorityProjection(testCase, directVerification);
  const cliVerification = verifyCli(testCase);
  assertHistoricalOnlyAuthorityProjection(testCase, cliVerification);
}

console.log(
  `protected records runtime artifact authority exhaustion: ${assertions}/${assertions} assertions passed`
);
