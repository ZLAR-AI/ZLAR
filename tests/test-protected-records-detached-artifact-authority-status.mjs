import { readFileSync } from 'node:fs';
import {
  formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification,
  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact,
} from '../lib/protected-records-installed-runtime-profile-recognition-proof.mjs';
import {
  formatProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification,
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification,
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';

const RECOGNITION_ARTIFACT_SHA256 =
  '502f303f094bc213a03208ae7edcb490edddd3b7f2e20698915b6010a2ec26c3';
const SOURCE_PREFLIGHT_ARTIFACT_SHA256 =
  '2b5427aec78c63cc9768bb25ed8cdde316d4b8e3f07dac11c80baa54e1b71bec';
const SERVICE_ARTIFACT_SHA256 =
  '3e6bac95ba0a6b41d0ac53c16d598a22d47c871757473025a550556626f5fea8';
const TERMINAL_ARTIFACT_SHA256 =
  '0f8db51f11885e7867c6f0fa4d737adf51774e7cd9ad711cd2073b5b684c303f';

let assertions = 0;

function assertEqual(label, expected, actual) {
  assertions += 1;
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertIncludes(label, text, expected) {
  assertions += 1;
  if (!text.includes(expected)) {
    throw new Error(`${label}: missing ${JSON.stringify(expected)}`);
  }
}

function readArtifact(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function assertExhaustedPinnedProjection(label, verification) {
  assertEqual(`${label} verified`, true, verification.verified);
  assertEqual(
    `${label} structural self-integrity`,
    true,
    verification.structural_self_integrity_verified
  );
  assertEqual(`${label} exact artifact identity matched`, true, verification.artifact_identity_sha256_matched);
  assertEqual(`${label} historical boarded fact preserved`, true, verification.recognized_write_boarded);
  assertEqual(`${label} authority status`, 'exhausted', verification.authority_grant_status);
  assertEqual(`${label} fresh effect refused`, false, verification.authority_grant_fresh_effect_allowed);
  assertEqual(
    `${label} repeated-use provenance invalid`,
    false,
    verification.authority_grant_repeated_use_provenance_valid
  );
  assertEqual(
    `${label} status refuses fixture-rightful projection`,
    false,
    verification.authority_grant_status_allows_fixture_rightful_projection
  );
  assertEqual(
    `${label} exhaustion reason`,
    'authority_grant_contract_exhausted',
    verification.authority_grant_status_reason_code
  );
  assertEqual(
    `${label} current fixture-rightful projection withheld`,
    false,
    verification.fixture_rightful_issuance_path_evidenced
  );
}

const recognitionArtifact = readArtifact(
  'tests/fixtures/protected-records-installed-runtime-profile-recognition-proof-artifact-v1.json'
);
const serviceArtifact = readArtifact(
  'tests/fixtures/protected-records-installed-runtime-profile-service-proof-artifact-v1.json'
);
const terminalArtifact = readArtifact(
  'tests/fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json'
);

assertEqual(
  'committed recognition artifact identity',
  RECOGNITION_ARTIFACT_SHA256,
  recognitionArtifact.integrity.body_sha256
);
assertEqual(
  'committed service artifact identity',
  SERVICE_ARTIFACT_SHA256,
  serviceArtifact.integrity.body_sha256
);
assertEqual(
  'committed terminal artifact identity',
  TERMINAL_ARTIFACT_SHA256,
  terminalArtifact.integrity.body_sha256
);

const recognitionStructural =
  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(
    recognitionArtifact
  );
assertEqual(
  'recognition structural-only boarding withheld',
  false,
  recognitionStructural.recognized_write_boarded
);
assertEqual(
  'recognition structural-only fixture-rightful projection withheld',
  false,
  recognitionStructural.fixture_rightful_issuance_path_evidenced
);

const recognitionPinned =
  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(
    recognitionArtifact,
    {
      expectedArtifactBodySha256: RECOGNITION_ARTIFACT_SHA256,
      expectedSourcePreflightBodySha256: SOURCE_PREFLIGHT_ARTIFACT_SHA256,
    }
  );
assertExhaustedPinnedProjection('recognition', recognitionPinned);
assertEqual(
  'recognition historical state append preserved',
  1,
  recognitionPinned.recognized_write_state_entry_delta
);
assertEqual(
  'recognition refusal history preserved',
  true,
  recognitionPinned.all_refusals_before_mutation
);
assertIncludes(
  'recognition formatted exhaustion status',
  formatProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifactVerification(
    recognitionPinned
  ),
  'status=exhausted'
);

const serviceStructural =
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(serviceArtifact);
assertEqual(
  'service structural-only boarding withheld',
  false,
  serviceStructural.recognized_write_boarded
);
assertEqual(
  'service structural-only fixture-rightful projection withheld',
  false,
  serviceStructural.fixture_rightful_issuance_path_evidenced
);

const servicePinned =
  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(
    serviceArtifact,
    { expectedArtifactBodySha256: SERVICE_ARTIFACT_SHA256 }
  );
assertExhaustedPinnedProjection('service', servicePinned);
assertEqual(
  'service historical state append preserved',
  1,
  servicePinned.recognized_write_state_append_count
);
assertEqual(
  'service recognition-refusal history preserved',
  true,
  servicePinned.all_recognition_refusals_before_mutation
);
assertEqual(
  'service authority-refusal history preserved',
  true,
  servicePinned.all_authority_refusals_before_consumption_and_mutation
);
assertIncludes(
  'service formatted exhaustion reason',
  formatProtectedRecordsInstalledRuntimeProfileServiceProofArtifactVerification(
    servicePinned
  ),
  'reason_code=authority_grant_contract_exhausted'
);

const terminalStructural =
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    terminalArtifact
  );
assertEqual(
  'terminal structural-only boarding withheld',
  false,
  terminalStructural.recognized_write_boarded
);
assertEqual(
  'terminal structural-only fixture-rightful projection withheld',
  false,
  terminalStructural.fixture_rightful_issuance_path_evidenced
);

const terminalPinned =
  verifyProtectedRecordsInstalledRuntimeProfileTerminalChainArtifact(
    terminalArtifact,
    { expectedArtifactBodySha256: TERMINAL_ARTIFACT_SHA256 }
  );
assertExhaustedPinnedProjection('terminal', terminalPinned);
assertEqual(
  'terminal recognition-refusal history preserved',
  true,
  terminalPinned.all_required_recognition_refusals_before_mutation
);
assertEqual(
  'terminal authority-refusal history preserved',
  true,
  terminalPinned.all_required_authority_refusals_before_consumption_and_mutation
);
assertIncludes(
  'terminal formatted fixture-rightful refusal',
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainArtifactVerification(
    terminalPinned
  ),
  'allows_fixture_rightful_projection=false'
);

console.log(
  `protected records detached artifact authority status: ${assertions}/${assertions} assertions passed`
);
