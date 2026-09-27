#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import {
  formatProtectedRecordsInstalledRuntimeProfileRecognitionProofSummary,
} from '../lib/protected-records-installed-runtime-profile-recognition-proof.mjs';
import {
  formatProtectedRecordsInstalledRuntimeProfileServiceProofSummary,
} from '../lib/protected-records-installed-runtime-profile-service-proof.mjs';
import {
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainSummary,
} from '../lib/protected-records-installed-runtime-profile-terminal-chain.mjs';
import {
  formatProtectedRecordsRuntimeProfileInstallationProofSummary,
} from '../lib/protected-records-runtime-profile-installation.mjs';
import {
  formatLocalProofPackSummary,
} from '../lib/local-proof-pack.mjs';

function readJson(path) {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
}

let passed = 0;
let failed = 0;

function assert(label, condition) {
  if (condition) {
    passed += 1;
    console.log(`PASS: ${label}`);
  } else {
    failed += 1;
    console.error(`FAIL: ${label}`);
  }
}

function assertHistoricalFormatter(label, output) {
  assert(
    `${label} labels the embedded positive field as historical`,
    output.includes('historical_artifact_fixture_rightful_issuance_path_recorded=true'),
  );
  assert(
    `${label} forces current fixture-rightful projection false`,
    output.includes('current_fixture_rightful_issuance_path_evidenced=false'),
  );
}

const recognitionArtifact = readJson(
  './fixtures/protected-records-installed-runtime-profile-recognition-proof-artifact-v1.json',
);
assertHistoricalFormatter(
  'recognition raw formatter',
  formatProtectedRecordsInstalledRuntimeProfileRecognitionProofSummary(
    recognitionArtifact.payload.proof,
  ),
);

const serviceArtifact = readJson(
  './fixtures/protected-records-installed-runtime-profile-service-proof-artifact-v1.json',
);
assertHistoricalFormatter(
  'service raw formatter',
  formatProtectedRecordsInstalledRuntimeProfileServiceProofSummary(
    serviceArtifact.payload.proof,
  ),
);

const terminalArtifact = readJson(
  './fixtures/protected-records-installed-runtime-profile-terminal-chain-artifact-v1.json',
);
const terminalOutput =
  formatProtectedRecordsInstalledRuntimeProfileTerminalChainSummary(
    terminalArtifact.payload.chain,
  );
assertHistoricalFormatter('terminal raw formatter', terminalOutput);
assert(
  'terminal target binding also labels embedded rightful field as historical',
  terminalOutput.includes(
    'historical_artifact_fixture_rightful_issuance_path_recorded=true; current_fixture_rightful_issuance_path_evidenced=false',
  ),
);

const installationArtifact = readJson(
  './fixtures/protected-records-runtime-profile-installation-artifact-v1.json',
);
assertHistoricalFormatter(
  'runtime installation raw formatter',
  formatProtectedRecordsRuntimeProfileInstallationProofSummary(
    installationArtifact.payload.proof,
    installationArtifact.payload.plan,
    installationArtifact.payload.runtime_profile,
  ),
);

const localProofPackArtifact = readJson(
  './fixtures/local-proof-pack-artifact-v1.json',
);
let localPackRefused = false;
try {
  formatLocalProofPackSummary(localProofPackArtifact.payload);
} catch (error) {
  localPackRefused = String(error?.message).includes(
    'permanently historical-only and cannot project current authority',
  );
}
assert(
  'local proof-pack raw formatter refuses the legacy schema',
  localPackRefused,
);

let injectedGrantBindingRefused = false;
try {
  formatLocalProofPackSummary({
    ...localProofPackArtifact.payload,
    artifact_bound_authority_grant_contract_sha256:
      '0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba',
  });
} catch (error) {
  injectedGrantBindingRefused = String(error?.message).includes(
    'permanently historical-only and cannot project current authority',
  );
}
assert(
  'injected SHA-shaped metadata cannot revive the legacy raw formatter',
  injectedGrantBindingRefused,
);

console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
