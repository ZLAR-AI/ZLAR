import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
  ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
} from '../lib/protected-records-active-persistent-profile-preflight.mjs';
import {
  runActivePersistentProfileLifecycleEvidence,
} from '../lib/protected-records-active-persistent-profile-lifecycle.mjs';

function iso(epochMillis) {
  return new Date(epochMillis).toISOString();
}

export function writeMinimalReadinessReport(evidenceDir) {
  const report = {
    report_type: 'zlar-north-star-readiness-v1',
    result: 'NOT_READY_FOR_V3_4_0',
    counts: {
      historical_active_persistent_profile_lifecycle_provided: true,
      historical_active_persistent_profile_lifecycle_verified: true,
      historical_active_persistent_profile_lifecycle_expected_hashes_bound: true,
      historical_active_persistent_profile_lifecycle_non_scoring: true,
      historical_active_persistent_profile_lifecycle_current_installation: false,
      historical_active_persistent_profile_lifecycle_product_proof_path_completion: false,
      historical_active_persistent_profile_lifecycle_enterprise_deployment_profile_completion: false,
      historical_active_persistent_profile_lifecycle_current_machine_governance_general: false,
      historical_active_persistent_profile_lifecycle_production_downstream_recognition: false,
    },
    claim_boundary: {
      current_machine_governance: false,
      public_external_attestation: false,
      production_authority: false,
      enterprise_readiness: false,
    },
  };
  writeFileSync(
    join(evidenceDir, 'north-star-readiness.json'),
    `${JSON.stringify(report, null, 2)}\n`,
    { mode: 0o600 }
  );
}

export function createPrivateVerifierReadinessEvidence() {
  const scratch = mkdtempSync(join(tmpdir(), 'zlar-private-verifier-readiness-test-'));
  const activationRoot = join(
    scratch,
    'activation',
    'protected-records-private-operator-records-terminal'
  );
  const evidenceDir = join(scratch, 'evidence');
  mkdirSync(evidenceDir, { recursive: true });
  const runnerResult = runActivePersistentProfileLifecycleEvidence({
    activationRoot,
    outputDir: evidenceDir,
    profilePath: ACTIVE_PERSISTENT_PROFILE_CANONICAL_RUNTIME_PROFILE_SOURCE,
    runtimeProfileId: 'protected-records-disposable-runtime-profile',
    runtimeProfileSha256: ACTIVE_PERSISTENT_PROFILE_REQUIRED_RUNTIME_PROFILE_SHA256,
    expiresAt: iso(Date.now() + 60 * 60 * 1000),
    allowNamedLiveRoot: true,
    expectedLiveRoot: activationRoot,
  });
  writeFileSync(
    join(evidenceDir, 'runner-result.json'),
    `${JSON.stringify(runnerResult, null, 2)}\n`,
    { mode: 0o600 }
  );
  writeFileSync(
    join(evidenceDir, 'pre-replacement-status.json'),
    `${JSON.stringify({
      status_type: 'zlar-protected-records-active-persistent-profile-live-status-v1',
      activation_root_state: 'empty',
      active: false,
      safe_for_install: true,
    }, null, 2)}\n`,
    { mode: 0o600 }
  );
  writeFileSync(
    join(evidenceDir, 'post-lifecycle-status.json'),
    `${JSON.stringify({
      status_type: 'zlar-protected-records-active-persistent-profile-live-status-v1',
      activation_root_state: 'closed_inert_evidence',
      active: false,
      safe_for_install: false,
    }, null, 2)}\n`,
    { mode: 0o600 }
  );
  writeMinimalReadinessReport(evidenceDir);
  return {
    scratch,
    evidenceDir,
  };
}
