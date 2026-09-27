export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_STATUS_TYPE =
  'zlar-protected-records-fixture-authority-grant-status-v1';

export const PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256 =
  '0c074a8e96559a29fc23d2f18f6062d539e2a1ea5baa25d53b7ba4b8fec4eaba';

export const PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_EXHAUSTED_REASON_CODE =
  'authority_grant_contract_exhausted';

export const PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MUTATION_AUTHORITY_ABSENT_REASON_CODE =
  'active_persistent_profile_mutation_authority_absent';

export const PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS =
  Object.freeze({
    status_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_STATUS_TYPE,
    authority_grant_contract_sha256:
      PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256,
    status: 'exhausted',
    status_source: 'control-tower-contract-and-execution-evidence-reconciliation',
    maximum_effect_uses: 1,
    recorded_effect_uses: 1,
    fresh_effect_allowed: false,
    repeated_use_provenance_valid: false,
    fresh_fixture_rightful_projection_allowed: false,
    replacement_authority_grant_present: false,
  });

function assertSha256(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error('Protected records fixture authority status contract SHA-256 must be SHA-256 hex');
  }
}

export function protectedRecordsFixtureAuthorityGrantStatus(contractSha256) {
  assertSha256(contractSha256);
  if (
    contractSha256 ===
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256
  ) {
    return PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_STATUS;
  }
  return Object.freeze({
    status_type: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_STATUS_TYPE,
    authority_grant_contract_sha256: contractSha256,
    status: 'unrecognized',
    status_source: 'no-source-authorized-status-record',
    maximum_effect_uses: null,
    recorded_effect_uses: null,
    fresh_effect_allowed: false,
    repeated_use_provenance_valid: false,
    fresh_fixture_rightful_projection_allowed: false,
    replacement_authority_grant_present: false,
  });
}

export function protectedRecordsFixtureAuthorityGrantEffectStatusReason(
  contractSha256
) {
  const status = protectedRecordsFixtureAuthorityGrantStatus(contractSha256);
  if (status.fresh_effect_allowed === true) return null;
  if (status.status === 'exhausted') {
    return Object.freeze({
      code: PROTECTED_RECORDS_FIXTURE_AUTHORITY_GRANT_EXHAUSTED_REASON_CODE,
      message:
        'The exact one-use fixture authority grant is source-recorded as exhausted; fresh effect use and repeated-use fixture-rightful projection are refused.',
    });
  }
  return Object.freeze({
    code: 'authority_grant_contract_status_unrecognized',
    message:
      'The fixture authority grant has no source-authorized effect status; fresh effect use is refused.',
  });
}

export function assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(
  label = 'Protected records fresh fixture-authority effect'
) {
  if (typeof label !== 'string' || label.length < 1) {
    throw new Error('Protected records fixture authority status label must be non-empty');
  }
  const reason = protectedRecordsFixtureAuthorityGrantEffectStatusReason(
    PROTECTED_RECORDS_CURRENT_FIXTURE_AUTHORITY_GRANT_CONTRACT_SHA256
  );
  if (reason) {
    throw new Error(`${label} refused: ${reason.code}`);
  }
  return true;
}

export function assertProtectedRecordsActivePersistentProfileMutationAuthorityPresent(
  label = 'Protected records active persistent profile mutation'
) {
  if (typeof label !== 'string' || label.length < 1) {
    throw new Error('Protected records active persistent profile mutation label must be non-empty');
  }
  throw new Error(
    `${label} refused: ${PROTECTED_RECORDS_ACTIVE_PERSISTENT_PROFILE_MUTATION_AUTHORITY_ABSENT_REASON_CODE}`
  );
}
