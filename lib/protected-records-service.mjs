export {
  NON_CLAIMS,
  PROTECTED_RECORDS_SERVICE_LAUNCHER_CONFIG_TYPE,
  PROTECTED_RECORDS_SERVICE_RESULT_TYPE,
  PROTECTED_RECORDS_SERVICE_TYPE,
  SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsServiceText,
  assertProtectedRecordsServiceResult,
} from './protected-records-service-verification.mjs';

export const PROTECTED_RECORDS_SERVICE_REQUEST_RETIREMENT_REASON =
  'e2_direct_request_factory_source_retired';

export function applyProtectedRecordsServiceRequest() {
  throw new Error(PROTECTED_RECORDS_SERVICE_REQUEST_RETIREMENT_REASON);
}
