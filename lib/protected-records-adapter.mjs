export {
  NON_CLAIMS,
  PROTECTED_RECORDS_ADAPTER_TYPE,
  PROTECTED_RECORDS_CONSUMED_STORE_TYPE,
  PROTECTED_RECORDS_WRITE_RESULT_TYPE,
  SAFE_CLAIM_CEILING,
  assertNoUnsafeProtectedRecordsAdapterText,
  assertProtectedRecordsWriteResult,
} from './protected-records-adapter-verification.mjs';

export const PROTECTED_RECORDS_ADAPTER_RETIREMENT_REASON =
  'e1_direct_adapter_factory_source_retired';

export function applyProtectedRecordsWrite() {
  throw new Error(PROTECTED_RECORDS_ADAPTER_RETIREMENT_REASON);
}
