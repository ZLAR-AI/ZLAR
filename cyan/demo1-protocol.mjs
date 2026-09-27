// Exact Demo 1 protocol grammar.
//
// This profile does not reuse Cyan's generic grant-or-credential wire format.
// Founder Decision D7 requires both a founder-originated Grant G and a
// non-expanding Boarding Credential A, verified independently at destination.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from 'node:crypto';

export const DESTINATION_ID = 'zlar.demo1.promotion.local.v1';
export const STAGED_OBJECT_ID = 'demo-1-release.json';
export const ALLOCATION_UNIT = 'protected_promotion';
export const MAX_ALLOCATION = 1;

export const DOMAINS = Object.freeze({
  challenge: 'ZLAR-DEMO1-CHALLENGE-N-V1',
  action: 'ZLAR-DEMO1-ACTION-V1',
  grant: 'ZLAR-DEMO1-GRANT-G-V1',
  credential: 'ZLAR-DEMO1-BOARDING-A-V1',
  commit: 'ZLAR-DEMO1-PROMOTION-COMMIT-V1',
  receipt: 'ZLAR-DEMO1-RECEIPT-V1',
  policy: 'ZLAR-DEMO1-RECOGNITION-POLICY-V1',
});

const SAFE_ID = /^sha256:[0-9a-f]{64}$/;
const KEY_ID = /^spki-sha256:[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const REQUEST_ID = /^req-[A-Za-z0-9_-]{16,64}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const PROFILE = /^[a-z0-9][a-z0-9._-]{0,95}$/;
const REASON = /^[a-z][a-z0-9_]{0,95}$/;

const BODY_KEYS = Object.freeze({
  challenge: [
    'v', 'type', 'profile_id', 'destination_id', 'principal_id',
    'challenge_nonce', 'staged_object_id', 'artifact_sha256',
    'from_generation', 'to_generation', 'issued_at', 'expires_at',
  ],
  action: [
    'v', 'type', 'profile_id', 'principal_id', 'destination_id',
    'consequence', 'operation', 'challenge_id', 'staged_object_id',
    'artifact_sha256', 'from_generation', 'to_generation', 'measure',
    'expires_at',
  ],
  grant: [
    'v', 'type', 'profile_id', 'authority_root_key_id',
    'authorized_issuer_key_id', 'grant_nonce', 'action', 'action_id',
    'allocation_unit', 'maximum_allocation', 'issued_at', 'not_before',
    'expires_at',
  ],
  credential: [
    'v', 'type', 'profile_id', 'issuer_key_id', 'credential_nonce',
    'grant_id', 'action', 'action_id', 'allocation_debit', 'not_before',
    'expires_at',
  ],
  commit: [
    'v', 'type', 'profile_id', 'destination_id', 'principal_id',
    'request_id', 'challenge_id', 'action_id', 'grant_id', 'credential_id',
    'staged_object_id', 'artifact_sha256', 'from_generation', 'to_generation',
    'allocation_before', 'allocation_debit', 'allocation_after',
    'recognition_policy_sha256', 'destination_nonce', 'committed_at',
  ],
  receipt: [
    'v', 'type', 'profile_id', 'destination_id', 'destination_key_id',
    'sequence', 'previous_receipt_hash', 'request_id', 'principal_id',
    'outcome', 'reason_code', 'challenge_id', 'action_id', 'grant_id',
    'credential_id', 'promotion_commit_id', 'state_before_sha256',
    'state_after_sha256', 'from_generation', 'to_generation',
    'allocation_before', 'allocation_debit', 'allocation_after',
    'recognition_policy_sha256', 'recorded_at',
  ],
});

export class ProtocolError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}:${detail}` : code);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

function refuse(condition, code, detail = '') {
  if (!condition) throw new ProtocolError(code, detail);
}

function exactKeys(value, keys, label) {
  refuse(value !== null && typeof value === 'object' && !Array.isArray(value), 'wrong_type', label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  refuse(actual.length === expected.length && actual.every((key, i) => key === expected[i]), 'unknown_or_missing_field', label);
}

function safeInteger(value, label, { minimum = 0 } = {}) {
  refuse(Number.isSafeInteger(value) && value >= minimum && !Object.is(value, -0), 'unsafe_integer', label);
}

function stringMatch(value, pattern, label) {
  refuse(typeof value === 'string' && pattern.test(value), 'invalid_string', label);
}

function nullableId(value, label) {
  if (value !== null) stringMatch(value, SAFE_ID, label);
}

function nullableInteger(value, label) {
  if (value !== null) safeInteger(value, label);
}

function assertNoUnpairedSurrogates(value, path = '$') {
  if (typeof value === 'string') {
    for (let i = 0; i < value.length; i += 1) {
      const code = value.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(i + 1);
        refuse(next >= 0xdc00 && next <= 0xdfff, 'lone_surrogate', path);
        i += 1;
      } else {
        refuse(!(code >= 0xdc00 && code <= 0xdfff), 'lone_surrogate', path);
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoUnpairedSurrogates(entry, `${path}[${index}]`));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      assertNoUnpairedSurrogates(key, `${path}.<key>`);
      assertNoUnpairedSurrogates(value[key], `${path}.${key}`);
    }
  }
}

function assertCanonicalData(value, path = '$') {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return;
  if (typeof value === 'number') {
    safeInteger(value, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertCanonicalData(entry, `${path}[${index}]`));
    return;
  }
  refuse(typeof value === 'object', 'unserializable_type', path);
  for (const key of Object.keys(value)) {
    refuse(value[key] !== undefined, 'undefined_value', `${path}.${key}`);
    assertCanonicalData(value[key], `${path}.${key}`);
  }
}

function encodeCanonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(encodeCanonical).join(',')}]`;
  const fields = Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${encodeCanonical(value[key])}`);
  return `{${fields.join(',')}}`;
}

export function canonical(value) {
  assertNoUnpairedSurrogates(value);
  assertCanonicalData(value);
  return encodeCanonical(value);
}

export function canonicalBytes(value) {
  return Buffer.from(canonical(value), 'utf8');
}

export function parseCanonical(input) {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  refuse(!(raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf), 'bom_forbidden');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    throw new ProtocolError('invalid_utf8');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ProtocolError('invalid_json');
  }
  const normalized = canonicalBytes(value);
  refuse(raw.equals(normalized), 'noncanonical_transport');
  return value;
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function sha256Id(bytes) {
  return `sha256:${sha256Hex(bytes)}`;
}

export function keyId(publicKeyInput) {
  const key = publicKeyInput?.type === 'public' ? publicKeyInput : createPublicKey(publicKeyInput);
  refuse(key.asymmetricKeyType === 'ed25519', 'wrong_algorithm', 'public_key');
  const der = key.export({ type: 'spki', format: 'der' });
  return `spki-sha256:${sha256Hex(der)}`;
}

export function publicKeyPem(keyInput) {
  const key = keyInput?.type === 'public' ? keyInput : createPublicKey(keyInput);
  return key.export({ type: 'spki', format: 'pem' }).toString();
}

export function preimage(kind, body) {
  const domain = DOMAINS[kind];
  refuse(typeof domain === 'string', 'unknown_domain', kind);
  validateBody(kind, body);
  return Buffer.concat([Buffer.from(`${domain}\0`, 'utf8'), canonicalBytes(body)]);
}

export function bodyId(kind, body) {
  return sha256Id(preimage(kind, body));
}

export function signedRecordHash(record) {
  validateSignedRecordShape(record);
  return sha256Id(canonicalBytes(record));
}

function validateSignedRecordShape(record) {
  exactKeys(record, ['body', 'signature'], 'signed_record');
  stringMatch(record.signature, /^[A-Za-z0-9_-]{86}$/, 'signature');
  const decoded = Buffer.from(record.signature, 'base64url');
  refuse(decoded.length === 64, 'wrong_signature_length');
  refuse(decoded.toString('base64url') === record.signature, 'noncanonical_signature');
}

export function signRecord(kind, body, privateKeyInput) {
  const key = privateKeyInput?.type === 'private' ? privateKeyInput : createPrivateKey(privateKeyInput);
  refuse(key.asymmetricKeyType === 'ed25519', 'wrong_algorithm', 'private_key');
  const signature = edSign(null, preimage(kind, body), key).toString('base64url');
  const record = { body, signature };
  validateSignedRecordShape(record);
  return record;
}

export function verifyRecord(kind, record, publicKeyInput) {
  try {
    validateSignedRecordShape(record);
    validateBody(kind, record.body);
    const key = publicKeyInput?.type === 'public' ? publicKeyInput : createPublicKey(publicKeyInput);
    refuse(key.asymmetricKeyType === 'ed25519', 'wrong_algorithm', 'verification_key');
    const ok = edVerify(null, preimage(kind, record.body), key, Buffer.from(record.signature, 'base64url'));
    refuse(ok, 'bad_signature', kind);
    return true;
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new ProtocolError('verification_error', kind);
  }
}

export function parseSignedRecord(kind, input) {
  const record = parseCanonical(input);
  validateSignedRecordShape(record);
  validateBody(kind, record.body);
  return record;
}

function validateAction(body) {
  exactKeys(body, BODY_KEYS.action, 'action');
  refuse(body.v === 1 && body.type === 'action', 'wrong_schema', 'action');
  stringMatch(body.profile_id, PROFILE, 'action.profile_id');
  stringMatch(body.principal_id, NAME, 'action.principal_id');
  refuse(body.destination_id === DESTINATION_ID, 'wrong_destination');
  refuse(body.consequence === 'code.deploy', 'wrong_consequence');
  refuse(body.operation === 'deployment.promote', 'wrong_operation');
  stringMatch(body.challenge_id, SAFE_ID, 'action.challenge_id');
  refuse(body.staged_object_id === STAGED_OBJECT_ID, 'wrong_staged_object');
  stringMatch(body.artifact_sha256, SAFE_ID, 'action.artifact_sha256');
  safeInteger(body.from_generation, 'action.from_generation');
  safeInteger(body.to_generation, 'action.to_generation');
  refuse(body.to_generation === body.from_generation + 1, 'generation_not_next');
  refuse(body.measure === 1, 'wrong_measure');
  safeInteger(body.expires_at, 'action.expires_at', { minimum: 1 });
}

function validateChallenge(body) {
  exactKeys(body, BODY_KEYS.challenge, 'challenge');
  refuse(body.v === 1 && body.type === 'challenge', 'wrong_schema', 'challenge');
  stringMatch(body.profile_id, PROFILE, 'challenge.profile_id');
  refuse(body.destination_id === DESTINATION_ID, 'wrong_destination');
  stringMatch(body.principal_id, NAME, 'challenge.principal_id');
  stringMatch(body.challenge_nonce, NONCE, 'challenge.nonce');
  refuse(body.staged_object_id === STAGED_OBJECT_ID, 'wrong_staged_object');
  stringMatch(body.artifact_sha256, SAFE_ID, 'challenge.artifact_sha256');
  safeInteger(body.from_generation, 'challenge.from_generation');
  safeInteger(body.to_generation, 'challenge.to_generation');
  refuse(body.to_generation === body.from_generation + 1, 'generation_not_next');
  safeInteger(body.issued_at, 'challenge.issued_at', { minimum: 1 });
  safeInteger(body.expires_at, 'challenge.expires_at', { minimum: 1 });
  refuse(body.expires_at > body.issued_at, 'invalid_time_window', 'challenge');
}

function validateGrant(body) {
  exactKeys(body, BODY_KEYS.grant, 'grant');
  refuse(body.v === 1 && body.type === 'grant', 'wrong_schema', 'grant');
  stringMatch(body.profile_id, PROFILE, 'grant.profile_id');
  stringMatch(body.authority_root_key_id, KEY_ID, 'grant.authority_root_key_id');
  stringMatch(body.authorized_issuer_key_id, KEY_ID, 'grant.authorized_issuer_key_id');
  stringMatch(body.grant_nonce, NONCE, 'grant.nonce');
  validateAction(body.action);
  stringMatch(body.action_id, SAFE_ID, 'grant.action_id');
  refuse(body.action_id === bodyId('action', body.action), 'action_id_mismatch', 'grant');
  refuse(body.profile_id === body.action.profile_id, 'profile_mismatch', 'grant');
  refuse(body.allocation_unit === ALLOCATION_UNIT, 'wrong_allocation_unit');
  refuse(body.maximum_allocation === MAX_ALLOCATION, 'wrong_maximum_allocation');
  safeInteger(body.issued_at, 'grant.issued_at', { minimum: 1 });
  safeInteger(body.not_before, 'grant.not_before', { minimum: 1 });
  safeInteger(body.expires_at, 'grant.expires_at', { minimum: 1 });
  refuse(body.issued_at <= body.not_before && body.not_before < body.expires_at, 'invalid_time_window', 'grant');
  refuse(body.expires_at <= body.action.expires_at, 'grant_expands_action_time');
}

function validateCredential(body) {
  exactKeys(body, BODY_KEYS.credential, 'credential');
  refuse(body.v === 1 && body.type === 'boarding_credential', 'wrong_schema', 'credential');
  stringMatch(body.profile_id, PROFILE, 'credential.profile_id');
  stringMatch(body.issuer_key_id, KEY_ID, 'credential.issuer_key_id');
  stringMatch(body.credential_nonce, NONCE, 'credential.nonce');
  stringMatch(body.grant_id, SAFE_ID, 'credential.grant_id');
  validateAction(body.action);
  stringMatch(body.action_id, SAFE_ID, 'credential.action_id');
  refuse(body.action_id === bodyId('action', body.action), 'action_id_mismatch', 'credential');
  refuse(body.profile_id === body.action.profile_id, 'profile_mismatch', 'credential');
  refuse(body.allocation_debit === 1, 'wrong_allocation_debit');
  safeInteger(body.not_before, 'credential.not_before', { minimum: 1 });
  safeInteger(body.expires_at, 'credential.expires_at', { minimum: 1 });
  refuse(body.not_before < body.expires_at, 'invalid_time_window', 'credential');
}

function validateCommit(body) {
  exactKeys(body, BODY_KEYS.commit, 'commit');
  refuse(body.v === 1 && body.type === 'promotion_commit', 'wrong_schema', 'commit');
  stringMatch(body.profile_id, PROFILE, 'commit.profile_id');
  refuse(body.destination_id === DESTINATION_ID, 'wrong_destination');
  stringMatch(body.principal_id, NAME, 'commit.principal_id');
  stringMatch(body.request_id, REQUEST_ID, 'commit.request_id');
  for (const field of ['challenge_id', 'action_id', 'grant_id', 'credential_id']) stringMatch(body[field], SAFE_ID, `commit.${field}`);
  refuse(body.staged_object_id === STAGED_OBJECT_ID, 'wrong_staged_object');
  stringMatch(body.artifact_sha256, SAFE_ID, 'commit.artifact_sha256');
  safeInteger(body.from_generation, 'commit.from_generation');
  safeInteger(body.to_generation, 'commit.to_generation');
  refuse(body.to_generation === body.from_generation + 1, 'generation_not_next');
  refuse(body.allocation_before === 1 && body.allocation_debit === 1 && body.allocation_after === 0, 'wrong_allocation_projection');
  stringMatch(body.recognition_policy_sha256, SAFE_ID, 'commit.policy_digest');
  stringMatch(body.destination_nonce, NONCE, 'commit.destination_nonce');
  safeInteger(body.committed_at, 'commit.committed_at', { minimum: 1 });
}

function validateReceipt(body) {
  exactKeys(body, BODY_KEYS.receipt, 'receipt');
  refuse(body.v === 1 && body.type === 'receipt', 'wrong_schema', 'receipt');
  stringMatch(body.profile_id, PROFILE, 'receipt.profile_id');
  refuse(body.destination_id === DESTINATION_ID, 'wrong_destination');
  stringMatch(body.destination_key_id, KEY_ID, 'receipt.destination_key_id');
  safeInteger(body.sequence, 'receipt.sequence', { minimum: 1 });
  nullableId(body.previous_receipt_hash, 'receipt.previous_receipt_hash');
  stringMatch(body.request_id, REQUEST_ID, 'receipt.request_id');
  stringMatch(body.principal_id, NAME, 'receipt.principal_id');
  refuse(body.outcome === 'executed' || body.outcome === 'refused', 'wrong_outcome');
  if (body.reason_code !== null) stringMatch(body.reason_code, REASON, 'receipt.reason_code');
  for (const field of ['challenge_id', 'action_id', 'grant_id', 'credential_id', 'promotion_commit_id']) nullableId(body[field], `receipt.${field}`);
  stringMatch(body.state_before_sha256, SAFE_ID, 'receipt.state_before');
  stringMatch(body.state_after_sha256, SAFE_ID, 'receipt.state_after');
  safeInteger(body.from_generation, 'receipt.from_generation');
  safeInteger(body.to_generation, 'receipt.to_generation');
  nullableInteger(body.allocation_before, 'receipt.allocation_before');
  refuse(body.allocation_debit === 0 || body.allocation_debit === 1, 'wrong_allocation_debit');
  nullableInteger(body.allocation_after, 'receipt.allocation_after');
  stringMatch(body.recognition_policy_sha256, SAFE_ID, 'receipt.policy_digest');
  safeInteger(body.recorded_at, 'receipt.recorded_at', { minimum: 1 });
  if (body.outcome === 'executed') {
    refuse(body.reason_code === null && body.promotion_commit_id !== null, 'invalid_executed_receipt');
    refuse(body.allocation_before === 1 && body.allocation_debit === 1 && body.allocation_after === 0, 'invalid_executed_allocation');
    refuse(body.state_before_sha256 !== body.state_after_sha256, 'executed_without_state_delta');
    refuse(body.to_generation === body.from_generation + 1, 'generation_not_next');
  } else {
    refuse(body.reason_code !== null && body.promotion_commit_id === null, 'invalid_refusal_receipt');
    refuse(body.allocation_debit === 0, 'refusal_debit');
    refuse(
      (body.allocation_before === null && body.allocation_after === null)
        || (body.allocation_before !== null
          && body.allocation_after !== null
          && body.allocation_before === body.allocation_after),
      'refusal_allocation_delta',
    );
    refuse(body.state_before_sha256 === body.state_after_sha256, 'refusal_state_delta');
    refuse(body.to_generation === body.from_generation, 'refusal_generation_delta');
  }
}

export function validateBody(kind, body) {
  assertNoUnpairedSurrogates(body);
  assertCanonicalData(body);
  switch (kind) {
    case 'challenge': return validateChallenge(body);
    case 'action': return validateAction(body);
    case 'grant': return validateGrant(body);
    case 'credential': return validateCredential(body);
    case 'commit': return validateCommit(body);
    case 'receipt': return validateReceipt(body);
    default: throw new ProtocolError('unknown_body_kind', kind);
  }
}

function validateRegistryEntry(entry, role) {
  exactKeys(entry, ['key_id', 'public_key_pem', 'role', 'status'], `policy.${role}`);
  stringMatch(entry.key_id, KEY_ID, `policy.${role}.key_id`);
  refuse(entry.role === role, 'wrong_key_role', role);
  refuse(entry.status === 'active' || entry.status === 'revoked', 'wrong_key_status', role);
  refuse(typeof entry.public_key_pem === 'string', 'wrong_type', `policy.${role}.public_key_pem`);
  refuse(keyId(entry.public_key_pem) === entry.key_id, 'key_id_mismatch', role);
}

export function validatePolicy(policy) {
  exactKeys(policy, ['algorithm', 'destination', 'destination_id', 'domains', 'issuers', 'profile_id', 'roots', 'type', 'v'], 'policy');
  refuse(policy.v === 1 && policy.type === 'recognition_policy', 'wrong_schema', 'policy');
  stringMatch(policy.profile_id, PROFILE, 'policy.profile_id');
  refuse(policy.destination_id === DESTINATION_ID, 'wrong_destination');
  refuse(policy.algorithm === 'Ed25519', 'wrong_algorithm', 'policy');
  exactKeys(policy.domains, Object.keys(DOMAINS), 'policy.domains');
  refuse(canonical(policy.domains) === canonical(DOMAINS), 'domain_set_mismatch');
  refuse(Array.isArray(policy.roots) && policy.roots.length >= 1, 'missing_root');
  refuse(Array.isArray(policy.issuers) && policy.issuers.length >= 1, 'missing_issuer');
  policy.roots.forEach((entry) => validateRegistryEntry(entry, 'grant_root'));
  policy.issuers.forEach((entry) => validateRegistryEntry(entry, 'boarding_issuer'));
  validateRegistryEntry(policy.destination, 'destination_signer');
  const all = [...policy.roots, ...policy.issuers, policy.destination].map((entry) => entry.key_id);
  refuse(new Set(all).size === all.length, 'key_role_collision');
  const canonicalOrder = (entries) => entries.every((entry, index) => index === 0 || entries[index - 1].key_id < entry.key_id);
  refuse(canonicalOrder(policy.roots) && canonicalOrder(policy.issuers), 'registry_order');
  return true;
}

export function policyDigest(policy) {
  validatePolicy(policy);
  return sha256Id(Buffer.concat([Buffer.from(`${DOMAINS.policy}\0`, 'utf8'), canonicalBytes(policy)]));
}

export function makeRecognitionPolicy({ profileId, roots, issuers, destination }) {
  const normalize = (entry, role) => ({
    key_id: keyId(entry.publicKeyPem),
    public_key_pem: publicKeyPem(entry.publicKeyPem),
    role,
    status: entry.status ?? 'active',
  });
  const policy = {
    v: 1,
    type: 'recognition_policy',
    profile_id: profileId,
    destination_id: DESTINATION_ID,
    algorithm: 'Ed25519',
    roots: roots.map((entry) => normalize(entry, 'grant_root')).sort((a, b) => (a.key_id < b.key_id ? -1 : a.key_id > b.key_id ? 1 : 0)),
    issuers: issuers.map((entry) => normalize(entry, 'boarding_issuer')).sort((a, b) => (a.key_id < b.key_id ? -1 : a.key_id > b.key_id ? 1 : 0)),
    destination: normalize(destination, 'destination_signer'),
    domains: { ...DOMAINS },
  };
  validatePolicy(policy);
  return policy;
}

export function actionFromChallenge(challengeBody) {
  validateChallenge(challengeBody);
  const action = {
    v: 1,
    type: 'action',
    profile_id: challengeBody.profile_id,
    principal_id: challengeBody.principal_id,
    destination_id: challengeBody.destination_id,
    consequence: 'code.deploy',
    operation: 'deployment.promote',
    challenge_id: bodyId('challenge', challengeBody),
    staged_object_id: challengeBody.staged_object_id,
    artifact_sha256: challengeBody.artifact_sha256,
    from_generation: challengeBody.from_generation,
    to_generation: challengeBody.to_generation,
    measure: 1,
    expires_at: challengeBody.expires_at,
  };
  validateAction(action);
  return action;
}

export function assertExactGrantToCredential(grant, credential) {
  validateGrant(grant);
  validateCredential(credential);
  refuse(credential.profile_id === grant.profile_id, 'credential_profile_expansion');
  refuse(credential.issuer_key_id === grant.authorized_issuer_key_id, 'credential_wrong_issuer');
  refuse(credential.grant_id === bodyId('grant', grant), 'credential_wrong_grant');
  refuse(credential.action_id === grant.action_id, 'credential_wrong_action_id');
  refuse(canonical(credential.action) === canonical(grant.action), 'credential_action_expansion');
  refuse(credential.allocation_debit <= grant.maximum_allocation, 'credential_allocation_expansion');
  refuse(credential.not_before >= grant.not_before, 'credential_time_expansion');
  refuse(credential.expires_at <= grant.expires_at, 'credential_time_expansion');
  return true;
}

export function parsePromotionRequest(input) {
  const request = parseCanonical(input);
  exactKeys(request, ['challenge_id', 'credential', 'grant', 'request_id'], 'promotion_request');
  stringMatch(request.request_id, REQUEST_ID, 'request.request_id');
  stringMatch(request.challenge_id, SAFE_ID, 'request.challenge_id');
  if (request.grant !== null) {
    validateSignedRecordShape(request.grant);
    validateGrant(request.grant.body);
  }
  if (request.credential !== null) {
    validateSignedRecordShape(request.credential);
    validateCredential(request.credential.body);
  }
  return request;
}

export function verifyReceiptChain(records, { destinationPublicKeyPem, policy }) {
  validatePolicy(policy);
  refuse(Array.isArray(records) && records.length > 0, 'empty_receipt_chain');
  let previous = null;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    verifyRecord('receipt', record, destinationPublicKeyPem);
    const body = record.body;
    refuse(body.profile_id === policy.profile_id, 'receipt_profile_mismatch');
    refuse(body.destination_key_id === policy.destination.key_id, 'receipt_destination_key_mismatch');
    refuse(body.recognition_policy_sha256 === policyDigest(policy), 'receipt_policy_mismatch');
    refuse(body.sequence === index + 1, 'receipt_sequence_gap');
    refuse(body.previous_receipt_hash === previous, 'receipt_chain_break');
    previous = signedRecordHash(record);
  }
  return { count: records.length, head: previous };
}

export function randomNonce(randomBytesFn) {
  return randomBytesFn(32).toString('base64url');
}
