#!/usr/bin/env node
// Offline verification for exact Demo 1 evidence.
// Trust inputs and the intended claim ceiling must be supplied independently;
// the evidence bundle is never allowed to recognize itself.

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import {
  MAX_ALLOCATION,
  ProtocolError,
  actionFromChallenge,
  assertExactGrantToCredential,
  bodyId,
  canonical,
  canonicalBytes,
  keyId,
  parseCanonical,
  policyDigest,
  sha256Id,
  signedRecordHash,
  validatePolicy,
  verifyReceiptChain,
  verifyRecord,
} from '../../cyan/demo1-protocol.mjs';
import {
  stateDigest,
  stateDigestFromFacts,
} from '../../cyan/demo1-destination.mjs';

const SAFE_ID = /^sha256:[0-9a-f]{64}$/;
const KEY_ID = /^spki-sha256:[0-9a-f]{64}$/;
const CLAIM_CEILINGS = new Set([
  'software_key_protocol_and_transaction_only',
  'installed_c_backed_candidate_evidence_only',
]);
const SOFTWARE_PROFILE_ID = 'zlar.demo1.software-test.v1';
const SOFTWARE_PRINCIPAL_ID = 'software-test:acting-client';
const INSTALLED_PROFILE_ID = 'zlar.demo1.c-backed.v1';
const INSTALLED_PRINCIPAL_ID = 'macos-euid:501';
const INSTALLED_ROOT_KEY_ID = 'spki-sha256:eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c';
const BASE64URL = /^[A-Za-z0-9_-]*$/;

function refuse(condition, code, detail = '') {
  if (!condition) throw new ProtocolError(code, detail);
}

function exactKeys(value, expected, label) {
  refuse(value !== null && typeof value === 'object' && !Array.isArray(value), 'wrong_type', label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  refuse(actual.length === wanted.length && actual.every((key, index) => key === wanted[index]), 'unknown_or_missing_field', label);
}

function safeInteger(value, label) {
  refuse(Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0), 'unsafe_integer', label);
}

function safeId(value, pattern, label) {
  refuse(typeof value === 'string' && pattern.test(value), 'invalid_string', label);
}

function sortedBy(rows, field) {
  return rows.every((row, index) => index === 0 || rows[index - 1][field] < row[field]);
}

function decodeCanonicalBase64url(value, label) {
  refuse(typeof value === 'string' && BASE64URL.test(value), 'invalid_string', label);
  const decoded = Buffer.from(value, 'base64url');
  refuse(decoded.toString('base64url') === value, 'noncanonical_base64url', label);
  return decoded;
}

function validateProjection(projection) {
  exactKeys(projection, ['active', 'commit_count', 'credentials', 'grants', 'receipt_count'], 'final_projection');
  exactKeys(projection.active, [
    'artifact_bytes_base64url', 'artifact_sha256', 'generation',
    'staged_object_id', 'state_sha256',
  ], 'final_projection.active');
  safeInteger(projection.active.generation, 'final_projection.active.generation');
  refuse(projection.active.staged_object_id === 'demo-1-a' || projection.active.staged_object_id === 'demo-1-release.json', 'wrong_staged_object', 'final_projection.active');
  safeId(projection.active.artifact_sha256, SAFE_ID, 'final_projection.active.artifact_sha256');
  safeId(projection.active.state_sha256, SAFE_ID, 'final_projection.active.state_sha256');
  const artifactBytes = decodeCanonicalBase64url(
    projection.active.artifact_bytes_base64url,
    'final_projection.active.artifact_bytes_base64url',
  );
  refuse(sha256Id(artifactBytes) === projection.active.artifact_sha256, 'projection_artifact_digest_mismatch');
  const computedState = stateDigest({
    generation: projection.active.generation,
    stagedObjectId: projection.active.staged_object_id,
    artifactSha256: projection.active.artifact_sha256,
    artifactBytes,
  });
  refuse(computedState === projection.active.state_sha256, 'projection_state_digest_mismatch');

  refuse(Array.isArray(projection.grants), 'wrong_type', 'final_projection.grants');
  for (const grant of projection.grants) {
    exactKeys(grant, ['grant_id', 'maximum_allocation', 'spent_allocation'], 'final_projection.grant');
    safeId(grant.grant_id, SAFE_ID, 'final_projection.grant.grant_id');
    safeInteger(grant.maximum_allocation, 'final_projection.grant.maximum_allocation');
    safeInteger(grant.spent_allocation, 'final_projection.grant.spent_allocation');
    refuse(grant.maximum_allocation === MAX_ALLOCATION, 'projection_wrong_maximum_allocation');
    refuse(grant.spent_allocation <= grant.maximum_allocation, 'projection_allocation_overdrawn');
  }
  refuse(sortedBy(projection.grants, 'grant_id'), 'projection_grant_order');

  refuse(Array.isArray(projection.credentials), 'wrong_type', 'final_projection.credentials');
  for (const credential of projection.credentials) {
    exactKeys(credential, ['credential_id', 'grant_id', 'used'], 'final_projection.credential');
    safeId(credential.credential_id, SAFE_ID, 'final_projection.credential.credential_id');
    safeId(credential.grant_id, SAFE_ID, 'final_projection.credential.grant_id');
    refuse(typeof credential.used === 'boolean', 'wrong_type', 'final_projection.credential.used');
  }
  refuse(sortedBy(projection.credentials, 'credential_id'), 'projection_credential_order');
  safeInteger(projection.commit_count, 'final_projection.commit_count');
  safeInteger(projection.receipt_count, 'final_projection.receipt_count');
  return { artifactBytes, computedState };
}

function compareCommitAndReceipt(commit, receipt) {
  for (const field of [
    'profile_id', 'destination_id', 'principal_id', 'request_id', 'challenge_id',
    'action_id', 'grant_id', 'credential_id', 'from_generation', 'to_generation',
    'allocation_before', 'allocation_debit', 'allocation_after',
    'recognition_policy_sha256',
  ]) {
    refuse(commit.body[field] === receipt.body[field], 'commit_receipt_field_mismatch', field);
  }
}

function indexAuthorityRecords(bundle, expectedDestinationPublicKeyPem, expectedPrincipalId) {
  refuse(Array.isArray(bundle.challenges) && Array.isArray(bundle.grants) && Array.isArray(bundle.credentials), 'wrong_type', 'authority_records');
  refuse(sortedBy(bundle.challenges, 'challenge_id'), 'challenge_record_order');
  refuse(sortedBy(bundle.grants, 'grant_id'), 'grant_record_order');
  refuse(sortedBy(bundle.credentials, 'credential_id'), 'credential_record_order');

  const challenges = new Map();
  for (const entry of bundle.challenges) {
    exactKeys(entry, ['challenge_id', 'consumed', 'record'], 'challenge_record');
    safeId(entry.challenge_id, SAFE_ID, 'challenge_record.challenge_id');
    refuse(typeof entry.consumed === 'boolean', 'wrong_type', 'challenge_record.consumed');
    verifyRecord('challenge', entry.record, expectedDestinationPublicKeyPem);
    refuse(entry.record.body.profile_id === bundle.recognition_policy.profile_id, 'challenge_profile_mismatch');
    refuse(entry.record.body.principal_id === expectedPrincipalId, 'challenge_principal_mismatch');
    refuse(bodyId('challenge', entry.record.body) === entry.challenge_id, 'challenge_id_mismatch');
    refuse(!challenges.has(entry.challenge_id), 'duplicate_challenge_record');
    challenges.set(entry.challenge_id, entry);
  }

  const grants = new Map();
  for (const entry of bundle.grants) {
    exactKeys(entry, ['grant_id', 'maximum_allocation', 'record', 'spent_allocation'], 'grant_record');
    safeId(entry.grant_id, SAFE_ID, 'grant_record.grant_id');
    safeInteger(entry.maximum_allocation, 'grant_record.maximum_allocation');
    safeInteger(entry.spent_allocation, 'grant_record.spent_allocation');
    refuse(entry.maximum_allocation === MAX_ALLOCATION && entry.spent_allocation <= MAX_ALLOCATION, 'grant_record_allocation');
    const body = entry.record?.body;
    const root = bundle.recognition_policy.roots.find((candidate) => candidate.key_id === body?.authority_root_key_id);
    refuse(root?.status === 'active', 'grant_root_unrecognized');
    const issuer = bundle.recognition_policy.issuers.find((candidate) => candidate.key_id === body?.authorized_issuer_key_id);
    refuse(issuer?.status === 'active', 'grant_issuer_unrecognized');
    verifyRecord('grant', entry.record, root.public_key_pem);
    refuse(body.profile_id === bundle.recognition_policy.profile_id, 'grant_profile_mismatch');
    refuse(bodyId('grant', body) === entry.grant_id, 'grant_id_mismatch');
    const challenge = challenges.get(body.action.challenge_id);
    refuse(challenge !== undefined, 'grant_challenge_missing');
    refuse(canonical(actionFromChallenge(challenge.record.body)) === canonical(body.action), 'grant_action_not_destination_challenge');
    refuse(body.issued_at >= challenge.record.body.issued_at, 'grant_predates_challenge');
    refuse(body.not_before >= challenge.record.body.issued_at, 'grant_predates_challenge');
    refuse(body.expires_at <= challenge.record.body.expires_at, 'grant_expands_challenge_time');
    refuse(!grants.has(entry.grant_id), 'duplicate_grant_record');
    grants.set(entry.grant_id, entry);
  }

  const credentials = new Map();
  for (const entry of bundle.credentials) {
    exactKeys(entry, ['credential_id', 'grant_id', 'record', 'used'], 'credential_record');
    safeId(entry.credential_id, SAFE_ID, 'credential_record.credential_id');
    safeId(entry.grant_id, SAFE_ID, 'credential_record.grant_id');
    refuse(typeof entry.used === 'boolean', 'wrong_type', 'credential_record.used');
    const grant = grants.get(entry.grant_id);
    refuse(grant !== undefined, 'credential_grant_missing');
    const issuer = bundle.recognition_policy.issuers.find((candidate) => candidate.key_id === entry.record?.body?.issuer_key_id);
    refuse(issuer?.status === 'active', 'credential_issuer_unrecognized');
    verifyRecord('credential', entry.record, issuer.public_key_pem);
    assertExactGrantToCredential(grant.record.body, entry.record.body);
    refuse(bodyId('credential', entry.record.body) === entry.credential_id, 'credential_id_mismatch');
    refuse(entry.record.body.grant_id === entry.grant_id, 'credential_grant_id_mismatch');
    refuse(!credentials.has(entry.credential_id), 'duplicate_credential_record');
    credentials.set(entry.credential_id, entry);
  }
  return { challenges, grants, credentials };
}

export function verifyEvidenceBundle(input, {
  expectedPolicyDigest,
  expectedDestinationPublicKeyPem,
  expectedClaimCeiling,
} = {}) {
  safeId(expectedPolicyDigest, SAFE_ID, 'expected_policy_digest');
  refuse(typeof expectedDestinationPublicKeyPem === 'string' || expectedDestinationPublicKeyPem?.type === 'public', 'expected_destination_key_required');
  refuse(CLAIM_CEILINGS.has(expectedClaimCeiling), 'expected_claim_ceiling_required');
  const expectedDestinationKeyId = keyId(expectedDestinationPublicKeyPem);
  safeId(expectedDestinationKeyId, KEY_ID, 'expected_destination_key_id');

  const bundle = Buffer.isBuffer(input) || typeof input === 'string' ? parseCanonical(input) : input;
  exactKeys(bundle, [
    'challenges', 'claim_ceiling', 'commits', 'credentials',
    'destination_public_key_pem', 'final_projection', 'grants',
    'recognition_policy', 'recognition_policy_sha256', 'receipts', 'type', 'v',
  ], 'evidence_bundle');
  refuse(bundle.v === 2 && bundle.type === 'demo1_evidence', 'wrong_schema', 'evidence_bundle');
  refuse(bundle.claim_ceiling === expectedClaimCeiling, 'unexpected_claim_ceiling');
  validatePolicy(bundle.recognition_policy);
  const installedEvidence = expectedClaimCeiling === 'installed_c_backed_candidate_evidence_only';
  const expectedProfileId = installedEvidence ? INSTALLED_PROFILE_ID : SOFTWARE_PROFILE_ID;
  const expectedPrincipalId = installedEvidence ? INSTALLED_PRINCIPAL_ID : SOFTWARE_PRINCIPAL_ID;
  refuse(bundle.recognition_policy.profile_id === expectedProfileId, 'claim_profile_mismatch');
  if (installedEvidence) {
    refuse(
      bundle.recognition_policy.roots.length === 1
        && bundle.recognition_policy.roots[0].status === 'active'
        && bundle.recognition_policy.roots[0].key_id === INSTALLED_ROOT_KEY_ID,
      'installed_claim_root_mismatch',
    );
  }
  refuse(bundle.recognition_policy_sha256 === policyDigest(bundle.recognition_policy), 'policy_digest_mismatch');
  refuse(bundle.recognition_policy_sha256 === expectedPolicyDigest, 'unexpected_policy_digest');
  refuse(keyId(bundle.destination_public_key_pem) === expectedDestinationKeyId, 'unexpected_destination_key');
  refuse(bundle.recognition_policy.destination.key_id === expectedDestinationKeyId, 'destination_key_mismatch');
  refuse(bundle.recognition_policy.destination.status === 'active', 'destination_key_not_active');
  refuse(Array.isArray(bundle.commits) && Array.isArray(bundle.receipts), 'wrong_type', 'evidence_records');
  const projection = validateProjection(bundle.final_projection);
  const authority = indexAuthorityRecords(bundle, expectedDestinationPublicKeyPem, expectedPrincipalId);

  const commits = new Map();
  for (const record of bundle.commits) {
    verifyRecord('commit', record, expectedDestinationPublicKeyPem);
    refuse(record.body.profile_id === bundle.recognition_policy.profile_id, 'commit_profile_mismatch');
    refuse(record.body.recognition_policy_sha256 === expectedPolicyDigest, 'commit_policy_mismatch');
    const commitId = signedRecordHash(record);
    refuse(!commits.has(commitId), 'duplicate_commit');
    commits.set(commitId, record);
  }

  const chain = verifyReceiptChain(bundle.receipts, {
    destinationPublicKeyPem: expectedDestinationPublicKeyPem,
    policy: bundle.recognition_policy,
  });
  const referencedCommits = new Set();
  const spentByGrant = new Map([...authority.grants.keys()].map((id) => [id, 0]));
  const usedCredentials = new Set();
  const consumedChallenges = new Set();
  const seenRequestIds = new Set();
  let priorState = null;
  let priorGeneration = null;
  let lastExecutedCommit = null;
  let executedCount = 0;
  let refusalCount = 0;
  for (const record of bundle.receipts) {
    refuse(!seenRequestIds.has(record.body.request_id), 'duplicate_receipt_request_id');
    seenRequestIds.add(record.body.request_id);
    refuse(record.body.principal_id === expectedPrincipalId, 'receipt_principal_mismatch');
    if (priorState !== null) {
      refuse(record.body.state_before_sha256 === priorState, 'receipt_state_continuity_break');
      refuse(record.body.from_generation === priorGeneration, 'receipt_generation_continuity_break');
    }
    priorState = record.body.state_after_sha256;
    priorGeneration = record.body.to_generation;
    if (record.body.outcome === 'executed') {
      executedCount += 1;
      const challenge = authority.challenges.get(record.body.challenge_id);
      const grant = authority.grants.get(record.body.grant_id);
      const credential = authority.credentials.get(record.body.credential_id);
      refuse(challenge !== undefined && grant !== undefined && credential !== undefined, 'executed_authority_record_missing');
      refuse(!consumedChallenges.has(record.body.challenge_id), 'duplicate_executed_challenge_id');
      refuse(!usedCredentials.has(record.body.credential_id), 'duplicate_executed_credential_id');
      refuse(grant.record.body.action.challenge_id === record.body.challenge_id, 'receipt_grant_challenge_mismatch');
      refuse(credential.record.body.action.challenge_id === record.body.challenge_id, 'receipt_credential_challenge_mismatch');
      refuse(grant.record.body.action_id === record.body.action_id, 'receipt_grant_action_mismatch');
      refuse(credential.record.body.action_id === record.body.action_id, 'receipt_credential_action_mismatch');
      refuse(record.body.recorded_at >= challenge.record.body.issued_at && record.body.recorded_at < challenge.record.body.expires_at, 'receipt_outside_challenge_window');
      refuse(record.body.recorded_at >= grant.record.body.not_before && record.body.recorded_at < grant.record.body.expires_at, 'receipt_outside_grant_window');
      refuse(record.body.recorded_at >= credential.record.body.not_before && record.body.recorded_at < credential.record.body.expires_at, 'receipt_outside_credential_window');
      const commit = commits.get(record.body.promotion_commit_id);
      refuse(commit !== undefined, 'executed_receipt_missing_commit');
      refuse(!referencedCommits.has(record.body.promotion_commit_id), 'commit_referenced_more_than_once');
      referencedCommits.add(record.body.promotion_commit_id);
      compareCommitAndReceipt(commit, record);
      refuse(commit.body.principal_id === grant.record.body.action.principal_id, 'commit_principal_mismatch');
      refuse(commit.body.staged_object_id === grant.record.body.action.staged_object_id, 'commit_staged_object_mismatch');
      refuse(commit.body.artifact_sha256 === grant.record.body.action.artifact_sha256, 'commit_artifact_mismatch');
      refuse(commit.body.from_generation === grant.record.body.action.from_generation, 'commit_from_generation_mismatch');
      refuse(commit.body.to_generation === grant.record.body.action.to_generation, 'commit_to_generation_mismatch');
      refuse(commit.body.committed_at <= record.body.recorded_at, 'receipt_before_commit');
      const expectedStateAfter = stateDigestFromFacts({
        generation: commit.body.to_generation,
        stagedObjectId: commit.body.staged_object_id,
        artifactSha256: commit.body.artifact_sha256,
        artifactBytesSha256: commit.body.artifact_sha256,
      });
      refuse(record.body.state_after_sha256 === expectedStateAfter, 'commit_receipt_state_mismatch');
      const spent = spentByGrant.get(record.body.grant_id);
      refuse(spent === 0, 'grant_executed_more_than_once');
      refuse(record.body.allocation_before === MAX_ALLOCATION - spent, 'executed_allocation_before_mismatch');
      spentByGrant.set(record.body.grant_id, spent + record.body.allocation_debit);
      consumedChallenges.add(record.body.challenge_id);
      usedCredentials.add(record.body.credential_id);
      lastExecutedCommit = commit;
    } else {
      refusalCount += 1;
      refuse(record.body.promotion_commit_id === null, 'refusal_has_commit');
      const spent = record.body.grant_id === null ? null : spentByGrant.get(record.body.grant_id);
      const remaining = spent === undefined || spent === null ? null : MAX_ALLOCATION - spent;
      refuse(record.body.allocation_before === remaining && record.body.allocation_after === remaining, 'refusal_allocation_projection_mismatch');
    }
  }
  refuse(referencedCommits.size === commits.size, 'unreferenced_commit');
  for (const [id, entry] of authority.challenges) refuse(entry.consumed === consumedChallenges.has(id), 'challenge_consumption_projection_mismatch');
  for (const [id, entry] of authority.credentials) refuse(entry.used === usedCredentials.has(id), 'credential_use_projection_mismatch');
  for (const [id, entry] of authority.grants) refuse(entry.spent_allocation === spentByGrant.get(id), 'grant_spend_projection_mismatch');
  refuse(bundle.final_projection.commit_count === bundle.commits.length, 'commit_count_mismatch');
  refuse(bundle.final_projection.receipt_count === bundle.receipts.length, 'receipt_count_mismatch');

  const expectedGrants = bundle.grants.map((entry) => ({
    grant_id: entry.grant_id,
    maximum_allocation: entry.maximum_allocation,
    spent_allocation: entry.spent_allocation,
  }));
  const expectedCredentials = bundle.credentials.map((entry) => ({
    credential_id: entry.credential_id,
    grant_id: entry.grant_id,
    used: entry.used,
  }));
  refuse(canonical(bundle.final_projection.grants) === canonical(expectedGrants), 'projection_grants_mismatch');
  refuse(canonical(bundle.final_projection.credentials) === canonical(expectedCredentials), 'projection_credentials_mismatch');

  const terminalReceipt = bundle.receipts.at(-1);
  refuse(terminalReceipt !== undefined, 'empty_receipt_chain');
  refuse(terminalReceipt.body.state_after_sha256 === projection.computedState, 'terminal_state_mismatch');
  refuse(terminalReceipt.body.to_generation === bundle.final_projection.active.generation, 'terminal_generation_mismatch');
  if (lastExecutedCommit !== null) {
    refuse(lastExecutedCommit.body.to_generation === bundle.final_projection.active.generation, 'active_generation_not_last_commit');
    refuse(lastExecutedCommit.body.staged_object_id === bundle.final_projection.active.staged_object_id, 'active_object_not_last_commit');
    refuse(lastExecutedCommit.body.artifact_sha256 === bundle.final_projection.active.artifact_sha256, 'active_artifact_not_last_commit');
  }

  return {
    status: expectedClaimCeiling === 'software_key_protocol_and_transaction_only'
      ? 'VERIFIED_SOFTWARE_PROFILE_ONLY'
      : 'VERIFIED_BOUNDED_EVIDENCE',
    claim_ceiling: bundle.claim_ceiling,
    challenge_count: bundle.challenges.length,
    grant_count: bundle.grants.length,
    credential_count: bundle.credentials.length,
    receipt_count: chain.count,
    receipt_head: chain.head,
    commit_count: bundle.commits.length,
    executed_count: executedCount,
    refusal_count: refusalCount,
    policy_digest: expectedPolicyDigest,
    destination_key_id: expectedDestinationKeyId,
    projection_digest: sha256Id(canonicalBytes(bundle.final_projection)),
  };
}

function parseArguments(argv) {
  const allowed = new Set(['--evidence', '--expected-policy-digest', '--destination-public-key', '--expected-claim-ceiling']);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    refuse(allowed.has(flag) && typeof value === 'string' && !values.has(flag), 'usage');
    values.set(flag, value);
  }
  refuse(argv.length === 8 && values.size === 4, 'usage');
  return values;
}

function main(argv) {
  try {
    const values = parseArguments(argv);
    const result = verifyEvidenceBundle(readFileSync(values.get('--evidence')), {
      expectedPolicyDigest: values.get('--expected-policy-digest'),
      expectedDestinationPublicKeyPem: readFileSync(values.get('--destination-public-key'), 'utf8'),
      expectedClaimCeiling: values.get('--expected-claim-ceiling'),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ reason: error.message, status: 'REFUSED' })}\n`);
    return 42;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = main(process.argv.slice(2));
}
