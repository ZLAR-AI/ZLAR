// Destination-owned Demo 1 consequence boundary.
//
// The acting client can stage bytes and transport G/A. It cannot supply the
// action, identity, protected state, policy, PromotionCommit, receipt, clock,
// issuer key, destination key, or allocation truth accepted by this module.

import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { basename, join } from 'node:path';
import { randomBytes } from 'node:crypto';

import {
  ALLOCATION_UNIT,
  DESTINATION_ID,
  MAX_ALLOCATION,
  STAGED_OBJECT_ID,
  ProtocolError,
  actionFromChallenge,
  assertExactGrantToCredential,
  bodyId,
  canonical,
  canonicalBytes,
  keyId,
  parseCanonical,
  parsePromotionRequest,
  policyDigest,
  publicKeyPem,
  randomNonce,
  sha256Id,
  signRecord,
  signedRecordHash,
  validateBody,
  validatePolicy,
  verifyRecord,
} from './demo1-protocol.mjs';
import { Demo1Store, StoreError } from './demo1-store.mjs';

const REQUEST_ID = /^req-[A-Za-z0-9_-]{16,64}$/;
const SAFE_ID = /^sha256:[0-9a-f]{64}$/;

export class DestinationRefusal extends Error {
  constructor(code, facts = {}) {
    super(code);
    this.name = 'DestinationRefusal';
    this.code = code;
    this.facts = facts;
  }
}

export class InjectedFault extends Error {
  constructor(point) {
    super(`fault_injected:${point}`);
    this.name = 'InjectedFault';
    this.point = point;
  }
}

export class PostCommitFault extends Error {
  constructor() {
    super('fault_injected:after_commit_before_response');
    this.name = 'PostCommitFault';
  }
}

function refuse(condition, code, facts = {}) {
  if (!condition) throw new DestinationRefusal(code, facts);
}

function nowSeconds(clock) {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('destination_clock_invalid');
  return value;
}

function fault(point, selected) {
  if (selected === point) throw new InjectedFault(point);
}

export function stateDigestFromFacts({
  generation,
  stagedObjectId,
  artifactSha256,
  artifactBytesSha256,
}) {
  return sha256Id(Buffer.concat([
    Buffer.from('ZLAR-DEMO1-ACTIVE-RELEASE-V1\0', 'utf8'),
    canonicalBytes({
      v: 1,
      generation,
      staged_object_id: stagedObjectId,
      artifact_sha256: artifactSha256,
      artifact_bytes_sha256: artifactBytesSha256,
    }),
  ]));
}

export function stateDigest(active) {
  return stateDigestFromFacts({
    generation: active.generation,
    stagedObjectId: active.stagedObjectId,
    artifactSha256: active.artifactSha256,
    artifactBytesSha256: sha256Id(active.artifactBytes),
  });
}

export function buildCandidateGrantBody({
  challengeRecord,
  authorityRootKeyId,
  authorizedIssuerKeyId,
  grantNonce,
  issuedAt,
  notBefore = issuedAt,
  expiresAt = challengeRecord.body.expires_at,
}) {
  validateBody('challenge', challengeRecord.body);
  const action = actionFromChallenge(challengeRecord.body);
  const body = {
    v: 1,
    type: 'grant',
    profile_id: action.profile_id,
    authority_root_key_id: authorityRootKeyId,
    authorized_issuer_key_id: authorizedIssuerKeyId,
    grant_nonce: grantNonce,
    action,
    action_id: bodyId('action', action),
    allocation_unit: ALLOCATION_UNIT,
    maximum_allocation: MAX_ALLOCATION,
    issued_at: issuedAt,
    not_before: notBefore,
    expires_at: expiresAt,
  };
  validateBody('grant', body);
  return body;
}

export class Demo1Destination {
  constructor({
    databasePath,
    stagingRoot,
    recognitionPolicy,
    destinationPrivateKeyPem,
    issuerPrivateKeyPem,
    initialArtifactBytes = Buffer.from('demo-1-a\n', 'utf8'),
    initialGeneration = 0,
    openingMode = 'initialize_or_open',
    evidenceClaimCeiling = 'software_key_protocol_and_transaction_only',
    clock = () => Math.floor(Date.now() / 1000),
    randomBytesFn = randomBytes,
  }) {
    validatePolicy(recognitionPolicy);
    this.policy = recognitionPolicy;
    this.policyDigest = policyDigest(recognitionPolicy);
    this.destinationPrivateKeyPem = destinationPrivateKeyPem;
    this.destinationPublicKeyPem = publicKeyPem(destinationPrivateKeyPem);
    this.issuerPrivateKeyPem = issuerPrivateKeyPem;
    this.issuerPublicKeyPem = publicKeyPem(issuerPrivateKeyPem);
    this.clock = clock;
    this.randomBytesFn = randomBytesFn;
    this.evidenceClaimCeiling = evidenceClaimCeiling;
    this.stagingRoot = realpathSync(stagingRoot);
    refuse(!lstatSync(this.stagingRoot).isSymbolicLink(), 'staging_root_symlink');
    refuse(keyId(this.destinationPublicKeyPem) === this.policy.destination.key_id, 'destination_key_not_policy');
    refuse(this.policy.destination.status === 'active', 'destination_key_not_active');
    const issuerId = keyId(this.issuerPublicKeyPem);
    const issuer = this.policy.issuers.find((entry) => entry.key_id === issuerId);
    refuse(issuer?.status === 'active', 'issuer_key_not_active');
    this.issuerKeyId = issuerId;
    this.store = new Demo1Store({
      databasePath,
      policyDigest: this.policyDigest,
      initialRelease: {
        generation: initialGeneration,
        stagedObjectId: 'demo-1-a',
        artifactSha256: sha256Id(initialArtifactBytes),
        artifactBytes: Buffer.from(initialArtifactBytes),
      },
      openingMode,
    });
  }

  close() {
    this.store.close();
  }

  activeRelease() {
    return this.store.activeRelease();
  }

  projection() {
    return this.store.projection();
  }

  receipts() {
    return this.store.receipts();
  }

  commits() {
    return this.store.commits();
  }

  challenges() {
    return this.store.challenges();
  }

  grants() {
    return this.store.grants();
  }

  credentials() {
    return this.store.credentials();
  }

  #readStagedBytes() {
    const path = join(this.stagingRoot, STAGED_OBJECT_ID);
    refuse(basename(path) === STAGED_OBJECT_ID, 'staged_object_path');
    const before = lstatSync(path);
    refuse(!before.isSymbolicLink() && before.isFile(), 'staged_object_not_regular');
    refuse(before.nlink === 1, 'staged_object_hardlink');
    let descriptor;
    try {
      descriptor = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
      const opened = fstatSync(descriptor);
      refuse(opened.isFile(), 'staged_object_not_regular');
      refuse(opened.dev === before.dev && opened.ino === before.ino, 'staged_object_raced');
      return readFileSync(descriptor);
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
  }

  issueChallenge({ observedPrincipalId, lifetimeSeconds = 300 }) {
    const issuedAt = nowSeconds(this.clock);
    if (!Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 30 || lifetimeSeconds > 900) {
      throw new Error('challenge_lifetime_out_of_range');
    }
    const bytes = this.#readStagedBytes();
    return this.store.transaction(() => {
      const active = this.store.activeRelease();
      const body = {
        v: 1,
        type: 'challenge',
        profile_id: this.policy.profile_id,
        destination_id: DESTINATION_ID,
        principal_id: observedPrincipalId,
        challenge_nonce: randomNonce(this.randomBytesFn),
        staged_object_id: STAGED_OBJECT_ID,
        artifact_sha256: sha256Id(bytes),
        from_generation: active.generation,
        to_generation: active.generation + 1,
        issued_at: issuedAt,
        expires_at: issuedAt + lifetimeSeconds,
      };
      const record = signRecord('challenge', body, this.destinationPrivateKeyPem);
      this.store.insertChallenge(bodyId('challenge', body), record);
      return record;
    });
  }

  issueCredential({ grantRecord, observedPrincipalId }) {
    return this.store.transaction(() => {
      const facts = this.#verifyGrant(grantRecord, { observedPrincipalId, requireStoredChallenge: true });
      const now = nowSeconds(this.clock);
      refuse(now >= grantRecord.body.not_before && now < grantRecord.body.expires_at, 'grant_not_current');
      const storedGrant = this.store.grant(facts.grantId);
      if (storedGrant === null) {
        this.store.insertGrant(facts.grantId, grantRecord, grantRecord.body.maximum_allocation);
      } else {
        refuse(canonical(storedGrant.record) === canonical(grantRecord), 'grant_identity_collision');
      }
      const body = {
        v: 1,
        type: 'boarding_credential',
        profile_id: grantRecord.body.profile_id,
        issuer_key_id: this.issuerKeyId,
        credential_nonce: randomNonce(this.randomBytesFn),
        grant_id: facts.grantId,
        action: grantRecord.body.action,
        action_id: grantRecord.body.action_id,
        allocation_debit: 1,
        not_before: Math.max(now, grantRecord.body.not_before),
        expires_at: grantRecord.body.expires_at,
      };
      assertExactGrantToCredential(grantRecord.body, body);
      const record = signRecord('credential', body, this.issuerPrivateKeyPem);
      const credentialId = bodyId('credential', body);
      refuse(this.store.credential(credentialId) === null, 'credential_identity_collision');
      this.store.insertCredential(credentialId, facts.grantId, record);
      return record;
    });
  }

  #verifyGrant(grantRecord, { observedPrincipalId, requireStoredChallenge }) {
    validateBody('grant', grantRecord?.body);
    const body = grantRecord.body;
    refuse(body.profile_id === this.policy.profile_id, 'grant_profile_unrecognized');
    refuse(body.action.principal_id === observedPrincipalId, 'grant_principal_mismatch');
    const root = this.policy.roots.find((entry) => entry.key_id === body.authority_root_key_id);
    refuse(root?.status === 'active', 'grant_root_unrecognized');
    const issuer = this.policy.issuers.find((entry) => entry.key_id === body.authorized_issuer_key_id);
    refuse(issuer?.status === 'active', 'grant_issuer_unrecognized');
    verifyRecord('grant', grantRecord, root.public_key_pem);
    const grantId = bodyId('grant', body);
    const challenge = this.store.challenge(body.action.challenge_id);
    if (requireStoredChallenge) refuse(challenge !== null, 'challenge_unrecognized');
    if (challenge !== null) {
      verifyRecord('challenge', challenge.record, this.destinationPublicKeyPem);
      const expected = actionFromChallenge(challenge.record.body);
      refuse(canonical(expected) === canonical(body.action), 'grant_action_not_destination_challenge');
      refuse(body.issued_at >= challenge.record.body.issued_at, 'grant_predates_challenge');
      refuse(body.not_before >= challenge.record.body.issued_at, 'grant_predates_challenge');
      refuse(body.expires_at <= challenge.record.body.expires_at, 'grant_expands_challenge_time');
    }
    return { grantId, root, issuer, challenge };
  }

  #verifyCredential(credentialRecord, grantRecord, issuer) {
    validateBody('credential', credentialRecord?.body);
    verifyRecord('credential', credentialRecord, issuer.public_key_pem);
    assertExactGrantToCredential(grantRecord.body, credentialRecord.body);
    return { credentialId: bodyId('credential', credentialRecord.body) };
  }

  #receiptBody({
    requestId,
    principalId,
    outcome,
    reasonCode,
    challengeId = null,
    actionId = null,
    grantId = null,
    credentialId = null,
    promotionCommitId = null,
    stateBefore,
    stateAfter,
    fromGeneration,
    toGeneration,
    allocationBefore = null,
    allocationDebit,
    allocationAfter = null,
    recordedAt,
  }) {
    const previous = this.store.lastReceipt();
    return {
      v: 1,
      type: 'receipt',
      profile_id: this.policy.profile_id,
      destination_id: DESTINATION_ID,
      destination_key_id: this.policy.destination.key_id,
      sequence: previous === null ? 1 : previous.sequence + 1,
      previous_receipt_hash: previous?.recordHash ?? null,
      request_id: requestId,
      principal_id: principalId,
      outcome,
      reason_code: reasonCode,
      challenge_id: challengeId,
      action_id: actionId,
      grant_id: grantId,
      credential_id: credentialId,
      promotion_commit_id: promotionCommitId,
      state_before_sha256: stateBefore,
      state_after_sha256: stateAfter,
      from_generation: fromGeneration,
      to_generation: toGeneration,
      allocation_before: allocationBefore,
      allocation_debit: allocationDebit,
      allocation_after: allocationAfter,
      recognition_policy_sha256: this.policyDigest,
      recorded_at: recordedAt,
    };
  }

  #appendRefusal({ requestId, principalId, reasonCode, facts = {} }) {
    return this.store.transaction(() => {
      const existing = this.store.request(requestId);
      if (existing !== null) return existing.receipt;
      const active = this.store.activeRelease();
      const state = stateDigest(active);
      let allocationBefore = null;
      let allocationAfter = null;
      if (facts.grantId) {
        const grant = this.store.grant(facts.grantId);
        if (grant !== null) {
          allocationBefore = grant.maximumAllocation - grant.spentAllocation;
          allocationAfter = allocationBefore;
        }
      }
      const body = this.#receiptBody({
        requestId,
        principalId,
        outcome: 'refused',
        reasonCode,
        challengeId: facts.challengeId ?? null,
        actionId: facts.actionId ?? null,
        grantId: facts.grantId ?? null,
        credentialId: facts.credentialId ?? null,
        stateBefore: state,
        stateAfter: state,
        fromGeneration: active.generation,
        toGeneration: active.generation,
        allocationBefore,
        allocationDebit: 0,
        allocationAfter,
        recordedAt: nowSeconds(this.clock),
      });
      const record = signRecord('receipt', body, this.destinationPrivateKeyPem);
      this.store.insertReceipt({
        record,
        recordHash: signedRecordHash(record),
        requestId,
        outcome: 'refused',
      });
      return record;
    });
  }

  promote(requestInput, { observedPrincipalId, faultAt = null } = {}) {
    let request;
    let requestId = null;
    let challengeId = null;
    try {
      const looselyParsed = parseCanonical(requestInput);
      requestId = typeof looselyParsed?.request_id === 'string' && REQUEST_ID.test(looselyParsed.request_id)
        ? looselyParsed.request_id : null;
      challengeId = typeof looselyParsed?.challenge_id === 'string' && SAFE_ID.test(looselyParsed.challenge_id)
        ? looselyParsed.challenge_id : null;
      request = parsePromotionRequest(requestInput);
      requestId = request.request_id;
      challengeId = request.challenge_id;
    } catch (error) {
      if (requestId === null) throw error;
      return this.#appendRefusal({
        requestId,
        principalId: observedPrincipalId,
        reasonCode: error instanceof ProtocolError ? error.code : 'malformed_request',
        facts: { challengeId },
      });
    }

    const existing = this.store.request(requestId);
    if (existing !== null) return existing.receipt;

    if (request.grant === null || request.credential === null) {
      return this.#appendRefusal({
        requestId,
        principalId: observedPrincipalId,
        reasonCode: 'missing_authority',
        facts: { challengeId },
      });
    }

    const facts = { challengeId };
    try {
      const result = this.store.transaction(() => {
        const duplicate = this.store.request(requestId);
        if (duplicate !== null) return duplicate.receipt;

        const grantFacts = this.#verifyGrant(request.grant, {
          observedPrincipalId,
          requireStoredChallenge: true,
        });
        const verifiedChallengeId = request.grant.body.action.challenge_id;
        facts.challengeId = verifiedChallengeId;
        refuse(request.challenge_id === verifiedChallengeId, 'request_challenge_mismatch', facts);
        facts.grantId = grantFacts.grantId;
        facts.actionId = request.grant.body.action_id;
        const credentialFacts = this.#verifyCredential(request.credential, request.grant, grantFacts.issuer);
        facts.credentialId = credentialFacts.credentialId;

        const challenge = grantFacts.challenge;
        let lastAuthorityTime = null;
        const assertCurrentAuthority = (now) => {
          refuse(lastAuthorityTime === null || now >= lastAuthorityTime, 'destination_clock_regressed', facts);
          refuse(now >= request.grant.body.not_before && now < request.grant.body.expires_at, 'grant_not_current', facts);
          refuse(now >= request.credential.body.not_before && now < request.credential.body.expires_at, 'credential_not_current', facts);
          refuse(now < challenge.record.body.expires_at, 'challenge_expired', facts);
          lastAuthorityTime = now;
        };
        assertCurrentAuthority(nowSeconds(this.clock));

        const grant = this.store.grant(facts.grantId);
        refuse(grant !== null, 'grant_not_issued', facts);
        refuse(canonical(grant.record) === canonical(request.grant), 'grant_identity_collision', facts);
        refuse(grant.spentAllocation + request.credential.body.allocation_debit <= grant.maximumAllocation, 'grant_allocation_exhausted', facts);

        const priorCredential = this.store.credential(facts.credentialId);
        refuse(priorCredential !== null, 'credential_not_issued', facts);
        refuse(canonical(priorCredential.record) === canonical(request.credential), 'credential_identity_collision', facts);
        refuse(!priorCredential.used, 'credential_replay', facts);

        refuse(!challenge.consumed, 'challenge_consumed', facts);
        const activeBefore = this.store.activeRelease();
        refuse(activeBefore.generation === challenge.record.body.from_generation, 'stale_generation', facts);
        const stagedBytes = this.#readStagedBytes();
        refuse(sha256Id(stagedBytes) === challenge.record.body.artifact_sha256, 'staged_artifact_changed', facts);
        const action = actionFromChallenge(challenge.record.body);
        refuse(canonical(action) === canonical(request.grant.body.action), 'destination_action_mismatch', facts);
        fault('after_verification', faultAt);

        const allocationBefore = grant.maximumAllocation - grant.spentAllocation;
        const committedAt = nowSeconds(this.clock);
        assertCurrentAuthority(committedAt);
        const commitBody = {
          v: 1,
          type: 'promotion_commit',
          profile_id: this.policy.profile_id,
          destination_id: DESTINATION_ID,
          principal_id: observedPrincipalId,
          request_id: requestId,
          challenge_id: facts.challengeId,
          action_id: facts.actionId,
          grant_id: facts.grantId,
          credential_id: facts.credentialId,
          staged_object_id: STAGED_OBJECT_ID,
          artifact_sha256: action.artifact_sha256,
          from_generation: activeBefore.generation,
          to_generation: activeBefore.generation + 1,
          allocation_before: allocationBefore,
          allocation_debit: 1,
          allocation_after: allocationBefore - 1,
          recognition_policy_sha256: this.policyDigest,
          destination_nonce: randomNonce(this.randomBytesFn),
          committed_at: committedAt,
        };
        const commitRecord = signRecord('commit', commitBody, this.destinationPrivateKeyPem);
        const commitId = signedRecordHash(commitRecord);
        fault('after_commit_formed', faultAt);

        this.store.insertCommit(commitId, requestId, commitRecord);
        fault('after_commit_inserted', faultAt);
        this.store.debitGrant(facts.grantId, 1);
        fault('after_debit', faultAt);
        this.store.consumeCredential(facts.credentialId);
        this.store.consumeChallenge(facts.challengeId);
        fault('after_consumption', faultAt);
        this.store.updateActiveRelease({
          generation: action.to_generation,
          stagedObjectId: action.staged_object_id,
          artifactSha256: action.artifact_sha256,
          artifactBytes: stagedBytes,
        });
        fault('after_active_update', faultAt);

        const activeAfter = this.store.activeRelease();
        const recordedAt = nowSeconds(this.clock);
        assertCurrentAuthority(recordedAt);
        const receiptBody = this.#receiptBody({
          requestId,
          principalId: observedPrincipalId,
          outcome: 'executed',
          reasonCode: null,
          challengeId: facts.challengeId,
          actionId: facts.actionId,
          grantId: facts.grantId,
          credentialId: facts.credentialId,
          promotionCommitId: commitId,
          stateBefore: stateDigest(activeBefore),
          stateAfter: stateDigest(activeAfter),
          fromGeneration: activeBefore.generation,
          toGeneration: activeAfter.generation,
          allocationBefore,
          allocationDebit: 1,
          allocationAfter: allocationBefore - 1,
          recordedAt,
        });
        const receipt = signRecord('receipt', receiptBody, this.destinationPrivateKeyPem);
        fault('after_receipt_formed', faultAt);
        this.store.insertReceipt({
          record: receipt,
          recordHash: signedRecordHash(receipt),
          requestId,
          outcome: 'executed',
        });
        fault('before_transaction_commit', faultAt);
        // Staging I/O, hashing, signing, and SQL writes may cross expiry.
        // Recheck at the last pre-commit decision point; a refusal rolls back
        // the debit, consumption, effect, commit record, and execution receipt.
        assertCurrentAuthority(nowSeconds(this.clock));
        return receipt;
      });
      if (faultAt === 'after_commit_before_response') throw new PostCommitFault();
      return result;
    } catch (error) {
      if (error instanceof InjectedFault || error instanceof PostCommitFault) throw error;
      const reasonCode = error instanceof DestinationRefusal
        ? error.code
        : error instanceof ProtocolError
          ? error.code
          : error instanceof StoreError
            ? error.code
            : 'destination_failure';
      return this.#appendRefusal({
        requestId,
        principalId: observedPrincipalId,
        reasonCode,
        facts,
      });
    }
  }

  evidenceBundle() {
    const projection = this.projection();
    return {
      v: 2,
      type: 'demo1_evidence',
      claim_ceiling: this.evidenceClaimCeiling,
      recognition_policy: this.policy,
      recognition_policy_sha256: this.policyDigest,
      destination_public_key_pem: this.destinationPublicKeyPem,
      challenges: this.challenges().map((entry) => ({
        challenge_id: entry.challengeId,
        record: entry.record,
        consumed: entry.consumed,
      })),
      grants: this.grants().map((entry) => ({
        grant_id: entry.grantId,
        record: entry.record,
        maximum_allocation: entry.maximumAllocation,
        spent_allocation: entry.spentAllocation,
      })),
      credentials: this.credentials().map((entry) => ({
        credential_id: entry.credentialId,
        grant_id: entry.grantId,
        record: entry.record,
        used: entry.used,
      })),
      commits: this.commits(),
      receipts: this.receipts(),
      final_projection: {
        active: {
          generation: projection.active.generation,
          staged_object_id: projection.active.stagedObjectId,
          artifact_sha256: projection.active.artifactSha256,
          artifact_bytes_base64url: projection.active.artifactBytes.toString('base64url'),
          state_sha256: stateDigest(projection.active),
        },
        grants: projection.grants.map((grant) => ({
          grant_id: grant.grantId,
          maximum_allocation: grant.maximumAllocation,
          spent_allocation: grant.spentAllocation,
        })),
        credentials: projection.credentials.map((credential) => ({
          credential_id: credential.credentialId,
          grant_id: credential.grantId,
          used: credential.used,
        })),
        commit_count: projection.commitCount,
        receipt_count: projection.receiptCount,
      },
    };
  }
}
