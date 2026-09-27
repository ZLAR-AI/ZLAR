// Exact one-request installed destination surface. The caller may stage bytes,
// ask for N, transport signed G/A, request promotion, or read public evidence.
// Identity is supplied only by the protected kernel-peer broker.

import {
  ProtocolError,
  bodyId,
  canonicalBytes,
  parseCanonical,
} from '../../cyan/demo1-protocol.mjs';
import {
  CLIENT_PRINCIPAL_ID,
  CLIENT_UID,
  INSTALLED_CLAIM_CEILING,
  INSTALLED_PROFILE_ID,
} from './demo1-installed-profile.mjs';

function refuse(condition, code) {
  if (!condition) throw new ProtocolError(code);
}

function exactKeys(value, expected, label) {
  refuse(value !== null && typeof value === 'object' && !Array.isArray(value), `${label}_wrong_type`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  refuse(actual.length === wanted.length && actual.every((key, index) => key === wanted[index]), `${label}_unknown_or_missing_field`);
}

export function handleInstalledRequest(raw, {
  destination,
  peerUid,
} = {}) {
  refuse(Number.isSafeInteger(peerUid) && peerUid === CLIENT_UID, 'peer_uid_refused');
  const request = parseCanonical(raw);
  exactKeys(request, request?.operation === 'credential'
    ? ['grant', 'operation']
    : request?.operation === 'promote'
      ? ['operation', 'request']
      : ['operation'], 'ipc_request');

  switch (request.operation) {
    case 'health': {
      const active = destination.activeRelease();
      return {
        v: 1,
        status: 'DESTINATION_REACHED',
        profile_id: INSTALLED_PROFILE_ID,
        claim_ceiling: INSTALLED_CLAIM_CEILING,
        observed_principal_id: CLIENT_PRINCIPAL_ID,
        active_generation: active.generation,
        recognition_policy_sha256: destination.policyDigest,
      };
    }
    case 'challenge': {
      const challenge = destination.issueChallenge({
        observedPrincipalId: CLIENT_PRINCIPAL_ID,
      });
      return {
        v: 1,
        status: 'CHALLENGE_ISSUED',
        challenge_id: bodyId('challenge', challenge.body),
        challenge,
      };
    }
    case 'credential': {
      const credential = destination.issueCredential({
        grantRecord: request.grant,
        observedPrincipalId: CLIENT_PRINCIPAL_ID,
      });
      return {
        v: 1,
        status: 'CREDENTIAL_DERIVED',
        credential_id: bodyId('credential', credential.body),
        credential,
      };
    }
    case 'promote': {
      const receipt = destination.promote(canonicalBytes(request.request), {
        observedPrincipalId: CLIENT_PRINCIPAL_ID,
      });
      return {
        v: 1,
        status: receipt.body.outcome === 'executed' ? 'EFFECT_EXECUTED' : 'EFFECT_REFUSED',
        receipt,
      };
    }
    case 'evidence':
      return destination.evidenceBundle();
    default:
      throw new ProtocolError('operation_refused');
  }
}
