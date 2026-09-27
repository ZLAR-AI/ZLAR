// The exact action envelope, and its digest.
//
// The digest is what a credential is bound to. The guard RECOMPUTES it from the
// action it is actually about to perform — it never trusts a description carried
// inside the credential. That is the whole defence against semantic escape: an
// agent that changes the effect after authorization changes the digest, and the
// credential no longer matches anything.

import { createHash } from 'node:crypto';
import { canonicalBytes } from './canonical.mjs';

// Consequence classes endure; tool names expire. An envelope declares which
// enduring effect is being attempted, never which tool was used to attempt it.
export const CONSEQUENCE_CLASSES = Object.freeze([
  'value.transfer',
  'ownership.alter',
  'record.change',
  'code.deploy',
  'information.disclose',
  'institution.bind',
  'machinery.activate',
  'energy.allocate',
  'material.move',
  'access.change',
  'state.action.issue',
  'physical.irreversible',
]);

export function makeEnvelope({ consequence, principal, destination, params, measure }) {
  if (!CONSEQUENCE_CLASSES.includes(consequence)) {
    throw new Error(`unknown consequence class: ${consequence}`);
  }
  if (!principal || !destination) throw new Error('principal and destination are required');
  if (measure !== undefined && (!Number.isInteger(measure) || measure < 0)) {
    throw new Error('measure must be a non-negative integer in smallest units');
  }
  return {
    v: 1,
    consequence,
    principal,
    destination,
    params: params ?? {},
    ...(measure === undefined ? {} : { measure }),
  };
}

export function envelopeDigest(envelope) {
  return createHash('sha256').update(canonicalBytes(envelope)).digest('hex');
}
