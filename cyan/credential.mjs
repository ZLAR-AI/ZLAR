// A ZLAR authorization credential.
//
// It is bound to one envelope digest, one principal, one destination, a validity
// window, and a consumption discipline. It carries no description of the action
// the guard is willing to trust — only the digest, which the guard recomputes.
//
// Ed25519 today. The suite is named in the credential so the field can be
// migrated across centuries without ambiguity about what verified what.

import { createPrivateKey, createPublicKey, sign, verify, randomUUID } from 'node:crypto';
import { canonicalBytes } from './canonical.mjs';

export const SUITE = 'ed25519-2020';

// Authority grammar. One-use is the atom, not the prison.
export const USE = Object.freeze({
  ONCE: 'once',       // single crossing, consumed on execution
  LEASE: 'lease',     // continuing authority, valid until exp, renewed or it ends
});

export function issue({ issuerKid, privateKeyPem, envelopeDigest, principal, destination,
                        use = USE.ONCE, notBefore, expiresAt, budget }) {
  if (!envelopeDigest) throw new Error('envelopeDigest is required');
  if (!expiresAt) throw new Error('expiresAt is required — authority that never expires is not authority, it is a standing grant of sovereignty');
  if (budget !== undefined && (!Number.isInteger(budget) || budget < 0)) {
    throw new Error('budget must be a non-negative integer in smallest units');
  }

  const claims = {
    v: 1,
    suite: SUITE,
    cid: randomUUID(),
    iss: issuerKid,
    principal,
    destination,
    digest: envelopeDigest,
    use,
    nbf: notBefore ?? Math.floor(Date.now() / 1000),
    exp: expiresAt,
    ...(budget === undefined ? {} : { budget }),
  };

  const signature = sign(null, canonicalBytes(claims), createPrivateKey(privateKeyPem));
  return { claims, sig: signature.toString('base64') };
}

export function verifySignature(credential, publicKeyPem) {
  try {
    return verify(
      null,
      canonicalBytes(credential.claims),
      createPublicKey(publicKeyPem),
      Buffer.from(credential.sig, 'base64'),
    );
  } catch {
    return false;
  }
}
