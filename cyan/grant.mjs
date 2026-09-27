// A standing grant: authority that is not recreated for every action.
//
// One-use is the atom, not the prison. Routine action must move at machine speed
// inside bounded standing authority; only the exceptional stops for a human.
//
// Invariant 1: delegation is a MEET, never a join. A derived grant is the
// greatest lower bound of what was held and what was asked for. Authority can
// only narrow or stay equal along a chain — never enlarge. That is algebra, not
// a rule anyone is asked to follow.

import { createPrivateKey, createPublicKey, sign, verify, randomUUID } from 'node:crypto';
import { canonicalBytes } from './canonical.mjs';

export const SUITE = 'ed25519-2020';

export function issueGrant({ issuerKid, privateKeyPem, principal, destination,
                             ceilings, allow, prohibitions = [], elevations = [],
                             windowSeconds, expiresAt, parent = null }) {
  if (!expiresAt) throw new Error('expiresAt is required — a grant without an expiry is a transfer of sovereignty');
  if (!windowSeconds) throw new Error('windowSeconds is required — composition needs a bounded horizon');

  const claims = {
    v: 1, suite: SUITE, gid: randomUUID(), iss: issuerKid,
    principal, destination,
    allow,                 // [{ class, scope? }] — what may be attempted at all
    ceilings,              // { class: maxCumulativeMeasure } over the window
    prohibitions,          // combinations no grant may permit
    elevations,            // composition rules this destination recognizes
    window: windowSeconds, // the horizon over which cumulative effect is summed
    exp: expiresAt,
    ...(parent ? { parent } : {}),
  };
  const sig = sign(null, canonicalBytes(claims), createPrivateKey(privateKeyPem)).toString('base64');
  return { claims, sig };
}

export function verifyGrant(grant, publicKeyPem) {
  try {
    return verify(null, canonicalBytes(grant.claims), createPublicKey(publicKeyPem),
                  Buffer.from(grant.sig, 'base64'));
  } catch { return false; }
}

// The meet. Everything narrows; nothing widens.
export function delegate({ parentGrant, requested, issuerKid, privateKeyPem }) {
  const p = parentGrant.claims;

  // allow: intersection. A child may only attempt classes the parent could.
  const allow = (requested.allow ?? p.allow).filter((r) =>
    p.allow.some((pa) => pa.class === r.class &&
      Object.keys(pa.scope ?? {}).every((k) => (r.scope ?? {})[k] === pa.scope[k])));

  // ceilings: per class, min(parent, requested). Absent in parent = not grantable.
  const ceilings = {};
  for (const [cls, want] of Object.entries(requested.ceilings ?? p.ceilings)) {
    if (p.ceilings[cls] === undefined) continue;
    ceilings[cls] = Math.min(p.ceilings[cls], want);
  }

  return issueGrant({
    issuerKid, privateKeyPem,
    principal: requested.principal,
    destination: p.destination,
    allow,
    ceilings,
    // prohibitions and elevations are a UNION — constraints only accumulate.
    prohibitions: [...p.prohibitions, ...(requested.prohibitions ?? [])],
    elevations: [...p.elevations, ...(requested.elevations ?? [])],
    windowSeconds: Math.min(p.window, requested.windowSeconds ?? p.window),
    expiresAt: Math.min(p.exp, requested.expiresAt ?? p.exp),
    parent: p.gid,
  });
}
