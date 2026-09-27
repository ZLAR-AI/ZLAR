// What the destination signs, so an execution or a refusal is provable later
// without trusting the agent, the orchestrator, ZLAR, or any ledger.
//
// A receipt is not evidence unless all three of these hold. Each one exists
// because the absence of it has a known failure:
//
//   1. ATTRIBUTABLE — signed by a NAMED destination key and verifiable offline
//      by anyone holding that public key. Nothing is asked of ZLAR at
//      verification time. A receipt that can only be checked by calling the
//      system that issued it is that system's word, restated.
//
//   2. NON-AUTHORITY — the signature is domain-separated, so a receipt can
//      never be presented as a credential and a credential can never be
//      presented as a receipt. "Evidence is never authority" is an invariant;
//      here it is arithmetic instead of a rule someone must remember. A
//      destination that signs a million receipts has not thereby minted a
//      million authorizations.
//
//   3. GAP-EVIDENT — every receipt carries its sequence number and the hash of
//      the receipt before it. One signed receipt proves one event happened. It
//      says nothing about what is missing, and a history that can be quietly
//      pruned is a history that will be pruned exactly where it matters. The
//      chain does not prevent deletion; it makes deletion visible, which is the
//      most a destination can honestly offer.
//
// Note on (2): only receipts carry the domain tag. That is sufficient for mutual
// non-interchangeability — a credential signed over bare canonical bytes cannot
// satisfy a verifier that prepends the tag, and a receipt cannot satisfy one
// that does not. Credentials are left untagged so this slice changes no
// credential on the wire.

import { createHash, createPublicKey, createPrivateKey, sign, verify } from 'node:crypto';
import { canonical, canonicalBytes } from './canonical.mjs';
export { canonicalBytes };

export const RECEIPT_DOMAIN = 'zlar.receipt.v1';

// The four terminal truths a destination can tell about one attempted crossing.
// AUTHORIZED is deliberately not terminal: it records that authority was
// recognized, and it is followed by EXECUTED or FAILED. An AUTHORIZED with no
// successor in the chain is a dangling authorization — visible, and exactly the
// thing an auditor should ask about.
export const OUTCOME = Object.freeze({
  AUTHORIZED: 'authorized',
  EXECUTED: 'executed',
  FAILED: 'failed',
  REFUSED: 'refused',
});

export const INVALID = Object.freeze({
  MALFORMED: 'malformed',
  UNSIGNED: 'unsigned',
  UNKNOWN_VERSION: 'unknown_version',
  UNNAMED_SIGNER: 'unnamed_signer',
  WRONG_SIGNER: 'wrong_signer',
  WRONG_DESTINATION: 'wrong_destination',
  BAD_SIGNATURE: 'bad_signature',
  UNKNOWN_OUTCOME: 'unknown_outcome',
  SEQUENCE_GAP: 'sequence_gap',
  BROKEN_LINK: 'broken_link',
  NOT_FROM_GENESIS: 'not_from_genesis',
  TRUNCATED_BELOW_HEAD: 'truncated_below_head',
});

// The signed preimage. The domain tag is inside the signature, not beside it —
// a tag that travels next to the signature is a tag an attacker can change.
export function receiptPreimage(body) {
  return Buffer.concat([Buffer.from(`${RECEIPT_DOMAIN}\0`, 'utf8'), canonicalBytes(body)]);
}

// The hash of a whole record — body AND signature. Chaining over the signature
// too means a re-signing of the same body by a different key breaks the link
// rather than silently substituting.
export function receiptHash(record) {
  return createHash('sha256')
    .update(canonicalBytes({ body: record.body, sig: record.sig ?? null }))
    .digest('hex');
}

// A digest of the guard's recognition rules — which issuers it accepts, their
// keys, and their revocations.
//
// A receipt that records only what happened is missing half the question an
// auditor asks. "This crossing was authorized" means nothing without "authorized
// under which rules". Change which issuers a destination recognizes and you have
// changed what authority means there, silently, with every existing receipt
// still verifying. Binding the recognition state into the receipt makes that
// change visible: receipts from before and after carry different digests, and an
// auditor can tell they are not comparable.
//
// Borrowed from Orange's orange-receipt-v1, which binds the policy and
// constitution hashes in force at the decision. Same idea, Cyan's vocabulary.
export function recognitionDigest(issuerRegistry) {
  const normalized = {};
  for (const kid of Object.keys(issuerRegistry ?? {}).sort()) {
    const entry = issuerRegistry[kid] ?? {};
    normalized[kid] = {
      publicKeyPem: String(entry.publicKeyPem ?? ''),
      revokedAt: entry.revokedAt ?? null,
    };
  }
  return createHash('sha256').update(canonicalBytes(normalized)).digest('hex');
}

// Returns { kid, sign(body) -> base64 }. The destination holds this. ZLAR does
// not, which is the point: ZLAR cannot forge a receipt saying it was obeyed.
export function receiptSigner({ kid, privateKeyPem }) {
  if (!kid) throw new Error('receipt signer requires a kid — an unnamed signer is an unattributable receipt');
  const key = createPrivateKey(privateKeyPem);
  return {
    kid,
    sign: (body) => sign(null, receiptPreimage(body), key).toString('base64'),
  };
}

// Verify one receipt in isolation. Offline, third-party, no ZLAR.
// Refusal is the default: every unrecognized condition is invalid.
export function verifyReceipt(record, { publicKeyPem, destinationId, kid } = {}) {
  const bad = (reason) => ({ ok: false, reason });

  if (!record || typeof record !== 'object' || !record.body) return bad(INVALID.MALFORMED);
  const b = record.body;

  if (b.v !== 1) return bad(INVALID.UNKNOWN_VERSION);
  if (!Object.values(OUTCOME).includes(b.outcome)) return bad(INVALID.UNKNOWN_OUTCOME);
  if (!record.sig) return bad(INVALID.UNSIGNED);
  if (!b.kid) return bad(INVALID.UNNAMED_SIGNER);
  if (kid !== undefined && b.kid !== kid) return bad(INVALID.WRONG_SIGNER);
  if (destinationId !== undefined && b.destination !== destinationId) return bad(INVALID.WRONG_DESTINATION);

  let ok = false;
  try {
    ok = verify(null, receiptPreimage(b), createPublicKey(publicKeyPem), Buffer.from(record.sig, 'base64'));
  } catch {
    return bad(INVALID.BAD_SIGNATURE);
  }
  return ok ? { ok: true, reason: null } : bad(INVALID.BAD_SIGNATURE);
}

// Verify a run of receipts as a chain.
//
// This is the part that answers "did anything happen that was not recorded?".
// It cannot answer it for a destination that never wrote a receipt at all — no
// cryptography can — but it makes any REMOVAL from a written history detectable,
// and that is the honest bound. State it that way and no further.
//
// expectFrom defaults to 1: by default a caller is asking "is this the whole
// history?". Pass expectFrom: null to verify a window without claiming it starts
// at the beginning.
export function verifyChain(records, { publicKeyPem, destinationId, kid, expectFrom = 1 } = {}) {
  if (!Array.isArray(records) || records.length === 0) {
    return { ok: false, reason: INVALID.MALFORMED, at: null };
  }

  if (expectFrom !== null && records[0].body?.seq !== expectFrom) {
    return { ok: false, reason: INVALID.NOT_FROM_GENESIS, at: 0 };
  }

  let prevHash = expectFrom === 1 ? null : undefined;
  let prevSeq = null;

  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const one = verifyReceipt(r, { publicKeyPem, destinationId, kid });
    if (!one.ok) return { ok: false, reason: one.reason, at: i };

    const seq = r.body.seq;
    if (!Number.isInteger(seq) || seq < 1) return { ok: false, reason: INVALID.MALFORMED, at: i };
    if (prevSeq !== null && seq !== prevSeq + 1) return { ok: false, reason: INVALID.SEQUENCE_GAP, at: i };

    // prevHash is undefined only for the first record of a mid-history window,
    // where there is nothing to compare against and no claim is being made.
    if (prevHash !== undefined && (r.body.prev ?? null) !== prevHash) {
      return { ok: false, reason: INVALID.BROKEN_LINK, at: i };
    }

    prevSeq = seq;
    prevHash = receiptHash(r);
  }

  return { ok: true, reason: null, at: null, from: records[0].body.seq, to: prevSeq, head: prevHash };
}

// ── Published heads ────────────────────────────────────────────────────────
//
// The chain catches deletion from the middle. It cannot catch truncation of the
// tail: lop off the newest entries and what remains is a shorter, internally
// consistent history. Nothing inside a chain can fix that, because the evidence
// that something is missing was the thing removed.
//
// The fix is to put a claim about the chain's length somewhere the destination
// cannot later retract: a small signed statement — "at this moment my chain was
// N entries long and ended with this hash" — published to anyone who cares.
// Hand it to a counterparty, an auditor, a regulator, a log service; the
// mechanism does not care where it goes, only that the destination no longer
// controls every copy.
//
// A head is deliberately NOT a receipt and carries its own domain tag, so
// neither can be presented as the other. Same discipline as evidence-vs-
// authority: a claim about the record is not itself a record of an event.

export const HEAD_DOMAIN = 'zlar.receipt-head.v1';

export function headPreimage(body) {
  return Buffer.concat([Buffer.from(`${HEAD_DOMAIN}\0`, 'utf8'), canonicalBytes(body)]);
}

// The head signer is deliberately a separate object from the receipt signer even
// when it wraps the same key — so a caller cannot pass one where the other is
// expected and quietly produce a statement that verifies as the wrong thing.
export function headSigner({ kid, privateKeyPem }) {
  if (!kid) throw new Error('head signer requires a kid');
  const key = createPrivateKey(privateKeyPem);
  return { kid, sign: (body) => sign(null, headPreimage(body), key).toString('base64') };
}

export function signHead({ destination, kid, seq, hash, at, sign }) {
  const body = { v: 1, destination, kid, seq, hash: hash ?? null, at };
  return { body, sig: sign ? sign(body) : null };
}

export function verifyHead(record, { publicKeyPem, destinationId, kid } = {}) {
  const bad = (reason) => ({ ok: false, reason });
  if (!record || !record.body) return bad(INVALID.MALFORMED);
  const b = record.body;
  if (b.v !== 1) return bad(INVALID.UNKNOWN_VERSION);
  if (!record.sig) return bad(INVALID.UNSIGNED);
  if (!b.kid) return bad(INVALID.UNNAMED_SIGNER);
  if (kid !== undefined && b.kid !== kid) return bad(INVALID.WRONG_SIGNER);
  if (destinationId !== undefined && b.destination !== destinationId) return bad(INVALID.WRONG_DESTINATION);
  if (!Number.isInteger(b.seq) || b.seq < 0) return bad(INVALID.MALFORMED);
  let ok = false;
  try {
    ok = verify(null, headPreimage(b), createPublicKey(publicKeyPem), Buffer.from(record.sig, 'base64'));
  } catch {
    return bad(INVALID.BAD_SIGNATURE);
  }
  return ok ? { ok: true, reason: null } : bad(INVALID.BAD_SIGNATURE);
}

// Verify a chain AND hold it against a head the destination previously signed.
// A history shorter than a head the destination itself published is a history
// that has been truncated, and the destination's own signature says so.
export function verifyChainAgainstHead(records, head, options = {}) {
  const chain = verifyChain(records, options);
  if (!chain.ok) return chain;

  const headCheck = verifyHead(head, options);
  if (!headCheck.ok) return { ok: false, reason: headCheck.reason, at: null, scope: 'head' };

  if (chain.to < head.body.seq) {
    return { ok: false, reason: INVALID.TRUNCATED_BELOW_HEAD, at: null,
             have: chain.to, published: head.body.seq };
  }
  // At exactly the published length the tail hash must match too — otherwise the
  // last entry was swapped rather than removed.
  if (chain.to === head.body.seq && chain.head !== head.body.hash) {
    return { ok: false, reason: INVALID.BROKEN_LINK, at: records.length - 1, scope: 'head' };
  }
  return { ...chain, anchoredAt: head.body.seq };
}

// Human-readable rendering for an auditor. Deliberately derived from the SIGNED
// body only — anything shown here is something the destination put its name to.
export function describeReceipt(record) {
  const b = record.body;
  const what = b.outcome === OUTCOME.REFUSED ? `refused (${b.refusal})` : b.outcome;
  return `#${b.seq ?? '?'} ${b.destination} ${what} ${b.consequence}` +
         `${b.measure === undefined ? '' : ` measure=${b.measure}`} by ${b.principal} at ${b.at}` +
         ` digest=${String(b.digest).slice(0, 12)}…`;
}

export { canonical };
