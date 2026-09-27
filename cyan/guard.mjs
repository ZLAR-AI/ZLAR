// The destination-owned guard.
//
// It is owned by the destination, runs inside the destination's trust boundary,
// and answers exactly one question before any effect:
//
//     Does this exact action carry authority I recognize?
//
// It does not trust the agent, the runtime, the orchestrator, the ledger, or the
// credential's own account of what it authorizes. It recomputes the digest from
// the action it is about to perform and compares.
//
// Refusal is the default. Every unrecognized condition refuses.

import { envelopeDigest } from './envelope.mjs';
import { verifySignature, USE } from './credential.mjs';
import { ReplayStore } from './replay-store.mjs';
import { GrantStore } from './grant-store.mjs';
import { verifyGrant } from './grant.mjs';
import { effectOf, join, prohibited, matches } from './lattice.mjs';
import { OUTCOME, recognitionDigest } from './receipt.mjs';

export const REFUSAL = Object.freeze({
  NO_CREDENTIAL: 'no_credential',
  UNRECOGNIZED_ISSUER: 'unrecognized_issuer',
  BAD_SIGNATURE: 'bad_signature',
  WRONG_DESTINATION: 'wrong_destination',
  WRONG_PRINCIPAL: 'wrong_principal',
  ACTION_MISMATCH: 'action_mismatch',
  NOT_YET_VALID: 'not_yet_valid',
  EXPIRED: 'expired',
  ALREADY_CONSUMED: 'already_consumed',
  BUDGET_EXCEEDED: 'budget_exceeded',
  UNKNOWN_USE: 'unknown_use',
  GRANT_EXPIRED: 'grant_expired',
  NOT_IN_ALLOW: 'not_in_allow',
  CEILING_EXCEEDED: 'ceiling_exceeded',
  PROHIBITED_COMBINATION: 'prohibited_combination',
});

export class Guard {
  // issuerRegistry: { kid -> { publicKeyPem, revokedAt? } }
  // Recognition is local. The guard never calls home at execution time — a guard
  // that must reach a server to decide is a guard that fails in a partition.
  // receiptKid names the destination key that signs receipts, and receiptLog is
  // the destination's own chain. Both are optional only so that slice-one
  // callers keep working; a receipt with no named signer and no position in a
  // chain will not survive verifyReceipt(), which is the correct outcome — it
  // is a note, not evidence.
  constructor({ destinationId, issuerRegistry, replayDir, grantDir, signReceipt, receiptKid, receiptLog }) {
    this.destinationId = destinationId;
    this.issuers = issuerRegistry;
    this.replay = new ReplayStore(replayDir);
    this.grantDir = grantDir ?? replayDir;
    this.signReceipt = signReceipt;
    this.receiptKid = receiptKid ?? null;
    this.receiptLog = receiptLog ?? null;
    // Which rules were in force. Computed once at construction: a guard whose
    // recognition changes is a different guard, and its receipts should say so.
    this.recognition = recognitionDigest(issuerRegistry);
  }

  // Returns { authorized: true, receipt } or { authorized: false, refusal, receipt }.
  // The caller must not perform the effect unless authorized is true.
  authorize({ envelope, credential, now = Math.floor(Date.now() / 1000) }) {
    const refuse = (refusal) => ({
      authorized: false,
      refusal,
      receipt: this.#receipt({ outcome: OUTCOME.REFUSED, refusal, envelope, credential, now }),
    });

    if (!credential || !credential.claims) return refuse(REFUSAL.NO_CREDENTIAL);
    const c = credential.claims;

    const issuer = this.issuers[c.iss];
    if (!issuer) return refuse(REFUSAL.UNRECOGNIZED_ISSUER);
    if (issuer.revokedAt !== undefined && issuer.revokedAt <= now) {
      return refuse(REFUSAL.UNRECOGNIZED_ISSUER);
    }

    // Signature before anything derived from the claims is believed.
    if (!verifySignature(credential, issuer.publicKeyPem)) return refuse(REFUSAL.BAD_SIGNATURE);

    // This guard speaks only for its own destination. A credential minted for
    // somewhere else is not weaker authority here — it is no authority here.
    if (c.destination !== this.destinationId) return refuse(REFUSAL.WRONG_DESTINATION);
    if (c.principal !== envelope.principal) return refuse(REFUSAL.WRONG_PRINCIPAL);

    // No semantic escape: recomputed here, never read from the credential.
    if (envelopeDigest(envelope) !== c.digest) return refuse(REFUSAL.ACTION_MISMATCH);

    if (now < c.nbf) return refuse(REFUSAL.NOT_YET_VALID);
    if (now >= c.exp) return refuse(REFUSAL.EXPIRED);

    if (c.budget !== undefined) {
      const measure = envelope.measure ?? 0;
      if (measure > c.budget) return refuse(REFUSAL.BUDGET_EXCEEDED);
    }

    if (c.use !== USE.ONCE && c.use !== USE.LEASE) return refuse(REFUSAL.UNKNOWN_USE);

    // Consumption is the last gate and is atomic. Under a race the kernel picks
    // one winner; everyone else is refused as already consumed.
    if (c.use === USE.ONCE && !this.replay.claim(c.cid, c.exp)) {
      return refuse(REFUSAL.ALREADY_CONSUMED);
    }

    // AUTHORIZED, not executed. Nothing has executed at this point, and a
    // receipt that reports intent as outcome is evidence of nothing. The
    // terminal receipt is minted by perform(), after the effect either happened
    // or did not.
    return {
      authorized: true,
      receipt: this.#receipt({ outcome: OUTCOME.AUTHORIZED, envelope, credential, now }),
    };
  }

  // ── Standing authority ────────────────────────────────────────────────────
  // Routine action inside a bounded grant, at machine speed, with no human
  // touched — and with every execution debiting the same measure, so volume and
  // composition are enforced across separately authorized actions.
  authorizeUnderGrant({ envelope, grant, now = Math.floor(Date.now() / 1000) }) {
    const refuse = (refusal, detail) => ({
      authorized: false, refusal, detail: detail ?? null,
      receipt: this.#receipt({ outcome: OUTCOME.REFUSED, refusal, envelope, credential: null, grant, now }),
    });

    if (!grant || !grant.claims) return refuse(REFUSAL.NO_CREDENTIAL);
    const g = grant.claims;

    const issuer = this.issuers[g.iss];
    if (!issuer) return refuse(REFUSAL.UNRECOGNIZED_ISSUER);
    if (issuer.revokedAt !== undefined && issuer.revokedAt <= now) return refuse(REFUSAL.UNRECOGNIZED_ISSUER);
    if (!verifyGrant(grant, issuer.publicKeyPem)) return refuse(REFUSAL.BAD_SIGNATURE);

    if (g.destination !== this.destinationId) return refuse(REFUSAL.WRONG_DESTINATION);
    if (g.principal !== envelope.principal) return refuse(REFUSAL.WRONG_PRINCIPAL);
    if (now >= g.exp) return refuse(REFUSAL.GRANT_EXPIRED);

    const effect = effectOf(envelope);
    if (!g.allow.some((sel) => matches(sel, effect))) return refuse(REFUSAL.NOT_IN_ALLOW);

    if (!this.grants) this.grants = new GrantStore(this.grantDir);

    const verdict = this.grants.commitIfAllowed(g.gid, g.window, now, effect, (history) => {
      // The join is computed over what ACTUALLY executed in the window plus this
      // step — not over a plan. Not declaring a plan is not an escape.
      const joined = join([...history, effect], { elevations: g.elevations });

      const banned = prohibited(joined, g.prohibitions);
      if (banned) return { ok: false, refusal: REFUSAL.PROHIBITED_COMBINATION, detail: banned.id ?? null };

      for (const [cls, total] of Object.entries(joined.totals)) {
        const ceiling = g.ceilings[cls];
        if (ceiling === undefined) {
          // A class reachable only by elevation, with no ceiling granted, is
          // ungranted authority. Refuse rather than treat silence as headroom.
          if (joined.elevations.some((e) => e.class === cls)) {
            return { ok: false, refusal: REFUSAL.PROHIBITED_COMBINATION, detail: `elevated to ungranted class ${cls}` };
          }
          continue;
        }
        if (total > ceiling) {
          return { ok: false, refusal: REFUSAL.CEILING_EXCEEDED, detail: `${cls}: ${total} > ${ceiling}` };
        }
      }
      return { ok: true, joined };
    });

    if (!verdict.ok) return refuse(verdict.refusal, verdict.detail);

    return {
      authorized: true,
      receipt: this.#receipt({ outcome: OUTCOME.AUTHORIZED, envelope, credential: null, grant, now }),
    };
  }

  // ── The load-bearing interface ────────────────────────────────────────────
  //
  // authorize() answers a question and trusts the caller to act on the answer.
  // That gap is only acceptable at Tier 1, and it does not survive contact with
  // Tier 3, where authority is not a verdict but a REQUIRED INPUT to producing
  // the effect. So the effect belongs inside the guard from the beginning.
  //
  // perform() is the interface every caller should use. The effect is produced
  // by the guard, or it is not produced. There is no window between "allowed"
  // and "done" for a caller to be wrong, lazy, or hostile in:
  //
  //   Tier 1  effectFn runs after the check          (today)
  //   Tier 2  effectFn is the only holder of the destination credential
  //   Tier 3  effectFn combines signature shares and the guard holds one —
  //           the artifact cannot be constructed without it
  //
  // Moving up the tiers substitutes what effectFn IS. It does not change this
  // signature, the callers, or the receipt shape. That is the whole point of
  // building it this way now.
  perform({ envelope, credential, grant, effectFn, now = Math.floor(Date.now() / 1000) }) {
    const decision = grant
      ? this.authorizeUnderGrant({ envelope, grant, now })
      : this.authorize({ envelope, credential, now });

    if (!decision.authorized) return { ...decision, effect: null };

    let effect, error = null;
    try {
      effect = effectFn ? effectFn(envelope) : null;
    } catch (e) {
      error = e;
    }

    // An authorized effect that failed to happen is not a silent success. The
    // receipt records what the destination actually did, because a receipt that
    // reports intent rather than outcome is evidence of nothing.
    //
    // This is a SECOND entry in the chain, after the AUTHORIZED one. Both are
    // true events and both are worth proving. It also means an authorization
    // with no terminal successor is visible as a dangling pair — which is the
    // only honest way to surface "the guard said yes and nobody ever said what
    // happened next."
    const receipt = this.#receipt({
      outcome: error ? OUTCOME.FAILED : OUTCOME.EXECUTED,
      failure: error ? String(error.message ?? error) : undefined,
      envelope, credential, grant, now,
    });

    return error
      ? { authorized: true, executed: false, refusal: null, error, effect: null, receipt }
      : { authorized: true, executed: true, refusal: null, effect, receipt };
  }

  // Destination-signed, so a refusal is provable later without trusting the
  // ledger, the agent, or ZLAR itself — and positioned in the destination's own
  // chain, so a receipt that is later removed leaves a hole someone can see.
  #receipt({ outcome, refusal, failure, envelope, credential, grant, now }) {
    const build = (seq, prev) => ({
      v: 1,
      destination: this.destinationId,
      kid: this.receiptKid,
      // The authority that produced this decision, and the recognition rules it
      // was decided under. "Authorized" is meaningless without "under what".
      recognition: this.recognition,
      iss: credential?.claims?.iss ?? grant?.claims?.iss ?? null,
      gid: grant?.claims?.gid ?? null,
      outcome,
      ...(refusal ? { refusal } : {}),
      ...(failure === undefined ? {} : { failure }),
      digest: envelopeDigest(envelope),
      consequence: envelope.consequence,
      principal: envelope.principal,
      ...(envelope.measure === undefined ? {} : { measure: envelope.measure }),
      cid: credential?.claims?.cid ?? null,
      seq,
      prev,
      at: now,
    });

    // Sequence, linkage and signature are decided together inside the log's
    // lock. Assigning a position outside it would let two crossings claim the
    // same one, and a forked chain reads exactly like a deleted one.
    if (this.receiptLog) return this.receiptLog.append(build, this.signReceipt);

    const body = build(null, null);
    return this.signReceipt ? { body, sig: this.signReceipt(body) } : { body, sig: null };
  }
}
