// A reference destination: a wallet that owns its own acceptance rule.
//
// This is the whole point of "destination-owned." The wallet is not asking ZLAR
// for permission and is not consulting a policy. It has one rule about what a
// transaction IS, and anything failing that rule was never a transaction.
//
// Tier 3: the rule requires two signatures — the owner's and ZLAR's. Possession
// of the owner key makes you a participant, not an authority.
//
// Note the three outcomes. Most systems have two, and that is the confusion the
// tier ladder exists to remove:
//
//   settled     — accepted, balance moved
//   refused     — a well-formed transaction the wallet declined (bad nonce,
//                 insufficient funds). Something said no.
//   incomplete  — NOT a transaction. Nothing to say no to. Half a cheque.

import { createPublicKey, verify } from 'node:crypto';
import { canonicalBytes } from './canonical.mjs';

export const OUTCOME = Object.freeze({
  SETTLED: 'settled',
  REFUSED: 'refused',
  INCOMPLETE: 'incomplete',
});

export class ReferenceWallet {
  // requiredSigners: the wallet's own constitution. Changing it is a protected
  // action of a higher class — not something a transaction can do.
  constructor({ id, requiredSigners, balances = {} }) {
    this.id = id;
    this.requiredSigners = requiredSigners;   // { role: publicKeyPem }
    this.balances = { ...balances };
    this.nonce = 0;
    this.log = [];
  }

  #wellFormed(tx) {
    if (!tx || !tx.body || !tx.signatures) {
      return { ok: false, missing: Object.keys(this.requiredSigners) };
    }
    const bytes = canonicalBytes(tx.body);
    const missing = [];
    for (const [role, pubPem] of Object.entries(this.requiredSigners)) {
      const sig = tx.signatures[role];
      let good = false;
      if (sig) {
        try {
          good = verify(null, bytes, createPublicKey(pubPem), Buffer.from(sig, 'base64'));
        } catch { good = false; }
      }
      if (!good) missing.push(role);
    }
    return { ok: missing.length === 0, missing };
  }

  submit(tx) {
    // Well-formedness is checked FIRST and is not a policy question. A thing
    // without every required signature is not a transaction this wallet can
    // reason about at all — there is no decision to make, and nothing to refuse.
    const form = this.#wellFormed(tx);
    if (!form.ok) {
      const out = {
        outcome: OUTCOME.INCOMPLETE,
        reason: 'not_a_transaction',
        missing_signatures: form.missing,
        note: 'No required signature set was presented. Nothing was refused, because nothing was submitted that this wallet recognizes as a transaction.',
      };
      this.log.push(out);
      return out;
    }

    const b = tx.body;
    if (b.wallet !== this.id) return this.#refuse('wrong_wallet');
    if (b.nonce !== this.nonce) return this.#refuse('bad_nonce');
    if ((this.balances[b.asset] ?? 0) < b.amount) return this.#refuse('insufficient_funds');

    this.balances[b.asset] -= b.amount;
    this.nonce += 1;
    const out = { outcome: OUTCOME.SETTLED, to: b.to, asset: b.asset, amount: b.amount, nonce: b.nonce };
    this.log.push(out);
    return out;
  }

  #refuse(reason) {
    const out = { outcome: OUTCOME.REFUSED, reason };
    this.log.push(out);
    return out;
  }
}
