// ZLAR's signing side — the second key.
//
// This is the only place ZLAR's wallet key is used, and it will not sign
// anything the guard has not authorized.
//
// It BUILDS the transaction body itself from the authorized envelope. It never
// signs a body handed to it. An agent — however compromised, however clever —
// can influence only what it proposes, and what it proposes is what gets
// authorized and then signed. There is no gap between "what was approved" and
// "what was signed" for anything to be substituted into.

import { createPrivateKey, sign } from 'node:crypto';
import { canonicalBytes } from './canonical.mjs';

export function bodyFromEnvelope(envelope, nonce, walletId) {
  return {
    wallet: walletId,
    nonce,
    to: envelope.params.to,
    asset: envelope.params.asset,
    amount: envelope.measure,
  };
}

export class ZlarCosigner {
  constructor({ privateKeyPem, guard, walletId }) {
    this.privateKeyPem = privateKeyPem;
    this.guard = guard;
    this.walletId = walletId;
  }

  // Returns { signed: true, body, signature } or { signed: false, refusal }.
  // A refusal here produces NO signature, which means no transaction can exist.
  cosign({ envelope, nonce, credential, grant, now }) {
    const result = this.guard.perform({
      envelope, credential, grant, now,
      effectFn: (authorizedEnvelope) => {
        const body = bodyFromEnvelope(authorizedEnvelope, nonce, this.walletId);
        const signature = sign(null, canonicalBytes(body),
                               createPrivateKey(this.privateKeyPem)).toString('base64');
        return { body, signature };
      },
    });

    if (!result.authorized || !result.executed) {
      return { signed: false, refusal: result.refusal ?? 'effect_failed', receipt: result.receipt };
    }
    return { signed: true, ...result.effect, receipt: result.receipt };
  }
}
