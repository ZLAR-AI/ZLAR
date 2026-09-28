// THE THEFT DEMONSTRATION — Tier 2 and Tier 3.
//
// The attacker is given more than any real attacker would have: a perfect copy
// of the owner's private key, full knowledge of the system, the ability to craft
// any transaction, and direct access to the wallet. In the Tier 3 tests the
// agent itself is treated as fully compromised.
//
// The claim under test is not "the theft is blocked." It is that the theft
// cannot produce a transaction at all.

import { generateKeyPairSync, createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join as pjoin } from 'node:path';
import { canonicalBytes } from './canonical.mjs';
import { makeEnvelope, envelopeDigest } from './envelope.mjs';
import { issue, USE } from './credential.mjs';
import { issueGrant } from './grant.mjs';
import { Guard } from './guard.mjs';
import { ReferenceWallet, OUTCOME } from './wallet.mjs';
import { HouseCosigner, bodyFromEnvelope } from './cosigner.mjs';

let pass = 0, fail = 0; const props = [];
const proves = (p, fn) => {
  try {
    const r = fn();
    // An async test body would resolve after this line and report a false pass.
    if (r && typeof r.then === 'function') throw new Error('test body must be synchronous');
    pass++; props.push(['PROVEN ', p]);
  } catch (e) { fail++; props.push(['FAILED ', `${p}  → ${e.message}`]); }
};
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}: expected ${b}, got ${a}`); };

const owner  = generateKeyPairSync('ed25519');   // the key the thief will steal
const cosignerKey  = generateKeyPairSync('ed25519');   // the house's co-signing key
const issuer = generateKeyPairSync('ed25519');   // the authority issuer
const pem  = (k) => k.export({ type: 'spki', format: 'pem' });
const priv = (k) => k.export({ type: 'pkcs8', format: 'pem' });

const WALLET = 'wallet:vincent-treasury';
const now = Math.floor(Date.now() / 1000);
const ownerSign = (body) => sign(null, canonicalBytes(body), createPrivateKey(priv(owner.privateKey))).toString('base64');

function setup() {
  const dir = mkdtempSync(pjoin(tmpdir(), 'cyan-theft-'));
  const wallet = new ReferenceWallet({
    id: WALLET,
    requiredSigners: { owner: pem(owner.publicKey), cosigner: pem(cosignerKey.publicKey) },
    balances: { USDC: 1_000_000 },
  });
  const guard = new Guard({
    destinationId: WALLET,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuer.publicKey) } },
    replayDir: dir, grantDir: dir,
  });
  const cosigner = new HouseCosigner({ privateKeyPem: priv(cosignerKey.privateKey), guard, walletId: WALLET });
  return { wallet, guard, cosigner };
}

const env = (to, amount) => makeEnvelope({
  consequence: 'value.transfer', principal: 'agent:treasury-bot',
  destination: WALLET, params: { to, asset: 'USDC' }, measure: amount,
});

// ── The legitimate path ──────────────────────────────────────────────────────

proves('LEGITIMATE: an authorized payment settles, signed by both keys', () => {
  const { wallet, cosigner } = setup();
  const e = env('supplier-a', 5_000);
  const cred = issue({
    issuerKid: 'zlar:issuer:1', privateKeyPem: priv(issuer.privateKey),
    envelopeDigest: envelopeDigest(e), principal: e.principal,
    destination: WALLET, use: USE.ONCE, expiresAt: now + 300,
  });

  const co = cosigner.cosign({ envelope: e, nonce: wallet.nonce, credential: cred, now });
  eq(co.signed, true, 'the cosigner co-signed');

  const tx = { body: co.body, signatures: { owner: ownerSign(co.body), cosigner: co.signature } };
  const r = wallet.submit(tx);
  eq(r.outcome, OUTCOME.SETTLED, 'settled');
  eq(wallet.balances.USDC, 995_000, 'balance moved exactly once');
});

// ── The theft ────────────────────────────────────────────────────────────────

proves('THEFT: a perfect copy of the owner key cannot form a transaction', () => {
  const { wallet } = setup();
  // The thief has everything: the key, the wallet id, the nonce, the format.
  const body = { wallet: WALLET, nonce: wallet.nonce, to: 'attacker-0xdead', asset: 'USDC', amount: 1_000_000 };
  const stolenTx = { body, signatures: { owner: ownerSign(body) } };

  const r = wallet.submit(stolenTx);
  eq(r.outcome, OUTCOME.INCOMPLETE, 'not settled, and NOT refused');
  eq(r.reason, 'not_a_transaction', 'it was never a transaction');
  eq(r.missing_signatures[0], 'cosigner', 'the missing half');
  eq(wallet.balances.USDC, 1_000_000, 'not one unit moved');
});

proves('the thief cannot forge the missing half — a wrong key is the same as no key', () => {
  const { wallet } = setup();
  const forger = generateKeyPairSync('ed25519');
  const body = { wallet: WALLET, nonce: 0, to: 'attacker-0xdead', asset: 'USDC', amount: 1_000_000 };
  const tx = { body, signatures: {
    owner: ownerSign(body),
    cosigner: sign(null, canonicalBytes(body), createPrivateKey(priv(forger.privateKey))).toString('base64'),
  }};
  eq(wallet.submit(tx).outcome, OUTCOME.INCOMPLETE, 'forgery is not a signature');
  eq(wallet.balances.USDC, 1_000_000, 'nothing moved');
});

proves('the thief cannot reuse the cosigner\'s signature from an earlier legitimate payment', () => {
  const { wallet, cosigner } = setup();
  const good = env('supplier-a', 5_000);
  const cred = issue({ issuerKid: 'zlar:issuer:1', privateKeyPem: priv(issuer.privateKey),
    envelopeDigest: envelopeDigest(good), principal: good.principal, destination: WALLET, expiresAt: now + 300 });
  const co = cosigner.cosign({ envelope: good, nonce: 0, credential: cred, now });

  // Thief lifts the cosigner's signature and staples it to their own payment.
  const evil = { wallet: WALLET, nonce: 0, to: 'attacker-0xdead', asset: 'USDC', amount: 1_000_000 };
  const tx = { body: evil, signatures: { owner: ownerSign(evil), cosigner: co.signature } };
  eq(wallet.submit(tx).outcome, OUTCOME.INCOMPLETE, 'a signature over other bytes signs nothing here');
  eq(wallet.balances.USDC, 1_000_000, 'nothing moved');
});

proves('A FULLY COMPROMISED AGENT cannot get the cosigner to sign a payment to itself', () => {
  const { cosigner } = setup();
  // The agent holds a genuine credential for a legitimate 5,000 supplier payment
  // and tries to spend it on a 1,000,000 payment to the attacker.
  const authorized = env('supplier-a', 5_000);
  const cred = issue({ issuerKid: 'zlar:issuer:1', privateKeyPem: priv(issuer.privateKey),
    envelopeDigest: envelopeDigest(authorized), principal: authorized.principal, destination: WALLET, expiresAt: now + 300 });

  const substituted = env('attacker-0xdead', 1_000_000);
  const co = cosigner.cosign({ envelope: substituted, nonce: 0, credential: cred, now });
  eq(co.signed, false, 'no signature produced');
  eq(co.refusal, 'action_mismatch', 'the swap is visible');
});

proves('the cosigner will not co-sign beyond a standing budget, so a drain cannot be split into slices', () => {
  const { wallet, cosigner } = setup();
  const grant = issueGrant({
    issuerKid: 'zlar:issuer:1', privateKeyPem: priv(issuer.privateKey),
    principal: 'agent:treasury-bot', destination: WALLET,
    allow: [{ class: 'value.transfer' }], ceilings: { 'value.transfer': 10_000 },
    windowSeconds: 86400, expiresAt: now + 3600,
  });
  let signed = 0;
  for (let i = 0; i < 10; i++) {
    const co = cosigner.cosign({ envelope: env(`out-${i}`, 4_000), nonce: wallet.nonce, grant, now });
    if (!co.signed) break;
    signed++;
  }
  eq(signed, 2, 'two payments of 4,000 fit under 10,000; the third gets no signature');
});

proves('no signature means no transaction — the wallet never even sees a decision to make', () => {
  const { wallet, cosigner } = setup();
  const refused = cosigner.cosign({ envelope: env('attacker', 999), nonce: 0, credential: null, now });
  eq(refused.signed, false, 'refused');
  const tx = { body: bodyFromEnvelope(env('attacker', 999), 0, WALLET), signatures: { owner: ownerSign({ x: 1 }) } };
  eq(wallet.submit(tx).outcome, OUTCOME.INCOMPLETE, 'incomplete');
  eq(wallet.log.filter(l => l.outcome === OUTCOME.REFUSED).length, 0, 'the wallet refused nothing — there was nothing to refuse');
});

proves('TIER 2 vs TIER 3: a bearer token that is stolen DOES move the money — which is why Tier 3 exists', () => {
  // Tier 2: destination accepts a single secret held exclusively by the guard.
  const token = 'exclusive-custody-secret';
  const t2Wallet = { balance: 1_000_000, submit(t) { if (t === token) { this.balance = 0; return 'drained'; } return 'refused'; } };
  eq(t2Wallet.submit('guess'), 'refused', 'an outsider without the token is refused');
  eq(t2Wallet.submit(token), 'drained', 'but whoever holds the token wins');
  // The honest statement of Tier 2's limit, asserted rather than glossed over.
});

console.log('\n  CYAN — THE THEFT DEMONSTRATION\n');
for (const [s, t] of props) console.log(`  ${s} ${t}`);
console.log(`\n  ${pass} proven, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
