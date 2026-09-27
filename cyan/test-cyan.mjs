// Cyan slice one — the proofs that matter.
// Each test names the escape it closes. A passing count is not the headline;
// the propositions are.

import { generateKeyPairSync, createSign, sign as rawSign, createPrivateKey } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeEnvelope, envelopeDigest } from './envelope.mjs';
import { issue, USE } from './credential.mjs';
import { Guard, REFUSAL } from './guard.mjs';
import { canonicalBytes } from './canonical.mjs';

let pass = 0, fail = 0;
const props = [];
function proves(proposition, fn) {
  try { fn(); pass++; props.push(['PROVEN ', proposition]); }
  catch (e) { fail++; props.push(['FAILED ', `${proposition}  → ${e.message}`]); }
}
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}: expected ${b}, got ${a}`); };

const issuerKeys = generateKeyPairSync('ed25519');
const otherKeys  = generateKeyPairSync('ed25519');
const destKeys   = generateKeyPairSync('ed25519');
const pem = (k) => k.export({ type: 'spki', format: 'pem' });
const priv = (k) => k.export({ type: 'pkcs8', format: 'pem' });

const DEST = 'wallet:treasury-1';
const now = Math.floor(Date.now() / 1000);
let dir;

function freshGuard(extra = {}) {
  dir = mkdtempSync(join(tmpdir(), 'cyan-replay-'));
  return new Guard({
    destinationId: DEST,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey) }, ...extra },
    replayDir: dir,
    signReceipt: (body) => rawSign(null, canonicalBytes(body), createPrivateKey(priv(destKeys.privateKey))).toString('base64'),
  });
}

const env = (over = {}) => makeEnvelope({
  consequence: 'value.transfer', principal: 'agent:claude', destination: DEST,
  params: { to: '0xabc', asset: 'USDC' }, measure: 5000, ...over,
});

const cred = (envelope, over = {}) => issue({
  issuerKid: 'zlar:issuer:1', privateKeyPem: priv(issuerKeys.privateKey),
  envelopeDigest: envelopeDigest(envelope), principal: envelope.principal,
  destination: DEST, use: USE.ONCE, expiresAt: now + 300, ...over,
});

proves('a recognized credential authorizes, and the destination signs the receipt', () => {
  const g = freshGuard(), e = env();
  const r = g.authorize({ envelope: e, credential: cred(e) });
  eq(r.authorized, true, 'authorized');
  // NOT 'executed' — authorize() has not executed anything. Claiming otherwise
  // is the "evidence of intent" failure this layer exists to refuse.
  eq(r.receipt.body.outcome, 'authorized', 'outcome');
  if (!r.receipt.sig) throw new Error('receipt unsigned');
});

proves('REPLAY: the same credential cannot execute twice', () => {
  const g = freshGuard(), e = env(), c = cred(e);
  eq(g.authorize({ envelope: e, credential: c }).authorized, true, 'first');
  const second = g.authorize({ envelope: e, credential: c });
  eq(second.authorized, false, 'second');
  eq(second.refusal, REFUSAL.ALREADY_CONSUMED, 'refusal');
});

proves('SEMANTIC ESCAPE: changing the action after authorization refuses', () => {
  const g = freshGuard(), authorized = env();
  const c = cred(authorized);
  const swapped = env({ params: { to: '0xATTACKER', asset: 'USDC' } });
  const r = g.authorize({ envelope: swapped, credential: c });
  eq(r.authorized, false, 'must refuse');
  eq(r.refusal, REFUSAL.ACTION_MISMATCH, 'refusal');
});

proves('VOLUME ESCAPE: an effect larger than the budget refuses', () => {
  const g = freshGuard(), e = env({ measure: 900000 });
  const c = cred(e, { budget: 5000 });
  eq(g.authorize({ envelope: e, credential: c }).refusal, REFUSAL.BUDGET_EXCEEDED, 'refusal');
});

proves('possession of a valid signature from an UNRECOGNIZED issuer is not authority', () => {
  const g = freshGuard(), e = env();
  const forged = issue({
    issuerKid: 'zlar:issuer:1', privateKeyPem: priv(otherKeys.privateKey),
    envelopeDigest: envelopeDigest(e), principal: e.principal, destination: DEST, expiresAt: now + 300,
  });
  eq(g.authorize({ envelope: e, credential: forged }).refusal, REFUSAL.BAD_SIGNATURE, 'refusal');
});

proves('a credential minted for another destination is no authority here', () => {
  const g = freshGuard(), e = env();
  eq(g.authorize({ envelope: e, credential: cred(e, { destination: 'wallet:other' }) }).refusal,
     REFUSAL.WRONG_DESTINATION, 'refusal');
});

proves('a credential for another principal does not travel between agents', () => {
  const g = freshGuard(), e = env();
  const c = cred(e, { principal: 'agent:someone-else' });
  eq(g.authorize({ envelope: e, credential: c }).refusal, REFUSAL.WRONG_PRINCIPAL, 'refusal');
});

proves('EXPIRY: a lease that is not renewed simply ends — no cancel message needed', () => {
  const g = freshGuard(), e = env();
  const c = cred(e, { use: USE.LEASE, expiresAt: now - 1 });
  eq(g.authorize({ envelope: e, credential: c }).refusal, REFUSAL.EXPIRED, 'refusal');
});

proves('SILENCE: absence of a credential is refusal, never a default allow', () => {
  const g = freshGuard();
  eq(g.authorize({ envelope: env(), credential: null }).refusal, REFUSAL.NO_CREDENTIAL, 'refusal');
});

proves('a revoked issuer stops being recognized without any credential changing', () => {
  const e = env();
  const c = cred(e);
  const g = new Guard({
    destinationId: DEST,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey), revokedAt: now - 10 } },
    replayDir: mkdtempSync(join(tmpdir(), 'cyan-replay-')),
  });
  eq(g.authorize({ envelope: e, credential: c }).refusal, REFUSAL.UNRECOGNIZED_ISSUER, 'refusal');
});

proves('CONCURRENCY: two guards racing one credential produce exactly one execution', () => {
  const g = freshGuard(), e = env(), c = cred(e);
  const twin = new Guard({
    destinationId: DEST,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey) } },
    replayDir: dir,   // same custody, as two replicas of one destination would share
  });
  const results = [g.authorize({ envelope: e, credential: c }), twin.authorize({ envelope: e, credential: c })];
  eq(results.filter(r => r.authorized).length, 1, 'exactly one execution');
});

proves('a refusal is provable afterwards from the destination-signed receipt alone', () => {
  const g = freshGuard(), e = env();
  const r = g.authorize({ envelope: e, credential: null });
  eq(r.receipt.body.outcome, 'refused', 'outcome');
  eq(r.receipt.body.refusal, REFUSAL.NO_CREDENTIAL, 'reason recorded');
  if (!r.receipt.sig) throw new Error('refusal receipt unsigned — unprovable later');
});

proves('TIER PATH: the effect is produced BY the guard, not by a caller it trusts', () => {
  const g = freshGuard(), e = env();
  let ran = false;
  const r = g.perform({ envelope: e, credential: cred(e), effectFn: () => { ran = true; return 'settled'; } });
  eq(r.executed, true, 'executed');
  eq(r.effect, 'settled', 'effect returned by the guard');
  eq(ran, true, 'effectFn ran inside the guard');
});

proves('a refused action never reaches the effect at all', () => {
  const g = freshGuard(), e = env();
  let ran = false;
  const r = g.perform({ envelope: e, credential: null, effectFn: () => { ran = true; } });
  eq(r.authorized, false, 'refused');
  eq(ran, false, 'effect never invoked');
});

proves('an authorized effect that FAILS is receipted as failed, never as executed', () => {
  const g = freshGuard(), e = env();
  const r = g.perform({ envelope: e, credential: cred(e), effectFn: () => { throw new Error('rail timeout'); } });
  eq(r.executed, false, 'not executed');
  eq(r.receipt.body.outcome, 'failed', 'receipt states the truth');
  if (!r.receipt.body.failure.includes('rail timeout')) throw new Error('failure not recorded');
});

console.log('\n  CYAN SLICE ONE — propositions\n');
for (const [state, text] of props) console.log(`  ${state} ${text}`);
console.log(`\n  ${pass} proven, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
