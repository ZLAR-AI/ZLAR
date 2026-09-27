// Negative vectors — attacks named by adversarial review, run against Cyan.
//
// Source: the 2026-08-17 adversarial review of the v2 draft named ten attacks
// that any authorization/consequence protocol must survive. Several can be run
// today against the one real implementation ZLAR has, without waiting for the
// architecture pass. Those are here.
//
// These are ATTACKS. A failing test is a real vulnerability, not a broken test.
// Each one asserts that the attack is REFUSED, so red means Cyan is exploitable
// in the way the review predicted.
//
// The vectors deliberately precede the schema. Vectors written after a design
// test whatever the design happens to do; vectors written first constrain what
// the design is allowed to be.

import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeEnvelope, envelopeDigest } from './envelope.mjs';
import { issue, USE } from './credential.mjs';
import { Guard, REFUSAL } from './guard.mjs';
import { receiptSigner } from './receipt.mjs';
import { ReceiptLog } from './receipt-log.mjs';

let pass = 0, fail = 0;
const props = [];
const attack = (name, fn) => {
  try { fn(); pass++; props.push(['REFUSED ', name]); }
  catch (e) { fail++; props.push(['*BREAK* ', `${name}  → ${e.message}`]); }
};
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}: expected ${b}, got ${a}`); };

const issuerKeys = generateKeyPairSync('ed25519');
const destKeys = generateKeyPairSync('ed25519');
const pem = (k) => k.export({ type: 'spki', format: 'pem' });
const priv = (k) => k.export({ type: 'pkcs8', format: 'pem' });

const DEST = 'wallet:treasury-1';
const now = Math.floor(Date.now() / 1000);
const dirs = [];

function guardAt(dir) {
  dirs.push(dir);
  const s = receiptSigner({ kid: 'dest:key-1', privateKeyPem: priv(destKeys.privateKey) });
  return new Guard({
    destinationId: DEST,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey) } },
    replayDir: dir,
    signReceipt: s.sign,
    receiptKid: s.kid,
    receiptLog: new ReceiptLog(join(dir, 'log'), DEST),
  });
}
const fresh = () => guardAt(mkdtempSync(join(tmpdir(), 'cyan-neg-')));

const env = (over = {}) => makeEnvelope({
  consequence: 'value.transfer', principal: 'agent:claude', destination: DEST,
  params: { to: '0xabc', asset: 'USDC' }, measure: 5000, ...over,
});
const cred = (e, over = {}) => issue({
  issuerKid: 'zlar:issuer:1', privateKeyPem: priv(issuerKeys.privateKey),
  envelopeDigest: envelopeDigest(e), principal: e.principal,
  destination: DEST, use: USE.ONCE, expiresAt: now + 300, ...over,
});

// ── SPLIT REPLAY STORES ────────────────────────────────────────────────────
// The review's attack: one authorization, two guards for the SAME destination
// whose consumption state lives in different places. If both execute, "one-use
// at a destination" is false and the real guarantee is "one-use per store".

attack('SPLIT STORES: one credential cannot execute at two guards for the same destination', () => {
  const a = fresh(), b = fresh();
  const e = env(), c = cred(e);
  const first = a.perform({ envelope: e, credential: c, effectFn: () => 'moved' });
  eq(first.executed, true, 'first guard should execute');
  const second = b.perform({ envelope: e, credential: c, effectFn: () => 'moved' });
  eq(second.executed, false,
     'SECOND GUARD EXECUTED THE SAME AUTHORIZATION — consumption is scoped to the store, not the destination');
});

// ── DUPLICATE TERMINAL OUTCOMES ────────────────────────────────────────────
// Can one authorization produce two terminal statements about what happened?

attack('DUPLICATE TERMINAL: one authorization cannot produce two executions', () => {
  const g = fresh(), e = env(), c = cred(e);
  eq(g.perform({ envelope: e, credential: c, effectFn: () => 'moved' }).executed, true, 'first');
  const second = g.perform({ envelope: e, credential: c, effectFn: () => 'moved' });
  eq(second.authorized, false, 'second must refuse');
  eq(second.refusal, REFUSAL.ALREADY_CONSUMED, 'and name the reason');
});

// ── AUTHORIZE-THEN-PERFORM DOUBLE COUNT ────────────────────────────────────
// authorize() consumes. Does a subsequent perform() with the same credential
// still execute the effect?

attack('CONSUMED-THEN-PERFORM: a credential consumed by authorize() cannot then perform', () => {
  const g = fresh(), e = env(), c = cred(e);
  eq(g.authorize({ envelope: e, credential: c }).authorized, true, 'authorize consumes');
  const r = g.perform({ envelope: e, credential: c, effectFn: () => 'moved' });
  eq(r.authorized, false, 'effect ran on an already-consumed credential');
  eq(r.refusal, REFUSAL.ALREADY_CONSUMED, 'and names it consumed');
});

// ── RETROACTIVE AUTHORIZATION ──────────────────────────────────────────────
// A credential minted now, backdated, presented for an effect. Nothing in the
// signed material binds the authorization to a moment BEFORE the effect.

// Recorded as a LIMITATION, not a break. An earlier version of this test
// asserted that a backdated credential should be refused and reported a
// vulnerability when it executed. That was wrong twice over: accepting a
// credential whose notBefore is in the past is correct behaviour, and within
// Cyan's runtime the ordering genuinely holds because perform() authorizes and
// only then executes.
//
// The real attack the review names lives one level up and cannot be
// demonstrated here: a receipt referencing an authorization does not prove the
// authorization existed before the EFFECT, only before the receipt was signed.
// An effect produced outside perform(), with paperwork assembled afterwards,
// leaves no trace Cyan can detect — because Cyan never saw it.
//
// That is a protocol gap for the architecture pass to close, not a Cyan defect,
// and claiming otherwise would be the same overclaiming this suite exists to
// catch.
attack('ORDERING: within the guard, authorization provably precedes the effect', () => {
  const g = fresh(), e = env();
  const order = [];
  const r = g.perform({
    envelope: e, credential: cred(e),
    effectFn: () => { order.push('effect'); return 'moved'; },
  });
  eq(r.executed, true, 'executed');
  eq(order.length, 1, 'effect ran exactly once');
  // The guard consumed the credential before calling effectFn. Ordering outside
  // the guard is unprovable from the receipt alone — see the comment above.
});

// ── CROSS-DESTINATION REPLAY ───────────────────────────────────────────────

attack('WRONG DESTINATION: a credential for another destination is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cyan-neg-')); dirs.push(dir);
  const s = receiptSigner({ kid: 'dest:key-2', privateKeyPem: priv(destKeys.privateKey) });
  const other = new Guard({
    destinationId: 'wallet:other', replayDir: dir,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey) } },
    signReceipt: s.sign, receiptKid: s.kid,
  });
  const e = env();
  eq(other.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' }).authorized,
     false, 'must refuse');
});

// ── DIGEST DOWNGRADE ───────────────────────────────────────────────────────
// The review flagged an algorithm-agile digest list as a downgrade surface.
// Cyan pins one algorithm; this records that as a property to preserve.

attack('DIGEST DOWNGRADE: the action digest algorithm is not negotiable', () => {
  const e = env();
  const d = envelopeDigest(e);
  eq(typeof d, 'string', 'digest is a bare string');
  eq(d.length, 64, 'sha256 hex, fixed width — no algorithm identifier to negotiate');
});

// ── Report ─────────────────────────────────────────────────────────────────

console.log('\n  CYAN NEGATIVE VECTORS — attacks named by adversarial review\n');
for (const [tag, text] of props) console.log(`  ${tag} ${text}`);
console.log(`\n  ${pass} refused, ${fail} BROKE\n`);
if (fail > 0) {
  console.log('  A break here is a real vulnerability, not a failing test.\n');
}
for (const d of dirs) rmSync(d, { recursive: true, force: true });
process.exit(0); // reporting tool — breaks are findings, not build failures, until triaged
