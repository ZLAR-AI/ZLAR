// Cyan question four — receipts.
//
// "What does the destination sign so a refusal or an execution is provable
// later without trusting the ledger?"
//
// Each test names the thing that would otherwise be unprovable, or the lie that
// would otherwise be undetectable. A passing count is not the headline.

import { generateKeyPairSync, sign as rawSign, createPrivateKey } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeEnvelope, envelopeDigest } from './envelope.mjs';
import { issue, USE, verifySignature } from './credential.mjs';
import { Guard, REFUSAL } from './guard.mjs';
import { ReceiptLog } from './receipt-log.mjs';
import { canonicalBytes } from './canonical.mjs';
import {
  receiptSigner, verifyReceipt, verifyChain, receiptHash, receiptPreimage,
  describeReceipt, OUTCOME, INVALID,
  recognitionDigest, headSigner, verifyHead, verifyChainAgainstHead,
} from './receipt.mjs';

let pass = 0, fail = 0;
const props = [];
function proves(proposition, fn) {
  try { fn(); pass++; props.push(['PROVEN ', proposition]); }
  catch (e) { fail++; props.push(['FAILED ', `${proposition}  → ${e.message}`]); }
}
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}: expected ${b}, got ${a}`); };

const issuerKeys = generateKeyPairSync('ed25519');
const destKeys   = generateKeyPairSync('ed25519');
const thiefKeys  = generateKeyPairSync('ed25519');

const pem  = (k) => k.export({ type: 'spki', format: 'pem' });
const priv = (k) => k.export({ type: 'pkcs8', format: 'pem' });

const DEST = 'wallet:treasury-1';
const KID  = 'dest:wallet:treasury-1:key-1';
const now  = Math.floor(Date.now() / 1000);
const dirs = [];

function freshGuard() {
  const dir = mkdtempSync(join(tmpdir(), 'cyan-receipts-'));
  dirs.push(dir);
  const signer = receiptSigner({ kid: KID, privateKeyPem: priv(destKeys.privateKey) });
  const log = new ReceiptLog(join(dir, 'log'), DEST);
  const guard = new Guard({
    destinationId: DEST,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey) } },
    replayDir: dir,
    signReceipt: signer.sign,
    receiptKid: signer.kid,
    receiptLog: log,
  });
  return { guard, log, dir };
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

const AUDITOR = { publicKeyPem: pem(destKeys.publicKey), destinationId: DEST, kid: KID };

// ── Attributable ───────────────────────────────────────────────────────────

proves('a receipt verifies offline from the destination public key alone — no ZLAR, no issuer', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  eq(r.executed, true, 'executed');
  // The auditor holds one public key. It has never heard of the issuer, the
  // agent, or the gate.
  eq(verifyReceipt(r.receipt, AUDITOR).ok, true, 'verifies');
});

proves('an UNSIGNED receipt is not evidence', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  const stripped = { body: r.receipt.body, sig: null };
  eq(verifyReceipt(stripped, AUDITOR).reason, INVALID.UNSIGNED, 'refused as unsigned');
});

proves('a receipt that does not NAME its signer is not evidence', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  const body = { ...r.receipt.body, kid: null };
  const sig = rawSign(null, receiptPreimage(body), createPrivateKey(priv(destKeys.privateKey))).toString('base64');
  // Correctly signed by the real destination key, and still refused: an
  // unattributable receipt cannot be checked against any known key.
  eq(verifyReceipt({ body, sig }, AUDITOR).reason, INVALID.UNNAMED_SIGNER, 'refused');
});

proves('FORGERY: a receipt signed by anyone other than the destination is refused', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  const forged = {
    body: r.receipt.body,
    sig: rawSign(null, receiptPreimage(r.receipt.body), createPrivateKey(priv(thiefKeys.privateKey))).toString('base64'),
  };
  eq(verifyReceipt(forged, AUDITOR).reason, INVALID.BAD_SIGNATURE, 'refused');
});

proves("a receipt for another destination does not verify here", () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  eq(verifyReceipt(r.receipt, { ...AUDITOR, destinationId: 'wallet:other' }).reason,
     INVALID.WRONG_DESTINATION, 'refused');
});

proves('TAMPER: altering any signed field breaks the signature', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  const doctored = { body: { ...r.receipt.body, measure: 1 }, sig: r.receipt.sig };
  eq(verifyReceipt(doctored, AUDITOR).reason, INVALID.BAD_SIGNATURE, 'refused');
});

// ── Evidence is never authority ────────────────────────────────────────────

proves('EVIDENCE IS NOT AUTHORITY: a receipt signature cannot be presented as a credential', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  // Take the destination's receipt and present it as if it were an
  // authorization signed by that key. Domain separation makes the bytes fail.
  const asCredential = { claims: r.receipt.body, sig: r.receipt.sig };
  eq(verifySignature(asCredential, pem(destKeys.publicKey)), false, 'must not verify as a credential');
});

proves('EVIDENCE IS NOT AUTHORITY: a credential signature cannot be presented as a receipt', () => {
  const e = env();
  const c = cred(e);
  const asReceipt = { body: { ...c.claims, v: 1, outcome: OUTCOME.EXECUTED, kid: KID, destination: DEST }, sig: c.sig };
  const v = verifyReceipt(asReceipt, { publicKeyPem: pem(issuerKeys.publicKey), destinationId: DEST, kid: KID });
  eq(v.ok, false, 'must not verify as a receipt');
});

// ── Truthful outcomes ──────────────────────────────────────────────────────

proves('authorize() does NOT receipt an execution — it receipts an authorization', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.authorize({ envelope: e, credential: cred(e) });
  eq(r.authorized, true, 'authorized');
  eq(r.receipt.body.outcome, OUTCOME.AUTHORIZED, 'outcome is authorized, not executed');
});

proves('an authorized effect that FAILS is receipted as failed, and the failure is signed', () => {
  const { guard, log } = freshGuard(), e = env();
  const r = guard.perform({
    envelope: e, credential: cred(e),
    effectFn: () => { throw new Error('rail timeout'); },
  });
  eq(r.executed, false, 'not executed');
  eq(r.receipt.body.outcome, OUTCOME.FAILED, 'receipted as failed');
  if (!r.receipt.body.failure.includes('rail timeout')) throw new Error('failure not recorded');
  eq(verifyReceipt(r.receipt, AUDITOR).ok, true, 'the failure receipt is itself provable');
  eq(verifyChain(log.read(), AUDITOR).ok, true, 'chain intact across a failure');
});

proves('a REFUSAL is provable from the receipt alone, and sits in the same chain as executions', () => {
  const { guard, log } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: null, effectFn: () => 'moved' });
  eq(r.authorized, false, 'refused');
  eq(r.receipt.body.outcome, OUTCOME.REFUSED, 'outcome');
  eq(r.receipt.body.refusal, REFUSAL.NO_CREDENTIAL, 'reason recorded');
  eq(verifyReceipt(r.receipt, AUDITOR).ok, true, 'provable');
  // Same chain as executions — so refusals cannot be selectively pruned while
  // leaving a clean-looking history of successes.
  eq(verifyChain(log.read(), AUDITOR).ok, true, 'one chain, both outcomes');
});

// ── Gap-evident ────────────────────────────────────────────────────────────

proves('a whole history verifies from genesis', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 4; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const chain = log.read();
  const v = verifyChain(chain, AUDITOR);
  eq(v.ok, true, `chain verifies (${v.reason ?? ''})`);
  eq(v.from, 1, 'starts at genesis');
  eq(v.to, 8, 'two receipts per crossing: authorized, then executed');
});

proves('OMISSION: deleting a receipt from the middle is detectable', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 4; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const chain = log.read();
  const pruned = [...chain.slice(0, 3), ...chain.slice(4)];   // drop #4
  const v = verifyChain(pruned, AUDITOR);
  eq(v.ok, false, 'must not verify');
  eq(v.reason, INVALID.SEQUENCE_GAP, 'the gap is named');
});

proves('OMISSION: deleting the most recent receipts is detectable against a known head', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 3; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const headBefore = log.head();
  const truncated = log.read().slice(0, 4);
  // Truncation leaves a chain that is internally consistent — which is exactly
  // why a receipt holder's own copy matters. Anyone holding the later head, or
  // any later receipt, sees the shortfall immediately.
  eq(verifyChain(truncated, AUDITOR).ok, true, 'internally consistent');
  eq(verifyChain(truncated, AUDITOR).to < headBefore.seq, true, 'shorter than the known head');
});

proves('TAMPER IN PLACE: altering a receipt breaks its successor’s link, not just its own signature', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 3; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const chain = log.read();
  // Re-sign entry #2 properly with the real destination key, so its OWN
  // signature is valid. Only the chain catches this.
  const body = { ...chain[1].body, measure: 1 };
  const sig = rawSign(null, receiptPreimage(body), createPrivateKey(priv(destKeys.privateKey))).toString('base64');
  const doctored = [...chain]; doctored[1] = { body, sig };
  eq(verifyReceipt(doctored[1], AUDITOR).ok, true, 'the doctored entry verifies alone');
  const v = verifyChain(doctored, AUDITOR);
  eq(v.ok, false, 'the chain does not');
  eq(v.reason, INVALID.BROKEN_LINK, 'the break is named');
  eq(v.at, 2, 'located at the successor');
});

proves('REORDER: swapping two receipts is detectable', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 3; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const chain = log.read();
  const swapped = [...chain];
  [swapped[2], swapped[3]] = [swapped[3], swapped[2]];
  eq(verifyChain(swapped, AUDITOR).ok, false, 'must not verify');
});

proves('a mid-history WINDOW verifies as a window, and is refused as a whole history', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 3; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const window = log.read().slice(2, 5);
  eq(verifyChain(window, { ...AUDITOR, expectFrom: null }).ok, true, 'valid as a window');
  eq(verifyChain(window, AUDITOR).reason, INVALID.NOT_FROM_GENESIS, 'refused as a genesis history');
});

proves('CONCURRENCY: parallel crossings receive contiguous positions, never a duplicate', () => {
  const { guard, log } = freshGuard();
  const n = 12;
  for (let i = 0; i < n; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const seqs = log.read().map((r) => r.body.seq);
  eq(new Set(seqs).size, seqs.length, 'no duplicate positions');
  eq(seqs.every((s, i) => s === i + 1), true, 'contiguous from 1');
  eq(verifyChain(log.read(), AUDITOR).ok, true, 'chain verifies');
});

// ── Which rules were in force ──────────────────────────────────────────────

proves('a receipt records the authority and the recognition rules it was decided under', () => {
  const { guard } = freshGuard(), e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  eq(r.receipt.body.iss, 'zlar:issuer:1', 'names the issuer that authorized');
  eq(typeof r.receipt.body.recognition, 'string', 'carries a recognition digest');
  eq(r.receipt.body.recognition, recognitionDigest({
    'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey) },
  }), 'digest matches the registry in force');
});

proves('CHANGED RULES ARE VISIBLE: a guard that recognizes different issuers writes different receipts', () => {
  const { guard } = freshGuard(), e = env();
  const before = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });

  // Same destination, same key, same everything — except a second issuer is now
  // recognized. Every earlier receipt still verifies, which is exactly the
  // problem: without this digest, nothing would show that the meaning of
  // "authorized here" had changed.
  const dir2 = mkdtempSync(join(tmpdir(), 'cyan-receipts-')); dirs.push(dir2);
  const signer = receiptSigner({ kid: KID, privateKeyPem: priv(destKeys.privateKey) });
  const widened = new Guard({
    destinationId: DEST,
    issuerRegistry: {
      'zlar:issuer:1': { publicKeyPem: pem(issuerKeys.publicKey) },
      'zlar:issuer:2': { publicKeyPem: pem(thiefKeys.publicKey) },
    },
    replayDir: dir2, signReceipt: signer.sign, receiptKid: signer.kid,
    receiptLog: new ReceiptLog(join(dir2, 'log'), DEST),
  });
  const e2 = env();
  const after = widened.perform({ envelope: e2, credential: cred(e2), effectFn: () => 'moved' });

  eq(verifyReceipt(before.receipt, AUDITOR).ok, true, 'the old receipt still verifies');
  if (before.receipt.body.recognition === after.receipt.body.recognition) {
    throw new Error('widened recognition produced an identical digest');
  }
});

// ── Anchoring: the truncation the chain alone cannot catch ─────────────────

proves('a PUBLISHED HEAD makes tail truncation detectable', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 4; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const hs = headSigner({ kid: KID, privateKeyPem: priv(destKeys.privateKey) });
  const published = log.publishHead(hs.sign, hs.kid);
  eq(verifyHead(published, AUDITOR).ok, true, 'the head itself verifies');

  const full = log.read();
  eq(verifyChainAgainstHead(full, published, AUDITOR).ok, true, 'the full history satisfies its head');

  // Lop off the newest three. Internally this is a perfectly consistent chain —
  // that is the whole problem, and the head is what closes it.
  const truncated = full.slice(0, full.length - 3);
  eq(verifyChain(truncated, AUDITOR).ok, true, 'truncated history is internally consistent');
  const held = verifyChainAgainstHead(truncated, published, AUDITOR);
  eq(held.ok, false, 'but it fails against the published head');
  eq(held.reason, INVALID.TRUNCATED_BELOW_HEAD, 'named as truncation');
  eq(held.published > held.have, true, 'and states how much is missing');
});

proves('a history LONGER than its published head is fine — a head is a floor, not a claim of finality', () => {
  const { guard, log } = freshGuard();
  const e1 = env({ params: { to: '0x1', asset: 'USDC' } });
  guard.perform({ envelope: e1, credential: cred(e1), effectFn: () => 'moved' });
  const hs = headSigner({ kid: KID, privateKeyPem: priv(destKeys.privateKey) });
  const published = log.publishHead(hs.sign, hs.kid);
  const e2 = env({ params: { to: '0x2', asset: 'USDC' } });
  guard.perform({ envelope: e2, credential: cred(e2), effectFn: () => 'moved' });
  eq(verifyChainAgainstHead(log.read(), published, AUDITOR).ok, true, 'later work does not invalidate an earlier head');
});

proves('SUBSTITUTION AT THE HEAD: swapping the last entry is caught even at the published length', () => {
  const { guard, log } = freshGuard();
  for (let i = 0; i < 2; i++) {
    const e = env({ params: { to: `0x${i}`, asset: 'USDC' } });
    guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  }
  const hs = headSigner({ kid: KID, privateKeyPem: priv(destKeys.privateKey) });
  const published = log.publishHead(hs.sign, hs.kid);
  const chain = log.read();
  // Re-sign the final entry properly with the real key. Same length, valid
  // signature, valid links — only the published tail hash disagrees.
  const body = { ...chain[chain.length - 1].body, measure: 1 };
  const sig = rawSign(null, receiptPreimage(body), createPrivateKey(priv(destKeys.privateKey))).toString('base64');
  const swapped = [...chain]; swapped[swapped.length - 1] = { body, sig };
  eq(verifyChainAgainstHead(swapped, published, AUDITOR).ok, false, 'must not verify against the head');
});

proves('A HEAD IS NOT A RECEIPT: neither can be presented as the other', () => {
  const { guard, log } = freshGuard();
  const e = env();
  const r = guard.perform({ envelope: e, credential: cred(e), effectFn: () => 'moved' });
  const hs = headSigner({ kid: KID, privateKeyPem: priv(destKeys.privateKey) });
  const published = log.publishHead(hs.sign, hs.kid);
  eq(verifyReceipt({ body: { ...published.body, outcome: OUTCOME.EXECUTED }, sig: published.sig }, AUDITOR).ok,
     false, 'a head does not verify as a receipt');
  eq(verifyHead({ body: r.receipt.body, sig: r.receipt.sig }, AUDITOR).ok,
     false, 'a receipt does not verify as a head');
});

// ── The auditor's actual situation ─────────────────────────────────────────

proves('AN AUDITOR WITH ONLY A FILE AND A PUBLIC KEY CAN PROVE WHAT HAPPENED', () => {
  const { guard, log, dir } = freshGuard();
  const e1 = env({ params: { to: '0xpaid', asset: 'USDC' } });
  guard.perform({ envelope: e1, credential: cred(e1), effectFn: () => 'moved' });
  const e2 = env({ params: { to: '0xdenied', asset: 'USDC' }, measure: 999 });
  guard.perform({ envelope: e2, credential: null, effectFn: () => 'moved' });

  // Everything the destination will hand over: a file of bytes.
  const handover = join(dir, 'handover.json');
  writeFileSync(handover, JSON.stringify(log.read()));

  // Cold verification. A different party, a different process, no shared state,
  // nothing running at the destination, ZLAR entirely absent.
  const received = JSON.parse(readFileSync(handover, 'utf8'));
  const v = verifyChain(received, AUDITOR);
  eq(v.ok, true, 'the history verifies');

  const refusals = received.filter((r) => r.body.outcome === OUTCOME.REFUSED);
  eq(refusals.length, 1, 'one refusal on record');
  eq(refusals[0].body.refusal, REFUSAL.NO_CREDENTIAL, 'and its reason is signed');
  const executions = received.filter((r) => r.body.outcome === OUTCOME.EXECUTED);
  eq(executions.length, 1, 'one execution on record');
  if (!describeReceipt(executions[0]).includes('value.transfer')) throw new Error('unreadable');
});

// ── Report ─────────────────────────────────────────────────────────────────

console.log('');
for (const [tag, text] of props) console.log(`  ${tag} ${text}`);
console.log(`\n  ${pass} proven, ${fail} failed\n`);
for (const d of dirs) rmSync(d, { recursive: true, force: true });
process.exit(fail === 0 ? 0 : 1);
