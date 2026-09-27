// A watchable demonstration. Run: node demo-theft.mjs
// No test framework, no jargon — just the story, narrated as it happens.

import { generateKeyPairSync, createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join as pjoin } from 'node:path';
import { canonicalBytes } from './canonical.mjs';
import { makeEnvelope, envelopeDigest } from './envelope.mjs';
import { issue, USE } from './credential.mjs';
import { Guard } from './guard.mjs';
import { ReferenceWallet, OUTCOME } from './wallet.mjs';
import { ZlarCosigner } from './cosigner.mjs';

const B = '\x1b[1m', G = '\x1b[32m', R = '\x1b[31m', D = '\x1b[2m', N = '\x1b[0m';
const say = (s = '') => console.log(s);
const money = (n) => `$${n.toLocaleString()}`;

const owner = generateKeyPairSync('ed25519');
const zlarW = generateKeyPairSync('ed25519');
const issuer = generateKeyPairSync('ed25519');
const pem = (k) => k.export({ type: 'spki', format: 'pem' });
const priv = (k) => k.export({ type: 'pkcs8', format: 'pem' });
const WALLET = 'wallet:vincent-treasury';
const now = Math.floor(Date.now() / 1000);
const ownerSigns = (body) => sign(null, canonicalBytes(body), createPrivateKey(priv(owner.privateKey))).toString('base64');

const wallet = new ReferenceWallet({
  id: WALLET,
  requiredSigners: { owner: pem(owner.publicKey), zlar: pem(zlarW.publicKey) },
  balances: { USDC: 1_000_000 },
});
const guard = new Guard({
  destinationId: WALLET,
  issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(issuer.publicKey) } },
  replayDir: mkdtempSync(pjoin(tmpdir(), 'cyan-demo-')),
});
const cosigner = new ZlarCosigner({ privateKeyPem: priv(zlarW.privateKey), guard, walletId: WALLET });

say(`\n${B}  THE WALLET${N}`);
say(`  Balance: ${B}${money(wallet.balances.USDC)}${N}`);
say(`  ${D}This wallet's own rule: a transfer needs two signatures — the owner's, and ZLAR's.${N}`);
say(`  ${D}Nobody can change that rule from inside a transaction.${N}`);

// ── Act 1 ────────────────────────────────────────────────────────────────────
say(`\n${B}  1. A NORMAL PAYMENT${N}`);
say(`  The finance agent wants to pay a supplier ${money(5000)}.`);
const good = makeEnvelope({ consequence: 'value.transfer', principal: 'agent:treasury-bot',
  destination: WALLET, params: { to: 'supplier-a', asset: 'USDC' }, measure: 5000 });
const cred = issue({ issuerKid: 'zlar:issuer:1', privateKeyPem: priv(issuer.privateKey),
  envelopeDigest: envelopeDigest(good), principal: good.principal, destination: WALLET,
  use: USE.ONCE, expiresAt: now + 300 });
const co = cosigner.cosign({ envelope: good, nonce: wallet.nonce, credential: cred, now });
say(`  ZLAR checks it against the rules, agrees, and adds its signature. ${G}✓${N}`);
const settled = wallet.submit({ body: co.body, signatures: { owner: ownerSigns(co.body), zlar: co.signature } });
say(`  Wallet: ${G}${settled.outcome.toUpperCase()}${N}. Balance is now ${B}${money(wallet.balances.USDC)}${N}.`);

// ── Act 2 ────────────────────────────────────────────────────────────────────
say(`\n${B}  2. THE THEFT${N}`);
say(`  ${R}The owner's private key is stolen. A perfect copy.${N}`);
say(`  ${D}The thief knows the wallet, the format, everything. He writes his own transfer:${N}`);
say(`  ${D}the entire remaining balance, to his own address.${N}`);
const evil = { wallet: WALLET, nonce: wallet.nonce, to: 'attacker-0xdead', asset: 'USDC', amount: 995_000 };
say(`\n  He signs it with the stolen key — a real, valid signature.`);
const theft = wallet.submit({ body: evil, signatures: { owner: ownerSigns(evil) } });
say(`  He submits it to the wallet.\n`);
say(`  Wallet: ${R}${B}${theft.outcome.toUpperCase()}${N} — ${B}${theft.reason}${N}`);
say(`  Missing: ${theft.missing_signatures.join(', ')}`);
say(`\n  ${B}Read that carefully. The wallet did not refuse him.${N}`);
say(`  ${D}There was nothing to refuse. What he submitted was not a transaction —${N}`);
say(`  ${D}it was half of one. Like presenting half a cheque. There is no rule to${N}`);
say(`  ${D}argue with, no guard to get past, no exception to find.${N}`);
say(`\n  Balance: ${B}${money(wallet.balances.USDC)}${N} — ${G}not one dollar moved.${N}`);

// ── Act 3 ────────────────────────────────────────────────────────────────────
say(`\n${B}  3. THE THIEF GETS SMARTER${N}`);
say(`  He copies ZLAR's signature from the legitimate supplier payment`);
say(`  and staples it onto his own transfer.`);
const stapled = wallet.submit({ body: evil, signatures: { owner: ownerSigns(evil), zlar: co.signature } });
say(`  Wallet: ${R}${B}${stapled.outcome.toUpperCase()}${N} — ZLAR signed different words. It signs nothing here.`);

say(`\n${B}  4. THE AGENT ITSELF IS COMPROMISED${N}`);
say(`  Now the attacker owns the AI. It holds a real, valid approval for the`);
say(`  ${money(5000)} supplier payment, and tries to spend it on ${money(995000)} to himself.`);
const swapped = makeEnvelope({ consequence: 'value.transfer', principal: 'agent:treasury-bot',
  destination: WALLET, params: { to: 'attacker-0xdead', asset: 'USDC' }, measure: 995_000 });
const attempt = cosigner.cosign({ envelope: swapped, nonce: wallet.nonce, credential: cred, now });
say(`  ZLAR: ${R}${B}no signature produced${N} — ${attempt.refusal}`);
say(`  ${D}The approval was for one exact payment. It is not currency.${N}`);

say(`\n  ${B}Final balance: ${money(wallet.balances.USDC)}${N}`);
say(`  ${D}Stolen key. Forged signature. Reused signature. Compromised AI.${N}`);
say(`  ${G}${B}  The money never moved.${N}\n`);
