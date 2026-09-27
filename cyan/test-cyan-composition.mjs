// Cyan slice two — composition and cumulative effect.
// The escapes here are the ones that break systems in ten years, not ten minutes.

import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join as pjoin } from 'node:path';
import { makeEnvelope } from './envelope.mjs';
import { issueGrant, delegate } from './grant.mjs';
import { Guard, REFUSAL } from './guard.mjs';

let pass = 0, fail = 0; const props = [];
const proves = (p, fn) => { try { fn(); pass++; props.push(['PROVEN ', p]); }
  catch (e) { fail++; props.push(['FAILED ', `${p}  → ${e.message}`]); } };
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}: expected ${b}, got ${a}`); };

const keys = generateKeyPairSync('ed25519');
const pem = (k) => k.export({ type: 'spki', format: 'pem' });
const priv = (k) => k.export({ type: 'pkcs8', format: 'pem' });
const DEST = 'treasury:acme-1';
const now = Math.floor(Date.now() / 1000);

// The destination declares what combinations mean. Only it knows that granting
// read access and then disclosing equals exfiltration.
const ELEVATIONS = [{
  id: 'read-then-disclose-is-exfiltration',
  when: [{ class: 'access.change', scope: { resource: 'customer-pii' } },
         { class: 'information.disclose', scope: { resource: 'customer-pii' } }],
  then: { class: 'physical.irreversible', measure: 1 },
  note: 'disclosure of PII cannot be undone',
}];

const PROHIBITIONS = [{
  id: 'no-deploy-then-activate',
  when: [{ class: 'code.deploy' }, { class: 'machinery.activate' }],
}];

function setup(over = {}) {
  const dir = mkdtempSync(pjoin(tmpdir(), 'cyan-grant-'));
  const guard = new Guard({
    destinationId: DEST,
    issuerRegistry: { 'zlar:issuer:1': { publicKeyPem: pem(keys.publicKey) } },
    replayDir: dir, grantDir: dir,
  });
  const grant = issueGrant({
    issuerKid: 'zlar:issuer:1', privateKeyPem: priv(keys.privateKey),
    principal: 'agent:treasury-bot', destination: DEST,
    allow: [{ class: 'value.transfer' }, { class: 'access.change' },
            { class: 'information.disclose' }, { class: 'code.deploy' },
            { class: 'machinery.activate' }],
    ceilings: { 'value.transfer': 10000, 'access.change': 100, 'information.disclose': 100,
                'code.deploy': 10, 'machinery.activate': 10 },
    elevations: ELEVATIONS, prohibitions: PROHIBITIONS,
    windowSeconds: 86400, expiresAt: now + 3600, ...over,
  });
  return { guard, grant };
}

const env = (o) => makeEnvelope({ principal: 'agent:treasury-bot', destination: DEST, ...o });

proves('routine action inside standing authority executes with no human touched', () => {
  const { guard, grant } = setup();
  const r = guard.authorizeUnderGrant({ envelope: env({ consequence: 'value.transfer', params: { to: 'supplier-a' }, measure: 500 }), grant, now });
  eq(r.authorized, true, 'authorized');
});

proves('VOLUME ESCAPE, the real one: many separately-authorized actions cannot sum past the ceiling', () => {
  const { guard, grant } = setup();
  let executed = 0, refusal = null;
  // Each action is individually well within budget. None declares a plan.
  for (let i = 0; i < 40; i++) {
    const r = guard.authorizeUnderGrant({ envelope: env({ consequence: 'value.transfer', params: { to: `supplier-${i}` }, measure: 500 }), grant, now });
    if (r.authorized) executed++; else { refusal = r.refusal; break; }
  }
  eq(executed, 20, 'exactly 20 × 500 = the 10000 ceiling');
  eq(refusal, REFUSAL.CEILING_EXCEEDED, 'then refused');
});

proves('COMPOSITION ESCAPE: two individually permitted steps refuse at the join', () => {
  const { guard, grant } = setup();
  const step1 = guard.authorizeUnderGrant({ envelope: env({ consequence: 'access.change', params: { resource: 'customer-pii' }, measure: 1 }), grant, now });
  eq(step1.authorized, true, 'step 1 alone is permitted');
  const step2 = guard.authorizeUnderGrant({ envelope: env({ consequence: 'information.disclose', params: { resource: 'customer-pii' }, measure: 1 }), grant, now });
  eq(step2.authorized, false, 'step 2 must refuse in combination');
  eq(step2.refusal, REFUSAL.PROHIBITED_COMBINATION, 'refusal');
});

proves('the same second step is permitted when the first never happened', () => {
  const { guard, grant } = setup();
  const r = guard.authorizeUnderGrant({ envelope: env({ consequence: 'information.disclose', params: { resource: 'customer-pii' }, measure: 1 }), grant, now });
  eq(r.authorized, true, 'no combination, no elevation');
});

proves('CONSTITUTIONAL: a prohibited combination refuses even with ceilings to spare', () => {
  const { guard, grant } = setup();
  eq(guard.authorizeUnderGrant({ envelope: env({ consequence: 'code.deploy', params: { unit: 'line-3' }, measure: 1 }), grant, now }).authorized, true, 'deploy alone');
  const r = guard.authorizeUnderGrant({ envelope: env({ consequence: 'machinery.activate', params: { unit: 'line-3' }, measure: 1 }), grant, now });
  eq(r.refusal, REFUSAL.PROHIBITED_COMBINATION, 'new code must not drive the machine');
});

proves('DELEGATION IS A MEET: a child grant cannot exceed its parent, even when it asks', () => {
  const { grant } = setup();
  const child = delegate({
    parentGrant: grant, issuerKid: 'zlar:issuer:1', privateKeyPem: priv(keys.privateKey),
    requested: { principal: 'agent:sub-bot', ceilings: { 'value.transfer': 999999 }, allow: [{ class: 'value.transfer' }] },
  });
  eq(child.claims.ceilings['value.transfer'], 10000, 'narrowed to the parent ceiling');
  eq(child.claims.allow.length, 1, 'allow intersected, not widened');
  if (child.claims.exp > grant.claims.exp) throw new Error('child outlived parent');
});

proves('delegation cannot introduce a class the parent never held', () => {
  const { grant } = setup();
  const child = delegate({
    parentGrant: grant, issuerKid: 'zlar:issuer:1', privateKeyPem: priv(keys.privateKey),
    requested: { principal: 'agent:sub-bot', allow: [{ class: 'state.action.issue' }], ceilings: { 'state.action.issue': 500 } },
  });
  eq(child.claims.allow.length, 0, 'nothing granted');
  eq(child.claims.ceilings['state.action.issue'], undefined, 'no ceiling minted from nothing');
});

proves('constraints accumulate down a delegation chain — prohibitions union, never subtract', () => {
  const { grant } = setup();
  const child = delegate({
    parentGrant: grant, issuerKid: 'zlar:issuer:1', privateKeyPem: priv(keys.privateKey),
    requested: { principal: 'agent:sub-bot', prohibitions: [{ id: 'extra', when: [{ class: 'value.transfer' }] }] },
  });
  eq(child.claims.prohibitions.length, grant.claims.prohibitions.length + 1, 'union');
});

proves('an action outside the allow list refuses even with budget available', () => {
  const { guard, grant } = setup({ allow: [{ class: 'value.transfer' }] });
  const r = guard.authorizeUnderGrant({ envelope: env({ consequence: 'energy.allocate', measure: 1 }), grant, now });
  eq(r.refusal, REFUSAL.NOT_IN_ALLOW, 'refusal');
});

proves('an expired grant ends standing authority with no cancel message', () => {
  const { guard, grant } = setup({ expiresAt: now - 1 });
  eq(guard.authorizeUnderGrant({ envelope: env({ consequence: 'value.transfer', measure: 1 }), grant, now }).refusal,
     REFUSAL.GRANT_EXPIRED, 'refusal');
});

proves('the composition window is bounded — ancient history does not forbid present action', () => {
  const { guard, grant } = setup({ windowSeconds: 60 });
  guard.authorizeUnderGrant({ envelope: env({ consequence: 'value.transfer', params: { to: 'a' }, measure: 9000 }), grant, now });
  const later = guard.authorizeUnderGrant({ envelope: env({ consequence: 'value.transfer', params: { to: 'b' }, measure: 9000 }), grant, now: now + 300 });   // past the 60s window, still inside the grant's life
  eq(later.authorized, true, 'spend outside the window no longer counts');
});

proves('every refusal states which ceiling or combination caused it', () => {
  const { guard, grant } = setup();
  guard.authorizeUnderGrant({ envelope: env({ consequence: 'value.transfer', params: { to: 'a' }, measure: 9999 }), grant, now });
  const r = guard.authorizeUnderGrant({ envelope: env({ consequence: 'value.transfer', params: { to: 'b' }, measure: 500 }), grant, now });
  if (!r.detail || !r.detail.includes('value.transfer')) throw new Error(`unhelpful detail: ${r.detail}`);
});

console.log('\n  CYAN SLICE TWO — composition and cumulative effect\n');
for (const [s, t] of props) console.log(`  ${s} ${t}`);
console.log(`\n  ${pass} proven, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
