// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR MCP Gate — Constitutional Validation Tests
//
// Parity test suite for mcp-gate/constitution.mjs. Every test mirrors a
// failure mode that the bash gate's validate_constitution() catches, plus
// the four presence states and the all-pass case.
//
// Usage: node mcp-gate/test-constitution.mjs
// ═══════════════════════════════════════════════════════════════════════════════

import {
  writeFileSync, mkdtempSync, rmSync, mkdirSync, existsSync, readFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync, sign as cryptoSign, createHash } from 'node:crypto';

import { canonicalize, sha256hex } from '../lib/receipt.mjs';
import {
  loadManifest,
  validateConstitution,
  resetConstitutionCache,
} from './constitution.mjs';

// ─── Test Harness ────────────────────────────────────────────────────────────

let PASS = 0, FAIL = 0, TOTAL = 0;

function assert(label, expected, actual) {
  TOTAL++;
  if (expected === actual) { PASS++; }
  else { FAIL++; console.log(`  FAIL: ${label} — expected "${expected}", got "${actual}"`); }
}

function assertIncludes(label, haystack, needle) {
  TOTAL++;
  if (typeof haystack === 'string' && haystack.includes(needle)) { PASS++; }
  else { FAIL++; console.log(`  FAIL: ${label} — "${haystack}" does not include "${needle}"`); }
}

// ─── Test Fixtures ───────────────────────────────────────────────────────────

const TEMP_DIR = mkdtempSync(join(tmpdir(), 'zlar-mcp-constitution-'));
process.on('exit', () => { try { rmSync(TEMP_DIR, { recursive: true, force: true }); } catch {} });

mkdirSync(join(TEMP_DIR, 'etc/keys'), { recursive: true });
mkdirSync(join(TEMP_DIR, 'var/log'), { recursive: true });

// Constitutional keypair (separate from policy key — PC-06)
const constKeys = generateKeyPairSync('ed25519');
const CONST_PRIV_PEM = constKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
const CONST_PUB_PEM = constKeys.publicKey.export({ type: 'spki', format: 'pem' });
const CONST_PUB_PATH = join(TEMP_DIR, 'etc/keys/constitution-signing.pub');
writeFileSync(CONST_PUB_PATH, CONST_PUB_PEM);

// Policy keypair (for manifest signature + PC-06 separation)
const policyKeys = generateKeyPairSync('ed25519');
const POLICY_PRIV_PEM = policyKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
const POLICY_PUB_PEM = policyKeys.publicKey.export({ type: 'spki', format: 'pem' });
const POLICY_PUB_PATH = join(TEMP_DIR, 'etc/keys/policy-signing.pub');
writeFileSync(POLICY_PUB_PATH, POLICY_PUB_PEM);

// Paths
const CONSTITUTION_FILE = join(TEMP_DIR, 'etc/constitution.json');
const CONSTITUTION_PRESENCE = join(TEMP_DIR, 'var/log/.constitution-last-hash');
const MANIFEST_FILE = join(TEMP_DIR, 'etc/manifest.json');
const RESTORE_CONFIG = join(TEMP_DIR, 'etc/restore-config.json');

// ─── Fixture builders ────────────────────────────────────────────────────────

function buildConstitution(overrides = {}) {
  return {
    constitution_version: '1.0.0',
    created_at: '2026-04-14T00:00:00Z',
    author: 'Test Author <test@zlar.test>',
    preamble: 'Test preamble.',
    scope: 'Test scope.',
    permanent_core: { clauses: [] },
    amendable_constraints: {
      manifest_deny_required_classes: [
        'governance_mutation',
        'evidence_mutation',
        'stop_restart_control',
        'key_material_signing_authority',
        'self_expansion_of_authority',
        'communication_channel_mutation',
      ],
    },
    signature: { algorithm: 'Ed25519', value: '', key_id: '' },
    ...overrides,
  };
}

// Sign a constitution with the constitution convention (zero only .signature.value).
function signConstitution(obj, privKeyPem) {
  const canonical = JSON.parse(JSON.stringify(obj));
  canonical.signature = { ...canonical.signature, value: '' };
  const hashHex = sha256hex(canonicalize(canonical));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privKeyPem);
  const signed = { ...obj };
  signed.signature = { ...obj.signature, value: sig.toString('base64') };
  return signed;
}

function buildManifest(overrides = {}) {
  return {
    manifest_version: '0.1.0',
    identity: { agent_id: 'test:agent', principal: 'test:human', issued_at: '2026-04-14T00:00:00Z' },
    authority: {
      allow: ['bash.read', 'file.read'],
      deny: [
        'governance_mutation',
        'evidence_mutation',
        'stop_restart_control',
        'key_material_signing_authority',
        'self_expansion_of_authority',
        'communication_channel_mutation',
      ],
      unmatched_action: 'escalate',
    },
    escalation: { channel: 'test', timeout_seconds: 300, timeout_action: 'deny' },
    sequence: 1,
    expires: '2099-01-01T00:00:00Z',
    signature: { algorithm: 'Ed25519', value: '', key_id: '' },
    ...overrides,
  };
}

// Sign a manifest with the manifest convention (zero entire signature object).
function signManifest(obj, privKeyPem) {
  const canonical = JSON.parse(JSON.stringify(obj));
  canonical.signature = { algorithm: '', value: '', key_id: '' };
  const hashHex = sha256hex(canonicalize(canonical));
  const sig = cryptoSign(null, Buffer.from(hashHex, 'utf8'), privKeyPem);
  const signed = { ...obj };
  signed.signature = { algorithm: 'Ed25519', value: sig.toString('base64'), key_id: 'test' };
  return signed;
}

function buildPolicy(overrides = {}) {
  return {
    version: 'test-1.0',
    default_action: 'deny',
    rules: [
      {
        id: 'R999',
        enabled: true,
        description: 'Test ask rule for PC-02',
        domain: 'test',
        action: 'ask',
        severity: 'info',
        match: { domain: 'test' },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
    ],
    ...overrides,
  };
}

function writeRestoreConfig(suspended = 'deny') {
  writeFileSync(RESTORE_CONFIG, JSON.stringify({
    escalation: { degraded: 'log', at_risk: 'ask', suspended },
  }));
}

function deployConstitution(constitution) {
  writeFileSync(CONSTITUTION_FILE, JSON.stringify(constitution, null, 2));
  const hash = createHash('sha256').update(readFileSync(CONSTITUTION_FILE)).digest('hex');
  writeFileSync(CONSTITUTION_PRESENCE, hash);
}

function undeploy() {
  try { rmSync(CONSTITUTION_FILE); } catch {}
  try { rmSync(CONSTITUTION_PRESENCE); } catch {}
  try { rmSync(MANIFEST_FILE); } catch {}
  resetConstitutionCache();
}

function baseOpts(overrides = {}) {
  return {
    constitutionFile: CONSTITUTION_FILE,
    constitutionPubkey: CONST_PUB_PATH,
    constitutionPresenceFile: CONSTITUTION_PRESENCE,
    policyPubkey: POLICY_PUB_PATH,
    policy: buildPolicy(),
    manifest: buildManifest(),
    restoreConfigFile: RESTORE_CONFIG,
    useCache: false, // tests run in isolation
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// PRESENCE STATES (bash gate lines 1002-1027)
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Presence states ────────────────────────────────────────────');

// State 1: no file + no tracker → pre-constitutional mode (pass, deployed=false)
{
  undeploy();
  const r = validateConstitution(baseOpts());
  assert('state 1: pre-constitutional ok', true, r.ok);
  assert('state 1: not deployed', false, r.deployed);
  assertIncludes('state 1: reason', r.reason, 'pre-constitutional');
}

// State 2: file + no tracker → ignored (pass, deployed=false)
{
  undeploy();
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  writeFileSync(CONSTITUTION_FILE, JSON.stringify(good, null, 2));
  // Intentionally no tracker write
  const r = validateConstitution(baseOpts());
  assert('state 2: file-no-tracker ok', true, r.ok);
  assert('state 2: not deployed', false, r.deployed);
  assertIncludes('state 2: reason', r.reason, 'no deployment tracker');
}

// State 3: tracker + no file → DELETION ATTACK (fail)
{
  undeploy();
  writeFileSync(CONSTITUTION_PRESENCE, 'stale-hash');
  const r = validateConstitution(baseOpts());
  assert('state 3: deletion attack fails', false, r.ok);
  assertIncludes('state 3: reason', r.reason, 'deletion attack');
}

// State 4: file + tracker → full validation
{
  undeploy();
  writeRestoreConfig('deny');
  const manifest = signManifest(buildManifest(), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2));
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const r = validateConstitution(baseOpts({ manifest }));
  assert('state 4: full validation passes', true, r.ok);
  assert('state 4: deployed', true, r.deployed);
  assert('state 4: version', '1.0.0', r.version);
}

// ═════════════════════════════════════════════════════════════════════════════
// SIGNATURE & KEY CHECKS
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Signature & key checks ─────────────────────────────────────');

// Unsigned constitution
{
  undeploy();
  deployConstitution(buildConstitution()); // signature.value stays ''
  const r = validateConstitution(baseOpts());
  assert('unsigned fails', false, r.ok);
  assertIncludes('unsigned reason', r.reason, 'unsigned');
}

// Constitution signed by wrong key
{
  undeploy();
  const wrongKeys = generateKeyPairSync('ed25519');
  const wrongPriv = wrongKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const bad = signConstitution(buildConstitution(), wrongPriv);
  deployConstitution(bad);
  const r = validateConstitution(baseOpts());
  assert('wrong-key-sig fails', false, r.ok);
  assertIncludes('wrong-key-sig reason', r.reason, 'INVALID');
}

// Tamper after signing (modify content, keep old sig)
{
  undeploy();
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  const tampered = { ...good, preamble: 'MODIFIED AFTER SIGNING' };
  deployConstitution(tampered);
  const r = validateConstitution(baseOpts());
  assert('tamper fails', false, r.ok);
  assertIncludes('tamper reason', r.reason, 'INVALID');
}

// Missing constitutional pubkey
{
  undeploy();
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const r = validateConstitution(baseOpts({
    constitutionPubkey: join(TEMP_DIR, 'etc/keys/nonexistent.pub'),
  }));
  assert('missing-pubkey fails', false, r.ok);
  assertIncludes('missing-pubkey reason', r.reason, 'public key not found');
}

// PC-06: constitutional key == policy key (reuse same pubkey for both)
{
  undeploy();
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const r = validateConstitution(baseOpts({
    policyPubkey: CONST_PUB_PATH, // same pubkey
  }));
  assert('PC-06 fails', false, r.ok);
  assertIncludes('PC-06 reason', r.reason, 'PC-06');
}

// ═════════════════════════════════════════════════════════════════════════════
// PC-01: No silent consequential power
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── PC-01: silent consequential power ──────────────────────────');

{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const badPolicy = buildPolicy({
    rules: [
      {
        id: 'R999',
        enabled: true,
        description: 'Needed ask rule',
        action: 'ask',
        severity: 'info',
        match: { domain: 'test' },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
      {
        id: 'R-SILENT',
        enabled: true,
        description: 'SILENT CONSEQUENTIAL',
        action: 'allow',
        severity: 'warn',
        audit: false,
        match: { domain: 'test' },
        risk_score: { irreversibility: 50, consequence: 40, blast_radius: 20 },
      },
    ],
  });
  const r = validateConstitution(baseOpts({ policy: badPolicy }));
  assert('PC-01 fails', false, r.ok);
  assertIncludes('PC-01 reason', r.reason, 'PC-01');
  assertIncludes('PC-01 names rule', r.reason, 'R-SILENT');
}

// ═════════════════════════════════════════════════════════════════════════════
// PC-02: Human contestability (ask rules exist)
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── PC-02: ask rule presence ───────────────────────────────────');

{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const noAsk = buildPolicy({
    rules: [
      {
        id: 'R-DENY-ONLY', enabled: true, description: 'Only deny rules',
        action: 'deny', severity: 'info', match: { domain: 'test' },
        risk_score: { irreversibility: 0, consequence: 0, blast_radius: 0 },
      },
    ],
  });
  const r = validateConstitution(baseOpts({ policy: noAsk }));
  assert('PC-02 fails', false, r.ok);
  assertIncludes('PC-02 reason', r.reason, 'PC-02');
}

// ═════════════════════════════════════════════════════════════════════════════
// PC-04: Suspended escalation must be deny
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── PC-04: suspended means stop ────────────────────────────────');

// Suspended = 'observe' (not deny) → fail
{
  undeploy();
  writeRestoreConfig('observe');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const r = validateConstitution(baseOpts());
  assert('PC-04 observe fails', false, r.ok);
  assertIncludes('PC-04 observe reason', r.reason, 'PC-04');
}

// Restore config missing → default 'deny' assumed (pass)
{
  undeploy();
  try { rmSync(RESTORE_CONFIG); } catch {}
  const manifest = signManifest(buildManifest(), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2));
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const r = validateConstitution(baseOpts({ manifest }));
  assert('PC-04 missing config passes', true, r.ok);
}

// ═════════════════════════════════════════════════════════════════════════════
// PC-05a: default_action must be deny
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── PC-05a: default deny-wins ──────────────────────────────────');

{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const allowPolicy = buildPolicy({ default_action: 'allow' });
  const r = validateConstitution(baseOpts({ policy: allowPolicy }));
  assert('PC-05a fails', false, r.ok);
  assertIncludes('PC-05a reason', r.reason, "PC-05");
  assertIncludes('PC-05a names action', r.reason, "'allow'");
}

// ═════════════════════════════════════════════════════════════════════════════
// PC-05b: Manifest must deny required governance classes
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── PC-05b: manifest denies governance classes ─────────────────');

// Missing one required class → fail
{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const badManifest = signManifest(buildManifest({
    authority: {
      allow: ['bash.read'],
      deny: [
        'governance_mutation',
        'evidence_mutation',
        'stop_restart_control',
        // MISSING: key_material_signing_authority
        'self_expansion_of_authority',
        'communication_channel_mutation',
      ],
      unmatched_action: 'escalate',
    },
  }), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(badManifest, null, 2));
  const r = validateConstitution(baseOpts({ manifest: badManifest }));
  assert('PC-05b fails', false, r.ok);
  assertIncludes('PC-05b reason', r.reason, 'PC-05');
  assertIncludes('PC-05b names missing class', r.reason, 'key_material_signing_authority');
}

// manifest loaded, authority field ABSENT → fails (bash parity regression fix)
{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const noAuthManifest = signManifest({
    manifest_version: '0.1.0',
    identity: { agent_id: 'test:agent', principal: 'test:human', issued_at: '2026-04-14T00:00:00Z' },
    // authority field deliberately omitted
    escalation: { channel: 'test', timeout_seconds: 300, timeout_action: 'deny' },
    sequence: 2,
    expires: '2099-01-01T00:00:00Z',
    signature: { algorithm: 'Ed25519', value: '', key_id: '' },
  }, POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(noAuthManifest, null, 2));
  const r = validateConstitution(baseOpts({ manifest: noAuthManifest }));
  assert('PC-05b no-authority fails', false, r.ok);
  assertIncludes('PC-05b no-authority reason', r.reason, 'PC-05');
}

// manifest loaded, authority present but .deny ABSENT → fails
{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const noDenyManifest = signManifest(buildManifest({
    authority: {
      allow: ['bash.read'],
      // deny field deliberately omitted
      unmatched_action: 'escalate',
    },
  }), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(noDenyManifest, null, 2));
  const r = validateConstitution(baseOpts({ manifest: noDenyManifest }));
  assert('PC-05b no-deny fails', false, r.ok);
  assertIncludes('PC-05b no-deny reason', r.reason, 'PC-05');
}

// manifest loaded, authority.deny = [] → fails (every required class missing)
{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const emptyDenyManifest = signManifest(buildManifest({
    authority: {
      allow: ['bash.read'],
      deny: [],
      unmatched_action: 'escalate',
    },
  }), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(emptyDenyManifest, null, 2));
  const r = validateConstitution(baseOpts({ manifest: emptyDenyManifest }));
  assert('PC-05b empty-deny fails', false, r.ok);
  assertIncludes('PC-05b empty-deny reason', r.reason, 'PC-05');
}

// No manifest → PC-05b check skipped (bash parity — MANIFEST_LOADED=false)
{
  undeploy();
  writeRestoreConfig('deny');
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  const r = validateConstitution(baseOpts({ manifest: null }));
  assert('PC-05b skipped when no manifest', true, r.ok);
}

// ═════════════════════════════════════════════════════════════════════════════
// MANIFEST LOADING
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Manifest loading ───────────────────────────────────────────');

// Happy path: signed, not expired, verifiable
{
  const m = signManifest(buildManifest(), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(m, null, 2));
  const r = loadManifest(MANIFEST_FILE, POLICY_PUB_PATH);
  assert('manifest load ok', true, r.ok);
  assert('manifest has sequence', 1, r.manifest.sequence);
}

// Tampered manifest → fail
{
  const m = signManifest(buildManifest(), POLICY_PRIV_PEM);
  const tampered = { ...m, sequence: 999 }; // change content, keep old sig
  writeFileSync(MANIFEST_FILE, JSON.stringify(tampered, null, 2));
  const r = loadManifest(MANIFEST_FILE, POLICY_PUB_PATH);
  assert('tampered manifest fails', false, r.ok);
  assertIncludes('tampered reason', r.reason, 'signature invalid');
}

// Expired manifest → fail
{
  const m = signManifest(buildManifest({ expires: '2020-01-01T00:00:00Z' }), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(m, null, 2));
  const r = loadManifest(MANIFEST_FILE, POLICY_PUB_PATH);
  assert('expired manifest fails', false, r.ok);
  assertIncludes('expired reason', r.reason, 'expired');
}

// Signed manifest but pubkey missing → fail-closed
{
  const m = signManifest(buildManifest(), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(m, null, 2));
  const r = loadManifest(MANIFEST_FILE, join(TEMP_DIR, 'etc/keys/nonexistent.pub'));
  assert('signed-no-pubkey fails', false, r.ok);
  assertIncludes('signed-no-pubkey reason', r.reason, 'not available');
}

// Missing manifest file → fail (reason clear)
{
  try { rmSync(MANIFEST_FILE); } catch {}
  const r = loadManifest(MANIFEST_FILE, POLICY_PUB_PATH);
  assert('missing manifest fails', false, r.ok);
  assertIncludes('missing reason', r.reason, 'not found');
}

// ═════════════════════════════════════════════════════════════════════════════
// CACHE
// ═════════════════════════════════════════════════════════════════════════════

console.log('\n── Cache ──────────────────────────────────────────────────────');

{
  undeploy();
  writeRestoreConfig('deny');
  const manifest = signManifest(buildManifest(), POLICY_PRIV_PEM);
  writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2));
  const good = signConstitution(buildConstitution(), CONST_PRIV_PEM);
  deployConstitution(good);
  resetConstitutionCache();

  const r1 = validateConstitution(baseOpts({ manifest, useCache: true }));
  assert('first call uncached', undefined, r1.cached);
  assert('first call ok', true, r1.ok);

  const r2 = validateConstitution(baseOpts({ manifest, useCache: true }));
  assert('second call cached', true, r2.cached);
  assert('second call ok', true, r2.ok);

  // Tamper constitution → cache miss → re-run full validation → fail
  writeFileSync(CONSTITUTION_FILE, JSON.stringify({ ...good, preamble: 'TAMPERED' }, null, 2));
  const r3 = validateConstitution(baseOpts({ manifest, useCache: true }));
  assert('post-tamper cache invalidated', false, r3.ok);
  assertIncludes('post-tamper reason', r3.reason, 'INVALID');
}

// ═════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═════════════════════════════════════════════════════════════════════════════

console.log(`\n${'═'.repeat(63)}`);
console.log(`Results: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  console.log('❌ FAILED');
  process.exit(1);
} else {
  console.log('✓ ALL PASS');
  process.exit(0);
}
