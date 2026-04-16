// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR MCP Gate — Constitutional Validation (Second Authority Law parity)
//
// Ports bin/zlar-gate validate_constitution() (lines 991-1149) to the
// JavaScript MCP gate. Must match bash behavior exactly so both enforcement
// surfaces deny the same tamper patterns.
//
// Responsibilities:
//   1. Presence check — distinguishes deployed constitution from stray file
//   2. Deletion-attack detection — tracker exists but file missing → FATAL
//   3. Constitution signature verification (Ed25519, canonicalization matches bash)
//   4. PC-06: key separation (constitutional key ≠ policy key)
//   5. PC-01: no policy rule has audit:false with consequential risk
//   6. PC-02: policy has at least one ask rule (human contestability)
//   7. PC-04: restore-config.json escalation.suspended = 'deny'
//   8. PC-05a: policy default_action = 'deny'
//   9. PC-05b: manifest.authority.deny contains every constitutional required class
//
// Canonicalization conventions match bash gate:
//   Constitution:  clear only .signature.value (preserves algorithm + key_id)
//   Manifest:      clear entire .signature object with triple empty strings
//
// Both use lib/receipt.mjs canonicalize() (recursive key-sort + compact) and
// SHA-256(canonical) → Ed25519 verify hex bytes, same as bash zlar_crypto_verify.
// ═══════════════════════════════════════════════════════════════════════════════

import { readFileSync, existsSync } from 'node:fs';
import { createHash, verify as cryptoVerify } from 'node:crypto';
import { canonicalize, sha256hex, pubkeyFingerprint } from '../lib/receipt.mjs';
import { canonicalFormVariants, verifyAnyCanonical } from '../lib/sig-verify.mjs';

// ─── Signature Verification ──────────────────────────────────────────────────

// Constitution convention: zero only .signature.value. Matches bash gate
// line 1071: jq '.signature.value = ""' (preserves algorithm + key_id).
function canonicalClearValueOnly(obj) {
  const c = JSON.parse(JSON.stringify(obj));
  c.signature = { ...c.signature, value: '' };
  return c;
}

// Manifest convention: zero entire signature object to triple empty strings.
// Matches bash gate line 370: jq -S -c '.signature = {algorithm:"",value:"",key_id:""}'.
function canonicalClearAllSignatureFields(obj) {
  const c = JSON.parse(JSON.stringify(obj));
  c.signature = { algorithm: '', value: '', key_id: '' };
  return c;
}

function verifyEd25519(publicKeyPath, canonicalObj, sigBase64) {
  if (!existsSync(publicKeyPath)) return false;
  try {
    const pubKeyPem = readFileSync(publicKeyPath, 'utf8');
    // Try all three canonical forms currently in circulation (ADR-011).
    // Constitution is signed under the bash-pretty form; manifest under the
    // bash-pipeline form; future signers should use the spec form.
    const forms = canonicalFormVariants(canonicalObj);
    const result = verifyAnyCanonical(forms, pubKeyPem, sigBase64);
    if (result.ok && result.form !== 'spec') {
      console.warn(`[gate] WARN: signature verified under LEGACY canonical form "${result.form}". Migration tracked by ADR-011.`);
    }
    return result.ok;
  } catch {
    return false;
  }
}

// ─── Manifest Loading ────────────────────────────────────────────────────────

/**
 * Load and verify the agent manifest.
 *
 * Verification: if pubkeyPath exists and manifest has a signature, the signature
 * is verified with the manifest canonicalization convention. If the manifest is
 * signed but the pubkey is missing, fail-closed (we can't trust an unverifiable
 * signed manifest). If the manifest has no signature, load it anyway (bootstrap
 * mode — bash gate has the same tolerance).
 *
 * Expiry check: if manifest has an `expires` timestamp in the past, fail-closed.
 *
 * @param {string} manifestPath   - Path to manifest.json
 * @param {string} pubkeyPath     - Path to policy-signing.pub (manifests signed
 *                                  by the policy key, not constitutional key)
 * @returns {{ok: boolean, manifest?: object, reason?: string}}
 */
export function loadManifest(manifestPath, pubkeyPath) {
  if (!existsSync(manifestPath)) {
    return { ok: false, reason: 'manifest file not found' };
  }

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (e) {
    return { ok: false, reason: `manifest parse error: ${e.message}` };
  }

  // Signature verification (fail-closed on mismatch OR when signed+unverifiable)
  if (manifest.signature?.value) {
    if (!existsSync(pubkeyPath)) {
      return { ok: false, reason: 'manifest signed but policy pubkey not available for verification' };
    }
    const canonical = canonicalClearAllSignatureFields(manifest);
    if (!verifyEd25519(pubkeyPath, canonical, manifest.signature.value)) {
      return { ok: false, reason: 'manifest signature invalid' };
    }
  }

  // Expiry check
  if (manifest.expires) {
    const exp = new Date(manifest.expires);
    if (!isNaN(exp.getTime()) && exp < new Date()) {
      return { ok: false, reason: `manifest expired at ${manifest.expires}` };
    }
  }

  return { ok: true, manifest };
}

// ─── Constitutional Validation ───────────────────────────────────────────────

// Module-level cache. Keyed by the constitution file's SHA-256. A cache miss
// happens automatically when the file changes (tamper or post-amendment
// activation), forcing full revalidation. Policy is loaded once per MCP gate
// process lifetime, so we don't need to include its hash in the cache key.
let _cache = { hash: null, result: null };

/**
 * Reset the in-process validation cache. Primarily for tests.
 */
export function resetConstitutionCache() {
  _cache = { hash: null, result: null };
}

/**
 * Validate the policy and manifest against the deployed constitution.
 *
 * Four presence states (from bash gate lines 1002-1014):
 *   file exists + tracker exists  → full validation
 *   file exists + no tracker      → ignore file (not deployed via ceremony)
 *   no file     + tracker exists  → FATAL deletion attack
 *   no file     + no tracker      → pre-constitutional mode (pass)
 *
 * @param {object} opts
 * @param {string} opts.constitutionFile         - Path to constitution.json
 * @param {string} opts.constitutionPubkey       - Path to constitution-signing.pub
 * @param {string} opts.constitutionPresenceFile - Deployment tracker path
 * @param {string} opts.policyPubkey             - Path to policy-signing.pub (for PC-06)
 * @param {object} opts.policy                   - Loaded policy object (for PC-01, PC-02, PC-05a)
 * @param {object|null} opts.manifest            - Loaded manifest (for PC-05b)
 * @param {string} opts.restoreConfigFile        - Path to restore-config.json (for PC-04)
 * @param {boolean} [opts.useCache=true]         - Disable cache (for tests)
 *
 * @returns {{ok: boolean, reason?: string, deployed?: boolean, version?: string, hash?: string, cached?: boolean}}
 */
export function validateConstitution(opts) {
  const {
    constitutionFile,
    constitutionPubkey,
    constitutionPresenceFile,
    policyPubkey,
    policy,
    manifest,
    restoreConfigFile,
    useCache = true,
  } = opts;

  // ── 1. Presence check (cheap, always runs) ────────────────────────────
  if (!existsSync(constitutionPresenceFile)) {
    if (existsSync(constitutionFile)) {
      return {
        ok: true,
        deployed: false,
        reason: 'constitution file exists but no deployment tracker — ignoring (not deployed via ceremony)',
      };
    }
    return { ok: true, deployed: false, reason: 'pre-constitutional mode' };
  }

  // Tracker exists — file must be present
  if (!existsSync(constitutionFile)) {
    return {
      ok: false,
      reason: 'constitution was deployed but file is now missing — possible deletion attack',
    };
  }

  // ── 2. Cache check ────────────────────────────────────────────────────
  const currentHash = createHash('sha256')
    .update(readFileSync(constitutionFile))
    .digest('hex');

  if (useCache && _cache.hash === currentHash && _cache.result) {
    return { ..._cache.result, cached: true };
  }

  // ── 3. Constitutional pubkey must exist ───────────────────────────────
  if (!existsSync(constitutionPubkey)) {
    return { ok: false, reason: `constitution public key not found at ${constitutionPubkey}` };
  }

  // ── 4. PC-06: key separation ──────────────────────────────────────────
  // Math-6 finding: missing policy pubkey silently passed (short-circuit
  // on null). If we can't verify key separation, we can't prove it holds.
  // Both keys must exist and must differ.
  let constFp, policyFp;
  try {
    constFp = pubkeyFingerprint(constitutionPubkey);
  } catch (e) {
    return { ok: false, reason: `constitution pubkey fingerprint error: ${e.message}` };
  }
  if (!existsSync(policyPubkey)) {
    return {
      ok: false,
      reason: 'PC-06 VIOLATED — policy public key not found (cannot verify key separation)',
    };
  }
  try {
    policyFp = pubkeyFingerprint(policyPubkey);
  } catch (e) {
    return {
      ok: false,
      reason: `PC-06 VIOLATED — policy pubkey fingerprint error: ${e.message}`,
    };
  }
  if (constFp === policyFp) {
    return {
      ok: false,
      reason: 'PC-06 VIOLATED — constitutional key fingerprint matches policy key',
    };
  }

  // ── 5. Parse + verify constitution signature ──────────────────────────
  let constitution;
  try {
    constitution = JSON.parse(readFileSync(constitutionFile, 'utf8'));
  } catch (e) {
    return { ok: false, reason: `constitution parse error: ${e.message}` };
  }

  if (!constitution.signature?.value) {
    return { ok: false, reason: 'constitution is unsigned' };
  }

  const canonical = canonicalClearValueOnly(constitution);
  if (!verifyEd25519(constitutionPubkey, canonical, constitution.signature.value)) {
    return { ok: false, reason: 'constitution signature INVALID' };
  }

  // ── 6. PC-01: No rule with consequential risk AND audit:false ─────────
  if (policy?.rules && Array.isArray(policy.rules)) {
    const silentRules = policy.rules
      .filter(r => r.audit === false &&
        ((r.risk_score?.irreversibility || 0) > 0 ||
         (r.risk_score?.consequence || 0) > 0 ||
         (r.risk_score?.blast_radius || 0) > 0))
      .map(r => r.id);
    if (silentRules.length > 0) {
      return {
        ok: false,
        reason: `PC-01 VIOLATED — rules with consequential risk and audit:false: ${silentRules.join(', ')}`,
      };
    }
  }

  // ── 7. PC-02: Human contestability must cover the consequential surface ─
  // Math-6 formal verification found: a single ask rule on an unreachable
  // pattern satisfies an existence check while allowing every consequential
  // action through without human review. The fix: ask rules must cover at
  // least one domain that also has consequential allow/log rules. This
  // proves the human review path intersects with the real action surface.
  if (Array.isArray(policy?.rules)) {
    const enabledRules = policy.rules.filter(r => r.enabled !== false);

    const askDomains = new Set(enabledRules
      .filter(r => r.action === 'ask')
      .map(r => r.domain || r.match?.domain || '*'));

    const consequentialAllowDomains = new Set(enabledRules
      .filter(r => (r.action === 'allow' || r.action === 'log') &&
        ((r.risk_score?.irreversibility || 0) > 0 ||
         (r.risk_score?.consequence || 0) > 0 ||
         (r.risk_score?.blast_radius || 0) > 0))
      .map(r => r.domain || r.match?.domain || '*'));

    if (askDomains.size === 0) {
      return {
        ok: false,
        reason: 'PC-02 VIOLATED — no ask rules in policy (no human contestability path)',
      };
    }

    // Ask domains must intersect with consequential-allow domains.
    // Wildcard '*' intersects with everything.
    if (consequentialAllowDomains.size > 0) {
      const intersects = [...askDomains].some(d =>
        d === '*' || consequentialAllowDomains.has(d) || consequentialAllowDomains.has('*'));
      if (!intersects) {
        return {
          ok: false,
          reason: `PC-02 VIOLATED — ask rules cover domains {${[...askDomains].join(', ')}} but consequential allow rules cover {${[...consequentialAllowDomains].join(', ')}} — no overlap (human review does not reach the consequential surface)`,
        };
      }
    }
  } else {
    return {
      ok: false,
      reason: 'PC-02 VIOLATED — policy has no rules array',
    };
  }

  // ── 8. PC-04: Suspended escalation must be deny ───────────────────────
  if (restoreConfigFile && existsSync(restoreConfigFile)) {
    try {
      const rc = JSON.parse(readFileSync(restoreConfigFile, 'utf8'));
      const escSuspended = rc?.escalation?.suspended ?? 'deny';
      if (escSuspended !== 'deny') {
        return {
          ok: false,
          reason: `PC-04 VIOLATED — suspended escalation is '${escSuspended}', must be 'deny'`,
        };
      }
    } catch (e) {
      // Math-6 finding: corrupt JSON silently passed. A corrupted restore-config
      // could mask a PC-04 violation. Fail-closed: if we can't read the config,
      // we can't prove suspended escalation is deny.
      return {
        ok: false,
        reason: `PC-04 VIOLATED — restore-config exists but cannot be parsed: ${e.message}`,
      };
    }
  }

  // ── 9. PC-05a: default_action must be deny ────────────────────────────
  const defaultAction = policy?.default_action || '';
  if (defaultAction !== 'deny') {
    return {
      ok: false,
      reason: `PC-05 VIOLATED — default_action is '${defaultAction}', must be 'deny'`,
    };
  }

  // ── 10a. PC-05b-pre: Constitution must declare ≥1 required deny class ──
  // Defense-in-depth against a vacuously-empty required_classes field.
  // bin/zlar-constitution _dp03_check (line 767-777) already enforces the
  // specific six-class content at deploy time, so this gate-load check
  // guards against post-deploy tamper and against constitutions deployed
  // by older ceremony versions that predated _dp03_check.
  //
  // Filters to non-empty strings only — a required_classes field populated
  // with nulls, non-strings, or empty strings is treated as vacuous.
  // Array.isArray guard handles the case where the field is a non-array
  // (string, number, object); bash gate's jq handles this via `if type ==
  // "array"`. Without the guard, JS would crash with TypeError on .filter.
  const _rawClasses = constitution.amendable_constraints?.manifest_deny_required_classes;
  const requiredClasses = (Array.isArray(_rawClasses) ? _rawClasses : [])
    .filter(c => typeof c === 'string' && c.length > 0);
  if (requiredClasses.length === 0) {
    return {
      ok: false,
      reason: 'PC-05 VIOLATED — constitution does not declare amendable_constraints.manifest_deny_required_classes (no reserved classes declared)',
    };
  }

  // ── 10b. PC-05b: Manifest must deny required governance classes ────────
  // Parity with bash gate lines 1124-1137: check runs when the manifest is
  // loaded (null-manifest means the manifest failed to load and the sub-check
  // is skipped — bash MANIFEST_LOADED=false behavior). A manifest that IS
  // loaded but omits authority or authority.deny must fail, because bash's
  // grep over an empty deny-set reports every required class as missing.
  // Math-6 finding: null manifest silently skipped PC-05b. A missing or
  // failed manifest means we cannot verify the six governance-critical
  // capabilities are denied. Fail-closed: if the constitution declares
  // required deny classes, the manifest must be present to prove them.
  if (!manifest) {
    return {
      ok: false,
      reason: `PC-05 VIOLATED — constitution requires manifest deny classes [${requiredClasses.join(', ')}] but no manifest is loaded (cannot verify agent capability restrictions)`,
    };
  }
  const manifestDenies = new Set(manifest.authority?.deny || []);
  const missing = requiredClasses.filter(c => !manifestDenies.has(c));
  if (missing.length > 0) {
    return {
      ok: false,
      reason: `PC-05 VIOLATED — manifest missing required deny classes: ${missing.join(', ')}`,
    };
  }

  // ── 11. Success ───────────────────────────────────────────────────────
  const result = {
    ok: true,
    deployed: true,
    hash: currentHash,
    version: constitution.constitution_version || '?',
  };

  if (useCache) {
    _cache = { hash: currentHash, result };
  }

  return result;
}
