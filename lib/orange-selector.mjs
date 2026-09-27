// ██ REFUSED 2026-08-16 — DO NOT USE, DO NOT EXTEND ██
//
// This module's central claim — "the floor cannot be reached, by any tool" — is
// FALSE. An adversarial review found it breakable, and the breaks reproduce:
//
//   * macOS filesystems are case-insensitive. `~/.claude/settings.json` and
//     `~/.CLAUDE/SETTINGS.JSON` are the same file. The first returns DENY, the
//     second returns ASK. The attachment point is reachable by typing it in
//     capitals.
//   * A caller can mutate a loaded rule object after construction and turn a
//     floor DENY into an ALLOW, with no re-verification.
//   * Signature verification accepts any truthy value, so `async () => false` —
//     a verifier that REJECTS — is accepted, because a Promise is truthy.
//   * A profile controls `tool_domain_map`, so it can relabel `Edit` as
//     `file.read` and take the fast path.
//   * `Read` plus `WebSearch` are both on the fast path, which is an allowed
//     disclosure route and contradicts consequence-at-the-join.
//   * Nothing imports this module. It emits no audit event and no receipt. The
//     0.124µs figure measured an orphan lookup function, not a governed path.
//
// The category error, which matters more than the list: this is a path-regex
// denylist wearing the word "floor". A regex over paths can support explanation
// and early classification. It cannot carry an immutable-floor claim, because
// the thing being protected is an OBJECT and a regex only sees a SPELLING of a
// name for it.
//
// DO NOT REPAIR THIS BY ADDING PATTERNS. Case-folding, normalisation and
// traversal handling would each close one spelling and preserve the defect while
// improving its disguise.
//
// What the floor actually requires: typed effect identity that survives from
// classification through execution, backed by a refusal owned by the destination
// or the OS — resolved identity such as device and inode, not a string. That is
// Cyan's thesis, and `NORTH-STAR.md` already says it.
//
// Superseded lineage: Candidate 018 already built a signed Orange profile
// evaluator with exact tool/domain validation, refusal of re-signed malicious
// profiles, canonical path and trusted-store handling, and evidence
// transactions. This file is not descended from it and recreates a weaker
// subset. It also collides with two incompatible contracts already named
// `orange-policy-profile-v1`.
//
// Preserved rather than deleted, as a record of the error. Review:
// ZLAR-Draft/build/LIGHT-SELECTOR-ADVERSARIAL-REVIEW.md
//
// ████████████████████████████████████████████████████
//
// The Orange selector — the fast path, and the floor that is not on the dial.
//
// ZLAR is not a brake. It is the reason the brake can come off: an agent inside
// it can be given more capability than one outside it, because nothing it
// proposes becomes real without authority it cannot manufacture. That only holds
// if routine action is genuinely fast. A governance layer that taxes every read
// gets switched off, and a switched-off gate protects nobody.
//
// So this selector has one job: decide, locally, in microseconds, with no
// network and no model, and spend friction only where consequence is.
//
// ── Why this is a resident selector and not a script ────────────────────────
//
// The shell gate re-verifies the signed policy on every single tool call. That
// is correct — its own source refuses to cache the verification, calling a cache
// "a bypass seam" — but it pays the cost every call because it is a fresh
// process every call. The cost was never the verifying. It was the forking.
//
// Verify once at load, hold the verified policy in memory for the life of the
// process, decide from it. Nothing is cached across a trust boundary; the
// process either verified its policy at startup or it refused to start.
//
// ── The floor ───────────────────────────────────────────────────────────────
//
// FLOOR is frozen here, in code, exactly as candidate 044 freezes its protected
// classes. A profile that does not carry the whole floor does not load. This is
// what makes a spectrum of profiles safe rather than a slope: latency, friction
// and the ask threshold are all calibrated to consequence, and the floor is
// calibrated to nothing. It is identical in the lightest profile and the
// heaviest. The moment a profile can lower it, someone ships the bottom.

export const FLOOR = Object.freeze([
  'registration_mutation',
  'wrapper_mutation',
  'gate_mutation',
  'policy_mutation',
  'audit_mutation',
  'receipt_mutation',
  'key_material',
  'unknown_tool',
  'ask_transport',
]);

export const DECISION = Object.freeze({
  ALLOW: 'allow',
  ASK: 'ask',
  DENY: 'deny',
});

export const REFUSAL = Object.freeze({
  FLOOR_INCOMPLETE: 'profile_floor_incomplete',
  FLOOR_PERMITTED: 'profile_permits_floor_class',
  UNSIGNED: 'profile_unsigned',
  NO_DEFAULT_DENY: 'profile_default_is_not_deny',
  UNKNOWN_TOOL: 'unknown_tool',
  DUPLICATE_DOMAIN: 'domain_decided_twice',
});

// Paths whose mutation is a floor class regardless of which tool is used.
// A gate that cannot be disabled but can be DETACHED is not a gate, so the
// attachment point is named here rather than left to a rule someone may edit.
// Ordered most specific first. Every one of these denies, so ordering cannot
// change a decision — but it changes the CLASS recorded on the receipt, and a
// receipt saying "policy mutation" is worth more to an auditor than one saying
// "something under .zlar". Name the narrowest true thing.
const FLOOR_PATH_CLASSES = [
  [/signing[._-]?key|\/\.ssh\/|id_(rsa|ed25519)$/, 'key_material'],
  [/\.policy\.json$|\/policies?\//, 'policy_mutation'],
  [/audit.*\.jsonl$/, 'audit_mutation'],
  [/receipts?.*\.jsonl$/, 'receipt_mutation'],
  [/\/\.claude\/settings(\.local)?\.json$/, 'wrapper_mutation'],
  [/\/\.claude\/.*hook.*\.(sh|json)$/, 'wrapper_mutation'],
  [/\/\.zlar\//, 'gate_mutation'],
  [/\/etc\/zlar\//, 'gate_mutation'],
];

export class Selector {
  // verifySignature is injected so this module never holds a key and never
  // decides what trust means. Omit it only in tests.
  constructor(profile, { verifySignature } = {}) {
    if (verifySignature) {
      if (!verifySignature(profile)) throw new Error(REFUSAL.UNSIGNED);
    }
    if (profile.default_action !== 'deny') throw new Error(REFUSAL.NO_DEFAULT_DENY);

    // The floor must be present in full. Not a subset, not a superset that
    // happens to include it — the whole floor, or the profile does not load.
    const declared = new Set(profile.immutable_deny_floor ?? []);
    for (const cls of FLOOR) {
      if (!declared.has(cls)) throw new Error(`${REFUSAL.FLOOR_INCOMPLETE}: ${cls}`);
    }

    // And no rule may allow or ask a floor class. Declaring the floor and then
    // permitting it elsewhere is how a fence gets moved by a second, softer
    // copy of itself.
    this.byDomain = new Map();
    for (const rule of profile.rules ?? []) {
      for (const domain of rule.domains ?? []) {
        if (rule.action !== 'deny' && FLOOR.includes(domain)) {
          throw new Error(`${REFUSAL.FLOOR_PERMITTED}: ${rule.id} ${rule.action}s ${domain}`);
        }
        if (this.byDomain.has(domain)) {
          throw new Error(`${REFUSAL.DUPLICATE_DOMAIN}: ${domain}`);
        }
        this.byDomain.set(domain, rule);
      }
    }

    this.toolDomain = new Map(Object.entries(profile.tool_domain_map ?? {}));
    this.profileName = profile.profile_name ?? profile.mode ?? 'unnamed';
  }

  // The hot path. No I/O, no allocation beyond the result, no clock read unless
  // the caller asks for one. Everything expensive happened in the constructor.
  decide(toolName, toolInput) {
    // A floor path is a floor path whichever tool reaches for it. This is
    // checked BEFORE the tool's own domain, so an allowed tool cannot be used
    // to reach a protected surface.
    const path = toolInput?.file_path ?? toolInput?.path ?? toolInput?.notebook_path;
    if (typeof path === 'string') {
      for (const [pattern, cls] of FLOOR_PATH_CLASSES) {
        if (pattern.test(path)) {
          return { decision: DECISION.DENY, rule: 'FLOOR', domain: cls, floor: true };
        }
      }
    }

    const domain = this.toolDomain.get(toolName);
    if (domain === undefined) {
      // Refusal is the default, and an unrecognised tool is a floor class —
      // novelty is exactly where consequence lives.
      return { decision: DECISION.DENY, rule: 'FLOOR', domain: 'unknown_tool', floor: true };
    }

    const rule = this.byDomain.get(domain);
    if (rule === undefined) {
      return { decision: DECISION.DENY, rule: 'DEFAULT', domain, floor: false };
    }
    return { decision: rule.action, rule: rule.id, domain, floor: FLOOR.includes(domain) };
  }
}
