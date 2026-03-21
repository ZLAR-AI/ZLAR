// ZLAR Governance Policies — Cedar PoC
// Three real rules from the bash gate, translated to Cedar syntax.
//
// Cedar is default-deny. Only `permit` policies grant access.
// `forbid` policies override permits (deny wins).

// ─── R012: Gate self-protection ──────────────────────────────────────────────
// The gate protects its own enforcement infrastructure. Any bash command
// touching gate binaries, config, policy files, or audit trails is denied.
// This is the rule that governs the governor.
@id("R012")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  (
    resource.command like "*/bin/zlar-*" ||
    resource.command like "*/.claude/hooks*" ||
    resource.command like "*/.claude/settings*" ||
    resource.command like "*policy*.json*" ||
    resource.command like "*gate.json*" ||
    resource.command like "*/var/log/audit*" ||
    resource.command like "*/var/log/gate*" ||
    resource.command like "*pf-zlar*" ||
    resource.command like "*pf.conf*"
  )
};

// ─── R001: Safe read-only shell ──────────────────────────────────────────────
// Allow simple, non-compound shell commands that only read state.
// The compound_guard (no pipes, redirects, semicolons, backticks, $())
// is enforced by the `unless` clause — Cedar's structural equivalent.
@id("R001")
permit (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  (
    resource.command like "ls *" ||
    resource.command like "pwd*" ||
    resource.command like "whoami*" ||
    resource.command like "hostname*" ||
    resource.command like "git status*" ||
    resource.command like "git log*" ||
    resource.command like "git diff*" ||
    resource.command like "wc *" ||
    resource.command like "date*"
  )
}
unless {
  // Compound guard — deny if command contains shell operators
  resource.command like "*;*" ||
  resource.command like "*|*" ||
  resource.command like "*&*" ||
  resource.command like "*`*" ||
  resource.command like "*>*" ||
  resource.command like "*$(*"
};

// ─── R014: Git push requires approval ────────────────────────────────────────
// Translates to forbid in Cedar (the gate would route to Telegram for HITL).
// In production Cedar, this would be a custom "ask" effect via an extension.
// For the PoC, forbid demonstrates the structural enforcement.
@id("R014")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*git push*"
};
