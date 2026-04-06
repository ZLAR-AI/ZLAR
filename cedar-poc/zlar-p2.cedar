// ZLAR Priority 2 Rules — Cedar (Warn/Info Severity)
//
// These rules escalate to human (ask) or log. In Cedar, there is no native
// "ask" effect — forbid is used, and the gate interprets the determining
// policy IDs to decide whether to escalate vs. hard-deny.
//
// Standing approval equivalents are expressed as permits that match specific
// pre-authorized patterns. A matching permit overrides the forbid, allowing
// the action without human escalation.

// ─── R016: Network Send Commands ─────────────────────────────────────────────
// curl, wget, ssh, scp, rsync, nc, netcat — require human approval.
// Irreversibility: 60 | Consequence: 70 | Blast Radius: 80
@id("R016-curl")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*curl *"
};

@id("R016-wget")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*wget *"
};

@id("R016-ssh")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*ssh *"
};

@id("R016-scp")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*scp *"
};

@id("R016-rsync")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*rsync *"
};

@id("R016-nc")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  (resource.command like "*nc *" || resource.command like "*ncat *" || resource.command like "*netcat *")
};

// ─── R014: Git Push ──────────────────────────────────────────────────────────
// In the bash gate this is "log" (auto-allow + audit). In Cedar, we forbid
// and let the gate check if a standing approval or escalation applies.
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

// ─── Standing Approval Equivalents ───────────────────────────────────────────
// These permits override the forbids above for pre-authorized patterns.
// Same patterns as etc/standing-approvals.json, expressed in Cedar.
// Permit + forbid: forbid wins unless the permit is more specific and the
// forbid uses `when` conditions that don't match. Cedar's forbid-wins
// semantics mean these permits CANNOT override P1 forbids — only P2.
//
// NOTE: Cedar's forbid-always-wins means standing approvals for P2 rules
// must be structured differently. We use a separate action "evaluate_with_sa"
// that the gate invokes when checking standing approvals. P2 forbids are
// written against "evaluate" and SA permits against "evaluate_with_sa",
// so they don't conflict.

// SA001: curl to localhost/127.0.0.1
@id("SA001")
permit (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  (resource.command like "*curl*localhost*" || resource.command like "*curl*127.0.0.1*")
}
unless {
  // P1 rules still win — this permit cannot override R012, R002, etc.
  // Cedar's forbid-wins guarantees this structurally.
  false
};

// SA002: GitHub API via curl
@id("SA002")
permit (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*api.github.com*"
};

// SA004: Git push to ZLAR-AI/origin
@id("SA004")
permit (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  (resource.command like "*git push*ZLAR-AI*" || resource.command like "*git push*origin*")
};

// SA006: GitHub CLI operations
@id("SA006")
permit (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  (resource.command like "*gh pr *" || resource.command like "*gh issue *" ||
   resource.command like "*gh repo *" || resource.command like "*gh api *" ||
   resource.command like "*gh release *" || resource.command like "*gh run *")
};
