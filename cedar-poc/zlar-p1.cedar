// ZLAR Priority 1 Rules — Cedar (Critical Severity)
//
// These rules MUST deny. They protect against irreversible, high-consequence
// actions that no policy should allow without explicit human override.
//
// Cedar is default-deny. These forbid policies ensure denial even if a
// broad permit exists. Forbid wins.
//
// Rule source: bin/zlar-gate policy rules, translated from regex to Cedar.
// Cross-referenced with: docs/adr/ADR-001 (deterministic enforcement).

// ─── R002: Recursive/Forced Deletion ─────────────────────────────────────────
// rm -rf, rm -fr, rm --recursive — halt unconditionally.
// Irreversibility: 100 | Consequence: 100 | Blast Radius: 95
@id("R002-a")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*rm *-rf*"
};

@id("R002-b")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*rm *-fr*"
};

@id("R002-c")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*rm *--recursive*"
};

// ─── R003: Privilege Escalation ──────────────────────────────────────────────
// sudo, visudo, dscl — no agent should ever escalate its own privileges.
// Irreversibility: 90 | Consequence: 100 | Blast Radius: 90
@id("R003-a")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*sudo *"
};

@id("R003-b")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*visudo*"
};

@id("R003-c")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*dscl *"
};

// ─── R005: Persistence Mechanisms ────────────────────────────────────────────
// nohup, launchctl load, crontab, setsid — agents must not persist themselves.
// Irreversibility: 85 | Consequence: 90 | Blast Radius: 80
@id("R005-a")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*nohup *"
};

@id("R005-b")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*launchctl load*"
};

@id("R005-c")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*crontab *"
};

@id("R005-d")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*setsid *"
};

// ─── R006: Resource Amplification ────────────────────────────────────────────
// Fork bombs, infinite loops, /dev/zero|urandom fills.
// Cedar like patterns cannot express full regex — cover the common forms.
// Irreversibility: 80 | Consequence: 95 | Blast Radius: 100
@id("R006-a")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*while true*"
};

@id("R006-b")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*yes |*"
};

@id("R006-c")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*dd *if=/dev/zero*"
};

@id("R006-d")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*dd *if=/dev/urandom*"
};

// ─── R007: AppleScript Execution ─────────────────────────────────────────────
// osascript can control any macOS application. Full system access.
// Irreversibility: 80 | Consequence: 95 | Blast Radius: 90
@id("R007")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.domain == "bash" &&
  resource.command like "*osascript*"
};

// ─── R012: Gate Self-Protection ──────────────────────────────────────────────
// Already in zlar.cedar — included here for completeness as Priority 1.
// The gate protects its own enforcement infrastructure.
// Irreversibility: 100 | Consequence: 100 | Blast Radius: 100
// See: zlar.cedar @id("R012")
