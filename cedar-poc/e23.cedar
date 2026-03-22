// ZLAR E-23 Governance Policies — Cedar
//
// OSFI Guideline E-23 (Model Risk Management) compliance policies.
// Effective May 1, 2027. These policies implement the runtime enforcement
// layer that E-23 demands but no existing MRM platform provides.
//
// Vocabulary follows bank risk management conventions:
//   Position limits  → maximum exposure before escalation
//   Pre-trade checks → validation before irreversible execution
//   Kill switch      → immediate halt on anomaly detection
//   Escalation ladder → tiered approval authority by risk level
//
// Cedar is default-deny. Only `permit` grants access.
// `forbid` overrides permits (deny wins).


// ═══════════════════════════════════════════════════════════════════════════════
// KILL SWITCHES — Circuit breakers that override everything
// E-23 Principle 2.3: "contingency plans for model failure"
// ═══════════════════════════════════════════════════════════════════════════════

// KS-001: Production kill switch — deny all actions from any agent
// with 3+ denials in the current session (behavioral anomaly).
// Like a trading desk kill switch after repeated limit breaches.
@id("KS-001")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.session_deny_count >= 3
};

// KS-002: No autonomous action in production when confidence is low.
// E-23 3.6: "monitoring for autonomous decision making"
// CPP Investments five-gate: human review triggered below 70% confidence.
@id("KS-002")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  context.environment == "prod" &&
  context.confidence < 70
};


// ═══════════════════════════════════════════════════════════════════════════════
// POSITION LIMITS — Financial exposure boundaries
// E-23 Principle 2.3: "limits or constraints on usage"
// ═══════════════════════════════════════════════════════════════════════════════

// PL-001: Tier 1 (critical) agents cannot execute any financial action
// above $10,000 without human approval.
// Like a junior trader's position limit.
@id("PL-001")
forbid (
  principal is ZLAR::Agent,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  principal.risk_tier == 1 &&
  resource.amount > 1000000 &&
  resource.is_irreversible
};

// PL-002: No agent — regardless of tier — can execute above $100,000.
// Like a desk-level position limit that even senior traders can't breach.
@id("PL-002")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  resource.amount > 10000000 &&
  resource.is_irreversible
};

// PL-003: All irreversible financial actions require explicit counterparty.
// Prevents "hallucinated account number" risk (RTR payment governance).
@id("PL-003")
forbid (
  principal,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  resource.is_irreversible &&
  resource.amount > 0 &&
  resource.counterparty == ""
};


// ═══════════════════════════════════════════════════════════════════════════════
// PRE-EXECUTION CHECKS — Tier-based access control
// E-23 Principle 2.2: risk rating drives "intensity of review"
// E-23 Principle 3.6: "alternative controls for autonomous models"
// ═══════════════════════════════════════════════════════════════════════════════

// PEC-001: Tier 3 (standard) agents may execute non-irreversible actions
// with risk_score <= 50 in any environment. Lightest touch.
@id("PEC-001")
permit (
  principal is ZLAR::Agent,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  principal.risk_tier == 3 &&
  resource.risk_score <= 50 &&
  !resource.is_irreversible
};

// PEC-002: Tier 2 (elevated) agents may execute non-irreversible actions
// with risk_score <= 30. Tighter threshold than Tier 3.
@id("PEC-002")
permit (
  principal is ZLAR::Agent,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  principal.risk_tier == 2 &&
  resource.risk_score <= 30 &&
  !resource.is_irreversible
};

// PEC-003: Tier 1 (critical) agents may execute ONLY read-only actions
// with risk_score == 0. Everything else requires human approval.
// Like a new trader on probation — can look, can't touch.
@id("PEC-003")
permit (
  principal is ZLAR::Agent,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  principal.risk_tier == 1 &&
  resource.risk_score == 0 &&
  !resource.is_irreversible &&
  context.domain == "read"
};


// ═══════════════════════════════════════════════════════════════════════════════
// ENVIRONMENT CONTROLS — Staging vs. production boundaries
// E-23 Principle 3.4: validation and testing requirements
// ═══════════════════════════════════════════════════════════════════════════════

// EC-001: In dev/staging, allow broader access for testing.
// E-23 explicitly requires validation environments.
@id("EC-001")
permit (
  principal is ZLAR::Agent,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  (context.environment == "dev" || context.environment == "staging") &&
  resource.risk_score <= 70 &&
  !resource.is_irreversible
};


// ═══════════════════════════════════════════════════════════════════════════════
// THIRD-PARTY MODEL CONTROLS — Vendor-agnostic enforcement
// E-23 / B-10: third-party models "assessed on a standalone basis"
// ═══════════════════════════════════════════════════════════════════════════════

// TP-001: Third-party (unidentified) models are treated as Tier 1
// regardless of declared tier. Trust is earned, not declared.
// "OSFI rejected stakeholder requests for grace periods for third-party
// validation or exemptions for proprietary black-box models."
@id("TP-001")
forbid (
  principal is ZLAR::Agent,
  action == ZLAR::Action::"evaluate",
  resource
)
when {
  principal.model_id == "unknown" &&
  resource.risk_score > 0
};
