Human-Attention Canary
Roadmap note. Design, not yet shipped. Constitutional-adjacent. Implementation requires separate review.

Last updated 2026-04-24. Live roadmap doctrine.

Status: named, designed, constitutional-compliance verified, code not written. This roadmap note records current design intent; it does not authorize policy, constitution, or gate behavior changes. Any future Claude or maintainer reading this file should not treat it as permission to implement or as proof the canary already exists. Implementation is a separate session, a separate review, and a separate approval.

—

1. The problem

H15 enforces a minimum deliberation floor per severity (critical 30s, warn 10s, info 3s per constitution amendable layer). The floor is enforced by hard-rejecting too-fast approvals: the gate returns `too_fast` and the approval does not process.

A competent operator reading quickly can approve correctly in under the floor. H15 as implemented rejects that approval, forcing a stare-and-tap cycle. In a real session on 2026-04-24, a single policy-signing workflow produced a sequence of R012 asks; each required the operator to wait the full 30s floor before tapping, despite recognizing the card instantly. The operator's attention degraded over the sequence — the forced waits trained a wait-then-tap rhythm that is the precise failure mode H15 was meant to prevent.

The constitution itself names this failure mode. PC-02 reads: "Governance becomes theater when burden predictably destroys discrimination." The current H15 implementation, when paired with a high-frequency rule like R012, is an example of that burden.

—

2. The reframe

Governance value lives in DETECTION of rubber-stamping, not in PUNISHMENT of fast approvals. A forced wait does not prevent rubber-stamping; it trains the operator to rubber-stamp after waiting. A detection layer that interrupts only when a pattern is suspicious preserves competent operator behavior AND catches the drift.

Fast competent approvals are assets, not risks. Penalizing them is structurally wrong. The correct response to "operator approved in 2 seconds" is not "reject." It is "record the fact, feed it to the variance detector, surface an alert only if the pattern across decisions looks like drift."

—

3. Design elements

Five changes, mutually reinforcing. The immediate v1 behavior can ship without constitutional amendment if the current constitution is interpreted as threshold values rather than hard-reject semantics — which PC-02's text supports. New parameter bands for canary tuning (variance_stddev_floor, variance_window, tier_pause_duration) should be ratified into amendable_constraints at a later amendment ceremony so policy tuning is constrained by constitutional floors.

Element A — H15 semantic shift.
Current: `hi_check_deliberation` returns `too_fast` if elapsed < severity_floor; gate rejects approval.
New: tiered response.
- severity == critical → hard-reject below floor retained. PC-02's "time to deliberate" is most needed where consequences are gravest: signing ceremonies, constitutional changes, key operations. 30s floor stays.
- severity ∈ {warn, info} → below-floor is recorded as a signal, not cause for rejection. The approval processes. The below-floor fact is appended to H14's variance data.

Canary zone boundaries. For warn/info severities:
- `elapsed < H17_min` (< 2s): hard-reject retained. "Too fast to be human" is an authenticity failure, not a deliberation quality signal. H17 is not softened.
- `H17_min <= elapsed < H15_floor`: canary zone. Approval processes, below-floor fact feeds H14.
- `elapsed >= H15_floor`: normal path.

For critical severity, `elapsed < H15_floor` remains hard-reject regardless (no canary zone). PC-02 "time to deliberate" is enforced strictly at the highest consequence tier.

Element B — H14 response shift.
Current: variance stddev < 4s over 20 decisions triggers a lockout (`ok: false, reason: 'rubber_stamping'`).
New: variance trip triggers a canary alert, not a lockout. Approvals continue to process. The alert surfaces to the operator through the Telegram channel via escalation tiers (see Element E).
Variance detection itself is unchanged. The existing critical-decision exclusion stays — deliberate uniformity on critical ops is not a rubber-stamp signal.

Element C — R012 severity split by effect, not by command class.
R012 today classifies all matches as `severity: critical`. Split into three by effect:
- R012I — pure status queries (no state change, no sensitive read): `zlar-status`, `zlar doctor`. Severity: info (3s signal floor).
- R012R — read of policy/enforcement state (no effect, but sensitive content): `cat policy.json`, `jq .rules`, `zlar-policy inspect`, `zlar-policy verify`. Severity: warn (10s signal floor).
- R012W — effect-producing: write/edit/cp into gated paths, `zlar-policy sign`, `zlar-policy deploy`, `zlar-constitution deploy`, hook edits. Severity: critical (30s hard floor retained).

The split is by effect, not by operation. `bin/zlar-*` commands distribute across all three: `zlar-status` is info, `zlar-policy inspect` is warn, `zlar-policy sign` is critical. A command-class split would miss that `zlar-policy sign` and `zlar-policy inspect` have very different consequences.

Element D — Receipt audit fields v1.
GAR v1 payload gains five fields present from the day this ships. No v2 deferral for audit fields: replay analysts need full context immediately.
- h15_elapsed_seconds — actual response time.
- h15_floor_seconds — the floor that would have applied to this severity.
- h15_below_floor — boolean; true iff elapsed < floor (possible for warn/info, rejected for critical).
- h14_alert_tier — 0 = no alert, 1 = banner, 2 = pre-confirm, 3 = forced pause.
- h14_alert_ack_receipt_id — if a prior canary ack preceded this approval, the ack's receipt ID.

Element E — Telegram UX with progressive escalation.
Tier 1 (first canary trip in session): inline banner on the next ask card. Visually distinct (colored header, canary emoji, short explanatory text: "Pattern check: you've approved N of these in M minutes. Everything OK?"). Operator approves as usual; the banner is the signal.
Tier 2 (pattern persists after Tier 1): pre-confirm gate. The next ask requires an explicit acknowledge step before the main approval card processes. Options on the pre-confirm: Acknowledge and continue | Slow down mode | Pause session | Deny this action. No "stop asking this session" option until a signed operator-local override story exists — otherwise the attacker pressures the operator into muting the warning.
Tier 3 (pattern persists through Tier 2): forced pause. The next ask inserts a 15-second mandatory pause regardless of severity. A narrowly-scoped hard floor that only engages after two softer signals were dismissed.

Escalation resets when the variance pattern resolves (operator slows down organically).

—

4. PC-02 compliance argument

PC-02 (permanent core) requires the system to preserve conditions for real human judgment: meaningful veto, time to deliberate, enough context, enough spacing. Burden that predictably destroys discrimination makes governance theater.

Under the canary implementation:
- Meaningful veto: unaffected. Human can always deny.
- Time to deliberate: for critical operations, the 30s floor retains the constitution's intent. For warn/info, time is available — the human can take it. The canary fires when the human's pattern suggests they systematically aren't taking it. Time is preserved, not compelled.
- Enough context: ask card content unchanged.
- Enough spacing: H14 variance monitors for absence of spacing; the canary alert surfaces the signal.
- Anti-theater clause: directly addressed. Today's floor-on-every-ask pattern is the theater case. Canary reduces the noise burden, so the operator's discrimination is not predictably destroyed.

The enforcement clause for PC-02 (`check_human_authority_real`) is where this behavior lives. The implementation change strengthens PC-02 compliance — does not weaken it.

—

5. Attack scenarios game-theoried

Scenario: habituation to Tier 1 banners.
Operator sees the same banner repeatedly, starts dismissing reflexively.
Defense: Tier 2 escalation. A second banner in the same session while the pattern persists triggers a pre-confirm gate that cannot be dismissed reflexively. This is why v1 must ship Tiers 1 and 2 together — Tier 1 alone is the failure mode the design exists to prevent.

Scenario: alert-copy capture through ritual familiarity.
The canary alert text, if static, becomes ritual. Operator reads "Pattern check: N of these..." enough times that it parses as background noise, just like the forced wait before.
Defense: alert copy rotates from a small signed set of phrasings ("Pattern check" / "Heads up" / "Attention" / "Noticed something"). Visual form stays distinct (color, icon, position). Alert exposure counts are audited — if one phrasing is hit N times per authorizer without triggering slowdown, rotate. The set itself is signed so an attacker cannot insert sympathetic-sounding phrasings.

Scenario: timing variation to evade variance detector.
Attacker-agent paces asks with deliberate jitter — some fast, some slow — to keep stddev above 4s.
Defense: H14 variance stays as one of multiple signals. Complementary detectors — cluster density over a sliding window, cross-ask similarity — should land in later iterations. Single-signal evasion remains hard for agents that don't know the exact stddev threshold.

Scenario: Tier 3 forced pause inverted.
Operator is in a legitimate high-velocity session (build cycles, interactive debugging) and hits Tier 3. The forced pause is now the very burden we tried to remove.
Defense: Tier 3 only fires after Tiers 1 and 2 were dismissed without pattern resolution. If the operator is genuinely deliberating at high velocity, their pattern is visible to the variance detector as having legitimate structure (e.g., response times cluster by severity or action class, not uniform fast). Tier 3 should be rare. Parameters tunable per policy within constitutional safety band.

Scenario: pattern reset gaming.
Agent deliberately pauses for several minutes to "reset" the variance window, then resumes rapid-fire asks.
Defense: variance window is sliding (last 20 decisions), not time-windowed. A pause doesn't clear history. The 20-decision lookback carries the pattern across pauses.

Scenario: cross-authorizer dilution.
Multiple standing approvers rotate. Each individual's variance looks fine; aggregate is drift.
Defense: variance detection is per-authorizer-identity. Aggregate-level drift monitoring is a sibling invariant (potentially H16 in future work), not H14.

Scenario: policy tampering to weaken canary.
Attacker with policy-edit authority sets variance threshold to 0.1s, window to 1000, min-sample to 500 — effectively disabling canary.
Defense: constitutional minimums on canary parameters. Constitution specifies stddev_floor >= 2s, window <= 50, min_sample <= 20. Policy tuning within those bands. The gate refuses to load policy that violates the constitution (Second Authority Law machinery). This is a new set of constitutional amendable values — documented here, ratified at the next amendment ceremony.

—

6. Parameter tuning (initial values, all within proposed constitutional bands)

- H14 variance stddev floor: 4s (unchanged from current code).
- H14 variance window: 20 decisions (unchanged).
- H14 variance min-sample: 10 decisions (unchanged).
- Tier 1 banner threshold: variance trip triggers banner.
- Tier 2 pre-confirm threshold: second variance trip within same session while variance stays below floor.
- Tier 3 forced pause threshold: third consecutive trip after Tier 2 pre-confirm.
- Tier 3 pause duration: 15s.
- Escalation reset: when variance stddev climbs above 2 * floor (8s). This is a reset heuristic, not a claim that 8s represents "legitimate deliberation" — legitimate deliberation has varied structure across asks, not a particular number.

All parameters are policy-tunable within constitutional bands. Constitutional bands should ratify in next amendment ceremony.

—

7. Build order

v1 (ships as a coherent unit):
- Element A: H15 semantic shift (warn/info signal-only with canary-zone boundaries per H17).
- Element B: H14 response shift (lockout → canary alert).
- Element C: R012 effect-based split.
- Element D: receipt audit fields.
- Element E Tier 1 AND Tier 2: inline banner + pre-confirm gate. Shipping Tier 1 alone risks the exact banner-habituation failure mode the design exists to prevent. Tier 2 is the structural answer to banner fatigue; without it, v1 is incomplete.

v2:
- Element E Tier 3: forced pause.
- Escalation reset logic.
- Constitutional amendment ceremony to ratify canary parameter bands.

v3:
- Complementary detectors (cluster density, cross-ask similarity, alert-copy rotation audit).
- H16 aggregate-authorizer variance for standing-approver rotations.

—

8. Connection to other doctrine

DNA §4 Invariant Four (Human authority at the contact boundary): canary strengthens this. Rubber-stamping is the failure mode that dissolves invariant four in practice. Detection-based mitigation is more faithful to the invariant than punishment-based mitigation.

DNA §7 Policy-Routed Human Authority: the framing "sustained low-variance response times are a warning sign that the system may be rubber-stamping" already anticipates this work. This design formalizes the detection.

SCOPE.md: no scope impact. Internal gate-behavior refinement. Claim unchanged.

Recognized-duplicate (superseded draft, not shipped): abandoned. What was proposed there as "recognized-duplicate modality with reduced floor" is subsumed here: duplicates are one input to H14's variance detector, not a separate authorization path.

—

9. Open questions

- Telegram Tier 1 banner copy: the rotating signed set needs initial members. Short, non-alarming, actionable. Draft members: "Pattern check", "Heads up", "Attention", "Noticed something" — final wording TBD.
- Tier 2 pre-confirm options: confirmed as Acknowledge and continue | Slow down mode | Pause session | Deny this action. Remaining question: what does "Slow down mode" actually do operationally? Proposed: raises all floor values by 2x for the rest of the session.
- H14 lockout legacy callers: if any code path currently depends on H14 returning `ok: false, reason: 'rubber_stamping'`, it must be updated to handle the new canary semantics. Audit required before ship.
- Canary state storage: per-session, per-authorizer. Where does the tier counter live? Likely alongside existing human-state HMAC-sealed files. Schema addition.
- Interaction with suspend state (PC-04): suspended gate denies everything. Canary does not fire in suspended state because no approvals are processing. No interaction.

—

10. Status and implementation scope

Not shipped. Design complete at the level documented here. Implementation waits for a focused session with separate review. Code paths are known:
- lib/human-invariants.sh: hi_check_deliberation, hi_check_response_variance.
- lib/human-invariants.mjs: checkDeliberation, checkResponseVariance.
- bin/zlar-gate: response-check caller.
- Telegram ask-card renderer: bin/zlar-status or mcp-gate/gate.mjs.
- Receipt payload: etc/receipt-v1-payload.schema.json.
- active.policy.json: R012 split into R012I/R012R/R012W.

Connection to Phase F: R012 split requires a policy-signing ceremony. Can piggyback on the next focused session. Not blocked on hardware-key rotation; software-rooted signing suffices until rotation.

Constitutional amendment for canary parameter bands: v2 or later. The v1 implementation ships without amendment; amendment ratifies the already-live values into amendable_constraints so future policy tuning is constitutionally bounded.
