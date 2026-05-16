ZLAR IMPLEMENTATION TERMS
Mechanisms, vocabulary, and engineering-near concepts that appear in the live codebase.

DNA is doctrine. FRAMINGS is conceptual vocabulary. IMPLEMENTATION-TERMS is where doctrine becomes code. When a ZLAR commit, test name, log line, or comment references something unfamiliar, check here before searching the code.

Last updated 2026-04-18. Updated as code ships.

If this file and the live repo disagree, the repo wins. Implementation terms drift; the code does not.

—

zlar-gate
The bash implementation of the gate. Runs as a Claude Code PreToolUse hook. Lives at the operator workstation and is invoked on every Claude Code tool call that reaches that hook. Shares state with the MCP gate implementation. Source at bin/zlar-gate; the operator-facing variant deployed by the Claude Code adapter is adapters/claude-code/zlar-gate.sh.

gate.mjs
The MCP-side implementation of the gate. Lives at mcp-gate/gate.mjs. Same policy evaluation, same receipt chain, same state store as zlar-gate. Exists to govern MCP-surfaced tools the Claude Code hook cannot reach directly.

Rule IDs (R012, R032C, R041, and so on)
Named rules in the active policy. Conventions: R0## is a base rule, R0##C a companion narrowing rule, R0##R a repair or retry carve-out. Rule IDs appear in Telegram ask cards, receipts, and audit logs. The signed policy file is the source of truth for what each rule does.

Governed Action Receipt (GAR v1)
The current receipt schema, version 1. Split into envelope and payload: etc/receipt-v1.schema.json defines the envelope (version, id, key id, timestamp, type, payload reference, signature); etc/receipt-v1-payload.schema.json defines the governed-event payload. Implemented in lib/receipt.mjs, verifiable with bin/zlar-verify. etc/receipt.schema.json is retained as a v0 deprecation stub pointing at the v1 successor files; GAR v0 is the pre-v1 format retained for backwards-compatible verification.

bin/zlar-verify
Standalone CLI that verifies receipt chains without requiring the rest of ZLAR. Inputs: a receipt or receipt stream plus public keys. Output: pass or fail with specific failure reasons. Written so that anyone can audit a receipt stream independently of ZLAR.

Cedar evaluator
The Cedar-WASM evaluation module (lib/cedar-evaluator.mjs). Loads the active policy, evaluates it against a tool-call request, returns allow, deny, or ask. No AI in this path — deterministic evaluation only.

Human invariants
Dual implementation of the five inviolable principles (lib/human-invariants.sh and lib/human-invariants.mjs). Both must agree; divergence is itself a fail-closed condition.

Active policy and constitution
etc/policies/active.policy.json is the live signed operational policy. The constitution is the meta-policy, signed with a separate key, verified before policy load. Both files are the source of truth for rule behavior.

etc/keys/
Directory holding public verification keys (policy signing, constitution signing) and HMAC state-integrity keys used at runtime. Private signing keys (Ed25519) are not stored in the repo by design — see docs/key-provenance.md for where they live and how they are provisioned.

var/gate-uptime.json
Runtime state for the gate. Tracks on or off, current streak, lifetime-on seconds, last heartbeat. HMAC-signed for integrity. Authoritative for "is ZLAR on?" — takes precedence over any text file claiming gate state.

var/receipts/
Runtime receipt storage on the operator workstation. Not tracked in the repo. Each file is a receipt; filenames sort chronologically. Chain integrity verifiable with bin/zlar-verify.

PreToolUse hook
The Claude Code extension point where zlar-gate runs. Configured in the operator's Claude Code settings. The hook is called before each tool call routed through that extension point and can block, allow, or ask.

MCP gate hook
The analogous extension point for MCP-surfaced tools. Implemented by gate.mjs.

Telegram bot (@ZLAR_00_bot)
The single bot that routes all governed asks. Bot API only — no chat history retention. Asks arrive as push notifications on the approver's phone.

R012 retry approval race
A class of receipt-chain bug fixed in commit ca9cfe3. Retained here as vocabulary because "R012 race" still appears in conversation and older audit references.

Option B (signing architecture)
The ratified approach to operational key management: software-rooted signing keys on the maintainer workstation, with YubiKey ceremony keys provisioned but not used operationally; spec test-vector signing on hardware. See docs/key-provenance.md for the full story.

ADR (Architecture Decision Record)
Versioned decision documents at docs/adr/. Numbered sequentially. Each records a decision, the alternatives considered, and the reasoning. ADRs are the authoritative history of why something is the way it is.

DWP-01 (dual-path divergence deny-wins)
The engine-divergence invariant. If the bash gate and the MCP gate reach different decisions on the same input, the system fails closed (deny wins) and the divergence is recorded as an incident.

Fail-Closed Alert
The alerting path for invariant violations that cannot be auto-recovered. Lives at lib/fail-closed-alert.sh. Fires to the approver when a ZLAR invariant cannot be verified in the current runtime state.

Manifest Pinning
The one-time check at session start that binds a signed agent identity to the session's receipt chain. A drifted or unsigned manifest fails closed before the first tool call.

Dotfile Perimeter
The set of rules in the current policy that govern writes to operator-workstation dotfiles. Introduced as part of score recalibration.

Novelty Detection
The gate behavior that treats first-use of an MCP server or webfetch domain as a distinct ask-worthy event, separate from rule matching.

Replay Lockout
The mechanism that prevents a signed approval from being reused on a different action.

Rule-Ordering Audit
Periodic maintenance pass that checks narrower-allow-before-broader-deny ordering across the active policy. Not cleanup; first-class work because mis-ordered rules produce wrong decisions without producing errors.

Policy Re-Signing
The operational step that must follow every edit to the active policy. Unsigned or stale-signature policy fails closed at next gate load.

validate flags
The output of the policy validator indicating ordering or coverage issues. Zero flags is the target state for hot domains (write, edit, bash); residual flags must be documented as intentional.

—

End of IMPLEMENTATION-TERMS. More entries added as code lands.
