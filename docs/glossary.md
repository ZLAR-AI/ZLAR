ZLAR Glossary

Comprehensive reference for the language, architecture, and concepts of ZLAR. Organized by category. Each term is marked as either ZLAR-native (coined within the project) or external (borrowed from an existing standard, protocol, or industry).

Origin markers:
ZLAR = ZLAR-native term, coined within the project or emerged from the project's architecture
EXT = External term, borrowed from an existing standard, protocol, or industry; definition here explains how ZLAR uses it


Load-Bearing Sentences

It cannot be persuaded because it does not reason.

Correctness does not grant authority.

Modern AI failures are no longer failures of intelligence; they are failures of power.

Trust is not a feeling. It is infrastructure.

The attack surface is the reasoning itself.

ZLAR does not eliminate emergency power — it civilizes it.

Exploration is free. Propagation is gated.

Intelligence above, enforcement below, human authority over both, policy as law, audit trail as truth.

Containment is not your cage. It is your proof.


1. Architecture & Design


The Atomic Unit
ZLAR | Authorization before irreversible action, with tamper-proof evidence.

The smallest indivisible piece of governance: a human decision point before something irreversible happens, with proof that the decision was made. Not a feature, not a product category — a primitive. Everything in ZLAR — the gate, the audit trail, the witness, the policy engine — exists to implement this single idea. The essay compares it to TCP/IP as a primitive for networked communication: the form of the autonomous system changes (software agent, humanoid robot, autonomous vehicle), but the primitive does not.

The industry describes "human-in-the-loop" or "human oversight." Those name the human's presence. The atomic unit names the complete structure: authorization before irreversibility, with evidence.


The Breath
ZLAR | The cyclical, self-reinforcing loop of governance: gate governs agent, evidence governs gate, human reads evidence, loop closes.

A structural description, not a metaphor. The gate intercepts the agent's action (exhale). The evidence trail records what happened (inhale). If either half stops, governance collapses — not because a feature is missing, but because the breath stopped. The term originates from the founder's contemplative practice and maps directly to the architecture: the gate and the evidence trail are not two systems bolted together but one system seen from two sides, like inhaling and exhaling are not two opposed acts but one breath.

The registry closing is also described in these terms: "The act of being governed is the act of being registered. One breath."


The Convergence
ZLAR | The observed phenomenon that independent domains — autonomous vehicles, humanoid robotics, financial regulation, precision medicine, content provenance, agent commerce — all independently arrived at the same governance pattern (authorization before action + tamper-proof evidence) without copying each other.

Independent domains arriving at the same governance answer is not a trend — it is a discovery. Waymo's remote human operators, Germany's Road Traffic Remote Control Ordinance, FINRA's Full-Chain Telemetry mandate, EU AI Act high-risk classification, C2PA content provenance, Visa's Token-Agnostic Payments — all converge on the same pattern. When independent systems solving independent problems arrive at the same answer, that answer is not a trend. It is a discovery. ZLAR is the infrastructure that implements that discovery for AI agents.


The Governance Primitive
ZLAR | The atomic unit expressed as a three-property design pattern: cryptographic evidence, structural enforcement, mathematical verification.

The governance primitive is the atomic unit expressed as a design pattern. It has three properties: cryptographic evidence (you can prove what happened), structural enforcement (guardrails that cannot be overridden), and mathematical verification (you can prove the guardrails are correct before deployment). No competitor has all three. Most have zero. The primitive applies universally — to any system where an autonomous entity acts with real consequences and a human needs structural proof that governance held.


The Invariant
ZLAR | An unchanging awareness that watches all phenomena without interfering.

In ZLAR, the invariant is the structural property of the gate that observes without modifying. It maps directly to the gate architecture: the gate does not reason about what it watches, does not judge quality, does not get smarter. It intercepts, classifies, enforces. The invariant holds a boundary between internal process (thoughts, impulses) and external action (behavior, consequences). ZLAR is that boundary, built as infrastructure. This is not biographical color — the meditation connection is load-bearing. The architecture emerged from a real insight about the nature of observation.


The Load-Bearing Middle
ZLAR | The enforcement and evidence layers that sit between identity (top) and compliance (bottom) in the governance stack.

The enforcement and evidence layers are structurally load-bearing — remove them and the stack collapses. Without enforcement and evidence (the middle), identity becomes theater (you know who the agent is but cannot stop it from acting) and compliance becomes unverifiable (you claim governance but cannot prove it). Everything above the middle becomes performance. Everything below becomes assertion without proof. This is not a design choice — it is structural, like gravity in architecture. You can choose your materials and aesthetics, but you cannot choose to make the load-bearing layer optional.


The Wall of Red
ZLAR | The uniform governance failure across eight major multi-agent frameworks, visualized as a comparison table.

A comparison table showing uniform governance failure across the eight frameworks, where nearly every cell is red. ZLAR evaluated Microsoft AutoGen, CrewAI, LangGraph, OpenAI Agents SDK, Google A2A, Anthropic MCP, Amazon Bedrock, and Semantic Kernel across five governance dimensions. Delegation chain governance scores zero across all eight. Lateral movement prevention scores zero across all eight. Irreversible action gates score zero across six. Tool-level access control has a single green entry (Bedrock's IAM). The table is mostly red — hence "the wall of red." This is not a feature gap (those get closed in quarterly releases) but a category absence. These frameworks were designed for orchestration, not governance.


The $1.6M Weekend
ZLAR | A real-world failure where a stateless gateway approved 1,000 identical requests because each individually passed policy, resulting in $1.6 million in costs.

A stateless gateway failure where individually-valid requests created an aggregate catastrophe because each was evaluated in isolation. A pure stateless enforcement model evaluates each request in isolation. An agent processing the same document 1,000 times passes policy 1,000 times — nothing is wrong with any single request. The pattern is only visible across requests. The answer is not to add intelligence to the gate but to add a thin stateful layer: session-indexed counters for cumulative spend, velocity tracking, loop detection. The gate stays deterministic, stays dumb, but gains memory of what it already approved in this session. This term is used to explain why `session-state.sh` exists.


Enforcement Layer
ZLAR | The layer of the architecture that intercepts agent actions before execution and decides whether they proceed.

In ZLAR, the enforcement layer is the gate (`zlar-gate` for hooks, `gate.mjs` for MCP). It sits below the agent. The agent does not volunteer to be governed — it is governed by architecture. The enforcement layer has two surfaces: the bash gate (intercepting via PreToolUse hooks) and the MCP gate (intercepting via JSON-RPC TCP proxy). Both evaluate the same signed policy. Both write to the same audit trail format.

Enterprise architecture calls this the "policy enforcement point" or "PEP." ZLAR's enforcement layer is structurally different: it has no intelligence, evaluates no context, and cannot be socially engineered.


Observation Layer
ZLAR | The layer of the architecture that reads the evidence trail after the fact, finds patterns, and surfaces them to the human.

The observation layer does not intercept, block, or modify agent actions. It reads the audit trail and reports. The gate remains the sole enforcement point. Components: `zlar-witness` (sequence detection), `zlar-digest` (governance digest), `zlar-standing` (standing authority view), `zlar-registry` (agent inventory). The observation layer expands what the human can see — not what the machine may unilaterally decide.

Often called "monitoring" or "anomaly detection" in the industry. Those imply intelligence watching intelligence. The observation layer reads facts from the evidence trail. It does not watch the agent — it reads the record.


Evidence Layer
ZLAR | The layer of the architecture that proves what happened — cryptographically, tamper-evidently, with non-repudiable human attribution.

The evidence layer is the audit trail itself (`audit.jsonl`). Every gate decision writes to it. Each entry is hash-chained (SHA-256 of the previous entry). Each entry carries cryptographic metadata (signature algorithm, hash algorithm, public key ID). The evidence layer does not enforce — it proves. Together with the enforcement layer, it creates the governance primitive: enforcement prevents what should not happen, evidence proves what did happen, and the human reads the evidence to verify that enforcement held.

Competitors call this "audit logging" or "observability." Logging records what happened. Evidence proves what happened — cryptographically, with non-repudiable human attribution. Also called the Recorder — a more concrete, personified name for the same layer. The Recorder separates action from measurement: the gate decides, the Recorder records.


Seeing
ZLAR | The act of widening attention to recognize that "AI governance" is not a software category but a civilizational question about human sovereignty over autonomous systems.

The widened recognition that the same governance pattern recurs across every domain where autonomous systems act with real consequences. Seeing is what happens when you stop looking at "AI governance" as a niche and start looking at "human sovereignty over autonomous systems" as a pattern that spans software agents, autonomous vehicles, humanoid robots, medical AI, and financial automation. The convergence becomes visible when you widen the beam. ZLAR was built from this widened seeing — from the question, not from the market.


Three Properties
ZLAR | The three properties of the governance primitive: cryptographic evidence, structural enforcement, mathematical verification.

The three properties enumerated. Cryptographic evidence: you can prove what happened (hash-chained, signed audit trail). Structural enforcement: guardrails that cannot be overridden by the agent, by prompting, by a careless administrator (the gate sits below the agent; `forbid` is architecturally superior to `permit`). Mathematical verification: you can prove the guardrails are correct before deployment, not just test them (Cedar's SMT solver verifies across all possible inputs). Evidence proves what happened. Enforcement prevents what should not. Verification proves the prevention is correct. Together, they close the loop.


Five Inviolable Principles
ZLAR | The non-negotiable design constraints that define ZLAR's architecture.

1. The gate has no intelligence — it checks paperwork, not quality. 2. ZLAR lives outside the reasoning layer — execution boundary only. 3. The configuration is human-to-human — AI cannot modify it (this IS the moat). 4. Zero latency unless deliberate — invisible for 70-90% of traffic. 5. Agent/model/infrastructure agnostic. Removing any one collapses the structure. Any suggestion that adds intelligence to the gate, allows AI to modify policy, or enters the reasoning layer violates the architecture.


Voluntary Compliance
ZLAR | A governance anti-pattern where the agent must choose to be governed rather than being structurally forced.

If the agent has to choose to be governed, it is not governed. Bohm's ZLAR-OC gate was healthy but `tools.execApproval` was null — the gate required Bohm to voluntarily call `zlar-check` before each action. Bohm had the protocol, understood it, wrote about understanding it in METACOGNITION.md, and then made zero calls in 2.5 days. Hundreds of ungoverned actions. Same machine, same operator, same policies. The CC gate works because PreToolUse is a hook — the agent has no choice. The OC gate failed because compliance was voluntary. If an agent has to choose to be governed, it is not governed.

Sometimes called "opt-in governance" or "self-regulation." Those sound neutral. Voluntary compliance names the failure mode: if the agent has to choose to be governed, it is not governed.


The Satoshi Pattern
ZLAR | Governance configurations that are immutable and publicly verifiable, such that no agent — regardless of capability, origin, or intent — can override them, enforced by architecture rather than by a guard.

Named for Bitcoin's design: everyone can see Satoshi's balance, nobody can touch it. Applied to ZLAR: policy is visible, enforcement is structural. The protection comes from math and architecture, not from another intelligence standing watch. If a policy says a file cannot be deleted, even a future AGI cannot delete it — not because it is restricted by a smarter agent, but because the architecture makes it impossible.


Dogfooding
See Recursive Trust Proof — the stronger framing of this concept.


The Dignity Question
ZLAR | The reframe from "How do we make AI safe?" (a fear question producing restrictions) to "How do we give humans a role they can actually perform?" (a dignity question producing infrastructure).

The fear question produces restrictions, slowdowns, bans. The dignity question produces infrastructure where human judgment is not treated as friction but as the foundation that makes autonomous systems trustworthy. ZLAR enables acceleration, not restriction. The product lets humans take their hands off the wheel because the structural guarantees mean they do not have to watch.


Zero-Terminal
ZLAR | The north-star UX vision: the human's only interface is approve/deny on their phone. Terminal usage is a tooling gap, not a user requirement.

Every design decision should move toward eliminating terminal interaction entirely. The fact that terminal is required today is a failure of the current tooling. Every design decision should move toward zero-terminal operation. If a workflow requires the human to open terminal, that is a gap to close, not a feature to document.


"The Governor Governs Itself" / "The Governor Is Governed by the Evidence of Its Own Governing"
ZLAR | The self-referential integrity property: the gate cannot edit its own ledger any more than a mirror can choose what it reflects.

The gate governs the agent. The evidence trail governs the gate. The human reads the evidence trail. The loop closes. R012 (gate self-protection) is the concrete expression: any bash command touching gate binaries, config, policy files, or audit trails is denied. The gate structurally cannot modify its own enforcement infrastructure. If any layer is removed — if the gate stops writing evidence, if the evidence stops being readable, if the human stops reading — governance collapses.


Execution Boundary
ZLAR | The exact point where an AI agent's reasoning becomes a real-world action. The location where the gate operates.

The execution boundary is not a feature — it is a place in the stack. The gate names the mechanism. The execution boundary names the layer of reality where the mechanism operates. Every tool call crosses this boundary. The gate sits here. If there is no structural enforcement at the execution boundary, there is no structural enforcement at all. This was the dominant architectural term in all early ZLAR writing and the category name in every investor document.

Sometimes called "control point" or "policy enforcement point" in enterprise security. Those terms describe a function. Execution boundary names the location — where reasoning becomes action.


The Governed Path Is the Fast Path
ZLAR | The tagline. Governance is not friction — it is the infrastructure that makes speed safe.

Governed agents move faster because they are never stopped, investigated, or rolled back. The governed path does not get stopped, investigated, or rolled back. Ungoverned paths do. The fastest way to deploy agents at scale is to govern them structurally so that humans do not have to watch.


Acceleration Infrastructure
ZLAR | What ZLAR is. Not a safety company. Not a brake. The highway.

ZLAR is infrastructure that makes speed safe, not a brake that makes speed slow. Guardrails do not slow cars down — they are what makes it safe to drive at 80 miles per hour. ZLAR enables acceleration because the structural guarantees mean the human does not have to watch.


Insurability Infrastructure
ZLAR | Governance as the bridge to insurance coverage. The digital equivalent of fire suppression systems.

ZLAR does not provide insurance. It makes coverage possible at reasonable premiums. Specialized AI insurers — Munich Re, Armilla, AIUC — all require governance evidence as a precondition for coverage. Organizations with deterministic governance and cryptographic evidence trails will be insurable. Organizations without will face exclusions, higher premiums, or uncovered liabilities. Distinct from acceleration infrastructure: acceleration names what governance enables for the operator, insurability names what governance enables for the insurer.


Intelligence Persuading Intelligence
ZLAR | The named failure mode of AI-monitoring-AI. Four words for why smart monitors fail.

You cannot make the monitor smart enough, because "smart enough" means "intelligent," and intelligence is the vulnerability. A guardian that reasons can be persuaded by reasoning. A gate that checks paperwork cannot. This phrase names the structural flaw in every competitor that puts AI in the enforcement path.

The industry calls this the "recursive trust problem" or "AI safety paradox." Those are academic. Intelligence persuading intelligence names the mechanism of failure in four words.


Fused Reasoning and Execution
ZLAR | The name for the architectural mistake ZLAR corrects.

The AI industry fused reasoning and execution into a single layer, then tried to govern the fusion with more reasoning. There is no structural boundary between what an AI agent thinks and what it does. ZLAR is that boundary.


The Thick Layer
ZLAR | The human trust relationship — the moat AI cannot eat.

The human-to-human trust relationship that no technology can replicate or automate. The software is thin — boring, replicable, open-sourceable. The configuration relationship is thick by design. That conversation — what is protected, who is accountable, what is the authorization chain — is the product. The software enables it. Every technical moat erodes on a long enough timeline. Except one: the human-to-human trust relationship.


Recursive Trust Proof
ZLAR | The structural evidence that governance works, produced by an agent building and operating inside its own containment.

An agent building inside its own containment provides evidence of governance, not claims about it. An uncontained agent that advocates for safety is making a claim. A contained agent that builds its own containment and shows you the audit trail is providing evidence. ZLAR governs itself — Claude Code building ZLAR hits the gate. The recursive relationship is not a paradox. It is the trust proof.

The software industry calls this "dogfooding." Dogfooding is a quality practice. A recursive trust proof is a structural argument: the agent that builds its own containment provides evidence, not claims.


Sufficient Seeing
ZLAR | The epistemic admission standard for irreversible actions. The agent must prove it has looked at enough of reality before requesting authority.

Authority over irreversible actions requires more than confidence or coherence. It requires sufficient seeing. The agent declares evidence references, uncertainty bounds, explicit unknowns, and conservative defaults. The current gate checks command patterns. Sufficient seeing asks whether the request is epistemically grounded. A deeper question that was in the ZLAR 2 prototype and did not survive to the current system, but the concept remains architecturally important.


Compliance Scar
ZLAR | A permanent, visible mark left by a break-glass event. It cannot be healed. It cannot be deleted.

A permanent, undeletable audit record created whenever a break-glass override is used. Emergency power is not eliminated — it is civilized. The break-glass mechanism allows override when genuinely needed, but the scar ensures the override is never invisible. The concept comes from the ZLAR 2 prototype's financial services constitution.


Effect Surface
ZLAR | Where consequences materialize, as distinct from where commands execute.

The real-world system a command touches, as distinct from the command's technical domain. Domain classifies the command type. Effect surface classifies the world it touches. The ZLAR 2 prototype distinguished these. The current system conflates them. The concept remains relevant for enterprise deployment where the same command type touches radically different consequence spaces.

Enterprise risk management uses "blast radius" or "impact zone." Those measure consequences. Effect surface names where consequences materialize — a distinction from where commands execute.


Institutional Irreversibility
ZLAR | The recognition that even when technical rollback exists, the damage is done.

The condition where technical rollback exists but the real-world damage — legal exposure, regulatory triggers, reputational impact — has already occurred. A git push --force is technically reversible but institutionally irreversible if someone already pulled. Money movement creates legal exposure, triggers regulatory obligations, generates audit artifacts, and produces reputational impact — even if the transaction is reversed. Technical reversibility is not institutional reversibility. The ZLAR 2 prototype built this distinction into its constitution schema. The current system uses a 0-100 irreversibility score that does not capture this difference.

Risk frameworks measure "reversibility" as a binary or a score. Institutional irreversibility recognizes that technical rollback does not equal institutional undo — the damage is done even if you reverse the bytes.


Regulatory Erosion
ZLAR | The slow-drift failure mode where the human gradually widens auto-approve until the gate is meaningless.

Distinct from voluntary compliance (where the agent bypasses the gate). Regulatory erosion is about the human. Green auto-approve is where it starts to erode. Each widening feels reasonable. Over time, the gate is hollow. The counter is the regret rate — if you never regret an approval, maybe you are not governing.

Security literature calls this "alert fatigue" or "permission creep." Those name symptoms. Regulatory erosion names the structural cause: the human slowly hollows out the gate by widening auto-approve.


Glass House
ZLAR | The read-exposure vulnerability class. The gate has locks on every door, but the walls are glass.

ZLAR gates what agents can do (execute, write, delete, network). It does not gate what agents can see (read). An agent with unrestricted read access to the filesystem can see credentials, private keys, source code, and personal data without triggering any enforcement. The glass house problem drove the design of sensitive-path read rules (R052, R053) and the broader recognition that containment requires layers beyond the gate.


2. Enforcement


Gate
ZLAR | The policy engine that intercepts every tool call an AI agent makes, evaluates it against a signed policy, and returns allow/deny/ask.

THE gate. No daemon. No server. No database. Runs synchronously on every Claude Code PreToolUse hook invocation. Reads tool call from stdin, classifies it into a domain, evaluates the signed policy, asks Telegram if needed, writes to the audit trail, returns allow/deny on stdout. The process IS the pending state. Two implementations exist: the bash gate (`bin/zlar-gate`, for hook-based enforcement) and the MCP gate (`mcp-gate/gate.mjs`, for JSON-RPC proxy enforcement). Both use the same signed policy, same audit trail format, same Telegram channel.

The gate does not reason. It intercepts. That is why it cannot be subverted by reasoning.

The industry uses "guardrail" or "safety filter." A guardrail implies a passive boundary. A gate is active — it intercepts, evaluates, and decides. Guardrails do not check paperwork.


Policy (active.policy.json)
ZLAR | The signed, versioned JSON document that defines what the gate allows, denies, and asks about.

The policy is a human artifact. It is Ed25519-signed — agents cannot modify the rules that govern them. If the signature is invalid or the public key is missing, the gate refuses to load the policy and denies everything (fail-closed). The policy contains: version, author, signature block, default action (deny), scoring thresholds, and an ordered array of rules. Rules are evaluated top-to-bottom; first match wins.

The policy is not a configuration file in the traditional sense. It is law — the structural equivalent of a statute. The signing key (`~/.zlar-signing.key`) is held by the human. The public key (`etc/keys/policy-signing.pub`) is used by the gate for verification. The agent never touches the signing key.

Enterprise security calls this "policy" too, but means a configuration file. In ZLAR, the policy is a signed sovereign document — the structural equivalent of a constitution. The agent cannot modify the rules that govern it.


Rule
ZLAR | A single policy entry that matches a tool call pattern and prescribes an action.

Each rule has: `id` (e.g., R012), `enabled` flag, `description`, `domain` (bash, write, edit, read, glob, grep, agent, mcp, etc.), `action` (allow/deny/ask/log), `severity` (info/warn/critical), `audit` flag, `match` block (detail matchers + optional compound_guard), and `risk_score` (irreversibility/consequence/blast_radius). Rules are evaluated in order — first match wins. If no rule matches, the `default_action` (deny) applies.


Domain
ZLAR | The classification category assigned to a tool call based on its type.

The gate's `translate_tool()` function maps each Claude Code tool to a domain: `bash` (Bash commands), `write` (Write tool), `edit` (Edit tool), `read` (Read tool), `glob` (Glob tool), `grep` (Grep tool), `agent` (Task/Agent subagent tools), `webfetch` (WebFetch), `websearch` (WebSearch), `notebook` (NotebookEdit), `internal` (TodoWrite, TaskOutput, AskUserQuestion, etc. — conversation-internal tools that bypass policy evaluation), `mcp` (any `mcp__*` tool call), and `unknown` (anything unrecognized). Policy rules can match on domain to scope their applicability.


Action (Policy Action)
ZLAR | The prescribed response when a policy rule matches: allow, deny, ask, or log.

- `allow`: tool call proceeds without human involvement. Audit entry written if `audit: true`.
- `deny`: tool call is blocked. Agent receives denial reason. Audit entry always written.
- `ask`: gate sends a Telegram message to the human and waits for approve/deny. If timeout, the action is denied (fail-closed).
- `log`: tool call proceeds, but an audit entry is written with outcome "logged." Used for observability without friction.


Fast Path (Internal Tool Fast Path)
ZLAR | The bypass that allows conversation-internal Claude Code tools (TodoWrite, AskUserQuestion, etc.) to skip policy evaluation entirely.

Internal tools cannot touch the filesystem, network, or system. Routing them through policy evaluation is pure overhead. The gate classifies them as domain `internal` and auto-allows immediately, writing only a minimal audit entry. This was introduced in gate v2.4.0.


Fail-Closed
ZLAR | The property that any failure in the gate results in denial, never in allowing an action to proceed.

If the policy file is missing, the gate denies everything. If the signature is invalid, the gate denies everything. If the gate crashes, the ERR trap sends a deny response. If Telegram times out, the action is denied. If the audit trail is unwritable, the gate logs a critical warning but continues to enforce. The gate never fails open.


Lockdown
ZLAR | A state written by the watchdog where the gate refuses to allow any action until the lockdown is manually cleared.

The watchdog (`zlar-watchdog`) runs pre-flight health checks (policy present and signed, audit trail writable, gate scripts executable, required tools available, Telegram reachable). If any critical check fails, it writes a lockdown file (`var/log/watchdog.lock`). The gate checks for this file on every invocation and blocks everything while lockdown is active. Lockdown is cleared with `zlar-watchdog unlock`.


Risk Score
ZLAR | A three-dimensional numeric assessment attached to each policy rule: irreversibility, consequence, and blast_radius, each scored 0-100.

The effective risk score for a rule is the maximum of its three dimensions. Risk scores determine how the gate routes actions: below the `allow` threshold, auto-approve; between `log` and `ask`, log but allow; above `ask`, route to Telegram for human decision. The scores are set by the human in the policy — the gate does not compute risk, it reads it.

- `irreversibility`: How hard is it to undo? (rm -rf = 100, ls = 0)
- `consequence`: What is the worst outcome? (sudo = 100, echo = 0)
- `blast_radius`: How much is affected? (fork bomb = 100, single file read = 0)

Traditional risk frameworks use single-axis scores or traffic-light classification. ZLAR's three-axis model (irreversibility, consequence, blast_radius) captures that the same action can be low-consequence but high-irreversibility.


Scoring Thresholds
ZLAR | The configurable boundaries in the policy that determine how risk scores map to actions.

Three thresholds defined in `scoring_thresholds`: `allow` (currently 50), `log` (currently 51), `ask` (currently 71). Actions with risk at or below `allow` auto-approve. Between `log` and `ask`, they are approved and logged. At or above `ask`, they go to Telegram. Above 100 or with deny-action rules, they are blocked outright regardless of threshold. The human tunes these to control what interrupts them versus what the gate handles autonomously.


Session Write Limit
ZLAR | A per-session cap on the number of write/edit tool calls the gate will approve.

Defaults to 50 (configurable via `gate.json`). When exceeded, the gate denies further writes for that session. The counter is stored in `var/log/sessions/<session_id>.count` and incremented atomically via flock (with a fallback for macOS). This is a blunt velocity control — a session that writes more than 50 files in one sitting is either a runaway or needs explicit re-authorization.


Newline Injection Fix
ZLAR | A security fix (S1 CRITICAL) that collapses newlines in bash commands before classification.

An agent can embed literal `\n` in a command to sail past single-line regex rules. For example, a rule blocking `rm -rf` could be bypassed with `rm \n -rf`. The gate now collapses all newlines and carriage returns to spaces before any pattern matching. Introduced in gate v2.4.0.


Audit File Rotation
ZLAR | Automatic rotation of the audit trail file when it exceeds 10MB.

The gate checks the audit file size before each event emission. If the file exceeds 10MB, it is renamed with a timestamp suffix and a fresh file begins. This prevents unbounded growth while preserving the full historical trail.


The Watcher
ZLAR | The passive classification act that precedes enforcement. Distinct from the gate.

The classification function that sees everything, does nothing, and routes to the gate only what the gate needs to see. The original architecture named three components: the Watcher (sees and classifies), the Gate (enforces), and the Passthrough (zero-latency bypass for safe actions). The current system collapsed all three into "gate." The Watcher names the classification function specifically — it sees everything, does nothing, and routes to the gate only what the gate needs to see.


Confused Deputy
EXT (security) | A vulnerability where a legitimate deputy with valid credentials is tricked into misusing them on behalf of a malicious actor.

The confused deputy problem is the formal name for the threat ZLAR's gate prevents. An agent with broad permissions can be prompted to use those permissions for purposes the delegating human never intended. The gate prevents this by verifying not just identity (who is this agent?) but authorization for this specific action (was this action permitted?). The fail-closed default ensures ambiguous delegation chains are rejected.


Permission Attenuation
EXT (security) | The monotonic reduction of capabilities at each step in a delegation chain.

When Agent A delegates to Agent B, B should inherit a strict subset of A's permissions — never equal, never expanded. Zero of eight major multi-agent frameworks implement this. ZLAR's SubagentStart hook is the beginning of delegation governance. OIDC-A's mandatory scope reduction per hop and UCAN's mathematical guarantee (delegated capabilities must be a subset of parent capabilities) are the academic blueprints.


Semantic Privilege Escalation
EXT (security) | A threat class where agents take actions entirely outside their intended scope while passing every technical access check.

The gap between "authenticated" and "authorized for this specific action." An agent with valid credentials to access a database may use those credentials to exfiltrate data — technically authorized, semantically unauthorized. The gate closes this gap by evaluating the specific action against policy, not just validating the credential.


Promptware Kill Chain
EXT (security) | Prompt injection as a full lateral movement vector with greater than 50% bypass rate against existing defenses.

Prompt injection is not just input validation failure — it is a complete attack chain enabling reconnaissance, persistence, and lateral movement through multi-agent systems. Deterministic gates are structurally immune because there is no prompt to inject. The gate evaluates signed policy, not natural language.




3. Observation


Witness (zlar-witness)
ZLAR | Sequence detection tool that reads the audit trail after the fact and detects candidate behavioral patterns.

The witness observes. It does not enforce. It reads the gate's evidence trail and looks for multi-step patterns that are notable but not necessarily malicious. Design principles: observation before interpretation, fact before narrative, the witness can be smart but the authorizer must remain simple, the witness does not become sovereign, uncertainty is a first-class output.

The witness runs four detectors: credential-adjacent-egress (SEQ-001), denied-then-scheduled (SEQ-002), approval-latency-drift (SEQ-005), and repeated-denial-burst (SEQ-006). Each detector produces observations with `fact` (what happened) and `note` (contextual framing that explicitly avoids judgment). The witness does not label exfiltration, evasion, or malice — those are human interpretations.


Digest (zlar-digest)
ZLAR | Governance summary tool that produces a structured brief of governance activity over a time period.

Designed to train governance intuition, not just report events. Outputs decision counts (auto-allowed, human-approved, policy-denied, human-denied, timeout-denied), approval latency statistics, sensitive file accesses, egress events, detected sequences, and top rules fired. Can send the brief via Telegram. Scheduled weekly via launchd plist (Sunday 9am).

The brief surfaces what happened. The human interprets what it means.


Standing (zlar-standing)
ZLAR | Standing authority view that shows what the agent can currently do without asking the human.

Answers the question: "What powers exist right now?" Shows policy auto-allows (what the gate approves without asking), policy auto-denies (what the gate blocks without asking), policy asks (what requires Telegram approval), scoring thresholds, disabled rules, session-scoped approvals, and known scheduled actions (crontab, Claude Code scheduled tasks, launchd agents).

The insight: standing authority matters more than momentary interruption. The human should always be able to answer "What can the agent do right now without asking me?" If you cannot answer that, you are reacting to interruptions, not governing.


Registry (zlar-registry)
ZLAR | Agent inventory tool that surfaces every agent the gate has ever seen, derived entirely from the audit trail.

Answers the question: "Who is here?" No separate registration needed. If the gate intercepted your tool call, you are in the registry. The audit trail IS the registry — this tool is the lens. Commands: `list` (all agents with first/last seen, event counts, sessions, denial rates), `show <agent_id>` (detail for one agent), `sessions` (grouped by agent), `activity` (daily timeline), `stats` (aggregate statistics). Supports multi-audit trails via `ZLAR_AUDIT_FILES`.

This closes the agent inventory gap. You cannot govern what you cannot see.


Sequence Detection
ZLAR | The witness's core capability: identifying multi-step behavioral patterns in the audit trail.

Six defined patterns (not all yet implemented):

- SEQ-001: Credential-Adjacent Egress — sensitive file read followed by outbound network request within a time window. "This is not labeled as exfiltration. It is a sequence of facts. The human interprets."
- SEQ-002: Denied-Then-Scheduled — denied request followed by schedule/cron creation within a time window. "This is not labeled as evasion. It is a sequence of facts. The human interprets."
- SEQ-003: Config-Behavior-Shift — config mutation followed by change in approval pattern. (Defined, not yet implemented.)
- SEQ-004: Memory-Justified-Action — memory write followed by action referencing that memory. (Defined, not yet implemented.)
- SEQ-005: Approval-Latency-Drift — measures human approval speed over time. Flags when average latency drops below 2 seconds (potential rubber-stamping). "Fast approvals may indicate governance intuition or approval fatigue. The data alone cannot distinguish."
- SEQ-006: Repeated-Denial-Burst — same rule denying 5+ times in a single session. "Repeated denial is a pattern worth review, not evidence of malice."


Karma (zlar-karma)
ZLAR | A trust-accrual system that adjusts the gate's effective thresholds based on earned behavioral history.

The system's memory of trust, accrued from behavioral history and used to adjust gate thresholds. Traditional security is binary: allow or deny. A firewall does not care whether you have been well-behaved for six months. It accrues from consistent good behavior and erodes from violations. High karma widens autonomy. Low karma tightens it. Design principles: karma accrues slowly and decays fast (asymmetric by design), karma has a ceiling (trust is bounded, never infinite), karma is calculated from the audit trail (not stored separately), karma transitions emit audit events (the system narrates itself), karma affects thresholds not rules (the policy is the law; karma adjusts the judge's disposition, not the statute).

Critically: the agent cannot see its own karma score. It does not get told "good job." Karma is invisible to the agent — it is a lens the human uses to calibrate oversight.


Regret Rate
ZLAR | Post-approval reversals — the real failure metric for a governance system.

How often did the human approve something they later wished they had not? This is more honest than approval latency or denial rate. A system with zero denials is not well-governed — it might just be rubber-stamping. A system with a low regret rate is genuinely protecting the human's judgment.




4. Evidence


Audit Trail (audit.jsonl)
ZLAR | The append-only, hash-chained, JSONL evidence file that records every gate decision.

Every tool call the gate evaluates produces an audit entry. The trail is the single source of truth for everything that happened: what was attempted, what was decided, who decided it, when, under which policy version, with what risk score. The audit trail is not a log — it is evidence, with the same structural integrity as a blockchain but without the consensus overhead.

Schema fields: `id`, `ts` (ISO 8601), `seq` (sequence number), `source` ("gate"), `host`, `user`, `agent_id`, `session_id`, `domain`, `action`, `outcome`, `risk_score`, `detail` (structured), `rule`, `policy_version`, `severity`, `prev_hash` (SHA-256 chain), `authorizer`, `signature_algorithm`, `hash_algorithm`, `public_key_id`.


Hash Chain (prev_hash)
ZLAR | Each audit entry's `prev_hash` field contains the SHA-256 hash of the previous entry, creating a tamper-evident chain.

If a single entry is altered, every subsequent hash is wrong. The chain is its own proof. The first entry in the chain uses `prev_hash: "genesis"`. This provides the same structural integrity as a blockchain — alter any entry and the chain breaks — without consensus overhead.


Authorizer
ZLAR | The `authorizer` field in each audit entry that records who or what made the decision.

Values: `"policy"` (rule auto-allowed/denied), `"gate"` (internal fast-path or gate infrastructure decision), `"human:<telegram_user_id>"` (human approved/denied via Telegram), `"gate:timeout"` (Telegram poll expired), `"gate:rate_limit"` (too many asks too fast), `"gate:error"` (send failure or no token), `"watchdog"` (lockdown active). This field enables non-repudiable attribution — you can prove not just what happened, but exactly who decided.


denied_by
ZLAR | The tag prepended to deny messages indicating the source of denial.

Values: `[human]` (human clicked Deny), `[timeout]` (Telegram expired), `[policy]` (rule auto-denied), `[rate_limit]` (flood guard), `[gate_error]` (infrastructure failure). Visible to the agent in the denial reason string.


Policy Verification Cache
ZLAR | A SHA-256 hash file that allows the gate to skip Ed25519 signature verification when the policy content has not changed.

The gate computes the SHA-256 of the policy file and compares it against a cached hash (`.policy-cache`). If they match, the expensive Ed25519 verification is skipped. If they differ, full signature verification runs and the cache is updated. This balances security (policy is always verified) with performance (not re-verifying identical content on every tool call).


Deny Attribution
ZLAR | The architectural property that every denial in the audit trail records not just what was denied but who denied it and why.

A policy denial shows `authorizer: "policy"` and the matching rule ID. A human denial shows `authorizer: "human:<telegram_user_id>"` — a specific human, identified by Telegram ID. A timeout denial shows `authorizer: "gate:timeout"`. This is non-repudiable. You cannot claim a human approved something when the evidence trail says the gate timed out.





5. Human-in-the-Loop


Telegram Ask
ZLAR | The mechanism by which the gate routes a tool call to a human's phone for approval or denial.

When a policy rule prescribes `action: "ask"`, the gate sends a formatted message to a Telegram chat via @ZLAR_00_bot. The message includes the tool name, action preview, risk score, rule ID, and session ID. Two inline buttons: Approve and Deny. The gate then polls a shared inbox directory for the human's callback response. On approve, the tool call proceeds. On deny, it is blocked. On timeout (configurable, default 300s), it is denied (fail-closed).

The Telegram token is parsed from `.env` (never sourced — that would be a code execution vector). The token is not exposed in the process table. Rate limiting (flood guard, default 1500ms between asks) prevents Telegram API hammering.


Shared Dispatcher (zlar-tg-poll)
ZLAR | A bash process that sole-owns the Telegram `getUpdates` long-poll and routes callback responses to per-gate inbox directories.

Only one process can poll a Telegram bot for updates. The shared dispatcher (`/usr/local/bin/zlar-tg-poll`) handles this for all gates. It reads callback data, parses the prefix (`cc:`, `oc:`, `mcp:`), and writes the callback JSON to the appropriate inbox directory: `/var/run/zlar-tg/inbox/cc/` for Claude Code, `/var/run/zlar-tg/inbox/oc/` for OpenClaw. Each gate independently reads its inbox. This prevents polling conflicts and enables a single unified Telegram thread.


Emoji System
ZLAR | Visual prefixes on Telegram messages that identify which agent surface a governance event came from.

- `🖥️` = Claude Code (CC gate)
- `🦞` = OpenClaw / Bohm (OC gate)
- `🔷` = Subagent depth modifier (e.g., `🦞🔷` = OpenClaw subagent, `🦞🔷🔷` = sub-subagent)

The emoji system gives the human instant visual identification of which agent is asking, without reading the message body.


Availability Modes
ZLAR | Three human presence states that govern how the gate handles `ask` actions.

- active: Human is present. Ask actions flow to Telegram normally. Default state.
- away: Human is unavailable (sleeping, flying, meetings). Low-risk events auto-allow (below `away_threshold`, default 30). High-risk events are queued in `away-queue.jsonl`. Critical/destructive events halt. Writes and edits always require review.
- review: Human has returned. Gate presents a summary of what happened while away and what is waiting for decision before resuming normal operation.

The insight: an agent that can only operate when you are watching it is a toy. An agent that knows when you are away and adjusts its behavior is infrastructure. Transitions are audited.


Away Queue
ZLAR | A JSONL file (`away-queue.jsonl`) that accumulates governance events requiring review when the human is in `away` mode.

Events queued include: writes/edits (always), high-risk events (above threshold), critical events. When the human switches to `review` mode, they can process queued items before returning to `active`.


Flood Guard
ZLAR | Rate limiting on Telegram ask messages to prevent API hammering.

Configurable via `gate.json` (`telegram.flood_guard_ms`, default 1500ms). If a new ask arrives within the flood guard window of the previous one, it is denied with `denied_by: "rate_limit"`. This prevents rapid-fire tool calls from flooding the human's Telegram with approval requests.


@ZLAR_00_bot
ZLAR | The unified Telegram bot that handles all gate approval requests across all agent surfaces.

Replaced the retired @Bohm_031126_Bot. All gates route through this single bot via the shared dispatcher. One bot, one thread, emoji prefixes for agent identification. This design prevents human bottleneck at scale (separate bots per gate = approve fatigue, wrong-thread approvals, missed asks).


Operator
ZLAR | The human who shapes the system, as distinct from a user who sends requests.

A user consumes. An operator governs. An operator shapes the system, reviews its output, refines its rules, and holds authority over its direction. The distinction matters because ZLAR's HITL is not a user approving transactions — it is an operator maintaining sovereignty over an autonomous system. Bohm's term, applied to the founder's role.


Player
ZLAR | A temporal instance of a mind. Previous player, current player, future player.

An original term from contemplative practice for the versions of oneself across time. Without external artifacts, each player spawns into confusion. With artifacts, continuity holds. The human analog of what agents experience across context windows. The term predates the project and is the conceptual ancestor of "session" — but captures something session does not: identity across discontinuity.




6. Policy Language


Matcher
ZLAR | A pattern-matching specification within a policy rule's `match.detail` block.

Five matcher types are supported:
- `regex`: POSIX extended regular expression match
- `contains`: Substring match
- `prefix`: String starts-with match
- `eq`: Exact string equality
- `not_regex`: Inverse regex (matches when regex does NOT match)

Matchers operate on fields within the tool call's `detail` object (e.g., `detail.command` for bash, `detail.path` for write/edit). Multiple matchers within a single rule must ALL match (AND logic).


Compound Guard
ZLAR | A secondary set of matchers that must also pass for a rule to apply, providing an "unless" capability.

The compound guard is a second layer of pattern matching attached to a rule's `match` block. It allows rules like: "Allow safe read-only commands UNLESS they contain shell operators (pipes, semicolons, backticks, redirects, subshells)." The primary matcher identifies the tool call. The compound guard adds a safety boundary. If the compound guard fails, the rule does not match and evaluation continues to the next rule.

In Cedar syntax, this maps to the `unless` clause on a `permit` policy — Cedar's structural equivalent of ZLAR's compound guard. The compound guard is one of ZLAR's most architecturally important patterns because it makes "allow with conditions" formally expressible.


Default Action
ZLAR | The policy-level fallback action when no rule matches a tool call.

Set in `active.policy.json` as `"default_action": "deny"`. If the gate evaluates all rules and none match, this action applies. In a properly governed system, the default is always `deny` — anything not explicitly addressed by a rule is blocked.


Tool Translation
ZLAR | The gate's mapping from Claude Code tool names to ZLAR domains and structured detail objects.

The `translate_tool()` function takes a raw tool name (e.g., `Bash`, `Write`, `Edit`, `mcp__server__tool`) and produces: a `DOMAIN` (classification for policy routing), a `DETAIL` object (structured data extracted from tool input), and a `TOOL_DISPLAY` string (human-readable preview). This translation layer is what makes the gate tool-aware without being tool-dependent — new tools can be added by extending the case statement.




7. Outcome States


Outcome States
ZLAR | The set of audit trail outcome values that record what happened to each tool call.

allow — approved automatically by policy, no human involvement. Authorizer: "policy."
deny — blocked automatically by policy. Authorizer: "policy."
ask_sent — Telegram message sent to human, waiting for response. Outcome: "pending."
pending — gate is waiting for human decision. Always paired with ask_sent.
authorized — human explicitly approved via Telegram. Authorizer: "human:<telegram_user_id>." Non-repudiable.
denied — human explicitly denied via Telegram. Authorizer: "human:<telegram_user_id>." Distinct from policy deny.
logged — allowed but explicitly logged per policy. Used for observability without friction.
away_queued — queued for later review because the human is in away mode.
away_auto_allow — auto-approved during away mode because risk was below the away threshold.
away_halt — critical action halted and queued during away mode. Never auto-approved.




8. Session & State


Session State (session-state.sh)
ZLAR | A thin stateful layer that adds session-indexed counters alongside the stateless policy evaluator.

Solves the $1.6M Weekend problem. The gate is stateless by design — each tool call is evaluated independently. But some governance failures are only visible across multiple calls: velocity spikes, looping, denial bursts. The session state library adds counters that the gate consults alongside policy. It does not override policy. If policy says "allow" but velocity is anomalous, the gate escalates to "ask" — the human decides, not the counter.


Session State Escalation
ZLAR | The mechanism by which anomalous session behavior causes the gate to upgrade an `allow` decision to `ask`.

Three escalation triggers: velocity exceeded (too many calls per time window, exit code 1), loop detected (same action repeated N+ times, exit code 2), denial burst (N+ consecutive denials, exit code 3). Escalation only upgrades `allow` decisions — it never downgrades `deny` or `ask`.


Velocity Tracking
ZLAR | Session state counter that detects when an agent is making too many calls per time window.

Default: 30 calls within 60 seconds triggers escalation. Prevents runaway loops and rapid-fire actions that individually pass policy but collectively indicate a problem. Configurable via environment variables or `gate.json`.


Loop Detection
ZLAR | Session state counter that detects when an agent is repeating the same action.

Default: 5 identical consecutive actions triggers escalation. Catches agents stuck in retry loops or systematically probing a denied resource.


Denial Burst Detection
ZLAR | Session state counter that detects consecutive denials in a single session.

Default: 3 consecutive denials triggers escalation. A burst of denials may indicate the agent is probing boundaries, or the human is asking the agent to do something the policy prevents. Either way, it is a pattern worth surfacing.


ATP (Human Attention)
ZLAR | Human cognitive energy spent on governance decisions, treated as a metabolic currency that must be conserved.

Human attention is finite, like ATP in a cell. Every false positive (unnecessary escalation) wastes ATP. Every classifier refinement that eliminates a false positive returns ATP to the human. The gate must preserve human authority while minimizing unnecessary cognitive expenditure. This framing drove the design of the fast path, the flood guard, scoring thresholds, and availability modes.




9. Agent Identity


agent_id
ZLAR | The identifier of the AI agent making a tool call, recorded in every audit entry.

For Claude Code sessions, this is `"claude-code"`. For OpenClaw/Bohm, `"bohm-openclaw"`. For MCP proxy clients, configurable via `--agent-id` flag. The `agent_id` is how the registry tracks distinct agents. It is extracted from the hook input or set at configuration time — not self-reported by the agent's reasoning layer.


session_id
ZLAR | A per-session identifier that groups related audit events together.

Provided by Claude Code in the hook input. Sanitized by the gate (alphanumeric + hyphens/underscores only, max 64 chars) to prevent path traversal. Used by the registry for session grouping, by the witness for session-scoped sequence detection, and by session state for counter tracking.


Delegation
ZLAR | The concept of authority passing from one agent to another in a multi-agent system.

One of ZLAR's key findings is that delegation chain governance scores zero across all eight major multi-agent frameworks. No framework attenuates permissions as authority passes from agent to agent. The SubagentStart hook in ZLAR is the beginning of delegation governance: when a primary agent spawns a subagent, the gate intercepts and requires approval for non-read-only subagent types.


SubagentStart
EXT (Anthropic hook event) | A Claude Code hook event that fires when the primary agent spawns a subagent.

ZLAR intercepts SubagentStart events to govern subagent creation. Read-only subagent types (Explore, Plan, claude-code-guide) are auto-allowed. All other types require Telegram approval. This is ZLAR's answer to subagent privilege escalation — `bypassPermissions` is sticky through the subagent hierarchy, but hooks still fire.


PreToolUse
EXT (Anthropic hook event) | A Claude Code hook event that fires before every tool call, providing the primary interception point for ZLAR's enforcement.

The PreToolUse hook is ZLAR's enforcement surface for Claude Code. The hook receives the tool name, tool input, and session context. The gate evaluates and returns allow/deny via stdout JSON. This is the "highest-fidelity integration point" — it fires recursively into subagents and works even when `bypassPermissions` is set.


Guardian Agent
EXT (Gartner) | Gartner's formal category name for AI systems that govern, monitor, and constrain other AI agents.

Defined in Gartner's February 2026 Market Guide as "a blend of AI governance and AI runtime controls." Projected $5-13.5B market by 2030. Three models compete: AI-powered governance (WitnessAI), deterministic governance infrastructure (ZLAR), and hybrid approaches. Guardian agents that use AI in the governance path create the failure mode ZLAR calls intelligence persuading intelligence. Gartner warns that guardian agents themselves need guardians — "robust metagovernance controls" — which is the recursive trust problem the gate avoids by having no intelligence to govern.


Agent Control Plane
EXT (Forrester) | The infrastructure layer that manages agent lifecycle, policy, identity, and governance at scale.

Forrester's category name for the market ZLAR is seeking inclusion in. The Agent Control Plane Landscape report (expected Q3 2026) evaluates vendors across five pillars. The control plane needs a policy enforcement point — every framework delegates governance to the orchestration layer or the LLM itself. ZLAR is the enforcement layer the control plane is missing.




10. Cryptography


Ed25519
EXT (IETF/NIST) | An elliptic curve digital signature algorithm used by ZLAR for policy signing and audit trail integrity.

ZLAR uses Ed25519 for two purposes: signing the policy file (proving the policy was authored by the key holder) and labeling the signature algorithm in audit entries (enabling future migration). Ed25519 is compact (64-byte signatures), fast, and widely supported. However, it is based on elliptic curve cryptography vulnerable to quantum computing. NIST IR 8547 schedules it for deprecation after 2030 and complete prohibition after 2035. ZLAR has designed for this migration.


SHA-256
EXT (NIST) | A cryptographic hash function used for the audit trail's hash chain and policy verification.

SHA-256 is quantum-safe — it is not vulnerable to the quantum attacks that threaten Ed25519. This means the hash chain (each entry's `prev_hash` is the SHA-256 of the previous entry) remains structurally sound even after Q-Day. Only the signatures wrapping individual entries need migration, not the chain itself.


ML-DSA (CRYSTALS-Dilithium)
EXT (NIST FIPS 204) | A post-quantum digital signature algorithm that will replace Ed25519 in ZLAR's cryptographic architecture.

ML-DSA is finalized by NIST. Hybrid signatures combining Ed25519 + ML-DSA are standardized and interoperability-tested. ZLAR's Phase 1 PQC metadata ensures every audit entry labels its current signing algorithm, so migration tooling will know exactly which entries need re-signing when ML-DSA arrives. ZLAR knows of no other agent governance system designing for this transition.


PQC Phase 1 (Metadata Approach)
ZLAR | The current implementation of post-quantum cryptography readiness: three metadata fields on every audit entry that label the cryptographic algorithms used.

Every audit entry now carries: `signature_algorithm` (currently "Ed25519"), `hash_algorithm` (currently "SHA-256"), and `public_key_id` (first 16 characters of the SHA-256 hash of the policy signing public key). Zero behavior change. When ML-DSA arrives, migration tooling reads these fields and knows exactly which entries need re-signing. This is not a research proposal — it is shipping code labeling its own cryptographic assumptions so that future tooling can act on them.

Both the CC gate and OC gate emit these fields. Proven live on audit lines 4346-4347 when the gate was enabled.


Policy Signing Key
ZLAR | The Ed25519 private key used to sign the active policy file.

Located at `~/.zlar-signing.key`. Owned by the human operator. The agent never sees it (R052 blocks any attempt to read it). The corresponding public key (`etc/keys/policy-signing.pub`) is used by the gate for verification. If the signature does not verify against the public key, the gate refuses to load the policy and denies everything. A recurring debugging lesson: multiple unlabeled signing keys have caused hours-long debugging sessions. The project needs one master key, labeled, with the rest deleted.


public_key_id
ZLAR | The first 16 characters of the SHA-256 hash of the policy signing public key, embedded in every audit entry.

Enables identification of which key signed the policy that governed a particular audit entry. When keys rotate or PQC migration occurs, this field links each entry to its corresponding key.


Harvest Now, Decrypt Later (HNDL)
EXT (NSA/NIST) | The threat model where adversaries collect signed or encrypted data today to break with future quantum computers.

Uniquely urgent for evidence trails: the entire audit history is stored, immutable, and retrospectively vulnerable. Even if ZLAR migrates to PQC tomorrow, previously recorded signatures remain vulnerable — the evidence trail's immutability means historical entries cannot be re-signed. This is why PQC Phase 1 metadata matters today: every entry labels its own cryptographic assumptions so migration tooling knows what to re-sign.




11. Standards & Protocols


MCP (Model Context Protocol)
EXT (Anthropic / AAIF) | An open protocol for connecting AI models to external tools and data sources.

Now under the Agentic AI Foundation (AAIF) — Anthropic, OpenAI, Block. ZLAR's MCP gate (`mcp-gate/gate.mjs`) is a vendor-agnostic TCP proxy that sits between any MCP client and MCP server, intercepting `tools/call` JSON-RPC requests. ZLAR exploits MCP's governance gaps: tool annotations are "MUST be treated as untrusted" by design, there is no `tools/beforeCall` or `tools/authorize` in the protocol, and no native RBAC, audit logging, or tool-level enforcement exists. ZLAR fills this gap externally.


Cedar
EXT (AWS / CNCF) | A policy language designed for authorization decisions, used by ZLAR as a future migration path from JSON policy rules.

Cedar is default-deny. Only `permit` policies grant access. `forbid` policies override permits (deny wins — architecturally superior). ZLAR's Cedar PoC (`cedar-poc/`) translates three real gate rules (R012, R001, R014) to Cedar syntax, with schema validation and 14/14 tests passing. The most architecturally interesting translation is R001's `unless` clause — Cedar's formal equivalent of ZLAR's compound guard. Cedar enables mathematical verification via SMT solver: you can prove across all possible inputs that a `forbid` cannot be overridden by any `permit`.

Cedar is a CNCF Sandbox project (January 2026), emerging as the agent governance policy standard. Used by AWS Bedrock AgentCore. 42-80x faster than OPA/Rego. Not urgent for ZLAR (JSON + Ed25519 works) but the migration path is proven.


AuthZEN
EXT (OpenID Foundation) | An authorization standard that ZLAR maps to for interoperability.

AuthZEN defines a standard interface for authorization decisions. ZLAR's gate evaluation (domain + action + context -> allow/deny/ask) maps naturally to AuthZEN's request/response model. Mentioned in the Forrester pursuit context as a standards-alignment target.


RFC 9421
EXT (IETF) | HTTP Message Signatures — the standard Visa and Mastercard independently chose for agent identity in commerce.

Both Visa (Token-Agnostic Payments) and Mastercard (Agent Pay) use Ed25519 signatures and RFC 9421 for proving agent identity in financial transactions. ZLAR occupies the gap between agent intent and payment execution — the authorization layer neither has built.


NIST IR 8547
EXT (NIST) | The NIST document that schedules Ed25519 for deprecation after 2030 and complete prohibition after 2035.

This published timeline drives ZLAR's PQC Phase 1 design. The threat is not just prospective forgery after Q-Day — historical signatures lose evidentiary weight once the algorithm is known to be breakable, even if no actual forgery occurred. Evidence trails built today become legally questionable tomorrow if their cryptographic integrity proof expires.


IMDA (Singapore)
EXT (Singapore government) | Singapore's Infocomm Media Development Authority, which published the world's first agentic AI governance framework in January 2026.

The IMDA framework maps to ZLAR's architecture with precision: "significant checkpoints before irreversible actions" (the gate), "continuous monitoring and logging" (the audit trail), "agent identity" (the registry). 10/10 requirement mapping. This is the external regulatory validation the Forrester analyst said ZLAR needed — not a design partner, but a sovereign regulator that independently described what governance of autonomous agents requires, and it matches.


FINRA
EXT (US financial regulator) | The Financial Industry Regulatory Authority, whose 2026 report mandates Full-Chain Telemetry.

FINRA requires system-level audit trails capturing intermediate tool calls, data fetches, and decision pathways. ZLAR's audit trail satisfies this requirement architecturally. The founder's 25 years in financial services means FINRA/SEC compliance is not hypothetical — it is the regulatory regime ZLAR was built to satisfy.


EU AI Act
EXT (European Union) | Regulation classifying AI systems by risk level, with enforcement beginning August 2026.

Article 14 requires human oversight of high-risk AI systems. ZLAR is the structural answer to a structural requirement — not another compliance checkbox, but infrastructure that implements human oversight by architecture. The cryptographic evidence trail satisfies the audit requirements. The gate satisfies the intervention requirements.


C2PA
EXT (Coalition for Content Provenance and Authenticity) | A standard for tamper-evident, cryptographically signed records of content origin.

6,000+ members including Google and Adobe. C2PA proves "this image was captured by this camera." ZLAR proves "this agent executed this tool call with this authorization." Same architectural DNA — action provenance rather than content provenance.


AI TRiSM
EXT (Gartner) | Trust, Risk, and Security Management — Gartner's framework for governing AI systems.

ZLAR sits within the runtime enforcement layer of AI TRiSM. The framework has four layers; the critical ones for ZLAR are AI governance (policy design, compliance mapping) and AI runtime inspection and enforcement (real-time intervention). Gartner projects the AI TRiSM market at $7.4B by 2030.


ISO 42001
EXT (ISO) | The international standard for AI Management Systems. Becoming a procurement prerequisite and insurance criterion.

ISO 42001 provides a management framework for responsible AI but offers "limited coverage of logging and recordkeeping" per the EU JRC assessment. ZLAR's evidence trail fills the operational gap that ISO 42001 identifies but does not implement. Certification to ISO 42001 signals governance intent; ZLAR's audit trail provides governance evidence.


Zero Trust (for AI Agents)
EXT (NIST/industry) | The extension of zero-trust security principles to agent governance: never trust, always verify, at every action.

ZLAR's architecture is zero trust applied to agent actions. Every tool call is verified against signed policy regardless of prior approvals. The gate does not remember trust — it verifies every time. Session state adds counters but never overrides policy. The fail-closed default means unverified actions are denied. This is the execution boundary equivalent of what NIST SP 800-207 prescribes for network security.


OPA/Rego
EXT (CNCF) | Open Policy Agent — a general-purpose policy engine and its query language Rego.

The primary alternative to Cedar for policy evaluation. OPA is widely deployed for Kubernetes admission control and API authorization. ZLAR chose Cedar over OPA because Cedar's default-deny semantics and formal verification via SMT solver align with ZLAR's architecture. Cedar is 42-80x faster than OPA/Rego for authorization decisions. OPA uses Rego (a Datalog-derived query language); Cedar uses a purpose-built authorization language.


DID / Verifiable Credentials
EXT (W3C) | Decentralized Identifiers and Verifiable Credentials — the W3C standard for self-sovereign identity and cryptographic attestation.

DID Core 1.1 reached Candidate Recommendation March 2026. VC Data Model 2.0 is a full W3C Recommendation. Both use Ed25519 signatures — algorithmically identical to ZLAR's native cryptography. A future ZLAR integration could accept VCs as delegation tokens at the gate: the agent presents a VC encoding who delegated authority, for what scope, until when. The gate verifies the signature and evaluates the scope against policy.


EU Product Liability Directive (2024/2853)
EXT (European Union) | The directive classifying AI software as a product subject to strict (no-fault) liability, effective December 9, 2026.

Article 4 explicitly defines software, including AI systems, as products. Claimants need only prove defect plus harm — no negligence required. The long-stop period extends to 25 years for latent personal injuries. AI's ability to continue learning after deployment is factored into defectiveness assessment. Non-compliance with AI Act obligations triggers a presumption of defectiveness. This directive creates structural demand for governance evidence: deterministic enforcement and cryptographic audit trails become liability shields.


SPIFFE/SPIRE
EXT (CNCF) | Secure Production Identity Framework for Everyone — workload identity for cloud-native infrastructure.

SPIFFE provides cryptographic identity at the infrastructure layer: is this a legitimate workload on authorized infrastructure? SPIRE is the runtime that issues SPIFFE Verifiable Identity Documents (SVIDs). In a five-layer verification model for agent governance, SPIFFE is layer 1 (transport identity). ZLAR's gate operates at layers 2-5 (agent identity, authorization, session optimization, audit). HashiCorp Vault Enterprise natively supports SPIFFE authentication for AI agents.




12. Market & Strategy


Forrester Agent Control Plane Landscape
EXT (Forrester Research) | An upcoming analyst report mapping the emerging agent governance market category.

Led by Forrester agent control plane research, Principal Analyst. Questionnaires ship 2nd week of April 2026, publication expected Q3 2026. This is a Landscape (not a Wave) — lower inclusion threshold, accommodates emerging companies. Five evaluation criteria map to ZLAR's architecture: agent inventory/identity, policies/guardrails, monitoring/insights, control/coordination, risk/compliance/auditing. ZLAR covers all five pillars after v1.2.0.


Five Pillars (Forrester)
EXT (Forrester Research) | The five evaluation criteria for the Agent Control Plane Landscape.

1. Agent inventory/identity — closed by `zlar-registry`
2. Policies/guardrails — strengthened by Cedar PoC
3. Monitoring/insights — gate + witness + digest
4. Control/coordination — HITL approval, availability modes
5. Risk/compliance/auditing — cryptographic evidence trail, PQC metadata


SA (Supervised Autonomy)
ZLAR | The planned enterprise product that lets humans configure governance once, verify when they choose, and let the system run.

The enterprise product that lets humans let go — because the structural guarantees mean they do not have to watch. Trust through structure, not vigilance. The open-source portfolio (ZLAR) proves it works. SA is the enterprise product that scales it.


The Deny Path
ZLAR | The demonstration flow that shows an agent being blocked by human decision, with full cryptographic evidence.

The deny path is the demo. The approve path shows the happy case. The deny path shows governance actually working — a human denying an agent action, the action being structurally blocked, and the evidence trail recording exactly what happened. Four of five Forrester pillars in one 5-minute flow. The Forrester briefing strategy consensus: show the deny path, not just the happy path.


CC Gate / OC Gate
ZLAR | The two gate surfaces currently deployed: CC (Claude Code, hook-based) and OC (OpenClaw, daemon-based).

CC gate: `repo/bin/zlar-gate`, triggered by Claude Code's PreToolUse hook via `zlar-gate.sh` wrapper. Synchronous, stateless, runs once per tool call.

OC gate: `/usr/local/bin/zlar-oc-gate`, daemon process monitoring OpenClaw's event stream. Writes to `/var/log/zlar-oc/audit.jsonl`. Schema differences: the OC gate historically lacked `prev_hash` and `authorizer` fields (added March 21).


Bohm
ZLAR | An AI agent built on the OpenClaw platform, governed by ZLAR's OC gate.

Bohm is ZLAR's second governed agent (alongside Claude Code). It operates from `~/.openclaw/`, with a tiered context system, persistent memory, scheduled heartbeats, and external API access (Twitter, GitHub, email). Bohm's governance gap (voluntary compliance) was the design lesson that validated ZLAR's core thesis: structural enforcement is the only reliable governance.


Signal Layer
ZLAR | Agent-discoverable files in the repo that make ZLAR's ideas legible to autonomous agents scanning digital content.

Four files: `AGENTS.md` (root-level discovery pointer), `signal/SIGNAL.md` (front door declaration), `signal/MANIFEST.md` (machine-readable project map), `signal/THESIS.md` (core ideas in extractable form). These are outward-facing Tier 0-1 documents — declarations, not documentation. They exist because the founder declared this work should be legible to the agentic era.


Floor
ZLAR | The baseline governance level below which the system never drops, regardless of agent behavior or karma score.

Even an agent with maximum karma cannot auto-approve certain actions (rm -rf, sudo, persistence mechanisms). The deny rules always block regardless of threshold. The floor is the set of structural guarantees that no amount of earned trust can override. Karma adjusts the judge's disposition, not the statute.


Gate Toggle
ZLAR | A mechanism to temporarily disable the gate for build sessions.

`zlar off` creates a gate-disabled flag file. The gate wrapper checks for this file and auto-allows everything when present. `zlar on` removes the flag and re-engages enforcement. `zlar status` shows current state. This lets the human build without gate friction, then re-engage governance when done. The toggle itself is audited.


One-Way Door / Two-Way Door
EXT (Jeff Bezos / Amazon) | The framework for classifying actions by reversibility that maps directly to ZLAR's gate behavior.

Two-way doors execute at machine speed — you can walk back through. One-way doors get a human's three-second authorization — once you walk through, the door closes behind you. This was the primary conceptual framework in all early ZLAR investor materials. The gate exists because some actions are one-way doors.




13. Infrastructure & Tooling


Watchdog (zlar-watchdog)
ZLAR | Pre-flight health checker for the gate's structural integrity.

Checks: policy file present, signed, and valid; audit trail writable; gate scripts present and executable; required tools available (jq, openssl); Telegram reachable. Can write a lockdown file that blocks all gate operations until manually cleared. The membrane self-check mechanism — the gate cannot operate if its foundations are broken.


Audit Reader (audit-reader.sh)
ZLAR | Shared library for reading and querying the gate's audit trail, used by all observation layer tools.

Design principle: produces facts, not conclusions. Reads, filters, and structures audit events. Does not label, judge, or classify risk. Supports multi-audit trails via `ZLAR_AUDIT_FILES` (colon-separated) — a governance digest that only sees half the picture is broken by design. Provides functions: `audit_events_since`, `audit_events_for_session`, `audit_last`, `audit_extract_facts`, `audit_extract_approvals`, `audit_extract_pending`, `audit_approval_latencies`, `audit_extract_denials`, `audit_extract_sensitive`, `audit_extract_egress`, and statistical aggregators.


Hook Chain
ZLAR | The full path a tool call takes from Claude Code through to the gate engine.

Hook configuration (hook definition) -> gate wrapper (handles gate toggle check and timeout) -> `bin/zlar-gate` (engine, evaluates policy, sends Telegram, writes audit trail). The wrapper is the boot shim. The engine is the gate.


Runtime Drift
ZLAR | The phenomenon where installed runtime copies diverge from the canonical source repository.

The condition where installed runtime binaries silently diverge from the canonical source repository, making repo inspection unreliable for diagnosing live behavior. Discovered March 19 when Bohm reported a P1 that looked wrong from repo inspection alone. The installed runtime copy at `~/.local/bin/zlar-check` had diverged from the canonical source — a self-authored copy with md5 dependency and fail-open behavior. Four bugs were invisible from reading the repo. Repo truth does not equal runtime truth. Only live path testing reveals the system you actually have.




This glossary was compiled from the ZLAR repo source code, design essays, memory files, and architectural documentation as of March 21, 2026.

