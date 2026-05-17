# ADR-010: Interception Coverage Model

## Status

Accepted (April 15, 2026)

## Context

ZLAR governs by intercepting. The gate sits in the path of actions the agent takes and makes a decision before each one becomes real. This is the architectural center of the project: governance that stops an action before it is an action, not a dashboard that watches after the fact.

Every mechanism described in ADR-001 through ADR-009 assumes the action flowed through the gate. The First Authority Law applies to intercepted actions. The audit chain records intercepted actions. The constitution constrains policies that govern intercepted actions. The receipt is a signed claim about one intercepted action.

Actions that do not flow through the gate are not governed by ZLAR. They may still be governed by other layers — a sandbox, a network egress filter, an operating-system ACL — but they are not governed by this system. This is not a hidden flaw. It is the coverage model. It should be stated in plain language so that no reader, adversary, regulator, or procurement reviewer mistakes ZLAR for a total claim.

## Decision

State the coverage model explicitly in the public documentation, in ADR form here, and in the README. Every guarantee ZLAR makes — cryptographic evidence, human authority, fail-closed, deterministic decision, constitutional constraint — applies to actions that flow through an interception surface. The guarantees do not extend past the surface.

### What is an interception surface

A code path through which an action must pass before it reaches its effect. For the reference implementation:

- The bash/hook gate intercepts tool events emitted to a configured ZLAR hook or adapter, such as Codex/Claude-compatible PreToolUse surfaces and Cursor/Windsurf adapters. Only events the client emits to that hook flow through ZLAR before execution.
- The MCP gate intercepts MCP `tools/call` requests by sitting as a proxy between the MCP client and the MCP server. Only MCP tool invocations routed through this proxy flow through ZLAR.
- Sub-agent spawns (SubagentStart) are intercepted through the same hook layer and inherit the gate's decision before the sub-agent begins.

A detected client, plugin, connector, or executable is not an interception
surface by itself. Governance starts at the routed surface, not at install.

### What is not an interception surface

Anything the agent does that does not route through one of the above. Specifically:

- Shell commands spawned by a sub-process the hook does not see (e.g., a binary the agent invokes, which then invokes something else, which acts).
- Direct network calls the agent issues through a library that does not route through the MCP proxy.
- File operations performed by a tool the agent writes and then executes outside the hook.
- Agent-to-agent communication that occurs outside the intercepted transport.
- Any capability that reaches effect through a path the deployment did not route through the gate.

### Implication for deployment

The practical mission of a ZLAR deployment is to make intercepted equal to all. This is a deployment responsibility, not a code responsibility — the gate cannot intercept what is not routed to it. Closing the coverage model means:

1. The agent runs in an environment where all consequential capabilities are exposed only through intercepted surfaces. Remove or block un-routed capabilities at the sandbox layer.
2. The hook/profile configuration is signed and its integrity is verified before the agent starts. An attacker who can rewrite the configured hook or profile bypasses ZLAR by disabling the interception surface itself.
3. The MCP transport is the only MCP transport the agent can reach. A second, un-proxied MCP connection bypasses the gate even though the agent is "governed."
4. Layered defenses — network egress controls, syscall filters, OS sandboxing — catch the residual surface ZLAR cannot cover by architectural design.

### Implication for claims

Public claims about ZLAR must be framed against this coverage model. Acceptable: "ZLAR provides cryptographically verifiable evidence for every intercepted action." Unacceptable: "ZLAR provides cryptographically verifiable evidence for every action an agent takes." The latter collapses the deployment responsibility into a code claim the code cannot make.

## Consequences

### Honest

The gap between what the code guarantees and what the deployment must achieve is named, not hidden. Procurement and regulatory reviewers find the coverage model in the ADR rather than discovering it as a gotcha. Competitors cannot weaponize the boundary because the project names it first.

### Deployment-dependent

A ZLAR deployment is only as strong as its interception closure. A poorly-closed deployment gives the appearance of governance without the substance. This is a real risk and must be treated as a first-class concern of the deployment playbook rather than an afterthought.

### Architectural focus

The work of extending ZLAR coverage is the work of closing the surface. This includes native-code integrations that widen the bash hook's reach, MCP adapters that bring more capabilities under the proxy, and complementary layers at the OS and network levels. ZLAR does not claim to be the only layer needed. It claims to be the deterministic layer that other layers depend on for human authority.

## Related

- ADR-001: Deterministic enforcement (the action happens at the surface, not after)
- ADR-003: Fail-closed (when in doubt at the surface, deny)
- ADR-006: Structural independence (the surface is separable from the reasoner)
- signal/SIGNAL.md: The declared signal surface for the reference implementation
