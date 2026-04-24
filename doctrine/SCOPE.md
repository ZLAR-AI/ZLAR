ZLAR Scope
What ZLAR governs, what it does not, and what that means for any claim made about it.

Last updated 2026-04-24. Live doctrine.

Scope of this file: the public boundary of ZLAR's governance claim. DNA §11 establishes the scope boundary in one paragraph; this file is the elaboration. If this file and the live signed artifacts disagree, the artifacts win. If this file and DNA disagree on the principle, DNA wins; this file must be corrected.

—

1. The claim

Within the governed path, no consequential action reaches the world without either a signed policy allowing it or a signed human approval. Every such decision produces a signed receipt that chains to the prior receipt. This claim is structural. It holds when the agent is adversarial, misaligned, or buggy.

The claim applies only to the governed path.

—

2. The governed path

An action is on the governed path when it flows through a ZLAR interception surface before it takes effect. The reference implementation has two such surfaces:

- The bash gate — Claude Code PreToolUse hook. Every tool call the local CC process emits flows through this hook before execution.
- The MCP gate — TCP proxy between MCP client and MCP server. Every MCP tools/call the client issues to this upstream flows through the proxy.

See ADR-010 for the full treatment of what counts as an interception surface and what does not.

—

3. What ZLAR does not govern

Three categories. Each is named here so no reader mistakes ZLAR for a total claim.

Upstream of the contact boundary.
ZLAR does not govern the model, the prompt, the reasoning trace, or any internal agent state. Governance at the contact boundary is by design. Governing upstream is governance theater (DNA §3). Governing downstream is forensics.

Un-routed paths.
Any capability the deployment has not routed through a ZLAR interception surface is outside the gate. Shell commands spawned by a sub-process the hook does not see, direct network calls through a library that bypasses the proxy, file operations performed by a tool the agent wrote and then executed outside the hook — these reach effect without crossing the gate. They must be governed by sandboxes, network controls, and operating-system permissions. ADR-010 is the reference.

Out-of-SDK sub-runtimes.
When the local process delegates work to a sub-runtime that is not a ZLAR-mediated worker — a harness-managed agent running in a separate execution context, a subprocess with its own permission model, any future runtime that acts on behalf of the local process but outside ZLAR's SDK delegation chain — the sub-runtime has its own permission model and ZLAR sees neither the handoff nor anything the sub-runtime does. The sub-runtime's actions are not governed by ZLAR until a delegation-envelope gate (design, not shipped) covers the handoff itself. See doctrine/roadmap/delegation-envelope.md for the named plan.

—

4. The deployment owner's responsibility

Interception completeness is a deployment property, not a code property. The code guarantees hold for the routed surface; making the routed surface authoritative is the deployment owner's job. In practice this means:

- Run the agent in an environment where every consequential capability is exposed only through intercepted surfaces.
- Block or remove un-routed capabilities at the sandbox, OS, and network layers.
- Protect the hook configuration itself — an attacker who can rewrite the hook bypasses ZLAR by disabling the interception surface.
- Route MCP only through the proxy; a second, un-proxied connection is a bypass even when the first is governed.

A deployment that does not close these gaps has ZLAR running, not ZLAR governing.

—

5. Shipping status of scope-related capabilities

Shipped.
- Bash gate (Claude Code PreToolUse).
- MCP gate (TCP proxy).
- ADR-010 coverage model, public.
- Fail-closed on every error path.
- SDK delegation for in-runtime worker spawn.

Design, not shipped.
- Delegation-envelope gate for out-of-SDK sub-runtimes.
- Session-level decision surface that exposes which actions the gate saw, asked, denied, or did not see at all.
- Cross-deployment ZLAR↔ZLAR federation (zlar-meets-zlar).
- Cumulative irreversibility detection and restorative governance (DNA §10).
- Sequence-aware enforcement for the Semantic-Gap Frontier (DNA §10).

—

6. Rules for public claims

Any ZLAR claim must be framed against this scope. Acceptable: "Within the governed path, ZLAR produces cryptographically verifiable evidence for every intercepted action." Unacceptable: "ZLAR produces cryptographically verifiable evidence for every action an agent takes." The second collapses deployment responsibility into a code claim the code cannot make.

Copy that implies a wider scope than this file describes is overclaim. Correct the copy.
