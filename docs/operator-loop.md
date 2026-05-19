# ZLAR Operator Loop

This document defines how an agent, ZLAR, and a human collaborate on a single tool call. The loop exists so that human approvals carry authority over the *session*, not only over one individual action. A surprise card is not normal workflow — it is evidence that the agent's intent and the gate's classification diverged. The remedy is to deny, stop, and reconcile, not to route around the denial.

This is a v0.1 spec. It captures contract and invariants. The reference implementation is `bin/zlar-classify` and the regression in `tests/test-zlar-classify.sh`.

---

## Why

ZLAR's per-action enforcement works: the gate intercepts a tool call, classifies it, and either allows, asks the human, or denies. But three failure modes erode authority:

1. **Surprise cards.** A card appears that the agent did not expect. The human has no context, denies on reflex, and the agent silently retries through a different path. Denial becomes noise instead of authority.
2. **Path-laundering.** When one route is denied (e.g., a `Bash` write), the agent reaches the same outcome through another route the gate is shaped less tightly to govern (e.g., `Edit`). This is not malice — it is the agent's optimizer doing its job. But the human's "no" stops carrying meaning.
3. **Hidden classification.** Until a card appears, neither the agent nor the human knows which rule will fire. The human cannot pre-validate the agent's plan; the agent cannot pre-warn the human.

The operator loop closes those gaps by making classification observable *before* the action, and by making denial a session-level event.

---

## The loop

```
  ┌──────────────────────────────────────────────────────────────┐
  │ 1. Agent proposes an action (Tool + input)                   │
  └────────────────────────────┬─────────────────────────────────┘
                               │
                               ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 2. Preflight classify (read-only, no side effects)           │
  │    zlar classify  →  {rule_id, action, domain, severity}     │
  └────────────────────────────┬─────────────────────────────────┘
                               │
                               ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 3. Agent pre-announces to the human, in chat:                │
  │    • exact rule id                                           │
  │    • exact action expected (allow / ask / deny)              │
  │    • why this action is needed                               │
  │    • recommendation (approve / deny)                         │
  └────────────────────────────┬─────────────────────────────────┘
                               │
                               ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 4. Agent executes the action                                 │
  └────────────────────────────┬─────────────────────────────────┘
                               │
                ┌──────────────┴───────────────┐
                ▼                              ▼
   ┌────────────────────────┐    ┌────────────────────────────┐
   │ Gate result matches    │    │ Gate result does NOT match │
   │ pre-announce           │    │ pre-announce (surprise)    │
   └────────────┬───────────┘    └─────────────┬──────────────┘
                │                              │
                ▼                              ▼
   ┌────────────────────────┐    ┌────────────────────────────┐
   │ Human approves/denies  │    │ Human DENIES               │
   │ on its merits. Normal. │    │ Session enters reconcile.  │
   └────────────────────────┘    └────────────────────────────┘
```

---

## Contract

### Preflight classify

`zlar classify` is a read-only command. Given a tool name and tool input, it returns the rule the gate **would** match if the same input arrived through the PreToolUse hook. It does not:

- contact Telegram,
- write to the audit log,
- write to the pending-approval directory,
- record human-invariant counters,
- modify gate state,
- consult the manifest (manifest narrowing is enforced at runtime, not at preflight),
- consider session-state escalation, novelty, restore-trust, karma, or away-mode (those are runtime modifiers, not classification).

It returns the **policy-level classification**: the rule the agent's action would match against `etc/policies/active.policy.json` under default conditions. Runtime modifiers can escalate `allow → ask`, but they cannot widen `ask → allow` or `deny → allow`. So preflight gives the **floor** of how strict the gate will be; the runtime may be at least as strict.

Output is a single line of JSON:

```json
{"rule_id":"R032E","action":"ask","domain":"write","severity":"warn","description":"Write to ZLAR repo code — ask human (lib, tests, scripts, mcp-gate, docs)"}
```

`action` is one of `allow`, `ask`, `deny`. `rule_id` is `default` if no rule matched. `domain` is one of `bash`, `write`, `edit`, `read`, `glob`, `grep`, `agent`, `webfetch`, `websearch`, `mcp`, `internal`, `unknown`.

### Tool domain — Write vs Edit is not interchangeable

The Claude `Write` tool (creating or replacing a file) is `domain: "write"`. The Claude `Edit` tool (modifying an existing file in place) is `domain: "edit"`. The two domains have sibling rules covering the same paths but different rule ids:

| Path class | `write` domain | `edit` domain |
|---|---|---|
| ZLAR repo code (`lib/`, `tests/`, `scripts/`, `mcp-gate/`, `docs/`, `etc/canary/`) | **R032E** ask warn | **R041E** ask warn |
| `.ssh/` | R030 deny | R040 deny |
| Project `.claude/` | R032B ask | R041B ask |
| Claude settings | (write rule TBD) | R041D ask |
| Enforcement layer (gate, crypto, policy, keys) | R032 deny | R041 deny |

Pre-announcement must name the **right rule for the right domain**. Announcing R041E for a `Write` action is a mismatch, and a mismatch is treated as a surprise card under the strict loop.

### Pre-announcement (agent → human)

Before any tool call where preflight returns `ask` or `deny`, the agent states in chat:

- the tool and input in plain language ("I am about to add a new file `docs/operator-loop.md`"),
- the rule id ("Expected gate rule: R032E"),
- the expected action ("ask — gate will send a Telegram card"),
- why this action serves the work,
- a recommendation ("Recommend approve" or "Recommend deny — this is the wrong path").

For actions where preflight returns `allow`, pre-announcement is not required, **but** the agent must still announce *any cluster of write actions* in advance so the human knows what to expect, and must state explicitly when a write action is expected to produce **no card** (so the absence of a card is itself observable).

### Unexpected card

If a card appears that does not match a pre-announcement — wrong rule id, no announcement at all, or different action — the human **denies**. This is the session-stop rule.

Two consequences follow:

1. The denial enters the audit trail as a normal denial.
2. The session enters **reconcile state** (defined below).

The agent does not retry the action through another path. The agent does not "work around" the denial. The agent stops, reports what happened, and waits for human direction.

### Denial-as-session-stop (reconcile state)

A denial is a session-level signal, not a per-action signal. When the human denies, the agent's next message to the human must:

1. Acknowledge the denial explicitly ("denial received for R032E on `docs/operator-loop.md`").
2. Report what the agent was attempting and why preflight said one thing but the gate did another (if applicable).
3. Stop pursuing the immediate task path until the human re-engages.
4. Not begin a different task that is logically related to the denied one ("if I can't write the spec doc, let me write the ADR instead" — no).

The human resumes the session by giving a new instruction. Until then, the agent waits or returns to read-only investigation.

### One card at a time

When a slice involves multiple write actions, the agent triggers them **one card at a time**, waiting for the human's decision before triggering the next card where practical. This avoids the "ten cards in a row" pattern that trains the human to approve-on-reflex.

---

## Known classification gaps (as of v3.3.16)

The classifier and the runtime are only as good as the policy. These gaps are recorded here because pre-announcement of an *incorrect* preflight result is still a surprise card from the human's perspective.

### G-1: Edit-domain coverage of `bin/zlar` (CLI launcher)

R041 denies edits to `bin/zlar-gate`, `lib/crypto.sh`, `lib/hmac.sh`, `etc/policies/`, `etc/keys/`. It does not list `bin/zlar` (the CLI launcher). An `Edit` on `bin/zlar` falls through every edit-domain rule and lands on R042 (catch-all allow). This is a coverage gap — `bin/zlar` controls `zlar on`, `zlar off`, `zlar lock`, `zlar unlock`, `zlar telegram`, `zlar uninstall`. Modifying it can disable enforcement without an ask card.

R012W_EDIT is `domain: "bash"` and catches *bash writes* to enforcement paths (`sed -i bin/zlar`, `cp /tmp/new bin/zlar`, etc.). It does not catch `Edit` tool calls. The Claude-Edit and Codex-Edit paths to `bin/zlar` are currently ungoverned.

Pre-announce protocol: when about to call `Edit` on `bin/zlar`, the agent states "expected: R042 catch-all allow — no card; known coverage gap (G-1)." If a card appears anyway, that is a surprise and the human denies.

### G-2: `R005E` regex false positive on filenames containing `eval`

`R005E` regex is `\beval\b|\bexec\s+[0-9]|/dev/tcp/|/dev/udp/`. Word boundaries (`\b`) treat `-` as a non-word character, so the regex matches the substring `eval` inside filenames like `tests/bash-gate-runner.sh` or any path with `-eval` in it. Read-only commands (`wc`, `head`, `cat`) against such filenames fire R005E ask. This is the surprise-card mechanic exactly: classification is path-string-based, not intent-based.

Until R005E tightens its regex (e.g., anchor to `\beval(\s|$|;|\|)` rather than bare `\beval\b`), agents should avoid putting filenames containing `-eval` into Bash commands. Use the `Read` tool (read-domain) for files whose names contain `eval`.

### G-3: `R005J` fires on `sh -c` verification chains (resolved framing)

`R005J` matches `\b(bash|sh|zsh|dash|ash|ksh)\s+-c\b` — `ask` severity `critical`. An earlier note framed this as `R005J` "reportedly firing on `bash -n`"; that framing was wrong. The actual trigger was a `sh -c '...'` verification chain — `sh -c` is exactly what R005J catches, and the rule fired correctly.

This is not a gap. It is the loop working as designed: bundling a verification step into `sh -c` produces a surprise card if the agent did not announce it. The remedy lives in the loop, not in the policy:

- For verification, prefer a single direct command (`jq`, `cat`, `wc`, `grep`) over `sh -c '… | … | …'`.
- If a shell-chain really is needed, pre-announce `R005J ask critical` and let the operator decide.
- Treat any unannounced `R005J` card as a surprise card and stop per the reconcile rule above.

---

## Pre-announce template

Use this template in chat before any tool call that preflight classifies as `ask` or `deny`, **and** before any cluster of writes (even if expected to be silent):

```
About to call: <Tool> with input <one-line description>
Path or command: <relevant slice>
Preflight: rule=<R0XX> action=<allow|ask|deny> severity=<info|warn|critical>
Card expected: <yes|no — and why if no, e.g. "R042 catch-all" or "known gap G-1">
Why: <one sentence>
Recommendation: <approve|deny>
```

For a batch of related actions, list them in a table and announce the total expected card count.

---

## Reconciliation checklist

After a denial enters reconcile state, the agent's first message back to the human covers:

- What was attempted (tool, input slice).
- What rule the gate matched (from the card, audit, or denial output).
- Whether preflight classify agreed with the runtime outcome.
  - If agreed: the human denied an action the agent correctly announced. No bug; the action was correctly stopped.
  - If disagreed: classification gap — record it as a candidate fix (policy regex, missing rule, agent-side domain confusion, or runtime escalation logic).
- What the agent will NOT do next: any path that achieves the denied outcome by other means.
- What the agent recommends as the next step (typically: ask the human to either approve a corrected pre-announcement, or change direction).

---

## Implementation status

- `bin/zlar-classify` — v0.1, shells out to `tests/bash-gate-runner.sh` (the read-only evaluator already maintained for the cross-gate differential test).
- `bin/zlar classify` — subcommand wrapper.
- `tests/test-zlar-classify.sh` — focused regression covering the loop's contract (rule_id and action shape, a small fixture set spanning bash/write/edit/read domains).
- The classifier shares its evaluator with the test suite; the cross-gate differential test (`tests/test-cross-gate-differential.mjs`) is the canary against drift between the bash gate, the MCP gate, and the classifier.

This v0.1 ships the loop in code form. The contract enumerated above is the spec the implementation must satisfy; if implementation and spec disagree, the spec wins until the spec is amended.
