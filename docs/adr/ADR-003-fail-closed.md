# ADR-003: Fail-Closed as Default

Status: Accepted
Date: 2026-01-15
Author: Vincent Nijjar

## Context

When something goes wrong in a governance system — policy fails to load, signing key is missing, upstream is unreachable, an exception is thrown — the system must choose: allow the action (fail-open) or deny it (fail-closed).

Most software defaults to fail-open because availability is prioritized over security. For agent governance, this is backwards. An agent that operates without governance during a failure window can take irreversible actions in seconds.

## Decision

Every error path in ZLAR denies. No exceptions.

- Policy file missing: deny all.
- Policy signature invalid: deny all.
- Policy parse failure: deny all.
- Gate crash (ERR trap): deny the current action.
- Signing key missing: audit entry written as "unsigned" (or denied in strict mode).
- Upstream MCP server unreachable: deny to client.
- Telegram timeout: deny (human didn't respond = human didn't authorize).
- Unknown policy action: deny.
- Unhandled exception: deny and exit.

The gate has no `--permissive` flag. There is no way to configure fail-open behavior. This is not an oversight.

## Consequences

- A misconfigured gate blocks all agent operations. This is the correct behavior — a governance system that fails silently is worse than one that fails loudly.
- Operators must ensure policy is valid and signed before deploying. The quickstart handles this. Manual deployment requires attention.
- Availability depends on policy correctness. If the policy is wrong, the agent is blocked. This creates strong incentive to test policy changes before deployment.
- Timeout-as-deny means the human's absence is a denial. The agent cannot act without affirmative human authorization. Silence is not consent.
