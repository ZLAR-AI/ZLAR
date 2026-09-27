# ADR-005: Manifest Narrows Policy, Never Widens

Status: Accepted
Date: 2026-03-20
Author: Vincent Nijjar

## Context

ZLAR has two authority documents: the policy (what rules exist) and the manifest (what an agent is authorized to do). When both exist, the system must decide how they interact.

The dangerous option: let the manifest grant permissions that the policy denies. This turns the manifest into a bypass mechanism. An agent with a permissive manifest could override policy restrictions.

## Decision

The manifest can only narrow what the policy allows. It cannot widen it.

Precedence order (highest to lowest):
1. Manifest deny — absolute, cannot be overridden
2. Policy deny — respected unless manifest is more restrictive
3. Policy ask — escalates to human
4. Manifest allow — only permits what policy already permits
5. Policy allow — baseline permission

If the manifest says "allow file.write" but the policy says "deny file.write", the action is denied. If the manifest says "deny bash.dangerous" but the policy says "ask bash.dangerous", the action is denied (manifest deny wins).

The manifest declares a ceiling, never a floor.

## Consequences

- An agent cannot escalate its own authority by manipulating its manifest. Even a perfectly forged manifest (impossible with Ed25519 signing, but hypothetically) could only restrict, never expand.
- Manifest-less operation falls back to policy-only. The manifest is an interface to governance, not governance itself. Removing the manifest does not remove governance.
- Expired manifests result in hard deny (not policy fallback). A manifest that was once issued and has expired is more suspicious than one that never existed.
- This design enables delegation: a parent agent's manifest constrains what it can delegate to child agents. The child's authority is always a subset of the parent's.
