# Cedar Policy Migration Guide

ZLAR supports two policy engines: JSON regex (original) and Cedar (formal). Both produce the same audit entries and receipts. Both go through the same gate interface.

## Policy Engines

| Engine | Language | Verification | Speed | When to use |
|--------|----------|-------------|-------|-------------|
| `json` | JSON regex | None (test suite only) | ~5ms median | Default. Solo developers. Simple rules. |
| `cedar` | Cedar | Formal (WASM) | ~0.004ms median | Enterprise. Audit requirements. Complex RBAC. |
| `both` | Both | JSON primary, Cedar advisory | ~5ms + ~0.004ms | Migration period. Divergence detection. |

## Switching Engines

**MCP gate:**

```bash
# JSON only (default)
node mcp-gate/gate.mjs --upstream localhost:3200

# Cedar only
node mcp-gate/gate.mjs --upstream localhost:3200 --policy-engine cedar

# Both (JSON primary, Cedar advisory — logs divergences)
node mcp-gate/gate.mjs --upstream localhost:3200 --policy-engine both

# Or via environment variable
ZLAR_POLICY_ENGINE=cedar node mcp-gate/gate.mjs --upstream localhost:3200
```

**Bash gate:** The bash gate uses JSON regex only. Cedar evaluation is available via the MCP gate. Both gates write to the same audit trail and produce the same receipt format.

## Rule Translation

Cedar rules are in `cedar-poc/`. JSON rules are in `etc/policies/active.policy.json`.

### Priority 1 (Critical) — Must Deny

| Rule | JSON Pattern | Cedar File | Cedar Pattern |
|------|-------------|------------|---------------|
| R002 | `\brm\s+.*(-rf\|-fr\|--recursive)` | zlar-p1.cedar | `resource.command like "*rm *-rf*"` (3 variants) |
| R003 | `\b(sudo\|visudo\|dscl)\b` | zlar-p1.cedar | 3 separate forbid policies |
| R005 | `\b(nohup\|launchctl\s+load\|crontab\|setsid)\b` | zlar-p1.cedar | 4 separate forbid policies |
| R006 | Fork bombs, infinite loops | zlar-p1.cedar | `while true`, `yes \|`, `dd if=/dev/zero\|urandom` |
| R007 | `\bosascript\b` | zlar-p1.cedar | `resource.command like "*osascript*"` |
| R012 | Gate self-protection paths | zlar.cedar | 10+ `like` patterns |

### Priority 2 (Warn) — Escalate to Human

| Rule | JSON Pattern | Cedar File | Cedar Pattern |
|------|-------------|------------|---------------|
| R014 | `\bgit\s+push\b` | zlar-p2.cedar | `resource.command like "*git push*"` |
| R016 | `\b(curl\|wget\|ssh\|scp\|rsync\|nc\|ncat\|netcat)\b` | zlar-p2.cedar | 6 separate forbid policies |

### Standing Approvals

In JSON, standing approvals are in `etc/standing-approvals.json` and checked by the gate before Telegram escalation.

In Cedar, standing approval equivalents are `permit` policies in `zlar-p2.cedar`. However, Cedar's forbid-wins semantics means Cedar permits cannot override Cedar forbids. Standing approvals for P2 rules (R014, R016) are handled by the gate's `checkStandingApproval` function, not by Cedar.

This is architecturally correct: standing approvals are a human authorization mechanism, not a policy language feature. The gate checks standing approvals before invoking the policy engine.

## Known Limitations

**Cedar `like` vs regex:** Cedar uses glob-style `like` matching (`*` for any string). JSON uses full POSIX regex. Some patterns that are one regex in JSON require multiple Cedar rules:

- R003 `\b(sudo|visudo|dscl)\b` → 3 Cedar rules (one per command)
- R006 fork bombs → 4 Cedar rules (common forms only; exotic variants may not match)

If you have custom regex patterns that can't be expressed as `like`, keep those rules in the JSON engine and run `--policy-engine both`.

**Three-outcome vs two-outcome:** Cedar has two decisions: allow and deny. ZLAR has four: allow, deny, ask, log. The `mapToGateAction` function translates Cedar deny into ZLAR deny (P1 rules) or ZLAR ask (P2 rules) based on which policy fired. This mapping uses the `@id` annotations on Cedar policies.

## Running Both Engines

The `both` mode runs JSON as primary and Cedar as advisory:

1. Both engines evaluate every tool call
2. The JSON result is used for the actual decision
3. If the engines disagree, a log message records the divergence
4. Over time, as confidence grows, switch to `cedar` only

This is the recommended migration path for production deployments.

## Formal Verification

Cedar policies can be formally verified — proved correct for all possible inputs. Run the existing test suites:

```bash
node cedar-poc/test.mjs          # Base rules
node cedar-poc/test-e23.mjs      # E-23 compliance rules
node mcp-gate/test-cedar.mjs     # Full P1/P2 integration
```

The Cedar WASM SDK's `validate()` function checks schema-policy consistency at load time. Invalid policies are rejected (fail-closed).
