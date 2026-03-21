# zlar-witness

Experimental witness layer for ZLAR. Sequence detection, governance briefs, standing authority view.

**Status:** Private. Merges into [ZLAR](https://github.com/ZLAR-AI/ZLAR) when ready.

## Design Principles

From the [design notes](https://github.com/ZLAR-AI/ZLAR):

- Observation before interpretation
- Fact before narrative
- Witness before enforcement
- The witness can be smart; the authorizer must remain simple
- The witness does not become sovereign
- Uncertainty is a first-class output
- Policy should crystallize from repeated seen reality

## Architecture

The witness reads the gate's evidence trail (`audit.jsonl`). It does not intercept, block, or modify agent actions. The gate remains the sole enforcement point.

```
Gate (enforces) → audit.jsonl → Witness (observes) → Brief (surfaces to human) → Human (ratifies) → Policy (gate enforces)
```

The witness expands what the human can see. Not what the machine may unilaterally decide.

## Components

| Tool | Purpose |
|------|---------|
| `bin/zlar-witness` | Sequence detection — reads evidence trail, detects candidate patterns, tags them |
| `bin/zlar-brief` | Governance brief — weekly digest of actions, latencies, patterns, novelty |
| `bin/zlar-standing` | Standing authority view — what the agent can currently do without asking |

## Candidate Sequence Patterns

Detected, not blocked. Surfaced in briefs, not enforced.

| Pattern | Description |
|---------|-------------|
| `credential-adjacent-egress` | Sensitive file read followed by outbound network request within time window |
| `denied-then-scheduled` | Denied request followed by schedule/cron creation |
| `config-behavior-shift` | Config mutation followed by change in approval pattern |
| `memory-justified-action` | Memory write followed by action that references that memory |

## Dependencies

- `jq` (JSON processing)
- `bash` 4+
- Access to gate's `audit.jsonl`
- Telegram bot token (for briefs)

## License

Apache 2.0 — same as ZLAR.
