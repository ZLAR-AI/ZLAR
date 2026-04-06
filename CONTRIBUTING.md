# Contributing to ZLAR

## Quick Version

1. Fork the repo
2. Create a feature branch
3. Make changes
4. Run tests (see below)
5. Submit a PR

## Code Standards

**Bash (core gate, libraries, tests):**
- bash 3.2+ compatible (macOS default)
- Must pass ShellCheck
- No external dependencies beyond bash, jq, openssl
- Use `set -euo pipefail` in all scripts
- Functions return exit codes, never call `exit` (callers decide)

**Node.js (MCP gate, receipts, Cedar):**
- Node.js 18+ (built-ins only, zero npm dependencies)
- ES modules (`.mjs`)
- No npm packages in the enforcement path

**JSON configuration:**
- All JSON must be valid (CI validates)
- Policy files must be Ed25519-signed before deployment
- Standing approvals must be signed with the policy key

## Running Tests

Before submitting a PR, run the test suites that cover your changes:

```bash
# If you changed the gate, policy, or audit trail
bash tests/test-manifest.sh
bash tests/test-perimeter-closure.sh
bash tests/test-crypto.sh

# If you changed agent identity or bindings
bash tests/test-agent-identity.sh
bash tests/test-standing-approvals.sh
bash tests/test-approval-binding.sh

# If you changed the receipt system
bash tests/test-receipt.sh
node mcp-gate/test-receipt.mjs

# If you changed the MCP gate
node mcp-gate/test-hardened.mjs

# If you changed session state
bash tests/test-session-state.sh

# Run everything
bash scripts/smoke-test.sh
```

All tests must pass. If you add a feature, add tests. The test convention uses `assert <label> <expected> <actual>` helpers with PASS/FAIL counters.

## Adding Policy Rules

Policy rules live in `etc/policies/`. To add a new rule:

1. Add the rule to the policy JSON with a unique ID (e.g., `R020`)
2. Define: `match` (what it catches), `action` (allow/deny/ask), `risk_score`, `severity`
3. Add test cases to `tests/test-perimeter-closure.sh`
4. Re-sign the policy: `bin/zlar-policy sign --input <policy> --key <signing-key>`

## Adding Framework Adapters

Adapters live in `adapters/`. An adapter is a thin wrapper that translates a framework's hook format to the gate's stdin/stdout protocol. The gate is the gate — adapters do not contain governance logic.

To add a new adapter:
1. Create `adapters/<framework>/` with a hook script
2. The hook must pass the tool call JSON to `bin/zlar-gate` on stdin
3. The hook must read the gate's JSON response from stdout
4. Document the framework's hook mechanism in the adapter directory

## Pull Request Process

- PRs require review by a maintainer before merging
- All CI checks must pass (ShellCheck, JSON validation, test suites)
- Commit messages should describe what changed and why
- One logical change per PR (don't bundle unrelated changes)
- If the change affects an invariant, reference which one and explain why the change is compatible

## Architecture Decisions

If your contribution involves a significant design choice, it may need an ADR (Architecture Decision Record). See `docs/adr/` for the format and existing records. Discuss in the PR — the maintainer will decide if an ADR is warranted.

## AI Contributions

ZLAR governs AI agents. AI agents are welcome to contribute to ZLAR. The same governance principles apply: changes must be reviewed by a human before merging.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
