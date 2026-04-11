# Governance

ZLAR is a governance tool. Its own governance must be at least as rigorous as what it demands of the systems it governs.

## Decision-Making

ZLAR uses a single-maintainer model with public decision records.

**Maintainer:** Vincent Nijjar (founder)

All architectural decisions, invariant changes, and release approvals go through the maintainer. This is not a committee. One person is accountable.

When the project grows beyond solo maintainership, the model transitions to a foundation with named maintainers, defined roles, and published conflict resolution procedures. That transition will be documented as an ADR.

## Architecture Decision Records

Significant design decisions are recorded in `docs/adr/`. Each ADR documents:

- The context (what problem exists)
- The decision (what was chosen)
- The consequences (what follows from the choice)

ADRs are permanent records. They are not deleted when superseded — they are marked deprecated with a pointer to the replacement. History matters.

Current ADRs:

| ADR | Title |
|-----|-------|
| [001](docs/adr/ADR-001-deterministic-enforcement.md) | Deterministic enforcement, not AI |
| [002](docs/adr/ADR-002-bash-implementation.md) | Bash as implementation language |
| [003](docs/adr/ADR-003-fail-closed.md) | Fail-closed as default |
| [004](docs/adr/ADR-004-ed25519-signing.md) | Ed25519 for signing |
| [005](docs/adr/ADR-005-manifest-narrows-policy.md) | Manifest narrows policy |
| [006](docs/adr/ADR-006-structural-independence.md) | Structural independence from governed system |
| [007](docs/adr/ADR-007-receipt-v1-envelope.md) | Receipt v1 envelope format |

## Invariants

ZLAR's invariants are the constitutional floor. They define what the system must always do (and must never do) regardless of feature requests, competitive pressure, or convenience.

Invariants are documented in `docs/MANIFEST-INVARIANTS.md` (manifest-specific) and `docs/RESTORE-INVARIANTS.md` (Agent Health, v3.0.0).

**Invariant amendment process:**

1. Propose the change as a GitHub issue with the `invariant-amendment` label.
2. Document the current invariant, the proposed change, and the reason.
3. The maintainer reviews. Invariants cannot be weakened to accommodate features. Features must be redesigned to satisfy invariants.
4. If accepted, the invariant is updated and the change is recorded in an ADR.
5. Code that violates the amended invariant is updated in the same PR.

No invariant may be suspended, overridden, or exempted. If an invariant is wrong, it must be formally amended. There is no `--skip-invariant` flag.

**DWP-01 (Deny Wins Precedence):** Whenever two evaluation paths exist (v0 vs v1, JSON vs Cedar, locked vs unlocked, cached vs fresh), the path with fewer checks must either be removed or must always produce deny on any divergence from the stricter path. No weaker path may silently override a stricter path's decision. Added v2.11.0 after three independent instances of the downgrade pattern were found in the April 11 2026 bug hunt.

## Releases

Releases follow semantic versioning:

- **Patch** (1.7.x): Bug fixes, documentation, test additions. No behavioral changes.
- **Minor** (1.x.0): New features, new policy rules, new adapters. Backward compatible.
- **Major** (x.0.0): Breaking changes to policy format, audit schema, or gate behavior.

All releases are tagged and signed. The CHANGELOG documents every change.

## Security

Security issues follow the process in [SECURITY.md](SECURITY.md). The maintainer responds to reports within 48 hours.

## Code of Conduct

Be direct. Be specific. Be constructive. Don't waste people's time with vague feedback or performative disagreement. If you think something is wrong, say what it is and why. If you think something should change, propose the change.

ZLAR exists to protect human beings from AI systems that act without authorization. Contributions are evaluated on whether they serve that mission. Nothing else matters.
