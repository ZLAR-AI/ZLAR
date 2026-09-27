# ZLAR V4 formation kernel

This package is the private, deterministic, consequence-incapable V4 source
kernel accepted by ADR-V4-003. It has no live mode, effect abstraction,
adapter, transport, persistence, credential, environment loader, or V3 runtime
dependency.

The package exports exactly seven pure functions:

- `createKernel(input)`
- `canonicalize(value)`
- `identifyEvidence(input)`
- `validateGraph(graph)`
- `evaluateTransition(input)`
- `projectAuthorityView(input)`
- `deriveClaims(input)`

Only exact synthetic formation inputs construct or evaluate. Expected domain
invalidity returns a data-only refusal. The package does not issue authority,
recognize a destination, attempt an effect, or certify its own source boundary.

Claim ceiling: private synthetic source evidence only. Runtime incapability,
dependency closure, import/export closure, and source-foundation completion
remain external test-and-source claims.
