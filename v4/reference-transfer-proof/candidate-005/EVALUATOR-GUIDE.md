# Candidate 005 Evaluator Guide

This package is a bounded, local, standard-library proof for one disposable
stdio MCP terminal. Its sole consequence-capable tool is
`deployment.promote`. The destination changes one synthetic active artifact to
one fixed staged synthetic artifact and increments one generation exactly
once.

## Runtime and trust boundary

Use one local Python 3 runtime with its standard library on a POSIX host that
supports `fork` and anonymous pipes. The declared TCB is the frozen package,
that Python runtime, the local OS/process/filesystem implementation, and the
execution bridge used to start the commands. No dependency installation,
network, environment secret, operator configuration, Git metadata, historical
evidence, caller working directory, or private operator state is required.

The runner accepts only one canonical absolute output root that does not yet
exist. It verifies the frozen internal package identity before creating that
root or opening the destination. The ephemeral RSA private exponent exists
only in process memory. The runner and forked destination inherit it in memory;
it is never saved, printed, logged, serialized, placed in argv, or placed in
the environment. No secure-erasure claim is made.

## Fresh evaluator sequence

From any working directory, set absolute paths for the frozen package and a
new absent disposable output root, then run exactly:

```text
python3 -B /absolute/path/to/frozen-package/runner.py --output-root /absolute/path/to/new-absent-output
python3 -B /absolute/path/to/frozen-package/offline_verify.py --campaign-root /absolute/path/to/new-absent-output
python3 -B /absolute/path/to/frozen-package/coverage_regenerate.py --campaign-root /absolute/path/to/new-absent-output
```

The first command is consequence-capable only inside the newly created
synthetic output. Do not rerun it against the same or a replacement root when
evaluating one frozen campaign. The second and third commands are read-only and
must leave the complete campaign tree byte-exact.

## Evidence meanings

- `run-plan.json` enumerates all 86 exact cases before execution with closed
  subtotals `52/27/1/1/1/4`.
- `attempt-inputs.json` binds every raw request byte to one planned case.
- `public-key.json` exposes the complete lowercase hexadecimal RSA modulus and
  decimal exponent. Generic verification derives `n.bit_length()` and requires
  exactly 2048 before any signature or later proposition is accepted.
- `decision-receipts/`, `refusal-receipts/`, `effect-receipt.json`,
  `consumption-receipt.json`, and `state-final.json` form the linked
  authorization-to-settlement chain.
- `matrix-evidence.json` signs the exact ordered case set, classes, outcomes,
  and protected mutation/consumption counters.
- `runtime-inventory.json`, `destination-registry.json`,
  `matrix-evidence.json`, and `noncoverage-baseline.json` are the four
  separately hash-bound coverage inputs.
- `coverage-map.json` separates surface disposition from observed outcome.
  Refusal is never promoted into a governed claim.
- `output-manifest.json` signs the exact saved evidence file set and every raw
  byte identity except its explicitly self-excluded signed file.

Every adversarial request returns structured refusal data. A thrown harness
exception, package drift, non-2048 actual public modulus, signature failure,
set mismatch, coverage mismatch, or any negative/replay/prohibited mutation or
consumption fails the candidate.

## Expected structural result

The plan, attempt-input set, runner matrix, signed matrix count and cases, and
case-class map must be exactly equal. The bounded campaign has one recognized
promotion, one recognized authorization consumption, one generation
increment, 85 structured refusals, and zero negative, replay, prohibited,
outside-domain, real, or external protected mutation or consumption. Coverage
has exactly 43 rows and exactly one governed surface:
`mcp.tool.deployment-promote`.

## Side doors and claim ceiling

Source-owner modification/imports, debugger/process memory, same-user state,
direct filesystem/destination mutation, alternate clients/servers/transports/
tools/adapters/shell/browser/app/network, host/runtime/kernel/filesystem/Codex
bridge integrity, crash/power-loss/parallel/cross-process/durable exactly-once
and recovery, receipt retention/external custody, revocation/key custody, and
human/institutional/external-domain/production/public recognition remain open
or unknown.

A passing run supports only this claim: one frozen Candidate 005 and its
bounded self-check are ready for independent review. It does not establish
independent reproduction, accepted Star 4, MCP OAuth or Enterprise-Managed
Authorization, accountable-human approval, full MCP, host/runtime integrity,
enterprise, institutional, external-domain, production, public, Star 5,
later-Star, universal, or V4-complete governance.
