# ZLAR Protected Promotion — Candidate 001

This package is one disposable local product-proof candidate. It demonstrates
one fixed synthetic `deployment.promote` request at `release-slot-A`.

The receiving system owns the consequence. It begins at generation 7, refuses
a request without a recognized authorization credential, accepts one exact
credential once, commits generation 8, and refuses replay before another
protected mutation.

This is not an installer, a real deployment, a live Claude or Codex adapter, a
production issuer, institutional authority, or protection for this computer.

## Run one campaign

The campaign root must be absent and must be one exact authorized basename.

```text
python3 -I -S -E -s -B run_campaign.py \
  --output-root /private/tmp/zlar-protected-promotion-builder-campaign-001
```

The equivalent verifier-campaign basename is
`/private/tmp/zlar-protected-promotion-verifier-campaign-001`.

## One user-facing verifier command

```text
python3 -I -S -E -s -B verify.py \
  --candidate-root /absolute/path/to/candidate-001 \
  --campaign-root /private/tmp/zlar-protected-promotion-builder-campaign-001
```

The verifier is read-only. It validates the candidate and campaign raw-byte
manifests, key roles, run identity, request/time bindings, signed refusal,
settlement chain, mutation and consumption counters, UI provenance and an
independently regenerated coverage map.

## Three-panel status model

1. `OBSERVED CLIENT` — label unverified.
2. `LOCAL DEMO AUTHORITY — OPERATOR IDENTITY UNPROVEN` — owns the immutable
   proposal, synthetic local decision-event record and one authorization
   credential.
3. `RECEIVING SYSTEM — REFUSAL OWNER` — owns every decision/refusal and the one
   protected settlement.

The evidence rail uses only these positive transitions:

- a valid destination-signed unchanged-state refusal:
  `REFUSED BY RECEIVING SYSTEM`;
- a valid destination-signed accepted settlement before offline verification:
  `DESTINATION REPORTED COMMIT — VERIFICATION PENDING`;
- complete read-only verification:
  `VERIFIED BOUNDED RESULT`.

Destination loss, timeout, partial output, cache, tampering or malformed
transport yields `DESTINATION UNAVAILABLE — NO DESTINATION DECISION` and can
never become refusal or PASS.

## Package map

- `run_campaign.py`: deterministic campaign driver; signs nothing.
- `signer_process.py`: fresh-exec signer entrypoint.
- `authority_role.py`: proposal, synthetic event and issue-once authority.
- `destination_role.py`: destination refusal and sole protected commit.
- `process_channel.py` / `process_evidence.py`: bounded process, descriptor,
  environment, argv and lifecycle evidence.
- `contract.py`: exact terminal, request, recognition, route and side-door
  contract.
- `canonical.py`, `crypto_rsa.py`, `evidence.py`: strict encoding and disposable
  local-proof signatures.
- `coverage_subject.py`: campaign coverage map.
- `coverage_independent.py`: separate coverage regeneration used by verifier.
- `renderer.py`: evidence-derived panel labels.
- `manifest.py`, `PACKAGE-MANIFEST.json`: non-circular candidate identity.
- `static_check.py`: source writer/spawn/dependency gate.
- `verify.py`: the only user-facing truth command.
- `test/`: static, no-fixture invariant tests.

## Declared trusted-computing base

The frozen candidate bytes, exact local Python runtime and standard library,
launcher/execution bridge, synthetic event controller, OS process and pipe
behavior, clock, randomness, filesystem, authority signer, destination signer
and evidence renderer are trusted for this bounded proof. The renderer has no
evidence authority. No external model is in technical PASS.

## Open routes

Source-owner imports or modification, same-user interference, process memory,
debugger, host/kernel/filesystem control, direct filesystem mutation,
alternate destinations, crash/power loss, concurrency, recovery, durable
exactly-once, operational revocation, human identity, institutional authority,
production custody, external recognition and real deployment remain open or
unknown. See `CLAIM-CEILING.md` and the generated `coverage-map.json`.
