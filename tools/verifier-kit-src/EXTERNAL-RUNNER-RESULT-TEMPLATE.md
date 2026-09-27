# ZLAR Verifier Kit External Runner Result

Verdict: PASS | PARTIAL | FAIL

## Runner

- Name or pseudonym:
- Relationship to ZLAR:
- Date completed:
- Approximate time spent:

## Environment

- OS and version:
- CPU architecture:
- Shell:
- Node version:
- Tar version:
- SHA-256 tool used:
- OpenSSL version, if available:

## Artifact Hashes

- `zlar-verifier-kit-v0.1.0.tar.gz`:
- `zlar-verifier-kit-issuer-status-fixture.json`, or `N/A` if no JSON output was generated:
- `examples/trusted-receipt-issuers-v1.json`:
- `engagement-bundle/engagement-receipt.json`, or `N/A` if no engagement bundle was supplied:
- `engagement-bundle/engagement-pubkey.pub`, or `N/A` if no engagement bundle was supplied:
- `engagement-bundle/engagement-chain.jsonl`, or `N/A` if no engagement bundle was supplied:

## Commands And Results

The issuer-status JSON output can be generated either by redirecting
`node verify-issuer-status.mjs --json` or by running
`bash external-runner-dry-run.sh --issuer-status-json-out <file>`.

For each command, record the command, exit code, relevant output, and
whether it matched the expected result.

```text
command:
exit_code:
output:
matched_expectation:
```

## README Or Packet Friction

Record any place you paused, re-read, got stuck, or thought the command
boundary was unclear. Record any question you would have asked if usage
coaching were allowed.

## Overall Notes

Explain the verdict in one short paragraph.

## Private Intake Boundary

If this result is returned privately, the source repository may wrap the
returned hashes and target metadata in `zlar-private-verifier-result-v1.json`
and validate it with:

```bash
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json
bin/zlar private-verifier-result verify --input zlar-private-verifier-result-v1.json --evidence-dir release-forward-result-dir
```

That intake envelope is private-by-default custody metadata. It is not public
attribution and not public external attestation. With `--evidence-dir <dir>`,
the validator recomputes the declared artifact hashes against local evidence
files and fails closed without printing the local evidence directory.

## Coverage Boundary

This run checks the supplied kit artifact, built-in receipt vectors,
bundled sample receipt, bundled sample audit chain, the bundled issuer-status
fixture, the bundled trusted issuer registry fixture recognition path, and any
supplied synthetic engagement receipt or chain. It does not prove routed
coverage, human attendance, external time anchoring, live active issuer status,
key custody, revocation truth, production trust-registry state, production
downstream recognition, production signing identity, hardware-rooted signing,
policy replay, or broad agent governance.

If no actual non-operator runner performed the flow, keep this line:

```text
No external attestation is claimed for this run unless a real non-operator runner fills, signs, or publishes the result.
```
