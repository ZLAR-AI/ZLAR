# External Runner Flow

This file is a privacy-safe helper for a clean-room ZLAR Verifier Kit run.
It is not external attestation, not a public release claim, and not proof
of routed coverage. A real attestation requires an actual non-operator
runner to complete the flow and return their result under their own
authority.

## Inputs

The runner should receive:

- `zlar-verifier-kit-v0.1.0.tar.gz`
- `zlar-verifier-kit-v0.1.0.tar.gz.sha256`
- Optional `engagement-bundle/engagement-receipt.json`
- Optional `engagement-bundle/engagement-pubkey.pub`
- Optional `engagement-bundle/engagement-chain.jsonl`

The runner does not need the ZLAR source repository, npm, internet access,
ZLAR credentials, private keys, live Telegram, real chat IDs, or real
human IDs.

## Environment

Required:

- Node.js 18 or newer
- `tar`
- `sha256sum` on Linux, or `shasum` on macOS
- A shell

Optional:

- `openssl version` for environment reporting only. A missing OpenSSL CLI
  is not a failure for a prebuilt kit run.

## Manual Flow

Run these commands from the directory containing the tarball, sidecar, and
optional `engagement-bundle/` directory.

```bash
pwd
uname -a
node --version
tar --version
openssl version
```

On Linux:

```bash
sha256sum -c zlar-verifier-kit-v0.1.0.tar.gz.sha256
```

On macOS:

```bash
shasum -a 256 -c zlar-verifier-kit-v0.1.0.tar.gz.sha256
```

Expected sidecar output:

```text
zlar-verifier-kit-v0.1.0.tar.gz: OK
```

Then run:

```bash
tar xzf zlar-verifier-kit-v0.1.0.tar.gz
cd zlar-verifier-kit-v0.1.0
node verify-test-vectors.mjs
node verify.mjs examples/sample-receipt.json --pubkey spec/test-key.pub
node verify-chain.mjs examples/sample-chain.jsonl
```

Expected clean-path snippets:

- `ALL VECTORS MATCH SPEC EXPECTATIONS`
- `VALID`
- `Result: INTACT`

If an engagement bundle was provided, also run:

```bash
node verify.mjs ../engagement-bundle/engagement-receipt.json --pubkey ../engagement-bundle/engagement-pubkey.pub
node verify-chain.mjs ../engagement-bundle/engagement-chain.jsonl
```

Expected engagement snippets:

- `VALID`
- `Result: INTACT`

## Dry-Run Helper

After unpacking the kit, the helper can run the kit-local checks and
produce a compact pass/fail transcript. It runs after the tarball has
already been unpacked, so it does not verify the tarball SHA-256 sidecar.

Without an engagement bundle:

```bash
bash external-runner-dry-run.sh
```

With an engagement bundle beside the extracted kit:

```bash
bash external-runner-dry-run.sh --engagement-dir ../engagement-bundle
```

The helper does not replace a human result. It simply reduces command
drift and records the same bounded checks in one place.

## Result To Return

Use `EXTERNAL-RUNNER-RESULT-TEMPLATE.md` as the return shape. Include:

- Runner name or pseudonym and relationship to ZLAR.
- Date completed and approximate time spent.
- OS, architecture, shell, Node version, tar version, SHA tool, and
  OpenSSL version if available.
- SHA-256 values for the kit tarball and engagement files, using `N/A`
  for engagement files if no engagement bundle was supplied.
- Each command, exit code, and relevant output.
- Any README or packet friction.
- Verdict: PASS, PARTIAL, or FAIL.

PASS means the required commands matched expected output with exit code 0
and the runner did not need source inspection or real-time usage coaching.

## Coverage Boundary

This flow checks the kit artifact, built-in receipt vectors, a bundled
sample receipt, a bundled sample audit chain, and any supplied synthetic
engagement receipt or chain. It does not prove routed coverage, human
attendance, external time anchoring, production signing identity,
hardware-rooted signing, policy replay, or broad agent governance.

If no actual non-operator runner performed the flow, say:

```text
Not externally attested yet.
```
