# Suites that need private material

This public repository starts on 2026-09-27 with a single snapshot. Earlier
development history, and the founder's working folders, are private.

The suites listed in `tests/requires-private-history-test-suites.txt` need one of
two things this repository doesn't contain, so they can't run here.
`tests/count-assertions.sh` records them as skipped, with the reason "needs private
history or workspace".

**The private development history.** These suites check files against specific
earlier commits and tags: they read exact bytes from those commits, or confirm
that a tag points where a record says it does.

- `test-current-machine-approval-intake-cli.mjs`
- `test-current-machine-approval-intake.mjs`
- `test-current-machine-approval-packet-cli.mjs`
- `test-current-machine-approval-packet.mjs`
- `test-current-machine-approval-request-preview-cli.mjs`
- `test-current-machine-approval-request-preview.mjs`
- `test-current-machine-governance-preview.mjs`
- `test-future-installer-retired-source-residue-cleanup-v0.mjs`
- `test-legacy-runtime-v1-e3-source-disposition-overlay-v0.mjs`

**The founder's private workspace.** These suites expect private folders
(`ZLAR-Draft/`, `ZLAR_Website/`) to sit next to the repository.

- `test-zlar-owned-runner-cli.sh`
- `test-zlar-source-transport-movement-report.mjs`
- `test-zlar-source-transport-preflight.mjs`

Skipping them here is not a claim that what they check is broken, and not a claim
that it holds in this checkout. The code they exercise is unchanged and still
here. Only the material they compare against is missing.

## The two cedar-poc suites

`cedar-poc/test.mjs` and `cedar-poc/test-e23.mjs` need their dependencies
installed first:

```bash
cd cedar-poc && npm ci
```

CI does this before running the suite.
