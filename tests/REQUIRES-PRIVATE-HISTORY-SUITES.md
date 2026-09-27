# Suites that need the private development history

This public repository starts on 2026-09-27 with a single snapshot. Earlier
development history is private.

The suites listed in `tests/requires-private-history-test-suites.txt` check files
against specific earlier commits and tags: they read exact bytes from those
commits, or confirm that a tag points where a record says it does. Those commits
aren't in this repository, so the suites can't run here. `tests/count-assertions.sh`
records them as skipped, with the reason "needs private development history".

They pass in the private history repository. Skipping them here is not a claim
that what they check is broken, and not a claim that it holds in this checkout.

The code they exercise is unchanged and still here. Only the historical evidence
they compare against is missing.

## The two cedar-poc suites

`cedar-poc/test.mjs` and `cedar-poc/test-e23.mjs` need their dependencies
installed first:

```bash
cd cedar-poc && npm ci
```

CI does this before running the suite.
