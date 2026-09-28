# Known failures on a fresh copy

Run the full suite with `bash tests/count-assertions.sh`. On a fresh copy of this
repository, two older checks are known to fail. Neither points at broken
protection code. A failure not listed here is new, and worth reporting.

## `tests/test-public-privacy.sh`: 2 of 58 fail

Both flag the same thing: the Demo 1 installer
(`demos/zlar-destination-gate/demo1-install.py`) and its test name the founder's
own Node.js location, a path under `/Users/`. The installer's exact bytes are
locked by `demos/zlar-destination-gate/PRODUCT-MANIFEST.json` and by the evidence
from the August 2026 installed run, so changing the path would break that record.
The privacy guard is right to flag it. The path is known and kept on purpose.

## `tests/test-citation-integrity.mjs`: 35 references don't resolve

This check confirms that every file or section a document names actually exists
in the repository. The 35 it can't find fall into five groups:

- **Files that exist only on an installed machine,** such as the first design's
  settings, its policy signing key and its trust state, or Demo 1's authority
  roots. Installing ZLAR's first design or Demo 1 creates them. They're never
  committed.
- **Files a command writes when you run it,** such as the dry-run result and the
  JSON reports named in `docs/cli-reference.md`.
- **Files inside the packaged verifier kit,** such as its examples and its
  engagement bundle, which the kit's own documents name relative to the kit.
- **Section numbers in a neighbouring document.** `spec/CONFORMANCE.md` and
  `tools/verifier-kit-src/README.md` cite sections of `spec/CONFORMANCE.md`
  itself, and the checker looks for them in a different file.
- **Files in the founder's private workspace,** which sit next to the repository
  on the founder's machine. The checker finds them there and nowhere else, so
  on the founder's machine the count is 34.

One more is a working note that was never part of this repository. ADR-012 names
it and says so.

None of the 35 points at a file that was removed from this repository.

## A failure your own change may cause

If you change a file in `cyan/` or in `demos/zlar-destination-gate/`,
`tests/test-file-identity-agreement.mjs` fails on Demo 1's identity record until
you re-record it. That's expected. [CONTRIBUTING.md](../CONTRIBUTING.md), under
"Changing the force field", explains how.

## Checks that skip instead of failing

- **`cedar-poc/test.mjs` and `cedar-poc/test-e23.mjs`** need
  `cd cedar-poc && npm ci` first.
- **`tests/test-v1-envelope-integrity.mjs`** skips until the verifier kit is
  built with `tools/build-verifier-kit.sh`.
- **`tests/test-hook-contract.sh`** skips on a machine where ZLAR's first design
  is installed and switched off.
- **Suites that need private material** (the private development history, or the
  founder's working folders) are listed in
  [`REQUIRES-PRIVATE-HISTORY-SUITES.md`](REQUIRES-PRIVATE-HISTORY-SUITES.md).

The suite needs `bash`, `jq`, `openssl` with Ed25519 support, and Node.js 22.
