# Superseded Source-Bound Test Suites

This inventory is source-snapshot routing metadata, not authority metadata and
not permission to ignore regressions.

The following integration suites reconstruct exact source bytes from historical
commit `e7c621927df35eb31cf3f0dfc1ea2a42df6d5dd5`; the reachability suite also
requires its private immutable parent map:

- `test-consequence-path-coverage-dependency-map-v0.mjs`
- `test-source-bound-static-reachability-delta-v0.mjs`

The later `legacy-runtime-v1-governed-disposition-v0` source checkpoint
intentionally replaces those exact CLI bytes with a permanent refusal. The old
artifacts and libraries remain byte-pinned historical evidence and are not
regenerated or edited to pretend they describe the new source. The integration
test reconstructs the exact historical source through
`tests/source-bound-historical-source-v0.mjs`. No durable positive source copy
is added: the helper reads the exact existing Git blobs into an OS-temporary,
non-executed analyzer root and removes that root through normal `try/finally`
cleanup. Abnormal termination or power loss can leave temporary residue, so
cleanup is not a crash-durability claim. Both suites
pass locally and separately require the new checkout to refuse as source drift.
`tests/count-assertions.sh` records them as superseded in a standalone checkout
because shallow/public clones need not contain the historical Git object and
the private parent is intentionally not copied into repository source.

`test-legacy-runtime-v1-governed-disposition-v0.mjs` was the additive current,
standalone-portable suite at the direct-entry checkpoint. The later
`legacy-runtime-v1-direct-factory-disposition-v0` checkpoint replaces the
exported v1 factory body with a fixed refusal. The old suite and artifact remain
unchanged historical evidence; the new direct-factory suite pins their exact
identities and validates the current source refusal without executing the old
positive factory path. Private artifact bytes are revalidated in the local
Draft packet rather than required in public CI.
