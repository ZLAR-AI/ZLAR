# Public Privacy And Claim Guard

This guard keeps tracked public surfaces from quietly carrying private operator
details or stronger public claims than the repo evidence supports.

The CI loop runs `tests/test-public-privacy.sh` through the normal assertion
harness. That script scans current public narrative docs, authority docs,
spec/verifier-kit docs, GitHub metadata/templates, public sample
profiles, demos, and committed fixture surfaces where a fixture leak would be
visible to public readers.

## Covered Surfaces

The guard scans these tracked repo surfaces:

- current public narrative: `README.md`, `SECURITY.md`,
  `LEGAL.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and
  `AGENTS.md`;
- documentation and authority surfaces: `docs/`, `spec/`, and
  `tools/verifier-kit-src/`;
- public sample and demo surfaces: `profiles/` and `demos/`;
- GitHub metadata and templates under `.github/`;
- committed fixture surfaces under `tests/fixtures/`, with fixture checks kept
  to shapes that should not appear even in evidence fixtures.

## Guarded Shapes

The guard rejects:

- private absolute local paths outside narrow placeholders;
- fixture role fields that name the operator instead of a role;
- hardware serial numbers and security-key serial wording;
- machine model names in guarded public docs;
- numeric Telegram or human authorizer identifiers;
- token, secret, bearer, or API-key shaped strings in guarded public docs;
- unsupported production, adaptor, enterprise-readiness, live-coverage,
  current-machine, sovereign-recognition, or public-attestation claim wording;
- unsupported recognition-status wording that turns local fixture receipt
  recognition into external, live, production, or public-infrastructure
  recognition.

Use role language in examples and fixtures: `operator`, `authorizer`,
`external_verifier`, or `non_operator_reviewer`.

## Allowlist Policy

The allowlist lives at `tests/public-privacy-allowlist.txt`. Entries are matched
against `git grep` output in `path:line:content` form.

Allowlist entries must be:

- path-scoped;
- narrow enough to explain the exact placeholder or preserved provenance;
- tight enough that a matching placeholder line cannot also carry another
  private path, secret, identifier, or overclaim;
- unsuitable for real secrets, real hardware identifiers, numeric human IDs, or
  public-claim widening.

Legitimate founder, maintainer, author, and public sender attribution remains
allowed. The guard does not ban all `Vincent`, `Claude`, or Telegram mentions.
Claude and Telegram wording is valid when it accurately describes a bounded
adapter, transport, historical, or disabled-by-default state.

Synthetic adversarial inputs inside tests may still contain bad-looking strings
when the test is proving redaction or refusal. Do not promote those strings into
public docs, public examples, or committed output fixtures.

## Out Of Scope

`CHANGELOG.md` is preserved release/provenance history, not the current public
claim surface. Historical entries may contain maintainer-local observations,
retired transport names, old placeholder paths, or wording that was accurate for
the release being recorded. Do not rewrite history just to satisfy a current
guard. New changelog entries and public release preparation still must pass the
privacy/claim guard unless a specific historical exception is reviewed and
documented. The guard scans the active changelog window, meaning `## Unreleased`
plus the newest release entry, while leaving older release entries as preserved
history.

`ZLAR_Website/` is a separate versioned website repo and is not scanned by this
core-repo guard. Website alignment remains a separate publication step and must
run its own review before publication.

This guard does not authorize edits to signed or policy artifacts under `etc/`,
website publication, tags, releases, verifier contact, secrets/signing material,
service activation, or machine configuration.

## Release Readiness

Before public tag, GitHub Release, or website alignment, `bash
tests/test-public-privacy.sh` must pass for the release candidate commit. A
passing guard is not publication authority, not privacy certification, and not
external attestation. It is the CI refusal line for obvious public privacy leaks
and unsupported public claims in the guarded core-repo surfaces.
