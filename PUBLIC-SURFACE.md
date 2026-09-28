# What's public

**Updated 2026-09-27.** This replaces an August 2026 draft that planned to
publish only a small verifier kit and keep everything else closed. That plan is
retired. The earlier version is still in this repository's history.

## Today

- **This whole repository is public to read.** Anyone can see the code, the
  tests and the documents. The public history starts on 2026-09-27 with a single
  snapshot. Earlier development history is kept privately, and documents here
  sometimes cite commit IDs from it.
- **The license lets people read and evaluate.** The [LICENSE](LICENSE) lets
  anyone download the code and run it on their own computer to study and try it.
  Using it for real work, providing it as a service, or distributing changed
  copies needs written permission from ZLAR Inc. or Vincent Nijjar. Write to
  hello@zlar.ai.
- **Earlier open-source releases stay open.** ZLAR source that was released under
  the Apache License 2.0 before the license changed remains under that license.
  The text is kept at
  [`LICENSES/Apache-2.0-prior-public.txt`](LICENSES/Apache-2.0-prior-public.txt).
- **The checking tools are open.** Since 2026-09-27 the [LICENSE](LICENSE) puts
  the checking tool, the written rules it checks against, and the force field's
  record format under the Apache License 2.0, so anyone can check ZLAR's records
  without trusting ZLAR. The LICENSE lists the exact files. Everything else stays
  under the evaluation license.
- **The verifier kit is still built and published separately.**
  [`tools/build-verifier-kit.sh`](tools/build-verifier-kit.sh) packages the files
  someone needs to check a ZLAR receipt without trusting ZLAR. The kit states its
  own license (Apache 2.0) inside it, and
  [`tests/test-public-surface-boundary.sh`](tests/test-public-surface-boundary.sh)
  checks that the kit contains exactly the files it declares, and nothing else.

## What never goes in this repository

Everything here can be read by anyone, forever. Public copies can't be recalled.
So none of the following belongs here:

- private keys, signing material, passwords or tokens;
- personal information about anyone;
- logs or records of real decisions made on anyone's machine;
- the state of any installed system;
- business plans.

The repository checks some of this automatically:
[`tests/test-public-privacy.sh`](tests/test-public-privacy.sh) looks for private
file paths, hardware serial numbers, personal identifiers, secret-shaped strings,
and claims stronger than the evidence.

## Before adding anything new

Ask one question: **would we be comfortable with anyone in the world reading this,
permanently?** If the answer isn't a clear yes, it doesn't go in.
