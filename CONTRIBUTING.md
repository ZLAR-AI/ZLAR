# Contributing to ZLAR

ZLAR is building a way for AI to become as capable as it likes without that
capability quietly turning into authority. The [README](README.md) explains the
idea. This page explains how to help.

You don't have to arrive convinced. A clear argument that something doesn't hold
is as valuable as new code.

## Two ways in

- **Join the company.** ZLAR Inc. is looking for the people who will build this
  with us: engineers, mathematicians, security researchers, and people who own
  something worth protecting. If this is the problem you want to spend years on,
  write to **hello@zlar.ai**.
- **Challenge the work.** Open an issue with a question, a counterexample, a
  failing test, or a better explanation.

## Finding your way around

A lot has already been tried here. The fastest way in: point your AI at this
repository. [AGENTS.md](AGENTS.md) teaches it where everything is and what's
already been done, and it's a good reading path for people too. The
[README](README.md)'s "What isn't built yet" and its map are the other quick
start.

For bigger ideas, open an issue and tell us what you're thinking. We'll point you
to anything related that already exists.

## Open questions, and the minds we need

[ZLAR's Principles](PRINCIPLES.md) are the properties we're trying to keep. We
don't know yet that all of them can hold together, at every scale, against
someone actively trying to break them. Finding out is the work. If you can show
that one of them fails, you may be the contributor we most need.

- **Cryptographers and protocol people:** try to break the keys: copying, replay,
  stretching a key to cover more, or separating a key from the one action it's
  bound to.
- **Distributed-systems engineers:** one key must be spent once even across many
  checkpoints, under concurrency, crashes and network failures. That's the known
  "one key, two doors" break (`node cyan/test-cyan-negative-vectors.mjs` reports it
  on purpose).
- **Security engineers:** look for side doors, meaning any way to reach a
  protected thing without its key.
- **Mathematicians and formal-methods people:** prove or break the conjecture that
  no chain of allowed steps can add up to authority nobody granted.
- **Systems and product engineers:** bring a real system (a payment flow, a
  release pipeline, a record store) and work out where its force field belongs.
- **Human-factors researchers:** can the people holding keys keep real authority
  under volume, pressure, fatigue and deception?
- **Writers:** find any sentence that claims more than the code shows.
- **Skeptics:** bring counterexamples.

**If your expertise isn't listed here, come anyway.** Tell us what you see.

## Where the work is

The live list is the repository's
[issues](https://github.com/ZLAR-AI/ZLAR/issues). Issues labeled
[good first issue](https://github.com/ZLAR-AI/ZLAR/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
are small and well defined. Issues labeled
[help wanted](https://github.com/ZLAR-AI/ZLAR/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
are larger open problems. If you pick one up, leave a comment on it so others
know and can join you.

The quickest start needs no issue at all: run `node cyan/demo-theft.mjs`, then
try to make a stolen key, a copied signature or a hijacked AI move money. If you
find a way, report it privately (see below). That's a very big deal.

## What a strong proposal says

1. What real-world consequence it protects (money, records, code, access, a
   machine).
2. Where the authority comes from today, and who holds it.
3. Exactly which path the change protects.
4. Which other paths to the same consequence would still be open.
5. What evidence would show it works, and what evidence would show it doesn't.

## Running the code

The heart of ZLAR is in [`cyan/`](cyan/). It needs Node.js (tested on 22), with no
installs and no dependencies:

```bash
node cyan/demo-theft.mjs                 # the stolen-key wallet demo
node cyan/test-cyan.mjs                  # one-use keys and the guard
node cyan/test-cyan-theft.mjs            # theft scenarios
node cyan/test-cyan-receipts.mjs         # the signed record
node cyan/test-cyan-composition.mjs      # combining authority
node cyan/test-cyan-negative-vectors.mjs # known open problems, reported on purpose
node cyan/test-demo1-destination.mjs     # the Demo 1 protected service
```

ZLAR's first design, the checkpoint that sits next to the AI, has its own install
and test instructions in
[`docs/first-design-install.md`](docs/first-design-install.md).

**Changing the force field.** Demo 1's identity record,
[`demos/zlar-destination-gate/PRODUCT-MANIFEST.json`](demos/zlar-destination-gate/PRODUCT-MANIFEST.json),
fixes the exact bytes of every file in `cyan/` and in the Demo 1 folder. If your
change touches them, which most of the open issues will, the identity check fails
until you re-record it:

```bash
python3 -B demos/zlar-destination-gate/product_identity.py --write
python3 -B demos/zlar-destination-gate/product_identity.py --verify
```

Commit the updated record with your change and say so in the pull request. A
re-recorded identity is a new version of Demo 1. The August 2026 installed
evidence stays tied to what was installed then, in
[`demos/zlar-destination-gate/INSTALLED-MANIFEST-20260822.json`](demos/zlar-destination-gate/INSTALLED-MANIFEST-20260822.json),
and never describes the new version.

## What the code must protect

Some things are the point of ZLAR, and no feature is worth weakening them:

- Missing, invalid, expired, reused or mismatched authority means **no**.
- Silence is never a yes.
- A record of what happened never grants authority for what happens next.
- Nothing an AI produces can count as a person's authority.
- **When two paths exist, the stricter one wins.** If a path with fewer checks
  disagrees with a stricter one, it must refuse, or it must be removed.
- The people holding keys stay protected too: not flooded, not rushed, not
  impersonated. See the human invariants in
  [`lib/human-invariants.sh`](lib/human-invariants.sh).

The ZLAR check, in section 10 of [AGENTS.md](AGENTS.md), turns these and ZLAR's
Principles into ten questions anyone's AI can run on a proposal. The AI flags; a
person decides.

If one of these is wrong, argue it in an issue. Don't route around it in code.

## Code standards

- **JavaScript:** ES modules (`.mjs`), Node.js built-ins only, no npm packages
  in anything that decides or enforces.
- **Bash:** works on Bash 3.2 or later, passes ShellCheck, uses
  `set -euo pipefail`, depends on nothing beyond Bash, `jq` and OpenSSL.
- **JSON and policy:** valid JSON, and signed before it's used.
- Never weaken a refusal just to make a test pass.

## Pull requests

- One logical change per pull request.
- Say what changed, why it matters, how you tested it, and what remains unproven.
- Keep claims no stronger than the evidence in the pull request.
- A person reviews every change before it's merged.
- AI-assisted work is welcome. A human stays accountable for it and must
  understand it.

## Who decides

Vincent Nijjar, the founder, decides what goes in for now. As the founding team
forms, the way decisions are made will be written down here.

Significant design decisions are recorded in [`docs/adr/`](docs/adr/). They're
never deleted. When one is replaced, it's marked and points to its replacement.

Releases use version numbers the usual way: the last number for fixes, the middle
for new features that don't break anything, the first for changes that do.

## Terms

The code is published to read, and the [LICENSE](LICENSE) lets anyone download it
and run it on their own computer to study and try it, including offering changes
back as a pull request. Anyone may also test it, attack it and publish what they
find, without asking; for a way to break it, we ask for a private heads-up first
([SECURITY.md](SECURITY.md)). Anything beyond that needs written permission.

Before we can merge a code contribution, you accept the
[contributor agreement](CLA/INDIVIDUAL.md). It's in French and English, and each
version starts with a plain-words summary. You keep ownership of your work and
give ZLAR Inc. a permanent license to use it, including commercially or under an
open-source license later. It's one click: a bot posts the link on your first pull
request. If your employer owns your work, your employer signs the
[company version](CLA/ENTITY.md) instead. Ideas, questions and bug reports need no
agreement.

## Security

Don't open a public issue for a security problem. Follow [SECURITY.md](SECURITY.md).
