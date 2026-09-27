# ZLAR

**Capable was never supposed to mean allowed.**

For all of history, those two came as a pair. If you had the key, you could open
the door. If you knew the password, you could move the money. Nobody noticed,
because the only ones holding keys were people.

Now we're handing keys to machines.

Want an AI to pay your bills? Give it your bank login. Now it can do anything
your bank login can do. That isn't because you agreed to any of it. It's because
nothing stands between *able* and *allowed*.

So the world is stuck with two options. Keep AI outside, where it's safe and not
much use. Or let it in with everything, where it's very useful and quietly
terrifying.

AI is becoming a force of nature, like the wind: strong, everywhere, and not
something anyone is going to put on a leash. ZLAR doesn't try to control it or
change its mind. ZLAR is a third option, and it turns out to be surprisingly
simple.

---

## A few things that turn out to be simple

**You don't need to know what the AI wants.**
Brilliant people are working hard to make AI want the right things. We hope they
succeed. But banks worked out long ago that you don't need every teller to have a
pure heart. You need the vault to need two keys. ZLAR works on the day the AI
wants the wrong thing, and it never needs to find out what the AI wants.

**The AI can read this whole page.**
Everything about how ZLAR works is written down here and in the code. The AI is
welcome to study all of it. Knowing exactly how a combination lock works still
doesn't tell you the combination.

**Smarter doesn't mean more allowed.**
Think of the AI as a power plant: a million volts today, a billion next year. The
thing you care about is a light bulb. ZLAR keeps the wire cut until the right
people close it. A billion volts across an open circuit lights exactly as many
bulbs as one volt: none.

**Most of what AI does needs no permission at all.**
Reading, thinking, planning, comparing and drafting all run untouched and at full
speed. ZLAR only stands at the few moments where something real changes: money
moves, a record is rewritten, code ships, a door unlocks.

**The human isn't "in the loop." The human holds a key.**
"Human in the loop" made sense when there was one loop. Picture a superintelligence
doing ten million things a second. Where exactly is the human supposed to stand?
The answer is at the lock, not in the loop. People decide who holds which keys,
and they turn them only for the moments that truly need a person.

**A missed call isn't a yes.**
If the person with the key doesn't answer, nothing happens. Silence never turns
into permission. And in ZLAR's design, a key that isn't renewed simply stops
working.

**Good behavior isn't a credential.**
Some systems give an AI a trust score and let it do more as it behaves well.
That's also exactly how a patient con artist works. ZLAR doesn't keep score.
Either the right people turned their keys for this exact thing, or it doesn't
happen.

**Watching isn't stopping.**
Much of today's AI safety is monitoring: logs, dashboards, alerts. A security
camera will record a burglary in beautiful detail. ZLAR is about there being no
burglary to record.

**A stolen key doesn't produce a theft. It produces nothing.**
In our test wallet, a thief with a perfect copy of the owner's key tries to empty
the account. The wallet doesn't refuse him, and it doesn't have to. What he sent
isn't a transaction, just half of one. There's no guard to sneak past, because
there's nothing to guard. Not one dollar moves.

**Brakes are why cars are allowed to go fast.**
Nobody lets a car onto the highway because it promises to drive carefully. It's
allowed on because it can stop. Once the few things that matter can't happen
without the right people, you can let everything else go as fast as it likes.

---

## What ZLAR builds: a force field

This is the design. Parts of it are built and working today, and parts are not
yet. Both lists are below.

Around each thing that matters, whether an account, a record, a software release
or a machine, ZLAR puts a force field.

Outside it, the AI is free. It can research, reason, plan and prepare the whole
action down to the last comma.

Inside, nothing changes until the right people turn their keys. The rule can be
one person, any two of three, or all three. (Today's code does one person or one
fixed pair; the rest is on the list of work below.) If the rule says Alex, Ben and Cole
must all agree, then Ben and Cole can't open it without Alex, and neither can the
most persuasive AI ever built.

Each key is issued for an exact purpose, either one action or a set budget, and it
can't be stretched to cover anything bigger. Copy it all you like: a copy can never
do more than the original was allowed to, and a one-time key works only once. To a
thief, a spent key is worth nothing.

The protected thing signs its own record of what it allowed and what it refused,
each entry chained to the one before, so an entry removed or altered afterwards
shows. Anyone can check that record without taking our word for it. You
don't have to trust the AI, and you don't have to trust us either.

The force field lives with the thing being protected, not next to the AI. That
detail is the whole trick. A guard standing next to the AI can be argued with,
fooled, or walked around. A force field around your money doesn't care who's
asking.

The properties every ZLAR key follows are written down in
[ZLAR's Principles](PRINCIPLES.md).

---

## If I'm right about this

If I'm right, this is a very big deal.

People keep the two powers that matter most: the power to say **no** (a veto) and
the power to say **yes** (consent). No machine picks up either one by accident,
however capable it becomes.

The worst an AI can do shrinks to the size of the key you handed it, not the size
of the intelligence holding it. And once the worst case has a size, you can
finally say yes to a lot more.

A farmer in Malawi and a farmer in Manitoba get the same deal: let the AI run the
irrigation, the orders, the paperwork and the insurance claims, at full speed.
The one thing it can't do without them is sell the farm.

That's the road to abundance. Not holding AI back, but letting it go, because the
few doors that matter only open for the people who live behind them.

It doesn't change as things get bigger. The same rule protects one bank account
or a billion of them, one small program or something far smarter than us. No one
has to hold a master switch. Every house keeps its own keys.

---

## What already works

These pieces are real, and deliberately small. Each one proves one part of the idea.

- **The wallet that a stolen key can't rob.** A test wallet needs two signatures,
  and one of them is held apart from the AI. A perfect copy of the owner's key
  fails. So does a signature copied from an earlier payment, and so does a fully
  hijacked AI. Run it yourself, no setup needed (tested on Node.js 22):

  ```bash
  node cyan/demo-theft.mjs
  ```

  This is a model wallet in code, not a real bank or blockchain.

- **One protected action, installed and live.** In August 2026, on my own
  computer, an AI with every permission tried to promote a software release and
  was refused. I then approved it once, with a hardware key that needs a PIN and a
  physical touch, and it happened exactly once. Reusing that same approval was
  refused. The protected service signed a record of all three outcomes, and the
  record can be checked offline. That's one harmless action on one machine. The
  details are in [demos/zlar-destination-gate](demos/zlar-destination-gate/).

- **This repository protects itself.** Pushing changes to it from my computer
  takes a hardware key, a PIN and a physical touch, every time. An AI on the same
  computer, with every permission, gets turned away. The first thing ZLAR
  protected was ZLAR.

- **Budgets and combinations, in the reference code.** Standing permission with a
  budget: many separately allowed actions can't add up past the limit. Two steps
  that are each harmless are refused when, together, they cross a line the owner
  declared. A key handed on can only shrink, and every key must expire. These are
  tested in code (`node cyan/test-cyan-composition.mjs` prints what it proves),
  not yet installed or used in a real system.

---

## What isn't built yet, and where you come in

This is the honest gap between the idea and the code. It's also the work.

**Engineering**

- **More than one key-holder.** "Any two of Alex, Ben and Cole," or "all three."
  Today the rule is one person, or one fixed pair.
- **Budgets in real use.** "Up to $100 in total, across as many purchases as
  needed" works in the reference code. The installed demonstration still uses
  one-time keys. Budgets haven't been installed or tried on a real system.
- **Small steps that add up, in general.** The reference code refuses combinations
  the owner declared in advance. Catching combinations nobody thought to declare,
  or combinations spread across different houses, isn't solved.
- **One key, two doors.** This is a known break. In testing, one key worked at two
  separate checkpoints guarding the same thing, and it needs closing.
- **Renewal in practice.** In the reference code every key must expire, and an
  expired key simply stops, with no cancel message needed. Renewing keys smoothly
  on a real system isn't built. It's what makes the whole thing hold when people
  are asleep, away, or out of contact.
- **Keys in everyone's hands.** Today the hardware keys are mine. This needs to
  work for anyone, on devices they already own.
- **Real things to protect.** Payments, software releases, records, access and
  machines. Today there are demos, and the next step is real systems.

**Proof**

Here is the big claim: no chain of steps, however long or clever, can add up to
permission that nobody granted. Right now that's a conjecture, not a theorem, and
it needs to be proven or broken. Mathematicians, cryptographers, and people who
enjoy finding holes are especially welcome.

**The people side**

The key has to be held by the right person, meaning the one who lives with the
consequence. That person also has to stay able to mean it: not buried in
requests, not rushed, not tricked, not impersonated. Some early checks exist
([`lib/human-invariants.sh`](lib/human-invariants.sh)), but most of the thinking
is still ahead.

**The houses**

A force field only works if the owner of the thing installs it. Engineers can
build a perfect one, but they can't make a bank, a hospital or a payments network
put it in. If you own or run something worth protecting, you're who we most want
to meet.

---

## What's in this repository

It grew in layers, so here's the map.

| Where | What it is |
|---|---|
| [`PRINCIPLES.md`](PRINCIPLES.md) | **ZLAR's Principles**: the properties every key follows. |
| [`cyan/`](cyan/) | **The heart.** The force field in code: one-use keys, the wallet, the signed records and the Demo 1 service. Start here. |
| [`demos/zlar-destination-gate/`](demos/zlar-destination-gate/) | Demo 1: the installed version, plus the evidence from the August run. |
| [`spec/`](spec/) | Written rules that an implementation has to meet. |
| `bin/`, `lib/`, `adapters/`, `mcp-gate/`, `sdk/`, `tests/` | **ZLAR's first design**: a checkpoint that sits next to the AI and asks a person before its actions go through. It works, and it taught us the most important lesson here: the protection belongs with the thing being protected, not next to the AI. It's worth reading, but it isn't where things are heading. How to install and test it: [`docs/first-design-install.md`](docs/first-design-install.md). |
| [`docs/`](docs/) | Deeper material, including the full technical manual for the first design ([`docs/technical-reference.md`](docs/technical-reference.md)). |
| Everything else | Earlier experiments. |

This public repository starts on 2026-09-27 with a snapshot of the work so far.
The earlier development history is kept privately; documents here sometimes cite
commit IDs from it.

A lot has already been tried here. The fastest way in: point your AI at this
repository. [AGENTS.md](AGENTS.md) teaches it where everything is and what's
already been done.

---

## Come build it

ZLAR is a company, ZLAR Inc., and we're looking for the people who will build it
with us: engineers, mathematicians, security researchers, and people who own
something worth protecting.

I'm not looking only for people who agree with me. I'm looking for people who can
see the problem clearly enough to show me where I'm wrong, and then help build
whatever survives.

There are two ways in:

- **Join us.** If this is the problem you want to spend years on, write to
  **hello@zlar.ai**. The list of what isn't built yet is the work.
- **Challenge us.** Hard questions, counterexamples, failing tests and better
  explanations are all welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

Found a security problem? Report it privately through [SECURITY.md](SECURITY.md).

Want your AI to explain this repository to you? Point it here. There's a reading
guide written for AI in [AGENTS.md](AGENTS.md).

**About the license:** read it, download it, run it, try to break it: all
welcome, and the [LICENSE](LICENSE) says so. Using it for real work, building
products on it, or passing on changed copies needs a written yes from us. Write
to **hello@zlar.ai**.

— **Vincent Nijjar**, founder, ZLAR Inc.
