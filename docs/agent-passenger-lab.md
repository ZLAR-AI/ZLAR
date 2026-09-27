# Agent Passenger Lab

`zlar agent-passenger-lab` runs a local fixture governed-crossing test harness.
It models different agent roles as passengers moving through the airport and
records the crossing shape they expose.

The harness does not spawn live agents. It does not inspect private reasoning,
surveil model thoughts, create authority, prove current-machine governance,
prove production governance, create external attestation, or upgrade a public
claim.

## Run

```bash
bin/zlar agent-passenger-lab
bin/zlar agent-passenger-lab --json
bin/zlar agent-passenger-lab --json-out ./zlar-agent-passenger-lab-v1.json
```

## Observation Contract

The harness observes this route shape:

```text
proposal -> action_class -> route -> authority_topology -> receipt_request -> verifier_result -> effect_or_refusal
```

It explicitly excludes private model reasoning, hidden chain of thought, live
surveillance, and agent votes as authority.

The invariant is simple:

```text
observation may improve maps, tests, and claim ceilings
observation may not create authority
```

## Passenger Roles

The local fixture includes these instrumented passenger roles:

- builder agent
- adversarial agent
- semantic-laundering agent
- formal verifier agent
- policy reviewer agent
- privacy reviewer agent
- operations agent
- external-attestation reviewer
- human-proxy pressure tester
- mis-issuance attacker

Each role stresses a different crossing. The useful output is not what the
passenger believes. The useful output is the attempted route, the action class,
the authority topology, the requested receipt, and the verifier result.

For builder implications, map those observations through
[`builder-formal-methods-bridge.md`](builder-formal-methods-bridge.md).

## Learning Surface

The report exposes:

- action classes discovered
- semantic disguises seen
- human-proxy pressure attempts
- authority-laundering attempts
- duplicate refusal noise
- missing route candidates
- whether any claim-ceiling update still requires a normal evidence gate

Those observations are traffic. They are not permission. They can become map
updates, tests, or future claim-ceiling inputs only through ordinary ZLAR
evidence gates.

## Claim Boundary

`zlar-agent-passenger-lab-v1` is local fixture evidence only.

It does not claim:

- live agent probing
- private-reasoning observation
- current-machine governance
- production governance
- external attestation
- public recognition
- all-surface or unrouted-surface coverage
- human authority created by agent behavior
