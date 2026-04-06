# ADR-001: Deterministic Enforcement, Not AI

Status: Accepted
Date: 2026-03-01
Author: Vincent Nijjar

## Context

AI agent governance requires an enforcement layer that decides whether an action proceeds. The industry default is to use AI models (trust scoring, behavioral analysis, intent classification) in the enforcement path. This creates an architectural contradiction: the entity doing the reasoning can be attacked by reasoning. A sufficiently capable agent can persuade, confuse, or manipulate an AI-based enforcement layer.

The biological analogy is instructive. An immune system that reasons becomes an autoimmune disorder — it attacks what it should protect, and protects what it should attack.

## Decision

ZLAR uses deterministic, rule-based enforcement only. No language models, no neural networks, no statistical classifiers, no trust scores in the decision path. Policy rules are pattern matches evaluated by bash conditionals and regex. The gate does not understand what an action means. It matches what an action is against what the policy says.

If a rule matches, the gate knows what to do. If no rule matches, the gate denies (fail-closed) or escalates to a human. At no point does the gate reason about whether an action is acceptable.

## Consequences

- The gate cannot be subverted by prompt injection, social engineering, or adversarial reasoning. There is no reasoning to attack.
- False positives are possible. A legitimate action that matches a deny pattern will be denied. The human reviews and overrides. This is a feature, not a bug — it forces the system toward explicit permission rather than implicit trust.
- Policy authoring requires specificity. Rules must enumerate what they match. There is no "figure out if this looks dangerous." This constrains what can be governed to what can be described as a pattern.
- Adding new governance capabilities requires new rules, not model retraining. Rules are auditable, versionable, and signable. Models are none of these things.
