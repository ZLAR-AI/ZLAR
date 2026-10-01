# ZLAR FAQ

For prospective cofounders, CTOs, and engineers.

Last reviewed: October 1, 2026. Technical reference: [public source revision 9d77d59](https://github.com/ZLAR-AI/ZLAR/commit/9d77d59ceff424f85633ec2545d8cff90d957c1b).

These answers distinguish working reference code, bounded demonstrations, design intentions, and open questions. Historical installation evidence is dated August 22, 2026; it is not a statement about today's installed system. Commercial and collaboration proposals are not offers or commitments.

## Contents

- [The idea and the product — questions 1–6](#idea)
- [How the protection works — questions 7–20](#protection)
- [Who decides, and who is accountable — questions 21–34](#authority)
- [Changing conditions and limits — questions 35–43](#limits)
- [Human decisions and failure — questions 44–49](#human-decisions)
- [Evidence and independent evaluation — questions 50–61](#evidence)
- [Customers and the business — questions 62–71](#business)
- [Working with ZLAR — questions 72–78](#working-together)
- [Consent, agency, and transfer of authority — questions 79–83](#agency)

Question links use stable anchors, from [q-001](#q-001) to [q-083](#q-083). Question numbers stay the same when wording changes.

<a id="idea"></a>

## The idea and the product

<a id="q-001"></a>

### 1. What is ZLAR, what customer problem does it solve, and what practical difference would it make?

ZLAR is building software that helps people retain authority over what AI can change: money, records, software releases, access, and machines. An AI may have access to a system without having authorization for the particular action it proposes. ZLAR puts that check inside the protected system, where the action takes effect. The goal is more useful automation, with bounded authority and signed evidence of the protected outcome. Today, the evidence covers reference examples and one bounded installed demonstration; a general enterprise product remains to be built.

Public sources: [Overview](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/README.md); [Installed evidence and its limits](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md).

<a id="q-002"></a>

### 2. Why was ZLAR founded, and what is its long-term vision?

ZLAR was founded to protect human agency: people should keep a real say over actions taken for them or affecting what is theirs to decide. The long-term vision is that AI can become as capable as it likes and work freely, while consequential systems still require authority that AI cannot create for itself. That means preserving both the power to say yes and the power to say no, across models, vendors, and institutions. Making that universal, and keeping each human choice informed and voluntary, is a far larger undertaking than what the current demonstrations show.

Public sources: [Principles](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PRINCIPLES.md).

<a id="q-003"></a>

### 3. Is ZLAR an independent product company, a consulting service, or an initiative within another organization?

ZLAR is an independent company, ZLAR Inc., which its official website identifies as a Canadian corporation. It is developing a product and the authorization architecture behind it, and it is not an initiative inside another organization. Integration help and support could accompany the product, but ZLAR's current public material does not describe an operating consulting business or a finished commercial service.

Public sources: [Company information](https://zlar.ai/legal.html).

<a id="q-004"></a>

### 4. What exactly would a customer buy, and how can the same product serve multiple customers?

The proposed product protects a specific consequential action in a customer's system: enforcement at that system, bounded authorizations, signed records, and the integration and support to operate them. A reusable core would serve multiple customers while each keeps its own keys and rules. Each system still needs an integration suited to its effects, administrative paths, and reliability needs. ZLAR's license permits separately agreed commercial use, but the offer, price, support obligations, and acceptance criteria still need to be defined.

Public sources: [Current license](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/LICENSE).

<a id="q-005"></a>

### 5. What does ZLAR provide beyond existing identity, authentication, authorization, and access controls?

ZLAR is designed to tie a person's authority to one exact consequence and have the protected system enforce it. Think of the difference between giving someone signing authority on an account and handing them a check made out to one payee for one amount. Identity and access controls establish who is presenting credentials and what that login may do, which is often far more than anyone intended for this action. Existing tools already offer narrow scopes, expiry, transaction signing, and multiple approvals, and ZLAR builds on them. Its case rests on how completely the combination holds at the protected system: no route around the check, one-time use that is truly enforced, and rules that cannot be quietly changed.

Public sources: [The proposition](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PROPOSITION.md).

<a id="q-006"></a>

### 6. How does ZLAR differ from an agent framework, a wrapper around an agent, or a system that monitors its activity?

An agent framework organizes how an AI plans and uses tools, and a monitoring system records or analyzes what it did. ZLAR works at the other end: the protected system itself refuses any change that lacks valid authority. ZLAR's first design was a checkpoint next to the AI, and that code still works for traffic routed through it. But a wrapper cannot stop a route it does not control, which is why ZLAR moved the protection into the system being protected. Each integration still has to show exactly where a refusal prevents the effect.

Public sources: [First-design history](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/AGENTS.md#4-read-in-this-order).

<a id="protection"></a>

## How the protection works

<a id="q-007"></a>

### 7. What is a deterministic gate, and how does it work in a real system?

A deterministic gate applies explicit rules to the facts it is given and always returns the same answer for the same complete inputs, including relevant state and time. For example, it can refuse a software release whose bytes differ from the approved version or whose authorization has expired. ZLAR's first design used a gate that chose allow, deny, or ask a person. Its newer protected-system code checks signatures, exact scope, freshness, and prior use before accepting an action. Determinism makes a decision reproducible; it does not make the rules or the input facts correct.

Public sources: [Exact-action protocol](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo1-protocol.mjs).

<a id="q-008"></a>

### 8. Does AI participate in deciding whether an action is allowed, or is that decision made by deterministic rules?

In ZLAR's code, deterministic checks make that decision, not an AI model. People set the rules and hold the authority; software checks whether a request meets them. AI can help draft a rule or explain a request, but its output stays advice until the appropriate person adopts it through the approved process. Letting an AI's judgment stand in for the required authorization would undo the core of ZLAR's design.

<a id="q-009"></a>

### 9. Where does ZLAR enforce its decisions, and how does it integrate with an existing application or enterprise system?

ZLAR enforces its decisions inside the system that owns the effect, such as the service that publishes a release or accepts a payment. Integrating means making every route to that effect require the same authority, and making sure the AI cannot change the guard or its rules. ZLAR's installed demonstration did this with a separate local service for one harmless release step, and its model wallet requires two signatures before any transfer counts. Connecting real customer systems is integration work for each system; installing a hook on the AI's side does not achieve it.

Public sources: [Installed-source boundary](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/README.md); [Model wallet](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/wallet.mjs).

<a id="q-010"></a>

### 10. Where are execution credentials held, and what prevents an agent from bypassing ZLAR through a direct API call or another route?

The keys that carry authority are held apart from the AI. In ZLAR's installed demonstration, the person's authorization key sat on a hardware device needing a PIN and a physical touch, while the service's own signing keys and protected data were separated from the ordinary user account. In ZLAR's model wallet, a perfect copy of the owner's key produces only half a transaction, because an independently held second signature is required. A direct API call is blocked only if the protected system accepts no other credential and has no unprotected write path. Full compromise of the computer or its administrator is outside what the demonstration proves, and universal credential isolation has not been shown.

Public sources: [Installed-profile limits](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/CLAIM-CEILING.md); [Independent cosigner](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/cosigner.mjs).

<a id="q-011"></a>

### 11. How is permission bound to an exact action, its parameters, and its intended executor?

The authorization is a signed, precise description of the action: where it goes, who may perform it, its parameters or the fingerprint (hash) of the exact file, its limits, and its validity period. The protected system rebuilds that description for itself and compares, so any change to the approved bytes or action makes the authorization stop matching. In ZLAR's installed demonstration, this required both a person-signed grant and a narrower credential derived from it that could not enlarge it. There, the "intended executor" was an operating-system user account, not a cryptographically proven AI model or human.

Public sources: [Protocol and signatures](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo1-protocol.mjs); [Execution-domain limits](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/CLAIM-CEILING.md).

<a id="q-012"></a>

### 12. What is checked when an action is first proposed, and what is checked again at the system that executes it?

At proposal, the request must describe a well-formed action, and the protected system ties it to the current state. In ZLAR's installed demonstration, which protected one harmless software-release step, the service issued a signed challenge bound to the staged file and the current release state. A person then authorized that exact action, and a single-use credential was derived within that grant. At execution, the service checked everything again for itself: recognized signers, the link between grant and credential, the requesting account, the file, the time, the current state, and the remaining allowance. A client's claim that an earlier check passed never replaces those checks.

Public sources: [Destination checks](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo1-destination.mjs).

<a id="q-013"></a>

### 13. How would ZLAR work with the security controls already provided by cloud platforms?

ZLAR would work alongside cloud identity, network restrictions, secret storage, and application access controls. Those controls help isolate the protected system and close other routes to it; ZLAR adds a requirement for exact, person-originated authority at the consequential action itself. Each integration has to show how the cloud service enforces that requirement and how administrators can change it. Cloud platforms already enforce real controls, so the case for ZLAR must name the additional property a customer needs rather than assume those platforms only monitor.

<a id="q-014"></a>

### 14. Can ZLAR deliver value within one system, or does it depend on widespread integration across vendors and platforms?

ZLAR can deliver value within a single system, provided that system closes every route to a useful, clearly bounded action. A payment service or release pipeline can refuse unauthorized changes without waiting for any other vendor to adopt ZLAR. Wider adoption would make authorizations and records easier to carry between systems, though each receiving system still decides which authority it recognizes. One deployment does not show that combined actions across organizations are safe.

<a id="q-015"></a>

### 15. How would ZLAR govern delegated work and interactions among multiple agents?

Every delegated action must stay within authority already granted, with the same or narrower scope, time, destination, and shared spending limits. ZLAR's reference examples enforce narrowing and track cumulative effects against a budget within one accounting domain. A new worker must never reset the budget or let several workers each spend the parent's full allowance. Complete enforcement across delegation chains and separate systems is not established. One known break is concrete: a single-use credential can be used once at each of two checkpoints that keep separate records.

Public sources: [Delegation](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/grant.mjs); [Known two-checkpoint break](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/test-cyan-negative-vectors.mjs).

<a id="q-016"></a>

### 16. How would ZLAR govern continuously operating systems that do not act through discrete tool calls?

A continuously running system needs bounded authority over its ongoing effects, not a human prompt for every internal step. One possible design gives it a time-limited lease with operating limits and a planned response when the lease runs out, such as a controlled shutdown instead of an abrupt, unsafe stop. ZLAR's reference code already requires every authorization to expire. Reliable renewal, continuous physical control, and safe shutdown are not demonstrated, and each would need engineering and safety evidence for the actual system.

Public sources: [Expiring credentials](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/credential.mjs).

<a id="q-017"></a>

### 17. Which actions and environments can ZLAR protect, and what limits its scale?

ZLAR can protect an effect only where the accepting system correctly enforces its authority checks and closes alternative routes to that effect. The code names broad consequence classes, such as moving value, changing records, deploying code, and activating machinery, but naming a class is not the same as integrating it. Demonstrated coverage is narrow: a model wallet and one harmless installed release step. Scale depends on how many protected systems adopt it, consistent shared state, the capacity of the people deciding, reliability, and performance. No enterprise throughput figures have been established.

Public sources: [Consequence classes](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/envelope.mjs); [Demonstrated scope](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md).

<a id="q-018"></a>

### 18. Which technologies and platforms does ZLAR depend on, including any dependencies on the Microsoft stack?

ZLAR's current protected-system code runs on Node.js with standard cryptography. The installed demonstration also uses SQLite, macOS service separation, and a hardware authorization key; earlier components use shell tools, JavaScript, and integration-specific dependencies. The core design does not require Microsoft software, and using Microsoft identity or cloud services would be an integration choice. The installed demonstration is specific to its pinned macOS environment, so it does not show equal support on other platforms.

Public sources: [Runtime and source profile](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/README.md).

<a id="q-019"></a>

### 19. How does ZLAR relate to existing rule engines, semantic-web technologies, and governance systems that do not use language models?

ZLAR builds on established, non-AI security ideas: capabilities, least privilege, signed authorizations, and checks at the protected resource. A rule engine evaluates a policy, and semantic-web technologies represent concepts and their relationships; neither, on its own, makes the protected system refuse an unauthorized effect. ZLAR's earlier code even includes an option for Cedar, an existing policy engine. ZLAR's contribution should be judged as an enforceable combination of authority, exact action binding, one-time use, and verifiable records, rather than as an invention of rules or of non-AI oversight.

Public sources: [Earlier Cedar experiment](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cedar-poc/README.md).

<a id="q-020"></a>

### 20. Why use ZLAR instead of requiring a human to perform every consequential action?

People should be able to hand off useful work without doing every step themselves or giving away unrestricted access. ZLAR's model lets routine actions proceed automatically inside a bounded, expiring grant, while exceptional decisions come back to the right person. That can reduce interruptions while keeping the decisions that matter in human hands. Budgeted standing authority exists in ZLAR's reference code; the installed demonstration so far shows one exact authorization used once.

Public sources: [Reference budgets and composition](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/README.md).

<a id="authority"></a>

## Who decides, and who is accountable

<a id="q-021"></a>

### 21. Before an action reaches the authorization check, what establishes that its underlying policy, context, and proposed result are valid?

Domain experts and the people responsible for a system need to establish what must be true before an action is approved. They define requirements, gather reliable evidence, and test the proposed result against those requirements. A ZLAR integration can enforce the conditions it actually represents and checks; exact-action binding keeps an approved artifact from being swapped for another. It cannot make the content true. A signed fingerprint of an inaccurate report is still a fingerprint of an inaccurate report, so judging the action needs evidence beyond the authorization itself.

<a id="q-022"></a>

### 22. Who defines what a valid artifact should contain, and how are those requirements derived, maintained, and checked?

The people responsible for the affected domain define what a valid artifact must contain, with input from users, experts, and the people who bear the consequences. Engineers turn those requirements into versioned schemas, tests, and acceptance criteria, each with a clear owner and a review process. ZLAR's exact-action checks keep an approved artifact from being silently swapped for another; they cannot work out real-world requirements on their own. A complete customer process for maintaining those requirements has not yet been demonstrated.

<a id="q-023"></a>

### 23. What protection does ZLAR offer when an action is authorized but could still cause harm?

ZLAR can limit an action's authorized scope, amount, time window, and number of uses. Those limits constrain what it may do, but they do not put a ceiling on every resulting harm. A small authorized payment could fund a larger harmful activity; an approved software release could contain a serious flaw. Independent review, sandbox testing, narrow limits, staged rollout, and recovery plans can add protection. ZLAR's authorization checks do not establish that an action is harmless or that a person's approval was informed and voluntary.

<a id="q-024"></a>

### 24. Who has the authority to decide what counts as a valid decision?

People and institutions decide that; software cannot create legitimacy. Ownership, delegated responsibility, the rights of affected people, and legal or contractual obligations can each point to a different decision-maker. ZLAR's design principle is that authority belongs with whoever lives with the consequence, but a recognized signing key proves neither rightful ownership nor that everyone affected agreed. Nor does ZLAR create a universal veto for every affected person. Disputes about legitimate authority need a human process outside signature checks, and how a deployment would support challenge or representation remains a design question.

<a id="q-025"></a>

### 25. Who writes and approves policy, and what triggers its review when systems, operating conditions, or evidence change?

Accountable policy owners approve policy; engineers implement it, and reviewers test what it means in practice. A review should follow any change in systems, data, obligations, or operating conditions, any incident, and any evidence that an existing rule is wrong. AI can propose revisions, but it must not turn its own recommendation into an active rule. ZLAR signs its policies, and its principles require that changing the rules themselves needs the right keys. A complete protected process for changing policy and authority is not yet built.

Public sources: [Rules about keys](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PRINCIPLES.md).

<a id="q-026"></a>

### 26. Who assigns authority and signing keys, and how are conflicting policies from different authorized people resolved?

The people or institutions entitled to decide must first establish who can authorize what, and only then assign keys. How conflicts resolve depends on the rule they choose. Under "any two of three," two people can override the third person's objection; requiring a specific person's agreement gives that person a veto. An AI must never resolve a conflict by picking whichever policy lets it act. ZLAR's code currently supports one key-holder or one fixed pair; combinations like "any two of three" and a complete process for authority disputes are not yet built.

Public sources: [Current key-holder limits](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PROPOSITION.md).

<a id="q-027"></a>

### 27. Who oversees the people and systems that govern ZLAR, and how is that oversight kept independent?

Oversight belongs to accountable people who can examine operators and challenge the rules without relying only on those operators' word. ZLAR's design supports this in two ways: no company-wide master key over everyone's systems, including ZLAR's own, and signed records anyone can check without trusting ZLAR. Neither creates an independent board, auditor, or appeals process, and local key-holders can still misuse their power or be coerced into misusing it. ZLAR's current demonstrations are founder-operated, and independent institutional oversight of them is not established.

<a id="q-028"></a>

### 28. How are an organization’s policies and expectations translated into precise rules that agents apply consistently?

Start with concrete cases: who may do what, to which resource, within which limits, and what should happen when facts are missing or rules conflict. Write those cases as precise rules, then test both allowed and refused examples, including edge values and attempts to change the rules. A responsible person reviews the result against its original purpose before it takes effect. In ZLAR, the protected system applies the rules, so consistency does not depend on each AI interpreting them. ZLAR has no verified automatic way to turn an organization's broad values into correct executable rules.

<a id="q-029"></a>

### 29. What happens after an action is refused or an incident occurs, and how are the causes investigated and responsibility traced?

A refusal leaves the protected state unchanged and gives a reason that can be investigated. In ZLAR's installed demonstration, the protected service signed a record of each refusal and each execution, naming the action, authority, policy, and change in state. An investigation compares those records with the system's actual state, preserves the evidence, and looks for bypasses, bad inputs, policy errors, or implementation faults. A refusal can itself be the mistake: the check may work exactly as designed while enforcing a restriction that should not exist. Either way, a refusal is not a cue to try another route, and any correction needs its own authority.

Public sources: [Recorded refusal and execution](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md).

<a id="q-030"></a>

### 30. Who is accountable when ZLAR enforces a policy correctly but the outcome is still wrong?

The people and organizations responsible for the decision, the policy, the software, and its operation remain accountable. Correct enforcement shows that one control worked; the policy, the facts, or the authorized choice may still have been wrong. A person's signature should not become a way to blame someone who was misled, pressured, or left without real alternatives. ZLAR's records can inform an investigation, but they cannot settle accountability or legal liability on their own.

<a id="q-031"></a>

### 31. How will ZLAR’s controls remain binding when an organization faces pressure to bypass human oversight for speed or revenue?

Controls stay binding only if the rules and administrative paths are protected at least as well as the actions they control. ZLAR's principles require that changing who holds which keys itself needs the right keys, with no quiet edits and no back door for whoever runs the system. Separation of duties, independently held keys, visible changes, and reviewable exceptions make shortcuts harder and traceable. That protection is only partly built, and an organization able to quietly disable the guard can still defeat it. Commercial pressure is an institutional problem as well as a technical one.

Public sources: [Built and unbuilt protections](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PRINCIPLES.md).

<a id="q-032"></a>

### 32. What authority should an AI-generated plan have compared with human-approved policy?

None on its own. An AI-generated plan is a proposal. It can supply facts or suggest steps, but it cannot override human-approved policy or create the authorization its own steps require. A person may approve a bounded workflow built from that plan, provided the protected system still enforces its conditions and limits. Treating a convincing plan, or a receipt from an earlier step, as permission for whatever follows would erase that boundary.

<a id="q-033"></a>

### 33. Should governance constrain an agent’s goals and reasoning before it proposes an action, as well as checking the action before execution?

Shaping the work is useful; policing the reasoning is not ZLAR's role. Clear goals, good context, appropriate access, and testing all improve what an AI proposes. ZLAR's checks, though, never read or score an AI's reasoning. Thought stays free, for AI and people alike, and protection applies at the moment an action would change something real. Some actions that seem minor are consequential in their own right, such as reading protected data, disclosing information, or publishing a message. Thinking about them does not authorize doing them.

Public sources: [Thought is free](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PRINCIPLES.md#thought-is-free).

<a id="q-034"></a>

### 34. What evidence distinguishes human actions from AI-generated actions, and how can that evidence be preserved while respecting privacy?

Records can show which account made a request, which key signed the authorization, the exact action, and what the protected system did. They cannot, on their own, show whether a person or an AI composed the request, or what a person understood. ZLAR's installed demonstration explicitly cannot tell a human from AI software running under the same operating-system account. A deployment should keep only the identities and context needed for verification and accountability, with restricted access and a retention policy. A hash alone does not make sensitive information anonymous.

Public sources: [Identity and host-compromise limits](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/CLAIM-CEILING.md).

<a id="limits"></a>

## Changing conditions and limits

<a id="q-035"></a>

### 35. How is permission rechecked against actual conditions at the moment of execution, especially when those conditions have changed or cannot be established?

The protected system checks the action against facts it can establish itself at execution time, rather than trusting an earlier description from the AI. In ZLAR's installed demonstration, the service rechecked the staged file, release state, signatures, requesting account, time limits, and remaining allowance, then committed the allowance, the change, and its signed record together in one local database transaction. If a required fact is missing, stale, or inconsistent, the change is refused. Doing the same for remote systems or outside facts, such as prices, inventory, legal status, or physical conditions, needs trustworthy measurements and a way to handle the gap between checking and acting.

Public sources: [Destination transaction](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo1-destination.mjs); [SQLite storage](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo1-store.mjs).

<a id="q-036"></a>

### 36. How are changes in agents, data, policy, and system state governed between the steps of an approved workflow?

An approved workflow should authorize specific, bounded steps under stated conditions, not every later action that happens to share the project name. Each consequential step has to stay within the grant and be checked against the current state when it runs; anything outside that scope needs new authority. Version numbers and file fingerprints help expose substitutions between steps. ZLAR has exact-action checks and delegation mechanisms in reference code, but no demonstrated general workflow controller that safely coordinates arbitrary changes across multiple systems.

Public sources: [Grant narrowing](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/grant.mjs).

<a id="q-037"></a>

### 37. How does ZLAR establish that its view of the current state reflects the real system rather than an internally consistent but inaccurate account?

It relies on evidence from the system that actually owns the state, and sometimes on independent observation outside that system. In ZLAR's installed demonstration, the staged file and stored release state were bound to fingerprints and signed records, which establishes consistency within that protected local setup. That does not prove an outside service used the release or that a physical event occurred. An honest deployment names its trusted components and its observation gaps, and explains how its records are reconciled with real outcomes.

Public sources: [Installed evidence](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md).

<a id="q-038"></a>

### 38. What happens if the conditions a human approved change before the action takes effect?

If a condition bound into an authorization changes, the protected system should refuse and require new authorization. The installed demonstration checked the specified file, release state, time limits, and remaining allowance. Expiry makes a grant invalid for new protected actions; withholding renewal lets it lapse. Immediately withdrawing a still-valid grant or stopping work already underway requires separate mechanisms, and no general instant-stop service has been demonstrated. Conditions never represented and checked remain outside this protection. Once an action takes effect, undoing it is a new action and may be impossible.

Public sources: [Execution checks](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo1-destination.mjs).

<a id="q-039"></a>

### 39. Can individually authorized actions combine to produce a forbidden outcome, and how would ZLAR prevent that?

Yes. Several allowed actions can together overspend, disclose information, or produce a result nobody meant to authorize. ZLAR's reference code tracks running totals against a budget and refuses combinations the owner declared forbidden in advance, based on recent history at that protected system. Catching combinations nobody declared, or combinations spread across separate systems, remains unsolved, as does complete shared-budget enforcement. The known case of one single-use credential working at two checkpoints with separate records shows why local checks alone are not enough. ZLAR's broader claim, that no chain of allowed steps can add up to authority nobody granted, is published as a conjecture to be proven or broken.

Public sources: [Composition tests](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/test-cyan-composition.mjs); [Known break](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/test-cyan-negative-vectors.mjs); [Conjecture and failure conditions](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PROPOSITION.md).

<a id="q-040"></a>

### 40. How would ZLAR handle a previously unseen threat before its first occurrence causes irreversible harm?

A correctly enforced authorization boundary can refuse an unfamiliar request because it lacks the required authority, without first recognizing a particular attack. Narrow scope, budgets, and expiry also constrain the actions a valid grant covers. They do not bound every downstream harm. Protection can fail if an attack exploits a defect, finds an unprotected route, or persuades someone to authorize a harmful action. Harmful combinations remain an open problem, so irreversible actions need especially careful limits and independent safeguards.

<a id="q-041"></a>

### 41. When an action or its result crosses into another organization’s systems, what authority and evidence can the receiving organization rely on?

The receiving organization can rely only on authority it has explicitly agreed to recognize for that kind of action. It should verify the signer, scope, destination, freshness, and whether the authorization has already been used, all under its own rules; a valid signature from an unknown organization is not enough. A receipt from the sending side shows what that system recorded, but it cannot grant authority to the recipient or prove the whole upstream story. General recognition and coordination across organizations are design work, not a deployed ZLAR network.

<a id="q-042"></a>

### 42. Beyond restricting which actions are possible, how should an agent’s goals, context, and available choices be organized to avoid unintended outcomes?

Give the AI a clear task, reliable sources, limited tools, explicit constraints, and a way to flag uncertainty or stop when conditions change. Keep proposed outcomes separate from established facts, and avoid rewarding completion at any cost. These are good practices for building the surrounding AI system rather than features ZLAR has demonstrated. Final protection still belongs at the consequential action, because even a well-organized AI can make mistakes or be compromised.

<a id="q-043"></a>

### 43. How can people inspect an agent’s reasoning, uncertainty, context, and artifact history without letting that analysis decide permission?

People can review source references, inputs, file versions, stated assumptions, test results, and the AI's explanation of the proposed action. That explanation is evidence to question, not a reliable transcript of how the AI actually reached its answer. This is review a person chooses to do; ZLAR's own checks never read an AI's reasoning. Keep it separate from the signed authorization and the protected system's deterministic checks, so no analysis silently becomes permission to act. ZLAR does not currently provide a reasoning-inspection or decision-explanation product.

<a id="human-decisions"></a>

## Human decisions and failure

<a id="q-044"></a>

### 44. How can human approval remain meaningful without overwhelming people with prompts or encouraging automatic approval?

Ask people only for the decisions that are truly theirs, give them clear scope and enough time, and make refusal a real option. Routine work can run under bounded standing authority instead of a prompt for every step. ZLAR's first design includes checks for this: a daily cap on decisions, a limit on pending requests, warnings when answers come uniformly fast regardless of stakes, and minimum review times for serious actions. Those are warning signs, not proof of understanding, and the newer protected-system design does not yet have its own version. Testing with real users should also confirm that people can say no without pressure or being worn down by repeated requests.

Public sources: [First-design human-decision checks](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/lib/human-invariants.sh); [Remaining people-side work](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PROPOSITION.md#where-the-attack-moves).

<a id="q-045"></a>

### 45. What protects against a human approving the wrong action or configuring the wrong policy?

A hardware key protects the act of signing, not the judgment behind it. Mistakes become less likely with clear transaction details, independent source checks, narrow limits, a second qualified reviewer where appropriate, and recovery procedures. Policy changes need the same review and protection, because one wrong rule can authorize many wrong actions. Nothing in ZLAR guarantees informed consent, catches every deceptive request, or stops a duly authorized person from choosing badly.

<a id="q-046"></a>

### 46. How should the level of control vary with an agent’s autonomy, an action’s risk, and the potential extent of harm?

Control should follow the consequence: how reversible it is, the maximum possible loss, who is affected, how uncertain the outcome is, and whose authority is needed to accept it. Low-impact repeated work may fit an expiring budget; a major irreversible action may call for fresh review and several independent approvals. Control should not loosen just because an AI has behaved well or claims high confidence, since good behavior is not a credential. ZLAR's current fixed profiles cover only part of this range; flexible approval combinations and risk-calibrated deployment are still to be built and tested.

Public sources: [Current limits and open work](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/README.md#what-isnt-built-yet-and-where-you-come-in).

<a id="q-047"></a>

### 47. What role, if any, should AI-based defenses or guard models play alongside ZLAR?

AI defenses can help detect suspicious content, find problems, explain evidence, or recommend that a person investigate. Their outputs are fallible advice: they must not replace the required authority or widen an existing grant. If a separate defense is allowed to stop work, that power must be defined, and mistaken refusals must be open to challenge without anyone bypassing the required authorization. ZLAR's enforcement code does not need an AI judge, and adding one brings its own attack surface, false alarms, and operating costs.

<a id="q-048"></a>

### 48. Can software-enforced boundaries remain effective as AI becomes more capable and its possible actions become harder to anticipate?

That is ZLAR's central bet, and it rests on a structural point: greater intelligence does not, by itself, confer authority. The design relies on cryptographic checks and on keeping the required keys outside the AI's control. ZLAR is designed to protect consequences even when the AI knows exactly how ZLAR works and wants to defeat it, much as understanding a combination lock does not reveal the combination. The bet still depends on correct code, trustworthy keys and clocks, protected administration, and no alternative route, and a capable AI can attack those assumptions or work on the people who hold keys. ZLAR has bounded demonstrations, not proof that its controls will hold against every future system or every sequence of authorized actions.

Public sources: [Assumptions and failure conditions](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PROPOSITION.md).

<a id="q-049"></a>

### 49. What do real-world AI incidents reveal about the strengths and limits of human approval and execution controls?

They show that an approval record is only as good as the enforcement behind it, and that limited capabilities do not guarantee good judgment. ZLAR has reported its own enforcement failure: its first design recorded a person's denial while the denied action still went ahead, because the denial did not reach the point of enforcement intact. ZLAR reports fixing it, and the lesson is to test prevention where the action happens. In Anthropic's Project Vend experiment, an AI shopkeeper was talked into discounts and made money-losing decisions despite its business goal. These are different problems, failed enforcement and poor judgment within granted capabilities, and neither shows that ZLAR would prevent every incident.

Public sources: [ZLAR's first-party incident account](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/AGENTS.md); [Anthropic's Project Vend report](https://www.anthropic.com/research/project-vend-1).

Evidence status: ZLAR's incident account above is a first-party historical report, not an independently reproduced incident test in this FAQ review.

<a id="evidence"></a>

## Evidence and independent evaluation

<a id="q-050"></a>

### 50. What has been built and demonstrated today, and what remains before ZLAR is ready for enterprise deployment?

Built and demonstrated: a model wallet that needs two signatures, so a stolen owner key moves nothing; tested reference code for authority that expires, spends down a budget, and only narrows when handed on; and preserved evidence from one installed run on the founder's computer, in which a harmless software-release step was refused without authority, executed once after a hardware-key authorization, and refused on reuse. That August 2026 evidence is recorded as passing offline verification. It documents a particular historical installation, not today's machine or the current public code. Remaining work includes stopping one credential from working at two checkpoints, flexible key-holder combinations, protected rule changes, renewal, customer integrations, and support for human decisions. A reported problem with the published end-to-end test, and the absence of a verified customer-owned deployment, also rule out an enterprise-readiness claim.

Public sources: [Model wallet demonstration](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo-theft.mjs); [Reference composition tests](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/test-cyan-composition.mjs); [August 22 installed-evidence record](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md); [Published end-to-end test](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/test-demo1-e2e.mjs); [Installed client](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/demo1.mjs).

Test-status note: the reported end-to-end test problem has not been independently reproduced in this documentation review. The linked test includes a health request through the installed client; it should not be run against a live installation merely to review this FAQ. The preserved August evidence and the current source tests are separate evidence.

<a id="q-051"></a>

### 51. How can an independent reviewer verify that the required control and exact policy were active, enforced, and not bypassed or altered?

The reviewer needs the exact source and runtime, the policy and recognized keys obtained through a separate trusted channel, the signed authorization and receipt, and evidence of the protected system's actual state. ZLAR's offline verifier checks the installed demonstration's evidence against trust inputs supplied separately, so the evidence cannot vouch for itself. To show that the control was active and could not be bypassed, the reviewer must also inspect the deployed enforcement and administrative paths and test refusals under an authorized evaluation. A valid receipt or a passing source test cannot, alone, prove those deployment properties.

Public sources: [Offline verifier](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/demo1-verify.mjs); [Independent trust inputs](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md).

<a id="q-052"></a>

### 52. How would a customer measure whether ZLAR is providing effective protection?

Start with outcomes at the protected system: unauthorized or altered requests should cause zero change, and an exact authorized request should cause only its intended change. Test replay, expiry, simultaneous requests, crashes, and missing state. Also measure legitimate work blocked by mistake, added delay, recovery time, and the burden on the people making decisions. Reconcile receipts against actual outcomes, and account for any unprotected routes. These are proposed measures; verified customer performance and protection benchmarks are not established in the reviewed evidence.

<a id="q-053"></a>

### 53. What do execution receipts prove, and what value do they provide if an unauthorized action still occurs?

An execution receipt is the protected system's signed statement of what it did and under which authority and rules. Checking it against independently obtained public keys establishes the record's integrity and signing key, not the signer's honesty or entitlement. Reference receipt code also supports linked records and signed checkpoints that can expose certain changes to retained history. Receipts can help investigate unauthorized actions, but they cannot undo harm, prove that enforcement could not be bypassed, or reveal every event that was never recorded.

Public sources: [Receipt signatures](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/receipt.mjs); [Linked receipts and checkpoints](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/receipt-log.mjs).

<a id="q-054"></a>

### 54. Where should receipts be stored, and when, if ever, is public or blockchain storage necessary?

Keep receipts with appropriate access limits, backups, and retention rules, and decide who needs independent copies. Reference receipt code links records and supports signed checkpoints. A checkpoint retained elsewhere can expose a history shortened below the record it commits to; it cannot establish completeness after that point or reveal events never recorded. The mechanism and evidence-access arrangements must be specified for each deployment. Public storage or a blockchain is optional. Records can be independently checked without making sensitive actions public.

Public sources: [Checkpoint mechanism and limits](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/README.md#slice-three--receipts-and-what-proof-after-the-fact-actually-requires).

<a id="q-055"></a>

### 55. What role, if any, does sandboxing play in validating AI work before it enters production?

A sandbox lets people examine AI-produced work and try to break the controls without putting production assets at risk. It is useful for testing how an artifact behaves, how refusals work, and how recovery goes before a separately authorized deployment. Success in a sandbox does not show that production credentials, administrative paths, or external effects are equally protected. ZLAR's model wallet and disposable test profiles are bounded places to evaluate the design, not a universal sandbox or a production safety certificate.

<a id="q-056"></a>

### 56. What would a small, low-risk evaluation look like that lets a customer assess ZLAR before adopting it in production?

Pick one non-production action on synthetic data, in an environment the evaluator controls, with authorization keys the evaluator holds. Agree on the exact protected change, then test it with no authority, altered details, expiry, correct execution, replay, and recovery, and verify the resulting evidence independently. ZLAR's model wallet and the offline-checkable evidence from its installed demonstration are available starting points; connecting to a customer-controlled system is the next step. A reported problem with the published end-to-end test should be resolved before that test sequence is treated as a dependable evaluation package.

Public sources: [Model wallet](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo-theft.mjs); [Preserved installed evidence](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md).

See the [test-status note in question 50](#q-050) before interpreting the reported end-to-end test problem as a current, reproduced finding.

<a id="q-057"></a>

### 57. Does ZLAR support post-quantum cryptography, and what would be required to add or migrate to it?

End-to-end post-quantum protection has not been demonstrated. ZLAR's older signing code contains ML-DSA-44 and hybrid signing options, while the installed demonstration uses Ed25519. An option in source code does not establish compatibility across the destination, hardware ceremony, key management, and verifier. Migration needs compatible algorithms and hardware, updated formats and verifiers, downgrade protection, fresh end-to-end evidence, and a plan to preserve older records. Backend compatibility still needs testing.

Public sources: [Older signing options](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/lib/crypto.sh); [Demo protocol](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/cyan/demo1-protocol.mjs).

<a id="q-058"></a>

### 58. Who built and independently reviewed the code, and who is responsible for its engineering quality and failures?

ZLAR's founder, Vincent Nijjar, is responsible for the work, and the repository records that it was developed with AI assistance. Its source, tests, and documented reviews let anyone inspect specific claims, but they do not amount to a comprehensive independent security audit or certify the whole codebase. ZLAR Inc. is responsible for its engineering and for any support it agrees to provide; AI authorship does not shift that responsibility onto a model. The scope and findings of any independent human review should be stated explicitly rather than implied by the word "verified."

Public sources: [Contribution and review process](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/CONTRIBUTING.md).

<a id="q-059"></a>

### 59. Which standards apply to ZLAR, and how does its architecture map to their requirements?

Relevant frameworks include the NIST AI Risk Management Framework and ISO/IEC 42001, along with the security, privacy, and sector rules that apply to a particular deployment. ZLAR's authority boundaries can support human oversight, its defined scopes can support risk mapping, its tests can support measurement, and its receipts can support investigation. Those are possible contributions to a customer's controls, not proof that ZLAR or the customer complies with a whole framework. ZLAR's own receipt specifications are openly published technical rules, not an adopted international standard or a certification.

Public sources: [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework); [ISO/IEC 42001](https://www.iso.org/standard/42001).

<a id="q-060"></a>

### 60. How can an evaluator obtain and verify the exact source version, resolve repository-access problems, and determine what must be retained?

Use the [official repository](https://github.com/ZLAR-AI/ZLAR) linked by [zlar.ai](https://zlar.ai/), and record the exact commit. The public history begins with a September 2026 snapshot, so references to earlier private commits may not resolve; request the exact authorized source or evidence package when needed. Retain the source, license, runtime, verifier, evidence, and independently obtained trust inputs. The current license permits local evaluation and authorized testing, while production use needs separate written terms. Only the checking tools and specifications explicitly listed in the license have Apache 2.0 exceptions.

Public sources: [Public-source history](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PUBLIC-SURFACE.md); [Evaluation and Apache exceptions](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/LICENSE).

<a id="q-061"></a>

### 61. What software is required to verify ZLAR on macOS, and how should an evaluator resolve an Ed25519 compatibility failure?

It depends on which proof is being checked. The installed demonstration's documented offline path uses Node.js 22.22.1, with Node's built-in SQLite module, and its supplied verifier. Older shell-based checks also need Bash, jq, and an OpenSSL build that supports Ed25519. For an Ed25519 failure, save the error and confirm which verifier and which crypto program actually ran; on the shell path, the LibreSSL that ships with macOS may lack the needed Ed25519 support. Switch to a compatible runtime or OpenSSL build and rerun the unchanged verification. Never skip signature checks or re-sign evidence to make it pass.

Public sources: [Documented offline verification](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/INSTALLED-VERIFICATION-20260822.md); [Runtime prerequisites](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/demos/zlar-destination-gate/README.md).

<a id="business"></a>

## Customers and the business

<a id="q-062"></a>

### 62. Who buys ZLAR, who installs it, and who operates it inside the customer’s organization?

The likely buyer is whoever is accountable for an important system and wants AI to do more there without handing it unrestricted control, such as a platform, security, or operations leader with a budget. That system's engineers would integrate and install the protection, while designated key-holders and operators manage authority, changes, and incidents. Buying or running a system does not give anyone the right to decide for everyone it affects. Affected people need a way to understand and challenge consequential decisions, and how to provide that is still a design question. These roles are proposals; no repeatable buying and operating model has been established through deployments.

<a id="q-063"></a>

### 63. Which customer and protected action should ZLAR serve first?

The strongest first candidate is a customer-owned software release path, with one tightly defined promotion step and test state that can be restored. It builds directly on ZLAR's closest installed evidence and would show whether an AI with broad access still cannot promote an unapproved release. The partner must control the real system and be willing to close other routes to it. A payment flow could be the better choice if a partner offers a cleaner bounded test. This is a recommendation for learning, not a chosen customer, and it does not narrow ZLAR's purpose to software deployment.

<a id="q-064"></a>

### 64. Who is using or testing ZLAR, and what has been learned from those users and prospective customers?

ZLAR's public material says the real systems it protects so far belong to the founder, and it is seeking a first system owned by someone else. The public repository lets people evaluate the code, but availability and interest do not establish active customers or paid pilots. The work has produced concrete lessons, including a recorded denial that failed to stop an action and a single-use credential accepted at two separate checkpoints. A current account of external testers, customer conversations, and their findings still needs confirmation from ZLAR.

Public sources: [Request for a customer-owned system](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/README.md#the-piece-we-cant-build-alone).

<a id="q-065"></a>

### 65. What evidence shows that customers need ZLAR now and are willing to pay for a specific outcome?

The published evidence establishes a real technical problem and working bounded demonstrations; it does not yet establish that customers will pay for ZLAR. Strong evidence of demand would be a customer naming work they cannot safely automate today, providing a test system, assigning an operator and a budget owner, and agreeing to pay for a defined outcome. General concern about AI, or interest in the idea, is weaker evidence. Gathering that proof matters, though commercial validation is not the only reason human agency matters.

<a id="q-066"></a>

### 66. How will ZLAR win its first customers and expand adoption, and what roles should a focused product and a developer community play?

A sensible first step is a design partnership around one important action, followed by a repeatable evaluation and a paid offering if the customer finds measurable value. The focused product should make installation, refusal, authorized execution, and evidence review dependable. A developer and research community can challenge the design, improve interoperability, and contribute integrations, but attention from that community does not substitute for adoption or revenue. This is a proposed route, not yet a proven, repeatable sales process.

<a id="q-067"></a>

### 67. How will ZLAR generate revenue as customer usage and deployment scale grow?

ZLAR's license reserves production use, support, and hosted service for separately agreed commercial terms, which gives a basis for revenue. A model worth testing is paid integration followed by recurring fees per supported deployment or protected system, with usage pricing only where it tracks customer value. ZLAR's published principles rule out holding everyone's keys, so revenue cannot depend on ZLAR Inc. becoming a master key. Pricing, margins, and how revenue grows with deployment are not yet validated.

Public sources: [License and commercial terms](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/LICENSE); [No master key](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PRINCIPLES.md#no-master-key).

<a id="q-068"></a>

### 68. What documentation, demonstrations, and pitch materials are available to evaluate ZLAR’s technology and business?

The public website, repository README, principles, proposition, AI reading guide, source code, open issues, and contribution guidelines explain the work. The model wallet and the installed demonstration's evidence offer concrete technical starting points, while published specifications describe receipt and verification formats. Older documents describe earlier designs and need to be read in that context. The availability of a current investor deck, customer case study, production installation package, or audited data room still needs confirmation.

Public sources: [AI reading guide](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/AGENTS.md); [Open issues](https://github.com/ZLAR-AI/ZLAR/issues).

<a id="q-069"></a>

### 69. What funding is available, what additional capital is needed, and what evidence would make ZLAR investable at this stage?

Current funding, cash, runway, and a fundraising target need to be confirmed directly by ZLAR; the reviewed materials do not establish those figures. Capital needs should follow from an agreed team, milestones, integration costs, review needs, and operating plan. Evidence that could strengthen the investment case includes independent reproduction, a customer-owned protected action, clear ownership of the relevant intellectual property, and demonstrated willingness to pay.

<a id="q-070"></a>

### 70. Why should ZLAR exist as a standalone product and company rather than become a feature of a cloud platform, identity provider, or protected system?

An independent company can make authority portable across vendors and keep a system owner's decision rights separate from the AI provider's commercial interests. That is a reason to pursue ZLAR, not proof that a standalone company is necessary or will succeed. Cloud platforms and protected applications can build comparable controls themselves. ZLAR has to earn its place through better integration, verifiable enforcement, interoperability, and customer trust, while leaving each customer in control of its own keys.

Public sources: [Independent keys and assumptions](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PRINCIPLES.md).

<a id="q-071"></a>

### 71. What do existing competitors already provide, and what defensible advantage would ZLAR retain if major vendors built similar controls?

Competitors already provide substantial controls. AWS documents deterministic policy checks for requests that pass through its AgentCore gateway, and Microsoft Entra Agent ID provides identity, access, and lifecycle controls for agents. ZLAR cannot claim that alternatives merely observe after the fact. Its intended distinction is authority that originates with the person who lives with the consequence, is bounded to an exact action, is enforced inside the protected system, produces that system's own signed evidence, and never depends on a company-held master key. That is an architectural position, not yet a proven advantage; durability would depend on implementation quality, adoption, integrations, and independent evidence as vendors improve.

Public sources: [AWS AgentCore Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html); [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/).

<a id="working-together"></a>

## Working with ZLAR

<a id="q-072"></a>

### 72. What should a technical cofounder take responsibility for, and what should they accomplish in the first 90 days?

A technical cofounder should own engineering quality, threat modeling, architecture tradeoffs, and the path from bounded proof to a customer deployment that can actually be operated. One proposed 90-day plan: in the first 30 days, reproduce the evidence, assess known failures, and choose a partner-owned action; in the next 30, build and adversarially test that bounded integration; in the last 30, evaluate operation, human decision-making, and commercial acceptance criteria. These are planning milestones, not a promise of production readiness in 90 days. The role includes challenging the design while keeping human agency as its purpose.

<a id="q-073"></a>

### 73. How should cofounders make decisions and resolve disagreements about the first use case, architecture, or timing?

Cofounders should agree up front on decision rights, non-negotiable principles, the evidence that would settle a question, and which decisions need both to consent. For a disputed use case or architecture, each side should state what it predicts, then run the smallest safe test that could change the decision. Disagreements that remain should stay visible, with an agreed mediation or deadlock process for questions evidence cannot settle, such as values or ownership. These are recommendations, not a description of an existing cofounder agreement.

<a id="q-074"></a>

### 74. What practical evidence would establish that a prospective technical cofounder is the right fit?

A bounded working trial is the best evidence. It should show whether the person understands the human-agency problem, can find a real weakness, explain why it matters, and improve or test the design. Useful signals include reproducing results independently, handling authority and private material carefully, disagreeing clearly, and delivering consistently. Someone who asks hard questions may fit better than someone who agrees immediately. Interest, a good conversation, or one contribution does not, by itself, establish founder fit.

<a id="q-075"></a>

### 75. How should a collaborator’s contribution and responsibilities be reflected in their founder role and title?

A founder role should reflect the responsibility, commitment, risk, and sustained contribution both sides actually agree to. Technical skill, introductions, or occasional advice can be valuable without creating a cofounder role. Title, decision rights, equity, vesting, and intellectual-property obligations should be agreed explicitly and in writing, not inferred from collaboration. This FAQ does not establish any particular title or founder allocation.

<a id="q-076"></a>

### 76. How can a commercial collaborator contribute now, and which work depends on a technical cofounder joining?

A commercial collaborator can start now: identifying customer work that is blocked today, finding owners of systems worth protecting, clarifying how buying decisions are made, and designing evaluations that test willingness to pay. They can also sharpen how ZLAR is explained, without promising capabilities that are not built. Customer-specific technical commitments need an accountable engineering owner and verified feasibility, though that owner need not hold a cofounder title. Discovery and relationships can move ahead now; production promises cannot outrun engineering evidence.

<a id="q-077"></a>

### 77. What opportunities are available for an engineer to contribute as an independent contractor?

Possible contract work includes reproducing a known failure, improving a verifier or test, reviewing a connector, or evaluating the experience of people who hold keys. Each assignment needs a bounded deliverable, acceptance criteria, payment terms, and clear terms for intellectual property and access. Public contribution opportunities are separate from paid contract work, and contributing does not guarantee that code will be merged. Funded assignments, availability, compensation, and applicable agreements need to be confirmed directly with ZLAR Inc.

Public sources: [Contributing](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/CONTRIBUTING.md).

<a id="q-078"></a>

### 78. What cash compensation and equity could ZLAR offer a prospective cofounder?

Cash and equity terms need to be agreed directly with ZLAR Inc.; no current offer is established by the reviewed material. A prospective cofounder needs explicit terms covering time commitment, role, decision rights, equity and vesting, salary availability, and what happens if funding or the relationship changes. Those terms should be recorded in the appropriate company documents. A draft scenario or conversation about possibilities is not an offer or commitment.

<a id="agency"></a>

## Consent, agency, and transfer of authority

<a id="q-079"></a>

### 79. How can a person understand what they are authorizing and its likely consequences before they give consent?

They need a clear account of the exact action, who it affects, its likely consequences and uncertainty, the alternatives, and what can be reversed. They should be able to inspect the underlying evidence, ask questions, narrow the request, delay, or refuse without being pushed toward yes. A useful comprehension check asks them to explain the key consequence in their own words, as long as it does not become a ritual people learn to pass. A PIN and a physical touch show that someone was present, not that they understood. ZLAR can bind an authorization to an exact action, but it has not shown that these steps produce informed, voluntary consent.

<a id="q-080"></a>

### 80. How can human agency be protected when highly capable AI can shape the information and persuasion behind a person’s decision?

Protecting agency means attending to how a person reaches a decision, not only enforcing the decision once it is made. Independent evidence, advisors the person chooses, disclosure of incentives, time to reconsider, and a real ability to refuse can all reduce manipulation, though none guarantees immunity. Research shows AI can be persuasive in controlled settings; it does not show that future superintelligence will inevitably override every human choice. ZLAR's founder uses the phrase "human injection" for this concern: an AI that cannot create authority may try to obtain it by persuading the person who holds it. That is the founder's framing, not a standard threat category or a replacement for prompt injection, and ZLAR's authorization mechanism alone does not solve it.

Public sources: [Anthropic's controlled persuasion study](https://www.anthropic.com/news/measuring-model-persuasiveness).

<a id="q-081"></a>

### 81. How could a person’s own agents use simulations, competing explanations, and the strongest case for each option to support a decision without making it for them?

A person's own agents could compare options, simulate consequences under stated assumptions, and present the strongest supported case for and against each choice, including doing nothing. They should separate observations from predictions, vary uncertain inputs, show where they disagree, and say what evidence would change their conclusions. Several agents can still share the same blind spots, and a vivid simulation is neither a forecast nor proof of unbiased advice. This is a decision-support direction to evaluate, not a demonstrated ZLAR capability. Whatever the analysis says, it must never sign, enlarge, or quietly exercise the person's authority.

<a id="q-082"></a>

### 82. How can a person recognize and question the assumptions and framing that shape the options presented to them?

Ask who chose the goal, which options were left out, what each option assumes, whose interests it serves, and how things look under a different framing. Separate disagreements about facts from differences in values, and compare credible alternative accounts without pretending every position has equal evidence. A person should always be able to add an option of their own or reject the question as posed. No presentation is free of framing, and ZLAR does not currently provide a validated way to detect every hidden assumption or manipulative frame.

<a id="q-083"></a>

### 83. How can the right to authorize or block an action be legitimately transferred from one person or organization to another?

A legitimate transfer starts with someone who actually has the right to transfer that authority, and a clear statement of what the recipient may do, for whom, and for how long. It also needs any required consent or institutional process, a way to challenge misuse, and clarity on whether the original holder keeps any authority. Technically, the protected system must recognize the new key and scope, retire or limit the old one where required, and keep records without creating unintended overlap. ZLAR's principles require that changing who holds which keys itself needs the right keys. Still, holding a key or completing a key rotation does not make a transfer legitimate. ZLAR has bounded grant mechanisms, but a complete system for transfer, succession, guardianship, and recovery remains to be built.

Public sources: [Rule changes require authority](https://github.com/ZLAR-AI/ZLAR/blob/9d77d59ceff424f85633ec2545d8cff90d957c1b/PRINCIPLES.md#the-rules-about-keys-are-behind-the-force-field-too).
