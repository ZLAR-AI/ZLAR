# If an AI Agent Took an Action That Affected You

This document is for you if an AI agent did something on your behalf, or to you, and you want to know what happened, who decided it, and what you can do about it.

## Who this is for

You may be reading this because:

- An AI agent made a decision that affected your work, your money, your health care, your housing, your case file, your benefits, or something else important to you.
- You were told you were the person responsible for approving or denying actions an agent attempted to take, but the request was unclear, you felt pressured to approve, or you did not have time to think.
- You denied a request from an AI agent, and the system or someone using the system overrode your decision.
- You think you should have been asked about an action that affected you, and nobody asked you.
- You were told that "the system approved it" or "the policy allowed it" and you want to know what that means and whether it is true.

You have the right to know what happened and what counted as authorization.

## What ZLAR is

ZLAR is software that some organizations use to govern what AI agents do. When an organization uses ZLAR, every important routed action an agent attempts is checked against rules, sometimes routed to a person for approval, and recorded in a signed receipt. A log records what happened. A ZLAR receipt records what counted as authorized effect when the action tried to become consequence.

ZLAR does not understand what the agents are doing. It does not predict their behavior. It is a checkpoint. The agent has to go through the checkpoint before it can take certain actions, and the checkpoint either lets it through, blocks it, or asks a person to decide.

Many organizations that use AI agents do not use ZLAR or any equivalent. If your situation involves a system that does not produce receipts, the questions in this document still matter, but the answers will look different. Skip to "What to do if there is no receipt."

## How to find out if a receipt exists

Not every AI action produces a receipt. Receipts exist when the organization runs ZLAR (or an equivalent system), the action was the kind ZLAR was set up to record, and the receipt was created and stored at the time.

Ask the organization directly:

- "Do you use ZLAR or any similar governance system to record AI agent actions?"
- "Was a receipt created for the action that affected me on [date]?"
- "Can you provide me with the receipt and the public key needed to verify it?"

If the organization says they do not record AI agent actions, that fact may itself be important if you need to escalate. If the organization says records exist but you cannot have them, see "What to do if the organization will not give you the receipt."

## How to read a receipt

A receipt is a small block of structured text. The fields that matter to you are:

- **`tool`** — what kind of action the agent attempted. Writing a file, running a command, sending a message, making a payment, reading a document.
- **`outcome`** — what happened:
  - `allow` — a rule said this was OK and the action proceeded.
  - `deny` — a rule said this was not OK and the action was blocked.
  - `authorized` — **a person** made the decision to allow it. Different from `allow`. `authorized` means a specific human, not a rule.
  - `denied` — a person made the decision to block it.
  - `timeout` — a person was supposed to decide but did not respond in time, and the action was blocked.
- **`authorizer`** — who made the decision: `policy` (a rule), `human` (a specific human), `gate` (a system default, usually fail-closed), `timeout` (no human response), `manifest` (a configuration constraint).
- **`ts`** — the date and time of the decision, in UTC.
- **`policy_version`** — the version of the rules that was in effect.
- **`manifest_principal`** — the human who is accountable for the agent under the configuration. This may be the person you need to speak with.

The two fields that matter most are `outcome` and `authorizer`.

If the outcome is `authorized` and the authorizer is `human`, **a specific person made the decision that affected you**. That person is identifiable and accountable. You have the right to ask who they were and on what basis they decided.

If the outcome is `allow` and the authorizer is `policy`, **a rule made the decision**. No human was involved in your specific case. The rule was written before your situation occurred. You have the right to ask who wrote the rule and why it covered your case.

If the outcome is `deny` or `denied`, the receipt says the governed path did
not authorize the effect. If something did happen anyway, the receipt does not
match the actions taken or the action may have bypassed the governed path -
that is itself a serious problem.

## How to verify a receipt

A ZLAR receipt is cryptographically signed. Anyone with the right public key can mathematically check that the receipt has not been changed since it was created. You do not need to trust the organization that gave you the receipt to run that integrity check. You can verify it yourself or ask a third party.

You need the receipt and the organization's public key. The public key is a small text file. The organization should provide it. The public key cannot forge receipts; it can only verify them.

Three paths, in order of effort:

1. **Verify it yourself.** The verification tool is at `bin/zlar-verify` in the public ZLAR repository at github.com/ZLAR-AI/ZLAR. One command, two files (receipt and public key), output is `VALID`, `INVALID`, or `UNKNOWN-SIGNER`.

2. **Ask someone with technical access.** Anyone with Node.js installed can run the same tool. Computer science departments, technology journalists, and consumer advocates can usually do this within hours.

3. **Ask an independent party.** Legal aid clinics, regulatory authorities, and consumer protection organizations may be willing to verify on your behalf, especially if your situation is part of a pattern.

A `VALID` result means the receipt has not been tampered with: its contents
match what the signing key signed. It does not mean the decision was good, that
the signing key is still active, that the key was never compromised, or that the
organization governed every path the agent could use. Whether the decision was
correct is a separate question. Whether the issuer was recognized for this
deployment is also a separate question.

It also does not reconstruct the agent's full history, intent, context, or
reasoning. It proves what counted as authorized effect at the checkpoint.

An `UNKNOWN-SIGNER` result means the receipt names a signing key that does not
match the supplied public key. It may be the wrong public key, the wrong
receipt, or an issuer the verifier does not recognize. Escalate.

An `INVALID` result is a serious problem. It means the receipt was modified,
the wrong receipt was provided, or the receipt failed structural or semantic
checks. Escalate.

## How to contest an action

**If a human authorized the action and you disagree with the decision**, ask the organization to identify the person (the receipt's `manifest_principal` field is a starting point) and ask them to explain. If they cannot or will not, escalate to the organization's compliance or legal contact. The fact that a specific person is named in the receipt is what makes them accountable.

**If a policy rule allowed the action and you believe the rule should not have applied**, ask for the text of the rule and the policy version named in the receipt. The rule was written by a human. That human is accountable for the rule. The organization should be able to explain why the rule covered your case and who is authorized to change it.

**If the receipt is UNKNOWN-SIGNER** when you or a third party verifies it, the
receipt's signing key does not match the supplied public key. Ask the
organization for the recognized public key and the issuer status for that
receipt. Do not treat a matching signature as issuer recognition until the
issuer boundary is explained.

**If the receipt is INVALID** when you or a third party verifies it, the receipt
has been tampered with, the organization gave you the wrong receipt, or the
receipt failed structural or semantic checks. Do not accept the organization's
account of the action without further investigation. Contact a consumer
advocate, a lawyer, or the regulator who handles AI complaints in your
jurisdiction.

**If the action that was taken does not match what the receipt says was authorized**, the recording system has failed or has been bypassed. This is the kind of situation a regulator should know about.

## Who is responsible

Responsibility for what an AI agent does rests with the organization that runs the agent, not with the agent itself. AI agents are software. People and organizations bear responsibility.

In a ZLAR-governed system, responsibility is recorded in two places:

1. The `manifest_principal` field names the human accountable for the agent under the current configuration.
2. The signing key that produced the receipt belongs to the organization that runs the agent. The organization is responsible for keeping that key secure and for not signing false receipts.

You can ask:

- Who is the manifest principal for the agent that took the action?
- Who authorized the specific action — a named human, or a rule?
- Who owns the signing key?
- Was that signing key an active recognized issuer for this deployment at the
  time of the action?

You have the right to ask these questions. If the organization will not answer, that fact is itself information you can use when escalating.

## What to do if there is no receipt

If the organization tells you they have no receipt for the action, ask why. Possible reasons:

- They do not use ZLAR or any equivalent. Many organizations that deploy AI agents do not record agent actions in any verifiable way. The absence of a receipt is not a system failure — it is the absence of any system.
- They use a system that records some actions but not your category. Ask what categories ARE recorded and why yours is not.
- They use ZLAR (or equivalent) but the receipt for your specific action was not generated. Ask why.

The absence of a receipt is information. An organization that cannot show how a decision was made cannot meaningfully claim that the decision was made carefully. If your situation has consequences that matter — financial, legal, medical, employment-related — the absence of a verifiable record is something a regulator, a lawyer, or a consumer advocate should know about.

## What to do if the organization will not give you the receipt

Some organizations refuse to provide receipts even when they have them. The result is that you cannot independently verify what happened.

This is itself a problem, and it is one that some regulatory frameworks are starting to address. The European Union's AI Act, in particular, includes requirements for human oversight and record-keeping for AI systems that affect individuals. Similar frameworks exist or are developing in Canada, Singapore, the United Kingdom, the United States, and other jurisdictions.

Your options:

- File a complaint with the relevant regulator. In the European Union, this is your national data protection authority. In the United Kingdom, the Information Commissioner's Office. In Canada, the Office of the Privacy Commissioner. In other jurisdictions, the relevant data protection or AI oversight authority.
- Contact a legal aid clinic or a lawyer. If the decision had legal or financial consequences, you may have rights under your jurisdiction's data protection or AI law.
- Contact a consumer advocacy organization.
- Document everything in writing. The fact that you asked and were refused is itself evidence. Keep a written record with dates and the names of anyone you spoke with.

## Where to get more help

This document is part of the ZLAR project. Current core source access is private. The project cannot provide individual legal advice or case-by-case help. We can answer general questions about how ZLAR works.

For individual help, the right resources are a lawyer or legal aid clinic in your jurisdiction, a consumer advocacy organization that handles AI complaints, the data protection authority or AI oversight authority in your jurisdiction, or a journalist who covers AI accountability if your situation is a pattern that may affect others.

---

*This document may be reproduced and translated freely if kept intact with this notice. Prior ZLAR source distributions that were made public under Apache-2.0 remain governed by Apache-2.0; current private-core source access is private.*
