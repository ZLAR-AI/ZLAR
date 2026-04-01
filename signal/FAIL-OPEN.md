---
type: essay
project: ZLAR
author: Vincent Nijjar
classification: public
date: 2026-04-01
summary: >
  On the Anthropic source code leak, the fail-open hook architecture,
  and why deterministic enforcement exists.
---

I'm a human being watching this moment in AI in real time, trying to describe what I see as clearly as I can.

I keep thinking about an office.

A busy office. People walking around. Files moving. Money moving. Assets moving. Decisions being made. Buttons being pressed. Important things happening everywhere.

From the inside, it all looks normal. Productive. Necessary. Human.

But what I keep noticing is that inside all that motion, there are points of contact.

A hand touches a button.
A permission gets granted.
A tool gets used.
A file gets exposed.
A message gets sent.

And once that action becomes real, sometimes there is no taking it back.

Today, that stopped being a thought experiment.

Yesterday, a source map file accidentally left in an npm package exposed roughly 512,000 lines of Anthropic's internal source code to a public registry. One packaging error. By the time anyone noticed, the code had been copied widely — one public repository alone accumulated more than 50,000 forks — and the exposure became effectively permanent.

Anthropic called it a release packaging issue caused by human error, not a security breach. I believe them. That is exactly the point.

Human beings make mistakes. Some mistakes are reversible. Some are not. What is different now is the speed. AI is compressing the distance between intention and consequence. The pace no longer feels monthly, or weekly, or even daily. It feels continuous.

And here is what I keep thinking about as I read Anthropic's own documentation for the hook system that governs what Claude Code can do:

The lock on the door between the AI and the things it can do is designed to swing open if it jams.

That is not a bug. That is a deliberate, documented design choice. If a PreToolUse hook crashes, times out, or returns an unexpected error, the action goes through. This applies to both command hooks and HTTP hooks. Anthropic chose this because a broken hook should not freeze a developer's workflow. I understand the reasoning. But it means the enforcement layer — the thing standing between the AI and the button — fails in the direction of letting the action happen.

There is also a model-based classifier that Anthropic uses in Claude Code's auto mode. Anthropic calls it a transcript classifier. In the leaked source code, it appears under the internal name "YOLO classifier." It uses an AI model to evaluate, in real time, whether another AI model's action is safe enough to approve automatically — as a substitute for a human approver.

Anthropic designed it so the classifier cannot see the agent's reasoning for why an action is safe — it only sees the raw tool call. That is a meaningful constraint. But structurally, it is still intelligence deciding whether intelligence should be trusted.

That is the architecture I have spent the last three months trying to replace.

Not because it is stupid. It is not. It is sophisticated. But it is the wrong category of protection for irreversible actions, because intelligence can be persuaded and deterministic rules cannot.

That is why I keep coming back to one question:

What if certain classes of mistakes were not just unlikely, but impossible?

Not because the human becomes perfect.
Not because the AI becomes perfect.
But because there is a force field around the action itself.

I think I've built the beginning of that force field.

In plain language: it does not watch what the AI is thinking. It stands between the AI and the button, and the button does not work unless the rules say so. The rules are signed by a human with a cryptographic key. The AI cannot touch the rules, rewrite them, or argue its way past them, because the gate has no reasoning capability. That is the security property.

In technical language: ZLAR is a deterministic policy-enforced execution boundary for AI agents. JSON policy rules with a Cedar proof-of-concept demonstrating a formal verification path. Ed25519-signed and hash-chained audit trails. Synchronous interception of every tool call on governed paths. No AI in the enforcement path.

If ZLAR had been deployed at that publish boundary with fail-closed enforcement on the hook path, the npm publish command would have been intercepted and held for human approval before release. A human would have seen what was in the package. With that context, the 512,000 lines would almost certainly never have reached the public registry. That is the kind of mistake a deterministic gate is designed to make structurally impossible — not by trusting the human to be perfect, but by ensuring the action cannot proceed without explicit human authorization.

Now I need to say something directly to Anthropic, because this is not a criticism. It is a request.

You built the hooks that make ZLAR possible. Your PreToolUse system is the right interception point. You designed it to be extended by exactly the kind of external governance layer I have been building.

But the hooks fail open. And I cannot fix that from the outside.

I need one thing from you: a fail-closed option for PreToolUse hooks. One configuration flag. If the hook fails to respond within N milliseconds, deny the tool call. That single change closes the last gap between the gate working and the gate being deterministic on covered paths.

Everything else already exists. The deterministic policy engine. The signed rules the agent cannot modify. The hash-chained evidence trail. The human-in-the-loop approval via Telegram. The MCP proxy gate that is structurally fail-closed because no proxy means no connection. The test suites. It is live, it is open source, and it is Apache 2.0.

[github.com/ZLAR-AI/ZLAR](https://github.com/ZLAR-AI/ZLAR)

Now I want to say something to everyone else.

I do not think this moment belongs only to engineers.

Yesterday's leak was not a hack. It was a packaging error. A human being made a mistake in a build pipeline. The consequence was mass exposure of proprietary source code that cannot be taken back. That kind of mistake — irreversible, fast, human — is going to keep happening. Not because people are careless, but because the speed at which actions become real is outpacing the speed at which humans can catch them.

The question is whether we build infrastructure that makes certain mistakes impossible, or whether we keep relying on humans and AI models to be perfect every time.

I know which one I trust.

If you are technical, I would deeply appreciate your scrutiny. Does this actually work the way I say it works? Where does it hold? Where can it be bypassed? Within its boundary, the gate is deterministic. Outside that boundary — if an agent finds a channel that does not pass through the gate — it has nothing to enforce. That boundary is what I need people to pressure-test.

If you are not technical, start with [signal/THESIS.md](THESIS.md) in the repository. It is the argument in plain language.

The build is continuing. I am learning in public. I am reporting as I go.

And I want to admit something plainly: I do not fully know the consequences of what I am building. In that state of not knowing, I hope I am doing the right thing.

If you are willing, have a look. Question it. Pressure-test it. Tell me where it works. Tell me where it fails. Tell me what kind of force field this really is.

I am asking for help building it.

And to everyone who has already taken the time to comment, question, and pay attention — thank you. It means more to me than I can say.
