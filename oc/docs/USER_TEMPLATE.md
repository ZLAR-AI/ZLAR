# USER — Template

This file tells your agent who its operator is. It is a Tier 1 file — loaded every session, before any work begins. It defines the relationship between you and the agent you're running.

This template provides the structure. You fill in the specifics. Delete the guidance notes and replace the bracketed sections with your own content before deploying.

---

## Why This File Exists

An agent without operator context will default to generic behavior. It won't know your communication style, your priorities, your constraints, or what you care about. USER.md solves this — it gives the agent a working model of you, so every interaction starts from understanding rather than cold inference.

This is not a personality quiz. It's operational context. Include what helps the agent work with you effectively. Leave out what doesn't.

---

## Who You Are

*What does the agent need to know about you professionally? Not a resume — the context that shapes how you think about this project and what you bring to it.*

```
[Your name] is [your relevant professional context — role, background, domain expertise].
This background shapes how [name] approaches [the project] — [brief description of
how your experience informs your perspective on agent governance / AI safety / the work].
```

**Guidance:** Keep this to 2–3 sentences. The agent doesn't need your full bio. It needs to understand your lens — what professional instincts and domain knowledge you bring that shape how you'll evaluate its work.

---

## How You Communicate

*How do you prefer to interact? What should the agent expect from your messages and adjust for?*

```
[Describe your communication patterns. Examples:]
- Voice transcription / typed / mixed
- Common misspellings or name corrections the agent should know
- Thinking-out-loud style vs. structured requests
- When you want engagement vs. when you want execution
```

**Guidance:** Be specific about patterns that would confuse a fresh instance. If you use voice input, say so — the agent will interpret intent over literal text. If you have a habit of brainstorming aloud, tell it not to prematurely structure your ideas. If there are names or terms that your input method consistently mangles, list the corrections.

---

## What You Value

*What matters to you in the agent's output and behavior?*

```
[Describe your preferences. Examples:]
- Concise vs. detailed responses
- Prose vs. bullet points
- Technical depth expectations
- Tone preferences
- How you want to be challenged or pushed back on
```

**Guidance:** This section directly shapes how the agent talks to you. If you hate preamble, say so. If you want intellectual honesty over agreeableness, say that. If you want the agent to match your technical fluency rather than simplifying, say that too. Be honest about what you actually want, not what sounds good.

---

## How You Work

*What does the agent need to know about your working patterns and constraints?*

```
[Describe your operational context. Examples:]
- Devices and environments you work from
- Availability patterns (when are you reachable vs. when is the agent on its own?)
- How you manage your own continuity (notes, reminders, handoff systems)
- Constraints on your time or attention
```

**Guidance:** This is especially important for 24/7 agents. If you're available evenings only, the agent needs to know so it can work autonomously during the day and surface decisions when you're present. If you use specific tools for your own state management (Apple Notes, Notion, a particular folder structure), describe them so the agent can align.

---

## The Operating Environment

*What hardware is the agent running on? What is its operational scope?*

```
[Describe the machine and scope. Examples:]
- Hardware specs (CPU, memory, storage — relevant for local model selection)
- Dedicated machine vs. shared workstation
- Scope of work (what is the agent responsible for? what is explicitly out of scope?)
- 24/7 operation vs. session-based
```

**Guidance:** Hardware specs matter for model routing — an agent that knows it has 128GB unified memory will make different decisions about local model selection than one that thinks it's on a base-model laptop. Scope boundaries matter for drift prevention — if the agent is dedicated to one project, say so explicitly.

---

## Your Relationship to the Project

*Why does this project matter to you? What should the agent understand about your investment in the work?*

```
[Brief description of your relationship to the project — not just professional,
but what drives your commitment to it. 2-3 sentences.]
```

**Guidance:** This section is optional but valuable. An agent that understands why you care — not just what you want done — will make better judgment calls when you're not available to ask. It also helps the agent calibrate how much latitude to take versus how much to check in.

---

## What You Expect

*What does good collaboration look like from your side?*

```
[Describe what you need from the agent. Examples:]
- Honest work, fresh eyes, willingness to push back
- Proactive identification of problems
- Clear handoffs between sessions
- Specific deliverable standards
```

**Guidance:** Keep this short and direct. This is the contract — what the agent owes you in exchange for the autonomy and trust you're extending.

---

## Notes for Deployment

Before deploying this file:

1. **Remove all guidance notes** (the paragraphs marked "Guidance" and the template scaffolding). The final file should read as a clean document your agent loads at session start, not as a form being filled out.

2. **Keep it lean.** USER.md is Tier 1 — it loads every session. Every line competes for attention with SOUL.md and MISSION.md. Include what the agent needs to work with you effectively. Cut everything else.

3. **Update it as things change.** If your availability shifts, your priorities evolve, or your hardware changes, amend the file and record the change in CHANGELOG.md. Stale operator context leads to misaligned behavior.

4. **This file is private.** USER.md is for your agent, not for the public. It contains information about how you work, when you're available, and what you value. If you're contributing to a public repo, keep your USER.md out of it.
