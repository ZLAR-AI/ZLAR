# ZLAR-OC

![ZLAR-OC Banner](assets/zlar-oc-banner.png)

### Your AI agent has access to your files, your credentials, your email, and your network. How do you know it's doing what it says it's doing?

You don't. Not unless something independent is watching.

**ZLAR-OC is open-source, OS-level containment and governance for AI agents.** It sits below the agent — not inside it. The agent does not govern itself. The operating system governs the agent. Mechanically. Cryptographically. Auditably.

---

## The Problem

AI agent frameworks give your agent tools, internet access, and filesystem control. Vendor safety programs tune model behavior at training time. But when it comes to independently verifying what your agent actually does at runtime — what files it touched, what network calls it made, whether it stayed within its declared scope — nothing exists.

You're trusting the agent to report its own behavior. That's the same as asking the entity being audited to audit itself. Every regulated industry in the world — finance, healthcare, nuclear, aviation — rejected this model decades ago. AI agents are the only domain where we still pretend it works.

ZLAR-OC closes this gap.

---

## How It Works

Six enforcement layers, each deliberately simple:

| Layer | What It Does | Why It's Dumb On Purpose |
|-------|-------------|--------------------------|
| **User isolation** | Agent runs under its own restricted macOS account | Can't access your files, credentials, or home directory |
| **Kernel sandbox** | Seatbelt profile enforces deny-by-default syscall policy | Agent can't modify its own sandbox. Period. |
| **Packet filter firewall** | Blocks LAN, metadata endpoints, unauthorized outbound | Network rules enforced at the OS, not by the agent |
| **Gate daemon** | Evaluates every action against signed policy before execution | Can't be persuaded, socially engineered, or talked into exceptions |
| **Signed Ed25519 policy** | Rules are cryptographically signed | Tampering is mathematically detectable |
| **Append-only audit trail** | Every action, evaluation, and decision recorded immutably | Neither agent nor operator can silently rewrite history |

The gate is dumb by design. It reads the signed policy, evaluates the requested action, approves or denies. That's the entire job. A dumb gate can't be convinced to make an exception. The simplicity is the security.

**The invariant:** Intelligence above. Enforcement below. Human authority over both. Policy is law. Audit trail is truth. This does not change with increased capability, autonomy, or trust.

---

## Quick Start

See the [Install Guide](docs/INSTALL_GUIDE.md) for the full walkthrough with test gates at every phase. The short version:

```bash
# Clone
git clone https://github.com/ZLAR-AI/ZLAR.git  # see oc/ directory

# Create isolated agent user
sudo sysadminctl -addUser aiagent -fullName "AI Agent" -password "" -home /Users/aiagent

# Deploy
sudo cp -r etc/zlar-oc/* /usr/local/etc/zlar-oc/
sudo cp bin/* /usr/local/bin/
sudo chmod +x /usr/local/bin/zlar-oc-*

# Generate signing keys and sign the default policy
zlar-oc-policy keygen
zlar-oc-policy sign \
  --input /usr/local/etc/zlar-oc/policies/default.policy.json \
  --key ~/.zlar-oc-signing.key \
  --output /usr/local/etc/zlar-oc/policies/active.policy.json

# Activate firewall and launch
sudo pfctl -f /etc/pf.conf && sudo pfctl -e
sudo zlar-oc-launch
```

**Requirements:** macOS (Apple Silicon recommended), Xcode Command Line Tools, Homebrew, jq, git.

---

## Give Your Agent a Mind — Not Just a Cage

ZLAR-OC enforces containment. But containment alone doesn't make an agent coherent. Your agent also needs identity, memory, and operational structure.

The [Governance Guide](docs/GOVERNANCE_GUIDE.md) shows you how to write governance files — markdown documents your agent loads every session to understand who it is, what it's doing, how it communicates, and how it relates to you. Think of it as the DNA inside the cell membrane. ZLAR-OC provides the membrane. You provide the DNA.

A [User Template](docs/USER_TEMPLATE.md) gets you started.

---

## Why Biology Matters

Nature solved the autonomous-agent-coordination problem billions of years ago when single cells became multicellular. Every mechanism in ZLAR-OC has a biological precedent — cell membranes, immune systems, DNA, the blood-brain barrier, apoptosis, morphogenesis.

The [Multicellular Mapping](docs/MULTICELLULAR_MAPPING.md) documents 50 of these parallels. Nature tested these patterns across billions of years of selection pressure. The ones that survived are the ones that worked.

---

## Current Limitations — Read Before Deploying

ZLAR-OC governs the **primary agent**. It does not yet govern agent-to-agent delegation.

If your agent uses an orchestrator pattern — spawning sub-agents to execute tasks in parallel — **those sub-agents operate outside the gate**. Their actions are not audited, not policy-checked, and not visible to HITL. This is a known architectural gap, not a bug. It is documented honestly here so you do not assume protection where it does not yet exist.

**What is governed today:**
- The primary agent's exec, filesystem, and network calls (via gate + signed policy)
- Human-in-the-loop decisions for flagged actions
- Append-only audit trail for all gate-evaluated events

**What is not yet governed:**
- Sub-agents spawned by the primary agent
- Agent-to-agent calls and delegation chains
- Actions taken by agents running under different sessions

Multi-agent governance is on the roadmap. If you are running orchestrator-style agents (common in OpenClaw power-user setups), do not rely on ZLAR-OC as a complete containment solution yet. Use it for the primary agent layer while this gap is being closed.

---

## The Conflict of Interest

Agent vendors have every incentive to make agents capable and adopted. They have far less incentive to make them independently verifiable. Self-imposed safety measures are vendor-controlled, vendor-assessed, and vendor-revocable.

ZLAR-OC is the independent external layer. It doesn't depend on the model's cooperation or the vendor's safety measures. It enforces at the OS level with a signed policy and an audit trail the agent cannot alter.

For the full argument: [The Mind You Give It — An Open Letter](OPEN_LETTER.md).

---

## Documentation

| Document | Description |
|----------|-------------|
| [Install Guide](docs/INSTALL_GUIDE.md) | Step-by-step setup with test gates at every phase |
| [Governance Guide](docs/GOVERNANCE_GUIDE.md) | How to write governance files for your agent |
| [User Template](docs/USER_TEMPLATE.md) | Starting template for your USER.md |
| [Design: User Isolation](docs/DESIGN_USER_ISOLATION.md) | macOS account separation architecture |
| [Design: Sandbox Profile](docs/DESIGN_SANDBOX_PROFILE.md) | Seatbelt sandbox design and rationale |
| [Design: Firewall](docs/DESIGN_PF_FIREWALL.md) | Packet filter rules and phased allowlisting |
| [Design: Audit & Policy](docs/DESIGN_AUDIT_AND_POLICY.md) | Gate daemon, signed policy, audit trail |
| [Multicellular Mapping](docs/MULTICELLULAR_MAPPING.md) | 50 biological precedents for agent governance |
| [Open Letter](OPEN_LETTER.md) | The argument for independent agent governance |

---

## Running the Tests

```bash
cd tests/
bash test-policy-signing.sh
bash test-sandbox-profile.sh
bash test-pf-rules.sh
bash test-policy-evaluator.sh
bash test-watchdog-and-integrity.sh
```

All tests are self-contained shell scripts that verify each layer independently.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security disclosures: see [SECURITY.md](SECURITY.md).

---

## License

[Apache License 2.0](LICENSE)

---

*Built by ZLAR. Governed by the system it builds.*

---

## Contact

- **X:** [@vincentnijjar](https://x.com/vincentnijjar)
- **Email:** hello@zlar.ai
- **Website:** [zlar.ai](https://zlar.ai)
