# Security Policy

## Scope

ZLAR-OC is an OS-level containment system for AI agents. Its security boundary is the enforcement surface between an autonomous agent and the host operating system — user isolation, kernel sandbox, packet filter firewall, gate daemon, signed policy, and append-only audit trail.

Any vulnerability that allows an agent (or external attacker) to bypass, weaken, or tamper with any of these six layers is in scope.

---

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:

1. Go to [ZLAR-AI/ZLAR-OC Security Advisories](https://github.com/ZLAR-AI/ZLAR/security/advisories)
2. Click **"Report a vulnerability"**
3. Provide a clear description, reproduction steps, and affected components

We will acknowledge receipt within 48 hours and provide a timeline for remediation. We aim to resolve critical issues within 14 days.

If you cannot use GitHub's reporting tool, open a regular issue with the title **"Security concern — requesting private channel"** and we will establish one.

---

## Threat Model

ZLAR-OC defends against the following adversaries:

**Compromised or misaligned agent.** The agent attempts to escalate privileges, exfiltrate data, modify its own containment, or act outside its declared policy scope. ZLAR-OC assumes the agent is adversarial by default — containment does not depend on agent cooperation.

**Policy tampering.** An attacker (or the agent itself) attempts to modify enforcement rules after deployment. Ed25519 signature verification ensures that any alteration to the policy is mathematically detectable. Unsigned or mis-signed policies are rejected by the gate.

**Audit trail manipulation.** An attacker attempts to rewrite, truncate, or selectively delete audit records to conceal unauthorized actions. The append-only audit trail, combined with log rotation via newsyslog, makes silent history rewriting detectable.

**Network exfiltration.** The agent attempts to reach unauthorized endpoints, contact LAN devices, or use metadata services to discover infrastructure. The pf firewall enforces deny-by-default with explicit allowlisting at the OS level.

**Sandbox escape.** The agent attempts to break out of Seatbelt confinement to access files, processes, or system calls outside its profile. The sandbox profile is deny-default; the agent cannot modify its own profile.

### Out of Scope

ZLAR-OC does not protect against compromise of the host operating system itself, physical access attacks, or vulnerabilities in the underlying macOS kernel. It also does not govern what happens inside the agent's inference process — it governs what the agent can *do*, not what it can *think*.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| main (HEAD) | Yes |
| Tagged releases | Yes, current and previous minor |

---

## Disclosure Policy

We practice coordinated disclosure. If you report a vulnerability, we will:

1. Acknowledge within 48 hours
2. Confirm the issue and assess severity within 7 days
3. Develop and test a fix
4. Release the fix and publish a security advisory
5. Credit you in the advisory (unless you prefer anonymity)

We ask that reporters refrain from public disclosure until a fix is available, or until 90 days have elapsed — whichever comes first.

---

## Security Design Principles

ZLAR-OC's architecture follows one invariant: **intelligence above, enforcement below, human authority over both.**

Every enforcement mechanism is deliberately simple. The gate daemon evaluates actions against a signed policy — it does not reason, negotiate, or make exceptions. Simplicity is the security property. A mechanism too simple to be persuaded is a mechanism that cannot be socially engineered.

For detailed architecture documentation:

- [Design: User Isolation](docs/DESIGN_USER_ISOLATION.md)
- [Design: Sandbox Profile](docs/DESIGN_SANDBOX_PROFILE.md)
- [Design: Firewall](docs/DESIGN_PF_FIREWALL.md)
- [Design: Audit & Policy](docs/DESIGN_AUDIT_AND_POLICY.md)
