# Changelog

All notable changes to ZLAR-OC will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/). ZLAR-OC uses calendar versioning (YYYY.MM.patch).

---

## [Unreleased]

### Added
- Complete six-layer containment stack: user isolation, Seatbelt sandbox, pf firewall, gate daemon, Ed25519 signed policy, append-only audit trail
- 12 CLI tools: `zlar-oc-gate`, `zlar-oc-audit`, `zlar-oc-policy`, `zlar-oc-karma`, `zlar-oc-journal`, `zlar-oc-launch`, `zlar-oc-watchdog`, `zlar-oc-availability`, `zlar-oc-brief`, `zlar-oc-audit-domains`, `zlar-oc-install-plist`, `zlar-oc-policy-health`
- Default sandbox profile (`openclaw.sb`) with deny-default Seatbelt rules
- Default firewall rules with HTTPS allowlist and LAN blocking
- Default gate policy (`default.policy.json`) with Ed25519 signing support
- Newsyslog configuration for audit trail rotation
- Test suite covering policy signing, sandbox profile, firewall rules, policy evaluator, and watchdog integrity
- Governance Guide explaining the three-tier governance file pattern
- User Template for writing agent governance files
- Multicellular Mapping documenting 50 biological precedents
- Install Guide with test gates at every phase
- Design documents for all six containment layers
- Open letter: "The Mind You Give It"
- Apache 2.0 license
- Security policy with threat model and coordinated disclosure process

### Platform
- macOS (Apple Silicon recommended)
- Requires Xcode Command Line Tools, Homebrew, jq, git
