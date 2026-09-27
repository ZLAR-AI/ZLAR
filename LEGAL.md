# Legal Notice — ZLAR

**Effective Date:** March 2026
**Entity:** ZLAR Inc., a corporation incorporated under the Canada Business Corporations Act (CBCA)

---

## 1. Regulatory Classification

ZLAR is a deterministic, rule-based policy enforcement tool. It does not use machine learning, does not make inferences from inputs, and does not generate predictions, recommendations, or decisions. It classifies actions via string matching against human-authored rules and blocks actions that match deny patterns.

Under the definitions established by the EU AI Act (Regulation 2024/1689, Article 3(1)), the OECD AI framework, the Colorado AI Act (SB 24-205), and other enacted AI legislation, **ZLAR does not meet the definition of an "AI system."** Recital 12 of the EU AI Act explicitly excludes "systems that are based on the rules defined solely by natural persons to automatically execute operations."

ZLAR is an authorization tool that helps operators of AI systems manage risk. It is not itself an AI system. This distinction is legally significant: AI-specific regulatory obligations (risk tiers, transparency requirements, conformity assessments) do not apply to ZLAR.

ZLAR may assist AI system providers and deployers in satisfying obligations under Articles 9 (risk management), 14 (human oversight), and 15 (cybersecurity) of the EU AI Act. However, ZLAR Inc. makes no representation that use of ZLAR satisfies any specific regulatory requirement. See Section 7.

---

## 2. Software Provided "As Is"

ZLAR is provided "AS IS" and "AS AVAILABLE" without warranty of any kind, express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, non-infringement, and any warranties arising out of course of dealing or usage of trade.

ZLAR Inc., its founders, officers, directors, employees, contributors, and agents (collectively, "ZLAR Parties") make no representations or warranties regarding:

- The completeness, accuracy, reliability, or suitability of ZLAR for any purpose
- The ability of ZLAR to prevent, detect, contain, or mitigate any specific threat, vulnerability, or harmful action
- The continuous, uninterrupted, error-free, or secure operation of ZLAR
- The compatibility of ZLAR with any specific platform, tool, model, or runtime environment, including but not limited to Anthropic's Claude Code, Cursor, or Windsurf

---

## 3. No Guarantee of Containment or Protection

**ZLAR is an authorization tool, not a guarantee.**

ZLAR provides policy enforcement mechanisms for AI agent tool calls. It is designed to classify risk, match against human-authored policy rules, and block actions that match deny patterns. However:

- **No authorization or safety system can guarantee containment.** AI agents may behave in ways that are novel, unexpected, or outside the design parameters of any enforcement mechanism.
- **ZLAR does not control the AI model.** It operates at the tool-call layer. The model's reasoning, intent, and outputs are outside ZLAR's enforcement surface.
- **ZLAR does not replace human judgment.** It provides a structured mechanism for setting boundaries. The quality of protection depends on the policy rules in use and the diligence of the operator's oversight.
- **Agentic AI is an emerging technology.** The behavior of autonomous AI systems is not fully understood by any entity — including model providers, researchers, and safety and security tool developers. Users acknowledge this inherent uncertainty.

### Known Limitations

ZLAR Inc. discloses the following limitations in the interest of transparency:

- ZLAR's agent-side checkpoint acts only at the tool-call layer (framework hooks). Actions taken by AI agents outside the hooks protocol are not intercepted.
- The risk classifier uses pattern matching against known command signatures. Novel commands, obfuscated inputs, or encoding variations may not be classified correctly.
- ZLAR is one layer of defense in a defense-in-depth strategy. It is not a complete security solution and should not be relied upon as the sole mechanism for protecting against AI agent actions.
- Cursor and Windsurf adapters are built from framework hook documentation and have not been tested against live hook payloads. The Claude Code adapter is verified.
- ZLAR has not undergone independent third-party security audit as of the effective date of this notice.

This disclosure is provided to ensure that users can make informed decisions. It is not an exhaustive list of all possible limitations.

---

## 4. Assumption of Risk

By downloading, installing, configuring, or using ZLAR, you expressly acknowledge and agree that:

a) You understand that agentic AI systems can take actions that are unexpected, harmful, or irreversible.

b) You understand that ZLAR is a risk-reduction tool, not a risk-elimination tool.

c) You assume full responsibility for all actions taken by any AI agent operating on your systems, whether or not ZLAR is installed and functioning.

d) You assume full responsibility for the configuration, deployment, and maintenance of ZLAR, including the management of cryptographic keys and the review of audit logs.

e) You understand that ZLAR has not been independently certified, audited, or validated by any regulatory body, standards organization, or third-party security firm as a sufficient protection mechanism for any particular use case, jurisdiction, or compliance requirement.

f) You are solely responsible for determining whether ZLAR is appropriate for your use case, your regulatory environment, and your risk tolerance.

---

## 5. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL ANY ZLAR PARTY BE LIABLE FOR ANY:

- Direct, indirect, incidental, special, consequential, exemplary, or punitive damages
- Loss of profits, revenue, data, goodwill, or business opportunity
- Cost of procurement of substitute goods or services
- Damages arising from unauthorized access to or alteration of your data, systems, or transmissions
- Damages arising from the actions or failures of any AI agent, model, or system, whether or not ZLAR is in use
- Damages arising from the failure of ZLAR to prevent, detect, or contain any specific action, threat, or vulnerability

This limitation applies regardless of the legal theory (contract, tort, negligence, strict liability, or otherwise) and regardless of whether any ZLAR Party has been advised of the possibility of such damages.

**In jurisdictions that do not permit the exclusion or limitation of certain damages:** the aggregate liability of all ZLAR Parties for all claims arising from or related to ZLAR shall not exceed the amount you paid to ZLAR Inc. for ZLAR in the twelve (12) months preceding the claim, or CAD $100, whichever is greater.

---

## 6. Third-Party Dependencies

ZLAR interacts with and depends upon third-party software and services, including but not limited to:

- **Anthropic's Claude Code** — an AI coding agent. ZLAR Inc. is not affiliated with, endorsed by, or responsible for Anthropic or its products.
- **Cursor** — an AI-powered code editor. ZLAR Inc. is not affiliated with or responsible for Anysphere Inc. or its products.
- **Windsurf** — an AI-powered code editor. ZLAR Inc. is not affiliated with or responsible for Codeium Inc. or its products.
- **Telegram** — optionally used for approval notifications. ZLAR Inc. is not affiliated with or responsible for Telegram's service, availability, or security.

ZLAR Inc. has no control over and assumes no responsibility for the behavior, availability, security, or compliance of any third-party software, service, or platform. Changes to third-party software (including breaking changes to framework hook protocols) may affect ZLAR's operation without notice.

---

## 7. No Professional Advice or Regulatory Certification

Nothing in ZLAR's documentation, source code, examples, or communications constitutes:

- Legal advice
- Security consulting, assurance, or certification
- Compliance guidance for any regulatory framework, including but not limited to:
  - **Canada:** PIPEDA, OSFI guidelines, provincial privacy legislation (note: Canada's proposed AIDA was never enacted and is not currently in force)
  - **European Union:** EU AI Act, GDPR, NIS2 Directive, EU Cyber Resilience Act, EU Product Liability Directive
  - **United States:** CCPA/CPRA, Colorado AI Act, Texas TRAIGA, state AI laws, NIST AI Risk Management Framework, sector-specific regulations (HIPAA, SOX, GLBA)
  - **Asia-Pacific:** APPI (Japan), PDPA (Singapore), PIPL (China), IT Act (India)
  - **International:** ISO/IEC 42001 (AI Management Systems), ISO 27001
- A certification or representation that your AI deployment meets any standard of safety, security, or oversight

**Note on NIST AI RMF:** Parts of ZLAR map to functions of the NIST AI Risk Management Framework. Compliance with NIST AI RMF provides statutory affirmative defenses in certain US jurisdictions (including Colorado and Texas). However, ZLAR Inc. does not certify that use of ZLAR constitutes compliance with NIST AI RMF or any other framework.

If you require assurance that your use of AI meets regulatory requirements in your jurisdiction, consult qualified legal and security professionals.

---

## 8. Indemnification

You agree to indemnify, defend, and hold harmless all ZLAR Parties from and against any and all claims, damages, losses, liabilities, costs, and expenses (including reasonable legal fees) arising from or related to:

a) Your use of ZLAR

b) Your violation of these terms or any applicable law

c) Any actions taken by AI agents operating on your systems, whether or not ZLAR is in use

d) Any claim by a third party arising from your deployment of ZLAR or any AI agent

e) Your failure to maintain adequate security, oversight, or configuration of ZLAR or any associated system

---

## 9. Vulnerability Disclosure and Security Maintenance

ZLAR Inc. is committed to responsible vulnerability disclosure and timely patching of known security issues in ZLAR. Security vulnerabilities should be reported privately to [security@zlar.ai](mailto:security@zlar.ai) or through GitHub's private vulnerability reporting, as described in [SECURITY.md](SECURITY.md).

This commitment does not create an obligation to provide ongoing maintenance, support, or updates to any version of ZLAR. Rights to use current ZLAR source are set by the [LICENSE](LICENSE) and by any written permission or separate written terms. Users and source reviewers are responsible for monitoring the terms and update path that apply to their own access grant or deployment.

---

## 10. Prior Public Distribution and the Current License

Prior ZLAR source distributions that were made public under the Apache License 2.0 remain under the Apache License 2.0. Making the current private core proprietary/commercial does not revoke, narrow, claw back, or alter rights in those prior public copies.

Current private-core ZLAR source is proprietary/commercial source. Use, copying, modification, distribution, sublicensing, hosting, service provision, publication, benchmarking for publication, and derivative works require written permission or a separate written agreement from ZLAR Inc. or Vincent Nijjar unless another written license applies, such as the Permission to Evaluate in the [LICENSE](LICENSE).

This notice is not a final customer agreement. Source review, evaluation access, paid support, enterprise features, hosted service access, or customer distribution may be subject to additional terms and legal obligations. ZLAR Inc. makes no representation in this repository notice that any particular commercial, regulatory, product-liability, or cybersecurity-law posture has been approved by counsel.

---

## 11. Intellectual Property

Current private-core ZLAR source is proprietary/commercial source. See [LICENSE](LICENSE). Prior public ZLAR source distributions remain under the Apache License 2.0, whose text is preserved at [LICENSES/Apache-2.0-prior-public.txt](LICENSES/Apache-2.0-prior-public.txt).

"ZLAR," "ZLAR," "ZLAR-CC," "ZLAR-OC," "ZLAR Gate," and the ZLAR name and associated marks are trademarks of ZLAR Inc. Use of these marks is subject to ZLAR Inc.'s trademark policies.

---

## 12. Data and Privacy

ZLAR processes data locally on your machine. It does not transmit data to ZLAR Inc. or any ZLAR-controlled server. However:

- ZLAR generates audit logs and records of agent actions on your local filesystem.
- If Telegram approval is enabled, ZLAR sends approval requests to your Telegram account, which involves transmission of action descriptions over Telegram's network.
- You are solely responsible for the handling, storage, and protection of any data processed or logged by ZLAR, including any personal data, credentials, or sensitive information that may appear in audit logs or approval requests.

ZLAR Inc. does not collect, store, or process your data through ZLAR.

---

## 13. Export Compliance

ZLAR includes cryptographic functionality (Ed25519 signing and verification). You are responsible for compliance with all applicable export control laws and regulations in your jurisdiction, including but not limited to Canadian export controls, U.S. Export Administration Regulations (EAR), and EU dual-use regulations.

---

## 14. Governing Law and Jurisdiction

These terms shall be governed by and construed in accordance with the laws of the Province of Manitoba and the federal laws of Canada applicable therein, without regard to conflict of law principles.

Any dispute arising from or relating to ZLAR or these terms shall be subject to the exclusive jurisdiction of the courts of the Province of Manitoba, Canada.

Before initiating any legal proceeding, the parties agree to attempt good-faith resolution through written communication for a period of not less than thirty (30) days.

---

## 15. Severability

If any provision of this notice is held to be unenforceable or invalid, that provision shall be modified to the minimum extent necessary to make it enforceable, or if modification is not possible, severed. The remaining provisions shall continue in full force and effect.

---

## 16. Entire Agreement

This repository legal notice and the current private-core source license notice do not replace any separate written agreement executed by ZLAR Inc. or Vincent Nijjar. They also do not revoke, narrow, claw back, or alter rights in prior public ZLAR source distributions made under Apache-2.0.

---

## 17. Changes to This Notice

ZLAR Inc. reserves the right to modify this legal notice at any time. Changes will be reflected in the repository and on [zlar.ai](https://zlar.ai). Continued use of ZLAR after changes constitutes acceptance.

---

## 18. Contact

**ZLAR Inc.**
Email: [hello@zlar.ai](mailto:hello@zlar.ai)
Web: [zlar.ai](https://zlar.ai)

---

*This legal notice describes the current private-core source boundary and preserves the prior Apache-2.0 non-clawback boundary. It is not a customer commercial agreement and does not represent counsel approval of any external distribution terms.*
