# ZLAR-OC Pre-Public Security Audit

**Date:** 2026-03-12
**Scope:** Full repository audit before converting to public visibility
**Auditor:** Automated deep scan (secrets, git history, code vulnerabilities)

---

## Executive Summary

The repository is **largely safe to open-source**. No secrets, credentials, or
PII are leaked in current code or git history. The `.gitignore` is comprehensive.
The main findings are logic-level security bugs in the enforcement code itself,
not data exposure issues.

**Findings:** 2 HIGH, 5 MEDIUM, 3 LOW severity issues.

---

## Secrets & Credentials Scan: CLEAN

- No hardcoded API keys, passwords, tokens, or private keys in code or git history
- Telegram config uses empty template strings; secrets loaded from environment variables
- `.gitignore` properly blocks `.env`, `*.pem`, `*.key`, `*.secret`, `*.token`, cloud config dirs
- Git history clean across all 14 commits — no deleted secret files
- No `.env`, certificate, or cloud credential files in the repo
- Largest binary: `assets/zlar-oc-banner.png` (~908KB) — acceptable

---

## Findings

### HIGH Severity

#### H1: Policy Signature Verification Bypass

- **Location:** `bin/zlar-oc-gate` lines 293-296
- **Issue:** When `signature_required=true` but the public key file is missing,
  the gate logs a WARNING but loads the policy without verification.
- **Impact:** An attacker who deletes the public key file can deploy unsigned
  malicious policies, defeating the entire policy signing mechanism.
- **Recommendation:** Refuse to load the policy and exit with an error when
  the key is required but missing.

#### H2: Temporary File Race Conditions (CWE-377)

- **Location:** `bin/zlar-oc-policy` (lines 141, 157, 162, 235, 244, 249),
  `bin/zlar-oc-gate` (lines 481, 487, 492), `bin/zlar-oc-launch` (lines 197-199)
- **Issue:** ~10 temp files containing cryptographic material (policy hashes,
  signatures) are created as individual files in world-readable `/tmp`.
- **Impact:** Local symlink attacks could read or modify cryptographic material.
- **Recommendation:** Create a private temp directory per operation:
  ```bash
  TMPDIR=$(mktemp -d /tmp/zlar-oc-XXXXXX)
  chmod 700 "$TMPDIR"
  trap "rm -rf '$TMPDIR'" EXIT
  ```

### MEDIUM Severity

#### M1: JSON Injection via printf

- **Location:** `bin/zlar-oc-gate` lines 266, 1111, 1145, 1170
- **Issue:** JSON constructed with `printf` using unescaped variables (`${path}`,
  `${message}`, `${table_match}`). Filenames containing `"` break JSON structure.
- **Impact:** Audit log manipulation, broken event parsing, potential for hiding
  real security events behind crafted fake entries.
- **Recommendation:** Escape special characters or use `jq` to construct JSON safely.

#### M2: jq Filter Injection

- **Location:** `bin/zlar-oc-policy` line 453
- **Issue:** `${id}` variable interpolated directly into jq filter without escaping.
- **Impact:** Crafted rule IDs containing `"` can break the jq filter.
- **Recommendation:** Use `jq --arg` for safe variable interpolation.

#### M3: World-Writable Temp Path for Log Reading

- **Location:** `bin/zlar-oc-gate` line 1218
- **Issue:** Reads logs from `/tmp/.openclaw/` which is in a world-writable location.
- **Impact:** Symlink attacks could cause the gate to read arbitrary files.
- **Recommendation:** Use a non-world-writable path or validate file ownership.

#### M4: Silent Base64 Decode Failure

- **Location:** `bin/zlar-oc-gate` line 493
- **Issue:** Invalid base64 in signatures silently fails (stderr redirected to
  `/dev/null`), potentially causing signature verification to produce undefined results.
- **Recommendation:** Validate base64 input and fail explicitly on decode errors.

#### M5: Unvalidated Output File Paths

- **Location:** `bin/zlar-oc-audit` lines 343-349
- **Issue:** Fingerprint output path not validated before writing.
- **Impact:** If the output path is user-controlled, arbitrary file overwrite is possible.
- **Recommendation:** Validate output paths against an allowlist or restrict to
  expected directories.

### LOW Severity

#### L1: Root Execution Warning Without Exit

- **Location:** `bin/zlar-oc-gate` lines 1304-1310
- **Issue:** Running as root logs a warning but continues execution.
- **Recommendation:** Exit with error when running as root.

#### L2: Log Directory Permissions Not Enforced

- **Location:** `bin/zlar-oc-gate` lines 37-38
- **Issue:** `/var/log/zlar-oc/` permissions not explicitly set in scripts.
- **Recommendation:** Add `chmod 750 /var/log/zlar-oc` to setup/startup.

#### L3: Empty Password for aiagent User

- **Location:** Setup documentation
- **Issue:** `sysadminctl -addUser aiagent -password ""` creates a user with
  no password. While the account is sandboxed, this should be documented more
  clearly.
- **Recommendation:** Document that interactive login must be disabled after
  account creation.

---

## Prioritized Remediation

| Priority | Issue | Action |
|----------|-------|--------|
| **Must-fix** | H1: Signature bypass | Change warning to hard failure when key missing |
| **Should-fix** | H2: Temp file races | Use private temp directories with traps |
| **Should-fix** | M1: JSON injection | Escape variables or use jq for JSON construction |
| **Should-fix** | M2: jq filter injection | Use `jq --arg` for variable interpolation |
| **Nice-to-have** | M3-M5, L1-L3 | Address in follow-up commits |

---

## Conclusion

The repository contains no leaked secrets and is safe from a data-exposure
perspective. The identified issues are logic-level bugs in the security
enforcement code that should be addressed to ensure the tool's own security
posture withstands public scrutiny.
