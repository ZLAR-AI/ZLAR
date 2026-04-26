# Troubleshooting

Run `zlar doctor` first. It checks dependencies, keys, hooks, policy, and the gate in one command:

```bash
~/.zlar/bin/zlar doctor
```

If doctor doesn't resolve your issue, find your symptom below.

---

## Hook not firing (agent runs commands without governance)

**Symptom:** Your AI agent executes commands freely. No audit entries appear.

**Cause:** The hook is not configured for your framework, or the hook path is wrong.

**Fix:**

1. Check which frameworks have hooks:
   ```bash
   zlar doctor
   ```
   Look under "Hook Configuration" for red or yellow entries.

2. For Claude Code, verify `~/.claude/settings.json` contains a `PreToolUse` hook pointing to your ZLAR adapter:
   ```json
   {
     "hooks": {
       "PreToolUse": [{
         "matcher": ".*",
         "hooks": [{"type": "command", "command": "~/.zlar/adapters/claude-code/hook.sh", "timeout": 310}]
       }]
     }
   }
   ```

3. Verify the adapter is executable:
   ```bash
   chmod +x ~/.zlar/adapters/claude-code/hook.sh
   ```

4. Verify the gate is executable:
   ```bash
   chmod +x ~/.zlar/bin/zlar-gate
   ```

---

## Gate crashes or produces no output

**Symptom:** Every tool call is denied with "ZLAR gate crash" in the reason.

**Cause:** Usually a bash version or missing dependency issue.

**Fix:**

1. Check bash version (gate requires 4+):
   ```bash
   bash --version
   ```
   On macOS, the system bash is 3.2. Install bash 4+:
   ```bash
   brew install bash
   ```

2. Check that jq is installed and on PATH:
   ```bash
   jq --version
   ```
   If missing: `brew install jq` (macOS) or `sudo apt install jq` (Linux).

3. Check gate crash log for details:
   ```bash
   cat ~/.zlar/var/log/gate-crash.log
   ```

---

## Policy not loading or signature invalid

**Symptom:** Gate denies everything, or `zlar doctor` reports policy signature issues.

**Cause:** Policy file is missing, corrupted, or signed with a different key.

**Fix:**

1. Verify the policy file exists:
   ```bash
   ls -la ~/.zlar/etc/policies/active.policy.json
   ```

2. Re-sign the policy:
   ```bash
   ~/.zlar/bin/zlar-policy sign \
     --input ~/.zlar/etc/policies/active.policy.json \
     --key ~/.zlar-signing.key
   ```

3. If the signing key is missing, regenerate the keypair:
   ```bash
   ~/.zlar/bin/zlar-policy keygen
   ```
   Then re-sign the policy (step 2).

---

## Ed25519 not supported

**Symptom:** Install fails at "Ed25519 support" check, or signing operations fail.

**Cause:** System openssl is too old (pre-1.1.1) or macOS LibreSSL doesn't support Ed25519.

**Fix (macOS):**

```bash
brew install openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
```

Add the export to your `~/.zshrc` or `~/.bashrc` to make it permanent.

**Fix (Linux):**

```bash
sudo apt install openssl   # Debian/Ubuntu
sudo yum install openssl   # RHEL/CentOS
```

Verify: `openssl version` should show 1.1.1 or later.

---

## Key pair mismatch

**Symptom:** `zlar doctor` reports "Key pair mismatch" or receipt verification fails.

**Cause:** The public key doesn't correspond to the private key (usually after manual key operations).

**Fix:**

Re-derive the public key from the private key:

```bash
openssl pkey -in ~/.zlar-signing.key -pubout -out ~/.zlar/etc/keys/policy-signing.pub
```

Then re-sign the policy:

```bash
~/.zlar/bin/zlar-policy sign \
  --input ~/.zlar/etc/policies/active.policy.json \
  --key ~/.zlar-signing.key
```

---

## "Awaiting Telegram approval" but no Telegram configured

**Symptom:** Actions are denied with "Awaiting Telegram approval" message but you haven't set up Telegram.

**Cause:** Your policy has `"action": "ask"` rules but Telegram is not configured.

**Fix (option 1 — set up Telegram):**

```bash
~/.zlar/bin/zlar telegram
```

**Fix (option 2 — stay in deny-only mode):**

The default policy (`lt-default.policy.json`) uses only `allow` and `deny` rules, never `ask`. If you've modified the policy and added `ask` rules, either change them back to `deny` or set up Telegram.

---

## Telegram buttons don't respond after reboot

**Symptom:** The gate sends Telegram messages, but tapping Approve or Deny does nothing. Buttons stay static with no animation.

**Cause:** The callback listener daemon (`zlar-tg-poll`) is not running. It dies on reboot if the boot script can't find the token file. The gate sends messages (outbound API call), but nobody is polling for button callbacks (inbound).

**Fix:**

```bash
sudo /usr/local/bin/zlar-tg-boot.sh &
```

**Permanent fix:** The updated `zlar-tg-boot.sh` stores the admin user in `/etc/zlar/admin-user` so it survives reboots. If the problem recurs after a fresh OS install, run:

```bash
sudo mkdir -p /etc/zlar
echo "$(whoami)" | sudo tee /etc/zlar/admin-user
sudo /usr/local/bin/zlar-tg-boot.sh &
```

**After every reboot, run `zlar doctor`** — it checks whether the callback listener is alive and the HMAC secret is readable.

**If the dispatcher does not auto-restart after a crash**, the LaunchDaemon plist may be missing `KeepAlive`. The canonical plist is at `etc/com.zlar.tg-dispatcher.plist` in the repo. To reinstall it:

```bash
sudo cp etc/com.zlar.tg-dispatcher.plist /Library/LaunchDaemons/
sudo launchctl unload /Library/LaunchDaemons/com.zlar.tg-dispatcher.plist
sudo launchctl load /Library/LaunchDaemons/com.zlar.tg-dispatcher.plist
```

---

## Gate silently dies (all tool calls allowed, no audit entries)

**Symptom:** No audit entries being written. Agent runs commands freely. `zlar doctor` gate tests show "skipped (gate busy)."

**Cause:** The gate is crashing during initialization. The most common cause: the HMAC secret file at `/var/run/zlar-tg/inbox-hmac-secret` exists but is not readable by your user. With `set -euo pipefail`, this kills the gate before it reaches decision-making. Claude Code treats broken hook output as "continue."

**Fix:**

```bash
sudo chmod 640 /var/run/zlar-tg/inbox-hmac-secret
```

Or restart the boot script which regenerates it with correct permissions:

```bash
sudo /usr/local/bin/zlar-tg-boot.sh &
```

---

## Audit trail not writing

**Symptom:** `zlar audit` shows no entries even though the gate is running.

**Cause:** Audit directory doesn't exist or isn't writable.

**Fix:**

```bash
mkdir -p ~/.zlar/var/log
chmod u+w ~/.zlar/var/log
```

---

## Node.js not found (MCP gate or receipt verification)

**Symptom:** `bin/zlar-verify` fails with "node: command not found."

**Cause:** Node.js is not installed or not on PATH. The MCP gate and receipt verifier require Node.js 18+.

**Note:** The bash gate (`bin/zlar-gate`) does not require Node.js. If you're only using Claude Code, Cursor, or Windsurf, Node.js is optional.

**Fix:**

```bash
# macOS
brew install node

# Linux
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

---

## Permission errors on signing key

**Symptom:** "Permission denied" when the gate tries to sign audit entries.

**Cause:** The signing key file permissions are too restrictive or the key is owned by a different user.

**Fix:**

```bash
chmod 600 ~/.zlar-signing.key
ls -la ~/.zlar-signing.key    # verify owner is your user
```

---

## Still stuck?

1. Run `zlar doctor` and share the output
2. Check the gate log: `cat ~/.zlar/var/log/gate.log | tail -50`
3. Open an issue: https://github.com/ZLAR-AI/ZLAR/issues
