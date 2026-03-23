# ZLAR-OC Install Guide

**For:** New Mac setup with OpenClaw + ZLAR-OC containment
**Philosophy:** Shield before sword. Every layer is tested before the next is added.
**Audience:** Anyone who wants to run an autonomous AI agent safely.

---

## Pre-flight Checklist

Before you open the box:

- [ ] This guide printed or accessible from another device (your phone works)
- [ ] Telegram app installed on your phone
- [ ] Telegram bot created via @BotFather (you'll need the token)
- [ ] GitHub account with access to the ZLAR-OC repo
- [ ] Your soul.md drafted (or use the template — customize later)
- [ ] Time: budget 2-3 hours for a careful first install

---

## Phase 0: Open the Box

1. Power on the new Mac
2. Complete the macOS Setup Assistant
   - **Decision point:** Apple ID sign-in
   - Recommendation: Skip Apple ID for now. Sign in AFTER ZLAR-OC is running.
   - Reason: Shield before sword. Don't expose iCloud, Keychain, Photos, HomeKit
     until the containment is in place.
3. Install Xcode Command Line Tools:
   ```
   xcode-select --install
   ```
4. Install Homebrew:
   ```
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
5. Install core dependencies:
   ```
   brew install jq git
   ```

---

## Phase 1: Create the User Separation (Layer 2a)

The agent runs as a separate OS user. It cannot touch your files.

1. Create the `aiagent` user:
   ```
   sudo sysadminctl -addUser aiagent -fullName "AI Agent" -password "" -home /Users/aiagent
   sudo dscl . -create /Users/aiagent UserShell /bin/zsh
   ```

2. Create workspace directories:
   ```
   sudo mkdir -p /Users/aiagent/workspace
   sudo mkdir -p /Users/aiagent/.openclaw
   sudo chown -R aiagent:staff /Users/aiagent
   sudo chmod 700 /Users/aiagent
   ```

3. **TEST:** Verify isolation
   ```
   sudo -u aiagent ls ~/Desktop  # Should fail — can't see your files
   sudo -u aiagent whoami        # Should print: aiagent
   ```
   - [ ] Confirmed: aiagent cannot access admin home

---

## Phase 2: Install ZLAR-OC (The Shield)

1. Clone the repository:
   ```
   cd /usr/local
   sudo git clone https://github.com/ZLAR-AI/ZLAR.git /usr/local/etc/zlar-repo
   # ZLAR-OC files are in the oc/ subdirectory
   ```

2. Deploy configuration:
   ```
   sudo mkdir -p /usr/local/etc/zlar-oc
   sudo cp -r /usr/local/etc/zlar-oc-repo/etc/zlar-oc/* /usr/local/etc/zlar-oc/
   sudo cp /usr/local/etc/zlar-oc-repo/bin/* /usr/local/bin/
   sudo chmod +x /usr/local/bin/zlar-oc-*
   ```

3. Create log directories:
   ```
   sudo mkdir -p /var/log/zlar-oc
   sudo chown admin:_aiagent /var/log/zlar-oc
   sudo chmod 770 /var/log/zlar-oc
   ```

4. Generate signing keys:
   ```
   zlar-oc-policy keygen
   ```
   This creates:
   - `~/.zlar-oc-signing.key` (private, stays with you)
   - `/usr/local/etc/zlar-oc/keys/policy-signing.pub` (public, gate reads this)

5. Sign the default policy:
   ```
   zlar-oc-policy sign \
     --input /usr/local/etc/zlar-oc/policies/default.policy.json \
     --key ~/.zlar-oc-signing.key \
     --output /usr/local/etc/zlar-oc/policies/active.policy.json
   ```

6. **TEST:** Verify policy signature
   ```
   zlar-oc-policy verify /usr/local/etc/zlar-oc/policies/active.policy.json
   ```
   - [ ] Confirmed: Policy signature valid

---

## Phase 3: Activate the Firewall (Layer 3)

1. Install pf rules:
   ```
   sudo cp /usr/local/etc/zlar-oc/pf-rules/zlar-oc.rules /etc/pf.anchors/zlar-oc
   ```

2. Add anchor to pf.conf:
   ```
   # Add these lines to /etc/pf.conf:
   anchor "zlar-oc"
   load anchor "zlar-oc" from "/etc/pf.anchors/zlar-oc"
   ```

3. Enable and load:
   ```
   sudo pfctl -f /etc/pf.conf
   sudo pfctl -e
   ```

4. **TEST:** Verify firewall rules loaded
   ```
   sudo pfctl -a zlar-oc -sr  # Should show rules
   ```
   - [ ] Confirmed: pf rules active

---

## Phase 4: Configure Telegram (The Phone Line)

1. Open Telegram, search for @BotFather
2. Send `/newbot`, follow prompts to create your ZLAR-OC bot
3. Save the bot token (looks like: `123456789:ABCdefGhIjKlMnOpQrStUvWxYz`)
4. Start a chat with your new bot, send `/start`
5. Get your chat_id:
   ```
   curl https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   # Look for "chat":{"id": YOUR_CHAT_ID}
   ```
6. Configure gate.json:
   ```
   # Edit /usr/local/etc/zlar-oc/gate.json
   # Set telegram.enabled = true
   # Set telegram.bot_token = "your token"
   # Set telegram.chat_id = "your chat id"
   ```

7. **TEST:** Send a test message
   ```
   curl -s -X POST "https://api.telegram.org/bot<TOKEN>/sendMessage" \
     -d chat_id=<CHAT_ID> -d text="ZLAR-OC test: shield is online"
   ```
   - [ ] Confirmed: Message received on phone

---

## Phase 5: Install the Local Model

*Details TBD based on hardware specs and model selection.*
*Current candidates: MLX-based local model via mlx-lm or Ollama.*

1. Install MLX (for Apple Silicon):
   ```
   pip3 install mlx-lm
   ```

2. Download model:
   ```
   # Model selection happens here — depends on your RAM/disk
   ```

3. Start model server:
   ```
   # MLX server on localhost:8000
   ```

4. **TEST:** Verify model responds
   ```
   curl http://localhost:8000/v1/models
   ```
   - [ ] Confirmed: Local model serving

---

## Phase 6: Install OpenClaw

*Details TBD based on OpenClaw's install process at time of setup.*

1. Install OpenClaw as aiagent:
   ```
   sudo -u aiagent npm install -g @anthropic-ai/openclaw  # placeholder
   ```

2. Configure OpenClaw to use local model and ZLAR-OC gate

3. **TEST:** Verify OpenClaw starts under sandbox
   ```
   sudo -u aiagent sandbox-exec -f /usr/local/etc/zlar-oc/openclaw.sb -- openclaw --version
   ```
   - [ ] Confirmed: OpenClaw runs inside sandbox

---

## Phase 7: Start ZLAR-OC (Full System)

1. Set availability mode:
   ```
   zlar-oc-availability active
   ```

2. Launch everything:
   ```
   sudo zlar-oc-launch
   ```
   This starts (in order):
   - Integrity verification
   - pf firewall check
   - MLX server
   - OpenClaw gateway
   - Gate daemon
   - Watchdog

3. **TEST:** Verify all components running
   ```
   zlar-oc-launch --status
   ```
   - [ ] Confirmed: All components green

4. **TEST:** Trigger a Telegram ask
   ```
   # From aiagent, try to run something that hits R010
   # Check your phone — you should see the approval prompt
   ```
   - [ ] Confirmed: Telegram ask/approve flow works end-to-end

---

## Phase 8: Observation Period (48 Hours)

Now the system runs in Phase A — observe mode.

1. Let OpenClaw work normally for 48 hours
2. All HTTPS traffic is logged, not blocked
3. After 48h, review:
   ```
   zlar-oc-audit-domains --since 48h --format table
   zlar-oc-audit verdict --since 48h
   zlar-oc-audit fingerprint --since 48h
   ```
4. Review the domains, remove anything suspicious
5. Transition to Phase B:
   ```
   zlar-oc-audit-domains --since 48h --format pf > /usr/local/etc/zlar-oc/pf-rules/https-allowlist.txt
   # Edit zlar-oc.rules: comment Phase A, uncomment Phase B
   sudo pfctl -f /etc/pf.conf
   ```
   - [ ] Confirmed: Phase B active with allowlist

---

## Phase 9: Trust Expansion (Gradual)

Only after the observation period proves clean:

1. Sign in with Apple ID (if desired)
2. Selectively expand file access in policy
3. Each expansion is:
   - A policy change
   - Signed by admin
   - Audited
   - Reversible

Remember: the goal is not to restrict the agent. The goal is to give it maximum freedom
inside a provably safe boundary. The stronger the shield, the sharper the sword.

---

## Troubleshooting

### Gate won't start
```
zlar-oc-gate start --config /usr/local/etc/zlar-oc/gate.json --no-sig
```
(Run without signature verification to debug — NOT for production)

### Telegram not receiving messages
```
curl https://api.telegram.org/bot<TOKEN>/getMe
```
If this fails, your token is wrong.

### Agent is blocked on everything
Check the policy:
```
zlar-oc-policy inspect /usr/local/etc/zlar-oc/policies/active.policy.json
```
The default policy is conservative. Expand rules as trust builds.

### Watchdog triggered lockdown
```
cat /var/log/zlar-oc/watchdog.log | tail -20
```
The watchdog kills the agent if the gate crashes. Restart the gate first, then the agent.

---

*INSTALL_GUIDE.md · ZLAR-OC Project · March 2026*
