# Token & Credential Rotation Procedures

Runbook for rotating ZLAR credentials. Each section is self-contained.

---

## 1. Telegram Bot Token

**When:** Suspected compromise, scheduled rotation, or BotFather token reset.

**Credentials affected:**
- Persistent: `~/.config/zlar/tg-token`
- Runtime: `/var/run/zlar-tg/token`
- Env override: `ZLAR_TELEGRAM_TOKEN` in `repo/.env`

**Procedure:**

```bash
# 1. Get new token from @BotFather on Telegram
#    /mybots → @ZLAR_00_bot → API Token → Revoke → confirm

# 2. Update persistent storage
echo "NEW_TOKEN_HERE" > ~/.config/zlar/tg-token
chmod 600 ~/.config/zlar/tg-token

# 3. Update .env if it has a token override
#    Edit repo/.env — replace ZLAR_TELEGRAM_TOKEN value

# 4. Copy to runtime
sudo cp ~/.config/zlar/tg-token /var/run/zlar-tg/token
sudo chmod 600 /var/run/zlar-tg/token

# 5. Restart dispatcher
sudo kill $(cat /var/run/zlar-tg/poll.pid)
sudo /usr/local/bin/zlar-tg-poll &

# 6. Verify
curl -s "https://api.telegram.org/bot$(cat ~/.config/zlar/tg-token)/getMe" | python3 -m json.tool
# Should show: "ok": true, "username": "ZLAR_00_bot"

# 7. Test end-to-end: trigger an ask rule and confirm Telegram message arrives
```

**Rollback:** If new token fails, paste the old token back into `~/.config/zlar/tg-token` and repeat steps 4-5.

**Note:** The old token is revoked by BotFather at step 1. There is no going back once revoked. Test the new token (step 6) before restarting services.

---

## 2. HMAC Inbox Secret

**When:** No manual rotation needed — regenerated automatically on every boot by `zlar-tg-boot.sh`.

**How it works:**
- Generated: `openssl rand -hex 32` → `/var/run/zlar-tg/inbox-hmac-secret`
- Volatile: lives in `/var/run/`, cleared on reboot
- Shared by: dispatcher (writes HMACs), CC gate + OC gate (verify HMACs)

**Emergency rotation (mid-session, no reboot):**

```bash
# 1. Generate new secret
openssl rand -hex 32 | sudo tee /var/run/zlar-tg/inbox-hmac-secret > /dev/null
sudo chmod 600 /var/run/zlar-tg/inbox-hmac-secret

# 2. Restart dispatcher (picks up new secret)
sudo kill $(cat /var/run/zlar-tg/poll.pid)
sudo /usr/local/bin/zlar-tg-poll &

# 3. Any pending approval callbacks with old HMAC will fail verification
#    and be rejected. This is correct — re-trigger the ask.
```

---

## 3. Policy Signing Key (CC Gate)

**When:** Key compromise, algorithm migration (Ed25519 → ML-DSA), or scheduled rotation.

**Credentials affected:**
- Private key: `~/.zlar-signing.key` (CC) or `~/.zlar-oc-signing.key` (OC)
- Public key: `repo/etc/keys/policy-signing.pub` (CC) or `/usr/local/etc/zlar-oc/keys/policy-signing.pub` (OC)

**Procedure (CC gate):**

```bash
# 1. Generate new keypair
repo/bin/zlar-policy keygen
# Creates ~/.zlar-signing.key + repo/etc/keys/policy-signing.pub

# 2. Re-sign the active policy
repo/bin/zlar-policy sign \
  --input repo/etc/policies/active.policy.json \
  --output /tmp/policy-resigned.json

# 3. Deploy
cp /tmp/policy-resigned.json repo/etc/policies/active.policy.json

# 4. Verify — gate loads policy on next tool call automatically
# Check: repo/var/log/gate.log should show "Policy loaded: v..."
# No gate restart needed — policy is verified fresh on every invocation.

# 5. Clean up
rm /tmp/policy-resigned.json
```

**Procedure (OC gate):**

```bash
# 1. Generate new keypair
repo/oc/bin/zlar-oc-policy keygen
# Needs sudo if /usr/local/etc/zlar-oc/keys/ is root-owned:
sudo /opt/homebrew/bin/openssl pkey \
  -in ~/.zlar-oc-signing.key -pubout \
  -out /usr/local/etc/zlar-oc/keys/policy-signing.pub

# 2. Re-sign
repo/oc/bin/zlar-oc-policy sign \
  --input /usr/local/etc/zlar-oc/policies/active.policy.json \
  --output /tmp/oc-policy-resigned.json

# 3. Deploy (needs sudo)
sudo cp /tmp/oc-policy-resigned.json /usr/local/etc/zlar-oc/policies/active.policy.json

# 4. Restart OC gate (no sudo)
/usr/local/bin/zlar-oc-gate stop
/usr/local/bin/zlar-oc-gate start

# 5. Verify
# Check /var/log/zlar-oc/gate.log for "Policy signature verified" and rule count > 0
```

**Audit trail continuity:** Old audit entries remain valid. Each entry records `public_key_id` (fingerprint of the signing key at time of creation). Key rotation does not invalidate history.

---

## 4. Full Credential Reset (Nuclear Option)

If all credentials are suspected compromised:

```bash
# 1. Revoke Telegram token via @BotFather
# 2. Get new token, write to ~/.config/zlar/tg-token

# 3. Regenerate HMAC secret
openssl rand -hex 32 | sudo tee /var/run/zlar-tg/inbox-hmac-secret > /dev/null
sudo chmod 600 /var/run/zlar-tg/inbox-hmac-secret

# 4. Regenerate signing keys (CC + OC)
repo/bin/zlar-policy keygen
repo/oc/bin/zlar-oc-policy keygen

# 5. Re-sign both policies (see sections 3 above)

# 6. Restart all services
sudo cp ~/.config/zlar/tg-token /var/run/zlar-tg/token
sudo chmod 600 /var/run/zlar-tg/token
sudo kill $(cat /var/run/zlar-tg/poll.pid)
sudo /usr/local/bin/zlar-tg-poll &
/usr/local/bin/zlar-oc-gate stop
/usr/local/bin/zlar-oc-gate start

# 7. Verify all three: dispatcher, CC gate, OC gate
```

---

## Security Notes

- **Private keys never leave your machine.** Never commit them, never put them in `.env`.
- **Tokens never in process table.** All API calls use `curl --config -` with heredoc.
- **No sourcing `.env`.** Gate parses it line-by-line with a key whitelist to prevent injection.
- **HMAC is volatile by design.** Compromise requires runtime access, and reboot clears it.
- **Test before cutting over.** Verify the new token/key works before killing the old service.
