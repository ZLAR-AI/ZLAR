# Token & Credential Rotation Procedures

> Authority label: Human-authority-only secret/service runbook.
> Routing rule: Do not rotate tokens, touch secrets, restart services, use
> Telegram, or change machine config unless explicit in-session authority grants
> that exact action.

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

# 2. Update persistent storage without putting the token in shell history
mkdir -p ~/.config/zlar
umask 077
printf 'Paste new token: ' >&2
IFS= read -r ZLAR_NEW_TELEGRAM_TOKEN
printf '%s\n' "${ZLAR_NEW_TELEGRAM_TOKEN}" > ~/.config/zlar/tg-token
chmod 600 ~/.config/zlar/tg-token
unset ZLAR_NEW_TELEGRAM_TOKEN

# 3. Update .env if it has a token override
#    Edit repo/.env — replace ZLAR_TELEGRAM_TOKEN value

# 4. Copy to runtime
sudo cp ~/.config/zlar/tg-token /var/run/zlar-tg/token
sudo chmod 600 /var/run/zlar-tg/token

# 5. Restart dispatcher
sudo kill $(cat /var/run/zlar-tg/poll.pid)
sudo /usr/local/bin/zlar-tg-poll &

# 6. Verify without putting the token in the process table
ZLAR_TELEGRAM_TOKEN="$(cat ~/.config/zlar/tg-token)"
curl --config - <<EOF | python3 -m json.tool
silent
show-error
url = "https://api.telegram.org/bot${ZLAR_TELEGRAM_TOKEN}/getMe"
EOF
unset ZLAR_TELEGRAM_TOKEN
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

## 3. Policy Signing Key

**When:** Scheduled rotation, algorithm migration (Ed25519 to ML-DSA), or
suspected compromise.

Scheduled rotation and compromise response are different authority events.
Scheduled rotation preserves trust continuity by introducing a new active key
and retiring the old one on a documented schedule. Compromise response marks
the affected issuer retired or compromised for recognition, bounds the exposure
window, and preserves old receipts for investigation. A signature can remain
cryptographically verifiable after a key is retired; that does not mean the
issuer remains recognized for boarding.

**Credentials affected:**
- Private key: `~/.zlar-signing.key`
- Public key: `repo/etc/keys/policy-signing.pub`
- Signed policy: `repo/etc/policies/active.policy.json`

This procedure is the current software-rooted local path. It is not
hardware-custody evidence and does not create a production trust registry.

See [`trusted-receipt-issuer.md`](trusted-receipt-issuer.md) before treating a
rotated key as a recognized issuer.

**Procedure:**

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

**OC note:** The OC/OpenClaw gate is retired. Do not use this runbook to rotate
OC keys or restart OC services as part of current ZLAR operation.

**Audit trail continuity:** Old audit entries remain cryptographically
verifiable if their public key is preserved. If the old key is retired or
compromised, those entries are historical evidence for investigation, not proof
that the issuer is still recognized for new boarding.

---

## 4. Full Credential Reset (Nuclear Option)

If all credentials are suspected compromised:

```bash
# 1. Revoke Telegram token via @BotFather
# 2. Get new token, write to ~/.config/zlar/tg-token

# 3. Regenerate HMAC secret
openssl rand -hex 32 | sudo tee /var/run/zlar-tg/inbox-hmac-secret > /dev/null
sudo chmod 600 /var/run/zlar-tg/inbox-hmac-secret

# 4. Regenerate signing keys
repo/bin/zlar-policy keygen

# 5. Re-sign policy (see section 3 above)

# 6. Restart Telegram dispatcher if Telegram is configured
sudo cp ~/.config/zlar/tg-token /var/run/zlar-tg/token
sudo chmod 600 /var/run/zlar-tg/token
sudo kill $(cat /var/run/zlar-tg/poll.pid)
sudo /usr/local/bin/zlar-tg-poll &

# 7. Verify dispatcher if configured, then verify the CC gate loads the policy
```

---

## Security Notes

- **Private keys never leave your machine.** Never commit them, never put them in `.env`.
- **Tokens never in process table.** All API calls use `curl --config -` with stdin, not a token-bearing command argument.
- **No sourcing `.env`.** Gate parses it line-by-line with a key whitelist to prevent injection.
- **HMAC is volatile by design.** Compromise requires runtime access, and reboot clears it.
- **Test before cutting over.** Verify the new token/key works before killing the old service.
