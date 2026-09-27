#!/bin/bash
# One-time patch: add EVAL_AUTHORIZER to OC gate
# Run with: sudo bash ~/Desktop/ZLAR/tools/patch-authorizer.sh

FILE="/usr/local/bin/zlar-oc-gate"
BACKUP="${FILE}.bak.$(date +%Y%m%d%H%M%S)"

echo "Backing up to ${BACKUP}..."
cp "${FILE}" "${BACKUP}"

# 1. Declare EVAL_AUTHORIZER after EVAL_RULE_ID declaration
sed -i '' '/^EVAL_RULE_ID=""$/a\
EVAL_AUTHORIZER=""' "${FILE}"

# 2. Reset EVAL_AUTHORIZER in evaluate_event (after EVAL_RULE_ID reset)
sed -i '' '/^    EVAL_RULE_ID=""$/a\
    EVAL_AUTHORIZER=""' "${FILE}"

# 3. Set EVAL_AUTHORIZER="policy" when evaluate_event matches a rule
#    (right after EVAL_RULE_ID is set in the match block)
sed -i '' 's/            EVAL_RULE_ID="${RULE_IDS\[${i}\]}"/            EVAL_RULE_ID="${RULE_IDS[${i}]}"\
            EVAL_AUTHORIZER="policy"/' "${FILE}"

# 4. Set EVAL_AUTHORIZER in telegram_ask for human approve
sed -i '' '/log_gate "Telegram ask APPROVED/i\
            EVAL_AUTHORIZER="human:${TELEGRAM_CHAT_ID}"' "${FILE}"

# 5. Set EVAL_AUTHORIZER in telegram_ask for human deny
sed -i '' '/log_gate "Telegram ask DENIED/i\
            EVAL_AUTHORIZER="human:${TELEGRAM_CHAT_ID}"' "${FILE}"

# 6. Set EVAL_AUTHORIZER in telegram_ask for timeout
sed -i '' '/log_gate "Telegram ask TIMED OUT/i\
            EVAL_AUTHORIZER="gate:timeout"' "${FILE}"

# 7. Set EVAL_AUTHORIZER for away_auto_allow path
sed -i '' '/log_gate "AWAY AUTO-ALLOW:/i\
            EVAL_AUTHORIZER="gate:away_auto_allow"' "${FILE}"

# 8. Set EVAL_AUTHORIZER for away_halt path
sed -i '' '/log_gate "AWAY HALT:/i\
            EVAL_AUTHORIZER="gate:away_halt"' "${FILE}"

# 9. Set EVAL_AUTHORIZER for away_queued path
sed -i '' '/log_gate "AWAY QUEUE:/i\
            EVAL_AUTHORIZER="gate:away_queued"' "${FILE}"

# 10. Pass EVAL_AUTHORIZER to write_decision call
sed -i '' 's/write_decision "${CURRENT_REQUEST_ID}" "${outcome}" "${EVAL_RULE_ID}" "${domain}" "${action}"/write_decision "${CURRENT_REQUEST_ID}" "${outcome}" "${EVAL_RULE_ID}" "${domain}" "${action}" "${EVAL_AUTHORIZER}"/' "${FILE}"

echo "✅ Patch applied. Backup at ${BACKUP}"
echo "Verify with: grep EVAL_AUTHORIZER ${FILE}"
