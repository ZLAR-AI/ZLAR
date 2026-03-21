#!/bin/bash
# Fix: add lock file to prevent duplicate processing of same request_id
# Run with: sudo bash ~/Desktop/ZLAR/tools/patch-dedup-lock.sh

FILE="/usr/local/bin/zlar-oc-gate"
BACKUP="${FILE}.bak.dedup.$(date +%Y%m%d%H%M%S)"

echo "Backing up to ${BACKUP}..."
cp "${FILE}" "${BACKUP}"

# Replace the existing dedup check + process block with a locked version
python3 -c "
with open('${FILE}', 'r') as f:
    content = f.read()

old = '''        # Dedup: skip if this request_id was already processed (#BUG: tail -F double-delivery)
        if [ -n \"\${request_id}\" ] && [ -f \"\${DECISION_DIR}/\${request_id}.json\" ]; then
            return 0
        fi

        # Stash request_id and per-event agent_id for this event's lifecycle
        CURRENT_REQUEST_ID=\"\${request_id}\"'''

new = '''        # Dedup: skip if this request_id was already processed or is being processed
        if [ -n \"\${request_id}\" ]; then
            if [ -f \"\${DECISION_DIR}/\${request_id}.json\" ] || [ -f \"\${DECISION_DIR}/.\${request_id}.lock\" ]; then
                return 0
            fi
            # Lock: claim this request_id before processing
            touch \"\${DECISION_DIR}/.\${request_id}.lock\" 2>/dev/null
        fi

        # Stash request_id and per-event agent_id for this event's lifecycle
        CURRENT_REQUEST_ID=\"\${request_id}\"'''

count = content.count(old)
if count == 0:
    print('ERROR: target pattern not found')
    import sys; sys.exit(1)
elif count > 1:
    print(f'ERROR: pattern found {count} times, expected 1')
    import sys; sys.exit(1)

content = content.replace(old, new, 1)

with open('${FILE}', 'w') as f:
    f.write(content)

print('✅ Dedup lock patch applied')
"

# Also add lock cleanup after processing
python3 -c "
with open('${FILE}', 'r') as f:
    content = f.read()

old = '''        CURRENT_REQUEST_ID=\"\"
        CURRENT_EVENT_AGENT_ID=\"\"
        return 0'''

new = '''        # Clean up lock file
        rm -f \"\${DECISION_DIR}/.\${request_id}.lock\" 2>/dev/null
        CURRENT_REQUEST_ID=\"\"
        CURRENT_EVENT_AGENT_ID=\"\"
        return 0'''

count = content.count(old)
if count == 0:
    print('ERROR: cleanup pattern not found')
    import sys; sys.exit(1)
elif count > 1:
    print(f'ERROR: cleanup pattern found {count} times, expected 1')
    import sys; sys.exit(1)

content = content.replace(old, new, 1)

with open('${FILE}', 'w') as f:
    f.write(content)

print('✅ Lock cleanup patch applied')
"

echo "Verify:"
grep -n 'lock' "${FILE}" | head -10
