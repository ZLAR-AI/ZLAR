#!/bin/bash
# One-time patch: notify on unmatched events instead of silent deny
# Run with: sudo bash ~/Desktop/ZLAR/tools/patch-unmatched-notify.sh

FILE="/usr/local/bin/zlar-oc-gate"
BACKUP="${FILE}.bak.unmatched.$(date +%Y%m%d%H%M%S)"

echo "Backing up to ${BACKUP}..."
cp "${FILE}" "${BACKUP}"

# Use python for precise insertion — target process_openclaw_event function
python3 -c "
with open('${FILE}', 'r') as f:
    lines = f.readlines()

insert_block = [
    '\n',
    '    # If no rule matched, notify human instead of silent deny\n',
    '    if [ -z \"\${EVAL_RULE_ID}\" ] && [ \"\${outcome}\" = \"deny\" ] && [ \"\${TELEGRAM_ENABLED}\" = \"true\" ]; then\n',
    '        log_gate \"UNMATCHED EVENT: no rule matched for domain=\${domain} action=\${action} — notifying human\"\n',
    '        EVAL_RULE_ID=\"unmatched\"\n',
    '        EVAL_SEVERITY=\"warn\"\n',
    '        EVAL_AUTHORIZER=\"gate:unmatched\"\n',
    '        outcome=\"ask\"\n',
    '    fi\n',
]

# Find process_openclaw_event, then find evaluate_event line inside it
in_func = False
inserted = False
new_lines = []
for i, line in enumerate(lines):
    new_lines.append(line)
    if 'process_openclaw_event()' in line:
        in_func = True
    if in_func and not inserted and 'evaluate_event' in line:
        new_lines.extend(insert_block)
        inserted = True
        in_func = False

if inserted:
    with open('${FILE}', 'w') as f:
        f.writelines(new_lines)
    print('✅ Patch applied — 1 insertion in process_openclaw_event')
else:
    print('ERROR: could not find insertion point')
"

echo "Verify:"
grep -n 'UNMATCHED EVENT' "${FILE}"
