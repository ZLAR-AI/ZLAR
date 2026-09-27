#!/usr/bin/env node

import {
  readFileSync,
} from 'node:fs';
import {
  CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS,
  CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_SAFE_CLAIM_CEILING,
  CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE,
  assertCurrentMachineApprovalRequestPreviewReport,
  formatCurrentMachineApprovalRequestPreviewReport,
  previewCurrentMachineApprovalRequest,
  previewCurrentMachineApprovalRequestFromText,
} from '../lib/current-machine-approval-request-preview.mjs';
import { runCurrentMachineApprovalIntake } from '../lib/current-machine-approval-intake.mjs';
import { assertNoUnsafeCurrentMachineApprovalPacketText } from '../lib/current-machine-approval-packet.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;

function assert(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function assertEqual(label, expected, actual) {
  assert(label, expected === actual, `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function assertThrows(label, fn, expectedMessageFragment) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessageFragment || String(err.message).includes(expectedMessageFragment)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

const SAMPLE_PACKET_PATH = 'tests/fixtures/current-machine-approval-packet-claude-code-v1.json';
const SAMPLE_PACKET_SHA256 = '7012e6e6bb8e89358363ce073422bb74f30ee63af50be5870eace96e6f672e68';
const packetText = readFileSync(SAMPLE_PACKET_PATH, 'utf8');
const packet = JSON.parse(packetText);
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|BEGIN [A-Z ]*KEY/i;

section('valid intake report preview');
const intakeReport = runCurrentMachineApprovalIntake({ packetPath: SAMPLE_PACKET_PATH });
const preview = previewCurrentMachineApprovalRequest(intakeReport);
assert('preview validates', assertCurrentMachineApprovalRequestPreviewReport(preview));
assertEqual('preview type', CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_TYPE, preview.preview_type);
assertEqual('preview status', 'preview_prepared_no_authority_request', preview.preview_status);
assertEqual('preview can be prepared', true, preview.preview_can_be_prepared);
assertEqual('authority request made false', false, preview.authority_request_made);
assertEqual('install authority granted false', false, preview.install_authority_granted);
assertEqual('human approval granted false', false, preview.human_approval_granted);
assertEqual('intake authority request allowed', true, preview.intake_authority_request_allowed);
assertEqual('intake authority request made false', false, preview.intake_authority_request_made);
assertEqual('packet verification complete', true, preview.packet_verification_complete);
assertEqual('intake packet sha stable', SAMPLE_PACKET_SHA256, preview.intake_packet_sha256);
assertEqual('selected surface preserved', 'claude_code', preview.selected_surface);
assertEqual('hook event preserved', 'PreToolUse', preview.hook_target.hook_event);
assertEqual('hook target preserved', '~/.zlar/adapters/claude-code/hook.sh', preview.hook_target.hook_command_target);
assertEqual('delegation target preserved', '~/.zlar/bin/zlar-gate', preview.hook_target.delegation_target);
assertEqual('source target preserved', 'b89b0c2e2d79db4981cad69af4a190e9c77fb089', preview.source_target.target_commit_sha);
assertEqual('installer identity preserved', 'install.sh', preview.installer_identity.installer_path);
assertEqual('command posture preserved', 'repair', preview.command_posture.existing_install_mode);
assertEqual('dry-run plan identity preserved', 'zlar-install-plan-v1', preview.dry_run_plan_identity.plan_type);
assertEqual('authority request identity preserved as no request', false, preview.authority_request_identity.authority_request_made);
assertEqual('backup rollback preserved', true, preview.backup_rollback_requirements.backup_required_before_mutation);
assertEqual('issuer id preserved', 'zlar-current-machine-claude-code-fixture-issuer', preview.issuer_policy.issuer_id);
assertEqual('issuer kid preserved', 'zlar-current-machine-claude-code-fixture-kid', preview.issuer_policy.issuer_kid);
assertEqual('policy id preserved', 'zlar-current-machine-claude-code-policy-v1', preview.issuer_policy.policy_id);
assertEqual('receipt format preserved', 'zlar-receipt-v1', preview.receipt_path.receipt_format);
assertEqual('downstream refuses before effect', true, preview.downstream_refusal_matrix.downstream_refuses_before_effect);
assertEqual('refusal matrix complete', true, preview.downstream_refusal_matrix.refusal_matrix_complete);
assertEqual('refusal reason count preserved', intakeReport.refusal_reason_count, preview.downstream_refusal_matrix.refusal_reason_count);
for (const [field, value] of Object.entries(preview.preserved_sections)) {
  assertEqual(`preserved section true: ${field}`, true, value);
}
for (const [field, value] of Object.entries(preview.no_authority_boundary)) {
  assertEqual(`no-authority boundary false: ${field}`, false, value);
}
for (const claim of intakeReport.non_claims) {
  assert(`intake non-claim preserved: ${claim}`, preview.intake_non_claims.includes(claim));
}
for (const claim of intakeReport.packet_verification.non_claims) {
  assert(`packet non-claim preserved: ${claim}`, preview.packet_non_claims.includes(claim));
}
for (const claim of CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_NON_CLAIMS) {
  assert(`preview non-claim present: ${claim}`, preview.preview_non_claims.includes(claim));
}
assertEqual('safe claim ceiling exact', CURRENT_MACHINE_APPROVAL_REQUEST_PREVIEW_SAFE_CLAIM_CEILING, preview.safe_claim_ceiling);
assert('claim boundary says not install authority', preview.claim_boundary.includes('not install authority'));
assert('claim boundary says not approval', preview.claim_boundary.includes('not approval'));
assert('claim boundary says no current-machine governance', preview.claim_boundary.includes('no current-machine governance evidence'));
assert('preview JSON privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(preview)));
assert('preview JSON omits unsafe details', !unsafeOutputPattern.test(JSON.stringify(preview)));

const summary = formatCurrentMachineApprovalRequestPreviewReport(preview);
assert('summary title present', summary.includes('ZLAR Current-Machine Approval Request Preview v1'));
assert('summary says preview prepared', summary.includes('preview_can_be_prepared=true'));
assert('summary says authority request not made', summary.includes('authority_request_made=false'));
assert('summary says no install authority', summary.includes('install_authority_granted=false'));
assert('summary says no human approval', summary.includes('human_approval_granted=false'));
assert('summary preserves surface', summary.includes('selected_surface=claude_code'));
assert('summary preserves hook target', summary.includes('hook_target=~/.zlar/adapters/claude-code/hook.sh'));
assert('summary preserves delegation target', summary.includes('delegation_target=~/.zlar/bin/zlar-gate'));
assert('summary preserves source target', summary.includes('source_target:'));
assert('summary preserves installer identity', summary.includes('installer_identity:'));
assert('summary preserves command posture', summary.includes('command_posture:'));
assert('summary preserves dry-run plan identity', summary.includes('dry_run_plan_identity:'));
assert('summary preserves authority request identity', summary.includes('authority_request_identity:'));
assert('summary preserves backup rollback', summary.includes('backup_rollback:'));
assert('summary names refusal matrix', summary.includes('downstream_refusal_matrix:'));
assert('summary carries non-authority boundary', summary.includes('current_machine_governance_evidence=false'));
assert('summary explicitly says not install authority', summary.includes('This preview is not install authority.'));
assert('summary explicitly says not an approval', summary.includes('This preview is not an approval.'));
assert('summary privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(summary));
assert('summary omits unsafe details', !unsafeOutputPattern.test(summary));

section('text input preview');
const textPreview = previewCurrentMachineApprovalRequestFromText(`${JSON.stringify(intakeReport, null, 2)}\n`);
assert('text preview validates', assertCurrentMachineApprovalRequestPreviewReport(textPreview));
assertEqual('text preview can be prepared', true, textPreview.preview_can_be_prepared);
assertEqual('text preview authority request not made', false, textPreview.authority_request_made);

section('invalid intake reports refuse');
const wrongSurface = structuredClone(packet);
wrongSurface.selected_surface.selected_surface = 'codex';
const wrongSurfaceIntake = runCurrentMachineApprovalIntake({
  packetPath: '-',
  packetText: `${JSON.stringify(wrongSurface, null, 2)}\n`,
});
const refusedIntakePreview = previewCurrentMachineApprovalRequest(wrongSurfaceIntake);
assert('refused intake preview validates', assertCurrentMachineApprovalRequestPreviewReport(refusedIntakePreview));
assertEqual('refused intake preview status', 'refused_before_authority_request_preview', refusedIntakePreview.preview_status);
assertEqual('refused intake preview cannot prepare', false, refusedIntakePreview.preview_can_be_prepared);
assertEqual('refused intake authority request allowed false', false, refusedIntakePreview.intake_authority_request_allowed);
assertEqual('refused intake authority request made false', false, refusedIntakePreview.authority_request_made);
assertEqual('refused intake no install authority', false, refusedIntakePreview.install_authority_granted);
assertEqual('refused intake no human approval', false, refusedIntakePreview.human_approval_granted);
assertEqual('refused intake reason', 'intake_report_invalid', refusedIntakePreview.refusal_reason_code);
for (const [field, value] of Object.entries(refusedIntakePreview.preserved_sections)) {
  assertEqual(`refused intake preserved section false: ${field}`, false, value);
}

const madeRequest = structuredClone(intakeReport);
madeRequest.authority_request_made = true;
const madeRequestPreview = previewCurrentMachineApprovalRequest(madeRequest);
assertEqual('made request preview refuses', false, madeRequestPreview.preview_can_be_prepared);
assertEqual('made request preview does not preserve request made', false, madeRequestPreview.authority_request_made);
assertEqual('made request preview reason', 'intake_report_invalid', madeRequestPreview.refusal_reason_code);

const forgedTopLevelSurface = structuredClone(intakeReport);
forgedTopLevelSurface.selected_surface = 'cursor';
const forgedTopLevelSurfacePreview = previewCurrentMachineApprovalRequest(forgedTopLevelSurface);
assertEqual('forged top-level surface preview refuses', false, forgedTopLevelSurfacePreview.preview_can_be_prepared);
assertEqual('forged top-level surface reason', 'intake_report_invalid', forgedTopLevelSurfacePreview.refusal_reason_code);
assertEqual('forged top-level surface does not launder selected surface', 'unverified', forgedTopLevelSurfacePreview.selected_surface);

const forgedTopLevelHookTarget = structuredClone(intakeReport);
forgedTopLevelHookTarget.hook_command_target = '~/.zlar/adapters/cursor/hook.sh';
const forgedTopLevelHookTargetPreview = previewCurrentMachineApprovalRequest(forgedTopLevelHookTarget);
assertEqual('forged top-level hook target preview refuses', false, forgedTopLevelHookTargetPreview.preview_can_be_prepared);
assertEqual('forged top-level hook target reason', 'intake_report_invalid', forgedTopLevelHookTargetPreview.refusal_reason_code);
assertEqual('forged top-level hook target does not launder hook', 'unverified', forgedTopLevelHookTargetPreview.hook_target.hook_command_target);

const forgedTopLevelPacketSha = structuredClone(intakeReport);
forgedTopLevelPacketSha.packet_sha256 = '9'.repeat(64);
const forgedTopLevelPacketShaPreview = previewCurrentMachineApprovalRequest(forgedTopLevelPacketSha);
assertEqual('forged top-level packet sha preview refuses', false, forgedTopLevelPacketShaPreview.preview_can_be_prepared);
assertEqual('forged top-level packet sha reason', 'intake_report_invalid', forgedTopLevelPacketShaPreview.refusal_reason_code);
assertEqual('forged top-level packet sha does not launder hash', 'unverified', forgedTopLevelPacketShaPreview.intake_packet_sha256);

const forgedNestedHookTarget = structuredClone(intakeReport);
forgedNestedHookTarget.packet_verification.hook_command_target = '~/.zlar/adapters/cursor/hook.sh';
forgedNestedHookTarget.hook_command_target = '~/.zlar/adapters/cursor/hook.sh';
const forgedNestedHookTargetPreview = previewCurrentMachineApprovalRequest(forgedNestedHookTarget);
assertEqual('forged nested hook target preview refuses', false, forgedNestedHookTargetPreview.preview_can_be_prepared);
assertEqual('forged nested hook target reason', 'intake_report_invalid', forgedNestedHookTargetPreview.refusal_reason_code);
assertEqual('forged nested hook target does not launder hook', 'unverified', forgedNestedHookTargetPreview.hook_target.hook_command_target);

const forgedNestedDelegation = structuredClone(intakeReport);
forgedNestedDelegation.packet_verification.delegation_target = '~/.zlar/bin/not-zlar-gate';
forgedNestedDelegation.delegation_target = '~/.zlar/bin/not-zlar-gate';
const forgedNestedDelegationPreview = previewCurrentMachineApprovalRequest(forgedNestedDelegation);
assertEqual('forged nested delegation preview refuses', false, forgedNestedDelegationPreview.preview_can_be_prepared);
assertEqual('forged nested delegation reason', 'intake_report_invalid', forgedNestedDelegationPreview.refusal_reason_code);
assertEqual('forged nested delegation does not launder target', 'unverified', forgedNestedDelegationPreview.hook_target.delegation_target);

const forgedNestedSource = structuredClone(intakeReport);
forgedNestedSource.packet_verification.source_target = {
  ...forgedNestedSource.packet_verification.source_target,
  target_commit_sha: '1111111111111111111111111111111111111111',
};
forgedNestedSource.source_target = forgedNestedSource.packet_verification.source_target;
const forgedNestedSourcePreview = previewCurrentMachineApprovalRequest(forgedNestedSource);
assertEqual('forged nested source preview refuses', false, forgedNestedSourcePreview.preview_can_be_prepared);
assertEqual('forged nested source reason', 'intake_report_invalid', forgedNestedSourcePreview.refusal_reason_code);
assertEqual('forged nested source does not launder source', 'unverified', forgedNestedSourcePreview.source_target.verification_status);

const forgedNestedPacketIdentity = structuredClone(intakeReport);
forgedNestedPacketIdentity.packet_verification.packet_id = 'forged-packet-id';
forgedNestedPacketIdentity.packet_verification.packet_sha256 = '9'.repeat(64);
forgedNestedPacketIdentity.packet_sha256 = '9'.repeat(64);
const forgedNestedPacketIdentityPreview = previewCurrentMachineApprovalRequest(forgedNestedPacketIdentity);
assertEqual('forged nested packet identity preview refuses', false, forgedNestedPacketIdentityPreview.preview_can_be_prepared);
assertEqual('forged nested packet identity reason', 'intake_report_invalid', forgedNestedPacketIdentityPreview.refusal_reason_code);
assertEqual('forged nested packet identity does not launder hash', 'unverified', forgedNestedPacketIdentityPreview.intake_packet_sha256);

const incompletePacket = structuredClone(intakeReport);
incompletePacket.verifier_packet_complete = false;
const incompletePacketPreview = previewCurrentMachineApprovalRequest(incompletePacket);
assertEqual('incomplete packet preview refuses', false, incompletePacketPreview.preview_can_be_prepared);
assertEqual('incomplete packet preview packet complete false', false, incompletePacketPreview.packet_verification_complete);

const liveGovernanceClaim = structuredClone(intakeReport);
liveGovernanceClaim.no_write_boundary.current_machine_governance_evidence = true;
const liveGovernancePreview = previewCurrentMachineApprovalRequest(liveGovernanceClaim);
assertEqual('current-machine governance claim refuses', false, liveGovernancePreview.preview_can_be_prepared);
assertEqual('current-machine governance claim not carried', false, liveGovernancePreview.no_authority_boundary.current_machine_governance_evidence);

const installClaim = structuredClone(intakeReport);
installClaim.no_write_boundary.install_or_activation_applied = true;
const installClaimPreview = previewCurrentMachineApprovalRequest(installClaim);
assertEqual('install claim refuses', false, installClaimPreview.preview_can_be_prepared);
assertEqual('install claim not carried', false, installClaimPreview.no_authority_boundary.install_or_activation_applied);

const liveReceiptClaim = structuredClone(intakeReport);
liveReceiptClaim.no_write_boundary.live_receipt_emission_evidence = true;
const liveReceiptPreview = previewCurrentMachineApprovalRequest(liveReceiptClaim);
assertEqual('live receipt claim refuses', false, liveReceiptPreview.preview_can_be_prepared);
assertEqual('live receipt claim not carried', false, liveReceiptPreview.no_authority_boundary.live_receipt_emission_evidence);

const unparseablePreview = previewCurrentMachineApprovalRequestFromText('{');
assert('unparseable preview validates', assertCurrentMachineApprovalRequestPreviewReport(unparseablePreview));
assertEqual('unparseable preview refuses', false, unparseablePreview.preview_can_be_prepared);
assertEqual('unparseable preview reason', 'intake_report_unparseable', unparseablePreview.refusal_reason_code);

section('contract failures');
const forgedPrepared = structuredClone(preview);
forgedPrepared.install_authority_granted = true;
assertThrows(
  'install authority granted claim refuses',
  () => assertCurrentMachineApprovalRequestPreviewReport(forgedPrepared),
  'must be false'
);

const forgedApproval = structuredClone(preview);
forgedApproval.human_approval_granted = true;
assertThrows(
  'human approval claim refuses',
  () => assertCurrentMachineApprovalRequestPreviewReport(forgedApproval),
  'must be false'
);

const forgedCurrentMachine = structuredClone(preview);
forgedCurrentMachine.no_authority_boundary.current_machine_governance_evidence = true;
assertThrows(
  'current-machine governance boundary claim refuses',
  () => assertCurrentMachineApprovalRequestPreviewReport(forgedCurrentMachine),
  'must be false'
);

if (FAIL > 0) {
  console.log(`\nResults: ${PASS}/${TOTAL} passed`);
  console.log(`\nFAIL: ${FAIL}/${TOTAL} assertions failed`);
  process.exit(1);
}

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
console.log(`\nPASS: ${PASS}/${TOTAL} assertions passed`);
