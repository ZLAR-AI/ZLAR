#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { canonicalize } from '../lib/canonicalize.mjs';
import {
  CURRENT_MACHINE_APPROVAL_PACKET_BOARDING_RULE,
  CURRENT_MACHINE_APPROVAL_PACKET_SAFE_CLAIM_CEILING,
  CURRENT_MACHINE_APPROVAL_PACKET_TYPE,
  CURRENT_MACHINE_APPROVAL_PACKET_VERIFICATION_TYPE,
  REQUIRED_CURRENT_MACHINE_APPROVAL_NON_CLAIMS,
  REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS,
  assertCurrentMachineApprovalPacket,
  assertCurrentMachineApprovalPacketVerification,
  assertNoUnsafeCurrentMachineApprovalPacketText,
  currentMachineApprovalPacketSha256,
  formatCurrentMachineApprovalPacketVerification,
  parseCurrentMachineApprovalPacketText,
  verifyCurrentMachineApprovalPacket,
} from '../lib/current-machine-approval-packet.mjs';
import { sha256hex } from '../lib/receipt.mjs';

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

function withoutKeys(value, keys) {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !keys.includes(key))
  );
}

function recomputeAuthorityRequestSha256(candidate) {
  candidate.authority_request_identity.request_sha256 = sha256hex(canonicalize({
    packet_type: candidate.packet_type,
    packet_id: candidate.packet_id,
    selected_surface: candidate.selected_surface,
    hook_target: candidate.hook_target,
    source_target: candidate.source_target,
    installer_identity: candidate.installer_identity,
    command_posture: candidate.command_posture,
    dry_run_plan_identity: candidate.dry_run_plan_identity,
    authority_request_identity: withoutKeys(candidate.authority_request_identity, ['request_sha256']),
    backup_rollback_requirements: candidate.backup_rollback_requirements,
  }));
}

function recomputeSourceManifestSha256(candidate) {
  candidate.source_target.source_manifest_sha256 = sha256hex(canonicalize({
    source_target: withoutKeys(candidate.source_target, ['source_manifest_sha256']),
    installer_identity: candidate.installer_identity,
  }));
}

function recomputePacketBindingHashes(candidate) {
  recomputeSourceManifestSha256(candidate);
  candidate.dry_run_plan_identity.plan_sha256 = sha256hex(canonicalize(
    withoutKeys(candidate.dry_run_plan_identity, ['plan_sha256'])
  ));
  recomputeAuthorityRequestSha256(candidate);
}

function recomputeVerificationSourceManifestSha256(candidate) {
  candidate.source_target.source_manifest_sha256 = sha256hex(canonicalize({
    source_target: withoutKeys(candidate.source_target, ['source_manifest_sha256']),
    installer_identity: candidate.installer_identity,
  }));
}

function recomputeVerificationAuthorityRequestSha256(candidate) {
  candidate.authority_request_identity.request_sha256 = sha256hex(canonicalize({
    packet_type: candidate.packet_type,
    packet_id: candidate.packet_id,
    selected_surface: {
      selected_surface: candidate.selected_surface,
      surface_label: 'Claude Code',
      single_surface_scope: candidate.single_surface_scope,
      source_design: 'install.sh --surface claude-code --dry-run --json current_machine_governance_design',
      live_surface_probe_performed: candidate.live_surface_probe_performed,
    },
    hook_target: {
      hook_profile_path: candidate.hook_profile_path,
      hook_event: candidate.hook_event,
      hook_command_target: candidate.hook_command_target,
      delegation_target: candidate.delegation_target,
      expected_executable: true,
      hook_target_verified_by_live_read: candidate.hook_target_verified_by_live_read,
      writes_hook_profile: false,
    },
    source_target: candidate.source_target,
    installer_identity: candidate.installer_identity,
    command_posture: candidate.command_posture,
    dry_run_plan_identity: candidate.dry_run_plan_identity,
    authority_request_identity: withoutKeys(candidate.authority_request_identity, ['request_sha256']),
    backup_rollback_requirements: candidate.backup_rollback_requirements,
  }));
}

const SAMPLE_PACKET_PATH = 'tests/fixtures/current-machine-approval-packet-claude-code-v1.json';
const SAMPLE_PACKET_SHA256 = '7012e6e6bb8e89358363ce073422bb74f30ee63af50be5870eace96e6f672e68';
const packetText = readFileSync(SAMPLE_PACKET_PATH, 'utf8');
const packet = JSON.parse(packetText);
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|BEGIN [A-Z ]*KEY/i;

section('packet contract');
assert('packet text is privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(packetText));
assert('packet parses and validates', assertCurrentMachineApprovalPacket(packet));
assertEqual('packet type', CURRENT_MACHINE_APPROVAL_PACKET_TYPE, packet.packet_type);
assertEqual('packet sha stable', SAMPLE_PACKET_SHA256, currentMachineApprovalPacketSha256(packet));
assertEqual('boarding rule exact', CURRENT_MACHINE_APPROVAL_PACKET_BOARDING_RULE, packet.boarding_credential_rule);
assertEqual('selected surface', 'claude_code', packet.selected_surface.selected_surface);
assertEqual('single surface scope true', true, packet.selected_surface.single_surface_scope);
assertEqual('live surface probe false', false, packet.selected_surface.live_surface_probe_performed);
assertEqual('hook event PreToolUse', 'PreToolUse', packet.hook_target.hook_event);
assertEqual('hook delegation target preserved', '~/.zlar/bin/zlar-gate', packet.hook_target.delegation_target);
assertEqual('hook target live read false', false, packet.hook_target.hook_target_verified_by_live_read);
assertEqual('hook profile write false', false, packet.hook_target.writes_hook_profile);
assertEqual('source target commit bound', 'b89b0c2e2d79db4981cad69af4a190e9c77fb089', packet.source_target.target_commit_sha);
assertEqual('source target tree bound', '91eaff8cc48b905192ddc238b6c9a9049a9efbee', packet.source_target.target_tree_sha);
assertEqual('source target dirty worktree refused', false, packet.source_target.dirty_worktree_allowed);
assertEqual('source target claims private-core release', true, packet.source_target.published_release_claimed);
assertEqual('source target private-core tag bound', 'v3.4.55', packet.source_target.published_release_tag);
assertEqual('source target private-core peeled commit bound', packet.source_target.target_commit_sha, packet.source_target.published_release_commit_sha);
assertEqual('source target private-core tag object bound', 'fe16ef4d22a09fdb282898cb029bd25eefde24f5', packet.source_target.published_release_tag_object_sha);
assertEqual('installer path bound', 'install.sh', packet.installer_identity.installer_path);
assertEqual('installer blob bound', '295a71e6e6c1fd331c90f1c2f43d21903bc18057', packet.installer_identity.installer_git_blob_sha);
assertEqual('command posture selects claude', 'claude_code', packet.command_posture.selected_surface);
assertEqual('command posture no machine helpers', true, packet.command_posture.no_machine_helpers);
assertEqual('dry-run plan type bound', 'zlar-install-plan-v1', packet.dry_run_plan_identity.plan_type);
assertEqual('dry-run plan is no-write', true, packet.dry_run_plan_identity.no_write_plan);
assertEqual('dry-run plan hash bound', '1f1eb0150d6117e3036595a593b6eec87a5ce225796350702a3201e4447c64ea', packet.dry_run_plan_identity.plan_sha256);
assertEqual('dry-run planned writes hash bound', '32fa855729357903f7855301c5a0b92ac632029bb14c35a75b86ec15c2560198', packet.dry_run_plan_identity.planned_writes_sha256);
assertEqual('dry-run write effects hash bound', 'a90e1e5a66929231376bb37a9e9dec970736374b4b61232628bf159632968a33', packet.dry_run_plan_identity.write_effects_sha256);
assertEqual('authority request not made in packet', false, packet.authority_request_identity.authority_request_made);
assertEqual('authority replay guard required', true, packet.authority_request_identity.replay_guard_required);
assertEqual('backup required before mutation', true, packet.backup_rollback_requirements.backup_required_before_mutation);
assertEqual('installer does not claim backup enforcement', false, packet.backup_rollback_requirements.installer_backup_enforcement_present);
assertEqual('issuer status live verified false', false, packet.issuer_policy.issuer.issuer_status_verified_live);
assertEqual('public key material omitted', false, packet.issuer_policy.issuer.public_key_material_included);
assertEqual('private key material omitted', false, packet.issuer_policy.issuer.private_key_material_included);
assertEqual('policy signature required', true, packet.issuer_policy.policy.policy_signature_required);
assertEqual('accepted policy version', '3.4.55', packet.issuer_policy.policy.accepted_policy_version);
assertEqual('policy identity hash bound', '5fe78410bdbac8b1b91c062ca5c0f710194939da9dd8eb0140ba54af1525f0b0', packet.issuer_policy.policy.policy_sha256);
assertEqual('policy material omitted', false, packet.issuer_policy.policy.policy_material_included);
assertEqual('live policy signature verified false', false, packet.issuer_policy.policy.live_policy_signature_verified);
assertEqual('receipt format v1', 'zlar-receipt-v1', packet.receipt_path.receipt_format);
assertEqual('receipt required for boarding', true, packet.receipt_path.recognized_receipt_required_for_boarding);
assertEqual('verifier does not mint credential', false, packet.receipt_path.boarding_credential_minted_by_verifier);
assertEqual('live receipt emission false', false, packet.receipt_path.live_receipt_emission_verified);
assertEqual('downstream refuses before effect', true, packet.downstream_recognition.refuses_before_effect);
assertEqual('refusal matrix count', REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS.length, packet.downstream_recognition.refusal_matrix.length);
for (const reason of REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS) {
  const item = packet.downstream_recognition.refusal_matrix.find((candidate) => candidate.reason_code === reason);
  assert(`required refusal reason present: ${reason}`, Boolean(item));
  assertEqual(`required refusal reason before effect: ${reason}`, true, item.refuses_before_effect);
  assertEqual(`required refusal reason no mutation: ${reason}`, false, item.effect_mutation_allowed);
}
for (const claim of REQUIRED_CURRENT_MACHINE_APPROVAL_NON_CLAIMS) {
  assert(`required non-claim present: ${claim}`, packet.explicit_non_claims.includes(claim));
}
assertEqual('human authority required before install/config', true, packet.authority_boundary.human_authority_required_before_install_or_config);
assertEqual('install or activation false', false, packet.authority_boundary.install_or_activation_applied);
assertEqual('user config write false', false, packet.authority_boundary.user_config_written);
assertEqual('machine config write false', false, packet.authority_boundary.machine_config_written);
assertEqual('service start false', false, packet.authority_boundary.service_started);
assertEqual('signing material changed false', false, packet.authority_boundary.secrets_or_signing_material_changed);
assertEqual('Telegram use false', false, packet.authority_boundary.telegram_used);
assertEqual('current-machine governance evidence false', false, packet.authority_boundary.current_machine_governance_evidence);
assertEqual('live downstream recognition evidence false', false, packet.authority_boundary.live_downstream_recognition_evidence);
assertEqual('external attestation false', false, packet.authority_boundary.external_attestation);
assert('packet JSON omits unsafe details', !unsafeOutputPattern.test(JSON.stringify(packet)));

section('verification output');
const parsedPacket = parseCurrentMachineApprovalPacketText(packetText);
assert('parsed packet validates', assertCurrentMachineApprovalPacket(parsedPacket));
const verification = verifyCurrentMachineApprovalPacket(parsedPacket);
assert('verification validates', assertCurrentMachineApprovalPacketVerification(verification));
assertEqual('verification type', CURRENT_MACHINE_APPROVAL_PACKET_VERIFICATION_TYPE, verification.verification_type);
assertEqual('verification verified true', true, verification.verified);
assertEqual('packet complete true', true, verification.packet_complete);
assertEqual('verification packet sha stable', SAMPLE_PACKET_SHA256, verification.packet_sha256);
assertEqual('safe claim ceiling exact', CURRENT_MACHINE_APPROVAL_PACKET_SAFE_CLAIM_CEILING, verification.safe_claim_ceiling);
assertEqual('verification selected surface', 'claude_code', verification.selected_surface);
assertEqual('verification delegation target', '~/.zlar/bin/zlar-gate', verification.delegation_target);
assertEqual('verification source target commit', packet.source_target.target_commit_sha, verification.source_target.target_commit_sha);
assertEqual('verification installer sha', packet.installer_identity.installer_sha256, verification.installer_identity.installer_sha256);
assertEqual('verification command existing-install mode', 'repair', verification.command_posture.existing_install_mode);
assertEqual('verification dry-run plan sha', packet.dry_run_plan_identity.plan_sha256, verification.dry_run_plan_identity.plan_sha256);
assertEqual('verification authority request made false', false, verification.authority_request_identity.authority_request_made);
assertEqual('verification backup rollback required', true, verification.backup_rollback_requirements.rollback_plan_required);
assertEqual('verification refusal matrix complete', true, verification.refusal_matrix_complete);
assertEqual('verification refusal count', REQUIRED_CURRENT_MACHINE_APPROVAL_REFUSAL_REASONS.length, verification.refusal_reason_count);
assertEqual('verification current-machine governance false', false, verification.current_machine_governance_evidence);
assertEqual('verification live downstream evidence false', false, verification.live_downstream_recognition_evidence);
assertEqual('verification install false', false, verification.install_or_activation_applied);
assertEqual('verification signing material false', false, verification.secrets_or_signing_material_changed);
assertEqual('verification Telegram false', false, verification.telegram_used);
assertEqual('verification external attestation false', false, verification.external_attestation);
assertEqual('verification non-claim count', REQUIRED_CURRENT_MACHINE_APPROVAL_NON_CLAIMS.length, verification.non_claims.length);
assert('verification JSON is privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(JSON.stringify(verification)));
assert('verification JSON omits unsafe details', !unsafeOutputPattern.test(JSON.stringify(verification)));

const forgedVerificationTargetVersion = structuredClone(verification);
forgedVerificationTargetVersion.source_target.target_version = '9.9.9';
forgedVerificationTargetVersion.accepted_policy_version = '9.9.9';
recomputeVerificationSourceManifestSha256(forgedVerificationTargetVersion);
recomputeVerificationAuthorityRequestSha256(forgedVerificationTargetVersion);
assertThrows(
  'recomputed verification target version refuses',
  () => assertCurrentMachineApprovalPacketVerification(forgedVerificationTargetVersion),
  'target version is not the expected fixture version'
);

const summary = formatCurrentMachineApprovalPacketVerification(verification);
assert('summary title present', summary.includes('ZLAR Current-Machine Approval Packet Verification v1'));
assert('summary says packet complete', summary.includes('packet_complete=true'));
assert('summary names selected surface', summary.includes('selected_surface=claude_code'));
assert('summary names hook event', summary.includes('event=PreToolUse'));
assert('summary names delegation target', summary.includes('delegation_target=~/.zlar/bin/zlar-gate'));
assert('summary names source target', summary.includes('source_target:'));
assert('summary names installer identity', summary.includes('installer_identity:'));
assert('summary names command posture', summary.includes('command_posture:'));
assert('summary names dry-run plan identity', summary.includes('dry_run_plan_identity:'));
assert('summary names authority request identity', summary.includes('authority_request_identity:'));
assert('summary names backup rollback', summary.includes('backup_rollback:'));
assert('summary names issuer policy', summary.includes('issuer_policy:'));
assert('summary names receipt path', summary.includes('receipt_path:'));
assert('summary names refusal matrix', summary.includes('refusal_matrix_complete=true'));
assert('summary names authority boundary', summary.includes('install_or_activation_applied=false'));
assert('summary names non-claim', summary.includes('This packet is not installation or activation.'));
assert('summary is privacy safe', assertNoUnsafeCurrentMachineApprovalPacketText(summary));
assert('summary omits unsafe details', !unsafeOutputPattern.test(summary));

section('fail closed on incomplete or authority-bearing packets');
const wrongSurface = structuredClone(packet);
wrongSurface.selected_surface.selected_surface = 'codex';
assertThrows('wrong surface refuses', () => assertCurrentMachineApprovalPacket(wrongSurface), 'must select claude_code');

const missingHookTarget = structuredClone(packet);
delete missingHookTarget.hook_target.hook_command_target;
assertThrows('missing hook target refuses', () => assertCurrentMachineApprovalPacket(missingHookTarget), 'unexpected fields');

const wrongDelegationTarget = structuredClone(packet);
wrongDelegationTarget.hook_target.delegation_target = '~/.zlar/bin/not-zlar-gate';
assertThrows('wrong delegation target refuses', () => assertCurrentMachineApprovalPacket(wrongDelegationTarget), 'hook delegation target');

const missingSourceTarget = structuredClone(packet);
delete missingSourceTarget.source_target;
assertThrows('missing source target refuses', () => assertCurrentMachineApprovalPacket(missingSourceTarget), 'unexpected fields');

const dirtySourceAllowed = structuredClone(packet);
dirtySourceAllowed.source_target.dirty_worktree_allowed = true;
assertThrows('dirty source allowance refuses', () => assertCurrentMachineApprovalPacket(dirtySourceAllowed), 'dirty worktree allowed must be false');

const installerHashMismatch = structuredClone(packet);
installerHashMismatch.installer_identity.installer_sha256 = 'not-a-sha';
assertThrows('installer hash mismatch refuses', () => assertCurrentMachineApprovalPacket(installerHashMismatch), 'installer SHA-256');

const installerSourceCommitMismatch = structuredClone(packet);
installerSourceCommitMismatch.installer_identity.installer_source_commit_sha = '1111111111111111111111111111111111111111';
assertThrows('valid installer source commit mismatch refuses', () => assertCurrentMachineApprovalPacket(installerSourceCommitMismatch), 'installer source commit SHA is not the expected fixture target');

const installerValidHashMismatch = structuredClone(packet);
installerValidHashMismatch.installer_identity.installer_sha256 = '1'.repeat(64);
assertThrows('valid installer hash mismatch refuses via expected fixture installer', () => assertCurrentMachineApprovalPacket(installerValidHashMismatch), 'installer SHA-256 is not the expected fixture installer');

const recomputedFalseSourceIdentity = structuredClone(packet);
recomputedFalseSourceIdentity.source_target.target_commit_sha = '1111111111111111111111111111111111111111';
recomputedFalseSourceIdentity.source_target.target_tree_sha = '2222222222222222222222222222222222222222';
recomputedFalseSourceIdentity.installer_identity.installer_source_commit_sha = '1111111111111111111111111111111111111111';
recomputePacketBindingHashes(recomputedFalseSourceIdentity);
assertThrows(
  'recomputed false source identity refuses against local git',
  () => assertCurrentMachineApprovalPacket(recomputedFalseSourceIdentity),
  'target commit SHA is not the expected fixture target'
);

const recomputedFalseTreeIdentity = structuredClone(packet);
recomputedFalseTreeIdentity.source_target.target_tree_sha = '2222222222222222222222222222222222222222';
recomputePacketBindingHashes(recomputedFalseTreeIdentity);
assertThrows(
  'recomputed false tree identity refuses against local git',
  () => assertCurrentMachineApprovalPacket(recomputedFalseTreeIdentity),
  'target tree SHA is not the expected fixture target'
);

const wrongPrivateCoreTag = structuredClone(packet);
wrongPrivateCoreTag.source_target.published_release_tag = 'v3.4.54';
recomputePacketBindingHashes(wrongPrivateCoreTag);
assertThrows(
  'wrong private-core tag refuses',
  () => assertCurrentMachineApprovalPacket(wrongPrivateCoreTag),
  'private-core release tag mismatch'
);

const wrongPrivateCoreTagObject = structuredClone(packet);
wrongPrivateCoreTagObject.source_target.published_release_tag_object_sha = '1'.repeat(40);
recomputePacketBindingHashes(wrongPrivateCoreTagObject);
assertThrows(
  'wrong private-core tag object refuses',
  () => assertCurrentMachineApprovalPacket(wrongPrivateCoreTagObject),
  'private-core release tag object mismatch'
);

const wrongPrivateCorePeeledCommit = structuredClone(packet);
wrongPrivateCorePeeledCommit.source_target.published_release_commit_sha = '1'.repeat(40);
recomputePacketBindingHashes(wrongPrivateCorePeeledCommit);
assertThrows(
  'wrong private-core peeled commit refuses',
  () => assertCurrentMachineApprovalPacket(wrongPrivateCorePeeledCommit),
  'private-core release commit mismatch'
);

const wrongCommand = structuredClone(packet);
wrongCommand.command_posture.real_install_argv[3] = 'all';
assertThrows('wrong command posture refuses', () => assertCurrentMachineApprovalPacket(wrongCommand), 'real install argv drifted');

const wrongDryRunCommand = structuredClone(packet);
wrongDryRunCommand.command_posture.dry_run_argv = wrongDryRunCommand.command_posture.dry_run_argv.slice(0, -2);
assertThrows('dry-run command missing repair mode refuses', () => assertCurrentMachineApprovalPacket(wrongDryRunCommand), 'dry-run argv drifted');

const missingPlanHash = structuredClone(packet);
missingPlanHash.dry_run_plan_identity.plan_sha256 = '';
assertThrows('missing dry-run plan hash refuses', () => assertCurrentMachineApprovalPacket(missingPlanHash), 'dry-run plan SHA-256');

const validPlanHashMismatch = structuredClone(packet);
validPlanHashMismatch.dry_run_plan_identity.plan_sha256 = '2'.repeat(64);
assertThrows('valid dry-run plan hash mismatch refuses', () => assertCurrentMachineApprovalPacket(validPlanHashMismatch), 'dry-run plan SHA-256 mismatch');

const expiredRequest = structuredClone(packet);
expiredRequest.authority_request_identity.expires_at = expiredRequest.authority_request_identity.issued_at;
assertThrows('expired authority request refuses', () => assertCurrentMachineApprovalPacket(expiredRequest), 'expiry time is not the expected fixture request');

const ttlMismatchRequest = structuredClone(packet);
ttlMismatchRequest.authority_request_identity.ttl_seconds = 60;
recomputeAuthorityRequestSha256(ttlMismatchRequest);
assertThrows('authority request TTL mismatch refuses', () => assertCurrentMachineApprovalPacket(ttlMismatchRequest), 'TTL is not the expected fixture request');

const staleRecomputedRequest = structuredClone(packet);
staleRecomputedRequest.authority_request_identity.issued_at = '2026-01-01T00:00:00Z';
staleRecomputedRequest.authority_request_identity.expires_at = '2026-01-02T00:00:00Z';
staleRecomputedRequest.authority_request_identity.ttl_seconds = 86400;
recomputeAuthorityRequestSha256(staleRecomputedRequest);
assertThrows('stale recomputed authority request time refuses', () => assertCurrentMachineApprovalPacket(staleRecomputedRequest), 'issue time is not the expected fixture request');

const wrongRequestId = structuredClone(packet);
wrongRequestId.authority_request_identity.request_id = 'forged-current-machine-request';
recomputeAuthorityRequestSha256(wrongRequestId);
assertThrows('recomputed wrong request id refuses', () => assertCurrentMachineApprovalPacket(wrongRequestId), 'request id is not the expected fixture request');

const wrongNonce = structuredClone(packet);
wrongNonce.authority_request_identity.nonce_sha256 = '4'.repeat(64);
recomputeAuthorityRequestSha256(wrongNonce);
assertThrows('recomputed wrong nonce refuses', () => assertCurrentMachineApprovalPacket(wrongNonce), 'nonce SHA-256 is not the expected fixture nonce');

const wrongReplayScope = structuredClone(packet);
wrongReplayScope.authority_request_identity.replay_scope = 'forged-replay-scope';
recomputeAuthorityRequestSha256(wrongReplayScope);
assertThrows('recomputed wrong replay scope refuses', () => assertCurrentMachineApprovalPacket(wrongReplayScope), 'replay scope is not the expected fixture scope');

const validRequestHashMismatch = structuredClone(packet);
validRequestHashMismatch.authority_request_identity.request_sha256 = '3'.repeat(64);
assertThrows('valid request hash mismatch refuses', () => assertCurrentMachineApprovalPacket(validRequestHashMismatch), 'request SHA-256 mismatch');

const policyVersionMismatch = structuredClone(packet);
policyVersionMismatch.issuer_policy.policy.accepted_policy_version = '3.4.53';
assertThrows('policy version target mismatch refuses', () => assertCurrentMachineApprovalPacket(policyVersionMismatch), 'accepted policy version must match target version');

const policyHashMismatch = structuredClone(packet);
policyHashMismatch.issuer_policy.policy.policy_sha256 = '5'.repeat(64);
assertThrows('policy hash mismatch refuses', () => assertCurrentMachineApprovalPacket(policyHashMismatch), 'expected v3.4.55 private-core policy identity');

const missingBackupRollback = structuredClone(packet);
delete missingBackupRollback.backup_rollback_requirements;
assertThrows('missing backup rollback refuses', () => assertCurrentMachineApprovalPacket(missingBackupRollback), 'unexpected fields');

const backupScopeMissingInstallRoot = structuredClone(packet);
backupScopeMissingInstallRoot.backup_rollback_requirements.backup_scope =
  backupScopeMissingInstallRoot.backup_rollback_requirements.backup_scope.filter((item) => item !== '~/.zlar');
assertThrows('backup scope missing install root refuses', () => assertCurrentMachineApprovalPacket(backupScopeMissingInstallRoot), 'backup scope missing ~/.zlar');

const publicKeyIncluded = structuredClone(packet);
publicKeyIncluded.issuer_policy.issuer.public_key_material_included = true;
assertThrows('public key material flag refuses', () => assertCurrentMachineApprovalPacket(publicKeyIncluded), 'public key material included must be false');

const privateKeyText = structuredClone(packet);
privateKeyText.issuer_policy.issuer.public_key_reference = '-----BEGIN PRIVATE KEY-----';
assertThrows('raw key material refuses', () => assertCurrentMachineApprovalPacket(privateKeyText), 'unsafe private key material');

const livePolicyVerified = structuredClone(packet);
livePolicyVerified.issuer_policy.policy.live_policy_signature_verified = true;
assertThrows('live policy verification claim refuses', () => assertCurrentMachineApprovalPacket(livePolicyVerified), 'live policy signature verified must be false');

const mintedByVerifier = structuredClone(packet);
mintedByVerifier.receipt_path.boarding_credential_minted_by_verifier = true;
assertThrows('verifier-minted credential refuses', () => assertCurrentMachineApprovalPacket(mintedByVerifier), 'boarding credential minted by verifier must be false');

const missingReason = structuredClone(packet);
missingReason.downstream_recognition.refusal_matrix =
  missingReason.downstream_recognition.refusal_matrix.filter((item) => item.reason_code !== 'receipt_replay');
assertThrows('missing refusal reason refuses', () => assertCurrentMachineApprovalPacket(missingReason), 'reason count drifted');

const mutationAllowed = structuredClone(packet);
mutationAllowed.downstream_recognition.refusal_matrix[0].effect_mutation_allowed = true;
assertThrows('mutating refusal case refuses', () => assertCurrentMachineApprovalPacket(mutationAllowed), 'effect_mutation_allowed must be false');

const currentMachineGovernance = structuredClone(packet);
currentMachineGovernance.authority_boundary.current_machine_governance_evidence = true;
assertThrows('current-machine governance claim refuses', () => assertCurrentMachineApprovalPacket(currentMachineGovernance), 'current_machine_governance_evidence must be false');

const installationApplied = structuredClone(packet);
installationApplied.authority_boundary.install_or_activation_applied = true;
assertThrows('install claim refuses', () => assertCurrentMachineApprovalPacket(installationApplied), 'install_or_activation_applied must be false');

const missingNonClaim = structuredClone(packet);
missingNonClaim.explicit_non_claims = missingNonClaim.explicit_non_claims.slice(0, -1);
assertThrows('missing non-claim refuses', () => assertCurrentMachineApprovalPacket(missingNonClaim), 'explicit non-claims drifted');

const boardingRuleDrift = structuredClone(packet);
boardingRuleDrift.boarding_credential_rule = 'verifier can mint recognized receipts';
assertThrows('boarding rule drift refuses', () => assertCurrentMachineApprovalPacket(boardingRuleDrift), 'boarding credential rule drifted');

if (FAIL > 0) {
  console.log(`\nResults: ${PASS}/${TOTAL} passed`);
  console.log(`\nFAIL: ${FAIL}/${TOTAL} assertions failed`);
  process.exit(1);
}

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
console.log(`\nPASS: ${PASS}/${TOTAL} assertions passed`);
