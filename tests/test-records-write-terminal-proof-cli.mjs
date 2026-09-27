#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE,
  RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE,
  REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS,
  assertRecordsWriteTerminalProof,
} from '../lib/records-write-terminal-proof.mjs';

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

function runZlar(args, options = {}) {
  return spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const PLAN_PATH = 'profiles/protected-records-runtime-local-activation-plan.fixture.json';
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const SAMPLE_ARTIFACT_SHA256 = 'dbf2b182501a38c870377984d58c92ae28cfc857afa86fc9686dd90a64bd846b';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

const textRun = runZlar(['records-write-terminal-proof']);
assertEqual('default text command exits zero', 0, textRun.status);
assertEqual('default text command emits no stderr', '', textRun.stderr);
assert('default text title present', textRun.stdout.includes('ZLAR Records.Write One-Terminal Proof v1'));
assert('default text includes airport sentence', textRun.stdout.includes(RECORDS_WRITE_TERMINAL_AIRPORT_SENTENCE));
assert('default text includes artifact sha', textRun.stdout.includes(SAMPLE_ARTIFACT_SHA256));
assert('default text includes active profile selection', textRun.stdout.includes('Active profile selection: selected=true'));
assert('default text includes active profile scope', textRun.stdout.includes('scope=local-disposable-proof-harness'));
assert('default text includes active profile non-install', textRun.stdout.includes('persistent_runtime_profile_installed=false'));
assert('default text includes recognized write accepted', textRun.stdout.includes('recognized_write_accepted=true'));
assert('default text includes fixture rightful issuance', textRun.stdout.includes('fixture_rightful_issuance_path_evidenced=true'));
assert('default text includes authority grant refusals', textRun.stdout.includes('missing_grant=true; mismatched_grant=true; revoked_grant=true; expired_grant=true; request_supplied_grant=true'));
assert('default text includes burn window', textRun.stdout.includes('burn_window_named=true'));
assert('default text includes generic rightful ceiling', textRun.stdout.includes('generic_rightful_issuance=false'));
assert('default text includes lifecycle ceiling', textRun.stdout.includes('consequence_lifecycle_closed=false'));
assert('default text includes missing refusal', textRun.stdout.includes('missing_receipt_refused_before_mutation=true'));
assert('default text includes unrecognized refusal', textRun.stdout.includes('unrecognized_receipt_refused_before_mutation=true'));
assert('default text includes downstream refusal contract', textRun.stdout.includes(`Downstream refusal contract: type=${RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE}`));
assert('default text includes refusal count', textRun.stdout.includes(`cases=${REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length}/${REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length}`));
assert('default text includes zero mutation contract', textRun.stdout.includes('zero_state_delta=true'));
assert('default text includes open boundaries', textRun.stdout.includes('Open boundaries: local_activation_only'));
assert('default text includes non-claim', textRun.stdout.includes('not a persistent install or production deployment'));
assert('default text is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

const jsonRun = runZlar(['records-write-terminal-proof', '--json']);
assertEqual('default json command exits zero', 0, jsonRun.status);
assertEqual('default json command emits no stderr', '', jsonRun.stderr);
assert('default json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const proof = JSON.parse(jsonRun.stdout);
assert('default json proof validates', assertRecordsWriteTerminalProof(proof));
assertEqual('default json proof type', 'zlar-records-write-terminal-proof-v1', proof.proof_type);
assertEqual('default json active profile selected', true, proof.active_profile_selection.selected);
assertEqual('default json active profile scope', 'local-disposable-proof-harness', proof.active_profile_selection.selection_scope);
assertEqual('default json active profile source', 'explicit-plan-and-profile-inputs', proof.active_profile_selection.selection_source);
assertEqual('default json active profile no latest', false, proof.active_profile_selection.selects_latest_profile);
assertEqual('default json active profile not installed', false, proof.active_profile_selection.persistent_runtime_profile_installed);
assertEqual('default json active profile no live check', false, proof.active_profile_selection.live_runtime_profile_checked);
assertEqual('default json recognized accepted', true, proof.outcomes.recognized_write_accepted);
assertEqual('default json fixture rightful issuance', true, proof.claim_boundary.fixture_rightful_issuance_path_evidenced);
assertEqual('default json generic rightful false', false, proof.claim_boundary.rightful_issuance_proven);
assertEqual('default json portable rightful false', false, proof.claim_boundary.portable_rightful_issuance_proven);
assertEqual('default json live authority false', false, proof.claim_boundary.live_authority_proven);
assertEqual('default json production rightful false', false, proof.claim_boundary.production_rightful_issuance_proven);
assertEqual('default json current machine false', false, proof.claim_boundary.current_machine_governance_proven);
assertEqual('default json lifecycle closed false', false, proof.claim_boundary.consequence_lifecycle_closed);
assertEqual('default json same-process signed replay refused', true, proof.outcomes.same_process_signed_payload_replay_refused_before_mutation);
assertEqual('default json restart grant refused', true, proof.outcomes.restart_consumed_authority_grant_refused_before_mutation);
assertEqual('default json request grant refused', true, proof.outcomes.request_supplied_authority_grant_refused_before_mutation);
assertEqual('default json grant burn named', true, proof.storage_boundary.partial_grant_commit_burn_window_named);
assertEqual('default json joint rollback open', true, proof.storage_boundary.store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse);
assertEqual('default json missing refused', true, proof.outcomes.missing_receipt_refused_before_mutation);
assertEqual('default json unrecognized refused', true, proof.outcomes.unrecognized_receipt_refused_before_mutation);
assertEqual('default json invalid refused', true, proof.outcomes.invalid_receipt_refused_before_mutation);
assertEqual('default json stale refused', true, proof.outcomes.stale_receipt_refused_before_mutation);
assertEqual('default json wrong policy refused', true, proof.outcomes.wrong_policy_refused_before_mutation);
assertEqual('default json wrong domain refused', true, proof.outcomes.wrong_domain_refused_before_mutation);
assertEqual('default json wrong tool refused', true, proof.outcomes.wrong_tool_refused_before_mutation);
assertEqual('default json downstream refusal contract type', RECORDS_WRITE_DOWNSTREAM_REFUSAL_CONTRACT_TYPE, proof.downstream_refusal_contract.contract_type);
assertEqual('default json downstream refusal case count', REQUIRED_RECORDS_WRITE_DOWNSTREAM_REFUSALS.length, proof.downstream_refusal_contract.case_count);
assertEqual('default json downstream refusals before mutation', true, proof.downstream_refusal_contract.all_refused_before_mutation);
assertEqual('default json downstream refusals zero delta', true, proof.downstream_refusal_contract.all_zero_state_delta);
assertEqual('default json downstream reason codes match', true, proof.downstream_refusal_contract.all_expected_reason_codes_match);
assertEqual('default json receipt and grant required', true, proof.downstream_refusal_contract.recognized_receipt_and_authority_grant_required_to_mutate);
assertEqual('default json hook config false', false, proof.mutation_boundary.hook_configuration_written);

const explicitJsonRun = runZlar(['records-write-terminal-proof', '--plan', PLAN_PATH, '--profile', PROFILE_PATH, '--json']);
assertEqual('explicit json command exits zero', 0, explicitJsonRun.status);
assertEqual('explicit json command emits no stderr', '', explicitJsonRun.stderr);
assertEqual('explicit json matches default json', jsonRun.stdout, explicitJsonRun.stdout);

const plan = readFileSync(PLAN_PATH, 'utf8');
const stdinPlanRun = runZlar(['records-write-terminal-proof', '--plan', '-', '--profile', PROFILE_PATH, '--json'], {
  input: plan,
});
assertEqual('stdin plan command exits zero', 0, stdinPlanRun.status);
assertEqual('stdin plan command emits no stderr', '', stdinPlanRun.stderr);
assertEqual('stdin plan matches default json', jsonRun.stdout, stdinPlanRun.stdout);

const helpRun = runZlar(['records-write-terminal-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assertEqual('help emits no stdout', '', helpRun.stdout);
assert('help names usage', helpRun.stderr.includes('Usage: zlar records-write-terminal-proof [--json] [--plan <file|-> --profile <file|->]'));
assert('help says no latest', helpRun.stderr.includes('does not select --latest'));
assert('help names non-claims', helpRun.stderr.includes('does not install a runtime profile'));

const unsupported = runZlar(['records-write-terminal-proof', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
assert('unsupported option names unsupported', unsupported.stderr.includes('Unsupported option provided'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const missingPlan = runZlar(['records-write-terminal-proof', '--plan']);
assert('missing plan value exits usage error', missingPlan.status !== 0);
assertEqual('missing plan emits no stdout', '', missingPlan.stdout);
assert('missing plan names missing value', missingPlan.stderr.includes('Missing value for --plan'));

const bothStdin = runZlar(['records-write-terminal-proof', '--plan', '-', '--profile', '-'], {
  input: `${plan}\n${readFileSync(PROFILE_PATH, 'utf8')}`,
});
assert('both stdin exits usage error', bothStdin.status !== 0);
assertEqual('both stdin emits no stdout', '', bothStdin.stdout);
assert('both stdin names conflict', bothStdin.stderr.includes('--plan - and --profile - cannot both read from stdin'));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists records-write-terminal-proof', mainHelp.stdout.includes('records-write-terminal-proof'));

console.log(`\nResults: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) {
  process.exit(1);
}
console.log('ALL PASS');
