#!/usr/bin/env node

import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  assertProtectedRecordsRuntimeProfilePreflight,
} from '../lib/protected-records-runtime-profile-preflight.mjs';
import {
  REQUIRED_RUNTIME_PROFILE_CASES,
} from '../lib/protected-records-runtime-profile.mjs';

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

function section(title) {
  console.log(`\n-- ${title} --`);
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const PROFILE_PATH = 'profiles/protected-records-runtime-fixture.profile.json';
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-runtime-profile-preflight-cli-'));

function runZlar(args, options = {}) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    input: options.input,
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8'));
const expectedRuntimeProofCaseCount = REQUIRED_RUNTIME_PROFILE_CASES.length;

section('text preflight command');
const textRun = runZlar(['protected-records-runtime-profile-preflight', '--profile', PROFILE_PATH]);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Runtime Profile Preflight v1'));
assert('text summary includes profile id', textRun.stdout.includes('Profile: id=protected-records-runtime-fixture-profile'));
assert('text summary states preflight model', textRun.stdout.includes('Evidence model: local-disposable-runtime-profile-preflight-fixture; live probing=false'));
assert('text summary includes launcher grant requirements', textRun.stdout.includes('launcher_config=true; grant_contract_required=true; grant_appointment_required=true; issuance_decision_required=true; authorized_record_update_required=true; source_profile_authority_grant_present=false'));
assert('text summary includes storage identities', textRun.stdout.includes('consumed_authority_grant_store=persistent-single-use-authority-grant-contract-sha256-store; consumption_identity=authority-grant-contract-sha256; signed_payload_replay_identity=verified-signed-payload-sha256'));
assert('text summary includes witness boundary', textRun.stdout.includes('anchor=launcher-owned-local-store-hash-anchor; witness=launcher-owned-local-store-hash-witness; rollback_detection=single-host-anchor-and-witness-match-before-mutation; store_anchor_and_witness_joint_rollback_detection=false'));
assert('text summary includes proof case count', textRun.stdout.includes(`cases=${expectedRuntimeProofCaseCount}/${expectedRuntimeProofCaseCount}`));
assert('text summary includes rollback refusal', textRun.stdout.includes('rollback_refused=true; deletion_refused=true; replacement_refused=true'));
assert('text summary includes grant refusals', textRun.stdout.includes('missing_appointment_refused=true; mismatched_appointment_refused=true; revoked_refused=true; expired_refused=true; request_supplied_grant_refused=true'));
assert('text summary includes residual rollback boundary', textRun.stdout.includes('store_and_anchor_joint_rollback_refused_while_witness_ahead=true; store_anchor_and_witness_joint_rollback_detection=false; store_anchor_and_witness_joint_rollback_reopens_authority_grant_reuse=true'));
assert('text summary states production non-check', textRun.stdout.includes('production_records_service_checked=false; live_records_system_checked=false'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json preflight command');
const jsonRun = runZlar(['protected-records-runtime-profile-preflight', '--profile', PROFILE_PATH, '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes validation', assertProtectedRecordsRuntimeProfilePreflight(report, profile));
assertEqual('json preflight type', 'zlar-protected-records-runtime-profile-preflight-v1', report.preflight_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json evidence model', 'local-disposable-runtime-profile-preflight-fixture', report.evidence_model);
assertEqual('json proof run in preflight', true, report.proof_summary.proof_run_in_preflight);
assertEqual('json proof case count', expectedRuntimeProofCaseCount, report.proof_summary.proof_case_count);
assertEqual('json required proof case count', expectedRuntimeProofCaseCount, report.proof_summary.proof_required_case_count);
assert('json includes profile sha', /"profile_sha256": "[a-f0-9]{64}"/.test(jsonRun.stdout));
assertEqual('json mutation route exact', 'receipt-recognition-then-authority-grant-before-consumption-and-runtime-state-mutation', report.runtime_profile_contract.mutation_authoritative_route);
assertEqual('json consumed authority grant store exact', 'persistent-single-use-authority-grant-contract-sha256-store', report.runtime_profile_contract.consumed_authority_grant_store);
assertEqual('json consumption identity exact', 'authority-grant-contract-sha256', report.runtime_profile_contract.consumption_identity);
assertEqual('json signed payload replay identity exact', 'verified-signed-payload-sha256', report.runtime_profile_contract.signed_payload_replay_identity);
assertEqual('json launcher grant contract required', true, report.authority_boundary.authority_grant_contract_required_from_launcher);
assertEqual('json source profile grant absent', false, report.authority_boundary.source_profile_authority_grant_present);
assert('json includes hidden grant anchor path', jsonRun.stdout.includes('"consumed_grant_store_anchor_path_exposed_to_agent": false'));
assert('json includes hidden grant witness path', jsonRun.stdout.includes('"consumed_grant_store_witness_path_exposed_to_agent": false'));
assert('json includes witness rollback non-detection', jsonRun.stdout.includes('"store_anchor_and_witness_joint_rollback_detection": false'));
assertEqual('json request supplied grant refused', true, report.proof_summary.request_supplied_authority_grant_refused);
assert('json includes production anti rollback non-claim', jsonRun.stdout.includes('"production_grade_anti_rollback": false'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('stdin profile command');
const stdinRun = runZlar(['protected-records-runtime-profile-preflight', '--profile', '-', '--json'], {
  input: readFileSync(PROFILE_PATH, 'utf8'),
});
assertEqual('stdin command exits zero', 0, stdinRun.status);
assertEqual('stdin command emits no stderr', '', stdinRun.stderr);
const stdinReport = JSON.parse(stdinRun.stdout);
assert('stdin report passes validation', assertProtectedRecordsRuntimeProfilePreflight(stdinReport, profile));

section('help and fail closed command handling');
const helpRun = runZlar(['protected-records-runtime-profile-preflight', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-runtime-profile-preflight --profile <file|-> [--json]'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assert('help states no persistent install', helpRun.stderr.includes('install a persistent runtime profile'));
assert('help states anti-rollback boundary', helpRun.stderr.includes('prove production-grade anti-rollback'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const missingProfile = runZlar(['protected-records-runtime-profile-preflight']);
assert('missing profile exits usage error', missingProfile.status !== 0);
assertEqual('missing profile emits no stdout', '', missingProfile.stdout);
assert('missing profile refuses latest runtime profile', missingProfile.stderr.includes('does not select a live or latest runtime profile'));

const unsupported = runZlar(['protected-records-runtime-profile-preflight', '--profile', PROFILE_PATH, '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided.'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const driftedProfile = structuredClone(profile);
driftedProfile.storage_boundary.store_anchor_and_witness_joint_rollback_detection = true;
const driftedPath = join(scratch, 'drifted-runtime-profile.json');
writeFileSync(driftedPath, `${JSON.stringify(driftedProfile, null, 2)}\n`);
const driftedRun = runZlar(['protected-records-runtime-profile-preflight', '--profile', driftedPath]);
assert('drifted rollback closure claim fails', driftedRun.status !== 0);
assertEqual('drifted profile emits no stdout', '', driftedRun.stdout);
assert('drifted profile reports sanitized failure', driftedRun.stderr.includes('storage boundary drifted') || driftedRun.stderr.includes('private path or credential details were suppressed'));
assert('drifted profile stderr is privacy safe', !unsafeOutputPattern.test(driftedRun.stderr));

const retiredSchemaProfile = structuredClone(profile);
retiredSchemaProfile.consumed_receipt_store = retiredSchemaProfile.consumed_authority_grant_store;
delete retiredSchemaProfile.consumed_authority_grant_store;
const retiredSchemaPath = join(scratch, 'retired-runtime-profile-schema.json');
writeFileSync(retiredSchemaPath, `${JSON.stringify(retiredSchemaProfile, null, 2)}\n`);
const retiredSchemaRun = runZlar(['protected-records-runtime-profile-preflight', '--profile', retiredSchemaPath]);
assert('retired receipt-store schema exits nonzero', retiredSchemaRun.status !== 0);
assertEqual('retired receipt-store schema emits no stdout', '', retiredSchemaRun.stdout);
assert('retired receipt-store schema fails closed', retiredSchemaRun.stderr.includes('unexpected fields') || retiredSchemaRun.stderr.includes('private path or credential details were suppressed'));
assert('retired receipt-store stderr is privacy safe', !unsafeOutputPattern.test(retiredSchemaRun.stderr));

const invalidJsonRun = runZlar(['protected-records-runtime-profile-preflight', '--profile', '-'], {
  input: '{not-json}\n',
});
assert('invalid json exits nonzero', invalidJsonRun.status !== 0);
assertEqual('invalid json emits no stdout', '', invalidJsonRun.stdout);
assert('invalid json names parse failure', invalidJsonRun.stderr.includes('Could not parse protected records runtime profile JSON'));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists runtime profile preflight', mainHelp.stdout.includes('protected-records-runtime-profile-preflight'));

rmSync(scratch, { recursive: true, force: true });

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
