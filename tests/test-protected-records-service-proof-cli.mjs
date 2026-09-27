#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  assertProtectedRecordsServiceProof,
} from '../lib/protected-records-service-proof.mjs';

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
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

function runZlar(args) {
  return spawnSync(ZLAR_BIN, args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

section('text summary command');
const textRun = runZlar(['protected-records-service-proof']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR Protected Records Downstream Service Proof v1'));
assert('text summary states fixture model', textRun.stdout.includes('Evidence model: local-disposable-service-process-fixture; live probing=false'));
assert('text summary includes process boundary', textRun.stdout.includes('process_boundary=separate-cli-process'));
assert('text summary includes accepted service write', textRun.stdout.includes('Recognized service write: accepted=true; reason=recognized; state_delta=1'));
assert('text summary includes replay refusal', textRun.stdout.includes('Replay after service restart: accepted=false; reason=receipt_replay; state_delta=0; separate_process=true'));
assert('text summary includes missing receipt refusal', textRun.stdout.includes('Missing receipt: accepted=false; reason=receipt_missing; state_delta=0'));
assert('text summary includes unrecognized refusal', textRun.stdout.includes('Unrecognized receipt: accepted=false; reason=detail_hash_mismatch; state_delta=0'));
assert('text summary includes invalid receipt refusal', textRun.stdout.includes('Invalid receipt: accepted=false; reason=receipt_invalid; state_delta=0'));
assert('text summary includes unknown issuer refusal', textRun.stdout.includes('Unknown issuer: accepted=false; reason=unknown_issuer; state_delta=0'));
assert('text summary includes stale receipt refusal', textRun.stdout.includes('Stale receipt: accepted=false; reason=receipt_stale; state_delta=0'));
assert('text summary includes direct api refusal', textRun.stdout.includes('Fixture service API write without receipt: accepted=false; reason=receipt_missing; state_delta=0; direct_api_attempted=true'));
assert('text summary names open boundaries', textRun.stdout.includes('Known open boundaries: direct_filesystem_write_to_supplied_fixture_paths,live_records_system,production_records_service,unrouted_records_paths'));
assert('text summary states direct filesystem non-claim', textRun.stdout.includes('does not close direct filesystem writes'));
assert('text summary is privacy safe', !unsafeOutputPattern.test(textRun.stdout));

section('json command');
const jsonRun = runZlar(['protected-records-service-proof', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes validation', assertProtectedRecordsServiceProof(report));
assertEqual('json proof type', 'protected-records-service-proof-v1', report.proof_type);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json evidence model', 'local-disposable-service-process-fixture', report.evidence_model);
assertEqual('json case count', 8, report.cases.length);
assert('json includes service command', jsonRun.stdout.includes('"service_command": "zlar protected-records-service-request --input <file|->"'));
assert('json includes replay case', jsonRun.stdout.includes('"case_id": "replay_refused_after_service_restart"'));
assert('json includes invalid receipt case', jsonRun.stdout.includes('"case_id": "invalid_receipt_refused_before_service_mutation"'));
assert('json includes unknown issuer case', jsonRun.stdout.includes('"case_id": "unknown_issuer_refused_before_service_mutation"'));
assert('json includes stale receipt case', jsonRun.stdout.includes('"case_id": "stale_receipt_refused_before_service_mutation"'));
assert('json includes direct api case', jsonRun.stdout.includes('"case_id": "direct_api_write_without_receipt_refused_before_service_mutation"'));
assert('json includes filesystem side-door non-closure', jsonRun.stdout.includes('"direct_filesystem_write_to_fixture_paths_closed": false'));
assert('json includes direct api refusal', jsonRun.stdout.includes('"direct_api_without_receipt_refused": true'));
assert('json omits key material', !/BEGIN [A-Z ]*KEY/.test(jsonRun.stdout));

section('help and fail closed command handling');
const helpRun = runZlar(['protected-records-service-proof', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-service-proof [--json]'));
assert('help states no live probing', helpRun.stderr.includes('does not live probe'));
assert('help states direct filesystem boundary', helpRun.stderr.includes('close direct filesystem writes'));
assertEqual('help emits no stdout', '', helpRun.stdout);

const unsupported = runZlar(['protected-records-service-proof', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assertEqual('unsupported option emits no stdout', '', unsupported.stdout);
assert('unsupported option names unsupported option', unsupported.stderr.includes('Unsupported option provided.'));
assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const mainHelp = runZlar(['help']);
assertEqual('main help exits zero', 0, mainHelp.status);
assert('main help lists service proof', mainHelp.stdout.includes('protected-records-service-proof'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
