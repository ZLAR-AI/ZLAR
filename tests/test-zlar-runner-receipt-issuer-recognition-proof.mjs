#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  EVIDENCE_MODEL,
  FORBIDDEN_CLAIMS,
  PROOF_TYPE,
  RECEIPT_FORMAT,
  RUNNER_SCOPE,
  SAFE_CLAIM,
  assertNoUnsafeProofText,
  formatZlarRunnerReceiptIssuerRecognitionProof,
  runZlarRunnerReceiptIssuerRecognitionProof
} from '../lib/zlar-runner-receipt-issuer-recognition-proof.mjs';

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

function caseById(report, id) {
  const item = report.cases.find((candidate) => candidate.id === id);
  assert(`case exists: ${id}`, !!item);
  return item;
}

function assertRefusal(report, id, reasonCode) {
  const item = caseById(report, id);
  assertEqual(`${id} receipt bytes valid`, true, item.receipt_valid);
  assertEqual(`${id} refused`, false, item.recognized_for_runner_scope);
  assertEqual(`${id} decision`, 'refuse', item.decision);
  assertEqual(`${id} reason`, reasonCode, item.reason_code);
  assertEqual(`${id} boards false`, false, item.boards);
  assertEqual(`${id} boarding effect`, 'refused', item.boarding_effect);
  assertEqual(`${id} production trust false`, false, item.production_trust);
  assertEqual(`${id} custody false`, false, item.custody_proven);
  assertEqual(`${id} downstream production recognition false`, false, item.downstream_production_recognition);
  assertEqual(`${id} all-surface governance false`, false, item.all_surface_governance);
}

section('runner receipt issuer-recognition report');
const report = runZlarRunnerReceiptIssuerRecognitionProof();
assertEqual('proof type', PROOF_TYPE, report.proof_type);
assertEqual('evidence model', EVIDENCE_MODEL, report.evidence_model);
assertEqual('receipt format', RECEIPT_FORMAT, report.receipt_format);
assertEqual('runner scope', RUNNER_SCOPE, report.runner_scope);
assertEqual('safe claim exact', SAFE_CLAIM, report.safe_claim);
assertEqual('case count', 14, report.case_count);
assertEqual('recognized case count', 2, report.recognized_for_runner_scope_count);
assertEqual('refused case count', 12, report.refused_count);
assertEqual('production trust false', false, report.production_trust);
assertEqual('custody false', false, report.custody_proven);
assertEqual('downstream production recognition false', false, report.downstream_production_recognition);
assertEqual('all-surface governance false', false, report.all_surface_governance);
for (const claim of FORBIDDEN_CLAIMS) {
  assert(`forbidden claim present: ${claim}`, report.forbidden_claims.includes(claim));
}

section('recognized fixture cases');
const allow = caseById(report, 'active_allow_recognized');
assertEqual('allow receipt valid', true, allow.receipt_valid);
assertEqual('allow issuer known', true, allow.issuer_known);
assertEqual('allow issuer active', 'active', allow.issuer_status);
assertEqual('allow recognized', true, allow.recognized_for_runner_scope);
assertEqual('allow decision accepts', 'accept', allow.decision);
assertEqual('allow reason recognized', 'recognized', allow.reason_code);
assertEqual('allow outcome', 'allow', allow.receipt_outcome);
assertEqual('allow boards', true, allow.boards);
assertEqual('allow boarding effect', 'allow_can_board', allow.boarding_effect);
assert('allow audit id present', typeof allow.audit_event_id === 'string' && allow.audit_event_id.length > 0);
assert('allow prev hash present', /^[0-9a-f]{64}$/.test(allow.audit_prev_hash));
assert('allow detail hash present', /^[0-9a-f]{64}$/.test(allow.detail_hash));

const deny = caseById(report, 'active_deny_recognized_not_boarding');
assertEqual('deny receipt valid', true, deny.receipt_valid);
assertEqual('deny issuer known', true, deny.issuer_known);
assertEqual('deny issuer active', 'active', deny.issuer_status);
assertEqual('deny recognized', true, deny.recognized_for_runner_scope);
assertEqual('deny decision accepts as decision record', 'accept', deny.decision);
assertEqual('deny reason recognized', 'recognized', deny.reason_code);
assertEqual('deny outcome', 'deny', deny.receipt_outcome);
assertEqual('deny does not board', false, deny.boards);
assertEqual('deny boarding effect', 'deny_decision_record_not_boarding', deny.boarding_effect);

section('refusal matrix');
assertRefusal(report, 'retired_issuer_refused', 'issuer_not_active');
assertRefusal(report, 'compromised_issuer_refused', 'issuer_compromised');
assertRefusal(report, 'missing_status_refused', 'issuer_status_missing');
assertRefusal(report, 'unknown_issuer_refused', 'unknown_issuer');
assertRefusal(report, 'missing_public_key_refused', 'issuer_key_missing');
assertRefusal(report, 'wrong_policy_refused', 'policy_not_recognized');
assertRefusal(report, 'wrong_domain_refused', 'domain_out_of_scope');
assertRefusal(report, 'wrong_tool_refused', 'tool_out_of_scope');
assertRefusal(report, 'wrong_audit_event_id_refused', 'audit_event_mismatch');
assertRefusal(report, 'wrong_detail_hash_refused', 'detail_hash_mismatch');
assertRefusal(report, 'stale_receipt_refused', 'receipt_stale');
assertRefusal(report, 'valid_proof_key_receipt_not_recognized', 'unknown_issuer');

section('privacy and output shape');
const jsonText = JSON.stringify(report, null, 2);
const summary = formatZlarRunnerReceiptIssuerRecognitionProof(report);
assert('json output is privacy safe', assertNoUnsafeProofText(jsonText));
assert('summary output is privacy safe', assertNoUnsafeProofText(summary));
assert('json omits public key material', !jsonText.includes('BEGIN PUBLIC KEY'));
assert('json omits private key material', !jsonText.includes('BEGIN PRIVATE KEY'));
assert('json omits raw public key field', !jsonText.includes('public_key_pem'));
assert('summary states production trust false', summary.includes('Production trust: false'));
assert('summary states deny not boarding', summary.includes('deny_decision_record_not_boarding'));

section('cli');
const binPath = fileURLToPath(new URL('../bin/zlar-runner-receipt-issuer-recognition-proof', import.meta.url));
const zlarPath = fileURLToPath(new URL('../bin/zlar', import.meta.url));

const help = spawnSync(process.execPath, [binPath, '--help'], { encoding: 'utf8' });
assertEqual('direct CLI help exit', 0, help.status);
assert('direct CLI help mentions issuer-recognition', help.stdout.includes('issuer-recognition'));

const directJson = spawnSync(process.execPath, [binPath, '--json'], { encoding: 'utf8' });
assertEqual('direct CLI json exit', 0, directJson.status);
assert('direct CLI stderr empty', directJson.stderr === '');
const directReport = JSON.parse(directJson.stdout);
assertEqual('direct CLI proof type', PROOF_TYPE, directReport.proof_type);
assertEqual('direct CLI recognized count', 2, directReport.recognized_for_runner_scope_count);
assert('direct CLI json privacy safe', assertNoUnsafeProofText(directJson.stdout));

const zlarJson = spawnSync(zlarPath, ['runner-receipt-issuer-recognition-proof', '--json'], { encoding: 'utf8' });
assertEqual('zlar dispatch json exit', 0, zlarJson.status);
assert('zlar dispatch stderr empty', zlarJson.stderr === '');
const dispatchedReport = JSON.parse(zlarJson.stdout);
assertEqual('zlar dispatch proof type', PROOF_TYPE, dispatchedReport.proof_type);
assertEqual('zlar dispatch case count', 14, dispatchedReport.case_count);

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
