#!/usr/bin/env node

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE,
  buildTrustedReceiptIssuerCompletionProofTestVector,
  trustedReceiptIssuerCompletionProofBodySha256,
} from '../lib/trusted-receipt-issuer-completion-proof.mjs';

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

function assertIncludes(label, value, needle) {
  assert(label, value.includes(needle), `missing=${JSON.stringify(needle)}`);
}

function section(title) {
  console.log(`\n-- ${title} --`);
}

function runZlar(args, input = null) {
  return spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
    cwd: process.cwd(),
    input,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

function jsonFrom(run) {
  return JSON.parse(run.stdout);
}

const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;
const tmp = mkdtempSync(join(tmpdir(), 'zlar-trusted-issuer-completion-cli-'));

try {
  const proof = buildTrustedReceiptIssuerCompletionProofTestVector();
  const proofPath = join(tmp, 'completion-proof.json');
  writeFileSync(proofPath, JSON.stringify(proof, null, 2));
  const oneTerminalProof = buildTrustedReceiptIssuerCompletionProofTestVector({
    selected_surface_id: TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
  });
  const oneTerminalProofPath = join(tmp, 'one-terminal-completion-proof.json');
  writeFileSync(oneTerminalProofPath, JSON.stringify(oneTerminalProof, null, 2));

  section('json verify');
  const jsonRun = runZlar(['trusted-receipt-issuer-completion-proof', 'verify', '--input', proofPath, '--json']);
  assertEqual('json verify exits zero', 0, jsonRun.status);
  assertEqual('json verify stderr empty', '', jsonRun.stderr);
  assert('json verify output privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
  const verification = jsonFrom(jsonRun);
  assertEqual('verification type', TRUSTED_RECEIPT_ISSUER_COMPLETION_VERIFICATION_TYPE, verification.verification_type);
  assertEqual('verification proof sha', trustedReceiptIssuerCompletionProofBodySha256(proof), verification.proof_sha256);
  assertEqual('verification core sentence', TRUSTED_RECEIPT_ISSUER_COMPLETION_CORE_SENTENCE, verification.core_sentence);
  assertEqual('verification not human intention', true, verification.receipt_validity_distinct_from_human_intention);
  assertEqual('verification not human yes', true, verification.issuer_recognition_distinct_from_human_yes);
  assertEqual('verification not legal consent', true, verification.authority_event_distinct_from_legal_consent);
  assertEqual('verification no summary-only acceptance', false, verification.summary_only_evidence_accepted);
  assertEqual('verification no fixture-only acceptance', false, verification.fixture_only_evidence_accepted);

  const oneTerminalRun = runZlar([
    'trusted-receipt-issuer-completion-proof',
    'verify',
    '--input',
    oneTerminalProofPath,
    '--json',
  ]);
  assertEqual('one-terminal json verify exits zero', 0, oneTerminalRun.status);
  assertEqual('one-terminal json verify stderr empty', '', oneTerminalRun.stderr);
  assert('one-terminal json verify output privacy safe', !unsafeOutputPattern.test(oneTerminalRun.stdout));
  const oneTerminalVerification = jsonFrom(oneTerminalRun);
  assertEqual(
    'one-terminal verification selected surface',
    TRUSTED_RECEIPT_ISSUER_COMPLETION_PRIVATE_OPERATOR_RECORDS_TERMINAL_SURFACE_ID,
    oneTerminalVerification.selected_surface_id,
  );

  section('stdin and text verify');
  const stdinRun = runZlar(
    ['trusted-receipt-issuer-completion-proof', 'verify', '--input', '-', '--json'],
    JSON.stringify(proof)
  );
  assertEqual('stdin verify exits zero', 0, stdinRun.status);
  assertEqual('stdin verify stderr empty', '', stdinRun.stderr);
  assertEqual('stdin proof sha', verification.proof_sha256, jsonFrom(stdinRun).proof_sha256);

  const textRun = runZlar(['trusted-receipt-issuer-completion-proof', 'verify', '--input', proofPath]);
  assertEqual('text verify exits zero', 0, textRun.status);
  assertEqual('text verify stderr empty', '', textRun.stderr);
  assertIncludes('text names title', textRun.stdout, 'Trusted Receipt Issuer Completion Proof v1');
  assertIncludes('text names authority primitive', textRun.stdout, 'recognized_authority_event');
  assertIncludes('text names human boundary', textRun.stdout, 'not human intention');
  assertIncludes('text names legal boundary', textRun.stdout, 'legal consent');
  assert('text output privacy safe', !unsafeOutputPattern.test(textRun.stdout));

  section('fail closed command handling');
  const overclaim = structuredClone(proof);
  overclaim.claim_boundary.authority_event_is_legal_consent = true;
  const overclaimPath = join(tmp, 'overclaim.json');
  writeFileSync(overclaimPath, JSON.stringify(overclaim, null, 2));
  const overclaimRun = runZlar(['trusted-receipt-issuer-completion-proof', 'verify', '--input', overclaimPath, '--json']);
  assert('overclaim exits nonzero', overclaimRun.status !== 0);
  assertEqual('overclaim emits no stdout', '', overclaimRun.stdout);
  assertIncludes('overclaim names refusal', overclaimRun.stderr, 'claim_boundary.authority_event_is_legal_consent');
  assert('overclaim stderr privacy safe', !unsafeOutputPattern.test(overclaimRun.stderr));

  const helpRun = runZlar(['trusted-receipt-issuer-completion-proof', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assertEqual('help emits no stdout', '', helpRun.stdout);
  assertIncludes('help names usage', helpRun.stderr, 'Usage: zlar trusted-receipt-issuer-completion-proof verify --input <file|-> [--json]');
  assertIncludes('help names recognized authority event', helpRun.stderr, 'recognized authority events');

  const unsupportedRun = runZlar(['trusted-receipt-issuer-completion-proof', 'run']);
  assert('unsupported exits nonzero', unsupportedRun.status !== 0);
  assertEqual('unsupported emits no stdout', '', unsupportedRun.stdout);
  assertIncludes('unsupported names command', unsupportedRun.stderr, 'unsupported trusted-receipt-issuer-completion-proof command');

  const mainHelp = runZlar(['help']);
  assertEqual('main help exits zero', 0, mainHelp.status);
  assertIncludes('main help lists command', mainHelp.stdout, 'trusted-receipt-issuer-completion-proof');
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
