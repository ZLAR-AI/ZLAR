#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  KEY_STATE_REPORT_TYPE,
  assertKeyStateReport,
} from '../lib/key-state-report.mjs';

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
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|BEGIN [A-Z ]*PRIVATE KEY|ykman.*Serial:/i;

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
const textRun = runZlar(['key-state']);
assertEqual('text command exits zero', 0, textRun.status);
assertEqual('text command emits no stderr', '', textRun.stderr);
assert('text summary title present', textRun.stdout.includes('ZLAR KEY STATE'));
assert('text summary names software-rooted current posture', textRun.stdout.includes('current: software-rooted'));
assert('text summary marks hardware as migration target', textRun.stdout.includes('hardware slot 9C is migration target'));
assert('text summary points to docs', textRun.stdout.includes('docs/key-state.md'));

section('json command');
const jsonRun = runZlar(['key-state', '--json']);
assertEqual('json command exits zero', 0, jsonRun.status);
assertEqual('json command emits no stderr', '', jsonRun.stderr);
assert('json output is privacy safe', !unsafeOutputPattern.test(jsonRun.stdout));
const report = JSON.parse(jsonRun.stdout);
assert('json report passes validation', assertKeyStateReport(report));
assertEqual('json report type', KEY_STATE_REPORT_TYPE, report.report_type);
assertEqual('json evidence model', 'local-read-only-key-state', report.evidence_model);
assertEqual('json live probing false', false, report.live_probing);
assertEqual('json read-only true', true, report.read_only);
assertEqual('json policy posture', 'software-rooted-current', report.operational_posture.policy_manifest_constitution);
assertEqual('json private key material read false', false, report.privacy.private_key_material_read);
assertEqual('json private key material included false', false, report.privacy.private_key_material_included);
assertEqual('json private key paths included false', false, report.privacy.private_key_paths_included);
assertEqual('json YubiKey serial numbers omitted', false, report.privacy.yubi_key_serial_numbers_included);
assertEqual('json local private key bytes not read', false, report.local_private_key_presence.private_key_bytes_read);
assertEqual('json policy software pin alignment is boolean', 'boolean', typeof report.concerns.policy_signing.software_pins_aligned);
assertEqual('json constitution software pin alignment is boolean', 'boolean', typeof report.concerns.constitution_signing.software_pins_aligned);
assertEqual('json policy ceremony readiness is boolean', 'boolean', typeof report.concerns.policy_signing.current_ceremony_ready);
assertEqual('json constitution ceremony readiness is boolean', 'boolean', typeof report.concerns.constitution_signing.current_ceremony_ready);
assert('json carries key custody non-claim', report.non_claims.some((claim) => claim.includes('key custody')));
assert('json carries revocation non-claim', report.non_claims.some((claim) => claim.includes('revocation')));

section('sample json command');
const sampleJsonRun = runZlar(['key-state', '--sample', '--json']);
assertEqual('sample json exits zero', 0, sampleJsonRun.status);
assertEqual('sample json emits no stderr', '', sampleJsonRun.stderr);
assert('sample json output is privacy safe', !unsafeOutputPattern.test(sampleJsonRun.stdout));
const sampleReport = JSON.parse(sampleJsonRun.stdout);
assert('sample json report passes validation', assertKeyStateReport(sampleReport));
assertEqual('sample json report type', KEY_STATE_REPORT_TYPE, sampleReport.report_type);
assertEqual('sample json timestamp deterministic', '1970-01-01T00:00:00.000Z', sampleReport.generated_at);
assertEqual('sample json ykman unavailable fixture', false, sampleReport.tools.ykman_available);
assertEqual('sample json openssl unavailable fixture', false, sampleReport.tools.openssl_available);
assertEqual('sample json hardware count zero', 0, sampleReport.hardware_observation.yubi_key_count);
assertEqual('sample json local private key absent', false, sampleReport.local_private_key_presence.legacy_software_signing_key_present);
assertEqual('sample json policy hardware target unobserved', false, sampleReport.concerns.policy_signing.hardware_target_observed);
assertEqual('sample json constitution hardware target unobserved', false, sampleReport.concerns.constitution_signing.hardware_target_observed);
assertEqual('sample json spec hardware target unobserved', false, sampleReport.concerns.spec_test_vector_signing.hardware_target_observed);
assertEqual('sample json private key material read false', false, sampleReport.privacy.private_key_material_read);
assert('sample json carries current-machine governance non-claim', sampleReport.non_claims.some((claim) => claim.includes('current-machine governance')));

section('help and fail closed command handling');
const helpRun = runZlar(['key-state', '--help']);
assertEqual('help exits zero', 0, helpRun.status);
assertEqual('help emits no stdout', '', helpRun.stdout);
assert('help names usage', helpRun.stderr.includes('Usage: zlar key-state [--json]'));
assert('help names sample usage', helpRun.stderr.includes('zlar key-state --sample --json'));
assert('help states no private key bytes', helpRun.stderr.includes('no private key bytes'));
assert('help states non-claims', helpRun.stderr.includes('no key custody'));

const sampleWithoutJson = runZlar(['key-state', '--sample']);
assert('sample without json exits usage error', sampleWithoutJson.status !== 0);
assertEqual('sample without json emits no stdout', '', sampleWithoutJson.stdout);
assert('sample without json names requirement', sampleWithoutJson.stderr.includes('--sample requires --json'));
assert('sample without json is privacy safe', !unsafeOutputPattern.test(sampleWithoutJson.stderr));

const unsupported = runZlar(['key-state', '--latest']);
assert('unsupported option exits usage error', unsupported.status !== 0);
assertEqual('unsupported emits no stdout', '', unsupported.stdout);
assert('unsupported names unsupported option', unsupported.stderr.includes('Unsupported option'));
assert('unsupported is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

const helpList = runZlar(['help']);
assertEqual('main help exits zero', 0, helpList.status);
assert('main help lists key-state', helpList.stdout.includes('key-state'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
