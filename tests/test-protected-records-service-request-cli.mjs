#!/usr/bin/env node

import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  createReceiptV1FromEvent,
  pubkeyFingerprint,
  signReceiptV1,
} from '../lib/receipt.mjs';

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

function isoSecondsAgo(nowEpoch, seconds) {
  return new Date((nowEpoch - seconds) * 1000).toISOString();
}

const ZLAR_BIN = join(process.cwd(), 'bin', 'zlar');
const scratch = mkdtempSync(join(tmpdir(), 'zlar-protected-records-service-cli-'));
const unsafeOutputPattern = /\/Users\/|\/home\/|\/private\/|\/tmp\/|\/var\/|\b(?:sk|pk)-[A-Za-z0-9_-]{6,}\b|token=|api_key|\bchat_id\b|human:[0-9]|BEGIN [A-Z ]*KEY/i;

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

function keyFixture(label) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  const publicPath = join(scratch, `${label}.pub`);
  writeFileSync(publicPath, publicPem);
  return {
    privatePem,
    publicPem,
    kid: pubkeyFingerprint(publicPath),
  };
}

const nowEpoch = Math.floor(Date.now() / 1000);
const trusted = keyFixture('trusted');
const recordUpdate = {
  record_id: 'fixture-record-001',
  operation: 'update_status',
};

function eventFixture(overrides = {}) {
  return {
    id: overrides.id || 'protected-record-service-001',
    ts: overrides.ts || isoSecondsAgo(nowEpoch, 5),
    action: overrides.action || 'records.write',
    domain: overrides.domain || 'records',
    detail: overrides.detail || recordUpdate,
    outcome: overrides.outcome || 'allow',
    rule: overrides.rule || 'RRECORDS_ALLOW',
    authorizer: overrides.authorizer || 'policy',
    policy_version: overrides.policy_version || 'recognition-policy-v1',
    prev_hash: overrides.prev_hash || '0'.repeat(64),
  };
}

function signedReceipt(overrides = {}) {
  return signReceiptV1(
    createReceiptV1FromEvent(eventFixture(overrides)),
    trusted.privatePem,
    trusted.kid
  );
}

function baseInput(label, overrides = {}) {
  return {
    fixture_mode: true,
    receipt: signedReceipt(),
    recognition_rule: {
      deployment_scope: 'protected-records-service-fixture',
      accepted_issuers: [
        {
          kid: trusted.kid,
          public_key_pem: trusted.publicPem,
          status: 'active',
        },
      ],
      accepted_policy_versions: ['recognition-policy-v1'],
      accepted_domains: ['records'],
      accepted_tools: ['records.write'],
      accepted_outcomes: ['allow', 'authorized'],
      max_age_seconds: 120,
      required_audit_event_id: 'protected-record-service-001',
    },
    record_update: recordUpdate,
    request_mode: 'recognized_service_write',
    state_path: join(scratch, `${label}.jsonl`),
    consumed_receipts_path: join(scratch, `${label}-consumed.json`),
    now_epoch: nowEpoch,
    ...overrides,
  };
}

function launcherConfigFromInput(input) {
  return {
    config_type: 'protected-records-service-launcher-config-v1',
    fixture_mode: true,
    recognition_rule: input.recognition_rule,
    state_path: input.state_path,
    consumed_receipts_path: input.consumed_receipts_path,
    now_epoch: input.now_epoch,
    request_stream_authority_material_allowed: false,
    request_stream_allowed_fields: ['receipt', 'record_update'],
  };
}

function requestFromInput(input, overrides = {}) {
  return {
    receipt: input.receipt,
    record_update: input.record_update,
    ...overrides,
  };
}

function writeInput(label, input) {
  const path = join(scratch, `${label}.json`);
  writeFileSync(path, `${JSON.stringify(input, null, 2)}\n`);
  return path;
}

try {
  section('recognized service request command');
  const acceptedInput = baseInput('accepted');
  const acceptedPath = writeInput('accepted-input', acceptedInput);
  const acceptedRun = runZlar(['protected-records-service-request', '--input', acceptedPath, '--require-written']);
  assertEqual('accepted command exits zero', 0, acceptedRun.status);
  assertEqual('accepted command emits no stderr', '', acceptedRun.stderr);
  assert('accepted command output privacy safe', !unsafeOutputPattern.test(acceptedRun.stdout));
  const accepted = JSON.parse(acceptedRun.stdout);
  assertEqual('accepted result type', 'protected-records-service-result-v1', accepted.result_type);
  assertEqual('accepted service write true', true, accepted.service_write_accepted);
  assertEqual('accepted reason recognized', 'recognized', accepted.decision.reason_code);
  assertEqual('accepted state count', 1, accepted.state_entry_count_after);
  assert('accepted state exists', existsSync(acceptedInput.state_path));
  assert('accepted consumed store exists', existsSync(acceptedInput.consumed_receipts_path));
  const acceptedStateText = readFileSync(acceptedInput.state_path, 'utf8');
  assert('accepted state omits raw record id', !acceptedStateText.includes('fixture-record-001'));
  assert('accepted state omits key material', !/BEGIN [A-Z ]*KEY/.test(acceptedStateText));

  section('replay command refuses from persistent consumed store');
  const replayRun = runZlar(['protected-records-service-request', '--input', acceptedPath, '--require-refused']);
  assertEqual('replay command exits zero', 0, replayRun.status);
  assertEqual('replay command emits no stderr', '', replayRun.stderr);
  const replay = JSON.parse(replayRun.stdout);
  assertEqual('replay refused', false, replay.service_write_accepted);
  assertEqual('replay reason', 'receipt_replay', replay.decision.reason_code);
  assertEqual('replay state delta zero', 0, replay.state_entry_count_delta);
  assertEqual('replay leaves one state entry', 1, replay.state_entry_count_after);

  section('config-backed service request command');
  const configBackedBase = baseInput('config-backed');
  const configPath = writeInput('config-backed-config', launcherConfigFromInput(configBackedBase));
  const requestPath = writeInput('config-backed-request', requestFromInput(configBackedBase));
  const configAcceptedRun = runZlar([
    'protected-records-service-request',
    '--config',
    configPath,
    '--input',
    requestPath,
    '--require-written',
  ]);
  assertEqual('config-backed accepted exits zero', 0, configAcceptedRun.status);
  assertEqual('config-backed accepted emits no stderr', '', configAcceptedRun.stderr);
  assert('config-backed accepted output privacy safe', !unsafeOutputPattern.test(configAcceptedRun.stdout));
  const configAccepted = JSON.parse(configAcceptedRun.stdout);
  assertEqual('config-backed evidence model', 'local-fixture-launcher-owned-config', configAccepted.evidence_model);
  assertEqual('config-backed write true', true, configAccepted.service_write_accepted);
  assertEqual('config-backed request mode', 'config_backed_service_write', configAccepted.request_mode);
  assertEqual('config-backed reason recognized', 'recognized', configAccepted.decision.reason_code);
  assertEqual('config-backed state count', 1, configAccepted.state_entry_count_after);

  const configReplayRun = runZlar([
    'protected-records-service-request',
    '--config',
    configPath,
    '--input',
    requestPath,
    '--require-refused',
  ]);
  assertEqual('config-backed replay exits zero', 0, configReplayRun.status);
  const configReplay = JSON.parse(configReplayRun.stdout);
  assertEqual('config-backed replay refused', false, configReplay.service_write_accepted);
  assertEqual('config-backed replay reason', 'receipt_replay', configReplay.decision.reason_code);
  assertEqual('config-backed replay state delta zero', 0, configReplay.state_entry_count_delta);

  const configMissingBase = baseInput('config-missing');
  const configMissingConfigPath = writeInput('config-missing-config', launcherConfigFromInput(configMissingBase));
  const configMissingRequestPath = writeInput('config-missing-request', requestFromInput(configMissingBase, {
    receipt: null,
  }));
  const configMissingRun = runZlar([
    'protected-records-service-request',
    '--config',
    configMissingConfigPath,
    '--input',
    configMissingRequestPath,
    '--require-refused',
  ]);
  assertEqual('config-backed missing receipt exits zero', 0, configMissingRun.status);
  const configMissing = JSON.parse(configMissingRun.stdout);
  assertEqual('config-backed missing receipt refused', false, configMissing.service_write_accepted);
  assertEqual('config-backed missing receipt reason', 'receipt_missing', configMissing.decision.reason_code);
  assertEqual('config-backed missing receipt state delta zero', 0, configMissing.state_entry_count_delta);

  const authorityBase = baseInput('config-authority');
  const authorityConfigPath = writeInput('config-authority-config', launcherConfigFromInput(authorityBase));
  const authorityRequestPath = writeInput('config-authority-request', requestFromInput(authorityBase, {
    recognition_rule: authorityBase.recognition_rule,
    state_path: authorityBase.state_path,
    consumed_receipts_path: authorityBase.consumed_receipts_path,
    fixture_mode: true,
  }));
  const authorityRun = runZlar([
    'protected-records-service-request',
    '--config',
    authorityConfigPath,
    '--input',
    authorityRequestPath,
    '--require-refused',
  ]);
  assertEqual('request-stream authority material exits zero', 0, authorityRun.status);
  const authorityResult = JSON.parse(authorityRun.stdout);
  assertEqual('request-stream authority material refused', false, authorityResult.service_write_accepted);
  assertEqual('request-stream authority material reason', 'request_stream_authority_material', authorityResult.decision.reason_code);
  assertEqual('request-stream authority material mode', 'request_stream_authority_material', authorityResult.request_mode);
  assertEqual('request-stream authority material state delta zero', 0, authorityResult.state_entry_count_delta);

  const forbiddenBase = baseInput('config-forbidden');
  const forbiddenConfigPath = writeInput('config-forbidden-config', launcherConfigFromInput(forbiddenBase));
  const forbiddenRequestPath = writeInput('config-forbidden-request', requestFromInput(forbiddenBase, {
    direct_api_write: true,
  }));
  const forbiddenRun = runZlar([
    'protected-records-service-request',
    '--config',
    forbiddenConfigPath,
    '--input',
    forbiddenRequestPath,
    '--require-refused',
  ]);
  assertEqual('request-stream forbidden field exits zero', 0, forbiddenRun.status);
  const forbidden = JSON.parse(forbiddenRun.stdout);
  assertEqual('request-stream forbidden field refused', false, forbidden.service_write_accepted);
  assertEqual('request-stream forbidden field reason', 'request_stream_forbidden_fields', forbidden.decision.reason_code);
  assertEqual('request-stream forbidden field marked direct api', true, forbidden.direct_api_attempted);
  assertEqual('request-stream forbidden field state delta zero', 0, forbidden.state_entry_count_delta);

  section('stdin refused direct API command');
  const directApiInput = baseInput('direct-api', {
    receipt: null,
    request_mode: 'direct_api_write_without_receipt',
    direct_api_write: true,
  });
  const directApiRun = runZlar(['protected-records-service-request', '--input', '-', '--require-refused'], {
    input: `${JSON.stringify(directApiInput, null, 2)}\n`,
  });
  assertEqual('direct api stdin exits zero', 0, directApiRun.status);
  assertEqual('direct api stdin emits no stderr', '', directApiRun.stderr);
  const directApi = JSON.parse(directApiRun.stdout);
  assertEqual('direct api refused', 'receipt_missing', directApi.decision.reason_code);
  assertEqual('direct api marked', true, directApi.direct_api_attempted);
  assertEqual('direct api writes no state', false, existsSync(directApiInput.state_path));

  const requireWrittenFailure = runZlar(['protected-records-service-request', '--input', '-', '--require-written'], {
    input: `${JSON.stringify(directApiInput, null, 2)}\n`,
  });
  assert('require-written fails refused input', requireWrittenFailure.status !== 0);
  assertEqual('require-written failure emits no JSON', '', requireWrittenFailure.stdout);
  assert('require-written failure names refusal', requireWrittenFailure.stderr.includes('receipt_missing'));

  section('fail closed command handling');
  const missingInput = runZlar(['protected-records-service-request']);
  assert('missing input exits usage error', missingInput.status !== 0);
  assert('missing input refuses live writes', missingInput.stderr.includes('live protected-records service writes are not implemented'));
  assertEqual('missing input emits no JSON', '', missingInput.stdout);

  const unsupported = runZlar(['protected-records-service-request', '--input', acceptedPath, '--latest']);
  assert('unsupported option exits usage error', unsupported.status !== 0);
  assertEqual('unsupported option emits no JSON', '', unsupported.stdout);
  assert('unsupported option is privacy safe', !unsafeOutputPattern.test(unsupported.stderr));

  const bothRequire = runZlar([
    'protected-records-service-request',
    '--input',
    acceptedPath,
    '--require-written',
    '--require-refused',
  ]);
  assert('mutually exclusive require flags fail', bothRequire.status !== 0);
  assert('mutually exclusive error is explicit', bothRequire.stderr.includes('mutually exclusive'));
  assertEqual('mutually exclusive emits no JSON', '', bothRequire.stdout);

  const bothStdin = runZlar([
    'protected-records-service-request',
    '--config',
    '-',
    '--input',
    '-',
  ], {
    input: `${JSON.stringify(launcherConfigFromInput(baseInput('both-stdin')), null, 2)}\n`,
  });
  assert('config and input stdin conflict fails', bothStdin.status !== 0);
  assert('config and input stdin conflict explicit', bothStdin.stderr.includes('cannot both read from stdin'));
  assertEqual('config and input stdin conflict emits no JSON', '', bothStdin.stdout);

  const noFixtureInput = baseInput('no-fixture');
  delete noFixtureInput.fixture_mode;
  const noFixturePath = writeInput('no-fixture-input', noFixtureInput);
  const noFixtureRun = runZlar(['protected-records-service-request', '--input', noFixturePath]);
  assert('missing fixture mode fails', noFixtureRun.status !== 0);
  assertEqual('missing fixture mode emits no JSON', '', noFixtureRun.stdout);
  assert('missing fixture mode names boundary', noFixtureRun.stderr.includes('fixture_mode true is required'));
  assertEqual('missing fixture mode writes no state', false, existsSync(noFixtureInput.state_path));

  const missingStateParentInput = baseInput('missing-state-parent', {
    state_path: join(scratch, 'missing-parent', 'state.jsonl'),
    consumed_receipts_path: join(scratch, 'missing-state-parent-consumed.json'),
  });
  const missingStateParentPath = writeInput('missing-state-parent-input', missingStateParentInput);
  const missingStateParentRun = runZlar(['protected-records-service-request', '--input', missingStateParentPath, '--require-written']);
  assert('missing state parent fails', missingStateParentRun.status !== 0);
  assertEqual('missing state parent emits no JSON', '', missingStateParentRun.stdout);
  assert('missing state parent stderr is privacy safe', !unsafeOutputPattern.test(missingStateParentRun.stderr));
  assert('missing state parent suppresses private details', missingStateParentRun.stderr.includes('private path or credential details were suppressed') || missingStateParentRun.stderr.includes('state_path fixture path is not writable'));
  assertEqual('missing state parent writes no consumed store', false, existsSync(missingStateParentInput.consumed_receipts_path));

  const helpRun = runZlar(['protected-records-service-request', '--help']);
  assertEqual('help exits zero', 0, helpRun.status);
  assert('help names usage', helpRun.stderr.includes('Usage: zlar protected-records-service-request [--config <file|->] --input <file|->'));
  assert('help states launcher-owned config', helpRun.stderr.includes('launcher-owned config supplies fixture_mode'));
  assert('help states local fixture paths', helpRun.stderr.includes('local fixture service paths'));
  assertEqual('help emits no stdout', '', helpRun.stdout);

  const helpList = runZlar(['help']);
  assertEqual('main help exits zero', 0, helpList.status);
  assert('main help lists protected records service request', helpList.stdout.includes('protected-records-service-request'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
