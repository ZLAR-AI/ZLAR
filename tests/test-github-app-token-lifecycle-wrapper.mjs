import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import {
  EXPECTED_APP_ID,
  EXPECTED_APP_NAME,
  EXPECTED_CUSTODY_TARGET,
  EXPECTED_SELECTED_REPO,
  runGithubAppTokenLifecycleWrapper,
  scanUnsafeTokenLifecycleText,
} from '../lib/zlar-github-app-token-lifecycle-wrapper.mjs';

const repoRoot = process.cwd();
const cliPath = join(repoRoot, 'bin', 'zlar-github-app-token-lifecycle');

function fixture(overrides = {}) {
  return {
    mode: 'fake-fixture',
    expected_app: {
      name: EXPECTED_APP_NAME,
      app_id: EXPECTED_APP_ID,
      selected_repo: EXPECTED_SELECTED_REPO,
      custody_target_path: EXPECTED_CUSTODY_TARGET,
      ...(overrides.expected_app ?? {}),
    },
    fixture: {
      request_started_at: '2026-07-04T20:50:00Z',
      response_received_at: '2026-07-04T20:50:01Z',
      simulated_expires_at: '2026-07-04T21:50:01Z',
      simulated_revocation_status: 'not_exercised_in_fake_mode',
      network_calls: false,
      github_api_used: false,
      remote_ref_read: false,
      source_movement: false,
      git_push: false,
      git_fetch: false,
      git_ls_remote: false,
      credential_helper: false,
      private_key_touched: false,
      yubikey_used: false,
      ...(overrides.fixture ?? {}),
    },
    ...overrides.top,
  };
}

function assertRefused(input, code) {
  const report = runGithubAppTokenLifecycleWrapper(input);
  assert.equal(report.lifecycle_status, 'refused');
  assert.equal(report.refusal_reason_code, code);
}

function assertNoUnsafeStrings(report) {
  const serialized = JSON.stringify(report);
  assert.deepEqual(scanUnsafeTokenLifecycleText(serialized), []);
  assert.equal(serialized.includes('ghs_'), false);
  assert.equal(serialized.includes('Authorization:'), false);
  assert.equal(serialized.includes('BEGIN PRIVATE KEY'), false);
  assert.equal(serialized.includes('token_length'), false);
  assert.equal(serialized.includes('public_key'), false);
}

const positive = runGithubAppTokenLifecycleWrapper(fixture());
assert.equal(positive.lifecycle_status, 'passed');
assert.equal(positive.app.name, EXPECTED_APP_NAME);
assert.equal(positive.app.selected_repo, EXPECTED_SELECTED_REPO);
assert.equal(positive.no_secret_guarantees.network_path_used, false);
assert.equal(positive.no_secret_guarantees.private_key_file_touched, false);
assert.equal(positive.no_secret_guarantees.installation_token_minted, false);
assert.equal(positive.chat2_adversarial_review_required_before_live_token_authority, true);
assert.equal(positive.fake_lifecycle.simulated_installation_id, 'fixture-installation-id-redacted');
assertNoUnsafeStrings(positive);

assertRefused(fixture({ fixture: { request_started_at: 'ghs_1234567890abcdefghijklmnopqrstuvwxyz' } }), 'unsafe_secret_shaped_material');
assertRefused(
  fixture({ fixture: { request_started_at: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart' } }),
  'unsafe_secret_shaped_material',
);
assertRefused(fixture({ fixture: { request_started_at: 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { request_started_at: '-----BEGIN PRIVATE KEY-----' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { request_started_at: 'https://user:password@example.com/ZLAR-AI/ZLAR' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { request_started_at: 'TOKEN=abcdefghijklmnop' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { request_started_at: 'token: abcdefghijklmnop' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { request_started_at: 'private_key: abcdefghijklmnop' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { request_started_at: 'authorization: abcdefghijklmnop' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { request_started_at: 'secret: abcdefghijklmnop' } }), 'unsafe_secret_shaped_material');
assertRefused(fixture({ fixture: { token_length: 42 } }), 'unsafe_input_key');
assertRefused(fixture({ fixture: { access_token: 'redacted-probe' } }), 'unsafe_input_key');
assertRefused(fixture({ fixture: { installation_token: 'redacted-probe' } }), 'unsafe_input_key');
assertRefused(fixture({ fixture: { auth: 'redacted-probe' } }), 'unsafe_input_key');
assertRefused(fixture({ fixture: { headers: { authorization: 'redacted-probe' } } }), 'unsafe_input_key');
assertRefused(fixture({ fixture: { credentials: 'redacted-probe' } }), 'unsafe_input_key');
assertRefused(fixture({ fixture: { client_secret: 'redacted-probe' } }), 'unsafe_input_key');
assertRefused(fixture({ fixture: { simulated_installation_id: 'echo-this-value' } }), 'unknown_input_key');
assertRefused(fixture({ fixture: { harmless_probe: 'echo-this-value' } }), 'unknown_input_key');
assertRefused(fixture({ fixture: { simulated_revocation_status: 'echo-this-value' } }), 'invalid_revocation_status');
assertRefused(fixture({ fixture: { request_started_at: 'not-a-timestamp' } }), 'invalid_fixture_timestamp');
assertRefused(fixture({ fixture: { network_calls: true } }), 'network_path_requested');
assertRefused(fixture({ fixture: { github_api_used: true } }), 'github_api_requested');
assertRefused(fixture({ expected_app: { name: 'Wrong App' } }), 'app_name_mismatch');
assertRefused(fixture({ expected_app: { app_id: '0' } }), 'app_id_mismatch');
assertRefused(fixture({ expected_app: { selected_repo: 'ZLAR-AI/Other' } }), 'selected_repo_mismatch');
assertRefused(fixture({ expected_app: { custody_target_path: '/tmp/key.pem' } }), 'custody_target_mismatch');

const liveWithoutAuthority = runGithubAppTokenLifecycleWrapper({ mode: 'live' });
assert.equal(liveWithoutAuthority.lifecycle_status, 'refused');
assert.equal(liveWithoutAuthority.refusal_reason_code, 'live_mode_requires_later_authority_packet');

const liveWithAuthority = runGithubAppTokenLifecycleWrapper(
  { mode: 'live', authority_packet_path: '/safe/metadata-only.md', authority_packet_sha256: 'a'.repeat(64) },
);
assert.equal(liveWithAuthority.lifecycle_status, 'refused');
assert.equal(liveWithAuthority.refusal_reason_code, 'live_mode_disabled_in_no_secret_build');

const opaqueUnsupportedMode = 'opaquecredentialvalue-not-a-valid-mode';
const unsupportedModeReport = runGithubAppTokenLifecycleWrapper({ ...fixture(), mode: opaqueUnsupportedMode });
const unsupportedModeSerialized = JSON.stringify(unsupportedModeReport);
assert.equal(unsupportedModeReport.lifecycle_status, 'refused');
assert.equal(unsupportedModeReport.refusal_reason_code, 'unsupported_mode');
assert.equal(unsupportedModeReport.mode, 'unsupported');
assert.equal(unsupportedModeSerialized.includes(opaqueUnsupportedMode), false);

const tmp = mkdtempSync(join(tmpdir(), 'zlar-token-lifecycle-test-'));
const inputPath = join(tmp, 'fixture.json');
writeFileSync(inputPath, `${JSON.stringify(fixture())}\n`);
const cli = spawnSync('node', [cliPath, '--input', inputPath, '--json'], { encoding: 'utf8' });
assert.equal(cli.status, 0, cli.stderr);
const cliReport = JSON.parse(cli.stdout);
assert.equal(cliReport.lifecycle_status, 'passed');
assert.equal(cliReport.no_secret_guarantees.network_path_used, false);

const liveCli = spawnSync('node', [cliPath, '--live', '--json'], { encoding: 'utf8' });
assert.equal(liveCli.status, 2);
assert.equal(JSON.parse(liveCli.stdout).refusal_reason_code, 'live_mode_requires_later_authority_packet');

const liveCliWithAuthority = spawnSync(
  'node',
  [
    cliPath,
    '--live',
    '--authority-packet',
    '/operator-private-config/source-transport/github-app/zlar-source-transport.private-key-metadata-only.md',
    '--authority-sha256',
    'a'.repeat(64),
    '--json',
  ],
  { encoding: 'utf8' },
);
assert.equal(liveCliWithAuthority.status, 2);
const liveCliWithAuthorityReport = JSON.parse(liveCliWithAuthority.stdout);
assert.equal(liveCliWithAuthorityReport.refusal_reason_code, 'live_mode_disabled_in_no_secret_build');
assert.equal(liveCliWithAuthority.stdout.includes('private-key-metadata-only'), false);

const unsupportedModeCli = spawnSync('node', [cliPath, '--input', '-', '--json'], {
  encoding: 'utf8',
  input: JSON.stringify({ ...fixture(), mode: opaqueUnsupportedMode }),
});
assert.equal(unsupportedModeCli.status, 2);
assert.equal(unsupportedModeCli.stderr.includes(opaqueUnsupportedMode), false);
assert.equal(unsupportedModeCli.stdout.includes(opaqueUnsupportedMode), false);
const unsupportedModeCliReport = JSON.parse(unsupportedModeCli.stdout);
assert.equal(unsupportedModeCliReport.refusal_reason_code, 'unsupported_mode');
assert.equal(unsupportedModeCliReport.mode, 'unsupported');

const unsupportedModeOut = join(tmp, 'unsupported-mode-report.json');
const unsupportedModeJsonOutCli = spawnSync(
  'node',
  [cliPath, '--input', '-', '--json-out', unsupportedModeOut, '--json'],
  {
    encoding: 'utf8',
    input: JSON.stringify({ ...fixture(), mode: opaqueUnsupportedMode }),
  },
);
assert.equal(unsupportedModeJsonOutCli.status, 2);
assert.equal(unsupportedModeJsonOutCli.stdout.includes(opaqueUnsupportedMode), false);
assert.equal(unsupportedModeJsonOutCli.stderr.includes(opaqueUnsupportedMode), false);
assert.equal(existsSync(unsupportedModeOut), false);

const blockedOut = join(tmp, 'blocked-report.json');
const leakCli = spawnSync(
  'node',
  [cliPath, '--input', '-', '--json-out', blockedOut, '--json'],
  {
    encoding: 'utf8',
    input: JSON.stringify(fixture({ fixture: { request_started_at: 'token: abcdefghijklmnop' } })),
  },
);
assert.equal(leakCli.status, 2);
assert.equal(existsSync(blockedOut), false);

const unsafeArgCli = spawnSync('node', [cliPath, '--input', 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'], {
  encoding: 'utf8',
});
assert.equal(unsafeArgCli.status, 2);
assert.equal(unsafeArgCli.stderr.includes('abcdefghijklmnopqrstuvwxyz'), false);

console.log('github app token lifecycle wrapper: 97/97 assertions passed');
