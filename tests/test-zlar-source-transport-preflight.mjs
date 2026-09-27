#!/usr/bin/env node

import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  FORBIDDEN_CLAIMS,
  REQUIRED_FORBIDDEN_SIDE_EFFECTS,
  RUNTIME_LOCAL_COMMANDS,
  SOURCE_TRANSPORT_AUTHORITY_PACKET_TYPE,
  SOURCE_TRANSPORT_PREFLIGHT_TYPE,
  assertNoUnsafeSourceTransportPreflightText,
  runSourceTransportPreflight,
  writeSourceTransportPreflightReport
} from '../lib/zlar-source-transport-preflight.mjs';

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

function git(cwd, args) {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' }).trim();
}

const repoPath = process.cwd();
const websitePath = join(repoPath, '..', 'ZLAR_Website');
const branch = git(repoPath, ['rev-parse', '--abbrev-ref', 'HEAD']);
const head = git(repoPath, ['rev-parse', 'HEAD']);
const upstream = git(repoPath, ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}']);
const upstreamHead = git(repoPath, ['rev-parse', '@{u}']);
const remoteTrackingRef = `refs/remotes/${upstream}`;
const remoteTrackingHead = git(repoPath, ['show-ref', '--hash', remoteTrackingRef]);
const websiteHead = git(websitePath, ['rev-parse', 'HEAD']);
const nowIso = new Date().toISOString();
const tokenExpiresIso = new Date(Date.parse(nowIso) + (60 * 60 * 1000)).toISOString();

function packetFixture(overrides = {}) {
  const packet = {
    packet_type: SOURCE_TRANSPORT_AUTHORITY_PACKET_TYPE,
    human_grant: {
      human: 'Vincent Nijjar',
      grant_timestamp: nowIso,
      action: 'GitHub App installation-token source movement preflight only'
    },
    source_target: {
      repo: 'ZLAR-AI/ZLAR',
      local_path: repoPath,
      branch,
      remote_ref: `refs/heads/${branch}`,
      expected_local_commit: head,
      expected_pre_push_remote_ref: remoteTrackingHead,
      expected_post_push_remote_ref: head
    },
    transport: {
      push_mode: 'non-force-fast-forward-only',
      credential_class: 'github-app-installation-token',
      token_repository_scope: ['ZLAR-AI/ZLAR'],
      token_permission_scope: {
        contents: 'write'
      },
      token_expires_at: tokenExpiresIso,
      token_revocation_required: true,
      token_seen_by_report: false
    },
    forbidden_side_effects: [...REQUIRED_FORBIDDEN_SIDE_EFFECTS],
    proposed_source_movement: {
      force: false,
      tags: false,
      releases: false,
      pull_requests: false,
      website_publication: false,
      actions: false,
      github_settings: false,
      hooks_config_install_paths: false,
      manifests: false,
      production_issuer_authority: false,
      secret_material: false,
      paths: ['lib/zlar-source-transport-preflight.mjs'],
      allowed_side_effects: []
    },
    website: {
      path: websitePath,
      expected_head: websiteHead,
      allowed_untracked: ['var/']
    }
  };
  return merge(packet, overrides);
}

function merge(base, overrides) {
  const next = structuredClone(base);
  for (const [key, value] of Object.entries(overrides)) {
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      next[key] &&
      typeof next[key] === 'object' &&
      !Array.isArray(next[key])
    ) {
      next[key] = merge(next[key], value);
    } else {
      next[key] = value;
    }
  }
  return next;
}

function factsOverrides(packet = packetFixture()) {
  return {
    repoFactsOverride: {
      real_path: packet.source_target.local_path,
      branch,
      head,
      clean: true,
      status_summary: `## ${branch}...${upstream}`,
      upstream,
      upstream_head: upstreamHead,
      remote_tracking_ref: remoteTrackingRef,
      remote_tracking_head: remoteTrackingHead
    },
    websiteFactsOverride: {
      real_path: packet.website.path,
      head: websiteHead,
      status_summary: '## main...origin/main\n?? var/',
      unchanged_except_known_var: true,
      unexpected_status_lines: []
    }
  };
}

function run(packet, options = {}) {
  return runSourceTransportPreflight(packet, {
    ...factsOverrides(packet),
    ...options
  });
}

section('positive dry-run');
const goodPacket = packetFixture();
const goodReport = run(goodPacket);
assertEqual('report type', SOURCE_TRANSPORT_PREFLIGHT_TYPE, goodReport.report_type);
assertEqual('preflight passed', 'passed', goodReport.preflight_status);
assertEqual('no refusal', null, goodReport.refusal_reason_code);
assertEqual('credential class', 'github-app-installation-token', goodReport.authority_packet.credential_class);
assertEqual('token expiry bound', tokenExpiresIso, goodReport.authority_packet.token_expires_at);
assertEqual('token revocation required', true, goodReport.authority_packet.token_revocation_required);
assertEqual('token seen false', false, goodReport.token_metadata.token_seen_by_report);
assertEqual('token metadata expiry bound', tokenExpiresIso, goodReport.token_metadata.token_expires_at);
assertEqual('token metadata revocation required', true, goodReport.token_metadata.token_revocation_required);
assertEqual('fake token metadata only', true, goodReport.token_metadata.fake_non_secret_metadata_only);
assertEqual('can move source false', false, goodReport.no_source_movement_boundary.can_move_source);
assertEqual('network calls false', false, goodReport.no_source_movement_boundary.network_calls);
assertEqual('github api false', false, goodReport.no_source_movement_boundary.github_api_used);
assertEqual('token minted false', false, goodReport.no_source_movement_boundary.token_minted);
assertEqual('git push available false', false, goodReport.no_source_movement_boundary.git_push_available);
assertEqual('local branch bound', branch, goodReport.local_facts.branch);
assertEqual('local head bound', head, goodReport.local_facts.head);
assertEqual('remote tracking head bound', remoteTrackingHead, goodReport.local_facts.remote_tracking_head);
assertEqual('website head bound', websiteHead, goodReport.website_facts.head);
assertEqual('website unchanged except var', true, goodReport.website_facts.unchanged_except_known_var);
for (const claim of FORBIDDEN_CLAIMS) {
  assert(`forbidden claim present: ${claim}`, goodReport.forbidden_claims.includes(claim));
}
assert('good report is safe', assertNoUnsafeSourceTransportPreflightText(JSON.stringify(goodReport)));

section('authority packet refusals');
assertEqual(
  'absent packet refuses',
  'authority_packet_absent',
  runSourceTransportPreflight(null).refusal_reason_code
);
const missingGrant = packetFixture();
delete missingGrant.human_grant;
assertEqual('missing human grant fails', 'authority_packet_invalid', run(missingGrant).refusal_reason_code);

const staleGrant = packetFixture({
  human_grant: {
    grant_timestamp: '2026-01-01T00:00:00Z'
  }
});
assertEqual('stale grant fails', 'authority_packet_invalid', run(staleGrant).refusal_reason_code);

const wrongCommit = packetFixture({
  source_target: {
    expected_local_commit: '1111111111111111111111111111111111111111'
  }
});
assertEqual('mismatched expected local commit fails', 'expected_local_commit_mismatch', run(wrongCommit).refusal_reason_code);

const forcePush = packetFixture({
  transport: {
    push_mode: 'force'
  }
});
assertEqual('force push mode fails', 'authority_packet_invalid', run(forcePush).refusal_reason_code);

const workflowPath = packetFixture({
  proposed_source_movement: {
    paths: ['.github/workflows/ci.yml']
  }
});
assertEqual('workflow file scope fails', 'authority_packet_invalid', run(workflowPath).refusal_reason_code);

const websiteScope = packetFixture({
  proposed_source_movement: {
    website_publication: true
  }
});
assertEqual('website/publication scope fails', 'authority_packet_invalid', run(websiteScope).refusal_reason_code);

const settingsScope = packetFixture({
  proposed_source_movement: {
    github_settings: true
  }
});
assertEqual('GitHub settings scope fails', 'authority_packet_invalid', run(settingsScope).refusal_reason_code);

const issuerScope = packetFixture({
  proposed_source_movement: {
    production_issuer_authority: true
  }
});
assertEqual('production issuer scope fails', 'authority_packet_invalid', run(issuerScope).refusal_reason_code);

const wrongCredential = packetFixture({
  transport: {
    credential_class: 'deploy-key'
  }
});
assertEqual('wrong credential class fails', 'authority_packet_invalid', run(wrongCredential).refusal_reason_code);

const missingTokenExpiry = packetFixture();
delete missingTokenExpiry.transport.token_expires_at;
assertEqual('missing credential expiry fails', 'authority_packet_invalid', run(missingTokenExpiry).refusal_reason_code);

const missingCredentialDeath = packetFixture();
delete missingCredentialDeath.transport.token_revocation_required;
assertEqual('missing credential-death field fails', 'authority_packet_invalid', run(missingCredentialDeath).refusal_reason_code);

const falseCredentialDeath = packetFixture({
  transport: {
    token_revocation_required: false,
    credential_death_evidence_required: false
  }
});
assertEqual('false credential-death fields fail', 'authority_packet_invalid', run(falseCredentialDeath).refusal_reason_code);

const extraPermission = packetFixture({
  transport: {
    token_permission_scope: {
      contents: 'write',
      administration: 'read'
    }
  }
});
assertEqual('extra token permission key fails', 'authority_packet_invalid', run(extraPermission).refusal_reason_code);

const unknownPermission = packetFixture({
  transport: {
    token_permission_scope: {
      contents: 'write',
      mystery_permission: 'read'
    }
  }
});
assertEqual('unknown token permission key fails', 'authority_packet_invalid', run(unknownPermission).refusal_reason_code);

const metadataPermission = packetFixture({
  transport: {
    token_permission_scope: {
      contents: 'write',
      metadata: 'read'
    }
  }
});
assertEqual('metadata read permission is explicitly allowed', 'passed', run(metadataPermission).preflight_status);

const badMetadataPermission = packetFixture({
  transport: {
    token_permission_scope: {
      contents: 'write',
      metadata: 'write'
    }
  }
});
assertEqual('metadata write permission fails', 'authority_packet_invalid', run(badMetadataPermission).refusal_reason_code);

const nullPreRef = packetFixture({
  source_target: {
    expected_pre_push_remote_ref: null
  }
});
assertEqual('null pre-push ref fails', 'authority_packet_invalid', run(nullPreRef).refusal_reason_code);

const absentPreRef = packetFixture({
  source_target: {
    expected_pre_push_remote_ref: 'absent'
  }
});
assertEqual('absent pre-push ref fails', 'authority_packet_invalid', run(absentPreRef).refusal_reason_code);

const missingPreRef = packetFixture();
delete missingPreRef.source_target.expected_pre_push_remote_ref;
assertEqual('missing pre-push ref fails', 'authority_packet_invalid', run(missingPreRef).refusal_reason_code);

section('secret-shaped input refusal');
const secretPacket = packetFixture({
  transport: {
    token_note: 'Authorization: Bearer ghs_abcdefghijklmnopqrstuvwxyz123456'
  }
});
const secretText = JSON.stringify(secretPacket, null, 2);
const secretReport = runSourceTransportPreflight(secretText, factsOverrides(secretPacket));
const secretOutput = JSON.stringify(secretReport, null, 2);
assertEqual('secret-shaped input refused', 'secret_material_detected', secretReport.refusal_reason_code);
assert('secret report does not echo token', !secretOutput.includes('ghs_abcdefghijklmnopqrstuvwxyz123456'));
assert('secret report does not echo authorization header', !secretOutput.toLowerCase().includes('authorization: bearer'));

section('report writing boundary');
assertThrows(
  'report output outside scratch fails',
  () => writeSourceTransportPreflightReport(goodReport, join(tmpdir(), 'zlar-source-transport-preflight-outside.json')),
  'proof-owned build scratch root'
);

section('no network or source movement implementation path');
const modulePath = fileURLToPath(new URL('../lib/zlar-source-transport-preflight.mjs', import.meta.url));
const cliPath = fileURLToPath(new URL('../bin/zlar-source-transport-preflight', import.meta.url));
const zlarPath = fileURLToPath(new URL('../bin/zlar', import.meta.url));
const source = readFileSync(modulePath, 'utf8');
assert('runtime command list is local-only', JSON.stringify(RUNTIME_LOCAL_COMMANDS) === JSON.stringify(['git rev-parse', 'git status', 'git show-ref']));
assert('module does not import http', !source.includes("node:http"));
assert('module does not import https', !source.includes("node:https"));
assert('module does not import net', !source.includes("node:net"));
assert('module does not call fetch', !/\bfetch\s*\(/.test(source));
assert('module does not call git push', !/['"]push['"]/.test(source));
assert('module does not call git fetch', !/['"]fetch['"]/.test(source));
assert('module does not call git ls-remote', !/ls-remote/.test(source));
assert('module does not call git remote mutation', !/remote\s+(?:set-url|add|remove)/.test(source));
assert('module does not reference credential helper', !/credential-helper|credential\s+fill|credential\s+approve/.test(source));

const directHelp = spawnSync(process.execPath, [cliPath, '--help'], { encoding: 'utf8' });
assertEqual('direct CLI help exits zero', 0, directHelp.status);
assert('direct CLI help says cannot push', directHelp.stdout.includes('push'));
assert('direct CLI help says cannot mint tokens', directHelp.stdout.includes('mint tokens'));

const secretArg = 'ghs_abcdefghijklmnopqrstuvwxyz123456';
const unsupportedSecretArg = spawnSync(process.execPath, [cliPath, '--bogus', secretArg], { encoding: 'utf8' });
assertEqual('secret-shaped unsupported argv exits nonzero', 1, unsupportedSecretArg.status);
assert('secret-shaped unsupported argv not echoed', !unsupportedSecretArg.stderr.includes(secretArg));
assert('secret-shaped unsupported argv generic error', unsupportedSecretArg.stderr.includes('unsafe argument rejected'));

const missingPath = join(tmpdir(), 'zlar-source-transport-preflight-missing-input.json');
const missingInput = spawnSync(process.execPath, [cliPath, '--input', missingPath, '--json'], { encoding: 'utf8' });
assertEqual('missing input path exits nonzero', 1, missingInput.status);
assert('missing input path not echoed', !missingInput.stderr.includes(missingPath));
assert('missing input path generic error', missingInput.stderr.includes('input file could not be read'));

const secretInputPath = join(tmpdir(), secretArg);
const secretInput = spawnSync(process.execPath, [cliPath, '--input', secretInputPath, '--json'], { encoding: 'utf8' });
assertEqual('secret-shaped input path exits nonzero', 1, secretInput.status);
assert('secret-shaped input path not echoed', !secretInput.stderr.includes(secretArg));

const zlarHelp = spawnSync(zlarPath, ['source-transport-preflight', '--help'], { encoding: 'utf8' });
assertEqual('zlar dispatch help exits zero', 0, zlarHelp.status);
assert('zlar dispatch help mentions source-transport', zlarHelp.stdout.includes('source-transport'));

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed, ${FAIL} failed`);
if (FAIL > 0) process.exit(1);
console.log('ALL PASS');
