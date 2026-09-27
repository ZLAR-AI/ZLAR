#!/usr/bin/env node
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  PRIVATE_VERIFIER_READINESS_PACKET_FILE,
  assertNoUnsafePrivateVerifierReadinessText,
  assertPrivateVerifierReadinessPacket,
  buildPrivateVerifierReadinessPacket,
  buildPrivateVerifierReadinessVerification,
  writePrivateVerifierReadinessPacket,
} from '../lib/private-verifier-readiness.mjs';
import {
  createPrivateVerifierReadinessEvidence,
} from './private-verifier-readiness-fixture.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;
const TEMP_DIRS = [];

process.on('exit', () => {
  for (const dir of TEMP_DIRS) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function ok(label, condition, detail = '') {
  TOTAL++;
  if (condition) {
    PASS++;
    console.log(`  PASS: ${label}`);
  } else {
    FAIL++;
    console.log(`  FAIL: ${label}${detail ? ` -- ${detail}` : ''}`);
  }
}

function equal(label, actual, expected) {
  ok(label, Object.is(actual, expected), `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

function throws(label, fn, expectedMessage) {
  TOTAL++;
  try {
    fn();
    FAIL++;
    console.log(`  FAIL: ${label} -- expected throw`);
  } catch (err) {
    if (!expectedMessage || String(err.message).includes(expectedMessage)) {
      PASS++;
      console.log(`  PASS: ${label}`);
    } else {
      FAIL++;
      console.log(`  FAIL: ${label} -- ${err.message}`);
    }
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const COMMIT = '6d484a147fb3c52da0b48add380bc1200332953e';
const EVIDENCE_SOURCE_COMMIT = 'f6e54059193254eeb310936a6bba925f541c8f29';
const BRANCH = 'local-governed-destination-boarding-proof';

console.log('\n-- private verifier readiness packet --');
const { scratch, evidenceDir } = createPrivateVerifierReadinessEvidence();
TEMP_DIRS.push(scratch);
const packet = buildPrivateVerifierReadinessPacket({
  evidenceDir,
  commit: COMMIT,
  evidenceSourceCommit: EVIDENCE_SOURCE_COMMIT,
  branch: BRANCH,
  generatedAt: '2026-07-09T12:00:00.000Z',
});

ok('packet asserts', assertPrivateVerifierReadinessPacket(packet));
equal('packet type', packet.report_type, 'zlar-private-verifier-readiness-packet-v1');
equal('packet commit', packet.target.commit_sha, COMMIT);
equal('packet evidence source commit', packet.evidence.source_commit_sha, EVIDENCE_SOURCE_COMMIT);
equal('packet moving target false', packet.target.moving_target_used, false);
equal('packet is private readiness', packet.claim_ceiling.private_verifier_readiness, true);
equal('packet is not public attestation', packet.claim_ceiling.public_external_attestation, false);
equal('packet is not production authority', packet.claim_ceiling.production_authority, false);
equal('packet is not enterprise readiness', packet.claim_ceiling.enterprise_readiness, false);
equal('lifecycle non-scoring readiness', packet.evidence.readiness.lifecycle_non_scoring, true);
equal('lifecycle current installation false', packet.evidence.readiness.lifecycle_current_installation, false);
ok('packet has artifact set hash', /^[a-f0-9]{64}$/.test(packet.evidence.artifact_set_sha256));
ok('packet contains current lifecycle artifact hash', packet.evidence.artifact_hashes.some((entry) => entry.path === 'zlar-active-persistent-profile-lifecycle-v1.json'));
ok('packet text is safe', assertNoUnsafePrivateVerifierReadinessText(JSON.stringify(packet)) === undefined);

const verification = buildPrivateVerifierReadinessVerification(packet, {
  evidenceDir,
  requiredCommit: COMMIT,
  requiredEvidenceSourceCommit: EVIDENCE_SOURCE_COMMIT,
  requireArtifactSetSha: packet.evidence.artifact_set_sha256,
  requireRecomputedEvidence: true,
});
equal('verification true', verification.verified, true);
equal('verification recomputes evidence', verification.recomputed_evidence.matches_packet, true);
equal('verification preserves no public attestation', verification.claim_boundary_preserved.public_external_attestation, false);

const outDir = join(scratch, 'packet-out');
const writeResult = writePrivateVerifierReadinessPacket({
  packet,
  outputDir: outDir,
});
equal('write result packet file', writeResult.packet_file, PRIVATE_VERIFIER_READINESS_PACKET_FILE);
ok('write result packet sha', /^[a-f0-9]{64}$/.test(writeResult.packet_sha256));

console.log('\n-- private verifier readiness refusals --');
const publicClaim = clone(packet);
publicClaim.claim_ceiling.public_external_attestation = true;
throws('public attestation claim refused', () => assertPrivateVerifierReadinessPacket(publicClaim), 'public_external_attestation');

const movingTarget = clone(packet);
movingTarget.verifier_instructions.command_templates[0] = 'git checkout main';
throws('moving checkout command refused', () => assertPrivateVerifierReadinessPacket(movingTarget), 'moving git checkout');

const wrongPinnedCheckout = clone(packet);
wrongPinnedCheckout.verifier_instructions.command_templates[0] = `git checkout ${'b'.repeat(40)}`;
throws('wrong pinned checkout refused', () => assertPrivateVerifierReadinessPacket(wrongPinnedCheckout), 'checkout commit mismatch');

const wrongRequiredCommitTemplate = clone(packet);
wrongRequiredCommitTemplate.verifier_instructions.command_templates[3] =
  wrongRequiredCommitTemplate.verifier_instructions.command_templates[3].replace(COMMIT, 'c'.repeat(40));
throws('wrong required commit template refused', () => assertPrivateVerifierReadinessPacket(wrongRequiredCommitTemplate), 'required commit mismatch');

const wrongRequiredEvidenceSourceTemplate = clone(packet);
wrongRequiredEvidenceSourceTemplate.verifier_instructions.command_templates[3] =
  wrongRequiredEvidenceSourceTemplate.verifier_instructions.command_templates[3].replace(EVIDENCE_SOURCE_COMMIT, 'd'.repeat(40));
throws('wrong required evidence source template refused', () => assertPrivateVerifierReadinessPacket(wrongRequiredEvidenceSourceTemplate), 'required evidence source commit mismatch');

const missingEvidenceSource = clone(packet);
delete missingEvidenceSource.evidence.source_commit_sha;
throws('missing evidence source commit refused', () => assertPrivateVerifierReadinessPacket(missingEvidenceSource), 'unexpected fields');

const unsafePath = clone(packet);
unsafePath.side_doors.push('/Users/example/private.txt');
throws('private path refused', () => assertPrivateVerifierReadinessPacket(unsafePath), 'private operator path');

throws('wrong commit refused', () => buildPrivateVerifierReadinessVerification(packet, {
  requiredCommit: 'a'.repeat(40),
}), 'required commit mismatch');

throws('wrong evidence source commit refused', () => buildPrivateVerifierReadinessVerification(packet, {
  requiredEvidenceSourceCommit: 'a'.repeat(40),
}), 'required evidence source commit mismatch');

writeFileSync(join(evidenceDir, 'green-records-write-target.jsonl'), 'tampered\n');
throws('tampered evidence refused', () => buildPrivateVerifierReadinessVerification(packet, {
  evidenceDir,
  requireRecomputedEvidence: true,
}), 'recomputed artifact set SHA mismatch');

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
