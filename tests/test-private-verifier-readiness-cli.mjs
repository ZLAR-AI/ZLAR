#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PRIVATE_VERIFIER_READINESS_PACKET_FILE,
} from '../lib/private-verifier-readiness.mjs';
import {
  createPrivateVerifierReadinessEvidence,
} from './private-verifier-readiness-fixture.mjs';

let PASS = 0;
let FAIL = 0;
let TOTAL = 0;
const TEMP_DIRS = [];
const PROJECT_DIR = fileURLToPath(new URL('..', import.meta.url));

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

function run(args) {
  return spawnSync('node', ['bin/zlar-private-verifier-readiness', ...args], {
    cwd: PROJECT_DIR,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

const COMMIT = '6d484a147fb3c52da0b48add380bc1200332953e';
const EVIDENCE_SOURCE_COMMIT = 'f6e54059193254eeb310936a6bba925f541c8f29';
const BRANCH = 'local-governed-destination-boarding-proof';
const { scratch, evidenceDir } = createPrivateVerifierReadinessEvidence();
TEMP_DIRS.push(scratch);
const outDir = join(scratch, 'packet');

console.log('\n-- private verifier readiness CLI build --');
const build = run([
  'build',
  '--evidence-dir',
  evidenceDir,
  '--commit',
  COMMIT,
  '--evidence-source-commit',
  EVIDENCE_SOURCE_COMMIT,
  '--branch',
  BRANCH,
  '--output-dir',
  outDir,
  '--json',
]);
equal('build exits 0', build.status, 0);
equal('build stderr empty', build.stderr, '');
const buildJson = JSON.parse(build.stdout);
equal('build packet commit', buildJson.packet.target.commit_sha, COMMIT);
equal('build packet evidence source commit', buildJson.packet.evidence.source_commit_sha, EVIDENCE_SOURCE_COMMIT);
equal('build public attestation false', buildJson.packet.claim_ceiling.public_external_attestation, false);
equal('build production authority false', buildJson.packet.claim_ceiling.production_authority, false);
ok('packet file written', existsSync(join(outDir, PRIVATE_VERIFIER_READINESS_PACKET_FILE)));
ok('readme written', existsSync(join(outDir, 'PRIVATE-VERIFIER-README.md')));
ok('sha256sums written', existsSync(join(outDir, 'SHA256SUMS')));

console.log('\n-- private verifier readiness CLI verify --');
const packetPath = join(outDir, PRIVATE_VERIFIER_READINESS_PACKET_FILE);
const verify = run([
  'verify',
  '--input',
  packetPath,
  '--evidence-dir',
  evidenceDir,
  '--require-commit',
  COMMIT,
  '--require-evidence-source-commit',
  EVIDENCE_SOURCE_COMMIT,
  '--require-artifact-set-sha',
  buildJson.packet.evidence.artifact_set_sha256,
  '--require-recomputed-evidence',
  '--json',
]);
equal('verify exits 0', verify.status, 0);
equal('verify stderr empty', verify.stderr, '');
const verifyJson = JSON.parse(verify.stdout);
equal('verify true', verifyJson.verified, true);
equal('verify recomputed evidence true', verifyJson.recomputed_evidence.matches_packet, true);
equal('verify no external attestation', verifyJson.claim_boundary_preserved.public_external_attestation, false);

console.log('\n-- private verifier readiness CLI refusals --');
const wrongCommit = run([
  'verify',
  '--input',
  packetPath,
  '--require-commit',
  'a'.repeat(40),
]);
ok('wrong commit exits nonzero', wrongCommit.status !== 0);
ok('wrong commit mentions mismatch safely', /required commit mismatch/.test(wrongCommit.stderr));

const wrongEvidenceSourceCommit = run([
  'verify',
  '--input',
  packetPath,
  '--require-evidence-source-commit',
  'a'.repeat(40),
]);
ok('wrong evidence source commit exits nonzero', wrongEvidenceSourceCommit.status !== 0);
ok('wrong evidence source commit mentions mismatch safely', /required evidence source commit mismatch/.test(wrongEvidenceSourceCommit.stderr));

const missingEvidenceSourceBuild = run([
  'build',
  '--evidence-dir',
  evidenceDir,
  '--commit',
  COMMIT,
  '--branch',
  BRANCH,
  '--output-dir',
  join(scratch, 'missing-source-commit'),
]);
ok('missing evidence source commit build exits nonzero', missingEvidenceSourceBuild.status !== 0);
ok('missing evidence source commit build names required option', /--evidence-source-commit/.test(missingEvidenceSourceBuild.stderr));

writeFileSync(join(evidenceDir, 'green-records-write-target.jsonl'), 'tampered\n');
const tampered = run([
  'verify',
  '--input',
  packetPath,
  '--evidence-dir',
  evidenceDir,
  '--require-recomputed-evidence',
]);
ok('tampered evidence exits nonzero', tampered.status !== 0);
ok('tampered evidence mentions recomputed mismatch', /recomputed artifact set SHA mismatch/.test(tampered.stderr));

const readmeText = readFileSync(join(outDir, 'PRIVATE-VERIFIER-README.md'), 'utf8');
ok('readme stays no-send', /not external contact/.test(readmeText) || /not a verifier request/.test(readmeText));

console.log(`\nResults: ${PASS}/${TOTAL} passed`);
if (FAIL > 0) {
  process.exit(1);
}
