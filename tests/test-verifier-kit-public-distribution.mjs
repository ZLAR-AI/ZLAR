#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  assertNoUnsafeVerifierKitPublicDistributionText,
  assertVerifierKitPublicDistributionReport,
  buildVerifierKitPublicDistributionReport,
  formatVerifierKitPublicDistributionSummary,
} from '../lib/verifier-kit-public-distribution.mjs';
import {
  assertVerifierKitReleaseAssetsLiveReadReport,
  buildVerifierKitReleaseAssetsLiveReadReport,
} from '../lib/verifier-kit-release-assets-live-read.mjs';

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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

function write(path, text) {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, text);
}

function runZlar(args) {
  return spawnSync(join(process.cwd(), 'bin', 'zlar'), args, {
    cwd: process.cwd(),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

console.log('\n-- verifier-kit public distribution posture --');

const root = mkdtempSync(join(tmpdir(), 'zlar-verifier-kit-public-distribution-test-'));
try {
  const assetDir = join(root, 'assets-root');
  const fixtureDir = join(root, 'fixtures');
  mkdirSync(assetDir, { recursive: true });
  mkdirSync(fixtureDir, { recursive: true });

  const fileBodies = new Map([
    ['dist/zlar-verifier-kit-v0.1.0.tar.gz', 'kit tarball bytes\n'],
    ['dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256', `${sha256('kit tarball bytes\n')}  zlar-verifier-kit-v0.1.0.tar.gz\n`],
    ['dist/zlar-verifier-kit-v0.1.0/MANIFEST.json', '{"files":[]}\n'],
    ['dist/zlar-verifier-kit-v0.1.0/MANIFEST.sig', 'manifest signature bytes\n'],
  ]);
  for (const [path, body] of fileBodies.entries()) {
    write(join(assetDir, path), body);
  }

  const repro = {
    report_type: 'zlar-verifier-kit-reproducibility-v1',
    schema_version: 1,
    result: 'PASS',
    kit_version: 'v0.1.0',
    evidence_model: 'local-source-build-same-test-publisher-key-twice',
    publisher_key_model: 'temporary test Ed25519 key generated for this check; private key removed on exit',
    publisher_kid: 'fixture-kid',
    reproducible: {
      tarball_sha256_identical: true,
      manifest_and_signature_sha256_identical: true,
      sidecar_matches_tarball: true,
    },
    public_artifact_hashes: [...fileBodies.entries()].map(([path, body]) => ({
      path,
      sha256: sha256(body),
    })),
    claim_boundary: {
      external_attestation: false,
      production_publisher_key_custody: false,
      production_signing_identity: false,
      public_release_publication: false,
      live_trust_registry_state: false,
      revocation_truth: false,
      enterprise_readiness: false,
      v3_4_0_readiness: false,
    },
  };
  const reproBytes = `${JSON.stringify(repro, null, 2)}\n`;
  const reproSha256 = sha256(reproBytes);
  const reproPath = join(fixtureDir, 'repro.json');
  writeFileSync(reproPath, reproBytes);

  const noAssets = {
    tagName: 'v3.3.109',
    url: 'https://github.com/ZLAR-AI/ZLAR/releases/tag/v3.3.109',
    evidence_model: 'github-release-assets-json',
    assets: [],
  };
  const noAssetsPath = join(fixtureDir, 'no-assets.json');
  writeFileSync(noAssetsPath, `${JSON.stringify(noAssets, null, 2)}\n`);

  const noAssetsReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: noAssets,
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assert('no-assets report validates', assertVerifierKitPublicDistributionReport(noAssetsReport));
  assertEqual('no-assets posture', 'public_release_assets_absent', noAssetsReport.posture);
  assertEqual('no-assets not ready', false, noAssetsReport.ready_for_public_distribution_claim);
  assert('no-assets blockers named', noAssetsReport.blocking_reasons.some((reason) => reason.includes('missing public release assets')));
  assertEqual('no-assets local hashes match', true, noAssetsReport.local_artifact_hashes.all_checked_hashes_match);
  assert('no-assets summary privacy safe', assertNoUnsafeVerifierKitPublicDistributionText(formatVerifierKitPublicDistributionSummary(noAssetsReport)));

  const presentAssets = {
    tagName: 'v3.3.109',
    url: 'https://github.com/ZLAR-AI/ZLAR/releases/tag/v3.3.109',
    evidence_model: 'github-release-assets-json',
    isDraft: false,
    assets: [
      { name: 'zlar-verifier-kit-v0.1.0.tar.gz', size: 10, state: 'uploaded' },
      { name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256', size: 11, state: 'uploaded' },
      { name: 'zlar-verifier-kit-reproducibility-v1.json', size: 12, state: 'uploaded' },
    ],
  };
  const presentAssetsPath = join(fixtureDir, 'present-assets.json');
  writeFileSync(presentAssetsPath, `${JSON.stringify(presentAssets, null, 2)}\n`);
  const presentBoundaryFalseReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: presentAssets,
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual(
    'present assets but boundary false posture',
    'release_assets_present_but_publication_boundary_not_upgraded',
    presentBoundaryFalseReport.posture
  );
  assertEqual('present assets but boundary false not ready', false, presentBoundaryFalseReport.ready_for_public_distribution_claim);

  const livePresentAssets = {
    ...presentAssets,
    evidence_model: 'github-release-assets-json-live-read',
    repository: 'ZLAR-AI/ZLAR',
    assets: [
      {
        name: 'zlar-verifier-kit-v0.1.0.tar.gz',
        size: 10,
        state: 'uploaded',
        browser_download_url: 'https://github.com/ZLAR-AI/ZLAR/releases/download/v3.3.109/zlar-verifier-kit-v0.1.0.tar.gz',
        api_url: 'https://api.github.com/repos/ZLAR-AI/ZLAR/releases/assets/1',
        digest: `sha256:${sha256(fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz'))}`,
      },
      {
        name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256',
        size: 11,
        state: 'uploaded',
        browser_download_url: 'https://github.com/ZLAR-AI/ZLAR/releases/download/v3.3.109/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
        api_url: 'https://api.github.com/repos/ZLAR-AI/ZLAR/releases/assets/2',
        digest: `sha256:${sha256(fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256'))}`,
      },
      {
        name: 'zlar-verifier-kit-reproducibility-v1.json',
        size: reproBytes.length,
        state: 'uploaded',
        browser_download_url: 'https://github.com/ZLAR-AI/ZLAR/releases/download/v3.3.109/zlar-verifier-kit-reproducibility-v1.json',
        api_url: 'https://api.github.com/repos/ZLAR-AI/ZLAR/releases/assets/3',
        digest: `sha256:${reproSha256}`,
      },
    ],
  };
  const livePresentAssetsPath = join(fixtureDir, 'live-present-assets.json');
  writeFileSync(livePresentAssetsPath, `${JSON.stringify(livePresentAssets, null, 2)}\n`);
  const readyReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: livePresentAssets,
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('ready posture', 'public_distribution_posture_ready', readyReport.posture);
  assertEqual('ready claim true', true, readyReport.ready_for_public_distribution_claim);
  assertEqual('ready publication evidence supported', true, readyReport.release_assets.public_release_publication_evidence.supported);
  assertEqual('ready repository matches expected', true, readyReport.release_assets.public_release_publication_evidence.repository_matches_expected);
  assertEqual('ready release URL names expected repository', true, readyReport.release_assets.public_release_publication_evidence.release_url_names_expected_repository);
  assertEqual('ready asset URLs name expected repository', true, readyReport.release_assets.public_release_publication_evidence.asset_urls_name_expected_repository);
  assertEqual('ready public asset byte binding true', true, readyReport.release_assets.release_asset_hashes.all_required_assets_bound);
  assertEqual('ready keeps reproducibility publication boundary false', false, readyReport.reproducibility.public_release_publication_boundary);
  assert('ready report validates', assertVerifierKitPublicDistributionReport(readyReport));

  const staticPublicAssets = {
    tagName: 'v3.4.59',
    url: 'https://zlar.ai/verifier-kit/v3.4.59/',
    evidence_model: 'static-public-artifact-source-live-read',
    public_artifact_source: 'zlar.ai',
    anonymous_access_verified: true,
    assets: [
      {
        name: 'zlar-verifier-kit-v0.1.0.tar.gz',
        size: 10,
        state: 'uploaded',
        browser_download_url: 'https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-v0.1.0.tar.gz',
        digest: `sha256:${sha256(fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz'))}`,
      },
      {
        name: 'zlar-verifier-kit-v0.1.0.tar.gz.sha256',
        size: 11,
        state: 'uploaded',
        browser_download_url: 'https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
        digest: `sha256:${sha256(fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256'))}`,
      },
      {
        name: 'zlar-verifier-kit-reproducibility-v1.json',
        size: reproBytes.length,
        state: 'uploaded',
        browser_download_url: 'https://zlar.ai/verifier-kit/v3.4.59/zlar-verifier-kit-reproducibility-v1.json',
        digest: `sha256:${reproSha256}`,
      },
    ],
  };
  const staticPublicAssetsPath = join(fixtureDir, 'static-public-assets.json');
  writeFileSync(staticPublicAssetsPath, `${JSON.stringify(staticPublicAssets, null, 2)}\n`);
  const staticPublicReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.4.59',
    releaseAssetsJson: staticPublicAssets,
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('static public posture ready', 'public_distribution_posture_ready', staticPublicReport.posture);
  assertEqual('static public ready claim true', true, staticPublicReport.ready_for_public_distribution_claim);
  assertEqual('static public source type', 'static-public-artifact-source', staticPublicReport.release_assets.public_release_publication_evidence.source_type);
  assertEqual('static public source is zlar.ai', 'zlar.ai', staticPublicReport.release_assets.public_release_publication_evidence.public_artifact_source);
  assertEqual('static public source binding true', true, staticPublicReport.release_assets.public_release_publication_evidence.public_artifact_source_matches_expected);
  assertEqual('static public asset URL binding true', true, staticPublicReport.release_assets.public_release_publication_evidence.asset_urls_name_public_source);
  assertEqual('static public anonymous access true', true, staticPublicReport.release_assets.public_release_publication_evidence.anonymous_access_verified);
  assert('static public report validates', assertVerifierKitPublicDistributionReport(staticPublicReport));

  const wrongStaticSourceReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.4.59',
    releaseAssetsJson: {
      ...staticPublicAssets,
      url: 'https://example.com/verifier-kit/v3.4.59/',
      public_artifact_source: 'example.com',
      assets: staticPublicAssets.assets.map((asset) => ({
        ...asset,
        browser_download_url: asset.browser_download_url.replace('https://zlar.ai/', 'https://example.com/'),
      })),
    },
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('wrong static source not ready', false, wrongStaticSourceReport.ready_for_public_distribution_claim);
  assertEqual('wrong static source posture not upgraded', 'release_assets_present_but_publication_boundary_not_upgraded', wrongStaticSourceReport.posture);
  assert('wrong static source blocker named', wrongStaticSourceReport.blocking_reasons.some((reason) => reason.includes('static public artifact source zlar.ai')));

  const missingAnonymousAccessReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.4.59',
    releaseAssetsJson: {
      ...staticPublicAssets,
      anonymous_access_verified: false,
    },
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('missing anonymous access not ready', false, missingAnonymousAccessReport.ready_for_public_distribution_claim);
  assert('missing anonymous access blocker named', missingAnonymousAccessReport.blocking_reasons.some((reason) => reason.includes('anonymous public asset access verification')));

  const extraPublicDistributionClaimBoundary = clone(readyReport);
  extraPublicDistributionClaimBoundary.claim_boundary.public_distribution_claim_summary = false;
  assertThrows(
    'public distribution extra claim-boundary field fails',
    () => assertVerifierKitPublicDistributionReport(extraPublicDistributionClaimBoundary),
    'verifier-kit public distribution claim boundary contains unexpected fields',
  );

  const missingPublicDistributionClaimBoundary = clone(readyReport);
  delete missingPublicDistributionClaimBoundary.claim_boundary.creates_public_external_attestation;
  assertThrows(
    'public distribution missing claim-boundary field fails',
    () => assertVerifierKitPublicDistributionReport(missingPublicDistributionClaimBoundary),
    'verifier-kit public distribution claim boundary contains unexpected fields',
  );

  const renamedPublicDistributionClaimBoundary = clone(readyReport);
  renamedPublicDistributionClaimBoundary.claim_boundary.external_attestation =
    renamedPublicDistributionClaimBoundary.claim_boundary.creates_public_external_attestation;
  delete renamedPublicDistributionClaimBoundary.claim_boundary.creates_public_external_attestation;
  assertThrows(
    'public distribution renamed claim-boundary field fails',
    () => assertVerifierKitPublicDistributionReport(renamedPublicDistributionClaimBoundary),
    'verifier-kit public distribution claim boundary contains unexpected fields',
  );

  const summaryShapedPublicDistributionClaimBoundary = clone(readyReport);
  summaryShapedPublicDistributionClaimBoundary.claim_boundary.claim_boundary_summary = {
    all_public_claims_false: true,
    creates_public_external_attestation: false,
  };
  assertThrows(
    'public distribution summary-shaped claim-boundary field fails',
    () => assertVerifierKitPublicDistributionReport(summaryShapedPublicDistributionClaimBoundary),
    'verifier-kit public distribution claim boundary contains unexpected fields',
  );

  const wrongRepoAssets = {
    ...livePresentAssets,
    repository: 'not-zlar/not-zlar',
    url: 'https://github.com/not-zlar/not-zlar/releases/tag/v3.3.109',
    assets: livePresentAssets.assets.map((asset, index) => ({
      ...asset,
      browser_download_url: `https://github.com/not-zlar/not-zlar/releases/download/v3.3.109/${asset.name}`,
      api_url: `https://api.github.com/repos/not-zlar/not-zlar/releases/assets/${index + 1}`,
    })),
  };
  const wrongRepoReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: wrongRepoAssets,
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('wrong repo not ready', false, wrongRepoReport.ready_for_public_distribution_claim);
  assertEqual('wrong repo posture not upgraded', 'release_assets_present_but_publication_boundary_not_upgraded', wrongRepoReport.posture);
  assertEqual('wrong repo expected binding false', false, wrongRepoReport.release_assets.public_release_publication_evidence.repository_matches_expected);
  assert('wrong repo blocker named', wrongRepoReport.blocking_reasons.some((reason) => reason.includes('release repository ZLAR-AI/ZLAR')));

  const liveReadReport = buildVerifierKitReleaseAssetsLiveReadReport({
    releaseTag: 'v3.3.109',
    repository: 'ZLAR-AI/ZLAR',
    releaseJson: livePresentAssets,
    downloadedHashesByName: {
      'zlar-verifier-kit-v0.1.0.tar.gz': {
        sha256: sha256(fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz')),
        size: fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz').length,
      },
      'zlar-verifier-kit-v0.1.0.tar.gz.sha256': {
        sha256: sha256(fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256')),
        size: fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256').length,
      },
      'zlar-verifier-kit-reproducibility-v1.json': {
        sha256: reproSha256,
        size: reproBytes.length,
      },
    },
    generatedAt: '2026-06-23T00:00:00Z',
  });
  assert('live-read report validates', assertVerifierKitReleaseAssetsLiveReadReport(liveReadReport));
  assertEqual('live-read required assets present', true, liveReadReport.all_required_assets_present);
  assertEqual('live-read required assets downloaded', true, liveReadReport.all_required_assets_downloaded);

  const extraLiveReadClaimBoundary = clone(liveReadReport);
  extraLiveReadClaimBoundary.claim_boundary.release_asset_claim_summary = false;
  assertThrows(
    'live-read extra claim-boundary field fails',
    () => assertVerifierKitReleaseAssetsLiveReadReport(extraLiveReadClaimBoundary),
    'release assets live-read claim boundary contains unexpected fields',
  );

  const missingLiveReadClaimBoundary = clone(liveReadReport);
  delete missingLiveReadClaimBoundary.claim_boundary.creates_public_external_attestation;
  assertThrows(
    'live-read missing claim-boundary field fails',
    () => assertVerifierKitReleaseAssetsLiveReadReport(missingLiveReadClaimBoundary),
    'release assets live-read claim boundary contains unexpected fields',
  );

  const renamedLiveReadClaimBoundary = clone(liveReadReport);
  renamedLiveReadClaimBoundary.claim_boundary.external_attestation =
    renamedLiveReadClaimBoundary.claim_boundary.creates_public_external_attestation;
  delete renamedLiveReadClaimBoundary.claim_boundary.creates_public_external_attestation;
  assertThrows(
    'live-read renamed claim-boundary field fails',
    () => assertVerifierKitReleaseAssetsLiveReadReport(renamedLiveReadClaimBoundary),
    'release assets live-read claim boundary contains unexpected fields',
  );

  const summaryShapedLiveReadClaimBoundary = clone(liveReadReport);
  summaryShapedLiveReadClaimBoundary.claim_boundary.claim_boundary_summary = {
    all_public_claims_false: true,
    creates_public_external_attestation: false,
  };
  assertThrows(
    'live-read summary-shaped claim-boundary field fails',
    () => assertVerifierKitReleaseAssetsLiveReadReport(summaryShapedLiveReadClaimBoundary),
    'release assets live-read claim boundary contains unexpected fields',
  );
  const readyFromLiveRead = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: liveReadReport,
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('live-read feeds public distribution ready posture', 'public_distribution_posture_ready', readyFromLiveRead.posture);
  assertEqual('live-read feeds public distribution ready claim', true, readyFromLiveRead.ready_for_public_distribution_claim);

  const missingDigestReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: {
      ...livePresentAssets,
      assets: livePresentAssets.assets.map(({ digest, ...asset }) => asset),
    },
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('missing digest posture', 'release_assets_present_but_release_hashes_not_verified', missingDigestReport.posture);
  assertEqual('missing digest not ready', false, missingDigestReport.ready_for_public_distribution_claim);
  assert('missing digest blocker named', missingDigestReport.blocking_reasons.some((reason) => reason.includes('SHA-256 evidence is missing')));

  const badDigestAssets = {
    ...livePresentAssets,
    assets: livePresentAssets.assets.map((asset) => (
      asset.name === 'zlar-verifier-kit-v0.1.0.tar.gz'
        ? { ...asset, digest: `sha256:${'0'.repeat(64)}` }
        : asset
    )),
  };
  const badDigestReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: badDigestAssets,
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('bad digest posture', 'release_assets_present_but_release_hashes_not_verified', badDigestReport.posture);
  assertEqual('bad digest not ready', false, badDigestReport.ready_for_public_distribution_claim);
  assert('bad digest blocker named', badDigestReport.blocking_reasons.some((reason) => reason.includes('does not match reproducibility evidence')));

  const unknownDraftReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: Object.fromEntries(
      Object.entries(livePresentAssets).filter(([key]) => key !== 'isDraft')
    ),
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('unknown draft state not ready', false, unknownDraftReport.ready_for_public_distribution_claim);
  assert('unknown draft blocker named', unknownDraftReport.blocking_reasons.some((reason) => reason.includes('explicit non-draft public release')));

  const badMetadataReport = buildVerifierKitPublicDistributionReport({
    releaseTag: 'v3.3.109',
    releaseAssetsJson: {
      ...livePresentAssets,
      assets: livePresentAssets.assets.map((asset) => (
        asset.name === 'zlar-verifier-kit-v0.1.0.tar.gz.sha256'
          ? { ...asset, size: 0, state: 'unknown' }
          : asset
      )),
    },
    reproducibility: repro,
    reproducibilitySha256: reproSha256,
    assetDir,
  });
  assertEqual('bad metadata posture', 'release_assets_present_but_metadata_incomplete', badMetadataReport.posture);
  assertEqual('bad metadata not ready', false, badMetadataReport.ready_for_public_distribution_claim);
  assert('bad metadata blocker named', badMetadataReport.blocking_reasons.some((reason) => reason.includes('not all uploaded with positive sizes')));

  const jsonRun = runZlar([
    'verifier-kit-public-distribution',
    '--release-tag', 'v3.3.109',
    '--release-assets-json', noAssetsPath,
    '--reproducibility', reproPath,
    '--asset-dir', assetDir,
    '--json',
  ]);
  assertEqual('json cli exits zero', 0, jsonRun.status);
  assertEqual('json cli emits no stderr', '', jsonRun.stderr);
  const jsonReport = JSON.parse(jsonRun.stdout);
  assertEqual('json cli report type', 'zlar-verifier-kit-public-distribution-v1', jsonReport.report_type);
  assertEqual('json cli not ready', false, jsonReport.ready_for_public_distribution_claim);

  const requirePublicFail = runZlar([
    'verifier-kit-public-distribution',
    '--release-tag', 'v3.3.109',
    '--release-assets-json', noAssetsPath,
    '--reproducibility', reproPath,
    '--asset-dir', assetDir,
    '--require-public',
  ]);
  assertEqual('require-public fails when not ready', 1, requirePublicFail.status);

  const requirePublicPass = runZlar([
    'verifier-kit-public-distribution',
    '--release-tag', 'v3.3.109',
    '--release-assets-json', livePresentAssetsPath,
    '--reproducibility', reproPath,
    '--asset-dir', assetDir,
    '--require-public',
  ]);
  assertEqual('require-public passes when ready', 0, requirePublicPass.status);

  const requireStaticPublicPass = runZlar([
    'verifier-kit-public-distribution',
    '--release-tag', 'v3.4.59',
    '--release-assets-json', staticPublicAssetsPath,
    '--reproducibility', reproPath,
    '--asset-dir', assetDir,
    '--require-public',
  ]);
  assertEqual('require-public passes for static public source', 0, requireStaticPublicPass.status);

  const liveReadDownloadDir = join(root, 'live-read-downloads');
  mkdirSync(liveReadDownloadDir, { recursive: true });
  write(join(liveReadDownloadDir, 'zlar-verifier-kit-v0.1.0.tar.gz'), fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz'));
  write(join(liveReadDownloadDir, 'zlar-verifier-kit-v0.1.0.tar.gz.sha256'), fileBodies.get('dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256'));
  write(join(liveReadDownloadDir, 'zlar-verifier-kit-reproducibility-v1.json'), reproBytes);
  const liveReadCliRun = runZlar([
    'verifier-kit-release-assets-live-read',
    '--release-tag', 'v3.3.109',
    '--release-json', livePresentAssetsPath,
    '--download-dir', liveReadDownloadDir,
    '--json',
  ]);
  assertEqual('live-read cli exits zero', 0, liveReadCliRun.status);
  assertEqual('live-read cli emits no stderr', '', liveReadCliRun.stderr);
  const liveReadCliReport = JSON.parse(liveReadCliRun.stdout);
  assertEqual('live-read cli report type', 'zlar-verifier-kit-release-assets-live-v1', liveReadCliReport.report_type);
  assertEqual('live-read cli records downloaded required assets', true, liveReadCliReport.all_required_assets_downloaded);

  const jsonOut = join(fixtureDir, 'report.json');
  const jsonOutRun = runZlar([
    'verifier-kit-public-distribution',
    '--release-tag', 'v3.3.109',
    '--release-assets-json', noAssetsPath,
    '--reproducibility', reproPath,
    '--asset-dir', assetDir,
    '--json-out', jsonOut,
  ]);
  assertEqual('json-out exits zero', 0, jsonOutRun.status);
  assertEqual('json-out emits no stdout', '', jsonOutRun.stdout);
  assertEqual('json-out report type', 'zlar-verifier-kit-public-distribution-v1', JSON.parse(readFileSync(jsonOut, 'utf8')).report_type);
  const overwriteRun = runZlar([
    'verifier-kit-public-distribution',
    '--release-tag', 'v3.3.109',
    '--release-assets-json', noAssetsPath,
    '--reproducibility', reproPath,
    '--asset-dir', assetDir,
    '--json-out', jsonOut,
  ]);
  assertEqual('json-out refuses overwrite', 2, overwriteRun.status);
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log();
console.log(`Results: ${PASS}/${TOTAL} passed${FAIL ? ` (${FAIL} FAILED)` : ' ✓'}`);
if (FAIL > 0) process.exit(1);
