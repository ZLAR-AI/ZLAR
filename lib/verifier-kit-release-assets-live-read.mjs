export const VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_TYPE =
  'zlar-verifier-kit-release-assets-live-v1';

export const VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_EVIDENCE_MODEL =
  'github-release-assets-json-live-read';

export const VERIFIER_KIT_RELEASE_ASSETS_FIXTURE_READ_EVIDENCE_MODEL =
  'github-release-assets-json-fixture-read';

export const REQUIRED_VERIFIER_KIT_RELEASE_ASSET_NAMES = Object.freeze([
  'zlar-verifier-kit-v0.1.0.tar.gz',
  'zlar-verifier-kit-v0.1.0.tar.gz.sha256',
  'zlar-verifier-kit-reproducibility-v1.json',
]);

export const VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_NON_CLAIMS = Object.freeze([
  'This report only reads release metadata and release asset bytes.',
  'This report does not upload release assets or mutate GitHub release state.',
  'This report does not prove production publisher key custody or production signing identity.',
  'This report does not create external attestation or prove non-operator review.',
  'This report does not prove enterprise readiness, sovereign recognition, or v3.4.0 readiness.',
]);

const VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_CLAIM_BOUNDARY_KEYS = Object.freeze([
  'creates_public_external_attestation',
  'mutates_release',
  'proves_enterprise_readiness',
  'proves_non_operator_review',
  'proves_production_publisher_key_custody',
  'proves_production_signing_identity',
  'proves_sovereign_recognition',
  'proves_v3_4_0_readiness',
  'uploads_release_assets',
]);

const UNSAFE_TEXT_PATTERNS = Object.freeze([
  { label: 'private operator path', pattern: /\/Users\/[^\s"'`]+/ },
  { label: 'home path', pattern: /\/home\/[^\s"'`]+/ },
  { label: 'private path', pattern: /\/private\/[^\s"'`]+/ },
  { label: 'temp path', pattern: /\/tmp\/[^\s"'`]+/ },
  { label: 'var path', pattern: /\/var\/[^\s"'`]+/ },
  { label: 'private key material', pattern: /BEGIN [A-Z ]*PRIVATE KEY/ },
  { label: 'token-shaped credential', pattern: /\b(?:sk|pk)-[A-Za-z0-9_-]{12,}\b/ },
  { label: 'GitHub token', pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{10,}\b/ },
]);

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(label, value, expectedKeys) {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function releaseTagFromJson(releaseJson) {
  return releaseJson?.tag_name || releaseJson?.tagName || releaseJson?.tag || '';
}

function releaseUrlFromJson(releaseJson) {
  return releaseJson?.html_url || releaseJson?.url || 'not-provided';
}

function releaseDraftState(releaseJson) {
  if (releaseJson?.draft === true || releaseJson?.isDraft === true) return true;
  if (releaseJson?.draft === false || releaseJson?.isDraft === false) return false;
  return 'unknown';
}

function assetApiUrl(asset) {
  return asset?.api_url || asset?.apiUrl || asset?.url || '';
}

function assetBrowserDownloadUrl(asset) {
  return asset?.browser_download_url || asset?.browserDownloadUrl || '';
}

function normalizeDownloadedHashes(downloadedHashesByName) {
  if (downloadedHashesByName instanceof Map) return downloadedHashesByName;
  const out = new Map();
  if (!isObject(downloadedHashesByName)) return out;
  for (const [name, value] of Object.entries(downloadedHashesByName)) {
    if (typeof value === 'string') {
      out.set(name, { sha256: value });
    } else if (isObject(value)) {
      out.set(name, value);
    }
  }
  return out;
}

function normalizeAsset(asset, downloadedHashes) {
  const name = String(asset?.name || '');
  const downloaded = downloadedHashes.get(name) || {};
  return {
    name,
    size: Number.isFinite(asset?.size) ? asset.size : null,
    state: asset?.state || 'unknown',
    content_type: asset?.content_type || asset?.contentType || 'unknown',
    digest: asset?.digest || '',
    browser_download_url: assetBrowserDownloadUrl(asset),
    api_url: assetApiUrl(asset),
    downloaded_sha256: downloaded.sha256 || '',
    downloaded_size: Number.isFinite(downloaded.size) ? downloaded.size : null,
    downloaded: Boolean(downloaded.sha256),
  };
}

function requiredAssetSummary(assets) {
  const byName = new Map(assets.map((asset) => [asset.name, asset]));
  return REQUIRED_VERIFIER_KIT_RELEASE_ASSET_NAMES.map((name) => {
    const asset = byName.get(name) || null;
    return {
      name,
      present: Boolean(asset),
      downloaded_sha256_present: Boolean(asset?.downloaded_sha256),
    };
  });
}

export function buildVerifierKitReleaseAssetsLiveReadReport({
  releaseTag,
  repository = 'ZLAR-AI/ZLAR',
  releaseJson,
  downloadedHashesByName = new Map(),
  evidenceModel = VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_EVIDENCE_MODEL,
  generatedAt = '',
} = {}) {
  if (!/^v\d+\.\d+\.\d+$/.test(releaseTag || '')) {
    throw new Error('releaseTag must look like vX.Y.Z');
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || '')) {
    throw new Error('repository must look like owner/name');
  }
  if (!isObject(releaseJson)) {
    throw new Error('releaseJson must be an object');
  }
  const observedTag = releaseTagFromJson(releaseJson);
  if (observedTag !== releaseTag) {
    throw new Error(`release tag mismatch: ${observedTag || 'missing'} !== ${releaseTag}`);
  }
  if (typeof releaseJson.assets_url === 'string' && !releaseJson.assets_url.includes(repository)) {
    throw new Error('release assets URL does not name the expected repository');
  }

  const downloadedHashes = normalizeDownloadedHashes(downloadedHashesByName);
  const sourceAssets = Array.isArray(releaseJson.assets) ? releaseJson.assets : [];
  const assets = sourceAssets
    .map((asset) => normalizeAsset(asset, downloadedHashes))
    .filter((asset) => asset.name);
  const requiredAssets = requiredAssetSummary(assets);

  return {
    report_type: VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_TYPE,
    schema_version: 1,
    generated_at: generatedAt,
    evidence_model: evidenceModel,
    repository,
    tagName: releaseTag,
    tag_name: releaseTag,
    url: releaseUrlFromJson(releaseJson),
    html_url: releaseJson.html_url || releaseUrlFromJson(releaseJson),
    isDraft: releaseDraftState(releaseJson),
    draft: releaseDraftState(releaseJson),
    immutable: releaseJson.immutable === true,
    prerelease: releaseJson.prerelease === true,
    published_at: releaseJson.published_at || '',
    asset_count: assets.length,
    assets,
    required_release_assets: requiredAssets,
    all_required_assets_present: requiredAssets.every((asset) => asset.present),
    all_required_assets_downloaded:
      requiredAssets.every((asset) => asset.present && asset.downloaded_sha256_present),
    claim_boundary: {
      mutates_release: false,
      uploads_release_assets: false,
      creates_public_external_attestation: false,
      proves_non_operator_review: false,
      proves_production_publisher_key_custody: false,
      proves_production_signing_identity: false,
      proves_enterprise_readiness: false,
      proves_sovereign_recognition: false,
      proves_v3_4_0_readiness: false,
    },
    non_claims: [...VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_NON_CLAIMS],
  };
}

export function assertVerifierKitReleaseAssetsLiveReadReport(report) {
  if (!isObject(report)) throw new Error('release assets live-read report must be an object');
  if (report.report_type !== VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_TYPE) {
    throw new Error('release assets live-read report type drifted');
  }
  if (report.schema_version !== 1) {
    throw new Error('release assets live-read schema version drifted');
  }
  if (!/^v\d+\.\d+\.\d+$/.test(report.tagName || '')) {
    throw new Error('release assets live-read tagName drifted');
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(report.repository || '')) {
    throw new Error('release assets live-read repository drifted');
  }
  if (report.tag_name !== report.tagName) {
    throw new Error('release assets live-read tag fields disagree');
  }
  if (
    report.evidence_model === VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_EVIDENCE_MODEL &&
    (
      typeof report.html_url !== 'string' ||
      !report.html_url.includes(`github.com/${report.repository}/releases/tag/${report.tagName}`)
    )
  ) {
    throw new Error('release assets live-read URL does not name the expected repository and tag');
  }
  if (
    report.evidence_model !== VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_EVIDENCE_MODEL &&
    report.evidence_model !== VERIFIER_KIT_RELEASE_ASSETS_FIXTURE_READ_EVIDENCE_MODEL
  ) {
    throw new Error('release assets live-read evidence model drifted');
  }
  if (!Array.isArray(report.assets)) {
    throw new Error('release assets live-read assets must be an array');
  }
  if (!Array.isArray(report.required_release_assets)) {
    throw new Error('release assets live-read required assets must be an array');
  }
  for (const name of REQUIRED_VERIFIER_KIT_RELEASE_ASSET_NAMES) {
    const required = report.required_release_assets.find((asset) => asset.name === name);
    if (!required || typeof required.present !== 'boolean') {
      throw new Error(`release assets live-read required asset drifted: ${name}`);
    }
    const asset = report.assets.find((entry) => entry.name === name);
    if (
      report.evidence_model === VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_EVIDENCE_MODEL &&
      required.present === true &&
      (
        typeof asset?.browser_download_url !== 'string' ||
        !asset.browser_download_url.includes(
          `github.com/${report.repository}/releases/download/${report.tagName}/${name}`
        )
      )
    ) {
      throw new Error(`release assets live-read asset URL does not name the expected repository: ${name}`);
    }
  }
  if (!isObject(report.claim_boundary)) {
    throw new Error('release assets live-read claim boundary missing');
  }
  exactKeys(
    'release assets live-read claim boundary',
    report.claim_boundary,
    VERIFIER_KIT_RELEASE_ASSETS_LIVE_READ_CLAIM_BOUNDARY_KEYS,
  );
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    if (value !== false) {
      throw new Error(`release assets live-read claim boundary ${key} must remain false`);
    }
  }
  if (!Array.isArray(report.non_claims) || report.non_claims.length === 0) {
    throw new Error('release assets live-read non-claims missing');
  }
  assertNoUnsafeVerifierKitReleaseAssetsLiveReadText(JSON.stringify(report));
  return true;
}

export function assertNoUnsafeVerifierKitReleaseAssetsLiveReadText(text) {
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`Release assets live-read output contains unsafe ${label}`);
    }
  }
  return true;
}

export function formatVerifierKitReleaseAssetsLiveReadSummary(report) {
  assertVerifierKitReleaseAssetsLiveReadReport(report);
  const lines = [
    'ZLAR Verifier Kit Release Assets Live Read',
    '',
    `Release tag: ${report.tagName}`,
    `Repository: ${report.repository}`,
    `Release URL: ${report.html_url}`,
    `Draft: ${report.draft}`,
    `Asset count: ${report.asset_count}`,
    '',
    'Required assets:',
  ];
  for (const asset of report.required_release_assets) {
    lines.push(
      `- ${asset.name}: ${asset.present ? 'present' : 'missing'}, ` +
        `downloaded_sha256=${asset.downloaded_sha256_present}`
    );
  }
  lines.push('', 'Boundary:', ...report.non_claims.map((claim) => `- ${claim}`), '');
  const output = lines.join('\n');
  assertNoUnsafeVerifierKitReleaseAssetsLiveReadText(output);
  return output;
}
