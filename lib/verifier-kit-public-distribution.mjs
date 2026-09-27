import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export const VERIFIER_KIT_PUBLIC_DISTRIBUTION_REPORT_TYPE =
  'zlar-verifier-kit-public-distribution-v1';

export const VERIFIER_KIT_PUBLIC_DISTRIBUTION_NON_CLAIMS = Object.freeze([
  'This report does not publish release assets.',
  'This report does not prove production publisher key custody or production signing identity.',
  'This report does not prove external attestation or non-operator review.',
  'This report does not prove live trust-registry state, revocation truth, production downstream recognition, enterprise readiness, sovereign recognition, or v3.4.0 readiness.',
]);

const KIT_VERSION = 'v0.1.0';
const KIT_DIR_NAME = `zlar-verifier-kit-${KIT_VERSION}`;
const REQUIRED_RELEASE_ASSET_NAMES = Object.freeze([
  `${KIT_DIR_NAME}.tar.gz`,
  `${KIT_DIR_NAME}.tar.gz.sha256`,
  'zlar-verifier-kit-reproducibility-v1.json',
]);
const REQUIRED_REPRO_HASH_PATHS = Object.freeze([
  `dist/${KIT_DIR_NAME}.tar.gz`,
  `dist/${KIT_DIR_NAME}.tar.gz.sha256`,
  `dist/${KIT_DIR_NAME}/MANIFEST.json`,
  `dist/${KIT_DIR_NAME}/MANIFEST.sig`,
]);
const PUBLIC_RELEASE_PUBLICATION_EVIDENCE_MODELS = Object.freeze([
  'github-release-assets-json-live-read',
  'github-release-assets-api-live-read',
]);
const EXPECTED_PUBLIC_RELEASE_REPOSITORY = 'ZLAR-AI/ZLAR';
const STATIC_PUBLIC_ARTIFACT_SOURCE_EVIDENCE_MODELS = Object.freeze([
  'static-public-artifact-source-live-read',
]);
const EXPECTED_STATIC_PUBLIC_ARTIFACT_SOURCE = 'zlar.ai';
const VERIFIER_KIT_PUBLIC_DISTRIBUTION_CLAIM_BOUNDARY_KEYS = Object.freeze([
  'creates_public_external_attestation',
  'proves_enterprise_readiness',
  'proves_live_trust_registry_state',
  'proves_non_operator_review',
  'proves_production_downstream_recognition',
  'proves_production_publisher_key_custody',
  'proves_production_signing_identity',
  'proves_revocation_truth',
  'proves_sovereign_recognition',
  'proves_v3_4_0_readiness',
  'publishes_release_assets',
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

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function normalizedSha256FromAsset(asset) {
  const candidates = [
    ['digest', asset?.digest],
    ['sha256', asset?.sha256],
    ['downloaded_sha256', asset?.downloaded_sha256],
    ['downloadedSha256', asset?.downloadedSha256],
  ];
  for (const [source, raw] of candidates) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    const prefixed = trimmed.match(/^sha256:([0-9a-f]{64})$/i);
    if (prefixed) {
      return { sha256: prefixed[1].toLowerCase(), source };
    }
    if (/^[0-9a-f]{64}$/i.test(trimmed)) {
      return { sha256: trimmed.toLowerCase(), source };
    }
  }
  return { sha256: null, source: 'absent' };
}

function normalizeAsset(asset) {
  if (typeof asset === 'string') {
    return {
      name: asset,
      size: null,
      state: 'unknown',
      content_type: 'unknown',
      digest: '',
      sha256: null,
      sha256_source: 'absent',
      browser_download_url: '',
      api_url: '',
    };
  }
  const normalizedHash = normalizedSha256FromAsset(asset);
  return {
    name: String(asset?.name || ''),
    size: Number.isFinite(asset?.size) ? asset.size : null,
    state: asset?.state || 'unknown',
    content_type: asset?.contentType || asset?.content_type || 'unknown',
    digest: asset?.digest || '',
    sha256: normalizedHash.sha256,
    sha256_source: normalizedHash.source,
    browser_download_url: asset?.browserDownloadUrl || asset?.browser_download_url || '',
    api_url: asset?.apiUrl || asset?.api_url || asset?.url || '',
  };
}

function normalizeAssets(releaseAssetsJson) {
  const rawAssets = Array.isArray(releaseAssetsJson)
    ? releaseAssetsJson
    : Array.isArray(releaseAssetsJson?.assets)
      ? releaseAssetsJson.assets
      : [];
  return rawAssets.map(normalizeAsset).filter((asset) => asset.name);
}

function releaseTagFromJson(releaseAssetsJson) {
  if (Array.isArray(releaseAssetsJson)) return '';
  return releaseAssetsJson?.tagName || releaseAssetsJson?.tag_name || releaseAssetsJson?.tag || '';
}

function releaseUrlFromJson(releaseAssetsJson) {
  if (Array.isArray(releaseAssetsJson)) return 'not-provided';
  return releaseAssetsJson?.url || releaseAssetsJson?.html_url || 'not-provided';
}

function releaseRepositoryFromJson(releaseAssetsJson) {
  if (Array.isArray(releaseAssetsJson)) return 'not-provided';
  return releaseAssetsJson?.repository || 'not-provided';
}

function publicArtifactSourceFromJson(releaseAssetsJson) {
  if (Array.isArray(releaseAssetsJson)) return 'not-provided';
  return releaseAssetsJson?.public_artifact_source ||
    releaseAssetsJson?.artifact_source ||
    releaseAssetsJson?.source ||
    'not-provided';
}

function releaseAssetEvidenceModel(releaseAssetsJson) {
  if (Array.isArray(releaseAssetsJson)) return 'asset-array-supplied';
  return releaseAssetsJson?.evidence_model || 'release-assets-json-supplied';
}

function releaseDraftState(releaseAssetsJson) {
  if (Array.isArray(releaseAssetsJson)) return 'unknown';
  if (releaseAssetsJson?.isDraft === true || releaseAssetsJson?.draft === true) return true;
  if (releaseAssetsJson?.isDraft === false || releaseAssetsJson?.draft === false) return false;
  return 'unknown';
}

function releaseUrlNamesExpectedRepositoryAndTag({ releaseUrl, releaseTag, expectedRepository }) {
  return (
    typeof releaseUrl === 'string' &&
    releaseUrl.includes(`github.com/${expectedRepository}/releases/tag/${releaseTag}`)
  );
}

function requiredAssetUrlsNameExpectedRepository({ assets, releaseTag, expectedRepository }) {
  const assetByName = new Map(assets.map((asset) => [asset.name, asset]));
  return REQUIRED_RELEASE_ASSET_NAMES.every((name) => {
    const asset = assetByName.get(name);
    return (
      typeof asset?.browser_download_url === 'string' &&
      asset.browser_download_url.includes(
        `github.com/${expectedRepository}/releases/download/${releaseTag}/${name}`
      )
    );
  });
}

function urlNamesStaticPublicSourceAndTag({ url, releaseTag, expectedSource }) {
  return (
    typeof url === 'string' &&
    url.startsWith(`https://${expectedSource}/`) &&
    url.includes(releaseTag)
  );
}

function requiredAssetUrlsNameStaticPublicSource({ assets, releaseTag, expectedSource }) {
  const assetByName = new Map(assets.map((asset) => [asset.name, asset]));
  return REQUIRED_RELEASE_ASSET_NAMES.every((name) => {
    const asset = assetByName.get(name);
    return (
      typeof asset?.browser_download_url === 'string' &&
      asset.browser_download_url.startsWith(`https://${expectedSource}/`) &&
      asset.browser_download_url.includes(releaseTag) &&
      asset.browser_download_url.endsWith(`/${name}`)
    );
  });
}

function releasePublicationEvidence({
  releaseAssetsJson,
  releaseTag,
  assets,
  expectedRepository = EXPECTED_PUBLIC_RELEASE_REPOSITORY,
}) {
  const evidenceModel = releaseAssetEvidenceModel(releaseAssetsJson);
  const releaseUrl = releaseUrlFromJson(releaseAssetsJson);
  const repository = releaseRepositoryFromJson(releaseAssetsJson);
  const publicArtifactSource = publicArtifactSourceFromJson(releaseAssetsJson);
  const staticPublicEvidenceModel =
    STATIC_PUBLIC_ARTIFACT_SOURCE_EVIDENCE_MODELS.includes(evidenceModel);
  if (staticPublicEvidenceModel) {
    const expectedSource = EXPECTED_STATIC_PUBLIC_ARTIFACT_SOURCE;
    const sourceMatchesExpected = publicArtifactSource === expectedSource;
    const sourceUrlNamesTag =
      typeof releaseUrl === 'string' && releaseUrl.includes(releaseTag);
    const sourceUrlNamesExpectedSource =
      urlNamesStaticPublicSourceAndTag({ url: releaseUrl, releaseTag, expectedSource });
    const assetUrlsNamePublicSource =
      requiredAssetUrlsNameStaticPublicSource({ assets, releaseTag, expectedSource });
    const anonymousAccessVerified = releaseAssetsJson?.anonymous_access_verified === true;
    const supported =
      sourceMatchesExpected &&
      sourceUrlNamesTag &&
      sourceUrlNamesExpectedSource &&
      assetUrlsNamePublicSource &&
      anonymousAccessVerified;
    const missing = [];
    if (!sourceMatchesExpected) missing.push(`static public artifact source ${expectedSource}`);
    if (!sourceUrlNamesTag) missing.push('static artifact source URL naming the target tag');
    if (!sourceUrlNamesExpectedSource) {
      missing.push(`static artifact source URL naming ${expectedSource}`);
    }
    if (!assetUrlsNamePublicSource) {
      missing.push(`static artifact asset URLs naming ${expectedSource} and the target tag`);
    }
    if (!anonymousAccessVerified) missing.push('anonymous public asset access verification');
    return {
      supported,
      evidence_model: evidenceModel,
      supported_evidence_model: true,
      source_type: 'static-public-artifact-source',
      public_artifact_source: publicArtifactSource,
      expected_public_artifact_source: expectedSource,
      public_artifact_source_matches_expected: sourceMatchesExpected,
      source_url: releaseUrl,
      release_url: releaseUrl,
      source_url_names_tag: sourceUrlNamesTag,
      source_url_names_expected_source: sourceUrlNamesExpectedSource,
      asset_urls_name_public_source: assetUrlsNamePublicSource,
      anonymous_access_verified: anonymousAccessVerified,
      repository,
      expected_repository: 'not-applicable',
      repository_matches_expected: false,
      release_url_names_tag: sourceUrlNamesTag,
      release_url_names_expected_repository: false,
      asset_urls_name_expected_repository: false,
      release_draft: 'not-applicable',
      missing,
    };
  }

  const supportedEvidenceModel =
    PUBLIC_RELEASE_PUBLICATION_EVIDENCE_MODELS.includes(evidenceModel);
  const releaseUrlNamesTag =
    typeof releaseUrl === 'string' &&
    releaseUrl.includes(`/releases/tag/${releaseTag}`);
  const repositoryMatchesExpected = repository === expectedRepository;
  const releaseUrlNamesExpectedRepository =
    releaseUrlNamesExpectedRepositoryAndTag({ releaseUrl, releaseTag, expectedRepository });
  const assetUrlsNameExpectedRepository =
    requiredAssetUrlsNameExpectedRepository({ assets, releaseTag, expectedRepository });
  const releaseDraft = releaseDraftState(releaseAssetsJson);
  const releaseIsPublic = releaseDraft === false;
  const supported =
    supportedEvidenceModel &&
    repositoryMatchesExpected &&
    releaseUrlNamesTag &&
    releaseUrlNamesExpectedRepository &&
    assetUrlsNameExpectedRepository &&
    releaseIsPublic;
  const missing = [];
  if (!supportedEvidenceModel) missing.push('live GitHub release-asset evidence model');
  if (!repositoryMatchesExpected) missing.push(`release repository ${expectedRepository}`);
  if (!releaseUrlNamesTag) missing.push('release URL naming the target tag');
  if (!releaseUrlNamesExpectedRepository) {
    missing.push(`release URL naming ${expectedRepository}`);
  }
  if (!assetUrlsNameExpectedRepository) {
    missing.push(`release asset download URLs naming ${expectedRepository}`);
  }
  if (!releaseIsPublic) missing.push('explicit non-draft public release');
  return {
    supported,
    evidence_model: evidenceModel,
    supported_evidence_model: supportedEvidenceModel,
    source_type: 'github-release-assets',
    repository,
    expected_repository: expectedRepository,
    repository_matches_expected: repositoryMatchesExpected,
    release_url: releaseUrl,
    release_url_names_tag: releaseUrlNamesTag,
    release_url_names_expected_repository: releaseUrlNamesExpectedRepository,
    asset_urls_name_expected_repository: assetUrlsNameExpectedRepository,
    release_draft: releaseDraft,
    missing,
  };
}

function publicationEvidenceSupportsReadyClaim(publicationEvidence) {
  if (publicationEvidence?.source_type === 'static-public-artifact-source') {
    return (
      publicationEvidence.supported === true &&
      publicationEvidence.public_artifact_source_matches_expected === true &&
      publicationEvidence.source_url_names_tag === true &&
      publicationEvidence.source_url_names_expected_source === true &&
      publicationEvidence.asset_urls_name_public_source === true &&
      publicationEvidence.anonymous_access_verified === true
    );
  }
  return (
    publicationEvidence?.supported === true &&
    publicationEvidence.repository_matches_expected === true &&
    publicationEvidence.release_url_names_expected_repository === true &&
    publicationEvidence.asset_urls_name_expected_repository === true
  );
}

function expectedReleaseAssetHashMap({ reproducibility, reproducibilitySha256 = '' }) {
  const publicHashes = publicArtifactHashMap(reproducibility);
  const out = new Map([
    [`${KIT_DIR_NAME}.tar.gz`, publicHashes.get(`dist/${KIT_DIR_NAME}.tar.gz`) || null],
    [`${KIT_DIR_NAME}.tar.gz.sha256`, publicHashes.get(`dist/${KIT_DIR_NAME}.tar.gz.sha256`) || null],
    [
      'zlar-verifier-kit-reproducibility-v1.json',
      /^[0-9a-f]{64}$/.test(reproducibilitySha256)
        ? reproducibilitySha256
        : reproducibility?.file_sha256 || reproducibility?.sha256 || null,
    ],
  ]);
  return out;
}

function buildReleaseAssetHashBindings({ assets, reproducibility, reproducibilitySha256 = '' }) {
  const assetByName = new Map(assets.map((asset) => [asset.name, asset]));
  const expectedHashes = expectedReleaseAssetHashMap({ reproducibility, reproducibilitySha256 });
  const checks = REQUIRED_RELEASE_ASSET_NAMES.map((name) => {
    const asset = assetByName.get(name) || null;
    const expectedSha256 = expectedHashes.get(name) || null;
    const present = Boolean(asset);
    const stateUploaded = asset?.state === 'uploaded';
    const positiveSize = Number.isFinite(asset?.size) && asset.size > 0;
    const suppliedSha256 = asset?.sha256 || null;
    return {
      name,
      present,
      state: asset?.state || 'missing',
      state_uploaded: stateUploaded,
      size: asset?.size ?? null,
      positive_size: positiveSize,
      expected_sha256: expectedSha256,
      supplied_sha256: suppliedSha256,
      sha256_source: asset?.sha256_source || 'absent',
      matches_expected_sha256:
        present &&
        Boolean(expectedSha256) &&
        Boolean(suppliedSha256) &&
        expectedSha256 === suppliedSha256,
    };
  });
  return {
    all_required_assets_uploaded: checks.every((check) => check.present && check.state_uploaded),
    all_required_assets_positive_size: checks.every((check) => check.present && check.positive_size),
    all_required_expected_hashes_present:
      checks.every((check) => check.present && Boolean(check.expected_sha256)),
    all_required_supplied_hashes_present:
      checks.every((check) => check.present && Boolean(check.supplied_sha256)),
    all_required_assets_bound:
      checks.every((check) =>
        check.present &&
        check.state_uploaded &&
        check.positive_size &&
        Boolean(check.expected_sha256) &&
        Boolean(check.supplied_sha256) &&
        check.matches_expected_sha256 === true
      ),
    checks,
  };
}

function publicArtifactHashMap(reproducibility) {
  const out = new Map();
  const hashes = Array.isArray(reproducibility?.public_artifact_hashes)
    ? reproducibility.public_artifact_hashes
    : [];
  for (const entry of hashes) {
    if (typeof entry?.path === 'string' && /^[0-9a-f]{64}$/.test(entry?.sha256 || '')) {
      out.set(entry.path, entry.sha256);
    }
  }
  return out;
}

function resolveArtifactPath(assetDir, artifactPath) {
  const candidates = [join(assetDir, artifactPath)];
  if (artifactPath.startsWith('dist/')) {
    candidates.push(join(assetDir, artifactPath.slice('dist/'.length)));
  }
  return candidates.find((candidate) => existsSync(candidate)) || candidates[0];
}

function buildLocalArtifactHashes({ assetDir, reproducibility }) {
  if (!assetDir) {
    return {
      asset_dir_provided: false,
      all_checked_hashes_match: false,
      checks: [],
    };
  }
  const expectedHashes = publicArtifactHashMap(reproducibility);
  const checks = REQUIRED_REPRO_HASH_PATHS.map((artifactPath) => {
    const localPath = resolveArtifactPath(assetDir, artifactPath);
    if (!existsSync(localPath)) {
      return {
        path: artifactPath,
        present: false,
        sha256: null,
        expected_sha256: expectedHashes.get(artifactPath) || null,
        matches_reproducibility_report: false,
      };
    }
    const sha256 = sha256File(localPath);
    const expected = expectedHashes.get(artifactPath) || null;
    return {
      path: artifactPath,
      present: true,
      sha256,
      expected_sha256: expected,
      matches_reproducibility_report: expected ? sha256 === expected : false,
    };
  });
  return {
    asset_dir_provided: true,
    all_checked_hashes_match: checks.every((check) => check.matches_reproducibility_report === true),
    checks,
  };
}

function publicHashesPresent(reproducibility) {
  const hashes = publicArtifactHashMap(reproducibility);
  return REQUIRED_REPRO_HASH_PATHS.every((path) => hashes.has(path));
}

function derivePosture({
  missingAssets,
  publicationEvidence,
  releaseAssetHashes,
  publicHashes,
  localHashes,
}) {
  if (missingAssets.length === REQUIRED_RELEASE_ASSET_NAMES.length) {
    return 'public_release_assets_absent';
  }
  if (missingAssets.length > 0) {
    return 'public_release_assets_incomplete';
  }
  if (publicationEvidence.supported !== true) {
    return 'release_assets_present_but_publication_boundary_not_upgraded';
  }
  if (
    releaseAssetHashes.all_required_assets_uploaded !== true ||
    releaseAssetHashes.all_required_assets_positive_size !== true
  ) {
    return 'release_assets_present_but_metadata_incomplete';
  }
  if (releaseAssetHashes.all_required_assets_bound !== true) {
    return 'release_assets_present_but_release_hashes_not_verified';
  }
  if (!publicHashes || localHashes.all_checked_hashes_match !== true) {
    return 'release_assets_present_but_hashes_not_verified';
  }
  return 'public_distribution_posture_ready';
}

export function buildVerifierKitPublicDistributionReport({
  releaseTag,
  releaseAssetsJson,
  reproducibility,
  reproducibilitySha256 = '',
  assetDir = '',
} = {}) {
  if (!/^v\d+\.\d+\.\d+$/.test(releaseTag || '')) {
    throw new Error('releaseTag must look like vX.Y.Z');
  }
  if (!isObject(releaseAssetsJson) && !Array.isArray(releaseAssetsJson)) {
    throw new Error('releaseAssetsJson must be an object or asset array');
  }
  if (!isObject(reproducibility)) {
    throw new Error('reproducibility must be an object');
  }

  const observedReleaseTag = releaseTagFromJson(releaseAssetsJson) || releaseTag;
  if (observedReleaseTag !== releaseTag) {
    throw new Error(`release assets tag mismatch: ${observedReleaseTag} !== ${releaseTag}`);
  }

  const assets = normalizeAssets(releaseAssetsJson);
  const assetNames = new Set(assets.map((asset) => asset.name));
  const requiredAssets = REQUIRED_RELEASE_ASSET_NAMES.map((name) => ({
    name,
    present: assetNames.has(name),
  }));
  const missingAssets = requiredAssets.filter((asset) => !asset.present).map((asset) => asset.name);
  const publicationEvidence =
    releasePublicationEvidence({ releaseAssetsJson, releaseTag, assets });
  const releaseAssetHashes = buildReleaseAssetHashBindings({
    assets,
    reproducibility,
    reproducibilitySha256,
  });
  const publicHashes = publicHashesPresent(reproducibility);
  const localHashes = buildLocalArtifactHashes({ assetDir, reproducibility });
  const claimBoundary = reproducibility.claim_boundary || {};
  const blockingReasons = [];

  if (missingAssets.length > 0) {
    blockingReasons.push(`missing public release assets: ${missingAssets.join(', ')}`);
  }
  if (reproducibility.report_type !== 'zlar-verifier-kit-reproducibility-v1') {
    blockingReasons.push('reproducibility report type is not zlar-verifier-kit-reproducibility-v1');
  }
  if (reproducibility.result !== 'PASS') {
    blockingReasons.push('verifier-kit reproducibility report is not PASS');
  }
  if (reproducibility.reproducible?.tarball_sha256_identical !== true) {
    blockingReasons.push('verifier-kit tarball reproducibility is not proven');
  }
  if (reproducibility.reproducible?.manifest_and_signature_sha256_identical !== true) {
    blockingReasons.push('verifier-kit manifest/signature reproducibility is not proven');
  }
  if (reproducibility.reproducible?.sidecar_matches_tarball !== true) {
    blockingReasons.push('verifier-kit sidecar does not report matching the tarball');
  }
  if (!publicHashes) {
    blockingReasons.push('reproducibility report does not carry all required public artifact hashes');
  }
  if (publicationEvidence.supported !== true) {
    blockingReasons.push(
      `release asset evidence does not prove public release publication: ${publicationEvidence.missing.join(', ')}`
    );
  }
  if (missingAssets.length === 0) {
    const metadataFailures = releaseAssetHashes.checks
      .filter((check) => check.state_uploaded !== true || check.positive_size !== true)
      .map((check) => check.name);
    if (metadataFailures.length > 0) {
      blockingReasons.push(
        `public release assets are not all uploaded with positive sizes: ${metadataFailures.join(', ')}`
      );
    }
    if (releaseAssetHashes.all_required_expected_hashes_present !== true) {
      blockingReasons.push('expected public release asset hashes are incomplete');
    }
    if (releaseAssetHashes.all_required_supplied_hashes_present !== true) {
      blockingReasons.push('public release asset SHA-256 evidence is missing');
    } else if (releaseAssetHashes.all_required_assets_bound !== true) {
      blockingReasons.push('public release asset SHA-256 evidence does not match reproducibility evidence');
    }
  }
  if (!localHashes.asset_dir_provided) {
    blockingReasons.push('local artifact hashes were not checked against the reproducibility report');
  } else if (localHashes.all_checked_hashes_match !== true) {
    blockingReasons.push('local artifact hashes do not all match the reproducibility report');
  }

  const readyForPublicDistributionClaim = blockingReasons.length === 0;
  const posture = derivePosture({
    missingAssets,
    publicationEvidence,
    releaseAssetHashes,
    publicHashes,
    localHashes,
  });

  return {
    report_type: VERIFIER_KIT_PUBLIC_DISTRIBUTION_REPORT_TYPE,
    schema_version: 1,
    result: 'AUDIT_PASS',
    release_tag: releaseTag,
    kit_version: KIT_VERSION,
    release_assets: {
      evidence_model: releaseAssetEvidenceModel(releaseAssetsJson),
      release_url: releaseUrlFromJson(releaseAssetsJson),
      asset_count: assets.length,
      assets,
      public_release_publication_evidence: publicationEvidence,
      release_asset_hashes: releaseAssetHashes,
    },
    required_public_release_assets: requiredAssets,
    reproducibility: {
      provided: true,
      report_type: reproducibility.report_type || 'unknown',
      result: reproducibility.result || 'unknown',
      evidence_model: reproducibility.evidence_model || 'unknown',
      publisher_key_model: reproducibility.publisher_key_model || 'unknown',
      publisher_kid: reproducibility.publisher_kid || 'unknown',
      public_artifact_hashes_present: publicHashes,
      public_release_publication_boundary:
        claimBoundary.public_release_publication === true,
      production_publisher_key_custody:
        claimBoundary.production_publisher_key_custody === true,
      production_signing_identity:
        claimBoundary.production_signing_identity === true,
    },
    local_artifact_hashes: localHashes,
    posture,
    ready_for_public_distribution_claim: readyForPublicDistributionClaim,
    blocking_reasons: blockingReasons,
    claim_boundary: {
      publishes_release_assets: false,
      creates_public_external_attestation: false,
      proves_non_operator_review: false,
      proves_production_publisher_key_custody: false,
      proves_production_signing_identity: false,
      proves_live_trust_registry_state: false,
      proves_revocation_truth: false,
      proves_production_downstream_recognition: false,
      proves_enterprise_readiness: false,
      proves_sovereign_recognition: false,
      proves_v3_4_0_readiness: false,
    },
    non_claims: [...VERIFIER_KIT_PUBLIC_DISTRIBUTION_NON_CLAIMS],
  };
}

export function assertVerifierKitPublicDistributionReport(report) {
  if (!isObject(report)) throw new Error('verifier-kit public distribution report must be an object');
  if (report.report_type !== VERIFIER_KIT_PUBLIC_DISTRIBUTION_REPORT_TYPE) {
    throw new Error('verifier-kit public distribution report type drifted');
  }
  if (report.schema_version !== 1) {
    throw new Error('verifier-kit public distribution schema version drifted');
  }
  if (report.result !== 'AUDIT_PASS') {
    throw new Error('verifier-kit public distribution result must be AUDIT_PASS');
  }
  if (!/^v\d+\.\d+\.\d+$/.test(report.release_tag || '')) {
    throw new Error('verifier-kit public distribution release tag drifted');
  }
  if (report.kit_version !== KIT_VERSION) {
    throw new Error('verifier-kit public distribution kit version drifted');
  }
  if (!Array.isArray(report.required_public_release_assets)) {
    throw new Error('verifier-kit public distribution required asset list missing');
  }
  const releaseAssetHashes = report.release_assets?.release_asset_hashes;
  if (!isObject(releaseAssetHashes) || !Array.isArray(releaseAssetHashes.checks)) {
    throw new Error('verifier-kit public distribution release asset hash binding missing');
  }
  for (const name of REQUIRED_RELEASE_ASSET_NAMES) {
    const asset = report.required_public_release_assets.find((entry) => entry.name === name);
    if (!asset || typeof asset.present !== 'boolean') {
      throw new Error(`verifier-kit public distribution required asset drifted: ${name}`);
    }
    const hashCheck = releaseAssetHashes.checks.find((entry) => entry.name === name);
    if (!hashCheck || typeof hashCheck.matches_expected_sha256 !== 'boolean') {
      throw new Error(`verifier-kit public distribution release asset hash drifted: ${name}`);
    }
  }
  if (!Array.isArray(report.blocking_reasons)) {
    throw new Error('verifier-kit public distribution blocking reasons must be an array');
  }
  if (report.ready_for_public_distribution_claim !== (report.blocking_reasons.length === 0)) {
    throw new Error('verifier-kit public distribution readiness/blocker mismatch');
  }
  if (!isObject(report.claim_boundary)) {
    throw new Error('verifier-kit public distribution claim boundary missing');
  }
  exactKeys(
    'verifier-kit public distribution claim boundary',
    report.claim_boundary,
    VERIFIER_KIT_PUBLIC_DISTRIBUTION_CLAIM_BOUNDARY_KEYS,
  );
  for (const [key, value] of Object.entries(report.claim_boundary)) {
    if (value !== false) {
      throw new Error(`verifier-kit public distribution claim boundary ${key} must remain false`);
    }
  }
  if (
    !Array.isArray(report.non_claims) ||
    report.non_claims.length !== VERIFIER_KIT_PUBLIC_DISTRIBUTION_NON_CLAIMS.length
  ) {
    throw new Error('verifier-kit public distribution non-claims drifted');
  }
  if (
    report.ready_for_public_distribution_claim === false &&
    report.posture === 'public_distribution_posture_ready'
  ) {
    throw new Error('verifier-kit public distribution posture/readiness mismatch');
  }
  if (
    report.ready_for_public_distribution_claim === true &&
    releaseAssetHashes.all_required_assets_bound !== true
  ) {
    throw new Error('verifier-kit public distribution ready claim requires release asset byte binding');
  }
  if (report.ready_for_public_distribution_claim === true) {
    const publicationEvidence = report.release_assets?.public_release_publication_evidence || {};
    if (publicationEvidenceSupportsReadyClaim(publicationEvidence) !== true) {
      throw new Error('verifier-kit public distribution ready claim requires expected public source binding');
    }
  }
  return true;
}

export function formatVerifierKitPublicDistributionSummary(report) {
  assertVerifierKitPublicDistributionReport(report);
  const lines = [
    'ZLAR Verifier Kit Public Distribution Posture',
    '',
    `Result: ${report.result}`,
    `Release tag: ${report.release_tag}`,
    `Kit version: ${report.kit_version}`,
    `Posture: ${report.posture}`,
    `Ready for public distribution claim: ${report.ready_for_public_distribution_claim}`,
    '',
    'Required release assets:',
  ];
  for (const asset of report.required_public_release_assets) {
    lines.push(`- ${asset.name}: ${asset.present ? 'present' : 'missing'}`);
  }
  lines.push('', 'Release asset byte binding:');
  const hashChecks = report.release_assets?.release_asset_hashes?.checks || [];
  for (const check of hashChecks) {
    lines.push(`- ${check.name}: ${check.matches_expected_sha256 ? 'verified' : 'not verified'}`);
  }
  lines.push('', 'Blocking reasons:');
  if (report.blocking_reasons.length === 0) {
    lines.push('- none');
  } else {
    for (const reason of report.blocking_reasons) lines.push(`- ${reason}`);
  }
  lines.push('', 'Boundary:');
  for (const claim of report.non_claims) lines.push(`- ${claim}`);
  return `${lines.join('\n')}\n`;
}

export function assertNoUnsafeVerifierKitPublicDistributionText(text) {
  for (const { label, pattern } of UNSAFE_TEXT_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error(`verifier-kit public distribution output contains unsafe ${label}`);
    }
  }
  return true;
}
