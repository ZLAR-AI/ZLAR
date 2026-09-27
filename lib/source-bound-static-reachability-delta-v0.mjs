import { canonicalize } from './canonicalize.mjs';
import { sha256hex } from './sha256.mjs';

export const SOURCE_BOUND_STATIC_REACHABILITY_DELTA_TYPE_V0 =
  'zlar.source-bound-static-reachability-delta.v0';
export const SOURCE_BOUND_STATIC_REACHABILITY_DELTA_VERSION_V0 = 0;

const ACTION_CLASS = 'records.write';
const AUTHORITY_DOMAIN = 'protected-records.local-disposable-fixture';
const SELECTED_PATH =
  'protected-records.installed-runtime-profile.terminal-chain.records.write';
const ANALYZED_SOURCE_COMMIT = 'e7c621927df35eb31cf3f0dfc1ea2a42df6d5dd5';
const PARENT_FILE_SHA256 =
  'a275b74cb7e468bed6a8376c8ccc0aab81937d945e240d69090293ae9b38a4de';
const PARENT_BODY_SHA256 =
  'b39767ba79435bede70784d416b25ad52c47a6fb1c22df195a32b4af115f6b9b';
const PARENT_SOURCE_INVENTORY_SHA256 =
  '76e863aa745815dd5322d8c2f8b1b219acf5cf46bcc66719523681e0b8ff2262';
const EXPECTED_DELTA_BODY_SHA256_V0 =
  '219d36fa18b01de5477ff2bebf0e00892868c65fead36446227a86838db23f89';
const SHA256_RE = /^[a-f0-9]{64}$/;
const GIT_SHA1_RE = /^[a-f0-9]{40}$/;

const PARENT_WRAPPER_ENTRYPOINTS = Object.freeze([
  'bin/zlar-protected-records-active-persistent-profile-lifecycle',
  'bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
  'bin/zlar-protected-records-installed-runtime-profile-service-proof',
  'bin/zlar-protected-records-runtime-activation-preflight',
  'bin/zlar-protected-records-runtime-profile-preflight',
  'bin/zlar-protected-records-runtime-profile-proof',
]);

const INHERITED_DEPENDENCY_PINS = Object.freeze({
  base_lifecycle_map: Object.freeze({
    file_sha256:
      'cff702d5c0928dfda490acc3bfde9e698fac8ec79abaec08a9ab4d73f9290f30',
    semantic_sha256:
      'c2d19a304fa38a19447f316456aff611c7bd70447f9524ab0ee85ea6a53c2db1',
  }),
  post_effect_route_evidence_index: Object.freeze({
    file_sha256:
      '29e10ad2fc559a4028630f344d226c14e501f30fe970da45afff4117e42abc8e',
    body_sha256:
      'a03dacbc26508a1dce20e350f8519f60477fc8ad90f776e1d7dec5a6bcb79b67',
  }),
  replacement_lifecycle_overlay: Object.freeze({
    file_sha256:
      'fe464285e78a33596247c4a84828cc0d5f3a28366529ffffb73f65b4bdbe5a27',
    semantic_sha256:
      'd1ccd8fb144c9e9fdd77980fa33be3ebedc3facb965826ef545642ed46df9693',
  }),
});

function witness(id, needle, codeAnchors = []) {
  return Object.freeze({ id, needle, code_anchors: Object.freeze(codeAnchors) });
}

const SOURCE_SPECS = Object.freeze({
  main_dispatch: Object.freeze({
    relative_path: 'bin/zlar',
    file_sha256:
      '15b228a1dcada560965bb118cedbc5a38ba68f8bbf850a4af8a07bcf377f8e92',
    git_blob_oid: 'bd01ae48dba2cccd6469e61659f2726ddd1343aa',
    git_mode: '100755',
    shebang: '#!/bin/bash',
    witnesses: Object.freeze([
      witness(
        'dispatch.runtime-service',
        '    protected-records-runtime-service) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-runtime-service" "$@" ;;',
      ),
      witness(
        'dispatch.runtime-profile-preflight',
        '    protected-records-runtime-profile-preflight) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-runtime-profile-preflight" "$@" ;;',
      ),
      witness(
        'dispatch.runtime-activation-preflight',
        '    protected-records-runtime-activation-preflight) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-runtime-activation-preflight" "$@" ;;',
      ),
      witness(
        'dispatch.runtime-profile-proof',
        '    protected-records-runtime-profile-proof) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-runtime-profile-proof" "$@" ;;',
      ),
      witness(
        'dispatch.active-persistent-lifecycle',
        '    protected-records-active-persistent-profile-lifecycle) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-active-persistent-profile-lifecycle" "$@" ;;',
      ),
      witness(
        'dispatch.installed-recognition-proof',
        '    protected-records-installed-runtime-profile-recognition-proof) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-installed-runtime-profile-recognition-proof" "$@" ;;',
      ),
      witness(
        'dispatch.installed-service-proof',
        '    protected-records-installed-runtime-profile-service-proof) ZLAR_PROJECT_DIR="${PROJECT_DIR}" node "${PROJECT_DIR}/bin/zlar-protected-records-installed-runtime-profile-service-proof" "$@" ;;',
      ),
    ]),
  }),
  runtime_service_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-runtime-service',
    file_sha256:
      '8aec7c8eed3a3e0072818c6a8d5110fcf66707ad4b48073308d8679af4370493',
    git_blob_oid: 'fc2241d9e4cf388a3877e6be7d6b7e84c714a526',
    git_mode: '100755',
    shebang: '#!/usr/bin/env node',
    witnesses: Object.freeze([
      witness(
        'runtime-service.import-factory',
        '  createProtectedRecordsRuntimeService,\n  isProtectedRecordsRuntimeServiceConfigV2,\n} from \'../lib/protected-records-runtime-profile.mjs\';',
        ['createProtectedRecordsRuntimeService', 'from'],
      ),
      witness(
        'runtime-service.v2-refusal-branch',
        '  if (isProtectedRecordsRuntimeServiceConfigV2(config)) {\n    throw new Error(\n      \'Direct protected-records runtime-service v2 execution is forbidden; use the exact replacement crossing route.\',\n    );\n  }\n  assertProtectedRecordsRuntimeServiceConfig(config);',
        ['isProtectedRecordsRuntimeServiceConfigV2', 'throw', 'assertProtectedRecordsRuntimeServiceConfig'],
      ),
      witness(
        'runtime-service.call-factory',
        '  const service = createProtectedRecordsRuntimeService(config);',
        ['createProtectedRecordsRuntimeService'],
      ),
      witness(
        'runtime-service.call-returned-method',
        '    const result = service.applyRequest(request);',
        ['service', 'applyRequest'],
      ),
    ]),
  }),
  runtime_profile_proof_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-runtime-profile-proof',
    file_sha256:
      '40f1bd2e4222b82f9a5a1e27c3dc4148da9e425d0ad0816fac39896ebb4425e7',
    git_blob_oid: '99d158d8c9b80f5a7aaf581e07b55dc57573251e',
    git_mode: '100755',
    shebang: '#!/usr/bin/env node',
    witnesses: Object.freeze([
      witness(
        'runtime-profile-proof.import-runner',
        '  runProtectedRecordsRuntimeProfileProof,\n} from \'../lib/protected-records-runtime-profile.mjs\';',
        ['runProtectedRecordsRuntimeProfileProof', 'from'],
      ),
      witness(
        'runtime-profile-proof.call-runner',
        '  const report = runProtectedRecordsRuntimeProfileProof();',
        ['runProtectedRecordsRuntimeProfileProof'],
      ),
    ]),
  }),
  runtime_profile_preflight_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-runtime-profile-preflight',
    file_sha256:
      '5abfc96d19c312f22a01175473531316bc1d0beaef550e26e3c49e3c08863c63',
    git_blob_oid: '9f2460d33e7e6195cca1f638e8c4e3355e1c8628',
    git_mode: '100755',
    shebang: '#!/usr/bin/env node',
    witnesses: Object.freeze([
      witness(
        'runtime-profile-preflight.import-runner',
        '  runProtectedRecordsRuntimeProfilePreflight,\n} from \'../lib/protected-records-runtime-profile-preflight.mjs\';',
        ['runProtectedRecordsRuntimeProfilePreflight', 'from'],
      ),
      witness(
        'runtime-profile-preflight.call-runner',
        '  const report = runProtectedRecordsRuntimeProfilePreflight(profile);',
        ['runProtectedRecordsRuntimeProfilePreflight'],
      ),
    ]),
  }),
  runtime_activation_preflight_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-runtime-activation-preflight',
    file_sha256:
      '048d6764cbac0caea8fc6ea72ea202f4decc9a68198077d102d698102bb81527',
    git_blob_oid: 'ba9ba420362fd30db57a7df2e37563aa7d1b57de',
    git_mode: '100755',
    shebang: '#!/usr/bin/env node',
    witnesses: Object.freeze([
      witness(
        'runtime-activation.import-runners',
        '  runProtectedRecordsRuntimeActivationPreflight,\n  verifyProtectedRecordsRuntimeActivationPreflightArtifact,\n  writeProtectedRecordsRuntimeActivationPreflightArtifact,',
        ['runProtectedRecordsRuntimeActivationPreflight', 'verifyProtectedRecordsRuntimeActivationPreflightArtifact'],
      ),
      witness(
        'runtime-activation.verify-branch',
        "if (args[0] === 'verify') {\n  try {\n    runVerifyCommand(args.slice(1));",
        ['if', 'runVerifyCommand'],
      ),
      witness(
        'runtime-activation.call-verifier',
        '  const baseVerification = verifyProtectedRecordsRuntimeActivationPreflightArtifact(artifact);',
        ['verifyProtectedRecordsRuntimeActivationPreflightArtifact'],
      ),
      witness(
        'runtime-activation.call-runner',
        '  const report = runProtectedRecordsRuntimeActivationPreflight(plan, profile);',
        ['runProtectedRecordsRuntimeActivationPreflight'],
      ),
    ]),
  }),
  installed_recognition_cli: Object.freeze({
    relative_path:
      'bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
    file_sha256:
      'e745cfbf32054b0cbc7cba21d93ad435fd014b8059b93bcf98c405352eb4d106',
    git_blob_oid: 'bbd07485a881aed55ff849de57db0d04d4d2fe61',
    git_mode: '100755',
    shebang: '#!/usr/bin/env node',
    witnesses: Object.freeze([
      witness(
        'installed-recognition.import-runners',
        '  runProtectedRecordsInstalledRuntimeProfileRecognitionProof,\n  verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact,\n  writeProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact,',
        ['runProtectedRecordsInstalledRuntimeProfileRecognitionProof', 'verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact'],
      ),
      witness(
        'installed-recognition.verify-branch',
        "if (args[0] === 'verify') {\n  try {\n    runVerifyCommand(args.slice(1));",
        ['if', 'runVerifyCommand'],
      ),
      witness(
        'installed-recognition.call-verifier',
        '  const baseVerification = verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(',
        ['verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact'],
      ),
      witness(
        'installed-recognition.cli-guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records installed runtime profile recognition proof generation'\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'installed-recognition.call-runner',
        '  const report = runProtectedRecordsInstalledRuntimeProfileRecognitionProof(artifact);',
        ['runProtectedRecordsInstalledRuntimeProfileRecognitionProof'],
      ),
    ]),
  }),
  installed_service_cli: Object.freeze({
    relative_path:
      'bin/zlar-protected-records-installed-runtime-profile-service-proof',
    file_sha256:
      '45b866d7f18db7fd5b5ecb598bc1f324e0cc7c0a015d0f3c7db9e363518f8191',
    git_blob_oid: '0c8f9ef9c338f3c6e2d21ed8f683b0528a49148c',
    git_mode: '100755',
    shebang: '#!/usr/bin/env node',
    witnesses: Object.freeze([
      witness(
        'installed-service.import-runners',
        '  runProtectedRecordsInstalledRuntimeProfileServiceProof,\n  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,\n  writeProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,',
        ['runProtectedRecordsInstalledRuntimeProfileServiceProof', 'verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact'],
      ),
      witness(
        'installed-service.verify-branch',
        "if (args[0] === 'verify') {\n  try {\n    runVerifyCommand(args.slice(1));",
        ['if', 'runVerifyCommand'],
      ),
      witness(
        'installed-service.call-verifier',
        '  const baseVerification = verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(',
        ['verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact'],
      ),
      witness(
        'installed-service.cli-guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records installed runtime profile service proof generation'\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'installed-service.call-runner',
        '  const report = runProtectedRecordsInstalledRuntimeProfileServiceProof(artifact);',
        ['runProtectedRecordsInstalledRuntimeProfileServiceProof'],
      ),
    ]),
  }),
  active_lifecycle_cli: Object.freeze({
    relative_path: 'bin/zlar-protected-records-active-persistent-profile-lifecycle',
    file_sha256:
      '04a5f99d811b625e1bcf4f579e03d47b5468f562541fa33cd9285395b5631c54',
    git_blob_oid: '408a6327ab5f3d5ac11a7b34b4910fe26defad5d',
    git_mode: '100755',
    shebang: '#!/usr/bin/env node',
    witnesses: Object.freeze([
      witness(
        'active-lifecycle.import-runners',
        '  buildActivePersistentProfileLifecycleReportFromFiles,\n  formatActivePersistentProfileLifecycleRunResult,\n  formatActivePersistentProfileLifecycleReport,\n  runActivePersistentProfileLifecycleEvidence,',
        ['buildActivePersistentProfileLifecycleReportFromFiles', 'runActivePersistentProfileLifecycleEvidence'],
      ),
      witness(
        'active-lifecycle.run-branch',
        "if (args[0] === 'run') {",
        ['if'],
      ),
      witness(
        'active-lifecycle.call-runner',
        '    const result = runActivePersistentProfileLifecycleEvidence({',
        ['runActivePersistentProfileLifecycleEvidence'],
      ),
      witness(
        'active-lifecycle.call-report-verifier',
        '  const report = buildActivePersistentProfileLifecycleReportFromFiles({',
        ['buildActivePersistentProfileLifecycleReportFromFiles'],
      ),
      witness(
        'active-lifecycle.optional-report-write',
        '    const sha = writeActivePersistentProfileLifecycleReport({',
        ['writeActivePersistentProfileLifecycleReport'],
      ),
    ]),
  }),
  runtime_profile: Object.freeze({
    relative_path: 'lib/protected-records-runtime-profile.mjs',
    file_sha256:
      'a99ad56f2b2b96944b266b51296b7d68cddb3d3ea849ec8f9b94b8e34a5ad5d2',
    git_blob_oid: 'd927dc2a13da3c69340e2c6f5e0568d95fdcd7e6',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'runtime-profile.factory-definition',
        'export function createProtectedRecordsRuntimeService(config = {}) {',
        ['export', 'function', 'createProtectedRecordsRuntimeService'],
      ),
      witness(
        'runtime-profile.apply-definition-v1',
        "  function applyRequest(input = {}) {\n    const stateEntryCountBefore = stateEntries.length;\n    let request;\n    try {\n      request = freezeCanonicalSnapshot(\n        snapshotAccessorFreeData(\n          requireObject('Protected records runtime request', input),",
        ['function', 'applyRequest', 'stateEntries'],
      ),
      witness(
        'runtime-profile.return-method-binding-v1',
        '  return {\n    applyRequest,\n    status() {',
        ['return', 'applyRequest', 'status'],
      ),
      witness(
        'runtime-profile.call-append-v1',
        '          appendRuntimeStateEntry(stateEntry);',
        ['appendRuntimeStateEntry'],
      ),
      witness(
        'runtime-profile.append-definition-v1',
        '  function appendRuntimeStateEntry(entry) {',
        ['function', 'appendRuntimeStateEntry'],
      ),
      witness(
        'runtime-profile.e3-sink',
        '    stateEntries.push(entry);',
        ['stateEntries', 'push'],
      ),
      witness(
        'runtime-profile.proof-definition',
        'export function runProtectedRecordsRuntimeProfileProof({',
        ['export', 'function', 'runProtectedRecordsRuntimeProfileProof'],
      ),
      witness(
        'runtime-profile.proof-guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records runtime-profile proof generation',\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'runtime-profile.call-child-helper',
        "    const activeRun = runRuntimeService(activeConfig, activeRequests, scratch, 'active');",
        ['runRuntimeService'],
      ),
      witness(
        'runtime-profile.child-helper-definition',
        'function runRuntimeService(config, requests, scratch, label) {',
        ['function', 'runRuntimeService'],
      ),
      witness(
        'runtime-profile.child-target-binding',
        "const ZLAR_BIN = fileURLToPath(new URL('../bin/zlar', import.meta.url));",
        ['const', 'ZLAR_BIN', 'fileURLToPath', 'new', 'URL'],
      ),
      witness(
        'runtime-profile.unresolved-child-spawn',
        "  const run = spawnSync(ZLAR_BIN, ['protected-records-runtime-service', '--config', configPath], {\n    cwd: fileURLToPath(new URL('..', import.meta.url)),\n    encoding: 'utf8',\n    input,\n    env: {\n      ...process.env,\n      NO_COLOR: '1',\n    },\n  });",
        ['spawnSync', 'ZLAR_BIN', 'cwd', 'env', 'process', 'NO_COLOR'],
      ),
    ]),
  }),
  runtime_profile_preflight: Object.freeze({
    relative_path: 'lib/protected-records-runtime-profile-preflight.mjs',
    file_sha256:
      '506b47c9ca33788d8a7659bec90573ec37faffb5b5e4bf8038ec87d30bef32f4',
    git_blob_oid: '5fc09e3317b83c3dd6799c79955071629ad8ef0a',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'runtime-preflight.import-proof-runner',
        '  runProtectedRecordsRuntimeProfileProof,\n} from \'./protected-records-runtime-profile.mjs\';',
        ['runProtectedRecordsRuntimeProfileProof', 'from'],
      ),
      witness(
        'runtime-preflight.definition',
        'export function runProtectedRecordsRuntimeProfilePreflight(profile) {',
        ['export', 'function', 'runProtectedRecordsRuntimeProfilePreflight'],
      ),
      witness(
        'runtime-preflight.guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records runtime-profile preflight proof generation',\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'runtime-preflight.call-proof',
        '  const proof = runProtectedRecordsRuntimeProfileProof();',
        ['runProtectedRecordsRuntimeProfileProof'],
      ),
    ]),
  }),
  runtime_activation_preflight: Object.freeze({
    relative_path: 'lib/protected-records-runtime-activation-preflight.mjs',
    file_sha256:
      'a00ff776db5148e1bb513cb1164842844eaeb47972f4267312eaed476d54952c',
    git_blob_oid: 'a2d0151a08f84fe10614e6981d6cb32c165b5f3d',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'runtime-activation.import-profile-preflight-runner',
        '  runProtectedRecordsRuntimeProfilePreflight,\n  runtimeProfileSha256,\n} from \'./protected-records-runtime-profile-preflight.mjs\';',
        ['runProtectedRecordsRuntimeProfilePreflight', 'from'],
      ),
      witness(
        'runtime-activation.definition',
        'export function runProtectedRecordsRuntimeActivationPreflight(plan, profile) {',
        ['export', 'function', 'runProtectedRecordsRuntimeActivationPreflight'],
      ),
      witness(
        'runtime-activation.guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records runtime activation-preflight proof generation',\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'runtime-activation.call-preflight',
        '  const runtimePreflight = runProtectedRecordsRuntimeProfilePreflight(profile);',
        ['runProtectedRecordsRuntimeProfilePreflight'],
      ),
      witness(
        'runtime-activation.verifier-definition',
        'export function verifyProtectedRecordsRuntimeActivationPreflightArtifact(artifact) {',
        ['export', 'function', 'verifyProtectedRecordsRuntimeActivationPreflightArtifact'],
      ),
      witness(
        'runtime-activation.evidence-write',
        '  writeFileSync(outputPath, output, { mode: 0o600 });',
        ['writeFileSync'],
      ),
    ]),
  }),
  installed_recognition: Object.freeze({
    relative_path:
      'lib/protected-records-installed-runtime-profile-recognition-proof.mjs',
    file_sha256:
      '860a68d3135d571eef1b909c6ca7e21d31cc16f2be2f2ac75b36bbef86ea297f',
    git_blob_oid: 'e2a1fe7111ea4a1b508ee6f6a2d69caef0fa65fc',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'installed-recognition.import-runtime-factory',
        '  createProtectedRecordsRuntimeService,\n  createProtectedRecordsRuntimeTargetBinding,',
        ['createProtectedRecordsRuntimeService', 'createProtectedRecordsRuntimeTargetBinding'],
      ),
      witness(
        'installed-recognition.definition',
        'export function runProtectedRecordsInstalledRuntimeProfileRecognitionProof(',
        ['export', 'function', 'runProtectedRecordsInstalledRuntimeProfileRecognitionProof'],
      ),
      witness(
        'installed-recognition.guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Installed runtime-profile recognition proof generation',\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'installed-recognition.call-runtime-factory',
        '    const service = createProtectedRecordsRuntimeService({',
        ['createProtectedRecordsRuntimeService'],
      ),
      witness(
        'installed-recognition.call-returned-method',
        '      const result = service.applyRequest({',
        ['service', 'applyRequest'],
      ),
      witness(
        'installed-recognition.verifier-definition',
        'export function verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact(',
        ['export', 'function', 'verifyProtectedRecordsInstalledRuntimeProfileRecognitionProofArtifact'],
      ),
    ]),
  }),
  installed_service: Object.freeze({
    relative_path:
      'lib/protected-records-installed-runtime-profile-service-proof.mjs',
    file_sha256:
      '93c8d4bfce6f985e70ecfbdd6fe526da6305fbf6912e63db77da5fb86fefa009',
    git_blob_oid: '8a98c9db028dde6dacf31ea3886f4da909d04178',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'installed-service.definition',
        'export function runProtectedRecordsInstalledRuntimeProfileServiceProof(',
        ['export', 'function', 'runProtectedRecordsInstalledRuntimeProfileServiceProof'],
      ),
      witness(
        'installed-service.guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Installed runtime-profile service proof generation',\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'installed-service.call-child-helper',
        "    const primaryResults = runRuntimeService(config, primaryRequests, scratch, 'primary');",
        ['runRuntimeService'],
      ),
      witness(
        'installed-service.child-helper-definition',
        'function runRuntimeService(config, requests, scratch, label) {',
        ['function', 'runRuntimeService'],
      ),
      witness(
        'installed-service.child-target-binding',
        "const ZLAR_BIN = fileURLToPath(new URL('../bin/zlar', import.meta.url));",
        ['const', 'ZLAR_BIN', 'fileURLToPath', 'new', 'URL'],
      ),
      witness(
        'installed-service.unresolved-child-spawn',
        "  const run = spawnSync(ZLAR_BIN, ['protected-records-runtime-service', '--config', configPath], {\n    cwd: fileURLToPath(new URL('..', import.meta.url)),\n    encoding: 'utf8',\n    input,\n    env: { ...process.env, NO_COLOR: '1' },\n  });",
        ['spawnSync', 'ZLAR_BIN', 'cwd', 'env', 'process', 'NO_COLOR'],
      ),
      witness(
        'installed-service.verifier-definition',
        'export function verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact(',
        ['export', 'function', 'verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact'],
      ),
    ]),
  }),
  active_lifecycle: Object.freeze({
    relative_path: 'lib/protected-records-active-persistent-profile-lifecycle.mjs',
    file_sha256:
      '85e27bc3552bd403e5bac4e5ab84ee9c4907aa31daf8431c3ceae0561fa7ad99',
    git_blob_oid: '2f55b6ba870dfe6e5f0a61992e888f5bc714722a',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'active-lifecycle.import-action-crossing',
        '  runProtectedRecordsActivePersistentProfileActionCrossing,\n  writeProtectedRecordsActivePersistentProfileActionCrossingReport,\n} from \'./protected-records-active-persistent-profile-action-crossing.mjs\';',
        ['runProtectedRecordsActivePersistentProfileActionCrossing', 'from'],
      ),
      witness(
        'active-lifecycle.import-service-proof',
        '  runProtectedRecordsInstalledRuntimeProfileServiceProof,\n  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,\n} from \'./protected-records-installed-runtime-profile-service-proof.mjs\';',
        ['runProtectedRecordsInstalledRuntimeProfileServiceProof', 'from'],
      ),
      witness(
        'active-lifecycle.run-definition',
        'export function runActivePersistentProfileLifecycleEvidence({',
        ['export', 'function', 'runActivePersistentProfileLifecycleEvidence'],
      ),
      witness(
        'active-lifecycle.guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records active persistent profile lifecycle evidence run'\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'active-lifecycle.call-action-crossing',
        '  const greenReport = runProtectedRecordsActivePersistentProfileActionCrossing({',
        ['runProtectedRecordsActivePersistentProfileActionCrossing'],
      ),
      witness(
        'active-lifecycle.call-red-path',
        '  const redReport = runActivePersistentProfileRedPathRefusal({',
        ['runActivePersistentProfileRedPathRefusal'],
      ),
      witness(
        'active-lifecycle.red-path-definition',
        'export function runActivePersistentProfileRedPathRefusal({',
        ['export', 'function', 'runActivePersistentProfileRedPathRefusal'],
      ),
      witness(
        'active-lifecycle.red-path-guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records active persistent profile red-path evidence run'\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'active-lifecycle.red-path-call-service-proof',
        '  const serviceProof = runProtectedRecordsInstalledRuntimeProfileServiceProof(\n    preflightArtifact,',
        ['runProtectedRecordsInstalledRuntimeProfileServiceProof'],
      ),
      witness(
        'active-lifecycle.call-closeout-path',
        '  const closeoutReport = runActivePersistentProfileCloseoutRefusal({',
        ['runActivePersistentProfileCloseoutRefusal'],
      ),
      witness(
        'active-lifecycle.closeout-definition',
        'export function runActivePersistentProfileCloseoutRefusal({',
        ['export', 'function', 'runActivePersistentProfileCloseoutRefusal'],
      ),
      witness(
        'active-lifecycle.closeout-call-action-crossing',
        '  try {\n    runProtectedRecordsActivePersistentProfileActionCrossing({',
        ['try', 'runProtectedRecordsActivePersistentProfileActionCrossing'],
      ),
      witness(
        'active-lifecycle.report-verifier-definition',
        'export function buildActivePersistentProfileLifecycleReportFromFiles(paths = {}) {',
        ['export', 'function', 'buildActivePersistentProfileLifecycleReportFromFiles'],
      ),
    ]),
  }),
  active_action_crossing: Object.freeze({
    relative_path:
      'lib/protected-records-active-persistent-profile-action-crossing.mjs',
    file_sha256:
      '4260d9abd14cc57aaa06b2470240465ebb0b7af979c935e491ceebccd6f86df1',
    git_blob_oid: '3cb3f199b40471c8c52fb3b5f9880512b362d07d',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'active-action.import-service-proof',
        '  runProtectedRecordsInstalledRuntimeProfileServiceProof,\n  verifyProtectedRecordsInstalledRuntimeProfileServiceProofArtifact,\n} from \'./protected-records-installed-runtime-profile-service-proof.mjs\';',
        ['runProtectedRecordsInstalledRuntimeProfileServiceProof', 'from'],
      ),
      witness(
        'active-action.definition',
        'export function runProtectedRecordsActivePersistentProfileActionCrossing({',
        ['export', 'function', 'runProtectedRecordsActivePersistentProfileActionCrossing'],
      ),
      witness(
        'active-action.guard',
        "  assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(\n    'Protected records active persistent profile action crossing'\n  );",
        ['assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'active-action.call-service-proof',
        '  const serviceProof = runProtectedRecordsInstalledRuntimeProfileServiceProof(',
        ['runProtectedRecordsInstalledRuntimeProfileServiceProof'],
      ),
      witness(
        'active-action.call-proof-target-writer',
        '  const proofTargetMarker = writeProofTargetMarker({',
        ['writeProofTargetMarker'],
      ),
      witness(
        'active-action.proof-target-writer-definition',
        'function writeProofTargetMarker({',
        ['function', 'writeProofTargetMarker'],
      ),
      witness(
        'active-action.e5-sink',
        '  writeFileSync(proofTarget, output, { mode: 0o600 });',
        ['writeFileSync', 'proofTarget'],
      ),
    ]),
  }),
  fixture_authority_status: Object.freeze({
    relative_path: 'lib/protected-records-fixture-authority-status.mjs',
    file_sha256:
      '194cfcb0da405f3deefba95f5ed76e002cef4d067fe7165217ddeaf288078fc4',
    git_blob_oid: '30dfc8992c0423f4e6589b0be3a62d70446705a0',
    git_mode: '100644',
    shebang: null,
    witnesses: Object.freeze([
      witness(
        'fixture-status.guard-definition',
        'export function assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed(',
        ['export', 'function', 'assertProtectedRecordsCurrentFixtureAuthorityGrantFreshEffectAllowed'],
      ),
      witness(
        'fixture-status.source-exhausted',
        "    status: 'exhausted',\n    status_source: 'control-tower-contract-and-execution-evidence-reconciliation',",
        ['status', 'status_source'],
      ),
    ]),
  }),
});

export const SOURCE_BOUND_STATIC_REACHABILITY_SOURCE_PATHS_V0 = Object.freeze(
  Object.fromEntries(
    Object.entries(SOURCE_SPECS).map(([role, spec]) => [role, spec.relative_path]),
  ),
);

function edge(
  edgeId,
  edgeKind,
  fromSymbol,
  toSymbol,
  supportingWitnessIds,
  { status = 'resolved', reason = null, branchPredicate = null } = {},
) {
  return Object.freeze({
    edge_id: edgeId,
    edge_kind: edgeKind,
    from_symbol: fromSymbol,
    to_symbol: toSymbol,
    supporting_witness_ids: Object.freeze(supportingWitnessIds),
    resolution_status: status,
    unresolved_reason: reason,
    branch_predicate: branchPredicate,
  });
}

const EDGE_SPECS = Object.freeze([
  edge('D1', 'shell_dispatch', 'bin/zlar:protected-records-runtime-service', 'runtime-service-cli:top-level', ['dispatch.runtime-service']),
  edge('D2', 'shell_dispatch', 'bin/zlar:protected-records-runtime-profile-proof', 'runtime-profile-proof-cli:top-level', ['dispatch.runtime-profile-proof']),
  edge('D3', 'shell_dispatch', 'bin/zlar:protected-records-runtime-profile-preflight', 'runtime-profile-preflight-cli:top-level', ['dispatch.runtime-profile-preflight']),
  edge('D4', 'shell_dispatch', 'bin/zlar:protected-records-runtime-activation-preflight', 'runtime-activation-preflight-cli:top-level', ['dispatch.runtime-activation-preflight']),
  edge('D5', 'shell_dispatch', 'bin/zlar:protected-records-installed-runtime-profile-recognition-proof', 'installed-recognition-cli:top-level', ['dispatch.installed-recognition-proof']),
  edge('D6', 'shell_dispatch', 'bin/zlar:protected-records-installed-runtime-profile-service-proof', 'installed-service-cli:top-level', ['dispatch.installed-service-proof']),
  edge('D7', 'shell_dispatch', 'bin/zlar:protected-records-active-persistent-profile-lifecycle', 'active-lifecycle-cli:top-level', ['dispatch.active-persistent-lifecycle']),
  edge('R1', 'esm_import_binding_and_direct_call', 'runtime-service-cli:top-level', 'runtime-profile:createProtectedRecordsRuntimeService', ['runtime-service.import-factory', 'runtime-service.call-factory', 'runtime-profile.factory-definition']),
  edge('R2', 'returned_method_binding', 'runtime-profile:createProtectedRecordsRuntimeService', 'runtime-profile:applyRequest-v1', ['runtime-profile.return-method-binding-v1', 'runtime-profile.apply-definition-v1']),
  edge('R3', 'returned_method_call', 'runtime-service-cli:service.applyRequest', 'runtime-profile:applyRequest-v1', ['runtime-service.call-returned-method', 'runtime-profile.apply-definition-v1']),
  edge('R4', 'direct_call', 'runtime-profile:applyRequest-v1', 'runtime-profile:appendRuntimeStateEntry-v1', ['runtime-profile.call-append-v1', 'runtime-profile.append-definition-v1']),
  edge('R5', 'mutation_candidate_sink', 'runtime-profile:appendRuntimeStateEntry-v1', 'E3.legacy-runtime-process-private-state-v1', ['runtime-profile.e3-sink']),
  edge('P1', 'esm_import_binding_and_direct_call', 'runtime-profile-proof-cli:top-level', 'runtime-profile:runProtectedRecordsRuntimeProfileProof', ['runtime-profile-proof.import-runner', 'runtime-profile-proof.call-runner', 'runtime-profile.proof-definition']),
  edge('P2', 'guard', 'runtime-profile:runProtectedRecordsRuntimeProfileProof', 'fixture-status:fresh-effect-guard', ['runtime-profile.proof-guard', 'fixture-status.guard-definition']),
  edge('P3', 'direct_call', 'runtime-profile:runProtectedRecordsRuntimeProfileProof', 'runtime-profile:runRuntimeService', ['runtime-profile.call-child-helper', 'runtime-profile.child-helper-definition']),
  edge('P4', 'child_process', 'runtime-profile:runRuntimeService', 'bin/zlar:protected-records-runtime-service', ['runtime-profile.child-target-binding', 'runtime-profile.unresolved-child-spawn'], {
    status: 'unresolved',
    reason: 'child-environment-inherits-process-env-including-bash-env-exported-shell-functions-path-node-options-and-loader-state',
  }),
  edge('PF1', 'esm_import_binding_and_direct_call', 'runtime-profile-preflight-cli:top-level', 'runtime-preflight:runProtectedRecordsRuntimeProfilePreflight', ['runtime-profile-preflight.import-runner', 'runtime-profile-preflight.call-runner', 'runtime-preflight.definition']),
  edge('PF2', 'guard', 'runtime-preflight:runProtectedRecordsRuntimeProfilePreflight', 'fixture-status:fresh-effect-guard', ['runtime-preflight.guard', 'fixture-status.guard-definition']),
  edge('PF3', 'esm_import_binding_and_direct_call', 'runtime-preflight:runProtectedRecordsRuntimeProfilePreflight', 'runtime-profile:runProtectedRecordsRuntimeProfileProof', ['runtime-preflight.import-proof-runner', 'runtime-preflight.call-proof', 'runtime-profile.proof-definition']),
  edge('A1', 'esm_import_binding_and_direct_call', 'runtime-activation-preflight-cli:top-level', 'runtime-activation:runProtectedRecordsRuntimeActivationPreflight', ['runtime-activation.import-runners', 'runtime-activation.call-runner', 'runtime-activation.definition']),
  edge('A2', 'guard', 'runtime-activation:runProtectedRecordsRuntimeActivationPreflight', 'fixture-status:fresh-effect-guard', ['runtime-activation.guard', 'fixture-status.guard-definition']),
  edge('A3', 'esm_import_binding_and_direct_call', 'runtime-activation:runProtectedRecordsRuntimeActivationPreflight', 'runtime-preflight:runProtectedRecordsRuntimeProfilePreflight', ['runtime-activation.import-profile-preflight-runner', 'runtime-activation.call-preflight', 'runtime-preflight.definition']),
  edge('AV1', 'mode_branch_and_direct_call', 'runtime-activation-preflight-cli:verify-mode', 'runtime-activation:verifyArtifact', ['runtime-activation.import-runners', 'runtime-activation.verify-branch', 'runtime-activation.call-verifier', 'runtime-activation.verifier-definition'], { branchPredicate: "argv[0] === 'verify'" }),
  edge('I1', 'esm_import_binding_and_direct_call', 'installed-recognition-cli:generation-mode', 'installed-recognition:runProof', ['installed-recognition.import-runners', 'installed-recognition.call-runner', 'installed-recognition.definition']),
  edge('I2', 'guard', 'installed-recognition-cli:generation-mode', 'fixture-status:fresh-effect-guard', ['installed-recognition.cli-guard', 'fixture-status.guard-definition']),
  edge('I3', 'guard', 'installed-recognition:runProof', 'fixture-status:fresh-effect-guard', ['installed-recognition.guard', 'fixture-status.guard-definition']),
  edge('I4', 'esm_import_binding_and_direct_call', 'installed-recognition:runProof', 'runtime-profile:createProtectedRecordsRuntimeService', ['installed-recognition.import-runtime-factory', 'installed-recognition.call-runtime-factory', 'runtime-profile.factory-definition']),
  edge('I5', 'returned_method_call', 'installed-recognition:service.applyRequest', 'runtime-profile:applyRequest-v1', ['installed-recognition.call-returned-method', 'runtime-profile.return-method-binding-v1', 'runtime-profile.apply-definition-v1']),
  edge('IV1', 'mode_branch_and_direct_call', 'installed-recognition-cli:verify-mode', 'installed-recognition:verifyArtifact', ['installed-recognition.import-runners', 'installed-recognition.verify-branch', 'installed-recognition.call-verifier', 'installed-recognition.verifier-definition'], { branchPredicate: "argv[0] === 'verify'" }),
  edge('S1', 'esm_import_binding_and_direct_call', 'installed-service-cli:generation-mode', 'installed-service:runProof', ['installed-service.import-runners', 'installed-service.call-runner', 'installed-service.definition']),
  edge('S2', 'guard', 'installed-service-cli:generation-mode', 'fixture-status:fresh-effect-guard', ['installed-service.cli-guard', 'fixture-status.guard-definition']),
  edge('S3', 'guard', 'installed-service:runProof', 'fixture-status:fresh-effect-guard', ['installed-service.guard', 'fixture-status.guard-definition']),
  edge('S4', 'direct_call', 'installed-service:runProof', 'installed-service:runRuntimeService', ['installed-service.call-child-helper', 'installed-service.child-helper-definition']),
  edge('S5', 'child_process', 'installed-service:runRuntimeService', 'bin/zlar:protected-records-runtime-service', ['installed-service.child-target-binding', 'installed-service.unresolved-child-spawn'], {
    status: 'unresolved',
    reason: 'child-environment-inherits-process-env-including-bash-env-exported-shell-functions-path-node-options-and-loader-state',
  }),
  edge('SV1', 'mode_branch_and_direct_call', 'installed-service-cli:verify-mode', 'installed-service:verifyArtifact', ['installed-service.import-runners', 'installed-service.verify-branch', 'installed-service.call-verifier', 'installed-service.verifier-definition'], { branchPredicate: "argv[0] === 'verify'" }),
  edge('L1', 'mode_branch_and_esm_call', 'active-lifecycle-cli:run-mode', 'active-lifecycle:runEvidence', ['active-lifecycle.import-runners', 'active-lifecycle.run-branch', 'active-lifecycle.call-runner', 'active-lifecycle.run-definition'], { branchPredicate: "argv[0] === 'run'" }),
  edge('L2', 'guard', 'active-lifecycle:runEvidence', 'fixture-status:fresh-effect-guard', ['active-lifecycle.guard', 'fixture-status.guard-definition']),
  edge('L3', 'esm_import_binding_and_direct_call', 'active-lifecycle:runEvidence', 'active-action:runCrossing', ['active-lifecycle.import-action-crossing', 'active-lifecycle.call-action-crossing', 'active-action.definition']),
  edge('L4', 'guard', 'active-action:runCrossing', 'fixture-status:fresh-effect-guard', ['active-action.guard', 'fixture-status.guard-definition']),
  edge('L5', 'esm_import_binding_and_direct_call', 'active-action:runCrossing', 'installed-service:runProof', ['active-action.import-service-proof', 'active-action.call-service-proof', 'installed-service.definition']),
  edge('L6', 'direct_call', 'active-action:runCrossing', 'active-action:writeProofTargetMarker', ['active-action.call-proof-target-writer', 'active-action.proof-target-writer-definition']),
  edge('L7', 'mutation_candidate_sink', 'active-action:writeProofTargetMarker', 'E5.active-persistent-proof-target-marker-v1', ['active-action.e5-sink']),
  edge('LR1', 'direct_call', 'active-lifecycle:runEvidence', 'active-lifecycle:runRedPathRefusal', ['active-lifecycle.call-red-path', 'active-lifecycle.red-path-definition']),
  edge('LR2', 'guard', 'active-lifecycle:runRedPathRefusal', 'fixture-status:fresh-effect-guard', ['active-lifecycle.red-path-guard', 'fixture-status.guard-definition']),
  edge('LR3', 'esm_import_binding_and_direct_call', 'active-lifecycle:runRedPathRefusal', 'installed-service:runProof', ['active-lifecycle.import-service-proof', 'active-lifecycle.red-path-call-service-proof', 'installed-service.definition']),
  edge('LC1', 'direct_call', 'active-lifecycle:runEvidence', 'active-lifecycle:runCloseoutRefusal', ['active-lifecycle.call-closeout-path', 'active-lifecycle.closeout-definition']),
  edge('LC2', 'esm_import_binding_and_direct_call', 'active-lifecycle:runCloseoutRefusal', 'active-action:runCrossing', ['active-lifecycle.import-action-crossing', 'active-lifecycle.closeout-call-action-crossing', 'active-action.definition']),
  edge('LV1', 'default_mode_esm_call', 'active-lifecycle-cli:supplied-report-mode', 'active-lifecycle:buildReportFromFiles', ['active-lifecycle.import-runners', 'active-lifecycle.call-report-verifier', 'active-lifecycle.report-verifier-definition'], { branchPredicate: "argv[0] !== 'run' and required report flags supplied" }),
  edge('LV2', 'evidence_write_sink', 'active-lifecycle-cli:supplied-report-mode', 'active-lifecycle:optional-report-file', ['active-lifecycle.optional-report-write'], { branchPredicate: '--report supplied' }),
]);

const MODES = Object.freeze([
  Object.freeze({
    surface_mode_id: 'protected-records-runtime-service.legacy-v1-execution',
    surface_id: 'source-discovered:bin/zlar-protected-records-runtime-service-v1',
    entrypoint: 'bin/zlar-protected-records-runtime-service',
    argv_mode_predicate: 'valid --config whose parsed object is not runtime-service-v2',
    surface_role: 'direct_source_entrypoint',
    relationship_to_selected_path: 'distinct_effect',
    resolution_status: 'resolved_to_existing_node_candidate',
    source_resolved_call_path: true,
    resolved_edge_ids: Object.freeze(['D1', 'R1', 'R2', 'R3', 'R4', 'R5']),
    unresolved_edge_ids: Object.freeze([]),
    source_resolved_existing_node_candidate_ids: Object.freeze([
      'E3.legacy-runtime-process-private-state-v1',
    ]),
    unresolved_expected_node_candidate_ids: Object.freeze([]),
    source_guard_edge_ids: Object.freeze([]),
    coverage_disposition: 'observed_uncovered',
    output_branch_variants: Object.freeze(['stdout-jsonl']),
  }),
  Object.freeze({
    surface_mode_id: 'protected-records-runtime-profile-proof.generate',
    surface_id: 'bin/zlar-protected-records-runtime-profile-proof',
    entrypoint: 'bin/zlar-protected-records-runtime-profile-proof',
    argv_mode_predicate: 'default generation mode with optional --json',
    surface_role: 'proof_generator',
    relationship_to_selected_path: 'wrapper',
    resolution_status: 'unresolved_at_child_environment',
    source_resolved_call_path: false,
    resolved_edge_ids: Object.freeze(['D2', 'P1', 'P2', 'P3']),
    unresolved_edge_ids: Object.freeze(['P4']),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([
      'E3.legacy-runtime-process-private-state-v1',
    ]),
    source_guard_edge_ids: Object.freeze(['P2']),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze(['stdout-summary', 'stdout-json']),
  }),
  Object.freeze({
    surface_mode_id: 'protected-records-runtime-profile-preflight.generate',
    surface_id: 'bin/zlar-protected-records-runtime-profile-preflight',
    entrypoint: 'bin/zlar-protected-records-runtime-profile-preflight',
    argv_mode_predicate: 'generation mode with required --profile',
    surface_role: 'preflight_generator',
    relationship_to_selected_path: 'wrapper',
    resolution_status: 'unresolved_at_nested_child_environment',
    source_resolved_call_path: false,
    resolved_edge_ids: Object.freeze(['D3', 'PF1', 'PF2', 'PF3', 'P2', 'P3']),
    unresolved_edge_ids: Object.freeze(['P4']),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([
      'E3.legacy-runtime-process-private-state-v1',
    ]),
    source_guard_edge_ids: Object.freeze(['PF2', 'P2']),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze(['stdout-summary', 'stdout-json']),
  }),
  Object.freeze({
    surface_mode_id: 'protected-records-runtime-activation-preflight.generate',
    surface_id: 'bin/zlar-protected-records-runtime-activation-preflight',
    entrypoint: 'bin/zlar-protected-records-runtime-activation-preflight',
    argv_mode_predicate: 'non-verify generation mode with required plan and profile',
    surface_role: 'preflight_generator',
    relationship_to_selected_path: 'wrapper',
    resolution_status: 'unresolved_at_nested_child_environment',
    source_resolved_call_path: false,
    resolved_edge_ids: Object.freeze(['D4', 'A1', 'A2', 'A3', 'PF2', 'PF3', 'P2', 'P3']),
    unresolved_edge_ids: Object.freeze(['P4']),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([
      'E3.legacy-runtime-process-private-state-v1',
    ]),
    source_guard_edge_ids: Object.freeze(['A2', 'PF2', 'P2']),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze([
      'stdout-summary',
      'stdout-json',
      'artifact-file-evidence-write',
      'artifact-stdout',
    ]),
  }),
  Object.freeze({
    surface_mode_id: 'protected-records-runtime-activation-preflight.verify',
    surface_id: 'bin/zlar-protected-records-runtime-activation-preflight:verify-mode',
    entrypoint: 'bin/zlar-protected-records-runtime-activation-preflight',
    argv_mode_predicate: "argv[0] === 'verify'",
    surface_role: 'verification_candidate_import_time_closure_open',
    relationship_to_selected_path: 'unclassified',
    resolution_status: 'resolved_to_verifier_sink_import_time_closure_open',
    source_resolved_call_path: true,
    resolved_edge_ids: Object.freeze(['D4', 'AV1']),
    unresolved_edge_ids: Object.freeze([]),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([]),
    source_guard_edge_ids: Object.freeze([]),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze(['stdout-summary', 'stdout-json']),
  }),
  Object.freeze({
    surface_mode_id:
      'protected-records-installed-runtime-profile-recognition-proof.generate',
    surface_id:
      'bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
    entrypoint:
      'bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
    argv_mode_predicate: 'non-verify generation mode with one source artifact',
    surface_role: 'proof_generator',
    relationship_to_selected_path: 'wrapper',
    resolution_status: 'resolved_to_existing_node_candidate',
    source_resolved_call_path: true,
    resolved_edge_ids: Object.freeze(['D5', 'I2', 'I1', 'I3', 'I4', 'R2', 'I5', 'R4', 'R5']),
    unresolved_edge_ids: Object.freeze([]),
    source_resolved_existing_node_candidate_ids: Object.freeze([
      'E3.legacy-runtime-process-private-state-v1',
    ]),
    unresolved_expected_node_candidate_ids: Object.freeze([]),
    source_guard_edge_ids: Object.freeze(['I2', 'I3']),
    coverage_disposition: 'observed_uncovered',
    output_branch_variants: Object.freeze([
      'stdout-summary',
      'stdout-json',
      'artifact-file-evidence-write',
      'artifact-stdout',
    ]),
  }),
  Object.freeze({
    surface_mode_id:
      'protected-records-installed-runtime-profile-recognition-proof.verify',
    surface_id:
      'bin/zlar-protected-records-installed-runtime-profile-recognition-proof:verify-mode',
    entrypoint:
      'bin/zlar-protected-records-installed-runtime-profile-recognition-proof',
    argv_mode_predicate: "argv[0] === 'verify'",
    surface_role: 'verification_candidate_import_time_closure_open',
    relationship_to_selected_path: 'unclassified',
    resolution_status: 'resolved_to_verifier_sink_import_time_closure_open',
    source_resolved_call_path: true,
    resolved_edge_ids: Object.freeze(['D5', 'IV1']),
    unresolved_edge_ids: Object.freeze([]),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([]),
    source_guard_edge_ids: Object.freeze([]),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze(['stdout-summary', 'stdout-json']),
  }),
  Object.freeze({
    surface_mode_id:
      'protected-records-installed-runtime-profile-service-proof.generate',
    surface_id: 'bin/zlar-protected-records-installed-runtime-profile-service-proof',
    entrypoint: 'bin/zlar-protected-records-installed-runtime-profile-service-proof',
    argv_mode_predicate: 'non-verify generation mode with one source artifact',
    surface_role: 'proof_generator',
    relationship_to_selected_path: 'wrapper',
    resolution_status: 'unresolved_at_child_environment',
    source_resolved_call_path: false,
    resolved_edge_ids: Object.freeze(['D6', 'S2', 'S1', 'S3', 'S4']),
    unresolved_edge_ids: Object.freeze(['S5']),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([
      'E3.legacy-runtime-process-private-state-v1',
    ]),
    source_guard_edge_ids: Object.freeze(['S2', 'S3']),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze([
      'stdout-summary',
      'stdout-json',
      'artifact-file-evidence-write',
      'artifact-stdout',
    ]),
  }),
  Object.freeze({
    surface_mode_id:
      'protected-records-installed-runtime-profile-service-proof.verify',
    surface_id:
      'bin/zlar-protected-records-installed-runtime-profile-service-proof:verify-mode',
    entrypoint: 'bin/zlar-protected-records-installed-runtime-profile-service-proof',
    argv_mode_predicate: "argv[0] === 'verify'",
    surface_role: 'verification_candidate_import_time_closure_open',
    relationship_to_selected_path: 'unclassified',
    resolution_status: 'resolved_to_verifier_sink_import_time_closure_open',
    source_resolved_call_path: true,
    resolved_edge_ids: Object.freeze(['D6', 'SV1']),
    unresolved_edge_ids: Object.freeze([]),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([]),
    source_guard_edge_ids: Object.freeze([]),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze(['stdout-summary', 'stdout-json']),
  }),
  Object.freeze({
    surface_mode_id: 'protected-records-active-persistent-profile-lifecycle.run',
    surface_id: 'bin/zlar-protected-records-active-persistent-profile-lifecycle:run',
    entrypoint: 'bin/zlar-protected-records-active-persistent-profile-lifecycle',
    argv_mode_predicate: "argv[0] === 'run'",
    surface_role: 'lifecycle_evidence_generator',
    relationship_to_selected_path: 'wrapper',
    resolution_status: 'resolved_to_mixed_existing_and_unresolved_candidate_sinks',
    source_resolved_call_path: true,
    resolved_edge_ids: Object.freeze([
      'D7',
      'L1',
      'L2',
      'L3',
      'L4',
      'L5',
      'S3',
      'S4',
      'L6',
      'L7',
      'LR1',
      'LR2',
      'LR3',
      'LC1',
      'LC2',
    ]),
    unresolved_edge_ids: Object.freeze(['S5']),
    branch_steps: Object.freeze([
      Object.freeze({
        branch_id: 'green-action-crossing',
        ordered_edge_steps: Object.freeze([
          Object.freeze({ edge_id: 'D7', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L1', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L2', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L3', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L4', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L5', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S3', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S4', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S5', expected_status: 'unresolved' }),
          Object.freeze({ edge_id: 'L6', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L7', expected_status: 'resolved' }),
        ]),
        source_resolved_existing_node_candidate_ids: Object.freeze([
          'E5.active-persistent-proof-target-marker-v1',
        ]),
        unresolved_expected_node_candidate_ids: Object.freeze([
          'E3.legacy-runtime-process-private-state-v1',
        ]),
      }),
      Object.freeze({
        branch_id: 'red-path-evidence',
        ordered_edge_steps: Object.freeze([
          Object.freeze({ edge_id: 'D7', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L1', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L2', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'LR1', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'LR2', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'LR3', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S3', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S4', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S5', expected_status: 'unresolved' }),
        ]),
        source_resolved_existing_node_candidate_ids: Object.freeze([]),
        unresolved_expected_node_candidate_ids: Object.freeze([
          'E3.legacy-runtime-process-private-state-v1',
        ]),
      }),
      Object.freeze({
        branch_id: 'post-closeout-expected-refusal-probe',
        ordered_edge_steps: Object.freeze([
          Object.freeze({ edge_id: 'D7', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L1', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L2', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'LC1', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'LC2', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L4', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L5', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S3', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S4', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'S5', expected_status: 'unresolved' }),
          Object.freeze({ edge_id: 'L6', expected_status: 'resolved' }),
          Object.freeze({ edge_id: 'L7', expected_status: 'resolved' }),
        ]),
        source_resolved_existing_node_candidate_ids: Object.freeze([
          'E5.active-persistent-proof-target-marker-v1',
        ]),
        unresolved_expected_node_candidate_ids: Object.freeze([
          'E3.legacy-runtime-process-private-state-v1',
        ]),
        current_refusal_behavior_proven: false,
      }),
    ]),
    source_resolved_existing_node_candidate_ids: Object.freeze([
      'E5.active-persistent-proof-target-marker-v1',
    ]),
    unresolved_expected_node_candidate_ids: Object.freeze([
      'E3.legacy-runtime-process-private-state-v1',
    ]),
    source_guard_edge_ids: Object.freeze(['L2', 'L4', 'LR2', 'S3']),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze([
      'stdout-summary',
      'stdout-json',
      'governance-and-evidence-file-writes',
    ]),
  }),
  Object.freeze({
    surface_mode_id:
      'protected-records-active-persistent-profile-lifecycle.verify-supplied-reports',
    surface_id:
      'bin/zlar-protected-records-active-persistent-profile-lifecycle:supplied-report-mode',
    entrypoint: 'bin/zlar-protected-records-active-persistent-profile-lifecycle',
    argv_mode_predicate: "argv[0] !== 'run' with four required report flags",
    surface_role: 'verification_candidate_import_time_closure_open',
    relationship_to_selected_path: 'unclassified',
    resolution_status: 'resolved_to_verifier_sink_import_time_closure_open',
    source_resolved_call_path: true,
    resolved_edge_ids: Object.freeze(['D7', 'LV1']),
    unresolved_edge_ids: Object.freeze([]),
    source_resolved_existing_node_candidate_ids: Object.freeze([]),
    unresolved_expected_node_candidate_ids: Object.freeze([]),
    source_guard_edge_ids: Object.freeze([]),
    coverage_disposition: 'unclassified',
    output_branch_variants: Object.freeze([
      'stdout-summary',
      'stdout-json',
      'optional-report-file-evidence-write',
    ]),
  }),
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(label, value, expectedKeys) {
  assert(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  assert(
    canonicalize(actual) === canonicalize(expected),
    `${label} keys do not match the exact schema`,
  );
}

function lineAt(text, byteOffset) {
  return text.slice(0, byteOffset).split('\n').length;
}

function occurrenceOffsets(text, needle) {
  const offsets = [];
  let cursor = 0;
  while (cursor <= text.length - needle.length) {
    const index = text.indexOf(needle, cursor);
    if (index === -1) break;
    offsets.push(index);
    cursor = index + Math.max(1, needle.length);
  }
  return offsets;
}

function regexCanStart(previousToken) {
  return (
    previousToken === '' ||
    [
      '(',
      '[',
      '{',
      ',',
      ':',
      ';',
      '=',
      '!',
      '?',
      '&',
      '|',
      '+',
      '-',
      '*',
      '%',
      '^',
      '~',
      '<',
      '>',
      '=>',
      'return',
      'throw',
      'case',
      'delete',
      'void',
      'typeof',
      'yield',
      'await',
      'else',
      'do',
      'in',
      'of',
      'instanceof',
      'new',
    ].includes(previousToken)
  );
}

// Conservative lexical mask. String, comment, template and likely-regex bytes are
// replaced with spaces while byte offsets and newlines are preserved. Template
// expressions are deliberately masked too; unsupported constructs must not create
// a positive edge.
export function maskJavaScriptNonCodeV0(source) {
  assert(typeof source === 'string', 'JavaScript source must be text');
  const chars = [...source];
  const out = [...source];
  let state = 'code';
  let escaped = false;
  let regexClass = false;
  let previousToken = '';
  let identifier = '';

  function flushIdentifier() {
    if (identifier) {
      previousToken = identifier;
      identifier = '';
    }
  }

  function mask(index) {
    if (out[index] !== '\n' && out[index] !== '\r') out[index] = ' ';
  }

  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index];
    const next = chars[index + 1] || '';
    if (state === 'line-comment') {
      mask(index);
      if (char === '\n') state = 'code';
      continue;
    }
    if (state === 'block-comment') {
      mask(index);
      if (char === '*' && next === '/') {
        mask(index + 1);
        index += 1;
        state = 'code';
      }
      continue;
    }
    if (state === 'single' || state === 'double' || state === 'template') {
      mask(index);
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (
        (state === 'single' && char === "'") ||
        (state === 'double' && char === '"') ||
        (state === 'template' && char === '`')
      ) {
        state = 'code';
        previousToken = 'value';
      }
      continue;
    }
    if (state === 'regex') {
      mask(index);
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (char === '[') regexClass = true;
      if (char === ']') regexClass = false;
      if (char === '/' && !regexClass) {
        while (/[a-z]/i.test(chars[index + 1] || '')) {
          mask(index + 1);
          index += 1;
        }
        state = 'code';
        previousToken = 'value';
      }
      continue;
    }

    if (/[A-Za-z0-9_$]/.test(char)) {
      identifier += char;
      continue;
    }
    flushIdentifier();
    if (char === '/' && next === '/') {
      mask(index);
      mask(index + 1);
      index += 1;
      state = 'line-comment';
      continue;
    }
    if (char === '/' && next === '*') {
      mask(index);
      mask(index + 1);
      index += 1;
      state = 'block-comment';
      continue;
    }
    if (char === "'") {
      mask(index);
      state = 'single';
      continue;
    }
    if (char === '"') {
      mask(index);
      state = 'double';
      continue;
    }
    if (char === '`') {
      mask(index);
      state = 'template';
      continue;
    }
    if (char === '/' && regexCanStart(previousToken)) {
      mask(index);
      state = 'regex';
      regexClass = false;
      continue;
    }
    if (!/\s/.test(char)) {
      previousToken = char === '>' && chars[index - 1] === '=' ? '=>' : char;
    }
  }
  flushIdentifier();
  assert(state !== 'block-comment', 'JavaScript source contains an unterminated block comment');
  assert(!['single', 'double', 'template', 'regex'].includes(state), 'JavaScript source contains an unterminated literal');
  return out.join('');
}

export function validateExactSourceWitnessesV0({
  relativePath,
  rawBytes,
  expectedFileSha256,
  witnesses,
  javascript = true,
}) {
  assert(typeof relativePath === 'string' && relativePath.length > 0, 'Source path is required');
  assert(Buffer.isBuffer(rawBytes), `${relativePath} must be supplied as inert bytes`);
  assert(SHA256_RE.test(expectedFileSha256), `${relativePath} expected SHA-256 is invalid`);
  const actualSha = sha256hex(rawBytes);
  assert(actualSha === expectedFileSha256, `${relativePath} full-file SHA-256 mismatch`);
  const text = rawBytes.toString('utf8');
  assert(Buffer.from(text, 'utf8').equals(rawBytes), `${relativePath} is not canonical UTF-8 text`);
  assert(!text.includes('\0'), `${relativePath} contains a NUL byte`);
  const codeMask = javascript ? maskJavaScriptNonCodeV0(text) : null;
  const ids = new Set();
  return witnesses.map((item) => {
    assert(!ids.has(item.id), `${relativePath} repeats witness id ${item.id}`);
    ids.add(item.id);
    const offsets = occurrenceOffsets(text, item.needle);
    assert(offsets.length === 1, `${relativePath} witness ${item.id} must occur exactly once`);
    const start = offsets[0];
    const end = start + item.needle.length;
    if (javascript) {
      const maskedRange = codeMask.slice(start, end);
      for (const anchor of item.code_anchors) {
        assert(
          maskedRange.includes(anchor),
          `${relativePath} witness ${item.id} code anchor ${anchor} is not executable lexical code`,
        );
      }
    }
    return {
      witness_id: item.id,
      relative_path: relativePath,
      byte_start: Buffer.byteLength(text.slice(0, start), 'utf8'),
      byte_end_exclusive: Buffer.byteLength(text.slice(0, end), 'utf8'),
      line_start: lineAt(text, start),
      line_end: lineAt(text, Math.max(start, end - 1)),
      exact_range_sha256: sha256hex(Buffer.from(item.needle, 'utf8')),
      code_anchor_count: item.code_anchors.length,
      exact_occurrence_count: 1,
    };
  });
}

function parseParent(parentRawBytes) {
  assert(Buffer.isBuffer(parentRawBytes), 'Immutable parent map must be supplied as bytes');
  const parentFileSha = sha256hex(parentRawBytes);
  assert(parentFileSha === PARENT_FILE_SHA256, 'Immutable parent map file SHA-256 mismatch');
  let parent;
  try {
    parent = JSON.parse(parentRawBytes.toString('utf8'));
  } catch {
    throw new Error('Immutable parent map is not valid JSON');
  }
  assert(parent.artifact_type === 'zlar.consequence-path-coverage-dependency-map.v0', 'Immutable parent artifact type mismatch');
  assert(parent.schema_version === 0, 'Immutable parent schema version mismatch');
  assert(parent.integrity?.body_sha256 === PARENT_BODY_SHA256, 'Immutable parent recorded body SHA-256 mismatch');
  const { integrity, ...body } = parent;
  assert(sha256hex(canonicalize(body)) === PARENT_BODY_SHA256, 'Immutable parent self-integrity mismatch');
  assert(parent.map_status === 'mapped_open', 'Immutable parent must remain mapped_open');
  assert(parent.domain_inventory_complete === false, 'Immutable parent domain inventory unexpectedly closed');
  assert(parent.equivalent_route_closure === false, 'Immutable parent equivalent-route closure unexpectedly true');
  assert(parent.closure?.lifecycle_closed === false, 'Immutable parent lifecycle unexpectedly closed');
  assert(parent.source_binding?.dependency_map_source_commit_oid === ANALYZED_SOURCE_COMMIT, 'Immutable parent source commit mismatch');
  assert(parent.source_binding?.source_inventory_sha256 === PARENT_SOURCE_INVENTORY_SHA256, 'Immutable parent source inventory mismatch');
  assert(parent.domain_inventory?.source_observed_surface_count === 24, 'Immutable parent surface count mismatch');
  assert(parent.domain_inventory?.known_static_uncatalogued_wrapper_count === 6, 'Immutable parent uncatalogued count mismatch');
  assert(parent.domain_inventory?.unresolved_surface_count === 30, 'Immutable parent unresolved count mismatch');
  assert(parent.topology_model?.source_projected_mutation_node_candidate_count === 5, 'Immutable parent node-candidate count mismatch');
  assert(
    canonicalize(
      parent.topology_model.effect_nodes
        .map((item) => item.effect_node_id)
        .sort(),
    ) ===
      canonicalize(
        [
          'E1.adapter-ledger-append-v1',
          'E2.service-jsonl-state-append-v1',
          'E3.legacy-runtime-process-private-state-v1',
          'E4.replacement-runtime-process-private-state-v2',
          'E5.active-persistent-proof-target-marker-v1',
        ].sort(),
      ),
    'Immutable parent effect-node candidate identities mismatch',
  );
  assert(parent.domain_inventory?.authorized_outside_coverage_count === 0, 'Immutable parent outside-coverage count mismatch');
  const parentWrappers = parent.topology_model.known_static_wrappers_not_catalogued;
  assert(Array.isArray(parentWrappers), 'Immutable parent wrapper inventory missing');
  assert(
    canonicalize(parentWrappers.map((item) => item.executable_entrypoint).sort()) ===
      canonicalize([...PARENT_WRAPPER_ENTRYPOINTS].sort()),
    'Immutable parent wrapper entrypoints mismatch',
  );
  for (const item of parentWrappers) {
    assert(
      item.surface_id === `known-static-uncatalogued:${item.executable_entrypoint}`,
      'Immutable parent wrapper surface identity mismatch',
    );
  }
  assert(
    parent.topology_model.surfaces.some(
      (item) =>
        item.surface_id ===
          'source-discovered:bin/zlar-protected-records-runtime-service-v1' &&
        item.entrypoint_reference === 'bin/zlar-protected-records-runtime-service',
    ),
    'Immutable parent direct legacy-v1 surface mismatch',
  );
  for (const [name, expected] of Object.entries(INHERITED_DEPENDENCY_PINS)) {
    const actual = parent.caller_pinned_dependencies?.[name];
    assert(actual && typeof actual === 'object', `Immutable parent missing inherited dependency ${name}`);
    for (const [key, value] of Object.entries(expected)) {
      assert(actual[key] === value, `Immutable parent inherited dependency ${name}.${key} mismatch`);
    }
  }
  return parent;
}

function sourceInventory(sourceFiles) {
  const suppliedRoles = Object.keys(sourceFiles).sort();
  const requiredRoles = Object.keys(SOURCE_SPECS).sort();
  assert(canonicalize(suppliedRoles) === canonicalize(requiredRoles), 'Supplied source roles do not match the exact source inventory');
  const allWitnesses = [];
  const files = [];
  const witnessIds = new Set();
  for (const role of requiredRoles) {
    const spec = SOURCE_SPECS[role];
    const raw = sourceFiles[role];
    const found = validateExactSourceWitnessesV0({
      relativePath: spec.relative_path,
      rawBytes: raw,
      expectedFileSha256: spec.file_sha256,
      witnesses: spec.witnesses,
      javascript: spec.relative_path !== 'bin/zlar',
    });
    const text = raw.toString('utf8');
    if (spec.shebang !== null) {
      assert(text.startsWith(`${spec.shebang}\n`), `${spec.relative_path} shebang mismatch`);
    }
    for (const item of found) {
      assert(!witnessIds.has(item.witness_id), `Duplicate global witness id ${item.witness_id}`);
      witnessIds.add(item.witness_id);
      allWitnesses.push(item);
    }
    files.push({
      role,
      relative_path: spec.relative_path,
      file_sha256: spec.file_sha256,
      byte_length: raw.length,
      git_blob_oid: spec.git_blob_oid,
      git_mode: spec.git_mode,
      git_identity_source: 'caller-pinned-controller-observation-not-evaluated-by-pure-analyzer',
      shebang: spec.shebang,
      exact_witness_count: found.length,
    });
  }
  files.sort((a, b) => a.relative_path.localeCompare(b.relative_path));
  allWitnesses.sort((a, b) => a.witness_id.localeCompare(b.witness_id));
  const inventorySha256 = sha256hex(canonicalize(files));
  return { files, witnesses: allWitnesses, inventorySha256, witnessIds };
}

function resolvedEdges(witnessIds) {
  const edgeIds = new Set();
  return EDGE_SPECS.map((item, index) => {
    assert(!edgeIds.has(item.edge_id), `Duplicate edge id ${item.edge_id}`);
    edgeIds.add(item.edge_id);
    for (const id of item.supporting_witness_ids) {
      assert(witnessIds.has(id), `Edge ${item.edge_id} references missing witness ${id}`);
    }
    return { ordinal: index + 1, ...item };
  });
}

function modeResults(edgeRecords) {
  const edgeMap = new Map(edgeRecords.map((item) => [item.edge_id, item]));
  const modeIds = new Set();
  return MODES.map((mode) => {
    const { branch_steps: declaredBranchSteps, ...modeFields } = mode;
    assert(!modeIds.has(mode.surface_mode_id), `Duplicate mode ${mode.surface_mode_id}`);
    modeIds.add(mode.surface_mode_id);
    for (const id of mode.resolved_edge_ids) {
      const item = edgeMap.get(id);
      assert(item, `${mode.surface_mode_id} references missing resolved edge ${id}`);
      assert(item.resolution_status === 'resolved', `${mode.surface_mode_id} treats unresolved edge ${id} as resolved`);
    }
    for (const id of mode.unresolved_edge_ids) {
      const item = edgeMap.get(id);
      assert(item, `${mode.surface_mode_id} references missing unresolved edge ${id}`);
      assert(item.resolution_status === 'unresolved', `${mode.surface_mode_id} treats resolved edge ${id} as unresolved`);
    }
    const verificationCandidate = mode.surface_role.startsWith('verification_candidate');
    assert(
      !verificationCandidate || mode.source_resolved_existing_node_candidate_ids.length === 0,
      `${mode.surface_mode_id} verification candidate cannot project a target node`,
    );
    const directLegacy =
      mode.surface_mode_id ===
      'protected-records-runtime-service.legacy-v1-execution';
    assert(
      directLegacy || PARENT_WRAPPER_ENTRYPOINTS.includes(mode.entrypoint),
      `${mode.surface_mode_id} has no exact immutable-parent surface`,
    );
    const parentSurfaceId = directLegacy
      ? 'source-discovered:bin/zlar-protected-records-runtime-service-v1'
      : `known-static-uncatalogued:${mode.entrypoint}`;
    const sourcePathBranches = (
      declaredBranchSteps || [
        {
          branch_id: 'selected-mode-call-path',
          ordered_edge_steps: [
            ...mode.resolved_edge_ids.map((edgeId) => ({
              edge_id: edgeId,
              expected_status: 'resolved',
            })),
            ...mode.unresolved_edge_ids.map((edgeId) => ({
              edge_id: edgeId,
              expected_status: 'unresolved',
            })),
          ],
          source_resolved_existing_node_candidate_ids:
            mode.source_resolved_existing_node_candidate_ids,
          unresolved_expected_node_candidate_ids:
            mode.unresolved_expected_node_candidate_ids,
        },
      ]
    ).map((branch) => {
      assert(branch.ordered_edge_steps.length > 0, `${mode.surface_mode_id} has an empty branch`);
      for (const step of branch.ordered_edge_steps) {
        const item = edgeMap.get(step.edge_id);
        assert(item, `${mode.surface_mode_id} branch references missing edge ${step.edge_id}`);
        assert(
          item.resolution_status === step.expected_status,
          `${mode.surface_mode_id} branch status mismatch for ${step.edge_id}`,
        );
        assert(
          mode.resolved_edge_ids.includes(step.edge_id) ||
            mode.unresolved_edge_ids.includes(step.edge_id),
          `${mode.surface_mode_id} branch edge ${step.edge_id} is absent from its edge sets`,
        );
      }
      return {
        ...branch,
        current_refusal_behavior_proven: false,
        runtime_reachability_proven: false,
        effect_occurrence_proven: false,
      };
    });
    return {
      ...modeFields,
      surface_id: parentSurfaceId,
      parent_surface_reference: {
        container: directLegacy
          ? 'topology_model.surfaces'
          : 'topology_model.known_static_wrappers_not_catalogued',
        surface_id: parentSurfaceId,
        executable_entrypoint: mode.entrypoint,
        parent_route_existence_proven: false,
        parent_effect_capability_proven: false,
        parent_coverage_disposition: directLegacy
          ? 'observed_uncovered'
          : 'unclassified',
      },
      reached_node_relationship_to_selected_path:
        mode.source_resolved_existing_node_candidate_ids.length > 0 ||
        mode.unresolved_expected_node_candidate_ids.length > 0
          ? 'distinct_effect'
          : 'unclassified',
      source_path_branches: sourcePathBranches,
      source_resolution_basis:
        'human-reviewed-exact-byte-edge-certificate-not-general-ast-or-cfg-derivation',
      source_resolution_mechanically_derived: false,
      main_dispatch_source_edge_resolved: true,
      dispatcher_interpreter_identity_resolved: false,
      entrypoint_interpreter_identity_resolved: false,
      import_time_side_effect_closure_complete: false,
      source_refusal_dominance: {
        status: mode.source_guard_edge_ids.length
          ? 'not_proven_import_time_closure_open'
          : 'not_applicable_or_not_proven',
        all_candidate_paths_guarded: false,
        guard_precedes_observed_in_function_candidate_call: mode.source_guard_edge_ids.length > 0,
        import_time_candidate_sink_before_guard_ruled_out: false,
        current_refusal_behavior_proven: false,
      },
      adds_new_effect_exit: false,
      runtime_reachability_proven: false,
      effect_capability_proven: false,
      effect_occurrence_proven: false,
      current_refusal_behavior_proven: false,
      authority_domain_membership_proven: false,
      current_authority_projected: false,
      authorized_outside_coverage: false,
      governed_lifecycle_proven: false,
      evidence_freshness: 'caller-pinned-exact-source-edge-resolution',
    };
  });
}

export function sourceBoundStaticReachabilitySourceInventorySha256V0(sourceFiles) {
  return sourceInventory(sourceFiles).inventorySha256;
}

export function buildSourceBoundStaticReachabilityDeltaV0({
  parentRawBytes,
  sourceFiles,
  expectedParentFileSha256,
  expectedParentBodySha256,
  expectedAnalyzedSourceCommitOid,
  expectedSourceInventorySha256,
}) {
  assert(expectedParentFileSha256 === PARENT_FILE_SHA256, 'Caller parent file SHA-256 pin mismatch');
  assert(expectedParentBodySha256 === PARENT_BODY_SHA256, 'Caller parent body SHA-256 pin mismatch');
  assert(GIT_SHA1_RE.test(expectedAnalyzedSourceCommitOid), 'Caller source commit must be a Git SHA-1');
  assert(expectedAnalyzedSourceCommitOid === ANALYZED_SOURCE_COMMIT, 'Caller analyzed source commit pin mismatch');
  assert(SHA256_RE.test(expectedSourceInventorySha256), 'Caller source inventory SHA-256 is invalid');
  parseParent(parentRawBytes);
  const inventory = sourceInventory(sourceFiles);
  assert(inventory.inventorySha256 === expectedSourceInventorySha256, 'Caller source inventory SHA-256 mismatch');
  const edges = resolvedEdges(inventory.witnessIds);
  const modes = modeResults(edges);
  const resolvedMutationModes = modes.filter(
    (item) => item.source_resolved_existing_node_candidate_ids.length > 0,
  );
  const unresolvedMutationModes = modes.filter(
    (item) => item.unresolved_expected_node_candidate_ids.length > 0,
  );
  const verifierModes = modes.filter((item) =>
    item.resolution_status.startsWith('resolved_to_verifier_sink'),
  );

  const body = {
    action_class: ACTION_CLASS,
    analysis_contract: {
      implementation_kind: 'version-specific-exact-edge-certificate-validator',
      general_javascript_control_flow_analyzer: false,
      exact_full_file_sha_required: true,
      exact_source_span_sha_required: true,
      comments_strings_and_templates_masked_for_code_anchors: true,
      recognized_regex_contexts_masked_for_code_anchors: true,
      regex_lexical_closure_complete: false,
      edge_semantics_machine_derived_from_general_ast_or_cfg: false,
      edge_semantics_basis:
        'human-reviewed-version-specific-certificate-over-exact-pinned-bytes',
      unsupported_source_drift_policy: 'fail_closed',
      child_process_resolution_rule:
        'command-arguments-cwd-environment-and-source-bound-target-must-all-be-exact',
      inherited_process_environment_resolves_child_edge: false,
      target_modules_imported_or_executed: false,
      git_invoked_by_analyzer: false,
      source_files_written: false,
    },
    artifact_type: SOURCE_BOUND_STATIC_REACHABILITY_DELTA_TYPE_V0,
    authority_domain_context: AUTHORITY_DOMAIN,
    authority_domain_evaluated: false,
    canonicalization: 'ZLAR canonical JSON v1',
    claim_boundary: {
      all_surface_governance: false,
      crash_atomicity: false,
      current_authority: false,
      current_machine_governance: false,
      current_refusal_behavior: false,
      domain_inventory_completeness: false,
      effect_capability: false,
      effect_occurrence: false,
      enterprise_readiness: false,
      equivalent_route_closure: false,
      exactly_once_effect: false,
      lifecycle_closure: false,
      production_governance: false,
      public_external_attestation: false,
      rightful_issuance: false,
      runtime_reachability: false,
      same_route_closeout: false,
      side_door_closure: false,
      sovereign_recognition: false,
    },
    decision: {
      implementation_gate: 'go_new_source_resolved_call_path_evidence',
      exact_positive_delta:
        'A human-reviewed certificate over exact pinned source bytes records three modes with paths to existing parent mutation-node candidates: direct legacy runtime-v1 and installed recognition generation lead to E3; active lifecycle run contains green and closeout-probe paths leading syntactically to E5. Two unique inherited-environment child boundaries affect five modes. Four supplied-artifact modes end at verifier sinks while import-time closure remains open.',
      new_effect_exit_proven: false,
      parent_mutation_required: false,
    },
    dependency_map_delta: {
      additive_only: true,
      parent_regenerated: false,
      parent_mutated: false,
      new_effect_node_ids: [],
      existing_source_resolved_node_candidate_ids: [
        'E3.legacy-runtime-process-private-state-v1',
        'E5.active-persistent-proof-target-marker-v1',
      ],
      unresolved_expected_node_candidate_ids: [
        'E3.legacy-runtime-process-private-state-v1',
      ],
      selected_node_e4_reached_by_any_analyzed_mode: false,
      wrappers_counted_as_effect_exits: false,
      evidence_writes_counted_as_target_mutations: false,
      output_branch_variants_counted_as_distinct_routes: false,
      before_after_claim_delta: {
        before: 'parent route_existence_proven=false and six wrappers not mode-resolved',
        after:
          'exact source-bound mode call paths, verifier paths and strict child-boundary failures recorded; runtime and effect claims unchanged false',
      },
    },
    edge_certificates: edges,
    hash_scope: 'canonical delta body without integrity',
    immutable_parent_binding: {
      artifact_type: 'zlar.consequence-path-coverage-dependency-map.v0',
      file_sha256: PARENT_FILE_SHA256,
      body_sha256: PARENT_BODY_SHA256,
      source_commit_oid: ANALYZED_SOURCE_COMMIT,
      source_inventory_sha256: PARENT_SOURCE_INVENTORY_SHA256,
      map_status: 'mapped_open',
      parent_exact_bytes_validated: true,
      parent_self_integrity_validated: true,
      parent_selected_boundary_fields_validated: true,
      parent_full_schema_validated: false,
      parent_claim_strings_evaluated: false,
      inherited_dependency_pins_validated_inside_parent: true,
      underlying_parent_dependency_bytes_reloaded: false,
      parent_mutated: false,
      parent_regenerated: false,
    },
    inventory_posture_after: {
      parent_catalogued_surface_count_preserved: 24,
      parent_known_static_uncatalogued_count_preserved: 6,
      parent_unresolved_surface_count_preserved: 30,
      parent_mutation_node_candidate_count_preserved: 5,
      delta_mode_count: modes.length,
      delta_source_resolved_mutation_candidate_mode_count: resolvedMutationModes.length,
      delta_unresolved_mutation_candidate_mode_count: unresolvedMutationModes.length,
      delta_resolved_verifier_sink_mode_count: verifierModes.length,
      domain_inventory_recomputed: false,
      domain_inventory_complete: false,
      equivalent_route_closure: false,
      lifecycle_status: 'mapped_open',
    },
    map_status: 'mapped_open',
    mode_results: modes,
    non_claims: [
      'A source-resolved call path is a fact about exact inert bytes at one caller-pinned commit; it is not runtime reachability, effect capability, effect occurrence, current refusal behavior, authority-domain membership, current authority, or governed coverage.',
      'E3 and E5 remain parent mutation-node candidates. This delta neither promotes them to proven effect exits nor creates a new effect node.',
      'Inherited process.env makes the runtime-profile and installed-service child-process edges unresolved, including BASH_ENV, exported shell functions, PATH, NODE_OPTIONS, loader, preload and interpreter state.',
      'Verification-mode call paths end at verifiers, but imported generation-capable modules execute before argv branching and their transitive import-time side-effect closure was not proven.',
      'Observed freshness guards do not establish source-refusal dominance because complete import-time and alternate-path closure was not proven.',
      'The analyzer does not invoke Git. Commit, blob and mode identities are caller-pinned controller observations cross-bound to exact loaded file SHA-256 values.',
      'Edge semantics are a human-reviewed, version-specific certificate over exact pinned bytes; the validator does not independently derive symbol scope, dead-code reachability, shadowing, alias or re-export closure from a general AST or CFG.',
      'The conservative lexical mask recognizes common regular-expression contexts but does not prove complete JavaScript regular-expression lexical closure.',
      'The delta does not prove domain completeness, equivalent-route closure, lifecycle closure, same-route closeout, rightful issuance, exactly-once, crash atomicity, recovery, side-door closure, current-machine governance, production, enterprise readiness, public attestation, sovereign recognition, or all-surface governance.',
    ],
    safe_claim_ceiling:
      'Over exact loaded source bytes caller-pinned to commit e7c621927df35eb31cf3f0dfc1ea2a42df6d5dd5, a human-reviewed additive exact-edge certificate records three modes with source paths to existing parent mutation-node candidates, two unique inherited-environment child boundaries affecting five modes, and four selected modes ending at verifier sinks. No runtime, effect, authority, domain, refusal, closure, or completeness claim moves.',
    schema_version: SOURCE_BOUND_STATIC_REACHABILITY_DELTA_VERSION_V0,
    selected_consequence_path_context: SELECTED_PATH,
    side_doors: [
      'direct-legacy-runtime-v1-caller-config-time-grant-recognition-and-store-inputs',
      'inherited-child-process-environment-including-bash-env-exported-shell-functions-path-node-options-loaders-and-preloads',
      'unqualified-node-token-in-main-dispatcher',
      'usr-bin-env-node-entrypoint-interpreter-selection',
      'transitive-esm-import-time-execution-before-mode-branch-or-freshness-guard',
      'direct-module-invocation-custom-imports-and-generated-entrypoints',
      'runtime-activation-builder-default-argument-generation-path-not-attributed-to-the-cli-mode',
      'raw-filesystem-writes-around-fixture-storage',
      'shell-mcp-browser-app-control-filesystem-and-network-routes-not-bound-to-a-named-node',
      'path-interpreter-and-same-user-source-substitution',
      'source-drift-after-the-caller-pinned-commit',
      'parent-unresolved-surfaces-not-recomputed-by-this-additive-delta',
      'lexical-mask-is-not-a-complete-javascript-regex-ast-or-control-flow-parser',
    ],
    source_binding: {
      analyzed_source_commit_oid: ANALYZED_SOURCE_COMMIT,
      analyzed_source_commit_caller_pinned: true,
      analyzed_source_commit_object_presence_evaluated_by_analyzer: false,
      loaded_source_matches_commit_evaluated_by_analyzer: false,
      repository_id: 'ZLAR_Repo',
      source_inventory_sha256: inventory.inventorySha256,
      source_file_count: inventory.files.length,
      source_files: inventory.files,
      exact_witness_count: inventory.witnesses.length,
      exact_witnesses: inventory.witnesses,
    },
    verification_mode: 'source-only-inert-byte-exact-edge-certificate-validation',
  };
  const artifact = {
    ...body,
    integrity: { body_sha256: sha256hex(canonicalize(body)) },
  };
  assertSourceBoundStaticReachabilityDeltaV0(artifact);
  return artifact;
}

export function assertSourceBoundStaticReachabilityDeltaV0(artifact) {
  assertExactKeys('Reachability delta', artifact, [
    'action_class',
    'analysis_contract',
    'artifact_type',
    'authority_domain_context',
    'authority_domain_evaluated',
    'canonicalization',
    'claim_boundary',
    'decision',
    'dependency_map_delta',
    'edge_certificates',
    'hash_scope',
    'immutable_parent_binding',
    'integrity',
    'inventory_posture_after',
    'map_status',
    'mode_results',
    'non_claims',
    'safe_claim_ceiling',
    'schema_version',
    'selected_consequence_path_context',
    'side_doors',
    'source_binding',
    'verification_mode',
  ]);
  assert(artifact.artifact_type === SOURCE_BOUND_STATIC_REACHABILITY_DELTA_TYPE_V0, 'Reachability delta artifact type mismatch');
  assert(artifact.schema_version === 0, 'Reachability delta schema version mismatch');
  assert(artifact.action_class === ACTION_CLASS, 'Reachability delta action class mismatch');
  assert(artifact.authority_domain_context === AUTHORITY_DOMAIN, 'Reachability delta authority domain mismatch');
  assert(artifact.authority_domain_evaluated === false, 'Reachability delta cannot evaluate authority domain membership');
  assert(artifact.map_status === 'mapped_open', 'Reachability delta must remain mapped_open');
  assert(artifact.mode_results.length === 11, 'Reachability delta must contain exactly 11 semantic modes');
  assert(new Set(artifact.mode_results.map((item) => item.surface_mode_id)).size === 11, 'Reachability delta mode ids must be unique');
  assert(artifact.dependency_map_delta.new_effect_node_ids.length === 0, 'Reachability delta cannot add an effect node');
  assert(artifact.inventory_posture_after.domain_inventory_complete === false, 'Reachability delta cannot close domain inventory');
  assert(artifact.inventory_posture_after.equivalent_route_closure === false, 'Reachability delta cannot close equivalent routes');
  assert(artifact.inventory_posture_after.lifecycle_status === 'mapped_open', 'Reachability delta cannot close lifecycle');
  for (const value of Object.values(artifact.claim_boundary)) {
    assert(value === false, 'Every reachability delta claim-boundary value must remain false');
  }
  for (const mode of artifact.mode_results) {
    assert(mode.runtime_reachability_proven === false, `${mode.surface_mode_id} runtime reachability must remain false`);
    assert(mode.effect_capability_proven === false, `${mode.surface_mode_id} effect capability must remain false`);
    assert(mode.effect_occurrence_proven === false, `${mode.surface_mode_id} effect occurrence must remain false`);
    assert(mode.current_refusal_behavior_proven === false, `${mode.surface_mode_id} current refusal must remain false`);
    assert(mode.authority_domain_membership_proven === false, `${mode.surface_mode_id} domain membership must remain false`);
    assert(mode.authorized_outside_coverage === false, `${mode.surface_mode_id} outside coverage cannot be authorized`);
    assert(mode.adds_new_effect_exit === false, `${mode.surface_mode_id} cannot add an effect exit`);
    for (const nodeId of mode.source_resolved_existing_node_candidate_ids) {
      assert(
        [
          'E3.legacy-runtime-process-private-state-v1',
          'E5.active-persistent-proof-target-marker-v1',
        ].includes(nodeId),
        `${mode.surface_mode_id} projects an unsupported parent node candidate`,
      );
    }
    for (const nodeId of mode.unresolved_expected_node_candidate_ids) {
      assert(
        nodeId === 'E3.legacy-runtime-process-private-state-v1',
        `${mode.surface_mode_id} carries an unsupported unresolved node candidate`,
      );
    }
    if (mode.surface_role.startsWith('verification_candidate')) {
      assert(mode.source_resolved_existing_node_candidate_ids.length === 0, `${mode.surface_mode_id} verifier cannot project a target node`);
    }
  }
  assert(SHA256_RE.test(artifact.integrity?.body_sha256 || ''), 'Reachability delta integrity SHA-256 missing');
  const { integrity, ...body } = artifact;
  assert(sha256hex(canonicalize(body)) === integrity.body_sha256, 'Reachability delta self-integrity mismatch');
  assert(
    integrity.body_sha256 === EXPECTED_DELTA_BODY_SHA256_V0,
    'Reachability delta exact v0 semantic body identity mismatch',
  );
  return true;
}

export function canonicalSourceBoundStaticReachabilityDeltaBytesV0(artifact) {
  assertSourceBoundStaticReachabilityDeltaV0(artifact);
  return `${canonicalize(artifact)}\n`;
}

export function formatSourceBoundStaticReachabilityDeltaSummaryV0(artifact) {
  assertSourceBoundStaticReachabilityDeltaV0(artifact);
  const posture = artifact.inventory_posture_after;
  return [
    `artifact_type=${artifact.artifact_type}`,
    `map_status=${artifact.map_status}`,
    `decision=${artifact.decision.implementation_gate}`,
    `delta_mode_count=${posture.delta_mode_count}`,
    `resolved_mutation_candidate_modes=${posture.delta_source_resolved_mutation_candidate_mode_count}`,
    `unresolved_mutation_candidate_modes=${posture.delta_unresolved_mutation_candidate_mode_count}`,
    `resolved_verifier_sink_modes=${posture.delta_resolved_verifier_sink_mode_count}`,
    `domain_inventory_complete=${posture.domain_inventory_complete}`,
    `equivalent_route_closure=${posture.equivalent_route_closure}`,
    `runtime_reachability_proven=${artifact.claim_boundary.runtime_reachability}`,
    `effect_capability_proven=${artifact.claim_boundary.effect_capability}`,
    `body_sha256=${artifact.integrity.body_sha256}`,
    '',
  ].join('\n');
}
