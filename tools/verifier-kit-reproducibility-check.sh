#!/usr/bin/env bash
# Build the verifier kit twice with the same temporary publisher key and prove
# that the distributable archive hash is stable. This is reproducible-build
# evidence for the source package, not production publisher-key custody.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KIT_VERSION="v0.1.0"
KIT_DIR_NAME="zlar-verifier-kit-${KIT_VERSION}"
TARBALL="${REPO_ROOT}/dist/${KIT_DIR_NAME}.tar.gz"
TARBALL_SHA="${TARBALL}.sha256"
MANIFEST="${REPO_ROOT}/dist/${KIT_DIR_NAME}/MANIFEST.json"
MANIFEST_SIG="${REPO_ROOT}/dist/${KIT_DIR_NAME}/MANIFEST.sig"

JSON_MODE=0
JSON_OUT=""
TMP_DIR=""

cleanup() {
    if [ -n "${TMP_DIR}" ] && [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: bash tools/verifier-kit-reproducibility-check.sh [--json|--json-out <file>]

Builds the verifier kit twice with one temporary test publisher key and requires
the tarball SHA-256 to be identical. This proves local source-build archive
determinism for identical inputs and the same key. It does not prove production
publisher key custody, external attestation, or public release publication.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --json)
            JSON_MODE=1
            shift
            ;;
        --json-out)
            if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
                usage >&2
                echo "ERROR: --json-out requires a file path" >&2
                exit 2
            fi
            JSON_OUT="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            echo "ERROR: unsupported option: $1" >&2
            exit 2
            ;;
    esac
done

if [ "${JSON_MODE}" -eq 1 ] && [ -n "${JSON_OUT}" ]; then
    usage >&2
    echo "ERROR: use either --json or --json-out, not both" >&2
    exit 2
fi

if [ -n "${JSON_OUT}" ] && [ -e "${JSON_OUT}" ]; then
    echo "ERROR: JSON output file already exists" >&2
    exit 2
fi

for tool in node openssl shasum gzip awk sed sleep; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "ERROR: required tool not on PATH: ${tool}" >&2
        exit 2
    fi
done

if ! echo "" | openssl genpkey -algorithm ED25519 -out /dev/null 2>/dev/null; then
    echo "ERROR: openssl does not support Ed25519 (--algorithm ED25519)." >&2
    exit 2
fi

TMP_DIR="$(mktemp -d -t zlar-verifier-kit-repro.XXXXXX)"
chmod 700 "${TMP_DIR}"
PUBLISHER_KEY="${TMP_DIR}/publisher.key"
PUBLISHER_PUB="${TMP_DIR}/publisher.pub"

openssl genpkey -algorithm ED25519 -out "${PUBLISHER_KEY}" 2>/dev/null
chmod 600 "${PUBLISHER_KEY}"
openssl pkey -in "${PUBLISHER_KEY}" -pubout -out "${PUBLISHER_PUB}" 2>/dev/null
PUBLISHER_KID="$(shasum -a 256 "${PUBLISHER_PUB}" | awk '{print substr($1, 1, 16)}')"

FIRST_TARBALL_SHA=""
FIRST_SIDECAR_FILE_SHA=""
FIRST_MANIFEST_SHA=""
FIRST_MANIFEST_SIG_SHA=""
SECOND_TARBALL_SHA=""
SECOND_SIDECAR_FILE_SHA=""
SECOND_MANIFEST_SHA=""
SECOND_MANIFEST_SIG_SHA=""

fail_with_log() {
    local label="$1"
    local log_file="$2"
    echo "ERROR: verifier kit reproducibility ${label} build failed" >&2
    sed -E \
        -e 's#/Users/[^[:space:]]+#<local-path>#g' \
        -e 's#/home/[^[:space:]]+#<local-path>#g' \
        -e 's#/private/[^[:space:]]+#<local-path>#g' \
        -e 's#/tmp/[^[:space:]]+#<local-path>#g' \
        -e 's#/var/[^[:space:]]+#<local-path>#g' \
        "${log_file}" >&2
    exit 1
}

record_build() {
    local label="$1"
    local log_file="${TMP_DIR}/${label}.log"
    local tarball_sha sidecar_recorded_sha sidecar_file_sha manifest_sha manifest_sig_sha

    set +e
    bash "${REPO_ROOT}/tools/build-verifier-kit.sh" \
        --publisher-key "${PUBLISHER_KEY}" \
        --publisher-pub "${PUBLISHER_PUB}" \
        > "${log_file}" 2>&1
    local ec=$?
    set -e
    if [ "${ec}" -ne 0 ]; then
        fail_with_log "${label}" "${log_file}"
    fi

    for path in "${TARBALL}" "${TARBALL_SHA}" "${MANIFEST}" "${MANIFEST_SIG}"; do
        if [ ! -f "${path}" ]; then
            echo "ERROR: expected build artifact missing: ${path}" | sed -E 's#/Users/[^[:space:]]+#<local-path>#g' >&2
            exit 1
        fi
    done

    tarball_sha="$(shasum -a 256 "${TARBALL}" | awk '{print $1}')"
    sidecar_recorded_sha="$(awk '{print $1}' "${TARBALL_SHA}")"
    sidecar_file_sha="$(shasum -a 256 "${TARBALL_SHA}" | awk '{print $1}')"
    manifest_sha="$(shasum -a 256 "${MANIFEST}" | awk '{print $1}')"
    manifest_sig_sha="$(shasum -a 256 "${MANIFEST_SIG}" | awk '{print $1}')"

    if [ "${tarball_sha}" != "${sidecar_recorded_sha}" ]; then
        echo "ERROR: tarball SHA-256 sidecar does not match ${label} build" >&2
        exit 1
    fi

    if [ "${label}" = "first" ]; then
        FIRST_TARBALL_SHA="${tarball_sha}"
        FIRST_SIDECAR_FILE_SHA="${sidecar_file_sha}"
        FIRST_MANIFEST_SHA="${manifest_sha}"
        FIRST_MANIFEST_SIG_SHA="${manifest_sig_sha}"
    else
        SECOND_TARBALL_SHA="${tarball_sha}"
        SECOND_SIDECAR_FILE_SHA="${sidecar_file_sha}"
        SECOND_MANIFEST_SHA="${manifest_sha}"
        SECOND_MANIFEST_SIG_SHA="${manifest_sig_sha}"
    fi
}

record_build first
sleep 2
record_build second

REPRODUCIBLE_TARBALL=false
REPRODUCIBLE_MANIFEST=false
if [ "${FIRST_TARBALL_SHA}" = "${SECOND_TARBALL_SHA}" ]; then
    REPRODUCIBLE_TARBALL=true
fi
if [ "${FIRST_MANIFEST_SHA}" = "${SECOND_MANIFEST_SHA}" ] &&
    [ "${FIRST_MANIFEST_SIG_SHA}" = "${SECOND_MANIFEST_SIG_SHA}" ]; then
    REPRODUCIBLE_MANIFEST=true
fi

RESULT="FAIL"
if [ "${REPRODUCIBLE_TARBALL}" = true ] && [ "${REPRODUCIBLE_MANIFEST}" = true ]; then
    RESULT="PASS"
fi

REPORT_JSON="$(
    RESULT="${RESULT}" \
    KIT_VERSION="${KIT_VERSION}" \
    PUBLISHER_KID="${PUBLISHER_KID}" \
    FIRST_TARBALL_SHA="${FIRST_TARBALL_SHA}" \
    FIRST_SIDECAR_FILE_SHA="${FIRST_SIDECAR_FILE_SHA}" \
    FIRST_MANIFEST_SHA="${FIRST_MANIFEST_SHA}" \
    FIRST_MANIFEST_SIG_SHA="${FIRST_MANIFEST_SIG_SHA}" \
    SECOND_TARBALL_SHA="${SECOND_TARBALL_SHA}" \
    SECOND_SIDECAR_FILE_SHA="${SECOND_SIDECAR_FILE_SHA}" \
    SECOND_MANIFEST_SHA="${SECOND_MANIFEST_SHA}" \
    SECOND_MANIFEST_SIG_SHA="${SECOND_MANIFEST_SIG_SHA}" \
    REPRODUCIBLE_TARBALL="${REPRODUCIBLE_TARBALL}" \
    REPRODUCIBLE_MANIFEST="${REPRODUCIBLE_MANIFEST}" \
    node <<'NODE'
const report = {
  report_type: 'zlar-verifier-kit-reproducibility-v1',
  schema_version: 1,
  result: process.env.RESULT,
  kit_version: process.env.KIT_VERSION,
  evidence_model: 'local-source-build-same-test-publisher-key-twice',
  publisher_key_model: 'temporary test Ed25519 key generated for this check; private key removed on exit',
  publisher_kid: process.env.PUBLISHER_KID,
  builds: [
    {
      label: 'first',
      tarball_sha256: process.env.FIRST_TARBALL_SHA,
      tarball_sidecar_file_sha256: process.env.FIRST_SIDECAR_FILE_SHA,
      manifest_sha256: process.env.FIRST_MANIFEST_SHA,
      manifest_sig_sha256: process.env.FIRST_MANIFEST_SIG_SHA,
    },
    {
      label: 'second',
      tarball_sha256: process.env.SECOND_TARBALL_SHA,
      tarball_sidecar_file_sha256: process.env.SECOND_SIDECAR_FILE_SHA,
      manifest_sha256: process.env.SECOND_MANIFEST_SHA,
      manifest_sig_sha256: process.env.SECOND_MANIFEST_SIG_SHA,
    },
  ],
  reproducible: {
    tarball_sha256_identical: process.env.REPRODUCIBLE_TARBALL === 'true',
    manifest_and_signature_sha256_identical: process.env.REPRODUCIBLE_MANIFEST === 'true',
    sidecar_matches_tarball: true,
  },
  public_artifact_hashes: [
    {
      path: 'dist/zlar-verifier-kit-v0.1.0.tar.gz',
      sha256: process.env.SECOND_TARBALL_SHA,
    },
    {
      path: 'dist/zlar-verifier-kit-v0.1.0.tar.gz.sha256',
      sha256: process.env.SECOND_SIDECAR_FILE_SHA,
    },
    {
      path: 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.json',
      sha256: process.env.SECOND_MANIFEST_SHA,
    },
    {
      path: 'dist/zlar-verifier-kit-v0.1.0/MANIFEST.sig',
      sha256: process.env.SECOND_MANIFEST_SIG_SHA,
    },
  ],
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
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
NODE
)"

if [ -n "${JSON_OUT}" ]; then
    printf '%s' "${REPORT_JSON}" > "${JSON_OUT}"
fi

if [ "${JSON_MODE}" -eq 1 ]; then
    printf '%s' "${REPORT_JSON}"
else
    cat <<EOF
ZLAR Verifier Kit Reproducibility

Result: ${RESULT}
Kit version: ${KIT_VERSION}
Publisher key model: temporary test key
Publisher kid: ${PUBLISHER_KID}
Tarball SHA-256: ${SECOND_TARBALL_SHA}
Tarball reproducible: ${REPRODUCIBLE_TARBALL}
Manifest/signature reproducible: ${REPRODUCIBLE_MANIFEST}

Boundary:
- This is same-source, same-key local reproducible-build evidence.
- It does not prove production publisher key custody, external attestation,
  public release publication, live trust-registry state, revocation truth,
  enterprise readiness, or v3.4.0 readiness.
EOF
    if [ -n "${JSON_OUT}" ]; then
        echo "JSON written: ${JSON_OUT}" | sed -E \
            -e 's#/Users/[^[:space:]]+#<local-path>#g' \
            -e 's#/home/[^[:space:]]+#<local-path>#g' \
            -e 's#/private/[^[:space:]]+#<local-path>#g' \
            -e 's#/tmp/[^[:space:]]+#<local-path>#g' \
            -e 's#/var/[^[:space:]]+#<local-path>#g'
    fi
fi

if [ "${RESULT}" != "PASS" ]; then
    exit 1
fi
