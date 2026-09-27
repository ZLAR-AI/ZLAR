#!/bin/bash
# No-write install planning contract for install.sh --dry-run --json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLER="${PROJECT_DIR}/install.sh"
README_FILE="${PROJECT_DIR}/docs/first-design-install.md"  # install detail moved out of README on 2026-09-26
TROUBLESHOOTING_DOC="${PROJECT_DIR}/docs/troubleshooting.md"
ARCHITECTURE_MAP="${PROJECT_DIR}/docs/architecture-map.md"
CLI_REFERENCE="${PROJECT_DIR}/docs/cli-reference.md"
ZLAR_CLI="${PROJECT_DIR}/bin/zlar"
TARGET_VERSION="$(tr -d '[:space:]' < "${PROJECT_DIR}/VERSION")"

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS + 1)); }

fail() {
    local label="$1"
    local detail="${2:-}"
    FAIL=$((FAIL + 1))
    printf '  FAIL: %s\n' "${label}"
    if [ -n "${detail}" ]; then
        printf '%s\n' "${detail}" | sed 's/^/    /'
    fi
}

assert_equal() {
    local label="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "${expected}" = "${actual}" ]; then
        pass
    else
        fail "${label}" "expected=${expected} actual=${actual}"
    fi
}

assert_true() {
    local label="$1" value="$2"
    assert_equal "${label}" "true" "${value}"
}

assert_false() {
    local label="$1" value="$2"
    assert_equal "${label}" "false" "${value}"
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    TOTAL=$((TOTAL + 1))
    if printf '%s\n' "${haystack}" | grep -Fq -- "${needle}"; then
        pass
    else
        fail "${label}" "missing: ${needle}"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    TOTAL=$((TOTAL + 1))
    if printf '%s\n' "${haystack}" | grep -Fq -- "${needle}"; then
        fail "${label}" "unexpected: ${needle}"
    else
        pass
    fi
}

assert_file_contains() {
    local label="$1" path="$2" needle="$3"
    TOTAL=$((TOTAL + 1))
    if grep -Fq -- "${needle}" "${path}"; then
        pass
    else
        fail "${label}" "${path} missing: ${needle}"
    fi
}

assert_file_not_contains() {
    local label="$1" path="$2" needle="$3"
    TOTAL=$((TOTAL + 1))
    if grep -Fq -- "${needle}" "${path}"; then
        fail "${label}" "${path} unexpectedly contains: ${needle}"
    else
        pass
    fi
}

assert_jq_true() {
    local label="$1" json="$2" expr="$3"
    TOTAL=$((TOTAL + 1))
    if printf '%s\n' "${json}" | jq -e "${expr}" >/dev/null 2>&1; then
        pass
    else
        fail "${label}" "jq expression failed: ${expr}"
    fi
}

home_snapshot() {
    local home="$1"
    (
        cd "${home}"
        find . -print | LC_ALL=C sort
        find . -type f -exec shasum -a 256 {} + | LC_ALL=C sort
    )
}

run_dry_plan() {
    local home="$1"
    shift
    HOME="${home}" PATH="/usr/bin:/bin:/usr/sbin:/sbin" bash "${INSTALLER}" --dry-run --json "$@"
}

run_plan_error() {
    local home="$1"
    shift
    HOME="${home}" PATH="/usr/bin:/bin:/usr/sbin:/sbin" bash "${INSTALLER}" "$@" 2>&1
}

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq unavailable"
    exit 77
fi

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

echo "=== Install Plan Dry-Run ==="
echo

PLAN_HOME="${TMP_ROOT}/home-plan"
mkdir -p "${PLAN_HOME}/.claude" "${PLAN_HOME}/.cursor" "${PLAN_HOME}/.codeium/windsurf"
printf '{"hooks":{"PreToolUse":[]}}\n' > "${PLAN_HOME}/.claude/settings.json"
printf '{"beforeShellExecution":[{"command":"~/.zlar/bin/zlar-gate"}]}\n' > "${PLAN_HOME}/.cursor/hooks.json"

before=$(home_snapshot "${PLAN_HOME}")
plan_json=$(run_dry_plan "${PLAN_HOME}")
after=$(home_snapshot "${PLAN_HOME}")

assert_equal "dry-run exits before writes" "${before}" "${after}"
assert_not_contains "json output does not leak absolute temp HOME" "${PLAN_HOME}" "${plan_json}"
assert_not_contains "json output does not print private user path prefix" "/Users/" "${plan_json}"
assert_equal "json parses" "zlar-install-plan-v1" "$(printf '%s\n' "${plan_json}" | jq -r '.plan_type')"
assert_true "dry-run flag true" "$(printf '%s\n' "${plan_json}" | jq -r '.dry_run')"
assert_equal "source identity binds installer path" "install.sh" "$(printf '%s\n' "${plan_json}" | jq -r '.source_identity.installer_path')"
assert_jq_true "source identity has commit sha or unknown" "${plan_json}" \
    '(.source_identity.source_commit_sha == "unknown") or (.source_identity.source_commit_sha | test("^[a-f0-9]{40}$"))'
assert_jq_true "source identity has tree sha or unknown" "${plan_json}" \
    '(.source_identity.source_tree_sha == "unknown") or (.source_identity.source_tree_sha | test("^[a-f0-9]{40}$"))'
assert_jq_true "source identity has installer blob or unknown" "${plan_json}" \
    '(.source_identity.installer_git_blob_sha == "unknown") or (.source_identity.installer_git_blob_sha | test("^[a-f0-9]{40}$"))'
assert_jq_true "source identity has installer sha or unknown" "${plan_json}" \
    '(.source_identity.installer_sha256 == "unknown") or (.source_identity.installer_sha256 | test("^[a-f0-9]{64}$"))'
assert_jq_true "source identity names clean dirty or unknown" "${plan_json}" \
    '.source_identity.source_state as $state | ["tracked_clean","tracked_dirty","unknown"] | index($state)'

SOURCE_IDENTITY_REPO="${TMP_ROOT}/source-identity-repo"
mkdir -p "${SOURCE_IDENTITY_REPO}/bin" "${SOURCE_IDENTITY_REPO}/lib"
cp "${INSTALLER}" "${SOURCE_IDENTITY_REPO}/install.sh"
cp "${PROJECT_DIR}/VERSION" "${SOURCE_IDENTITY_REPO}/VERSION"
cp "${PROJECT_DIR}/bin/zlar-gate" "${SOURCE_IDENTITY_REPO}/bin/zlar-gate"
cp "${PROJECT_DIR}/bin/zlar-policy" "${SOURCE_IDENTITY_REPO}/bin/zlar-policy"
git -C "${SOURCE_IDENTITY_REPO}" init -q
git -C "${SOURCE_IDENTITY_REPO}" add install.sh VERSION bin/zlar-gate bin/zlar-policy
git -C "${SOURCE_IDENTITY_REPO}" -c user.name="ZLAR Test" -c user.email="zlar-test@example.invalid" commit -qm baseline
printf '# untracked copied payload\n' > "${SOURCE_IDENTITY_REPO}/lib/untracked-payload.sh"
untracked_source_json=$(HOME="${PLAN_HOME}" PATH="/usr/bin:/bin:/usr/sbin:/sbin" bash "${SOURCE_IDENTITY_REPO}/install.sh" --dry-run --json --surface claude-code --no-machine-helpers)
assert_equal "untracked copied source files mark source dirty" "tracked_dirty" \
    "$(printf '%s\n' "${untracked_source_json}" | jq -r '.source_identity.source_state')"
assert_true "no-write proof says no writes" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.performs_no_writes')"
assert_true "no-write proof exits before phases" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.exits_before_installer_phases')"
assert_true "no-write proof does not create temp dirs" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.does_not_create_temp_dirs')"
assert_true "no-write proof does not download or clone" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.does_not_download_or_clone')"
assert_true "no-write proof does not probe sudo" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.does_not_probe_sudo')"
assert_true "no-write proof avoids private key material" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.does_not_generate_or_read_private_key_material')"
assert_true "no-write proof avoids hooks and config writes" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.does_not_write_hooks_or_config')"
assert_true "no-write proof avoids services" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.does_not_start_services')"
assert_true "no-write proof avoids machine config" "$(printf '%s\n' "${plan_json}" | jq -r '.no_write_proof.does_not_modify_machine_config')"
assert_jq_true "planned bin wrappers include local boarding proof" "${plan_json}" \
    '.planned_installed_bin_wrappers[] | select(.=="zlar-protected-records-local-boarding-proof")'
assert_jq_true "planned bin wrappers include downstream refusal proof" "${plan_json}" \
    '.planned_installed_bin_wrappers[] | select(.=="zlar-downstream-refusal-proof")'
assert_jq_true "planned bin wrappers include records write terminal proof" "${plan_json}" \
    '.planned_installed_bin_wrappers[] | select(.=="zlar-records-write-terminal-proof")'
assert_jq_true "planned bin wrappers include runtime profile terminal chain" "${plan_json}" \
    '.planned_installed_bin_wrappers[] | select(.=="zlar-protected-records-installed-runtime-profile-terminal-chain")'
assert_jq_true "planned bin wrappers exclude retired direct E2 request" "${plan_json}" \
    '[.planned_installed_bin_wrappers[] | select(.=="zlar-protected-records-service-request")] | length == 0'
assert_jq_true "planned bin wrappers exclude retired direct E1 adapter" "${plan_json}" \
    '[.planned_installed_bin_wrappers[] | select(.=="zlar-protected-records-write")] | length == 0'
assert_equal "fresh install plans no retired source residue removal" "0" \
    "$(printf '%s\n' "${plan_json}" | jq '.planned_retired_source_removals | length')"

DISPATCH_WRAPPERS=$(sed -n 's/.*"${PROJECT_DIR}\/bin\/\(zlar-[^"]*\)".*/\1/p' "${ZLAR_CLI}" | LC_ALL=C sort -u)
assert_true "dispatcher wrapper extraction found commands" "$([ -n "${DISPATCH_WRAPPERS}" ] && echo true || echo false)"
while IFS= read -r wrapper_name; do
    [ -n "${wrapper_name}" ] || continue
    assert_true "dispatcher wrapper exists in source: ${wrapper_name}" "$([ -f "${PROJECT_DIR}/bin/${wrapper_name}" ] && echo true || echo false)"
    assert_jq_true "dry-run plans dispatcher wrapper: ${wrapper_name}" "${plan_json}" \
        ".planned_installed_bin_wrappers[] | select(.==\"${wrapper_name}\")"
done <<EOF
${DISPATCH_WRAPPERS}
EOF

assert_false "fresh temp home has no existing install" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_install.detected')"
assert_equal "fresh plan existing mode default refuse" "refuse" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_install.requested_mode')"
assert_equal "fresh plan decision is fresh install" "fresh_install" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_install.decision')"
assert_equal "fresh plan operation is fresh install" "fresh_install" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_install.operation')"
assert_false "fresh plan does not exit before writes" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_true "fresh plan would continue after existing install check" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_install.real_install_would_continue_after_existing_install_check')"
assert_true "claude surface detected by config dir" "$(printf '%s\n' "${plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .detected')"
assert_true "cursor surface detected by config dir" "$(printf '%s\n' "${plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="cursor") | .detected')"
assert_true "windsurf surface detected by config dir" "$(printf '%s\n' "${plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="windsurf") | .detected')"
assert_false "claude has no existing zlar conflict" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_zlar_hook_profile_conflicts.claude_code')"
assert_false "cursor stale zlar-gate text is not current adapter conflict" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_zlar_hook_profile_conflicts.cursor')"
assert_false "windsurf has no existing zlar conflict" "$(printf '%s\n' "${plan_json}" | jq -r '.existing_zlar_hook_profile_conflicts.windsurf')"
assert_true "claude hook write planned" "$(printf '%s\n' "${plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .planned_hook_write')"
assert_true "cursor stale zlar-gate text does not suppress current adapter hook" "$(printf '%s\n' "${plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="cursor") | .planned_hook_write')"
assert_true "windsurf hook write planned" "$(printf '%s\n' "${plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="windsurf") | .planned_hook_write')"
assert_equal "claude path is home placeholder" "~/.claude/settings.json" "$(printf '%s\n' "${plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .hook_profile_path')"

assert_jq_true "planned writes include install dir" "${plan_json}" '.planned_file_writes[] | select(.path=="~/.zlar/bin/" and .category=="core_binaries")'
assert_jq_true "planned writes include signing key" "${plan_json}" '.planned_file_writes[] | select(.path=="~/.zlar-signing.key" and .category=="signing_material")'
assert_jq_true "planned writes include claude hook profile" "${plan_json}" '.planned_file_writes[] | select(.path=="~/.claude/settings.json" and .category=="hook_profile")'
assert_jq_true "planned writes include optional system dispatcher" "${plan_json}" '.planned_file_writes[] | select(.path=="/usr/local/bin/zlar-tg-poll" and .category=="optional_machine_script")'
assert_jq_true "human approvals include hook writes" "${plan_json}" '.required_human_approvals[] | select(test("framework hook/profile writes"))'
assert_jq_true "side doors include direct MCP" "${plan_json}" '.side_doors_left_open[] | select(test("direct MCP"))'
assert_jq_true "non-claims include current-machine governance" "${plan_json}" '.non_claims[] | select(test("current-machine governance"))'
assert_equal "current-machine design type" "zlar-current-machine-governance-design-v1" \
    "$(printf '%s\n' "${plan_json}" | jq -r '.current_machine_governance_design.design_type')"
assert_false "current-machine design is not evidence" \
    "$(printf '%s\n' "${plan_json}" | jq -r '.current_machine_governance_design.current_machine_governance_evidence')"
assert_true "current-machine design requires approval packet" \
    "$(printf '%s\n' "${plan_json}" | jq -r '.current_machine_governance_design.approval_packet_required')"
assert_true "current-machine design requires recognized receipt for boarding" \
    "$(printf '%s\n' "${plan_json}" | jq -r '.current_machine_governance_design.recognized_receipt_required_for_boarding')"
assert_jq_true "current-machine packet names hook profile" "${plan_json}" \
    '.current_machine_governance_design.approval_packet_must_name[] | select(test("hook/profile"))'
assert_jq_true "current-machine packet names downstream terminal" "${plan_json}" \
    '.current_machine_governance_design.approval_packet_must_name[] | select(test("downstream terminal"))'
assert_jq_true "current-machine recognition refuses missing receipt" "${plan_json}" \
    '.current_machine_governance_design.downstream_recognition_must_refuse[] | select(.=="receipt_missing")'
assert_jq_true "current-machine recognition refuses request-stream authority material" "${plan_json}" \
    '.current_machine_governance_design.downstream_recognition_must_refuse[] | select(.=="request_stream_authority_material")'
assert_jq_true "current-machine claim gate names unrouted side doors" "${plan_json}" \
    '.current_machine_governance_design.before_current_machine_claim[] | select(test("unrouted side door"))'
assert_jq_true "current-machine non-claims include live downstream recognition" "${plan_json}" \
    '.current_machine_governance_design.non_claims[] | select(test("live downstream recognition"))'
assert_true "real install would create keys in fresh home" "$(printf '%s\n' "${plan_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_keys')"
assert_true "real install would create hooks in detected fresh home" "$(printf '%s\n' "${plan_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_hooks')"
assert_false "real install does not create services" "$(printf '%s\n' "${plan_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_services')"
assert_true "real install can touch user config" "$(printf '%s\n' "${plan_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_user_config')"
assert_true "real install can touch machine config conditionally" "$(printf '%s\n' "${plan_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_machine_config')"

surface_plan_json=$(run_dry_plan "${PLAN_HOME}" --surface claude-code)
assert_equal "surface plan command includes requested surface" \
    "install.sh --dry-run --json --surface claude_code" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.command')"
assert_equal "selected surface reported as claude_code" "claude_code" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.selected_client_surfaces[0]')"
assert_true "surface plan records single-surface scope" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.current_machine_governance_design.single_surface_scope')"
assert_equal "surface plan design scope is claude_code" "claude_code" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.current_machine_governance_design.surface_scope')"
assert_true "selected surface keeps claude candidate" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .selected_surface')"
assert_false "selected surface drops cursor candidate" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="cursor") | .selected_surface')"
assert_false "selected surface drops windsurf candidate" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.detected_client_surfaces[] | select(.id=="windsurf") | .selected_surface')"
assert_equal "surface plan excludes cursor hook write path" \
    "0" "$(printf '%s\n' "${surface_plan_json}" | jq '[.planned_file_writes[] | select(.path=="~/.cursor/hooks.json")] | length')"
assert_equal "surface plan excludes windsurf hook write path" \
    "0" "$(printf '%s\n' "${surface_plan_json}" | jq '[.planned_file_writes[] | select(.path=="~/.codeium/windsurf/hooks.json")] | length')"
assert_equal "surface plan excludes cursor adapter write path" \
    "0" "$(printf '%s\n' "${surface_plan_json}" | jq '[.planned_file_writes[] | select(.path=="~/.zlar/adapters/cursor/")] | length')"
assert_equal "surface plan excludes windsurf adapter write path" \
    "0" "$(printf '%s\n' "${surface_plan_json}" | jq '[.planned_file_writes[] | select(.path=="~/.zlar/adapters/windsurf/")] | length')"
assert_equal "surface plan includes only claude adapter write path" "1" \
    "$(printf '%s\n' "${surface_plan_json}" | jq '[.planned_file_writes[] | select(.path=="~/.zlar/adapters/claude-code/")] | length')"
assert_equal "surface plan includes only claude hook write path" "1" \
    "$(printf '%s\n' "${surface_plan_json}" | jq '[.planned_file_writes[] | select(.path=="~/.claude/settings.json")] | length')"
assert_true "surface plan observation keeps claude selected" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.current_machine_governance_design.dry_run_observation.claude_code_selected')"
assert_true "surface plan observation plans claude hook write in fresh home" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.current_machine_governance_design.dry_run_observation.claude_code_planned_hook_write')"
assert_false "surface plan observation drops cursor" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.current_machine_governance_design.dry_run_observation.cursor_selected')"
assert_false "surface plan observation drops windsurf" \
    "$(printf '%s\n' "${surface_plan_json}" | jq -r '.current_machine_governance_design.dry_run_observation.windsurf_selected')"

SPOOF_PROFILE_HOME="${TMP_ROOT}/home-spoof-profile"
mkdir -p "${SPOOF_PROFILE_HOME}/.claude"
printf '{"note":"contains zlar but no PreToolUse hook"}\n' > "${SPOOF_PROFILE_HOME}/.claude/settings.json"
spoof_profile_json=$(run_dry_plan "${SPOOF_PROFILE_HOME}" --surface claude-code)
assert_false "claude profile note with zlar does not count as hook conflict" \
    "$(printf '%s\n' "${spoof_profile_json}" | jq -r '.existing_zlar_hook_profile_conflicts.claude_code')"
assert_true "claude spoof profile still plans hook write" \
    "$(printf '%s\n' "${spoof_profile_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .planned_hook_write')"

SPOOF_EXACT_PROFILE_HOME="${TMP_ROOT}/home-spoof-exact-profile"
mkdir -p "${SPOOF_EXACT_PROFILE_HOME}/.claude"
printf '{"metadata":{"command":"~/.zlar/adapters/claude-code/hook.sh"},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"~/.zlar/adapters/claude-code/hook.sh"}]}]}}\n' > "${SPOOF_EXACT_PROFILE_HOME}/.claude/settings.json"
spoof_exact_profile_json=$(run_dry_plan "${SPOOF_EXACT_PROFILE_HOME}" --surface claude-code)
assert_false "claude exact command outside PreToolUse hook slot does not count as conflict" \
    "$(printf '%s\n' "${spoof_exact_profile_json}" | jq -r '.existing_zlar_hook_profile_conflicts.claude_code')"
assert_true "claude exact command outside hook slot still plans hook write" \
    "$(printf '%s\n' "${spoof_exact_profile_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .planned_hook_write')"

surface_plan_no_helpers_json=$(run_dry_plan "${PLAN_HOME}" --surface claude-code --no-machine-helpers)
assert_equal "no-machine-helpers omits optional machine scripts" "0" \
    "$(printf '%s\n' "${surface_plan_no_helpers_json}" | jq '[.planned_file_writes[] | select(.category=="optional_machine_script")] | length')"
assert_false "no-machine-helpers blocks machine-config writes" \
    "$(printf '%s\n' "${surface_plan_no_helpers_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_machine_config')"

set +e
surface_unknown_status=$(run_plan_error "${PLAN_HOME}" --surface does-not-exist)
surface_unknown_status_code=$?
set -e
assert_equal "unknown surface exits with error" "1" "${surface_unknown_status_code}"
assert_contains "unknown surface names value" "Unknown surface: does-not-exist" "${surface_unknown_status}"

EXISTING_HOME="${TMP_ROOT}/home-existing"
mkdir -p "${EXISTING_HOME}/.zlar/bin" "${EXISTING_HOME}/.zlar/lib"
printf '3.4.52\n' > "${EXISTING_HOME}/.zlar/VERSION"
for stale_path in \
    bin/zlar-protected-records-write \
    bin/zlar-protected-records-service-request \
    lib/protected-records-adapter.mjs \
    lib/protected-records-service.mjs; do
    printf 'stale-retired-source\n' > "${EXISTING_HOME}/.zlar/${stale_path}"
done
existing_before=$(home_snapshot "${EXISTING_HOME}")
existing_json=$(run_dry_plan "${EXISTING_HOME}")
existing_after=$(home_snapshot "${EXISTING_HOME}")
assert_equal "existing-install dry-run still no-write" "${existing_before}" "${existing_after}"
assert_true "existing install detected" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.detected')"
assert_equal "existing install records installed version" "3.4.52" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.installed_version')"
assert_equal "existing install records target version" "${TARGET_VERSION}" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.target_version')"
assert_equal "existing install default requested mode refuse" "refuse" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.requested_mode')"
assert_equal "existing install default decision refuses" "refuse_existing_install" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.decision')"
assert_equal "existing install default operation refusal" "refusal" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.operation')"
assert_equal "existing install default reason names existing install" "existing install detected" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.refusal_reason')"
assert_true "existing install would exit before writes" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_false "existing install would not continue after check" "$(printf '%s\n' "${existing_json}" | jq -r '.existing_install.real_install_would_continue_after_existing_install_check')"
assert_true "existing install design observes blocked real install" "$(printf '%s\n' "${existing_json}" | jq -r '.current_machine_governance_design.dry_run_observation.real_install_would_exit_before_writes')"
assert_equal "existing install design preserves decision" "refuse_existing_install" "$(printf '%s\n' "${existing_json}" | jq -r '.current_machine_governance_design.dry_run_observation.existing_install_decision')"
assert_true "existing install blocks write effects" "$(printf '%s\n' "${existing_json}" | jq -r '.write_effects_if_real_install_runs.blocked_by_existing_install')"
assert_equal "write effects preserve existing install decision" "refuse_existing_install" "$(printf '%s\n' "${existing_json}" | jq -r '.write_effects_if_real_install_runs.existing_install_decision')"
assert_false "existing install means no effective file writes" "$(printf '%s\n' "${existing_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"
assert_false "existing install means no effective key writes" "$(printf '%s\n' "${existing_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_keys')"
assert_false "existing install means no effective machine config writes" "$(printf '%s\n' "${existing_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_machine_config')"
assert_equal "default existing-install refusal plans no retired source removal" "0" \
    "$(printf '%s\n' "${existing_json}" | jq '.planned_retired_source_removals | length')"

existing_upgrade_json=$(run_dry_plan "${EXISTING_HOME}" --surface claude-code --no-machine-helpers --existing-install upgrade)
assert_equal "upgrade command records existing-install mode" \
    "install.sh --dry-run --json --surface claude_code --no-machine-helpers --existing-install upgrade" \
    "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.command')"
assert_equal "upgrade mode selected" "upgrade" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.existing_install.requested_mode')"
assert_equal "version-different existing install can upgrade" "upgrade_existing_install" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.existing_install.decision')"
assert_equal "upgrade operation recorded" "upgrade" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.existing_install.operation')"
assert_true "upgrade requires backup before mutation" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.existing_install.requires_backup_before_mutation')"
assert_false "upgrade would not exit before writes" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_true "upgrade would continue after existing check" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.existing_install.real_install_would_continue_after_existing_install_check')"
assert_false "upgrade is not blocked by existing install" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.write_effects_if_real_install_runs.blocked_by_existing_install')"
assert_true "upgrade can modify files" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"
assert_false "upgrade with no-machine-helpers avoids machine config" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_machine_config')"
assert_false "upgrade keeps cursor unselected" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.detected_client_surfaces[] | select(.id=="cursor") | .selected_surface')"
assert_false "upgrade keeps windsurf unselected" "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.detected_client_surfaces[] | select(.id=="windsurf") | .selected_surface')"
assert_equal "upgrade excludes cursor hook write path" \
    "0" "$(printf '%s\n' "${existing_upgrade_json}" | jq '[.planned_file_writes[] | select(.path=="~/.cursor/hooks.json")] | length')"
assert_equal "upgrade excludes windsurf hook write path" \
    "0" "$(printf '%s\n' "${existing_upgrade_json}" | jq '[.planned_file_writes[] | select(.path=="~/.codeium/windsurf/hooks.json")] | length')"
assert_equal "upgrade plans all exact retired E1/E2 source residue removals" "4" \
    "$(printf '%s\n' "${existing_upgrade_json}" | jq '.planned_retired_source_removals | length')"
assert_false "regular-file cleanup does not trigger type refusal" \
    "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.existing_install.retired_source_cleanup_would_refuse_before_writes')"
assert_false "regular-file cleanup does not block real install" \
    "$(printf '%s\n' "${existing_upgrade_json}" | jq -r '.write_effects_if_real_install_runs.blocked_by_retired_source_cleanup')"
for stale_path in \
    bin/zlar-protected-records-write \
    bin/zlar-protected-records-service-request \
    lib/protected-records-adapter.mjs \
    lib/protected-records-service.mjs; do
    assert_jq_true "upgrade plans exact retired source removal: ${stale_path}" "${existing_upgrade_json}" \
        ".planned_retired_source_removals[] | select(.path==\"~/.zlar/${stale_path}\" and .action==\"remove_retired_positive_source_residue\")"
done
assert_equal "upgrade dry-run leaves stale retired files byte-identical" "${existing_before}" "$(home_snapshot "${EXISTING_HOME}")"

UNEXPECTED_TYPE_HOME="${TMP_ROOT}/home-unexpected-retired-type"
mkdir -p "${UNEXPECTED_TYPE_HOME}/.zlar/bin/zlar-protected-records-write"
printf '3.4.52\n' > "${UNEXPECTED_TYPE_HOME}/.zlar/VERSION"
unexpected_type_before=$(home_snapshot "${UNEXPECTED_TYPE_HOME}")
unexpected_type_json=$(run_dry_plan "${UNEXPECTED_TYPE_HOME}" --surface claude-code --no-machine-helpers --existing-install upgrade)
assert_equal "unexpected-type plan keeps requested upgrade decision visible" "upgrade_existing_install" \
    "$(printf '%s\n' "${unexpected_type_json}" | jq -r '.existing_install.decision')"
assert_true "unexpected retired path type refuses before writes" \
    "$(printf '%s\n' "${unexpected_type_json}" | jq -r '.existing_install.retired_source_cleanup_would_refuse_before_writes')"
assert_true "unexpected retired path type blocks write effects" \
    "$(printf '%s\n' "${unexpected_type_json}" | jq -r '.write_effects_if_real_install_runs.blocked_by_retired_source_cleanup')"
assert_true "unexpected retired path type sets generic pre-write exit" \
    "$(printf '%s\n' "${unexpected_type_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_false "unexpected retired path type permits no file writes" \
    "$(printf '%s\n' "${unexpected_type_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"
assert_equal "unexpected retired path is not planned as a removal" "0" \
    "$(printf '%s\n' "${unexpected_type_json}" | jq '.planned_retired_source_removals | length')"
assert_jq_true "unexpected retired path is named as exact refusal" "${unexpected_type_json}" \
    '.planned_retired_source_cleanup_refusals[] | select(.path=="~/.zlar/bin/zlar-protected-records-write" and .reason=="unexpected_file_type")'
assert_equal "unexpected-type dry-run leaves path byte-identical" "${unexpected_type_before}" "$(home_snapshot "${UNEXPECTED_TYPE_HOME}")"

SYMLINK_PARENT_HOME="${TMP_ROOT}/home-symlink-retired-parent"
SYMLINK_PARENT_OUTSIDE="${TMP_ROOT}/outside-symlink-retired-parent"
mkdir -p "${SYMLINK_PARENT_HOME}/.zlar" "${SYMLINK_PARENT_OUTSIDE}"
printf '3.4.52\n' > "${SYMLINK_PARENT_HOME}/.zlar/VERSION"
printf 'must-remain\n' > "${SYMLINK_PARENT_OUTSIDE}/zlar-protected-records-write"
ln -s "${SYMLINK_PARENT_OUTSIDE}" "${SYMLINK_PARENT_HOME}/.zlar/bin"
symlink_parent_home_before=$(home_snapshot "${SYMLINK_PARENT_HOME}")
symlink_parent_outside_before=$(home_snapshot "${SYMLINK_PARENT_OUTSIDE}")
symlink_parent_json=$(run_dry_plan "${SYMLINK_PARENT_HOME}" --surface claude-code --no-machine-helpers --existing-install upgrade)
assert_true "symlinked retired parent blocks projected writes" \
    "$(printf '%s\n' "${symlink_parent_json}" | jq -r '.write_effects_if_real_install_runs.blocked_by_retired_source_cleanup')"
assert_true "symlinked retired parent sets generic pre-write exit" \
    "$(printf '%s\n' "${symlink_parent_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_false "symlinked retired parent permits no file writes" \
    "$(printf '%s\n' "${symlink_parent_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"
assert_equal "symlinked retired parent plans no leaf removal" "0" \
    "$(printf '%s\n' "${symlink_parent_json}" | jq '.planned_retired_source_removals | length')"
assert_jq_true "symlinked bin parent is named as exact refusal" "${symlink_parent_json}" \
    '.planned_retired_source_parent_refusals[] | select(.path=="~/.zlar/bin" and .reason=="symlinked_parent")'
assert_not_contains "symlink parent plan hides absolute outside path" "${SYMLINK_PARENT_OUTSIDE}" "${symlink_parent_json}"
assert_equal "symlink parent dry-run leaves home byte-identical" "${symlink_parent_home_before}" "$(home_snapshot "${SYMLINK_PARENT_HOME}")"
assert_equal "symlink parent dry-run leaves outside bytes intact" "${symlink_parent_outside_before}" "$(home_snapshot "${SYMLINK_PARENT_OUTSIDE}")"

existing_repair_mismatch_json=$(run_dry_plan "${EXISTING_HOME}" --surface claude-code --no-machine-helpers --existing-install repair)
assert_equal "repair refuses version mismatch" "refuse_repair_version_mismatch" "$(printf '%s\n' "${existing_repair_mismatch_json}" | jq -r '.existing_install.decision')"
assert_true "repair mismatch exits before writes" "$(printf '%s\n' "${existing_repair_mismatch_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_true "repair mismatch blocks write effects" "$(printf '%s\n' "${existing_repair_mismatch_json}" | jq -r '.write_effects_if_real_install_runs.blocked_by_existing_install')"
assert_equal "refused repair plans no retired source removal" "0" \
    "$(printf '%s\n' "${existing_repair_mismatch_json}" | jq '.planned_retired_source_removals | length')"

UNKNOWN_VERSION_HOME="${TMP_ROOT}/home-unknown-version"
mkdir -p "${UNKNOWN_VERSION_HOME}/.zlar" "${UNKNOWN_VERSION_HOME}/.claude"
unknown_repair_json=$(run_dry_plan "${UNKNOWN_VERSION_HOME}" --surface claude-code --no-machine-helpers --existing-install repair)
assert_equal "unknown-version repair records unknown version" "unknown" "$(printf '%s\n' "${unknown_repair_json}" | jq -r '.existing_install.installed_version')"
assert_equal "unknown-version repair refuses" "refuse_repair_unknown_version" "$(printf '%s\n' "${unknown_repair_json}" | jq -r '.existing_install.decision')"
assert_equal "unknown-version repair reason names readable version" "repair requires a readable existing VERSION" "$(printf '%s\n' "${unknown_repair_json}" | jq -r '.existing_install.refusal_reason')"
assert_false "unknown-version repair does not mark backup-gated mutation" "$(printf '%s\n' "${unknown_repair_json}" | jq -r '.existing_install.requires_backup_before_mutation')"
assert_true "unknown-version repair exits before writes" "$(printf '%s\n' "${unknown_repair_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_false "unknown-version repair does not continue" "$(printf '%s\n' "${unknown_repair_json}" | jq -r '.existing_install.real_install_would_continue_after_existing_install_check')"
assert_false "unknown-version repair cannot modify files" "$(printf '%s\n' "${unknown_repair_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"

unknown_upgrade_json=$(run_dry_plan "${UNKNOWN_VERSION_HOME}" --surface claude-code --no-machine-helpers --existing-install upgrade)
assert_equal "unknown-version upgrade refuses" "refuse_upgrade_unknown_version" "$(printf '%s\n' "${unknown_upgrade_json}" | jq -r '.existing_install.decision')"
assert_true "unknown-version upgrade exits before writes" "$(printf '%s\n' "${unknown_upgrade_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"

SAME_HOME="${TMP_ROOT}/home-same-version"
mkdir -p "${SAME_HOME}/.zlar/bin" "${SAME_HOME}/.zlar/lib" "${SAME_HOME}/.claude"
printf '%s\n' "${TARGET_VERSION}" > "${SAME_HOME}/.zlar/VERSION"
printf '{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"~/.zlar/adapters/claude-code/hook.sh"}]}]}}\n' > "${SAME_HOME}/.claude/settings.json"
for stale_path in \
    bin/zlar-protected-records-write \
    bin/zlar-protected-records-service-request \
    lib/protected-records-adapter.mjs \
    lib/protected-records-service.mjs; do
    printf 'stale-retired-source\n' > "${SAME_HOME}/.zlar/${stale_path}"
done
same_before=$(home_snapshot "${SAME_HOME}")

same_noop_json=$(run_dry_plan "${SAME_HOME}" --surface claude-code --no-machine-helpers --existing-install no-op)
assert_equal "no-op command normalizes spelling" \
    "install.sh --dry-run --json --surface claude_code --no-machine-helpers --existing-install no-op" \
    "$(printf '%s\n' "${same_noop_json}" | jq -r '.command')"
assert_equal "same-version no-op decision" "no_op_existing_install" "$(printf '%s\n' "${same_noop_json}" | jq -r '.existing_install.decision')"
assert_equal "same-version no-op operation" "no_op" "$(printf '%s\n' "${same_noop_json}" | jq -r '.existing_install.operation')"
assert_true "same-version no-op exits before writes" "$(printf '%s\n' "${same_noop_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_false "same-version no-op does not continue" "$(printf '%s\n' "${same_noop_json}" | jq -r '.existing_install.real_install_would_continue_after_existing_install_check')"
assert_false "same-version no-op not blocked as refusal" "$(printf '%s\n' "${same_noop_json}" | jq -r '.write_effects_if_real_install_runs.blocked_by_existing_install')"
assert_false "same-version no-op performs no file writes" "$(printf '%s\n' "${same_noop_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"
assert_equal "same-version no-op plans no retired source removal" "0" \
    "$(printf '%s\n' "${same_noop_json}" | jq '.planned_retired_source_removals | length')"

same_repair_json=$(run_dry_plan "${SAME_HOME}" --surface claude-code --no-machine-helpers --existing-install repair)
assert_equal "same-version repair decision" "repair_existing_install" "$(printf '%s\n' "${same_repair_json}" | jq -r '.existing_install.decision')"
assert_equal "same-version repair operation" "repair" "$(printf '%s\n' "${same_repair_json}" | jq -r '.existing_install.operation')"
assert_true "same-version repair requires backup" "$(printf '%s\n' "${same_repair_json}" | jq -r '.existing_install.requires_backup_before_mutation')"
assert_false "same-version repair does not exit before writes" "$(printf '%s\n' "${same_repair_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"
assert_true "same-version repair would continue" "$(printf '%s\n' "${same_repair_json}" | jq -r '.existing_install.real_install_would_continue_after_existing_install_check')"
assert_true "same-version repair can modify files" "$(printf '%s\n' "${same_repair_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"
assert_false "same-version repair skips existing claude zlar hook" "$(printf '%s\n' "${same_repair_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .planned_hook_write')"
assert_equal "same-version repair plans all retired source removals" "4" \
    "$(printf '%s\n' "${same_repair_json}" | jq '.planned_retired_source_removals | length')"

ABSOLUTE_HOOK_HOME="${TMP_ROOT}/home-absolute-hook"
mkdir -p "${ABSOLUTE_HOOK_HOME}/.zlar" "${ABSOLUTE_HOOK_HOME}/.claude"
printf '%s\n' "${TARGET_VERSION}" > "${ABSOLUTE_HOOK_HOME}/.zlar/VERSION"
printf '{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"%s/.zlar/adapters/claude-code/hook.sh"}]}]}}\n' \
    "${ABSOLUTE_HOOK_HOME}" > "${ABSOLUTE_HOOK_HOME}/.claude/settings.json"
absolute_hook_repair_json=$(run_dry_plan "${ABSOLUTE_HOOK_HOME}" --surface claude-code --no-machine-helpers --existing-install repair)
assert_true "absolute installer-created claude hook is detected as conflict" \
    "$(printf '%s\n' "${absolute_hook_repair_json}" | jq -r '.existing_zlar_hook_profile_conflicts.claude_code')"
assert_false "absolute installer-created claude hook suppresses duplicate hook write" \
    "$(printf '%s\n' "${absolute_hook_repair_json}" | jq -r '.detected_client_surfaces[] | select(.id=="claude_code") | .planned_hook_write')"

same_reinstall_json=$(run_dry_plan "${SAME_HOME}" --surface claude-code --no-machine-helpers --existing-install reinstall)
assert_equal "same-version reinstall decision" "reinstall_existing_install" "$(printf '%s\n' "${same_reinstall_json}" | jq -r '.existing_install.decision')"
assert_equal "same-version reinstall operation" "reinstall" "$(printf '%s\n' "${same_reinstall_json}" | jq -r '.existing_install.operation')"
assert_true "same-version reinstall requires backup" "$(printf '%s\n' "${same_reinstall_json}" | jq -r '.existing_install.requires_backup_before_mutation')"
assert_true "same-version reinstall can modify files" "$(printf '%s\n' "${same_reinstall_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"
assert_equal "same-version reinstall plans all retired source removals" "4" \
    "$(printf '%s\n' "${same_reinstall_json}" | jq '.planned_retired_source_removals | length')"
assert_equal "all same-version dry-runs leave stale retired files byte-identical" "${same_before}" "$(home_snapshot "${SAME_HOME}")"

same_upgrade_json=$(run_dry_plan "${SAME_HOME}" --surface claude-code --no-machine-helpers --existing-install upgrade)
assert_equal "same-version upgrade refuses" "refuse_upgrade_version_not_different" "$(printf '%s\n' "${same_upgrade_json}" | jq -r '.existing_install.decision')"
assert_true "same-version upgrade exits before writes" "$(printf '%s\n' "${same_upgrade_json}" | jq -r '.existing_install.real_install_would_exit_before_writes')"

missing_existing_repair_json=$(run_dry_plan "${PLAN_HOME}" --surface claude-code --no-machine-helpers --existing-install repair)
assert_equal "repair without existing install refuses" "refuse_existing_install_required" "$(printf '%s\n' "${missing_existing_repair_json}" | jq -r '.existing_install.decision')"
assert_false "repair without existing install writes nothing" "$(printf '%s\n' "${missing_existing_repair_json}" | jq -r '.write_effects_if_real_install_runs.would_create_or_modify_files')"

unsupported_scope_json=$(run_dry_plan "${EXISTING_HOME}" --surface cursor --no-machine-helpers --existing-install repair)
assert_equal "existing-install mode refuses non-claude surface" "refuse_existing_install_mode_requires_claude_code_surface" "$(printf '%s\n' "${unsupported_scope_json}" | jq -r '.existing_install.decision')"

missing_no_helpers_json=$(run_dry_plan "${EXISTING_HOME}" --surface claude-code --existing-install repair)
assert_equal "existing-install mode refuses machine helper posture" "refuse_existing_install_mode_requires_no_machine_helpers" "$(printf '%s\n' "${missing_no_helpers_json}" | jq -r '.existing_install.decision')"

ERROR_HOME="${TMP_ROOT}/home-error"
mkdir -p "${ERROR_HOME}"
error_before=$(home_snapshot "${ERROR_HOME}")
set +e
dry_without_json=$(run_plan_error "${ERROR_HOME}" --dry-run)
dry_without_json_status=$?
json_without_dry=$(run_plan_error "${ERROR_HOME}" --json)
json_without_dry_status=$?
unknown_option=$(run_plan_error "${ERROR_HOME}" --bad-option)
unknown_option_status=$?
set -e
error_after=$(home_snapshot "${ERROR_HOME}")
assert_equal "error paths perform no writes" "${error_before}" "${error_after}"
assert_equal "dry-run without json fails" "1" "${dry_without_json_status}"
assert_contains "dry-run without json names machine-checkable plan" "machine-checkable" "${dry_without_json}"
assert_equal "json without dry-run fails" "1" "${json_without_dry_status}"
assert_contains "json without dry-run does not install" "--json is only supported with --dry-run" "${json_without_dry}"
assert_equal "unknown option fails" "1" "${unknown_option_status}"
assert_contains "unknown option names bad option" "Unknown option: --bad-option" "${unknown_option}"

assert_file_contains "installer usage permits scoped real install" "${INSTALLER}" "Usage: bash install.sh [--surface <surface>] [--no-machine-helpers]"
assert_file_contains "installer usage permits existing-install mode" "${INSTALLER}" "--existing-install <mode>"
assert_file_not_contains "installer no longer rejects real surface scope" "${INSTALLER}" "--surface is only supported with --dry-run"
assert_file_not_contains "installer no longer rejects real no-machine-helpers" "${INSTALLER}" "--no-machine-helpers is only supported with --dry-run"
assert_file_contains "installer real mode can no-op existing install" "${INSTALLER}" "no_op_existing_install"
assert_file_contains "installer real mode can repair existing install" "${INSTALLER}" "repair_existing_install"
assert_file_contains "installer real mode can upgrade existing install" "${INSTALLER}" "upgrade_existing_install"
assert_file_contains "installer real mode can reinstall existing install" "${INSTALLER}" "reinstall_existing_install"
assert_file_contains "installer copies dispatcher-required bin wrappers" "${INSTALLER}" 'for wrapper in "${SCRIPT_SOURCE_DIR}/bin"/zlar-*; do'
assert_file_contains "installer chmods copied bin wrappers" "${INSTALLER}" 'chmod +x "${INSTALL_DIR}/bin/${wrapper_name}"'
assert_file_contains "installer removal is limited to accepted existing-install mutation modes" "${INSTALLER}" 'repair|upgrade|reinstall) ;;'
assert_file_contains "installer removes exact retired E1 wrapper residue" "${INSTALLER}" '"${INSTALL_DIR}/bin/zlar-protected-records-write"'
assert_file_contains "installer removes exact retired E2 wrapper residue" "${INSTALLER}" '"${INSTALL_DIR}/bin/zlar-protected-records-service-request"'
assert_file_contains "installer removes exact retired E1 module residue" "${INSTALLER}" '"${INSTALL_DIR}/lib/protected-records-adapter.mjs"'
assert_file_contains "installer removes exact retired E2 module residue" "${INSTALLER}" '"${INSTALL_DIR}/lib/protected-records-service.mjs"'
assert_file_contains "installer invokes exact retired source cleanup" "${INSTALLER}" 'remove_retired_installed_positive_source_surfaces'
assert_file_contains "installer validates retired paths before cleanup" "${INSTALLER}" 'validate_retired_installed_positive_source_surfaces'
assert_file_contains "installer validates retired path parents before cleanup" "${INSTALLER}" 'validate_retired_installed_positive_source_parents'
assert_file_contains "installer names unexpected cleanup path type refusal" "${INSTALLER}" 'Retired source cleanup refused unexpected file type'
assert_file_contains "installer names unsafe cleanup parent refusal" "${INSTALLER}" 'Retired source cleanup refused unsafe parent'
assert_file_not_contains "installer does not recursively delete retired paths" "${INSTALLER}" 'rm -rf --'
assert_file_contains "installer requires claude surface for existing install modes" "${INSTALLER}" "existing-install modes other than refuse require --surface claude-code"
assert_file_contains "installer refuses unknown-version repair" "${INSTALLER}" "refuse_repair_unknown_version"
assert_file_contains "installer dry-run claude conflict uses exact hook target" "${INSTALLER}" 'cc_conflict=$(detect_existing_zlar_hook "${HOME}/.claude/settings.json" "~/.zlar/adapters/claude-code/hook.sh")'
assert_file_contains "installer dry-run cursor conflict uses exact hook target" "${INSTALLER}" 'cursor_conflict=$(detect_existing_zlar_hook "${HOME}/.cursor/hooks.json" "~/.zlar/adapters/cursor/hook.sh")'
assert_file_contains "installer dry-run windsurf conflict uses exact hook target" "${INSTALLER}" 'windsurf_conflict=$(detect_existing_zlar_hook "${HOME}/.codeium/windsurf/hooks.json" "~/.zlar/adapters/windsurf/hook.sh")'
assert_file_contains "installer counts selected claude hook only" "${INSTALLER}" 'if surface_is_selected "claude_code" && [ "$(detect_existing_zlar_hook "${HOME}/.claude/settings.json" "~/.zlar/adapters/claude-code/hook.sh")" -eq 1 ]; then'
assert_file_contains "installer uses shared hook detector in real claude config" "${INSTALLER}" 'if [ "$(detect_existing_zlar_hook "${CC_SETTINGS}" "${CC_HOOK}")" -eq 1 ]; then'
assert_file_contains "installer gates real cursor hook by selected surface" "${INSTALLER}" 'if surface_is_selected "cursor" && [ "${HAS_CURSOR}" -eq 1 ]; then'
assert_file_contains "installer gates real windsurf hook by selected surface" "${INSTALLER}" 'if surface_is_selected "windsurf" && [ "${HAS_WINDSURF}" -eq 1 ]; then'
assert_file_contains "installer gates real cursor adapter copy by selected surface" "${INSTALLER}" 'if surface_is_selected "cursor"; then'

assert_file_contains "Install doc names installer-managed Claude/Cursor/Windsurf profiles" "${README_FILE}" "Installer-managed framework hook/profile settings for detected Claude Code"
assert_file_contains "Install doc names scoped install surface behavior" "${README_FILE}" 'Use `--surface claude-code` to scope install or dry-run planning to Claude Code'
assert_file_contains "Install doc names explicit existing-install modes" "${README_FILE}" '`--existing-install no-op|repair|upgrade|reinstall`'
assert_file_contains "Install doc says repair refuses unknown version" "${README_FILE}" '`repair` is same-version only and refuses a missing, empty, unreadable,'
assert_file_contains "Install doc bounds Codex hook reality to local verification" "${README_FILE}" "Codex hook reality is host/version-specific"
assert_file_not_contains "Install doc no longer claims installer-managed Codex hook path" "${README_FILE}" 'including Codex `~/.codex/hooks.json`'
assert_file_contains "troubleshooting avoids installer-managed Codex assumption" "${TROUBLESHOOTING_DOC}" 'For Codex, do not assume `install.sh` configured the route.'
assert_file_contains "troubleshooting names host-specific Codex config" "${TROUBLESHOOTING_DOC}" "hook/profile paths are host/version-specific"
assert_file_not_contains "troubleshooting no longer names old Codex hook pair" "${TROUBLESHOOTING_DOC}" '`~/.codex/hooks.json` or `~/.Codex/hooks.json`'
assert_file_contains "architecture map keeps Codex hook path locally verified" "${ARCHITECTURE_MAP}" "host-specific"
assert_file_contains "architecture map says Codex hook path is verified on that machine" "${ARCHITECTURE_MAP}" "Codex hook/profile path verified on that machine"
assert_file_not_contains "architecture map no longer hard-codes old Codex hook file" "${ARCHITECTURE_MAP}" 'Codex `~/.codex/hooks.json`'
assert_file_contains "CLI reference does not publish stale Codex hook path" "${CLI_REFERENCE}" "Codex hook target (PreToolUse):              <verify locally; host/version-specific>"
assert_file_contains "doctor fix text avoids installer-managed Codex claim" "${ZLAR_CLI}" "install.sh manages Claude Code, Cursor, and Windsurf hook profiles"
assert_file_not_contains "doctor no longer tells users install.sh fixes missing Codex hook" "${ZLAR_CLI}" "Fix: run \${BOLD}bash install.sh\${NC} or add the Codex hook manually"

echo
echo "${PASS} passed, ${FAIL} failed out of ${TOTAL} tests"
[ "${FAIL}" -eq 0 ] || exit 1
