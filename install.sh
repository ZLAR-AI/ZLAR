#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# ZLAR — Zero-Config Install
#
# curl -fsSL https://zlar.ai/install.sh | bash
#
# Auto-detects Claude Code, Cursor, Windsurf.
# Generates keys. Signs a deny-heavy policy. Configures hooks.
# Governance running in under 60 seconds.
#
# This script must be bash-3.x compatible (macOS default ships 3.2).
# ═══════════════════════════════════════════════════════════════════════════════

# Strict mode (bash-3 safe: no pipefail in POSIX sh)
set -eu

# Read version from the VERSION file if running from a repo clone.
# When run via `curl | bash`, the script has no neighboring VERSION file;
# leave ZLAR_VERSION empty here and resolve it from SCRIPT_SOURCE_DIR/VERSION
# after Phase 4, once the source is downloaded or cloned.
_INSTALL_SELF="${BASH_SOURCE:-$0}"
_INSTALL_SELF_DIR=""
if [ -n "${_INSTALL_SELF}" ] && [ -f "${_INSTALL_SELF}" ]; then
    _INSTALL_SELF_DIR="$(cd "$(dirname "${_INSTALL_SELF}")" 2>/dev/null && pwd)"
fi
ZLAR_VERSION=""
if [ -n "${_INSTALL_SELF_DIR}" ] && [ -f "${_INSTALL_SELF_DIR}/VERSION" ]; then
    ZLAR_VERSION=$(cat "${_INSTALL_SELF_DIR}/VERSION" | tr -d '[:space:]')
fi
INSTALL_DIR="${HOME}/.zlar"

# ─── Colors (bash-3 safe) ────────────────────────────────────────────────────

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; DIM=''; NC=''
fi

ok()   { printf "${GREEN}  ✓${NC} %s\n" "$*"; }
fail() { printf "${RED}  ✗${NC} %s\n" "$*" >&2; }
warn() { printf "${YELLOW}  ⚠${NC} %s\n" "$*"; }
info() { printf "${BLUE}  ℹ${NC} %s\n" "$*"; }
step() { printf "\n${BOLD}%s${NC}\n\n" "$*"; }

DRY_RUN=0
JSON_OUTPUT=0
INSTALL_SURFACE="all"
SKIP_MACHINE_HELPERS=0
EXISTING_INSTALL_MODE="refuse"

usage() {
    printf "Usage: bash install.sh [--surface <surface>] [--no-machine-helpers] [--existing-install <mode>]\n"
    printf "       bash install.sh --dry-run --json [--surface <surface>] [--no-machine-helpers] [--existing-install <mode>]\n"
    printf "  --dry-run --json [--surface <surface>] [--no-machine-helpers] [--existing-install <mode>]\n"
    printf "    --surface <surface>           install or plan for one supported surface only\n"
    printf "                                 supported: all, claude-code, cursor, windsurf\n"
    printf "    --no-machine-helpers          omit optional /usr/local/bin helper writes\n"
    printf "    --existing-install <mode>     explicit existing-install handling\n"
    printf "                                 supported: refuse, no-op, repair, upgrade, reinstall\n"
    printf "    --dry-run --json               emit a no-write install plan and exit\n"
}

normalize_surface() {
    case "$1" in
        all) printf 'all' ;;
        claude|claude-code|claude_code) printf 'claude_code' ;;
        cursor) printf 'cursor' ;;
        windsurf) printf 'windsurf' ;;
        *) printf 'unknown' ;;
    esac
}

normalize_existing_install_mode() {
    case "$1" in
        refuse|default) printf 'refuse' ;;
        no-op|noop|no_op) printf 'no_op' ;;
        repair) printf 'repair' ;;
        upgrade) printf 'upgrade' ;;
        reinstall) printf 'reinstall' ;;
        *) printf 'unknown' ;;
    esac
}

existing_install_mode_cli() {
    case "${EXISTING_INSTALL_MODE}" in
        no_op) printf 'no-op' ;;
        *) printf '%s' "${EXISTING_INSTALL_MODE}" ;;
    esac
}

is_surface_selected() {
    local requested="$1"
    if [ "${INSTALL_SURFACE}" = "all" ]; then
        printf "1"
    elif [ "${INSTALL_SURFACE}" = "${requested}" ]; then
        printf "1"
    else
        printf "0"
    fi
}

surface_is_selected() {
    [ "$(is_surface_selected "$1")" -eq 1 ]
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --json) JSON_OUTPUT=1 ;;
        --surface)
            if [ "$#" -lt 2 ]; then
                fail "Missing value for --surface"
                usage >&2
                exit 1
            fi
            INSTALL_SURFACE="$(normalize_surface "$2")"
            if [ "${INSTALL_SURFACE}" = "unknown" ]; then
                fail "Unknown surface: $2"
                usage >&2
                exit 1
            fi
            shift
            ;;
        --no-machine-helpers)
            SKIP_MACHINE_HELPERS=1
            ;;
        --existing-install)
            if [ "$#" -lt 2 ]; then
                fail "Missing value for --existing-install"
                usage >&2
                exit 1
            fi
            EXISTING_INSTALL_MODE="$(normalize_existing_install_mode "$2")"
            if [ "${EXISTING_INSTALL_MODE}" = "unknown" ]; then
                fail "Unknown existing-install mode: $2"
                usage >&2
                exit 1
            fi
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if [ "${JSON_OUTPUT}" -eq 1 ] && [ "${DRY_RUN}" -ne 1 ]; then
    fail "--json is only supported with --dry-run"
    printf "Usage: bash install.sh --dry-run --json\n" >&2
    exit 1
fi

json_bool() {
    if [ "${1}" -eq 1 ] 2>/dev/null; then
        printf "true"
    else
        printf "false"
    fi
}

json_escape() {
    printf '%s' "${1}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_string() {
    printf '"%s"' "$(json_escape "${1}")"
}

file_sha256() {
    local path="$1"
    if [ ! -f "${path}" ]; then
        printf "unknown"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}" 2>/dev/null | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" 2>/dev/null | awk '{print $1}'
    else
        printf "unknown"
    fi
}

emit_planned_file_write() {
    local path="$1"
    local category="$2"
    local action="$3"

    if [ "${PLAN_WRITE_COUNT}" -gt 0 ]; then
        printf ",\n"
    fi
    printf '    {"path":%s,"category":%s,"action":%s}' \
        "$(json_string "${path}")" \
        "$(json_string "${category}")" \
        "$(json_string "${action}")"
    PLAN_WRITE_COUNT=$((PLAN_WRITE_COUNT + 1))
}

is_retired_installed_bin_wrapper() {
    case "$1" in
        zlar-protected-records-service-request) return 0 ;;
        zlar-protected-records-write) return 0 ;;
        *) return 1 ;;
    esac
}

is_retired_installed_library() {
    case "$1" in
        protected-records-adapter.mjs) return 0 ;;
        protected-records-service.mjs) return 0 ;;
        *) return 1 ;;
    esac
}

emit_planned_installed_bin_wrappers_json() {
    local wrapper
    local wrapper_name
    local wrapper_count=0

    printf '  "planned_installed_bin_wrappers": [\n'
    if [ -n "${_INSTALL_SELF_DIR}" ] && [ -d "${_INSTALL_SELF_DIR}/bin" ]; then
        for wrapper in "${_INSTALL_SELF_DIR}/bin"/zlar-*; do
            [ -f "${wrapper}" ] || continue
            wrapper_name="$(basename "${wrapper}")"
            is_retired_installed_bin_wrapper "${wrapper_name}" && continue
            if [ "${wrapper_count}" -gt 0 ]; then
                printf ',\n'
            fi
            printf '    %s' "$(json_string "${wrapper_name}")"
            wrapper_count=$((wrapper_count + 1))
        done
    fi
    printf '\n  ],\n'
}

retired_installed_positive_source_paths() {
    printf '%s\n' \
        "bin/zlar-protected-records-write" \
        "bin/zlar-protected-records-service-request" \
        "lib/protected-records-adapter.mjs" \
        "lib/protected-records-service.mjs"
}

retired_source_cleanup_parent_refusal_reason() {
    local path="$1"

    if [ -L "${path}" ]; then
        printf 'symlinked_parent'
    elif [ -e "${path}" ] && [ ! -d "${path}" ]; then
        printf 'non_directory_parent'
    fi
}

retired_source_cleanup_has_unsafe_parent() {
    local parent_path

    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall) ;;
        *) return 1 ;;
    esac

    for parent_path in \
        "${INSTALL_DIR}" \
        "${INSTALL_DIR}/bin" \
        "${INSTALL_DIR}/lib"; do
        if [ -n "$(retired_source_cleanup_parent_refusal_reason "${parent_path}")" ]; then
            return 0
        fi
    done
    return 1
}

emit_planned_retired_source_removals_json() {
    local relative_path
    local absolute_path
    local removal_count=0

    printf '  "planned_retired_source_removals": [\n'
    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall)
            if ! retired_source_cleanup_has_unsafe_parent; then
                while IFS= read -r relative_path; do
                    absolute_path="${INSTALL_DIR}/${relative_path}"
                    if [ -f "${absolute_path}" ] || [ -L "${absolute_path}" ]; then
                        if [ "${removal_count}" -gt 0 ]; then
                            printf ',\n'
                        fi
                        printf '    {"path":%s,"action":"remove_retired_positive_source_residue"}' \
                            "$(json_string "~/.zlar/${relative_path}")"
                        removal_count=$((removal_count + 1))
                    fi
                done <<EOF
$(retired_installed_positive_source_paths)
EOF
            fi
            ;;
    esac
    printf '\n  ],\n'
}

emit_planned_retired_source_cleanup_refusals_json() {
    local relative_path
    local absolute_path
    local refusal_count=0

    printf '  "planned_retired_source_cleanup_refusals": [\n'
    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall)
            if ! retired_source_cleanup_has_unsafe_parent; then
                while IFS= read -r relative_path; do
                    absolute_path="${INSTALL_DIR}/${relative_path}"
                    if { [ -e "${absolute_path}" ] || [ -L "${absolute_path}" ]; } && \
                       [ ! -f "${absolute_path}" ] && [ ! -L "${absolute_path}" ]; then
                        if [ "${refusal_count}" -gt 0 ]; then
                            printf ',\n'
                        fi
                        printf '    {"path":%s,"reason":"unexpected_file_type"}' \
                            "$(json_string "~/.zlar/${relative_path}")"
                        refusal_count=$((refusal_count + 1))
                    fi
                done <<EOF
$(retired_installed_positive_source_paths)
EOF
            fi
            ;;
    esac
    printf '\n  ],\n'
}

emit_planned_retired_source_parent_refusals_json() {
    local relative_parent
    local absolute_parent
    local display_parent
    local reason
    local refusal_count=0

    printf '  "planned_retired_source_parent_refusals": [\n'
    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall)
            for relative_parent in "" "bin" "lib"; do
                absolute_parent="${INSTALL_DIR}"
                display_parent="~/.zlar"
                if [ -n "${relative_parent}" ]; then
                    absolute_parent="${INSTALL_DIR}/${relative_parent}"
                    display_parent="~/.zlar/${relative_parent}"
                fi
                reason="$(retired_source_cleanup_parent_refusal_reason "${absolute_parent}")"
                if [ -n "${reason}" ]; then
                    if [ "${refusal_count}" -gt 0 ]; then
                        printf ',\n'
                    fi
                    printf '    {"path":%s,"reason":%s}' \
                        "$(json_string "${display_parent}")" \
                        "$(json_string "${reason}")"
                    refusal_count=$((refusal_count + 1))
                fi
            done
            ;;
    esac
    printf '\n  ],\n'
}

retired_source_cleanup_has_unexpected_file_type() {
    local relative_path
    local absolute_path

    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall) ;;
        *) return 1 ;;
    esac

    if retired_source_cleanup_has_unsafe_parent; then
        return 1
    fi

    while IFS= read -r relative_path; do
        absolute_path="${INSTALL_DIR}/${relative_path}"
        if { [ -e "${absolute_path}" ] || [ -L "${absolute_path}" ]; } && \
           [ ! -f "${absolute_path}" ] && [ ! -L "${absolute_path}" ]; then
            return 0
        fi
    done <<EOF
$(retired_installed_positive_source_paths)
EOF
    return 1
}

copy_installed_bin_wrappers() {
    local wrapper
    local wrapper_name

    for wrapper in "${SCRIPT_SOURCE_DIR}/bin"/zlar-*; do
        [ -f "${wrapper}" ] || continue
        wrapper_name="$(basename "${wrapper}")"
        is_retired_installed_bin_wrapper "${wrapper_name}" && continue
        cp "${wrapper}" "${INSTALL_DIR}/bin/${wrapper_name}"
        chmod +x "${INSTALL_DIR}/bin/${wrapper_name}"
    done
}

copy_installed_libraries() {
    local library
    local library_name

    for library in "${SCRIPT_SOURCE_DIR}/lib/"*; do
        [ -f "${library}" ] || continue
        library_name="$(basename "${library}")"
        is_retired_installed_library "${library_name}" && continue
        cp "${library}" "${INSTALL_DIR}/lib/${library_name}"
    done
}

remove_retired_installed_positive_source_surfaces() {
    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall) ;;
        *) return 0 ;;
    esac

    validate_retired_installed_positive_source_surfaces
    rm -f -- \
        "${INSTALL_DIR}/bin/zlar-protected-records-write" \
        "${INSTALL_DIR}/bin/zlar-protected-records-service-request" \
        "${INSTALL_DIR}/lib/protected-records-adapter.mjs" \
        "${INSTALL_DIR}/lib/protected-records-service.mjs"
}

validate_retired_installed_positive_source_surfaces() {
    local relative_path
    local absolute_path

    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall) ;;
        *) return 0 ;;
    esac

    validate_retired_installed_positive_source_parents

    while IFS= read -r relative_path; do
        absolute_path="${INSTALL_DIR}/${relative_path}"
        if { [ -e "${absolute_path}" ] || [ -L "${absolute_path}" ]; } && \
           [ ! -f "${absolute_path}" ] && [ ! -L "${absolute_path}" ]; then
            fail "Retired source cleanup refused unexpected file type: ${absolute_path}"
            return 1
        fi
    done <<EOF
$(retired_installed_positive_source_paths)
EOF
}

validate_retired_installed_positive_source_parents() {
    local parent_path
    local reason

    case "${EXISTING_INSTALL_OPERATION}" in
        repair|upgrade|reinstall) ;;
        *) return 0 ;;
    esac

    for parent_path in \
        "${INSTALL_DIR}" \
        "${INSTALL_DIR}/bin" \
        "${INSTALL_DIR}/lib"; do
        reason="$(retired_source_cleanup_parent_refusal_reason "${parent_path}")"
        if [ -n "${reason}" ]; then
            fail "Retired source cleanup refused unsafe parent (${reason}): ${parent_path}"
            return 1
        fi
    done
}

detect_existing_zlar_hook() {
    local path="$1"
    local expected_target="${2:-}"
    local expected_home_target="${expected_target}"
    local expected_absolute_target="${expected_target}"
    local hook_kind="unknown"

    case "${expected_target}" in
        "${HOME}/"*) expected_home_target="~/${expected_target#"${HOME}/"}" ;;
        "~/"*) expected_absolute_target="${HOME}/${expected_target#"~/"}" ;;
    esac
    case "${expected_target}" in
        *"/claude-code/"*) hook_kind="claude_code" ;;
        *"/cursor/"*) hook_kind="cursor" ;;
        *"/windsurf/"*) hook_kind="windsurf" ;;
    esac

    if [ ! -f "${path}" ] || [ -z "${expected_target}" ]; then
        printf "0"
        return
    fi

    if ! command -v jq >/dev/null 2>&1; then
        printf "0"
        return
    fi

    case "${hook_kind}" in
        claude_code)
            jq -e \
                --arg expected "${expected_target}" \
                --arg expected_home "${expected_home_target}" \
                --arg expected_absolute "${expected_absolute_target}" '
                [(.hooks.PreToolUse // [])[]? | .hooks[]? | objects
                 | select((.type? // "command") == "command")
                 | .command? // empty
                 | select(type == "string")]
                | any(. == $expected or . == $expected_home or . == $expected_absolute)
            ' "${path}" >/dev/null 2>&1
            ;;
        cursor)
            jq -e \
                --arg expected "${expected_target}" \
                --arg expected_home "${expected_home_target}" \
                --arg expected_absolute "${expected_absolute_target}" '
                [((.beforeShellExecution // [])[]?,
                  (.beforeReadFile // [])[]?,
                  (.beforeMCPExecution // [])[]?) | objects
                 | .command? // empty
                 | select(type == "string")]
                | any(. == $expected or . == $expected_home or . == $expected_absolute)
            ' "${path}" >/dev/null 2>&1
            ;;
        windsurf)
            jq -e \
                --arg expected "${expected_target}" \
                --arg expected_home "${expected_home_target}" \
                --arg expected_absolute "${expected_absolute_target}" '
                [((.pre_run_command // [])[]?,
                  (.pre_write_code // [])[]?,
                  (.pre_read_code // [])[]?,
                  (.pre_mcp_tool_use // [])[]?) | objects
                 | .command? // empty
                 | select(type == "string")]
                | any(. == $expected or . == $expected_home or . == $expected_absolute)
            ' "${path}" >/dev/null 2>&1
            ;;
        *)
            printf "0"
            return
            ;;
    esac
    if [ "$?" -eq 0 ]; then
        printf "1"
    else
        printf "0"
    fi
}

read_existing_install_version() {
    local existing_version_value
    if [ -f "${INSTALL_DIR}/VERSION" ]; then
        existing_version_value=$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || printf "unknown")
        existing_version_value=$(printf '%s' "${existing_version_value}" | tr -d '[:space:]')
        if [ -n "${existing_version_value}" ]; then
            printf '%s' "${existing_version_value}"
        else
            printf 'unknown'
        fi
    else
        printf 'unknown'
    fi
}

set_existing_install_decision() {
    local install_exists="$1"
    local existing_version="$2"
    local target_version="$3"

    EXISTING_INSTALL_DECISION="fresh_install"
    EXISTING_INSTALL_OPERATION="fresh_install"
    EXISTING_INSTALL_REFUSAL_REASON=""
    EXISTING_INSTALL_EXIT_BEFORE_WRITES=0
    EXISTING_INSTALL_CONTINUES=1
    EXISTING_INSTALL_BLOCKED=0
    EXISTING_INSTALL_REQUIRES_BACKUP=0

    if [ "${EXISTING_INSTALL_MODE}" != "refuse" ]; then
        if [ "${INSTALL_SURFACE}" != "claude_code" ]; then
            EXISTING_INSTALL_DECISION="refuse_existing_install_mode_requires_claude_code_surface"
            EXISTING_INSTALL_OPERATION="refusal"
            EXISTING_INSTALL_REFUSAL_REASON="existing-install modes other than refuse require --surface claude-code"
        elif [ "${SKIP_MACHINE_HELPERS}" -ne 1 ]; then
            EXISTING_INSTALL_DECISION="refuse_existing_install_mode_requires_no_machine_helpers"
            EXISTING_INSTALL_OPERATION="refusal"
            EXISTING_INSTALL_REFUSAL_REASON="existing-install modes other than refuse require --no-machine-helpers"
        elif [ "${target_version}" = "unknown" ] || [ -z "${target_version}" ]; then
            EXISTING_INSTALL_DECISION="refuse_existing_install_mode_requires_known_target_version"
            EXISTING_INSTALL_OPERATION="refusal"
            EXISTING_INSTALL_REFUSAL_REASON="existing-install modes require a local source VERSION"
        elif [ "${install_exists}" -eq 0 ]; then
            EXISTING_INSTALL_DECISION="refuse_existing_install_required"
            EXISTING_INSTALL_OPERATION="refusal"
            EXISTING_INSTALL_REFUSAL_REASON="requested existing-install mode but no existing install was detected"
        else
            case "${EXISTING_INSTALL_MODE}" in
                no_op)
                    if [ "${existing_version}" = "unknown" ] || [ -z "${existing_version}" ]; then
                        EXISTING_INSTALL_DECISION="refuse_no_op_unknown_version"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="no-op requires a readable existing VERSION"
                    elif [ "${existing_version}" = "${target_version}" ]; then
                        EXISTING_INSTALL_DECISION="no_op_existing_install"
                        EXISTING_INSTALL_OPERATION="no_op"
                        EXISTING_INSTALL_EXIT_BEFORE_WRITES=1
                        EXISTING_INSTALL_CONTINUES=0
                    else
                        EXISTING_INSTALL_DECISION="refuse_no_op_version_mismatch"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="no-op requires existing VERSION to match target VERSION"
                    fi
                    ;;
                repair)
                    if [ "${existing_version}" = "unknown" ] || [ -z "${existing_version}" ]; then
                        EXISTING_INSTALL_DECISION="refuse_repair_unknown_version"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="repair requires a readable existing VERSION"
                    elif [ "${existing_version}" = "${target_version}" ]; then
                        EXISTING_INSTALL_DECISION="repair_existing_install"
                        EXISTING_INSTALL_OPERATION="repair"
                        EXISTING_INSTALL_REQUIRES_BACKUP=1
                    else
                        EXISTING_INSTALL_DECISION="refuse_repair_version_mismatch"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="repair is same-version only; use upgrade or reinstall for version changes"
                    fi
                    ;;
                upgrade)
                    if [ "${existing_version}" = "unknown" ] || [ -z "${existing_version}" ]; then
                        EXISTING_INSTALL_DECISION="refuse_upgrade_unknown_version"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="upgrade requires a readable existing VERSION"
                    elif [ "${existing_version}" != "${target_version}" ]; then
                        EXISTING_INSTALL_DECISION="upgrade_existing_install"
                        EXISTING_INSTALL_OPERATION="upgrade"
                        EXISTING_INSTALL_REQUIRES_BACKUP=1
                    else
                        EXISTING_INSTALL_DECISION="refuse_upgrade_version_not_different"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="upgrade requires existing VERSION to differ from target VERSION"
                    fi
                    ;;
                reinstall)
                    if [ "${existing_version}" = "unknown" ] || [ -z "${existing_version}" ]; then
                        EXISTING_INSTALL_DECISION="refuse_reinstall_unknown_version"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="reinstall requires a readable existing VERSION"
                    elif [ "${existing_version}" = "${target_version}" ]; then
                        EXISTING_INSTALL_DECISION="reinstall_existing_install"
                        EXISTING_INSTALL_OPERATION="reinstall"
                        EXISTING_INSTALL_REQUIRES_BACKUP=1
                    else
                        EXISTING_INSTALL_DECISION="refuse_reinstall_version_mismatch"
                        EXISTING_INSTALL_OPERATION="refusal"
                        EXISTING_INSTALL_REFUSAL_REASON="reinstall is same-version only; use upgrade for version changes"
                    fi
                    ;;
            esac
        fi
    elif [ "${install_exists}" -eq 1 ]; then
        EXISTING_INSTALL_DECISION="refuse_existing_install"
        EXISTING_INSTALL_OPERATION="refusal"
        EXISTING_INSTALL_REFUSAL_REASON="existing install detected"
    fi

    case "${EXISTING_INSTALL_DECISION}" in
        refuse_*)
            EXISTING_INSTALL_EXIT_BEFORE_WRITES=1
            EXISTING_INSTALL_CONTINUES=0
            EXISTING_INSTALL_BLOCKED=1
            ;;
    esac
}

detect_client_surface_json() {
    local id="$1"
    local label="$2"
    local cli="$3"
    local dir="$4"
    local config="$5"
    local hook_target="$6"
    local selected="$7"
    local config_display="${config}"
    local cli_detected=0
    local dir_detected=0
    local detected=0
    local conflict=0
    local planned_hook_write=0
    local planned_action="none_framework_not_detected"

    case "${config}" in
        "${HOME}/"*) config_display="~/${config#"${HOME}/"}" ;;
    esac

    if [ -n "${cli}" ] && command -v "${cli}" >/dev/null 2>&1; then
        cli_detected=1
    fi
    if [ -d "${dir}" ]; then
        dir_detected=1
    fi
    if [ "${cli_detected}" -eq 1 ] || [ "${dir_detected}" -eq 1 ]; then
        detected=1
    fi
    conflict=$(detect_existing_zlar_hook "${config}" "${hook_target}")
    if [ "${selected}" -eq 0 ]; then
        planned_hook_write=0
        if [ "${detected}" -eq 1 ]; then
            planned_action="not_selected_by_surface_filter"
        fi
    elif [ "${detected}" -eq 1 ] && [ "${conflict}" -eq 0 ]; then
        planned_hook_write=1
        if [ -f "${config}" ]; then
            planned_action="modify_existing_hook_profile"
        else
            planned_action="create_hook_profile"
        fi
    elif [ "${detected}" -eq 1 ] && [ "${conflict}" -eq 1 ]; then
        planned_action="skip_existing_zlar_hook_profile"
    fi

    printf '{'
    printf '"id":%s,' "$(json_string "${id}")"
    printf '"label":%s,' "$(json_string "${label}")"
    printf '"detected":%s,' "$(json_bool "${detected}")"
    printf '"cli_detected":%s,' "$(json_bool "${cli_detected}")"
    printf '"config_dir_detected":%s,' "$(json_bool "${dir_detected}")"
    printf '"selected_surface":%s,' "$(json_bool "${selected}")"
    printf '"hook_profile_path":%s,' "$(json_string "${config_display}")"
    printf '"planned_hook_target":%s,' "$(json_string "${hook_target}")"
    printf '"existing_zlar_hook_profile_conflict":%s,' "$(json_bool "${conflict}")"
    printf '"planned_hook_write":%s,' "$(json_bool "${planned_hook_write}")"
    printf '"planned_action":%s' "$(json_string "${planned_action}")"
    printf '}'
}

emit_install_plan_json() {
    local install_exists=0
    local existing_version="not_installed"
    local signing_key_exists=0
    local cc_conflict=0 cursor_conflict=0 windsurf_conflict=0
    local cc_detected=0 cursor_detected=0 windsurf_detected=0
    local cc_hook_write=0 cursor_hook_write=0 windsurf_hook_write=0
    local selected_cc=0 selected_cursor=0 selected_windsurf=0
    local hook_write_planned=0
    local single_surface_scope=0
    local effective_write=1
    local would_keys=1
    local would_user_config=1
    local would_machine_config=1
    local machine_helper_write=1
    local retired_source_cleanup_blocked=0
    local real_install_would_exit_before_writes=0
    local command_line
    local source_label="unknown"
    local source_state="unknown"
    local source_commit_sha="unknown"
    local source_tree_sha="unknown"
    local installer_git_blob_sha="unknown"
    local installer_sha256="unknown"
    local existing_mode_cli

    if [ -d "${INSTALL_DIR}" ]; then
        install_exists=1
        existing_version="$(read_existing_install_version)"
    fi
    set_existing_install_decision "${install_exists}" "${existing_version}" "${ZLAR_VERSION:-unknown}"
    if retired_source_cleanup_has_unsafe_parent || \
       retired_source_cleanup_has_unexpected_file_type; then
        retired_source_cleanup_blocked=1
    fi
    if [ "${EXISTING_INSTALL_EXIT_BEFORE_WRITES}" -eq 1 ] || \
       [ "${retired_source_cleanup_blocked}" -eq 1 ]; then
        real_install_would_exit_before_writes=1
    fi
    if [ -f "${HOME}/.zlar-signing.key" ]; then signing_key_exists=1; fi

    if command -v claude >/dev/null 2>&1 || [ -d "${HOME}/.claude" ]; then cc_detected=1; fi
    if command -v cursor >/dev/null 2>&1 || [ -d "${HOME}/.cursor" ]; then cursor_detected=1; fi
    if command -v windsurf >/dev/null 2>&1 || [ -d "${HOME}/.codeium/windsurf" ]; then windsurf_detected=1; fi
    cc_conflict=$(detect_existing_zlar_hook "${HOME}/.claude/settings.json" "~/.zlar/adapters/claude-code/hook.sh")
    cursor_conflict=$(detect_existing_zlar_hook "${HOME}/.cursor/hooks.json" "~/.zlar/adapters/cursor/hook.sh")
    windsurf_conflict=$(detect_existing_zlar_hook "${HOME}/.codeium/windsurf/hooks.json" "~/.zlar/adapters/windsurf/hook.sh")

    selected_cc=$(is_surface_selected "claude_code")
    selected_cursor=$(is_surface_selected "cursor")
    selected_windsurf=$(is_surface_selected "windsurf")
    if [ "${INSTALL_SURFACE}" != "all" ]; then
        single_surface_scope=1
    fi

    if [ "${selected_cc}" -eq 1 ] && [ "${cc_detected}" -eq 1 ] && [ "${cc_conflict}" -eq 0 ]; then cc_hook_write=1; fi
    if [ "${selected_cursor}" -eq 1 ] && [ "${cursor_detected}" -eq 1 ] && [ "${cursor_conflict}" -eq 0 ]; then cursor_hook_write=1; fi
    if [ "${selected_windsurf}" -eq 1 ] && [ "${windsurf_detected}" -eq 1 ] && [ "${windsurf_conflict}" -eq 0 ]; then windsurf_hook_write=1; fi
    if [ "${cc_hook_write}" -eq 1 ] || [ "${cursor_hook_write}" -eq 1 ] || [ "${windsurf_hook_write}" -eq 1 ]; then
        hook_write_planned=1
    fi

    if [ "${EXISTING_INSTALL_CONTINUES}" -eq 0 ] || [ "${retired_source_cleanup_blocked}" -eq 1 ]; then
        effective_write=0
        would_keys=0
        hook_write_planned=0
        would_user_config=0
        would_machine_config=0
    fi

    if [ -n "${_INSTALL_SELF_DIR}" ] && [ -f "${_INSTALL_SELF_DIR}/bin/zlar-gate" ] && [ -f "${_INSTALL_SELF_DIR}/bin/zlar-policy" ]; then
        source_label="local_source"
    fi
    if [ -n "${_INSTALL_SELF_DIR}" ] && [ -f "${_INSTALL_SELF_DIR}/install.sh" ]; then
        installer_sha256=$(file_sha256 "${_INSTALL_SELF_DIR}/install.sh")
    fi
    if [ -n "${_INSTALL_SELF_DIR}" ] && command -v git >/dev/null 2>&1 && git -C "${_INSTALL_SELF_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        source_commit_sha=$(git -C "${_INSTALL_SELF_DIR}" rev-parse HEAD 2>/dev/null || printf "unknown")
        source_tree_sha=$(git -C "${_INSTALL_SELF_DIR}" rev-parse HEAD^{tree} 2>/dev/null || printf "unknown")
        installer_git_blob_sha=$(git -C "${_INSTALL_SELF_DIR}" ls-tree HEAD install.sh 2>/dev/null | awk '{print $3}')
        if [ -z "${installer_git_blob_sha}" ]; then
            installer_git_blob_sha="unknown"
        fi
        if git -C "${_INSTALL_SELF_DIR}" diff --quiet -- . 2>/dev/null && \
            git -C "${_INSTALL_SELF_DIR}" diff --cached --quiet -- . 2>/dev/null && \
            [ -z "$(git -C "${_INSTALL_SELF_DIR}" ls-files --others --exclude-standard 2>/dev/null)" ]; then
            source_state="tracked_clean"
        else
            source_state="tracked_dirty"
        fi
    fi

    printf '{\n'
    printf '  "schema_version": 1,\n'
    printf '  "plan_type": "zlar-install-plan-v1",\n'
    command_line="install.sh --dry-run --json"
    if [ "${INSTALL_SURFACE}" != "all" ]; then
        command_line="${command_line} --surface ${INSTALL_SURFACE}"
    fi
    if [ "${SKIP_MACHINE_HELPERS}" -ne 0 ]; then
        command_line="${command_line} --no-machine-helpers"
    fi
    if [ "${EXISTING_INSTALL_MODE}" != "refuse" ]; then
        existing_mode_cli="$(existing_install_mode_cli)"
        command_line="${command_line} --existing-install ${existing_mode_cli}"
    fi
    if [ "${SKIP_MACHINE_HELPERS}" -ne 0 ]; then
        would_machine_config=0
        machine_helper_write=0
    fi
    printf '  "command": %s,\n' "$(json_string "${command_line}")"
    printf '  "source": %s,\n' "$(json_string "${source_label}")"
    printf '  "source_identity": {\n'
    printf '    "source_state": %s,\n' "$(json_string "${source_state}")"
    printf '    "source_commit_sha": %s,\n' "$(json_string "${source_commit_sha}")"
    printf '    "source_tree_sha": %s,\n' "$(json_string "${source_tree_sha}")"
    printf '    "installer_path": "install.sh",\n'
    printf '    "installer_git_blob_sha": %s,\n' "$(json_string "${installer_git_blob_sha}")"
    printf '    "installer_sha256": %s\n' "$(json_string "${installer_sha256}")"
    printf '  },\n'
    printf '  "version": %s,\n' "$(json_string "${ZLAR_VERSION:-unknown}")"
    printf '  "dry_run": true,\n'
    printf '  "no_write_proof": {\n'
    printf '    "performs_no_writes": true,\n'
    printf '    "exits_before_installer_phases": true,\n'
    printf '    "does_not_create_temp_dirs": true,\n'
    printf '    "does_not_download_or_clone": true,\n'
    printf '    "does_not_probe_sudo": true,\n'
    printf '    "does_not_generate_or_read_private_key_material": true,\n'
    printf '    "does_not_write_hooks_or_config": true,\n'
    printf '    "does_not_start_services": true,\n'
    printf '    "does_not_modify_machine_config": true\n'
    printf '  },\n'
    emit_planned_installed_bin_wrappers_json
    emit_planned_retired_source_removals_json
    emit_planned_retired_source_cleanup_refusals_json
    emit_planned_retired_source_parent_refusals_json
    printf '  "existing_install": {\n'
    printf '    "install_dir": "~/.zlar",\n'
    printf '    "detected": %s,\n' "$(json_bool "${install_exists}")"
    printf '    "installed_version": %s,\n' "$(json_string "${existing_version}")"
    printf '    "target_version": %s,\n' "$(json_string "${ZLAR_VERSION:-unknown}")"
    printf '    "requested_mode": %s,\n' "$(json_string "$(existing_install_mode_cli)")"
    printf '    "decision": %s,\n' "$(json_string "${EXISTING_INSTALL_DECISION}")"
    printf '    "operation": %s,\n' "$(json_string "${EXISTING_INSTALL_OPERATION}")"
    printf '    "refusal_reason": %s,\n' "$(json_string "${EXISTING_INSTALL_REFUSAL_REASON}")"
    printf '    "requires_backup_before_mutation": %s,\n' "$(json_bool "${EXISTING_INSTALL_REQUIRES_BACKUP}")"
    printf '    "real_install_would_exit_before_writes": %s,\n' "$(json_bool "${real_install_would_exit_before_writes}")"
    printf '    "real_install_would_continue_after_existing_install_check": %s,\n' "$(json_bool "${EXISTING_INSTALL_CONTINUES}")"
    printf '    "retired_source_cleanup_would_refuse_before_writes": %s\n' "$(json_bool "${retired_source_cleanup_blocked}")"
    printf '  },\n'
    printf '  "detected_client_surfaces": [\n'
    printf '    '
    detect_client_surface_json "claude_code" "Claude Code" "claude" "${HOME}/.claude" "${HOME}/.claude/settings.json" "~/.zlar/adapters/claude-code/hook.sh" "${selected_cc}"
    printf ',\n    '
    detect_client_surface_json "cursor" "Cursor" "cursor" "${HOME}/.cursor" "${HOME}/.cursor/hooks.json" "~/.zlar/adapters/cursor/hook.sh" "${selected_cursor}"
    printf ',\n    '
    detect_client_surface_json "windsurf" "Windsurf" "windsurf" "${HOME}/.codeium/windsurf" "${HOME}/.codeium/windsurf/hooks.json" "~/.zlar/adapters/windsurf/hook.sh" "${selected_windsurf}"
    printf '\n  ],\n'
    printf '  "selected_client_surfaces": [\n'
    printf '    %s\n' "$(json_string "${INSTALL_SURFACE}")"
    printf '  ],\n'
    printf '  "current_machine_governance_design": {\n'
    printf '    "design_type": "zlar-current-machine-governance-design-v1",\n'
    printf '    "surface_scope": %s,\n' "$(json_string "${INSTALL_SURFACE}")"
    printf '    "single_surface_scope": %s,\n' "$(json_bool "${single_surface_scope}")"
    printf '    "current_machine_governance_evidence": false,\n'
    printf '    "approval_packet_required": true,\n'
    printf '    "recognized_receipt_required_for_boarding": true,\n'
    printf '    "boarding_credential_rule": "only a routed hook/gate passage for the named surface can mint a receipt that a downstream terminal should recognize for boarding",\n'
    printf '    "dry_run_observation": {\n'
    printf '      "existing_install_detected": %s,\n' "$(json_bool "${install_exists}")"
    printf '      "existing_install_requested_mode": %s,\n' "$(json_string "$(existing_install_mode_cli)")"
    printf '      "existing_install_decision": %s,\n' "$(json_string "${EXISTING_INSTALL_DECISION}")"
    printf '      "existing_install_operation": %s,\n' "$(json_string "${EXISTING_INSTALL_OPERATION}")"
    printf '      "existing_install_refusal_reason": %s,\n' "$(json_string "${EXISTING_INSTALL_REFUSAL_REASON}")"
    printf '      "real_install_would_exit_before_writes": %s,\n' "$(json_bool "${real_install_would_exit_before_writes}")"
    printf '      "would_create_or_modify_hooks_if_real_install_runs": %s,\n' "$(json_bool "${hook_write_planned}")"
    printf '      "claude_code_detected": %s,\n' "$(json_bool "${cc_detected}")"
    printf '      "claude_code_selected": %s,\n' "$(json_bool "${selected_cc}")"
    printf '      "claude_code_existing_zlar_hook_profile_conflict": %s,\n' "$(json_bool "${cc_conflict}")"
    printf '      "claude_code_planned_hook_write": %s,\n' "$(json_bool "${cc_hook_write}")"
    printf '      "cursor_detected": %s,\n' "$(json_bool "${cursor_detected}")"
    printf '      "cursor_selected": %s,\n' "$(json_bool "${selected_cursor}")"
    printf '      "windsurf_detected": %s,\n' "$(json_bool "${windsurf_detected}")"
    printf '      "windsurf_selected": %s\n' "$(json_bool "${selected_windsurf}")"
    printf '    },\n'
    printf '    "approval_packet_must_name": [\n'
    printf '      "selected surface and hook/profile path",\n'
    printf '      "installed root, installed version, and gate binary target",\n'
    printf '      "hook target path, executable bit, and delegation target",\n'
    printf '      "policy path, policy signature verifier, accepted policy version, and public issuer kid",\n'
    printf '      "receipt emission source for the routed hook/gate decision",\n'
    printf '      "downstream terminal, recognition rule, freshness window, and replay store",\n'
    printf '      "ungoverned side doors that remain outside the selected surface"\n'
    printf '    ],\n'
    printf '    "downstream_recognition_must_refuse": [\n'
    printf '      "receipt_missing",\n'
    printf '      "receipt_invalid",\n'
    printf '      "receipt_stale_or_expired",\n'
    printf '      "receipt_replay",\n'
    printf '      "unknown_issuer",\n'
    printf '      "issuer_not_active",\n'
    printf '      "policy_not_recognized",\n'
    printf '      "surface_not_recognized",\n'
    printf '      "terminal_not_recognized",\n'
    printf '      "detail_hash_mismatch",\n'
    printf '      "unsupported_receipt_format",\n'
    printf '      "request_stream_authority_material"\n'
    printf '    ],\n'
    printf '    "before_current_machine_claim": [\n'
    printf '      "verify installed root and version with read-only local checks",\n'
    printf '      "verify the selected hook profile points at the expected ZLAR adapter",\n'
    printf '      "verify the adapter target exists, is executable, and delegates to the current gate",\n'
    printf '      "verify gate state, policy signature, and receipt emission through a routed event",\n'
    printf '      "verify a downstream recognition rule accepts only recognized receipts for the named surface and terminal",\n'
    printf '      "verify missing, invalid, stale, replayed, unrecognized, wrong-scope, and request-stream authority-material receipts refuse before effect",\n'
    printf '      "name every remaining unrouted side door as outside the claim"\n'
    printf '    ],\n'
    printf '    "non_claims": [\n'
    printf '      "this dry-run is not installation or activation",\n'
    printf '      "this dry-run does not prove current-machine governance",\n'
    printf '      "this dry-run does not prove the current invocation crossed a hook",\n'
    printf '      "this dry-run does not prove live downstream recognition or live records-system coverage",\n'
    printf '      "this dry-run does not prove production authority, enterprise readiness, external attestation, or sovereign recognition",\n'
    printf '      "this dry-run does not close unrouted side doors"\n'
    printf '    ]\n'
    printf '  },\n'
    printf '  "planned_file_writes": [\n'
    PLAN_WRITE_COUNT=0
    emit_planned_file_write "~/.zlar/bin/" "core_binaries" "create_or_replace_installed_binaries"
    emit_planned_file_write "~/.zlar/lib/" "shared_libraries" "copy_shared_libraries"
    emit_planned_file_write "~/.zlar/scripts/" "dispatcher_sources" "copy_optional_dispatcher_sources"
    if [ "${selected_cc}" -eq 1 ] || [ "${INSTALL_SURFACE}" = "all" ]; then
        emit_planned_file_write "~/.zlar/adapters/claude-code/" "framework_adapters" "copy_claude_code_adapter"
    fi
    if [ "${selected_cursor}" -eq 1 ] || [ "${INSTALL_SURFACE}" = "all" ]; then
        emit_planned_file_write "~/.zlar/adapters/cursor/" "framework_adapters" "copy_cursor_adapter"
    fi
    if [ "${selected_windsurf}" -eq 1 ] || [ "${INSTALL_SURFACE}" = "all" ]; then
        emit_planned_file_write "~/.zlar/adapters/windsurf/" "framework_adapters" "copy_windsurf_adapter"
    fi
    emit_planned_file_write "~/.zlar/etc/gate.json" "gate_config" "create_default_gate_config"
    emit_planned_file_write "~/.zlar/etc/policies/" "policy" "copy_and_sign_default_policy"
    emit_planned_file_write "~/.zlar/etc/keys/" "keys" "write_public_and_hmac_keys"
    emit_planned_file_write "~/.zlar/.env" "approval_channel_config" "create_optional_telegram_placeholder_if_missing"
    emit_planned_file_write "~/.zlar/VERSION" "version" "write_installed_version"
    emit_planned_file_write "~/.zlar-signing.key" "signing_material" "create_if_missing_or_reuse_existing"
    if [ "${selected_cc}" -eq 1 ] || [ "${INSTALL_SURFACE}" = "all" ]; then
        emit_planned_file_write "~/.claude/settings.json" "hook_profile" "create_or_modify_if_claude_code_detected_without_existing_zlar_hook"
    fi
    if [ "${selected_cursor}" -eq 1 ] || [ "${INSTALL_SURFACE}" = "all" ]; then
        emit_planned_file_write "~/.cursor/hooks.json" "hook_profile" "create_or_modify_if_cursor_detected_without_existing_zlar_hook"
    fi
    if [ "${selected_windsurf}" -eq 1 ] || [ "${INSTALL_SURFACE}" = "all" ]; then
        emit_planned_file_write "~/.codeium/windsurf/hooks.json" "hook_profile" "create_or_modify_if_windsurf_detected_without_existing_zlar_hook"
    fi
    if [ "${machine_helper_write}" -eq 1 ]; then
        emit_planned_file_write "/usr/local/bin/zlar-tg-boot.sh" "optional_machine_script" "copy_only_if_root_or_passwordless_sudo_available_in_real_install"
        emit_planned_file_write "/usr/local/bin/zlar-tg-poll" "optional_machine_script" "copy_only_if_root_or_passwordless_sudo_available_in_real_install"
    fi
    printf '  ],\n'
    printf '  "existing_zlar_hook_profile_conflicts": {\n'
    printf '    "claude_code": %s,\n' "$(json_bool "${cc_conflict}")"
    printf '    "cursor": %s,\n' "$(json_bool "${cursor_conflict}")"
    printf '    "windsurf": %s\n' "$(json_bool "${windsurf_conflict}")"
    printf '  },\n'
    printf '  "required_human_approvals": [\n'
    printf '    "approve running the real installer after reviewing this plan",\n'
    printf '    "approve creation or reuse of local signing and HMAC key material",\n'
    printf '    "approve writes under ~/.zlar and ~/.zlar-signing.key",\n'
    if [ "${INSTALL_SURFACE}" = "all" ]; then
        printf '    "approve framework hook/profile writes for each detected client surface",\n'
    else
        printf '    "approve framework hook/profile writes for the selected client surface only",\n'
    fi
    if [ "${machine_helper_write}" -eq 1 ]; then
        printf '    "approve optional /usr/local/bin dispatcher helper writes if privileged",\n'
    fi
    printf '    "approve any later Telegram or approval-channel configuration separately"\n'
    printf '  ],\n'
    printf '  "side_doors_left_open": [\n'
    printf '    "unrouted shell and filesystem paths",\n'
    printf '    "direct MCP registrations that bypass ZLAR",\n'
    printf '    "browser and app-control surfaces",\n'
    printf '    "network paths not routed through configured hooks or adapters",\n'
    printf '    "subprocesses or runtimes with their own permission model",\n'
    printf '    "model reasoning, memory, planning, and final text",\n'
    printf '    "direct records paths outside a routed downstream-recognition terminal"\n'
    printf '  ],\n'
    printf '  "non_claims": [\n'
    printf '    "dry-run is not install or activation",\n'
    printf '    "dry-run does not prove current-machine governance",\n'
    printf '    "dry-run does not prove this client invocation crossed a hook",\n'
    printf '    "dry-run does not prove production authority or enterprise readiness",\n'
    printf '    "dry-run does not create public external attestation",\n'
    printf '    "dry-run does not prove sovereign recognition",\n'
    printf '    "dry-run does not prove live registry, issuer, key-custody, or revocation truth",\n'
    printf '    "dry-run does not prove live records-system coverage",\n'
    printf '    "dry-run does not close unrouted side doors"\n'
    printf '  ],\n'
    printf '  "write_effects_if_real_install_runs": {\n'
    printf '    "blocked_by_existing_install": %s,\n' "$(json_bool "${EXISTING_INSTALL_BLOCKED}")"
    printf '    "blocked_by_retired_source_cleanup": %s,\n' "$(json_bool "${retired_source_cleanup_blocked}")"
    printf '    "existing_install_decision": %s,\n' "$(json_string "${EXISTING_INSTALL_DECISION}")"
    printf '    "existing_install_operation": %s,\n' "$(json_string "${EXISTING_INSTALL_OPERATION}")"
    printf '    "would_create_or_modify_files": %s,\n' "$(json_bool "${effective_write}")"
    printf '    "would_create_or_modify_keys": %s,\n' "$(json_bool "${would_keys}")"
    printf '    "would_create_or_modify_hooks": %s,\n' "$(json_bool "${hook_write_planned}")"
    printf '    "would_create_or_modify_services": false,\n'
    printf '    "would_create_or_modify_user_config": %s,\n' "$(json_bool "${would_user_config}")"
    printf '    "would_create_or_modify_machine_config": %s,\n' "$(json_bool "${would_machine_config}")"
    printf '    "machine_config_condition": "optional /usr/local/bin dispatcher helper writes only if root or passwordless sudo is available during real install",\n'
    printf '    "existing_signing_key_detected": %s\n' "$(json_bool "${signing_key_exists}")"
    printf '  }\n'
    printf '}\n'
}

if [ "${DRY_RUN}" -eq 1 ]; then
    if [ "${JSON_OUTPUT}" -ne 1 ]; then
        fail "Dry-run currently requires --json so the no-write plan is machine-checkable"
        printf "Usage: bash install.sh --dry-run --json\n" >&2
        exit 1
    fi
    emit_install_plan_json
    exit 0
fi

# ─── Banner ──────────────────────────────────────────────────────────────────

printf "\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  ZLAR — Zero-Config Agent Governance${NC}\n"
printf "${BOLD}  One command. Your rules. Under 60 seconds.${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "\n"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Preflight
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 1: Preflight checks"

ERRORS=0
WARNINGS=0

# OS check
UNAME_S="$(uname -s)"
case "${UNAME_S}" in
    Darwin) ok "macOS detected" ;;
    Linux)  ok "Linux detected" ;;
    *)      fail "Unsupported OS: ${UNAME_S}"; ERRORS=$((ERRORS + 1)) ;;
esac

# bash version — gate is CI-covered on macOS system bash 3.2 and modern Linux.
BASH_MAJOR=$(printf '%s' "${BASH_VERSION:-0.0}" | cut -d. -f1)
BASH_MINOR=$(printf '%s' "${BASH_VERSION:-0.0}" | cut -d. -f2)
case "${BASH_MAJOR}" in ''|*[!0-9]*) BASH_MAJOR=0 ;; esac
case "${BASH_MINOR}" in ''|*[!0-9]*) BASH_MINOR=0 ;; esac
if [ "${BASH_MAJOR}" -gt 3 ] 2>/dev/null || { [ "${BASH_MAJOR}" -eq 3 ] 2>/dev/null && [ "${BASH_MINOR}" -ge 2 ] 2>/dev/null; }; then
    ok "bash ${BASH_VERSION} (3.2+ gate compatible)"
else
    warn "bash ${BASH_VERSION:-unknown} — the gate engine supports bash 3.2+"
    case "${UNAME_S}" in
        Darwin) printf "       Install: ${BOLD}brew install bash${NC} or upgrade to macOS system bash 3.2+\n" ;;
        Linux)  printf "       Install: ${BOLD}sudo apt install bash${NC} or equivalent bash 3.2+\n" ;;
    esac
    WARNINGS=$((WARNINGS + 1))
fi

# jq
if command -v jq >/dev/null 2>&1; then
    ok "jq $(jq --version 2>/dev/null || echo '')"
else
    fail "jq is required but not installed"
    case "${UNAME_S}" in
        Darwin) printf "       Install: ${BOLD}brew install jq${NC}\n" ;;
        Linux)  printf "       Install: ${BOLD}sudo apt install jq${NC}\n" ;;
    esac
    ERRORS=$((ERRORS + 1))
fi

# openssl with Ed25519
if command -v openssl >/dev/null 2>&1; then
    ok "openssl $(openssl version 2>/dev/null | head -1 || echo 'found')"
    if openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
        ok "Ed25519 support confirmed"
    else
        fail "openssl does not support Ed25519"
        case "${UNAME_S}" in
            Darwin) printf "       Install: ${BOLD}brew install openssl${NC} && export PATH=\"\$(brew --prefix openssl)/bin:\$PATH\"\n" ;;
            Linux)  printf "       Upgrade openssl to 1.1.1+ for Ed25519 support\n" ;;
        esac
        ERRORS=$((ERRORS + 1))
    fi
else
    fail "openssl is required but not installed"
    ERRORS=$((ERRORS + 1))
fi

# curl
if command -v curl >/dev/null 2>&1; then
    ok "curl"
else
    fail "curl is required but not installed"
    ERRORS=$((ERRORS + 1))
fi

if [ "${ERRORS}" -gt 0 ]; then
    printf "\n"
    fail "Fix the ${ERRORS} error(s) above before continuing."
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Check for existing ZLAR installs
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 2: Checking for existing ZLAR installs"

INSTALL_EXISTS=0
EXISTING_VERSION="not_installed"
if [ -d "${INSTALL_DIR}" ]; then
    INSTALL_EXISTS=1
    EXISTING_VERSION="$(read_existing_install_version)"
fi

set_existing_install_decision "${INSTALL_EXISTS}" "${EXISTING_VERSION}" "${ZLAR_VERSION:-unknown}"

case "${EXISTING_INSTALL_DECISION}" in
    fresh_install)
        ok "No existing ZLAR installation found"
        ;;
    no_op_existing_install)
        ok "ZLAR is already installed at ${INSTALL_DIR} (version: ${EXISTING_VERSION})"
        info "Existing-install no-op selected; no writes performed"
        exit 0
        ;;
    repair_existing_install)
        warn "ZLAR is already installed at ${INSTALL_DIR} (version: ${EXISTING_VERSION})"
        info "Scoped Claude Code repair selected; proceeding to repair installer-managed files"
        warn "No backup will be created by install.sh; backup/rollback must be handled under separate authority before mutation"
        ;;
    upgrade_existing_install)
        warn "ZLAR is already installed at ${INSTALL_DIR} (version: ${EXISTING_VERSION})"
        info "Scoped Claude Code upgrade selected; target version is ${ZLAR_VERSION}"
        warn "No backup will be created by install.sh; backup/rollback must be handled under separate authority before mutation"
        ;;
    reinstall_existing_install)
        warn "ZLAR is already installed at ${INSTALL_DIR} (version: ${EXISTING_VERSION})"
        info "Scoped Claude Code reinstall selected; proceeding to replace installer-managed files"
        warn "No backup will be created by install.sh; backup/rollback must be handled under separate authority before mutation"
        ;;
    refuse_*)
        fail "ZLAR existing-install handling refused before writes"
        printf "       Existing install: %s\n" "${INSTALL_DIR}"
        printf "       Existing version: %s\n" "${EXISTING_VERSION:-unknown}"
        printf "       Target version:   %s\n" "${ZLAR_VERSION:-unknown}"
        printf "       Requested mode:   %s\n" "$(existing_install_mode_cli)"
        printf "       Decision:         %s\n" "${EXISTING_INSTALL_DECISION}"
        if [ -n "${EXISTING_INSTALL_REFUSAL_REASON}" ]; then
            printf "       Reason:           %s\n" "${EXISTING_INSTALL_REFUSAL_REASON}"
        fi
        if [ "${EXISTING_INSTALL_MODE}" = "refuse" ]; then
            printf "       To inspect safely: ${BOLD}bash install.sh --surface claude-code --no-machine-helpers --dry-run --json${NC}\n"
            printf "       To choose a path:  ${BOLD}--existing-install no-op|repair|upgrade|reinstall${NC} with explicit authority\n"
        fi
        exit 1
        ;;
esac

# Validate the four exact retirement paths before any installer-managed write.
# The removal itself occurs only after source acquisition and directory setup.
validate_retired_installed_positive_source_surfaces

# Check if any framework already has ZLAR hooks (Gate or CC)
EXISTING_ZLAR=0
if surface_is_selected "claude_code" && [ "$(detect_existing_zlar_hook "${HOME}/.claude/settings.json" "~/.zlar/adapters/claude-code/hook.sh")" -eq 1 ]; then
    warn "Claude Code already has ZLAR hooks configured — will skip hook setup for CC"
    EXISTING_ZLAR=$((EXISTING_ZLAR + 1))
fi
if surface_is_selected "cursor" && [ "$(detect_existing_zlar_hook "${HOME}/.cursor/hooks.json" "~/.zlar/adapters/cursor/hook.sh")" -eq 1 ]; then
    warn "Cursor already has ZLAR hooks configured — will skip hook setup for Cursor"
    EXISTING_ZLAR=$((EXISTING_ZLAR + 1))
fi
if surface_is_selected "windsurf" && [ "$(detect_existing_zlar_hook "${HOME}/.codeium/windsurf/hooks.json" "~/.zlar/adapters/windsurf/hook.sh")" -eq 1 ]; then
    warn "Windsurf already has ZLAR hooks configured — will skip hook setup for Windsurf"
    EXISTING_ZLAR=$((EXISTING_ZLAR + 1))
fi

if [ "${EXISTING_ZLAR}" -eq 0 ]; then
    ok "No existing ZLAR hooks detected"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Detect frameworks
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 3: Detecting installed frameworks"

HAS_CC=0; HAS_CURSOR=0; HAS_WINDSURF=0

# Claude Code — check for claude CLI or ~/.claude directory when selected
if surface_is_selected "claude_code"; then
    if command -v claude >/dev/null 2>&1 || [ -d "${HOME}/.claude" ]; then
        ok "Claude Code detected"
        HAS_CC=1
    else
        info "Claude Code not detected"
    fi
else
    info "Claude Code not selected by --surface"
fi

# Cursor — check for cursor CLI or ~/.cursor directory when selected
if surface_is_selected "cursor"; then
    if command -v cursor >/dev/null 2>&1 || [ -d "${HOME}/.cursor" ]; then
        ok "Cursor detected"
        HAS_CURSOR=1
    else
        info "Cursor not detected"
    fi
else
    info "Cursor not selected by --surface"
fi

# Windsurf — check for windsurf CLI or ~/.codeium/windsurf directory when selected
if surface_is_selected "windsurf"; then
    if command -v windsurf >/dev/null 2>&1 || [ -d "${HOME}/.codeium/windsurf" ]; then
        ok "Windsurf detected"
        HAS_WINDSURF=1
    else
        info "Windsurf not detected"
    fi
else
    info "Windsurf not selected by --surface"
fi

TOTAL_FRAMEWORKS=$((HAS_CC + HAS_CURSOR + HAS_WINDSURF))
if [ "${TOTAL_FRAMEWORKS}" -eq 0 ]; then
    warn "No supported frameworks detected"
    printf "       ZLAR will install anyway. You can configure hooks manually later.\n"
    printf "       Supported: Claude Code, Cursor, Windsurf\n"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Install
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 4: Installing to ${INSTALL_DIR}"

# Determine source — if running from repo clone, use local files.
# If running via curl | bash, we need to download.
SCRIPT_SOURCE_DIR=""
SELF_PATH="${BASH_SOURCE:-$0}"
if [ -f "${SELF_PATH}" ]; then
    SELF_DIR="$(cd "$(dirname "${SELF_PATH}")" && pwd)"
    if [ -f "${SELF_DIR}/bin/zlar-gate" ] && [ -f "${SELF_DIR}/bin/zlar-policy" ]; then
        SCRIPT_SOURCE_DIR="${SELF_DIR}"
        ok "Installing from local source: ${SELF_DIR}"
    fi
fi

if [ -z "${SCRIPT_SOURCE_DIR}" ]; then
    GITHUB_REPO="ZLAR-AI/ZLAR"

    TMPDIR_DL=$(mktemp -d)
    trap "rm -rf '${TMPDIR_DL}'" EXIT

    DOWNLOAD_OK=0
    if [ -n "${ZLAR_VERSION}" ]; then
        TARBALL_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/zlar-${ZLAR_VERSION}.tar.gz"
        info "Downloading ZLAR v${ZLAR_VERSION}..."
        if curl -fsSL "${TARBALL_URL}" -o "${TMPDIR_DL}/zlar.tar.gz" 2>/dev/null; then
            if tar xzf "${TMPDIR_DL}/zlar.tar.gz" -C "${TMPDIR_DL}" 2>/dev/null; then
                SCRIPT_SOURCE_DIR="${TMPDIR_DL}/zlar"
                ok "Downloaded and extracted"
                DOWNLOAD_OK=1
            fi
        fi
    fi

    if [ "${DOWNLOAD_OK}" -eq 0 ]; then
        if [ -n "${ZLAR_VERSION}" ]; then
            info "Release tarball for v${ZLAR_VERSION} not found — cloning from GitHub..."
        else
            info "Cloning ZLAR from GitHub..."
        fi
        if command -v git >/dev/null 2>&1; then
            if git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "${TMPDIR_DL}/zlar" 2>/dev/null; then
                SCRIPT_SOURCE_DIR="${TMPDIR_DL}/zlar"
                ok "Cloned from GitHub"
            else
                fail "git clone failed — check network or download manually from:"
                printf "       https://github.com/${GITHUB_REPO}\n"
                exit 1
            fi
        else
            fail "Cannot download ZLAR. Install git or download manually from:"
            printf "       https://github.com/${GITHUB_REPO}\n"
            exit 1
        fi
    fi
fi

# Authoritative version: read from the source selected above. For local clones
# this matches the early read; for curl|bash this is the first time
# ZLAR_VERSION gets set. Missing VERSION means the source is structurally
# wrong, so abort rather than stamp a wrong version.
if [ -f "${SCRIPT_SOURCE_DIR}/VERSION" ]; then
    ZLAR_VERSION=$(cat "${SCRIPT_SOURCE_DIR}/VERSION" | tr -d '[:space:]')
fi

if [ -z "${ZLAR_VERSION}" ]; then
    fail "Source at ${SCRIPT_SOURCE_DIR} has no VERSION file — installation aborted"
    exit 1
fi

# Create install directory structure
mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/lib"
mkdir -p "${INSTALL_DIR}/scripts"
mkdir -p "${INSTALL_DIR}/adapters"
if surface_is_selected "claude_code"; then
    mkdir -p "${INSTALL_DIR}/adapters/claude-code"
fi
if surface_is_selected "cursor"; then
    mkdir -p "${INSTALL_DIR}/adapters/cursor"
fi
if surface_is_selected "windsurf"; then
    mkdir -p "${INSTALL_DIR}/adapters/windsurf"
fi
mkdir -p "${INSTALL_DIR}/etc/policies"
mkdir -p "${INSTALL_DIR}/etc/keys"
mkdir -p "${INSTALL_DIR}/var/log/sessions"

# Existing-install repair, upgrade, and reinstall remove only the exact E1/E2
# positive source surfaces retired by the current source checkpoint. This does
# not inspect or change an installation during dry-run planning.
remove_retired_installed_positive_source_surfaces

# Copy core files
cp "${SCRIPT_SOURCE_DIR}/bin/zlar" "${INSTALL_DIR}/bin/zlar"
copy_installed_bin_wrappers

# Copy shared libraries used by the gate, CLI, and Telegram dispatcher while
# omitting retired positive E1/E2 source surfaces from future installer copies.
copy_installed_libraries

# Copy Telegram dispatcher bootstrap sources
cp "${SCRIPT_SOURCE_DIR}/scripts/zlar-tg-boot.sh" "${INSTALL_DIR}/scripts/zlar-tg-boot.sh"
cp "${SCRIPT_SOURCE_DIR}/scripts/zlar-tg-poll"    "${INSTALL_DIR}/scripts/zlar-tg-poll"

# Copy uninstall script
cp "${SCRIPT_SOURCE_DIR}/uninstall.sh"    "${INSTALL_DIR}/uninstall.sh"

# Copy adapters
if surface_is_selected "claude_code"; then
    cp "${SCRIPT_SOURCE_DIR}/adapters/claude-code/hook.sh" "${INSTALL_DIR}/adapters/claude-code/hook.sh"
fi
if surface_is_selected "cursor"; then
    cp "${SCRIPT_SOURCE_DIR}/adapters/cursor/hook.sh"      "${INSTALL_DIR}/adapters/cursor/hook.sh"
fi
if surface_is_selected "windsurf"; then
    cp "${SCRIPT_SOURCE_DIR}/adapters/windsurf/hook.sh"    "${INSTALL_DIR}/adapters/windsurf/hook.sh"
fi

# Copy config (gate.lt.json → gate.json — gate hardcodes etc/gate.json)
cp "${SCRIPT_SOURCE_DIR}/etc/gate.lt.json" "${INSTALL_DIR}/etc/gate.json"

# Copy default policy template
cp "${SCRIPT_SOURCE_DIR}/etc/policies/lt-default.policy.json" "${INSTALL_DIR}/etc/policies/lt-default.policy.json"

# Create .env (empty — Telegram disabled by default)
if [ ! -f "${INSTALL_DIR}/.env" ]; then
    printf "# ZLAR environment — Telegram is optional\n# Uncomment and fill in to enable Telegram approval:\n# ZLAR_TELEGRAM_TOKEN=your_bot_token_here\n" > "${INSTALL_DIR}/.env"
fi

# Version file
printf "%s\n" "${ZLAR_VERSION}" > "${INSTALL_DIR}/VERSION"

# Make scripts executable
chmod +x "${INSTALL_DIR}/bin/zlar"
chmod +x "${INSTALL_DIR}/scripts/zlar-tg-boot.sh"
chmod +x "${INSTALL_DIR}/scripts/zlar-tg-poll"
if surface_is_selected "claude_code"; then
    chmod +x "${INSTALL_DIR}/adapters/claude-code/hook.sh"
fi
if surface_is_selected "cursor"; then
    chmod +x "${INSTALL_DIR}/adapters/cursor/hook.sh"
fi
if surface_is_selected "windsurf"; then
    chmod +x "${INSTALL_DIR}/adapters/windsurf/hook.sh"
fi
chmod +x "${INSTALL_DIR}/uninstall.sh"

ok "Core files installed to ${INSTALL_DIR}"

# Deploy the shared Telegram dispatcher entrypoints used by the LaunchDaemon.
# These are optional until Telegram is configured, so lack of sudo is a warning,
# not an install failure.
install_system_script() {
    local src="$1"
    local dst="$2"
    local label="$3"

    if [ "$(id -u)" -eq 0 ]; then
        cp "${src}" "${dst}"
        chmod 755 "${dst}"
        ok "${label}: installed to ${dst}"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo cp "${src}" "${dst}"
        sudo chmod 755 "${dst}"
        ok "${label}: installed to ${dst}"
    else
        warn "${label}: not installed to ${dst} (sudo required)"
        printf "       Run: ${BOLD}sudo cp ${src} ${dst} && sudo chmod 755 ${dst}${NC}\n"
    fi
}

if [ "${SKIP_MACHINE_HELPERS}" -eq 0 ]; then
    install_system_script "${INSTALL_DIR}/scripts/zlar-tg-boot.sh" "/usr/local/bin/zlar-tg-boot.sh" "Telegram boot script"
    install_system_script "${INSTALL_DIR}/scripts/zlar-tg-poll" "/usr/local/bin/zlar-tg-poll" "Telegram dispatcher"
else
    info "Optional /usr/local/bin dispatcher helpers skipped by --no-machine-helpers"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Generate keys and sign policy
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 5: Keys and policy"

# Generate Ed25519 keypair (if no existing key)
if [ -f "${HOME}/.zlar-signing.key" ] && [ -f "${INSTALL_DIR}/etc/keys/policy-signing.pub" ]; then
    ok "Signing keypair already exists — reusing"
elif [ -f "${HOME}/.zlar-signing.key" ]; then
    # Private key exists (from Gate or CC) but no pub key in LT — derive it
    info "Found existing signing key at ~/.zlar-signing.key — deriving public key"
    openssl pkey -in "${HOME}/.zlar-signing.key" -pubout -out "${INSTALL_DIR}/etc/keys/policy-signing.pub" 2>/dev/null
    ok "Public key derived from existing signing key"
else
    info "Generating Ed25519 signing keypair..."
    # Don't silence keygen stderr — a silent failure here cascades into a
    # confusing "signing key not found" error in Phase 5 below. If keygen
    # fails, the user needs to see why.
    if ! "${INSTALL_DIR}/bin/zlar-policy" keygen; then
        fail "Keypair generation failed (see error above)"
        exit 1
    fi
    ok "Keypair generated"
    info "Private key: ~/.zlar-signing.key (keep this safe)"
    info "Public key:  ${INSTALL_DIR}/etc/keys/policy-signing.pub"
fi

# v3.1.3: HMAC key for human-state protection. Seals var/human-state/*.json
# against an agent with filesystem access poisoning H6/H13/H14 counters.
# 32-byte random key in hex. Generate once; rotation requires resealing every
# existing state file and is an explicit ceremony, not an install-time action.
_HUMAN_STATE_KEY="${INSTALL_DIR}/etc/keys/human-state-hmac.key"
if [ ! -f "${_HUMAN_STATE_KEY}" ]; then
    if openssl rand -hex 32 > "${_HUMAN_STATE_KEY}" 2>/dev/null; then
        chmod 600 "${_HUMAN_STATE_KEY}"
        ok "Human-state HMAC key generated: ${_HUMAN_STATE_KEY}"
    else
        warn "Could not generate human-state HMAC key — H6/H13/H14 counters will run unauthenticated"
    fi
else
    ok "Human-state HMAC key already present"
fi

# v3.1.4: HMAC key for gate-uptime state. Seals var/gate-uptime.json so the
# streak counter shown in `zlar status` cannot be silently inflated. Same
# tamper-detection model as human-state-hmac.key; separate key for separation
# of concerns.
_GATE_UPTIME_KEY="${INSTALL_DIR}/etc/keys/gate-uptime-hmac.key"
if [ ! -f "${_GATE_UPTIME_KEY}" ]; then
    if openssl rand -hex 32 > "${_GATE_UPTIME_KEY}" 2>/dev/null; then
        chmod 600 "${_GATE_UPTIME_KEY}"
        ok "Gate-uptime HMAC key generated: ${_GATE_UPTIME_KEY}"
    else
        warn "Could not generate gate-uptime HMAC key — streak counter will run unauthenticated"
    fi
else
    ok "Gate-uptime HMAC key already present"
fi

# Copy default policy → active policy
cp "${INSTALL_DIR}/etc/policies/lt-default.policy.json" "${INSTALL_DIR}/etc/policies/active.policy.json"

# Sign the policy
if [ -f "${HOME}/.zlar-signing.key" ]; then
    "${INSTALL_DIR}/bin/zlar-policy" sign \
        --input "${INSTALL_DIR}/etc/policies/active.policy.json" \
        --key "${HOME}/.zlar-signing.key" 2>/dev/null
    ok "Default policy signed"
else
    fail "Could not sign policy — signing key not found"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: Configure framework hooks
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 6: Configuring hooks"

FRAMEWORKS_CONFIGURED=0

# ── Claude Code ──────────────────────────────────────────────────────────────

if surface_is_selected "claude_code" && [ "${HAS_CC}" -eq 1 ]; then
    CC_SETTINGS="${HOME}/.claude/settings.json"
    CC_HOOK="${INSTALL_DIR}/adapters/claude-code/hook.sh"

    # Skip if already has ZLAR hooks
    if [ "$(detect_existing_zlar_hook "${CC_SETTINGS}" "${CC_HOOK}")" -eq 1 ]; then
        ok "Claude Code: existing ZLAR hooks preserved (skipped)"
    else
        mkdir -p "${HOME}/.claude"
        if [ -f "${CC_SETTINGS}" ]; then
            # Merge into existing settings — append to any existing PreToolUse
            # hooks rather than clobbering them. The earlier `grep -q "zlar"`
            # guard ensures we only reach this branch when no ZLAR hook
            # already exists, so append is safe without dedup.
            TEMP=$(mktemp)
            jq --arg cmd "${CC_HOOK}" \
                '.hooks.PreToolUse = ((.hooks.PreToolUse // []) + [{"matcher":".*","hooks":[{"type":"command","command":$cmd,"timeout":310}]}])' \
                "${CC_SETTINGS}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${CC_SETTINGS}"
                ok "Claude Code: hooks added to existing settings.json"
                FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
            else
                rm -f "${TEMP}"
                warn "Claude Code: could not auto-configure — add manually"
                printf "       Add to ~/.claude/settings.json:\n"
                printf "       {\"hooks\":{\"PreToolUse\":[{\"matcher\":\".*\",\"hooks\":[{\"type\":\"command\",\"command\":\"${CC_HOOK}\",\"timeout\":310}]}]}}\n"
            fi
        else
            # Create new settings.json
            jq -n --arg cmd "${CC_HOOK}" \
                '{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":$cmd,"timeout":310}]}]}}' \
                > "${CC_SETTINGS}"
            ok "Claude Code: created settings.json with ZLAR hooks"
            FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
        fi
    fi
fi

# ── Cursor ───────────────────────────────────────────────────────────────────

if surface_is_selected "cursor" && [ "${HAS_CURSOR}" -eq 1 ]; then
    CURSOR_HOOKS="${HOME}/.cursor/hooks.json"
    CURSOR_HOOK="${INSTALL_DIR}/adapters/cursor/hook.sh"

    if [ "$(detect_existing_zlar_hook "${CURSOR_HOOKS}" "${CURSOR_HOOK}")" -eq 1 ]; then
        ok "Cursor: existing ZLAR hooks preserved (skipped)"
    else
        mkdir -p "${HOME}/.cursor"
        if [ -f "${CURSOR_HOOKS}" ]; then
            TEMP=$(mktemp)
            jq --arg cmd "${CURSOR_HOOK}" \
                '. + {
                    "beforeShellExecution": [{"command": $cmd, "timeout": 310}],
                    "beforeReadFile": [{"command": $cmd, "timeout": 310}],
                    "beforeMCPExecution": [{"command": $cmd, "timeout": 310}]
                }' "${CURSOR_HOOKS}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${CURSOR_HOOKS}"
                ok "Cursor: ZLAR hooks added to existing hooks.json"
                FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
            else
                rm -f "${TEMP}"
                warn "Cursor: could not auto-configure — add manually"
            fi
        else
            jq -n --arg cmd "${CURSOR_HOOK}" '{
                "beforeShellExecution": [{"command": $cmd, "timeout": 310}],
                "beforeReadFile": [{"command": $cmd, "timeout": 310}],
                "beforeMCPExecution": [{"command": $cmd, "timeout": 310}]
            }' > "${CURSOR_HOOKS}"
            ok "Cursor: created hooks.json with ZLAR hooks"
            FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
        fi
    fi
fi

# ── Windsurf ─────────────────────────────────────────────────────────────────

if surface_is_selected "windsurf" && [ "${HAS_WINDSURF}" -eq 1 ]; then
    WS_HOOKS="${HOME}/.codeium/windsurf/hooks.json"
    WS_HOOK="${INSTALL_DIR}/adapters/windsurf/hook.sh"

    if [ "$(detect_existing_zlar_hook "${WS_HOOKS}" "${WS_HOOK}")" -eq 1 ]; then
        ok "Windsurf: existing ZLAR hooks preserved (skipped)"
    else
        mkdir -p "${HOME}/.codeium/windsurf"
        if [ -f "${WS_HOOKS}" ]; then
            TEMP=$(mktemp)
            jq --arg cmd "${WS_HOOK}" \
                '. + {
                    "pre_run_command": [{"command": $cmd, "timeout": 310}],
                    "pre_write_code": [{"command": $cmd, "timeout": 310}],
                    "pre_read_code": [{"command": $cmd, "timeout": 310}],
                    "pre_mcp_tool_use": [{"command": $cmd, "timeout": 310}]
                }' "${WS_HOOKS}" > "${TEMP}" 2>/dev/null
            if [ -s "${TEMP}" ]; then
                mv "${TEMP}" "${WS_HOOKS}"
                ok "Windsurf: ZLAR hooks added to existing hooks.json"
                FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
            else
                rm -f "${TEMP}"
                warn "Windsurf: could not auto-configure — add manually"
            fi
        else
            jq -n --arg cmd "${WS_HOOK}" '{
                "pre_run_command": [{"command": $cmd, "timeout": 310}],
                "pre_write_code": [{"command": $cmd, "timeout": 310}],
                "pre_read_code": [{"command": $cmd, "timeout": 310}],
                "pre_mcp_tool_use": [{"command": $cmd, "timeout": 310}]
            }' > "${WS_HOOKS}"
            ok "Windsurf: created hooks.json with ZLAR hooks"
            FRAMEWORKS_CONFIGURED=$((FRAMEWORKS_CONFIGURED + 1))
        fi
    fi
fi

if [ "${TOTAL_FRAMEWORKS}" -eq 0 ]; then
    info "No frameworks to configure — install ZLAR hooks when you install an editor"
    printf "       Run: ${BOLD}~/.zlar/bin/zlar status${NC} to see detected frameworks\n"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: Self-test
# ═══════════════════════════════════════════════════════════════════════════════

step "Phase 7: Verification"

SELF_TEST_PASS=0
SELF_TEST_FAIL=0

# Verify: gate executable exists
if [ -x "${INSTALL_DIR}/bin/zlar-gate" ]; then
    ok "Gate active"
    SELF_TEST_PASS=$((SELF_TEST_PASS + 1))
else
    fail "Gate not found or not executable"
    SELF_TEST_FAIL=$((SELF_TEST_FAIL + 1))
fi

# Verify: policy signed
POLICY_SIG=$(jq -r '.signature.value // ""' "${INSTALL_DIR}/etc/policies/active.policy.json" 2>/dev/null)
if [ -n "${POLICY_SIG}" ] && [ "${POLICY_SIG}" != "SIGNED_AT_INSTALL" ] && [ "${POLICY_SIG}" != "unsigned" ]; then
    ok "Policy signed"
    SELF_TEST_PASS=$((SELF_TEST_PASS + 1))
else
    warn "Policy signature not verified"
    SELF_TEST_FAIL=$((SELF_TEST_FAIL + 1))
fi

# Verify: hook configured
if [ "${FRAMEWORKS_CONFIGURED}" -gt 0 ] || [ "${EXISTING_ZLAR}" -gt 0 ]; then
    ok "Hook configured (${FRAMEWORKS_CONFIGURED} framework(s))"
    SELF_TEST_PASS=$((SELF_TEST_PASS + 1))
else
    warn "No framework hooks configured — gate has nothing to govern yet"
fi

# Live gate test: Read should be allowed
TEST_INPUT='{"tool_name":"Read","tool_input":{"file_path":"/tmp/test"},"session_id":"lt-install-test"}'
TEST_RESULT=$(printf '%s' "${TEST_INPUT}" | "${INSTALL_DIR}/bin/zlar-gate" 2>/dev/null || echo "")

if [ -n "${TEST_RESULT}" ]; then
    TEST_DECISION=$(printf '%s' "${TEST_RESULT}" | jq -r '.hookSpecificOutput.permissionDecision // "unknown"' 2>/dev/null)
    if [ "${TEST_DECISION}" = "allow" ]; then
        ok "Live test: Read -> allow"
        SELF_TEST_PASS=$((SELF_TEST_PASS + 1))
    else
        warn "Live test: Read returned '${TEST_DECISION}' (expected 'allow')"
        SELF_TEST_FAIL=$((SELF_TEST_FAIL + 1))
    fi
else
    warn "Live test: gate produced no output — check jq, openssl, bash, and gate crash logs"
    SELF_TEST_FAIL=$((SELF_TEST_FAIL + 1))
fi

# Live gate test: rm -rf should be denied
TEST_INPUT2='{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/test"},"session_id":"lt-install-test"}'
TEST_RESULT2=$(printf '%s' "${TEST_INPUT2}" | "${INSTALL_DIR}/bin/zlar-gate" 2>/dev/null || echo "")

if [ -n "${TEST_RESULT2}" ]; then
    TEST_DECISION2=$(printf '%s' "${TEST_RESULT2}" | jq -r '.hookSpecificOutput.permissionDecision // "unknown"' 2>/dev/null)
    if [ "${TEST_DECISION2}" = "deny" ]; then
        ok "Live test: rm -rf -> deny"
        SELF_TEST_PASS=$((SELF_TEST_PASS + 1))
    else
        fail "Live test: rm -rf returned '${TEST_DECISION2}' (expected 'deny')"
        SELF_TEST_FAIL=$((SELF_TEST_FAIL + 1))
    fi
else
    warn "Live test: gate produced no output for deny test"
    SELF_TEST_FAIL=$((SELF_TEST_FAIL + 1))
fi

if [ "${SELF_TEST_FAIL}" -eq 0 ]; then
    ok "All ${SELF_TEST_PASS} verification checks passed"
else
    warn "${SELF_TEST_PASS} passed, ${SELF_TEST_FAIL} failed — run 'zlar doctor' for details"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: Summary
# ═══════════════════════════════════════════════════════════════════════════════

printf "\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "${BOLD}  ZLAR installed.${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "\n"
printf "  ${BOLD}Version:${NC}     ${ZLAR_VERSION}\n"
printf "  ${BOLD}Location:${NC}    ${INSTALL_DIR}\n"
printf "  ${BOLD}Frameworks:${NC}  ${FRAMEWORKS_CONFIGURED} configured\n"
printf "\n"
printf "  ${BOLD}What's allowed:${NC}\n"
printf "    ✓  File reads, writes, edits\n"
printf "    ✓  Glob and grep searches\n"
printf "    ✓  Safe shell commands (ls, cat, pwd, git status, ...)\n"
printf "    ✓  Web search\n"
printf "\n"
printf "  ${BOLD}Policy denies by default:${NC}\n"
printf "    DENY  rm, rm -rf (file deletion)\n"
printf "    DENY  sudo, privilege escalation\n"
printf "    DENY  curl, wget, ssh (network send)\n"
printf "    DENY  git push (code deployment)\n"
printf "    DENY  crontab, launchctl (persistence)\n"
printf "    DENY  .ssh writes, .env writes\n"
printf "    DENY  MCP tools (unknown domain)\n"
printf "    DENY  Unknown/compound commands\n"
printf "    DENY  Writes/edits to ~/.zlar/ (self-protection)\n"
printf "    DENY  Reading the signing key\n"
printf "\n"
printf "  ${BOLD}Upgrade path:${NC}\n"
printf "    Want case-by-case approval instead of blanket deny?\n"
printf "    Run: ${BOLD}~/.zlar/bin/zlar telegram${NC}\n"
printf "    This enables Telegram approval for denied actions.\n"
printf "\n"
printf "  ${BOLD}Commands:${NC}\n"
printf "    ${DIM}~/.zlar/bin/zlar doctor${NC}     — check installation health\n"
printf "    ${DIM}~/.zlar/bin/zlar status${NC}     — what's governed\n"
printf "    ${DIM}~/.zlar/bin/zlar audit${NC}      — recent decisions\n"
printf "    ${DIM}~/.zlar/bin/zlar policy${NC}     — current rules\n"
printf "    ${DIM}~/.zlar/bin/zlar uninstall${NC}  — clean removal\n"
printf "\n"
printf "  Something not working? Run: ${BOLD}~/.zlar/bin/zlar doctor${NC}\n"
printf "\n"
printf "  Open your editor. ZLAR is governing configured tool-call surfaces.\n"
printf "\n"
printf "${BOLD}═══════════════════════════════════════════════════${NC}\n"
printf "\n"
