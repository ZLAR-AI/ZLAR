#!/usr/bin/env python3
"""Complete Demo 1 source identity construction and read-only verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

PRODUCT_RELATIVE = Path("demos/zlar-destination-gate")
MANIFEST_RELATIVE = PRODUCT_RELATIVE / "PRODUCT-MANIFEST.json"
CYAN_RELATIVE = Path("cyan")
ENGINE_RELATIVE = Path("v4/reference-transfer-proof/candidate-005")
TEST_RELATIVE = Path("tests/product-cut-0.1")
CURRENT_SOURCE_ROOTS = (CYAN_RELATIVE, PRODUCT_RELATIVE)
MANIFEST_COMPATIBILITY_ROOTS = (TEST_RELATIVE,)
HISTORICAL_BASELINE_ROOTS = (ENGINE_RELATIVE,)
MANIFEST_ROOTS = CURRENT_SOURCE_ROOTS + MANIFEST_COMPATIBILITY_ROOTS + HISTORICAL_BASELINE_ROOTS
CANDIDATE_ROOTS = MANIFEST_ROOTS  # compatibility name for existing read-only tests
SELF_EXCLUSION = "PRODUCT-MANIFEST.json excludes only its own bytes; the Git tree and commit bind those bytes"
HISTORICAL_PRODUCT_CUT_COMMIT = "9dab89ec16edd6009dc34f973361502eda35b73c"


class ProductIdentityFailure(RuntimeError):
    pass


def repository_root() -> Path:
    root = Path(__file__).absolute().parents[2]
    if (root / PRODUCT_RELATIVE).absolute() != Path(__file__).absolute().parent:
        raise ProductIdentityFailure("product_outside_expected_clone_path")
    if root.is_symlink() or not root.is_dir():
        raise ProductIdentityFailure("repository_root_invalid")
    return root


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _aggregate(records: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in records:
        digest.update(row["path"].encode("utf-8") + b"\0")
        digest.update(str(row["byte_length"]).encode("ascii") + b"\0")
        digest.update(row["sha256"].encode("ascii") + b"\n")
    return digest.hexdigest()


def collect_candidate(root: Path) -> tuple[list[str], list[dict[str, Any]]]:
    directories: list[str] = []
    records: list[dict[str, Any]] = []
    seen_inodes: set[tuple[int, int]] = set()
    root_real = root.resolve(strict=True)
    for relative_root in MANIFEST_ROOTS:
        candidate_root = root / relative_root
        if candidate_root.is_symlink() or not candidate_root.is_dir():
            raise ProductIdentityFailure(f"candidate_root_invalid:{relative_root.as_posix()}")
        candidate_real = candidate_root.resolve(strict=True)
        if candidate_real != root_real / relative_root:
            raise ProductIdentityFailure(f"candidate_root_outside_clone:{relative_root.as_posix()}")
        directories.append(relative_root.as_posix())
        for current_text, dirnames, filenames in os.walk(candidate_root, topdown=True, followlinks=False):
            dirnames.sort(key=lambda value: value.encode("utf-8"))
            filenames.sort(key=lambda value: value.encode("utf-8"))
            current = Path(current_text)
            for dirname in dirnames:
                node = current / dirname
                mode = node.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    raise ProductIdentityFailure(f"candidate_directory_node_invalid:{node.relative_to(root).as_posix()}")
                if node.resolve(strict=True) != root_real / node.relative_to(root):
                    raise ProductIdentityFailure(f"candidate_directory_outside_clone:{node.relative_to(root).as_posix()}")
                directories.append(node.relative_to(root).as_posix())
            for filename in filenames:
                node = current / filename
                relative = node.relative_to(root)
                mode = node.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                    raise ProductIdentityFailure(f"candidate_file_node_invalid:{relative.as_posix()}")
                if node.resolve(strict=True) != root_real / relative:
                    raise ProductIdentityFailure(f"candidate_file_outside_clone:{relative.as_posix()}")
                metadata = node.stat()
                inode = (metadata.st_dev, metadata.st_ino)
                if metadata.st_nlink != 1 or inode in seen_inodes:
                    raise ProductIdentityFailure(f"candidate_hardlink_refused:{relative.as_posix()}")
                seen_inodes.add(inode)
                if relative == MANIFEST_RELATIVE:
                    continue
                records.append({"byte_length": metadata.st_size, "path": relative.as_posix(), "sha256": _sha256(node)})
    directories.sort(key=lambda value: value.encode("utf-8"))
    records.sort(key=lambda row: row["path"].encode("utf-8"))
    return directories, records


def build_manifest(root: Path) -> dict[str, Any]:
    directories, records = collect_candidate(root)
    engine_prefix = ENGINE_RELATIVE.as_posix() + "/"
    engine_records = [
        {**row, "path": row["path"][len(engine_prefix):]}
        for row in records
        if row["path"].startswith(engine_prefix)
    ]
    internal = json.loads((root / ENGINE_RELATIVE / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    return {
        "aggregate_algorithm": "sha256(path_utf8 || NUL || decimal_byte_length || NUL || raw_sha256_ascii || LF)",
        "aggregate_sha256": _aggregate(records),
        "candidate_roots": [path.as_posix() for path in MANIFEST_ROOTS],
        "current_source_roots": [path.as_posix() for path in CURRENT_SOURCE_ROOTS],
        "manifest_compatibility_roots": [path.as_posix() for path in MANIFEST_COMPATIBILITY_ROOTS],
        "historical_baseline_roots": [path.as_posix() for path in HISTORICAL_BASELINE_ROOTS],
        "historical_product_cut_commit": HISTORICAL_PRODUCT_CUT_COMMIT,
        "current_entrypoint": "demos/zlar-destination-gate/demo1.mjs",
        "installed_profile_id": "zlar.demo1.c-backed.v1",
        "installed_source_status": "source_only_not_installed",
        "installed_client_uid": 501,
        "installed_service_uid": 450,
        "installed_service_entrypoint": "demos/zlar-destination-gate/demo1-installed-service.mjs",
        "installed_broker_source": "demos/zlar-destination-gate/demo1-peer-broker.c",
        "installed_installer": "demos/zlar-destination-gate/demo1-install.py",
        "historical_runner": "demos/zlar-destination-gate/run.py",
        "historical_runner_status": "fail_closed_non_routing",
        "directories": directories,
        "engine_complete_13_file_aggregate_sha256": _aggregate(engine_records),
        "engine_file_count": len(engine_records),
        "engine_internal_self_excluding_aggregate_sha256": internal["aggregate_sha256"],
        "file_count_excluding_manifest": len(records),
        "files": records,
        "locale_independent_comparator": "ascending unsigned lexicographic order of relative UTF-8 path bytes",
        "manifest_path": MANIFEST_RELATIVE.as_posix(),
        "schema_version": "zlar.demo1.source-manifest.v1",
        "self_exclusion": SELF_EXCLUSION,
    }


def verify_manifest(root: Path | None = None) -> dict[str, Any]:
    root = repository_root() if root is None else root.absolute()
    path = root / MANIFEST_RELATIVE
    if path.is_symlink() or not path.is_file():
        raise ProductIdentityFailure("product_manifest_invalid")
    saved = json.loads(path.read_text(encoding="utf-8"))
    actual = build_manifest(root)
    if saved != actual:
        raise ProductIdentityFailure("product_manifest_drift")
    if saved["self_exclusion"] != SELF_EXCLUSION:
        raise ProductIdentityFailure("product_manifest_self_exclusion")
    if saved["engine_file_count"] != 13:
        raise ProductIdentityFailure("engine_file_count")
    if saved["engine_complete_13_file_aggregate_sha256"] != "e037738dc7abe3b2c1d6c63e7103275ed73ce241ab0236f21f1feadee4914e2f":
        raise ProductIdentityFailure("engine_complete_aggregate")
    if saved["engine_internal_self_excluding_aggregate_sha256"] != "958171c7219e9d0aec9878cb03fa4e29b01af8a824216be9df3451c0becb70d3":
        raise ProductIdentityFailure("engine_internal_aggregate")
    if saved["current_source_roots"] != ["cyan", "demos/zlar-destination-gate"]:
        raise ProductIdentityFailure("current_source_roots")
    if saved["historical_runner_status"] != "fail_closed_non_routing":
        raise ProductIdentityFailure("historical_runner_status")
    if saved["installed_profile_id"] != "zlar.demo1.c-backed.v1":
        raise ProductIdentityFailure("installed_profile_id")
    if saved["installed_source_status"] != "source_only_not_installed":
        raise ProductIdentityFailure("installed_source_status")
    if saved["installed_client_uid"] != 501 or saved["installed_service_uid"] != 450:
        raise ProductIdentityFailure("installed_identity")
    return saved


def main() -> int:
    parser = argparse.ArgumentParser(description="Build or read-only verify the complete Demo 1 source manifest")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    root = repository_root()
    path = root / MANIFEST_RELATIVE
    if args.write:
        raw = _canonical(build_manifest(root)) + b"\n"
        path.write_bytes(raw)
        print(json.dumps({"manifest_sha256": hashlib.sha256(raw).hexdigest(), "status": "WRITTEN"}, sort_keys=True))
    else:
        manifest = verify_manifest(root)
        print(json.dumps({"aggregate_sha256": manifest["aggregate_sha256"], "status": "VERIFIED_READ_ONLY"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
