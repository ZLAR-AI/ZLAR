#!/usr/bin/env python3
"""Non-circular candidate and campaign manifest validation."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from canonical import CanonicalError, aggregate_records, path_key, read_json, sha256_file, validate_relative_path
from contract import PACKAGE_SCHEMA_VERSION


MANIFEST_NAME = "PACKAGE-MANIFEST.json"
CAMPAIGN_MANIFEST_NAME = "campaign-tree.json"


def collect_regular_files(root: Path, exclude: set[str] | None = None) -> list[dict[str, Any]]:
    exclude = exclude or set()
    if not root.is_absolute():
        raise CanonicalError("root_not_absolute")
    root_stat = os.lstat(root)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise CanonicalError("root_not_directory")
    records: list[dict[str, Any]] = []
    stack = [root]
    while stack:
        current = stack.pop()
        entries = list(os.scandir(current))
        entries.sort(key=lambda entry: entry.name.encode("utf-8", errors="strict"), reverse=True)
        for entry in entries:
            relative = Path(entry.path).relative_to(root).as_posix()
            validate_relative_path(relative)
            node = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(node.st_mode):
                raise CanonicalError(f"manifest_symlink:{relative}")
            if stat.S_ISDIR(node.st_mode):
                stack.append(Path(entry.path))
                continue
            if not stat.S_ISREG(node.st_mode):
                raise CanonicalError(f"manifest_special:{relative}")
            if relative in exclude:
                continue
            records.append(
                {
                    "byte_length": node.st_size,
                    "node_type": "regular",
                    "path": relative,
                    "sha256": sha256_file(Path(entry.path)),
                }
            )
    records.sort(key=lambda record: path_key(record["path"]))
    if len({record["path"] for record in records}) != len(records):
        raise CanonicalError("manifest_duplicate")
    return records


def expected_internal(root: Path) -> dict[str, Any]:
    records = collect_regular_files(root, {MANIFEST_NAME})
    return {
        "aggregate_algorithm": "sha256(canonical_json(sorted_regular_file_records))",
        "aggregate_sha256": aggregate_records(records),
        "canonical_path_contract": "POSIX relative UTF-8; bytewise ascending; no absolute empty repeated slash trailing slash dot dot-dot symlink or special node",
        "files": records,
        "manifest_self_exclusion": MANIFEST_NAME,
        "package_file_set": sorted([record["path"] for record in records] + [MANIFEST_NAME], key=path_key),
        "schema_version": PACKAGE_SCHEMA_VERSION,
    }


def validate_internal(root: Path) -> dict[str, Any]:
    stored = read_json(root / MANIFEST_NAME)
    expected = expected_internal(root)
    if stored != expected:
        raise CanonicalError("package_manifest_mismatch")
    return stored


def complete_identity(root: Path) -> dict[str, Any]:
    validate_internal(root)
    records = collect_regular_files(root)
    source_records = [record for record in records if record["path"].endswith(".py")]
    return {
        "file_count": len(records),
        "package_id": "package-sha256:" + aggregate_records(records),
        "records": records,
        "source_id": "source-sha256:" + aggregate_records(source_records),
    }


def campaign_identity(root: Path) -> dict[str, Any]:
    records = collect_regular_files(root, {CAMPAIGN_MANIFEST_NAME})
    return {
        "aggregate_algorithm": "sha256(canonical_json(sorted_regular_file_records))",
        "aggregate_sha256": aggregate_records(records),
        "file_count": len(records),
        "files": records,
        "manifest_self_exclusion": CAMPAIGN_MANIFEST_NAME,
        "schema_version": "zlar.protected-promotion.campaign-tree.v1",
    }
