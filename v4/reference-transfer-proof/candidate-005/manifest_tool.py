#!/usr/bin/env python3
"""Mechanical package-manifest generator; not part of proof execution."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import os
from pathlib import Path
from typing import Any

from canonical import aggregate_file_records, canonical_bytes, sha256_file, utf8_path_key


def collect(root: Path, exclude: set[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for current_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort(key=utf8_path_key)
        filenames.sort(key=utf8_path_key)
        current = Path(current_root)
        for dirname in dirnames:
            path = current / dirname
            if path.is_symlink():
                raise SystemExit("manifest_symlink")
        for filename in filenames:
            path = current / filename
            if path.is_symlink() or not path.is_file():
                raise SystemExit("manifest_nonregular_node")
            relative = path.relative_to(root).as_posix()
            if relative in exclude:
                continue
            records.append({"byte_length": path.stat().st_size, "path": relative, "sha256": sha256_file(path)})
    records.sort(key=lambda row: utf8_path_key(row["path"]))
    return records


def internal_manifest(package_root: Path) -> dict[str, Any]:
    records = collect(package_root, {"PACKAGE-MANIFEST.json"})
    exact_files = sorted([row["path"] for row in records] + ["PACKAGE-MANIFEST.json"], key=utf8_path_key)
    return {
        "aggregate_algorithm": "sha256(path_utf8 || NUL || decimal_byte_length || NUL || raw_sha256_ascii || LF)",
        "aggregate_sha256": aggregate_file_records(records),
        "files": records,
        "locale_independent_comparator": "ascending unsigned lexicographic order of each relative path encoded as UTF-8 bytes",
        "package_file_set": exact_files,
        "schema_version": "zlar.star4.package-manifest.v1",
        "self_exclusion": "PACKAGE-MANIFEST.json is covered by the external complete-package manifest",
    }


def external_manifest(snapshot_root: Path) -> dict[str, Any]:
    records = collect(snapshot_root, set())
    return {
        "aggregate_algorithm": "sha256(path_utf8 || NUL || decimal_byte_length || NUL || raw_sha256_ascii || LF)",
        "aggregate_sha256": aggregate_file_records(records),
        "file_count": len(records),
        "files": records,
        "locale_independent_comparator": "ascending unsigned lexicographic order of each relative path encoded as UTF-8 bytes",
        "schema_version": "zlar.star4.external-complete-package-manifest.v1",
    }


def write_new(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--print-internal", action="store_true")
    modes.add_argument("--write-external", action="store_true")
    parser.add_argument("--package-root")
    parser.add_argument("--snapshot-root")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.print_internal:
        if not args.package_root:
            raise SystemExit("package_root_required")
        sys.stdout.buffer.write(canonical_bytes(internal_manifest(Path(args.package_root))) + b"\n")
        return 0
    if not args.snapshot_root or not args.output:
        raise SystemExit("snapshot_root_and_output_required")
    write_new(Path(args.output), external_manifest(Path(args.snapshot_root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
