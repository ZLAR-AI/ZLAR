#!/usr/bin/env python3
"""Strict canonical JSON and fail-closed file helpers for the local proof."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Iterable


CANONICALIZATION_ID = "zlar.protected-promotion.json-utf8-sort.v1"


class CanonicalError(ValueError):
    """Input cannot be represented by the bounded canonical contract."""


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _reject_float(_: str) -> Any:
    raise CanonicalError("byte_ambiguity:floating_point_not_permitted")


def _reject_constant(value: str) -> Any:
    raise CanonicalError(f"byte_ambiguity:non_finite_number:{value}")


def _validate(value: Any, location: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"non_string_key:{location}")
            _validate(item, f"{location}.{key}")
        return
    raise CanonicalError(f"unsupported_json_type:{location}:{type(value).__name__}")


def strict_loads(raw: str | bytes) -> Any:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalError("byte_ambiguity:invalid_utf8") from exc
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_object_no_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise CanonicalError("malformed_json") from exc
    _validate(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    _validate(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalError("canonicalization_failed") from exc


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CanonicalError("file_not_regular")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CanonicalError("file_identity_drift")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def validate_relative_path(path: str) -> None:
    if not isinstance(path, str) or not path:
        raise CanonicalError("path_empty")
    try:
        encoded = path.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise CanonicalError("path_invalid_utf8") from exc
    if b"\x00" in encoded or path.startswith("/") or path.endswith("/") or "//" in path:
        raise CanonicalError("path_noncanonical")
    components = path.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise CanonicalError("path_component_forbidden")


def path_key(path: str) -> bytes:
    validate_relative_path(path)
    return path.encode("utf-8", errors="strict")


def aggregate_records(records: Iterable[dict[str, Any]]) -> str:
    ordered = sorted(records, key=lambda record: path_key(record["path"]))
    return sha256_bytes(canonical_bytes(ordered))


def write_bytes_exclusive(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short_write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_exclusive(path: Path, value: Any) -> None:
    write_bytes_exclusive(path, canonical_bytes(value) + b"\n")


def read_json(path: Path) -> Any:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CanonicalError("json_not_regular")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise CanonicalError("json_too_large")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CanonicalError("json_identity_drift")
        return strict_loads(b"".join(chunks))
    finally:
        os.close(descriptor)
