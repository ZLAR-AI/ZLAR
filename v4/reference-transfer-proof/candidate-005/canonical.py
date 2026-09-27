#!/usr/bin/env python3
"""Strict, locale-independent canonical JSON and exclusive file helpers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable


CANONICALIZATION_ID = "zlar-json-utf8-sort-v1"


class CanonicalError(ValueError):
    pass


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise CanonicalError("byte_ambiguity:floating_point_not_permitted")


def _reject_constant(value: str) -> Any:
    raise CanonicalError(f"byte_ambiguity:non_finite_number:{value}")


def strict_loads(raw: str | bytes) -> Any:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalError("byte_ambiguity:invalid_utf8") from exc
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_pairs_no_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise CanonicalError("malformed_json") from exc
    _validate_json_value(value)
    return value


def _validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"non_string_key:{path}")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise CanonicalError(f"unsupported_json_type:{path}:{type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _validate_json_value(value)
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


def canonical_text(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utf8_path_key(path: str) -> bytes:
    return path.encode("utf-8", errors="strict")


def aggregate_file_records(records: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    ordered = sorted(records, key=lambda item: utf8_path_key(item["path"]))
    for item in ordered:
        digest.update(item["path"].encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(item["byte_length"]).encode("ascii"))
        digest.update(b"\x00")
        digest.update(item["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def write_bytes_exclusive(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def write_json_exclusive(path: Path, value: Any) -> None:
    write_bytes_exclusive(path, canonical_bytes(value) + b"\n")


def read_json(path: Path) -> Any:
    return strict_loads(path.read_bytes())


def require_absolute_absent(path_text: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute() or str(path) != os.path.abspath(path_text):
        raise CanonicalError("output_root_not_canonical_absolute")
    try:
        os.lstat(path)
    except FileNotFoundError:
        return path
    raise CanonicalError("pre_existing_output_collision")
