#!/usr/bin/env python3
"""Bounded child-process inheritance observations."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any

from canonical import sha256_json


def capture_and_validate_startup_environment() -> list[dict[str, str]]:
    records = [{"name": name, "value": value} for name, value in sorted(os.environ.items())]
    allowed_names = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    if {record["name"] for record in records} - allowed_names:
        raise ValueError("startup_environment_name")
    for record in records:
        if record["name"] == "LC_CTYPE" and record["value"] not in {"C", "C.UTF-8", "UTF-8"}:
            raise ValueError("startup_environment_locale")
        if record["name"] == "__CF_USER_TEXT_ENCODING":
            value = record["value"]
            if len(value) > 48 or not value or any(character not in "0123456789abcdefABCDEFxX:" for character in value):
                raise ValueError("startup_environment_cf_encoding")
    return records


def _node_type(mode: int) -> str:
    if stat.S_ISFIFO(mode):
        return "pipe"
    if stat.S_ISCHR(mode):
        return "character"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "other"


def observe(role: str, candidate_root: Path) -> dict[str, Any]:
    descriptors: list[dict[str, Any]] = []
    for descriptor in range(0, 256):
        try:
            node = os.fstat(descriptor)
        except OSError:
            continue
        descriptors.append(
            {
                "descriptor": descriptor,
                "device": node.st_dev,
                "inode": node.st_ino,
                "node_type": _node_type(node.st_mode),
            }
        )
    origin_counts = {"builtin_or_frozen": 0, "candidate": 0, "runtime": 0}
    runtime_root = Path(sys.base_prefix).resolve()
    invalid_origins: list[str] = []
    for module in list(sys.modules.values()):
        origin = getattr(module, "__file__", None)
        if origin is None:
            origin_counts["builtin_or_frozen"] += 1
            continue
        try:
            resolved = Path(origin).resolve(strict=True)
        except (OSError, RuntimeError):
            invalid_origins.append("unresolvable")
            continue
        if resolved == candidate_root or candidate_root in resolved.parents:
            origin_counts["candidate"] += 1
        elif resolved == runtime_root or runtime_root in resolved.parents:
            origin_counts["runtime"] += 1
        else:
            invalid_origins.append(resolved.name)
    environment = [
        {"name": name, "value": value}
        for name, value in sorted(os.environ.items())
    ]
    argv_shape = {
        "argument_count": len(sys.argv),
        "role_argument": sys.argv[1] if len(sys.argv) == 2 else None,
        "script_basename": Path(sys.argv[0]).name,
    }
    core = {
        "argv_shape": argv_shape,
        "candidate_module_root": "candidate-root",
        "cwd_basename": Path.cwd().name,
        "environment": environment,
        "invalid_module_origins": invalid_origins,
        "module_origin_counts": origin_counts,
        "open_descriptors": descriptors,
        "private_material_in_argv_or_environment": False,
        "role": role,
    }
    return {**core, "observation_digest": sha256_json(core)}


def validate_observation(value: object, role: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("process_evidence_not_object")
    body = {key: item for key, item in value.items() if key != "observation_digest"}
    if value.get("observation_digest") != sha256_json(body):
        raise ValueError("process_evidence_digest")
    if value.get("role") != role or value.get("private_material_in_argv_or_environment") is not False:
        raise ValueError("process_evidence_role_or_secret")
    if value.get("environment") != []:
        raise ValueError("child_active_environment_not_empty")
    argv_shape = value.get("argv_shape")
    if argv_shape != {"argument_count": 2, "role_argument": role, "script_basename": "signer_process.py"}:
        raise ValueError("child_argv_shape")
    descriptors = value.get("open_descriptors")
    if not isinstance(descriptors, list) or [row.get("descriptor") for row in descriptors] != [0, 1, 2]:
        raise ValueError("child_descriptor_allowlist")
    if value.get("invalid_module_origins") != []:
        raise ValueError("child_module_origin")
    return value
