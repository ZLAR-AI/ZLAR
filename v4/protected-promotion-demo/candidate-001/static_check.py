#!/usr/bin/env python3
"""Read-only static gate for write sites, imports, process creation and live-adapter absence."""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical import canonical_bytes, sha256_file
from manifest import validate_internal


STANDARD_IMPORTS = {
    "__future__",
    "argparse",
    "ast",
    "base64",
    "collections",
    "copy",
    "dataclasses",
    "errno",
    "hashlib",
    "json",
    "math",
    "os",
    "pathlib",
    "secrets",
    "select",
    "shutil",
    "stat",
    "subprocess",
    "sys",
    "time",
    "typing",
    "unittest",
}


def run(candidate_root: Path, require_manifest: bool = True) -> dict[str, Any]:
    if require_manifest:
        validate_internal(candidate_root)
    python_files = sorted(candidate_root.rglob("*.py"), key=lambda path: path.relative_to(candidate_root).as_posix().encode())
    local_modules = {path.stem for path in python_files if path.parent == candidate_root}
    imports: list[dict[str, str]] = []
    popen_sites: list[str] = []
    network_imports: list[str] = []
    for path in python_files:
        relative = path.relative_to(candidate_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [str(node.module).split(".")[0]] if node.module else []
            else:
                names = []
            for name in names:
                imports.append({"module": name, "path": relative})
                if name in {"requests", "socket", "urllib", "http", "ftplib"}:
                    network_imports.append(f"{relative}:{name}")
                if name not in STANDARD_IMPORTS and name not in local_modules:
                    raise ValueError(f"undeclared_import:{relative}:{name}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess" and node.func.attr == "Popen":
                    popen_sites.append(f"{relative}:{node.lineno}")
    if len(popen_sites) != 1 or not popen_sites[0].startswith("process_channel.py:"):
        raise ValueError("process_spawn_site_set")
    destination = candidate_root / "destination_role.py"
    lines = destination.read_text(encoding="utf-8").splitlines()
    commit_markers = [index + 1 for index, line in enumerate(lines) if "PROTECTED_COMMIT_SITE" in line]
    if len(commit_markers) != 1:
        raise ValueError("protected_commit_marker_count")
    later = lines[commit_markers[0] : commit_markers[0] + 4]
    if sum("self.state = after" in line for line in later) != 1:
        raise ValueError("protected_commit_assignment")
    independent_source = (candidate_root / "coverage_independent.py").read_text(encoding="utf-8")
    if "coverage_subject" in independent_source:
        raise ValueError("coverage_regenerator_dependency")
    executable_text = "\n".join(path.read_text(encoding="utf-8") for path in python_files)
    forbidden_tokens = ("anth" + "ropic", "open" + "ai", "claude" + "_adapter", "codex" + "_adapter")
    live_adapter_tokens = [token for token in forbidden_tokens if token in executable_text.lower()]
    if live_adapter_tokens:
        raise ValueError("live_adapter_dependency")
    return {
        "checks": {
            "candidate_manifest": require_manifest,
            "coverage_regenerator_independent": True,
            "exactly_one_child_spawn_site": True,
            "exactly_one_protected_commit_site": True,
            "live_agent_adapter_absent": True,
            "network_imports_absent": not network_imports,
        },
        "imports": imports,
        "network_imports": network_imports,
        "popen_sites": popen_sites,
        "protected_commit_site": f"destination_role.py:{commit_markers[0]}",
        "python_file_count": len(python_files),
        "schema_version": "zlar.protected-promotion.static-surface.v1",
        "source_files": [
            {"path": path.relative_to(candidate_root).as_posix(), "sha256": sha256_file(path)} for path in python_files
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--without-manifest", action="store_true")
    args = parser.parse_args()
    result = run(Path(args.candidate_root).resolve(), require_manifest=not args.without_manifest)
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
