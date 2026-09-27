#!/usr/bin/env python3
"""Bounded parent-side JSONL channel for fresh-exec signer children."""

from __future__ import annotations

import os
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from canonical import canonical_bytes, strict_loads
from process_evidence import validate_observation


class ChannelError(RuntimeError):
    pass


class SignerChannel:
    def __init__(self, role: str, candidate_root: Path, campaign_root: Path):
        if role not in ("authority", "destination"):
            raise ChannelError("role")
        self.role = role
        self.command_count = 0
        self.lifecycle: dict[str, Any] = {
            "close_fds": True,
            "commands": 0,
            "active_environment_empty": True,
            "startup_environment_allowlisted": True,
            "role": role,
            "spawned": False,
            "stderr_byte_length": None,
            "wait_status": None,
        }
        script = candidate_root / "signer_process.py"
        argv = [sys.executable, "-I", "-S", "-E", "-s", "-B", str(script), role]
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=campaign_root,
            env={},
            close_fds=True,
            bufsize=0,
            start_new_session=False,
        )
        self.lifecycle["spawned"] = True
        self.lifecycle["pid"] = self.process.pid
        self.lifecycle["argv_shape"] = ["bound_interpreter", "-I", "-S", "-E", "-s", "-B", "signer_process.py", role]
        hello = self._read_line(120.0)
        if not isinstance(hello, dict) or hello.get("hello") != "fresh_exec_signer_ready" or hello.get("role") != role:
            self.abort()
            raise ChannelError("signer_hello")
        validate_observation(hello.get("process_evidence"), role)
        startup_environment = hello.get("startup_environment_allowlist")
        if not isinstance(startup_environment, list) or {
            row.get("name") for row in startup_environment if isinstance(row, dict)
        } - {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}:
            self.abort()
            raise ChannelError("startup_environment_allowlist")
        if hello.get("private_material_export_count") != 0:
            self.abort()
            raise ChannelError("private_material_export")
        self.hello = hello

    def _read_line(self, timeout: float) -> Any:
        assert self.process.stdout is not None
        ready, _, _ = select.select([self.process.stdout], [], [], timeout)
        if not ready:
            raise ChannelError("child_response_timeout")
        raw = self.process.stdout.readline()
        if raw == b"":
            raise ChannelError("child_channel_closed")
        return strict_loads(raw)

    def command(self, name: str, params: dict[str, Any], timeout: float = 15.0) -> Any:
        if self.process.poll() is not None:
            raise ChannelError("child_not_running")
        self.command_count += 1
        request_id = f"{self.role}-control-{self.command_count:03d}"
        message = {"command": name, "id": request_id, "params": params}
        assert self.process.stdin is not None
        self.process.stdin.write(canonical_bytes(message) + b"\n")
        self.process.stdin.flush()
        response = self._read_line(timeout)
        if not isinstance(response, dict) or response.get("id") != request_id or response.get("ok") is not True:
            raise ChannelError("child_command_refused:" + str(response.get("error") if isinstance(response, dict) else "shape"))
        self.lifecycle["commands"] = self.command_count
        return response["result"]

    def close(self) -> dict[str, Any]:
        summary = self.command("shutdown", {}, timeout=15.0)
        assert self.process.stdin is not None and self.process.stderr is not None
        self.process.stdin.close()
        try:
            status = self.process.wait(timeout=15.0)
        except subprocess.TimeoutExpired as exc:
            self.process.kill()
            self.process.wait(timeout=5.0)
            raise ChannelError("child_shutdown_timeout") from exc
        stderr = self.process.stderr.read()
        self.lifecycle["wait_status"] = status
        self.lifecycle["stderr_byte_length"] = len(stderr)
        self.lifecycle["normal_exit"] = status == 0
        if status != 0 or stderr:
            raise ChannelError("child_exit_or_stderr")
        return {"lifecycle": self.lifecycle, "summary": summary}

    def abort(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass
