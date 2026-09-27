#!/usr/bin/env python3
"""Fresh-exec entrypoint for exactly one authority or destination signer."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
CANDIDATE_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(CANDIDATE_ROOT))

from authority_role import AuthorityRole
from canonical import canonical_bytes, strict_loads
from crypto_rsa import generate_key, public_evidence
from destination_role import DestinationRole
from process_evidence import capture_and_validate_startup_environment, observe


def _emit(value: object) -> None:
    sys.stdout.buffer.write(canonical_bytes(value) + b"\n")
    sys.stdout.buffer.flush()


def _safe_error(exc: BaseException) -> str:
    text = str(exc)
    permitted = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-"
    cleaned = "".join(character if character in permitted else "_" for character in text)[:160]
    return f"{type(exc).__name__}:{cleaned}"


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("authority", "destination"):
        return 64
    role_name = sys.argv[1]
    startup_environment = capture_and_validate_startup_environment()
    os.environ.clear()
    key, generation = generate_key()
    process_record = observe(role_name, CANDIDATE_ROOT)
    if role_name == "authority":
        role: AuthorityRole | DestinationRole = AuthorityRole(key, process_record)
    else:
        role = DestinationRole(key, process_record, Path.cwd())
    _emit(
        {
            "generation": generation,
            "hello": "fresh_exec_signer_ready",
            "private_material_export_count": 0,
            "process_evidence": process_record,
            "public_key": public_evidence(key),
            "role": role_name,
            "startup_environment_allowlist": startup_environment,
        }
    )
    for raw in sys.stdin.buffer:
        request_id = "unidentified-control-message"
        shutdown = False
        try:
            message = strict_loads(raw)
            if not isinstance(message, dict) or set(message) != {"command", "id", "params"}:
                raise ValueError("control_message_shape")
            request_id = message["id"]
            command = message["command"]
            params = message["params"]
            if not isinstance(request_id, str) or not isinstance(command, str) or not isinstance(params, dict):
                raise ValueError("control_message_types")
            if command == "bind_run" and set(params) == {"run_identity"}:
                result = role.bind_run(params["run_identity"])
            elif role_name == "authority" and command == "create_proposal" and params == {}:
                assert isinstance(role, AuthorityRole)
                result = role.create_proposal()
            elif role_name == "authority" and command == "record_event" and set(params) == {
                "event_nonce",
                "proposal_digest",
            }:
                assert isinstance(role, AuthorityRole)
                result = role.record_event(params["proposal_digest"], params["event_nonce"])
            elif role_name == "authority" and command == "issue_once" and params == {}:
                assert isinstance(role, AuthorityRole)
                result = role.issue_once()
            elif role_name == "destination" and command == "bind_authority_context" and set(params) == {
                "event",
                "proposal",
            }:
                assert isinstance(role, DestinationRole)
                result = role.bind_authority_context(params["proposal"], params["event"])
            elif role_name == "destination" and command == "attempt" and set(params) == {"attempt_id", "raw_hex"}:
                assert isinstance(role, DestinationRole)
                try:
                    result = role.handle_attempt(params["attempt_id"], params["raw_hex"])
                except BaseException:
                    result = role._refuse(
                        params["attempt_id"] if isinstance(params["attempt_id"], str) else "unidentified-attempt",
                        "internal_uncertainty",
                    )
            elif command == "shutdown" and params == {}:
                result = role.summary()
                shutdown = True
            else:
                raise ValueError("control_command_not_permitted")
            _emit({"id": request_id, "ok": True, "result": result})
        except BaseException as exc:
            _emit({"error": _safe_error(exc), "id": request_id, "ok": False})
        if shutdown:
            break
    # Drop the only private-key reference before normal exit. It was never serialized.
    del key
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
