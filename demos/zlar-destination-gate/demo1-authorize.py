#!/usr/bin/python3
"""Private attended YubiKey C Grant G ceremony for the installed Demo 1 profile.

This program accepts only a destination-signed N, independently checks the
installed public trust pins, constructs exact G, displays its public meaning,
then invokes PKCS#11 interactively. It never accepts a PIN argument or exposes
any private key.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

HUMAN_UID = 501
CLIENT_PRINCIPAL_ID = "macos-euid:501"
PROFILE_ID = "zlar.demo1.c-backed.v1"
DESTINATION_ID = "zlar.demo1.promotion.local.v1"
STAGED_OBJECT_ID = "demo-1-release.json"
C_ROOT_KEY_ID = "spki-sha256:eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c"
C_PUBLIC_SHA256 = "4260a266c255059b041b8af5805b89fdaa5dfb5c40a291a146842deda2b09890"
POLICY_PATH = Path("/etc/zlar/demo1-authority-roots.json")
MANIFEST_PATH = Path("/etc/zlar/demo1-installation-manifest.json")
C_PUBLIC_PATH = Path("/etc/zlar/demo1-founder-authority-root-c-v1.pub.pem")
DESTINATION_PUBLIC_PATH = Path("/etc/zlar/demo1-destination-public.pem")
SIGNED_GRANT_PATH = Path("/var/tmp/zlar-demo1-authority/grant-g.json")
CHALLENGE_PATH = Path("/var/tmp/zlar-demo1-authority/challenge-n.json")
AUTHORITY_TRANSFER_ROOT = Path("/var/tmp/zlar-demo1-authority")
TRANSFER_GID = 20
SOCKET_GROUP_GID = 80
PKCS11_TOOL = Path("/opt/homebrew/Cellar/opensc/0.27.1/bin/pkcs11-tool")
PKCS11_MODULE = Path("/opt/homebrew/Cellar/yubico-piv-tool/2.7.3/lib/libykcs11.2.7.3.dylib")
OPENSSL = Path("/opt/homebrew/Cellar/openssl@3/3.6.3/bin/openssl")
TRUSTED_TOOL_FILES = {
    PKCS11_TOOL: ("aa4b928e52df065265fc70630df927c797e2c12cad546b4e1ad566fc061ce2d2", 0o555),
    PKCS11_MODULE: ("fd7e3585238582b3b7eb20ced983179d8349862163c79886e7738632d558a51e", 0o444),
    OPENSSL: ("103fc7706cf6646f226d96f29242d81890363499afc730e7ef1fadd64b3a123c", 0o555),
}
SAFE_ID_PREFIX = "sha256:"

DOMAINS = {
    "challenge": "ZLAR-DEMO1-CHALLENGE-N-V1",
    "action": "ZLAR-DEMO1-ACTION-V1",
    "grant": "ZLAR-DEMO1-GRANT-G-V1",
    "credential": "ZLAR-DEMO1-BOARDING-A-V1",
    "commit": "ZLAR-DEMO1-PROMOTION-COMMIT-V1",
    "receipt": "ZLAR-DEMO1-RECEIPT-V1",
    "policy": "ZLAR-DEMO1-RECOGNITION-POLICY-V1",
}


class CeremonyRefusal(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_canonical(path: Path) -> Any:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or path.is_symlink():
        raise CeremonyRefusal(f"input_file_refused:{path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CeremonyRefusal(f"invalid_json:{path}") from error
    if canonical(value) != raw:
        raise CeremonyRefusal(f"noncanonical_transport:{path}")
    return value


def exact_keys(value: Any, keys: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise CeremonyRefusal(f"{label}_shape")


def digest_id(domain: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + canonical(value)).hexdigest()


def public_key_id(path: Path, temporary: Path) -> str:
    der_path = temporary / (path.name + ".der")
    subprocess.run(
        [str(OPENSSL), "pkey", "-pubin", "-in", str(path), "-pubout", "-outform", "DER", "-out", str(der_path)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    return "spki-sha256:" + hashlib.sha256(der_path.read_bytes()).hexdigest()


def verify_ed25519(public_key: Path, preimage: bytes, signature: bytes, temporary: Path, label: str) -> None:
    input_path = temporary / f"{label}.preimage"
    signature_path = temporary / f"{label}.signature"
    input_path.write_bytes(preimage)
    signature_path.write_bytes(signature)
    input_path.chmod(0o600)
    signature_path.chmod(0o600)
    result = subprocess.run(
        [
            str(OPENSSL), "pkeyutl", "-verify", "-pubin", "-rawin",
            "-inkey", str(public_key), "-in", str(input_path), "-sigfile", str(signature_path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode != 0:
        raise CeremonyRefusal(f"{label}_signature_invalid")


def decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != 86:
        raise CeremonyRefusal("signature_shape")
    try:
        raw = base64.urlsafe_b64decode(value + "==")
    except ValueError as error:
        raise CeremonyRefusal("signature_encoding") from error
    if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise CeremonyRefusal("signature_noncanonical")
    return raw


def load_trust(temporary: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    for path in [POLICY_PATH, MANIFEST_PATH, C_PUBLIC_PATH, DESTINATION_PUBLIC_PATH]:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or path.is_symlink():
            raise CeremonyRefusal(f"trusted_path_refused:{path}")
    for path, (expected_digest, expected_mode) in TRUSTED_TOOL_FILES.items():
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or path.is_symlink()
            or metadata.st_uid != HUMAN_UID
            or metadata.st_gid != 80
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest
        ):
            raise CeremonyRefusal(f"trusted_tool_identity:{path}")
    if hashlib.sha256(C_PUBLIC_PATH.read_bytes()).hexdigest() != C_PUBLIC_SHA256:
        raise CeremonyRefusal("c_public_key_digest")
    if public_key_id(C_PUBLIC_PATH, temporary) != C_ROOT_KEY_ID:
        raise CeremonyRefusal("c_public_key_identity")
    policy = parse_canonical(POLICY_PATH)
    manifest = parse_canonical(MANIFEST_PATH)
    exact_keys(manifest, {
        "authority_transfer_gid", "authority_transfer_mode", "authority_transfer_uid", "broker_sha256",
        "ceremony_tool_sha256", "clang_sha256", "client_uid", "installed_file_sha256",
        "node_sha256", "profile_id",
        "recognition_policy_sha256", "service_gid", "service_uid", "source_commit",
        "socket_group_gid", "source_manifest_sha256", "type", "v",
    }, "installation_manifest")
    if manifest.get("v") != 1 or manifest.get("type") != "zlar.demo1.installation_manifest":
        raise CeremonyRefusal("installation_manifest_schema")
    if (
        manifest.get("profile_id") != PROFILE_ID
        or manifest.get("client_uid") != HUMAN_UID
        or manifest.get("socket_group_gid") != SOCKET_GROUP_GID
        or manifest.get("authority_transfer_uid") != HUMAN_UID
        or manifest.get("authority_transfer_gid") != TRANSFER_GID
        or manifest.get("authority_transfer_mode") != 0o700
    ):
        raise CeremonyRefusal("installation_manifest_scope")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != manifest.get("ceremony_tool_sha256"):
        raise CeremonyRefusal("ceremony_tool_digest")
    exact_keys(policy, {"algorithm", "destination", "destination_id", "domains", "issuers", "profile_id", "roots", "type", "v"}, "policy")
    if policy.get("v") != 1 or policy.get("type") != "recognition_policy":
        raise CeremonyRefusal("policy_schema")
    if policy.get("profile_id") != PROFILE_ID or policy.get("destination_id") != DESTINATION_ID:
        raise CeremonyRefusal("policy_scope")
    if policy.get("algorithm") != "Ed25519" or policy.get("domains") != DOMAINS:
        raise CeremonyRefusal("policy_algorithm_or_domains")
    if len(policy.get("roots", [])) != 1 or policy["roots"][0].get("key_id") != C_ROOT_KEY_ID or policy["roots"][0].get("status") != "active":
        raise CeremonyRefusal("policy_c_root")
    if len(policy.get("issuers", [])) != 1 or policy["issuers"][0].get("status") != "active":
        raise CeremonyRefusal("policy_issuer")
    if policy.get("destination", {}).get("status") != "active":
        raise CeremonyRefusal("policy_destination")
    policy_digest = digest_id(DOMAINS["policy"], policy)
    if manifest.get("recognition_policy_sha256") != policy_digest:
        raise CeremonyRefusal("independent_policy_digest")
    if public_key_id(DESTINATION_PUBLIC_PATH, temporary) != policy["destination"]["key_id"]:
        raise CeremonyRefusal("destination_public_key_identity")
    return policy, manifest


def validate_challenge(response: Any, policy: dict[str, Any], temporary: Path) -> dict[str, Any]:
    record = response.get("challenge") if isinstance(response, dict) and "challenge" in response else response
    exact_keys(record, {"body", "signature"}, "challenge_record")
    body = record["body"]
    exact_keys(body, {
        "v", "type", "profile_id", "destination_id", "principal_id", "challenge_nonce",
        "staged_object_id", "artifact_sha256", "from_generation", "to_generation",
        "issued_at", "expires_at",
    }, "challenge_body")
    if body.get("v") != 1 or body.get("type") != "challenge":
        raise CeremonyRefusal("challenge_schema")
    if body.get("profile_id") != PROFILE_ID or body.get("destination_id") != DESTINATION_ID:
        raise CeremonyRefusal("challenge_scope")
    if body.get("principal_id") != CLIENT_PRINCIPAL_ID or body.get("staged_object_id") != STAGED_OBJECT_ID:
        raise CeremonyRefusal("challenge_binding")
    if body.get("to_generation") != body.get("from_generation") + 1:
        raise CeremonyRefusal("challenge_generation")
    now = int(time.time())
    if not (body.get("issued_at") <= now < body.get("expires_at")):
        raise CeremonyRefusal("challenge_not_current")
    preimage = DOMAINS["challenge"].encode() + b"\0" + canonical(body)
    verify_ed25519(DESTINATION_PUBLIC_PATH, preimage, decode_signature(record["signature"]), temporary, "challenge")
    return record


def action_from_challenge(challenge: dict[str, Any]) -> dict[str, Any]:
    body = challenge["body"]
    action = {
        "v": 1,
        "type": "action",
        "profile_id": body["profile_id"],
        "principal_id": body["principal_id"],
        "destination_id": body["destination_id"],
        "consequence": "code.deploy",
        "operation": "deployment.promote",
        "challenge_id": digest_id(DOMAINS["challenge"], body),
        "staged_object_id": body["staged_object_id"],
        "artifact_sha256": body["artifact_sha256"],
        "from_generation": body["from_generation"],
        "to_generation": body["to_generation"],
        "measure": 1,
        "expires_at": body["expires_at"],
    }
    return action


def construct_grant(challenge: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    now = int(time.time())
    if now >= challenge["body"]["expires_at"]:
        raise CeremonyRefusal("challenge_expired_before_grant")
    action = action_from_challenge(challenge)
    return {
        "v": 1,
        "type": "grant",
        "profile_id": PROFILE_ID,
        "authority_root_key_id": C_ROOT_KEY_ID,
        "authorized_issuer_key_id": policy["issuers"][0]["key_id"],
        "grant_nonce": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
        "action": action,
        "action_id": digest_id(DOMAINS["action"], action),
        "allocation_unit": "protected_promotion",
        "maximum_allocation": 1,
        "issued_at": now,
        "not_before": now,
        "expires_at": challenge["body"]["expires_at"],
    }


def write_exclusive(path: Path, raw: bytes) -> None:
    parent = path.parent.lstat()
    if (
        path.parent != AUTHORITY_TRANSFER_ROOT
        or not stat.S_ISDIR(parent.st_mode)
        or path.parent.is_symlink()
        or parent.st_uid != HUMAN_UID
        or parent.st_gid != TRANSFER_GID
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise CeremonyRefusal("authority_transfer_root_identity")
    if path.exists() or path.is_symlink():
        raise CeremonyRefusal("output_exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        os.fchown(descriptor, HUMAN_UID, TRANSFER_GID)
        os.fchmod(descriptor, 0o640)
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if metadata.st_uid != HUMAN_UID or metadata.st_gid != TRANSFER_GID or stat.S_IMODE(metadata.st_mode) != 0o640:
        raise CeremonyRefusal("signed_grant_file_identity")


def ceremony(challenge_path: Path, output_path: Path) -> dict[str, Any]:
    if os.geteuid() != HUMAN_UID:
        raise CeremonyRefusal("human_ceremony_uid_refused")
    if output_path.absolute() != SIGNED_GRANT_PATH:
        raise CeremonyRefusal("output_path_refused")
    if challenge_path.absolute() != CHALLENGE_PATH:
        raise CeremonyRefusal("challenge_path_refused")
    challenge_metadata = challenge_path.lstat()
    if (
        challenge_metadata.st_uid != HUMAN_UID
        or challenge_metadata.st_gid != TRANSFER_GID
        or stat.S_IMODE(challenge_metadata.st_mode) != 0o640
    ):
        raise CeremonyRefusal("challenge_file_identity")
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="zlar-demo1-g-") as directory:
            temporary = Path(directory)
            policy, _manifest = load_trust(temporary)
            challenge = validate_challenge(parse_canonical(challenge_path), policy, temporary)
            body = construct_grant(challenge, policy)
            preimage = DOMAINS["grant"].encode() + b"\0" + canonical(body)
            print("Exact proposed Grant G (public, not yet authority):")
            print(canonical(body).decode())
            print("Grant preimage SHA-256:", hashlib.sha256(preimage).hexdigest())
            print("Maximum protected-effect allocation: 1")
            print("The next command requires YubiKey C PIN ALWAYS and one fresh touch.")
            input("Press Enter to begin the private C signing act, or Control-C to abort: ")

            preimage_path = temporary / "grant.preimage"
            signature_path = temporary / "grant.signature"
            preimage_path.write_bytes(preimage)
            preimage_path.chmod(0o600)
            result = subprocess.run(
                [
                    str(PKCS11_TOOL), "--module", str(PKCS11_MODULE), "--login", "--sign",
                    "--id", "02", "--mechanism", "EDDSA", "--input-file", str(preimage_path),
                    "--output-file", str(signature_path),
                ],
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
            if result.returncode != 0:
                raise CeremonyRefusal("c_signing_failed")
            signature = signature_path.read_bytes()
            if len(signature) != 64:
                raise CeremonyRefusal("c_signature_length")
            verify_ed25519(C_PUBLIC_PATH, preimage, signature, temporary, "grant")
            record = {
                "body": body,
                "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
            }
            write_exclusive(output_path, canonical(record))
            return {
                "v": 1,
                "status": "FRESH_G_SIGNED_AND_VERIFIED",
                "grant_id": digest_id(DOMAINS["grant"], body),
                "output": str(output_path),
                "authority_status": "bounded_authority_originated_in_exact_G",
                "protected_effect_delta": 0,
            }
    finally:
        os.umask(old_umask)


def main() -> int:
    parser = argparse.ArgumentParser(description="Attended YubiKey C Grant G ceremony")
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = ceremony(args.challenge, args.output)
        print(canonical(result).decode())
        return 0
    except (CeremonyRefusal, OSError, subprocess.SubprocessError) as error:
        print(canonical({"v": 1, "status": "REFUSED", "reason": str(error)}).decode(), file=sys.stderr)
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
