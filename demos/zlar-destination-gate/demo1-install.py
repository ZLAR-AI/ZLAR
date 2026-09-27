#!/usr/bin/env python3
"""Bounded root installer and read-only planner for the Demo 1 destination.

No installation is performed without --install, EUID 0, and independently
supplied exact source commit and product-manifest hash pins.
"""

from __future__ import annotations

import argparse
import base64
import grp
import hashlib
import json
import os
import plistlib
import pwd
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

CLIENT_USER = "vincentnijjar"
CLIENT_UID = 501
SERVICE_USER = "_zlar_demo1"
SERVICE_GROUP = "_zlar_demo1"
SERVICE_UID = 450
SERVICE_GID = 450
HUMAN_USER = "vincentnijjar"
HUMAN_UID = 501
HUMAN_GID = 20
SOCKET_GROUP = "admin"
SOCKET_GROUP_GID = 80
PROFILE_ID = "zlar.demo1.c-backed.v1"
DESTINATION_ID = "zlar.demo1.promotion.local.v1"
C_KEY_ID = "spki-sha256:eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c"
EXPECTED_NODE_SHA256 = "245e0321af97d3c21dd4e7104457334dfe3c3ba7982d0db75363e354565f8cbb"
EXPECTED_CLANG_SHA256 = "b8763cf250e607a778bb4603cecb5b90338814d0a3dfcba0d57b1de242f610e9"
EXPECTED_BROKER_SHA256 = "a5a2ee64e734563470ea35ec9c7686b9fc77b895cbe4f417735ffc1e2a057878"
NODE_SOURCE = Path("/Users/vincentnijjar/.local/node-versions/node-v22.22.1-darwin-arm64/bin/node")
CLANG = Path("/usr/bin/clang")
GIT = Path("/usr/bin/git")
LAUNCHCTL = Path("/bin/launchctl")
DSCL = Path("/usr/bin/dscl")
IOREG = Path("/usr/sbin/ioreg")

REPOSITORY_ROOT = Path(__file__).absolute().parents[2]
PRODUCT_ROOT = REPOSITORY_ROOT / "demos/zlar-destination-gate"
PRODUCT_MANIFEST = PRODUCT_ROOT / "PRODUCT-MANIFEST.json"

BROKER = Path("/usr/local/libexec/zlar-demo1-destination")
RUNTIME_ROOT = Path("/usr/local/libexec/zlar-demo1")
NODE_TARGET = RUNTIME_ROOT / "node"
CLIENT = Path("/usr/local/bin/zlar-demo1")
AUTHORIZE = Path("/usr/local/bin/zlar-demo1-authorize")
POLICY = Path("/etc/zlar/demo1-authority-roots.json")
C_PUBLIC = Path("/etc/zlar/demo1-founder-authority-root-c-v1.pub.pem")
ISSUER_PRIVATE = Path("/etc/zlar/demo1-issuer-key.pem")
ISSUER_PUBLIC = Path("/etc/zlar/demo1-issuer-public.pem")
DESTINATION_PRIVATE = Path("/etc/zlar/demo1-destination-key.pem")
DESTINATION_PUBLIC = Path("/etc/zlar/demo1-destination-public.pem")
INSTALLATION_MANIFEST = Path("/etc/zlar/demo1-installation-manifest.json")
STATE_ROOT = Path("/var/db/zlar-demo1")
DATABASE = STATE_ROOT / "state.sqlite"
STAGING_ROOT = Path("/var/tmp/zlar-demo1-staging")
AUTHORITY_TRANSFER_ROOT = Path("/var/tmp/zlar-demo1-authority")
SOCKET = Path("/var/run/zlar-demo1.sock")
PLIST = Path("/Library/LaunchDaemons/ai.zlar.demo1-destination.plist")
LAUNCHD_LABEL = "ai.zlar.demo1-destination"
SOCKET_NAME = "Demo1DestinationSocket"

DOMAINS = {
    "challenge": "ZLAR-DEMO1-CHALLENGE-N-V1",
    "action": "ZLAR-DEMO1-ACTION-V1",
    "grant": "ZLAR-DEMO1-GRANT-G-V1",
    "credential": "ZLAR-DEMO1-BOARDING-A-V1",
    "commit": "ZLAR-DEMO1-PROMOTION-COMMIT-V1",
    "receipt": "ZLAR-DEMO1-RECEIPT-V1",
    "policy": "ZLAR-DEMO1-RECOGNITION-POLICY-V1",
}

MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}

SOURCE_TO_INSTALLED = {
    REPOSITORY_ROOT / "cyan/demo1-protocol.mjs": RUNTIME_ROOT / "cyan/demo1-protocol.mjs",
    REPOSITORY_ROOT / "cyan/demo1-store.mjs": RUNTIME_ROOT / "cyan/demo1-store.mjs",
    REPOSITORY_ROOT / "cyan/demo1-destination.mjs": RUNTIME_ROOT / "cyan/demo1-destination.mjs",
    PRODUCT_ROOT / "demo1-installed-profile.mjs": RUNTIME_ROOT / "demos/zlar-destination-gate/demo1-installed-profile.mjs",
    PRODUCT_ROOT / "demo1-installed-handler.mjs": RUNTIME_ROOT / "demos/zlar-destination-gate/demo1-installed-handler.mjs",
    PRODUCT_ROOT / "demo1-installed-service.mjs": RUNTIME_ROOT / "demos/zlar-destination-gate/demo1-installed-service.mjs",
    PRODUCT_ROOT / "demo1-peer-broker.c": RUNTIME_ROOT / "demos/zlar-destination-gate/demo1-peer-broker.c",
    PRODUCT_ROOT / "demo1.mjs": RUNTIME_ROOT / "demos/zlar-destination-gate/demo1.mjs",
}

LIVE_TARGETS = [
    BROKER, RUNTIME_ROOT, CLIENT, AUTHORIZE, POLICY, C_PUBLIC,
    ISSUER_PRIVATE, ISSUER_PUBLIC, DESTINATION_PRIVATE, DESTINATION_PUBLIC,
    INSTALLATION_MANIFEST, STATE_ROOT, STAGING_ROOT, AUTHORITY_TRANSFER_ROOT, SOCKET, PLIST,
]


class InstallRefusal(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def run(command: list[str], *, capture: bool = True, check: bool = True, env: dict[str, str] | None = None, preexec_fn=None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
        preexec_fn=preexec_fn,
    )


def drop_to_human() -> None:
    os.setgroups(os.getgrouplist(HUMAN_USER, HUMAN_GID))
    os.setgid(HUMAN_GID)
    os.setuid(HUMAN_UID)
    os.umask(0o077)


def run_unprivileged(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(
        command,
        check=check,
        env=MINIMAL_ENV,
        preexec_fn=drop_to_human if os.geteuid() == 0 else None,
    )


def read_source_bytes(path: Path, expected_digest: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise InstallRefusal(f"source_file_refused:{path}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if sha256_bytes(raw) != expected_digest:
        raise InstallRefusal(f"source_file_digest_mismatch:{path}")
    return raw


def verify_system_tool(path: Path, expected_digest: str) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or sha256(path) != expected_digest
    ):
        raise InstallRefusal(f"system_tool_identity:{path}")


def identity_absent(kind: str, name: str) -> bool:
    result = run([str(DSCL), ".", "-read", f"/{kind}/{name}"], check=False)
    return result.returncode != 0


def verify_source(expected_commit: str, expected_manifest_sha256: str) -> dict[str, Any]:
    if not (len(expected_commit) == 40 and all(character in "0123456789abcdef" for character in expected_commit)):
        raise InstallRefusal("expected_commit_invalid")
    if not (len(expected_manifest_sha256) == 64 and all(character in "0123456789abcdef" for character in expected_manifest_sha256)):
        raise InstallRefusal("expected_manifest_sha256_invalid")
    head = run_unprivileged([str(GIT), "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"]).stdout.strip()
    if head != expected_commit:
        raise InstallRefusal("source_commit_mismatch")
    if run_unprivileged([str(GIT), "-C", str(REPOSITORY_ROOT), "status", "--porcelain=v1"]).stdout:
        raise InstallRefusal("source_worktree_not_clean")
    manifest_raw = read_source_bytes(PRODUCT_MANIFEST, expected_manifest_sha256)
    verification = run_unprivileged([sys.executable, "-B", str(PRODUCT_ROOT / "product_identity.py"), "--verify"])
    if "VERIFIED_READ_ONLY" not in verification.stdout:
        raise InstallRefusal("source_manifest_verification_failed")
    manifest = json.loads(manifest_raw)
    records = manifest.get("files")
    if not isinstance(records, list) or manifest.get("schema_version") != "zlar.demo1.source-manifest.v1":
        raise InstallRefusal("source_manifest_schema")
    manifest_files: dict[str, str] = {}
    for row in records:
        if not isinstance(row, dict) or set(row) != {"byte_length", "path", "sha256"}:
            raise InstallRefusal("source_manifest_file_shape")
        relative = row["path"]
        digest = row["sha256"]
        if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
            raise InstallRefusal("source_manifest_file_path")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or relative in manifest_files
        ):
            raise InstallRefusal("source_manifest_file_digest")
        manifest_files[relative] = digest
    read_source_bytes(NODE_SOURCE, EXPECTED_NODE_SHA256)
    verify_system_tool(CLANG, EXPECTED_CLANG_SHA256)
    run_unprivileged(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(NODE_SOURCE)])
    run_unprivileged(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(CLANG)])
    return {
        "source_commit": head,
        "source_manifest_sha256": expected_manifest_sha256,
        "node_sha256": EXPECTED_NODE_SHA256,
        "clang_sha256": EXPECTED_CLANG_SHA256,
        "broker_sha256": EXPECTED_BROKER_SHA256,
        "manifest_files": manifest_files,
    }


def verify_preconditions() -> None:
    try:
        client = pwd.getpwnam(CLIENT_USER)
    except KeyError as error:
        raise InstallRefusal("client_user_missing") from error
    if (
        CLIENT_USER != HUMAN_USER
        or CLIENT_UID != HUMAN_UID
        or client.pw_uid != CLIENT_UID
        or client.pw_gid != HUMAN_GID
    ):
        raise InstallRefusal("actual_client_identity_mismatch")
    admin = grp.getgrnam(SOCKET_GROUP)
    if admin.gr_gid != SOCKET_GROUP_GID or set(admin.gr_mem) != {"root", CLIENT_USER}:
        raise InstallRefusal("socket_group_membership_mismatch")
    protected_parents = {
        Path("/etc/zlar"): (0, 0, 0o755),
        Path("/usr/local"): (0, 0, 0o755),
        Path("/usr/local/bin"): (0, 0, 0o755),
        Path("/var/db"): (0, 0, 0o755),
        Path("/var/tmp"): (0, 0, 0o1777),
        Path("/var/run"): (0, 1, 0o775),
        Path("/Library/LaunchDaemons"): (0, 0, 0o755),
    }
    for path, (uid, gid, mode) in protected_parents.items():
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise InstallRefusal(f"protected_parent_identity:{path}")
    optional_libexec = Path("/usr/local/libexec")
    if optional_libexec.exists() or optional_libexec.is_symlink():
        metadata = optional_libexec.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or optional_libexec.is_symlink()
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o755
        ):
            raise InstallRefusal("protected_parent_identity:/usr/local/libexec")
    if not identity_absent("Users", SERVICE_USER) or not identity_absent("Groups", SERVICE_GROUP):
        raise InstallRefusal("service_identity_exists")
    for entry in pwd.getpwall():
        if entry.pw_uid == SERVICE_UID:
            raise InstallRefusal("service_uid_collision")
    for entry in grp.getgrall():
        if entry.gr_gid == SERVICE_GID:
            raise InstallRefusal("service_gid_collision")
    for path in LIVE_TARGETS:
        if path.exists() or path.is_symlink():
            raise InstallRefusal(f"target_exists:{path}")
    usb_tree = run_unprivileged([str(IOREG), "-r", "-c", "IOUSBHostDevice", "-l"]).stdout
    if '"idVendor" = 4176' in usb_tree:
        raise InstallRefusal("yubikey_connected_during_install")
    launch = run([str(LAUNCHCTL), "print", f"system/{LAUNCHD_LABEL}"], check=False)
    if launch.returncode == 0:
        raise InstallRefusal("launchd_label_exists")


def make_group(name: str, gid: int, members: list[str] | None = None) -> None:
    run([str(DSCL), ".", "-create", f"/Groups/{name}"])
    run([str(DSCL), ".", "-create", f"/Groups/{name}", "PrimaryGroupID", str(gid)])
    run([str(DSCL), ".", "-create", f"/Groups/{name}", "RealName", name])
    if members:
        run([str(DSCL), ".", "-create", f"/Groups/{name}", "GroupMembership", *members])


def make_service_user() -> None:
    run([str(DSCL), ".", "-create", f"/Users/{SERVICE_USER}"])
    for key, value in [
        ("UniqueID", str(SERVICE_UID)),
        ("PrimaryGroupID", str(SERVICE_GID)),
        ("NFSHomeDirectory", "/var/empty"),
        ("UserShell", "/usr/bin/false"),
        ("RealName", "ZLAR Demo 1 Destination"),
        ("IsHidden", "1"),
        ("Password", "*"),
    ]:
        run([str(DSCL), ".", "-create", f"/Users/{SERVICE_USER}", key, value])


def mkdir_exact(path: Path, uid: int, gid: int, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=False)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def copy_exact(source: Path, target: Path, uid: int, gid: int, mode: int, expected_digest: str) -> None:
    raw = read_source_bytes(source, expected_digest)
    missing: list[Path] = []
    parent = target.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        os.chown(directory, 0, 0)
        os.chmod(directory, 0o755)
    write_exact(target, raw, uid, gid, mode)
    if sha256(target) != expected_digest:
        raise InstallRefusal(f"installed_file_digest_mismatch:{target}")


def write_exact(path: Path, raw: bytes, uid: int, gid: int, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


KEYGEN_SCRIPT = """
import { generateKeyPairSync } from 'node:crypto';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' });
const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' });
const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' });
process.stdout.write(JSON.stringify({
  private_key_pem: privateKeyPem,
  public_key_pem: publicKeyPem,
  public_key_spki_der_b64: publicKeyDer.toString('base64'),
}));
"""


def generate_keypair() -> dict[str, str]:
    result = run(
        [str(NODE_TARGET), "--disable-proto=throw", "--input-type=module", "--eval", KEYGEN_SCRIPT],
        env=MINIMAL_ENV,
        preexec_fn=drop_to_service,
    )
    material = json.loads(result.stdout)
    if set(material) != {"private_key_pem", "public_key_pem", "public_key_spki_der_b64"}:
        raise InstallRefusal("generated_key_shape")
    private_pem = material["private_key_pem"]
    public_pem = material["public_key_pem"]
    if not isinstance(private_pem, str) or not private_pem.startswith("-----BEGIN PRIVATE KEY-----\n"):
        raise InstallRefusal("generated_private_key_shape")
    if not isinstance(public_pem, str) or not public_pem.startswith("-----BEGIN PUBLIC KEY-----\n"):
        raise InstallRefusal("generated_public_key_shape")
    try:
        public_der = base64.b64decode(material["public_key_spki_der_b64"], validate=True)
    except (ValueError, TypeError) as error:
        raise InstallRefusal("generated_public_key_der") from error
    if len(public_der) != 44:
        raise InstallRefusal("generated_public_key_der_length")
    material["key_id"] = "spki-sha256:" + hashlib.sha256(public_der).hexdigest()
    return material


def registry_entry(public_key_pem: str, key_id: str, role: str) -> dict[str, str]:
    return {
        "key_id": key_id,
        "public_key_pem": public_key_pem,
        "role": role,
        "status": "active",
    }


def generate_keys_and_policy() -> str:
    issuer = generate_keypair()
    destination = generate_keypair()
    write_exact(ISSUER_PRIVATE, issuer["private_key_pem"].encode(), 0, SERVICE_GID, 0o440)
    write_exact(ISSUER_PUBLIC, issuer["public_key_pem"].encode(), 0, 0, 0o444)
    write_exact(DESTINATION_PRIVATE, destination["private_key_pem"].encode(), 0, SERVICE_GID, 0o440)
    write_exact(DESTINATION_PUBLIC, destination["public_key_pem"].encode(), 0, 0, 0o444)
    c_entry = registry_entry(C_PUBLIC.read_text(encoding="utf-8"), C_KEY_ID, "grant_root")
    policy = {
        "v": 1,
        "type": "recognition_policy",
        "profile_id": PROFILE_ID,
        "destination_id": DESTINATION_ID,
        "algorithm": "Ed25519",
        "roots": [c_entry],
        "issuers": [registry_entry(issuer["public_key_pem"], issuer["key_id"], "boarding_issuer")],
        "destination": registry_entry(destination["public_key_pem"], destination["key_id"], "destination_signer"),
        "domains": DOMAINS,
    }
    write_exact(POLICY, canonical(policy), 0, 0, 0o444)
    return "sha256:" + hashlib.sha256(DOMAINS["policy"].encode() + b"\0" + canonical(policy)).hexdigest()


def launchd_plist() -> bytes:
    payload = {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": [str(BROKER)],
        "UserName": SERVICE_USER,
        "GroupName": SERVICE_GROUP,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 2,
        "Umask": 0o077,
        "Sockets": {
            SOCKET_NAME: {
                "SockPathName": str(SOCKET),
                "SockPathOwner": 0,
                "SockPathGroup": SOCKET_GROUP_GID,
                "SockPathMode": 0o660,
            },
        },
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True)


def drop_to_service() -> None:
    os.setgroups([SERVICE_GID])
    os.setgid(SERVICE_GID)
    os.setuid(SERVICE_UID)
    os.umask(0o077)


def install(expected_commit: str, expected_manifest_sha256: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InstallRefusal("root_required")
    source = verify_source(expected_commit, expected_manifest_sha256)
    verify_preconditions()
    old_umask = os.umask(0o077)
    try:
        make_group(SERVICE_GROUP, SERVICE_GID)
        make_service_user()

        for parent in [Path("/usr/local/libexec"), Path("/usr/local/bin")]:
            if not parent.exists():
                parent.mkdir(parents=True, mode=0o755)
                os.chown(parent, 0, 0)
                os.chmod(parent, 0o755)
        RUNTIME_ROOT.mkdir(mode=0o755)
        os.chown(RUNTIME_ROOT, 0, 0)
        os.chmod(RUNTIME_ROOT, 0o755)
        copy_exact(NODE_SOURCE, NODE_TARGET, 0, 0, 0o555, EXPECTED_NODE_SHA256)
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(NODE_TARGET)])
        for source_path, target_path in SOURCE_TO_INSTALLED.items():
            relative = source_path.relative_to(REPOSITORY_ROOT).as_posix()
            expected_digest = source["manifest_files"].get(relative)
            if expected_digest is None:
                raise InstallRefusal(f"source_not_in_manifest:{relative}")
            copy_exact(source_path, target_path, 0, 0, 0o444, expected_digest)

        broker_source = SOURCE_TO_INSTALLED[PRODUCT_ROOT / "demo1-peer-broker.c"]
        run([
            str(CLANG), "-std=c17", "-Wall", "-Wextra", "-Werror", "-O2",
            str(broker_source), "-o", str(BROKER),
        ], env=MINIMAL_ENV)
        os.chown(BROKER, 0, 0)
        os.chmod(BROKER, 0o555)
        if sha256(BROKER) != EXPECTED_BROKER_SHA256:
            raise InstallRefusal("compiled_broker_digest_mismatch")

        client_wrapper = (
            "#!/bin/sh\n"
            "exec /usr/local/libexec/zlar-demo1/node --disable-proto=throw "
            "/usr/local/libexec/zlar-demo1/demos/zlar-destination-gate/demo1.mjs \"$@\"\n"
        ).encode()
        write_exact(CLIENT, client_wrapper, 0, 0, 0o555)
        authorize_source = PRODUCT_ROOT / "demo1-authorize.py"
        authorize_digest = source["manifest_files"].get(authorize_source.relative_to(REPOSITORY_ROOT).as_posix())
        c_source = PRODUCT_ROOT / "founder-authority-root-c-v1.pub.pem"
        c_digest = source["manifest_files"].get(c_source.relative_to(REPOSITORY_ROOT).as_posix())
        if authorize_digest is None or c_digest is None:
            raise InstallRefusal("ceremony_source_not_in_manifest")
        copy_exact(authorize_source, AUTHORIZE, 0, 80, 0o550, authorize_digest)
        copy_exact(c_source, C_PUBLIC, 0, 0, 0o444, c_digest)
        if sha256(C_PUBLIC) != "4260a266c255059b041b8af5805b89fdaa5dfb5c40a291a146842deda2b09890":
            raise InstallRefusal("c_public_pem_digest")

        mkdir_exact(STATE_ROOT, SERVICE_UID, SERVICE_GID, 0o700)
        mkdir_exact(STAGING_ROOT, CLIENT_UID, SERVICE_GID, 0o2750)
        mkdir_exact(AUTHORITY_TRANSFER_ROOT, HUMAN_UID, HUMAN_GID, 0o700)
        policy_digest = generate_keys_and_policy()
        write_exact(PLIST, launchd_plist(), 0, 0, 0o644)

        hashed_files = [
            BROKER, NODE_TARGET, CLIENT, POLICY, C_PUBLIC,
            ISSUER_PUBLIC, DESTINATION_PUBLIC, PLIST, *SOURCE_TO_INSTALLED.values(),
        ]
        installed_file_sha256 = {str(path): sha256(path) for path in sorted(hashed_files, key=lambda item: str(item).encode())}
        manifest = {
            "v": 1,
            "type": "zlar.demo1.installation_manifest",
            "profile_id": PROFILE_ID,
            "client_uid": CLIENT_UID,
            "socket_group_gid": SOCKET_GROUP_GID,
            "service_uid": SERVICE_UID,
            "service_gid": SERVICE_GID,
            "authority_transfer_uid": HUMAN_UID,
            "authority_transfer_gid": HUMAN_GID,
            "authority_transfer_mode": 0o700,
            "source_commit": source["source_commit"],
            "source_manifest_sha256": source["source_manifest_sha256"],
            "node_sha256": source["node_sha256"],
            "clang_sha256": source["clang_sha256"],
            "broker_sha256": source["broker_sha256"],
            "recognition_policy_sha256": policy_digest,
            "installed_file_sha256": installed_file_sha256,
            "ceremony_tool_sha256": sha256(AUTHORIZE),
        }
        write_exact(INSTALLATION_MANIFEST, canonical(manifest), 0, 0, 0o444)

        service_environment = {**MINIMAL_ENV, "TMPDIR": str(STATE_ROOT)}
        initialize = run(
            [str(NODE_TARGET), "--disable-proto=throw", str(SOURCE_TO_INSTALLED[PRODUCT_ROOT / "demo1-installed-service.mjs"]), "--initialize"],
            env=service_environment,
            preexec_fn=drop_to_service,
        )
        initialized = json.loads(initialize.stdout)
        if initialized.get("status") != "INITIALIZED" or initialized.get("recognition_policy_sha256") != policy_digest:
            raise InstallRefusal("destination_initialization_failed")
        os.chown(DATABASE, SERVICE_UID, SERVICE_GID)
        os.chmod(DATABASE, 0o600)
        for suffix in ["-wal", "-shm"]:
            sidecar = Path(str(DATABASE) + suffix)
            if sidecar.exists():
                os.chown(sidecar, SERVICE_UID, SERVICE_GID)
                os.chmod(sidecar, 0o600)

        run([str(LAUNCHCTL), "bootstrap", "system", str(PLIST)])
        run([str(LAUNCHCTL), "print", f"system/{LAUNCHD_LABEL}"])
        return {
            "v": 1,
            "status": "INSTALLED_NOT_DEMO_PASSED",
            "source_commit": source["source_commit"],
            "source_manifest_sha256": source["source_manifest_sha256"],
            "recognition_policy_sha256": policy_digest,
            "node_sha256": source["node_sha256"],
            "client_uid": CLIENT_UID,
            "service_uid": SERVICE_UID,
            "socket": str(SOCKET),
            "claim_ceiling": "installed_bytes_and_service_only_no_c_backed_effect_or_demo_pass",
        }
    finally:
        os.umask(old_umask)


def plan(expected_commit: str, expected_manifest_sha256: str) -> dict[str, Any]:
    source = verify_source(expected_commit, expected_manifest_sha256)
    verify_preconditions()
    return {
        "v": 1,
        "status": "PLAN_VERIFIED_NO_CHANGES",
        "source_commit": source["source_commit"],
        "source_manifest_sha256": source["source_manifest_sha256"],
        "node_sha256": source["node_sha256"],
        "clang_sha256": source["clang_sha256"],
        "broker_sha256": source["broker_sha256"],
        "client": {"name": CLIENT_USER, "uid": CLIENT_UID},
        "service": {"name": SERVICE_USER, "uid": SERVICE_UID, "gid": SERVICE_GID},
        "socket_group": {"name": SOCKET_GROUP, "gid": SOCKET_GROUP_GID},
        "live_targets": [str(path) for path in LIVE_TARGETS],
        "claim_ceiling": "read_only_installation_plan_only",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Demo 1 protected destination installer")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--install", action="store_true")
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        result = install(args.expected_commit, args.expected_manifest_sha256) if args.install else plan(args.expected_commit, args.expected_manifest_sha256)
        print(canonical(result).decode())
        return 0
    except (InstallRefusal, OSError, subprocess.SubprocessError, KeyError, ValueError) as error:
        print(canonical({"v": 1, "status": "REFUSED", "reason": str(error)}).decode(), file=sys.stderr)
        return 42


if __name__ == "__main__":
    raise SystemExit(main())
