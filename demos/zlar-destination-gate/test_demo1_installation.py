#!/usr/bin/env python3
"""Authority-effect-none tests for the installed Demo 1 source profile."""

from __future__ import annotations

import ast
import ctypes
import hashlib
import importlib.util
import json
import os
import plistlib
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).absolute().parent


def load(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise AssertionError(f"cannot_import:{path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


installer = load("demo1_install", HERE / "demo1-install.py")
authorize = load("demo1_authorize", HERE / "demo1-authorize.py")

for path in [HERE / "demo1-install.py", HERE / "demo1-authorize.py"]:
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

assert installer.CLIENT_USER == "vincentnijjar"
assert installer.CLIENT_UID == 501
assert installer.SERVICE_UID == 450
assert installer.SERVICE_GID == 450
assert authorize.HUMAN_UID == 501
assert authorize.CLIENT_PRINCIPAL_ID == "macos-euid:501"
assert authorize.SIGNED_GRANT_PATH == Path("/var/tmp/zlar-demo1-authority/grant-g.json")
assert authorize.CHALLENGE_PATH == Path("/var/tmp/zlar-demo1-authority/challenge-n.json")
assert authorize.C_ROOT_KEY_ID == "spki-sha256:eb746072b61c1f21225e6504accf55ec99d5ba73f3117c80e0d092c1436ab07c"

installer.verify_preconditions()
installer.verify_system_tool(installer.CLANG, installer.EXPECTED_CLANG_SHA256)

plist = plistlib.loads(installer.launchd_plist())
assert plist["Label"] == "ai.zlar.demo1-destination"
assert plist["UserName"] == "_zlar_demo1"
assert plist["GroupName"] == "_zlar_demo1"
assert plist["ProgramArguments"] == ["/usr/local/libexec/zlar-demo1-destination"]
listener = plist["Sockets"]["Demo1DestinationSocket"]
assert listener == {
    "SockPathGroup": 80,
    "SockPathMode": 0o660,
    "SockPathName": "/var/run/zlar-demo1.sock",
    "SockPathOwner": 0,
}

c_public = HERE / "founder-authority-root-c-v1.pub.pem"
assert hashlib.sha256(c_public.read_bytes()).hexdigest() == authorize.C_PUBLIC_SHA256
with tempfile.TemporaryDirectory(prefix="zlar-demo1-install-test-") as directory:
    temporary = Path(directory)
    assert authorize.public_key_id(c_public, temporary) == authorize.C_ROOT_KEY_ID

    source = temporary / "source.bin"
    target = temporary / "target.bin"
    source.write_bytes(b"frozen-source-bytes")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    installer.copy_exact(source, target, os.geteuid(), os.getegid(), 0o400, digest)
    assert target.read_bytes() == b"frozen-source-bytes"
    assert target.stat().st_mode & 0o777 == 0o400

    fixed_challenge = {
        "body": {
            "v": 1,
            "type": "challenge",
            "profile_id": authorize.PROFILE_ID,
            "destination_id": authorize.DESTINATION_ID,
            "principal_id": authorize.CLIENT_PRINCIPAL_ID,
            "challenge_nonce": "A" * 43,
            "staged_object_id": authorize.STAGED_OBJECT_ID,
            "artifact_sha256": "sha256:" + "1" * 64,
            "from_generation": 0,
            "to_generation": 1,
            "issued_at": 1000,
            "expires_at": 1300,
        },
        "signature": "A" * 86,
    }
    fixed_policy = {"issuers": [{"key_id": "spki-sha256:" + "2" * 64}]}
    original_time = authorize.time.time
    original_token_bytes = authorize.secrets.token_bytes
    try:
        authorize.time.time = lambda: 1001
        authorize.secrets.token_bytes = lambda count: b"\0" * count
        grant = authorize.construct_grant(fixed_challenge, fixed_policy)
    finally:
        authorize.time.time = original_time
        authorize.secrets.token_bytes = original_token_bytes
    node_validation = subprocess.run(
        [
            "/Users/vincentnijjar/.local/node-versions/node-v22.22.1-darwin-arm64/bin/node",
            "--input-type=module",
            "--eval",
            (
                "import fs from 'node:fs';"
                "import {canonicalBytes,validateBody} from './cyan/demo1-protocol.mjs';"
                "const grant=JSON.parse(fs.readFileSync(0,'utf8'));"
                "validateBody('grant',grant);process.stdout.write(canonicalBytes(grant));"
            ),
        ],
        cwd=HERE.parents[1],
        input=authorize.canonical(grant),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert node_validation.returncode == 0, node_validation.stderr.decode()
    assert node_validation.stdout == authorize.canonical(grant)

    keygen_result = subprocess.run(
        [str(installer.NODE_SOURCE), "--disable-proto=throw", "--input-type=module", "--eval", installer.KEYGEN_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=installer.MINIMAL_ENV,
    )
    assert keygen_result.returncode == 0, keygen_result.stderr.decode()
    key_material = json.loads(keygen_result.stdout)
    assert set(key_material) == {"private_key_pem", "public_key_pem", "public_key_spki_der_b64"}
    assert key_material["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----\n")
    assert key_material["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----\n")

    broker = temporary / "zlar-demo1-destination"
    compile_result = subprocess.run(
        [
            "/usr/bin/clang", "-std=c17", "-Wall", "-Wextra", "-Werror", "-O2",
            str(HERE / "demo1-peer-broker.c"), "-o", str(broker),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=installer.MINIMAL_ENV,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    assert hashlib.sha256(broker.read_bytes()).hexdigest() == installer.EXPECTED_BROKER_SHA256
    assert subprocess.run([str(broker)], check=False).returncode == 78
    symbols = subprocess.run(["/usr/bin/nm", "-u", str(broker)], check=True, text=True, stdout=subprocess.PIPE).stdout
    assert "_getpeereid" in symbols
    assert "_launch_activate_socket" in symbols

left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    libc = ctypes.CDLL(None, use_errno=True)
    peer_uid = ctypes.c_uint()
    peer_gid = ctypes.c_uint()
    result = libc.getpeereid(left.fileno(), ctypes.byref(peer_uid), ctypes.byref(peer_gid))
    assert result == 0, ctypes.get_errno()
    assert peer_uid.value == os.geteuid()
    assert peer_gid.value == os.getegid()
finally:
    left.close()
    right.close()

broker_source = (HERE / "demo1-peer-broker.c").read_text(encoding="utf-8")
for required in [
    "launch_activate_socket", "getpeereid", "peer_uid != CLIENT_UID",
    "MAX_FRAME", "posix_spawn", "SERVICE_PATH", "NODE_PATH",
]:
    assert required in broker_source, required
for forbidden in ["127.0.0.1", "AF_INET", "system(", "popen(", "getenv("]:
    assert forbidden not in broker_source, forbidden

authorize_source = (HERE / "demo1-authorize.py").read_text(encoding="utf-8")
assert authorize_source.startswith("#!/usr/bin/python3\n")
assert '"--login", "--sign"' in authorize_source
assert '"--id", "02"' in authorize_source
assert '"--mechanism", "EDDSA"' in authorize_source
for forbidden in ["--pin", "PIN=", "PUK", "PRIVATE KEY-----"]:
    assert forbidden not in authorize_source, forbidden
for tool, (expected_digest, expected_mode) in authorize.TRUSTED_TOOL_FILES.items():
    metadata = tool.lstat()
    assert not tool.is_symlink()
    assert metadata.st_uid == 501 and metadata.st_gid == 80
    assert metadata.st_mode & 0o777 == expected_mode
    assert hashlib.sha256(tool.read_bytes()).hexdigest() == expected_digest

install_source = (HERE / "demo1-install.py").read_text(encoding="utf-8")
for required in [
    "--expected-commit", "--expected-manifest-sha256", "root_required", "--initialize",
    "source_file_digest_mismatch", "socket_group_membership_mismatch",
]:
    assert required in install_source, required
for forbidden in ["brew install", "pip install", "sudo ", "YubiKey D"]:
    assert forbidden not in install_source, forbidden

print("PASS demo1 installation source: exact source copy, collision-free plan, launchd socket, native peer credentials, Python-JS G, private C ceremony")
