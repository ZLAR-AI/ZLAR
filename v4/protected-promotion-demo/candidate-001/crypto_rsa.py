#!/usr/bin/env python3
"""Standard-library 2048-bit RSA for disposable local proof evidence only."""

from __future__ import annotations

import base64
import hashlib
import math
import secrets
from dataclasses import dataclass

from canonical import canonical_bytes, sha256_bytes


RSA_BITS = 2048
PUBLIC_EXPONENT = 65537
MILLER_RABIN_ROUNDS = 24
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class CryptoError(ValueError):
    pass


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int


def _is_probable_prime(candidate: int) -> bool:
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    if candidate in small:
        return True
    if candidate < 2 or candidate % 2 == 0:
        return False
    for prime in small[1:]:
        if candidate % prime == 0:
            return False
    remainder = candidate - 1
    exponent_of_two = 0
    while remainder % 2 == 0:
        exponent_of_two += 1
        remainder //= 2
    for _ in range(MILLER_RABIN_ROUNDS):
        base = secrets.randbelow(candidate - 3) + 2
        value = pow(base, remainder, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(exponent_of_two - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if math.gcd(candidate - 1, PUBLIC_EXPONENT) == 1 and _is_probable_prime(candidate):
            return candidate


def generate_key(max_attempts: int = 32) -> tuple[PrivateKey, dict[str, object]]:
    observed_bits: list[int] = []
    for attempt in range(1, max_attempts + 1):
        p = _prime(RSA_BITS // 2)
        q = _prime(RSA_BITS // 2)
        while p == q:
            q = _prime(RSA_BITS // 2)
        modulus = p * q
        observed_bits.append(modulus.bit_length())
        if modulus.bit_length() != RSA_BITS:
            continue
        totient = (p - 1) * (q - 1)
        key = PrivateKey(modulus, PUBLIC_EXPONENT, pow(PUBLIC_EXPONENT, -1, totient))
        return key, {
            "actual_modulus_bits": RSA_BITS,
            "attempt_count": attempt,
            "observed_modulus_bits": observed_bits,
            "requested_modulus_bits": RSA_BITS,
        }
    raise CryptoError("rsa_generation_attempt_limit")


def public_evidence(key: PrivateKey) -> dict[str, object]:
    if key.n.bit_length() != RSA_BITS or key.e != PUBLIC_EXPONENT:
        raise CryptoError("rsa_key_profile")
    core: dict[str, object] = {
        "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "e_decimal": key.e,
        "kty": "RSA",
        "n_hex": format(key.n, "0512x"),
        "requested_modulus_bits": RSA_BITS,
    }
    return {
        **core,
        "actual_modulus_bits": key.n.bit_length(),
        "public_key_id": "rsa-sha256:" + sha256_bytes(canonical_bytes(core)),
    }


def parse_public(value: object) -> tuple[int, int, str]:
    required = {
        "actual_modulus_bits",
        "algorithm",
        "e_decimal",
        "kty",
        "n_hex",
        "public_key_id",
        "requested_modulus_bits",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise CryptoError("public_key_field_set")
    modulus_hex = value["n_hex"]
    if (
        not isinstance(modulus_hex, str)
        or len(modulus_hex) != 512
        or modulus_hex != modulus_hex.lower()
        or any(character not in "0123456789abcdef" for character in modulus_hex)
    ):
        raise CryptoError("public_key_encoding")
    modulus = int(modulus_hex, 16)
    exponent = value["e_decimal"]
    if (
        not isinstance(exponent, int)
        or isinstance(exponent, bool)
        or exponent != PUBLIC_EXPONENT
        or modulus.bit_length() != RSA_BITS
        or value["actual_modulus_bits"] != RSA_BITS
        or value["requested_modulus_bits"] != RSA_BITS
        or value["algorithm"] != "RSASSA-PKCS1-v1_5-SHA256"
        or value["kty"] != "RSA"
    ):
        raise CryptoError("public_key_profile")
    core = {
        "algorithm": value["algorithm"],
        "e_decimal": exponent,
        "kty": value["kty"],
        "n_hex": modulus_hex,
        "requested_modulus_bits": value["requested_modulus_bits"],
    }
    key_id = "rsa-sha256:" + sha256_bytes(canonical_bytes(core))
    if value["public_key_id"] != key_id:
        raise CryptoError("public_key_identity")
    return modulus, exponent, key_id


def _encoded_message(message: bytes, modulus_bytes: int) -> bytes:
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = modulus_bytes - len(digest_info) - 3
    if padding_length < 8:
        raise CryptoError("rsa_modulus_too_short")
    return b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info


def sign(key: PrivateKey, message: bytes) -> str:
    modulus_bytes = (key.n.bit_length() + 7) // 8
    encoded = _encoded_message(message, modulus_bytes)
    signature = pow(int.from_bytes(encoded, "big"), key.d, key.n).to_bytes(modulus_bytes, "big")
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def verify(public: object, message: bytes, signature_text: object) -> bool:
    try:
        modulus, exponent, _ = parse_public(public)
        if not isinstance(signature_text, str) or not signature_text:
            return False
        padding = "=" * ((4 - len(signature_text) % 4) % 4)
        signature = base64.urlsafe_b64decode((signature_text + padding).encode("ascii"))
        modulus_bytes = (modulus.bit_length() + 7) // 8
        if len(signature) != modulus_bytes:
            return False
        recovered = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(modulus_bytes, "big")
        return secrets.compare_digest(recovered, _encoded_message(message, modulus_bytes))
    except (CryptoError, ValueError, TypeError, UnicodeError):
        return False
