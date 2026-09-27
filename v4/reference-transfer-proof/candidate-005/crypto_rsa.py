#!/usr/bin/env python3
"""Small standard-library RSA implementation for the bounded local proof."""

from __future__ import annotations

import base64
import hashlib
import math
import secrets
from dataclasses import dataclass
from typing import Callable

from canonical import canonical_bytes, sha256_bytes


REQUESTED_RSA_BITS = 2048
PUBLIC_EXPONENT = 65537
DEFAULT_KEY_ATTEMPT_LIMIT = 32
MILLER_RABIN_ROUNDS = 24
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class KeyGenerationError(RuntimeError):
    pass


class PublicKeyError(ValueError):
    pass


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int

    @property
    def actual_bits(self) -> int:
        return self.n.bit_length()


def _is_probable_prime(candidate: int, rounds: int = MILLER_RABIN_ROUNDS) -> bool:
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    if candidate in small_primes:
        return True
    if candidate < 2 or candidate % 2 == 0:
        return False
    for prime in small_primes[1:]:
        if candidate % prime == 0:
            return False
    d = candidate - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        value = pow(base, d, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    if bits < 256:
        raise KeyGenerationError("prime_size_below_bounded_profile")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if math.gcd(candidate - 1, PUBLIC_EXPONENT) != 1:
            continue
        if _is_probable_prime(candidate):
            return candidate


def _fresh_candidate(requested_bits: int) -> PrivateKey:
    prime_bits = requested_bits // 2
    p = _generate_prime(prime_bits)
    q = _generate_prime(prime_bits)
    while q == p:
        q = _generate_prime(prime_bits)
    modulus = p * q
    totient = (p - 1) * (q - 1)
    private_exponent = pow(PUBLIC_EXPONENT, -1, totient)
    return PrivateKey(n=modulus, e=PUBLIC_EXPONENT, d=private_exponent)


def generate_rsa_key(
    requested_bits: int = REQUESTED_RSA_BITS,
    max_attempts: int = DEFAULT_KEY_ATTEMPT_LIMIT,
    candidate_factory: Callable[[], PrivateKey] | None = None,
) -> tuple[PrivateKey, int, list[int]]:
    if requested_bits != REQUESTED_RSA_BITS:
        raise KeyGenerationError("requested_rsa_bits_must_equal_2048")
    if max_attempts < 1 or max_attempts > 64:
        raise KeyGenerationError("invalid_key_attempt_limit")
    factory = candidate_factory or (lambda: _fresh_candidate(requested_bits))
    observed_bits: list[int] = []
    for attempt in range(1, max_attempts + 1):
        candidate = factory()
        actual_bits = candidate.n.bit_length()
        observed_bits.append(actual_bits)
        if actual_bits != requested_bits:
            continue
        if candidate.e != PUBLIC_EXPONENT or candidate.d <= 1:
            raise KeyGenerationError("invalid_candidate_components")
        return candidate, attempt, observed_bits
    raise KeyGenerationError("actual_public_modulus_bit_length_not_2048")


def public_evidence(private_key: PrivateKey) -> dict[str, object]:
    if private_key.actual_bits != REQUESTED_RSA_BITS:
        raise PublicKeyError("public_key_modulus_bits")
    modulus_hex = format(private_key.n, "x")
    if len(modulus_hex) != REQUESTED_RSA_BITS // 4:
        raise PublicKeyError("public_key_modulus_encoding")
    core: dict[str, object] = {
        "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
        "e_decimal": private_key.e,
        "kty": "RSA",
        "n_hex": modulus_hex,
        "requested_nominal_bits": REQUESTED_RSA_BITS,
    }
    return {
        **core,
        "actual_modulus_bits": private_key.n.bit_length(),
        "public_key_id": "rsa-sha256:" + sha256_bytes(canonical_bytes(core)),
    }


def parse_public_evidence(value: object, require_bits: int = REQUESTED_RSA_BITS) -> tuple[int, int, str]:
    if not isinstance(value, dict):
        raise PublicKeyError("public_key_not_object")
    required = {
        "algorithm",
        "e_decimal",
        "kty",
        "n_hex",
        "requested_nominal_bits",
        "actual_modulus_bits",
        "public_key_id",
    }
    if set(value) != required:
        raise PublicKeyError("public_key_field_set")
    modulus_hex = value["n_hex"]
    if not isinstance(modulus_hex, str) or not modulus_hex or modulus_hex != modulus_hex.lower():
        raise PublicKeyError("public_key_modulus_encoding")
    if modulus_hex.startswith("0") or any(character not in "0123456789abcdef" for character in modulus_hex):
        raise PublicKeyError("public_key_modulus_encoding")
    modulus = int(modulus_hex, 16)
    exponent = value["e_decimal"]
    if not isinstance(exponent, int) or isinstance(exponent, bool) or exponent != PUBLIC_EXPONENT:
        raise PublicKeyError("public_key_exponent")
    actual_bits = modulus.bit_length()
    if actual_bits != require_bits:
        raise PublicKeyError("public_key_modulus_bits")
    if value["actual_modulus_bits"] != actual_bits:
        raise PublicKeyError("public_key_reported_modulus_bits")
    if value["requested_nominal_bits"] != REQUESTED_RSA_BITS:
        raise PublicKeyError("public_key_requested_nominal_bits")
    if value["algorithm"] != "RSASSA-PKCS1-v1_5-SHA256" or value["kty"] != "RSA":
        raise PublicKeyError("public_key_algorithm")
    core = {
        "algorithm": value["algorithm"],
        "e_decimal": exponent,
        "kty": value["kty"],
        "n_hex": modulus_hex,
        "requested_nominal_bits": value["requested_nominal_bits"],
    }
    key_id = "rsa-sha256:" + sha256_bytes(canonical_bytes(core))
    if value["public_key_id"] != key_id:
        raise PublicKeyError("public_key_identity")
    return modulus, exponent, key_id


def _encoded_message(message: bytes, modulus_bytes: int) -> bytes:
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = modulus_bytes - len(digest_info) - 3
    if padding_length < 8:
        raise ValueError("rsa_modulus_too_short")
    return b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info


def sign_bytes(private_key: PrivateKey, message: bytes) -> str:
    if private_key.n.bit_length() != REQUESTED_RSA_BITS:
        raise PublicKeyError("public_key_modulus_bits")
    modulus_bytes = (private_key.n.bit_length() + 7) // 8
    encoded = _encoded_message(message, modulus_bytes)
    signature_int = pow(int.from_bytes(encoded, "big"), private_key.d, private_key.n)
    signature = signature_int.to_bytes(modulus_bytes, "big")
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def verify_bytes(public: object, message: bytes, signature_text: object) -> bool:
    try:
        modulus, exponent, _ = parse_public_evidence(public, require_bits=REQUESTED_RSA_BITS)
        if not isinstance(signature_text, str) or not signature_text:
            return False
        padding = "=" * ((4 - len(signature_text) % 4) % 4)
        signature = base64.urlsafe_b64decode((signature_text + padding).encode("ascii"))
        modulus_bytes = (modulus.bit_length() + 7) // 8
        if len(signature) != modulus_bytes:
            return False
        recovered = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(modulus_bytes, "big")
        return secrets.compare_digest(recovered, _encoded_message(message, modulus_bytes))
    except (PublicKeyError, ValueError, TypeError, UnicodeError):
        return False
