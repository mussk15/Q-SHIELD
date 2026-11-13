"""Security and authentication utilities for Q-SHIELD.

Provides NIST-aligned password hashing using scrypt (memory-hard, salted)
and constant-time verification against brute-force timing attacks.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Tuple


def hash_password(password: str, salt: bytes | None = None) -> str:
    """
    Hash a password using hashlib.scrypt with a cryptographically secure random salt.

    Format: scrypt$<n>$<r>$<p>$<salt_hex>$<hash_hex>
    Default parameters: n=16384 (CPU/memory cost), r=8 (block size), p=1 (parallelization).
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    if salt is None:
        salt = secrets.token_bytes(16)
    elif len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    n = 16384
    r = 8
    p = 1
    maxmem = 32 * 1024 * 1024  # 32 MB limit

    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        maxmem=maxmem,
        dklen=32,
    )

    return f"scrypt${n}${r}${p}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored hash using constant-time comparison.
    Supports both scrypt$<n>$<r>$<p>$<salt_hex>$<hash_hex> and pbkdf2$<iterations>$<salt_hex>$<hash_hex>.
    """
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False

    parts = stored_hash.strip().split("$")
    if len(parts) < 3:
        return False

    scheme = parts[0].lower()

    try:
        if scheme == "scrypt" and len(parts) == 6:
            n = int(parts[1])
            r = int(parts[2])
            p = int(parts[3])
            salt = bytes.fromhex(parts[4])
            expected_hash = bytes.fromhex(parts[5])

            derived = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=64 * 1024 * 1024,
                dklen=len(expected_hash),
            )
            return hmac.compare_digest(derived, expected_hash)

        elif scheme == "pbkdf2" and len(parts) == 4:
            iterations = int(parts[1])
            salt = bytes.fromhex(parts[2])
            expected_hash = bytes.fromhex(parts[3])

            derived = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt=salt,
                iterations=iterations,
                dklen=len(expected_hash),
            )
            return hmac.compare_digest(derived, expected_hash)

        else:
            return False
    except (ValueError, TypeError, OverflowError):
        return False

