"""CLI utility to generate a secure salted password hash for Q-SHIELD.

Usage:
    python -m scripts.generate_password_hash
or:
    python scripts/generate_password_hash.py
"""
from __future__ import annotations

import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qshield.security.auth import hash_password, verify_password


def main():
    print("=" * 65)
    print("Q-SHIELD — SECURE PASSWORD HASH GENERATOR (scrypt)")
    print("=" * 65)
    print("This utility generates a memory-hard, salted scrypt hash for use")
    print("in the QSHIELD_DASHBOARD_PASSWORD_HASH environment variable.\n")

    try:
        pw1 = getpass.getpass("Enter dashboard password: ")
        if not pw1.strip():
            print("Error: Password cannot be blank.")
            sys.exit(1)

        pw2 = getpass.getpass("Confirm dashboard password: ")
        if pw1 != pw2:
            print("Error: Passwords do not match.")
            sys.exit(1)
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
        sys.exit(1)

    hashed = hash_password(pw1)
    assert verify_password(pw1, hashed)

    print("\n" + "-" * 65)
    print("Generated Password Hash:")
    print("-" * 65)
    print(hashed)
    print("-" * 65)
    print("\nAdd this line to your production .env file:")
    print(f"QSHIELD_DASHBOARD_PASSWORD_HASH={hashed}\n")


if __name__ == "__main__":
    main()

