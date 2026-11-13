"""Tests for cloud deployment hardening, session reconciliation, and authentication."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from qshield.net.server import reconcile_active_sessions
from qshield.security.auth import hash_password, verify_password
from scripts.health_check import check_tcp_server, check_evidence


def test_auth_scrypt_hashing_and_verification():
    secret = "SuperSecureCloudPassword2026!"
    hashed = hash_password(secret)

    assert hashed.startswith("scrypt$16384$8$1$")
    assert verify_password(secret, hashed) is True
    assert verify_password("WrongSecret", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(secret, "invalid_hash_string") is False


def test_auth_pbkdf2_compatibility():
    # Verify legacy pbkdf2 format verification if encountered
    import hashlib
    salt = b"0123456789abcdef"
    dk = hashlib.pbkdf2_hmac("sha256", b"my_password", salt, 600000, 32)
    pbkdf2_hash = f"pbkdf2$600000${salt.hex()}${dk.hex()}"

    assert verify_password("my_password", pbkdf2_hash) is True
    assert verify_password("wrong_password", pbkdf2_hash) is False


def test_session_reconciliation_on_server_restart(tmp_path: Path):
    sessions_file = tmp_path / "sessions.jsonl"
    sessions_file.write_text(
        json.dumps({"session_id": "sess-1", "remote_ip": "10.0.0.1", "status": "Connected"}) + "\n"
        + json.dumps({"session_id": "sess-2", "remote_ip": "10.0.0.2", "status": "Active"}) + "\n"
        + json.dumps({"session_id": "sess-3", "remote_ip": "10.0.0.3", "status": "Disconnected"}) + "\n",
        encoding="utf-8",
    )

    reconciled = reconcile_active_sessions(sessions_file=sessions_file)
    assert reconciled == 2

    # Verify that sess-1 and sess-2 are now Disconnected
    lines = [json.loads(line) for line in sessions_file.read_text(encoding="utf-8").strip().split("\n")]
    assert len(lines) == 3
    assert lines[0]["status"] == "Disconnected"
    assert lines[0]["disconnect_reason"] == "Server restarted"
    assert lines[1]["status"] == "Disconnected"
    assert lines[1]["disconnect_reason"] == "Server restarted"
    assert lines[2]["status"] == "Disconnected"

    # Second reconciliation should reconcile 0
    assert reconcile_active_sessions(sessions_file=sessions_file) == 0


def test_health_check_tcp_unreachable():
    # Connecting to closed port returns False without raising exception
    ok, msg = check_tcp_server("127.0.0.1", 59999, timeout=0.1)
    assert ok is False
    assert "unreachable" in msg.lower()


def test_health_check_evidence(tmp_path: Path):
    # Empty dir has valid empty chain
    ok, msg = check_evidence(tmp_path)
    assert ok is True

