"""Security and functional tests for Q-SHIELD post-quantum secure file transfer."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import tempfile
import threading
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.net.protocol import receive_message, send_message
from qshield.net.secure_filetransfer import (
    CHUNK_SIZE,
    MAX_FILE_SIZE,
    _chunk_aad,
    _metadata_bytes,
    receive_encrypted_file,
    send_encrypted_file,
)


@pytest.fixture
def session_key():
    return secrets.token_bytes(32)


def run_transfer(source_file: Path, destination_dir: Path, key: bytes):
    sender, receiver = socket.socketpair()
    send_err = []

    def client_worker():
        try:
            send_encrypted_file(sender, source_file, key)
        except Exception as exc:
            send_err.append(exc)
        finally:
            sender.close()

    thread = threading.Thread(target=client_worker, daemon=True)
    thread.start()

    try:
        result = receive_encrypted_file(receiver, destination_dir, key)
    finally:
        receiver.close()
        thread.join(timeout=5.0)

    if send_err:
        raise send_err[0]
    return result


def test_successful_encrypted_file_transfer(tmp_path, session_key):
    src = tmp_path / "document.pdf"
    content = b"%PDF-1.5 test content payload " * 500
    src.write_bytes(content)

    dest_dir = tmp_path / "dest"
    saved = run_transfer(src, dest_dir, session_key)

    assert saved.exists()
    assert saved.name == "document.pdf"
    assert saved.read_bytes() == content
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == hashlib.sha256(content).hexdigest()


def test_empty_file_transfer(tmp_path, session_key):
    src = tmp_path / "empty.txt"
    src.write_bytes(b"")

    dest_dir = tmp_path / "dest"
    saved = run_transfer(src, dest_dir, session_key)

    assert saved.exists()
    assert saved.read_bytes() == b""


def test_multi_chunk_file_transfer(tmp_path, session_key):
    src = tmp_path / "large.bin"
    # Create file that spans multiple 64KB chunks
    content = secrets.token_bytes(CHUNK_SIZE * 2 + 1024)
    src.write_bytes(content)

    dest_dir = tmp_path / "dest"
    saved = run_transfer(src, dest_dir, session_key)

    assert saved.exists()
    assert saved.read_bytes() == content


def test_duplicate_file_rejection(tmp_path, session_key):
    src = tmp_path / "existing.txt"
    src.write_bytes(b"New data")

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / "existing.txt").write_bytes(b"Original data")

    with pytest.raises(FileExistsError):
        run_transfer(src, dest_dir, session_key)

    assert (dest_dir / "existing.txt").read_bytes() == b"Original data"


def test_path_traversal_rejection(tmp_path, session_key):
    sender, receiver = socket.socketpair()
    dest_dir = tmp_path / "dest"

    try:
        # Malicious metadata attempting path traversal
        bad_metadata = {
            "filename": "../evil.txt",
            "size": 10,
            "sha256": "0" * 64,
            "chunk_size": CHUNK_SIZE,
            "chunk_count": 1,
        }
        send_message(sender, json.dumps(bad_metadata))

        with pytest.raises(ValueError, match="Unsafe filename"):
            receive_encrypted_file(receiver, dest_dir, session_key)
    finally:
        sender.close()
        receiver.close()


def test_modified_ciphertext_fails_tag(tmp_path, session_key):
    sender, receiver = socket.socketpair()
    dest_dir = tmp_path / "dest"

    try:
        plaintext = b"Secret payload"
        metadata = {
            "filename": "tamper.bin",
            "size": len(plaintext),
            "sha256": hashlib.sha256(plaintext).hexdigest(),
            "chunk_size": CHUNK_SIZE,
            "chunk_count": 1,
        }
        send_message(sender, json.dumps(metadata))

        # Encrypt validly then tamper ciphertext
        enc = AES256GCM.encrypt(session_key, plaintext, associated_data=_chunk_aad(metadata, 0))
        tampered_bytes = bytearray(enc.to_bytes())
        # Flip a bit in the ciphertext portion
        tampered_bytes[-1] ^= 0x01
        send_message(sender, base64.b64encode(tampered_bytes).decode("ascii"))

        with pytest.raises(InvalidTag):
            receive_encrypted_file(receiver, dest_dir, session_key)

        # Confirm no temporary files leaked
        if dest_dir.exists():
            assert not any(p.name.startswith(".qshield_secure_") for p in dest_dir.iterdir())
    finally:
        sender.close()
        receiver.close()


def test_wrong_hash_rejected_and_cleaned_up(tmp_path, session_key):
    sender, receiver = socket.socketpair()
    dest_dir = tmp_path / "dest"

    try:
        plaintext = b"Payload with wrong declared hash"
        metadata = {
            "filename": "bad_hash.bin",
            "size": len(plaintext),
            "sha256": "a" * 64,  # Incorrect hash
            "chunk_size": CHUNK_SIZE,
            "chunk_count": 1,
        }
        send_message(sender, json.dumps(metadata))

        enc = AES256GCM.encrypt(session_key, plaintext, associated_data=_chunk_aad(metadata, 0))
        send_message(sender, base64.b64encode(enc.to_bytes()).decode("ascii"))

        with pytest.raises(ValueError, match="integrity verification failed"):
            receive_encrypted_file(receiver, dest_dir, session_key)

        # Verify no file saved
        assert not (dest_dir / "bad_hash.bin").exists()
        if dest_dir.exists():
            assert not any(p.name.startswith(".qshield_secure_") for p in dest_dir.iterdir())
    finally:
        sender.close()
        receiver.close()

