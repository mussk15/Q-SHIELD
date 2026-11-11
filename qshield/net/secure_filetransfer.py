import base64
import hashlib
import json
import os
import re
import tempfile
import struct
from pathlib import Path

from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.net.protocol import send_message, receive_message

MAX_FILE_SIZE = 100 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


def _metadata_bytes(metadata):
    return json.dumps(
        metadata, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _chunk_aad(metadata, index):
    return (
        b"QSHIELD_FILE_CHUNK_V1\x00"
        + _metadata_bytes(metadata)
        + struct.pack("!I", index)
    )


def send_encrypted_file(conn, file_path, session_key):
    """Send a file as independently authenticated AES-256-GCM chunks."""
    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError("Selected file does not exist")

    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 100 MB limit")

    hasher = hashlib.sha256()
    with file_path.open("rb") as source:
        for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
            hasher.update(chunk)

    chunk_count = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)

    metadata = {
        "filename": file_path.name,
        "size": file_size,
        "sha256": hasher.hexdigest(),
        "chunk_size": CHUNK_SIZE,
        "chunk_count": chunk_count,
    }

    send_message(conn, _metadata_bytes(metadata).decode("utf-8"))

    sent = 0
    transfer_hash = hashlib.sha256()

    with file_path.open("rb") as source:
        for index in range(chunk_count):
            chunk = source.read(CHUNK_SIZE)
            if index < chunk_count - 1 and len(chunk) != CHUNK_SIZE:
                raise OSError("Source file changed during transfer")

            transfer_hash.update(chunk)
            encrypted = AES256GCM.encrypt(
                session_key,
                chunk,
                associated_data=_chunk_aad(metadata, index),
            )

            encoded = base64.b64encode(encrypted.to_bytes()).decode("ascii")
            send_message(conn, encoded)
            sent += len(chunk)

    if sent != file_size or transfer_hash.hexdigest() != metadata["sha256"]:
        raise OSError("Source file changed during transfer")

    return metadata


def receive_encrypted_file(conn, destination_dir, session_key):
    """Receive, authenticate, hash-check and safely save encrypted chunks."""
    try:
        metadata = json.loads(receive_message(conn))
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid file metadata") from exc

    if not isinstance(metadata, dict):
        raise ValueError("Invalid file metadata")

    filename = metadata.get("filename")
    file_size = metadata.get("size")
    expected_hash = metadata.get("sha256")
    chunk_size = metadata.get("chunk_size")
    chunk_count = metadata.get("chunk_count")

    if (
        not isinstance(filename, str)
        or not filename
        or filename in (".", "..")
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or Path(filename).name != filename
    ):
        raise ValueError("Unsafe filename")

    if (
        not isinstance(file_size, int)
        or isinstance(file_size, bool)
        or not 0 <= file_size <= MAX_FILE_SIZE
    ):
        raise ValueError("Invalid file size")

    if (
        not isinstance(expected_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
    ):
        raise ValueError("Invalid SHA-256 hash")

    expected_chunks = max(1, (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    if chunk_size != CHUNK_SIZE or chunk_count != expected_chunks:
        raise ValueError("Invalid chunk configuration")

    destination_dir = Path(destination_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / filename

    if destination.exists():
        raise FileExistsError("A file with this name already exists")

    temporary_path = None
    final_created = False

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination_dir,
            prefix=".qshield_secure_",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            hasher = hashlib.sha256()
            received = 0

            for index in range(chunk_count):
                encoded = receive_message(conn)
                encrypted_bytes = base64.b64decode(
                    encoded, validate=True
                )
                encrypted = EncryptedMessage.from_bytes(encrypted_bytes)

                plaintext = AES256GCM.decrypt(
                    session_key,
                    encrypted,
                    associated_data=_chunk_aad(metadata, index),
                )

                expected_length = (
                    0 if file_size == 0
                    else min(CHUNK_SIZE, file_size - received)
                )

                if len(plaintext) != expected_length:
                    raise ValueError("Invalid decrypted chunk length")

                temporary.write(plaintext)
                hasher.update(plaintext)
                received += len(plaintext)

        if received != file_size or hasher.hexdigest() != expected_hash:
            raise ValueError("File integrity verification failed")

        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        final_created = True

        with os.fdopen(descriptor, "wb") as output:
            with temporary_path.open("rb") as source:
                while True:
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    output.write(chunk)

        return destination

    except Exception:
        if final_created:
            destination.unlink(missing_ok=True)
        raise

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
