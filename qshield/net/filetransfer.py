import hashlib
import json
import os
import re
import shutil
import socket
import struct
import tempfile
from pathlib import Path

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_METADATA_SIZE = 4096
CHUNK_SIZE = 64 * 1024  # 64 KB


def receive_exact(conn, size):
    """Receive exactly the requested number of bytes."""
    data = bytearray()

    while len(data) < size:
        chunk = conn.recv(min(CHUNK_SIZE, size - len(data)))

        if not chunk:
            raise ConnectionError("Connection closed during file transfer")

        data.extend(chunk)

    return bytes(data)


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    hasher = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


def send_file(conn, file_path):
    """Send a file with metadata and SHA-256 integrity information."""
    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError("The selected file does not exist")

    file_size = file_path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds the maximum allowed size")

    metadata = {
        "filename": file_path.name,
        "size": file_size,
        "sha256": calculate_sha256(file_path)
    }

    metadata_bytes = json.dumps(metadata).encode("utf-8")

    if len(metadata_bytes) > MAX_METADATA_SIZE:
        raise ValueError("File metadata is too large")

    # Send metadata length followed by metadata
    conn.sendall(struct.pack("!I", len(metadata_bytes)))
    conn.sendall(metadata_bytes)

    # Send file contents in chunks
    bytes_sent = 0

    with open(file_path, "rb") as file:
        while bytes_sent < file_size:
            chunk = file.read(min(CHUNK_SIZE, file_size - bytes_sent))

            if not chunk:
                raise OSError("Source file changed during transfer")

            conn.sendall(chunk)
            bytes_sent += len(chunk)

    return metadata


def receive_file(conn, destination_dir):
    """Receive a file, verify its hash and save it without overwriting."""
    metadata_length = struct.unpack(
        "!I", receive_exact(conn, 4)
    )[0]

    if metadata_length == 0 or metadata_length > MAX_METADATA_SIZE:
        raise ValueError("Invalid file metadata length")

    try:
        metadata = json.loads(
            receive_exact(conn, metadata_length).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid file metadata") from error

    if not isinstance(metadata, dict):
        raise ValueError("Invalid file metadata")

    filename = metadata.get("filename")
    file_size = metadata.get("size")
    expected_hash = metadata.get("sha256")

    # Validate the filename to prevent path traversal
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
        or file_size < 0
        or file_size > MAX_FILE_SIZE
    ):
        raise ValueError("Invalid file size")

    if (
        not isinstance(expected_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
    ):
        raise ValueError("Invalid SHA-256 hash")

    destination_dir = Path(destination_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    destination = destination_dir / filename

    # Never overwrite an existing file
    if destination.exists():
        raise FileExistsError("A file with this name already exists")

    temporary_path = None
    final_created = False

    try:
        # Store incoming data temporarily until integrity is verified
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination_dir,
            prefix=".qshield_",
            suffix=".tmp",
            delete=False
        ) as temporary_file:

            temporary_path = Path(temporary_file.name)
            hasher = hashlib.sha256()
            remaining = file_size

            while remaining > 0:
                chunk = receive_exact(
                    conn, min(CHUNK_SIZE, remaining)
                )

                temporary_file.write(chunk)
                hasher.update(chunk)
                remaining -= len(chunk)

        # Reject the file if its contents do not match the hash
        if hasher.hexdigest() != expected_hash:
            raise ValueError("File integrity verification failed")

        # Create the final file exclusively to prevent overwriting
        file_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )
        final_created = True

        with os.fdopen(file_descriptor, "wb") as output_file:
            with open(temporary_path, "rb") as input_file:
                shutil.copyfileobj(input_file, output_file)

        return destination

    except Exception:
        if final_created:
            destination.unlink(missing_ok=True)
        raise

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
