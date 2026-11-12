"""Secure File Transfer Service Adapter for Q-SHIELD Dashboard.

Manages post-quantum encrypted chunk-based file transfers and file server
lifecycle using AES-256-GCM and SHA-256 integrity verification.
"""
from __future__ import annotations

import hashlib
import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.keystore import KeyStore, KeyStoreError
from qshield.crypto.sig import SignatureKeyPair
from qshield.net.handshake import (
    ClientFinish,
    HandshakeError,
    ServerFinish,
    ServerHello,
    begin_server_handshake,
    finalize_server_handshake,
    respond_to_server,
)
from qshield.net.protocol import receive_message, send_message
from qshield.net.secure_filetransfer import (
    receive_encrypted_file,
    send_encrypted_file,
)
from qshield.net.server import check_connection_allowed

DEFAULT_FILE_PORT = 5002
RECEIVED_DIR = Path("data/received_files")
TEST_FILES_DIR = Path("data/test_files")


class FileTransferService:
    """Manages post-quantum authenticated file transfers."""

    def __init__(self, key_dir: str | Path = "keys"):
        self.key_dir = Path(key_dir)
        self.host = "127.0.0.1"
        self.port = DEFAULT_FILE_PORT
        self._server_sock: socket.socket | None = None
        self._server_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._is_server_managed = False
        self._history: list[dict[str, Any]] = []

        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        TEST_FILES_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def is_port_in_use(host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return True
            except (ConnectionRefusedError, TimeoutError, OSError):
                return False

    def ensure_file_server(self, password: str = "QSHIELD") -> bool:
        """Ensure file server is listening on port 5002; start if not running."""
        with self._lock:
            if self.is_port_in_use(self.host, self.port):
                return True

            server_key_path = self.key_dir / "server_private.keystore"
            client_pub_path = self.key_dir / "client_public.bin"

            if not server_key_path.exists() or not client_pub_path.exists():
                return False

            try:
                server_private = KeyStore.load_private_key(
                    server_key_path, password, expected_algorithm=SIGNATURE_ALGORITHM
                )
                trusted_client = client_pub_path.read_bytes()
            except Exception:
                return False

            try:
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind((self.host, self.port))
                server_sock.listen(5)
                server_sock.settimeout(1.0)
                self._server_sock = server_sock
            except OSError:
                return False

            self._stop_event.clear()
            self._is_server_managed = True

            def file_server_worker():
                while not self._stop_event.is_set():
                    try:
                        conn, addr = server_sock.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

                    allowed, _ = check_connection_allowed(addr[0])
                    if not allowed:
                        conn.close()
                        continue

                    def handle_file_client(c, a):
                        try:
                            with c:
                                state = begin_server_handshake(server_private)
                                send_message(c, state.hello.to_bytes().decode("utf-8"))

                                raw_cf = receive_message(c).encode("utf-8")
                                cf = ClientFinish.from_bytes(raw_cf)
                                res = finalize_server_handshake(state, cf, trusted_client)
                                send_message(c, res.server_finish.to_bytes().decode("utf-8"))

                                saved_path = receive_encrypted_file(
                                    c, RECEIVED_DIR, res.session_key
                                )
                                ack = {
                                    "status": "success",
                                    "filename": saved_path.name,
                                    "size": saved_path.stat().st_size,
                                    "message": "File received and verified with SHA-256",
                                }
                                import json
                                send_message(c, json.dumps(ack))
                        except Exception as exc:
                            print(f"[FILE SERVER ERROR] {exc}")

                    th = threading.Thread(target=handle_file_client, args=(conn, addr), daemon=True)
                    th.start()

            self._server_thread = threading.Thread(
                target=file_server_worker, name="qshield-file-server", daemon=True
            )
            self._server_thread.start()
            return True

    def send_file(
        self,
        file_path: str | Path,
        password: str = "QSHIELD",
        host: str = "127.0.0.1",
        port: int = DEFAULT_FILE_PORT,
    ) -> dict[str, Any]:
        """Perform authenticated post-quantum encrypted transfer of a file."""
        target_path = Path(file_path)
        if not target_path.exists() or not target_path.is_file():
            return {"success": False, "message": f"File does not exist: {target_path}"}

        # Ensure server is ready
        if not self.ensure_file_server(password=password):
            return {"success": False, "message": f"Unable to start or reach file server on {host}:{port}"}

        client_key_path = self.key_dir / "client_private.keystore"
        client_pub_path = self.key_dir / "client_public.bin"
        server_pub_path = self.key_dir / "server_public.bin"

        try:
            client_private = KeyStore.load_private_key(
                client_key_path, password, expected_algorithm=SIGNATURE_ALGORITHM
            )
            client_identity = SignatureKeyPair(
                public_key=client_pub_path.read_bytes(),
                secret_key=client_private,
            )
            trusted_server = server_pub_path.read_bytes()
        except Exception as exc:
            return {"success": False, "message": f"Cryptographic identity error: {exc}"}

        try:
            with socket.create_connection((host, port), timeout=30.0) as conn:
                conn.settimeout(30.0)

                # Handshake
                raw_hello = receive_message(conn).encode("utf-8")
                server_hello = ServerHello.from_bytes(raw_hello)
                client_res = respond_to_server(server_hello, trusted_server, client_identity)
                send_message(conn, client_res.client_finish.to_bytes().decode("utf-8"))

                raw_sf = receive_message(conn).encode("utf-8")
                server_finish = ServerFinish.from_bytes(raw_sf)
                if not client_res.verify_server_finished(server_finish):
                    raise HandshakeError("Server identity verification failed")

                # Send encrypted file
                metadata = send_encrypted_file(conn, target_path, client_res.session_key)

                # Receive acknowledgement
                ack_raw = receive_message(conn)
                import json
                ack = json.loads(ack_raw)

                result = {
                    "success": True,
                    "filename": metadata["filename"],
                    "size_bytes": metadata["size"],
                    "sha256": metadata["sha256"],
                    "chunk_count": metadata["chunk_count"],
                    "status": "VERIFIED",
                    "destination": str(RECEIVED_DIR / metadata["filename"]),
                    "server_ack": ack.get("message", "Verified"),
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
                self._history.append(result)
                return result

        except Exception as exc:
            return {"success": False, "message": f"File transfer failed: {exc}"}

    def list_received_files(self) -> list[dict[str, Any]]:
        """List all files in the received files directory with hashes and sizes."""
        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
        items = []
        for file in RECEIVED_DIR.iterdir():
            if file.is_file():
                try:
                    stat = file.stat()
                    sha = hashlib.sha256(file.read_bytes()).hexdigest()
                    items.append({
                        "filename": file.name,
                        "size_bytes": stat.st_size,
                        "sha256": sha,
                        "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"),
                    })
                except OSError:
                    pass
        return sorted(items, key=lambda x: x["modified"], reverse=True)

    def get_history(self) -> list[dict[str, Any]]:
        return list(self._history)

