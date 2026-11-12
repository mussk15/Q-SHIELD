"""Secure TCP Client Service Adapter for Q-SHIELD Dashboard.

Provides dashboard-based post-quantum secure messaging and in-band re-keying
over the existing length-prefixed TCP protocol.
"""
from __future__ import annotations

import base64
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.keystore import KeyStore, KeyStoreError
from qshield.crypto.sig import SignatureKeyPair
from qshield.net.handshake import (
    ClientFinish,
    HandshakeError,
    ServerFinish,
    ServerHello,
    respond_to_server,
)
from qshield.net.protocol import receive_message, send_message
from qshield.net.rekey import (
    REKEY_COMMIT_PREFIX,
    REKEY_FINISHED_PREFIX,
    REKEY_OFFER_PREFIX,
    REKEY_RESPONSE_PREFIX,
    RekeyCommit,
    RekeyFinished,
    RekeyOffer,
    make_control_frame,
    parse_control_frame,
    respond_to_rekey,
)

AAD = b"QSHIELD_APP_V1"


class ClientService:
    """Manages an active secure client connection to the Q-SHIELD server."""

    def __init__(self, key_dir: str | Path = "keys"):
        self.key_dir = Path(key_dir)
        self._sock: socket.socket | None = None
        self._session_key: bytes | None = None
        self._session_id: str | None = None
        self._generation: int = 0
        self._client_identity: SignatureKeyPair | None = None
        self._trusted_server: bytes | None = None
        self._host: str = "127.0.0.1"
        self._port: int = 5001
        self._connected: bool = False
        self._lock = threading.Lock()
        self._history: list[dict[str, Any]] = []

    @property
    def is_connected(self) -> bool:
        with self._lock:
            return self._connected and self._sock is not None

    def get_status(self) -> dict[str, Any]:
        """Return a snapshot of client connection status and history."""
        with self._lock:
            return {
                "connected": self._connected,
                "session_id": self._session_id,
                "generation": self._generation,
                "host": self._host,
                "port": self._port,
                "message_count": len(self._history),
                "history": list(self._history),
            }

    def connect(
        self,
        host: str = "127.0.0.1",
        port: int = 5001,
        password: str = "QSHIELD",
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Establish an authenticated post-quantum secure session with the server."""
        with self._lock:
            if self._connected and self._sock:
                return {"success": True, "message": f"Already connected to {self._host}:{self._port}"}

            self._host = host
            self._port = port

            # 1. Load keys
            client_key_path = self.key_dir / "client_private.keystore"
            client_pub_path = self.key_dir / "client_public.bin"
            server_pub_path = self.key_dir / "server_public.bin"

            if not client_key_path.exists():
                return {"success": False, "message": f"Client keystore not found: {client_key_path}"}
            if not client_pub_path.exists():
                return {"success": False, "message": f"Client public key not found: {client_pub_path}"}
            if not server_pub_path.exists():
                return {"success": False, "message": f"Server public key not found: {server_pub_path}"}

            try:
                client_private = KeyStore.load_private_key(
                    client_key_path, password, expected_algorithm=SIGNATURE_ALGORITHM
                )
                client_public = client_pub_path.read_bytes()
                self._trusted_server = server_pub_path.read_bytes()
                self._client_identity = SignatureKeyPair(
                    public_key=client_public,
                    secret_key=client_private,
                )
            except KeyStoreError as exc:
                return {"success": False, "message": f"Keystore password rejected: {exc}"}
            except Exception as exc:
                return {"success": False, "message": f"Failed to load client identity: {exc}"}

            # 2. Connect socket and execute post-quantum handshake
            try:
                conn = socket.create_connection((host, port), timeout=timeout)
                conn.settimeout(timeout)

                raw_hello = receive_message(conn).encode("utf-8")
                server_hello = ServerHello.from_bytes(raw_hello)
                client_res = respond_to_server(
                    server_hello, self._trusted_server, self._client_identity
                )
                send_message(conn, client_res.client_finish.to_bytes().decode("utf-8"))

                raw_server_finish = receive_message(conn).encode("utf-8")
                server_finish = ServerFinish.from_bytes(raw_server_finish)
                if not client_res.verify_server_finished(server_finish):
                    conn.close()
                    raise HandshakeError("Server handshake signature verification failed")

                self._sock = conn
                self._session_key = client_res.session_key
                self._generation = 0
                self._session_id = f"client-{conn.getsockname()[1]}"
                self._connected = True

                return {
                    "success": True,
                    "message": (
                        f"Post-quantum handshake successful with {host}:{port}. "
                        "ML-KEM-768 key established, ML-DSA-65 authenticated."
                    ),
                    "generation": self._generation,
                    "session_id": self._session_id,
                }
            except Exception as exc:
                self._sock = None
                self._connected = False
                return {"success": False, "message": f"Connection failed: {exc}"}

    def send_encrypted_message(self, text: str) -> dict[str, Any]:
        """Encrypt, send, receive reply, and transparently handle in-band re-keying."""
        with self._lock:
            if not self._connected or not self._sock or not self._session_key:
                return {"success": False, "message": "Client is not connected."}

            try:
                clean_text = str(text).strip()
                if not clean_text:
                    return {"success": False, "message": "Cannot send empty message."}

                # 1. Encrypt and send under current session key
                encrypted = AES256GCM.encrypt(
                    self._session_key, clean_text.encode("utf-8"), associated_data=AAD
                )
                send_message(self._sock, base64.b64encode(encrypted.to_bytes()).decode("ascii"))

                # 2. Receive reply (with possible in-band re-key offers)
                encoded_reply = receive_message(self._sock)
                rekey_occurred = False

                while encoded_reply.startswith(REKEY_OFFER_PREFIX):
                    rekey_occurred = True
                    offer = RekeyOffer.from_bytes(
                        parse_control_frame(encoded_reply, REKEY_OFFER_PREFIX)
                    )
                    assert self._trusted_server is not None
                    assert self._client_identity is not None

                    client_rekey = respond_to_rekey(
                        offer,
                        self._session_key,
                        self._trusted_server,
                        self._client_identity,
                        expected_generation=self._generation + 1,
                    )
                    send_message(
                        self._sock,
                        make_control_frame(REKEY_RESPONSE_PREFIX, client_rekey.response.to_bytes()),
                    )

                    finished_frame = receive_message(self._sock)
                    finished = RekeyFinished.from_bytes(
                        parse_control_frame(finished_frame, REKEY_FINISHED_PREFIX)
                    )
                    if not client_rekey.verify_server_finished(finished):
                        raise RuntimeError("Server re-key key-confirmation MAC verification failed")

                    send_message(
                        self._sock,
                        make_control_frame(
                            REKEY_COMMIT_PREFIX,
                            client_rekey.create_client_commit().to_bytes(),
                        ),
                    )

                    self._session_key = client_rekey.session_key
                    self._generation = offer.generation
                    encoded_reply = receive_message(self._sock)

                # 3. Decrypt application response under (updated) session key
                encrypted_reply = EncryptedMessage.from_bytes(
                    base64.b64decode(encoded_reply, validate=True)
                )
                plaintext_reply = AES256GCM.decrypt(
                    self._session_key, encrypted_reply, associated_data=AAD
                ).decode("utf-8")

                item = {
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "sent": clean_text,
                    "received": plaintext_reply,
                    "generation": self._generation,
                    "rekeyed": rekey_occurred,
                }
                self._history.append(item)

                return {
                    "success": True,
                    "sent": clean_text,
                    "received": plaintext_reply,
                    "generation": self._generation,
                    "rekeyed": rekey_occurred,
                }
            except Exception as exc:
                self._connected = False
                return {"success": False, "message": f"Message exchange failed: {exc}"}

    def disconnect(self) -> dict[str, Any]:
        """Send /quit and disconnect cleanly."""
        with self._lock:
            if not self._connected or not self._sock:
                return {"success": True, "message": "Client already disconnected."}

            try:
                if self._session_key:
                    quit_enc = AES256GCM.encrypt(
                        self._session_key, b"/quit", associated_data=AAD
                    )
                    send_message(
                        self._sock, base64.b64encode(quit_enc.to_bytes()).decode("ascii")
                    )
            except OSError:
                pass
            finally:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
                self._connected = False
                self._session_key = None

            return {"success": True, "message": "Secure client disconnected cleanly."}

