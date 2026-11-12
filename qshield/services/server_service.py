"""Secure TCP Server Service Adapter for Q-SHIELD Dashboard.

Manages the lifecycle of the post-quantum secure communication server
without duplicating underlying cryptographic or networking logic.
"""
from __future__ import annotations

import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.keystore import KeyStore, KeyStoreError
from qshield.net.secure_server import handle_client
from qshield.net.server import (
    DATA_DIR,
    HOST as DEFAULT_HOST,
    PORT as DEFAULT_PORT,
    active_sessions,
    active_sessions_lock,
    check_connection_allowed,
    command_processor,
    command_stop_event,
)


DEFAULT_SERVER_PORT = 5001


class ServerService:
    """Thread-safe manager for the Q-SHIELD post-quantum TCP server."""

    def __init__(self, key_dir: str | Path = "keys"):
        self.key_dir = Path(key_dir)
        self.host: str = DEFAULT_HOST
        self.port: int = DEFAULT_SERVER_PORT
        self._server_socket: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._command_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._status: str = "STOPPED"
        self._started_at: str | None = None
        self._last_error: str | None = None
        self._managed_by_service: bool = False

    @staticmethod
    def is_port_in_use(host: str, port: int) -> bool:
        """Check whether a given host/port is currently accepting connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return True
            except (ConnectionRefusedError, TimeoutError, OSError):
                return False

    def get_status(self) -> dict[str, Any]:
        """Return a snapshot of current server health and connection counts."""
        with self._lock:
            port_active = self.is_port_in_use(self.host, self.port)
            if self._managed_by_service and self._status == "RUNNING":
                current_status = "RUNNING"
            elif port_active:
                current_status = "RUNNING (External)"
            else:
                current_status = "STOPPED"

            with active_sessions_lock:
                active_count = len(active_sessions)

            return {
                "status": current_status,
                "host": self.host,
                "port": self.port,
                "managed": self._managed_by_service,
                "active_sessions": active_count,
                "started_at": self._started_at,
                "last_error": self._last_error,
            }

    def start_server(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        password: str = "QSHIELD",
    ) -> dict[str, Any]:
        """Start the secure server in a managed background thread."""
        with self._lock:
            self.host = host
            self.port = port
            self._last_error = None

            if self.is_port_in_use(host, port):
                if self._managed_by_service and self._status == "RUNNING":
                    return {"success": True, "message": f"Server is already running on {host}:{port}"}
                return {
                    "success": True,
                    "message": f"Server is already active on {host}:{port} (External process detected)",
                }

            # 1. Load cryptographic identities
            server_key_path = self.key_dir / "server_private.keystore"
            client_pub_path = self.key_dir / "client_public.bin"

            if not server_key_path.exists():
                self._last_error = f"Server keystore not found at {server_key_path}"
                return {"success": False, "message": self._last_error}
            if not client_pub_path.exists():
                self._last_error = f"Client public key not found at {client_pub_path}"
                return {"success": False, "message": self._last_error}

            try:
                server_private = KeyStore.load_private_key(
                    server_key_path,
                    password,
                    expected_algorithm=SIGNATURE_ALGORITHM,
                )
                trusted_client = client_pub_path.read_bytes()
            except KeyStoreError as exc:
                self._last_error = f"Keystore password rejected or corrupted: {exc}"
                return {"success": False, "message": self._last_error}
            except Exception as exc:
                self._last_error = f"Failed to load cryptographic identity: {exc}"
                return {"success": False, "message": self._last_error}

            # 2. Start command processor
            command_stop_event.clear()
            self._command_thread = threading.Thread(
                target=command_processor,
                name="dashboard-command-processor",
                daemon=True,
            )
            self._command_thread.start()

            # 3. Create server socket
            try:
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind((host, port))
                server_sock.listen(10)
                server_sock.settimeout(1.0)
                self._server_socket = server_sock
            except Exception as exc:
                self._last_error = f"Failed to bind socket on {host}:{port}: {exc}"
                return {"success": False, "message": self._last_error}

            self._stop_event.clear()
            self._managed_by_service = True
            self._status = "RUNNING"
            self._started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

            # 4. Accept loop worker
            def accept_loop():
                while not self._stop_event.is_set():
                    try:
                        conn, address = server_sock.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break

                    allowed, reason = check_connection_allowed(address[0])
                    if not allowed:
                        try:
                            conn.close()
                        except OSError:
                            pass
                        continue

                    worker = threading.Thread(
                        target=handle_client,
                        args=(conn, address, server_private, trusted_client),
                        daemon=True,
                    )
                    worker.start()

            self._accept_thread = threading.Thread(
                target=accept_loop,
                name="qshield-server-accept",
                daemon=True,
            )
            self._accept_thread.start()

            return {
                "success": True,
                "message": f"Secure server started on {host}:{port} with post-quantum authentication.",
            }

    def stop_server(self) -> dict[str, Any]:
        """Stop the managed secure server gracefully."""
        with self._lock:
            if not self._managed_by_service:
                if self.is_port_in_use(self.host, self.port):
                    return {
                        "success": False,
                        "message": (
                            f"Port {self.port} is active, but running as an external process. "
                            "Stop it from the terminal where it was started."
                        ),
                    }
                return {"success": True, "message": "Server is not running."}

            self._stop_event.set()
            command_stop_event.set()

            if self._server_socket:
                try:
                    self._server_socket.close()
                except OSError:
                    pass
                self._server_socket = None

            if self._accept_thread and self._accept_thread.is_alive():
                self._accept_thread.join(timeout=2.0)
                self._accept_thread = None

            self._managed_by_service = False
            self._status = "STOPPED"
            self._started_at = None

            return {"success": True, "message": "Secure server stopped successfully."}
