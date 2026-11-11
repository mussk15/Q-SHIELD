import os
import tempfile
import json
import socket
import uuid
import threading
from datetime import datetime, timezone
from pathlib import Path
from getpass import getpass


from cryptography.exceptions import InvalidTag

from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.keystore import KeyStore
from qshield.net.protocol import send_message, receive_message
from qshield.net.handshake import (
    begin_server_handshake,
    ClientFinish,
    finalize_server_handshake,
    HandshakeError,
)
from qshield.net.secure_filetransfer import receive_encrypted_file
from qshield.monitor.event_bridge import process_event
from qshield.net.server import check_connection_allowed


HOST = "127.0.0.1"
PORT = 5002

EVENT_FILE = Path("data/events.jsonl")
EVENT_LOCK = threading.Lock()
SESSIONS_FILE = Path("data/sessions.jsonl")
SESSION_LOCK = threading.Lock()


def update_session(session_id, status, remote_ip, user_id=None):
    """Create or update one secure file-transfer session."""
    with SESSION_LOCK:
        SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)

        records = []
        existing = None

        if SESSIONS_FILE.exists():
            with SESSIONS_FILE.open("r", encoding="utf-8") as file:
                for line in file:
                    if not line.strip():
                        continue

                    record = json.loads(line)

                    if not isinstance(record, dict):
                        raise ValueError("Invalid session record")

                    if record.get("session_id") == session_id:
                        existing = record
                    else:
                        records.append(record)

        session = {
            "session_id": session_id,
            "user_id": user_id if user_id is not None else (
                existing.get("user_id", "unauthenticated") if existing else "unauthenticated"
            ),
            "remote_ip": remote_ip,
            "status": status,
            "started_at": (
                existing.get("started_at")
                if existing
                else datetime.now(timezone.utc).isoformat()
            ),
        }

        if existing and existing.get("key_fingerprint"):
            session["key_fingerprint"] = existing["key_fingerprint"]

        if status == "Disconnected":
            session["ended_at"] = datetime.now(timezone.utc).isoformat()

        records.append(session)
        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=SESSIONS_FILE.parent,
                prefix=".sessions_",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)

                for record in records:
                    temporary_file.write(
                        json.dumps(record, ensure_ascii=False) + "\n"
                    )

            os.replace(temporary_path, SESSIONS_FILE)

        finally:
            if temporary_path and temporary_path.exists():
                temporary_path.unlink()


def log_event(event_type, outcome, source_ip, session_id,
              severity="INFO", details=None, byte_count=0):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": source_ip,
        "session_id": session_id,
        "bytes": byte_count,
        "severity": severity,
        "source": "secure_file_server",
        "details": details or {},
    }

    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with EVENT_LOCK:
        with EVENT_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")

    try:
        alerts = process_event(event)
        for alert in alerts:
            print(f"[IDS ALERT] {alert.severity}: {alert.title}")
    except Exception as exc:
        print(f"[IDS BRIDGE ERROR] {exc}")


def main():
    password = getpass("Server private-key password: ")

    server_private = KeyStore.load_private_key(
        "keys/server_private.keystore",
        password,
        expected_algorithm=SIGNATURE_ALGORITHM,
    )
    trusted_client = Path("keys/client_public.bin").read_bytes()

    print("Server identity loaded.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        print(f"Secure file server listening on {HOST}:{PORT}")

        conn, address = server.accept()
        allowed, reason = check_connection_allowed(address[0])
        if not allowed:
            print("Connection rejected:", address, "-", reason)
            conn.close()
            return
        source_ip = address[0]
        session_id = str(uuid.uuid4())

        with conn:
            conn.settimeout(120)

            log_event(
                "CLIENT_CONNECTED", "SUCCESS",
                source_ip, session_id,
                details={"service": "secure_file_transfer"},
            )
            update_session(
                session_id,
                "Connected",
                source_ip,
            )

            try:
                state = begin_server_handshake(server_private)

                send_message(
                    conn, state.hello.to_bytes().decode("utf-8")
                )

                client_finish = ClientFinish.from_bytes(
                    receive_message(conn).encode("utf-8")
                )

                result = finalize_server_handshake(
                    state, client_finish, trusted_client
                )

                send_message(
                    conn,
                    result.server_finish.to_bytes().decode("utf-8"),
                )

                print("Post-quantum handshake successful!")
                print("Client identity verified.")

                update_session(
                    session_id,
                    "Connected",
                    source_ip,
                    user_id="verified-client",
                )

                log_event(
                    "HANDSHAKE_SUCCESS", "SUCCESS",
                    source_ip, session_id,
                    details={"service": "secure_file_transfer"},
                )

                print("Waiting for encrypted file...")

                destination = receive_encrypted_file(
                    conn,
                    "data/received_files",
                    result.session_key,
                )

                file_size = destination.stat().st_size

                log_event(
                    "FILE_TRANSFER_SUCCESS", "SUCCESS",
                    source_ip, session_id,
                    details={
                        "filename": destination.name,
                        "destination": str(destination),
                    },
                    byte_count=file_size,
                )

                print("File decrypted and verified successfully!")
                print("Saved at:", destination)

                send_message(conn, "FILE_RECEIVED_AND_VERIFIED")

            except HandshakeError as exc:
                log_event(
                    "HANDSHAKE_FAIL", "FAILED",
                    source_ip, session_id,
                    severity="HIGH",
                    details={"error": str(exc)},
                )
                print("Handshake failed:", exc)

            except InvalidTag:
                log_event(
                    "TAG_FAIL", "FAILED",
                    source_ip, session_id,
                    severity="CRITICAL",
                    details={
                        "error": "Encrypted file chunk authentication failed"
                    },
                )
                print("IDS: Encrypted file authentication failed.")

            except ValueError as exc:
                is_integrity_failure = (
                    "integrity verification failed" in str(exc).lower()
                )

                log_event(
                    "FILE_INTEGRITY_FAIL" if is_integrity_failure
                    else "FILE_TRANSFER_FAIL",
                    "FAILED",
                    source_ip,
                    session_id,
                    severity="HIGH",
                    details={"error": str(exc)},
                )
                print("File transfer failed:", exc)

            except (ConnectionError, OSError, TimeoutError) as exc:
                log_event(
                    "FILE_TRANSFER_FAIL", "FAILED",
                    source_ip, session_id,
                    severity="MEDIUM",
                    details={"error": str(exc)},
                )
                print("Connection or transfer error:", exc)

            finally:
                try:
                    update_session(
                        session_id,
                        "Disconnected",
                        source_ip,
                    )
                except (OSError, ValueError) as exc:
                    print("Session logging error:", exc)
                    
                log_event(
                    "CLIENT_DISCONNECTED", "SUCCESS",
                    source_ip, session_id,
                    details={"service": "secure_file_transfer"},
                )
                print("Client disconnected:", address)


if __name__ == "__main__":
    main()
