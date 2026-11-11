from qshield.net.server import active_sessions_lock
from qshield.net.server import active_sessions
import base64
import json
import socket
import threading
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from qshield.monitor.event_bridge import process_event

from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.keystore import KeyStore
from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.net.protocol import send_message, receive_message
from qshield.net.handshake import (
    begin_server_handshake,
    ClientFinish,
    finalize_server_handshake,
    HandshakeError,
)
from qshield.net.server import check_connection_allowed
from threading  import Lock



HOST = "127.0.0.1"
PORT = 5001
active_sessions = {}
active_sessions_lock = Lock()
AAD = b"QSHIELD_APP_V1"

EVENT_FILE = Path("data/events.jsonl")
EVENT_LOCK = threading.Lock()


def log_event(event_type, outcome, source_ip, session_id,
              severity="INFO", details="", byte_count=0):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": source_ip,
        "session_id": session_id,
        "bytes": byte_count,
        "severity": severity,
        "source": "secure_server",
        "details": details,
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


def handle_client(conn, address, server_private, trusted_client):
    source_ip = address[0]
    session_id = str(uuid.uuid4())
    handshake_complete = False

    try:
        with conn:
            conn.settimeout(60)

            log_event(
                "CLIENT_CONNECTED", "SUCCESS",
                source_ip, session_id
            )

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
                conn, result.server_finish.to_bytes().decode("utf-8")
            )

            handshake_complete = True
            with active_sessions_lock:
                active_sessions[session_id] = conn
                print(f"[SESSION REGISTERED] {session_id}")


            log_event(
                "HANDSHAKE_SUCCESS", "SUCCESS",
                source_ip, session_id,
                details="Client identity verified; session key established"
            )

            encrypted_data = EncryptedMessage.from_bytes(
                base64.b64decode(
                    receive_message(conn), validate=True
                )
            )

            try:
                plaintext = AES256GCM.decrypt(
                    result.session_key,
                    encrypted_data,
                    associated_data=AAD,
                )
            except InvalidTag:
                log_event(
                    "TAG_FAIL", "FAILED", source_ip, session_id,
                    severity="HIGH",
                    details="AES-GCM authentication tag verification failed",
                )
                raise

            log_event(
                "MESSAGE_RECEIVED", "SUCCESS",
                source_ip, session_id,
                byte_count=len(plaintext),
                details="Encrypted application message decrypted",
            )

            print(
                f"[{session_id[:8]}] Decrypted message: "
                f"{plaintext.decode('utf-8', errors='replace')}"
            )

            reply = b"Secure message received by Q-SHIELD server!"

            encrypted_reply = AES256GCM.encrypt(
                result.session_key,
                reply,
                associated_data=AAD,
            )

            send_message(
                conn,
                base64.b64encode(
                    encrypted_reply.to_bytes()
                ).decode("ascii"),
            )

            log_event(
                "MESSAGE_SENT", "SUCCESS",
                source_ip, session_id,
                byte_count=len(reply),
                details="Encrypted server reply sent",
            )

    except HandshakeError as exc:
        log_event(
            "HANDSHAKE_FAIL", "FAILED",
            source_ip, session_id,
            severity="HIGH",
            details=str(exc),
        )
        print(f"[{session_id[:8]}] Handshake failed: {exc}")

    except InvalidTag:
        print(f"[{session_id[:8]}] Message authentication failed.")

    except (ConnectionError, OSError, ValueError, TimeoutError) as exc:
        if not handshake_complete:
            log_event(
                "HANDSHAKE_FAIL", "FAILED",
                source_ip, session_id,
                severity="MEDIUM",
                details=str(exc),
            )
        print(f"[{session_id[:8]}] Connection error: {exc}")

    finally:
        with active_sessions_lock:
            active_sessions.pop(session_id, None)
        log_event(
            "CLIENT_DISCONNECTED", "SUCCESS",
            source_ip, session_id
        )
        print(f"Client disconnected: {address}")


def main():
    password = getpass("Server private-key password: ")

    server_private = KeyStore.load_private_key(
        "keys/server_private.keystore",
        password,
        expected_algorithm=SIGNATURE_ALGORITHM,
    )

    trusted_client = Path(
        "keys/client_public.bin"
    ).read_bytes()

    print("Server identity loaded.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)

        print(f"Q-SHIELD secure server listening on {HOST}:{PORT}")
        print("Waiting for multiple client connections...")

        try:
            while True:
                conn, address = server.accept()
                allowed, reason = check_connection_allowed(address[0])
                if not allowed:
                    print("Connection rejected:", address, "-", reason)
                    conn.close()
                    continue
                print(f"Client connected: {address}")
                worker = threading.Thread(
                    target=handle_client,
                    args=(
                        conn,
                        address,
                        server_private,
                        trusted_client,
                    ),
                    daemon=True
                )
                worker.start()

        except KeyboardInterrupt:
            print("\nQ-SHIELD secure server shutting down.")


if __name__ == "__main__":
    main()
