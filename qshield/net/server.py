import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

from qshield.net.protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000

MAX_CLIENTS = 5
CLIENT_TIMEOUT = 30

client_slots = threading.BoundedSemaphore(MAX_CLIENTS)

# Save security events in the project logs folder
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_FILE = PROJECT_ROOT / "logs" / "security_events.jsonl"

# Prevent simultaneous threads from mixing log entries
log_lock = threading.Lock()

VALID_SEVERITIES = {"INFO", "WARNING", "ERROR", "CRITICAL"}


def log_event(event_type, severity="INFO", source=None, details=None,
              log_file=None):
    """Save one security event as a JSON line."""

    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Event type must be a non-empty string")

    if severity not in VALID_SEVERITIES:
        raise ValueError("Invalid event severity")

    if source is not None and not isinstance(source, str):
        raise TypeError("Source must be a string or None")

    if details is not None and not isinstance(details, dict):
        raise TypeError("Details must be a dictionary or None")

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "details": details if details is not None else {}
    }

    destination = Path(log_file) if log_file else LOG_FILE
    serialized_event = json.dumps(event, ensure_ascii=False)

    with log_lock:
        destination.parent.mkdir(parents=True, exist_ok=True)

        with destination.open("a", encoding="utf-8") as file:
            file.write(serialized_event + "\n")

    return event


def safe_log_event(event_type, severity="INFO", source=None, details=None):
    """Prevent a logging failure from interrupting server communication."""

    try:
        log_event(event_type, severity, source, details)
    except (OSError, TypeError, ValueError) as error:
        print("Security logging error:", error)


def handle_client(conn, addr):
    client_address = f"{addr[0]}:{addr[1]}"

    print("Connected by:", addr)

    safe_log_event(
        "CLIENT_CONNECTED",
        source=client_address
    )

    try:
        conn.settimeout(CLIENT_TIMEOUT)

        message = receive_message(conn)

        print("Client says:", message)

        send_message(conn, "Message received by Q-SHIELD Server!")

        safe_log_event(
            "MESSAGE_RECEIVED",
            source=client_address,
            details={"message_length": len(message.encode("utf-8"))}
        )

    except socket.timeout:
        print("Client timed out:", addr)

        safe_log_event(
            "CLIENT_TIMEOUT",
            severity="WARNING",
            source=client_address
        )

    except UnicodeDecodeError as error:
        print("Invalid message encoding:", error)

        safe_log_event(
            "INVALID_MESSAGE_ENCODING",
            severity="WARNING",
            source=client_address
        )

    except ValueError as error:
        print("Invalid client message:", error)

        safe_log_event(
            "INVALID_CLIENT_MESSAGE",
            severity="WARNING",
            source=client_address,
            details={"error": str(error)}
        )

    except (ConnectionError, OSError) as error:
        print("Client communication error:", error)

        safe_log_event(
            "COMMUNICATION_ERROR",
            severity="ERROR",
            source=client_address,
            details={"error": str(error)}
        )

    finally:
        try:
            conn.close()
        finally:
            client_slots.release()

        print("Connection closed:", addr)

        safe_log_event(
            "CLIENT_DISCONNECTED",
            source=client_address
        )


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(5)

        print("Q-SHIELD Server is running...")
        print("Waiting for client connections...")
        print("Maximum active clients:", MAX_CLIENTS)
        print("Client timeout:", CLIENT_TIMEOUT, "seconds")

        safe_log_event(
            "SERVER_STARTED",
            source=f"{HOST}:{PORT}",
            details={
                "maximum_clients": MAX_CLIENTS,
                "client_timeout_seconds": CLIENT_TIMEOUT
            }
        )

        while True:
            conn, addr = server.accept()

            if not client_slots.acquire(blocking=False):
                print("Maximum clients reached. Rejecting:", addr)

                safe_log_event(
                    "CONNECTION_REJECTED",
                    severity="WARNING",
                    source=f"{addr[0]}:{addr[1]}",
                    details={"reason": "Maximum active clients reached"}
                )

                conn.close()
                continue

            try:
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    daemon=True
                )

                client_thread.start()

            except Exception as error:
                conn.close()
                client_slots.release()

                safe_log_event(
                    "CLIENT_THREAD_START_FAILED",
                    severity="ERROR",
                    source=f"{addr[0]}:{addr[1]}",
                    details={"error": str(error)}
                )

                raise

    except KeyboardInterrupt:
        print("\nQ-SHIELD Server is shutting down...")

        safe_log_event(
            "SERVER_SHUTDOWN",
            source=f"{HOST}:{PORT}"
        )

    finally:
        server.close()


if __name__ == "__main__":
    start_server()
