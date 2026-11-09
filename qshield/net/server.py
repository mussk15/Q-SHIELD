import json
import os
import socket
import tempfile
import threading
import time
import uuid

from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from qshield.net.protocol import send_message, receive_message
from response.blocklist import is_blocked


# --------------------------------------------------
# SERVER CONFIGURATION
# --------------------------------------------------

HOST = "127.0.0.1"
PORT = 5000

MAX_CLIENTS = 5
CLIENT_TIMEOUT = 30

# Rate-limiting configuration
RATE_LIMIT_ATTEMPTS = 10
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_COOLDOWN = 60

client_slots = threading.BoundedSemaphore(MAX_CLIENTS)

connection_attempts = defaultdict(deque)
temporarily_blocked = {}
rate_limit_lock = threading.Lock()


# --------------------------------------------------
# DATA DIRECTORY
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")

configured_dir = Path(os.getenv("QSHIELD_DATA_DIR", "data"))

DATA_DIR = (
    configured_dir
    if configured_dir.is_absolute()
    else PROJECT_ROOT / configured_dir
)

EVENTS_FILE = DATA_DIR / "events.jsonl"
SESSIONS_FILE = DATA_DIR / "sessions.jsonl"

log_lock = threading.Lock()
session_lock = threading.Lock()

VALID_SEVERITIES = {"INFO", "WARNING", "ERROR", "CRITICAL"}


# --------------------------------------------------
# SECURITY EVENT LOGGING
# --------------------------------------------------

def log_event(
    event_type,
    severity="INFO",
    source=None,
    details=None,
    log_file=None,
    outcome="success",
    source_ip=None,
    session_id=None,
    byte_count=0
):
    """Write a structured security event for the dashboard."""

    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Event type must be a non-empty string")

    if severity not in VALID_SEVERITIES:
        raise ValueError("Invalid event severity")

    if source is not None and not isinstance(source, str):
        raise TypeError("Source must be a string or None")

    if details is not None and not isinstance(details, dict):
        raise TypeError("Details must be a dictionary or None")

    if not isinstance(outcome, str) or not outcome:
        raise ValueError("Outcome must be a non-empty string")

    if (
        not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count < 0
    ):
        raise ValueError("Byte count must be a non-negative integer")

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type.lower(),
        "outcome": outcome,
        "source_ip": source_ip,
        "session_id": session_id,
        "bytes": byte_count,
        "severity": severity,
        "source": source,
        "details": details if details is not None else {}
    }

    destination = Path(log_file) if log_file else EVENTS_FILE
    serialized_event = json.dumps(event, ensure_ascii=False)

    with log_lock:
        destination.parent.mkdir(parents=True, exist_ok=True)

        with destination.open("a", encoding="utf-8") as file:
            file.write(serialized_event + "\n")

    return event


def safe_log_event(*args, **kwargs):
    """Prevent logging errors from interrupting server communication."""

    try:
        return log_event(*args, **kwargs)
    except (OSError, TypeError, ValueError) as error:
        print("Security logging error:", error)
        return None


# --------------------------------------------------
# CONNECTION SECURITY: BLOCKLIST + RATE LIMITING
# --------------------------------------------------

def check_connection_allowed(ip):
    """Check dashboard blocklist and connection rate limits."""

    # Check the dashboard-managed IP blocklist.
    try:
        if is_blocked(ip, DATA_DIR / "blocklist.json"):
            return False, "IP address is on the dashboard blocklist"

    except (OSError, RuntimeError, ValueError) as error:
        print("Blocklist check failed:", error)
        return False, "Blocklist could not be checked"

    now = time.monotonic()

    with rate_limit_lock:

        # Check whether this IP is in its temporary cooldown.
        blocked_until = temporarily_blocked.get(ip)

        if blocked_until is not None:

            if now < blocked_until:
                return False, "Connection rate limit cooldown"

            temporarily_blocked.pop(ip, None)

        attempts = connection_attempts[ip]

        # Remove attempts older than the rolling time window.
        while attempts and now - attempts[0] >= RATE_LIMIT_WINDOW:
            attempts.popleft()

        # Reject if the IP has reached its attempt limit.
        if len(attempts) >= RATE_LIMIT_ATTEMPTS:

            temporarily_blocked[ip] = now + RATE_LIMIT_COOLDOWN

            return False, "Too many connection attempts"

        attempts.append(now)

        return True, "Allowed"


# --------------------------------------------------
# SESSION MANAGEMENT
# --------------------------------------------------

def update_session(session_id, status, remote_ip, started_at=None):
    """Create or update a session record without duplicate IDs."""

    with session_lock:

        SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)

        records = []
        existing = None

        if SESSIONS_FILE.exists():

            with SESSIONS_FILE.open("r", encoding="utf-8") as file:

                for line in file:

                    if not line.strip():
                        continue

                    try:
                        record = json.loads(line)

                    except json.JSONDecodeError as error:
                        raise ValueError(
                            "Existing sessions.jsonl contains invalid JSON"
                        ) from error

                    if not isinstance(record, dict):
                        raise ValueError(
                            "Existing session record must be a JSON object"
                        )

                    if record.get("session_id") == session_id:
                        existing = record
                    else:
                        records.append(record)

        session = {
            "session_id": session_id,
            "user_id": "unauthenticated",
            "remote_ip": remote_ip,
            "status": status,
            "started_at": (
                existing.get("started_at")
                if existing
                else started_at or datetime.now(timezone.utc).isoformat()
            )
        }

        if status == "Disconnected":
            session["ended_at"] = datetime.now(timezone.utc).isoformat()

        records.append(session)

        temporary_path = None

        try:

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=DATA_DIR,
                prefix=".sessions_",
                suffix=".tmp",
                delete=False
            ) as temporary_file:

                temporary_path = Path(temporary_file.name)

                for record in records:
                    temporary_file.write(
                        json.dumps(record, ensure_ascii=False) + "\n"
                    )

                temporary_file.flush()
                os.fsync(temporary_file.fileno())

            os.replace(temporary_path, SESSIONS_FILE)

        finally:

            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        return session


# --------------------------------------------------
# CLIENT HANDLER
# --------------------------------------------------

def handle_client(conn, addr):

    client_address = f"{addr[0]}:{addr[1]}"

    session_id = f"session-{uuid.uuid4().hex}"

    started_at = datetime.now(timezone.utc).isoformat()

    print("Connected by:", addr)

    try:

        update_session(
            session_id,
            "Active",
            addr[0],
            started_at
        )

    except (OSError, ValueError) as error:

        print("Unable to create session:", error)

        conn.close()
        client_slots.release()

        return

    safe_log_event(
        "client_connected",
        source=client_address,
        source_ip=addr[0],
        session_id=session_id
    )

    try:

        conn.settimeout(CLIENT_TIMEOUT)

        message = receive_message(conn)

        message_bytes = len(message.encode("utf-8"))

        print("Client says:", message)

        send_message(
            conn,
            "Message received by Q-SHIELD Server!"
        )

        safe_log_event(
            "message_received",
            source=client_address,
            source_ip=addr[0],
            session_id=session_id,
            byte_count=message_bytes
        )

    except socket.timeout:

        print("Client timed out:", addr)

        safe_log_event(
            "client_timeout",
            severity="WARNING",
            outcome="timeout",
            source=client_address,
            source_ip=addr[0],
            session_id=session_id
        )

    except UnicodeDecodeError as error:

        print("Invalid message encoding:", error)

        safe_log_event(
            "invalid_message_encoding",
            severity="WARNING",
            outcome="rejected",
            source=client_address,
            source_ip=addr[0],
            session_id=session_id
        )

    except ValueError as error:

        print("Invalid client message:", error)

        safe_log_event(
            "invalid_client_message",
            severity="WARNING",
            outcome="rejected",
            source=client_address,
            source_ip=addr[0],
            session_id=session_id,
            details={"error": str(error)}
        )

    except (ConnectionError, OSError) as error:

        print("Client communication error:", error)

        safe_log_event(
            "communication_error",
            severity="ERROR",
            outcome="failure",
            source=client_address,
            source_ip=addr[0],
            session_id=session_id,
            details={"error": str(error)}
        )

    finally:

        try:
            conn.close()

        finally:

            try:

                update_session(
                    session_id,
                    "Disconnected",
                    addr[0],
                    started_at
                )

            except (OSError, ValueError) as error:
                print("Session update error:", error)

            client_slots.release()

        print("Connection closed:", addr)

        safe_log_event(
            "client_disconnected",
            source=client_address,
            source_ip=addr[0],
            session_id=session_id
        )


# --------------------------------------------------
# START SERVER
# --------------------------------------------------

def start_server():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    try:

        server.bind((HOST, PORT))
        server.listen(5)

        print("Q-SHIELD Server is running...")
        print("Waiting for client connections...")
        print("Maximum active clients:", MAX_CLIENTS)
        print("Client timeout:", CLIENT_TIMEOUT, "seconds")
        print("Connection attempts allowed:", RATE_LIMIT_ATTEMPTS)
        print("Rate limit window:", RATE_LIMIT_WINDOW, "seconds")
        print("Rate limit cooldown:", RATE_LIMIT_COOLDOWN, "seconds")
        print("Dashboard data directory:", DATA_DIR)

        safe_log_event(
            "server_started",
            source=f"{HOST}:{PORT}",
            source_ip=HOST,
            details={
                "maximum_clients": MAX_CLIENTS,
                "client_timeout_seconds": CLIENT_TIMEOUT,
                "rate_limit_attempts": RATE_LIMIT_ATTEMPTS,
                "rate_limit_window_seconds": RATE_LIMIT_WINDOW,
                "rate_limit_cooldown_seconds": RATE_LIMIT_COOLDOWN
            }
        )

        while True:

            conn, addr = server.accept()

            # Check blocklist and rate limit before creating a session.
            allowed, reason = check_connection_allowed(addr[0])

            if not allowed:

                print("Connection rejected:", addr, "-", reason)

                safe_log_event(
                    "connection_rejected",
                    severity="WARNING",
                    outcome="rejected",
                    source=f"{addr[0]}:{addr[1]}",
                    source_ip=addr[0],
                    details={"reason": reason}
                )

                conn.close()
                continue

            # Enforce maximum simultaneous clients.
            if not client_slots.acquire(blocking=False):

                print("Maximum clients reached. Rejecting:", addr)

                safe_log_event(
                    "connection_rejected",
                    severity="WARNING",
                    outcome="rejected",
                    source=f"{addr[0]}:{addr[1]}",
                    source_ip=addr[0],
                    details={
                        "reason": "Maximum active clients reached"
                    }
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
                    "client_thread_start_failed",
                    severity="ERROR",
                    outcome="failure",
                    source=f"{addr[0]}:{addr[1]}",
                    source_ip=addr[0],
                    details={"error": str(error)}
                )

                raise

    except KeyboardInterrupt:

        print("\nQ-SHIELD Server is shutting down...")

        safe_log_event(
            "server_shutdown",
            source=f"{HOST}:{PORT}",
            source_ip=HOST
        )

    finally:

        server.close()


if __name__ == "__main__":
    start_server()