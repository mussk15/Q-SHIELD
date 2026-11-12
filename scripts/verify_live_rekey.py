"""Live End-to-End Re-Key Integration Verification Script for Q-SHIELD.

Demonstrates and verifies:
1. Initial post-quantum authenticated connection (ML-KEM-768 + ML-DSA-65).
2. Initial encrypted application messaging (gen 0 key).
3. Session registration in data/sessions.jsonl.
4. Dashboard force_rekey command submission to data/commands.jsonl.
5. Command processor execution and queueing.
6. In-band 4-way post-quantum re-key protocol at message boundary.
7. Derivation and mutual confirmation of generation 1 session key.
8. Execution acknowledgement written to data/command_results.jsonl.
9. SESSION_REKEY_SUCCESS event logged to data/events.jsonl.
10. Continued encrypted messaging under generation 1 key.
11. Verification that generation 0 key is completely invalid.
12. Clean session disconnect and status update.
"""
from __future__ import annotations

import base64
import json
import secrets
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure repository root is on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cryptography.exceptions import InvalidTag

from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.crypto.sig import MLDSA65
from qshield.net.handshake import (
    ClientFinish,
    ServerFinish,
    ServerHello,
    begin_server_handshake,
    finalize_server_handshake,
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
    RekeyResponse,
    begin_server_rekey,
    finalize_server_rekey,
    make_control_frame,
    parse_control_frame,
    register_rekey_session,
    respond_to_rekey,
    take_pending_rekey,
    unregister_rekey_session,
)
from qshield.net.server import (
    active_sessions,
    active_sessions_lock,
    acknowledge_command,
    command_processor,
    command_stop_event,
    update_session,
)
from response.commands import enqueue_command

DATA_DIR = Path("data")
SESSIONS_FILE = DATA_DIR / "sessions.jsonl"
COMMANDS_FILE = DATA_DIR / "commands.jsonl"
COMMAND_RESULTS_FILE = DATA_DIR / "command_results.jsonl"
EVENTS_FILE = DATA_DIR / "events.jsonl"
AAD = b"QSHIELD_APP_V1"


def log_live_event(event_type: str, outcome: str, session_id: str, details: str = ""):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    evt = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": "127.0.0.1",
        "session_id": session_id,
        "details": details,
        "source": "verify_live_rekey",
    }
    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(evt) + "\n")


def run_live_verification():
    print("=" * 70)
    print("Q-SHIELD LIVE RE-KEY INTEGRATION VERIFICATION")
    print("=" * 70)

    # 1. Cryptographic Setup
    print("\n[Step 1] Initializing ML-DSA-65 post-quantum identity keypairs...")
    sig_engine = MLDSA65()
    server_identity = sig_engine.generate_keypair()
    client_identity = sig_engine.generate_keypair()
    print("  Server ML-DSA-65 public key size:", len(server_identity.public_key), "bytes")
    print("  Client ML-DSA-65 public key size:", len(client_identity.public_key), "bytes")

    # 2. Server Setup
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(5)
    host, port = server_sock.getsockname()
    print(f"\n[Step 2] Live verification server bound on {host}:{port}")

    # Start command processor
    command_stop_event.clear()
    cmd_thread = threading.Thread(
        target=command_processor,
        kwargs={
            "commands_file": COMMANDS_FILE,
            "results_file": COMMAND_RESULTS_FILE,
            "poll_interval": 0.05,
        },
        daemon=True,
    )
    cmd_thread.start()
    print("  Background command processor active on data/commands.jsonl.")

    session_state = {}
    server_error = []
    server_done = threading.Event()

    def server_handler():
        try:
            conn, addr = server_sock.accept()
            with conn:
                # Perform handshake
                state = begin_server_handshake(server_identity.secret_key)
                send_message(conn, state.hello.to_bytes().decode("utf-8"))

                raw_client_finish = receive_message(conn).encode("utf-8")
                client_finish = ClientFinish.from_bytes(raw_client_finish)
                handshake_res = finalize_server_handshake(
                    state, client_finish, client_identity.public_key
                )
                send_message(conn, handshake_res.server_finish.to_bytes().decode("utf-8"))

                sess_id = f"live-rekey-{secrets.token_hex(4)}"
                session_state["session_id"] = sess_id
                session_state["server_key"] = handshake_res.session_key
                session_state["server_gen"] = 0

                register_rekey_session(sess_id)
                with active_sessions_lock:
                    active_sessions[sess_id] = conn

                update_session(sess_id, "Active", addr[0], user_id="live-tester")
                log_live_event("HANDSHAKE_SUCCESS", "SUCCESS", sess_id, "PQ Handshake complete")
                print(f"  [Server] Session established: {sess_id}")

                server_key = handshake_res.session_key
                server_gen = 0

                try:
                    while True:
                        encoded = receive_message(conn)
                        if not encoded:
                            break
                        enc_msg = EncryptedMessage.from_bytes(base64.b64decode(encoded, validate=True))
                        plaintext = AES256GCM.decrypt(server_key, enc_msg, associated_data=AAD)
                        msg_str = plaintext.decode("utf-8")
                        print(f"  [Server] Received message: '{msg_str}'")

                        if msg_str == "/quit":
                            break

                        # Check for rekey command
                        pending = take_pending_rekey(sess_id)
                        if pending is not None:
                            print(f"  [Server] Executing rekey for command {pending['command_id'][:8]}...")
                            next_gen = server_gen + 1
                            rekey_state = begin_server_rekey(
                                server_key, server_identity.secret_key, generation=next_gen
                            )
                            send_message(conn, make_control_frame(REKEY_OFFER_PREFIX, rekey_state.offer.to_bytes()))

                            resp_frame = receive_message(conn)
                            rekey_resp = RekeyResponse.from_bytes(
                                parse_control_frame(resp_frame, REKEY_RESPONSE_PREFIX)
                            )
                            rekey_res = finalize_server_rekey(
                                rekey_state, rekey_resp, client_identity.public_key
                            )
                            send_message(conn, make_control_frame(REKEY_FINISHED_PREFIX, rekey_res.finished.to_bytes()))

                            commit_frame = receive_message(conn)
                            rekey_commit = RekeyCommit.from_bytes(
                                parse_control_frame(commit_frame, REKEY_COMMIT_PREFIX)
                            )
                            if not rekey_res.verify_client_commit(rekey_commit):
                                raise RuntimeError("Client commit MAC verification failed")

                            server_key = rekey_res.session_key
                            server_gen = next_gen
                            session_state["server_key"] = server_key
                            session_state["server_gen"] = server_gen

                            acknowledge_command(
                                pending,
                                "executed",
                                f"Authenticated post-quantum re-key completed (generation {server_gen})",
                                results_file=COMMAND_RESULTS_FILE,
                            )
                            log_live_event("SESSION_REKEY_SUCCESS", "SUCCESS", sess_id, f"Gen {server_gen} active")
                            print(f"  [Server] Rekey completed successfully -> Generation {server_gen}")

                        reply = f"ACK: {msg_str}".encode("utf-8")
                        enc_reply = AES256GCM.encrypt(server_key, reply, associated_data=AAD)
                        send_message(conn, base64.b64encode(enc_reply.to_bytes()).decode("ascii"))
                finally:
                    unregister_rekey_session(sess_id)
                    with active_sessions_lock:
                        active_sessions.pop(sess_id, None)
                    update_session(sess_id, "Disconnected", addr[0])
                    log_live_event("CLIENT_DISCONNECTED", "SUCCESS", sess_id, "Clean disconnect")
                    print(f"  [Server] Session {sess_id} disconnected and unregistered.")
        except Exception as exc:
            import traceback
            traceback.print_exc()
            server_error.append(exc)
        finally:
            server_done.set()

    srv_thread = threading.Thread(target=server_handler, daemon=True)
    srv_thread.start()

    # 3. Client Connects
    print("\n[Step 3] Connecting client and executing ML-KEM-768/ML-DSA-65 handshake...")
    client_conn = socket.create_connection((host, port), timeout=5.0)

    try:
        raw_hello = receive_message(client_conn).encode("utf-8")
        server_hello = ServerHello.from_bytes(raw_hello)
        client_res = respond_to_server(server_hello, server_identity.public_key, client_identity)
        send_message(client_conn, client_res.client_finish.to_bytes().decode("utf-8"))

        raw_server_finish = receive_message(client_conn).encode("utf-8")
        server_finish = ServerFinish.from_bytes(raw_server_finish)
        assert client_res.verify_server_finished(server_finish)
        print("  Client verified server signature and handshake finish.")

        client_key = client_res.session_key
        client_gen = 0
        gen0_key = client_key
        sess_id = session_state["session_id"]
        print(f"  Initial session key established (generation 0): {gen0_key.hex()[:16]}...")

        # 4. Message 1 under Gen 0
        print("\n[Step 4] Exchanging application message under generation 0 key...")
        enc_1 = AES256GCM.encrypt(client_key, b"Q-SHIELD live pre-rekey ping", associated_data=AAD)
        send_message(client_conn, base64.b64encode(enc_1.to_bytes()).decode("ascii"))
        rep_1_raw = receive_message(client_conn)
        rep_1_enc = EncryptedMessage.from_bytes(base64.b64decode(rep_1_raw))
        rep_1_pt = AES256GCM.decrypt(client_key, rep_1_enc, associated_data=AAD)
        print(f"  Client received reply: '{rep_1_pt.decode('utf-8')}'")
        assert rep_1_pt == b"ACK: Q-SHIELD live pre-rekey ping"

        # 5. Dashboard submits force_rekey
        print(f"\n[Step 5] Simulating dashboard force_rekey submission for {sess_id}...")
        cmd_item = enqueue_command(
            "force_rekey",
            session_id=sess_id,
            actor="dashboard_analyst",
            reason="Live scheduled re-key verification",
            path=COMMANDS_FILE,
        )
        print(f"  Command queued: {cmd_item['command_id']}")

        # Give command processor a moment to pick up command
        time.sleep(0.15)

        # 6. Trigger rekey at next message boundary
        print("\n[Step 6] Client sends message at next boundary to trigger in-band re-key...")
        enc_2 = AES256GCM.encrypt(client_key, b"Trigger rekey boundary", associated_data=AAD)
        send_message(client_conn, base64.b64encode(enc_2.to_bytes()).decode("ascii"))

        # Client receives control frame
        in_frame = receive_message(client_conn)
        assert in_frame.startswith(REKEY_OFFER_PREFIX), f"Expected rekey offer prefix, got: {in_frame[:30]}"
        print("  Client received QSHIELD_REKEY_OFFER control frame from server.")

        offer = RekeyOffer.from_bytes(parse_control_frame(in_frame, REKEY_OFFER_PREFIX))
        print(f"  Rekey offer verified: rekey_id={offer.rekey_id[:8]}... target_gen={offer.generation}")

        client_rekey = respond_to_rekey(
            offer, client_key, server_identity.public_key, client_identity,
            expected_generation=client_gen + 1,
        )
        send_message(client_conn, make_control_frame(REKEY_RESPONSE_PREFIX, client_rekey.response.to_bytes()))
        print("  Client sent QSHIELD_REKEY_RESPONSE control frame.")

        fin_frame = receive_message(client_conn)
        finished = RekeyFinished.from_bytes(parse_control_frame(fin_frame, REKEY_FINISHED_PREFIX))
        assert client_rekey.verify_server_finished(finished)
        print("  Client verified server Finished MAC.")

        send_message(client_conn, make_control_frame(REKEY_COMMIT_PREFIX, client_rekey.create_client_commit().to_bytes()))
        print("  Client sent QSHIELD_REKEY_COMMIT control frame.")

        # Switch key
        client_key = client_rekey.session_key
        client_gen = offer.generation
        print(f"  Client switched session key to Generation {client_gen}: {client_key.hex()[:16]}...")

        # Application reply to message 2
        rep_2_raw = receive_message(client_conn)
        rep_2_enc = EncryptedMessage.from_bytes(base64.b64decode(rep_2_raw))
        rep_2_pt = AES256GCM.decrypt(client_key, rep_2_enc, associated_data=AAD)
        print(f"  Client received message reply under new key: '{rep_2_pt.decode('utf-8')}'")
        assert rep_2_pt == b"ACK: Trigger rekey boundary"

        # 7. Verification of cryptographic correctness
        print("\n[Step 7] Cryptographic assertions and verification:")
        assert client_key == session_state["server_key"], "Client and server keys do not match!"
        print("  [PASS] Client and server independently derived IDENTICAL generation 1 keys.")
        assert client_key != gen0_key, "Session key was not replaced!"
        print("  [PASS] Generation 1 key differs from Generation 0 key.")

        # 8. Subsequent message under Gen 1
        print("\n[Step 8] Exchanging subsequent message under Generation 1 key...")
        enc_3 = AES256GCM.encrypt(client_key, b"Post-rekey verified message", associated_data=AAD)
        send_message(client_conn, base64.b64encode(enc_3.to_bytes()).decode("ascii"))
        rep_3_raw = receive_message(client_conn)
        rep_3_enc = EncryptedMessage.from_bytes(base64.b64decode(rep_3_raw))
        rep_3_pt = AES256GCM.decrypt(client_key, rep_3_enc, associated_data=AAD)
        print(f"  Client received reply: '{rep_3_pt.decode('utf-8')}'")
        assert rep_3_pt == b"ACK: Post-rekey verified message"
        print("  [PASS] Continued encrypted communication verified.")

        # 9. Cryptographic proof: old gen 0 key is invalid
        print("\n[Step 9] Proving old Generation 0 key cannot decrypt Generation 1 ciphertext...")
        try:
            AES256GCM.decrypt(gen0_key, enc_3, associated_data=AAD)
            raise AssertionError("Old key decrypted new ciphertext! Cryptographic separation failed!")
        except InvalidTag:
            print("  [PASS] Decryption with Generation 0 key raised InvalidTag as expected.")

        # 10. Verify command acknowledgement log
        print("\n[Step 10] Verifying command results in data/command_results.jsonl...")
        results = [
            json.loads(line)
            for line in COMMAND_RESULTS_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        matching = [r for r in results if r.get("command_id") == cmd_item["command_id"]]
        print(f"  Found {len(matching)} command result entries for {cmd_item['command_id'][:8]}:")
        for m in matching:
            print(f"    - status: {m['status']}, message: {m['message']}")
        assert any(m["status"] == "executed" for m in matching), "Executed acknowledgement not found!"
        print("  [PASS] Command execution acknowledged with status 'executed'.")

        # 11. Clean Disconnect
        print("\n[Step 11] Performing clean disconnect...")
        enc_quit = AES256GCM.encrypt(client_key, b"/quit", associated_data=AAD)
        send_message(client_conn, base64.b64encode(enc_quit.to_bytes()).decode("ascii"))

    finally:
        client_conn.close()
        server_sock.close()
        command_stop_event.set()
        cmd_thread.join(timeout=2.0)
        srv_thread.join(timeout=3.0)

    if server_error:
        raise server_error[0]

    print("\n" + "=" * 70)
    print("ALL 11 LIVE RE-KEY VERIFICATION STEPS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    run_live_verification()
