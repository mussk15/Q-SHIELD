"""Repeatable End-to-End Integration Test for Q-SHIELD.

Demonstrates the complete workflow across all four team member subsystems:
1. Post-Quantum Cryptography (ML-KEM-768, ML-DSA-65, HKDF, AES-256-GCM)
2. Secure Networking & File Transfer (TCP framing, sessions, file integrity)
3. Network Monitoring & IDS (feature extraction, rule-based alerts, ML anomaly alerts)
4. Dashboard, Evidence & Response (command queue, kill_session execution, hash-chain evidence)
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import threading
import time
from pathlib import Path

import pytest

from cryptography.exceptions import InvalidTag
from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.crypto.sig import MLDSA65, SignatureKeyPair
from qshield.monitor.alerts import AlertManager
from qshield.monitor.rules import RuleEngine
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
from qshield.net.secure_filetransfer import receive_encrypted_file, send_encrypted_file
from qshield.net.server import (
    active_sessions,
    active_sessions_lock,
    acknowledge_command,
    command_processor,
    command_stop_event,
    execute_command,
    load_processed_command_ids,
    update_session,
)
from response.commands import enqueue_command
from response.evidence import append_event, verify_chain


def test_complete_qshield_e2e_workflow(tmp_path):
    # Setup isolated test data directory
    events_path = tmp_path / "events.jsonl"
    alerts_path = tmp_path / "alerts.jsonl"
    sessions_path = tmp_path / "sessions.jsonl"
    commands_path = tmp_path / "commands.jsonl"
    results_path = tmp_path / "command_results.jsonl"
    evidence_path = tmp_path / "evidence.jsonl"

    # 1. Cryptographic Identity Setup (Member 1)
    sig_engine = MLDSA65()
    server_identity = sig_engine.generate_keypair()
    client_identity = sig_engine.generate_keypair()

    trusted_server_pub = server_identity.public_key
    trusted_client_pub = client_identity.public_key

    # 2. Start Secure TCP Server on loopback (Member 2)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(5)
    host, port = server_sock.getsockname()

    session_id_holder = {}
    server_error = []
    server_done = threading.Event()

    def server_worker():
        try:
            conn, addr = server_sock.accept()
            with conn:
                # Perform Server Handshake
                state = begin_server_handshake(server_identity.secret_key)
                send_message(conn, state.hello.to_bytes().decode("utf-8"))

                raw_client_finish = receive_message(conn).encode("utf-8")
                client_finish = ClientFinish.from_bytes(raw_client_finish)
                handshake_res = finalize_server_handshake(
                    state, client_finish, trusted_client_pub
                )
                send_message(conn, handshake_res.server_finish.to_bytes().decode("utf-8"))

                # Register active session
                sess_id = "e2e-session-" + secrets.token_hex(6)
                session_id_holder["session_id"] = sess_id
                session_id_holder["key"] = handshake_res.session_key

                with active_sessions_lock:
                    active_sessions[sess_id] = conn

                # Write initial session record
                with sessions_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({
                        "session_id": sess_id,
                        "user_id": "verified-client",
                        "remote_ip": addr[0],
                        "status": "Active",
                        "started_at": "2026-11-11T12:00:00Z",
                    }) + "\n")

                # Receive encrypted application message
                enc_msg_b64 = receive_message(conn)
                enc_obj = EncryptedMessage.from_bytes(base64.b64decode(enc_msg_b64))
                plaintext = AES256GCM.decrypt(
                    handshake_res.session_key, enc_obj, associated_data=b"QSHIELD_APP_V1"
                )
                assert plaintext == b"Hello Post-Quantum World"

                # Send encrypted reply
                reply = AES256GCM.encrypt(
                    handshake_res.session_key, b"Q-SHIELD ACK", associated_data=b"QSHIELD_APP_V1"
                )
                send_message(conn, base64.b64encode(reply.to_bytes()).decode("ascii"))

                # Keep connection alive until closed by kill_session command
                try:
                    while True:
                        data = receive_message(conn)
                        if not data:
                            break
                except (ConnectionError, OSError):
                    pass
                finally:
                    with active_sessions_lock:
                        active_sessions.pop(sess_id, None)
                    # Mark disconnected in sessions.jsonl
                    with sessions_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps({
                            "session_id": sess_id,
                            "user_id": "verified-client",
                            "remote_ip": addr[0],
                            "status": "Disconnected",
                        }) + "\n")
        except Exception as exc:
            server_error.append(exc)
        finally:
            server_done.set()

    server_thread = threading.Thread(target=server_worker, daemon=True)
    server_thread.start()

    # 3. Connect Trusted Client and Perform Handshake
    client_conn = socket.create_connection((host, port), timeout=5.0)
    try:
        raw_hello = receive_message(client_conn).encode("utf-8")
        server_hello = ServerHello.from_bytes(raw_hello)
        client_res = respond_to_server(server_hello, trusted_server_pub, client_identity)
        send_message(client_conn, client_res.client_finish.to_bytes().decode("utf-8"))

        raw_server_finish = receive_message(client_conn).encode("utf-8")
        server_finish = ServerFinish.from_bytes(raw_server_finish)
        assert client_res.verify_server_finished(server_finish)

        # Exchange encrypted messages
        encrypted_req = AES256GCM.encrypt(
            client_res.session_key, b"Hello Post-Quantum World", associated_data=b"QSHIELD_APP_V1"
        )
        send_message(client_conn, base64.b64encode(encrypted_req.to_bytes()).decode("ascii"))

        enc_reply_b64 = receive_message(client_conn)
        reply_obj = EncryptedMessage.from_bytes(base64.b64decode(enc_reply_b64))
        reply_pt = AES256GCM.decrypt(
            client_res.session_key, reply_obj, associated_data=b"QSHIELD_APP_V1"
        )
        assert reply_pt == b"Q-SHIELD ACK"

        sess_id = session_id_holder["session_id"]
        assert sess_id in active_sessions

        # 4. Perform Secure Encrypted File Transfer over isolated socketpair
        sender_s, receiver_s = socket.socketpair()
        file_to_send = tmp_path / "quantum_report.txt"
        file_content = b"Quantum-Shield classified post-quantum evidence log payload."
        file_to_send.write_bytes(file_content)
        file_dest_dir = tmp_path / "received"

        def f_sender():
            try:
                send_encrypted_file(sender_s, file_to_send, client_res.session_key)
            finally:
                sender_s.close()

        f_thread = threading.Thread(target=f_sender, daemon=True)
        f_thread.start()
        saved_file = receive_encrypted_file(receiver_s, file_dest_dir, client_res.session_key)
        receiver_s.close()
        f_thread.join(timeout=3.0)

        assert saved_file.exists()
        assert saved_file.read_bytes() == file_content

        # 5. Network Monitoring & IDS Alerts (Member 3)
        from qshield.monitor.rules import load_config
        manager = AlertManager(str(alerts_path), cooldown_seconds=0)
        config = load_config()
        config["rules"]["port_scan"]["enabled"] = True
        engine = RuleEngine(config, manager)

        # Simulate suspicious port scan window
        class MockWindow:
            src_ip = "192.168.1.100"
            distinct_dst_ports = 50
            connection_attempts = 50
            syn_count = 1
            rst_count = 0
            half_open_syns = 0

        emitted = engine.evaluate_window(MockWindow())
        assert len(emitted) >= 1
        assert alerts_path.exists()
        alerts = [json.loads(l) for l in alerts_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(alerts) >= 1
        assert alerts[0]["rule_id"] == "PORT_SCAN"

        # 6. Evidence Recording & Hash Chain (Member 4)
        append_event("session_started", {"session_id": sess_id}, path=evidence_path)
        append_event("ids_alert_generated", {"alert_id": alerts[0]["alert_id"]}, path=evidence_path)
        valid, msg = verify_chain(evidence_path)
        assert valid, f"Evidence chain verification failed: {msg}"

        # 7. Analyst Queues `kill_session` Command
        cmd_item = enqueue_command(
            "kill_session", session_id=sess_id, reason="Analyst E2E test", path=commands_path
        )
        assert cmd_item["status"] == "queued"

        # 8. Server Executes `kill_session` and Acknowledges
        execute_command(cmd_item, results_file=results_path, sessions_file=sessions_path)

        # Confirm client connection is terminated
        client_conn.settimeout(2.0)
        data = client_conn.recv(1024)
        assert data == b"", "Client connection should receive EOF upon kill_session termination"

        # Confirm command result acknowledgement
        assert results_path.exists()
        results = [json.loads(l) for l in results_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert any(r["command_id"] == cmd_item["command_id"] and r["status"] == "executed" for r in results)

    finally:
        client_conn.close()
        server_sock.close()
        server_thread.join(timeout=3.0)

    if server_error:
        raise server_error[0]


def test_complete_qshield_e2e_rekey_workflow(tmp_path):
    """Verify full end-to-end authenticated in-band post-quantum re-key workflow.

    Workflow tested:
    1. Client-server ML-KEM-768 & ML-DSA-65 authenticated handshake (gen 0 key).
    2. Register active secure session for rekeying.
    3. Normal encrypted application messaging under gen 0 key.
    4. Analyst enqueues force_rekey command; server queues request.
    5. At message boundary, server initiates 4-way in-band rekey exchange.
    6. Both endpoints independently derive and confirm replacement key (gen 1).
    7. Server writes executed acknowledgement with generation 1.
    8. Subsequent messages encrypted and decrypted with gen 1 key.
    9. Old gen 0 key is cryptographically invalidated (fails tag verification).
    10. Clean disconnect and session teardown.
    """
    sessions_path = tmp_path / "sessions.jsonl"
    commands_path = tmp_path / "commands.jsonl"
    results_path = tmp_path / "command_results.jsonl"

    sig_engine = MLDSA65()
    server_identity = sig_engine.generate_keypair()
    client_identity = sig_engine.generate_keypair()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(5)
    host, port = server_sock.getsockname()

    session_info: dict[str, Any] = {}
    server_error: list[Exception] = []
    server_done = threading.Event()

    def server_worker():
        try:
            conn, addr = server_sock.accept()
            with conn:
                state = begin_server_handshake(server_identity.secret_key)
                send_message(conn, state.hello.to_bytes().decode("utf-8"))

                raw_client_finish = receive_message(conn).encode("utf-8")
                client_finish = ClientFinish.from_bytes(raw_client_finish)
                handshake_res = finalize_server_handshake(
                    state, client_finish, client_identity.public_key
                )
                send_message(conn, handshake_res.server_finish.to_bytes().decode("utf-8"))

                sess_id = "rekey-session-" + secrets.token_hex(6)
                session_info["session_id"] = sess_id
                session_info["initial_key"] = handshake_res.session_key
                server_key = handshake_res.session_key
                server_generation = 0

                register_rekey_session(sess_id)
                with active_sessions_lock:
                    active_sessions[sess_id] = conn

                try:
                    while True:
                        encoded = receive_message(conn)
                        if not encoded:
                            break
                        enc_msg = EncryptedMessage.from_bytes(
                            base64.b64decode(encoded, validate=True)
                        )
                        plaintext = AES256GCM.decrypt(
                            server_key, enc_msg, associated_data=b"QSHIELD_APP_V1"
                        )
                        msg_str = plaintext.decode("utf-8")

                        if msg_str == "/quit":
                            break

                        pending = take_pending_rekey(sess_id)
                        if pending is not None:
                            next_gen = server_generation + 1
                            rekey_state = begin_server_rekey(
                                server_key, server_identity.secret_key, generation=next_gen
                            )
                            send_message(
                                conn,
                                make_control_frame(REKEY_OFFER_PREFIX, rekey_state.offer.to_bytes()),
                            )
                            resp_frame = receive_message(conn)
                            rekey_resp = RekeyResponse.from_bytes(
                                parse_control_frame(resp_frame, REKEY_RESPONSE_PREFIX)
                            )
                            rekey_res = finalize_server_rekey(
                                rekey_state, rekey_resp, client_identity.public_key
                            )
                            send_message(
                                conn,
                                make_control_frame(REKEY_FINISHED_PREFIX, rekey_res.finished.to_bytes()),
                            )
                            commit_frame = receive_message(conn)
                            rekey_commit = RekeyCommit.from_bytes(
                                parse_control_frame(commit_frame, REKEY_COMMIT_PREFIX)
                            )
                            assert rekey_res.verify_client_commit(rekey_commit)

                            server_key = rekey_res.session_key
                            server_generation = next_gen
                            session_info["final_key"] = server_key
                            session_info["final_generation"] = server_generation

                            acknowledge_command(
                                pending,
                                "executed",
                                f"Authenticated post-quantum re-key completed (generation {server_generation})",
                                results_file=results_path,
                            )

                        reply = f"ACK: {msg_str}".encode("utf-8")
                        enc_reply = AES256GCM.encrypt(
                            server_key, reply, associated_data=b"QSHIELD_APP_V1"
                        )
                        send_message(
                            conn,
                            base64.b64encode(enc_reply.to_bytes()).decode("ascii"),
                        )
                finally:
                    unregister_rekey_session(sess_id)
                    with active_sessions_lock:
                        active_sessions.pop(sess_id, None)
        except Exception as exc:
            server_error.append(exc)
        finally:
            server_done.set()

    server_thread = threading.Thread(target=server_worker, daemon=True)
    server_thread.start()

    client_conn = socket.create_connection((host, port), timeout=5.0)
    try:
        # Handshake
        raw_hello = receive_message(client_conn).encode("utf-8")
        server_hello = ServerHello.from_bytes(raw_hello)
        client_res = respond_to_server(
            server_hello, server_identity.public_key, client_identity
        )
        send_message(client_conn, client_res.client_finish.to_bytes().decode("utf-8"))

        raw_server_finish = receive_message(client_conn).encode("utf-8")
        server_finish = ServerFinish.from_bytes(raw_server_finish)
        assert client_res.verify_server_finished(server_finish)

        client_key = client_res.session_key
        client_generation = 0
        old_client_key = client_key

        # Message 1 under gen 0 key
        enc_msg1 = AES256GCM.encrypt(
            client_key, b"Message 1 before rekey", associated_data=b"QSHIELD_APP_V1"
        )
        send_message(client_conn, base64.b64encode(enc_msg1.to_bytes()).decode("ascii"))
        reply1_raw = receive_message(client_conn)
        reply1_enc = EncryptedMessage.from_bytes(base64.b64decode(reply1_raw))
        reply1_pt = AES256GCM.decrypt(
            client_key, reply1_enc, associated_data=b"QSHIELD_APP_V1"
        )
        assert reply1_pt == b"ACK: Message 1 before rekey"

        sess_id = session_info["session_id"]

        # Analyst submits force_rekey
        cmd = enqueue_command(
            "force_rekey", session_id=sess_id, reason="Test rekey", path=commands_path
        )
        execute_command(cmd, results_file=results_path, sessions_file=sessions_path)

        # Message 2 triggers re-key processing at server
        enc_msg2 = AES256GCM.encrypt(
            client_key, b"Message 2 trigger rekey", associated_data=b"QSHIELD_APP_V1"
        )
        send_message(client_conn, base64.b64encode(enc_msg2.to_bytes()).decode("ascii"))

        # Client receives in-band control frame
        incoming_frame = receive_message(client_conn)
        assert incoming_frame.startswith(REKEY_OFFER_PREFIX)

        offer = RekeyOffer.from_bytes(
            parse_control_frame(incoming_frame, REKEY_OFFER_PREFIX)
        )
        client_rekey = respond_to_rekey(
            offer, client_key, server_identity.public_key, client_identity,
            expected_generation=client_generation + 1,
        )
        send_message(
            client_conn,
            make_control_frame(REKEY_RESPONSE_PREFIX, client_rekey.response.to_bytes()),
        )

        fin_frame = receive_message(client_conn)
        finished = RekeyFinished.from_bytes(
            parse_control_frame(fin_frame, REKEY_FINISHED_PREFIX)
        )
        assert client_rekey.verify_server_finished(finished)

        send_message(
            client_conn,
            make_control_frame(
                REKEY_COMMIT_PREFIX,
                client_rekey.create_client_commit().to_bytes(),
            ),
        )

        client_key = client_rekey.session_key
        client_generation = offer.generation
        assert client_generation == 1

        # Now receive application response to Message 2 under new gen 1 key
        reply2_raw = receive_message(client_conn)
        reply2_enc = EncryptedMessage.from_bytes(base64.b64decode(reply2_raw))
        reply2_pt = AES256GCM.decrypt(
            client_key, reply2_enc, associated_data=b"QSHIELD_APP_V1"
        )
        assert reply2_pt == b"ACK: Message 2 trigger rekey"

        # Verify both sides derived the exact same replacement key
        assert client_key == session_info["final_key"]
        assert client_key != old_client_key

        # Message 3 under gen 1 key
        enc_msg3 = AES256GCM.encrypt(
            client_key, b"Message 3 after rekey", associated_data=b"QSHIELD_APP_V1"
        )
        send_message(client_conn, base64.b64encode(enc_msg3.to_bytes()).decode("ascii"))
        reply3_raw = receive_message(client_conn)
        reply3_enc = EncryptedMessage.from_bytes(base64.b64decode(reply3_raw))
        reply3_pt = AES256GCM.decrypt(
            client_key, reply3_enc, associated_data=b"QSHIELD_APP_V1"
        )
        assert reply3_pt == b"ACK: Message 3 after rekey"

        # Cryptographic proof: old gen 0 key CANNOT decrypt Message 3 ciphertext
        with pytest.raises(InvalidTag):
            AES256GCM.decrypt(
                old_client_key, enc_msg3, associated_data=b"QSHIELD_APP_V1"
            )

        # Verify command results log
        results_lines = [
            json.loads(line)
            for line in results_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert any(r["command_id"] == cmd["command_id"] and r["status"] == "queued" for r in results_lines)
        assert any(r["command_id"] == cmd["command_id"] and r["status"] == "executed" for r in results_lines)

        # Clean disconnect
        enc_quit = AES256GCM.encrypt(
            client_key, b"/quit", associated_data=b"QSHIELD_APP_V1"
        )
        send_message(client_conn, base64.b64encode(enc_quit.to_bytes()).decode("ascii"))

    finally:
        client_conn.close()
        server_sock.close()
        server_thread.join(timeout=3.0)

    if server_error:
        raise server_error[0]
