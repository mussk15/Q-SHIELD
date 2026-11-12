import json
import pytest

from response.commands import enqueue_command


import json
import socket
import threading
import time
import pytest

from response.commands import enqueue_command
from qshield.net.server import (
    active_sessions,
    active_sessions_lock,
    acknowledge_command,
    execute_command,
    load_processed_command_ids,
    command_processor,
    command_stop_event,
)
from qshield.net.rekey import (
    register_rekey_session,
    unregister_rekey_session,
    take_pending_rekey,
)


def test_valid_command_is_queued(tmp_path):
    path = tmp_path / "commands.jsonl"
    item = enqueue_command("kill_session", session_id="session-01", path=path)
    saved = json.loads(path.read_text(encoding="utf-8").strip())
    assert saved["command_id"] == item["command_id"]
    assert saved["command"] == "kill_session"
    assert saved["status"] == "queued"


def test_unsupported_command_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        enqueue_command("run_shell", session_id="session-01", path=tmp_path / "commands.jsonl")


def test_empty_session_id_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        enqueue_command("force_rekey", session_id=" ", path=tmp_path / "commands.jsonl")


def test_command_id_uniqueness(tmp_path):
    path = tmp_path / "commands.jsonl"
    item1 = enqueue_command("kill_session", session_id="session-01", path=path)
    item2 = enqueue_command("kill_session", session_id="session-02", path=path)
    assert item1["command_id"] != item2["command_id"]


def test_kill_session_terminates_active_socket(tmp_path):
    server_sock, client_sock = socket.socketpair()
    session_id = "test-session-active-01"
    results_path = tmp_path / "command_results.jsonl"

    with active_sessions_lock:
        active_sessions[session_id] = server_sock

    try:
        command = {
            "command_id": "cmd-kill-001",
            "command": "kill_session",
            "session_id": session_id,
            "status": "queued",
        }
        execute_command(command, results_file=results_path)

        # Client socket should receive EOF when server socket is closed/shutdown
        client_sock.settimeout(2.0)
        data = client_sock.recv(1024)
        assert data == b"", "Client socket should receive EOF after session termination"

        # Verify command result was written
        assert results_path.exists()
        result = json.loads(results_path.read_text(encoding="utf-8").strip())
        assert result["command_id"] == "cmd-kill-001"
        assert result["status"] == "executed"
        assert result["session_id"] == session_id
    finally:
        with active_sessions_lock:
            active_sessions.pop(session_id, None)
        client_sock.close()
        server_sock.close()


def test_kill_session_already_disconnected(tmp_path):
    results_path = tmp_path / "command_results.jsonl"
    sessions_path = tmp_path / "sessions.jsonl"

    session_rec = {
        "session_id": "test-session-disconnected",
        "remote_ip": "127.0.0.1",
        "status": "Disconnected",
    }
    sessions_path.write_text(json.dumps(session_rec) + "\n", encoding="utf-8")

    command = {
        "command_id": "cmd-kill-002",
        "command": "kill_session",
        "session_id": "test-session-disconnected",
        "status": "queued",
    }
    execute_command(command, results_file=results_path, sessions_file=sessions_path)

    result = json.loads(results_path.read_text(encoding="utf-8").strip())
    assert result["command_id"] == "cmd-kill-002"
    assert result["status"] == "already_disconnected"


def test_kill_session_unknown_session_rejected(tmp_path):
    results_path = tmp_path / "command_results.jsonl"
    sessions_path = tmp_path / "sessions.jsonl"

    command = {
        "command_id": "cmd-kill-003",
        "command": "kill_session",
        "session_id": "unknown-nonexistent-session",
        "status": "queued",
    }
    execute_command(command, results_file=results_path, sessions_file=sessions_path)

    result = json.loads(results_path.read_text(encoding="utf-8").strip())
    assert result["command_id"] == "cmd-kill-003"
    assert result["status"] == "rejected"


def test_force_rekey_queued_acknowledgement(tmp_path):
    results_path = tmp_path / "command_results.jsonl"
    session_id = "session-rekey-target"

    register_rekey_session(session_id)
    try:
        command = {
            "command_id": "cmd-rekey-001",
            "command": "force_rekey",
            "session_id": session_id,
            "status": "queued",
        }
        execute_command(command, results_file=results_path)

        assert results_path.exists()
        result = json.loads(results_path.read_text(encoding="utf-8").strip())
        assert result["command_id"] == "cmd-rekey-001"
        assert result["status"] == "queued"
        assert result["session_id"] == session_id
        assert take_pending_rekey(session_id) == command
    finally:
        unregister_rekey_session(session_id)


def test_force_rekey_inactive_session_rejected(tmp_path):
    results_path = tmp_path / "command_results.jsonl"
    session_id = "inactive-session-target"

    command = {
        "command_id": "cmd-rekey-002",
        "command": "force_rekey",
        "session_id": session_id,
        "status": "queued",
    }
    execute_command(command, results_file=results_path)

    assert results_path.exists()
    result = json.loads(results_path.read_text(encoding="utf-8").strip())
    assert result["command_id"] == "cmd-rekey-002"
    assert result["status"] == "rejected"
    assert "not an active secure session" in result["message"]


def test_force_rekey_duplicate_request_rejected(tmp_path):
    results_path = tmp_path / "command_results.jsonl"
    session_id = "session-duplicate-target"

    register_rekey_session(session_id)
    try:
        command_1 = {
            "command_id": "cmd-rekey-dup-1",
            "command": "force_rekey",
            "session_id": session_id,
            "status": "queued",
        }
        execute_command(command_1, results_file=results_path)

        command_2 = {
            "command_id": "cmd-rekey-dup-2",
            "command": "force_rekey",
            "session_id": session_id,
            "status": "queued",
        }
        execute_command(command_2, results_file=results_path)

        assert results_path.exists()
        lines = [line.strip() for line in results_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert len(lines) == 2
        res1 = json.loads(lines[0])
        res2 = json.loads(lines[1])
        assert res1["command_id"] == "cmd-rekey-dup-1"
        assert res1["status"] == "queued"
        assert res2["command_id"] == "cmd-rekey-dup-2"
        assert res2["status"] == "rejected"
        assert "already has a re-key request pending" in res2["message"]
    finally:
        unregister_rekey_session(session_id)


def test_command_processor_integration(tmp_path):
    commands_path = tmp_path / "commands.jsonl"
    results_path = tmp_path / "command_results.jsonl"
    session_id = "test-session-processor-01"

    server_sock, client_sock = socket.socketpair()
    with active_sessions_lock:
        active_sessions[session_id] = server_sock

    stop_evt = threading.Event()
    try:
        command_stop_event.clear()
        processor_thread = threading.Thread(
            target=command_processor,
            kwargs={
                "commands_file": commands_path,
                "results_file": results_path,
                "poll_interval": 0.05,
            },
            daemon=True,
        )
        processor_thread.start()

        # Enqueue command
        cmd_item = enqueue_command(
            "kill_session", session_id=session_id, path=commands_path
        )

        # Wait for processor to execute
        client_sock.settimeout(3.0)
        data = client_sock.recv(1024)
        assert data == b"", "Client socket should be closed by command processor"

        # Verify result was written to results_path
        processed = set()
        for _ in range(30):
            processed = load_processed_command_ids(results_file=results_path)
            if cmd_item["command_id"] in processed:
                break
            time.sleep(0.05)

        assert cmd_item["command_id"] in processed
    finally:
        command_stop_event.set()
        processor_thread.join(timeout=2.0)
        with active_sessions_lock:
            active_sessions.pop(session_id, None)
        client_sock.close()
        server_sock.close()


def test_concurrent_command_queueing(tmp_path):
    path = tmp_path / "commands.jsonl"
    queued_ids = set()
    lock = threading.Lock()

    def worker(worker_id):
        for i in range(10):
            res = enqueue_command(
                "kill_session",
                session_id=f"session-worker-{worker_id}-{i}",
                path=path,
            )
            with lock:
                queued_ids.add(res["command_id"])

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(queued_ids) == 40
    # Verify file integrity
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 40
    saved_ids = {item["command_id"] for item in lines}
    assert saved_ids == queued_ids

