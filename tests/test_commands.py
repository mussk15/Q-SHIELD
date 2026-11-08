import json
import pytest

from response.commands import enqueue_command


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
