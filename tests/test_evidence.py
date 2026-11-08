import json

from response.evidence import append_event, verify_chain


def test_two_records_verify(tmp_path):
    path = tmp_path / "evidence.jsonl"
    append_event("test_started", {"case": "T14"}, path=path)
    append_event("test_completed", {"result": "pass"}, path=path)
    valid, message = verify_chain(path)
    assert valid is True
    assert "2" in message


def test_modified_record_fails_verification(tmp_path):
    path = tmp_path / "evidence.jsonl"
    append_event("ip_blocked", {"ip": "127.0.0.2"}, path=path)
    record = json.loads(path.read_text(encoding="utf-8").strip())
    record["details"]["ip"] = "127.0.0.3"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    valid, message = verify_chain(path)
    assert valid is False
    assert "hash mismatch" in message.lower()


def test_missing_file_is_valid_empty_chain(tmp_path):
    valid, message = verify_chain(tmp_path / "missing.jsonl")
    assert valid is True
    assert "No evidence" in message
