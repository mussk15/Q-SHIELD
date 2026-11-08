import json
import pytest

from response.blocklist import block_ip, unblock_ip, is_blocked, load_blocklist


def test_block_and_unblock(tmp_path):
    path = tmp_path / "blocklist.json"
    entry = block_ip("127.0.0.2", "Test scan", path=path)
    assert entry["ip"] == "127.0.0.2"
    assert is_blocked("127.0.0.2", path)
    assert unblock_ip("127.0.0.2", path)
    assert not is_blocked("127.0.0.2", path)
    assert load_blocklist(path)["blocked_ips"] == []


def test_invalid_ip_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        block_ip("not-an-ip", path=tmp_path / "blocklist.json")


def test_duplicate_ip_is_not_added_twice(tmp_path):
    path = tmp_path / "blocklist.json"
    block_ip("127.0.0.2", "First", path=path)
    block_ip("127.0.0.2", "Second", path=path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["blocked_ips"]) == 1
