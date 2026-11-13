"""Unit and headless functional tests for the Q-SHIELD Streamlit Dashboard."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from dashboard.app import (
    alerts_frame,
    commands_frame,
    format_dataframe_for_display,
    read_jsonl,
    sanitize_cell_value,
    sessions_frame,
)


def test_read_jsonl_empty_and_missing(tmp_path):
    missing_file = tmp_path / "nonexistent.jsonl"
    records, errors = read_jsonl(missing_file)
    assert records == []
    assert errors == 0

    empty_file = tmp_path / "empty.jsonl"
    empty_file.write_text("\n\n", encoding="utf-8")
    records, errors = read_jsonl(empty_file)
    assert records == []
    assert errors == 0


def test_read_jsonl_handles_malformed_lines(tmp_path):
    path = tmp_path / "mixed.jsonl"
    content = (
        '{"id": "1", "data": "valid"}\n'
        'not valid json\n'
        '{"id": "2", "data": "also valid"}\n'
        '[1, 2, 3]\n'  # Valid JSON but not an object
    )
    path.write_text(content, encoding="utf-8")
    records, errors = read_jsonl(path)
    assert len(records) == 2
    assert errors == 2


def test_alerts_frame_structure():
    raw = [
        {
            "timestamp": "2026-11-11T10:00:00Z",
            "title": "Port Scan Detected",
            "source_ip": "192.168.1.50",
            "severity": "high",
            "status": "Open",
            "description": "50 ports probed",
        }
    ]
    frame = alerts_frame(raw)
    assert isinstance(frame, pd.DataFrame)
    assert list(frame.columns) == ["Time", "Alert", "Source IP", "Severity", "Status", "Evidence"]
    assert frame.iloc[0]["Severity"] == "HIGH"
    assert frame.iloc[0]["Source IP"] == "192.168.1.50"


def test_sessions_frame_structure():
    raw = [
        {
            "session_id": "sess-001",
            "user_id": "alice",
            "remote_ip": "10.0.0.1",
            "status": "Active",
            "started_at": "2026-11-11T09:00:00Z",
            "key_fingerprint": "sha256:abc123",
            "key_generation": 0,
        }
    ]
    frame = sessions_frame(raw)
    assert isinstance(frame, pd.DataFrame)
    for col in ["Session ID", "Client IP", "Identity", "Status", "Key Generation", "Started"]:
        assert col in frame.columns
    assert frame.iloc[0]["Session ID"] == "sess-001"
    assert frame.iloc[0]["Status"] == "Active"
    assert frame.iloc[0]["Key Generation"] == "Gen 0"


def test_commands_frame_merges_acknowledgements():
    commands = [
        {
            "command_id": "cmd-001",
            "session_id": "sess-active",
            "command": "kill_session",
            "timestamp": "2026-11-11T10:05:00Z",
            "status": "queued",
        },
        {
            "command_id": "cmd-002",
            "session_id": "sess-rekey",
            "command": "force_rekey",
            "timestamp": "2026-11-11T10:06:00Z",
            "status": "queued",
        },
    ]
    results = [
        {
            "command_id": "cmd-001",
            "status": "executed",
            "message": "Session termination requested by dashboard",
        },
        {
            "command_id": "cmd-002",
            "status": "deferred",
            "message": "Deferred: Waiting for Member 1 rekey API",
        },
    ]
    frame = commands_frame(commands, results)
    assert isinstance(frame, pd.DataFrame)
    assert len(frame) == 2
    # Verify newest is displayed first (reversed)
    assert frame.iloc[0]["Command type"] == "force_rekey"
    assert frame.iloc[0]["Execution status"] == "DEFERRED"
    assert "Member 1" in frame.iloc[0]["Server response / Reason"]
    assert frame.iloc[1]["Execution status"] == "EXECUTED"


def test_dashboard_headless_page_navigation():
    """Verify that all six dashboard pages load and render without exceptions."""
    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=20)
    at.run()
    assert not at.exception

    # Authenticate
    at.session_state["logged_in"] = True
    at.run()
    assert not at.exception

    # Test exact 6 pages via sidebar radio
    pages = [
        "Overview",
        "Threat Alerts",
        "Sessions",
        "Response Centre",
        "Evidence",
        "Cryptographic Benchmarks",
    ]
    for page in pages:
        if at.sidebar.radio:
            at.sidebar.radio[0].set_value(page)
            at.run()
            assert not at.exception, f"Exception occurred while rendering page: {page}"


def test_sanitize_cell_value():
    """Verify scalar sanitization handles dicts, lists, bytes, None and scalars."""
    assert sanitize_cell_value(None) == ""
    assert sanitize_cell_value(float("nan")) == ""
    assert sanitize_cell_value({"k": "v"}) == '{"k": "v"}'
    assert sanitize_cell_value([1, "a"]) == '[1, "a"]'
    assert sanitize_cell_value(b"hello") == "hello"
    assert sanitize_cell_value(b"\xff\xfe") == "fffe"
    assert sanitize_cell_value("already str") == "already str"
    assert sanitize_cell_value(123) == 123
    assert sanitize_cell_value(45.6) == 45.6
    assert sanitize_cell_value(True) is True


def test_format_dataframe_for_display_mixed_types():
    """Verify mixed object columns (such as Details with str and dict) serialize to PyArrow."""
    import pyarrow as pa

    df = pd.DataFrame({
        "Details": ["simple string", {"cmd": "kill_session", "code": 1}, None, b"binary_data"],
        "Count": [10, 20, 30, 40],
        "Score": [1.5, 2.5, 3.5, 4.5],
    })

    # Prior to formatting, PyArrow would fail on mixed dict/str in Details
    with pytest.raises(Exception):
        pa.Table.from_pandas(df)

    # After formatting, PyArrow serialization succeeds smoothly
    formatted = format_dataframe_for_display(df)
    tbl = pa.Table.from_pandas(formatted)
    assert tbl.num_rows == 4
    assert str(tbl.schema.field("Details").type) in ("string", "large_string")
    assert str(tbl.schema.field("Count").type).startswith("int")
    assert str(tbl.schema.field("Score").type).startswith("double")


def test_all_dashboard_frames_arrow_compatible():
    """Ensure all dashboard DataFrame builders generate Arrow-compatible tables."""
    import pyarrow as pa

    # 1. Alerts with mixed evidence
    alerts = alerts_frame([
        {"timestamp": "2026-11-12T10:00:00Z", "title": "Alert 1", "evidence": "text evidence"},
        {"timestamp": "2026-11-12T10:01:00Z", "title": "Alert 2", "evidence": {"nested": "evidence"}},
    ])
    tbl_alerts = pa.Table.from_pandas(format_dataframe_for_display(alerts))
    assert tbl_alerts.num_rows == 2

    # 2. Sessions
    sessions = sessions_frame([
        {"session_id": "s1", "remote_ip": "127.0.0.1", "status": "active"},
    ])
    tbl_sessions = pa.Table.from_pandas(format_dataframe_for_display(sessions))
    assert tbl_sessions.num_rows == 1

    # 3. Commands with mixed responses
    commands = commands_frame(
        [{"command_id": "c1", "command": "force_rekey"}],
        [{"command_id": "c1", "status": "executed", "message": "Rekey successful"}],
    )
    tbl_commands = pa.Table.from_pandas(format_dataframe_for_display(commands))
    assert tbl_commands.num_rows == 1

