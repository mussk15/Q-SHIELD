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
    read_jsonl,
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
        }
    ]
    frame = sessions_frame(raw)
    assert isinstance(frame, pd.DataFrame)
    assert list(frame.columns) == ["Session ID", "User", "Remote IP", "Status", "Started", "Key fingerprint"]
    assert frame.iloc[0]["Session ID"] == "sess-001"
    assert frame.iloc[0]["Status"] == "Active"


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
    """Verify that every dashboard page loads and renders without exceptions."""
    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=20)
    at.run()
    assert not at.exception

    # Authenticate
    at.session_state["logged_in"] = True
    at.run()
    assert not at.exception

    # Test pages via sidebar radio
    pages = [
        "Overview",
        "Secure Communication",
        "File Transfer",
        "Sessions",
        "Network Monitoring",
        "Threat Alerts",
        "Response Centre",
        "Evidence",
        "Cryptographic Benchmarks",
        "System Status and Settings",
    ]
    for page in pages:
        # Find radio widget and select page
        if at.sidebar.radio:
            at.sidebar.radio[0].set_value(page)
            at.run()
            assert not at.exception, f"Exception occurred while rendering page: {page}"
