"""Create small synthetic data files for a local dashboard preview.

The generator never overwrites existing JSONL files. The records are examples,
not real attack observations or measured project results.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


def write_jsonl(filename: str, records: list[dict]) -> None:
    destination = DATA / filename
    if destination.exists():
        print(f"Kept existing {filename}; not overwriting it.")
        return
    with destination.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"Created {filename}")


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    events = [
        {"timestamp": (now - timedelta(minutes=8)).isoformat(), "event_type": "handshake_started", "outcome": "started", "source_ip": "127.0.0.1", "bytes": 100},
        {"timestamp": (now - timedelta(minutes=7)).isoformat(), "event_type": "handshake_success", "outcome": "success", "source_ip": "127.0.0.1", "bytes": 320},
        {"timestamp": (now - timedelta(minutes=5)).isoformat(), "event_type": "message_received", "outcome": "success", "source_ip": "127.0.0.1", "bytes": 180},
        {"timestamp": (now - timedelta(minutes=3)).isoformat(), "event_type": "rate_limit_hit", "outcome": "blocked", "source_ip": "192.0.2.10", "bytes": 64},
        {"timestamp": (now - timedelta(minutes=2)).isoformat(), "event_type": "handshake_failed", "outcome": "failure", "source_ip": "192.0.2.10", "bytes": 120},
    ]
    alerts = [
        {"id": "demo-alert-001", "timestamp": (now - timedelta(minutes=3)).isoformat(), "type": "Port Scan", "source_ip": "192.0.2.10", "severity": "MEDIUM", "evidence": "Synthetic example: multiple ports accessed", "status": "Open"},
        {"id": "demo-alert-002", "timestamp": (now - timedelta(minutes=2)).isoformat(), "type": "Handshake Brute Force", "source_ip": "192.0.2.10", "severity": "HIGH", "evidence": "Synthetic example: repeated failed handshakes", "status": "In Progress"},
        {"id": "demo-alert-003", "timestamp": (now - timedelta(minutes=1)).isoformat(), "type": "Replay Attempt", "source_ip": "127.0.0.1", "severity": "CRITICAL", "evidence": "Synthetic example: replay detection", "status": "Open"},
    ]
    sessions = [
        {"session_id": "demo-session-01", "user_id": "alice-demo", "remote_ip": "127.0.0.1", "status": "Active", "started_at": (now - timedelta(minutes=7)).isoformat(), "key_fingerprint": "sha256:demo-fingerprint-only"},
        {"session_id": "demo-session-02", "user_id": "bob-demo", "remote_ip": "127.0.0.1", "status": "Active", "started_at": (now - timedelta(minutes=5)).isoformat(), "key_fingerprint": "sha256:another-demo-fingerprint"},
    ]
    write_jsonl("events.jsonl", events)
    write_jsonl("alerts.jsonl", alerts)
    write_jsonl("sessions.jsonl", sessions)
    print("Synthetic dashboard preview data is ready. These are not real attack measurements.")


if __name__ == "__main__":
    main()
