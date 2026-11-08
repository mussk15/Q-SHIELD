"""Append-only response command queue.

Member 2's secure server must consume, validate, execute and acknowledge these
commands. Writing a command here does NOT itself kill or re-key a session.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_COMMANDS = {"kill_session", "force_rekey"}


def default_path() -> Path:
    return Path(os.getenv("QSHIELD_DATA_DIR", "data")) / "commands.jsonl"


def enqueue_command(
    command: str,
    *,
    session_id: str,
    actor: str = "dashboard",
    reason: str = "Analyst response",
    path: str | Path | None = None,
) -> dict[str, Any]:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Unsupported command: {command}")

    clean_session_id = str(session_id).strip()
    if not clean_session_id or len(clean_session_id) > 128:
        raise ValueError("Session ID must contain 1–128 characters")

    file_path = Path(path) if path is not None else default_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)

    item = {
        "command_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": command,
        "session_id": clean_session_id,
        "actor": str(actor).strip()[:80],
        "reason": str(reason).strip()[:500],
        "status": "queued",
    }
    with file_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return item
