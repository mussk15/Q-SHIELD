"""SHA-256 hash-chained JSONL evidence log for the Q-SHIELD prototype.

The chain makes accidental or partial modification detectable. It is not a
signature, trusted timestamp, immutable storage system, or tamper-proof log.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
EVIDENCE_LOCK = threading.Lock()


def default_path() -> Path:
    return Path(os.getenv("QSHIELD_DATA_DIR", "data")) / "evidence.jsonl"


def _canonical_json(record: dict[str, Any]) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(record)).hexdigest()


def read_records(path: str | Path) -> list[dict[str, Any]]:
    file_path = Path(path)
    records: list[dict[str, Any]] = []
    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {line_number}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"Evidence record at line {line_number} is not an object")
            records.append(record)
    return records


def verify_chain(path: str | Path | None = None) -> tuple[bool, str]:
    file_path = Path(path) if path is not None else default_path()
    if not file_path.exists():
        return True, "No evidence records found."

    try:
        records = read_records(file_path)
    except (OSError, ValueError) as exc:
        return False, str(exc)

    previous_hash = GENESIS_HASH
    for expected_sequence, record in enumerate(records, start=1):
        stored_hash = record.get("hash")
        unsigned_record = {key: value for key, value in record.items() if key != "hash"}

        if record.get("sequence") != expected_sequence:
            return False, f"Sequence mismatch at record {expected_sequence}."
        if record.get("prev_hash") != previous_hash:
            return False, f"Previous hash mismatch at record {expected_sequence}."
        if not isinstance(stored_hash, str) or stored_hash != _record_hash(unsigned_record):
            return False, f"Hash mismatch at record {expected_sequence}."
        previous_hash = stored_hash

    return True, f"Verified {len(records)} evidence records."


def append_event(
    event_type: str,
    details: dict[str, Any] | None = None,
    *,
    actor: str = "system",
    path: str | Path | None = None,
) -> dict[str, Any]:
    clean_event_type = str(event_type).strip()
    if not clean_event_type or len(clean_event_type) > 100:
        raise ValueError("Event type must contain 1–100 characters")
    if details is not None and not isinstance(details, dict):
        raise TypeError("details must be a dictionary")

    file_path = Path(path) if path is not None else default_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with EVIDENCE_LOCK:
        valid, message = verify_chain(file_path)
        if not valid:
            raise RuntimeError(f"Cannot append to invalid evidence chain: {message}")

        records = read_records(file_path)
        previous_hash = records[-1]["hash"] if records else GENESIS_HASH
        unsigned_record = {
            "sequence": len(records) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event_type": clean_event_type,
            "actor": str(actor).strip()[:80],
            "details": details or {},
            "prev_hash": previous_hash,
        }
        record = {**unsigned_record, "hash": _record_hash(unsigned_record)}

        with file_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    return record
