"""JSON-backed simulated IP blocklist for the Q-SHIELD lab prototype.

This module does not modify Windows Firewall or any operating-system firewall.
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def default_path() -> Path:
    return Path(os.getenv("QSHIELD_DATA_DIR", "data")) / "blocklist.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_ip(ip: str) -> str:
    """Return a canonical IPv4/IPv6 address or raise ValueError."""
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip}") from exc


def load_blocklist(path: str | Path | None = None) -> dict[str, Any]:
    file_path = Path(path) if path is not None else default_path()
    if not file_path.exists():
        return {"version": 1, "updated_at": None, "blocked_ips": []}

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read blocklist {file_path}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("blocked_ips", []), list):
        raise RuntimeError("Invalid blocklist format: expected an object with blocked_ips list")

    data.setdefault("version", 1)
    data.setdefault("updated_at", None)
    data.setdefault("blocked_ips", [])
    return data


def save_blocklist(data: dict[str, Any], path: str | Path | None = None) -> None:
    file_path = Path(path) if path is not None else default_path()
    file_path.parent.mkdir(parents=True, exist_ok=True)

    fd, temporary_name = tempfile.mkstemp(
        prefix="blocklist_", suffix=".tmp", dir=str(file_path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, file_path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def is_blocked(ip: str, path: str | Path | None = None) -> bool:
    canonical_ip = validate_ip(ip)
    data = load_blocklist(path)
    return any(
        isinstance(entry, dict) and entry.get("ip") == canonical_ip
        for entry in data["blocked_ips"]
    )


def block_ip(
    ip: str,
    reason: str = "Suspicious activity",
    source: str = "dashboard",
    path: str | Path | None = None,
) -> dict[str, str]:
    canonical_ip = validate_ip(ip)
    data = load_blocklist(path)

    for entry in data["blocked_ips"]:
        if isinstance(entry, dict) and entry.get("ip") == canonical_ip:
            return entry

    entry = {
        "ip": canonical_ip,
        "reason": str(reason).strip()[:500],
        "source": str(source).strip()[:80],
        "added_at": _utc_now(),
    }
    data["blocked_ips"].append(entry)
    data["updated_at"] = _utc_now()
    save_blocklist(data, path)
    return entry


def unblock_ip(ip: str, path: str | Path | None = None) -> bool:
    canonical_ip = validate_ip(ip)
    data = load_blocklist(path)
    previous_count = len(data["blocked_ips"])
    data["blocked_ips"] = [
        entry for entry in data["blocked_ips"]
        if not (isinstance(entry, dict) and entry.get("ip") == canonical_ip)
    ]
    removed = len(data["blocked_ips"]) < previous_count
    if removed:
        data["updated_at"] = _utc_now()
        save_blocklist(data, path)
    return removed
