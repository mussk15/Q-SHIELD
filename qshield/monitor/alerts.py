"""Alert schema, severity ordering, de-duplication, and JSONL output."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
import json
import time
import uuid


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    source_ip: str
    rule_id: str
    title: str
    description: str
    severity: str
    score: int
    evidence: dict

    def to_dict(self) -> dict:
        return asdict(self)


class AlertManager:
    def __init__(self, output_path: str = "data/alerts.jsonl",
                 cooldown_seconds: int = 30):
        self.output_path = Path(output_path)
        self.cooldown_seconds = cooldown_seconds
        self._last_emitted: dict[tuple[str, str], float] = {}
        self._lock = Lock()

    def create(self, *, source_ip: str, rule_id: str, title: str,
               description: str, severity: str, score: int,
               evidence: dict | None = None) -> Alert | None:
        severity = severity.upper()
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported severity: {severity}")
        now = time.time()
        key = (source_ip, rule_id)
        with self._lock:
            previous = self._last_emitted.get(key)
            if previous is not None and now - previous < self.cooldown_seconds:
                return None
            self._last_emitted[key] = now

        return Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            score=max(0, min(100, int(score))),
            evidence=evidence or {},
        )

    def write(self, alert: Alert) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(alert.to_dict(), ensure_ascii=False)
        with self._lock, self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    @staticmethod
    def prioritise(alerts: list[Alert]) -> list[Alert]:
        return sorted(
            alerts,
            key=lambda a: (SEVERITY_ORDER[a.severity], a.score, a.timestamp),
            reverse=True,
        )
