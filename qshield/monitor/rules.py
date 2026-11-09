"""Configurable threshold rules for network features and application security events."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from collections import defaultdict, deque
import time
import yaml

from .features import FeatureWindow
from .alerts import Alert, AlertManager


DEFAULT_CONFIG = {
    "window_seconds": 10,
    "alert_cooldown_seconds": 30,
    "rules": {
        "port_scan": {"enabled": True, "min_distinct_ports": 12,
                      "min_connection_attempts": 15, "severity": "HIGH", "score": 80},
        "syn_flood": {"enabled": True, "min_syn_count": 30,
                      "min_half_open_syns": 20, "severity": "CRITICAL", "score": 95},
        "failed_login": {"enabled": True, "min_failures": 5,
                         "severity": "HIGH", "score": 85},
        "malformed_input": {"enabled": True, "min_events": 1,
                            "severity": "HIGH", "score": 85},
        "replay_or_tamper": {"enabled": True, "min_events": 1,
                             "severity": "CRITICAL", "score": 100},
    },
}


def load_config(path: str | Path = "config/thresholds.yaml") -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return DEFAULT_CONFIG
    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    # Keep defaults for omitted settings.
    merged = {**DEFAULT_CONFIG, **loaded}
    merged["rules"] = {**DEFAULT_CONFIG["rules"], **loaded.get("rules", {})}
    return merged


class RuleEngine:
    def __init__(self, config: dict[str, Any], alert_manager: AlertManager):
        self.config = config
        self.alert_manager = alert_manager
        self._auth_failures: dict[str, deque[float]] = defaultdict(deque)

    def evaluate_window(self, window: FeatureWindow) -> list[Alert]:
        emitted: list[Alert] = []
        rules = self.config.get("rules", {})

        scan = rules.get("port_scan", {})
        if scan.get("enabled", True) and (
            window.distinct_dst_ports >= int(scan.get("min_distinct_ports", 12))
            and window.connection_attempts >= int(scan.get("min_connection_attempts", 15))
        ):
            self._emit(emitted, window.src_ip, "PORT_SCAN", "Possible port scan",
                       "One source contacted many destination ports in one time window.",
                       scan, {"distinct_dst_ports": window.distinct_dst_ports,
                              "connection_attempts": window.connection_attempts})

        flood = rules.get("syn_flood", {})
        if flood.get("enabled", True) and (
            window.syn_count >= int(flood.get("min_syn_count", 30))
            and window.half_open_syns >= int(flood.get("min_half_open_syns", 20))
        ):
            self._emit(emitted, window.src_ip, "SYN_FLOOD", "Possible SYN flood",
                       "High SYN volume with many unmatched SYN attempts was observed.",
                       flood, {"syn_count": window.syn_count,
                               "half_open_syns": window.half_open_syns})

        return emitted

    def evaluate_application_event(self, event: dict[str, Any]) -> list[Alert]:
        """Consume Member 2 JSONL events; payloads are never inspected."""
        raw_event_type = str(event.get("event_type", "")).upper()
        event_type_mapping = {
            "INVALID_CLIENT_MESSAGE": "MALFORMED",
            "INVALID_MESSAGE_ENCODING": "MALFORMED",
            }
        event_type = event_type_mapping.get(raw_event_type, raw_event_type)
        source_ip = str(event.get("source_ip") or "unknown")
        emitted: list[Alert] = []
        rules = self.config.get("rules", {})

        if event_type in {"HANDSHAKE_FAIL", "SIG_FAIL"}:
            rule = rules.get("failed_login", {})
            threshold = int(rule.get("min_failures", 5))
            now = time.time()
            failures = self._auth_failures[source_ip]
            failures.append(now)
            # Keep the failure count bounded to a rolling five-minute interval.
            while failures and now - failures[0] > 300:
                failures.popleft()
            if len(failures) >= threshold:
                self._emit(emitted, source_ip, "AUTH_FAILURE", "Repeated authentication failures",
                           f"{len(failures)} authentication/signature failures occurred in five minutes.",
                           rule, {"event_type": event_type, "failure_count": len(failures),
                                  "session_id": event.get("session_id")})

        if event_type == "MALFORMED":
            rule = rules.get("malformed_input", {})
            self._emit(emitted, source_ip, "MALFORMED_INPUT", "Malformed application input",
                       "Member 2 reported a message validation failure.",
                       rule, {
                        "event_type": raw_event_type,
                        "description": event.get("details", {}).get("error")
                        or event.get("description")
                        or "Member 2 reported invalid application input."
                        })

        if event_type in {"REPLAY", "TAG_FAIL", "SIG_FAIL"}:
            rule = rules.get("replay_or_tamper", {})
            self._emit(emitted, source_ip, "REPLAY_OR_TAMPER", "Replay or tamper indicator",
                       f"Application event {event_type} indicates a protected-record security failure.",
                       rule, {"event_type": event_type, "session_id": event.get("session_id")})

        return emitted

    def _emit(self, output: list[Alert], source_ip: str, rule_id: str,
              title: str, description: str, rule: dict, evidence: dict) -> None:
        if not rule.get("enabled", True):
            return
        alert = self.alert_manager.create(
            source_ip=source_ip,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=rule.get("severity", "MEDIUM"),
            score=rule.get("score", 50),
            evidence=evidence,
        )
        if alert is not None:
            self.alert_manager.write(alert)
            output.append(alert)
