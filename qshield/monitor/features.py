"""Per-source-IP sliding-window feature extraction.

This module deliberately does not inspect application payloads. With encrypted Q-SHIELD
records, login failures, replay attempts, and malformed messages must come from the
application security-event log emitted by Member 2.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


def utc_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    flags: str
    packet_bytes: int


@dataclass
class FeatureWindow:
    timestamp: str
    src_ip: str
    window_seconds: int
    packet_count: int
    connection_attempts: int
    syn_count: int
    syn_ack_count: int
    rst_count: int
    half_open_syns: int
    failed_handshakes: int
    distinct_dst_ports: int
    distinct_dst_ips: int
    bytes_total: int
    message_rate: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SlidingWindowFeatureExtractor:
    """Maintain recent packet records and produce one feature row per source IP."""

    def __init__(self, window_seconds: int = 10):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._records: dict[str, deque[PacketRecord]] = defaultdict(deque)

    def add_packet(self, packet: PacketRecord) -> None:
        queue = self._records[packet.src_ip]
        queue.append(packet)
        self._prune(queue, packet.timestamp)

    def _prune(self, queue: deque[PacketRecord], now: float) -> None:
        cutoff = now - self.window_seconds
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()

    def snapshot(self, now: float | None = None) -> list[FeatureWindow]:
        """Return current windows; `now` is injectable for deterministic tests."""
        if now is None:
            now = datetime.now(tz=timezone.utc).timestamp()

        rows: list[FeatureWindow] = []
        for src_ip, queue in list(self._records.items()):
            self._prune(queue, now)
            if not queue:
                del self._records[src_ip]
                continue

            records = list(queue)
            syn_records = [r for r in records if "S" in r.flags and "A" not in r.flags]
            syn_ack_records = [r for r in records if "S" in r.flags and "A" in r.flags]
            rst_count = sum("R" in r.flags for r in records)

            # A passive source-IP window can only approximate half-open attempts.
            # Count SYNs not matched by an observed SYN-ACK from the same source window.
            # For accurate state tracking, capture both directions and correlate tuples.
            half_open = max(0, len(syn_records) - len(syn_ack_records))

            first_ts = min(r.timestamp for r in records)
            elapsed = max(1.0, min(float(self.window_seconds), now - first_ts + 1.0))
            rows.append(FeatureWindow(
                timestamp=utc_iso(now),
                src_ip=src_ip,
                window_seconds=self.window_seconds,
                packet_count=len(records),
                connection_attempts=len(syn_records),
                syn_count=len(syn_records),
                syn_ack_count=len(syn_ack_records),
                rst_count=rst_count,
                half_open_syns=half_open,
                failed_handshakes=rst_count,
                distinct_dst_ports=len({r.dst_port for r in records if r.dst_port is not None}),
                distinct_dst_ips=len({r.dst_ip for r in records if r.dst_ip}),
                bytes_total=sum(r.packet_bytes for r in records),
                message_rate=round(len(records) / elapsed, 3),
            ))
        return rows

    def clear(self) -> None:
        self._records.clear()
