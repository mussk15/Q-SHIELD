"""Generate controlled, synthetic lab traffic windows for Q-SHIELD IDS evaluation.

These records represent controlled synthetic lab data and MUST NOT be described
or treated as real-world production network traffic.
"""
from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FIELDS = [
    "timestamp", "src_ip", "window_seconds", "packet_count",
    "connection_attempts", "syn_count", "syn_ack_count", "rst_count",
    "half_open_syns", "failed_handshakes", "distinct_dst_ports",
    "distinct_dst_ips", "bytes_total", "message_rate", "label"
]


def generate_lab_windows(
    normal_count: int = 50,
    port_scan_count: int = 15,
    syn_flood_count: int = 15,
    output_path: Path | None = None,
    seed: int = 42,
) -> Path:
    rng = random.Random(seed)
    destination = output_path or (ROOT / "data" / "lab_labelled_windows.csv")
    destination.parent.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 11, 11, 10, 0, 0, tzinfo=timezone.utc)
    rows: list[dict[str, str | int | float]] = []

    # 1. Normal baseline traffic windows (benign web/API queries, DNS, keep-alives)
    for i in range(normal_count):
        t = base_time + timedelta(seconds=10 * i)
        src_ip = f"192.168.1.{10 + (i % 8)}"
        pkt_count = rng.randint(4, 30)
        bytes_total = pkt_count * rng.randint(60, 450)
        rate = round(pkt_count / 10.0, 3)
        rows.append({
            "timestamp": t.isoformat(),
            "src_ip": src_ip,
            "window_seconds": 10,
            "packet_count": pkt_count,
            "connection_attempts": 0,
            "syn_count": rng.choice([0, 0, 1]),
            "syn_ack_count": rng.choice([0, 0, 1]),
            "rst_count": 0,
            "half_open_syns": 0,
            "failed_handshakes": 0,
            "distinct_dst_ports": rng.randint(1, 3),
            "distinct_dst_ips": 1,
            "bytes_total": bytes_total,
            "message_rate": rate,
            "label": "normal",
        })

    # 2. Port scan attack windows (rapid probing of many distinct ports)
    for i in range(port_scan_count):
        t = base_time + timedelta(seconds=10 * (normal_count + i))
        src_ip = "192.168.1.199"
        pkt_count = rng.randint(150, 400)
        conn_att = rng.randint(70, 180)
        syns = conn_att
        rsts = conn_att - rng.randint(0, 5)
        distinct_ports = rng.randint(60, 250)
        bytes_total = pkt_count * rng.randint(50, 70)
        rate = round(pkt_count / 10.0, 3)
        rows.append({
            "timestamp": t.isoformat(),
            "src_ip": src_ip,
            "window_seconds": 10,
            "packet_count": pkt_count,
            "connection_attempts": conn_att,
            "syn_count": syns,
            "syn_ack_count": rng.randint(0, 2),
            "rst_count": rsts,
            "half_open_syns": conn_att,
            "failed_handshakes": conn_att,
            "distinct_dst_ports": distinct_ports,
            "distinct_dst_ips": 1,
            "bytes_total": bytes_total,
            "message_rate": rate,
            "label": "port_scan",
        })

    # 3. SYN flood attack windows (high half-open SYNs, no ACKs, high packet rate)
    for i in range(syn_flood_count):
        t = base_time + timedelta(seconds=10 * (normal_count + port_scan_count + i))
        src_ip = "192.168.1.250"
        pkt_count = rng.randint(200, 500)
        syns = pkt_count
        rate = round(pkt_count / 10.0, 3)
        rows.append({
            "timestamp": t.isoformat(),
            "src_ip": src_ip,
            "window_seconds": 10,
            "packet_count": pkt_count,
            "connection_attempts": syns,
            "syn_count": syns,
            "syn_ack_count": 0,
            "rst_count": 0,
            "half_open_syns": syns,
            "failed_handshakes": syns,
            "distinct_dst_ports": 1,
            "distinct_dst_ips": 1,
            "bytes_total": pkt_count * 54,
            "message_rate": rate,
            "label": "syn_flood",
        })

    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    return destination


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic lab traffic windows")
    parser.add_argument("--normal", type=int, default=50, help="Number of normal windows")
    parser.add_argument("--port-scans", type=int, default=15, help="Number of port scan windows")
    parser.add_argument("--syn-floods", type=int, default=15, help="Number of syn flood windows")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "lab_labelled_windows.csv")
    args = parser.parse_args()

    out = generate_lab_windows(
        normal_count=args.normal,
        port_scan_count=args.port_scans,
        syn_flood_count=args.syn_floods,
        output_path=args.output,
    )
    print(f"Generated synthetic lab dataset: {out} ({args.normal} normal, {args.port_scans + args.syn_floods} attack windows)")


if __name__ == "__main__":
    main()

