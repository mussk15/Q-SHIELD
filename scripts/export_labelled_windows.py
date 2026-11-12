"""Export timestamp-correct, labelled traffic windows from a PCAP."""

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qshield.monitor.features import SlidingWindowFeatureExtractor
from qshield.monitor.sniffer import replay_pcap


FIELDS = [
    "timestamp", "src_ip", "window_seconds", "packet_count",
    "connection_attempts", "syn_count", "syn_ack_count", "rst_count",
    "half_open_syns", "failed_handshakes", "distinct_dst_ports",
    "distinct_dst_ips", "bytes_total", "message_rate", "label"
]


def main():
    parser = argparse.ArgumentParser(
        description="Export labelled Q-SHIELD traffic feature windows"
    )
    parser.add_argument("--pcap", required=True)
    parser.add_argument(
        "--label",
        required=True,
        choices=[
            "normal", "port_scan", "syn_flood",
            "failed_login", "unknown"
        ],
    )
    parser.add_argument(
        "--output",
        default="data/labelled_windows.csv"
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=10
    )

    args = parser.parse_args()

    if args.window_seconds <= 0:
        parser.error("--window-seconds must be positive")

    pcap_path = Path(args.pcap)
    if not pcap_path.is_file():
        parser.error(f"PCAP file not found: {pcap_path}")

    extractor = SlidingWindowFeatureExtractor(
        args.window_seconds
    )

    exported_rows = []
    window_start = None
    last_timestamp = None

    def process_packet(record):
        nonlocal window_start, last_timestamp

        extractor.add_packet(record)
        last_timestamp = record.timestamp

        if window_start is None:
            window_start = record.timestamp
            return

        if record.timestamp - window_start >= args.window_seconds:
            exported_rows.extend(
                extractor.snapshot(now=record.timestamp)
            )
            extractor.clear()
            window_start = record.timestamp

    packet_count = replay_pcap(
        str(pcap_path),
        process_packet
    )

    # Flush the final partial window using the PCAP timestamp.
    if last_timestamp is not None:
        exported_rows.extend(
            extractor.snapshot(now=last_timestamp)
        )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    write_header = (
        not output.exists()
        or output.stat().st_size == 0
    )

    with output.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=FIELDS
        )

        if write_header:
            writer.writeheader()

        for row in exported_rows:
            record = row.to_dict()
            record["label"] = args.label
            writer.writerow(record)

    print(f"PCAP: {pcap_path}")
    print(f"TCP packets read: {packet_count}")
    print(f"Feature windows exported: {len(exported_rows)}")
    print(f"Label: {args.label}")
    print(f"Output: {output}")


if __name__ == "__main__":
    main()