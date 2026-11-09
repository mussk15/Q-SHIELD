"""Export per-source-IP feature windows from a PCAP with a supplied ground-truth label.

Run this separately for each labelled capture, then combine CSV files for Member 1.
The label is supplied by the operator based on the controlled lab scenario; it is not
guessed by the detector.
"""
import argparse
import csv
from pathlib import Path

from qshield.monitor.features import SlidingWindowFeatureExtractor
from qshield.monitor.sniffer import replay_pcap


FIELDS = [
    "timestamp", "src_ip", "window_seconds", "packet_count",
    "connection_attempts", "syn_count", "syn_ack_count", "rst_count",
    "half_open_syns", "failed_handshakes", "distinct_dst_ports",
    "distinct_dst_ips", "bytes_total", "message_rate", "label"
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--label", required=True,
                        choices=["normal", "port_scan", "syn_flood", "failed_login", "unknown"])
    parser.add_argument("--output", default="data/labelled_windows.csv")
    parser.add_argument("--window-seconds", type=int, default=10)
    args = parser.parse_args()

    extractor = SlidingWindowFeatureExtractor(args.window_seconds)
    packet_count = replay_pcap(args.pcap, extractor.add_packet)
    rows = extractor.snapshot()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    write_header = not output.exists() or output.stat().st_size == 0
    with output.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        if write_header:
            writer.writeheader()
        for row in rows:
            record = row.to_dict()
            record["label"] = args.label
            writer.writerow(record)

    print(f"Read {packet_count} TCP packets; exported {len(rows)} windows to {output}")


if __name__ == "__main__":
    main()
