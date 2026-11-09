"""Run live capture or replay a PCAP through the Member 3 IDS."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from qshield.monitor.alerts import AlertManager
from qshield.monitor.features import SlidingWindowFeatureExtractor
from qshield.monitor.rules import RuleEngine, load_config
from qshield.monitor.sniffer import capture_live, replay_pcap


def consume_security_events(path: str, engine: RuleEngine) -> int:
    file_path = Path(path)
    if not file_path.exists():
        return 0
    count = 0
    with file_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"Skipping invalid JSONL at {file_path}:{line_number}")
                continue
            engine.evaluate_application_event(event)
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Q-SHIELD Member 3 IDS sensor")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Read a previously captured PCAP file")
    source.add_argument("--live", action="store_true", help="Capture live TCP traffic")
    parser.add_argument("--interface", help="Capture interface name (live mode)")
    parser.add_argument("--duration", type=int, default=60, help="Live capture seconds")
    parser.add_argument("--events", default="data/events.jsonl",
                        help="Member 2 application-event JSONL path")
    parser.add_argument("--config", default="config/thresholds.yaml")
    parser.add_argument("--alerts", default="data/alerts.jsonl")
    args = parser.parse_args()

    config = load_config(args.config)
    
    extractor = SlidingWindowFeatureExtractor(
        int(config.get("window_seconds", 10))
    )

    manager = AlertManager(
        args.alerts,
        int(config.get("alert_cooldown_seconds", 30))
    )

    engine = RuleEngine(config, manager)

    latest_timestamp = None

    
# Define this inside main(), before on_packet()
    latest_timestamp = None

    def on_packet(record):
        nonlocal latest_timestamp

        extractor.add_packet(record)

        if latest_timestamp is None:
            latest_timestamp = record.timestamp
        else:
            latest_timestamp = max(
                latest_timestamp,
                record.timestamp
            )



    if args.live:
        capture_live(on_packet, interface=args.interface, duration=args.duration)
    else:
        packet_count = replay_pcap(args.pcap, on_packet)
        print(f"Replayed {packet_count} TCP packets from {args.pcap}")

    if args.pcap:
        windows = extractor.snapshot(now=latest_timestamp)
        print("\n========== EXTRACTED FEATURES ==========")

        for window in windows:
            print(window.to_dict())

        print("========================================\n")
    else:
        windows = extractor.snapshot()
    for window in windows:
        engine.evaluate_window(window)

    event_count = consume_security_events(args.events, engine)
    print(f"Feature windows: {len(windows)}")
    print(f"Application events processed: {event_count}")
    print(f"Alerts appended to: {args.alerts}")


if __name__ == "__main__":
    main()
