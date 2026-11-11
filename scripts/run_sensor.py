"""Q-SHIELD IDS: PCAP replay, live capture, ML detection and event monitoring.

Run from the Q-SHIELD project root.
Only monitor networks you own or are authorized to monitor.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path
from typing import Any

from qshield.monitor.alerts import AlertManager
from qshield.monitor.features import SlidingWindowFeatureExtractor
from qshield.monitor.rules import RuleEngine, load_config
from qshield.monitor.sniffer import capture_live, replay_pcap
from qshield.monitor.anomaly import IsolationForestAnomalyDetector


def load_model(path: Path):
    """Load a trusted locally trained Isolation Forest model."""

    if not path.exists():
        print(f"No trained ML model found at {path}.")
        print("Rule-based IDS will remain active.")
        return None

    import joblib

    model = joblib.load(path)

    if not isinstance(model, IsolationForestAnomalyDetector):
        raise SystemExit(f"Unsupported model type: {path}")

    print(f"Loaded Isolation Forest model: {path}")
    return model


def process_event_line(raw, line_number, path, engine):
    """Process one application security event."""

    if not raw.strip():
        return False

    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        print(f"Malformed JSON skipped: {path}:{line_number}")
        return False

    if not isinstance(event, dict):
        return False

    engine.evaluate_application_event(event)
    return True


def consume_security_events(path, engine):
    """Process existing application security events."""

    file_path = Path(path)

    if not file_path.exists():
        return 0

    count = 0

    with file_path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if process_event_line(line, number, file_path, engine):
                count += 1

    return count


def follow_security_events(
    path,
    engine,
    stop_event,
    poll_seconds=0.5,
):
    """Continuously monitor newly appended application events."""

    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    position = (
        file_path.stat().st_size
        if file_path.exists()
        else 0
    )

    line_number = 0

    print(f"Following application events: {file_path}")

    while not stop_event.is_set():

        try:
            if not file_path.exists():
                stop_event.wait(poll_seconds)
                continue

            current_size = file_path.stat().st_size

            if current_size < position:
                position = 0
                line_number = 0

            with file_path.open("r", encoding="utf-8") as handle:
                handle.seek(position)

                while not stop_event.is_set():

                    line = handle.readline()

                    if not line:
                        break

                    position = handle.tell()
                    line_number += 1

                    process_event_line(
                        line,
                        line_number,
                        file_path,
                        engine,
                    )

        except (OSError, UnicodeError) as error:
            print("Event follower error:", error)

        stop_event.wait(poll_seconds)


def evaluate_windows(windows, engine, manager, model):
    """Run rule-based and ML detection on every feature window."""

    for window in windows:

        # Rule-based detection
        engine.evaluate_window(window)

        # ML detection
        if model is None:
            continue

        result = model.predict_one(window)

        if not result.is_anomaly:
            continue

        alert = manager.create(
            source_ip=window.src_ip,
            rule_id="ISOLATION_FOREST_ANOMALY",
            title="Unusual network traffic pattern",
            description=(
                "Isolation Forest identified an unusual traffic pattern. "
                "This is an investigation signal, not proof of an attack."
            ),
            severity="MEDIUM",
            score=70,
            evidence={
                "anomaly_score": result.anomaly_score,
                "features": window.to_dict(),
            },
        )

        if alert is not None:
            manager.write(alert)

            print(
                f"[ML IDS ALERT] {alert.source_ip} "
                f"score={result.anomaly_score:.4f}"
            )


def main():

    parser = argparse.ArgumentParser(
        description="Q-SHIELD Intrusion Detection Sensor"
    )

    source = parser.add_mutually_exclusive_group()

    source.add_argument(
        "--pcap",
        help="Replay an existing PCAP file",
    )

    source.add_argument(
        "--live",
        action="store_true",
        help="Capture live TCP traffic",
    )

    parser.add_argument("--interface")
    parser.add_argument("--duration", type=int, default=60)

    parser.add_argument(
        "--events",
        default="data/events.jsonl",
    )

    parser.add_argument(
        "--config",
        default="config/thresholds.yaml",
    )

    parser.add_argument(
        "--alerts",
        default="data/alerts.jsonl",
    )

    parser.add_argument(
        "--model",
        default="data/anomaly_model.joblib",
    )

    parser.add_argument(
        "--follow-events",
        action="store_true",
        help="Continuously follow new application events",
    )

    parser.add_argument(
        "--replay-existing-events",
        action="store_true",
        help="Process existing application events at startup",
    )

    args = parser.parse_args()

    if args.duration < 1:
        parser.error("--duration must be at least one second")

    if args.interface and not args.live:
        parser.error("--interface requires --live")

    if not args.pcap and not args.live and not args.follow_events:
        parser.error(
            "Choose --pcap, --live, or --follow-events"
        )

    # Configuration
    config = load_config(args.config)

    window_seconds = int(
        config.get("window_seconds", 10)
    )

    cooldown = int(
        config.get("alert_cooldown_seconds", 30)
    )

    extractor = SlidingWindowFeatureExtractor(
        window_seconds
    )

    manager = AlertManager(
        args.alerts,
        cooldown,
    )

    engine = RuleEngine(
        config,
        manager,
    )

    model = load_model(
        Path(args.model)
    )

    stop_event = threading.Event()
    follower = None

    # Application event monitoring
    if args.follow_events:

        if args.replay_existing_events:
            count = consume_security_events(
                args.events,
                engine,
            )
            print(f"Existing events processed: {count}")

        follower = threading.Thread(
            target=follow_security_events,
            args=(
                args.events,
                engine,
                stop_event,
            ),
            daemon=True,
        )

        follower.start()

    latest_timestamp = None
    window_start = None

    totals = {
        "windows": 0,
        "packets": 0,
    }

    def flush_window(timestamp):

        windows = extractor.snapshot(
            now=timestamp
        )

        if windows:
            evaluate_windows(
                windows,
                engine,
                manager,
                model,
            )

            totals["windows"] += len(windows)

        extractor.clear()

        print(
            f"Processed {len(windows)} traffic feature windows."
        )

    def on_packet(record: Any):

        nonlocal latest_timestamp
        nonlocal window_start

        extractor.add_packet(record)

        totals["packets"] += 1

        latest_timestamp = (
            record.timestamp
            if latest_timestamp is None
            else max(latest_timestamp, record.timestamp)
        )

        if window_start is None:
            window_start = record.timestamp
            return

        if record.timestamp - window_start >= window_seconds:

            flush_window(record.timestamp)

            window_start = record.timestamp

    try:

        # PCAP replay
        if args.pcap:

            print("Starting PCAP replay...")

            packet_count = replay_pcap(
                args.pcap,
                on_packet,
            )

            print(
                f"PCAP packets processed: {packet_count}"
            )

        # Authorized live capture
        elif args.live:

            print("Starting authorized live capture...")

            capture_live(
                on_packet,
                interface=args.interface,
                duration=args.duration,
            )

        # Flush final partial window
        if (args.live or args.pcap) and latest_timestamp is not None:

            final_windows = extractor.snapshot(
                now=latest_timestamp
            )

            if final_windows:
                evaluate_windows(
                    final_windows,
                    engine,
                    manager,
                    model,
                )

                totals["windows"] += len(final_windows)

        if args.live or args.pcap:

            print("\nCapture summary")
            print("------------------------")
            print("Packets:", totals["packets"])
            print("Feature windows:", totals["windows"])

        # Existing application events
        if not args.follow_events:

            count = consume_security_events(
                args.events,
                engine,
            )

            print(
                f"Application events processed: {count}"
            )

        elif not (args.live or args.pcap):

            print(
                "Monitoring application events. "
                "Press Ctrl+C to stop."
            )

            while True:
                time.sleep(0.5)

    except KeyboardInterrupt:

        print("\nStopping Q-SHIELD IDS...")

    finally:

        stop_event.set()

        if follower is not None:
            follower.join(timeout=2)

    print(
        f"IDS alerts saved in: {args.alerts}"
    )


if __name__ == "__main__":
    main()