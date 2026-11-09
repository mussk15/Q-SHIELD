"""Create synthetic failed-login events for IDS testing; no password guessing occurs."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-ip", default="127.0.0.1")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--output", default="data/security_events.jsonl")
    args = parser.parse_args()

    if args.source_ip not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("Safety guard: synthetic events may only use loopback source IP.")
    if not 1 <= args.attempts <= 50:
        parser.error("--attempts must be between 1 and 50")

    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for index in range(args.attempts):
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "HANDSHAKE_FAIL",
                "severity": "HIGH",
                "source_ip": args.source_ip,
                "session_id": f"lab-failed-login-{index + 1}",
                "description": "Synthetic lab authentication failure event"
            }
            handle.write(json.dumps(event) + "\n")
    print(f"Wrote {args.attempts} synthetic events to {path}")


if __name__ == "__main__":
    main()
