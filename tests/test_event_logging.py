import json
import tempfile
import threading
import unittest
from pathlib import Path

from qshield.net.server import log_event


class TestEventLogging(unittest.TestCase):

    def test_event_saved_as_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.jsonl"

            event = log_event(
                "client_connected",
                severity="INFO",
                source="127.0.0.1:5000",
                details={"message": "Client connected"},
                log_file=log_path
            )

            saved_event = json.loads(
                log_path.read_text(encoding="utf-8").strip()
            )

            self.assertEqual(
                saved_event["event_type"], "client_connected"
            )
            self.assertEqual(saved_event["severity"], "INFO")
            self.assertEqual(saved_event["source"], "127.0.0.1:5000")
            self.assertIn("timestamp", event)

    def test_empty_event_type_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.jsonl"

            with self.assertRaises(ValueError):
                log_event("", log_file=log_path)

    def test_invalid_severity_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.jsonl"

            with self.assertRaises(ValueError):
                log_event(
                    "client_connected",
                    severity="UNKNOWN",
                    log_file=log_path
                )

    def test_concurrent_events_saved_separately(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "events.jsonl"

            def write_event(number):
                log_event(
                    "client_connected",
                    source=f"client-{number}",
                    log_file=log_path
                )

            threads = [
                threading.Thread(target=write_event, args=(i,))
                for i in range(20)
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

            lines = log_path.read_text(
                encoding="utf-8"
            ).splitlines()

            self.assertEqual(len(lines), 20)

            events = [json.loads(line) for line in lines]

            self.assertEqual(
                len({event["source"] for event in events}),
                20
            )


if __name__ == "__main__":
    unittest.main()

