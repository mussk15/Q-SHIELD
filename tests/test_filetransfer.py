import hashlib
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from qshield.net.filetransfer import (
    send_file,
    receive_file
)


class TestFileTransfer(unittest.TestCase):

    def transfer(self, source, destination):
        sender, receiver = socket.socketpair()
        errors = []

        def send():
            try:
                send_file(sender, source)
            except Exception as error:
                errors.append(error)
            finally:
                sender.close()

        worker = threading.Thread(target=send)
        worker.start()

        try:
            result = receive_file(receiver, destination)
        finally:
            receiver.close()
            worker.join(timeout=5)

        self.assertFalse(worker.is_alive(), "Sender thread did not finish")

        if errors:
            raise errors[0]

        return result

    def test_binary_file_transfer(self):
        with tempfile.TemporaryDirectory() as source_dir, \
             tempfile.TemporaryDirectory() as destination_dir:

            source = Path(source_dir) / "sample.bin"
            original_data = bytes(range(256)) * 1000
            source.write_bytes(original_data)

            received = self.transfer(source, destination_dir)

            self.assertEqual(received.read_bytes(), original_data)

            self.assertEqual(
                hashlib.sha256(received.read_bytes()).hexdigest(),
                hashlib.sha256(original_data).hexdigest()
            )

    def test_empty_file_transfer(self):
        with tempfile.TemporaryDirectory() as source_dir, \
             tempfile.TemporaryDirectory() as destination_dir:

            source = Path(source_dir) / "empty.txt"
            source.write_bytes(b"")

            received = self.transfer(source, destination_dir)

            self.assertEqual(received.read_bytes(), b"")

    def test_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as source_dir, \
             tempfile.TemporaryDirectory() as destination_dir:

            source = Path(source_dir) / "report.txt"
            source.write_text("New content", encoding="utf-8")

            existing = Path(destination_dir) / "report.txt"
            existing.write_text("Original content", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                self.transfer(source, destination_dir)

            self.assertEqual(
                existing.read_text(encoding="utf-8"),
                "Original content"
            )

    def test_hash_mismatch_rejected(self):
        sender, receiver = socket.socketpair()

        metadata = {
            "filename": "tampered.txt",
            "size": 4,
            "sha256": "0" * 64
        }

        encoded = json.dumps(metadata).encode("utf-8")

        sender.sendall(struct.pack("!I", len(encoded)) + encoded + b"TEST")

        try:
            with tempfile.TemporaryDirectory() as destination_dir:
                with self.assertRaisesRegex(
                    ValueError, "integrity verification failed"
                ):
                    receive_file(receiver, destination_dir)

                self.assertEqual(
                    list(Path(destination_dir).iterdir()),
                    []
                )
        finally:
            sender.close()
            receiver.close()


if __name__ == "__main__":
    unittest.main()
