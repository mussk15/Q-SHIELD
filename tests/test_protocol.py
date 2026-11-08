import socket
import struct
import unittest

from qshield.net.protocol import (
    send_message,
    receive_message
)


class TestProtocol(unittest.TestCase):

    def test_normal_message(self):
        sender, receiver = socket.socketpair()

        try:
            send_message(sender, "Hello Q-SHIELD")

            result = receive_message(receiver)

            self.assertEqual(result, "Hello Q-SHIELD")

        finally:
            sender.close()
            receiver.close()

    def test_unicode_message(self):
        sender, receiver = socket.socketpair()

        try:
            send_message(sender, "Hello नमस्ते")

            result = receive_message(receiver)

            self.assertEqual(result, "Hello नमस्ते")

        finally:
            sender.close()
            receiver.close()

    def test_large_message_rejected(self):
        sender, receiver = socket.socketpair()

        try:
            sender.sendall(struct.pack("!I", 1024 * 1024 + 1))

            with self.assertRaises(ValueError):
                receive_message(receiver)

        finally:
            sender.close()
            receiver.close()

    def test_outgoing_large_message_rejected(self):
        sender, receiver = socket.socketpair()

        try:
            message = "A" * (1024 * 1024 + 1)

            with self.assertRaises(ValueError):
                send_message(sender, message)

        finally:
            sender.close()
            receiver.close()

    def test_invalid_message_type_rejected(self):
        sender, receiver = socket.socketpair()

        try:
            with self.assertRaises(TypeError):
                send_message(sender, 12345)

        finally:
            sender.close()
            receiver.close()

    def test_fragmented_message(self):

        class ChunkedSocket:
            def __init__(self, data):
                self.data = data

            def recv(self, size):
                chunk = self.data[:2]
                self.data = self.data[2:]
                return chunk

        message = "Hello Q-SHIELD"

        encoded = message.encode("utf-8")
        header = struct.pack("!I", len(encoded))

        fake_socket = ChunkedSocket(header + encoded)

        result = receive_message(fake_socket)

        self.assertEqual(result, message)

    def test_invalid_utf8_rejected(self):
        sender, receiver = socket.socketpair()

        try:
            invalid_data = b"\xff"

            header = struct.pack("!I", len(invalid_data))

            sender.sendall(header + invalid_data)

            with self.assertRaises(UnicodeDecodeError):
                receive_message(receiver)

        finally:
            sender.close()
            receiver.close()


if __name__ == "__main__":
    unittest.main()