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


if __name__ == "__main__":
    unittest.main()