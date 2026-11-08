import socket
import threading
import unittest

import qshield.net.server as server_module


class TestServer(unittest.TestCase):

    def test_idle_client_times_out_and_releases_slot(self):
        acquired = server_module.client_slots.acquire(blocking=False)
        self.assertTrue(acquired, "A client slot should be available")

        client_socket, peer_socket = socket.socketpair()
        original_timeout = server_module.CLIENT_TIMEOUT

        server_module.CLIENT_TIMEOUT = 0.2

        worker = threading.Thread(
            target=server_module.handle_client,
            args=(client_socket, ("test-client", 12345)),
            daemon=True
        )

        try:
            worker.start()
            worker.join(timeout=3)

            self.assertFalse(
                worker.is_alive(),
                "Idle client handler should finish after timeout"
            )

            self.assertEqual(
                peer_socket.recv(1),
                b"",
                "Server should close the idle client connection"
            )

            # Check that the client slot was released
            slot_available = server_module.client_slots.acquire(
                blocking=False
            )

            self.assertTrue(
                slot_available,
                "Client slot should be released after timeout"
            )

            if slot_available:
                server_module.client_slots.release()

        finally:
            server_module.CLIENT_TIMEOUT = original_timeout
            peer_socket.close()
            client_socket.close()


if __name__ == "__main__":
    unittest.main()
