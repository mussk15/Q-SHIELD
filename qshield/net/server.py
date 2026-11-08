import socket
import threading

from qshield.net.protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000

# Maximum number of clients allowed at the same time
MAX_CLIENTS = 5

# Controls how many clients can be active simultaneously
client_slots = threading.BoundedSemaphore(MAX_CLIENTS)


def handle_client(conn, addr):
    print("Connected by:", addr)

    try:
        message = receive_message(conn)

        print("Client says:", message)

        send_message(conn, "Message received by Q-SHIELD Server!")

    except (ConnectionError, OSError, ValueError, UnicodeDecodeError) as error:
        print("Client communication error:", error)

    finally:
        try:
            conn.close()
        finally:
            # Release the slot when this client disconnects
            client_slots.release()

        print("Connection closed:", addr)


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(5)

        print("Q-SHIELD Server is running...")
        print("Waiting for client connections...")
        print("Maximum active clients:", MAX_CLIENTS)

        while True:
            conn, addr = server.accept()

            # Check whether a client slot is available
            if not client_slots.acquire(blocking=False):
                print("Maximum clients reached. Rejecting:", addr)
                conn.close()
                continue

            try:
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    daemon=True
                )

                client_thread.start()

            except Exception:
                # Clean up if the thread could not start
                conn.close()
                client_slots.release()
                raise

    except KeyboardInterrupt:
        print("\nQ-SHIELD Server is shutting down...")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()