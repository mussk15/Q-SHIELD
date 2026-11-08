import socket
import threading

from qshield.net.protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000


def handle_client(conn, addr):
    print("Connected by:", addr)

    try:
        message = receive_message(conn)

        print("Client says:", message)

        send_message(conn, "Message received by Q-SHIELD Server!")

    except (ConnectionError, OSError, ValueError) as error:
        print("Client communication error:", error)

    finally:
        conn.close()
        print("Connection closed:", addr)


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))

    server.listen(5)

    print("Q-SHIELD Server is running...")
    print("Waiting for client connections...")

    try:
        while True:
            conn, addr = server.accept()

            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            )

            client_thread.start()

    except KeyboardInterrupt:
        print("\nQ-SHIELD Server is shutting down...")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()