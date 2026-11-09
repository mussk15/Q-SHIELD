import socket
import time

from qshield.net.protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000


def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(300)

    try:
        client.connect((HOST, PORT))
        print("Waiting test client connected.")

        while True:
            send_message(client, "Keep this test session open")
            print("Message sent. Waiting for server response...")

            response = receive_message(client)
            print("Server response received:", response)

            time.sleep(5)

    except (ConnectionError, OSError, socket.timeout) as error:
        print("Connection closed:", error)

    finally:
        client.close()
        print("Waiting test client stopped.")


if __name__ == "__main__":
    main()