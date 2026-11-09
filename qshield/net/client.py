import socket

from qshield.net.protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(10)

try:
    client.connect((HOST, PORT))

    print("Connected to Q-SHIELD Server!")

    send_message(client, "Hello Q-SHIELD Server!")

    response = receive_message(client)

    print("Server response:", response)

except ConnectionResetError:
    print("Connection rejected or closed by Q-SHIELD Server.")
    print("Check the server terminal for the rejection reason.")

except ConnectionRefusedError:
    print("Connection refused. Make sure the Q-SHIELD server is running.")

except socket.timeout:
    print("Connection timed out.")

except (ConnectionError, OSError) as error:
    print("Network communication error:", error)

finally:
    client.close()