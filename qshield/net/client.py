import socket
from qshield.net.protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

print("Connected to Q-SHIELD Server!")

send_message(client, "Hello Q-SHIELD Server!")

response = receive_message(client)

print("Server response:", response)

client.close()