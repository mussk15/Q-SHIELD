import socket
from qshield.net.protocol import send_message, receive_message

HOST = "127.0.0.1"
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((HOST, PORT))
server.listen()

print("Q-SHIELD Server is running...")
print("Waiting for a client connection...")

conn, addr = server.accept()

print("Connected by:", addr)

message = receive_message(conn)

print("Client says:", message)

send_message(conn, "Message received by Q-SHIELD Server!")

conn.close()
server.close()