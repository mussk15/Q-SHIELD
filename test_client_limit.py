import socket

HOST = "127.0.0.1"
PORT = 5000

connections = []

try:
    # Connect five clients and keep their connections open
    for i in range(5):
        client = socket.create_connection((HOST, PORT))
        client.settimeout(3)
        connections.append(client)

        print(f"Client {i + 1}: Connected successfully")

    # Try connecting a sixth client
    print("\nTrying to connect the sixth client...")

    sixth_client = socket.create_connection((HOST, PORT))
    sixth_client.settimeout(3)

    response = sixth_client.recv(1)

    if response == b"":
        print("Client 6: Rejected successfully!")
    else:
        print("Client 6: Unexpected response received.")

    sixth_client.close()

except Exception as error:
    print("Test error:", error)

finally:
    for client in connections:
        client.close()

    print("\nAll test connections closed.")
