import struct

def send_message(conn, message):
    data = message.encode("utf-8")

    length = len(data)

    header = struct.pack("!I", length)

    conn.sendall(header + data)


def receive_exact(conn, size):
    data = b""

    while len(data) < size:
        chunk = conn.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data += chunk

    return data


def receive_message(conn):
    header = receive_exact(conn, 4)

    length = struct.unpack("!I", header)[0]

    if length > 1024 * 1024:
        raise ValueError("Message too large")

    data = receive_exact(conn, length)

    return data.decode("utf-8")