import struct

MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB


def send_message(conn, message):
    if not isinstance(message, str):
        raise TypeError("Message must be a string")

    data = message.encode("utf-8")

    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large")

    length = len(data)

    header = struct.pack("!I", length)

    conn.sendall(header + data)


def receive_exact(conn, size):
    data = bytearray()

    while len(data) < size:
        chunk = conn.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed")

        data.extend(chunk)

    return bytes(data)


def receive_message(conn):
    header = receive_exact(conn, 4)

    length = struct.unpack("!I", header)[0]

    if length > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large")

    data = receive_exact(conn, length)

    return data.decode("utf-8")