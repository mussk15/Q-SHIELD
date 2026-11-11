from getpass import getpass
from pathlib import Path
import socket

from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.sig import SignatureKeyPair
from qshield.crypto.keystore import KeyStore
from qshield.net.protocol import send_message, receive_message
from qshield.net.handshake import (
    ServerHello,
    ServerFinish,
    respond_to_server,
)
from qshield.net.secure_filetransfer import send_encrypted_file

HOST = "127.0.0.1"
PORT = 5002


def main():
    password = getpass("Client private-key password: ")

    client_private = KeyStore.load_private_key(
        "keys/client_private.keystore",
        password,
        expected_algorithm=SIGNATURE_ALGORITHM,
    )

    client_public = Path("keys/client_public.bin").read_bytes()
    trusted_server = Path("keys/server_public.bin").read_bytes()

    client_identity = SignatureKeyPair(
        public_key=client_public,
        secret_key=client_private,
    )

    file_path = Path(input("Enter the file path to send: ").strip().strip('"'))

    if not file_path.is_file():
        raise FileNotFoundError("Selected file does not exist.")

    print("Client identity loaded.")

    with socket.create_connection((HOST, PORT), timeout=120) as conn:
        conn.settimeout(120)

        hello = ServerHello.from_bytes(
            receive_message(conn).encode("utf-8")
        )

        result = respond_to_server(
            hello, trusted_server, client_identity
        )

        send_message(
            conn, result.client_finish.to_bytes().decode("utf-8")
        )

        server_finish = ServerFinish.from_bytes(
            receive_message(conn).encode("utf-8")
        )

        if not result.verify_server_finished(server_finish):
            raise RuntimeError("Server handshake confirmation failed.")

        print("Post-quantum handshake successful!")
        print("Server identity verified.")
        print("Shared session key established.")

        metadata = send_encrypted_file(
            conn, file_path, result.session_key
        )

        print("Encrypted file sent successfully!")
        print("Filename:", metadata["filename"])
        print("Size:", metadata["size"], "bytes")
        print("SHA-256:", metadata["sha256"])

        acknowledgement = receive_message(conn)

        if acknowledgement != "FILE_RECEIVED_AND_VERIFIED":
            raise RuntimeError("Server did not confirm file verification.")

        print("Server confirmed successful decryption and integrity verification.")


if __name__ == "__main__":
    main()
