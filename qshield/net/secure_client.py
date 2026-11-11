from getpass import getpass
import base64
import socket

from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.sig import MLDSA65, SignatureKeyPair
from qshield.crypto.keystore import KeyStore
from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.net.protocol import send_message, receive_message
from qshield.net.handshake import (
    ServerHello,
    ServerFinish,
    respond_to_server,
)

HOST = "127.0.0.1"
PORT = 5001
AAD = b"QSHIELD_APP_V1"


def main():
    password = getpass("Client private-key password: ")

    client_private = KeyStore.load_private_key(
        "keys/client_private.keystore",
        password,
        expected_algorithm=SIGNATURE_ALGORITHM,
    )
    client_public = open("keys/client_public.bin", "rb").read()
    trusted_server = open("keys/server_public.bin", "rb").read()

    client_identity = SignatureKeyPair(
        public_key=client_public,
        secret_key=client_private,
    )

    print("Client identity loaded.")

    with socket.create_connection((HOST, PORT), timeout=60) as conn:
        conn.settimeout(60)

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
            raise RuntimeError("Server handshake confirmation failed!")

        print("Post-quantum handshake successful!")
        print("Server identity verified.")
        print("Shared session key established.")

        message = b"Hello Q-SHIELD! This is an encrypted client message."

        encrypted_message = AES256GCM.encrypt(
            result.session_key, message, associated_data=AAD
        )

        send_message(
            conn, base64.b64encode(encrypted_message.to_bytes()).decode("ascii")
        )

        encrypted_reply = EncryptedMessage.from_bytes(
            base64.b64decode(receive_message(conn), validate=True)
        )

        reply = AES256GCM.decrypt(
            result.session_key, encrypted_reply, associated_data=AAD
        )

        print("Decrypted server reply:", reply.decode("utf-8"))


if __name__ == "__main__":
    main()
