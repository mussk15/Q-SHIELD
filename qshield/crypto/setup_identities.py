"""Generate Q-SHIELD server and client identity keys."""

from getpass import getpass
from pathlib import Path

from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.sig import MLDSA65
from qshield.crypto.keystore import KeyStore

KEY_DIR = Path("keys")


def main():
    KEY_DIR.mkdir(exist_ok=True)

    files = [
        KEY_DIR / "server_private.keystore",
        KEY_DIR / "server_public.bin",
        KEY_DIR / "client_private.keystore",
        KEY_DIR / "client_public.bin",
    ]

    existing = [path for path in files if path.exists()]
    if existing:
        print("Identity files already exist. No files overwritten:")
        for path in existing:
            print(f" - {path}")
        return

    password = getpass("Create a password for the encrypted private keys: ")
    confirmation = getpass("Confirm password: ")

    if not password or password != confirmation:
        print("Passwords are empty or do not match. Exiting.")
        return

    signer = MLDSA65()

    print("Generating server identity...")
    server = signer.generate_keypair()

    print("Generating client identity...")
    client = signer.generate_keypair()

    KeyStore.save_private_key(
        KEY_DIR / "server_private.keystore",
        server.secret_key,
        password,
        algorithm=SIGNATURE_ALGORITHM,
    )

    KeyStore.save_private_key(
        KEY_DIR / "client_private.keystore",
        client.secret_key,
        password,
        algorithm=SIGNATURE_ALGORITHM,
    )

    (KEY_DIR / "server_public.bin").write_bytes(server.public_key)
    (KEY_DIR / "client_public.bin").write_bytes(client.public_key)

    print("\nIdentity keys generated successfully!")
    print("Four identity files created inside the keys folder.")
    print("Never upload private keys or passwords to GitHub.")


if __name__ == "__main__":
    main()
