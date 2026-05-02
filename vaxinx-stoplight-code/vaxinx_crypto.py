from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent
KEY_FILE = BASE_DIR / "secret.key"


def load_or_create_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()

    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    return key


def encrypt_bytes(data: bytes) -> bytes:
    return Fernet(load_or_create_key()).encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return Fernet(load_or_create_key()).decrypt(data)