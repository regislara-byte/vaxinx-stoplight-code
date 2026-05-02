from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent
QUARANTINE_DIR = BASE_DIR / "quarantine"
RESTORE_DIR = BASE_DIR / "test_lab"
KEY_FILE = BASE_DIR / "secret.key"


def load_key():
    return KEY_FILE.read_bytes()


def decrypt_file(enc_path: Path, output_path: Path):
    fernet = Fernet(load_key())

    encrypted_data = enc_path.read_bytes()
    decrypted_data = fernet.decrypt(encrypted_data)

    output_path.write_bytes(decrypted_data)


def restore_all():
    for file in QUARANTINE_DIR.glob("*.vxlocked"):
        original_name = file.name.split("_", 2)[-1].replace(".vxlocked", "")
        restore_path = RESTORE_DIR / original_name

        decrypt_file(file, restore_path)

        print(f"🔓 Restored: {restore_path}")


if __name__ == "__main__":
    restore_all()
    