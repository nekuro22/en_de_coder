"""Internal key module - device-bound key generation and storage.

The internal key is a 32-byte random key that is:
1. Generated once during first launch
2. Encrypted with a hardware-derived key (Argon2id)
3. Stored in a hidden file in APPDATA
4. Can only be decrypted on the same device

This allows binding encrypted files to a specific device.
"""

import os
import sys
import base64
import secrets

from en_de_coder.hardware_id import get_hardware_id


def _get_key_dir() -> str:
    """Get the directory for storing the internal key."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    return os.path.join(base, "en_de_coder")


def _get_key_file() -> str:
    """Get the path to the encrypted internal key file."""
    return os.path.join(_get_key_dir(), ".sys.dat")


def _derive_storage_key(hardware_id: str) -> bytes:
    """Derive an encryption key from the hardware ID using Argon2id."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    kdf = Argon2id(
        length=32,
        salt=bytes.fromhex(hardware_id[:32]),
        iterations=3,
        memory_cost=65536,
        lanes=4,
    )
    return kdf.derive(hardware_id.encode("utf-8"))


def _encrypt_key(data: bytes, hardware_id: str) -> bytes:
    """Encrypt the internal key with a hardware-derived key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    storage_key = _derive_storage_key(hardware_id)
    aesgcm = AESGCM(storage_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def _decrypt_key(data: bytes, hardware_id: str) -> bytes:
    """Decrypt the internal key with a hardware-derived key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    storage_key = _derive_storage_key(hardware_id)
    aesgcm = AESGCM(storage_key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def _set_hidden(path: str) -> None:
    """Set file as hidden on Windows, dotfile on Unix."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, 0x02 | 0x04)
        except Exception:
            pass


class NotInitializedError(Exception):
    """Raised when the internal key has not been generated yet."""
    pass


class HardwareMismatchError(Exception):
    """Raised when trying to load the key on a different device."""
    pass


def is_initialized() -> bool:
    """Check if the internal key has been generated."""
    return os.path.isfile(_get_key_file())


def initialize() -> str:
    """Generate and store a new internal key.

    Returns:
        The short hardware ID for display purposes.
    """
    from en_de_coder.hardware_id import get_short_hardware_id

    key_dir = _get_key_dir()
    os.makedirs(key_dir, exist_ok=True)

    key_file = _get_key_file()

    # Generate random 32-byte internal key
    internal_key = secrets.token_bytes(32)

    # Encrypt with hardware-derived key
    hardware_id = get_hardware_id()
    encrypted = _encrypt_key(internal_key, hardware_id)

    # Write to file
    with open(key_file, "wb") as f:
        f.write(encrypted)

    # Set hidden attribute
    _set_hidden(key_file)

    # Zero out sensitive data from memory
    internal_key = b"\x00" * 32

    return get_short_hardware_id()


def load_intern_key() -> bytes:
    """Load and decrypt the internal key.

    Returns:
        The 32-byte internal key.

    Raises:
        NotInitializedError: If the key hasn't been generated yet.
        HardwareMismatchError: If the key can't be decrypted (different device).
    """
    if not is_initialized():
        raise NotInitializedError(
            "Internal key not found. Run 'enc install' or start the GUI to initialize."
        )

    key_file = _get_key_file()

    with open(key_file, "rb") as f:
        encrypted = f.read()

    hardware_id = get_hardware_id()

    try:
        internal_key = _decrypt_key(encrypted, hardware_id)
    except Exception:
        raise HardwareMismatchError(
            "Cannot decrypt internal key - this device does not match "
            "the device where the key was generated."
        )

    return internal_key


def get_intern_key() -> bytes:
    """Get the internal key, raising appropriate errors if unavailable."""
    return load_intern_key()


def export_key(output_path: str) -> None:
    """Export the internal key file to the given path.

    Args:
        output_path: Destination path for the exported key.

    Raises:
        NotInitializedError: If no key has been generated yet.
    """
    if not is_initialized():
        raise NotInitializedError("No internal key to export. Run 'enc install' first.")

    key_file = _get_key_file()

    import shutil
    shutil.copy2(key_file, output_path)


def import_key(input_path: str) -> None:
    """Import an internal key file, replacing the current one.

    WARNING: This deletes the old key. Files bound to the old key
    will no longer be decryptable.

    Args:
        input_path: Path to the key file to import.

    Raises:
        FileNotFoundError: If the source file does not exist.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Key file not found: {input_path}")

    key_dir = _get_key_dir()
    os.makedirs(key_dir, exist_ok=True)

    key_file = _get_key_file()

    import shutil
    shutil.copy2(input_path, key_file)
    _set_hidden(key_file)


def regenerate_key() -> str:
    """Delete the old internal key and generate a new one.

    WARNING: All device-bound files will become undecryptable after this.

    Returns:
        The short hardware ID of the new key.
    """
    key_file = _get_key_file()
    if os.path.isfile(key_file):
        os.remove(key_file)

    return initialize()


def delete_key() -> None:
    """Delete the internal key file."""
    key_file = _get_key_file()
    if os.path.isfile(key_file):
        os.remove(key_file)
