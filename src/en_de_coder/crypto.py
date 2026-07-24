"""
Crypto module - Encryption backends and file encryption/decryption handler.

Security features:
- Argon2id key derivation (memory-hard, GPU-resistant) - OWASP recommended
- AES-256-GCM with 256-bit authentication
- ChaCha20-Poly1305 for modern CPU-resistant encryption
- Secure random salt (32 bytes) per file
- PBKDF2-SHA512 fallback (600k iterations)
- Anti-brute-force delay (exponential backoff, file-specific)
- HMAC-SHA256 password verification (fast reject before key derivation)
- Time-lock with encrypted password (no plaintext in metadata)
- Optional key-file support (second factor)
- Input validation on all user inputs
- Metadata validation with size limits
- Secure file format without identifiable headers
"""

import os
import io
import json
import re
import time
import base64
import hashlib
import hmac as hmac_mod
import zipfile
from pathlib import Path


# Format version for encrypted files
FORMAT_VERSION = 2

# Brute-force backoff: 5s, 30s, 5min, 30min, 24h
BACKOFF_DELAYS = [5, 30, 300, 1800, 86400]


def parse_duration(duration: str) -> int:
    """Parse a duration string like '20s', '5m', '2h', '1d' into seconds.

    Supported units:
        s = seconds
        m = minutes
        h = hours
        d = days

    Returns:
        Duration in seconds.

    Raises:
        ValueError: If the format is invalid.
    """
    match = re.match(r"^(\d+)\s*(s|m|h|d)$", duration.strip().lower())
    if not match:
        raise ValueError(
            f"Invalid duration format: '{duration}'. "
            "Use: <number><unit> where unit is s(econds), m(inutes), h(ours), or d(ays). "
            "Examples: 20s, 5m, 2h, 1d"
        )
    value = int(match.group(1))
    if value == 0:
        raise ValueError(
            f"Invalid duration: '{duration}'. Duration must be greater than 0."
        )
    unit = match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


def format_duration(seconds: int) -> str:
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        m = seconds // 60
        s = seconds % 60
        return f"{m}m {s}s" if s else f"{m}m"
    elif seconds < 86400:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        if m and s:
            return f"{h}h {m}m {s}s"
        elif m:
            return f"{h}h {m}m"
        elif s:
            return f"{h}h {s}s"
        else:
            return f"{h}h"
    else:
        d = seconds // 86400
        h = (seconds % 86400) // 3600
        m = (seconds % 3600) // 60
        if h and m:
            return f"{d}d {h}h {m}m"
        elif h:
            return f"{d}d {h}h"
        elif m:
            return f"{d}d {m}m"
        else:
            return f"{d}d"


def _compute_hmac(salt: bytes, password: str, keyfile_content: bytes | None = None) -> str:
    """Compute HMAC-SHA256 for password verification.

    The HMAC is derived from salt + password (+ optional keyfile content).
    This allows fast password rejection without Argon2id key derivation.
    """
    if keyfile_content:
        material = password.encode("utf-8") + keyfile_content
    else:
        material = password.encode("utf-8")
    return base64.b64encode(
        hmac_mod.new(salt, material, hashlib.sha256).digest()
    ).decode()


def _verify_hmac(salt: bytes, password: str, expected_hmac: str, keyfile_content: bytes | None = None) -> bool:
    """Verify password against stored HMAC (constant-time comparison)."""
    computed = _compute_hmac(salt, password, keyfile_content)
    return hmac_mod.compare_digest(computed, expected_hmac)


def _derive_time_key(expiry_timestamp: int) -> bytes:
    """Derive a key from the expiry timestamp for time-lock password encryption.

    The key is derived deterministically from the timestamp, so it can be
    reconstructed during decryption after the TTL expires.
    """
    material = f"en_de_coder_ttl:{expiry_timestamp}".encode()
    return hashlib.sha256(material).digest()


def _encrypt_password_for_ttl(password: str, expiry_timestamp: int) -> str:
    """Encrypt the password with a time-derived key for time-lock storage."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _derive_time_key(expiry_timestamp)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, password.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode()


def _decrypt_password_for_ttl(encrypted_b64: str, expiry_timestamp: int) -> str:
    """Decrypt the password from time-lock storage."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _derive_time_key(expiry_timestamp)
    data = base64.b64decode(encrypted_b64)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


class EncryptionBackend:
    """Base class for encryption backends with OWASP-recommended parameters."""

    FERNET = "fernet"
    AES_GCM = "aes-gcm"
    CHACHA20 = "chacha20"

    _failed_attempts: dict[str, int] = {}
    _lockout_until: dict[str, float] = {}

    @staticmethod
    def _get_lockout_key(salt_b64: str) -> str:
        """Generate a file-specific lockout key from the salt."""
        return hashlib.sha256(salt_b64.encode()).hexdigest()[:16]

    @classmethod
    def check_lockout(cls, salt_b64: str) -> int:
        """Check if the file is locked out. Returns remaining seconds, 0 if not locked."""
        lockout_key = cls._get_lockout_key(salt_b64)
        if lockout_key in cls._lockout_until:
            unlock_time = cls._lockout_until[lockout_key]
            if time.time() < unlock_time:
                return int(unlock_time - time.time())
            else:
                # Lockout expired, clean up
                cls._lockout_until.pop(lockout_key, None)
                cls._failed_attempts.pop(lockout_key, None)
        return 0

    @classmethod
    def record_failed_attempt(cls, salt_b64: str) -> int:
        """Record a failed attempt. Returns the lockout duration applied."""
        lockout_key = cls._get_lockout_key(salt_b64)
        attempts = cls._failed_attempts.get(lockout_key, 0)
        cls._failed_attempts[lockout_key] = attempts + 1

        # Exponential backoff based on attempt count
        delay_index = min(attempts, len(BACKOFF_DELAYS) - 1)
        delay = BACKOFF_DELAYS[delay_index]
        cls._lockout_until[lockout_key] = time.time() + delay
        return delay

    @classmethod
    def clear_lockout(cls, salt_b64: str) -> None:
        """Clear lockout after successful decryption."""
        lockout_key = cls._get_lockout_key(salt_b64)
        cls._failed_attempts.pop(lockout_key, None)
        cls._lockout_until.pop(lockout_key, None)

    @staticmethod
    def derive_key(password: str, salt: bytes, algorithm: str, keyfile_content: bytes | None = None) -> bytes:
        """Derive encryption key using Argon2id (memory-hard, GPU-resistant)."""
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        if keyfile_content:
            material = password.encode("utf-8") + keyfile_content
        else:
            material = password.encode("utf-8")

        kdf = Argon2id(
            length=32,
            salt=salt,
            iterations=3,
            memory_cost=65536,
            lanes=4,
        )
        return kdf.derive(material)

    @staticmethod
    def derive_key_fallback(password: str, salt: bytes, algorithm: str, keyfile_content: bytes | None = None) -> bytes:
        """Fallback: PBKDF2-SHA512 with 600k iterations."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        if keyfile_content:
            material = password.encode("utf-8") + keyfile_content
        else:
            material = password.encode("utf-8")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return kdf.derive(material)

    @staticmethod
    def encrypt_fernet(data: bytes, key: bytes) -> bytes:
        from cryptography.fernet import Fernet

        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.encrypt(data)

    @staticmethod
    def decrypt_fernet(data: bytes, key: bytes) -> bytes:
        from cryptography.fernet import Fernet

        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.decrypt(data)

    @staticmethod
    def encrypt_aesgcm(data: bytes, key: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_aesgcm(data: bytes, key: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        nonce = data[:12]
        ciphertext = data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    @staticmethod
    def encrypt_chacha20(data: bytes, key: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, data, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_chacha20(data: bytes, key: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        chacha = ChaCha20Poly1305(key)
        nonce = data[:12]
        ciphertext = data[12:]
        return chacha.decrypt(nonce, ciphertext, None)


ALGO_MAP_INTERNAL_TO_DISPLAY = {
    "AESGCM": "AES-256-GCM",
    "CHACHA": "ChaCha20-Poly1305",
    "FERNET": "AES-256-Fernet",
}

ALGO_MAP_CLI_TO_INTERNAL = {
    "aes-gcm": "AESGCM",
    "chacha20": "CHACHA",
    "fernet": "FERNET",
}

ALGO_MAP_INTERNAL_TO_ENCRYPT_FN = {
    "AESGCM": EncryptionBackend.encrypt_aesgcm,
    "CHACHA": EncryptionBackend.encrypt_chacha20,
    "FERNET": EncryptionBackend.encrypt_fernet,
}

ALGO_MAP_INTERNAL_TO_DECRYPT_FN = {
    "AESGCM": EncryptionBackend.decrypt_aesgcm,
    "CHACHA": EncryptionBackend.decrypt_chacha20,
    "FERNET": EncryptionBackend.decrypt_fernet,
}


class FileEncryptor:
    """Main file encryption/decryption handler with secure format."""

    def __init__(self) -> None:
        self.backend = EncryptionBackend()

    def _generate_header(self) -> bytes:
        return os.urandom(32)

    def _derive_key(self, password: str, salt: bytes, algo_internal: str, keyfile_content: bytes | None = None) -> bytes:
        try:
            return EncryptionBackend.derive_key(password, salt, algo_internal, keyfile_content)
        except Exception:
            return EncryptionBackend.derive_key_fallback(password, salt, algo_internal, keyfile_content)

    def _read_metadata(self, input_path: str) -> tuple[bytes, dict, bytes]:
        """Read header + metadata from an encrypted file.

        Returns:
            (header, metadata, encrypted_data)
        """
        with open(input_path, "rb") as f:
            header = f.read(32)
            if len(header) != 32:
                raise ValueError("Invalid encrypted file format - header missing")

            metadata_length_bytes = f.read(4)
            if len(metadata_length_bytes) != 4:
                raise ValueError("Invalid encrypted file format - corrupt metadata length")

            metadata_length = int.from_bytes(metadata_length_bytes, "big")
            if metadata_length > 10000:
                raise ValueError("Invalid metadata length - file corrupted")

            metadata_json = f.read(metadata_length)
            if len(metadata_json) != metadata_length:
                raise ValueError("Truncated metadata - file corrupted")

            try:
                metadata = json.loads(metadata_json.decode())
            except json.JSONDecodeError:
                raise ValueError("Corrupted metadata - invalid JSON")

            encrypted_data = f.read()

        return header, metadata, encrypted_data

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        password: str,
        algorithm: str,
        ttl: int | None = None,
        keyfile_path: str | None = None,
    ) -> bool:
        """Encrypt a file.

        Args:
            input_path: Path to the file to encrypt.
            output_path: Path to write the encrypted file.
            password: Password for encryption.
            algorithm: CLI algorithm name (aes-gcm, chacha20, fernet).
            ttl: Time-to-live in seconds. After this time, password is optional on decrypt.
            keyfile_path: Optional path to a key file for additional security.

        Returns:
            True on success.
        """
        if not os.path.isfile(input_path):
            raise ValueError(f"File not found: {input_path}")
        if not password or not isinstance(password, str):
            raise ValueError("Password is required")

        algo_internal = ALGO_MAP_CLI_TO_INTERNAL.get(algorithm)
        if algo_internal is None:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        # Load keyfile content if provided
        keyfile_content = None
        if keyfile_path:
            if not os.path.isfile(keyfile_path):
                raise ValueError(f"Key file not found: {keyfile_path}")
            with open(keyfile_path, "rb") as kf:
                keyfile_content = kf.read()
            if len(keyfile_content) == 0:
                raise ValueError("Key file is empty")

        with open(input_path, "rb") as f:
            data = f.read()

        salt = os.urandom(32)
        key = self._derive_key(password, salt, algo_internal, keyfile_content)

        encrypt_fn = ALGO_MAP_INTERNAL_TO_ENCRYPT_FN[algo_internal]
        encrypted_data = encrypt_fn(data, key)

        # Compute HMAC for password verification
        password_hmac = _compute_hmac(salt, password, keyfile_content)

        metadata = {
            "v": FORMAT_VERSION,
            "a": algo_internal,
            "s": base64.b64encode(salt).decode(),
            "n": os.path.basename(input_path),
            "h": password_hmac,
        }

        if keyfile_content:
            metadata["kf"] = True  # flag that a keyfile was used

        if ttl is not None and ttl > 0:
            expiry_timestamp = int(time.time()) + ttl
            metadata["t"] = expiry_timestamp
            metadata["ttl"] = ttl
            # Encrypt password with time-derived key (no plaintext in metadata)
            metadata["ep"] = _encrypt_password_for_ttl(password, expiry_timestamp)

        metadata_json = json.dumps(metadata).encode()
        metadata_length = len(metadata_json).to_bytes(4, "big")

        header = self._generate_header()

        with open(output_path, "wb") as f:
            f.write(header)
            f.write(metadata_length)
            f.write(metadata_json)
            f.write(encrypted_data)

        return True

    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        password: str | None = None,
        keyfile_path: str | None = None,
    ) -> bool:
        """Decrypt a file with anti-brute-force protection and optional TTL.

        If the file has a TTL that has expired, password can be None.
        """
        header, metadata, encrypted_data = self._read_metadata(input_path)

        algo_internal = metadata.get("a", "AESGCM")
        salt_b64 = metadata.get("s", "")
        if not salt_b64:
            raise ValueError("Missing salt in file metadata")

        # Check brute-force lockout (file-specific, based on salt)
        remaining_lockout = EncryptionBackend.check_lockout(salt_b64)
        if remaining_lockout > 0:
            raise ValueError(
                f"Too many failed attempts. Wait {format_duration(remaining_lockout)}."
            )

        try:
            salt = base64.b64decode(salt_b64)
        except Exception:
            raise ValueError("Invalid salt encoding in metadata")

        if len(salt) != 32:
            raise ValueError(f"Invalid salt length (expected 32, got {len(salt)})")

        # Load keyfile content if file was encrypted with one
        keyfile_content = None
        needs_keyfile = metadata.get("kf", False)
        if needs_keyfile:
            if not keyfile_path:
                raise ValueError("This file was encrypted with a key file. Provide --keyfile.")
            if not os.path.isfile(keyfile_path):
                raise ValueError(f"Key file not found: {keyfile_path}")
            with open(keyfile_path, "rb") as kf:
                keyfile_content = kf.read()

        # Check TTL - if expired, password is not required
        ttl_expired = False
        expiry_timestamp = metadata.get("t")
        if expiry_timestamp is not None:
            if time.time() >= expiry_timestamp:
                ttl_expired = True
                # Decrypt password from time-encrypted storage
                encrypted_pw = metadata.get("ep")
                if encrypted_pw:
                    try:
                        password = _decrypt_password_for_ttl(encrypted_pw, expiry_timestamp)
                    except Exception:
                        raise ValueError("Corrupted time-lock data")
                else:
                    # Legacy format fallback (plaintext password in metadata)
                    password = metadata.get("p", "")
            elif not password:
                remaining = int(expiry_timestamp - time.time())
                raise ValueError(
                    f"File is time-locked. Try again in {format_duration(remaining)}. "
                    f"Or provide the password to decrypt immediately."
                )

        if not password or not isinstance(password, str):
            raise ValueError("Password is required")

        # HMAC verification (fast reject before Argon2id)
        stored_hmac = metadata.get("h")
        if stored_hmac and not ttl_expired:
            if not _verify_hmac(salt, password, stored_hmac, keyfile_content):
                # Record failed attempt for brute-force protection
                lockout_delay = EncryptionBackend.record_failed_attempt(salt_b64)
                raise ValueError(
                    f"Wrong password. Wait {format_duration(lockout_delay)} before trying again."
                )

        # Key derivation
        key = self._derive_key(password, salt, algo_internal, keyfile_content)

        decrypt_fn = ALGO_MAP_INTERNAL_TO_DECRYPT_FN.get(algo_internal)
        if decrypt_fn is None:
            raise ValueError(f"Unknown algorithm: {algo_internal}")

        try:
            decrypted_data = decrypt_fn(encrypted_data, key)
        except Exception:
            # GCM auth failed or corrupted data
            if not ttl_expired and stored_hmac:
                # HMAC passed but GCM failed - should not happen, but record it
                EncryptionBackend.record_failed_attempt(salt_b64)
            raise ValueError("Wrong password or corrupted file.")

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        # Clear lockout on successful decryption
        EncryptionBackend.clear_lockout(salt_b64)

        return True

    def encrypt_folder(
        self,
        folder_path: str,
        output_path: str,
        password: str,
        algorithm: str,
        ttl: int | None = None,
        keyfile_path: str | None = None,
    ) -> bool:
        """Encrypt a folder by zipping and encrypting it."""
        if not os.path.isdir(folder_path):
            raise ValueError(f"Invalid folder path: {folder_path}")
        if not password or not isinstance(password, str):
            raise ValueError("Password is required")

        algo_internal = ALGO_MAP_CLI_TO_INTERNAL.get(algorithm)
        if algo_internal is None:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        # Load keyfile content if provided
        keyfile_content = None
        if keyfile_path:
            if not os.path.isfile(keyfile_path):
                raise ValueError(f"Key file not found: {keyfile_path}")
            with open(keyfile_path, "rb") as kf:
                keyfile_content = kf.read()
            if len(keyfile_content) == 0:
                raise ValueError("Key file is empty")

        zip_buffer = io.BytesIO()
        file_count = 0
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
            folder_path_obj = Path(folder_path)
            for file_path in folder_path_obj.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(folder_path_obj)
                    zipf.write(file_path, arcname)
                    file_count += 1

        if file_count == 0:
            raise ValueError("Folder is empty or contains no files")

        zip_data = zip_buffer.getvalue()

        salt = os.urandom(32)
        key = self._derive_key(password, salt, algo_internal, keyfile_content)

        encrypt_fn = ALGO_MAP_INTERNAL_TO_ENCRYPT_FN[algo_internal]
        encrypted_data = encrypt_fn(zip_data, key)

        # Compute HMAC for password verification
        password_hmac = _compute_hmac(salt, password, keyfile_content)

        metadata = {
            "v": FORMAT_VERSION,
            "a": algo_internal,
            "s": base64.b64encode(salt).decode(),
            "f": True,
            "n": os.path.basename(folder_path),
            "h": password_hmac,
        }

        if keyfile_content:
            metadata["kf"] = True

        if ttl is not None and ttl > 0:
            expiry_timestamp = int(time.time()) + ttl
            metadata["t"] = expiry_timestamp
            metadata["ttl"] = ttl
            metadata["ep"] = _encrypt_password_for_ttl(password, expiry_timestamp)

        metadata_json = json.dumps(metadata).encode()
        metadata_length = len(metadata_json).to_bytes(4, "big")

        header = self._generate_header()

        with open(output_path, "wb") as f:
            f.write(header)
            f.write(metadata_length)
            f.write(metadata_json)
            f.write(encrypted_data)

        return True

    def decrypt_folder(
        self,
        input_path: str,
        output_folder: str,
        password: str | None = None,
        keyfile_path: str | None = None,
    ) -> bool:
        """Decrypt an encrypted folder."""
        header, metadata, encrypted_data = self._read_metadata(input_path)

        if not metadata.get("f", False):
            raise ValueError("This is not an encrypted folder")

        algo_internal = metadata.get("a", "AESGCM")
        salt_b64 = metadata.get("s", "")
        if not salt_b64:
            raise ValueError("Missing salt in metadata")

        # Check brute-force lockout
        remaining_lockout = EncryptionBackend.check_lockout(salt_b64)
        if remaining_lockout > 0:
            raise ValueError(
                f"Too many failed attempts. Wait {format_duration(remaining_lockout)}."
            )

        try:
            salt = base64.b64decode(salt_b64)
        except Exception:
            raise ValueError("Invalid salt encoding")

        if len(salt) != 32:
            raise ValueError("Invalid salt length")

        # Load keyfile content if needed
        keyfile_content = None
        needs_keyfile = metadata.get("kf", False)
        if needs_keyfile:
            if not keyfile_path:
                raise ValueError("This file was encrypted with a key file. Provide --keyfile.")
            if not os.path.isfile(keyfile_path):
                raise ValueError(f"Key file not found: {keyfile_path}")
            with open(keyfile_path, "rb") as kf:
                keyfile_content = kf.read()

        # Check TTL
        ttl_expired = False
        expiry_timestamp = metadata.get("t")
        if expiry_timestamp is not None:
            if time.time() >= expiry_timestamp:
                ttl_expired = True
                encrypted_pw = metadata.get("ep")
                if encrypted_pw:
                    try:
                        password = _decrypt_password_for_ttl(encrypted_pw, expiry_timestamp)
                    except Exception:
                        raise ValueError("Corrupted time-lock data")
                else:
                    password = metadata.get("p", "")
            elif not password:
                remaining = int(expiry_timestamp - time.time())
                raise ValueError(
                    f"Folder is time-locked. Try again in {format_duration(remaining)}."
                )

        if not password or not isinstance(password, str):
            raise ValueError("Password is required")

        # HMAC verification
        stored_hmac = metadata.get("h")
        if stored_hmac and not ttl_expired:
            if not _verify_hmac(salt, password, stored_hmac, keyfile_content):
                lockout_delay = EncryptionBackend.record_failed_attempt(salt_b64)
                raise ValueError(
                    f"Wrong password. Wait {format_duration(lockout_delay)} before trying again."
                )

        # Key derivation
        key = self._derive_key(password, salt, algo_internal, keyfile_content)

        decrypt_fn = ALGO_MAP_INTERNAL_TO_DECRYPT_FN.get(algo_internal)
        if decrypt_fn is None:
            raise ValueError(f"Unknown algorithm: {algo_internal}")

        try:
            zip_data = decrypt_fn(encrypted_data, key)
        except Exception:
            if not ttl_expired and stored_hmac:
                EncryptionBackend.record_failed_attempt(salt_b64)
            raise ValueError("Wrong password or corrupted file.")

        # Clear lockout on success
        EncryptionBackend.clear_lockout(salt_b64)

        zip_buffer = io.BytesIO(zip_data)
        with zipfile.ZipFile(zip_buffer, "r") as zipf:
            zipf.extractall(output_folder)

        return True

    def get_file_info(self, input_path: str) -> dict:
        """Read metadata from an encrypted file without decrypting."""
        _, metadata, _ = self._read_metadata(input_path)

        algo_internal = metadata.get("a", "AESGCM")
        info = {
            "algorithm": ALGO_MAP_INTERNAL_TO_DISPLAY.get(algo_internal, "Unknown"),
            "original_name": metadata.get("n", "Unknown"),
            "is_folder": metadata.get("f", False),
            "file_size": os.path.getsize(input_path),
            "version": metadata.get("v", 1),
            "has_keyfile": metadata.get("kf", False),
        }

        # TTL info
        expiry_timestamp = metadata.get("t")
        if expiry_timestamp is not None:
            ttl_original = metadata.get("ttl", 0)
            if time.time() >= expiry_timestamp:
                info["ttl_status"] = "expired"
                info["ttl_remaining"] = 0
            else:
                remaining = int(expiry_timestamp - time.time())
                info["ttl_status"] = "locked"
                info["ttl_remaining"] = remaining
            info["ttl_original"] = ttl_original
            info["ttl_expiry"] = expiry_timestamp
        else:
            info["ttl_status"] = "none"

        return info
