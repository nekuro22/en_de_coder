"""Unit tests for crypto.py helper functions and EncryptionBackend."""

import os
import json
import time
import base64

import pytest

from en_de_coder.crypto import (
    FileEncryptor,
    EncryptionBackend,
    parse_duration,
    format_duration,
    _compute_hmac,
    _verify_hmac,
    _derive_time_key,
    _encrypt_password_for_ttl,
    _decrypt_password_for_ttl,
    FORMAT_VERSION,
)


class TestParseDuration:
    def test_seconds(self):
        assert parse_duration("20s") == 20

    def test_minutes(self):
        assert parse_duration("5m") == 300

    def test_hours(self):
        assert parse_duration("2h") == 7200

    def test_days(self):
        assert parse_duration("1d") == 86400

    def test_case_insensitive_with_whitespace(self):
        assert parse_duration(" 5M ") == 300

    def test_invalid_no_unit(self):
        with pytest.raises(ValueError):
            parse_duration("abc")

    def test_zero_minutes(self):
        with pytest.raises(ValueError):
            parse_duration("0m")

    def test_invalid_unit(self):
        with pytest.raises(ValueError):
            parse_duration("5x")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            parse_duration("")


class TestFormatDuration:
    def test_seconds_only(self):
        assert format_duration(45) == "45s"

    def test_minutes_and_seconds(self):
        assert format_duration(90) == "1m 30s"

    def test_minutes_only(self):
        assert format_duration(120) == "2m"

    def test_hours_minutes_seconds(self):
        assert format_duration(3661) == "1h 1m 1s"

    def test_hours_only(self):
        assert format_duration(3600) == "1h"

    def test_hours_minutes(self):
        assert format_duration(7200) == "2h"

    def test_days_hours_minutes(self):
        assert format_duration(90061) == "1d 1h 1m"

    def test_days_only(self):
        assert format_duration(86400) == "1d"

    def test_zero_seconds(self):
        assert format_duration(0) == "0s"

    def test_fifty_nine_seconds(self):
        assert format_duration(59) == "59s"

    def test_sixty_seconds(self):
        assert format_duration(60) == "1m"


class TestDeriveTimeKey:
    def test_deterministic(self):
        ts = int(time.time()) + 3600
        assert _derive_time_key(ts) == _derive_time_key(ts)

    def test_different_timestamps_different_keys(self):
        ts1 = int(time.time()) + 3600
        ts2 = int(time.time()) + 7200
        assert _derive_time_key(ts1) != _derive_time_key(ts2)

    def test_returns_32_bytes(self):
        key = _derive_time_key(int(time.time()) + 3600)
        assert len(key) == 32


class TestTTLPasswordEncryption:
    def test_roundtrip(self):
        password = "SuperSecret!"
        expiry = int(time.time()) + 3600
        encrypted = _encrypt_password_for_ttl(password, expiry)
        assert _decrypt_password_for_ttl(encrypted, expiry) == password

    def test_wrong_timestamp_fails(self):
        password = "SuperSecret!"
        expiry = int(time.time()) + 3600
        encrypted = _encrypt_password_for_ttl(password, expiry)
        with pytest.raises(Exception):
            _decrypt_password_for_ttl(encrypted, expiry + 1)


class TestHMAC:
    def test_valid_hmac(self):
        salt = os.urandom(32)
        pw = "TestPassword123!"
        h = _compute_hmac(salt, pw)
        assert _verify_hmac(salt, pw, h)

    def test_wrong_password(self):
        salt = os.urandom(32)
        h = _compute_hmac(salt, "Correct")
        assert not _verify_hmac(salt, "Wrong", h)

    def test_wrong_salt(self):
        h = _compute_hmac(os.urandom(32), "pw")
        assert not _verify_hmac(os.urandom(32), "pw", h)

    def test_with_keyfile(self):
        salt = os.urandom(32)
        kf = b"keyfile bytes"
        h = _compute_hmac(salt, "pw", kf)
        assert _verify_hmac(salt, "pw", h, kf)
        assert not _verify_hmac(salt, "pw", h)
        assert not _verify_hmac(salt, "pw", h, b"wrong keyfile")


class TestKeyDerivation:
    def test_derive_key_deterministic(self):
        salt = os.urandom(32)
        k1 = EncryptionBackend.derive_key("pass", salt, "AESGCM")
        k2 = EncryptionBackend.derive_key("pass", salt, "AESGCM")
        assert k1 == k2
        assert len(k1) == 32

    def test_derive_key_different_passwords(self):
        salt = os.urandom(32)
        k1 = EncryptionBackend.derive_key("pass1", salt, "AESGCM")
        k2 = EncryptionBackend.derive_key("pass2", salt, "AESGCM")
        assert k1 != k2

    def test_derive_key_with_keyfile(self):
        salt = os.urandom(32)
        kf = b"keyfile content"
        k1 = EncryptionBackend.derive_key("pass", salt, "AESGCM")
        k2 = EncryptionBackend.derive_key("pass", salt, "AESGCM", kf)
        assert k1 != k2
        assert len(k2) == 32

    def test_derive_key_with_intern_key(self):
        salt = os.urandom(32)
        ik = os.urandom(32)
        k1 = EncryptionBackend.derive_key("pass", salt, "AESGCM")
        k2 = EncryptionBackend.derive_key("pass", salt, "AESGCM", intern_key=ik)
        assert k1 != k2

    def test_fallback_deterministic(self):
        salt = os.urandom(32)
        k1 = EncryptionBackend.derive_key_fallback("pass", salt, "AESGCM")
        k2 = EncryptionBackend.derive_key_fallback("pass", salt, "AESGCM")
        assert k1 == k2
        assert len(k1) == 32

    def test_fallback_different_passwords(self):
        salt = os.urandom(32)
        k1 = EncryptionBackend.derive_key_fallback("pass1", salt, "AESGCM")
        k2 = EncryptionBackend.derive_key_fallback("pass2", salt, "AESGCM")
        assert k1 != k2


class TestEncryptDecryptUnit:
    def test_aesgcm_roundtrip(self):
        data = b"Hello AES-GCM!"
        key = os.urandom(32)
        enc = EncryptionBackend.encrypt_aesgcm(data, key)
        dec = EncryptionBackend.decrypt_aesgcm(enc, key)
        assert dec == data

    def test_chacha20_roundtrip(self):
        data = b"Hello ChaCha20!"
        key = os.urandom(32)
        enc = EncryptionBackend.encrypt_chacha20(data, key)
        dec = EncryptionBackend.decrypt_chacha20(enc, key)
        assert dec == data

    def test_fernet_roundtrip(self):
        data = b"Hello Fernet!"
        key = os.urandom(32)
        enc = EncryptionBackend.encrypt_fernet(data, key)
        dec = EncryptionBackend.decrypt_fernet(enc, key)
        assert dec == data

    def test_wrong_key_aesgcm_fails(self):
        data = b"secret"
        enc = EncryptionBackend.encrypt_aesgcm(data, os.urandom(32))
        with pytest.raises(Exception):
            EncryptionBackend.decrypt_aesgcm(enc, os.urandom(32))

    def test_wrong_key_chacha20_fails(self):
        data = b"secret"
        enc = EncryptionBackend.encrypt_chacha20(data, os.urandom(32))
        with pytest.raises(Exception):
            EncryptionBackend.decrypt_chacha20(enc, os.urandom(32))


class TestReadMetadataErrors:
    def test_header_too_short(self, tmp_dir):
        path = os.path.join(tmp_dir, "bad.bin")
        with open(path, "wb") as f:
            f.write(b"short")
        enc = FileEncryptor()
        with pytest.raises(ValueError, match="header missing"):
            enc._read_metadata(path)

    def test_missing_metadata_length(self, tmp_dir):
        path = os.path.join(tmp_dir, "bad2.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        enc = FileEncryptor()
        with pytest.raises(ValueError, match="metadata length"):
            enc._read_metadata(path)

    def test_oversized_metadata_length(self, tmp_dir):
        path = os.path.join(tmp_dir, "bad3.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(32))
            f.write((20000).to_bytes(4, "big"))
        enc = FileEncryptor()
        with pytest.raises(ValueError, match="metadata length"):
            enc._read_metadata(path)

    def test_corrupted_metadata_json(self, tmp_dir):
        path = os.path.join(tmp_dir, "bad4.bin")
        bad_json = b"this is not json"
        with open(path, "wb") as f:
            f.write(os.urandom(32))
            f.write(len(bad_json).to_bytes(4, "big"))
            f.write(bad_json)
        enc = FileEncryptor()
        with pytest.raises(ValueError, match="JSON"):
            enc._read_metadata(path)


class TestInputValidation:
    def test_empty_password(self, sample_file):
        enc = FileEncryptor()
        out = sample_file + ".enc"
        with pytest.raises(ValueError, match="Password"):
            enc.encrypt_file(sample_file, out, "", "aes-gcm")

    def test_nonexistent_input_file(self, tmp_dir):
        enc = FileEncryptor()
        with pytest.raises(ValueError, match="File not found"):
            enc.encrypt_file(
                os.path.join(tmp_dir, "nope.txt"),
                os.path.join(tmp_dir, "nope.enc"),
                "pass",
                "aes-gcm",
            )

    def test_unknown_algorithm(self, sample_file):
        enc = FileEncryptor()
        out = sample_file + ".enc"
        with pytest.raises(ValueError, match="Unknown algorithm"):
            enc.encrypt_file(sample_file, out, "pass", "unknown-algo")

    def test_empty_keyfile(self, sample_file, tmp_dir):
        kf = os.path.join(tmp_dir, "empty.key")
        with open(kf, "wb") as f:
            pass
        enc = FileEncryptor()
        out = sample_file + ".enc"
        with pytest.raises(ValueError, match="empty"):
            enc.encrypt_file(sample_file, out, "pass", "aes-gcm", keyfile_path=kf)

    def test_missing_keyfile(self, sample_file, tmp_dir):
        enc = FileEncryptor()
        out = sample_file + ".enc"
        with pytest.raises(ValueError, match="not found"):
            enc.encrypt_file(
                sample_file, out, "pass", "aes-gcm",
                keyfile_path=os.path.join(tmp_dir, "nope.key"),
            )

    def test_empty_folder(self, tmp_dir):
        empty_dir = os.path.join(tmp_dir, "empty")
        os.makedirs(empty_dir)
        enc = FileEncryptor()
        with pytest.raises(ValueError, match="empty"):
            enc.encrypt_folder(
                empty_dir, os.path.join(tmp_dir, "empty.enc"), "pass", "aes-gcm",
            )

    def test_invalid_folder_path(self, tmp_dir):
        enc = FileEncryptor()
        with pytest.raises(ValueError, match="Invalid folder"):
            enc.encrypt_folder(
                os.path.join(tmp_dir, "nope"),
                os.path.join(tmp_dir, "nope.enc"),
                "pass", "aes-gcm",
            )

    def test_decrypt_nonexistent_file(self, tmp_dir):
        enc = FileEncryptor()
        with pytest.raises((ValueError, FileNotFoundError, OSError)):
            enc.decrypt_file(
                os.path.join(tmp_dir, "nope.enc"),
                os.path.join(tmp_dir, "nope.txt"),
                "pass",
            )


class TestGetFileInfo:
    def test_file_info_basic(self, sample_file):
        enc = FileEncryptor()
        enc_file = sample_file + ".enc"
        enc.encrypt_file(sample_file, enc_file, "Pass123!", "aes-gcm")
        info = enc.get_file_info(enc_file)
        assert info["algorithm"] == "AES-256-GCM"
        assert info["original_name"] == "test_input.txt"
        assert info["is_folder"] is False
        assert info["version"] == FORMAT_VERSION
        assert info["has_keyfile"] is False
        assert info["device_bound"] is False
        assert info["ttl_status"] == "none"

    def test_file_info_folder(self, tmp_dir):
        enc = FileEncryptor()
        folder = os.path.join(tmp_dir, "test_folder")
        os.makedirs(folder)
        with open(os.path.join(folder, "file.txt"), "w") as f:
            f.write("content")
        enc_file = folder + ".enc"
        enc.encrypt_folder(folder, enc_file, "Pass123!", "aes-gcm")
        info = enc.get_file_info(enc_file)
        assert info["is_folder"] is True

    def test_file_info_with_keyfile(self, sample_file, tmp_dir):
        enc = FileEncryptor()
        kf = os.path.join(tmp_dir, "info.key")
        with open(kf, "wb") as f:
            f.write(b"key material")
        enc_file = sample_file + ".enc"
        enc.encrypt_file(sample_file, enc_file, "Pass123!", "aes-gcm", keyfile_path=kf)
        info = enc.get_file_info(enc_file)
        assert info["has_keyfile"] is True

    def test_file_info_ttl_locked(self, sample_file):
        enc = FileEncryptor()
        enc_file = sample_file + ".enc"
        enc.encrypt_file(sample_file, enc_file, "Pass123!", "aes-gcm", ttl=3600)
        info = enc.get_file_info(enc_file)
        assert info["ttl_status"] == "locked"
        assert info["ttl_remaining"] > 0
        assert info["ttl_original"] == 3600

    def test_file_info_all_algorithms(self, sample_file):
        enc = FileEncryptor()
        for algo, display in [("aes-gcm", "AES-256-GCM"), ("chacha20", "ChaCha20-Poly1305"), ("fernet", "AES-256-Fernet")]:
            enc_file = sample_file + f".{algo}.enc"
            enc.encrypt_file(sample_file, enc_file, "Pass123!", algo)
            info = enc.get_file_info(enc_file)
            assert info["algorithm"] == display

    def test_file_info_wrong_password_does_not_crash(self, sample_file):
        enc = FileEncryptor()
        enc_file = sample_file + ".enc"
        enc.encrypt_file(sample_file, enc_file, "Pass123!", "aes-gcm")
        info = enc.get_file_info(enc_file)
        assert info["algorithm"] == "AES-256-GCM"
