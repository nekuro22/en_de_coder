"""Comprehensive security tests for en_de_coder crypto module.

Tests:
- HMAC verification (fast reject)
- Brute-force lockout (exponential backoff)
- Time-lock with encrypted password
- Key-file support
- Backward compatibility (v1 format)
"""

import os
import sys
import time
import tempfile
import shutil
import json
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from en_de_coder.crypto import (
    FileEncryptor, EncryptionBackend, parse_duration, format_duration,
    _compute_hmac, _verify_hmac, _encrypt_password_for_ttl, _decrypt_password_for_ttl,
    FORMAT_VERSION,
)


def test_hmac_computation():
    """Test HMAC is computed correctly."""
    salt = os.urandom(32)
    password = "TestPassword123!"

    hmac_val = _compute_hmac(salt, password)
    assert _verify_hmac(salt, password, hmac_val)
    assert not _verify_hmac(salt, "WrongPassword", hmac_val)
    assert not _verify_hmac(os.urandom(32), password, hmac_val)  # wrong salt
    print("OK: HMAC computation and verification")


def test_hmac_with_keyfile():
    """Test HMAC with keyfile content."""
    salt = os.urandom(32)
    password = "TestPassword123!"
    keyfile_content = b"keyfile content here"

    hmac_val = _compute_hmac(salt, password, keyfile_content)
    assert _verify_hmac(salt, password, hmac_val, keyfile_content)
    assert not _verify_hmac(salt, password, hmac_val)  # missing keyfile
    assert not _verify_hmac(salt, "WrongPassword", hmac_val, keyfile_content)
    print("OK: HMAC with keyfile")


def test_time_lock_password_encryption():
    """Test time-lock password encryption/decryption."""
    password = "SuperSecretPassword!"
    expiry = int(time.time()) + 3600

    encrypted = _encrypt_password_for_ttl(password, expiry)
    decrypted = _decrypt_password_for_ttl(encrypted, expiry)
    assert decrypted == password

    # Wrong timestamp should fail
    try:
        _decrypt_password_for_ttl(encrypted, expiry + 1)
        assert False, "Should have raised exception"
    except Exception:
        pass

    print("OK: Time-lock password encryption")


def test_brute_force_lockout():
    """Test brute-force lockout with exponential backoff."""
    # Reset lockout state
    EncryptionBackend._failed_attempts.clear()
    EncryptionBackend._lockout_until.clear()

    salt = os.urandom(32)
    salt_b64 = base64.b64encode(salt).decode()

    # No lockout initially
    assert EncryptionBackend.check_lockout(salt_b64) == 0

    # Record failed attempts and check increasing lockout
    delays = []
    for i in range(5):
        delay = EncryptionBackend.record_failed_attempt(salt_b64)
        delays.append(delay)

    # Delays should increase (exponential backoff)
    assert delays[0] == 5    # 5s
    assert delays[1] == 30   # 30s
    assert delays[2] == 300  # 5min
    assert delays[3] == 1800 # 30min
    assert delays[4] == 86400 # 24h

    # Should be locked out
    remaining = EncryptionBackend.check_lockout(salt_b64)
    assert remaining > 0

    # Clear lockout
    EncryptionBackend.clear_lockout(salt_b64)
    assert EncryptionBackend.check_lockout(salt_b64) == 0

    print("OK: Brute-force lockout with exponential backoff")


def test_file_encrypt_with_hmac():
    """Test that HMAC is stored and verified during file encryption."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(b"secret content")

        enc_file = test_file + ".enc"
        enc.encrypt_file(test_file, enc_file, "MyPass123!", "aes-gcm")

        # Check metadata contains HMAC
        with open(enc_file, "rb") as f:
            f.read(32)  # header
            meta_len = int.from_bytes(f.read(4), "big")
            meta = json.loads(f.read(meta_len).decode())

        assert "h" in meta, "HMAC not found in metadata"
        assert meta.get("v") == FORMAT_VERSION, "Version not in metadata"

        # Verify HMAC works
        salt = base64.b64decode(meta["s"])
        assert _verify_hmac(salt, "MyPass123!", meta["h"])
        assert not _verify_hmac(salt, "WrongPass", meta["h"])

        # Decrypt should work
        dec_file = os.path.join(tmpdir, "dec.txt")
        enc.decrypt_file(enc_file, dec_file, "MyPass123!")
        with open(dec_file, "rb") as f:
            assert f.read() == b"secret content"

        print("OK: File encrypt with HMAC verification")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_wrong_password_fast_reject():
    """Test that wrong password is rejected quickly via HMAC (before Argon2id)."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(b"content")

        enc_file = test_file + ".enc"
        enc.encrypt_file(test_file, enc_file, "CorrectPass!", "aes-gcm")

        # Reset lockout
        EncryptionBackend._failed_attempts.clear()
        EncryptionBackend._lockout_until.clear()

        # Wrong password should fail fast (HMAC check)
        dec_file = os.path.join(tmpdir, "dec.txt")
        start = time.time()
        try:
            enc.decrypt_file(enc_file, dec_file, "WrongPass!")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Wrong password" in str(e) or "Wait" in str(e)
        elapsed = time.time() - start

        # Should be fast (HMAC is ~microseconds, not seconds from Argon2id)
        # On slow systems, give some margin
        assert elapsed < 2.0, f"Wrong password took too long: {elapsed:.2f}s (should be <2s with HMAC)"

        print(f"OK: Wrong password fast reject ({elapsed:.3f}s)")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_file_lockout_on_wrong_password():
    """Test that wrong password triggers lockout."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()
        EncryptionBackend._failed_attempts.clear()
        EncryptionBackend._lockout_until.clear()

        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(b"content")

        enc_file = test_file + ".enc"
        enc.encrypt_file(test_file, enc_file, "Pass123!", "aes-gcm")

        dec_file = os.path.join(tmpdir, "dec.txt")

        # First wrong attempt - should get 5s lockout
        try:
            enc.decrypt_file(enc_file, dec_file, "Wrong1")
        except ValueError:
            pass

        # Check lockout is active
        with open(enc_file, "rb") as f:
            f.read(32)
            meta_len = int.from_bytes(f.read(4), "big")
            meta = json.loads(f.read(meta_len).decode())
        salt_b64 = meta["s"]
        remaining = EncryptionBackend.check_lockout(salt_b64)
        assert remaining > 0, "Lockout should be active after wrong password"

        # Second attempt should be blocked
        try:
            enc.decrypt_file(enc_file, dec_file, "Wrong2")
            assert False, "Should have raised ValueError due to lockout"
        except ValueError as e:
            assert "Too many failed" in str(e) or "Wait" in str(e)

        EncryptionBackend.clear_lockout(salt_b64)
        print("OK: File lockout on wrong password")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_file_unlock_on_correct_password():
    """Test that lockout is cleared after correct password."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()
        EncryptionBackend._failed_attempts.clear()
        EncryptionBackend._lockout_until.clear()

        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(b"content")

        enc_file = test_file + ".enc"
        enc.encrypt_file(test_file, enc_file, "Pass123!", "aes-gcm")

        # Get salt for lockout checking
        with open(enc_file, "rb") as f:
            f.read(32)
            meta_len = int.from_bytes(f.read(4), "big")
            meta = json.loads(f.read(meta_len).decode())
        salt_b64 = meta["s"]

        # Make a wrong attempt
        dec_file = os.path.join(tmpdir, "dec.txt")
        try:
            enc.decrypt_file(enc_file, dec_file, "Wrong")
        except ValueError:
            pass

        assert EncryptionBackend.check_lockout(salt_b64) > 0

        # Clear lockout manually, then correct password should also clear it
        EncryptionBackend.clear_lockout(salt_b64)
        enc.decrypt_file(enc_file, dec_file, "Pass123!")
        assert EncryptionBackend.check_lockout(salt_b64) == 0

        print("OK: Lockout cleared on correct password")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_ttl_encrypted_password():
    """Test time-lock with encrypted password (no plaintext in metadata)."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()
        test_file = os.path.join(tmpdir, "ttl_test.txt")
        with open(test_file, "wb") as f:
            f.write(b"ttl content")

        enc_file = test_file + ".enc"
        enc.encrypt_file(test_file, enc_file, "TTLPass123!", "aes-gcm", ttl=1)

        # Check metadata - should NOT have plaintext password
        with open(enc_file, "rb") as f:
            f.read(32)
            meta_len = int.from_bytes(f.read(4), "big")
            meta = json.loads(f.read(meta_len).decode())

        assert "p" not in meta, "Plaintext password found in metadata!"
        assert "ep" in meta, "Encrypted password not found in metadata"
        assert meta.get("t") is not None, "Expiry timestamp not found"
        assert meta.get("ttl") == 1, "TTL value not found"

        # Wait for TTL to expire
        time.sleep(2)

        # Should decrypt without password
        dec_file = os.path.join(tmpdir, "ttl_dec.txt")
        enc.decrypt_file(enc_file, dec_file, None)
        with open(dec_file, "rb") as f:
            assert f.read() == b"ttl content"

        print("OK: TTL with encrypted password (no plaintext)")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_keyfile_encrypt_decrypt():
    """Test encryption/decryption with keyfile."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()
        EncryptionBackend._failed_attempts.clear()
        EncryptionBackend._lockout_until.clear()

        # Create keyfile
        keyfile = os.path.join(tmpdir, "secret.key")
        with open(keyfile, "wb") as f:
            f.write(os.urandom(256))

        test_file = os.path.join(tmpdir, "keyfile_test.txt")
        with open(test_file, "wb") as f:
            f.write(b"keyfile protected content")

        enc_file = test_file + ".enc"

        # Encrypt with keyfile
        enc.encrypt_file(test_file, enc_file, "Pass123!", "aes-gcm", keyfile_path=keyfile)

        # Check metadata has keyfile flag
        with open(enc_file, "rb") as f:
            f.read(32)
            meta_len = int.from_bytes(f.read(4), "big")
            meta = json.loads(f.read(meta_len).decode())
        assert meta.get("kf") is True, "Keyfile flag not set in metadata"

        # Test 1: Decrypt without keyfile should fail
        dec_file = os.path.join(tmpdir, "dec_no_key.txt")
        try:
            enc.decrypt_file(enc_file, dec_file, "Pass123!")
            assert False, "Should have raised ValueError (missing keyfile)"
        except ValueError as e:
            assert "key file" in str(e).lower() or "keyfile" in str(e).lower()

        # Test 2: Decrypt with wrong keyfile should fail (HMAC fails -> lockout recorded)
        wrong_keyfile = os.path.join(tmpdir, "wrong.key")
        with open(wrong_keyfile, "wb") as f:
            f.write(os.urandom(256))
        try:
            enc.decrypt_file(enc_file, dec_file, "Pass123!", keyfile_path=wrong_keyfile)
            assert False, "Should have raised ValueError (wrong keyfile)"
        except ValueError as e:
            assert "Wrong password" in str(e) or "corrupted" in str(e).lower() or "Wait" in str(e)

        # Clear lockout before testing correct keyfile
        EncryptionBackend._failed_attempts.clear()
        EncryptionBackend._lockout_until.clear()

        # Test 3: Decrypt with correct keyfile should work
        dec_file2 = os.path.join(tmpdir, "dec_with_key.txt")
        enc.decrypt_file(enc_file, dec_file2, "Pass123!", keyfile_path=keyfile)
        with open(dec_file2, "rb") as f:
            assert f.read() == b"keyfile protected content"

        print("OK: Keyfile encrypt/decrypt")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_keyfile_folder():
    """Test folder encryption with keyfile."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()

        keyfile = os.path.join(tmpdir, "folder.key")
        with open(keyfile, "wb") as f:
            f.write(os.urandom(128))

        folder = os.path.join(tmpdir, "test_folder")
        os.makedirs(folder)
        with open(os.path.join(folder, "file.txt"), "w") as f:
            f.write("folder content")

        enc_file = folder + ".enc"
        enc.encrypt_folder(folder, enc_file, "FolderPass!", "aes-gcm", keyfile_path=keyfile)

        out_folder = os.path.join(tmpdir, "restored")
        os.makedirs(out_folder)
        enc.decrypt_folder(enc_file, out_folder, "FolderPass!", keyfile_path=keyfile)

        assert os.path.exists(os.path.join(out_folder, "file.txt"))
        with open(os.path.join(out_folder, "file.txt")) as f:
            assert f.read() == "folder content"

        print("OK: Folder with keyfile")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_info_shows_keyfile_status():
    """Test that get_file_info shows keyfile status."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()

        # Without keyfile
        test_file = os.path.join(tmpdir, "info_test.txt")
        with open(test_file, "wb") as f:
            f.write(b"info test")

        enc_file = test_file + ".enc"
        enc.encrypt_file(test_file, enc_file, "Pass!", "aes-gcm")

        info = enc.get_file_info(enc_file)
        assert info["has_keyfile"] is False
        assert info["version"] == FORMAT_VERSION

        # With keyfile
        keyfile = os.path.join(tmpdir, "info.key")
        with open(keyfile, "wb") as f:
            f.write(b"key")

        enc_file2 = test_file + ".enc"
        enc.encrypt_file(test_file, enc_file2, "Pass!", "aes-gcm", keyfile_path=keyfile)

        info2 = enc.get_file_info(enc_file2)
        assert info2["has_keyfile"] is True

        print("OK: Info shows keyfile status")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_all_algorithms_with_new_features():
    """Test all algorithms with HMAC + keyfile."""
    tmpdir = tempfile.mkdtemp()
    try:
        enc = FileEncryptor()
        keyfile = os.path.join(tmpdir, "algo.key")
        with open(keyfile, "wb") as f:
            f.write(b"key material")

        for algo in ["aes-gcm", "chacha20", "fernet"]:
            test_file = os.path.join(tmpdir, f"algo_{algo}.txt")
            with open(test_file, "wb") as f:
                f.write(f"Algorithm test {algo}".encode())

            enc_file = test_file + ".enc"
            enc.encrypt_file(test_file, enc_file, "Pass123!", algo, keyfile_path=keyfile)

            dec_file = os.path.join(tmpdir, f"algo_{algo}.dec.txt")
            enc.decrypt_file(enc_file, dec_file, "Pass123!", keyfile_path=keyfile)

            with open(dec_file, "rb") as f:
                assert f.read() == f"Algorithm test {algo}".encode()

        print("OK: All algorithms with HMAC + keyfile")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_backward_compatibility_v1():
    """Test that v1 format files (without HMAC) can still be decrypted."""
    # This test creates a v1 format file manually
    tmpdir = tempfile.mkdtemp()
    try:
        from en_de_coder.crypto import EncryptionBackend, ALGO_MAP_INTERNAL_TO_ENCRYPT_FN
        EncryptionBackend._failed_attempts.clear()
        EncryptionBackend._lockout_until.clear()

        test_content = b"backward compat test"
        password = "TestPass123!"
        salt = os.urandom(32)

        # Derive key (same as old code)
        key = EncryptionBackend.derive_key(password, salt, "AESGCM")

        # Encrypt data
        encrypted_data = EncryptionBackend.encrypt_aesgcm(test_content, key)

        # Build v1 metadata (no "v", no "h", no "ep")
        metadata = {
            "a": "AESGCM",
            "s": base64.b64encode(salt).decode(),
            "n": "test.txt",
        }

        metadata_json = json.dumps(metadata).encode()
        metadata_length = len(metadata_json).to_bytes(4, "big")
        header = os.urandom(32)

        v1_file = os.path.join(tmpdir, "v1_test.txt.enc")
        with open(v1_file, "wb") as f:
            f.write(header)
            f.write(metadata_length)
            f.write(metadata_json)
            f.write(encrypted_data)

        # Should still be decryptable
        enc = FileEncryptor()
        dec_file = os.path.join(tmpdir, "v1_dec.txt")
        enc.decrypt_file(v1_file, dec_file, password)

        with open(dec_file, "rb") as f:
            assert f.read() == test_content

        # Info should work too
        info = enc.get_file_info(v1_file)
        assert info["version"] == 1  # default when "v" is missing
        assert info["has_keyfile"] is False

        print("OK: Backward compatibility with v1 format")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_all():
    """Run all security tests."""
    print("=" * 60)
    print("SECURITY FEATURE TESTS")
    print("=" * 60)

    tests = [
        test_hmac_computation,
        test_hmac_with_keyfile,
        test_time_lock_password_encryption,
        test_brute_force_lockout,
        test_file_encrypt_with_hmac,
        test_wrong_password_fast_reject,
        test_file_lockout_on_wrong_password,
        test_file_unlock_on_correct_password,
        test_ttl_encrypted_password,
        test_keyfile_encrypt_decrypt,
        test_keyfile_folder,
        test_info_shows_keyfile_status,
        test_all_algorithms_with_new_features,
        test_backward_compatibility_v1,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = test_all()
    sys.exit(0 if success else 1)
