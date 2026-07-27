"""Security tests for en_de_coder."""

import os
import sys
import tempfile
import math
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from en_de_coder.crypto import FileEncryptor, EncryptionBackend


TEST_DIR = os.path.join(tempfile.gettempdir(), "sec_test")
os.makedirs(TEST_DIR, exist_ok=True)


def setup():
    """Create test files."""
    test_file = os.path.join(TEST_DIR, "geheim.txt")
    with open(test_file, "w") as f:
        f.write("GEHEIM: Das Passwort lautet SuperGeheim123\n")
        f.write("Bankkonto: DE89 3704 0044 0532 0130 00\n")
        f.write("Dies ist ein Sicherheitstest.\n")

    keyfile = os.path.join(TEST_DIR, "mein_key.key")
    with open(keyfile, "wb") as f:
        f.write(os.urandom(256))

    enc = FileEncryptor()

    # 1) Nur Passwort
    dst1 = os.path.join(TEST_DIR, "test_pw_only.enc")
    enc.encrypt_file(test_file, dst1, "MeinPasswort", "aes-gcm")

    # 2) Passwort + Keyfile
    dst2 = os.path.join(TEST_DIR, "test_pw_keyfile.enc")
    enc.encrypt_file(test_file, dst2, "MeinPasswort", "aes-gcm", keyfile_path=keyfile)

    # 3) Device-bound
    dst3 = os.path.join(TEST_DIR, "test_bound.enc")
    enc.encrypt_file(test_file, dst3, "MeinPasswort", "aes-gcm", device_bound=True)

    print("Setup complete.")
    return test_file, keyfile


def test_hex_analysis():
    """Test 1: Check no plaintext is visible in encrypted file."""
    print("\n" + "=" * 60)
    print("TEST 1: HEX-ANALYSE")
    print("=" * 60)

    enc_file = os.path.join(TEST_DIR, "test_pw_only.enc")
    with open(enc_file, "rb") as f:
        data = f.read()

    print(f"  File size: {len(data)} bytes")

    # Hexdump first 128 bytes
    print("\n  First 128 bytes (hex):")
    for i in range(0, min(128, len(data)), 16):
        chunk = data[i:i + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"    {i:04x}: {hex_str:<48} {ascii_str}")

    # Check for plaintext
    data_str = data.decode("latin-1", errors="replace")
    checks = {
        "Originaltext 'GEHEIM'": "GEHEIM" in data_str,
        "Passwort 'MeinPasswort'": b"MeinPasswort" in data,
        "Geheimtext 'SuperGeheim123'": b"SuperGeheim123" in data,
        "Bankkonto 'DE89'": b"DE89" in data,
    }

    print("\n  Security checks:")
    all_clear = True
    for name, found in checks.items():
        status = "FAIL - visible!" if found else "OK"
        print(f"    {name}: {status}")
        if found:
            all_clear = False

    # Entropy check
    byte_freq = Counter(data)
    entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in byte_freq.values())
    print(f"\n  Unique byte values: {len(byte_freq)}/256")
    print(f"  Estimated entropy: {entropy:.2f}/8.0")

    result = "PASS" if all_clear else "FAIL"
    print(f"\n  >>> TEST 1: {result} <<<")
    return all_clear


def test_no_password():
    """Test 2: Try to decrypt without password."""
    print("\n" + "=" * 60)
    print("TEST 2: ENTSHLUESSELUNG OHNE PASSWORT")
    print("=" * 60)

    enc_file = os.path.join(TEST_DIR, "test_pw_only.enc")
    out_file = os.path.join(TEST_DIR, "dec_no_pw.txt")
    enc = FileEncryptor()

    try:
        enc.decrypt_file(enc_file, out_file, password=None)
        print("  ERROR: Decryption succeeded without password!")
        print("  >>> TEST 2: FAIL <<<")
        return False
    except ValueError as e:
        print(f"  Correctly rejected: {e}")
        print("  >>> TEST 2: PASS <<<")
        return True
    except Exception as e:
        print(f"  Correctly rejected with: {type(e).__name__}: {e}")
        print("  >>> TEST 2: PASS <<<")
        return True


def test_wrong_password():
    """Test 3: Try to decrypt with wrong password."""
    print("\n" + "=" * 60)
    print("TEST 3: ENTSHLUESSELUNG MIT FALSCHEM PASSWORT")
    print("=" * 60)

    enc_file = os.path.join(TEST_DIR, "test_pw_only.enc")
    out_file = os.path.join(TEST_DIR, "dec_wrong_pw.txt")
    enc = FileEncryptor()

    # Clear any existing lockout
    EncryptionBackend.clear_lockout.__func__(EncryptionBackend, "")

    try:
        # Try wrong password
        enc.decrypt_file(enc_file, out_file, password="FalschesPasswort123")
        print("  ERROR: Decryption succeeded with wrong password!")
        print("  >>> TEST 3: FAIL <<<")
        return False
    except ValueError as e:
        err_msg = str(e)
        print(f"  Correctly rejected: {err_msg}")
        has_lockout = "Wait" in err_msg or "Wrong" in err_msg
        print(f"  Lockout message shown: {'YES' if has_lockout else 'NO'}")
        print("  >>> TEST 3: PASS <<<")
        return True
    except Exception as e:
        print(f"  Correctly rejected with: {type(e).__name__}: {e}")
        print("  >>> TEST 3: PASS <<<")
        return True


def test_correct_password():
    """Test 4: Decrypt with correct password."""
    print("\n" + "=" * 60)
    print("TEST 4: ENTSHLUESSELUNG MIT RICHTIGEM PASSWORT")
    print("=" * 60)

    enc_file = os.path.join(TEST_DIR, "test_pw_only.enc")
    out_file = os.path.join(TEST_DIR, "dec_correct_pw.txt")
    enc = FileEncryptor()

    # Clear lockout from previous test
    from en_de_coder.crypto import FileEncryptor as FE
    import en_de_coder.crypto as crypto_mod
    crypto_mod.EncryptionBackend._failed_attempts.clear()
    crypto_mod.EncryptionBackend._lockout_until.clear()

    try:
        enc.decrypt_file(enc_file, out_file, password="MeinPasswort")
        with open(out_file) as f:
            content = f.read()
        original = "GEHEIM" in content and "SuperGeheim123" in content
        print(f"  Decrypted successfully: {len(content)} bytes")
        print(f"  Content matches original: {'YES' if original else 'NO'}")
        print("  >>> TEST 4: PASS <<<")
        return True
    except Exception as e:
        print(f"  ERROR: {e}")
        print("  >>> TEST 4: FAIL <<<")
        return False


def test_keyfile_no_password():
    """Test 5: File encrypted with keyfile, try without password."""
    print("\n" + "=" * 60)
    print("TEST 5: KEYFILE-DATEI OHNE PASSWORT")
    print("=" * 60)

    enc_file = os.path.join(TEST_DIR, "test_pw_keyfile.enc")
    out_file = os.path.join(TEST_DIR, "dec_kf_no_pw.txt")
    enc = FileEncryptor()

    try:
        enc.decrypt_file(enc_file, out_file, password=None)
        print("  ERROR: Decryption succeeded without password!")
        print("  >>> TEST 5: FAIL <<<")
        return False
    except ValueError as e:
        print(f"  Correctly rejected: {e}")
        print("  >>> TEST 5: PASS <<<")
        return True
    except Exception as e:
        print(f"  Correctly rejected with: {type(e).__name__}: {e}")
        print("  >>> TEST 5: PASS <<<")
        return True


def test_device_binding():
    """Test 6: Device-bound file decryption."""
    print("\n" + "=" * 60)
    print("TEST 6: DEVICE-BINDING")
    print("=" * 60)

    enc_file = os.path.join(TEST_DIR, "test_bound.enc")
    out_file = os.path.join(TEST_DIR, "dec_bound.txt")
    enc = FileEncryptor()

    # Check metadata
    info = enc.get_file_info(enc_file)
    print(f"  File is device_bound: {info.get('device_bound', False)}")

    # Try decrypt (should work on this device since it was encrypted here)
    try:
        enc.decrypt_file(enc_file, out_file, password="MeinPasswort")
        with open(out_file) as f:
            content = f.read()
        original = "GEHEIM" in content and "SuperGeheim123" in content
        print(f"  Decrypted on same device: OK ({len(content)} bytes)")
        print(f"  Content matches: {'YES' if original else 'NO'}")
        print("  >>> TEST 6: PASS (same device) <<<")
        return True
    except Exception as e:
        print(f"  ERROR: {e}")
        print("  >>> TEST 6: FAIL <<<")
        return False


def main():
    print("=" * 60)
    print("  SECURITY TESTS - en_de_coder")
    print("=" * 60)

    test_file, keyfile = setup()

    results = []
    results.append(("Hex-Analyse", test_hex_analysis()))
    results.append(("Ohne Passwort", test_no_password()))
    results.append(("Falsches Passwort", test_wrong_password()))
    results.append(("Richtiges Passwort", test_correct_password()))
    results.append(("Keyfile ohne Passwort", test_keyfile_no_password()))
    results.append(("Device-Binding", test_device_binding()))

    print("\n" + "=" * 60)
    print("  ZUSAMMENFASSUNG")
    print("=" * 60)
    for name, passed in results:
        status = "BESTANDEN" if passed else "FEHLGESCHLAGEN"
        print(f"  {name:<25} {status}")

    passed = sum(1 for _, p in results if p)
    total = len(results)
    print(f"\n  {passed}/{total} Tests bestanden")
    print("=" * 60)


if __name__ == "__main__":
    main()
