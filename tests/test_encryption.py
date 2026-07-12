"""
Quick test to verify encryption and decryption still work correctly
"""

import os
import sys
import tempfile
import shutil

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from en_de_coder.crypto import FileEncryptor


def test_encryption_decryption():
    """Test encryption and decryption"""
    print("Testing Encryption & Decryption...")
    print("=" * 50)

    tmpdir = tempfile.mkdtemp()
    try:
        test_file = os.path.join(tmpdir, "test_input.txt")
        test_content = b"Dies ist ein Test! Geheim! \x00\xFF\x01\x02\x03"

        with open(test_file, "wb") as f:
            f.write(test_content)

        print(f"Created test file: {test_file}")

        # Encrypt
        encrypted_file = os.path.join(tmpdir, "test_input.txt.enc")
        password = "TestPassword123!@#"
        algorithm = "aes-gcm"

        encryptor = FileEncryptor()

        print(f"\nEncrypting with {algorithm}...")
        result = encryptor.encrypt_file(test_file, encrypted_file, password, algorithm)

        if result:
            encrypted_size = os.path.getsize(encrypted_file)
            original_size = os.path.getsize(test_file)
            print(f"Encryption successful!")
            print(f"  Original: {original_size} bytes")
            print(f"  Encrypted: {encrypted_size} bytes")
        else:
            print("Encryption failed")
            return False

        # Decrypt
        decrypted_file = os.path.join(tmpdir, "test_output.txt")

        print(f"\nDecrypting...")
        result = encryptor.decrypt_file(encrypted_file, decrypted_file, password)

        if result:
            print(f"Decryption successful!")
        else:
            print("Decryption failed")
            return False

        # Verify
        with open(decrypted_file, "rb") as f:
            decrypted_content = f.read()

        if decrypted_content == test_content:
            print(f"\nVerification PASSED!")
            print(f"  Original and decrypted content match perfectly!")
            success = True
        else:
            print(f"\nVerification FAILED!")
            print(f"  Original:  {test_content[:50]}...")
            print(f"  Decrypted: {decrypted_content[:50]}...")
            success = False

        print("\n" + "=" * 50)
        if success:
            print("ALL TESTS PASSED - Encryption & Decryption working!")
        else:
            print("TESTS FAILED - There's an issue")

        return success
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    success = test_encryption_decryption()
    sys.exit(0 if success else 1)
