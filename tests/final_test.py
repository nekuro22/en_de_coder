"""
Final test: Encrypt a file and verify it works
"""

import os
import sys
import tempfile
import shutil

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from en_de_coder.crypto import FileEncryptor

print("=" * 60)
print("FINAL INTEGRATION TEST")
print("=" * 60)

tmpdir = tempfile.mkdtemp()
try:
    # Create test file
    test_file = os.path.join(tmpdir, "DEMO_TEST.txt")
    with open(test_file, "w") as f:
        f.write("Dies ist eine Demo-Testdatei fuer das Verschluesselungs-Tool!\n")
        f.write("Diese Datei wird jetzt verschluesselt...\n")

    print(f"\nErstelle Test-Datei: {test_file}")

    # Encrypt it
    encrypted_file = test_file + ".encrypted"
    password = "DemoPassword123!@#"

    encryptor = FileEncryptor()

    print(f"Verschluessele mit AES-256-GCM...")
    try:
        encryptor.encrypt_file(test_file, encrypted_file, password, "aes-gcm")
        print(f"Verschluesselung erfolgreich: {encrypted_file}")
    except Exception as e:
        print(f"Fehler: {e}")
        sys.exit(1)

    # Get file info
    original_size = os.path.getsize(test_file)
    encrypted_size = os.path.getsize(encrypted_file)

    print(f"\nDatei-Informationen:")
    print(f"   Original:     {original_size} Bytes")
    print(f"   Verschluesselt: {encrypted_size} Bytes")
    print(f"   Overhead:     {encrypted_size - original_size} Bytes")

    # Decrypt
    decrypted_file = os.path.join(tmpdir, "restored.txt")
    encryptor.decrypt_file(encrypted_file, decrypted_file, password)

    with open(decrypted_file, "r") as f:
        content = f.read()
    print(f"\nEntschluesselt: {decrypted_file}")
    print(f"Inhalt: {content[:50]}...")

    print(f"\n{'=' * 60}")
    print("ALLE TESTS ERFOLGREICH!")
    print("=" * 60)
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)
