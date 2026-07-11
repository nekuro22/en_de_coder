"""
Test the filename feature
"""

import os
import sys
import tempfile
import shutil

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from en_de_coder.crypto import FileEncryptor

tmpdir = tempfile.mkdtemp()
try:
    # Create test file with real extension
    test_file = os.path.join(tmpdir, "demo_document.pdf")
    with open(test_file, "wb") as f:
        f.write(b"Dies ist eine Test-PDF Datei")

    print("Test: Dateityp-Beibehaltung")
    print("-" * 50)
    print(f"Original-Datei: {test_file}")

    # Encrypt
    encrypted_file = test_file + ".encrypted"
    encryptor = FileEncryptor()
    encryptor.encrypt_file(test_file, encrypted_file, "Demo123!@#", "aes-gcm")

    print(f"Verschluesselt als: {encrypted_file}")

    # Check metadata
    import json
    import base64

    with open(encrypted_file, "rb") as f:
        header = f.read(32)
        meta_len_bytes = f.read(4)
        meta_len = int.from_bytes(meta_len_bytes, "big")
        meta_json = f.read(meta_len)
        metadata = json.loads(meta_json.decode())

    print(f"\nIn Metadaten gespeichert:")
    print(f"  Original-Name: {metadata.get('n')}")
    print(f"  Algorithmus: {metadata.get('a')}")

    # Decrypt
    decrypted_file = os.path.join(tmpdir, "restored_document.pdf")
    encryptor.decrypt_file(encrypted_file, decrypted_file, "Demo123!@#")

    print(f"\nEntschluesselt als: {decrypted_file}")

    # Verify
    if os.path.exists(decrypted_file):
        print(f"Status: Erfolgreich!")
        print(f"\nBeim Entschluesseln schlaegt das Programm vor:")
        print(f"  Dateiname: {metadata.get('n')}")
        print(f"  Verzeichnis: (Das Verzeichnis der .encrypted Datei)")
    else:
        print("FAILED!")
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)
