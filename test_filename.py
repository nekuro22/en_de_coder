"""
Test the filename feature
"""

import os
from file_encryptor import FileEncryptor

# Create test file with real extension
test_file = "demo_document.pdf"
with open(test_file, 'wb') as f:
    f.write(b"Dies ist eine Test-PDF Datei")

print("Test: Dateityp-Beibehaltung")
print("-" * 50)
print(f"Original-Datei: {test_file}")

# Encrypt
encrypted_file = test_file + ".encrypted"
encryptor = FileEncryptor()
encryptor.encrypt_file(test_file, encrypted_file, "Demo123!@#", "1. AES-256-GCM (Sicherster)")

print(f"Verschluesselt als: {encrypted_file}")

# Check metadata
import json, base64
with open(encrypted_file, 'rb') as f:
    header = f.read(32)
    meta_len_bytes = f.read(4)
    meta_len = int.from_bytes(meta_len_bytes, 'big')
    meta_json = f.read(meta_len)
    metadata = json.loads(meta_json.decode())
    
print(f"\nIn Metadaten gespeichert:")
print(f"  Original-Name: {metadata.get('n')}")
print(f"  Algorithmus: {metadata.get('a')}")

# Decrypt
decrypted_file = "restored_document.pdf"
encryptor.decrypt_file(encrypted_file, decrypted_file, "Demo123!@#")

print(f"\nEntschlusselt als: {decrypted_file}")

# Verify
if os.path.exists(decrypted_file):
    print(f"Status: Erfolgreich!")
    print(f"\nBeim Entschlusseln schlaegt das Programm vor:")
    print(f"  Dateiname: {metadata.get('n')}")
    print(f"  Verzeichnis: (Das Verzeichnis der .encrypted Datei)")
    
    # Cleanup
    os.remove(test_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)
    print(f"\nTest-Dateien geloescht.")
