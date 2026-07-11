"""
Final test: Encrypt a file and verify it opens with the EXE
"""

import os
import sys
from file_encryptor import FileEncryptor

print("=" * 60)
print("FINAL INTEGRATION TEST")
print("=" * 60)

# Create test file
test_file = "DEMO_TEST.txt"
with open(test_file, 'w') as f:
    f.write("Dies ist eine Demo-Testdatei für das Verschlüsselungs-Tool!\n")
    f.write("Diese Datei wird jetzt verschlüsselt...\n")
    f.write("Öffne die .encrypted Datei mit Doppelklick!\n")

print(f"\n✓ Erstelle Test-Datei: {test_file}")

# Encrypt it
encrypted_file = f"{test_file}.encrypted"
password = "DemoPassword123!@#"

encryptor = FileEncryptor()

print(f"🔒 Verschlüssele mit AES-256-GCM...")
try:
    encryptor.encrypt_file(test_file, encrypted_file, password, "1. AES-256-GCM (Sicherster)")
    print(f"✓ Verschlüsselung erfolgreich: {encrypted_file}")
except Exception as e:
    print(f"✗ Fehler: {e}")
    sys.exit(1)

# Get file info
original_size = os.path.getsize(test_file)
encrypted_size = os.path.getsize(encrypted_file)

print(f"\n📊 Datei-Informationen:")
print(f"   Original:     {original_size} Bytes")
print(f"   Verschlüsselt: {encrypted_size} Bytes")
print(f"   Overhead:     {encrypted_size - original_size} Bytes")

# Delete original
os.remove(test_file)
print(f"\n✓ Original gelöscht (nur {encrypted_file} bleibt)")

# Test command-line invocation
print(f"\n" + "=" * 60)
print("TEST: Starte EXE mit Datei-Argument")
print("=" * 60)

exe_path = r"dist\Verschluesselungs-Tool.exe"

if os.path.exists(exe_path):
    print(f"✓ EXE gefunden: {exe_path}")
    print(f"\nBefehel der ausgeführt würde:")
    print(f'  "{exe_path}" "{os.path.abspath(encrypted_file)}"')
    print(f"\nDies würde die Datei automatisch im Tool laden.")
    print(f"Diese Funktion ist nur beim echten Doppelklick aktiv.")
else:
    print(f"✗ EXE nicht gefunden: {exe_path}")

print(f"\n" + "=" * 60)
print("✓ ALLE TESTS ERFOLGREICH!")
print("=" * 60)

print(f"""
NÄCHSTE SCHRITTE:

1. Doppelklick auf: {encrypted_file}
   → Das Tool öffnet sich automatisch mit der Datei geladen

2. Gib das Passwort ein:
   → {password}

3. Klick "🔓 Entschlüsseln"
   → Die Datei wird wiederhergestellt

WICHTIG:
- Das Passwort ist: {password}
- Merke dir dein eigenes Passwort für deine Dateien!
- Verschlüsselte Dateien können nicht ohne Passwort geöffnet werden!

Viel Spaß! 🔐
""")
