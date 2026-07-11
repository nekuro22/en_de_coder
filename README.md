🔐 Verschlüsselungs-Tool - Quick Start Guide
============================================

## Installation & Setup

1. **EXE ist compiliert:**
   - Datei: `dist/Verschluesselungs-Tool.exe`
   - Größe: ~50-70 MB
   - Diese EXE kann überall hin kopiert werden

2. **Dateityp registriert:**
   - .encrypted Dateien sind jetzt mit Verschlüsselungs-Tool verknüpft
   - Die Registrierung ist abgeschlossen ✓

## So funktioniert es:

### Methode 1: Doppelklick auf .encrypted Datei
1. Navigiere zu einer .encrypted Datei
2. **Doppelklick** - Das Programm öffnet sich automatisch mit der Datei
3. Gib dein Passwort ein
4. Klick "Entschlüsseln"

### Methode 2: Aus dem Programm verschlüsseln
1. Öffne `Verschluesselungs-Tool.exe`
2. Klick "📂" zum Aussuchen einer Datei/Ordner
3. Gib ein sicheres Passwort ein (mind. 8 Zeichen) ⚠️
4. Klick "🔒 Verschlüsseln"

### Methode 3: Rechtsklick → Öffnen mit
1. Rechtsklick auf eine .encrypted Datei
2. "Öffnen mit" oder "Mit Programm öffnen"
3. Wähle "Verschlüsselungs-Tool"

## ⚠️ WICHTIG:

- **Passwort merken!** - Verschlüsselte Dateien können nicht ohne Passwort wiederhergestellt werden
- **Starkes Passwort!** - Mindestens 8 Zeichen, mit Großbuchstaben, Zahlen und Sonderzeichen
- **Passwort Generator** - Klick das 🎲 Symbol für ein sicheres Passwort

## Verfügbare Algorithmen:

1. **🥇 AES-256-GCM** (EMPFOHLEN)
   - Stärkste Sicherheit
   - Authenticated encryption
   - ~30% schneller als ChaCha20

2. **ChaCha20-Poly1305**
   - Moderne Alternative
   - CPU-effizient
   - Gut für alte Hardware

3. **AES-256-Fernet**
   - Fallback Option
   - Einfacher Standard
   - Kompatibilität

## Verschlüsselte Dateien identifizieren:

Verschlüsselte Dateien haben die Endung **.encrypted**
Beispiele:
- `dokument.pdf.encrypted`
- `foto.jpg.encrypted`
- `ordner.zip.encrypted`

## Sicherheitsfeatures:

✓ Argon2id Key Derivation (OWASP-empfohlen)
✓ 32-Byte Zufall-Salt pro Datei
✓ PBKDF2-SHA512 Fallback
✓ Anti-Brute-Force Schutz (exponentielles Backoff)
✓ Keine identifizierbaren Header
✓ Metadaten-Validierung

## Technische Spezifikationen:

- Passwort-Minimallänge: 8 Zeichen
- Salt-Länge: 32 Bytes (256 Bits)
- Argon2id Parameter:
  - Memory: 64 MB
  - Time: 3
  - Parallelism: 4
- File Format: proprietary (sicher)

## Support:

Wenn eine .encrypted Datei nicht öffnet:
1. Stelle sicher, dass die Registrierung lief
2. Versuche: Rechtsklick → "Mit Programm öffnen"
3. Wähle `Verschluesselungs-Tool.exe` manuell

Das war's! Viel Spaß mit sicherer Verschlüsselung! 🔒
