# en_de_coder

Cross-platform file & folder encryption CLI tool for Windows and Linux.

## Installation

```bash
pip install .
```

Or in development mode:

```bash
pip install -e ".[dev]"
```

## Usage

### Encrypt a file

```bash
enc encrypt document.pdf
# Prompts for password, creates document.pdf.enc and deletes the original file

enc encrypt document.pdf -p MySecretPass123!
# Uses password directly (visible in process list - use with caution)

enc encrypt folder/ -a chacha20
# Encrypt a folder with ChaCha20 algorithm

enc encrypt document.pdf -t 30m
# Time-lock: password optional after 30 minutes

enc encrypt secret.txt -t 1d -a chacha20
# Time-lock for 1 day with ChaCha20 algorithm
```

### Decrypt a file

```bash
enc decrypt document.pdf.enc
# Prompts for password, restores original file and deletes the .enc source

enc decrypt document.pdf.enc -o restored.pdf
# Specify output path

enc decrypt document.pdf.enc -p MySecretPass123!
# Decrypt with password directly

# If file was encrypted with -t, after TTL expires:
enc decrypt document.pdf.enc
# No password needed after time-lock expires
```

### Show file info

```bash
enc info document.pdf.enc
# Shows algorithm, original name, type, and file size
```

### Register file type

```bash
enc register
# Associates .enc files with this tool (Windows & Linux)
```

### Generate password

```bash
enc generate-password
# Generates a 16-character secure password

enc generate-password -l 32
# Generates a 32-character password
```

## CLI Reference

| Command | Alias | Description |
|---------|-------|-------------|
| `enc encrypt <input>` | `enc e` | Encrypt a file or folder |
| `enc decrypt <input>` | `enc d` | Decrypt a file or folder |
| `enc info <file>` | `enc i` | Show encrypted file metadata |
| `enc register` | `enc r` | Register .enc file type |
| `enc generate-password` | `enc g` | Generate a secure password |

### Options

| Flag | Description |
|------|-------------|
| `-p, --password` | Password (prompted interactively if omitted) |
| `-o, --output` | Output path |
| `-a, --algorithm` | Algorithm: `aes-gcm` (default), `chacha20`, `fernet` |
| `-t, --time` | Time-lock duration (e.g. `20s`, `5m`, `2h`, `1d`). Password optional after expiry. |
| `-f, --force` | Overwrite without asking |
| `-l, --length` | Password length for `generate-password` (default: 16) |

## Algorithms

| Algorithm | Description |
|-----------|-------------|
| `aes-gcm` | AES-256-GCM - Recommended (default) |
| `chacha20` | ChaCha20-Poly1305 - Modern, CPU-efficient |
| `fernet` | AES-256-Fernet - Compatibility fallback |

## Security Features

- Argon2id key derivation (OWASP recommended)
- 32-byte random salt per file
- PBKDF2-SHA512 fallback (600k iterations)
- Anti-brute-force protection (exponential backoff)
- No identifiable file headers
- Metadata validation
- Time-lock encryption (TTL-based password optionality)

## Backward Compatibility

The old `file_encryptor.py` interface still works:

```python
from file_encryptor import FileEncryptor

encryptor = FileEncryptor()
encryptor.encrypt_file("input.txt", "input.txt.enc", "password", "aes-gcm")
encryptor.decrypt_file("input.txt.enc", "output.txt", "password")
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
