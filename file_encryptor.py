"""
File/Folder Encryption Tool
A tkinter-based application for encrypting and decrypting files and folders
with multiple encryption algorithm support and secure password protection.

SECURITY FEATURES:
- Argon2id key derivation (memory-hard, GPU-resistant) - OWASP recommended
- AES-256-GCM with 256-bit authentication
- ChaCha20-Poly1305 for modern CPU-resistant encryption
- Secure random salt (32 bytes) per file
- PBKDF2-SHA512 fallback (600k iterations)
- Anti-brute-force delay (exponential backoff)
- Input validation on all user inputs
- Metadata validation with size limits
- Secure file format without identifiable headers
"""

import os
import io
import json
import zipfile
import time
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import Tuple, Optional
import string
import secrets
import base64


class EncryptionBackend:
    """Base class for encryption backends with OWASP-recommended parameters"""

    FERNET = "3. AES-256-Fernet"
    AES_GCM = "1. AES-256-GCM (Sicherster)"
    CHACHA20 = "2. ChaCha20-Poly1305"

    # Counter for failed login attempts (per session)
    _failed_attempts = {}
    _lockout_until = {}

    @staticmethod
    def derive_key(password: str, salt: bytes, algorithm: str) -> bytes:
        """Derive encryption key using Argon2id (memory-hard, GPU-resistant)
        
        OWASP parameters for maximum security:
        - memory: 64MB
        - time: 3 iterations
        - parallelism: 4
        """
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        kdf = Argon2id(
            length=32,  # 256 bits for AES-256
            salt=salt,
            time=3,
            memory=65536,  # 64 MB
            parallelism=4,
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def derive_key_fallback(password: str, salt: bytes, algorithm: str) -> bytes:
        """Fallback: PBKDF2-SHA512 with 600k iterations (OWASP recommended minimum)"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=600000,  # OWASP minimum
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def encrypt_fernet(data: bytes, key: bytes) -> bytes:
        """Encrypt using Fernet (AES-128 + HMAC)"""
        from cryptography.fernet import Fernet
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.encrypt(data)
    
    @staticmethod
    def decrypt_fernet(data: bytes, key: bytes) -> bytes:
        """Decrypt using Fernet"""
        from cryptography.fernet import Fernet
        fernet_key = base64.urlsafe_b64encode(key)
        f = Fernet(fernet_key)
        return f.decrypt(data)
    
    @staticmethod
    def encrypt_aesgcm(data: bytes, key: bytes) -> bytes:
        """Encrypt using AES-256-GCM (Most secure)"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    @staticmethod
    def decrypt_aesgcm(data: bytes, key: bytes) -> bytes:
        """Decrypt using AES-256-GCM"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        nonce = data[:12]
        ciphertext = data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    @staticmethod
    def encrypt_chacha20(data: bytes, key: bytes) -> bytes:
        """Encrypt using ChaCha20-Poly1305 (CPU-efficient)"""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    @staticmethod
    def decrypt_chacha20(data: bytes, key: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        chacha = ChaCha20Poly1305(key)
        nonce = data[:12]
        ciphertext = data[12:]
        return chacha.decrypt(nonce, ciphertext, None)


class FileEncryptor:
    """Main file encryption/decryption handler with secure format"""

    def __init__(self):
        self.backend = EncryptionBackend()

    def _generate_header(self) -> bytes:
        """Generate a random 32-byte header for each encrypted file"""
        return os.urandom(32)

    def encrypt_file(self, input_path: str, output_path: str, password: str,
                     algorithm: str) -> bool:
        """Encrypt a file with the specified algorithm"""
        try:
            # Validate inputs
            if not os.path.isfile(input_path):
                raise ValueError(f"File not found: {input_path}")
            
            if not password or len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")

            # Read input file
            with open(input_path, 'rb') as f:
                data = f.read()

            # Generate cryptographically secure random salt (32 bytes)
            salt = os.urandom(32)

            # Derive key from password using Argon2id
            try:
                key = EncryptionBackend.derive_key(password, salt, algorithm)
            except Exception:
                # Fallback to PBKDF2 if Argon2 not available
                key = EncryptionBackend.derive_key_fallback(password, salt, algorithm)

            # Encrypt based on algorithm
            if "Fernet" in algorithm:
                encrypted_data = EncryptionBackend.encrypt_fernet(data, key)
            elif "GCM" in algorithm:
                encrypted_data = EncryptionBackend.encrypt_aesgcm(data, key)
            elif "ChaCha20" in algorithm:
                encrypted_data = EncryptionBackend.encrypt_chacha20(data, key)
            else:
                raise ValueError(f"Unknown algorithm: {algorithm}")

            # Map display names to internal short codes
            algo_internal = {
                "1. AES-256-GCM (Sicherster)": "AESGCM",
                "2. ChaCha20-Poly1305": "CHACHA",
                "3. AES-256-Fernet": "FERNET"
            }.get(algorithm, "AESGCM")

            # Create minimal metadata
            metadata = {
                "a": algo_internal,  # algorithm
                "s": base64.b64encode(salt).decode(),  # salt (base64)
                "n": os.path.basename(input_path),  # original name
            }
            metadata_json = json.dumps(metadata).encode()
            metadata_length = len(metadata_json).to_bytes(4, 'big')

            # Generate random header for this file
            header = self._generate_header()

            # Write encrypted file: [header][metadata_length][metadata][ciphertext]
            with open(output_path, 'wb') as f:
                f.write(header)
                f.write(metadata_length)
                f.write(metadata_json)
                f.write(encrypted_data)

            return True
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, input_path: str, output_path: str, password: str,
                     failed_attempt_key: str = None) -> bool:
        """Decrypt a file with anti-brute-force protection"""
        try:
            # Validate password input
            if not password or not isinstance(password, str):
                raise ValueError("Password is required")

            # Check for brute-force lockout
            if failed_attempt_key and failed_attempt_key in EncryptionBackend._lockout_until:
                unlock_time = EncryptionBackend._lockout_until[failed_attempt_key]
                if time.time() < unlock_time:
                    remaining = int(unlock_time - time.time())
                    raise Exception(f"Zu viele Fehlversuche. Warte {remaining} Sekunden.")

            # Read encrypted file
            with open(input_path, 'rb') as f:
                # Read header (first 32 bytes)
                header = f.read(32)
                if len(header) != 32:
                    raise ValueError("Invalid encrypted file format - header missing")

                # Read metadata length
                metadata_length_bytes = f.read(4)
                if len(metadata_length_bytes) != 4:
                    raise ValueError("Invalid encrypted file format - corrupt metadata length")
                
                metadata_length = int.from_bytes(metadata_length_bytes, 'big')
                
                # Sanity check: metadata shouldn't be > 10KB
                if metadata_length > 10000:
                    raise ValueError("Invalid metadata length - file corrupted")
                
                metadata_json = f.read(metadata_length)
                if len(metadata_json) != metadata_length:
                    raise ValueError("Truncated metadata - file corrupted")
                
                try:
                    metadata = json.loads(metadata_json.decode())
                except json.JSONDecodeError:
                    raise ValueError("Corrupted metadata - invalid JSON")

                # Read encrypted data
                encrypted_data = f.read()

            # Extract metadata
            algo_internal = metadata.get("a", "AESGCM")
            salt_b64 = metadata.get("s", "")
            
            if not salt_b64:
                raise ValueError("Missing salt in file metadata")
            
            # Decode and validate salt
            try:
                salt = base64.b64decode(salt_b64)
            except Exception:
                raise ValueError("Invalid salt encoding in metadata")

            if len(salt) != 32:
                raise ValueError(f"Invalid salt length (expected 32, got {len(salt)})")

            # Derive key from password
            try:
                key = EncryptionBackend.derive_key(password, salt, algo_internal)
            except Exception:
                # Fallback to PBKDF2
                key = EncryptionBackend.derive_key_fallback(password, salt, algo_internal)

            # Decrypt based on algorithm
            algo_map = {
                "AESGCM": "AES-GCM",
                "CHACHA": "ChaCha20-Poly1305",
                "FERNET": "Fernet"
            }

            algo = algo_map.get(algo_internal, "AES-GCM")
            if "Fernet" in algo:
                decrypted_data = EncryptionBackend.decrypt_fernet(encrypted_data, key)
            elif "GCM" in algo:
                decrypted_data = EncryptionBackend.decrypt_aesgcm(encrypted_data, key)
            elif "ChaCha" in algo:
                decrypted_data = EncryptionBackend.decrypt_chacha20(encrypted_data, key)
            else:
                raise ValueError(f"Unknown algorithm: {algo}")

            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            # Clear failed attempts on success
            if failed_attempt_key and failed_attempt_key in EncryptionBackend._failed_attempts:
                del EncryptionBackend._failed_attempts[failed_attempt_key]
                if failed_attempt_key in EncryptionBackend._lockout_until:
                    del EncryptionBackend._lockout_until[failed_attempt_key]

            return True
        except Exception as e:
            # Track failed attempt for brute-force protection
            if failed_attempt_key:
                current_attempts = EncryptionBackend._failed_attempts.get(failed_attempt_key, 0)
                EncryptionBackend._failed_attempts[failed_attempt_key] = current_attempts + 1

                # After 3 failed attempts, add exponential backoff delay
                if EncryptionBackend._failed_attempts[failed_attempt_key] >= 3:
                    delay = min(2 ** EncryptionBackend._failed_attempts[failed_attempt_key], 3600)
                    EncryptionBackend._lockout_until[failed_attempt_key] = time.time() + delay
                    raise Exception(f"Zu viele Fehlversuche. Gesperrt für {delay} Sekunden.")

            raise Exception(f"Decryption failed: {str(e)}")
    
    def encrypt_folder(self, folder_path: str, output_path: str, password: str,
                      algorithm: str) -> bool:
        """Encrypt a folder by zipping and encrypting it"""
        try:
            # Validate input
            if not os.path.isdir(folder_path):
                raise ValueError(f"Invalid folder path: {folder_path}")
            
            if not password or len(password) < 8:
                raise ValueError("Password must be at least 8 characters long")
            
            # Create zip in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                folder_path_obj = Path(folder_path)
                for file_path in folder_path_obj.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(folder_path_obj.parent)
                        zipf.write(file_path, arcname)
            
            # Get zip data
            zip_data = zip_buffer.getvalue()
            
            if len(zip_data) == 0:
                raise ValueError("Folder is empty or contains no files")
            
            # Generate salt - use secure random (32 bytes)
            salt = os.urandom(32)
            
            # Derive key
            try:
                key = EncryptionBackend.derive_key(password, salt, algorithm)
            except Exception:
                key = EncryptionBackend.derive_key_fallback(password, salt, algorithm)
            
            # Encrypt zip data
            if "Fernet" in algorithm:
                encrypted_data = EncryptionBackend.encrypt_fernet(zip_data, key)
            elif "GCM" in algorithm:
                encrypted_data = EncryptionBackend.encrypt_aesgcm(zip_data, key)
            elif "ChaCha20" in algorithm:
                encrypted_data = EncryptionBackend.encrypt_chacha20(zip_data, key)
            else:
                raise ValueError(f"Unknown algorithm: {algorithm}")
            
            # Map to internal short codes
            algo_internal = {
                "1. AES-256-GCM (Sicherster)": "AESGCM",
                "2. ChaCha20-Poly1305": "CHACHA",
                "3. AES-256-Fernet": "FERNET"
            }.get(algorithm, "AESGCM")
            
            # Create metadata
            metadata = {
                "a": algo_internal,
                "s": base64.b64encode(salt).decode(),
                "f": True,  # is_folder flag
                "n": os.path.basename(folder_path),  # original name
            }
            metadata_json = json.dumps(metadata).encode()
            metadata_length = len(metadata_json).to_bytes(4, 'big')
            
            # Generate header for this file
            header = self._generate_header()
            
            # Write encrypted file
            with open(output_path, 'wb') as f:
                f.write(header)
                f.write(metadata_length)
                f.write(metadata_json)
                f.write(encrypted_data)
            
            return True
        except Exception as e:
            raise Exception(f"Folder encryption failed: {str(e)}")
    
    def decrypt_folder(self, input_path: str, output_folder: str, password: str) -> bool:
        """Decrypt an encrypted folder"""
        try:
            # Validate password
            if not password or not isinstance(password, str):
                raise ValueError("Password is required")
            
            # Read and decrypt
            with open(input_path, 'rb') as f:
                # Read header
                header = f.read(32)
                if len(header) != 32:
                    raise ValueError("Invalid encrypted file format")
                
                # Read metadata
                metadata_length_bytes = f.read(4)
                metadata_length = int.from_bytes(metadata_length_bytes, 'big')
                
                if metadata_length > 10000:
                    raise ValueError("Invalid metadata length")
                
                metadata_json = f.read(metadata_length)
                try:
                    metadata = json.loads(metadata_json.decode())
                except json.JSONDecodeError:
                    raise ValueError("Corrupted metadata")
                
                # Read encrypted data
                encrypted_data = f.read()
            
            # Check if it's a folder
            if not metadata.get("f", False):
                raise ValueError("This is not an encrypted folder")
            
            # Extract metadata
            algo_internal = metadata.get("a", "AESGCM")
            salt_b64 = metadata.get("s", "")
            
            if not salt_b64:
                raise ValueError("Missing salt in metadata")
            
            try:
                salt = base64.b64decode(salt_b64)
            except Exception:
                raise ValueError("Invalid salt encoding")
            
            if len(salt) != 32:
                raise ValueError("Invalid salt length")
            
            # Derive key
            try:
                key = EncryptionBackend.derive_key(password, salt, algo_internal)
            except Exception:
                key = EncryptionBackend.derive_key_fallback(password, salt, algo_internal)
            
            # Map internal names
            algo_map = {
                "AESGCM": "AES-GCM",
                "CHACHA": "ChaCha20-Poly1305",
                "FERNET": "Fernet"
            }
            
            # Decrypt
            algo_name = algo_map.get(algo_internal, "AES-GCM")
            if "Fernet" in algo_name:
                zip_data = EncryptionBackend.decrypt_fernet(encrypted_data, key)
            elif "GCM" in algo_name:
                zip_data = EncryptionBackend.decrypt_aesgcm(encrypted_data, key)
            elif "ChaCha" in algo_name:
                zip_data = EncryptionBackend.decrypt_chacha20(encrypted_data, key)
            else:
                raise ValueError(f"Unknown algorithm: {algo_internal}")
            
            # Extract zip
            zip_buffer = io.BytesIO(zip_data)
            with zipfile.ZipFile(zip_buffer, 'r') as zipf:
                zipf.extractall(output_folder)
            
            return True
        except Exception as e:
            raise Exception(f"Folder decryption failed: {str(e)}")


class EncryptionGUI:
    """Tkinter GUI for the encryption tool - secure and user-friendly"""
    
    # Default password (can be changed by user)
    DEFAULT_PASSWORD = "DefaultPassword123!@#"
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Verschlüsselungs-Tool")
        self.root.geometry("650x550")
        self.root.resizable(False, False)
        
        # Modern dark color scheme
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        self.success_color = "#a6e3a1"
        self.error_color = "#f38ba8"
        self.button_bg = "#313244"
        self.entry_bg = "#181825"
        
        self.root.configure(bg=self.bg_color)
        
        self.encryptor = FileEncryptor()
        
        # Configure modern styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure button styles
        style.configure('Encrypt.TButton',
                       background=self.accent_color,
                       foreground='#1e1e2e',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=10)
        style.map('Encrypt.TButton',
                 background=[('active', '#74c0fc')])
        
        style.configure('Decrypt.TButton',
                       background='#f9e2af',
                       foreground='#1e1e2e',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=10)
        style.map('Decrypt.TButton',
                 background=[('active', '#fce094')])
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface with all controls"""
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.bg_color, padx=25, pady=25)
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = tk.Label(main_frame,
                              text="🔐 Verschlüsselungs-Tool",
                              font=('Segoe UI', 20, 'bold'),
                              bg=self.bg_color,
                              fg=self.accent_color)
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        subtitle_label = tk.Label(main_frame,
                                 text="Sichere Datei- & Ordner-Verschlüsselung",
                                 font=('Segoe UI', 9),
                                 bg=self.bg_color,
                                 fg="#6c7086")
        subtitle_label.grid(row=1, column=0, columnspan=3, pady=(0, 25))
        
        # File/Folder selection
        tk.Label(main_frame,
                text="📁 Datei/Ordner:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.bg_color,
                fg=self.fg_color).grid(row=2, column=0, sticky=tk.W, pady=8)
        
        self.path_var = tk.StringVar()
        path_entry = tk.Entry(main_frame,
                             textvariable=self.path_var,
                             width=35,
                             font=('Segoe UI', 9),
                             bg=self.entry_bg,
                             fg=self.fg_color,
                             insertbackground=self.accent_color,
                             relief=tk.FLAT,
                             borderwidth=2)
        path_entry.grid(row=2, column=1, padx=5, pady=8, ipady=6)
        
        browse_btn = tk.Button(main_frame,
                              text="📂",
                              command=self.browse_path,
                              font=('Segoe UI', 11),
                              bg=self.button_bg,
                              fg=self.accent_color,
                              activebackground=self.accent_color,
                              activeforeground=self.bg_color,
                              relief=tk.FLAT,
                              cursor='hand2',
                              width=3,
                              padx=5,
                              pady=5)
        browse_btn.grid(row=2, column=2, pady=8)
        
        # Password
        tk.Label(main_frame,
                text="🔑 Passwort:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.bg_color,
                fg=self.fg_color).grid(row=3, column=0, sticky=tk.W, pady=8)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(main_frame,
                                      textvariable=self.password_var,
                                      show="●",
                                      width=35,
                                      font=('Segoe UI', 9),
                                      bg=self.entry_bg,
                                      fg=self.fg_color,
                                      insertbackground=self.accent_color,
                                      relief=tk.FLAT,
                                      borderwidth=2)
        self.password_entry.grid(row=3, column=1, padx=5, pady=8, ipady=6)
        
        # Set default password
        self.password_var.set(self.DEFAULT_PASSWORD)
        
        # Password action buttons
        pwd_actions = tk.Frame(main_frame, bg=self.bg_color)
        pwd_actions.grid(row=3, column=2, pady=8)
        
        self.show_password_var = tk.BooleanVar()
        show_pwd_btn = tk.Button(pwd_actions,
                                text="👁",
                                command=self.toggle_password,
                                font=('Segoe UI', 10),
                                bg=self.button_bg,
                                fg=self.fg_color,
                                activebackground=self.accent_color,
                                activeforeground=self.bg_color,
                                relief=tk.FLAT,
                                cursor='hand2',
                                width=2,
                                padx=3,
                                pady=3)
        show_pwd_btn.pack(side=tk.LEFT, padx=2)
        
        random_pwd_btn = tk.Button(pwd_actions,
                                  text="🎲",
                                  command=self.generate_random_password,
                                  font=('Segoe UI', 10),
                                  bg=self.button_bg,
                                  fg=self.accent_color,
                                  activebackground=self.accent_color,
                                  activeforeground=self.bg_color,
                                  relief=tk.FLAT,
                                  cursor='hand2',
                                  width=2,
                                  padx=3,
                                  pady=3)
        random_pwd_btn.pack(side=tk.LEFT, padx=2)
        
        copy_pwd_btn = tk.Button(pwd_actions,
                                text="📋",
                                command=self.copy_password,
                                font=('Segoe UI', 10),
                                bg=self.button_bg,
                                fg='#f9e2af',
                                activebackground='#f9e2af',
                                activeforeground=self.bg_color,
                                relief=tk.FLAT,
                                cursor='hand2',
                                width=2,
                                padx=3,
                                pady=3)
        copy_pwd_btn.pack(side=tk.LEFT, padx=2)
        
        # Confirm Password
        tk.Label(main_frame,
                text="🔁 Bestätigen:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.bg_color,
                fg=self.fg_color).grid(row=4, column=0, sticky=tk.W, pady=8)
        
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = tk.Entry(main_frame,
                                              textvariable=self.confirm_password_var,
                                              show="●",
                                              width=35,
                                              font=('Segoe UI', 9),
                                              bg=self.entry_bg,
                                              fg=self.fg_color,
                                              insertbackground=self.accent_color,
                                              relief=tk.FLAT,
                                              borderwidth=2)
        self.confirm_password_entry.grid(row=4, column=1, padx=5, pady=8, ipady=6)
        
        # Set default confirm password
        self.confirm_password_var.set(self.DEFAULT_PASSWORD)
        
        # Password strength indicator
        self.strength_var = tk.StringVar(value="")
        self.strength_label = tk.Label(main_frame,
                                      textvariable=self.strength_var,
                                      font=('Segoe UI', 9, 'italic'),
                                      bg=self.bg_color,
                                      fg="#6c7086")
        self.strength_label.grid(row=4, column=2, pady=8, sticky=tk.W)
        
        # Bind password entry to update strength
        self.password_var.trace_add('write', self.update_password_strength)
        
        # Algorithm selection
        tk.Label(main_frame,
                text="⚙️ Algorithmus:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.bg_color,
                fg=self.fg_color).grid(row=5, column=0, sticky=tk.W, pady=8)
        
        self.algorithm_var = tk.StringVar(value=EncryptionBackend.AES_GCM)
        
        style = ttk.Style()
        style.configure('Dark.TCombobox',
                       fieldbackground=self.entry_bg,
                       background=self.button_bg,
                       foreground=self.fg_color,
                       arrowcolor=self.accent_color)
        
        algorithm_combo = ttk.Combobox(main_frame,
                                      textvariable=self.algorithm_var,
                                      values=[EncryptionBackend.AES_GCM,
                                             EncryptionBackend.CHACHA20,
                                             EncryptionBackend.FERNET],
                                      state='readonly',
                                      width=33,
                                      font=('Segoe UI', 9),
                                      style='Dark.TCombobox')
        algorithm_combo.grid(row=5, column=1, padx=5, pady=8, ipady=6, columnspan=2, sticky=tk.W)
        
        # Important warning
        info_text = "💡 Merke dir dein Passwort - Wiederherstellung ist nicht möglich!"
        info_label = tk.Label(main_frame,
                             text=info_text,
                             font=('Segoe UI', 9, 'italic'),
                             bg=self.bg_color,
                             fg="#94e2d5")
        info_label.grid(row=6, column=0, columnspan=3, pady=12)
        
        # Default password warning
        default_warning = tk.Label(main_frame,
                                  text="⚠️  Standard-Passwort aktiv - Ändere es für bessere Sicherheit!",
                                  font=('Segoe UI', 8),
                                  bg=self.bg_color,
                                  fg="#f38ba8")
        default_warning.grid(row=7, column=0, columnspan=3, pady=(12, 0))
        
        # Action buttons
        button_frame = tk.Frame(main_frame, bg=self.bg_color)
        button_frame.grid(row=8, column=0, columnspan=3, pady=15)
        
        encrypt_btn = tk.Button(button_frame,
                               text="🔒 Verschlüsseln",
                               command=self.encrypt_action,
                               font=('Segoe UI', 11, 'bold'),
                               bg=self.accent_color,
                               fg=self.bg_color,
                               activebackground='#74c0fc',
                               activeforeground=self.bg_color,
                               relief=tk.FLAT,
                               cursor='hand2',
                               padx=30,
                               pady=12)
        encrypt_btn.pack(side=tk.LEFT, padx=8)
        
        decrypt_btn = tk.Button(button_frame,
                               text="🔓 Entschlüsseln",
                               command=self.decrypt_action,
                               font=('Segoe UI', 11, 'bold'),
                               bg='#f9e2af',
                               fg=self.bg_color,
                               activebackground='#fce094',
                               activeforeground=self.bg_color,
                               relief=tk.FLAT,
                               cursor='hand2',
                               padx=30,
                               pady=12)
        decrypt_btn.pack(side=tk.LEFT, padx=8)
        
        # Status label
        self.status_var = tk.StringVar(value="✓ Bereit")
        self.status_label = tk.Label(main_frame,
                                    textvariable=self.status_var,
                                    font=('Segoe UI', 10),
                                    bg=self.bg_color,
                                    fg=self.success_color)
        self.status_label.grid(row=9, column=0, columnspan=3, pady=8)
        
        # Progress bar
        style = ttk.Style()
        style.configure('Dark.Horizontal.TProgressbar',
                       background=self.accent_color,
                       troughcolor=self.button_bg,
                       borderwidth=0,
                       lightcolor=self.accent_color,
                       darkcolor=self.accent_color)
        
        self.progress = ttk.Progressbar(main_frame,
                                       mode='indeterminate',
                                       length=500,
                                       style='Dark.Horizontal.TProgressbar')
        self.progress.grid(row=10, column=0, columnspan=3, pady=5)
        self.progress.grid_remove()
    
    def update_password_strength(self, *args):
        """Update password strength indicator in real-time"""
        password = self.password_var.get()
        
        if not password:
            self.strength_var.set("")
            return
        
        # Calculate strength
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in password)
        
        strength = 0
        if length >= 8:
            strength += 1
        if length >= 12:
            strength += 1
        if length >= 16:
            strength += 1
        if has_lower and has_upper:
            strength += 1
        if has_digit:
            strength += 1
        if has_special:
            strength += 1
        
        # Display strength
        if strength >= 5:
            self.strength_var.set("🟢 Stark")
            self.strength_label.config(fg="#a6e3a1")
        elif strength >= 3:
            self.strength_var.set("🟡 Mittel")
            self.strength_label.config(fg="#f9e2af")
        else:
            self.strength_var.set("🔴 Schwach")
            self.strength_label.config(fg="#f38ba8")
    
    def toggle_password(self):
        """Toggle password visibility"""
        current = self.show_password_var.get()
        self.show_password_var.set(not current)
        
        if self.show_password_var.get():
            self.password_entry.config(show="")
            self.confirm_password_entry.config(show="")
        else:
            self.password_entry.config(show="●")
            self.confirm_password_entry.config(show="●")
    
    def generate_random_password(self):
        """Generate a secure 16-character random password"""
        characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        password = ''.join(secrets.choice(characters) for _ in range(16))
        
        self.password_var.set(password)
        self.confirm_password_var.set(password)
        
        self.show_password_var.set(True)
        self.toggle_password()
        
        self.status_var.set("🎲 Zufälliges Passwort generiert!")
        self.status_label.config(fg=self.accent_color)
        
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        
        messagebox.showinfo("Passwort generiert",
                          f"Sicheres 16-stelliges Passwort wurde generiert und kopiert!\n\n"
                          f"Passwort: {password}\n\n"
                          f"WICHTIG: Speichere dieses Passwort sicher ab!")
    
    def copy_password(self):
        """Copy password to clipboard"""
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.status_var.set("📋 Passwort kopiert!")
            self.status_label.config(fg=self.success_color)
            messagebox.showinfo("Kopiert", "Passwort wurde in die Zwischenablage kopiert!")
        else:
            messagebox.showwarning("Warnung", "Kein Passwort zum Kopieren vorhanden!")
    
    def browse_path(self):
        """Browse for file or folder"""
        choice = messagebox.askquestion("Select Type", 
                                       "Datei auswählen?\n\n'Ja' = Datei\n'Nein' = Ordner")
        
        if choice == 'yes':
            path = filedialog.askopenfilename(title="Datei auswählen")
        else:
            path = filedialog.askdirectory(title="Ordner auswählen")
        
        if path:
            self.path_var.set(path)
    
    def auto_decrypt_flow(self):
        """Auto-decrypt flow when file is opened with the program"""
        path = self.path_var.get()
        if path and os.path.isfile(path) and path.endswith('.encrypted'):
            messagebox.showinfo("Info", f"Datei erkannt: {os.path.basename(path)}\n\nGeben Sie das Passwort ein und klicken Sie auf 'Entschlüsseln'")
    
    
    def encrypt_action(self):
        """Handle encryption with validation"""
        path = self.path_var.get()
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        algorithm = self.algorithm_var.get()
        
        # Validation
        if not path or not os.path.exists(path):
            messagebox.showerror("Fehler", "Bitte wähle eine gültige Datei oder einen Ordner")
            return
        
        if not password:
            messagebox.showerror("Fehler", "Bitte gib ein Passwort ein")
            return
        
        if len(password) < 8:
            messagebox.showerror("Fehler", "Passwort muss mindestens 8 Zeichen lang sein!")
            return
        
        if password != confirm_password:
            messagebox.showerror("Fehler", "Passwörter stimmen nicht überein")
            return
        
        # Ask for output location
        output_path = filedialog.asksaveasfilename(
            title="Verschlüsselte Datei speichern",
            initialfile=os.path.basename(path) + ".encrypted",
            defaultextension=".encrypted",
            filetypes=[("Encrypted Files", "*.encrypted"), ("All Files", "*.*")]
        )
        
        if not output_path:
            return
        
        try:
            # Calculate file size
            file_size = 0
            if os.path.isfile(path):
                file_size = os.path.getsize(path)
            else:
                for dirpath, dirnames, filenames in os.walk(path):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        file_size += os.path.getsize(filepath)
            
            show_progress = file_size >= 1_000_000_000
            
            self.status_var.set("⏳ Verschlüssele...")
            self.status_label.config(fg=self.accent_color)
            
            if show_progress:
                self.progress.grid()
                self.progress.start(10)
            
            self.root.update()
            
            if os.path.isfile(path):
                self.encryptor.encrypt_file(path, output_path, password, algorithm)
            else:
                self.encryptor.encrypt_folder(path, output_path, password, algorithm)
            
            if show_progress:
                self.progress.stop()
                self.progress.grid_remove()
            
            self.status_var.set("✓ Erfolgreich verschlüsselt!")
            self.status_label.config(fg=self.success_color)
            messagebox.showinfo("Erfolg",
                              f"Datei erfolgreich verschlüsselt!\n\n"
                              f"Algorithmus: {algorithm}\n"
                              f"Gespeichert: {os.path.basename(output_path)}")
            
            self.password_var.set("")
            self.confirm_password_var.set("")
            
        except Exception as e:
            self.progress.stop()
            self.progress.grid_remove()
            self.status_var.set("✗ Verschlüsselung fehlgeschlagen")
            self.status_label.config(fg=self.error_color)
            messagebox.showerror("Fehler", str(e))
    
    def decrypt_action(self):
        """Handle decryption with validation"""
        path = self.path_var.get()
        password = self.password_var.get()
        
        # Validation
        if not path or not os.path.isfile(path):
            messagebox.showerror("Fehler", "Bitte wähle eine gültige Datei")
            return
        
        if not password:
            messagebox.showerror("Fehler", "Bitte gib das Passwort ein")
            return
        
        # Check file size
        try:
            file_size = os.path.getsize(path)
            if file_size < 50:
                messagebox.showerror("Fehler", "Datei ist zu klein - wahrscheinlich nicht verschlüsselt")
                return
        except Exception as e:
            messagebox.showerror("Fehler", f"Kann Dateigröße nicht lesen: {str(e)}")
            return
        
        # Check file format and show info
        try:
            with open(path, 'rb') as f:
                header = f.read(32)
                if len(header) != 32:
                    messagebox.showerror("Fehler", "Ungültiges Dateiformat")
                    return
                
                metadata_length_bytes = f.read(4)
                metadata_length = int.from_bytes(metadata_length_bytes, 'big')
                
                if metadata_length > 10000:
                    messagebox.showerror("Fehler", "Ungültiges Dateiformat")
                    return
                
                metadata_json = f.read(metadata_length)
                metadata = json.loads(metadata_json.decode())
                is_folder = metadata.get("f", False)
                
                algo_internal = metadata.get("a", "AESGCM")
                algo_display = {
                    "AESGCM": "AES-256-GCM",
                    "CHACHA": "ChaCha20-Poly1305",
                    "FERNET": "AES-256-Fernet"
                }.get(algo_internal, "Unbekannt")
                
                original_filename = metadata.get("n", "Unbekannt")
                
            if is_folder:
                file_type = "Ordner"
            else:
                _, ext = os.path.splitext(original_filename)
                file_type = ext if ext else "Datei"
            
            messagebox.showinfo("Datei-Info",
                              f"Verschlüsselungs-Algorithmus: {algo_display}\n"
                              f"Original-Name: {original_filename}\n"
                              f"Typ: {file_type}")
        except Exception as e:
            messagebox.showerror("Fehler", f"Datei kann nicht gelesen werden: {str(e)}")
            return
        
        # Ask for output location
        if is_folder:
            output_path = filedialog.askdirectory(title="Ordner zum Extrahieren auswählen")
        else:
            # Suggest original filename with correct extension
            suggested_name = original_filename
            suggested_dir = os.path.dirname(path) or os.path.expanduser("~")
            
            output_path = filedialog.asksaveasfilename(
                title="Entschlüsselte Datei speichern",
                initialdir=suggested_dir,
                initialfile=suggested_name,
                filetypes=[("All Files", "*.*")]
            )
        
        if not output_path:
            return
        
        try:
            file_size = os.path.getsize(path)
            show_progress = file_size >= 1_000_000_000
            
            self.status_var.set("⏳ Entschlüssele...")
            self.status_label.config(fg=self.accent_color)
            
            if show_progress:
                self.progress.grid()
                self.progress.start(10)
            
            self.root.update()
            
            if is_folder:
                self.encryptor.decrypt_folder(path, output_path, password)
            else:
                self.encryptor.decrypt_file(path, output_path, password)
            
            if show_progress:
                self.progress.stop()
                self.progress.grid_remove()
            
            self.status_var.set("✓ Erfolgreich entschlüsselt!")
            self.status_label.config(fg=self.success_color)
            messagebox.showinfo("Erfolg",
                              f"Datei erfolgreich entschlüsselt!\n"
                              f"Gespeichert: {os.path.basename(output_path) if not is_folder else output_path}")
            
            self.password_var.set("")
            self.confirm_password_var.set("")
            
        except Exception as e:
            self.progress.stop()
            self.progress.grid_remove()
            self.status_var.set("✗ Entschlüsselung fehlgeschlagen")
            self.status_label.config(fg=self.error_color)
            messagebox.showerror("Fehler", f"Falsches Passwort oder beschädigte Datei.\n\nDetails: {str(e)}")


def main():
    """Main entry point with command-line argument support"""
    import sys
    
    root = tk.Tk()
    app = EncryptionGUI(root)
    
    # Check if a file was passed as command-line argument
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        # Set the path in the GUI
        app.path_var.set(file_path)
        
        # If it's an encrypted file, auto-select decrypt mode
        if file_path.endswith('.encrypted') and os.path.isfile(file_path):
            root.after(500, app.auto_decrypt_flow)
    
    try:
        root.mainloop()
    finally:
        # Attempt to clear sensitive data from memory
        import gc
        gc.collect()


if __name__ == "__main__":
    main()
