"""Encrypt tab - Encrypt files and folders."""

import os
import shutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from en_de_coder.gui.widgets import FileSelector, PasswordField


class EncryptTab(ttk.Frame):
    """Tab for encrypting files and folders."""

    def __init__(self, parent, status_bar, **kwargs):
        super().__init__(parent, **kwargs)
        self.status_bar = status_bar
        self.advanced_visible = False

        self._build_ui()

    def _build_ui(self):
        padding = {"padx": 10, "pady": 5}

        # Input selector
        input_frame = ttk.LabelFrame(self, text="Eingabe", padding=10)
        input_frame.pack(fill="x", **padding)

        self.input_selector = FileSelector(input_frame, label="Datei/Ordner:", mode="file_or_folder")
        self.input_selector.pack(fill="x")

        # Password
        self._pw_frame = ttk.LabelFrame(self, text="Passwort", padding=10)
        self._pw_frame.pack(fill="x", **padding)

        self.password_field = PasswordField(self._pw_frame, show_confirm=True)
        self.password_field.pack(fill="x")

        # Advanced section (hidden by default)
        self.advanced_frame = ttk.Frame(self)

        # Key file
        keyfile_frame = ttk.LabelFrame(self.advanced_frame, text="Key-Datei (optional, Zweitfaktor)", padding=10)
        keyfile_frame.pack(fill="x", **padding)

        self.keyfile_selector = FileSelector(keyfile_frame, label="Key-Datei:", mode="file")
        self.keyfile_selector.pack(fill="x")

        # Options
        opts_frame = ttk.LabelFrame(self.advanced_frame, text="Optionen", padding=10)
        opts_frame.pack(fill="x", **padding)

        # Algorithm + TTL in one row
        opts_row = ttk.Frame(opts_frame)
        opts_row.pack(fill="x")

        ttk.Label(opts_row, text="Algo:").pack(side="left", padx=(0, 5))
        self.algo_var = tk.StringVar(value="aes-gcm")
        ttk.Combobox(
            opts_row,
            textvariable=self.algo_var,
            values=["aes-gcm", "chacha20", "fernet"],
            state="readonly",
            width=12,
        ).pack(side="left", padx=(0, 15))

        ttk.Label(opts_row, text="Time-lock:").pack(side="left", padx=(0, 5))
        self.ttl_var = tk.StringVar()
        ttk.Entry(opts_row, textvariable=self.ttl_var, width=10).pack(side="left", padx=(0, 5))
        ttk.Label(opts_row, text="z.B. 5m, 2h").pack(side="left")

        # Output path
        out_frame = ttk.LabelFrame(self.advanced_frame, text="Ausgabe (optional)", padding=10)
        out_frame.pack(fill="x", **padding)

        self.output_selector = FileSelector(out_frame, label="Ausgabedatei:", mode="save")
        self.output_selector.pack(fill="x")

        # Bottom bar: toggle + button
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(fill="x", **padding)

        self.toggle_btn = ttk.Button(bottom_frame, text="▶ Erweitert", command=self._toggle_advanced, width=12)
        self.toggle_btn.pack(side="left")

        self.encrypt_btn = ttk.Button(bottom_frame, text="Verschlüsseln", command=self._encrypt)
        self.encrypt_btn.pack(side="right")

    def _toggle_advanced(self):
        if self.advanced_visible:
            self.advanced_frame.pack_forget()
            self.toggle_btn.configure(text="▶ Erweitert")
        else:
            self.advanced_frame.pack(fill="x", after=self._pw_frame)
            self.toggle_btn.configure(text="▼ Erweitert")
        self.advanced_visible = not self.advanced_visible

    def _encrypt(self):
        input_path = self.input_selector.get().strip()
        if not input_path:
            messagebox.showwarning("Warnung", "Bitte eine Datei oder einen Ordner auswählen.")
            return

        if not os.path.exists(input_path):
            messagebox.showerror("Fehler", f"Pfad nicht gefunden:\n{input_path}")
            return

        password = self.password_field.get()
        if not password:
            messagebox.showwarning("Warnung", "Bitte ein Passwort eingeben.")
            return

        if not self.password_field.confirm_match():
            messagebox.showwarning("Warnung", "Die Passwörter stimmen nicht überein.")
            return

        # Parse TTL
        ttl_str = self.ttl_var.get().strip()
        ttl = None
        if ttl_str:
            try:
                from en_de_coder.crypto import parse_duration
                ttl = parse_duration(ttl_str)
            except ValueError as e:
                messagebox.showerror("Fehler", str(e))
                return

        # Key file (optional)
        keyfile_path = self.keyfile_selector.get().strip() or None
        if keyfile_path and not os.path.isfile(keyfile_path):
            messagebox.showerror("Fehler", f"Key-Datei nicht gefunden:\n{keyfile_path}")
            return

        output_path = self.output_selector.get().strip()
        if not output_path:
            output_path = input_path + ".enc"

        algorithm = self.algo_var.get()

        # Disable button during operation
        self.encrypt_btn.configure(state="disabled")
        self.status_bar.set("Verschlüsselung läuft...")

        def worker():
            try:
                from en_de_coder.crypto import FileEncryptor
                encryptor = FileEncryptor()

                if os.path.isfile(input_path):
                    encryptor.encrypt_file(input_path, output_path, password, algorithm, ttl=ttl, keyfile_path=keyfile_path)
                elif os.path.isdir(input_path):
                    encryptor.encrypt_folder(input_path, output_path, password, algorithm, ttl=ttl, keyfile_path=keyfile_path)
                else:
                    raise ValueError(f"Ungültiger Pfad: {input_path}")

                size = os.path.getsize(output_path)
                msg = f"Erfolg: {output_path} ({size:,} Bytes)"

                # Delete original after successful encryption
                if os.path.isfile(input_path):
                    os.remove(input_path)
                elif os.path.isdir(input_path):
                    shutil.rmtree(input_path)

                self.after(0, lambda: messagebox.showinfo("Erfolg", msg))
                self.after(0, lambda: self.status_bar.set(msg))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Fehler", str(e)))
                self.after(0, lambda: self.status_bar.set("Fehler aufgetreten"))
            finally:
                self.after(0, lambda: self.encrypt_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()
