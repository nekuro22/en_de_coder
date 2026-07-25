"""Decrypt tab - Decrypt files and folders."""

import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from en_de_coder.gui.widgets import FileSelector, PasswordField


class DecryptTab(ttk.Frame):
    """Tab for decrypting files and folders."""

    def __init__(self, parent, status_bar, **kwargs):
        super().__init__(parent, **kwargs)
        self.status_bar = status_bar
        self.advanced_visible = False

        self._build_ui()

    def _build_ui(self):
        padding = {"padx": 10, "pady": 5}

        # Input
        input_frame = ttk.LabelFrame(self, text="Verschlüsselte Datei", padding=10)
        input_frame.pack(fill="x", **padding)

        self.input_selector = FileSelector(
            input_frame,
            label="Datei (.enc):",
            mode="file",
            filetypes=[("Verschlüsselte Dateien", "*.enc"), ("Alle Dateien", "*.*")],
        )
        self.input_selector.pack(fill="x")

        # Info display
        self.info_frame = ttk.LabelFrame(self, text="Datei-Informationen", padding=10)
        self.info_frame.pack(fill="x", **padding)

        self.info_label = ttk.Label(self.info_frame, text="Datei laden für Infos...")
        self.info_label.pack(anchor="w")

        # Bind path change to load info
        self._info_after_id = None
        self.input_selector.path_var.trace_add("write", self._on_path_change)

        # Password
        self._pw_frame = ttk.LabelFrame(self, text="Passwort", padding=10)
        self._pw_frame.pack(fill="x", **padding)

        self.password_field = PasswordField(self._pw_frame, show_confirm=False)
        self.password_field.pack(fill="x")

        # Advanced section (hidden by default)
        self.advanced_frame = ttk.Frame(self)

        # Key file
        keyfile_frame = ttk.LabelFrame(self.advanced_frame, text="Key-Datei (falls verschlüsselt damit)", padding=10)
        keyfile_frame.pack(fill="x", **padding)

        self.keyfile_selector = FileSelector(keyfile_frame, label="Key-Datei:", mode="file")
        self.keyfile_selector.pack(fill="x")

        # Output
        out_frame = ttk.LabelFrame(self.advanced_frame, text="Ausgabe (optional)", padding=10)
        out_frame.pack(fill="x", **padding)

        self.output_selector = FileSelector(out_frame, label="Ausgabedatei:", mode="save")
        self.output_selector.pack(fill="x")

        # Bottom bar: toggle + button
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(fill="x", **padding)

        self.toggle_btn = ttk.Button(bottom_frame, text="▶ Erweitert", command=self._toggle_advanced, width=12)
        self.toggle_btn.pack(side="left")

        self.decrypt_btn = ttk.Button(bottom_frame, text="Entschlüsseln", command=self._decrypt)
        self.decrypt_btn.pack(side="right")

    def _toggle_advanced(self):
        if self.advanced_visible:
            self.advanced_frame.pack_forget()
            self.toggle_btn.configure(text="▶ Erweitert")
        else:
            self.advanced_frame.pack(fill="x", after=self._pw_frame)
            self.toggle_btn.configure(text="▼ Erweitert")
        self.advanced_visible = not self.advanced_visible

    def _on_path_change(self, *_args):
        if self._info_after_id:
            self.after_cancel(self._info_after_id)
        self._info_after_id = self.after(300, self._load_info)

    def _load_info(self):
        path = self.input_selector.get().strip()
        if not path or not os.path.isfile(path):
            self.info_label.configure(text="Datei laden für Infos...")
            return

        try:
            from en_de_coder.crypto import FileEncryptor, format_duration
            encryptor = FileEncryptor()
            info = encryptor.get_file_info(path)

            file_type = "Ordner" if info["is_folder"] else "Datei"
            lines = [
                f"Algorithmus: {info['algorithm']}",
                f"Originalname: {info['original_name']}",
                f"Typ: {file_type}",
                f"Größe: {info['file_size']:,} Bytes",
                f"Key-Datei: {'Erforderlich' if info.get('has_keyfile') else 'Nein'}",
            ]

            ttl_status = info.get("ttl_status", "none")
            if ttl_status == "locked":
                remaining = info.get("ttl_remaining", 0)
                lines.append(f"Time-lock: GESCHLOSSEN (läuft ab in {format_duration(remaining)})")
            elif ttl_status == "expired":
                lines.append("Time-lock: ABGELAUFEN (Passwort nicht nötig)")
            else:
                lines.append("Time-lock: Keiner")

            self.info_label.configure(text="\n".join(lines))
        except Exception as e:
            self.info_label.configure(text=f"Fehler beim Lesen: {e}")

    def _decrypt(self):
        input_path = self.input_selector.get().strip()
        if not input_path:
            messagebox.showwarning("Warnung", "Bitte eine verschlüsselte Datei auswählen.")
            return

        if not os.path.isfile(input_path):
            messagebox.showerror("Fehler", f"Datei nicht gefunden:\n{input_path}")
            return

        password = self.password_field.get() or None

        output_path = self.output_selector.get().strip() or None

        # Key file (optional)
        keyfile_path = self.keyfile_selector.get().strip() or None
        if keyfile_path and not os.path.isfile(keyfile_path):
            messagebox.showerror("Fehler", f"Key-Datei nicht gefunden:\n{keyfile_path}")
            return

        self.decrypt_btn.configure(state="disabled")
        self.status_bar.set("Entschlüsselung läuft...")

        def worker():
            try:
                from en_de_coder.crypto import FileEncryptor, format_duration
                encryptor = FileEncryptor()

                # Get info first
                info = encryptor.get_file_info(input_path)
                is_folder = info["is_folder"]
                original_name = info["original_name"]

                # Check if keyfile is required
                if info.get("has_keyfile") and not keyfile_path:
                    raise ValueError("Diese Datei wurde mit einer Key-Datei verschlüsselt. Bitte Key-Datei auswählen.")

                # Check TTL
                ttl_status = info.get("ttl_status", "none")
                if ttl_status == "locked" and not password:
                    remaining = info.get("ttl_remaining", 0)
                    raise ValueError(
                        f"Datei ist zeitgesperrt. Läuft ab in {format_duration(remaining)}.\n"
                        "Bitte Passwort eingeben."
                    )

                # Determine output
                out = output_path
                if not out:
                    out = os.path.join(os.path.dirname(input_path) or ".", original_name)

                if is_folder:
                    os.makedirs(out, exist_ok=True)
                    encryptor.decrypt_folder(input_path, out, password, keyfile_path=keyfile_path)
                else:
                    encryptor.decrypt_file(input_path, out, password, keyfile_path=keyfile_path)

                msg = f"Erfolg: {out}"

                # Delete encrypted source after successful decryption
                if os.path.exists(input_path):
                    os.remove(input_path)

                self.after(0, lambda: messagebox.showinfo("Erfolg", msg))
                self.after(0, lambda: self.status_bar.set(msg))
                self.after(0, self._load_info)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Fehler", str(e)))
                self.after(0, lambda: self.status_bar.set("Fehler aufgetreten"))
            finally:
                self.after(0, lambda: self.decrypt_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()
