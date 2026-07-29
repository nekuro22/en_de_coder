"""Info tab - Show encrypted file metadata."""

import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from en_de_coder.gui.widgets import FileSelector


class InfoTab(ttk.Frame):
    """Tab for showing encrypted file metadata."""

    def __init__(self, parent, status_bar, **kwargs):
        super().__init__(parent, **kwargs)
        self.status_bar = status_bar

        self._build_ui()

    def _build_ui(self):
        padding = {"padx": 10, "pady": 5}

        # File selector
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
        info_frame = ttk.LabelFrame(self, text="Informationen", padding=10)
        info_frame.pack(fill="both", expand=True, **padding)

        self.info_text = tk.Text(info_frame, height=15, wrap="word", state="disabled")
        scrollbar = ttk.Scrollbar(info_frame, orient="vertical", command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=scrollbar.set)

        self.info_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", **padding)

        ttk.Button(btn_frame, text="Infos laden", command=self._load_info).pack(side="right")

        # Auto-load on path change
        self._info_after_id = None
        self.input_selector.path_var.trace_add("write", self._on_path_change)

    def _on_path_change(self, *_args):
        if self._info_after_id:
            self.after_cancel(self._info_after_id)
        self._info_after_id = self.after(300, self._load_info)

    def _load_info(self):
        path = self.input_selector.get().strip()
        if not path or not os.path.isfile(path):
            return

        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", "Laden...")
        self.info_text.configure(state="disabled")

        def worker():
            try:
                from en_de_coder.crypto import FileEncryptor, format_duration
                encryptor = FileEncryptor()
                info = encryptor.get_file_info(path)

                file_type = "Ordner" if info["is_folder"] else "Datei"
                lines = [
                    f"Algorithmus:      {info['algorithm']}",
                    f"Originalname:     {info['original_name']}",
                    f"Typ:              {file_type}",
                    f"Verschl. Größe:   {info['file_size']:,} Bytes",
                    "",
                ]

                if info.get("device_bound"):
                    lines.append("Gerätebindung:    JA (nur auf diesem Gerät entschlüsselbar)")
                else:
                    lines.append("Gerätebindung:    Nein")

                if info.get("has_keyfile"):
                    lines.append("Key-Datei:        Ja (Zweitfaktor)")
                else:
                    lines.append("Key-Datei:        Nein")

                lines.append("")

                ttl_status = info.get("ttl_status", "none")
                if ttl_status == "locked":
                    remaining = info.get("ttl_remaining", 0)
                    lines.append(f"Time-lock:        GESCHLOSSEN (läuft ab in {format_duration(remaining)})")
                elif ttl_status == "expired":
                    lines.append("Time-lock:        ABGELAUFEN (Passwort nicht nötig)")
                else:
                    lines.append("Time-lock:        Keiner")

                text = "\n".join(lines)
                self.after(0, lambda: self._set_text(text))
                self.after(0, lambda: self.status_bar.set("Info geladen"))
            except Exception as e:
                self.after(0, lambda: self._set_text(f"Fehler beim Lesen:\n{e}"))
                self.after(0, lambda: self.status_bar.set("Fehler"))

        threading.Thread(target=worker, daemon=True).start()

    def _set_text(self, text: str):
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", text)
        self.info_text.configure(state="disabled")
