"""Password generation tab."""

import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox


class PasswordTab(ttk.Frame):
    """Tab for generating secure random passwords."""

    def __init__(self, parent, status_bar, **kwargs):
        super().__init__(parent, **kwargs)
        self.status_bar = status_bar

        self._build_ui()

    def _build_ui(self):
        padding = {"padx": 10, "pady": 5}

        # Options
        opts_frame = ttk.LabelFrame(self, text="Optionen", padding=10)
        opts_frame.pack(fill="x", **padding)

        row = ttk.Frame(opts_frame)
        row.pack(fill="x")

        ttk.Label(row, text="Länge:").pack(side="left", padx=(0, 5))
        self.length_var = tk.StringVar(value="16")
        ttk.Entry(row, textvariable=self.length_var, width=8).pack(side="left", padx=(0, 5))

        ttk.Button(row, text="Generieren", command=self._generate).pack(side="left", padx=(10, 0))

        # Result
        result_frame = ttk.LabelFrame(self, text="Generiertes Passwort", padding=10)
        result_frame.pack(fill="x", **padding)

        self.result_var = tk.StringVar()
        self.result_entry = ttk.Entry(result_frame, textvariable=self.result_var, state="readonly", width=50)
        self.result_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        ttk.Button(result_frame, text="Kopieren", command=self._copy).pack(side="right")

        # Warning
        warn_frame = ttk.Frame(self)
        warn_frame.pack(fill="x", **padding)

        ttk.Label(
            warn_frame,
            text="WICHTIG: Speichere das Passwort sicher!\nEntschlüsselung ist ohne Passwort nicht möglich.",
            foreground="red",
            justify="left",
        ).pack(anchor="w")

    def _generate(self):
        try:
            length = int(self.length_var.get())
            if length < 1:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Warnung", "Bitte eine gütlige Länge eingeben (>= 1).")
            return

        characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        password = "".join(secrets.choice(characters) for _ in range(length))

        self.result_var.set(password)
        self.status_bar.set(f"Passwort generiert ({length} Zeichen)")

    def _copy(self):
        password = self.result_var.get()
        if password:
            self.winfo_toplevel().clipboard_clear()
            self.winfo_toplevel().clipboard_append(password)
            self.status_bar.set("Passwort in Zwischenablage kopiert")
