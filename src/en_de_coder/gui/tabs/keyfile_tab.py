"""Key file generation tab."""

import os
import secrets
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


class KeyfileTab(ttk.Frame):
    """Tab for generating secure random key files."""

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

        ttk.Label(row, text="Länge (Bytes):").pack(side="left", padx=(0, 5))
        self.length_var = tk.StringVar(value="256")
        ttk.Entry(row, textvariable=self.length_var, width=8).pack(side="left", padx=(0, 5))

        # Output path
        out_frame = ttk.LabelFrame(self, text="Speichern unter", padding=10)
        out_frame.pack(fill="x", **padding)

        out_row = ttk.Frame(out_frame)
        out_row.pack(fill="x")

        self.output_var = tk.StringVar()
        ttk.Entry(out_row, textvariable=self.output_var, width=40).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(out_row, text="Durchsuchen", command=self._browse).pack(side="left")

        # Generate button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", **padding)

        ttk.Button(btn_frame, text="Key-Datei generieren", command=self._generate).pack(side="right")

        # Warning
        warn_frame = ttk.Frame(self)
        warn_frame.pack(fill="x", **padding)

        ttk.Label(
            warn_frame,
            text=(
                "WICHTIG: Speichere die Key-Datei sicher!\n"
                "Ohne Key-Datei ist Entschlüsselung nicht möglich.\n"
                "Erstelle ein Backup auf einem USB-Stick oder externen Laufwerk."
            ),
            foreground="red",
            justify="left",
        ).pack(anchor="w")

    def _browse(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".key",
            filetypes=[("Key-Dateien", "*.key"), ("Alle Dateien", "*.*")],
        )
        if path:
            self.output_var.set(path)

    def _generate(self):
        try:
            length = int(self.length_var.get())
            if length < 16:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Warnung", "Bitte eine gültige Länge eingeben (>= 16).")
            return

        output_path = self.output_var.get().strip()
        if not output_path:
            messagebox.showwarning("Warnung", "Bitte einen Speicherort auswählen.")
            return

        if os.path.exists(output_path):
            if not messagebox.askyesno("Bestätigung", f"Datei existiert bereits:\n{output_path}\nÜberschreiben?"):
                return

        try:
            keyfile_data = os.urandom(length)
            with open(output_path, "wb") as f:
                f.write(keyfile_data)

            msg = f"Key-Datei erstellt:\n{output_path}\n({length} Bytes)"
            self.status_bar.set(f"Key-Datei erstellt ({length} Bytes)")
            messagebox.showinfo("Erfolg", msg)
        except Exception as e:
            messagebox.showerror("Fehler", str(e))
            self.status_bar.set("Fehler bei der Key-Datei-Erstellung")
