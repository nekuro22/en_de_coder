"""Register tab - Register .enc file type with the OS."""

import threading
import tkinter as tk
from tkinter import ttk, messagebox


class RegisterTab(ttk.Frame):
    """Tab for registering .enc file type with the operating system."""

    def __init__(self, parent, status_bar, **kwargs):
        super().__init__(parent, **kwargs)
        self.status_bar = status_bar

        self._build_ui()

    def _build_ui(self):
        padding = {"padx": 10, "pady": 5}

        # Info
        info_frame = ttk.LabelFrame(self, text="Dateityp-Registrierung", padding=10)
        info_frame.pack(fill="x", **padding)

        ttk.Label(
            info_frame,
            text=(
                "Registriert den .enc Dateityp beim Betriebssystem.\n"
                "Danach können .enc Dateien per Doppelklick geöffnet werden."
            ),
            justify="left",
        ).pack(anchor="w")

        # Status
        self.status_label = ttk.Label(info_frame, text="Noch nicht registriert")
        self.status_label.pack(anchor="w", pady=(10, 0))

        # Button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", **padding)

        self.register_btn = ttk.Button(btn_frame, text="Registrieren", command=self._do_register)
        self.register_btn.pack(side="right")

    def _do_register(self):
        self.register_btn.configure(state="disabled")
        self.status_bar.set("Registrierung läuft...")

        def worker():
            try:
                from en_de_coder.register import register
                success = register()

                if success:
                    self.after(0, lambda: self.status_label.configure(text="Registriert"))
                    self.after(0, lambda: self.status_bar.set("Registrierung erfolgreich"))
                else:
                    self.after(0, lambda: self.status_label.configure(text="Registrierung fehlgeschlagen"))
                    self.after(0, lambda: self.status_bar.set("Registrierung fehlgeschlagen"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Fehler", str(e)))
                self.after(0, lambda: self.status_bar.set("Fehler bei der Registrierung"))
            finally:
                self.after(0, lambda: self.register_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()
