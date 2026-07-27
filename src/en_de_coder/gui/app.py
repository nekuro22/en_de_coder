"""Main application window for en_de_coder GUI."""

import sys
import tkinter as tk
from tkinter import ttk

from en_de_coder import __version__
from en_de_coder.gui.widgets import StatusBar
from en_de_coder.gui.tabs.encrypt_tab import EncryptTab
from en_de_coder.gui.tabs.decrypt_tab import DecryptTab
from en_de_coder.gui.tabs.info_tab import InfoTab
from en_de_coder.gui.tabs.password_tab import PasswordTab
from en_de_coder.gui.tabs.keyfile_tab import KeyfileTab
from en_de_coder.gui.tabs.register_tab import RegisterTab
from en_de_coder.gui.tabs.intern_key_tab import InternKeyTab


class App(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        self.title(f"en_de_coder GUI v{__version__}")
        self.geometry("700x550")
        self.minsize(600, 450)

        # Auto-setup: generate internal key on first launch
        self._run_auto_setup()

        # Style
        style = ttk.Style()
        available = style.theme_names()
        for theme in ("clam", "vista", "winnative", "default"):
            if theme in available:
                style.theme_use(theme)
                break

        # Status bar
        self.status_bar = StatusBar(self)
        self.status_bar.pack(side="bottom", fill="x")

        # Notebook (tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # Add tabs
        self.notebook.add(EncryptTab(self.notebook, self.status_bar), text="Verschlüsseln")
        self.notebook.add(DecryptTab(self.notebook, self.status_bar), text="Entschlüsseln")
        self.notebook.add(InfoTab(self.notebook, self.status_bar), text="Info")
        self.notebook.add(PasswordTab(self.notebook, self.status_bar), text="Passwort")
        self.notebook.add(KeyfileTab(self.notebook, self.status_bar), text="Key-Datei")
        self.notebook.add(InternKeyTab(self.notebook, self.status_bar), text="Geräte-Key")
        self.notebook.add(RegisterTab(self.notebook, self.status_bar), text="Registrieren")

    def _run_auto_setup(self):
        """Generate internal key on first launch if not already done."""
        try:
            from en_de_coder.intern_key import is_initialized, initialize
            from en_de_coder.hardware_id import get_short_hardware_id
            if not is_initialized():
                hw_id = initialize()
                self.after(100, lambda: self.status_bar.set(f"Gerät registriert (ID: {hw_id}...)"))
        except Exception:
            pass


def main():
    """Entry point for the GUI application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
