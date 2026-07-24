"""Reusable widgets for the GUI."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os


class FileSelector(ttk.Frame):
    """File/folder selector with browse button and path entry."""

    def __init__(
        self,
        parent,
        label: str = "Datei:",
        mode: str = "file",
        filetypes: list | None = None,
        **kwargs,
    ):
        super().__init__(parent, **kwargs)
        self.mode = mode
        self.filetypes = filetypes or [("Alle Dateien", "*.*")]

        ttk.Label(self, text=label).grid(row=0, column=0, sticky="w", padx=(0, 5))

        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(self, textvariable=self.path_var, width=50)
        self.path_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))

        self.browse_btn = ttk.Button(self, text="Durchsuchen", command=self._browse)
        self.browse_btn.grid(row=0, column=2)

        # Radio buttons for file_or_folder mode
        self._select_mode_var = tk.StringVar(value="file")
        if self.mode == "file_or_folder":
            radio_frame = ttk.Frame(self)
            radio_frame.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))
            ttk.Radiobutton(radio_frame, text="Datei", variable=self._select_mode_var, value="file").pack(side="left")
            ttk.Radiobutton(radio_frame, text="Ordner", variable=self._select_mode_var, value="folder").pack(side="left", padx=(10, 0))

        self.columnconfigure(1, weight=1)

    def _browse(self):
        if self.mode == "file_or_folder":
            if self._select_mode_var.get() == "folder":
                path = filedialog.askdirectory()
            else:
                path = filedialog.askopenfilename(filetypes=self.filetypes)
        elif self.mode == "file":
            path = filedialog.askopenfilename(filetypes=self.filetypes)
        elif self.mode == "save":
            path = filedialog.asksaveasfilename(filetypes=self.filetypes)
        elif self.mode == "folder":
            path = filedialog.askdirectory()
        else:
            path = ""
        if path:
            self.path_var.set(path)

    def get(self) -> str:
        return self.path_var.get()

    def set(self, value: str):
        self.path_var.set(value)


class PasswordField(ttk.Frame):
    """Password entry with show/hide toggle."""

    def __init__(self, parent, label: str = "Passwort:", show_confirm: bool = False, **kwargs):
        super().__init__(parent, **kwargs)
        self._visible = False

        ttk.Label(self, text=label).grid(row=0, column=0, sticky="w", padx=(0, 5))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self, textvariable=self.password_var, show="*", width=40)
        self.password_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))

        self.toggle_btn = ttk.Button(self, text="Augen", width=4, command=self._toggle)
        self.toggle_btn.grid(row=0, column=2)

        self.row = 1
        self.confirm_var = None
        if show_confirm:
            ttk.Label(self, text="Bestätigen:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=(5, 0))
            self.confirm_var = tk.StringVar()
            self.confirm_entry = ttk.Entry(self, textvariable=self.confirm_var, show="*", width=40)
            self.confirm_entry.grid(row=1, column=1, sticky="ew", padx=(0, 5), pady=(5, 0))
            self.row = 2

        self.columnconfigure(1, weight=1)

    def _toggle(self):
        self._visible = not self._visible
        char = "" if self._visible else "*"
        self.password_entry.configure(show=char)
        if self.confirm_var is not None:
            self.confirm_entry.configure(show=char)

    def get(self) -> str:
        return self.password_var.get()

    def confirm_match(self) -> bool:
        if self.confirm_var is None:
            return True
        return self.password_var.get() == self.confirm_var.get()


class StatusBar(ttk.Frame):
    """Status bar at the bottom of the window."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.status_var = tk.StringVar(value="Bereit")
        self.label = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        self.label.pack(fill="x", padx=2, pady=2)

    def set(self, text: str):
        self.status_var.set(text)

    def clear(self):
        self.status_var.set("Bereit")
