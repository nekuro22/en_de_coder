"""Internal key management tab - export, import, regenerate device key."""

import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


class InternKeyTab(ttk.Frame):
    """Tab for managing the device-bound internal key."""

    def __init__(self, parent, status_bar, **kwargs):
        super().__init__(parent, **kwargs)
        self.status_bar = status_bar

        self._build_ui()
        self._refresh_status()

    def _build_ui(self):
        padding = {"padx": 10, "pady": 5}

        # Status
        status_frame = ttk.LabelFrame(self, text="Status", padding=10)
        status_frame.pack(fill="x", **padding)

        self.status_label = ttk.Label(status_frame, text="Wird geprueft...")
        self.status_label.pack(anchor="w")

        # Export
        export_frame = ttk.LabelFrame(self, text="Key exportieren", padding=10)
        export_frame.pack(fill="x", **padding)

        ttk.Label(
            export_frame,
            text=(
                "Speichert den internen Key als Datei.\n"
                "Nur an vertrauenswuerdige Personen weitergeben!"
            ),
            foreground="gray",
            justify="left",
        ).pack(anchor="w")

        export_row = ttk.Frame(export_frame)
        export_row.pack(fill="x", pady=(5, 0))

        self.export_path_var = tk.StringVar()
        ttk.Entry(export_row, textvariable=self.export_path_var, width=35).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(export_row, text="Durchsuchen", command=self._browse_export).pack(side="left", padx=(0, 5))
        self.export_btn = ttk.Button(export_row, text="Exportieren", command=self._export_key)
        self.export_btn.pack(side="left")

        # Import
        import_frame = ttk.LabelFrame(self, text="Key importieren", padding=10)
        import_frame.pack(fill="x", **padding)

        ttk.Label(
            import_frame,
            text=(
                "Ersetzt den aktuellen Key durch einen importierten.\n"
                "ACHTUNG: Alle gerätegebundenen Dateien werden unentschluesselbar!"
            ),
            foreground="red",
            justify="left",
        ).pack(anchor="w")

        import_row = ttk.Frame(import_frame)
        import_row.pack(fill="x", pady=(5, 0))

        self.import_path_var = tk.StringVar()
        ttk.Entry(import_row, textvariable=self.import_path_var, width=35).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(import_row, text="Durchsuchen", command=self._browse_import).pack(side="left", padx=(0, 5))
        self.import_btn = ttk.Button(import_row, text="Importieren", command=self._import_key)
        self.import_btn.pack(side="left")

        # Regenerate
        regen_frame = ttk.LabelFrame(self, text="Key neu generieren", padding=10)
        regen_frame.pack(fill="x", **padding)

        ttk.Label(
            regen_frame,
            text=(
                "Loescht den aktuellen Key und generiert einen neuen.\n"
                "ACHTUNG: Alle gerätegebundenen Dateien werden unentschluesselbar!"
            ),
            foreground="red",
            justify="left",
        ).pack(anchor="w")

        regen_row = ttk.Frame(regen_frame)
        regen_row.pack(fill="x", pady=(5, 0))

        self.regen_btn = ttk.Button(regen_row, text="Neu generieren", command=self._regenerate_key)
        self.regen_btn.pack(side="right")

    def _refresh_status(self):
        try:
            from en_de_coder.intern_key import is_initialized
            from en_de_coder.hardware_id import get_short_hardware_id
            if is_initialized():
                hw_id = get_short_hardware_id()
                self.status_label.configure(text=f"Registriert (ID: {hw_id}...)")
            else:
                self.status_label.configure(text="Nicht registriert")
        except Exception:
            self.status_label.configure(text="Fehler beim Laden")

    def _browse_export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".dat",
            filetypes=[("Key-Dateien", "*.dat"), ("Alle Dateien", "*.*")],
        )
        if path:
            self.export_path_var.set(path)

    def _browse_import(self):
        path = filedialog.askopenfilename(
            filetypes=[("Key-Dateien", "*.dat"), ("Alle Dateien", "*.*")],
        )
        if path:
            self.import_path_var.set(path)

    def _export_key(self):
        from en_de_coder.intern_key import export_key, is_initialized

        if not is_initialized():
            messagebox.showwarning("Warnung", "Kein Key vorhanden. Bitte zuerst registrieren.")
            return

        output_path = self.export_path_var.get().strip()
        if not output_path:
            output_path = "intern_key_backup.dat"

        if os.path.exists(output_path):
            if not messagebox.askyesno("Bestaetigung", f"Datei existiert bereits:\n{output_path}\nUeberschreiben?"):
                return

        self.export_btn.configure(state="disabled")
        self.status_bar.set("Exportiere Key...")

        def worker():
            try:
                export_key(output_path)
                msg = f"Key exportiert nach:\n{output_path}\n\nNur an vertrauenswuerdige Personen weitergeben!"
                self.after(0, lambda: messagebox.showinfo("Erfolg", msg))
                self.after(0, lambda: self.status_bar.set("Key exportiert"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Fehler", str(e)))
                self.after(0, lambda: self.status_bar.set("Fehler beim Export"))
            finally:
                self.after(0, lambda: self.export_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    def _import_key(self):
        from en_de_coder.intern_key import import_key, is_initialized

        input_path = self.import_path_var.get().strip()
        if not input_path:
            messagebox.showwarning("Warnung", "Bitte eine Key-Datei auswaehlen.")
            return

        if not os.path.isfile(input_path):
            messagebox.showerror("Fehler", f"Datei nicht gefunden:\n{input_path}")
            return

        if is_initialized():
            if not messagebox.askyesno(
                "ACHTUNG",
                "Der aktuelle Key wird geloescht!\n\n"
                "Alle gerätegebundenen Dateien koennen danach NICHT mehr entschluesselt werden!\n\n"
                "Fortfahren?"
            ):
                return

        self.import_btn.configure(state="disabled")
        self.status_bar.set("Importiere Key...")

        def worker():
            try:
                import_key(input_path)
                self.after(0, lambda: messagebox.showinfo("Erfolg", "Key erfolgreich importiert."))
                self.after(0, lambda: self.status_bar.set("Key importiert"))
                self.after(0, self._refresh_status)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Fehler", str(e)))
                self.after(0, lambda: self.status_bar.set("Fehler beim Import"))
            finally:
                self.after(0, lambda: self.import_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    def _regenerate_key(self):
        from en_de_coder.intern_key import is_initialized, regenerate_key

        if not messagebox.askyesno(
            "ACHTUNG",
            "Ein neuer Key wird generiert!\n\n"
            "Der alte Key wird permanent geloescht!\n"
            "Alle gerätegebundenen Dateien koennen danach NICHT mehr entschluesselt werden!\n\n"
            "Fortfahren?"
        ):
            return

        self.regen_btn.configure(state="disabled")
        self.status_bar.set("Generiere neuen Key...")

        def worker():
            try:
                hw_id = regenerate_key()
                msg = f"Neuer Key generiert.\nHardware ID: {hw_id}..."
                self.after(0, lambda: messagebox.showinfo("Erfolg", msg))
                self.after(0, lambda: self.status_bar.set(f"Neuer Key: {hw_id}..."))
                self.after(0, self._refresh_status)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Fehler", str(e)))
                self.after(0, lambda: self.status_bar.set("Fehler bei Generierung"))
            finally:
                self.after(0, lambda: self.regen_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()
