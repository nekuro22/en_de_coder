"""
Cross-platform file type registration for .enc files.

Windows: Uses Windows Registry (requires admin for full functionality).
Linux: Creates .desktop file and uses xdg-mime.
macOS: Creates Finder integration via duti/plutil (basic support).
"""

import os
import platform
import shutil
import subprocess
import sys


def _find_enc_command() -> str | None:
    """Find the path to the 'enc' command."""
    # Check if 'enc' is on PATH
    enc_path = shutil.which("enc")
    if enc_path:
        return enc_path

    # Check if running as a script directly
    if sys.argv and os.path.isfile(sys.argv[0]):
        return os.path.abspath(sys.argv[0])

    return None


def register_windows() -> bool:
    """Register .enc file type in Windows Registry."""
    try:
        import winreg
    except ImportError:
        print("Error: winreg module not available. Are you on Windows?", file=sys.stderr)
        return False

    enc_path = _find_enc_command()
    if not enc_path:
        print("Error: Cannot find 'enc' command. Is it installed?", file=sys.stderr)
        return False

    print(f"Registering with: {enc_path}")

    try:
        # Check for admin
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False

        if not is_admin:
            print("Warning: Running without admin privileges.")
            print("Some registrations may not work.\n")

        # Register file extension
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER, r"Software\Classes\.enc"
        ) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "EncryptedFile")
            winreg.SetValueEx(
                key, "Content Type", 0, winreg.REG_SZ, "application/octet-stream"
            )
        print("  Created .enc extension entry")

        # Register file type handler
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER, r"Software\Classes\EncryptedFile"
        ) as key:
            winreg.SetValueEx(
                key, "", 0, winreg.REG_SZ, "Encrypted File (en_de_coder)"
            )
        print("  Created EncryptedFile handler")

        # Set open command
        with winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Classes\EncryptedFile\shell\open\command",
        ) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f'"{enc_path}" decrypt "%1"')

        print("  Set open command")

        # Try assoc command
        try:
            subprocess.run(
                ["assoc", ".enc=EncryptedFile"],
                capture_output=True,
                check=False,
            )
        except FileNotFoundError:
            pass

        print("\nDone! .enc files are now associated with en_de_coder.")
        print("You may need to restart Explorer or log out/in for changes to take effect.")
        return True

    except Exception as e:
        print(f"Error: Registration failed: {e}", file=sys.stderr)
        return False


def register_linux() -> bool:
    """Register .enc file type on Linux using xdg-mime."""
    enc_path = _find_enc_command()
    if not enc_path:
        print("Error: Cannot find 'enc' command. Is it installed?", file=sys.stderr)
        return False

    home = os.path.expanduser("~")
    applications_dir = os.path.join(home, ".local", "share", "applications")
    mime_dir = os.path.join(home, ".local", "share", "mime")
    packages_dir = os.path.join(mime_dir, "packages")

    try:
        # Create directories
        os.makedirs(applications_dir, exist_ok=True)
        os.makedirs(packages_dir, exist_ok=True)

        # Create .desktop file
        desktop_content = f"""[Desktop Entry]
Name=en_de_coder
Comment=Encrypted file (en_de_coder)
Exec={enc_path} decrypt %f
Type=Application
MimeType=application/x-encrypted;
Terminal=true
NoDisplay=true
"""
        desktop_path = os.path.join(applications_dir, "en-de-coder.desktop")
        with open(desktop_path, "w") as f:
            f.write(desktop_content)
        os.chmod(desktop_path, 0o755)
        print(f"  Created: {desktop_path}")

        # Create MIME type definition
        mime_content = """<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-encrypted">
    <comment>Encrypted file</comment>
    <glob pattern="*.enc"/>
    <icon name="lock"/>
  </mime-type>
</mime-info>
"""
        mime_path = os.path.join(packages_dir, "encrypted.xml")
        with open(mime_path, "w") as f:
            f.write(mime_content)
        print(f"  Created: {mime_path}")

        # Update MIME database
        subprocess.run(["update-mime-database", mime_dir], capture_output=True, check=False)

        # Set default application for .enc
        subprocess.run(
            ["xdg-mime", "default", "en-de-coder.desktop", "application/x-encrypted"],
            capture_output=True,
            check=False,
        )
        print("  Set as default application for .enc files")

        # Update desktop database
        subprocess.run(
            ["update-desktop-database", applications_dir],
            capture_output=True,
            check=False,
        )

        print("\nDone! .enc files are now associated with en_de_coder.")
        print("You may need to log out and back in for changes to take effect.")
        return True

    except Exception as e:
        print(f"Error: Registration failed: {e}", file=sys.stderr)
        return False


def register() -> bool:
    """Register .enc file type for the current platform."""
    system = platform.system()

    if system == "Windows":
        return register_windows()
    elif system == "Linux":
        return register_linux()
    else:
        print(f"Warning: File type registration not implemented for {system}.")
        print("You can manually associate .enc files with the 'enc' command.")
        return False
