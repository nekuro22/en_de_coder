"""
Register .encrypted file type with Verschluesselungs-Tool
Run this script with Administrator privileges to register the file type
"""

import os
import sys
import winreg
import subprocess
from pathlib import Path

def find_exe():
    """Find the Verschluesselungs-Tool.exe"""
    # Try current directory
    if os.path.exists("Verschluesselungs-Tool.exe"):
        return os.path.abspath("Verschluesselungs-Tool.exe")
    
    # Try dist folder
    if os.path.exists("dist/Verschluesselungs-Tool.exe"):
        return os.path.abspath("dist/Verschluesselungs-Tool.exe")
    
    # Try build folder
    if os.path.exists("build/Verschluesselungs-Tool.exe"):
        return os.path.abspath("build/Verschluesselungs-Tool.exe")
    
    return None

def register_file_type():
    """Register .encrypted file type in Windows Registry"""
    exe_path = find_exe()
    
    if not exe_path:
        print("ERROR: Verschluesselungs-Tool.exe not found!")
        print("Please make sure the EXE has been built using PyInstaller.")
        return False
    
    print(f"Found executable: {exe_path}")
    print()
    
    try:
        # Check if running as Administrator
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
        
        if not is_admin:
            print("⚠️  WARNING: This script should be run as Administrator!")
            print("The registration may not work properly without administrator privileges.")
            print()
        
        # Register file extension
        print("Registering .encrypted file type...")
        
        # HKEY_CURRENT_USER registry
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, 
                             r"Software\Classes\.encrypted") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "EncryptedFile")
            winreg.SetValueEx(key, "Content Type", 0, winreg.REG_SZ, 
                            "application/octet-stream")
        
        print("✓ Created .encrypted extension entry")
        
        # Register file type handler
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, 
                             r"Software\Classes\EncryptedFile") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, 
                            "Encrypted File (Verschlüsselungs-Tool)")
        
        print("✓ Created EncryptedFile handler")
        
        # Set default icon
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, 
                             r"Software\Classes\EncryptedFile\DefaultIcon") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"{exe_path},0")
        
        print("✓ Set default icon")
        
        # Set open command
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, 
                             r"Software\Classes\EncryptedFile\shell\open\command") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, 
                            f'"{exe_path}" "%1"')
        
        print("✓ Set open command")
        
        # Alternative method - direct to .encrypted
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, 
                             r"Software\Classes\.encrypted\shell\open\command") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, 
                            f'"{exe_path}" "%1"')
        
        print("✓ Created shell command")
        
        # Try to update file association using assoc command
        try:
            subprocess.run(["assoc", ".encrypted=EncryptedFile"], 
                         capture_output=True, check=False)
            print("✓ Updated file association")
        except:
            print("⚠️  Could not update file association with assoc command")
        
        print()
        print("SUCCESS! ✅")
        print()
        print("The following operations were completed:")
        print("  1. .encrypted extension registered")
        print("  2. EncryptedFile file type created")
        print("  3. Default icon set")
        print("  4. Open handler configured")
        print()
        print("You can now:")
        print("  • Double-click any .encrypted file to open it with Verschlüsselungs-Tool")
        print("  • Right-click and select 'Open with' → 'Verschlüsselungs-Tool'")
        print("  • Set Verschlüsselungs-Tool as the default program in Properties")
        print()
        print("IMPORTANT: If you built the EXE in a different location,")
        print("           you may need to run this script again from that location.")
        
        return True
        
    except Exception as e:
        print(f"ERROR: Registration failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = register_file_type()
    
    if not success:
        sys.exit(1)
