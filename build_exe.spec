# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Verschlüsselungs-Tool
Builds a single executable file
"""

block_cipher = None

a = Analysis(
    ['file_encryptor.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['cryptography', '_cffi_backend'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Verschluesselungs-Tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window
    disable_windowed_traceback=False,
    argv_emulation=True,  # Support command-line arguments
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
