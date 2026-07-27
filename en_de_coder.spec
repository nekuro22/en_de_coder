# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for en_de_coder
# Build: pyinstaller en_de_coder.spec --clean

import os
import sys

block_cipher = None

src_dir = os.path.join(os.path.dirname(os.path.abspath(SPEC)), 'src')

a = Analysis(
    [os.path.join(src_dir, 'en_de_coder', 'cli.py')],
    pathex=[src_dir],
    binaries=[],
    datas=[],
    hiddenimports=[
        'en_de_coder.hardware_id',
        'en_de_coder.intern_key',
        'en_de_coder.crypto',
        'en_de_coder.register',
        'en_de_coder.gui',
        'en_de_coder.gui.app',
        'en_de_coder.gui.widgets',
        'en_de_coder.gui.tabs.encrypt_tab',
        'en_de_coder.gui.tabs.decrypt_tab',
        'en_de_coder.gui.tabs.info_tab',
        'en_de_coder.gui.tabs.password_tab',
        'en_de_coder.gui.tabs.keyfile_tab',
        'en_de_coder.gui.tabs.register_tab',
        'cryptography',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.primitives.kdf.argon2',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'argon2',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter.test',
        'unittest',
        'pytest',
        'test',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='en_de_coder',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
