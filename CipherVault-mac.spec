# -*- mode: python ; coding: utf-8 -*-
# CipherVault-mac.spec — PyInstaller para macOS (lo usa .github/workflows/release.yml)
#
# Genera dist/CipherVault.app. Igual que en Windows, desktop_runtime_config.json se
# genera antes (con la URL y el secreto de activación, desde los secretos de GitHub) y
# se embebe dentro de la app. Nunca lleva claves del modo desarrollador.
import json
import os
import re

with open('desktop_runtime_config.json', encoding='utf-8-sig') as _f:
    _embedded = json.load(_f)
_forbidden = [k for k in _embedded if '_DEV_' in k or k.endswith('ENABLE_DEV_TOOLS')]
if _forbidden:
    raise SystemExit(f"ERROR: desktop_runtime_config.json contiene claves de desarrollador {_forbidden}.")

with open('Gestor_contrasenas_secure.py', encoding='utf-8') as _f:
    APP_VERSION = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', _f.read(), re.M).group(1)

ASSETS = 'Assets' if os.path.isdir('Assets') else 'assets'

a = Analysis(
    ['Main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('desktop_runtime_config.json', '.'),
        (ASSETS, 'assets'),
    ],
    hiddenimports=[
        'cryptography',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.primitives.hashes',
        'tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'tkinter.simpledialog', 'tkinter.filedialog',
        'sqlite3', 'logging.handlers',
        'cv_extras', 'cv_sync', 'segno',
        # Auto-escritura (pyobjc): atajo global, ventana activa y teclas
        'AppKit', 'Foundation', 'Quartz', 'objc',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['winrt'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CipherVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='CipherVault')

app = BUNDLE(
    coll,
    name='CipherVault.app',
    icon=os.path.join(ASSETS, 'icono_login.png'),     # PyInstaller lo convierte a .icns (requiere Pillow)
    bundle_identifier='co.sca.ciphervault',
    version=APP_VERSION,
    info_plist={
        'CFBundleName': 'CipherVault',
        'CFBundleDisplayName': 'CipherVault',
        'CFBundleShortVersionString': APP_VERSION,
        'CFBundleVersion': APP_VERSION,
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '11.0',
        # Auto-escritura: leer la dirección de la pestaña de Safari/Chrome/Edge/Brave con AppleScript
        'NSAppleEventsUsageDescription': 'CipherVault lee la dirección de la página abierta para '
                                         'saber qué usuario y contraseña escribir con Ctrl + Option + A.',
        'NSHumanReadableCopyright': '© 2026 S.C.A - CipherVault. Todos los derechos reservados.',
    },
)
