# -*- mode: python ; coding: utf-8 -*-
# CipherVault.spec — PyInstaller spec, usado por build.ps1
#
# build.ps1 genera desktop_runtime_config.json ANTES de llamar a PyInstaller,
# y este .spec lo embebe dentro del .exe (misma arquitectura que FileSync Pro).
import json
import os

# ── Barreras de seguridad del build ─────────────────────────────
# El .exe jamás debe llevar claves de modo desarrollador. build.ps1 ya no las
# escribe; esto detiene el build si un JSON antiguo o editado a mano las trae.
with open('desktop_runtime_config.json', encoding='utf-8-sig') as _f:
    _embedded = json.load(_f)
_forbidden = [k for k in _embedded if '_DEV_' in k or k.endswith('ENABLE_DEV_TOOLS')]
if _forbidden:
    raise SystemExit(
        "ERROR: desktop_runtime_config.json contiene claves de desarrollador "
        f"{_forbidden}. Genera el archivo con .\\build.ps1 (no las incluye) y vuelve a compilar."
    )

# El proyecto usa la carpeta "Assets" (Windows no distingue mayúsculas, otros sistemas sí).
ENTRY = 'Main.py' if os.path.exists('Main.py') else 'main.py'
ASSETS = 'Assets' if os.path.isdir('Assets') else 'assets'

# Analysis: qué script arrancar, qué archivos no-Python incluir dentro del .exe (datas)
# y qué módulos importar aunque PyInstaller no los detecte (hiddenimports).
a = Analysis(
    [ENTRY],
    pathex=[],
    binaries=[],
    # Dentro del .exe: la config embebida y TODA la carpeta de imágenes
    # (icono.ico, icono_login.png, icono_footer.png…), disponible como "assets/".
    datas=[
        ('desktop_runtime_config.json', '.'),
        (ASSETS, 'assets'),
    ],
    hiddenimports=[
        'cryptography',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.primitives.hashes',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.simpledialog',
        'tkinter.filedialog',
        'sqlite3',
        'logging.handlers',
        'winreg',
        'cv_extras',
        'cv_sync',
        'cv_bridge',
        # Windows Hello (paquetes winrt; si no están instalados PyInstaller los ignora)
        'winrt.system',
        'winrt.runtime',
        'winrt.windows.foundation',
        'winrt.windows.security.credentials',
        'winrt.windows.security.cryptography',
        'winrt.windows.storage.streams',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)  # empaqueta los módulos Python puros en un archivo comprimido

# EXE: arma el ejecutable final. console=False oculta la consola de Windows.
# upx=False: los ejecutables comprimidos con UPX disparan muchos más falsos
# positivos de antivirus y advertencias de SmartScreen.
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CipherVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(ASSETS, 'icono.ico')],
)

# ── Puente de la extensión del navegador ─────────────────────────
# CipherVaultBridge.exe: programa pequeño (solo biblioteca estándar) que Chrome/Edge/Brave
# ejecutan para hablar con CipherVault.exe. Es de consola porque el navegador se comunica
# con él por stdin/stdout (el navegador lo abre oculto).
bridge_a = Analysis(
    ['ciphervault_bridge.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'cryptography', 'sqlite3', 'winrt', 'cv_extras', 'cv_sync'],
    noarchive=False,
    optimize=0,
)
bridge_pyz = PYZ(bridge_a.pure)
bridge_exe = EXE(
    bridge_pyz,
    bridge_a.scripts,
    bridge_a.binaries,
    bridge_a.datas,
    [],
    name='CipherVaultBridge',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(ASSETS, 'icono.ico')],
)
