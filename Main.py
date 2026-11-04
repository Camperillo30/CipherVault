"""
Main.py – Punto de entrada CipherVault

Arranque real de la app de escritorio (la que se compila con build.ps1 y se abre
con run.ps1 / CipherVault.exe). Solo prepara el path de importación y llama a
`main()` de Gestor_contrasenas_secure.py, donde vive toda la lógica (login, bóveda
cifrada, generador, planes, activación por código).

El .exe se compila sin consola, así que los errores de arranque NO se muestran con
print()/input(): se guardan en %LOCALAPPDATA%\\CipherVault\\ciphervault.log y se
muestran en una ventana.

No confundir con src/main.py: ese es un proyecto aparte, una versión de consola
simplificada con fines académicos.

© 2026 S.C.A - CipherVault. Todos los derechos reservados. Software con
licencia comercial: queda prohibida su copia, distribución o modificación
sin autorización expresa del autor.
"""
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path


def _crash_log_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "CipherVault"
    root.mkdir(parents=True, exist_ok=True)
    return root / "ciphervault.log"


def _report_startup_error(summary: str):
    """Guarda el error en el log y lo muestra en una ventana (funciona sin consola)."""
    try:
        with _crash_log_path().open("a", encoding="utf-8") as log_file:
            log_file.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} CRITICAL {summary}\n")
            log_file.write(traceback.format_exc() + "\n")
    except OSError:
        pass
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("CipherVault", f"{summary}\n\nDetalle técnico guardado en:\n{_crash_log_path()}")
        root.destroy()
    except Exception:
        pass


def main() -> int:
    """Prepara el import de Gestor_contrasenas_secure y lanza la aplicación."""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, current_dir)
        from Gestor_contrasenas_secure import main as run_app
    except ImportError as exc:
        _report_startup_error(f"Falta un componente necesario ({exc}). Reinstala CipherVault; si "
                              "lo ejecutas desde código: pip install -r requirements-desktop.txt")
        return 1
    except Exception:
        _report_startup_error("CipherVault no pudo cargar.")
        return 1

    try:
        run_app()
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception:
        _report_startup_error("CipherVault se cerró por un error inesperado.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
