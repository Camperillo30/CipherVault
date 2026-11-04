"""
ciphervault_bridge.py – Punto de entrada de CipherVaultBridge.exe.

Chrome / Edge / Brave lo ejecutan cuando la extensión de CipherVault necesita hablar con
la app (native messaging). No tiene interfaz: reenvía los mensajes a CipherVault.exe,
que debe estar abierto. Ver cv_bridge.py.

© 2026 S.C.A - CipherVault. Todos los derechos reservados.
"""
from cv_bridge import host_main

if __name__ == "__main__":
    host_main()
