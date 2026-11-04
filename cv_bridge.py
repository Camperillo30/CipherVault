"""
cv_bridge.py – Puente entre la extensión de navegador y la app de CipherVault.

    Extensión (Chrome/Edge/Brave) ──native messaging──► CipherVaultBridge.exe
        ──TCP 127.0.0.1 + token──► CipherVault.exe (sesión abierta)

  · La app abre un servidor SOLO en 127.0.0.1 con un puerto al azar y un token
    aleatorio, y los escribe en %LOCALAPPDATA%\\CipherVault\\bridge.json (carpeta del
    usuario de Windows). Al cerrar la app o la sesión, el servidor deja de responder.
  · El navegador arranca CipherVaultBridge.exe (programa pequeño, sin interfaz) cuando
    la extensión lo pide; este lee bridge.json y reenvía cada mensaje a la app.
  · La primera vez, la extensión debe "emparejarse": la app muestra una ventana para
    que el usuario lo apruebe. Después la extensión manda su clave en cada petición.
  · La app nunca entrega contraseñas si la bóveda está bloqueada.

Este módulo solo usa la biblioteca estándar, para que CipherVaultBridge.exe sea pequeño.

© 2026 S.C.A - CipherVault. Todos los derechos reservados. Software con licencia
comercial: queda prohibida su copia, distribución o modificación sin autorización
expresa del autor.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import sys
import threading
from pathlib import Path

HOST_NAME = "com.sca.ciphervault"
MAX_MESSAGE = 64 * 1024
BROWSER_REG_KEYS = (
    r"Software\Google\Chrome\NativeMessagingHosts",
    r"Software\Microsoft\Edge\NativeMessagingHosts",
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
)


def data_dir() -> Path:
    """Carpeta de datos de CipherVault (la misma que usa la app)."""
    if os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "CipherVault"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "CipherVault"
    return Path.home() / "CipherVault"


def bridge_file() -> Path:
    return data_dir() / "bridge.json"


# ══════════════════════════════════════════════
#  LADO DE LA APP: servidor local
# ══════════════════════════════════════════════
class BridgeServer:
    """Servidor de una línea JSON por petición. `handler(request) -> dict` se ejecuta en
    el hilo del servidor (no debe tocar Tk directamente)."""

    def __init__(self, handler):
        self.handler = handler
        self.token = secrets.token_urlsafe(32)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    def start(self) -> bool:
        if self._sock:
            return True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sock.listen(8)
        except OSError:
            return False
        self._sock = sock
        self.port = sock.getsockname()[1]
        path = bridge_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"port": self.port, "token": self.token, "pid": os.getpid()}), encoding="utf-8")
        os.replace(tmp, path)
        self._thread = threading.Thread(target=self._serve, name="cv-bridge", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        sock, self._sock = self._sock, None
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        try:
            data = json.loads(bridge_file().read_text(encoding="utf-8"))
            if data.get("pid") == os.getpid():
                bridge_file().unlink()
        except (OSError, ValueError):
            pass

    def _serve(self):
        while self._sock:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        with conn:
            conn.settimeout(90)
            try:
                raw = b""
                while not raw.endswith(b"\n"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    raw += chunk
                    if len(raw) > MAX_MESSAGE:
                        return
                request = json.loads(raw.decode("utf-8"))
                if not isinstance(request, dict) or not hmac.compare_digest(
                        str(request.pop("_token", "")), self.token):
                    response = {"ok": False, "error": "forbidden"}
                else:
                    try:
                        response = self.handler(request)
                    except Exception:         # noqa: BLE001 - nunca tumbar el servidor
                        response = {"ok": False, "error": "internal"}
                conn.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            except (OSError, ValueError):
                return


def client_key_hash(client_key: str) -> str:
    return hashlib.sha256(("CipherVault/browser|" + (client_key or "")).encode("utf-8")).hexdigest()


# ══════════════════════════════════════════════
#  REGISTRO DEL "NATIVE MESSAGING HOST" (Windows, por usuario)
# ══════════════════════════════════════════════
def host_manifest(host_path: str, extension_ids: list[str]) -> dict:
    return {"name": HOST_NAME, "description": "CipherVault - puente con la extensión",
            "path": host_path, "type": "stdio",
            "allowed_origins": [f"chrome-extension://{i.strip()}/" for i in extension_ids if i.strip()]}


def register_native_host(host_path: str, extension_ids: list[str]) -> Path | None:
    """Escribe el manifiesto y lo registra en HKCU para Chrome, Edge y Brave. Devuelve la
    ruta del manifiesto (o None si no aplica)."""
    ids = [i.strip() for i in extension_ids if i and i.strip()]
    if os.name != "nt" or not ids or not host_path:
        return None
    folder = data_dir() / "native"
    folder.mkdir(parents=True, exist_ok=True)
    manifest = folder / f"{HOST_NAME}.json"
    manifest.write_text(json.dumps(host_manifest(host_path, ids), indent=2), encoding="utf-8")
    import winreg
    for base in BROWSER_REG_KEYS:
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{base}\\{HOST_NAME}") as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(manifest))
        except OSError:
            continue
    return manifest


def dev_host_script(python_exe: str, script: str) -> str:
    """Al ejecutar desde código fuente, el navegador lanza un .bat que corre el puente."""
    folder = data_dir() / "native"
    folder.mkdir(parents=True, exist_ok=True)
    bat = folder / "ciphervault_bridge_dev.bat"
    bat.write_text(f'@echo off\r\n"{python_exe}" -u "{script}" %*\r\n', encoding="utf-8")
    return str(bat)


# ══════════════════════════════════════════════
#  LADO DEL NAVEGADOR: CipherVaultBridge.exe
# ══════════════════════════════════════════════
def _read_native(stream) -> dict | None:
    header = stream.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("<I", header)
    if length > MAX_MESSAGE:
        return None
    return json.loads(stream.read(length).decode("utf-8"))


def _write_native(stream, message: dict):
    data = json.dumps(message, ensure_ascii=False).encode("utf-8")
    stream.write(struct.pack("<I", len(data)) + data)
    stream.flush()


def forward(message: dict, timeout: float = 90) -> dict:
    """Reenvía un mensaje de la extensión a la app abierta."""
    try:
        info = json.loads(bridge_file().read_text(encoding="utf-8"))
        port, token = int(info["port"]), str(info["token"])
    except (OSError, ValueError, KeyError):
        return {"ok": False, "error": "app_closed"}
    payload = dict(message)
    payload["_token"] = token
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.settimeout(timeout)
            conn.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                raw += chunk
        return json.loads(raw.decode("utf-8")) if raw else {"ok": False, "error": "app_closed"}
    except (OSError, ValueError):
        return {"ok": False, "error": "app_closed"}


def host_main():
    """Bucle del puente: mensajes de 4 bytes de longitud + JSON por stdin/stdout."""
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    while True:
        try:
            message = _read_native(stdin)
        except (OSError, ValueError):
            return
        if message is None:
            return
        _write_native(stdout, forward(message) if isinstance(message, dict) else {"ok": False, "error": "bad"})
