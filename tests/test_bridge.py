"""Puente de la extensión: servidor local de la app, emparejamiento y CipherVaultBridge."""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import cv_bridge
import Gestor_contrasenas_secure as gcs
from test_gui_smoke import PW, add, register_and_login, ui  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parent.parent
CLIENT = {"client_id": "abc123", "client_key": "k" * 64}


def ask(app, message, wait=5):
    """Llama al puente desde otro hilo mientras el hilo de Tk sigue atendiendo ventanas."""
    box = {}
    worker = threading.Thread(target=lambda: box.update(r=cv_bridge.forward(message, timeout=wait)))
    worker.start()
    end = time.time() + wait
    while worker.is_alive() and time.time() < end:
        app.root.update()
        time.sleep(0.02)
    worker.join(1)
    return box.get("r")


def test_emparejar_y_rellenar(ui):
    app = ui
    register_and_login(app)
    app._show_add_form()
    app.add_service.set("GitHub"); app.add_url.set("https://github.com"); app.add_uname.set("ana")
    app.add_pwd.set("Zq9#mLp2$vXr8&Kd"); app._save_password()
    add(app, "Bancolombia", "ana.b", "clave-banco-1")          # sin página web: coincidencia dudosa

    assert ask(app, {"action": "status", **CLIENT}) == {
        "ok": True, "app": "CipherVault", "version": gcs.APP_VERSION, "associated": False, "unlocked": True}
    assert ask(app, {"action": "logins", "url": "https://github.com", **CLIENT})["error"] == "not_associated"
    assert ask(app, {"action": "associate", "browser": "Chrome", **CLIENT}) == {"ok": True}  # askyesno → sí

    items = ask(app, {"action": "logins", "url": "https://github.com/login", **CLIENT})["items"]
    assert [(i["service"], i["weak"]) for i in items] == [("GitHub", False)]
    creds = ask(app, {"action": "credentials", "id": items[0]["id"], "url": "https://github.com/login", **CLIENT})
    assert creds["password"] == "Zq9#mLp2$vXr8&Kd" and creds["username"] == "ana"
    # un sitio falso no recibe la contraseña aunque pida el mismo id
    bad = ask(app, {"action": "credentials", "id": items[0]["id"], "url": "https://github.com.evil.io", **CLIENT})
    assert bad == {"ok": False, "error": "no_match"}
    # coincidencia solo por nombre: exige confirmación explícita
    url = "https://sucursalpersonas.transaccionesbancolombia.com"
    weak = ask(app, {"action": "logins", "url": url, **CLIENT})["items"][0]
    assert weak["weak"] is True
    assert ask(app, {"action": "credentials", "id": weak["id"], "url": url, **CLIENT})["error"] == "no_match"
    assert ask(app, {"action": "credentials", "id": weak["id"], "url": url, "confirm_weak": True,
                     **CLIENT})["password"] == "clave-banco-1"
    # otra clave de cliente no sirve; sesión cerrada: bloqueado
    assert ask(app, {"action": "logins", "url": "https://github.com", "client_id": "abc123",
                     "client_key": "x" * 64})["error"] == "not_associated"
    app._logout()
    assert ask(app, {"action": "logins", "url": "https://github.com", **CLIENT})["error"] == "locked"


def test_rechazar_emparejamiento_y_token(ui, monkeypatch):
    app = ui
    monkeypatch.setattr(gcs.messagebox, "askyesno", lambda *a, **k: False)
    assert ask(app, {"action": "associate", **CLIENT})["error"] == "rejected"
    info = json.loads(cv_bridge.bridge_file().read_text(encoding="utf-8"))
    with socket.create_connection(("127.0.0.1", info["port"]), timeout=3) as conn:
        conn.sendall(json.dumps({"_token": "falso", "action": "status"}).encode() + b"\n")
        assert json.loads(conn.recv(4096)) == {"ok": False, "error": "forbidden"}


def test_puente_por_stdin(ui):
    """CipherVaultBridge habla el protocolo de native messaging (4 bytes + JSON)."""
    app = ui
    msg = json.dumps({"action": "status", **CLIENT}).encode()
    proc = subprocess.Popen([sys.executable, str(ROOT / "ciphervault_bridge.py")], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, env={**os.environ}, cwd=str(ROOT))
    box = {}
    worker = threading.Thread(target=lambda: box.update(out=proc.communicate(struct.pack("<I", len(msg)) + msg,
                                                                               timeout=10)[0]))
    worker.start()
    while worker.is_alive():
        app.root.update(); time.sleep(0.02)
    out = box["out"]
    length = struct.unpack("<I", out[:4])[0]
    assert json.loads(out[4:4 + length])["app"] == "CipherVault"


def test_manifiesto_del_host():
    manifest = cv_bridge.host_manifest(r"C:\Apps\CipherVaultBridge.exe", ["abcdefghijklmnopabcdefghijklmnop", ""])
    assert manifest["name"] == "com.sca.ciphervault"
    assert manifest["allowed_origins"] == ["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]
