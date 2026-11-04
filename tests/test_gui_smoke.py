"""Prueba de humo de la interfaz real (Tk) con diálogos simulados. Se omite si no hay pantalla."""
import json
import tkinter as tk


import pytest

import Gestor_contrasenas_secure as gcs

PW = "Contraseña-Larga-123"
NEW_PW = "Otra-Contraseña-Nueva-456"


@pytest.fixture
def ui(monkeypatch, tmp_path):
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("sin pantalla")
    calls = []
    answers = []
    for name in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(gcs.messagebox, name, lambda t, m="", _n=name, **k: calls.append((_n, t, m)))
    monkeypatch.setattr(gcs.messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(gcs.simpledialog, "askstring", lambda *a, **k: answers.pop(0))
    # Diálogos de archivo: por defecto "cancelar" (las pruebas que los usan los reemplazan).
    monkeypatch.setattr(gcs.filedialog, "asksaveasfilename", lambda **k: "")
    monkeypatch.setattr(gcs.filedialog, "askopenfilename", lambda **k: "")
    app = gcs.CipherVaultApp(root)
    # Ventana de opciones (_choose): las pruebas fijan la respuesta en app.choices.
    app.choices = []
    monkeypatch.setattr(app, "_choose", lambda *a, **k: app.choices.pop(0) if app.choices else None)
    app.calls, app.answers = calls, answers
    yield app
    try:
        root.destroy()
    except tk.TclError:
        pass


def register_and_login(app, user="ana", email="ana@example.com", pw=PW):
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, user)
    app.entry_email.delete(0, "end"); app.entry_email.insert(0, email)
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, pw)
    app._register()
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, pw)
    app._login()


def add(app, service, username, pwd, notes=""):
    app._show_add_form()
    app.add_service.set(service); app.add_uname.set(username); app.add_pwd.set(pwd)
    app.add_notes.insert("1.0", notes)
    app._save_password()


def test_flujo_completo(ui):
    app = ui
    register_and_login(app)
    assert app.current_user and app.current_user["username"] == "ana"
    assert app.user_version == "trial"

    # todas las pestañas dibujan sin error
    for tab in (app._tab_dashboard, app._tab_generator, app._tab_list, app._tab_security,
                app._tab_settings, app._show_license_info, app._show_plans_screen):
        tab()
        app.root.update()

    add(app, "GitHub", "ana@git", "Zq9#mLp2$vXr8&Kd", "recuperación: 1234")
    add(app, "Gmail", "ana@gmail", "otra-clave-larga-77!")
    with gcs.db() as conn:
        rows = conn.execute("SELECT service,username,password_encrypted,notes FROM passwords").fetchall()
    assert len(rows) == 2
    blob = " ".join(" ".join(map(str, r)) for r in rows)
    assert "GitHub" not in blob and "recuperación" not in blob and "ana@git" not in blob

    app._tab_list(); app.root.update()
    app.selected_password_id = 1
    data = app._get_pwd_data()
    assert data["service"] == "GitHub" and data["notes"] == "recuperación: 1234"
    assert data["password"] == "Zq9#mLp2$vXr8&Kd"

    # bloqueo por inactividad
    app.config["lock_timeout"] = 1
    app._last_activity -= 60
    app._check_idle()
    assert app.current_user is None


def test_login_incorrecto_y_bloqueo(ui):
    app = ui
    register_and_login(app)
    app._logout()
    for _ in range(5):
        app.entry_user.delete(0, "end"); app.entry_user.insert(0, "ana")
        app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, "incorrecta-larga-1")
        app._login()
    assert app.current_user is None
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, PW)
    app._login()
    assert app.current_user is None            # bloqueado aun con la clave correcta
    assert any("Demasiados intentos" in m for _, _, m in app.calls)
    app.calls.clear()
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "nadie")
    app._login()
    assert app.calls[-1][2] == "Usuario o contraseña incorrectos."


def test_registro_valida_y_email_duplicado(ui):
    app = ui
    register_and_login(app)
    app._logout()
    app.calls.clear()
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "otra")
    app.entry_email.delete(0, "end"); app.entry_email.insert(0, "ANA@example.com")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, PW)
    app._register()
    assert "email" in app.calls[-1][2].lower()
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "../x")
    app._register()
    assert app.calls[-1][0] == "showerror"
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "corta")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, "corta")
    app._register()
    assert "12" in app.calls[-1][2]


def test_cambiar_contrasena_maestra(ui):
    app = ui
    register_and_login(app)
    add(app, "GitHub", "ana@git", "Zq9#mLp2$vXr8&Kd", "nota")
    app.answers[:] = [PW, NEW_PW, NEW_PW]
    app._change_master_password()
    assert app.calls[-1][1].startswith("✅")
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
    assert not gcs.authenticate(PW, user).ok
    assert gcs.authenticate(NEW_PW, user).ok
    # sesión actual sigue leyendo y un login nuevo con la clave nueva también
    app.selected_password_id = 1
    assert app._get_pwd_data()["password"] == "Zq9#mLp2$vXr8&Kd"
    app._logout()
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "ana")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, NEW_PW)
    app._login()
    assert app.current_user
    app.selected_password_id = 1
    assert app._get_pwd_data()["notes"] == "nota"


def test_cambiar_contrasena_con_actual_incorrecta_no_cambia_nada(ui):
    app = ui
    register_and_login(app)
    add(app, "GitHub", "u", "clave-larga-123!")
    app.answers[:] = ["no-es-la-actual"]
    app._change_master_password()
    with gcs.db() as conn:
        assert gcs.authenticate(PW, gcs.get_user_by_name(conn, "ana")).ok


def test_licencia_exportar_importar(ui, monkeypatch, tmp_path):
    app = ui
    monkeypatch.setattr(gcs, "VAULT_KDF_ITERATIONS", 100_000)   # mínimo que acepta la importación
    register_and_login(app)
    add(app, "GitHub", "ana@git", "Zq9#mLp2$vXr8&Kd", "n1")
    # exportar exige plan basic/premium: se activa un código
    code = "ABCD-EFGH-JKLM-NPQR"
    from test_ciphervault import FakeMake
    server = FakeMake()
    server.add(plan="premium", ref="R1", code=code)
    monkeypatch.setattr(gcs.LicenseActivationManager, "_call_server", staticmethod(server))
    res = gcs.LicenseActivationManager.redeem(code, "ana", "ana@example.com")
    app._refresh_license_state()
    assert app.user_version == "premium" and res["plan"] == "premium"
    app._show_license_info(); app.root.update()

    target = tmp_path / "respaldo.cvault"
    monkeypatch.setattr(gcs.filedialog, "asksaveasfilename", lambda **k: str(target))
    app.answers[:] = [PW, "contraseña-de-export-1", "contraseña-de-export-1"]
    app.choices[:] = ["cvault"]
    app._export_vault()
    assert target.exists()
    raw = target.read_text(encoding="utf-8")
    assert "GitHub" not in raw and json.loads(raw)["iterations"] == gcs.VAULT_KDF_ITERATIONS

    # borrar y volver a importar
    app.selected_password_id = 1
    app._delete_password()
    with gcs.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0] == 0
    monkeypatch.setattr(gcs.filedialog, "askopenfilename", lambda **k: str(target))
    app.answers[:] = [PW, "contraseña-de-export-1"]
    app._import_vault()
    assert "Importadas: 1" in app.calls[-1][2]
    app.selected_password_id = 2
    assert app._get_pwd_data()["service"] == "GitHub"
    # importar otra vez: se omite el duplicado; contraseña de respaldo mala: no importa nada
    app.answers[:] = [PW, "contraseña-de-export-1"]
    app._import_vault()
    assert "Ya existían" in app.calls[-1][2]
    app.answers[:] = [PW, "mala-mala-mala-1"]
    app._import_vault()
    assert app.calls[-1][0] == "showerror"


def test_licencia_manipulada_cae_a_gratis_al_entrar(ui):
    app = ui
    register_and_login(app)
    app._logout()
    with gcs.db() as conn:
        conn.execute("UPDATE users SET version='premium', license_expiry='2099-01-01 00:00:00'")
    app.calls.clear()
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "ana")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, PW)
    app._login()
    assert app.user_version == "free"
    assert any(t == "Licencia no válida" for _, t, _ in app.calls)


def test_dialogo_activar_licencia_abre(ui):
    app = ui
    register_and_login(app)
    app._activate_license_dialog()
    app.root.update()
    for child in app.root.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.grab_release(); child.destroy()


def test_login_de_cuenta_antigua_migra_y_conserva_datos(ui):
    from conftest import make_user
    app = ui
    user = make_user(app, username="vieja", email="vieja@example.com", legacy="pbkdf2")
    # contraseña guardada como las versiones anteriores: Fernet con clave PBKDF2 del vault_salt "nuevo"
    auth = gcs.authenticate(PW, user)
    vault = gcs._fernet_from_key(auth.key)
    with gcs.db() as conn:
        conn.execute("UPDATE users SET vault_salt=? WHERE id=?", (auth.vault_salt, user["id"]))
        conn.execute("INSERT INTO passwords(user_id,service,username,password_encrypted,strength,notes) "
                     "VALUES(?,?,?,?,?,?)", (user["id"], "Banco", "yo", vault.encrypt(b"clave-vieja").decode(),
                                              "Fuerte", "nota vieja"))
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "vieja")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, PW)
    app._login()
    assert app.current_user
    assert any(t == "Seguridad actualizada" for _, t, _ in app.calls)
    with gcs.db() as conn:
        u = gcs.get_user_by_name(conn, "vieja")
    assert u["password_hash"].startswith("v3$")
    app.selected_password_id = 1
    data = app._get_pwd_data()
    assert (data["service"], data["password"], data["notes"]) == ("Banco", "clave-vieja", "nota vieja")


class _InlineThread:
    """Ejecuta el trabajo en el hilo principal (en las pruebas no corre mainloop)."""
    def __init__(self, target=None, **_k):
        self._target = target

    def start(self):
        self._target()


def _pump(app, until, seconds=5):
    import time
    end = time.time() + seconds
    while time.time() < end and not until():
        app.root.update()
        time.sleep(0.02)


def test_login_repara_licencia_con_sello_danado(ui, monkeypatch):
    app = ui
    from test_ciphervault import FakeMake
    server = FakeMake()
    code = "ABCD-EFGH-JKLM-NPQR"
    server.add(plan="developer", meses="1200", ref="OWNER-DEV", code=code)
    monkeypatch.setattr(gcs.LicenseActivationManager, "_call_server", staticmethod(server))
    monkeypatch.setattr(gcs.threading, "Thread", _InlineThread)
    register_and_login(app)
    gcs.LicenseActivationManager.redeem(code, "ana", "ana@example.com")
    app._logout()
    with gcs.db() as conn:
        conn.execute("UPDATE users SET license_seal='roto'")
    app.calls.clear()
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "ana")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, PW)
    app._login()
    _pump(app, lambda: app.user_version == "developer")
    assert app.user_version == "developer"
    assert any(t == "Licencia restaurada" for _, t, _ in app.calls)
    assert not any(t == "Licencia no válida" for _, t, _ in app.calls)


def test_dialogo_pide_email_si_la_cuenta_no_tiene(ui, monkeypatch):
    app = ui
    from test_ciphervault import FakeMake
    server = FakeMake()
    code = "ABCD-EFGH-JKLM-NPQR"
    server.add(plan="premium", ref="R1", code=code, email="ana@example.com")
    monkeypatch.setattr(gcs.LicenseActivationManager, "_call_server", staticmethod(server))
    monkeypatch.setattr(gcs.threading, "Thread", _InlineThread)
    register_and_login(app)
    with gcs.db() as conn:
        conn.execute("UPDATE users SET email=''")
    app.current_user["email"] = ""
    app._activate_license_dialog()
    app.root.update()
    win = [c for c in app.root.winfo_children() if isinstance(c, tk.Toplevel)][-1]

    def walk(w):
        for c in w.winfo_children():
            yield c
            yield from walk(c)
    entries = [w for w in walk(win) if w.winfo_class() == "TEntry"]
    assert len(entries) == 2                    # código + email
    entries[0].insert(0, code)
    entries[1].insert(0, "ANA@example.com ")
    buttons = [w for w in walk(win) if w.winfo_class() == "TButton"]
    buttons[0].invoke()
    _pump(app, lambda: app.user_version == "premium")
    assert app.user_version == "premium"
    with gcs.db() as conn:
        assert gcs.get_user_by_name(conn, "ana")["email"] == "ana@example.com"
