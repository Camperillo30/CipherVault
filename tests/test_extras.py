"""Pruebas de las funciones nuevas: precios, CSV, 2FA, kit de emergencia, auto-escritura y
Windows Hello (la parte que no depende del hardware)."""
import base64
import tkinter as tk

import pytest

import cv_extras as cvx
import Gestor_contrasenas_secure as gcs
from test_gui_smoke import PW, add, register_and_login, ui  # noqa: F401  (fixture)


# ── precios y planes ─────────────────────────────────────────
def test_planes_nuevos():
    assert set(gcs.PLANES) == {"premium_mensual", "premium_anual", "premium_vida"}
    assert {p["plan"] for p in gcs.PLANES.values()} == {"premium"}
    assert [gcs.PLANES[k]["meses"] for k in ("premium_mensual", "premium_anual", "premium_vida")] == [1, 12, 1200]
    assert [gcs.PLANES[k]["precio_cop"] for k in ("premium_mensual", "premium_anual", "premium_vida")] == \
        [9900, 89900, 149900]
    assert gcs.get_features("free")["max_passwords"] == 50
    # los códigos "basic" emitidos antes siguen siendo válidos
    assert "basic" in gcs.REDEEMABLE_PLANS and "premium" in gcs.REDEEMABLE_PLANS
    assert gcs.get_features("basic")["max_passwords"] == -1


# ── CSV ──────────────────────────────────────────────────────
CHROME = "name,url,username,password,note\nGitHub,https://github.com/login,ana,clave-1,\n" \
         ",https://www.facebook.com/,ana.fb,clave-2,nota fb\nsin,https://x.com,u,,\n"
BITWARDEN = ("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
             "Trabajo,,login,Slack,,,0,https://slack.com,ana,pw,JBSWY3DPEHPK3PXP\n"
             ",,note,Nota segura,secreto,,0,,,,\n")
LASTPASS = "url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,nota,Mi nota,,0\n" \
           "https://bancolombia.com,ana,pw,,,Bancolombia,Finanzas,0\n"
KEEPASS = '"Group","Title","Username","Password","URL","Notes","TOTP"\n"Root","Nequi","300","1234","","",""\n'


def test_csv_formatos():
    recs, skipped = cvx.parse_password_csv(CHROME)
    assert [r["service"] for r in recs] == ["GitHub", "facebook.com"] and skipped == 1
    recs, skipped = cvx.parse_password_csv(BITWARDEN)
    assert recs[0]["totp"] == "JBSWY3DPEHPK3PXP" and recs[0]["category"] == "Trabajo" and skipped == 1
    recs, skipped = cvx.parse_password_csv(LASTPASS)
    assert recs[0]["service"] == "Bancolombia" and skipped == 1
    recs, _ = cvx.parse_password_csv(KEEPASS)
    assert recs[0]["category"] == "General" and recs[0]["service"] == "Nequi"
    recs, _ = cvx.parse_password_csv("name;url;username;password\nA;;u;p\n")
    assert recs[0]["password"] == "p"
    with pytest.raises(ValueError):
        cvx.parse_password_csv("a,b\n1,2\n")


def test_csv_ida_y_vuelta():
    recs, _ = cvx.parse_password_csv(CHROME)
    again, _ = cvx.parse_password_csv(cvx.records_to_csv(recs))
    assert [(r["service"], r["username"], r["password"]) for r in again] == \
        [(r["service"], r["username"], r["password"]) for r in recs]
    assert cvx.decode_csv_bytes("ñandú,é".encode("cp1252")) == "ñandú,é"
    assert cvx.decode_csv_bytes("\ufeffname".encode("utf-8")) == "name"


# ── 2FA ──────────────────────────────────────────────────────
def test_totp_rfc6238():
    secret = base64.b32encode(b"12345678901234567890").decode()
    cfg = cvx.parse_totp(f"otpauth://totp/Ej:ana?secret={secret}&digits=8&issuer=Ej")
    assert cvx.totp_code(cfg, 59)[0] == "94287082"
    assert cvx.totp_code(cfg, 1111111109)[0] == "07081804"
    assert cvx.totp_code(cfg, 2000000000)[0] == "69279037"
    assert cvx.totp_code("JBSW Y3DP EHPK 3PXP", 0) == ("282760", 30)
    for bad in ("", "1234", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "JBSWY3DP"):
        with pytest.raises(ValueError):
            cvx.parse_totp(bad)


# ── kit de emergencia ───────────────────────────────────────
def test_kit_pdf_no_incluye_contrasenas():
    pdf = cvx.build_emergency_kit_pdf("ana", "ana@example.com", r"C:\datos", "s@x.com", "3.1.0")
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    assert b"ana@example.com" in pdf and b"Kit de emergencia" in pdf


# ── auto-escritura ──────────────────────────────────────────
def test_match_entries():
    entries = [{"id": 1, "service": "Facebook", "url": ""},
               {"id": 2, "service": "Correo", "url": "https://mail.google.com"},
               {"id": 3, "service": "Bancolombia", "url": "https://www.bancolombia.com"},
               {"id": 4, "service": "GitHub", "url": "https://github.com"}]
    ids = lambda t: [e["id"] for e in cvx.match_entries(t, entries)]  # noqa: E731
    assert ids("Facebook - Inicia sesión - Google Chrome") == [1]
    assert ids("Bancolombia Personas - Microsoft Edge") == [3]
    assert ids("Sign in to GitHub · GitHub — Mozilla Firefox") == [4]
    assert ids("Nueva pestaña - Google Chrome") == []          # 'google' solo no basta
    assert ids("") == []
    # sin importar mayúsculas, tildes ni espacios
    assert ids("MercadoLibre - Google Chrome") == []
    entries.append({"id": 5, "service": "Mercado Libre", "url": ""})
    assert ids("MercadoLibre Colombia - Google Chrome") == [5]


def test_match_entries_por_direccion():
    entries = [{"id": 1, "service": "Facebook", "url": ""},
               {"id": 2, "service": "Correo", "url": "https://mail.google.com"},
               {"id": 3, "service": "Banco", "url": "https://www.bancolombia.com.co/personas"},
               {"id": 4, "service": "GitHub", "url": "https://github.com"},
               {"id": 5, "service": "Mercado Libre", "url": ""},
               {"id": 6, "service": "netflix.com", "url": ""},
               {"id": 7, "service": "Google Drive", "url": "https://drive.google.com"}]
    ids = lambda u: [e["id"] for e in cvx.match_entries_by_url(u, entries)]  # noqa: E731
    # el título ya no importa: basta la dirección
    assert ids("https://www.facebook.com/login.php") == [1]
    assert ids("m.facebook.com") == [1]
    assert ids("https://svpersonas.apps.bancolombia.com.co/autenticacion") == [3]
    assert ids("github.com/login") == [4]
    assert ids("https://www.mercadolibre.com.co/") == [5]
    assert ids("https://www.netflix.com/co/login") == [6]
    assert ids("https://mail.google.com/mail/u/0/") == [2, 7]          # host exacto primero
    # página falsa con el nombre en la ruta o en otro dominio: no coincide
    assert ids("https://facebook-login.example.com/facebook.com") == []
    assert ids("https://bancolombia.com.co.evil.net/") == []
    # texto de búsqueda o páginas internas del navegador
    assert ids("facebook login") == []
    assert ids("chrome://newtab") == []
    assert ids("") == []


def test_registrable_domain():
    assert cvx.registrable_domain("mail.google.com") == "google.com"
    assert cvx.registrable_domain("svp.bancolombia.com.co") == "bancolombia.com.co"
    assert cvx.registrable_domain("github.com") == "github.com"
    assert cvx.registrable_domain("www.gov.co") == "www.gov.co"


def test_autoescritura_desde_la_app(ui, monkeypatch):
    app = ui
    typed = []
    monkeypatch.setattr(cvx, "type_login", lambda u, p, enter=False: typed.append((u, p, enter)))
    monkeypatch.setattr(cvx, "focus_window", lambda hwnd: True)
    toasts = []
    monkeypatch.setattr(app, "_toast", lambda msg, seconds=4: toasts.append(msg))
    app._on_autotype(1, "GitHub - Google Chrome")
    assert toasts and "bloqueado" in toasts[-1]                 # sin sesión: no escribe nada
    register_and_login(app)
    add(app, "GitHub", "ana@git", "Zq9#mLp2$vXr8&Kd")
    app._on_autotype(1, "Sign in to GitHub · GitHub - Google Chrome")
    for _ in range(30):
        app.root.update(); app.root.after(20); app.root.update_idletasks()
        if typed:
            break
        import time; time.sleep(0.05)
    assert typed == [("ana@git", "Zq9#mLp2$vXr8&Kd", False)]
    app._on_autotype(1, "Netflix - Google Chrome")
    assert "No hay ninguna contraseña" in toasts[-1]

    # En un navegador manda la DIRECCIÓN: el título falso no basta y la página real sí.
    typed.clear()
    monkeypatch.setattr(cvx, "is_browser_window", lambda h: True)
    monkeypatch.setattr(cvx, "browser_url", lambda h: "https://github-login.example.net/session")
    app._on_autotype(1, "Sign in to GitHub · GitHub - Google Chrome")
    assert "github-login.example.net" in toasts[-1] and not typed
    monkeypatch.setattr(cvx, "browser_url", lambda h: "github.com/login")
    app._on_autotype(1, "Iniciar sesión - Google Chrome")       # título sin el nombre
    for _ in range(30):
        app.root.update(); app.root.after(20); app.root.update_idletasks()
        if typed:
            break
        import time; time.sleep(0.05)
    assert typed == [("ana@git", "Zq9#mLp2$vXr8&Kd", False)]


# ── importar CSV y 2FA en la interfaz ────────────────────────
def test_importar_csv_y_codigo_2fa(ui, monkeypatch, tmp_path):
    app = ui
    register_and_login(app)
    csv_file = tmp_path / "chrome.csv"
    csv_file.write_text(BITWARDEN, encoding="utf-8")
    app._import_vault(str(csv_file))
    assert any("Importadas: 1" in m for _, _, m in app.calls)
    assert not csv_file.exists()                               # se ofreció borrarlo y se aceptó
    with gcs.db() as conn:
        row = conn.execute("SELECT service, url, totp FROM passwords").fetchone()
    assert all(str(v).startswith(gcs.ENC_PREFIX) for v in row)  # todo cifrado
    app.selected_password_id = 1
    data = app._get_pwd_data()
    assert data["url"] == "https://slack.com" and data["totp"] == "JBSWY3DPEHPK3PXP"
    app.answers[:] = [PW]
    app._show_pwd_details(); app.root.update()
    for child in app.root.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.destroy()

    # exportar CSV (plan con exportación) y cambiar la contraseña maestra conserva url y 2FA
    monkeypatch.setattr(gcs, "get_features", lambda v: dict(gcs.VERSIONS["premium"]))
    out = tmp_path / "salida.csv"
    monkeypatch.setattr(gcs.filedialog, "asksaveasfilename", lambda **k: str(out))
    app.answers[:] = [PW]
    app.choices[:] = ["csv"]
    app._export_vault()
    assert "JBSWY3DPEHPK3PXP" in out.read_text(encoding="utf-8-sig")
    app.answers[:] = [PW, "Otra-Contraseña-Nueva-456", "Otra-Contraseña-Nueva-456"]
    app._change_master_password()
    data = app._get_pwd_data()
    assert data["url"] == "https://slack.com" and data["totp"] == "JBSWY3DPEHPK3PXP"


def test_clave_2fa_invalida_no_se_guarda(ui):
    app = ui
    register_and_login(app)
    app._show_add_form()
    app.add_service.set("X"); app.add_uname.set("u"); app.add_pwd.set("pw-larga-123")
    app.add_totp.set("no-es-base32!")
    app._save_password()
    assert app.calls[-1][1] == "Clave 2FA no válida"
    assert app._count_passwords() == 0


def test_kit_al_registrarse(ui, monkeypatch, tmp_path):
    app = ui
    target = tmp_path / "kit.pdf"
    monkeypatch.setattr(gcs.filedialog, "asksaveasfilename", lambda **k: str(target))
    register_and_login(app)
    assert target.exists() and target.read_bytes().startswith(b"%PDF")


# ── Windows Hello (lógica de claves, sin hardware) ──────────
def test_hello_envolver_y_desenvolver():
    key = b"k" * 32
    signature = b"firma-determinista" * 10
    wrapped = cvx.hello_wrap_key(key, signature)
    assert cvx.hello_unwrap_key(wrapped, signature) == key
    with pytest.raises(cvx.HelloError):
        cvx.hello_unwrap_key(wrapped, b"otra firma")


def test_login_con_windows_hello(ui, monkeypatch):
    app = ui
    register_and_login(app)
    signature = b"S" * 256
    monkeypatch.setattr(cvx, "hello_available", lambda: True)
    monkeypatch.setattr(cvx, "hello_sign", lambda user, challenge, create=False: signature)
    monkeypatch.setattr(gcs, "IS_WINDOWS", True)
    monkeypatch.setattr(cvx, "dpapi_protect", lambda b: b)     # DPAPI solo existe en Windows real
    monkeypatch.setattr(cvx, "dpapi_unprotect", lambda b: b)
    app.answers[:] = [PW]
    app._enable_hello()
    for _ in range(40):
        app.root.update()
        with gcs.db() as conn:
            if gcs.get_user_by_name(conn, "ana").get("hello_wrapped"):
                break
        import time; time.sleep(0.05)
    assert app._hello_users() == ["ana"]
    app._logout()
    app.entry_user.delete(0, "end")
    app._login_hello()
    for _ in range(40):
        app.root.update()
        if app.current_user:
            break
        import time; time.sleep(0.05)
    assert app.current_user and app.current_user["username"] == "ana"
    # con otra firma (otro equipo / clave de Hello distinta) no entra
    app._logout()
    monkeypatch.setattr(cvx, "hello_sign", lambda user, challenge, create=False: b"X" * 256)
    app._login_hello()
    for _ in range(20):
        app.root.update(); import time; time.sleep(0.05)
    assert app.current_user is None
    # cambiar la contraseña maestra desactiva Hello
    app.entry_user.insert(0, "ana"); app.entry_pass.insert(0, PW); app._login()
    app.answers[:] = [PW, "Otra-Contraseña-Nueva-456", "Otra-Contraseña-Nueva-456"]
    app._change_master_password()
    assert app._hello_users() == []


def test_elegir_paquete_de_equipo(ui, monkeypatch):
    app = ui
    register_and_login(app)
    opened = []
    monkeypatch.setattr(gcs.WompiHelper, "open_checkout", staticmethod(lambda key: opened.append(key) or True))
    monkeypatch.setattr(gcs.WompiHelper, "has_link", staticmethod(lambda key: True))
    app.choices[:] = ["equipo_ilimitado"]
    app._choose_team_plan()
    app.root.update()
    assert opened == ["equipo_ilimitado"]
    for child in app.root.winfo_children():
        if isinstance(child, tk.Toplevel):
            child.destroy()


# ── verificación en dos pasos al iniciar sesión ──────────────
def test_totp_de_inicio_de_sesion():
    secret = cvx.new_login_secret()
    cfg = {"secret": secret, "digits": 6, "period": 30, "algorithm": "SHA1"}
    now = 1_800_000_000
    code, _ = cvx.totp_code(cfg, at=now)
    counter = cvx.verify_login_totp(secret, code, at=now)
    assert counter == now // 30
    assert cvx.verify_login_totp(secret, code, last_counter=counter, at=now) is None   # no se repite
    assert cvx.verify_login_totp(secret, code, at=now + 30) == counter                 # reloj desfasado
    assert cvx.verify_login_totp(secret, code, at=now + 120) is None
    assert cvx.verify_login_totp(secret, "12345", at=now) is None
    assert "secret=" + secret in cvx.login_totp_uri(secret, "ana@example.com")
    codes = cvx.new_backup_codes()
    assert len(set(codes)) == 8 and all(len(cvx.normalize_backup_code(c)) == 8 for c in codes)
    assert cvx.hash_backup_code(1, codes[0]) == cvx.hash_backup_code(1, codes[0].lower().replace("-", " "))
    m = cvx.qr_matrix(cvx.login_totp_uri(secret, "ana"))
    assert len(m) == len(m[0]) >= 21


def _login_with(app, monkeypatch, answer, pw=PW):
    monkeypatch.setattr(gcs.simpledialog, "askstring", lambda *a, **k: answer)
    if app.current_user is not None:
        app._logout()
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "ana")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, pw)
    app._login()
    return app.current_user is not None


def test_verificacion_en_dos_pasos_en_la_app(ui, monkeypatch):
    app = ui
    errors = []
    monkeypatch.setattr(gcs.messagebox, "showerror", lambda *a, **k: errors.append(a))
    monkeypatch.setattr(gcs.messagebox, "showinfo", lambda *a, **k: None)
    monkeypatch.setattr(gcs.messagebox, "showwarning", lambda *a, **k: None)
    register_and_login(app)
    monkeypatch.setattr(app, "_ask_master", lambda: True)
    shown = []
    monkeypatch.setattr(app, "_show_plans_screen", lambda: shown.append("planes"))

    # Plan gratis: no se puede activar.
    app.user_version = "free"
    app._enable_login_2fa()
    assert shown == ["planes"]

    # Premium: QR, código y códigos de respaldo.
    app.user_version = "premium"
    secret_holder = {}
    real_new = cvx.new_login_secret
    monkeypatch.setattr(cvx, "new_login_secret", lambda: secret_holder.setdefault("s", real_new()))
    captured = {}
    monkeypatch.setattr(app, "_show_backup_codes", lambda codes, first_time=False: captured.update(codes=codes))
    app._enable_login_2fa()
    app.root.update()
    page = [c for c in _walk(app.root) if isinstance(c, gcs.InlinePage)][-1]
    entries = [w for w in _walk(page) if isinstance(w, tk.ttk.Entry) and str(w.cget("state")) != "readonly"]
    cfg = {"secret": secret_holder["s"], "digits": 6, "period": 30, "algorithm": "SHA1"}
    code, _ = cvx.totp_code(cfg)
    entries[0].insert(0, code)
    entries[0].event_generate("<Return>")
    app.root.update()
    assert len(captured["codes"]) == 8
    with gcs.db() as conn:
        row = gcs.get_user_by_id(conn, app.current_user["id"])
    assert row["login_totp"].startswith("enc1:") and secret_holder["s"] not in row["login_totp"]

    # Inicio de sesión: sin código, código malo, código ya usado → no entra.
    assert not _login_with(app, monkeypatch, None)
    assert not _login_with(app, monkeypatch, "000000")
    assert not _login_with(app, monkeypatch, code)                 # ya se usó al activar
    # Código de respaldo: entra una vez.
    backup = captured["codes"][0]
    assert _login_with(app, monkeypatch, backup.lower())
    assert not _login_with(app, monkeypatch, backup)
    # Siguiente código TOTP válido: entra.
    import time as _t
    nxt, _ = cvx.totp_code(cfg, at=_t.time() + 30)
    assert _login_with(app, monkeypatch, nxt)


def _walk(w):
    for c in w.winfo_children():
        yield c
        yield from _walk(c)
