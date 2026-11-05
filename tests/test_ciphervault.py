import json
import os
import subprocess
import sys
import textwrap

from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet

import Gestor_contrasenas_secure as gcs
from conftest import ROOT, make_user

PW = "Contraseña-Larga-123"
LAM = gcs.LicenseActivationManager


# ───────────── autenticación y formatos de hash ─────────────
def test_v3_login_ok_y_mala(app):
    user = make_user(app)
    assert user["password_hash"].startswith("v3$")
    ok = gcs.authenticate(PW, user)
    assert ok.ok and ok.key and not ok.needs_upgrade
    assert not gcs.authenticate("otra-contraseña-larga", user).ok


@pytest.mark.parametrize("legacy", ["pbkdf2", "sha256"])
def test_formato_antiguo_se_verifica_y_pide_actualizar(app, legacy):
    user = make_user(app, legacy=legacy)
    res = gcs.authenticate(PW, user)
    assert res.ok and res.needs_upgrade and res.vault_salt
    assert not gcs.authenticate("mala-contraseña-larga", user).ok


def test_hash_corrupto_no_lanza(app):
    user = make_user(app)
    user["password_hash"] = "pbkdf2_sha256$abc"
    assert not gcs.authenticate(PW, user).ok
    user["password_hash"] = ""
    assert not gcs.authenticate(PW, user).ok


# ───────────── cifrado de metadatos ─────────────
def test_enc_dec_roundtrip_y_texto_plano():
    vault = Fernet(Fernet.generate_key())
    token = gcs.enc_text(vault, "mi nota ñ")
    assert token.startswith("enc1:") and "mi nota" not in token
    assert gcs.dec_text(vault, token) == "mi nota ñ"
    assert gcs.dec_text(vault, "plano") == "plano"
    assert gcs.dec_text(vault, None) == ""
    other = Fernet(Fernet.generate_key())
    assert gcs.dec_text(other, token) == "⚠ ilegible"


# ───────────── migración ─────────────
def _insert_pw(user_id, service, username, enc, notes):
    with gcs.db() as conn:
        conn.execute("INSERT INTO passwords(user_id,service,username,password_encrypted,strength,notes) "
                     "VALUES(?,?,?,?,?,?)", (user_id, service, username, enc, "Fuerte", notes))


def test_migracion_cifra_plano_y_actualiza_login(app):
    user = make_user(app, legacy="pbkdf2")
    auth = gcs.authenticate(PW, user)
    vault = gcs._fernet_from_key(auth.key)
    _insert_pw(user["id"], "GitHub", "ana", "secreto-plano", "nota")
    changed, unreadable = app._migrate_security_material(user, auth, vault)
    assert changed and unreadable == 0
    with gcs.db() as conn:
        u = gcs.get_user_by_id(conn, user["id"])
        row = conn.execute("SELECT service,username,password_encrypted,notes FROM passwords").fetchone()
    assert u["password_hash"].startswith("v3$") and u["vault_salt"] == auth.vault_salt
    assert row[0].startswith("enc1:") and row[1].startswith("enc1:") and row[3].startswith("enc1:")
    assert vault.decrypt(row[2].encode()) == b"secreto-plano"
    # el siguiente login ya es v3 y abre la misma bóveda
    again = gcs.authenticate(PW, u)
    assert again.ok and not again.needs_upgrade and again.key == auth.key


def test_migracion_no_toca_tokens_de_otra_clave(app):
    user = make_user(app, legacy="sha256")
    auth = gcs.authenticate(PW, user)
    vault = gcs._fernet_from_key(auth.key)
    foreign = Fernet(Fernet.generate_key()).encrypt(b"ajena").decode()
    _insert_pw(user["id"], "X", "u", foreign, None)
    changed, unreadable = app._migrate_security_material(user, auth, vault)
    assert unreadable == 1
    with gcs.db() as conn:
        assert conn.execute("SELECT password_encrypted FROM passwords").fetchone()[0] == foreign


# ───────────── sin período de prueba ─────────────
def test_sin_prueba_todo_es_gratis(app):
    assert "trial" not in gcs.VERSIONS
    app.is_developer = False
    assert app._initial_version() == "free"
    # una cuenta vieja guardada como "trial" queda en el plan gratis
    assert gcs.compute_effective_version(make_user(app, version="trial"))[0] == "free"
    free = gcs.get_features("free")
    assert not free["security_analysis"] and not free["categories"] and not free["totp"]
    assert free["max_passwords"] == gcs.FREE_MAX_PASSWORDS


def test_equipo_sale_mas_barato_que_premium(app):
    premium = gcs.PLANES["premium_mensual"]["precio_cop"]
    for plan in gcs.TEAM_PLANES.values():
        if plan["usuarios"]:
            assert plan["precio_cop"] < premium * plan["usuarios"]
            assert plan["ahorro_pct"] > 0


# ───────────── versión efectiva y sello ─────────────
def _license(app, user, plan="premium", days=20):
    with gcs.db() as conn:
        gcs.set_user_license(conn, user["username"], plan, datetime.now() + timedelta(days=days),
                             "REF1", "Wompi", "test", "1 mes")
        return gcs.get_user_by_id(conn, user["id"])


def test_licencia_valida(app):
    user = _license(app, make_user(app))
    assert gcs.compute_effective_version(user)[::2] == ("premium", "ok")


def test_editar_plan_a_mano_es_manipulacion(app):
    user = make_user(app)
    with gcs.db() as conn:
        conn.execute("UPDATE users SET version='premium', license_expiry='2099-01-01 00:00:00' WHERE id=?",
                     (user["id"],))
        user = gcs.get_user_by_id(conn, user["id"])
    assert gcs.compute_effective_version(user)[::2] == ("free", "tampered")


def test_extender_vencimiento_o_borrar_sello(app):
    user = _license(app, make_user(app))
    forged = dict(user, license_expiry="2099-01-01 00:00:00")
    assert gcs.compute_effective_version(forged)[2] == "tampered"
    forged = dict(user, license_seal=None)
    assert gcs.compute_effective_version(forged)[2] == "tampered"


def test_licencia_vencida(app):
    user = _license(app, make_user(app), days=-1)
    assert gcs.compute_effective_version(user)[::2] == ("free", "expired")


def test_is_developer_en_db_no_sirve_sin_maquina_autorizada(app):
    user = make_user(app)
    with gcs.db() as conn:
        conn.execute("UPDATE users SET is_developer=1, version='developer' WHERE id=?", (user["id"],))
        user = gcs.get_user_by_id(conn, user["id"])
    assert gcs.compute_effective_version(user)[0] == "free"


# ───────────── canje de códigos (servicio de Make simulado) ─────────────
CODE = "ABCD-EFGH-JKLM-NPQR"
SECRET = gcs.ACTIVATION_SECRET


class FakeMake:
    """Imita el escenario de Make: Data Store de códigos, un código = hasta 3 equipos, respuesta firmada."""

    def __init__(self):
        self.store = {}
        self.requests = []

    def add(self, email="ana@example.com", code=CODE, plan="basic", ref="WOMPI-1", meses="1", created=None):
        created = created or datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        self.store[LAM.code_hash(code, email)] = dict(plan=plan, reference=ref, meses=meses,
                                                     created_at=created, machines=[])

    def __call__(self, payload):
        self.requests.append(payload)
        rec = self.store.get(payload["code_hash"])
        if rec is None:
            return {"ok": False, "error": "invalid"}
        if payload["machine"] not in rec["machines"]:
            if len(rec["machines"]) >= gcs.MAX_DEVICES:
                return {"ok": False, "error": "used"}
            rec["machines"].append(payload["machine"])
        out = {"ok": True, **{k: rec[k] for k in ("plan", "reference", "meses", "created_at")}}
        out["sig"] = LAM.response_signature(payload["code_hash"], payload["machine"], payload["nonce"],
                                            rec["plan"], rec["reference"], rec["meses"], rec["created_at"], SECRET)
        return out


@pytest.fixture
def make(monkeypatch):
    server = FakeMake()
    monkeypatch.setattr(LAM, "_call_server", staticmethod(server))
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-A")
    return server


def test_normalizacion_y_hash():
    assert LAM.normalize_code("abcd-efgh jklm_npqr") == "ABCDEFGHJKLMNPQR"
    assert LAM.code_hash("abcd-efgh-jklm-npqr", " ANA@Example.com ") == LAM.code_hash(CODE, "ana@example.com")
    assert LAM.code_hash(CODE, "otra@example.com") != LAM.code_hash(CODE, "ana@example.com")


def test_canje_ok_y_no_se_envia_codigo_ni_email(app, make):
    make.add(meses="2")
    make_user(app)
    res = LAM.redeem(CODE.lower(), "ana", "ana@example.com")
    assert res["plan"] == "basic" and not res["already"]
    sent = json.dumps(make.requests)
    assert "ABCDEFGH" not in sent.upper() and "ana@example.com" not in sent
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
    assert gcs.compute_effective_version(user)[::2] == ("basic", "ok")
    exp = gcs._parse_datetime(user["license_expiry"])
    assert abs((exp - (datetime.now() + timedelta(days=60))).total_seconds()) < 120


def test_codigo_de_dueno_de_por_vida(app, make):
    make.add(plan="premium", meses="1200", ref="OWNER-1")
    make_user(app)
    res = LAM.redeem(CODE, "ana", "ana@example.com")
    assert res["plan"] == "premium" and res["meses"] == 1200
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
    assert gcs.compute_effective_version(user)[::2] == ("premium", "ok")
    exp = gcs._parse_datetime(user["license_expiry"])
    assert exp.year >= datetime.now().year + 90


def test_codigo_developer_firmado(app, make):
    make.add(plan="developer", meses="1200", ref="OWNER-DEV")
    make_user(app)
    res = LAM.redeem(CODE, "ana", "ana@example.com")
    assert res["plan"] == "developer"
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
        assert gcs.compute_effective_version(user)[::2] == ("developer", "ok")
        # editar la base de datos a mano (sin sello) NO da developer
        conn.execute("UPDATE users SET license_seal='x' WHERE id=?", (user["id"],))
        user = gcs.get_user_by_name(conn, "ana")
        assert gcs.compute_effective_version(user)[0] == "free"
        conn.execute("UPDATE users SET version='developer', license_seal=NULL WHERE id=?", (user["id"],))
        user = gcs.get_user_by_name(conn, "ana")
        assert gcs.compute_effective_version(user)[0] == "free"


def test_codigo_hasta_tres_equipos(app, make, monkeypatch):
    make.add()
    make_user(app)
    for pc in ("equipo-A", "equipo-B", "equipo-C"):                  # tres PC de la misma persona
        monkeypatch.setattr(gcs, "machine_id", lambda pc=pc: pc)
        LAM.redeem(CODE, "ana", "ana@example.com")
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-D")        # el cuarto se rechaza
    with pytest.raises(gcs.ActivationError, match="3 equipos"):
        LAM.redeem(CODE, "ana", "ana@example.com")
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-A")        # un equipo ya registrado puede repetir
    assert LAM.redeem(CODE, "ana", "ana@example.com")["already"]


def test_cada_equipo_necesita_su_propio_codigo(app, make, monkeypatch):
    make.add(code=CODE, ref="R-A")
    make.add(code="WXYZ-2345-6789-ABCD", ref="R-B")
    make_user(app)
    LAM.redeem(CODE, "ana", "ana@example.com")
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-B")
    assert LAM.redeem("WXYZ-2345-6789-ABCD", "ana", "ana@example.com")["plan"] == "basic"


def test_licencia_local_atada_al_equipo(app, make, monkeypatch):
    make.add()
    make_user(app)
    LAM.redeem(CODE, "ana", "ana@example.com")
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
    assert gcs.compute_effective_version(user)[2] == "ok"
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-B")      # base de datos copiada a otro PC
    assert gcs.compute_effective_version(user)[::2] == ("free", "tampered")


def test_codigo_con_otro_email_no_sirve(app, make):
    make.add()
    make_user(app, username="eve", email="eve@example.com")
    with pytest.raises(gcs.ActivationError, match="no es válido"):
        LAM.redeem(CODE, "eve", "eve@example.com")


def test_codigo_malo_o_corto(app, make):
    make.add()
    make_user(app)
    with pytest.raises(gcs.ActivationError):
        LAM.redeem("ZZZZ-ZZZZ-ZZZZ-ZZZZ", "ana", "ana@example.com")
    with pytest.raises(gcs.ActivationError):
        LAM.redeem("abc", "ana", "ana@example.com")
    # el código inválido se consulta 2 veces (con el correo y como código de equipo);
    # el código corto ni siquiera sale de la app
    assert len(make.requests) == 2


def test_respuesta_falsificada_o_reutilizada_se_rechaza(app, monkeypatch):
    make_user(app)
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-A")
    good = FakeMake()
    good.add()
    captured = {}

    def server(payload):
        captured["resp"], captured["payload"] = good(payload), payload
        return captured["resp"]
    monkeypatch.setattr(LAM, "_call_server", staticmethod(server))
    LAM.redeem(CODE, "ana", "ana@example.com")
    # 1) servidor falso sin el secreto
    monkeypatch.setattr(LAM, "_call_server", staticmethod(lambda p: {**captured["resp"], "sig": "0" * 64}))
    with pytest.raises(gcs.ActivationError, match="no es válida"):
        LAM.redeem(CODE, "ana", "ana@example.com")
    # 2) cambiar el plan en una respuesta legítima
    monkeypatch.setattr(LAM, "_call_server", staticmethod(lambda p: {**captured["resp"], "plan": "premium"}))
    with pytest.raises(gcs.ActivationError, match="no es válida"):
        LAM.redeem(CODE, "ana", "ana@example.com")
    # 3) repetir una respuesta vieja (nonce distinto) en otro intento
    monkeypatch.setattr(LAM, "_call_server", staticmethod(lambda p: captured["resp"]))
    with pytest.raises(gcs.ActivationError, match="no es válida"):
        LAM.redeem(CODE, "ana", "ana@example.com")


def test_pago_viejo_vencido_se_rechaza(app, make):
    old = (datetime.now() - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%S")
    make.add(created=old)
    make_user(app)
    with pytest.raises(gcs.ActivationError):
        LAM.redeem(CODE, "ana", "ana@example.com")
    with gcs.db() as conn:
        assert gcs.get_user_by_name(conn, "ana")["version"] == "free"


def test_pago_reciente_cuenta_desde_la_fecha_del_pago(app, make):
    make.add(created=(datetime.now() - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S"))
    make_user(app)
    res = LAM.redeem(CODE, "ana", "ana@example.com")
    assert abs((res["expiry"] - (datetime.now() + timedelta(days=20))).total_seconds()) < 120


def test_idempotente_por_referencia(app, make):
    make.add()
    make_user(app)
    first = LAM.redeem(CODE, "ana", "ana@example.com")
    second = LAM.redeem(CODE, "ana", "ana@example.com")
    assert second["already"] and second["expiry"] == first["expiry"]
    with gcs.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM license_activations").fetchone()[0] == 1


def test_renovaciones_se_acumulan(app, make):
    c2 = "WXYZ-2345-6789-ABCD"
    make.add(ref="R1")
    make.add(code=c2, ref="R2")
    make_user(app)
    a = LAM.redeem(CODE, "ana", "ana@example.com")
    b = LAM.redeem(c2, "ana", "ana@example.com")
    assert (b["expiry"] - a["expiry"]).days == 30


def test_plan_desconocido_o_sin_referencia(app, make):
    make.add(plan="oro")
    make.add(code="WXYZ-2345-6789-ABCD", ref="")
    make_user(app)
    with pytest.raises(gcs.ActivationError):
        LAM.redeem(CODE, "ana", "ana@example.com")
    with pytest.raises(gcs.ActivationError):
        LAM.redeem("WXYZ-2345-6789-ABCD", "ana", "ana@example.com")


class _Resp:
    def __init__(self, body): self.body = body
    def read(self, n=-1): return self.body
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_errores_de_red_y_respuestas_raras(monkeypatch):
    monkeypatch.setattr(gcs.urllib.request, "urlopen", lambda *a, **k: _Resp(b"Accepted"))
    with pytest.raises(gcs.ActivationError, match="inesperado"):
        LAM._call_server({})
    def boom(*a, **k): raise gcs.urllib.error.URLError("sin red")
    monkeypatch.setattr(gcs.urllib.request, "urlopen", boom)
    with pytest.raises(gcs.ActivationError, match="conexión"):
        LAM._call_server({})
    def http(*a, **k): raise gcs.urllib.error.HTTPError("https://x", 500, "err", {}, None)
    monkeypatch.setattr(gcs.urllib.request, "urlopen", http)
    with pytest.raises(gcs.ActivationError, match="500"):
        LAM._call_server({})
    monkeypatch.setattr(gcs.urllib.request, "urlopen", lambda *a, **k: _Resp(b'{"ok": true}'))
    assert LAM._call_server({"a": 1}) == {"ok": True}


def test_se_envia_post_json_sin_secreto(monkeypatch):
    seen = {}
    def fake(req, timeout=None):
        seen["req"] = req
        return _Resp(b"{}")
    monkeypatch.setattr(gcs.urllib.request, "urlopen", fake)
    LAM._call_server({"code_hash": "x"})
    assert seen["req"].get_method() == "POST" and seen["req"].full_url.startswith("https://")
    assert SECRET.encode() not in seen["req"].data


def test_url_no_https_o_sin_configurar(monkeypatch):
    monkeypatch.setattr(gcs, "ACTIVATION_URL", "http://example.com/x")
    with pytest.raises(gcs.ActivationError):
        LAM._call_server({})
    monkeypatch.setattr(gcs, "ACTIVATION_URL", "")
    with pytest.raises(gcs.ActivationError):
        LAM._call_server({})
    monkeypatch.setattr(gcs, "ACTIVATION_URL", "https://x.example")
    monkeypatch.setattr(gcs, "ACTIVATION_SECRET", "")
    with pytest.raises(gcs.ActivationError):
        LAM._call_server({})


def test_machine_id_estable_y_sin_datos_crudos():
    first = gcs.machine_id()
    assert first == gcs.machine_id() and len(first) == 32 and first.isalnum()


# ───────────── bloqueo persistente, email único ─────────────
def test_bloqueo_tras_5_fallos_persiste(app):
    for _ in range(4):
        app._register_failure("Ana")
    assert app._lock_remaining("ana") == 0
    app._register_failure("ana")
    assert 0 < app._lock_remaining("ANA") <= 31
    # otra "sesión" de la app sigue viendo el bloqueo
    other = gcs.CipherVaultApp.__new__(gcs.CipherVaultApp)
    assert other._lock_remaining("ana") > 0
    app._clear_failures("ana")
    assert app._lock_remaining("ana") == 0


def test_email_unico_en_la_base(app):
    import sqlite3
    make_user(app)
    with pytest.raises(sqlite3.IntegrityError):
        make_user(app, username="otra", email="ana@example.com")
    make_user(app, username="sin1", email="")
    make_user(app, username="sin2", email="")   # vacíos permitidos


# ───────────── fortaleza ─────────────
def test_fortaleza():
    assert gcs.evaluate_strength("password123")[0] != "Fuerte"
    assert gcs.evaluate_strength("abcdefghijkl")[1] <= 2
    weak = gcs.evaluate_strength("Ab1!")[1]
    strong = gcs.evaluate_strength("x7#Qm!9vLp2$Zr8&Kd")[1]
    assert strong > weak
    base = "abcdefghijklmnop"
    scores = {s: gcs.evaluate_strength(base + s)[1] for s in "+-/;=[]_`~"}
    assert all(v >= gcs.evaluate_strength(base)[1] + 1 for v in scores.values()), scores


# ───────────── configuración del .exe ─────────────
def test_exe_ignora_entorno_y_desactiva_dev(tmp_path):
    meipass = tmp_path / "mei"
    meipass.mkdir()
    (meipass / "desktop_runtime_config.json").write_text(json.dumps({
        "CIPHERVAULT_ACTIVATION_URL": "https://embebida.example/hook",
        "CIPHERVAULT_ENABLE_DEV_TOOLS": "1",
        "CIPHERVAULT_DEV_PASSWORD": "filtrada"}))
    script = textwrap.dedent(f"""
        import sys, os
        sys.frozen = True; sys._MEIPASS = {str(meipass)!r}
        sys.path.insert(0, {str(ROOT)!r})
        os.environ["LOCALAPPDATA"] = {str(tmp_path / 'la')!r}
        import Gestor_contrasenas_secure as g
        print(g.ACTIVATION_URL, g.DeveloperLicenseManager.ENABLED,
              repr(g.DeveloperLicenseManager.DEV_PASSWORD), g.DeveloperLicenseManager.is_developer_machine())
    """)
    env = dict(os.environ, CIPHERVAULT_ACTIVATION_URL="https://atacante.example/x",
               CIPHERVAULT_ENABLE_DEV_TOOLS="1", CIPHERVAULT_DEV_HOSTNAMES=__import__("platform").node(),
               CIPHERVAULT_DEV_PASSWORD="malo")
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env,
                         cwd=str(tmp_path), timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["https://embebida.example/hook", "False", "''", "False"]


def test_dev_requiere_activacion_explicita(tmp_path):
    script = textwrap.dedent(f"""
        import sys, os
        sys.path.insert(0, {str(ROOT)!r})
        os.environ["LOCALAPPDATA"] = {str(tmp_path / 'la')!r}
        import Gestor_contrasenas_secure as g
        print(g.DeveloperLicenseManager.ENABLED, g.DeveloperLicenseManager.is_developer_machine())
    """)
    env = {k: v for k, v in os.environ.items() if not k.startswith("CIPHERVAULT_")}
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env,
                         cwd=str(tmp_path), timeout=60)
    assert out.stdout.split() == ["False", "False"], out.stderr


# ───────────── auto-reparación de la licencia (14-oct-2026) ─────────────
def _damage_seal(username="ana"):
    with gcs.db() as conn:
        conn.execute("UPDATE users SET license_seal='dañado' WHERE username=?", (username,))
        return gcs.get_user_by_name(conn, username)


def test_reingresar_codigo_repara_sello_danado(app, make):
    make.add(plan="developer", meses="1200", ref="OWNER-DEV")
    make_user(app)
    LAM.redeem(CODE, "ana", "ana@example.com")
    user = _damage_seal()
    assert gcs.compute_effective_version(user)[2] == "tampered"
    res = LAM.redeem(CODE, "ana", "ana@example.com")
    assert res["already"] and res.get("repaired")
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
        assert conn.execute("SELECT COUNT(*) FROM license_activations").fetchone()[0] == 1
    assert gcs.compute_effective_version(user)[::2] == ("developer", "ok")


def test_reparacion_automatica_al_iniciar_sesion(app, make):
    make.add(plan="developer", meses="1200", ref="OWNER-DEV")
    make_user(app)
    LAM.redeem(CODE, "ana", "ana@example.com")
    user = _damage_seal()
    assert user["activation_hash"] == LAM.code_hash(CODE, "ana@example.com")
    sent_before = len(make.requests)
    res = LAM.repair(user["id"])
    assert res and res["plan"] == "developer"
    assert make.requests[-1]["code_hash"] == user["activation_hash"] and len(make.requests) == sent_before + 1
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
    assert gcs.compute_effective_version(user)[::2] == ("developer", "ok")
    assert LAM.repair(user["id"]) is None          # ya está bien: no consulta de nuevo
    assert len(make.requests) == sent_before + 1


def test_reparacion_no_sirve_en_otro_equipo(app, make, monkeypatch):
    make.add(plan="premium", meses="1", ref="R1")
    make_user(app)
    LAM.redeem(CODE, "ana", "ana@example.com")
    make.store[next(iter(make.store))]["machines"] += ["equipo-X", "equipo-Y"]   # ya tiene sus 3 equipos
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-B")   # base copiada a un cuarto PC
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
    assert gcs.compute_effective_version(user)[2] == "tampered"
    with pytest.raises(gcs.ActivationError, match="3 equipos"):
        LAM.repair(user["id"])
    with gcs.db() as conn:
        user = gcs.get_user_by_name(conn, "ana")
    assert gcs.compute_effective_version(user)[0] == "free"


def test_reparacion_sin_codigo_guardado_no_aplica(app, make):
    user = make_user(app)
    assert LAM.repair(user["id"]) is None
    assert make.requests == []


def test_codigo_de_equipo_no_atado_al_correo(app, make, monkeypatch):
    """Los paquetes de Equipo los paga la empresa: el código sirve en la cuenta de cualquier empleado."""
    make.add(email="", code="TEAM-2345-6789-ABCD", plan="equipo", ref="5fZGtj-PAGO-1")
    make_user(app)
    make_user(app, username="beto", email="beto@empresa.com")
    assert LAM.redeem("TEAM-2345-6789-ABCD", "ana", "ana@example.com")["plan"] == "equipo"
    monkeypatch.setattr(gcs, "machine_id", lambda: "equipo-B")
    assert LAM.redeem("TEAM-2345-6789-ABCD", "beto", "beto@empresa.com")["plan"] == "equipo"
    # un código inexistente sigue dando "no es válido" (se probó con y sin correo)
    sent = len(make.requests)
    with pytest.raises(gcs.ActivationError, match="no es válido"):
        LAM.redeem("ZZZZ-ZZZZ-ZZZZ-ZZZZ", "ana", "ana@example.com")
    assert len(make.requests) == sent + 2


def test_paquetes_de_equipo():
    assert list(gcs.TEAM_PLANES) == ["equipo_3", "equipo_5", "equipo_10", "equipo_ilimitado"]
    assert [p["precio_cop"] for p in gcs.TEAM_PLANES.values()] == [24900, 37900, 64900, 199900]
    assert [p["usuarios"] for p in gcs.TEAM_PLANES.values()] == [3, 5, 10, None]
    assert all(p["plan"] == "equipo" for p in gcs.TEAM_PLANES.values())
