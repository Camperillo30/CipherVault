"""Sincronización por carpeta (dos "equipos" = dos bases de datos) y bóveda de equipo."""
import time
from pathlib import Path

import pytest

import cv_sync as cvs
import Gestor_contrasenas_secure as gcs
from test_gui_smoke import PW, add, register_and_login, ui  # noqa: F401  (fixture)


# ── módulo cv_sync ───────────────────────────────────────────
def test_merge_gana_lo_mas_reciente_y_las_lapidas():
    a = [{"uid": "1", "service": "viejo", "updated_at": "2026-01-01 00:00:00"},
         {"uid": "2", "service": "B", "updated_at": "2026-01-01 00:00:00"}]
    b = [{"uid": "1", "service": "nuevo", "updated_at": "2026-02-01 00:00:00"}]
    entries, tombs = cvs.merge(a, {}, b, {"2": "2026-03-01 00:00:00"})
    assert [e["service"] for e in entries] == ["nuevo"] and "2" in tombs
    # una edición posterior a la lápida "revive" la entrada
    entries, _ = cvs.merge([{"uid": "2", "service": "B", "updated_at": "2026-04-01 00:00:00"}], {}, [],
                           {"2": "2026-03-01 00:00:00"})
    assert [e["uid"] for e in entries] == ["2"]


def test_archivo_sync_cifrado_y_copias_en_conflicto(tmp_path):
    header = cvs.new_sync_header(1000)
    key = cvs.derive_sync_key("clave", header["salt"], 1000)
    path = tmp_path / cvs.sync_file_name("ana")
    cvs.sync_folder(path, key, header, [{"uid": "a", "service": "Gmail", "password": "x",
                                         "updated_at": cvs.utc_now()}], {}, "PC1")
    assert "Gmail" not in path.read_text(encoding="utf-8")
    conflict = tmp_path / (path.stem + "-PORTATIL" + path.suffix)
    cvs.write_sync(conflict, key, header, [{"uid": "b", "service": "Banco", "password": "y",
                                            "updated_at": cvs.utc_now()}], {}, "PC2")
    entries, _ = cvs.sync_folder(path, key, header, [], {}, "PC1")
    assert sorted(e["service"] for e in entries) == ["Banco", "Gmail"]
    assert not conflict.exists()
    with pytest.raises(cvs.SyncError):
        cvs.read_sync(path, cvs.derive_sync_key("otra", header["salt"], 1000))


def test_equipo_roles_e_invitaciones(tmp_path):
    a_priv, a_pub = cvs.new_member_keypair()
    b_priv, b_pub = cvs.new_member_keypair()
    team = cvs.TeamVault.create(tmp_path, "Mi Pyme", a_pub, "Ana", "ana@x.com")
    team.upsert({"service": "Banco empresa", "username": "pyme", "password": "123"})
    team.save_merged(a_priv)
    with pytest.raises(cvs.SyncError):
        cvs.TeamVault.open(team.path, b_priv)                    # aún no es miembro
    with pytest.raises(cvs.SyncError):
        team.add_member("CVM1-MAL", "Beto", "", "lector")
    team.add_member(cvs.member_code(b_pub), "Beto", "b@x.com", "lector")
    team.save_merged(a_priv)
    beto = cvs.TeamVault.open(team.path, b_priv)
    assert beto.my_role == "lector" and beto.entries[0]["password"] == "123"
    with pytest.raises(cvs.SyncError):
        beto.upsert({"service": "x", "password": "y"})
    assert "Banco empresa" not in team.path.read_text(encoding="utf-8")
    # quitarlo rota la clave: ya no abre el archivo
    team = cvs.TeamVault.open(team.path, a_priv)
    team.remove_member(cvs.fingerprint(b_pub))
    team.save_merged(a_priv)
    with pytest.raises(cvs.SyncError):
        cvs.TeamVault.open(team.path, b_priv)
    assert cvs.TeamVault.open(team.path, a_priv).key_version == 2


def test_dos_editores_guardando_a_la_vez(tmp_path):
    a_priv, a_pub = cvs.new_member_keypair()
    b_priv, b_pub = cvs.new_member_keypair()
    team = cvs.TeamVault.create(tmp_path, "Equipo", a_pub, "Ana", "")
    team.add_member(cvs.member_code(b_pub), "Beto", "", "editor")
    team.save_merged(a_priv)
    ana, beto = cvs.TeamVault.open(team.path, a_priv), cvs.TeamVault.open(team.path, b_priv)
    ana.upsert({"service": "A", "password": "1"}); ana.save_merged(a_priv)
    beto.upsert({"service": "B", "password": "2"}); beto.save_merged(b_priv)   # no pisa lo de Ana
    assert sorted(e["service"] for e in cvs.TeamVault.open(team.path, a_priv).entries) == ["A", "B"]


# ── integración con la app ───────────────────────────────────
def _wait(app, cond, seconds=5):
    end = time.time() + seconds
    while time.time() < end:
        app.root.update()
        if cond():
            return True
        time.sleep(0.03)
    return False


def _as_premium(app, monkeypatch, plan="premium"):
    app.user_version = plan


def test_sincronizar_dos_equipos(ui, monkeypatch, tmp_path):
    app = ui
    folder = tmp_path / "OneDrive"
    folder.mkdir()
    monkeypatch.setattr(gcs.filedialog, "askdirectory", lambda **k: str(folder))
    db1, db2 = str(tmp_path / "pc1.db"), str(tmp_path / "pc2.db")

    # PC 1
    monkeypatch.setattr(gcs, "DB_FILE", db1); app._ensure_db()
    register_and_login(app)
    _as_premium(app, monkeypatch)
    add(app, "GitHub", "ana@git", "clave-github-1")
    app.answers[:] = [PW]
    app._enable_sync()
    assert _wait(app, lambda: not getattr(app, "_sync_running", False) and list(folder.glob("*.cvsync")))
    app._logout()

    # PC 2: misma cuenta y contraseña maestra, otra base de datos
    monkeypatch.setattr(gcs, "DB_FILE", db2); app._ensure_db()
    register_and_login(app)
    _as_premium(app, monkeypatch)
    app.answers[:] = [PW]
    app._enable_sync()
    assert _wait(app, lambda: not getattr(app, "_sync_running", False) and app._count_passwords() == 1)
    add(app, "Banco", "ana", "clave-banco-2")
    app.selected_password_id = 1
    app._delete_password()                      # borra GitHub en el PC 2
    app._sync_now()
    assert _wait(app, lambda: not getattr(app, "_sync_running", False))
    app._logout()

    # PC 1 recibe el alta y el borrado
    monkeypatch.setattr(gcs, "DB_FILE", db1)
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "ana")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, PW)
    app._login()
    _as_premium(app, monkeypatch)
    app._sync_now()
    assert _wait(app, lambda: not getattr(app, "_sync_running", False))
    with gcs.db() as conn:
        services = [gcs.dec_text(app.current_user["vault"], r[0])
                    for r in conn.execute("SELECT service FROM passwords")]
    assert services == ["Banco"]


def test_boveda_de_equipo_en_la_app(ui, monkeypatch, tmp_path):
    app = ui
    shared = tmp_path / "Compartida"
    shared.mkdir()
    db1, db2 = str(tmp_path / "jefe.db"), str(tmp_path / "empleado.db")

    # empleado: obtiene su código
    monkeypatch.setattr(gcs, "DB_FILE", db2); app._ensure_db()
    register_and_login(app, user="beto", email="beto@x.com")
    app.user_version = "equipo"
    app._tab_team(); app.root.update()
    beto_code = cvs.member_code(app._team_keys()[1])
    app._logout()

    # administrador: crea el equipo, agrega una entrada y al empleado
    monkeypatch.setattr(gcs, "DB_FILE", db1); app._ensure_db()
    register_and_login(app)
    app.user_version = "equipo"
    monkeypatch.setattr(gcs.filedialog, "askdirectory", lambda **k: str(shared))
    app.answers[:] = ["Mi Pyme"]
    app._team_create()
    team = app._open_team()
    team.upsert({"service": "Banco empresa", "username": "pyme", "password": "123", "url": "https://banco.com"})
    app._team_save(team)
    team.add_member(beto_code, "Beto", "beto@x.com", "lector")
    app._team_save(team)
    app._tab_team(); app.root.update()
    assert app.team_tree.get_children()
    app._logout()

    # empleado: se une y ve la entrada; la auto-escritura también la encuentra
    monkeypatch.setattr(gcs, "DB_FILE", db2)
    app.entry_user.delete(0, "end"); app.entry_user.insert(0, "beto")
    app.entry_pass.delete(0, "end"); app.entry_pass.insert(0, PW)
    app._login()
    app.user_version = "equipo"
    team_file = next(shared.glob("*.cvteam"))
    monkeypatch.setattr(gcs.filedialog, "askopenfilename", lambda **k: str(team_file))
    app._team_join()
    assert app._team and app._team.my_role == "lector"
    ids = [e["id"] for e in app._autotype_entries()]
    assert any(str(i).startswith("t:") for i in ids)
    assert app._credentials_for(ids[0])[1] == "123"


def test_registro_de_actividad_e_informe(tmp_path):
    a_priv, a_pub = cvs.new_member_keypair()
    b_priv, b_pub = cvs.new_member_keypair()
    team = cvs.TeamVault.create(tmp_path, "Pyme", a_pub, "Ana", "")
    team.add_member(cvs.member_code(b_pub), "Beto", "", "editor")
    team.upsert({"service": "Banco", "password": "123"})
    team.save_merged(a_priv)
    beto = cvs.TeamVault.open(team.path, b_priv)
    entry = beto.upsert({"service": "Correo", "password": "123"})
    beto.log_copy(entry)
    beto.save_merged(b_priv)
    ana = cvs.TeamVault.open(team.path, a_priv)
    acciones = [(e["by_name"], e["action"], e["target"]) for e in ana.activity]
    assert ("Ana", "creó", "Banco") in acciones and ("Beto", "copió la contraseña de", "Correo") in acciones
    assert "Correo" not in team.path.read_text(encoding="utf-8")          # el registro va cifrado
    rep = cvs.security_report(ana.entries, lambda p: "DÉBIL" if len(p) < 8 else "FUERTE")
    assert rep["weak"] == ["Banco", "Correo"] and rep["reused"] == ["Banco", "Correo"] and rep["score"] == 0

