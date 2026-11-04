"""Configuración común de las pruebas.

El módulo principal lee variables de entorno y crea carpetas al importarse, así que
aquí se aísla todo ANTES del import: LOCALAPPDATA temporal, sin modo developer y con
una URL y secreto de activación de prueba. Cada prueba además usa su propia base de datos.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_TMP = tempfile.mkdtemp(prefix="cv_tests_")
os.environ["LOCALAPPDATA"] = _TMP
os.environ["CIPHERVAULT_ENABLE_DEV_TOOLS"] = "0"
os.environ["CIPHERVAULT_ACTIVATION_URL"] = "https://example.invalid/hook"
os.environ["CIPHERVAULT_ACTIVATION_SECRET"] = "secreto-de-prueba"
os.chdir(_TMP)                       # que no lea un .env ni un JSON de la carpeta del proyecto
sys.path.insert(0, str(ROOT))

import Gestor_contrasenas_secure as gcs  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    """Base de datos, archivo de instalación y registro propios de cada prueba,
    y PBKDF2 con pocas iteraciones para que la suite sea rápida."""
    monkeypatch.setattr(gcs, "DATA_PATH", tmp_path)
    monkeypatch.setattr(gcs, "DB_FILE", str(tmp_path / "passwords.db"))
    monkeypatch.setattr(gcs, "INSTALL_FILE", str(tmp_path / "install_date.txt"))
    monkeypatch.setattr(gcs, "VAULT_KDF_ITERATIONS", 1000)
    return tmp_path


@pytest.fixture
def app(isolated_data):
    """Instancia mínima de CipherVaultApp (sin ventana) con la base de datos creada."""
    instance = gcs.CipherVaultApp.__new__(gcs.CipherVaultApp)
    instance.current_user = None
    instance._ensure_db()
    return instance


def make_user(app, username="ana", email="ana@example.com", password="Contraseña-Larga-123",
              version="free", legacy=None):
    """Crea un usuario. legacy='pbkdf2' | 'sha256' crea el formato antiguo del hash de login."""
    import hashlib
    vault_salt = gcs._b64(os.urandom(16))
    if legacy == "pbkdf2":
        salt = os.urandom(16)
        raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)
        stored = f"pbkdf2_sha256$1000${gcs._b64(salt)}${gcs._b64(raw)}"
        vault_salt = None
    elif legacy == "sha256":
        stored = hashlib.sha256(password.encode()).hexdigest()
        vault_salt = None
    else:
        stored = gcs._hash_login_password(password, vault_salt)
    with gcs.db() as conn:
        conn.execute("INSERT INTO users(username,email,password_hash,master_key,vault_salt,version) "
                     "VALUES(?,?,?,?,?,?)",
                     (username, email, stored, "x", vault_salt, version))
        return gcs.get_user_by_name(conn, username)
