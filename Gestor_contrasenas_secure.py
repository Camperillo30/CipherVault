"""
CipherVault – Gestor de Contraseñas Seguras
Integración: Wompi (pagos) + Make (códigos de activación de un solo uso)

Flujo de licencias (v3, código de un solo uso por equipo):
  1. Usuario hace clic "Comprar" → la app abre el Payment Link fijo de Wompi
  2. Usuario paga → Wompi envía el webhook a Make
  3. Make filtra pagos APPROVED, genera un CÓDIGO ALEATORIO, lo envía por correo
     al customer_email y guarda en un Data Store SOLO el hash del código
     (nunca el email ni el código en claro). Ver GUIA_ACTIVACION_MAKE.md
  4. El usuario abre la app, inicia sesión y pega el código en "Activar licencia"
  5. La app envía a Make el hash (código + email) y el identificador del equipo.
     Make marca el código como USADO por ese equipo y devuelve el plan firmado;
     el mismo código en otro equipo se rechaza. La vigencia cuenta desde la
     FECHA DEL PAGO.

Configuración: toda la configuración sensible (links de Wompi, URL y secreto
de activación, precios) se carga en tiempo de ejecución desde `desktop_runtime_config.json`
(embebido en el .exe por build.ps1) o, solo en desarrollo, desde un `.env`.
En el .exe compilado NO se lee nada del disco ni del entorno, y el modo
desarrollador está desactivado por completo.

© 2026 S.C.A - CipherVault. Todos los derechos reservados.
Software con licencia comercial: queda prohibida su copia, distribución
o modificación sin autorización expresa del autor.
"""

import base64
import contextlib
import csv
import getpass
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import platform
import re
import secrets
import sqlite3
import string
import sys
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

from cryptography.fernet import Fernet, InvalidToken

import cv_extras as cvx
import cv_sync as cvs

# True dentro del .exe de PyInstaller. En ese caso la app NO confía en nada
# que el usuario pueda poner en disco o en el entorno (ver _lock_embedded_config).
IS_FROZEN = bool(getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", None))
IS_WINDOWS = os.name == "nt"

# ══════════════════════════════════════════════
#  CARGA DE CONFIGURACIÓN EN TIEMPO DE EJECUCIÓN
#  (mismo patrón que FileSync Pro / Organizador.py)
# ══════════════════════════════════════════════
DESKTOP_RUNTIME_CONFIG_NAME = "desktop_runtime_config.json"
DESKTOP_RUNTIME_CONFIG_OVERRIDE_NAME = "desktop_runtime_config.local.json"


def load_dotenv_file(path: str = ".env"):
    """Carga variables desde un .env local (solo relevante en modo desarrollo,
    ejecutando con `python main.py`). En el .exe compilado no se usa."""
    env_path = Path(path)
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_runtime_config_file(path: Path, override_existing: bool = False):
    """Lee un JSON de configuración y lo vuelca a variables de entorno."""
    if not path.exists():
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return

    for key, value in payload.items():
        normalized_key = str(key).strip()
        if not normalized_key:
            continue
        if isinstance(value, dict):
            serialized = json.dumps(value, ensure_ascii=False)
        elif value is not None:
            serialized = str(value).strip()
        else:
            continue
        if override_existing:
            os.environ[normalized_key] = serialized
        else:
            os.environ.setdefault(normalized_key, serialized)


# Variables del modo desarrollador. Solo existen en ejecución desde código
# fuente (python main.py); jamás se leen dentro del .exe.
_DEV_GATE_KEYS = (
    "CIPHERVAULT_ENABLE_DEV_TOOLS",
    "CIPHERVAULT_DEV_HOSTNAMES",
    "CIPHERVAULT_DEV_USERNAME",
    "CIPHERVAULT_DEV_PASSWORD",
)


def _read_embedded_config() -> dict:
    """Devuelve el contenido del desktop_runtime_config.json embebido en el .exe."""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return {}
    embedded_path = Path(base) / DESKTOP_RUNTIME_CONFIG_NAME
    try:
        payload = json.loads(embedded_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _lock_embedded_config():
    """
    BLINDAJE DE CONFIGURACIÓN (solo dentro del .exe).

    Quien tenga el .exe puede definir variables de entorno, un .env o un JSON
    junto al ejecutable antes de abrirlo. Para que eso no sirva de nada:

      1. Se borran TODAS las variables CIPHERVAULT_* que traiga el proceso.
      2. Se cargan únicamente las del desktop_runtime_config.json embebido.
      3. Las variables del modo desarrollador nunca se cargan (aunque alguien
         las haya metido por error en el JSON de un build).

    Así nadie puede apuntar la app a otro servidor de activación, otros links de pago
    ni activar herramientas de desarrollador.
    """
    for key in [k for k in os.environ if k.upper().startswith("CIPHERVAULT_")]:
        os.environ.pop(key, None)
    for key, value in _read_embedded_config().items():
        name = str(key).strip()
        if not name or name in _DEV_GATE_KEYS or value is None:
            continue
        if isinstance(value, dict):
            os.environ[name] = json.dumps(value, ensure_ascii=False)
        else:
            os.environ[name] = str(value).strip()


def load_runtime_config():
    """
    En el .exe: solo el JSON embebido (ver _lock_embedded_config).
    En desarrollo (python main.py), en este orden y sin pisar lo ya cargado:
      1. desktop_runtime_config.json en la carpeta actual / junto al script
      2. desktop_runtime_config.local.json (override manual, no se distribuye)
      3. .env local
    """
    if IS_FROZEN:
        _lock_embedded_config()
        return

    for candidate in (
        Path.cwd() / DESKTOP_RUNTIME_CONFIG_NAME,
        Path(__file__).resolve().with_name(DESKTOP_RUNTIME_CONFIG_NAME),
    ):
        load_runtime_config_file(candidate, override_existing=False)
    load_runtime_config_file(
        Path(__file__).resolve().with_name(DESKTOP_RUNTIME_CONFIG_OVERRIDE_NAME),
        override_existing=True,
    )
    load_dotenv_file(".env")


load_runtime_config()


def get_asset_path(filename: str) -> str:
    """
    Resuelve la ruta de un archivo en assets/ (o Assets/), tanto si la app corre
    como script (python main.py) como si corre compilada (.exe con PyInstaller).
    Retorna "" si no se encuentra (el llamador debe manejar ese caso).
    """
    candidates = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        candidates.append(Path(base) / "assets" / filename)

    here = Path(__file__).resolve().parent
    for folder in ("assets", "Assets"):
        candidates.append(here / folder / filename)
        candidates.append(Path.cwd() / folder / filename)

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return ""


def _env_str(key: str, default: str = "") -> str:
    """Lee una variable de entorno como texto; si está vacía o no existe, devuelve `default`."""
    val = os.environ.get(key, "")
    return val.strip() if val.strip() else default


def _env_int(key: str, default: int) -> int:
    """Lee una variable de entorno como entero; si falta o no es numérica, devuelve `default`."""
    val = os.environ.get(key, "")
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return default


def _env_list(key: str) -> list:
    """Lee una variable de entorno con valores separados por comas y los devuelve como lista (sin espacios ni vacíos)."""
    val = os.environ.get(key, "")
    return [item.strip() for item in val.split(",") if item.strip()]


# ──────────────────────────────────────────────
#  CONFIGURACIÓN WOMPI  ← viene de .env / desktop_runtime_config.json
#  Variables esperadas:
#    CIPHERVAULT_WOMPI_LINK_MAP              (JSON: {"premium_mensual": "https://checkout.wompi.co/l/XXXX",
#                                             "premium_anual": "...", "premium_vida": "..."})
#    CIPHERVAULT_ACTIVATION_URL             (webhook de Make que canjea los códigos)
#    CIPHERVAULT_ACTIVATION_SECRET          (secreto compartido con Make para firmar las respuestas)
#    CIPHERVAULT_PRICE_PREMIUM_MENSUAL_COP   (pesos, solo para MOSTRAR en la UI — no afecta el cobro real)
#    CIPHERVAULT_PRICE_PREMIUM_ANUAL_COP     (ídem)
#    CIPHERVAULT_PRICE_PREMIUM_VIDA_COP      (ídem)
#
#  IMPORTANTE: el precio REAL cobrado es el que configuraste en el Payment
#  Link de Wompi (dashboard.wompi.co → Links de pago). Los precios de aquí
#  son solo texto informativo en la pantalla de planes.
# ──────────────────────────────────────────────

def _env_json_map(key: str) -> dict:
    """Lee un valor que puede venir como dict nativo (ya vuelto string JSON
    por load_runtime_config_file) o directamente como string JSON desde .env."""
    raw = os.environ.get(key, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


# Links de pago reales (no son secretos). El .env / la config embebida solo los reemplaza
# si trae un link distinto para el mismo plan.
DEFAULT_WOMPI_LINKS = {
    "premium_mensual":  "https://checkout.wompi.co/l/KepI4g",
    "premium_anual":    "https://checkout.wompi.co/l/I75Zba",
    "premium_vida":     "https://checkout.wompi.co/l/nfKj8q",
    "equipo_3":         "https://checkout.wompi.co/l/eBC1hf",
    "equipo_5":         "https://checkout.wompi.co/l/5znGkS",
    "equipo_10":        "https://checkout.wompi.co/l/wnQAUN",
    "equipo_ilimitado": "https://checkout.wompi.co/l/bwpwwK",
}
# Links viejos que ya no se usan (precios anteriores del plan Equipo): si un .env antiguo
# todavía los trae, se usan los de DEFAULT_WOMPI_LINKS.
RETIRED_WOMPI_LINKS = {
    "https://checkout.wompi.co/l/5fZGtj",
    "https://checkout.wompi.co/l/1TY6Z1",
    "https://checkout.wompi.co/l/KUzO5b",
}
WOMPI_LINK_MAP = {**DEFAULT_WOMPI_LINKS,
                  **{k: v for k, v in _env_json_map("CIPHERVAULT_WOMPI_LINK_MAP").items()
                     if v and v.strip() not in RETIRED_WOMPI_LINKS}}

_PREMIUM_FEATURES = [
    "Contraseñas ilimitadas",
    "Análisis de seguridad y filtraciones",
    "Categorías para organizar tus claves",
    "Exportar e importar (.cvault y CSV)",
    "Copia de seguridad automática",
    "Códigos 2FA (TOTP)",
    "Verificación en dos pasos al entrar",
    "Soporte prioritario",
]

# Precios solo informativos (texto en pantalla). El cobro real lo define el Payment
# Link de Wompi correspondiente en WOMPI_LINK_MAP. Las tres opciones activan el mismo
# plan "premium"; solo cambia la duración (meses) que Make guarda con el código.
PLANES = {
    "premium_mensual": {
        "nombre":      "Mensual",
        "plan":        "premium",
        "precio_cop":  _env_int("CIPHERVAULT_PRICE_PREMIUM_MENSUAL_COP", 9900),
        "periodo":     "/mes",
        "descripcion": "Premium completo, pagas mes a mes.",
        "color":       "#00cec9",
        "meses":       1,
        "badge":       "",
        "features":    _PREMIUM_FEATURES,
    },
    "premium_anual": {
        "nombre":      "Anual",
        "plan":        "premium",
        "precio_cop":  _env_int("CIPHERVAULT_PRICE_PREMIUM_ANUAL_COP", 89900),
        "periodo":     "/año",
        "descripcion": "Premium por 12 meses. Ahorras un 24 % frente al mensual.",
        "color":       "#fd79a8",
        "meses":       12,
        "badge":       "MÁS ELEGIDO",
        "features":    _PREMIUM_FEATURES,
    },
    "premium_vida": {
        "nombre":      "De por vida",
        "plan":        "premium",
        "precio_cop":  _env_int("CIPHERVAULT_PRICE_PREMIUM_VIDA_COP", 149900),
        "periodo":     " pago único",
        "descripcion": "Un solo pago, sin suscripción ni renovaciones.",
        "color":       "#fdcb6e",
        "meses":       1200,
        "badge":       "SIN SUSCRIPCIÓN",
        "features":    _PREMIUM_FEATURES,
    },
}

_TEAM_FEATURES = [
    "Premium completo para cada persona",
    "Bóveda compartida con roles (admin, editor, lector)",
    "Registro de actividad: quién creó, editó o copió cada clave",
    "Informe de seguridad del equipo",
]


# Precios anteriores del plan Equipo (3, 5 y 10 usuarios): si un .env viejo los trae, se ignoran.
_RETIRED_TEAM_PRICES = {39900, 59900, 99900}


def _team_plan(key: str, users: int | None, default_price: int) -> dict:
    """Paquete del plan Equipo. users=None → usuarios ilimitados (un código de empresa)."""
    label = f"{users} usuarios" if users else "Hasta 100 usuarios"
    price = _env_int(f"CIPHERVAULT_PRICE_{key.upper()}_COP", default_price)
    if price in _RETIRED_TEAM_PRICES:          # precio viejo de un .env antiguo
        price = default_price
    premium = PLANES["premium_mensual"]["precio_cop"]
    saving = round(100 * (1 - price / (premium * users))) if users and premium else 0
    return {
        "nombre":      f"Equipo · {label}",
        "plan":        "equipo",
        "usuarios":    users,
        "precio_cop":  price,
        "periodo":     "/mes",
        "ahorro_pct":  saving,
        "descripcion": (f"{users} códigos de activación, uno por persona." if users else
                        "Un código de empresa para todo tu equipo: máximo 100 usuarios."),
        "color":       "#74b9ff",
        "meses":       1,
        "badge":       "EMPRESAS",
        "features":    _TEAM_FEATURES,
    }


# Plan para empresas. Un solo pago mensual de la empresa y le llegan por correo los códigos
# (o un código de empresa, en el paquete ilimitado) para repartir: estos códigos NO están
# atados al correo de quien paga. Cada persona sale más barata que un Premium individual
# (9.900/mes) y el plan suma funciones de administración que Premium no tiene.
TEAM_PLANES = {
    "equipo_3":         _team_plan("equipo_3", 3, 24900),      # 8.300 por persona (-16 %)
    "equipo_5":         _team_plan("equipo_5", 5, 37900),      # 7.580 por persona (-23 %)
    "equipo_10":        _team_plan("equipo_10", 10, 64900),    # 6.490 por persona (-34 %)
    "equipo_ilimitado": _team_plan("equipo_ilimitado", None, 199900),
}
ALL_PLANES = {**PLANES, **TEAM_PLANES}

# Planes que un código de activación firmado puede otorgar. "basic" ya no se vende,
# pero se sigue aceptando para los códigos emitidos antes. "developer" no se vende:
# solo lo concede un registro que tú creas en Make para tu correo.
REDEEMABLE_PLANS = frozenset({"basic", "premium", "equipo", "developer"})

# ──────────────────────────────────────────────
#  SERVICIO DE ACTIVACIÓN — escenario de Make (webhook con respuesta)
#  La app envía el hash del código + el identificador del equipo; Make registra ese
#  equipo en el código (un código sirve en hasta MAX_DEVICES equipos) y responde el plan
#  firmado con el secreto compartido. Sin URL configurada la activación queda
#  deshabilitada (no hay valor por defecto).
# ──────────────────────────────────────────────
ACTIVATION_URL = _env_str("CIPHERVAULT_ACTIVATION_URL", "")
ACTIVATION_SECRET = _env_str("CIPHERVAULT_ACTIVATION_SECRET", "")
ACTIVATION_TIMEOUT = 12   # segundos
# Equipos (PC) en los que se puede activar un mismo código. El límite real lo aplica el
# escenario de canje de Make; este valor solo se usa en los textos de la app.
MAX_DEVICES = 3

# ──────────────────────────────────────────────
#  RUTAS DE ARCHIVOS LOCALES
# ──────────────────────────────────────────────
BASE_PATH = os.path.dirname(os.path.abspath(__file__))


def _get_data_path() -> Path:
    """Ubicación escribible por usuario, separada del ejecutable instalado:
    %LOCALAPPDATA%\\CipherVault en Windows, ~/Library/Application Support/CipherVault en macOS."""
    if os.environ.get("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"]) / "CipherVault"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support" / "CipherVault"
    else:
        root = Path.home() / "CipherVault"
    root.mkdir(parents=True, exist_ok=True)
    # Conserva datos existentes de instalaciones antiguas sin sobrescribirlos.
    for filename in ("passwords.db", "app_config.json"):
        old, new = Path(BASE_PATH) / filename, root / filename
        if old.exists() and not new.exists():
            try:
                old.replace(new)
            except OSError:
                pass
    return root


DATA_PATH = _get_data_path()
DB_FILE = str(DATA_PATH / "passwords.db")
CONFIG_FILE = str(DATA_PATH / "app_config.json")
LICENSE_FILE = str(DATA_PATH / "developer.license")
LOG_FILE = str(DATA_PATH / "ciphervault.log")
# Credenciales de developer configuradas desde la propia app (Dev Panel).
# Vive junto a la DB del usuario, nunca se versiona ni se distribuye.
DEV_CREDENTIALS_FILE = str(DATA_PATH / "dev_credentials.json")

# 600.000 iteraciones: recomendación OWASP para PBKDF2-HMAC-SHA256.
PASSWORD_HASH_ITERATIONS = 600_000   # (heredado) hash de login de cuentas antiguas
VAULT_KDF_ITERATIONS = 600_000       # clave de la bóveda y de los respaldos .cvault


# ══════════════════════════════════════════════
#  LOG A ARCHIVO (el .exe no tiene consola)
# ══════════════════════════════════════════════
log = logging.getLogger("ciphervault")


def _setup_logging():
    """Registra eventos y errores en %LOCALAPPDATA%\\CipherVault\\ciphervault.log.
    Nunca se escriben contraseñas, códigos ni claves."""
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    try:
        handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=256 * 1024, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
    except OSError:
        log.addHandler(logging.NullHandler())


_setup_logging()


# ══════════════════════════════════════════════
#  ACCESO A LA BASE DE DATOS
# ══════════════════════════════════════════════
@contextlib.contextmanager
def db():
    """Conexión SQLite con commit/rollback automático y cierre garantizado.
    Lee DB_FILE en cada uso (así las pruebas pueden apuntar a otra base)."""
    conn = sqlite3.connect(DB_FILE, timeout=15)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _row_dict(cursor: sqlite3.Cursor, row) -> dict | None:
    """Convierte una fila de `SELECT *` en diccionario usando los nombres de columna."""
    if row is None:
        return None
    return dict(zip([d[0] for d in cursor.description], row))


def get_user_by_name(conn: sqlite3.Connection, username: str) -> dict | None:
    """Devuelve la fila completa de `users` para ese nombre de usuario (o None)."""
    cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return _row_dict(cur, cur.fetchone())


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> dict | None:
    """Devuelve la fila completa de `users` para ese id (o None)."""
    cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return _row_dict(cur, cur.fetchone())


# ══════════════════════════════════════════════
#  CRIPTOGRAFÍA: contraseña maestra → clave de bóveda
# ══════════════════════════════════════════════
def _b64(value: bytes) -> str:
    """Codifica bytes en base64 URL-safe, devolviendo texto ASCII listo para guardar en la base de datos."""
    return base64.urlsafe_b64encode(value).decode("ascii")


def _derive_vault_key(password: str, vault_salt: str) -> bytes:
    """PBKDF2-HMAC-SHA256 (600.000 iteraciones) → 32 bytes. Es la única derivación
    costosa del login: la clave sirve para descifrar la bóveda y, mediante un
    HMAC, también para verificar la contraseña maestra (formato "v3$")."""
    salt = base64.urlsafe_b64decode(vault_salt.encode("ascii"))
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               VAULT_KDF_ITERATIONS, dklen=32)


def _fernet_from_key(key: bytes) -> Fernet:
    """Construye el Fernet de la bóveda a partir de la clave derivada."""
    return Fernet(base64.urlsafe_b64encode(key))


def _vault_from_password(password: str, vault_salt: str) -> Fernet:
    """Deriva la clave simétrica (Fernet) de la bóveda a partir de la contraseña maestra y el salt propio del usuario. Nunca se guarda: se recalcula en cada login."""
    return _fernet_from_key(_derive_vault_key(password, vault_salt))


AUTH_PREFIX = "v3$"


def _make_login_hash(key: bytes) -> str:
    """Verificador de la contraseña maestra: HMAC(clave_de_bóveda, etiqueta). No permite
    recuperar la clave, y comprobarlo cuesta lo mismo que descifrar la bóveda."""
    tag = hmac.new(key, b"ciphervault/auth/v3", hashlib.sha256).digest()
    return AUTH_PREFIX + _b64(tag)


def _hash_login_password(password: str, vault_salt: str) -> str:
    """Hash de login formato v3 para una contraseña maestra y su vault_salt."""
    return _make_login_hash(_derive_vault_key(password, vault_salt))


class AuthResult:
    """Resultado de verificar la contraseña maestra de un usuario."""
    __slots__ = ("ok", "key", "vault_salt", "needs_upgrade")

    def __init__(self, ok: bool, key: bytes | None = None, vault_salt: str | None = None,
                 needs_upgrade: bool = False):
        self.ok = ok
        self.key = key
        self.vault_salt = vault_salt
        self.needs_upgrade = needs_upgrade


def authenticate(password: str, user: dict) -> AuthResult:
    """
    Verifica la contraseña maestra contra la cuenta `user` (fila de `users`).
    Soporta tres formatos y marca `needs_upgrade` cuando hay que guardar el v3:
      · v3$…               HMAC de la clave de bóveda (1 sola derivación)
      · pbkdf2_sha256$…    formato anterior (hash de login + bóveda por separado)
      · SHA-256 hexadecimal  cuentas muy antiguas
    """
    stored = str(user.get("password_hash") or "")
    vault_salt = user.get("vault_salt") or ""
    try:
        if stored.startswith(AUTH_PREFIX) and vault_salt:
            key = _derive_vault_key(password, vault_salt)
            ok = hmac.compare_digest(_make_login_hash(key), stored)
            return AuthResult(ok, key if ok else None, vault_salt, False)

        if stored.startswith("pbkdf2_sha256$"):
            _, iterations, salt_b64, hash_b64 = stored.split("$", 3)
            actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                         base64.urlsafe_b64decode(salt_b64), int(iterations))
            ok = hmac.compare_digest(_b64(actual), hash_b64)
        else:
            ok = hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)
    except (ValueError, TypeError):
        return AuthResult(False)

    if not ok:
        return AuthResult(False)
    vault_salt = vault_salt or _b64(os.urandom(16))
    return AuthResult(True, _derive_vault_key(password, vault_salt), vault_salt, True)


def authenticate_with_key(key: bytes, user: dict) -> AuthResult:
    """Verifica una clave de bóveda ya derivada (la que entrega Windows Hello) contra la cuenta."""
    stored = str(user.get("password_hash") or "")
    vault_salt = user.get("vault_salt") or ""
    if not (key and stored.startswith(AUTH_PREFIX) and vault_salt):
        return AuthResult(False)
    ok = hmac.compare_digest(_make_login_hash(key), stored)
    return AuthResult(ok, key if ok else None, vault_salt, False)


# ── Cifrado de metadatos (servicio, usuario, notas) ───────────────
ENC_PREFIX = "enc1:"


def enc_text(vault: Fernet, text: str) -> str:
    """Cifra un texto con la bóveda y le antepone un prefijo para reconocerlo."""
    return ENC_PREFIX + vault.encrypt((text or "").encode("utf-8")).decode("ascii")


def dec_text(vault: Fernet, value) -> str:
    """Descifra un campo cifrado con enc_text. Si el valor viene sin cifrar
    (datos anteriores a la migración) lo devuelve tal cual."""
    if value is None:
        return ""
    value = str(value)
    if not value.startswith(ENC_PREFIX):
        return value
    try:
        return vault.decrypt(value[len(ENC_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return "⚠ ilegible"


# ── Sello de la licencia guardada en la base de datos local ───────
# Evita el "editar una celda": cambiar plan/vencimiento con un editor de SQLite
# invalida el sello y la cuenta vuelve a gratis. La clave del sello se deriva del
# secreto de activación (CIPHERVAULT_ACTIVATION_SECRET), que va embebido en el .exe
# y NUNCA está en el repositorio: como el código es público, una clave fija escrita
# aquí permitiría a cualquiera fabricar un sello válido con un script. Sigue siendo
# un freno (quien desensamble el .exe podría sacar el secreto); la protección real
# es que el plan solo se otorga canjeando un código de un solo uso, atado al equipo.
# Los sellos hechos con la clave fija anterior dejan de valer: la app los trata como
# "tampered" y la auto-reparación los vuelve a pedir a Make (necesita activation_hash).
_SEAL_LABEL = b"ciphervault/license-seal/v2"
_SEAL_KEY_SIN_SECRETO = b"CipherVault/license-seal/v1/S.C.A/2026"   # solo sin secreto (código fuente sin .env)


def _seal_base_key() -> bytes:
    """Clave base del sello: HMAC del secreto de activación. Sin secreto configurado (ejecución
    desde código fuente sin .env, donde además no se puede canjear nada) usa la clave fija antigua."""
    secret = ACTIVATION_SECRET or ""
    if not secret:
        return _SEAL_KEY_SIN_SECRETO
    return hmac.new(secret.encode("utf-8"), _SEAL_LABEL, hashlib.sha256).digest()


_MACHINE_ID_CACHE: str | None = None


def machine_id() -> str:
    """Identificador estable de este equipo (hash del MachineGuid de Windows; en otros
    sistemas, machine-id o la MAC). No se envía en claro: solo su hash."""
    global _MACHINE_ID_CACHE
    if _MACHINE_ID_CACHE:
        return _MACHINE_ID_CACHE
    raw = ""
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                raw = str(winreg.QueryValueEx(key, "MachineGuid")[0])
        except (OSError, ImportError):
            raw = ""
    if not raw and sys.platform == "darwin":
        try:   # identificador del hardware del Mac (no cambia al reinstalar macOS)
            import subprocess
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], capture_output=True,
                                 text=True, timeout=5).stdout
            match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
            raw = match.group(1) if match else ""
        except (OSError, ValueError, subprocess.SubprocessError):
            raw = ""
    if not raw:
        for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                raw = Path(candidate).read_text(encoding="ascii").strip()
                break
            except OSError:
                continue
    if not raw:
        raw = f"{uuid.getnode()}|{platform.node()}"
    _MACHINE_ID_CACHE = hashlib.sha256(("ciphervault/machine/v1|" + raw).encode("utf-8")).hexdigest()[:32]
    return _MACHINE_ID_CACHE


def license_seal(user_id, version, expiry, vault_salt, machine: str | None = None) -> str:
    """HMAC que liga plan + vencimiento a esta cuenta (id + vault_salt) Y a este equipo:
    copiar passwords.db a otra PC invalida la licencia."""
    machine = machine if machine is not None else machine_id()
    msg = f"{user_id}|{version or ''}|{expiry or ''}|{machine}".encode("utf-8")
    key = _seal_base_key() + (vault_salt or "").encode("ascii", "ignore")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ── Fortaleza de contraseñas ──────────────────────────────────────
_COMMON_PASSWORDS = frozenset("""
password password1 password123 passw0rd p@ssw0rd p@ssword admin admin123 admin1234
administrator root toor qwerty qwerty123 qwertyuiop asdfgh asdfghjkl zxcvbnm abc123
abcd1234 abcdefgh 123456 1234567 12345678 123456789 1234567890 111111 000000 123123
654321 iloveyou letmein welcome welcome1 monkey dragon master login football
baseball sunshine princess shadow superman trustno1 contraseña contrasena clave
clave123 colombia colombia123 bogota123 medellin123 santiago123 hola1234 hola123
cipher cipherv ciphervault changeme default guest test test123 usuario usuario123
""".split())


def evaluate_strength(pwd: str) -> tuple[str, int]:
    """Calcula la fortaleza (1-5) y su etiqueta. Suma por longitud y variedad de
    caracteres (cualquier símbolo cuenta), y baja a DÉBIL las contraseñas comunes,
    de pocos caracteres distintos o con patrones obvios (secuencias, repeticiones)."""
    pwd = pwd or ""
    score = 0
    if len(pwd) >= 12:
        score += 2
    elif len(pwd) >= 8:
        score += 1
    if re.search(r"[a-z]", pwd): score += 1
    if re.search(r"[A-Z]", pwd): score += 1
    if re.search(r"\d", pwd):    score += 1
    if re.search(r"[^A-Za-z0-9]", pwd): score += 1

    lowered = pwd.lower()
    stripped = re.sub(r"[^a-z]", "", lowered)
    weak_pattern = (
        lowered in _COMMON_PASSWORDS
        or stripped in _COMMON_PASSWORDS and len(pwd) < 16
        or len(set(pwd)) <= 3
        or bool(re.fullmatch(r"(.{1,3})\1{2,}", pwd))
        or _is_sequence(lowered)
    )
    if weak_pattern:
        score = min(score, 1)
    names = {5: "MUY FUERTE", 4: "FUERTE", 3: "MODERADA", 2: "DÉBIL", 1: "DÉBIL"}
    score = min(score, 5)
    return names.get(score, "DÉBIL"), score


def _is_sequence(text: str) -> bool:
    """True si el texto es una secuencia ascendente o descendente (abcdef, 987654…)."""
    if len(text) < 6:
        return False
    steps = {ord(b) - ord(a) for a, b in zip(text, text[1:])}
    return steps in ({1}, {-1})



# ══════════════════════════════════════════════
#  HELPERS DE WOMPI — links de pago fijos por plan
# ══════════════════════════════════════════════
class WompiHelper:
    """
    Abre el Payment Link fijo de Wompi correspondiente al plan.
    Los links se crean una vez en el dashboard de Wompi (Links de pago)
    y viven en CIPHERVAULT_WOMPI_LINK_MAP (.env / desktop_runtime_config.json).

    A diferencia del checkout dinámico, estos links NO llevan usuario
    incrustado. La identificación del comprador se hace por el email que
    la persona escribe en el checkout de Wompi (customer_email en el
    webhook), por eso es crítico que el usuario pague con el MISMO email
    que registró en la app.
    """

    @staticmethod
    def get_plan_link(plan_key: str) -> str:
        """Devuelve el Payment Link de Wompi configurado para ese plan, o cadena vacía si no existe."""
        return WOMPI_LINK_MAP.get(plan_key, "")

    @staticmethod
    def has_link(plan_key: str) -> bool:
        """Indica si hay un link de pago configurado para el plan dado."""
        return bool(WompiHelper.get_plan_link(plan_key))

    @staticmethod
    def open_checkout(plan_key: str) -> bool:
        """Abre el link de pago del plan en el navegador predeterminado. Devuelve False si el plan no tiene link configurado."""
        link = WompiHelper.get_plan_link(plan_key)
        if not link:
            return False
        webbrowser.open(link)
        return True


# ══════════════════════════════════════════════
#  ACTIVACIÓN DE LICENCIAS (Wompi → Make → código de un solo uso → App)
# ══════════════════════════════════════════════
class ActivationError(Exception):
    """Error de activación con un mensaje listo para mostrarse al usuario. `reason` es el
    motivo que devolvió el servidor ("invalid", "used", "expired"…), si lo hubo."""

    def __init__(self, message: str, reason: str = ""):
        super().__init__(message)
        self.reason = reason


def _parse_datetime(text: str) -> datetime | None:
    """Interpreta las fechas que escribe Make (ISO con T, con espacio, con Z/offset
    o dd/mm/aaaa). Devuelve una fecha local sin zona horaria, o None si no se entiende."""
    text = (text or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M",
                "%Y-%m-%d", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


SQL_DATETIME = "%Y-%m-%d %H:%M:%S"


def set_user_license(conn: sqlite3.Connection, username: str, plan: str,
                     expiry: datetime, reference: str, method: str,
                     activated_by: str, duration_label: str,
                     activation_hash: str | None = None) -> bool:
    """Guarda en `users` el plan, el vencimiento y el sello de integridad, y deja
    constancia en el historial. Devuelve False si el usuario no existe."""
    user = get_user_by_name(conn, username)
    if not user:
        return False
    expiry_str = expiry.strftime(SQL_DATETIME)
    vault_salt = user.get("vault_salt")
    if not vault_salt:
        # Cuenta anterior que aún no inició sesión: se le asigna su vault_salt ahora
        # (el login la usará al migrarla) para poder sellar la licencia.
        vault_salt = _b64(os.urandom(16))
        conn.execute("UPDATE users SET vault_salt=? WHERE id=?", (vault_salt, user["id"]))
    seal = license_seal(user["id"], plan, expiry_str, vault_salt)
    conn.execute(
        """UPDATE users SET version=?, license_expiry=?, license_type=?,
               payment_reference=?, payment_method=?, payment_date=CURRENT_TIMESTAMP,
               license_seal=?, activation_hash=COALESCE(?, activation_hash) WHERE id=?""",
        (plan, expiry_str, plan, reference, method, seal, activation_hash, user["id"]))
    conn.execute(
        """INSERT INTO license_activations
               (username, license_type, duration, expiry_date,
                payment_method, payment_reference, activated_by)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (username, plan, duration_label, expiry_str, method, reference, activated_by))
    return True


class LicenseActivationManager:
    """
    Canje de códigos de activación, atados a los equipos (PC) del comprador: un código sirve
    en hasta MAX_DEVICES equipos.

    Make guarda por cada código (Data Store): code_hash | plan | reference | meses |
    created_at | machine | used_at, donde `machine` es la lista de equipos separados por coma y
      code_hash = SHA-256( CODIGO_SIN_GUIONES_EN_MAYUSCULAS + "|" + email_en_minusculas )

    La app NO envía el código ni el email: solo code_hash + el identificador del equipo
    + un nonce. Make responde {"ok": true, plan, reference, meses, created_at, sig}; la
    firma `sig` (SHA-256 con el secreto compartido) liga la respuesta a ese code_hash,
    equipo y nonce, así que no se puede reutilizar una respuesta en otro equipo ni
    falsificarla sin conocer el secreto.
      · equipo nuevo con cupo  → se agrega a la lista del código (máx. MAX_DEVICES)
      · equipo ya registrado   → se permite repetir (reinstalar la app) sin extender la vigencia
      · equipo nuevo sin cupo  → {"ok": false, "error": "used"}
    Ver GUIA_ACTIVACION_MAKE.md para configurar Make.
    """

    DAYS_PER_MONTH = 30
    # Tope de meses por código. Las compras normales traen 1; el código de dueño (licencia
    # de por vida, emitido por ti en Make) usa 1200 meses (100 años).
    MAX_MESES = 1200
    MIN_CODE_LENGTH = 12

    @staticmethod
    def normalize_code(code: str) -> str:
        """Quita espacios/guiones y pasa a mayúsculas: 'ab12-cd34 ef56' → 'AB12CD34EF56'."""
        return re.sub(r"[^A-Z0-9]", "", (code or "").upper())

    @staticmethod
    def code_hash(code: str, email: str) -> str:
        """Hash que Make guarda para ese código y email."""
        payload = f"{LicenseActivationManager.normalize_code(code)}|{(email or '').strip().lower()}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def response_signature(code_hash: str, machine: str, nonce: str, plan: str,
                           reference: str, meses: str, created_at: str, secret: str) -> str:
        """Firma que Make debe calcular: SHA-256 hex de los campos unidos por '|' + '|' + secreto."""
        text = "|".join((code_hash, machine, nonce, plan, reference, meses, created_at, secret))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    ERROR_MESSAGES = {
        "used": f"Este código ya está activado en {MAX_DEVICES} equipos, que es el máximo por licencia. "
                "Si cambiaste de computador, escribe a soporte para liberar uno de los anteriores; "
                "para más equipos necesitas otra licencia.",
        "invalid": "Ese código no es válido para esta cuenta. Revisa que lo copiaste completo y que "
                   "tu cuenta usa el mismo email con el que pagaste. Si pagaste hace pocos minutos, "
                   "espera un momento y vuelve a intentar.",
        "expired": "Este código corresponde a un pago cuya vigencia ya terminó. Compra un plan para activar uno nuevo.",
    }

    @staticmethod
    def _call_server(payload: dict) -> dict:
        """POST JSON al webhook de activación de Make. Lanza ActivationError con un mensaje
        claro si no hay configuración, red o una respuesta válida."""
        url = ACTIVATION_URL
        if not url or not ACTIVATION_SECRET:
            raise ActivationError("La activación de licencias no está configurada en esta versión de CipherVault.")
        if not url.lower().startswith("https://"):
            raise ActivationError("La dirección de activación no es segura (debe empezar por https).")
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": f"CipherVault/{APP_VERSION}"})
        try:
            with urllib.request.urlopen(req, timeout=ACTIVATION_TIMEOUT) as resp:
                raw = resp.read(100_000).decode("utf-8")
        except urllib.error.HTTPError as exc:
            log.warning("Activación: el servicio respondió HTTP %s", exc.code)
            raise ActivationError(f"El servicio de activación no está disponible (error {exc.code}). "
                                  "Inténtalo más tarde o escribe a soporte.") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("Activación: no se pudo conectar (%s)", type(exc).__name__)
            raise ActivationError("No se pudo conectar para verificar el código. Revisa tu conexión a "
                                  "internet e inténtalo de nuevo.") from exc
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        if not isinstance(body, dict):
            log.warning("Activación: respuesta que no es JSON")
            raise ActivationError("El servicio de activación respondió algo inesperado. Escribe a soporte.")
        return body

    @staticmethod
    def _verify(wanted: str) -> dict:
        """Pregunta a Make por ese code_hash en ESTE equipo y valida la respuesta firmada.
        Devuelve {"plan", "reference", "created", "meses"} o lanza ActivationError."""
        machine, nonce = machine_id(), secrets.token_hex(8)
        body = LicenseActivationManager._call_server(
            {"v": 3, "code_hash": wanted, "machine": machine, "nonce": nonce})

        if body.get("ok") is not True:
            reason = str(body.get("error", "")).lower()
            log.info("Activación rechazada por el servidor: %s", reason or "sin motivo")
            raise ActivationError(LicenseActivationManager.ERROR_MESSAGES.get(
                reason, "El servicio de activación rechazó el código. Escribe a soporte."), reason)

        fields = {k: str(body.get(k, "")) for k in ("plan", "reference", "meses", "created_at")}
        expected = LicenseActivationManager.response_signature(
            wanted, machine, nonce, fields["plan"], fields["reference"], fields["meses"],
            fields["created_at"], ACTIVATION_SECRET)
        if not hmac.compare_digest(str(body.get("sig", "")).lower(), expected):
            log.warning("Activación: firma de la respuesta inválida")
            raise ActivationError("La respuesta del servicio de activación no es válida. Escribe a soporte.")

        plan = fields["plan"].lower()
        reference = fields["reference"]
        if plan not in REDEEMABLE_PLANS or not reference:
            log.warning("Activación: respuesta incompleta (plan=%r, reference vacía=%s)", plan, not reference)
            raise ActivationError("El registro de tu pago está incompleto. Escribe a soporte con tu referencia de pago.")
        created = _parse_datetime(fields["created_at"])
        if created is None:
            raise ActivationError("El registro de tu pago no tiene una fecha válida. Escribe a soporte.")
        meses = int(fields["meses"]) if fields["meses"].isdigit() else 1
        meses = max(1, min(meses, LicenseActivationManager.MAX_MESES))
        return {"plan": plan, "reference": reference, "created": created, "meses": meses}

    @staticmethod
    def _reseal(conn: sqlite3.Connection, user: dict, info: dict, wanted: str) -> datetime:
        """Vuelve a sellar la licencia con los datos confirmados por el servidor
        (vencimiento = fecha del pago + meses). No crea una activación nueva."""
        expiry = info["created"] + timedelta(days=LicenseActivationManager.DAYS_PER_MONTH * info["meses"])
        if expiry <= datetime.now():
            raise ActivationError("La licencia de este código ya venció. Compra un plan para activar uno nuevo.")
        vault_salt = user.get("vault_salt")
        if not vault_salt:
            vault_salt = _b64(os.urandom(16))
            conn.execute("UPDATE users SET vault_salt=? WHERE id=?", (vault_salt, user["id"]))
        expiry_str = expiry.strftime(SQL_DATETIME)
        seal = license_seal(user["id"], info["plan"], expiry_str, vault_salt)
        conn.execute("UPDATE users SET version=?, license_type=?, license_expiry=?, license_seal=?, "
                     "activation_hash=? WHERE id=?",
                     (info["plan"], info["plan"], expiry_str, seal, wanted, user["id"]))
        return expiry

    @staticmethod
    def repair(user_id: int) -> dict | None:
        """Auto-reparación al iniciar sesión: si la licencia local no se puede validar
        pero la cuenta tiene un código canjeado, se vuelve a verificar con Make en este
        equipo (Make solo responde OK si el código está ligado a ESTE equipo) y se re-sella.
        Devuelve {"plan", "expiry"} si se reparó, None si no aplica. Lanza ActivationError
        si el servidor la rechaza."""
        with db() as conn:
            user = get_user_by_id(conn, user_id)
        if not user or not user.get("activation_hash"):
            return None
        if compute_effective_version(user)[2] == "ok":
            return None
        wanted = str(user["activation_hash"])
        info = LicenseActivationManager._verify(wanted)
        with db() as conn:
            user = get_user_by_id(conn, user_id)
            expiry = LicenseActivationManager._reseal(conn, user, info, wanted)
        log.info("Licencia %s reparada automáticamente para %s", info["plan"], user.get("username"))
        return {"plan": info["plan"], "expiry": expiry}

    @staticmethod
    def redeem(code: str, username: str, email: str) -> dict:
        """
        Canjea un código para la cuenta `username` (con el email `email`) en ESTE equipo.
        Devuelve {"plan", "expiry", "reference", "meses", "already"}.
        Lanza ActivationError con el motivo si no se puede activar.
        """
        norm = LicenseActivationManager.normalize_code(code)
        if len(norm) < LicenseActivationManager.MIN_CODE_LENGTH:
            raise ActivationError("El código no tiene el formato correcto. Cópialo completo del correo.")
        email = (email or "").strip().lower()
        if not email:
            raise ActivationError("Tu cuenta no tiene email registrado, así que no se puede validar el código.")

        wanted = LicenseActivationManager.code_hash(norm, email)
        try:
            info = LicenseActivationManager._verify(wanted)
        except ActivationError as exc:
            if exc.reason != "invalid":
                raise
            # Códigos del plan Equipo: los compra la empresa y los reparte, así que no
            # están atados al correo de nadie (su hash usa un email vacío).
            wanted = LicenseActivationManager.code_hash(norm, "")
            info = LicenseActivationManager._verify(wanted)
        plan, reference, created, meses = info["plan"], info["reference"], info["created"], info["meses"]

        with db() as conn:
            user = get_user_by_name(conn, username)
            if not user:
                raise ActivationError("No se encontró tu cuenta.")
            applied = conn.execute(
                "SELECT 1 FROM license_activations WHERE username=? AND payment_reference=? LIMIT 1",
                (username, reference)).fetchone()
            if applied:
                # Ya canjeado en esta cuenta. Si el sello local se dañó (base movida, migración,
                # cambio del equipo…) se vuelve a sellar con lo que confirma el servidor, en vez
                # de dejar al usuario atascado en el plan gratuito.
                if compute_effective_version(user)[2] != "ok":
                    expiry = LicenseActivationManager._reseal(conn, user, info, wanted)
                    log.info("Licencia %s re-sellada para %s (código ya canjeado)", plan, username)
                    return {"plan": plan, "expiry": expiry, "reference": reference,
                            "meses": meses, "already": True, "repaired": True}
                conn.execute("UPDATE users SET activation_hash=COALESCE(activation_hash, ?) WHERE id=?",
                             (wanted, user["id"]))
                current = _parse_datetime(user.get("license_expiry") or "")
                return {"plan": user.get("version") or plan, "expiry": current,
                        "reference": reference, "meses": meses, "already": True}

            # Si ya tiene una licencia vigente al momento del pago, el nuevo período se suma.
            start = created
            current = _parse_datetime(user.get("license_expiry") or "")
            if current and current > created and compute_effective_version(user)[2] == "ok":
                start = current
            expiry = start + timedelta(days=LicenseActivationManager.DAYS_PER_MONTH * meses)
            if expiry <= datetime.now():
                raise ActivationError(
                    f"Este código corresponde a un pago del {created:%d/%m/%Y} cuya vigencia "
                    f"terminó el {expiry:%d/%m/%Y}. Compra un plan para activar uno nuevo.")
            set_user_license(conn, username, plan, expiry, reference, "Wompi",
                             "codigo_activacion", f"{meses} mes(es)", activation_hash=wanted)
        log.info("Licencia %s activada para %s hasta %s", plan, username, expiry.date())
        return {"plan": plan, "expiry": expiry, "reference": reference,
                "meses": meses, "already": False}


# ══════════════════════════════════════════════
#  ¿CONTRASEÑA FILTRADA? (Have I Been Pwned, k-anonimato)
# ══════════════════════════════════════════════
class PwnedPasswords:
    """Consulta el servicio de rangos de Have I Been Pwned: solo se envían los
    primeros 5 caracteres del SHA-1 de la contraseña, nunca la contraseña."""
    API = "https://api.pwnedpasswords.com/range/"

    @staticmethod
    def count(password: str, timeout: int = 8) -> int:
        """Cantidad de filtraciones conocidas donde aparece la contraseña (0 = ninguna).
        Lanza OSError si no hay conexión."""
        digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        req = urllib.request.Request(
            PwnedPasswords.API + prefix,
            headers={"User-Agent": "CipherVault/2.0", "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        for line in body.splitlines():
            tail, _, num = line.partition(":")
            if tail.strip().upper() == suffix:
                return int(num.strip() or 0)
        return 0


def compute_effective_version(user: dict) -> tuple[str, str | None, str]:
    """
    Plan que realmente corresponde a una cuenta AHORA. Devuelve (plan, vencimiento, estado).
    La base de datos es editable por el usuario, así que no se fía de ella:
      · developer: solo en una máquina de desarrollo autorizada (nunca en el .exe)
      · basic/premium/developer(código firmado): requiere sello válido (lo pone el canje de un código) y vencimiento futuro
    Estado: "ok" | "expired" | "tampered" (plan sin sello válido, es decir, editado a mano).
    """
    plan = str(user.get("version") or "free").strip().lower()
    expiry_str = user.get("license_expiry") or None
    is_dev_flag = str(user.get("is_developer") or "0").strip().lower() in ("1", "true", "yes")

    if is_dev_flag and DeveloperLicenseManager.is_developer_machine():
        return "developer", None, "ok"

    if plan in REDEEMABLE_PLANS:
        seal = user.get("license_seal")
        expected = license_seal(user.get("id"), plan, expiry_str, user.get("vault_salt"))
        if not seal or not hmac.compare_digest(str(seal).encode("utf-8"), expected.encode("utf-8")):
            return "free", expiry_str, "tampered"
        expiry = _parse_datetime(expiry_str or "")
        if expiry is None or expiry <= datetime.now():
            return "free", expiry_str, "expired"
        return plan, expiry_str, "ok"

    # Cualquier otro valor (incluida la antigua prueba de 30 días) es el plan gratis.
    return "free", None, "ok"


# ══════════════════════════════════════════════
#  LICENCIA DE DESARROLLADOR
# ══════════════════════════════════════════════
class DeveloperLicenseManager:
    """Gestiona el modo desarrollador: solo se activa ejecutando desde código fuente (python main.py)
    en equipos explícitamente autorizados (por hostname). Dentro del .exe está desactivado siempre,
    sin importar qué haya en el entorno, en archivos o en la configuración embebida."""
    # IS_FROZEN → nunca. Además hace falta CIPHERVAULT_ENABLE_DEV_TOOLS=1 explícito.
    # OJO: _env_str siempre devuelve un string; por eso se compara con "1".
    ENABLED = (not IS_FROZEN) and _env_str("CIPHERVAULT_ENABLE_DEV_TOOLS", "0") == "1"
    _CONFIGURED_MACHINES = _env_list("CIPHERVAULT_DEV_HOSTNAMES")
    MY_MACHINES = _CONFIGURED_MACHINES

    # Usuario/contraseña de la cuenta de desarrollador local (solo desarrollo).
    # Sin valores por defecto: si no se configuran en .env o en el Dev Panel,
    # el login rápido de developer queda deshabilitado.
    DEV_USERNAME = _env_str("CIPHERVAULT_DEV_USERNAME", "")
    DEV_PASSWORD = _env_str("CIPHERVAULT_DEV_PASSWORD", "")

    @staticmethod
    def generate_key() -> str:
        """Genera una clave de licencia de desarrollador derivada del equipo y usuario actuales (no es secreta, solo identifica la instalación)."""
        info = f"{platform.node()}-{getpass.getuser()}-{platform.system()}"
        h    = hashlib.sha256(info.encode()).hexdigest()[:16].upper()
        return f"DEV-{h}"

    @staticmethod
    def get_dev_credentials() -> tuple[str, str]:
        """Usuario/contraseña de developer a usar. Prioridad:
        1) lo guardado desde el Dev Panel (dev_credentials.json, local, no versionado)
        2) .env (CIPHERVAULT_DEV_USERNAME/PASSWORD), solo en desarrollo
        Sin ninguno de los dos devuelve ("", "") y el login rápido queda deshabilitado.
        """
        try:
            if os.path.exists(DEV_CREDENTIALS_FILE):
                with open(DEV_CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                u = (data.get("username") or "").strip()
                p = (data.get("password") or "").strip()
                if u and p:
                    return u, p
        except Exception:
            pass
        return DeveloperLicenseManager.DEV_USERNAME, DeveloperLicenseManager.DEV_PASSWORD

    @staticmethod
    def save_dev_credentials(username: str, password: str):
        """Guarda usuario/contraseña de developer elegidos desde la app."""
        with open(DEV_CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            json.dump({"username": username.strip(), "password": password}, f)

    @staticmethod
    def is_developer_machine() -> bool:
        """Determina si el equipo actual está autorizado como máquina de desarrollador:
        ejecución desde código fuente + CIPHERVAULT_ENABLE_DEV_TOOLS=1 + hostname listado
        en CIPHERVAULT_DEV_HOSTNAMES."""
        if not DeveloperLicenseManager.ENABLED:
            return False
        return platform.node() in DeveloperLicenseManager.MY_MACHINES

    @staticmethod
    def create_license() -> str:
        """Genera y guarda en disco el archivo de licencia de desarrollador."""
        key = DeveloperLicenseManager.generate_key()
        with open(LICENSE_FILE, "w") as f:
            f.write(key)
        return key


# ══════════════════════════════════════════════
#  VERSIONES Y LÍMITES
# ══════════════════════════════════════════════
# El plan gratis guarda hasta 50 contraseñas (antes 3): suficiente para probar de verdad.
# El plan gratis no incluye análisis de seguridad, categorías ni códigos 2FA (son de Premium).
FREE_MAX_PASSWORDS = 50

VERSIONS = {

    "free": {
        "name": "Gratis", "max_passwords": FREE_MAX_PASSWORDS,
        "security_analysis": False, "password_length_max": 16,
        "categories": False, "export": False, "backup": False, "totp": False,
        "sync": False, "team": False, "login_2fa": False,
        "notes_max_length": 100, "price": 0, "color": "#b2bec3",
    },
    "basic": {
        "name": "Básico", "max_passwords": -1,
        "security_analysis": True, "password_length_max": 32,
        "categories": True, "export": True, "backup": False, "totp": True,
        "sync": False, "team": False, "login_2fa": False,
        "notes_max_length": 500, "price": 0, "color": "#00cec9",
    },
    "premium": {
        "name": "Premium", "max_passwords": -1,
        "security_analysis": True, "password_length_max": 64,
        "categories": True, "export": True, "backup": True, "totp": True,
        "sync": True, "team": False, "login_2fa": True,
        "notes_max_length": 2000, "price": PLANES["premium_mensual"]["precio_cop"], "color": "#fd79a8",
    },
    "equipo": {
        "name": "Equipo", "max_passwords": -1,
        "security_analysis": True, "password_length_max": 64,
        "categories": True, "export": True, "backup": True, "totp": True,
        "sync": True, "team": True, "login_2fa": True,
        "notes_max_length": 2000, "price": TEAM_PLANES["equipo_3"]["precio_cop"], "color": "#74b9ff",
    },
    "developer": {
        "name": "Desarrollador", "max_passwords": -1,
        "security_analysis": True, "password_length_max": 128,
        "categories": True, "export": True, "backup": True, "totp": True,
        "sync": True, "team": True, "login_2fa": True,
        "notes_max_length": 500000, "price": 0, "color": "#6c5ce7",
    },
}


def get_features(version: str) -> dict:
    """Devuelve el diccionario de límites y funciones del plan indicado (o los de 'free' si el plan no existe)."""
    return VERSIONS.get(version, VERSIONS["free"])


# ══════════════════════════════════════════════
#  MARCA / COPYRIGHT
# ══════════════════════════════════════════════
APP_NAME = "CipherVault"
APP_VERSION = "3.3.1"   # build.ps1 la usa para nombrar el instalador
SUPPORT_EMAIL = "ciphervaultpass@gmail.com"
APP_AUTHOR = "S.C.A"
APP_COPYRIGHT_YEAR = "2026"
APP_COPYRIGHT_TEXT = (
    f"© {APP_COPYRIGHT_YEAR} {APP_AUTHOR} - {APP_NAME}. Todos los derechos "
    "reservados. Software con licencia comercial: queda prohibida su copia, "
    "distribución o modificación sin autorización expresa del autor."
)


# ══════════════════════════════════════════════
#  PALETA DE COLORES
# ══════════════════════════════════════════════
C = {
    "bg":        "#0f0f13",
    "card":      "#1a1a24",
    "card2":     "#22222f",
    "border":    "#2e2e40",
    "primary":   "#6c5ce7",
    "secondary": "#00cec9",
    "accent":    "#fd79a8",
    "success":   "#00b894",
    "warning":   "#fdcb6e",
    "danger":    "#e17055",
    "text":      "#f0f0f5",
    "muted":     "#8888aa",
    "wompi":     "#ff6b35",   # naranja Wompi
    "make":      "#6366f1",   # índigo Make
}


# ══════════════════════════════════════════════
#  APLICACIÓN PRINCIPAL
# ══════════════════════════════════════════════
class InlinePage(tk.Frame):
    """Pantalla dentro de la ventana principal que reemplaza a las antiguas ventanas
    flotantes (planes, licencia, detalles, editar, equipo...). Se dibuja encima del área de
    contenido con una barra «← Volver» y desplazamiento vertical, y acepta las mismas
    llamadas que un Toplevel (title, transient, grab_set... no hacen nada) para que el
    código que la llena no cambie. `destroy()` la cierra y deja ver lo que había debajo."""

    def __init__(self, app: "CipherVaultApp", host: tk.Misc):
        self._app = app
        self._closing = False
        self._on_close = None
        outer = tk.Frame(host, bg=C["bg"])
        outer.place(relx=0, rely=0, relwidth=1, relheight=1)
        outer.lift()
        self._outer = outer
        bar = tk.Frame(outer, bg=C["bg"])
        bar.pack(fill="x", pady=(0, 6))
        app._btn(bar, "← Volver", self._back).pack(side="left")
        self._title_lbl = tk.Label(bar, text="", bg=C["bg"], fg=C["muted"], font=("Segoe UI", 11, "bold"))
        self._title_lbl.pack(side="left", padx=12)
        self._canvas = tk.Canvas(outer, bg=C["bg"], highlightthickness=0, bd=0)
        self._scroll = ttk.Scrollbar(outer, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._scroll.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        super().__init__(self._canvas, bg=C["bg"])
        self._item = self._canvas.create_window(0, 0, window=self, anchor="nw")
        self._canvas.bind("<Configure>", self._fit, "+")
        tk.Frame.bind(self, "<Configure>", self._fit, "+")
        outer.bind("<Enter>", lambda _e: self._wheel(True))
        outer.bind("<Leave>", lambda _e: self._wheel(False))

    def _fit(self, _event=None):
        """Ajusta el ancho al área visible y muestra la barra solo si el contenido no cabe."""
        try:
            self._canvas.itemconfigure(self._item, width=self._canvas.winfo_width())
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
            needs = self.winfo_reqheight() > self._canvas.winfo_height() > 1
            if needs and not self._scroll.winfo_ismapped():
                self._scroll.pack(side="right", fill="y", before=self._canvas)
            elif not needs and self._scroll.winfo_ismapped():
                self._scroll.pack_forget()
                self._canvas.yview_moveto(0)
        except tk.TclError:
            pass

    # ── desplazamiento con la rueda (Windows, macOS y Linux) ──
    def _wheel(self, on: bool):
        try:
            if on:
                self.bind_all("<MouseWheel>", self._on_wheel)
                self.bind_all("<Button-4>", lambda _e: self._canvas.yview_scroll(-1, "units"))
                self.bind_all("<Button-5>", lambda _e: self._canvas.yview_scroll(1, "units"))
            else:
                for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                    self.unbind_all(seq)
        except tk.TclError:
            pass

    def _on_wheel(self, event):
        if self._canvas.winfo_height() >= self.winfo_reqheight():
            return
        delta = event.delta if sys.platform == "darwin" else event.delta / 120
        self._canvas.yview_scroll(int(-delta) or (-1 if event.delta > 0 else 1), "units")

    def _back(self):
        if self._on_close:
            self._on_close()
        else:
            self.destroy()

    # ── API compatible con Toplevel ──
    def title(self, text: str = ""):
        self._title_lbl.config(text=text)

    def protocol(self, name=None, func=None):
        if name == "WM_DELETE_WINDOW" and func:
            self._on_close = func

    def transient(self, *_a, **_k):
        pass

    def grab_set(self, *_a, **_k):
        pass

    def attributes(self, *_a, **_k):
        pass

    def resizable(self, *_a, **_k):
        pass

    def geometry(self, *_a, **_k):
        pass

    def minsize(self, *_a, **_k):
        pass

    def destroy(self):
        if self._closing:
            return tk.Frame.destroy(self)
        self._closing = True
        self._wheel(False)
        try:
            self._outer.destroy()          # destruye también esta página (es hija del lienzo)
        except tk.TclError:
            pass


class CipherVaultApp:
    """
    Aplicación de escritorio (Tkinter) de CipherVault.

    Controla todo el ciclo de vida de la interfaz: pantalla de login/registro,
    panel principal con pestañas (dashboard, generador, lista de contraseñas,
    análisis de seguridad, configuración, herramientas de desarrollador),
    compra de planes vía Wompi y activación automática de licencias vía
    Make (códigos de un solo uso). Cada contraseña guardada se cifra con Fernet usando una
    clave derivada de la contraseña maestra del usuario (ver `_vault_from_password`).
    """
    def __init__(self, root: tk.Tk):
        """Inicializa la ventana principal: variables de estado, escalado responsivo, base de datos local, detección de modo desarrollador, versión inicial, bloqueo por inactividad y pantalla de login."""
        self.root = root
        self.root.title("🔒 CipherVault – Gestor de Contraseñas")
        self._set_window_icon()
        self.current_user: dict | None = None
        self.selected_password_id: int | None = None
        self.password_sort_order = "service"
        self._tutorial_active = False
        self._tutorial_step = 0
        self._tutorial_windows: list[tk.Toplevel] = []
        self._last_activity = time.monotonic()
        # Un tutorial nunca debe permanecer sobre el escritorio al minimizar.
        self.root.bind("<Unmap>", self._on_root_unmap, add="+")
        # Los errores inesperados de la interfaz van al log y se muestran sin cerrar la app.
        self.root.report_callback_exception = self._report_callback_exception
        self._configure_responsive_ui()

        # La base de datos se prepara primero.
        self._ensure_db()
        self.is_developer = DeveloperLicenseManager.is_developer_machine()
        self.user_version = self._initial_version()

        # Pantalla completa
        try:
            self.root.state("zoomed")
        except Exception:
            self.root.geometry("{0}x{1}+0+0".format(
                self.root.winfo_screenwidth(),
                self.root.winfo_screenheight(),
            ))

        self._ensure_dev_license()
        self._load_config()
        self._setup_styles()
        self._arm_idle_lock()
        self._start_autotype()
        self._sync_status = ""
        self.root.after(self.SYNC_INTERVAL_MS, self._sync_loop)
        self.show_login()

    # ── errores y bloqueo por inactividad ─────

    def _report_callback_exception(self, exc_type, exc, tb):
        """Registra en el log cualquier excepción de un callback de Tk y avisa al usuario
        sin cerrar la aplicación."""
        log.error("Error inesperado en la interfaz", exc_info=(exc_type, exc, tb))
        try:
            messagebox.showerror(
                "Error inesperado",
                "Ocurrió un error inesperado. Tus datos no se modificaron.\n\n"
                f"Detalle técnico guardado en:\n{LOG_FILE}")
        except Exception:
            pass

    def _touch_activity(self, _event=None):
        """Marca actividad del usuario (teclado/ratón) para el bloqueo por inactividad."""
        self._last_activity = time.monotonic()

    def _arm_idle_lock(self):
        """Activa la vigilancia de inactividad: cualquier tecla, clic o movimiento
        reinicia el contador; cada 10 s se comprueba si ya pasó el tiempo configurado."""
        for sequence in ("<Any-KeyPress>", "<Any-Button>", "<Motion>"):
            self.root.bind_all(sequence, self._touch_activity, add="+")
        self.root.after(10_000, self._check_idle)

    def _lock_timeout_seconds(self) -> int:
        """Segundos de inactividad antes de bloquear (0 = desactivado)."""
        try:
            return max(0, int(self.config.get("lock_timeout", 300)))
        except (TypeError, ValueError):
            return 300

    def _check_idle(self):
        """Cierra la sesión si el usuario lleva más del tiempo configurado sin actividad."""
        try:
            timeout = self._lock_timeout_seconds()
            idle = time.monotonic() - self._last_activity
            if self.current_user and timeout and idle >= timeout:
                self._lock_session("Sesión bloqueada por inactividad. Vuelve a iniciar sesión.")
        finally:
            self.root.after(10_000, self._check_idle)

    def _lock_session(self, message: str):
        """Cierra ventanas emergentes, olvida la clave de la bóveda y vuelve al login."""
        for child in list(self.root.winfo_children()):
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except tk.TclError:
                    pass
        self._close_tutorial()
        self._logout()
        try:
            messagebox.showinfo("Bloqueado", message)
        except tk.TclError:
            pass

    # ── init helpers ──────────────────────────

    def _configure_responsive_ui(self):
        """Define una escala cómoda según la resolución del equipo.

        La escala se limita para mantener la interfaz legible tanto en
        portátiles pequeños como en pantallas de alta resolución.
        """
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.ui_scale = max(0.78, min(1.45,
            min(self.screen_width / 1600, self.screen_height / 900)))
        # Tk aplica esta escala a todas las fuentes (incluidas las creadas
        # directamente con font=("Segoe UI", ...)).
        self.root.tk.call("tk", "scaling", 1.3333 * self.ui_scale)

    def _s(self, value: int | float) -> int:
        """Convierte una medida diseñada para 1600×900 a la pantalla actual."""
        return max(1, round(value * self.ui_scale))

    def _inline_page(self) -> "InlinePage":
        """Pantalla dentro de la app (en lugar de una ventana flotante): sobre el área de
        contenido si la sesión está abierta, o sobre toda la ventana (inicio de sesión)."""
        host = getattr(self, "content_frame", None)
        try:
            if not (host is not None and self.current_user and host.winfo_exists()):
                host = self.root
        except tk.TclError:
            host = self.root
        return InlinePage(self, host)

    def _set_popup_geometry(self, window: tk.Toplevel, width: int, height: int):
        """Centra una ventana flotante sin que exceda la pantalla disponible."""
        if isinstance(window, InlinePage):
            return
        margin = self._s(32)
        popup_w = min(self._s(width), self.screen_width - margin * 2)
        popup_h = min(self._s(height), self.screen_height - margin * 2)
        x = max(margin, (self.screen_width - popup_w) // 2)
        y = max(margin, (self.screen_height - popup_h) // 2)
        window.geometry(f"{popup_w}x{popup_h}+{x}+{y}")
        window.minsize(min(popup_w, self._s(320)), min(popup_h, self._s(260)))

    def _set_window_icon(self):
        """Aplica el logo real como ícono de ventana/taskbar. Si falla
        (p.ej. plataforma sin soporte para .ico), no rompe la app."""
        ico_path = get_asset_path("icono.ico")
        if ico_path:
            try:
                self.root.iconbitmap(ico_path)
                return
            except Exception:
                pass
        # Fallback multiplataforma vía PNG si .ico no fue aplicable
        png_path = get_asset_path("icono_login.png")
        if png_path:
            try:
                self._window_icon_img = tk.PhotoImage(file=png_path)
                self.root.iconphoto(True, self._window_icon_img)
            except Exception:
                pass

    def _initial_version(self) -> str:
        """Determina la versión inicial antes de iniciar sesión: 'developer' en máquinas autorizadas o 'free'."""
        return "developer" if self.is_developer else "free"

    def _ensure_dev_license(self):
        """Crea el archivo de licencia de desarrollador la primera vez que se detecta una máquina autorizada."""
        if self.is_developer and not os.path.exists(LICENSE_FILE):
            DeveloperLicenseManager.create_license()
            log.info("Licencia de desarrollador creada")

    def _load_config(self):
        """Carga la configuración local del usuario (config.json), completando con valores por defecto las claves faltantes."""
        default = {
            "password_length": 16,
            "require_uppercase": True, "require_lowercase": True,
            "require_numbers": True, "require_symbols": True,
            "theme": "dark", "backup_enabled": True,
            "user_version": self.user_version,
            "password_sort_order": "service",
            "lock_timeout": 300,
            "autotype_enabled": True,
            "autotype_enter": False,
        }
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    self.config = {**default, **json.load(f)}
            else:
                self.config = default
        except Exception:
            self.config = default
        self.password_sort_order = self.config.get("password_sort_order", "service")

    def _save_config(self):
        """Guarda en disco la configuración actual (orden de la lista, versión del usuario, etc.)."""
        self.config["password_sort_order"] = self.password_sort_order
        self.config["user_version"] = self.user_version
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2)

    def _auto_backup(self):
        """Mantiene los últimos cinco respaldos de la bóveda local cifrada (y programa una
        sincronización, porque se llama después de cada cambio)."""
        if self.current_user:
            self._schedule_sync()
        if not self.current_user or not get_features(self.user_version).get("backup"):
            return
        backup_dir = DATA_PATH / "backups"
        backup_dir.mkdir(exist_ok=True)
        target = backup_dir / f"vault_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            with contextlib.closing(sqlite3.connect(DB_FILE)) as source, \
                    contextlib.closing(sqlite3.connect(str(target))) as destination:
                source.backup(destination)
            for old in sorted(backup_dir.glob("vault_*.db"))[:-5]:
                old.unlink(missing_ok=True)
        except (sqlite3.Error, OSError) as exc:
            log.warning("No se pudo crear el respaldo automático: %s", exc)

    # ── base de datos ──────────────────────────

    def _ensure_db(self):
        """
        Crea las tablas de la base de datos SQLite si no existen y aplica las migraciones
        de columnas e índices. Tablas: users, passwords, license_activations,
        login_attempts (bloqueo por intentos, persistente) y app_meta.
        """
        with db() as conn:
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.Error:
                pass
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    master_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_encrypted TEXT NOT NULL,
                    strength TEXT NOT NULL,
                    category TEXT DEFAULT 'General',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            existing = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
            for col, defval in [
                ("email",             "NULL"),
                ("version",           "'free'"),
                ("is_developer",      "0"),
                ("license_key",       "NULL"),
                ("license_expiry",    "NULL"),
                ("license_type",      "NULL"),
                ("payment_method",    "NULL"),
                ("payment_reference", "NULL"),
                ("payment_date",      "NULL"),
                ("vault_salt",        "NULL"),
                ("license_seal",      "NULL"),
                ("activation_hash",   "NULL"),   # hash del código canjeado: permite re-verificar la licencia
                ("hello_challenge",   "NULL"),   # reto aleatorio que firma Windows Hello
                ("hello_wrapped",     "NULL"),   # clave de la bóveda cifrada con la firma de Windows Hello
                ("sync_path",         "NULL"),   # archivo .cvsync (cifrado con la bóveda)
                ("sync_key",          "NULL"),   # clave del archivo de sincronización (cifrada con la bóveda)
                ("sync_salt",         "NULL"),
                ("sync_iterations",   "NULL"),
                ("team_priv",         "NULL"),   # clave privada X25519 del miembro (cifrada con la bóveda)
                ("team_pub",          "NULL"),   # clave pública (base64), de ella sale el código de miembro
                ("team_path",         "NULL"),   # archivo .cvteam del equipo (cifrado con la bóveda)
                ("login_totp",        "NULL"),   # clave 2FA del inicio de sesión (cifrada con la bóveda)
                ("login_totp_last",   "NULL"),   # último intervalo de 30 s usado (no se acepta dos veces)
                ("login_totp_backup", "NULL"),   # JSON con el hash de los códigos de respaldo sin usar
            ]:
                if col not in existing:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {defval}")

            pwd_cols = {row[1] for row in conn.execute("PRAGMA table_info(passwords)")}
            for col in ("url", "totp", "uid"):   # url y totp van cifrados (enc1:); uid identifica la entrada al sincronizar
                if col not in pwd_cols:
                    conn.execute(f"ALTER TABLE passwords ADD COLUMN {col} TEXT DEFAULT NULL")
            conn.execute("UPDATE passwords SET uid=lower(hex(randomblob(16))) WHERE uid IS NULL OR uid=''")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_tombstones (
                    user_id INTEGER NOT NULL,
                    uid TEXT NOT NULL,
                    deleted_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, uid)
                )
            """)
            # Toda entrada nueva recibe un uid; todo borrado deja una "lápida" para que la
            # sincronización lo propague a los otros equipos.
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_passwords_uid AFTER INSERT ON passwords
                WHEN NEW.uid IS NULL OR NEW.uid = ''
                BEGIN
                    UPDATE passwords SET uid = lower(hex(randomblob(16))) WHERE id = NEW.id;
                END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS trg_passwords_tombstone AFTER DELETE ON passwords
                WHEN OLD.uid IS NOT NULL
                BEGIN
                    INSERT OR REPLACE INTO sync_tombstones(user_id, uid, deleted_at)
                    VALUES (OLD.user_id, OLD.uid, CURRENT_TIMESTAMP);
                END
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS license_activations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    license_type TEXT NOT NULL,
                    duration TEXT,
                    expiry_date TIMESTAMP,
                    payment_method TEXT DEFAULT 'Wompi',
                    payment_reference TEXT,
                    notes TEXT,
                    activated_by TEXT DEFAULT 'codigo_activacion',
                    activation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    username TEXT PRIMARY KEY,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_passwords_user ON passwords(user_id)")
            try:
                # Un email = una cuenta, garantizado por la base de datos (no solo por la interfaz).
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email "
                             "ON users(email) WHERE email IS NOT NULL AND email <> ''")
            except sqlite3.IntegrityError:
                log.warning("Hay emails duplicados en users; no se pudo crear el índice único.")

    # ── bloqueo por intentos fallidos (persistente) ─────

    LOCK_AFTER_ATTEMPTS = 5

    def _lock_remaining(self, username: str) -> int:
        """Segundos que faltan para poder reintentar el login de ese usuario (0 = no bloqueado)."""
        with db() as conn:
            row = conn.execute("SELECT locked_until FROM login_attempts WHERE username=?",
                               (username.lower(),)).fetchone()
        if row and row[0] > time.time():
            return int(row[0] - time.time()) + 1
        return 0

    def _register_failure(self, username: str):
        """Cuenta un intento fallido; desde el quinto bloquea 30 s, 60 s, 2 min… (máx. 15 min).
        Se guarda en la base de datos, así que cerrar y abrir la app no lo reinicia."""
        key = username.lower()
        with db() as conn:
            row = conn.execute("SELECT attempts FROM login_attempts WHERE username=?", (key,)).fetchone()
            attempts = (row[0] if row else 0) + 1
            extra = attempts - self.LOCK_AFTER_ATTEMPTS
            locked_until = time.time() + min(900, 30 * (2 ** extra)) if extra >= 0 else 0
            conn.execute("INSERT INTO login_attempts(username, attempts, locked_until) VALUES(?,?,?) "
                         "ON CONFLICT(username) DO UPDATE SET attempts=excluded.attempts, "
                         "locked_until=excluded.locked_until", (key, attempts, locked_until))

    def _clear_failures(self, username: str):
        """Borra el contador de intentos fallidos tras un login correcto."""
        with db() as conn:
            conn.execute("DELETE FROM login_attempts WHERE username=?", (username.lower(),))

    def _migrate_security_material(self, user: dict, auth: "AuthResult", vault: Fernet) -> tuple[bool, int]:
        """
        Tras un login correcto: pasa la cuenta al formato v3 si hacía falta, cifra los datos
        guardados sin cifrar (versiones anteriores) y devuelve (hubo_cambios, ilegibles).

        IMPORTANTE: solo se cifra lo que NO parece un token Fernet. Un valor que empieza por
        'gAAAAA' y no se puede abrir con esta clave se deja intacto y se cuenta como ilegible:
        volver a cifrarlo lo dejaría inaccesible con la clave correcta.
        """
        changed = False
        unreadable = 0
        with db() as conn:
            if auth.needs_upgrade or not user.get("vault_salt"):
                conn.execute("UPDATE users SET password_hash=?, vault_salt=?, master_key='v3' WHERE id=?",
                             (_make_login_hash(auth.key), auth.vault_salt, user["id"]))
                changed = True
            rows = conn.execute(
                "SELECT id, service, username, password_encrypted, notes FROM passwords WHERE user_id=?",
                (user["id"],)).fetchall()
            for pid, service, username, value, notes in rows:
                updates = {}
                value = value if isinstance(value, str) else str(value or "")
                try:
                    vault.decrypt(value.encode("utf-8"))
                except (InvalidToken, ValueError):
                    if value.startswith("gAAAAA"):
                        unreadable += 1
                    else:   # texto plano heredado
                        updates["password_encrypted"] = vault.encrypt(value.encode("utf-8")).decode("ascii")
                for column, current in (("service", service), ("username", username), ("notes", notes)):
                    if current is not None and not str(current).startswith(ENC_PREFIX):
                        updates[column] = enc_text(vault, str(current))
                if updates:
                    assignments = ", ".join(f"{column}=?" for column in updates)
                    conn.execute(f"UPDATE passwords SET {assignments} WHERE id=?",
                                 (*updates.values(), pid))
                    changed = True
        return changed, unreadable

    # ── estilos ttk ───────────────────────────

    def _setup_styles(self):
        """Configura los estilos ttk (colores, fuentes, botones) según la paleta de la app y el color asociado al plan del usuario."""
        self.style = ttk.Style()
        self.style.theme_use("clam")

        ver_color = get_features(self.user_version).get("color", C["primary"])

        self.style.configure("TFrame",    background=C["bg"])
        self.style.configure("TLabel",    background=C["bg"], foreground=C["text"], font=("Segoe UI", 11))
        self.style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), foreground=C["primary"], background=C["bg"])

        for name, bg, fg in [
            ("Primary",   ver_color,    "#000000"),
            ("Secondary", C["card2"],   C["text"]),
            ("Danger",    C["danger"],  C["text"]),
            ("Wompi",     C["wompi"],   "#ffffff"),
            ("Make",      C["make"],    "#ffffff"),
            ("Nav",       C["card"],    C["text"]),
            ("Dev",       C["primary"], "#ffffff"),
        ]:
            self.style.configure(f"{name}.TButton",
                background=bg, foreground=fg,
                font=("Segoe UI", 11, "bold"),
                padding=(self._s(16), self._s(10)), borderwidth=0, relief="flat", focuscolor="none")
            self.style.map(f"{name}.TButton",
                background=[("active", self._brighten(bg, 20))])

        self.style.configure("Nav.TButton",
            font=("Segoe UI", 11), padding=(self._s(14), self._s(10)), anchor="w")

        self.style.configure("TEntry",
            font=("Segoe UI", 11),
            fieldbackground=C["card2"],
            foreground=C["text"],
            borderwidth=1, relief="flat", padding=(self._s(10), self._s(8)))

        self.style.configure("TCombobox",
            font=("Segoe UI", 11),
            fieldbackground=C["card2"],
            foreground=C["text"])

        self.style.configure("Treeview",
            background=C["card"], fieldbackground=C["card"],
            foreground=C["text"], rowheight=self._s(28), font=("Segoe UI", 10))
        self.style.configure("Treeview.Heading",
            background=C["card2"], foreground=C["muted"],
            font=("Segoe UI", 10, "bold"))

    @staticmethod
    def _brighten(hex_color: str, amount: int) -> str:
        """Aclara un color hexadecimal sumando `amount` a cada canal RGB; se usa para el estado hover/activo de los botones."""
        try:
            h = hex_color.lstrip("#")
            r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
            r = min(255, r + amount)
            g = min(255, g + amount)
            b = min(255, b + amount)
            return f"#{r:02x}{g:02x}{b:02x}"
        except Exception:
            return hex_color

    # ── utilidades de UI ──────────────────────

    def _clear(self):
        """Elimina todos los widgets hijos directos de la ventana principal, para cambiar de pantalla por completo (p. ej. login ↔ app)."""
        for w in self.root.winfo_children():
            w.destroy()

    def _clear_content(self):
        """Elimina el contenido de la pestaña actual (content_frame) para dibujar una nueva pestaña encima."""
        if hasattr(self, "content_frame"):
            for w in self.content_frame.winfo_children():
                w.destroy()

    def _card(self, parent, **kwargs) -> tk.Frame:
        """Crea un Frame con el estilo de 'tarjeta' (fondo y relleno) usado en toda la interfaz."""
        defaults = dict(bg=C["card"], padx=20, pady=16)
        defaults.update(kwargs)
        return tk.Frame(parent, **defaults)

    def _label(self, parent, text, font_size=11, bold=False, color=None, **kwargs):
        """Crea una etiqueta (Label) con la tipografía y color estándar de la app."""
        font = ("Segoe UI", font_size, "bold" if bold else "normal")
        fg   = color or C["text"]
        return tk.Label(parent, text=text, font=font, bg=parent.cget("bg"),
                        fg=fg, **kwargs)

    def _btn(self, parent, text, command, style="Secondary.TButton", **kwargs):
        """Crea un botón ttk con el estilo indicado (por defecto, el estilo secundario)."""
        return ttk.Button(parent, text=text, command=command, style=style, **kwargs)

    # ── tutorial guiado ──────────────────────

    def _start_tutorial(self):
        """Inicia un recorrido visual de las funciones principales.

        El tutorial se muestra encima de la aplicación para que el usuario no
        pierda de vista el control que se está describiendo.
        """
        self._close_tutorial()
        self._tutorial_active = True
        self._tutorial_step = 0
        self._tutorial_steps = [
            {
                "target": "tutorial_nav_button",
                "title": "Bienvenido a CipherVault",
                "text": "Este recorrido te enseña a crear, guardar y encontrar tus contraseñas. Puedes abrirlo de nuevo cuando quieras desde este botón.",
            },
            {
                "target": "dashboard_stats",
                "action": self._tab_dashboard,
                "title": "1. Revisa el estado de tu bóveda",
                "text": "El panel muestra cuántas contraseñas tienes guardadas, el límite de tu plan, cuántas son fuertes y tu puntuación general de seguridad.",
            },
            {
                "target": "nav_generator",
                "title": "2. Genera una contraseña segura",
                "text": "Abre el generador para crear una contraseña aleatoria y robusta. No necesitas inventarla tú mismo.",
            },
            {
                "target": "gen_config_card",
                "action": self._tab_generator,
                "title": "3. Ajusta las reglas",
                "text": "Elige la longitud y los tipos de caracteres. Una mayor longitud y la combinación de letras, números y símbolos mejora la seguridad.",
            },
            {
                "target": "gen_actions_row",
                "title": "4. Genera, copia o guarda",
                "text": "Pulsa «Generar» hasta obtener una clave nueva. Puedes copiarla temporalmente o elegir «Guardar» para llevarla al formulario de la bóveda.",
            },
            {
                "target": "nav_passwords",
                "action": self._tab_list,
                "title": "5. Consulta tu bóveda",
                "text": "Aquí están todas tus credenciales cifradas. Desde esta sección también puedes buscar, ordenar, ver detalles, editar o eliminar un registro.",
            },
            {
                "target": "list_add_button",
                "title": "6. Añade una credencial",
                "text": "Usa «Agregar nueva» para guardar una cuenta manualmente. Completa servicio, usuario o email y contraseña; añade categoría y notas si están disponibles en tu plan.",
            },
            {
                "target": "list_search_entry",
                "title": "7. Encuentra una cuenta rápidamente",
                "text": "Escribe parte del servicio o del usuario en este buscador. La tabla se filtra al instante. Selecciona una fila para abrir sus detalles, editarla o eliminarla.",
            },
            {
                "target": "nav_settings",
                "action": self._tab_settings,
                "title": "8. Personaliza la aplicación",
                "text": "En Configuración defines la longitud predeterminada que utilizará el generador. También puedes consultar las funciones incluidas en tu plan.",
            },
        ]
        self._show_tutorial_step()

    def _close_tutorial(self):
        """Cierra el tutorial guiado y destruye sus ventanas flotantes (sombra, marco y globo de texto)."""
        self._tutorial_active = False
        for window in getattr(self, "_tutorial_windows", []):
            try:
                window.destroy()
            except tk.TclError:
                pass
        self._tutorial_windows = []

    def _on_root_unmap(self, event):
        """Cierra el tutorial únicamente al minimizar la ventana principal."""
        if event.widget is self.root and self._tutorial_active:
            # Algunos cambios de foco de ventanas transitorias generan Unmap
            # momentáneamente. Comprobamos el estado real en el siguiente ciclo
            # para no cerrar el tutorial justo al abrirlo.
            self.root.after_idle(self._close_tutorial_if_minimized)

    def _close_tutorial_if_minimized(self):
        """Verifica si la ventana principal quedó minimizada y, en ese caso, cierra el tutorial para que no quede flotando sobre el escritorio."""
        if self._tutorial_active and self.root.state() == "iconic":
            self._close_tutorial()

    def _show_tutorial_step(self):
        """Muestra el paso actual del tutorial: ejecuta la acción asociada (p. ej. cambiar de pestaña) y programa el dibujo del resaltado."""
        if not self._tutorial_active:
            return
        for window in self._tutorial_windows:
            try:
                window.destroy()
            except tk.TclError:
                pass
        self._tutorial_windows = []

        step = self._tutorial_steps[self._tutorial_step]
        if step.get("action"):
            step["action"]()
        self.root.update_idletasks()
        # Esperar a que Tk calcule la geometría tras cambiar de sección.
        self.root.after(80, self._draw_tutorial_step)

    def _draw_tutorial_step(self):
        """
        Dibuja el resaltado visual del paso actual del tutorial: una sombra semitransparente
        sobre toda la app, un marco luminoso alrededor del widget señalado y un globo de
        texto con la explicación y los botones de navegación (anterior/siguiente/salir).
        """
        if not self._tutorial_active:
            return
        step = self._tutorial_steps[self._tutorial_step]
        target = getattr(self, step["target"], None)
        if not target or not target.winfo_exists():
            self._close_tutorial()
            return
        self.root.update_idletasks()
        x, y = target.winfo_rootx(), target.winfo_rooty()
        w, h = max(target.winfo_width(), 1), max(target.winfo_height(), 1)

        # Sombra ligada a CipherVault, no "siempre encima". Así se oscurece la
        # aplicación sin quedar sobre otras ventanas cuando se minimiza.
        shade = tk.Toplevel(self.root)
        shade.overrideredirect(True)
        shade.transient(self.root)
        shade.configure(bg="#000000")
        try:
            shade.attributes("-alpha", 0.42)
        except tk.TclError:
            pass
        shade.geometry(
            f"{self.root.winfo_width()}x{self.root.winfo_height()}+"
            f"{self.root.winfo_rootx()}+{self.root.winfo_rooty()}"
        )
        shade.lift(self.root)

        # Marco grueso y luminoso para que el elemento explicado se distinga
        # claramente sobre el fondo atenuado.
        pad, glow_width = self._s(7), self._s(4)
        border_parts = []
        for part_w, part_h, part_x, part_y in [
            (w + pad * 2, glow_width, x - pad, y - pad),
            (w + pad * 2, glow_width, x - pad, y + h + pad - glow_width),
            (glow_width, h + pad * 2, x - pad, y - pad),
            (glow_width, h + pad * 2, x + w + pad - glow_width, y - pad),
        ]:
            border = tk.Toplevel(self.root)
            border.overrideredirect(True)
            border.transient(self.root)
            border.configure(bg=C["warning"])
            border.geometry(f"{part_w}x{part_h}+{part_x}+{part_y}")
            border.lift(shade)
            border_parts.append(border)

        bubble = tk.Toplevel(self.root)
        bubble.overrideredirect(True)
        bubble.transient(self.root)
        bubble.configure(bg=C["primary"])
        bubble_width, bubble_height = self._s(440), self._s(255)
        root_x, root_y = self.root.winfo_rootx(), self.root.winfo_rooty()
        max_x = root_x + self.root.winfo_width() - bubble_width - 16
        bubble_x = min(max(x + w + 20, root_x + 16), max_x)
        bubble_y = y if y + bubble_height <= root_y + self.root.winfo_height() - 16 else max(root_y + 16, y - bubble_height - 18)
        bubble.geometry(f"{bubble_width}x{bubble_height}+{bubble_x}+{bubble_y}")

        card = tk.Frame(bubble, bg=C["card"], padx=20, pady=16)
        edge = self._s(3)
        card.place(x=edge, y=edge, width=bubble_width - edge * 2, height=bubble_height - edge * 2)
        self._label(card, f"Paso {self._tutorial_step + 1} de {len(self._tutorial_steps)}", font_size=9,
                    bold=True, color=C["primary"]).pack(anchor="w")
        self._label(card, step["title"], font_size=14, bold=True).pack(anchor="w", pady=(5, 8))
        self._label(card, step["text"], font_size=11, color=C["text"], justify="left",
                    wraplength=self._s(390)).pack(anchor="w", fill="x")
        buttons = tk.Frame(card, bg=C["card"])
        buttons.pack(side="bottom", fill="x", pady=(16, 0))
        self._btn(buttons, "Salir", self._close_tutorial, "Danger.TButton", width=11).pack(side="left")
        if self._tutorial_step:
            self._btn(buttons, "← Anterior", self._tutorial_previous, width=12).pack(side="right", padx=(8, 0))
        next_text = "Finalizar ✓" if self._tutorial_step == len(self._tutorial_steps) - 1 else "Siguiente →"
        self._btn(buttons, next_text, self._tutorial_next, "Primary.TButton", width=13).pack(side="right")
        # El globo se eleva sobre la sombra y el marco, sin atributo topmost.
        bubble.lift(shade)
        bubble.focus_set()

        self._tutorial_windows = [shade, *border_parts, bubble]

    def _tutorial_next(self):
        """Avanza al siguiente paso del tutorial, o lo cierra si ya estaba en el último."""
        if self._tutorial_step >= len(self._tutorial_steps) - 1:
            self._close_tutorial()
            return
        self._tutorial_step += 1
        self._show_tutorial_step()

    def _tutorial_previous(self):
        """Retrocede al paso anterior del tutorial."""
        if self._tutorial_step:
            self._tutorial_step -= 1
            self._show_tutorial_step()

    # ─────────────────────────────────────────
    #  PANTALLA DE LOGIN — limpia y simple
    # ─────────────────────────────────────────
    def show_login(self):
        """Dibuja la pantalla de inicio de sesión / registro: logo, formulario de usuario, email y contraseña maestra, botón de compra de plan y accesos secundarios (licencia, dev panel, salir)."""
        self._clear()
        self._setup_styles()

        outer = tk.Frame(self.root, bg=C["bg"])
        outer.pack(expand=True, fill="both")

        # pie de pantalla: logo + copyright juntos, siempre abajo
        footer = tk.Frame(outer, bg=C["bg"])
        footer.pack(side="bottom", pady=10)

        footer_logo_path = get_asset_path("icono_footer.png")
        if footer_logo_path:
            try:
                self._login_footer_logo_img = tk.PhotoImage(file=footer_logo_path)
                tk.Label(footer, image=self._login_footer_logo_img,
                         bg=C["bg"]).pack(side="left", padx=(0, 6))
            except Exception:
                pass
        tk.Label(footer, text=APP_COPYRIGHT_TEXT, font=("Segoe UI", 8),
                 bg=C["bg"], fg=C["muted"], justify="left",
                 wraplength=self.screen_width - 100).pack(side="left")

        col = tk.Frame(outer, bg=C["bg"])
        col.place(relx=0.5, rely=0.5, anchor="center")

        # icono + titulo
        logo_frame = tk.Frame(col, bg=C["bg"])
        logo_frame.pack()

        self._label(logo_frame, "\U0001F512", font_size=56).pack()

        self._label(logo_frame, "CipherVault", font_size=28, bold=True,
                    color=C["primary"]).pack(pady=(4, 0))
        self._label(logo_frame, "Gestor de contraseñas seguras",
                    color=C["muted"]).pack(pady=(0, 8))

        # badge de estado (solo si aplica)
        if self.is_developer:
            self._badge(logo_frame, "MODO DESARROLLADOR", C["primary"])

        # formulario
        form = self._card(col, padx=32, pady=28)
        form.pack(pady=20, ipadx=10)

        self._label(form, "Usuario", bold=True, color=C["muted"]).pack(anchor="w", pady=(0, 4))
        self.entry_user = ttk.Entry(form, width=28, font=("Segoe UI", 12))
        self.entry_user.pack(fill="x", pady=(0, 14))

        self._label(form, "Email (para crear cuenta y activar tu plan)",
                    bold=True, color=C["muted"]).pack(anchor="w", pady=(0, 4))
        self.entry_email = ttk.Entry(form, width=28, font=("Segoe UI", 12))
        self.entry_email.pack(fill="x", pady=(0, 14))

        self._label(form, "Contraseña maestra", bold=True, color=C["muted"]).pack(anchor="w", pady=(0, 4))

        pwd_row = tk.Frame(form, bg=C["card"])
        pwd_row.pack(fill="x", pady=(0, 22))
        self.entry_pass = ttk.Entry(pwd_row, show="\u2022", font=("Segoe UI", 12))
        self.entry_pass.pack(side="left", fill="x", expand=True)
        self._vis_btn = tk.Button(pwd_row, text="\U0001F441",
                                  command=self._toggle_login_pass,
                                  bg=C["card2"], fg=C["muted"],
                                  font=("Segoe UI", 10), relief="flat",
                                  padx=6, cursor="hand2")
        self._vis_btn.pack(side="right", padx=(4, 0))

        # botones principales
        row = tk.Frame(form, bg=C["card"])
        row.pack()
        self._btn(row, "Iniciar sesión", self._login, "Primary.TButton").pack(side="left", padx=4)
        self._btn(row, "Crear cuenta",   self._register).pack(side="left", padx=4)
        if self._hello_users():
            self._btn(form, "🪟 Entrar con Windows Hello", self._login_hello).pack(fill="x", pady=(12, 0))

        # ── Un unico boton de planes, claro y directo ──
        plan_btn_row = tk.Frame(col, bg=C["bg"])
        plan_btn_row.pack(pady=(4, 12))

        if not self.is_developer:
            tk.Button(plan_btn_row,
                      text="\U0001F48E  Comprar plan",
                      command=self._show_plans_screen,
                      bg=C["wompi"], fg="#ffffff",
                      font=("Segoe UI", 12, "bold"),
                      relief="flat", padx=24, pady=10,
                      cursor="hand2").pack()

        # botones secundarios, discretos
        row2 = tk.Frame(col, bg=C["bg"])
        row2.pack()
        if self.is_developer:
            self._btn(row2, "Dev Panel", self._show_dev_panel, "Dev.TButton").pack(side="left", padx=4)
        self._btn(row2, "Mi licencia", self._show_license_info).pack(side="left", padx=4)
        self._btn(row2, "Salir", self.root.quit, "Danger.TButton").pack(side="left", padx=4)

        self.entry_pass.bind("<Return>", lambda _: self._login())
        if self.is_developer:
            dev_user, _ = DeveloperLicenseManager.get_dev_credentials()
            self.entry_user.insert(0, dev_user or "admin")
            self.entry_pass.focus()
        else:
            self.entry_user.focus()

    def _toggle_login_pass(self):
        """Alterna visibilidad de la contraseña en el login."""
        if self.entry_pass.cget("show") == "\u2022":
            self.entry_pass.config(show="")
            self._vis_btn.config(text="\U0001F648")
        else:
            self.entry_pass.config(show="\u2022")
            self._vis_btn.config(text="\U0001F441")

    def _badge(self, parent, text, color):
        """Muestra una pequeña insignia de color con texto (p. ej. "MODO DESARROLLADOR")."""
        f = tk.Frame(parent, bg=color, padx=10, pady=4)
        f.pack(pady=4)
        tk.Label(f, text=text, font=("Segoe UI", 9, "bold"), bg=color, fg="#000000").pack()


    # ─────────────────────────────────────────
    #  AUTENTICACIÓN
    # ─────────────────────────────────────────
    def _login(self):
        """
        Valida usuario y contraseña maestra. Tras 5 fallos seguidos bloquea ese usuario un
        tiempo creciente (persistente). Con la clave correcta abre la bóveda, migra datos
        antiguos y calcula el plan REAL (sello de licencia y vencimiento).
        """
        uname = self.entry_user.get().strip()
        pwd   = self.entry_pass.get()
        if not uname or not pwd:
            messagebox.showerror("Error", "Completa usuario y contraseña.")
            return
        try:
            remaining = self._lock_remaining(uname)
            if remaining:
                messagebox.showerror("Espera un momento",
                                     f"Demasiados intentos. Intenta de nuevo en {remaining} segundos.")
                return
            with db() as conn:
                user = get_user_by_name(conn, uname)
        except sqlite3.Error:
            log.exception("Error de base de datos en el login")
            messagebox.showerror("Error", "No se pudo leer la base de datos local. Revisa el archivo de registro.")
            return

        # Mismo mensaje para "no existe" y "clave incorrecta": no revela qué usuarios hay.
        auth = authenticate(pwd, user) if user else AuthResult(False)
        if not auth.ok:
            self._register_failure(uname)
            messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
            return
        if user.get("login_totp") and not self._check_login_2fa(user, auth):
            return
        self._clear_failures(uname)
        self._open_session(user, auth)

    def _check_login_2fa(self, user: dict, auth: "AuthResult") -> bool:
        """Segundo paso del inicio de sesión: pide el código de 6 dígitos de la app de
        autenticación (o un código de respaldo). Un código errado cuenta como intento fallido."""
        try:
            secret = dec_text(_fernet_from_key(auth.key), user["login_totp"])
        except Exception:  # noqa: BLE001
            log.exception("No se pudo leer la clave 2FA del inicio de sesión")
            secret = ""
        if not secret:
            messagebox.showerror("Verificación en dos pasos",
                                 "No se pudo leer la configuración de verificación en dos pasos. "
                                 "Entra con un código de respaldo o revisa el archivo de registro.")
        code = simpledialog.askstring(
            "Verificación en dos pasos",
            "Escribe el código de 6 dígitos de tu app de autenticación\n"
            "(o uno de tus códigos de respaldo):", parent=self.root)
        if code is None:
            return False
        if self._consume_login_code(user, secret, code):
            return True
        self._register_failure(user["username"])
        messagebox.showerror("Error", "El código no es correcto o ya se usó. Revisa que la hora de tu "
                                      "celular y de este computador estén bien.")
        return False

    def _consume_login_code(self, user: dict, secret: str, code: str) -> bool:
        """Valida un código TOTP (sin repetir) o un código de respaldo (y lo gasta)."""
        last = user.get("login_totp_last")
        last = int(last) if str(last or "").isdigit() else None
        counter = cvx.verify_login_totp(secret, code, last) if secret else None
        with db() as conn:
            if counter is not None:
                conn.execute("UPDATE users SET login_totp_last=? WHERE id=?", (str(counter), user["id"]))
                return True
            try:
                backups = json.loads(user.get("login_totp_backup") or "[]")
            except ValueError:
                backups = []
            digest = cvx.hash_backup_code(user["id"], code)
            if len(cvx.normalize_backup_code(code)) == 8 and digest in backups:
                backups.remove(digest)
                conn.execute("UPDATE users SET login_totp_backup=? WHERE id=?", (json.dumps(backups), user["id"]))
                log.info("Inicio de sesión con código de respaldo (%d restantes)", len(backups))
                if len(backups) <= 2:
                    self.root.after(1500, lambda: messagebox.showwarning(
                        "Códigos de respaldo",
                        f"Te quedan {len(backups)} código(s) de respaldo. Genera nuevos en Configuración."))
                return True
        return False

    def _open_session(self, user: dict, auth: "AuthResult"):
        """Abre la sesión de un usuario ya autenticado: prepara la bóveda, migra datos
        anteriores, calcula el plan efectivo y muestra el panel principal."""
        vault = _fernet_from_key(auth.key)
        migrated, unreadable = self._migrate_security_material(user, auth, vault)

        with db() as conn:
            user = get_user_by_id(conn, user["id"])
            version, expiry_str, status = compute_effective_version(user)
        if status == "tampered":
            log.warning("Licencia alterada en la base de datos del usuario %s; se aplica plan gratuito", user["username"])
        is_dev = version == "developer"

        self.user_version = version
        self.current_user = {
            "id":          user["id"],
            "username":    user["username"],
            "email":       (user.get("email") or "").strip(),
            "master_key":  user.get("master_key", ""),
            "vault":       vault,
            "vault_key":   auth.key,          # para activar Windows Hello sin volver a derivarla
            "version":     version,
            "is_developer": is_dev,
            "license_expiry": expiry_str,
        }
        self._touch_activity()
        self._setup_styles()
        self._save_config()
        self._show_main()
        self._schedule_sync(500)
        if status == "tampered" and user.get("activation_hash"):
            self._try_license_repair(user["id"])
        elif status == "tampered":
            messagebox.showwarning(
                "Licencia no válida",
                "No se pudo validar la licencia guardada en este equipo y se aplicó el plan gratuito. "
                "Si pagaste, vuelve a introducir tu código en «Activar licencia».")
        elif status == "expired" and (user.get("version") in REDEEMABLE_PLANS):
            messagebox.showinfo("Licencia vencida",
                                "Tu plan venció y la cuenta volvió al plan gratuito. Tus contraseñas siguen "
                                "guardadas; renueva tu plan para recuperar todas las funciones.")
        if migrated:
            messagebox.showinfo("Seguridad actualizada",
                                "Tus datos locales fueron migrados al formato cifrado más reciente.")
        if unreadable:
            messagebox.showwarning(
                "Entradas ilegibles",
                f"{unreadable} contraseña(s) no se pueden descifrar con esta contraseña maestra "
                "(probablemente se guardaron con otra). No se modificaron ni se borraron.")

    def _try_license_repair(self, user_id: int):
        """Re-verifica en segundo plano una licencia cuyo sello local no cuadra
        (ver LicenseActivationManager.repair) y, si Make la confirma, la restaura."""
        def worker():
            try:
                result, error = LicenseActivationManager.repair(user_id), None
            except ActivationError as exc:
                result, error = None, str(exc)
            except Exception:
                log.exception("Fallo inesperado reparando la licencia")
                result, error = None, "Ocurrió un error inesperado. Revisa el archivo de registro."

            def finish():
                if not self.current_user or self.current_user.get("id") != user_id:
                    return
                if result:
                    self._refresh_license_state()
                    messagebox.showinfo(
                        "Licencia restaurada",
                        f"Tu plan {get_features(result['plan'])['name']} se verificó de nuevo con el "
                        "servidor y quedó activo.")
                else:
                    messagebox.showwarning(
                        "Licencia no válida",
                        "No se pudo validar la licencia guardada en este equipo y se aplicó el plan "
                        "gratuito.\n\n" + (error or "") +
                        "\n\nCuando tengas conexión, vuelve a iniciar sesión o pega tu código en «Activar licencia».")
            try:
                self.root.after(0, finish)
            except Exception:
                pass

        threading.Thread(target=worker, daemon=True, name="license-repair").start()

    USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")

    def _register(self):
        """
        Crea una cuenta nueva: valida usuario (3-32 letras, números, _ . -), email y
        longitud mínima de la contraseña maestra (12). Un email solo puede tener una cuenta
        (lo garantiza un índice único). No activa ningún plan: eso se hace con el código
        de activación que llega por correo tras pagar.
        """
        uname = self.entry_user.get().strip()
        email = self.entry_email.get().strip().lower()
        pwd   = self.entry_pass.get()

        if not uname or not pwd:
            messagebox.showerror("Error", "Completa usuario y contraseña.")
            return
        if not self.USERNAME_RE.match(uname):
            messagebox.showerror("Error", "El usuario debe tener entre 3 y 32 caracteres: "
                                          "letras, números, punto, guion o guion bajo.")
            return
        if not email or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            messagebox.showerror("Error", "Ingresa un email válido. Lo necesitas para activar tu plan "
                                           "con el código que recibirás por correo al pagar.")
            return
        if len(pwd) < 12:
            messagebox.showerror("Error", "La contraseña maestra debe tener al menos 12 caracteres.")
            return

        vault_salt = _b64(os.urandom(16))
        key = _derive_vault_key(pwd, vault_salt)
        is_dev = uname.lower() in ["admin", "developer", "owner", "dev"] and self.is_developer
        version = "developer" if is_dev else "free"
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users (username,email,password_hash,master_key,vault_salt,version,is_developer) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (uname, email, _make_login_hash(key), "v3", vault_salt, version, int(is_dev)))
        except sqlite3.IntegrityError as exc:
            if "email" in str(exc).lower():
                messagebox.showerror("Error", "Ya existe una cuenta registrada con ese email.")
            else:
                messagebox.showerror("Error", "Ese usuario ya existe.")
            return
        log.info("Cuenta creada: %s", uname)
        messagebox.showinfo("Cuenta creada",
            f"✅ Cuenta '{uname}' creada. Plan inicial: {version.upper()}\n\n"
            "Cuando compres un plan, paga en Wompi con este mismo email: te llegará un código "
            "de activación por correo que pegarás en «Activar licencia».")
        if messagebox.askyesno(
                "Kit de emergencia",
                "Si olvidas tu contraseña maestra, nadie puede recuperar tus contraseñas.\n\n"
                "¿Quieres guardar ahora tu kit de emergencia (PDF para imprimir y anotar la "
                "contraseña a mano)?"):
            self._save_emergency_kit(uname, email)
        self.entry_pass.delete(0, "end")
        self.entry_user.focus()

    def _activate_license_dialog(self):
        """Ventana para pegar el código de activación recibido por correo y activar el plan."""
        if not self.current_user:
            messagebox.showinfo("Inicia sesión",
                                "Inicia sesión con tu cuenta (la del email con el que pagaste) y "
                                "luego usa «Activar licencia».")
            return
        user_email = self.current_user.get("email", "")

        win = self._inline_page()
        win.title("🔑 Activar licencia")
        self._set_popup_geometry(win, 520, 380)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, "🔑 Activar licencia", font_size=18, bold=True,
                    color=C["primary"]).pack(pady=(22, 4))
        self._label(win, f"Cuenta: {self.current_user['username']}  ·  Email: {user_email or '—'}",
                    color=C["muted"], font_size=9).pack()

        body = self._card(win, padx=24, pady=18)
        body.pack(fill="x", padx=24, pady=14)
        self._label(body, f"Pega el código que te enviamos por correo después de pagar (sirve hasta en {MAX_DEVICES} equipos tuyos):",
                    color=C["text"], font_size=10).pack(anchor="w", pady=(0, 8))
        code_var = tk.StringVar()
        entry = ttk.Entry(body, textvariable=code_var, font=("Consolas", 13), width=30)
        entry.pack(fill="x")
        entry.focus()
        email_var = tk.StringVar(value=user_email)
        if not user_email:
            # Cuenta sin email (p. ej. creada antes de que fuera obligatorio): se pide aquí
            # en lugar de fallar con un mensaje que no dice qué hacer.
            self._label(body, "Tu cuenta no tiene email. Escribe el email con el que pagaste "
                              "(al que te llegó el código):",
                        color=C["text"], font_size=10, wraplength=self._s(420),
                        justify="left").pack(anchor="w", pady=(10, 4))
            ttk.Entry(body, textvariable=email_var, font=("Segoe UI", 11), width=30).pack(fill="x")
        status = tk.StringVar(value="")
        self._label(body, "", color=C["warning"], font_size=9, wraplength=self._s(420),
                    justify="left", textvariable=status).pack(anchor="w", pady=(10, 0))

        busy = {"on": False}

        def activate():
            if busy["on"]:
                return
            code = code_var.get()
            email = email_var.get().strip().lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                status.set("Escribe un email válido: el mismo al que te llegó el código.")
                return
            username = self.current_user["username"]
            if email != user_email.lower():
                try:
                    with db() as conn:
                        taken = conn.execute("SELECT 1 FROM users WHERE email=? AND id<>?",
                                             (email, self.current_user["id"])).fetchone()
                        if taken:
                            status.set("Ese email ya pertenece a otra cuenta de este equipo. "
                                       "Inicia sesión con esa cuenta para activar el código.")
                            return
                        conn.execute("UPDATE users SET email=? WHERE id=?", (email, self.current_user["id"]))
                    self.current_user["email"] = email
                except sqlite3.Error:
                    log.exception("No se pudo guardar el email de la cuenta")
                    status.set("No se pudo guardar el email. Revisa el archivo de registro.")
                    return
            busy["on"] = True
            status.set("Verificando código…")

            def worker():
                try:
                    result, error = LicenseActivationManager.redeem(code, username, email), None
                except ActivationError as exc:
                    log.info("Activación fallida para %s: %s", username, exc)
                    result, error = None, str(exc)
                    if "no es válido" in error:
                        error += f"\n(Se verificó con el email: {email})"
                except Exception:
                    log.exception("Fallo inesperado al activar la licencia")
                    result, error = None, "Ocurrió un error inesperado. Revisa el archivo de registro."

                def finish():
                    busy["on"] = False
                    if not win.winfo_exists():
                        return
                    if error:
                        status.set(error)
                        return
                    self._refresh_license_state()
                    win.destroy()
                    until = result["expiry"].strftime("%d/%m/%Y") if result.get("expiry") else "—"
                    if result.get("repaired"):
                        messagebox.showinfo("Licencia restaurada",
                                            f"Tu plan {get_features(result['plan'])['name']} quedó activo de nuevo "
                                            f"(vigente hasta {until}).")
                    elif result["already"]:
                        messagebox.showinfo("Código ya canjeado",
                                            f"Este código ya estaba activado en esta cuenta (vigente hasta {until}).")
                    else:
                        messagebox.showinfo("¡Licencia activada!",
                                            f"Plan {get_features(result['plan'])['name']} activo hasta {until}.")
                self.root.after(0, finish)

            threading.Thread(target=worker, daemon=True, name="license-activation").start()

        entry.bind("<Return>", lambda _e: activate())
        btn_r = tk.Frame(win, bg=C["bg"])
        btn_r.pack(pady=6)
        self._btn(btn_r, "✅ Activar", activate, "Primary.TButton").pack(side="left", padx=6)
        self._btn(btn_r, "↩️ Cancelar", win.destroy).pack(side="left", padx=6)

    def _refresh_license_state(self):
        """Vuelve a calcular el plan de la sesión actual desde la base de datos (tras activar un código)."""
        if not self.current_user:
            return
        with db() as conn:
            user = get_user_by_id(conn, self.current_user["id"])
        version, expiry_str, _status = compute_effective_version(user)
        self.user_version = version
        self.current_user["version"] = version
        self.current_user["license_expiry"] = expiry_str
        self._show_main()

    # ─────────────────────────────────────────
    #  DASHBOARD PRINCIPAL
    # ─────────────────────────────────────────
    def _show_main(self):
        """Dibuja el panel principal tras iniciar sesión: barra lateral con navegación (según las funciones habilitadas por el plan) y área de contenido, mostrando el dashboard por defecto."""
        self._clear()

        root_frame = tk.Frame(self.root, bg=C["bg"])
        root_frame.pack(fill="both", expand=True)

        # ── sidebar ───────────────────────────
        sidebar = tk.Frame(root_frame, bg=C["card"], width=self._s(240))
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # header sidebar
        hdr = tk.Frame(sidebar, bg=get_features(self.user_version)["color"], height=90)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        self._label(hdr, f"👋 {self.current_user['username']}",
                    font_size=12, bold=True,
                    color="#000000").pack(expand=True)

        ver  = get_features(self.user_version)
        badge_txt = {
            "developer": "⚡ DESARROLLADOR",
            "premium":   "⭐ PREMIUM",
            "equipo":    "👥 EQUIPO",
            "basic":     "⭐ BÁSICO",
        }.get(self.user_version, "🆓 GRATIS")

        tk.Label(sidebar, text=badge_txt,
                 font=("Segoe UI", 9, "bold"),
                 bg=ver["color"], fg="#000000").pack(fill="x", ipady=3)

        # nav buttons
        nav = [
            ("🏠  Dashboard",           self._tab_dashboard, "nav_dashboard"),
            ("🔑  Generar contraseña",  self._tab_generator, "nav_generator"),
            ("📋  Mis contraseñas",     self._tab_list, "nav_passwords"),
        ]
        if get_features(self.user_version)["security_analysis"]:
            nav.append(("🛡️  Análisis de seguridad", self._tab_security, None))
        if get_features(self.user_version)["export"]:
            nav.append(("📦  Exportar bóveda", self._export_vault, None))
        nav.append(("📥  Importar bóveda", self._import_vault, None))
        nav.append(("⚙️  Configuración", self._tab_settings, "nav_settings"))
        nav.append(("❔  Tutorial guiado", self._start_tutorial, "tutorial_nav_button"))
        if self.user_version == "developer":
            nav.append(("⚡  Dev Tools", self._tab_dev_tools, None))
        if get_features(self.user_version).get("team"):
            nav.insert(3, ("👥  Bóveda de equipo", self._tab_team, None))
        if self.user_version not in ["premium", "equipo", "developer"]:
            nav.append(("💳  Comprar plan", self._show_plans_screen, None))
        if self.user_version != "developer":
            nav.append(("🔑  Activar licencia", self._activate_license_dialog, None))
        nav.append(("📜  Mi licencia", self._show_license_info, None))
        nav.append(("🚪  Cerrar sesión", self._logout, None))

        for text, cmd, target_name in nav:
            button = self._btn(sidebar, text, cmd, "Nav.TButton")
            button.pack(fill="x", padx=8, pady=2)
            if target_name:
                setattr(self, target_name, button)

        # pie de sidebar: logo + copyright juntos, siempre visible abajo
        sidebar_footer = tk.Frame(sidebar, bg=C["card"])
        sidebar_footer.pack(side="bottom", pady=8)

        footer_logo_path = get_asset_path("icono_footer.png")
        if footer_logo_path:
            try:
                self._sidebar_footer_logo_img = tk.PhotoImage(file=footer_logo_path)
                tk.Label(sidebar_footer, image=self._sidebar_footer_logo_img,
                         bg=C["card"]).pack(pady=(0, 4))
            except Exception:
                pass
        tk.Label(sidebar_footer, text=APP_COPYRIGHT_TEXT,
                 font=("Segoe UI", 7), bg=C["card"], fg=C["muted"],
                 justify="center", wraplength=self._s(210)).pack(padx=8)

        # ── content area ──────────────────────
        self.content_frame = tk.Frame(root_frame, bg=C["bg"])
        self.content_frame.pack(side="left", fill="both", expand=True,
                                padx=self._s(24), pady=self._s(20))

        self._tab_dashboard()

    # ─────────────────────────────────────────
    #  TAB: DASHBOARD
    # ─────────────────────────────────────────
    def _tab_dashboard(self):
        """Pestaña de inicio: resumen de contraseñas guardadas, límite del plan, contraseñas fuertes y puntuación de seguridad, además de accesos rápidos y el aviso de plan gratuito."""
        self._clear_content()
        f = self.content_frame

        self._label(f, "📊 Panel principal", font_size=20, bold=True).pack(anchor="w")
        ver = get_features(self.user_version)
        self._label(f, f"Versión: {ver['name']}  ·  Usuario: {self.current_user['username']}",
                    color=C["muted"]).pack(anchor="w", pady=(0, 16))

        with db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM passwords WHERE user_id=?",
                                 (self.current_user["id"],)).fetchone()[0]
            strong = conn.execute(
                "SELECT COUNT(*) FROM passwords WHERE user_id=? AND strength IN ('FUERTE','MUY FUERTE')",
                (self.current_user["id"],)).fetchone()[0]

        score = int(strong / total * 100) if total else 0
        mp    = ver["max_passwords"]
        lim   = "∞" if mp == -1 else str(mp)

        stats = tk.Frame(f, bg=C["bg"])
        stats.pack(fill="x", pady=(0, 24))
        self.dashboard_stats = stats
        for i,(val,lbl,col) in enumerate([
            (str(total),        "Contraseñas guardadas", C["primary"]),
            (f"{total}/{lim}",  "Límite del plan",        C["accent"]),
            (str(strong),       "Contraseñas fuertes",    C["success"]),
            (f"{score}%",       "Puntuación seguridad",   C["secondary"]),
        ]):
            card = self._card(stats)
            card.grid(row=0, column=i, padx=6, sticky="nsew")
            stats.columnconfigure(i, weight=1)
            self._label(card, val, font_size=22, bold=True, color=col).pack(anchor="w")
            self._label(card, lbl, color=C["muted"], font_size=9).pack(anchor="w")

        # acciones rápidas
        self._label(f, "🚀 Acciones rápidas", font_size=14, bold=True).pack(anchor="w", pady=(8, 10))
        row = tk.Frame(f, bg=C["bg"])
        row.pack(fill="x")
        for txt, cmd in [
            ("✨ Generar contraseña", self._tab_generator),
            ("📝 Agregar manualmente", self._show_add_form),
            ("🛡️ Análisis de seguridad", self._tab_security)
            if get_features(self.user_version)["security_analysis"]
            else ("🔒 Análisis de seguridad (Premium)", self._show_plans_screen),
        ]:
            card = self._card(row, padx=16, pady=14)
            card.pack(side="left", expand=True, fill="x", padx=5)
            self._label(card, txt, bold=True, color=C["secondary"]).pack(anchor="w")
            self._label(card, "Haz clic para acceder", color=C["muted"], font_size=9).pack(anchor="w")
            for w in [card] + card.winfo_children():
                w.bind("<Button-1>", lambda _, c=cmd: c())

        # banner de plan
        if self.user_version == "free":
            self._plan_banner(f, C["card"],
                "🆓 Versión gratuita",
                f"Usando {total}/{lim} contraseñas. Con Premium tienes contraseñas ilimitadas, "
                "análisis de seguridad, respaldos y códigos 2FA.",
                self._show_plans_screen, "💎 Comprar plan")

    def _plan_banner(self, parent, color, title, subtitle, cmd, btn_text):
        """Dibuja el banner inferior que invita a comprar o renovar un plan."""
        b = tk.Frame(parent, bg=color, padx=20, pady=14)
        b.pack(fill="x", pady=(20, 0))
        self._label(b, title, bold=True, font_size=12,
                    color="#000000" if color == C["warning"] else C["text"]).pack(anchor="w")
        self._label(b, subtitle,
                    color="#000000" if color == C["warning"] else C["muted"],
                    font_size=10).pack(anchor="w", pady=(2, 8))
        ttk.Button(b, text=btn_text, command=cmd, style="Wompi.TButton").pack(anchor="w")

    # ─────────────────────────────────────────
    #  TAB: GENERADOR
    # ─────────────────────────────────────────
    def _tab_generator(self):
        """Pestaña del generador de contraseñas: controles de longitud y tipos de caracteres, resultado generado con su nivel de fortaleza, y acciones para copiar o guardar."""
        self._clear_content()
        f = self.content_frame

        self._label(f, "🔑 Generador de contraseñas", font_size=20, bold=True).pack(anchor="w")
        self._label(f, "Crea contraseñas fuertes al instante", color=C["muted"]).pack(anchor="w", pady=(0, 16))

        feats = get_features(self.user_version)
        max_l = feats["password_length_max"]

        cfg = self._card(f)
        cfg.pack(fill="x", pady=(0, 12))
        self.gen_config_card = cfg
        self._label(cfg, "⚙️ Configuración", bold=True, font_size=12).pack(anchor="w", pady=(0, 10))

        lf = tk.Frame(cfg, bg=C["card"])
        lf.pack(fill="x", pady=(0, 10))
        self._label(lf, f"Longitud (máx {max_l}):", color=C["muted"]).pack(side="left")
        self.gen_len = tk.IntVar(value=min(self.config.get("password_length", 16), max_l))
        tk.Scale(lf, from_=8, to=max_l, variable=self.gen_len,
                 orient="horizontal", bg=C["card"], fg=C["text"],
                 troughcolor=C["border"], highlightbackground=C["card"],
                 length=200).pack(side="left", padx=12)
        self._label(lf, str(self.gen_len.get()), color=C["muted"]).pack(side="left")

        opf = tk.Frame(cfg, bg=C["card"])
        opf.pack(fill="x")
        self.gen_upper  = tk.BooleanVar(value=True)
        self.gen_lower  = tk.BooleanVar(value=True)
        self.gen_digits = tk.BooleanVar(value=True)
        self.gen_syms   = tk.BooleanVar(value=True)
        for text, var in [
            ("Mayúsculas (A-Z)", self.gen_upper),
            ("Minúsculas (a-z)", self.gen_lower),
            ("Números (0-9)",    self.gen_digits),
            ("Símbolos (!@#$)",  self.gen_syms),
        ]:
            tk.Checkbutton(opf, text=text, variable=var,
                           bg=C["card"], fg=C["text"],
                           selectcolor=C["bg"], activebackground=C["card"],
                           font=("Segoe UI", 10)).pack(anchor="w", pady=2)

        res = self._card(f)
        res.pack(fill="x", pady=(0, 12))
        self._label(res, "🔐 Contraseña generada:", bold=True, font_size=12).pack(anchor="w", pady=(0, 8))

        self.gen_result = tk.StringVar()
        ttk.Entry(res, textvariable=self.gen_result, font=("Consolas", 13), width=45).pack(fill="x", pady=(0, 4))

        self.gen_strength_lbl = self._label(res, "", color=C["success"])
        self.gen_strength_lbl.pack(anchor="w", pady=(0, 10))

        row = tk.Frame(res, bg=C["card"])
        row.pack()
        self.gen_actions_row = row
        self._btn(row, "🎲 Generar",    self._do_generate, "Primary.TButton").pack(side="left", padx=4)
        self._btn(row, "📋 Copiar",     self._copy_generated).pack(side="left", padx=4)
        self._btn(row, "💾 Guardar",    self._save_generated_form).pack(side="left", padx=4)

        self._do_generate()

    def _do_generate(self):
        """Genera una nueva contraseña aleatoria según las opciones elegidas (longitud y tipos de caracteres habilitados) y actualiza la indicación de fortaleza."""
        feats = get_features(self.user_version)
        length = min(self.gen_len.get(), feats["password_length_max"])
        chars = ""
        if self.gen_lower.get():  chars += string.ascii_lowercase
        if self.gen_upper.get():  chars += string.ascii_uppercase
        if self.gen_digits.get(): chars += string.digits
        if self.gen_syms.get():   chars += string.punctuation
        if not chars: chars = string.ascii_letters + string.digits
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        self.gen_result.set(pwd)
        strength, score = self._eval_strength(pwd)
        colors_ = {5: C["success"], 4: C["success"], 3: C["warning"], 2: C["danger"], 1: C["danger"]}
        self.gen_strength_lbl.config(text=f"Fortaleza: {strength}", fg=colors_.get(score, C["muted"]))

    def _copy_secret(self, text: str, seconds: int = 30):
        """Copia un secreto al portapapeles y lo borra a los `seconds` segundos si sigue ahí.
        Usa la ventana principal (no una emergente), así el borrado ocurre aunque se cierre
        la ventana desde la que se copió."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

        def clear_clipboard():
            try:
                if self.root.clipboard_get() == text:
                    self.root.clipboard_clear()
            except tk.TclError:
                pass
        self.root.after(seconds * 1000, clear_clipboard)

    def _copy_generated(self):
        """Copia la contraseña generada al portapapeles (se borra sola a los 30 s)."""
        pwd = self.gen_result.get()
        if pwd:
            self._copy_secret(pwd)
            messagebox.showinfo("✅ Copiado", "Contraseña copiada. El portapapeles se limpiará en 30 segundos.")

    def _save_generated_form(self):
        """Abre el formulario de 'agregar contraseña' con la contraseña recién generada ya rellenada."""
        pwd = self.gen_result.get()
        if not pwd:
            messagebox.showwarning("Vacío", "Genera una contraseña primero.")
            return
        self._show_add_form(prefill_password=pwd)

    # ─────────────────────────────────────────
    #  TAB: LISTA DE CONTRASEÑAS
    # ─────────────────────────────────────────
    def _tab_list(self):
        """Pestaña de la bóveda: tabla con todas las contraseñas guardadas, buscador, selector de orden y barra de uso del límite del plan."""
        self._clear_content()
        f = self.content_frame

        self._label(f, "📋 Mis contraseñas", font_size=20, bold=True).pack(anchor="w")

        # controles
        ctrl = tk.Frame(f, bg=C["bg"])
        ctrl.pack(fill="x", pady=(8, 12))

        self.list_add_button = self._btn(ctrl, "➕ Agregar nueva", self._show_add_form, "Primary.TButton")
        self.list_add_button.pack(side="left", padx=(0, 8))

        self._label(ctrl, "Ordenar:", color=C["muted"]).pack(side="left", padx=(8, 4))
        sort_opts = [("Alfabético", "service"), ("Por ID", "id"), ("Reciente", "date")]
        self.sort_var = tk.StringVar(value=next(n for n, v in sort_opts if v == self.password_sort_order))
        cb = ttk.Combobox(ctrl, textvariable=self.sort_var,
                          values=[n for n,_ in sort_opts], width=12, state="readonly")
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda _: self._on_sort_change(sort_opts))

        self._label(ctrl, "🔍", color=C["muted"]).pack(side="left", padx=(16, 4))
        self.search_var = tk.StringVar()
        self.list_search_entry = ttk.Entry(ctrl, textvariable=self.search_var, width=22)
        self.list_search_entry.pack(side="left")
        self.search_var.trace("w", lambda *_: self._load_passwords())

        # tabla
        tbl = tk.Frame(f, bg=C["card"])
        tbl.pack(fill="both", expand=True)

        cols = ("ID","Servicio","Usuario","Fortaleza","Categoría","Actualizado")
        self.tree = ttk.Treeview(tbl, columns=cols, show="headings", height=18)
        widths = dict(ID=50, Servicio=160, Usuario=160, Fortaleza=110, Categoría=120, Actualizado=130)
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=self._s(widths.get(col, 100)))
        if not get_features(self.user_version)["categories"]:
            self.tree["displaycolumns"] = tuple(c for c in cols if c != "Categoría")

        sb = ttk.Scrollbar(tbl, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_pwd_select)

        # límite
        feats = get_features(self.user_version)
        mp = feats["max_passwords"]
        if mp != -1:
            cnt = self._count_passwords()
            pct = min(cnt/mp, 1.0)
            inf = tk.Frame(f, bg=C["card"], padx=12, pady=8)
            inf.pack(fill="x", pady=(8, 0))
            self._label(inf, f"Usando {cnt}/{mp} contraseñas", color=C["muted"], font_size=10).pack(anchor="w")
            bar_bg = tk.Frame(inf, bg=C["border"], height=6)
            bar_bg.pack(fill="x", pady=4)
            bar_bg.pack_propagate(False)
            col_bar = C["success"] if pct < 0.8 else C["warning"] if pct < 0.95 else C["danger"]
            tk.Frame(bar_bg, bg=col_bar).place(relwidth=pct, relheight=1)

        self._load_passwords()

    def _on_sort_change(self, sort_opts):
        """Aplica el criterio de orden elegido en el combobox y vuelve a cargar la tabla."""
        sel = self.sort_var.get()
        for name, val in sort_opts:
            if name == sel:
                self.password_sort_order = val
                break
        self._save_config()
        self._load_passwords()

    def _count_passwords(self) -> int:
        """Cantidad de contraseñas guardadas por el usuario actual."""
        with db() as conn:
            return conn.execute("SELECT COUNT(*) FROM passwords WHERE user_id=?",
                                (self.current_user["id"],)).fetchone()[0]

    def _load_passwords(self):
        """Lee las contraseñas del usuario, descifra servicio y usuario, aplica orden y
        filtro de búsqueda (en memoria, porque esos campos están cifrados) y llena la tabla."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        vault = self.current_user["vault"]
        with db() as conn:
            rows = conn.execute(
                "SELECT id,service,username,strength,category,updated_at FROM passwords WHERE user_id=?",
                (self.current_user["id"],)).fetchall()
        records = [(pid, dec_text(vault, svc), dec_text(vault, uname), strength, cat, upd)
                   for pid, svc, uname, strength, cat, upd in rows]
        if self.password_sort_order == "id":
            records.sort(key=lambda r: r[0])
        elif self.password_sort_order == "date":
            records.sort(key=lambda r: r[5] or "", reverse=True)
        else:
            records.sort(key=lambda r: r[1].lower())
        term = self.search_var.get().lower() if hasattr(self, "search_var") else ""
        for pid, svc, uname, strength, cat, upd in records:
            if term and term not in svc.lower() and term not in uname.lower():
                continue
            try:
                upd_fmt = datetime.strptime(upd, "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y")
            except (TypeError, ValueError):
                upd_fmt = upd or "—"
            self.tree.insert("", "end", values=(pid, svc, uname, strength, cat, upd_fmt))

    def _on_pwd_select(self, _event):
        """Al seleccionar una fila de la tabla, guarda su ID y muestra los botones de ver detalles / editar / eliminar."""
        sel = self.tree.selection()
        if not sel:
            return
        self.selected_password_id = self.tree.item(sel[0])["values"][0]
        if hasattr(self, "_action_row"):
            self._action_row.destroy()
        self._action_row = tk.Frame(self.content_frame, bg=C["bg"])
        self._action_row.pack(fill="x", pady=(8, 0))
        self._btn(self._action_row, "👁️ Ver detalles", self._show_pwd_details).pack(side="left", padx=4)
        self._btn(self._action_row, "✏️ Editar",       self._edit_password).pack(side="left", padx=4)
        self._btn(self._action_row, "📄 Duplicar",     self._duplicate_password).pack(side="left", padx=4)
        self._btn(self._action_row, "🗑️ Eliminar",     self._delete_password, "Danger.TButton").pack(side="left", padx=4)

    # ─────────────────────────────────────────
    #  FORMULARIO AGREGAR CONTRASEÑA
    # ─────────────────────────────────────────
    def _show_add_form(self, prefill_password="", prefill: dict | None = None):
        """Muestra el formulario para agregar una contraseña nueva, respetando el límite máximo
        de contraseñas del plan actual. `prefill` (al duplicar) trae los datos de otra entrada."""
        prefill = prefill or {}
        feats = get_features(self.user_version)
        mp = feats["max_passwords"]
        if mp != -1:
            cnt = self._count_passwords()
            if cnt >= mp:
                messagebox.showwarning("Límite alcanzado",
                    f"Has llegado al límite de {mp} contraseñas en tu plan {self.user_version.upper()}.\n"
                    "Compra un plan superior para agregar más.")
                return

        self._clear_content()
        f = self.content_frame
        self._label(f, "📄 Duplicar contraseña" if prefill else "➕ Agregar contraseña",
                    font_size=20, bold=True).pack(anchor="w", pady=(0, 4 if prefill else 16))
        if prefill:
            self._label(f, "Es una copia nueva: cambia lo que necesites (por ejemplo el usuario) y guárdala. "
                           "La original no se modifica.", color=C["muted"], font_size=10
                        ).pack(anchor="w", pady=(0, 12))

        form = self._card(f, padx=28, pady=24)
        form.pack(fill="x")

        self._label(form, "Servicio / Sitio web:", bold=True, color=C["muted"]).grid(row=0, column=0, sticky="w", pady=6)
        self.add_service  = tk.StringVar(value=prefill.get("service", ""))
        ttk.Entry(form, textvariable=self.add_service, width=40).grid(row=0, column=1, padx=12, pady=6)

        self._label(form, "Usuario / Email:", bold=True, color=C["muted"]).grid(row=2, column=0, sticky="w", pady=6)
        self.add_uname = tk.StringVar(value=prefill.get("username", ""))
        ttk.Entry(form, textvariable=self.add_uname, width=40).grid(row=2, column=1, padx=12, pady=6)

        self._label(form, "Página web (opcional):", bold=True, color=C["muted"]).grid(row=1, column=0, sticky="w", pady=6)
        self.add_url = tk.StringVar(value=prefill.get("url", ""))
        ttk.Entry(form, textvariable=self.add_url, width=40).grid(row=1, column=1, padx=12, pady=6)

        self.add_totp = tk.StringVar(value=prefill.get("totp", "") if feats.get("totp") else "")
        if feats.get("totp"):
            self._label(form, "Clave 2FA (opcional):", bold=True, color=C["muted"]).grid(row=6, column=0, sticky="w", pady=6)
            ttk.Entry(form, textvariable=self.add_totp, width=40).grid(row=6, column=1, padx=12, pady=6)
            self._label(form, "La clave Base32 o el enlace otpauth:// que muestra el sitio al activar la "
                              "verificación en dos pasos (debajo del código QR).",
                        color=C["muted"], font_size=8, wraplength=self._s(380), justify="left"
                        ).grid(row=7, column=1, sticky="w", padx=12)

        self._label(form, "Contraseña:", bold=True, color=C["muted"]).grid(row=3, column=0, sticky="w", pady=6)
        pwd_row = tk.Frame(form, bg=C["card"])
        pwd_row.grid(row=3, column=1, padx=12, pady=6, sticky="w")
        self.add_pwd = tk.StringVar(value=prefill.get("password", prefill_password))
        self.add_pwd_entry = ttk.Entry(pwd_row, textvariable=self.add_pwd, show="•", width=30)
        self.add_pwd_entry.pack(side="left")
        self._btn(pwd_row, "👁️", lambda: self._toggle_vis(self.add_pwd_entry)).pack(side="left", padx=4)
        self._btn(pwd_row, "🎲 Gen", self._autofill_password).pack(side="left", padx=2)

        if feats["categories"]:
            self._label(form, "Categoría:", bold=True, color=C["muted"]).grid(row=4, column=0, sticky="w", pady=6)
            self.add_cat = tk.StringVar(value=prefill.get("category") or "General")
            ttk.Combobox(form, textvariable=self.add_cat, width=37,
                         values=["General","Trabajo","Personal","Finanzas","Redes Sociales","Correo"],
                         state="readonly").grid(row=4, column=1, padx=12, pady=6)

        self._label(form, f"Notas (máx {feats['notes_max_length']}):", bold=True, color=C["muted"]).grid(row=5, column=0, sticky="nw", pady=6)
        self.add_notes = tk.Text(form, height=4, width=40,
                                 bg=C["card2"], fg=C["text"], font=("Segoe UI", 10))
        self.add_notes.grid(row=5, column=1, padx=12, pady=6)
        if prefill.get("notes"):
            self.add_notes.insert("1.0", prefill["notes"][:feats["notes_max_length"]])

        btn_row = tk.Frame(form, bg=C["card"])
        btn_row.grid(row=8, column=0, columnspan=2, pady=20)
        self._btn(btn_row, "💾 Guardar",   self._save_password, "Primary.TButton").pack(side="left", padx=8)
        self._btn(btn_row, "↩️ Cancelar",  self._tab_list).pack(side="left", padx=8)

    def _toggle_vis(self, entry):
        """Alterna entre mostrar y ocultar el texto de un campo de contraseña."""
        entry.config(show="" if entry.cget("show") == "•" else "•")

    def _autofill_password(self):
        """Rellena el campo de contraseña del formulario con una contraseña aleatoria generada al vuelo."""
        feats = get_features(self.user_version)
        length = min(self.config.get("password_length", 16), feats["password_length_max"])
        chars  = string.ascii_letters + string.digits + string.punctuation
        self.add_pwd.set("".join(secrets.choice(chars) for _ in range(length)))

    def _save_password(self):
        """Valida y guarda una contraseña nueva. Contraseña, servicio, usuario y notas se
        cifran con la bóveda del usuario antes de tocar la base de datos."""
        svc   = self.add_service.get().strip()
        uname = self.add_uname.get().strip()
        pwd   = self.add_pwd.get()
        cat   = self.add_cat.get() if hasattr(self, "add_cat") else "General"
        notes = self.add_notes.get("1.0", "end-1c").strip() if hasattr(self, "add_notes") else ""
        url   = self.add_url.get().strip() if hasattr(self, "add_url") else ""
        totp  = self.add_totp.get().strip() if hasattr(self, "add_totp") else ""
        feats = get_features(self.user_version)

        if not svc or not uname or not pwd:
            messagebox.showerror("Error", "Servicio, usuario y contraseña son obligatorios.")
            return
        if totp:
            try:
                cvx.parse_totp(totp)
            except ValueError as exc:
                messagebox.showerror("Clave 2FA no válida", str(exc))
                return
        if len(notes) > feats["notes_max_length"]:
            messagebox.showerror("Notas demasiado largas",
                                 f"Tu plan permite hasta {feats['notes_max_length']} caracteres en las notas.")
            return
        if feats["max_passwords"] != -1 and self._count_passwords() >= feats["max_passwords"]:
            messagebox.showwarning("Límite alcanzado", "Has llegado al límite de contraseñas de tu plan.")
            return

        vault = self.current_user["vault"]
        strength, _ = self._eval_strength(pwd)
        try:
            with db() as conn:
                conn.execute("""
                    INSERT INTO passwords(user_id,service,username,password_encrypted,strength,category,notes,url,totp)
                    VALUES(?,?,?,?,?,?,?,?,?)
                """, (self.current_user["id"], enc_text(vault, svc), enc_text(vault, uname),
                      vault.encrypt(pwd.encode("utf-8")).decode("ascii"),
                      strength, cat, enc_text(vault, notes), enc_text(vault, url), enc_text(vault, totp)))
            self._auto_backup()
            messagebox.showinfo("✅ Guardado", "Contraseña guardada correctamente.")
            self._tab_list()
        except sqlite3.Error:
            log.exception("No se pudo guardar la contraseña")
            messagebox.showerror("Error", "No se pudo guardar. Revisa el archivo de registro.")

    # ─────────────────────────────────────────
    #  DETALLES / EDITAR / ELIMINAR
    # ─────────────────────────────────────────
    def _ask_master(self) -> bool:
        """Pide de nuevo la contraseña maestra antes de una acción sensible (ver detalles,
        editar, exportar) y la valida. Comparte el bloqueo por intentos con el login."""
        return self._ask_master_password() is not None

    def _ask_master_password(self) -> str | None:
        """Como _ask_master, pero devuelve la contraseña (la necesita la sincronización)."""
        username = self.current_user["username"]
        remaining = self._lock_remaining(username)
        if remaining:
            messagebox.showerror("Espera un momento", f"Demasiados intentos. Intenta de nuevo en {remaining} segundos.")
            return None
        mp = simpledialog.askstring("Contraseña maestra",
                                    "Ingresa tu contraseña maestra:", show="*")
        if not mp:
            return None
        with db() as conn:
            user = get_user_by_id(conn, self.current_user["id"])
        if not authenticate(mp, user).ok:
            self._register_failure(username)
            messagebox.showerror("Error", "Contraseña maestra incorrecta.")
            return None
        self._clear_failures(username)
        return mp

    def _get_pwd_data(self) -> dict | None:
        """Obtiene y descifra (contraseña, servicio, usuario y notas) la entrada seleccionada en la tabla."""
        if not self.selected_password_id:
            messagebox.showwarning("Sin selección", "Selecciona una contraseña primero.")
            return None
        with db() as conn:
            row = conn.execute("""
                SELECT service,username,password_encrypted,strength,category,notes,created_at,updated_at,url,totp
                FROM passwords WHERE id=? AND user_id=?
            """, (self.selected_password_id, self.current_user["id"])).fetchone()
        if not row:
            messagebox.showerror("Error", "No se encontró la contraseña.")
            return None
        keys = ["service","username","password","strength","category","notes","created_at","updated_at","url","totp"]
        data = dict(zip(keys, row))
        vault = self.current_user["vault"]
        try:
            data["password"] = vault.decrypt(data["password"].encode("utf-8")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError):
            messagebox.showerror("Error de bóveda", "No fue posible descifrar esta contraseña.")
            return None
        for field in ("service", "username", "notes", "url", "totp"):
            data[field] = dec_text(vault, data[field])
        return data

    def _show_pwd_details(self):
        """Muestra en una ventana emergente los detalles de una contraseña guardada, con la contraseña oculta por defecto y opción de verla o copiarla (el portapapeles se limpia solo a los 30 segundos)."""
        if not self.selected_password_id:
            messagebox.showwarning("Sin selección", "Selecciona una contraseña.")
            return
        if not self._ask_master():
            return
        d = self._get_pwd_data()
        if not d:
            return

        win = self._inline_page()
        win.title(f"🔐 {d['service']}")
        self._set_popup_geometry(win, 560, 560)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, f"🔐 {d['service']}", font_size=18, bold=True, color=C["primary"]).pack(pady=(20,10))

        body = self._card(win, padx=24, pady=20)
        body.pack(fill="both", expand=True, padx=20, pady=(0,20))

        for row_i,(lbl,val) in enumerate([
            ("👤 Usuario",     d["username"]),
            ("🌐 Página web",  d["url"] or "—"),
            *([("📂 Categoría", d["category"] or "—")] if get_features(self.user_version)["categories"] else []),
            ("📅 Creada",      d["created_at"]),
            ("🔄 Actualizada", d["updated_at"]),
            ("🛡️ Fortaleza",   d["strength"]),
        ]):
            self._label(body, lbl, bold=True, color=C["muted"]).grid(row=row_i, column=0, sticky="w", pady=5)
            self._label(body, val).grid(row=row_i, column=1, sticky="w", padx=12, pady=5)

        # contraseña oculta con toggle
        self._label(body, "🔑 Contraseña:", bold=True, color=C["muted"]).grid(row=6, column=0, sticky="w", pady=5)
        pwd_frame = tk.Frame(body, bg=C["card"])
        pwd_frame.grid(row=6, column=1, sticky="w", padx=12, pady=5)
        pwd_lbl = self._label(pwd_frame, "••••••••")
        pwd_lbl.pack(side="left")

        def toggle_pwd():
            pwd_lbl.config(text=d["password"] if pwd_lbl.cget("text") == "••••••••" else "••••••••")
        def copy_pwd():
            self._copy_secret(d["password"])
            messagebox.showinfo("✅", "Contraseña copiada. El portapapeles se limpiará en 30 segundos.")

        self._btn(pwd_frame, "👁️", toggle_pwd).pack(side="left", padx=4)
        self._btn(pwd_frame, "📋", copy_pwd).pack(side="left", padx=2)

        if d["totp"]:
            self._label(body, "🔢 Código 2FA:", bold=True, color=C["muted"]).grid(row=7, column=0, sticky="w", pady=5)
            totp_frame = tk.Frame(body, bg=C["card"])
            totp_frame.grid(row=7, column=1, sticky="w", padx=12, pady=5)
            if get_features(self.user_version).get("totp"):
                code_lbl = self._label(totp_frame, "------", font_size=14, bold=True, color=C["success"])
                code_lbl.pack(side="left")
                secs_lbl = self._label(totp_frame, "", color=C["muted"], font_size=9)
                secs_lbl.pack(side="left", padx=6)

                job = {"id": None}

                def tick():
                    if not code_lbl.winfo_exists():
                        return
                    try:
                        code, left = cvx.totp_code(d["totp"])
                        code_lbl.config(text=f"{code[:3]} {code[3:]}")
                        secs_lbl.config(text=f"{left}s")
                    except ValueError:
                        code_lbl.config(text="clave no válida")
                        return
                    job["id"] = win.after(1000, tick)

                def stop_tick(event):
                    if event.widget is win and job["id"]:
                        try:
                            win.after_cancel(job["id"])
                        except tk.TclError:
                            pass
                win.bind("<Destroy>", stop_tick, add="+")

                def copy_code():
                    try:
                        self._copy_secret(cvx.totp_code(d["totp"])[0])
                    except ValueError:
                        return
                    messagebox.showinfo("✅", "Código copiado. El portapapeles se limpiará en 30 segundos.")
                tick()
                self._btn(totp_frame, "📋", copy_code).pack(side="left", padx=2)
            else:
                self._label(totp_frame, "Disponible con Premium", color=C["muted"]).pack(side="left")

        if d["notes"]:
            self._label(body, "📝 Notas:", bold=True, color=C["muted"]).grid(row=8, column=0, sticky="nw", pady=5)
            ntxt = tk.Text(body, height=3, width=28, bg=C["card2"], fg=C["text"], font=("Segoe UI", 10))
            ntxt.grid(row=8, column=1, padx=12, pady=5)
            ntxt.insert("1.0", d["notes"])
            ntxt.config(state="disabled")

        self._btn(win, "↩️ Cerrar", win.destroy).pack(pady=8)

    def _duplicate_password(self):
        """Abre el formulario de agregar con los datos de la entrada seleccionada (servicio con
        «(copia)», mismo usuario, contraseña, página, notas, categoría y 2FA) para guardarla
        como una entrada nueva. Útil para otra cuenta del mismo sitio."""
        if not self.selected_password_id:
            messagebox.showwarning("Sin selección", "Selecciona una contraseña.")
            return
        if not self._ask_master():
            return
        d = self._get_pwd_data()
        if not d:
            return
        d = dict(d)
        d["service"] = f"{d['service']} (copia)"[:200]
        self._show_add_form(prefill=d)

    def _edit_password(self):
        """Abre un formulario para editar una contraseña existente y guarda los cambios ya cifrados."""
        if not self.selected_password_id:
            messagebox.showwarning("Sin selección", "Selecciona una contraseña.")
            return
        if not self._ask_master():
            return
        d = self._get_pwd_data()
        if not d:
            return

        win = self._inline_page()
        win.title(f"✏️ Editar: {d['service']}")
        self._set_popup_geometry(win, 560, 600)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, "✏️ Editar contraseña", font_size=18, bold=True).pack(pady=(18, 10))
        body = self._card(win, padx=24, pady=20)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        sv, uv, pv, cv = (tk.StringVar(value=d[k])
                          for k in ("service","username","password","category"))

        for row_i,(lbl,var) in enumerate([("Servicio:",sv),("Usuario:",uv)]):
            self._label(body, lbl, bold=True, color=C["muted"]).grid(row=row_i, column=0, sticky="w", pady=6)
            ttk.Entry(body, textvariable=var, width=32).grid(row=row_i, column=1, padx=10, pady=6)

        self._label(body, "Contraseña:", bold=True, color=C["muted"]).grid(row=2, column=0, sticky="w", pady=6)
        pf = tk.Frame(body, bg=C["card"])
        pf.grid(row=2, column=1, padx=10, pady=6, sticky="w")
        pe = ttk.Entry(pf, textvariable=pv, show="•", width=24)
        pe.pack(side="left")
        self._btn(pf, "👁️", lambda: self._toggle_vis(pe)).pack(side="left", padx=3)

        if get_features(self.user_version)["categories"]:
            self._label(body, "Categoría:", bold=True, color=C["muted"]).grid(row=3, column=0, sticky="w", pady=6)
            ttk.Combobox(body, textvariable=cv, width=29,
                         values=["General","Trabajo","Personal","Finanzas","Redes Sociales","Correo"],
                         state="readonly").grid(row=3, column=1, padx=10, pady=6)

        self._label(body, "Notas:", bold=True, color=C["muted"]).grid(row=4, column=0, sticky="nw", pady=6)
        ntxt = tk.Text(body, height=4, width=30, bg=C["card2"], fg=C["text"], font=("Segoe UI", 10))
        ntxt.grid(row=4, column=1, padx=10, pady=6)
        ntxt.insert("1.0", d["notes"] or "")

        urlv, totpv = tk.StringVar(value=d["url"] or ""), tk.StringVar(value=d["totp"] or "")
        self._label(body, "Página web:", bold=True, color=C["muted"]).grid(row=5, column=0, sticky="w", pady=6)
        ttk.Entry(body, textvariable=urlv, width=32).grid(row=5, column=1, padx=10, pady=6)
        if get_features(self.user_version).get("totp"):
            self._label(body, "Clave 2FA:", bold=True, color=C["muted"]).grid(row=6, column=0, sticky="w", pady=6)
            ttk.Entry(body, textvariable=totpv, width=32, show="•").grid(row=6, column=1, padx=10, pady=6)

        def save_edit():
            ns, nu, np_, nc = sv.get().strip(), uv.get().strip(), pv.get(), cv.get()
            notes = ntxt.get("1.0", "end-1c").strip()
            nurl, ntotp = urlv.get().strip(), totpv.get().strip()
            feats = get_features(self.user_version)
            if not ns or not nu or not np_:
                messagebox.showerror("Error", "Completa todos los campos obligatorios.")
                return
            if ntotp:
                try:
                    cvx.parse_totp(ntotp)
                except ValueError as exc:
                    messagebox.showerror("Clave 2FA no válida", str(exc))
                    return
            if len(notes) > feats["notes_max_length"]:
                messagebox.showerror("Notas demasiado largas",
                                     f"Tu plan permite hasta {feats['notes_max_length']} caracteres en las notas.")
                return
            vault = self.current_user["vault"]
            strength, _ = self._eval_strength(np_)
            try:
                with db() as conn:
                    conn.execute("""
                        UPDATE passwords SET service=?,username=?,password_encrypted=?,
                        strength=?,category=?,notes=?,url=?,totp=?,updated_at=CURRENT_TIMESTAMP
                        WHERE id=? AND user_id=?
                    """, (enc_text(vault, ns), enc_text(vault, nu),
                          vault.encrypt(np_.encode("utf-8")).decode("ascii"),
                          strength, nc, enc_text(vault, notes), enc_text(vault, nurl), enc_text(vault, ntotp),
                          self.selected_password_id, self.current_user["id"]))
                self._auto_backup()
                messagebox.showinfo("✅", "Contraseña actualizada.")
                win.destroy()
                self._tab_list()
            except sqlite3.Error:
                log.exception("No se pudo actualizar la contraseña")
                messagebox.showerror("Error", "No se pudo guardar. Revisa el archivo de registro.")

        btn_r = tk.Frame(win, bg=C["bg"])
        btn_r.pack(pady=10)
        self._btn(btn_r, "💾 Guardar cambios", save_edit, "Primary.TButton").pack(side="left", padx=6)
        self._btn(btn_r, "↩️ Cancelar", win.destroy).pack(side="left", padx=6)

    def _delete_password(self):
        """Elimina la contraseña seleccionada, pidiendo confirmación previa."""
        if not self.selected_password_id:
            messagebox.showwarning("Sin selección", "Selecciona una contraseña.")
            return
        if not messagebox.askyesno("Confirmar eliminación",
            "¿Seguro que deseas eliminar esta contraseña?\nEsta acción no se puede deshacer."):
            return
        try:
            with db() as conn:
                conn.execute("DELETE FROM passwords WHERE id=? AND user_id=?",
                             (self.selected_password_id, self.current_user["id"]))
            self._auto_backup()
            messagebox.showinfo("✅", "Contraseña eliminada.")
            self.selected_password_id = None
            self._tab_list()
        except sqlite3.Error:
            log.exception("No se pudo eliminar la contraseña")
            messagebox.showerror("Error", "No se pudo eliminar. Revisa el archivo de registro.")

    # ─────────────────────────────────────────
    #  TAB: ANÁLISIS DE SEGURIDAD
    # ─────────────────────────────────────────
    def _tab_security(self):
        """
        Pestaña de análisis de seguridad (solo planes de pago): distribución de fortaleza,
        contraseñas duplicadas (comparando el texto ya descifrado, porque Fernet no produce
        el mismo cifrado dos veces) y búsqueda opcional de contraseñas filtradas
        (Have I Been Pwned, sin enviar nunca la contraseña).
        """
        self._clear_content()
        f = self.content_frame
        self._label(f, "🛡️ Análisis de seguridad", font_size=20, bold=True).pack(anchor="w", pady=(0, 16))

        if not get_features(self.user_version)["security_analysis"]:
            self._label(f, "🔒 Esta función requiere un plan de pago.",
                        font_size=14, color=C["warning"]).pack(pady=30)
            self._btn(f, "💳 Ver planes", self._show_plans_screen, "Wompi.TButton").pack()
            return

        vault = self.current_user["vault"]
        with db() as conn:
            dist = conn.execute("SELECT strength,COUNT(*) FROM passwords WHERE user_id=? GROUP BY strength",
                                (self.current_user["id"],)).fetchall()
            stored = conn.execute("SELECT service,password_encrypted FROM passwords WHERE user_id=?",
                                  (self.current_user["id"],)).fetchall()
        all_pwds = []
        for service, encrypted in stored:
            try:
                all_pwds.append((dec_text(vault, service),
                                 vault.decrypt(encrypted.encode("utf-8")).decode("utf-8")))
            except (InvalidToken, UnicodeDecodeError):
                continue
        self._security_pwds = all_pwds

        password_counts: dict[str, int] = {}
        for _, plain in all_pwds:
            password_counts[plain] = password_counts.get(plain, 0) + 1
        dups = sum(1 for count in password_counts.values() if count > 1)

        total = sum(c for _,c in dist)

        card = self._card(f)
        card.pack(fill="x", pady=(0, 12))
        self._label(card, "📊 Distribución de fortaleza", bold=True, font_size=12).pack(anchor="w", pady=(0, 10))

        for strength, count in dist:
            pct = count/total*100 if total else 0
            col_s = C["success"] if strength in ("FUERTE","MUY FUERTE") else \
                    C["warning"] if strength == "MODERADA" else C["danger"]
            emoji = "✅" if strength in ("FUERTE","MUY FUERTE") else \
                    "⚠️" if strength == "MODERADA" else "❌"
            self._label(card, f"{emoji} {strength}: {count} ({pct:.1f}%)", color=col_s).pack(anchor="w", pady=2)

        dup_col = C["danger"] if dups else C["success"]
        self._label(card, f"🔍 Contraseñas duplicadas: {dups}", color=dup_col).pack(anchor="w", pady=(10, 0))

        # Servicios con contraseñas débiles
        if self.user_version in ("premium","developer"):
            weak = [svc for svc,pwd in all_pwds if self._eval_strength(pwd)[1] < 3]
            if weak:
                card2 = self._card(f)
                card2.pack(fill="x", pady=(0, 12))
                self._label(card2, "⚠️ Servicios con contraseñas débiles:",
                            bold=True, color=C["warning"]).pack(anchor="w", pady=(0, 8))
                for svc in weak[:8]:
                    self._label(card2, f"   • {svc}", color=C["text"]).pack(anchor="w", pady=1)
                if len(weak) > 8:
                    self._label(card2, f"   ... y {len(weak)-8} más", color=C["muted"]).pack(anchor="w")

        # Contraseñas filtradas (opcional, requiere internet)
        card_p = self._card(f)
        card_p.pack(fill="x", pady=(0, 12))
        self._label(card_p, "🌐 Contraseñas filtradas", bold=True, font_size=12).pack(anchor="w", pady=(0, 6))
        self._label(card_p,
                    "Comprueba si alguna de tus contraseñas aparece en filtraciones públicas. De cada "
                    "contraseña solo se envían los primeros 5 caracteres de su huella SHA-1 (k-anonimato); "
                    "la contraseña nunca sale de tu equipo.",
                    color=C["muted"], font_size=9, wraplength=self._s(640), justify="left").pack(anchor="w")
        self.pwned_status = tk.StringVar(value="")
        self._btn(card_p, "Buscar contraseñas filtradas", self._check_pwned).pack(anchor="w", pady=(8, 4))
        self._label(card_p, "", color=C["text"], font_size=10, wraplength=self._s(640), justify="left",
                    textvariable=self.pwned_status).pack(anchor="w")

        # Recomendaciones
        card3 = self._card(f)
        card3.pack(fill="x")
        self._label(card3, "💡 Recomendaciones", bold=True, font_size=12).pack(anchor="w", pady=(0, 10))
        recs = []
        weak_cnt = sum(c for s,c in dist if s in ("DÉBIL","MODERADA"))
        if weak_cnt:  recs.append(f"• Actualiza {weak_cnt} contraseña(s) débil(es)")
        if dups:      recs.append(f"• Cambia {dups} contraseña(s) duplicada(s)")
        if not recs:  recs.append("• ¡Excelente! Tu seguridad es sólida 🎉")
        for r in recs:
            self._label(card3, r, color=C["text"]).pack(anchor="w", pady=2)

    def _check_pwned(self):
        """Revisa en segundo plano cada contraseña contra Have I Been Pwned y muestra el resultado."""
        pwds = list(getattr(self, "_security_pwds", []))
        if not pwds:
            self.pwned_status.set("No hay contraseñas para revisar.")
            return
        if not messagebox.askyesno(
                "Buscar contraseñas filtradas",
                "Se consultará el servicio Have I Been Pwned por internet. Solo se envían 5 caracteres "
                "del hash de cada contraseña, nunca la contraseña.\n\n¿Continuar?"):
            return
        self.pwned_status.set("Revisando…")
        status_var = self.pwned_status

        def worker():
            found, error = [], None
            try:
                for service, plain in pwds:
                    hits = PwnedPasswords.count(plain)
                    if hits:
                        found.append((service, hits))
            except OSError:
                error = "No se pudo conectar con el servicio. Revisa tu conexión a internet."

            def show():
                if error:
                    status_var.set(error)
                elif found:
                    lines = [f"• {svc}: aparece en {n:,} filtraciones".replace(",", ".") for svc, n in found[:10]]
                    more = f"\n… y {len(found) - 10} más" if len(found) > 10 else ""
                    status_var.set("⚠️ Cambia estas contraseñas cuanto antes:\n" + "\n".join(lines) + more)
                else:
                    status_var.set("✅ Ninguna de tus contraseñas aparece en filtraciones conocidas.")
            self.root.after(0, show)

        threading.Thread(target=worker, daemon=True, name="pwned-check").start()

    # ─────────────────────────────────────────
    #  PLANES / PAGO CON WOMPI
    # ─────────────────────────────────────────
    def _show_plans_screen(self, preselect: str = ""):
        """Pantalla de planes: clara, con info completa de cada uno."""
        self._clear_content() if hasattr(self, "content_frame") and self.content_frame.winfo_exists() else None

        if preselect and preselect in ALL_PLANES:
            self._show_wompi_checkout(preselect)
            return

        win = self._inline_page()
        win.title("Planes CipherVault")
        self._set_popup_geometry(win, 980, 720)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        # ── Header ──────────────────────────────────────────
        header = tk.Frame(win, bg=C["bg"])
        header.pack(fill="x", pady=(16, 4))
        self._label(header, "Elige tu plan", font_size=24, bold=True,
                    color=C["primary"]).pack()
        self._label(header, "Todas las opciones incluyen Premium completo · Pago seguro con Wompi "
                            "(PSE, Nequi o tarjeta) · El plan se vincula al email usado en el pago",
                    color=C["muted"], font_size=10).pack(pady=(4, 0))
        self._label(header, f"El plan gratis sigue disponible con hasta {FREE_MAX_PASSWORDS} contraseñas.",
                    color=C["muted"], font_size=9).pack(pady=(2, 0))

        # ── Tarjetas de planes ──────────────────────────────
        plans_frame = tk.Frame(win, bg=C["bg"])
        plans_frame.pack(fill="both", expand=True, padx=30, pady=12)

        for i, (plan_key, plan) in enumerate(PLANES.items()):
            outer_card = tk.Frame(plans_frame, bg=C["card"], padx=2, pady=2)
            outer_card.grid(row=0, column=i, padx=12, sticky="nsew")
            plans_frame.columnconfigure(i, weight=1)

            # franja superior de color
            tk.Frame(outer_card, bg=plan["color"], height=6).pack(fill="x")

            card = tk.Frame(outer_card, bg=C["card"], padx=18, pady=14)
            card.pack(fill="both", expand=True)

            # nombre del plan (+ etiqueta destacada, si tiene)
            if plan.get("badge"):
                tk.Label(card, text=plan["badge"], font=("Segoe UI", 8, "bold"),
                         bg=plan["color"], fg="#000000", padx=6).pack(anchor="w", pady=(0, 4))
            self._label(card, plan["nombre"], font_size=18, bold=True,
                        color=plan["color"]).pack(anchor="w")

            # precio grande y claro
            # precio_cop ya está expresado en pesos colombianos, no en centavos
            cop_formatted = f"COP {plan['precio_cop']:,.0f}".replace(",", ".")
            self._label(card, cop_formatted, font_size=22, bold=True,
                        color=C["text"]).pack(anchor="w", pady=(6, 0))
            self._label(card, plan["periodo"].strip(), font_size=10,
                        color=C["muted"]).pack(anchor="w", pady=(0, 4))

            # descripcion corta
            self._label(card, plan["descripcion"], color=C["muted"],
                        font_size=10, wraplength=self._s(230), justify="left").pack(anchor="w", pady=(0, 8))

            # separador
            tk.Frame(card, bg=C["border"], height=1).pack(fill="x", pady=(0, 8))

            # lista de caracteristicas, una por linea, clara
            for feat in plan.get("features", []):
                feat_row = tk.Frame(card, bg=C["card"])
                feat_row.pack(anchor="w", fill="x", pady=1)
                tk.Label(feat_row, text="✓", font=("Segoe UI", 10, "bold"),
                         bg=C["card"], fg=C["success"]).pack(side="left", padx=(0, 8))
                self._label(feat_row, feat, color=C["text"], font_size=9,
                            wraplength=self._s(210), justify="left").pack(side="left")

            # boton comprar
            def on_buy(pk=plan_key, pw=win):
                pw.destroy()
                self._show_wompi_checkout(pk)

            tk.Button(card, text=f"Elegir {plan['nombre'].lower()}",
                      command=on_buy,
                      bg=plan["color"], fg="#000000",
                      font=("Segoe UI", 11, "bold"),
                      relief="flat", padx=18, pady=10,
                      cursor="hand2").pack(fill="x", pady=(10, 0))

        # ── plan para empresas ──────────────────────────────
        team = TEAM_PLANES["equipo_3"]
        strip = tk.Frame(win, bg=C["card"], padx=18, pady=10)
        strip.pack(fill="x", padx=42, pady=(0, 4))
        team_price = f"COP {team['precio_cop']:,.0f}".replace(",", ".")
        self._label(strip, f"👥 ¿Para tu empresa? Plan Equipo desde {team_price}/mes",
                    bold=True, color=team["color"]).pack(side="left")
        self._label(strip, "  Hasta 34 % menos por persona · registro de actividad e informe de seguridad",
                    color=C["muted"],
                    font_size=9).pack(side="left")
        tk.Button(strip, text="Ver paquetes", command=lambda: [win.destroy(), self._choose_team_plan()],
                  bg=team["color"], fg="#000000", font=("Segoe UI", 10, "bold"), relief="flat",
                  padx=12, pady=4, cursor="hand2").pack(side="right")

        # ── pie de pagina: explicacion breve y clara ─────────
        footer = tk.Frame(win, bg=C["bg"])
        footer.pack(fill="x", padx=30, pady=(0, 8))
        foot_btns = tk.Frame(footer, bg=C["bg"])
        foot_btns.pack(pady=(8, 0))
        self._btn(foot_btns, "🔑 Ya tengo un código",
                  lambda: [win.destroy(), self._activate_license_dialog()]).pack(side="left", padx=6)
        self._btn(foot_btns, "Volver", win.destroy).pack(side="left", padx=6)

    def _choose_team_plan(self):
        """Elige el paquete del plan Equipo y abre su pago."""
        options = []
        for key, plan in TEAM_PLANES.items():
            price = f"COP {plan['precio_cop']:,.0f}".replace(",", ".")
            per_user = (f" · {plan['precio_cop'] // plan['usuarios']:,.0f} por persona".replace(",", ".")
                        + (f" (−{plan['ahorro_pct']} %)" if plan["ahorro_pct"] > 0 else "")
                        if plan["usuarios"] else "")
            options.append((key, f"{plan['nombre'].split('· ')[1]} — {price}/mes{per_user}"))
        key = self._choose("Plan Equipo", "Un solo pago mensual de la empresa; te llegan por correo los códigos "
                                          "para repartir. Incluye Premium para cada persona, bóveda compartida "
                                          "con roles, registro de actividad e informe de seguridad.", options,
                           inline=True)
        if key:
            self._show_wompi_checkout(key)

    def _show_wompi_checkout(self, plan_key: str):
        """Abre el Payment Link fijo de Wompi para el plan y muestra las instrucciones de activación."""
        plan = ALL_PLANES[plan_key]

        if not WompiHelper.has_link(plan_key):
            messagebox.showerror(
                "Link no configurado",
                f"No hay un link de pago configurado para el plan {plan['nombre']} en esta versión. "
                "Escribe a soporte para completar tu compra.")
            return

        user_email = ""
        if self.current_user:
            user_email = self.current_user.get("email", "") or ""

        WompiHelper.open_checkout(plan_key)

        win = self._inline_page()
        win.title("💳 Pago en proceso")
        self._set_popup_geometry(win, 600, 580)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, "✅ Checkout abierto en tu navegador",
                    font_size=16, bold=True, color=C["success"]).pack(pady=(24, 8))
        price_text = f"COP {plan['precio_cop']:,.0f}".replace(",", ".")
        plan_title = plan["nombre"] if plan["plan"] == "equipo" else f"Premium {plan['nombre'].lower()}"
        self._label(win, f"Plan seleccionado: {plan_title} · {price_text}{plan['periodo']}",
                    color=C["muted"]).pack()

        body = self._card(win, padx=24, pady=20)
        body.pack(fill="x", padx=24, pady=16)

        # Aviso crítico: el código solo funciona en la cuenta con el email usado en el pago
        warn = tk.Frame(body, bg=C["warning"], padx=14, pady=10)
        warn.pack(fill="x", pady=(0, 14))
        if plan["plan"] == "equipo":
            n_codes = (f"los {plan['usuarios']} códigos" if plan["usuarios"] else "el código de empresa")
            warn_text = (f"⚠️ Te llegarán {n_codes} al email que escribas en Wompi.\n"
                         "Repártelos: cada persona lo activa en SU cuenta, con su propio correo.")
        elif user_email:
            warn_text = (f"⚠️ IMPORTANTE: paga con este email exacto:\n{user_email}\n"
                         f"El código sirve para esta cuenta, hasta en {MAX_DEVICES} equipos.")
        else:
            warn_text = ("⚠️ IMPORTANTE: paga con el MISMO email de tu cuenta de CipherVault.\n"
                         f"El código sirve para esa cuenta, hasta en {MAX_DEVICES} equipos.")
        tk.Label(warn, text=warn_text, font=("Segoe UI", 10, "bold"), wraplength=self._s(460),
                 bg=C["warning"], fg="#000000", justify="left").pack(anchor="w")

        if plan["plan"] == "equipo":
            steps = [
                "1️⃣  Completa el pago en la ventana del navegador.",
                "2️⃣  Al aprobarse, te llega un correo con los códigos (revisa también spam).",
                "3️⃣  Dale un código a cada persona: lo pega en «Activar licencia» de su cuenta.",
                "4️⃣  Luego crea el equipo en la pestaña «Bóveda de equipo» y agrega a cada persona.",
            ]
        else:
            steps = None
        steps = steps or [
            "1️⃣  Completa el pago en la ventana del navegador.",
            "2️⃣  Al aprobarse, recibirás un correo con tu código de activación.",
            "3️⃣  Vuelve aquí, pulsa «Activar licencia» y pega el código.",
            "4️⃣  Tu plan queda activo de inmediato (revisa también la carpeta de spam).",
        ]
        for step in steps:
            self._label(body, step, font_size=10, color=C["text"], wraplength=self._s(460),
                        justify="left").pack(anchor="w", pady=3)

        def reopen():
            WompiHelper.open_checkout(plan_key)

        btn_r = tk.Frame(win, bg=C["bg"])
        btn_r.pack(pady=12)
        tk.Button(btn_r, text="🔄 Reabrir checkout", command=reopen,
                  bg=C["wompi"], fg="#ffffff", font=("Segoe UI", 11, "bold"),
                  relief="flat", padx=16, pady=8, cursor="hand2").pack(side="left", padx=6)
        self._btn(btn_r, "🔑 Activar licencia",
                  lambda: [win.destroy(), self._activate_license_dialog()],
                  "Primary.TButton").pack(side="left", padx=6)
        self._btn(btn_r, "Cerrar", win.destroy).pack(side="left", padx=6)

    # ─────────────────────────────────────────
    #  INFORMACIÓN DE LICENCIA
    # ─────────────────────────────────────────
    def _show_license_info(self):
        """Muestra en una ventana emergente el estado actual de la licencia: usuario, email, plan, vigencia y tipo de cuenta."""
        win = self._inline_page()
        win.title("📜 Mi licencia")
        self._set_popup_geometry(win, 480, 360)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, "📜 Información de licencia",
                    font_size=18, bold=True, color=C["primary"]).pack(pady=(20, 12))

        body = self._card(win, padx=24, pady=20)
        body.pack(fill="x", padx=24)

        uname = self.current_user["username"] if self.current_user else "—"
        ver   = get_features(self.user_version)

        if self.is_developer:
            status = "Ilimitada ⚡"
            color  = C["primary"]
        else:
            expiry = self.current_user.get("license_expiry") if self.current_user else None
            if expiry:
                try:
                    ed = datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S")
                    status = f"Activa hasta {ed.strftime('%d/%m/%Y')}"
                    color  = C["success"]
                except Exception:
                    status = expiry
                    color  = C["muted"]
            else:
                status = "Versión gratuita"
                color  = C["muted"]

        items = [
            ("👤 Usuario",  uname),
            ("📧 Email",    (self.current_user.get("email") if self.current_user else None) or "— (no registrado)"),
            ("📦 Plan",     ver["name"]),
            ("⚡ Estado",   status),
            ("🔑 Tipo",     self.user_version.upper()),
        ]
        for lbl, val in items:
            row = tk.Frame(body, bg=C["card"])
            row.pack(fill="x", pady=4)
            self._label(row, lbl, bold=True, color=C["muted"]).pack(side="left")
            self._label(row, val, color=color).pack(side="left", padx=12)

        btn_r = tk.Frame(win, bg=C["bg"])
        btn_r.pack(pady=16)
        if self.user_version not in ("premium","developer"):
            self._btn(btn_r, "💳 Comprar plan", self._show_plans_screen, "Wompi.TButton").pack(side="left", padx=6)
        if self.current_user and self.user_version != "developer":
            self._btn(btn_r, "🔑 Activar licencia",
                      lambda: [win.destroy(), self._activate_license_dialog()]).pack(side="left", padx=6)
        self._btn(btn_r, "✅ Cerrar", win.destroy, "Primary.TButton").pack(side="left", padx=6)

    # ─────────────────────────────────────────
    #  CONFIGURACIÓN
    # ─────────────────────────────────────────
    def _tab_settings(self):
        """Pestaña de configuración: longitud predeterminada del generador y resumen de las funciones incluidas en el plan actual."""
        self._clear_content()
        f = self.content_frame
        self._label(f, "⚙️ Configuración", font_size=20, bold=True).pack(anchor="w", pady=(0, 16))

        card = self._card(f, padx=24, pady=20)
        card.pack(fill="x")

        feats = get_features(self.user_version)
        max_l = feats["password_length_max"]

        self._label(card, "Longitud predeterminada de contraseñas:",
                    bold=True, color=C["muted"]).pack(anchor="w", pady=(0, 6))
        lf = tk.Frame(card, bg=C["card"])
        lf.pack(fill="x", pady=(0, 16))
        self.settings_len = tk.IntVar(value=min(self.config.get("password_length", 16), max_l))
        tk.Scale(lf, from_=8, to=max_l, variable=self.settings_len,
                 orient="horizontal", bg=C["card"], fg=C["text"],
                 troughcolor=C["border"], highlightbackground=C["card"],
                 length=220).pack(side="left")
        self._label(lf, f"Máx: {max_l}", color=C["muted"]).pack(side="left", padx=10)

        self._label(card, "Bloqueo automático por inactividad:",
                    bold=True, color=C["muted"]).pack(anchor="w", pady=(0, 6))
        current_lock = self._lock_timeout_seconds()
        labels = {label: secs for label, secs in self.LOCK_CHOICES}
        current_label = next((label for label, secs in self.LOCK_CHOICES if secs == current_lock),
                             self.LOCK_CHOICES[3][0])
        self.settings_lock = tk.StringVar(value=current_label)
        ttk.Combobox(card, textvariable=self.settings_lock, values=list(labels), width=18,
                     state="readonly").pack(anchor="w", pady=(0, 16))

        btn_r = tk.Frame(card, bg=C["card"])
        btn_r.pack()
        self._btn(btn_r, "💾 Guardar", self._save_settings, "Primary.TButton").pack(side="left", padx=6)
        self._btn(btn_r, "🔄 Restablecer", self._reset_settings).pack(side="left", padx=6)

        # seguridad de la cuenta
        # Seguridad (izquierda) y funciones del plan (derecha) en una misma fila.
        sec_info_row = tk.Frame(f, bg=C["bg"])
        sec_info_row.pack(fill="x", pady=(12, 0))
        # Auto-escritura (izquierda) y sincronización (derecha) en otra fila.
        extra_row = tk.Frame(f, bg=C["bg"])
        extra_row.pack(fill="x", pady=(12, 0))
        sec = self._card(sec_info_row, padx=24, pady=20)
        sec.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self._label(sec, "Seguridad de la cuenta", bold=True).pack(anchor="w", pady=(0, 8))
        sec_row = tk.Frame(sec, bg=C["card"])
        sec_row.pack(anchor="w")
        self._btn(sec_row, "🔐 Cambiar contraseña maestra", self._change_master_password).pack(side="left", padx=(0, 8))
        self._btn(sec_row, "📄 Kit de emergencia (PDF)", self._save_emergency_kit).pack(side="left")

        if IS_WINDOWS:
            with db() as conn:
                hello_on = bool((get_user_by_id(conn, self.current_user["id"]) or {}).get("hello_wrapped"))
            self._label(sec, "Windows Hello (huella, rostro o PIN)", bold=True,
                        color=C["muted"]).pack(anchor="w", pady=(14, 4))
            if hello_on:
                self._label(sec, "✅ Activado: puedes entrar sin escribir la contraseña maestra.",
                            color=C["success"], font_size=10).pack(anchor="w")
                self._btn(sec, "Desactivar Windows Hello", self._disable_hello).pack(anchor="w", pady=(6, 0))
            else:
                self._btn(sec, "🪟 Activar Windows Hello", self._enable_hello).pack(anchor="w")

        # verificación en dos pasos al iniciar sesión (Premium y Equipo)
        with db() as conn:
            u2 = get_user_by_id(conn, self.current_user["id"]) or {}
        tfa_on = bool(u2.get("login_totp"))
        self._label(sec, "Verificación en dos pasos al iniciar sesión", bold=True,
                    color=C["muted"]).pack(anchor="w", pady=(14, 4))
        if tfa_on:
            try:
                left = len(json.loads(u2.get("login_totp_backup") or "[]"))
            except ValueError:
                left = 0
            self._label(sec, f"✅ Activada: después de la contraseña maestra se pide el código de tu "
                             f"celular. Códigos de respaldo sin usar: {left}.",
                        color=C["success"], font_size=10, wraplength=self._s(440), justify="left").pack(anchor="w")
            row2 = tk.Frame(sec, bg=C["card"])
            row2.pack(anchor="w", pady=(6, 0))
            self._btn(row2, "🔁 Nuevos códigos de respaldo", self._regen_backup_codes).pack(side="left", padx=(0, 8))
            self._btn(row2, "Desactivar", self._disable_login_2fa).pack(side="left")
        elif get_features(self.user_version).get("login_2fa"):
            self._label(sec, "Pide además un código de 6 dígitos de Google Authenticator, Microsoft "
                             "Authenticator u otra app similar cada vez que entras.",
                        color=C["muted"], font_size=10, wraplength=self._s(440), justify="left").pack(anchor="w")
            self._btn(sec, "📱 Activar verificación en dos pasos", self._enable_login_2fa).pack(anchor="w", pady=(6, 0))
        else:
            self._label(sec, "🔒 Disponible en los planes Premium y Equipo.", color=C["muted"],
                        font_size=10).pack(anchor="w")
            self._btn(sec, "Ver planes", self._show_plans_screen).pack(anchor="w", pady=(6, 0))

        # auto-escritura (Windows y macOS)
        if IS_WINDOWS or sys.platform == "darwin":
            auto = self._card(extra_row, padx=24, pady=16)
            auto.pack(side="left", fill="both", expand=True, padx=(0, 6))
            self._label(auto, f"Auto-escritura ({cvx.AUTOTYPE_HOTKEY_LABEL})", bold=True).pack(anchor="w")
            self._label(auto, "Abre la página de inicio de sesión, haz clic en el campo de usuario y pulsa "
                              f"{cvx.AUTOTYPE_HOTKEY_LABEL}: CipherVault escribe tu usuario y contraseña. "
                              "En el navegador reconoce el sitio por la dirección de la página (la página "
                              "web guardada o, si no la tiene, el nombre del servicio); en otros programas, "
                              "por el título de la ventana.",
                        color=C["muted"], font_size=9, wraplength=self._s(440), justify="left"
                        ).pack(anchor="w", pady=(4, 8))
            self.settings_autotype = tk.BooleanVar(value=bool(self.config.get("autotype_enabled", True)))
            self.settings_enter = tk.BooleanVar(value=bool(self.config.get("autotype_enter", False)))
            for text, var in (("Activar el atajo", self.settings_autotype),
                              ("Pulsar Enter al final (inicia sesión de una vez)", self.settings_enter)):
                tk.Checkbutton(auto, text=text, variable=var, bg=C["card"], fg=C["text"],
                               selectcolor=C["card2"], activebackground=C["card"],
                               activeforeground=C["text"], font=("Segoe UI", 10), highlightthickness=0,
                               command=self._save_autotype_settings).pack(anchor="w")
            hotkey = getattr(self, "_hotkey", None)
            if hotkey and hotkey.error:
                self._label(auto, f"⚠️ {hotkey.error}", color=C["warning"], font_size=9,
                            wraplength=self._s(440), justify="left").pack(anchor="w", pady=(6, 0))
            if sys.platform == "darwin" and not cvx.mac_accessibility_trusted():
                self._btn(auto, "Abrir ajustes de Accesibilidad",
                          cvx.open_mac_accessibility_settings).pack(anchor="w", pady=(6, 0))

        # info versión
        if feats.get("sync"):
            sync_card = self._card(extra_row, padx=24, pady=16)
            sync_card.pack(side="left", fill="both", expand=True, padx=(6, 0))
            cfg = self._sync_config()
            head = tk.Frame(sync_card, bg=C["card"])
            head.pack(fill="x")
            self._label(head, "Sincronizar entre tus equipos", bold=True).pack(side="left")
            if cfg:
                self._label(sync_card, f"📁 {cfg['path']}", color=C["muted"], font_size=9,
                            wraplength=self._s(440), justify="left").pack(anchor="w", pady=(4, 0))
                if getattr(self, "_sync_status", ""):
                    self._label(sync_card, self._sync_status, color=C["muted"], font_size=9).pack(anchor="w")
                row = tk.Frame(sync_card, bg=C["card"])
                row.pack(anchor="w", pady=(6, 0))
                self._btn(row, "🔄 Sincronizar ahora", lambda: self._sync_now(interactive=True)).pack(side="left", padx=(0, 6))
                self._btn(row, "Desactivar", self._disable_sync).pack(side="left")
            else:
                self._label(sync_card, "Elige una carpeta de OneDrive, Google Drive o Dropbox. Tus contraseñas "
                                       "se guardan ahí cifradas: nunca pasan por servidores de CipherVault.",
                            color=C["muted"], font_size=9, wraplength=self._s(440), justify="left"
                            ).pack(anchor="w", pady=(4, 6))
                self._btn(sync_card, "📁 Elegir carpeta y activar", self._enable_sync).pack(anchor="w")

        info = self._card(sec_info_row, padx=24, pady=20)
        info.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self._label(info, f"✅ Funciones de tu plan {feats['name']}:", bold=True).pack(anchor="w", pady=(0, 8))
        for feature, val in [
            ("Máx contraseñas",     "Ilimitadas" if feats["max_passwords"]==-1 else str(feats["max_passwords"])),
            ("Análisis de seguridad", "✅" if feats["security_analysis"] else "❌"),
            ("Categorías",           "✅" if feats["categories"] else "❌"),
            ("Exportación",          "✅" if feats["export"] else "❌"),
            ("Backup automático",    "✅" if feats["backup"] else "❌"),
            ("Long. máx contraseña", f"{feats['password_length_max']} caracteres"),
        ]:
            row = tk.Frame(info, bg=C["card"])
            row.pack(fill="x", pady=2)
            self._label(row, feature, color=C["muted"]).pack(side="left")
            self._label(row, val, color=C["text"]).pack(side="left", padx=12)

    LOCK_CHOICES = [("Desactivado", 0), ("1 minuto", 60), ("2 minutos", 120), ("5 minutos", 300),
                    ("10 minutos", 600), ("15 minutos", 900), ("30 minutos", 1800)]

    def _save_autotype_settings(self):
        self.config["autotype_enabled"] = bool(self.settings_autotype.get())
        self.config["autotype_enter"] = bool(self.settings_enter.get())
        self._save_config()
        self._start_autotype()

    def _save_settings(self):
        """Guarda la longitud de contraseña predeterminada y el tiempo de bloqueo automático."""
        self.config["password_length"] = self.settings_len.get()
        self.config["lock_timeout"] = dict(self.LOCK_CHOICES).get(self.settings_lock.get(), 300)
        self._save_config()
        messagebox.showinfo("✅ Guardado", "Configuración guardada.")

    def _reset_settings(self):
        """Restablece la configuración a sus valores por defecto, con confirmación previa."""
        if messagebox.askyesno("Confirmar", "¿Restablecer configuración por defecto?"):
            self.config["password_length"] = 16
            self.config["lock_timeout"] = 300
            self._save_config()
            self._tab_settings()

    # ─────────────────────────────────────────
    #  DEV TOOLS
    # ─────────────────────────────────────────
    def _tab_dev_tools(self):
        """Pestaña de herramientas de desarrollador (solo visible en modo developer): estadísticas de la base de datos, datos de prueba, limpieza de contraseñas, acceso a la carpeta de datos, exportación y activación manual de licencias."""
        self._clear_content()
        f = self.content_frame
        self._label(f, "⚡ Dev Tools", font_size=20, bold=True, color=C["primary"]).pack(anchor="w", pady=(0, 16))

        tools = [
            ("📊 Stats DB",            self._dev_db_stats),
            ("🗂️ Generar datos prueba", self._dev_generate_test_data),
            ("🧹 Limpiar mis datos",    self._dev_reset_my_passwords),
            ("📁 Abrir carpeta datos",  self._dev_open_folder),
            ("📋 Exportar todo",        self._dev_export_all),
            ("🔑 Activar licencia manual", self._dev_activate_license),
        ]
        grid = tk.Frame(f, bg=C["bg"])
        grid.pack(fill="x")
        for i,(txt,cmd) in enumerate(tools):
            card = self._card(grid, padx=16, pady=14)
            card.grid(row=i//3, column=i%3, padx=6, pady=6, sticky="nsew")
            grid.columnconfigure(i%3, weight=1)
            self._label(card, txt, bold=True, color=C["secondary"]).pack(anchor="w", pady=(0, 8))
            self._btn(card, "Abrir", cmd, "Primary.TButton").pack(anchor="w")

    def _dev_db_stats(self):
        """Muestra estadísticas rápidas de la base de datos local (usuarios, contraseñas y tamaño en disco)."""
        with db() as conn:
            users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            pwds = conn.execute("SELECT COUNT(*) FROM passwords").fetchone()[0]
        size  = os.path.getsize(DB_FILE) / 1024
        messagebox.showinfo("📊 Stats DB",
            f"Usuarios: {users}\nContraseñas totales: {pwds}\n"
            f"Tamaño DB: {size:.1f} KB\nRuta: {DB_FILE}\nLog: {LOG_FILE}")

    def _dev_generate_test_data(self):
        """Inserta un conjunto de contraseñas de ejemplo, útil para probar la interfaz sin capturar datos reales."""
        samples = [
            ("Google","test@gmail.com","G00gle!2025","MUY FUERTE","Trabajo"),
            ("GitHub","dev@github.com","GitH0b!Dev","MUY FUERTE","Trabajo"),
            ("Netflix","user@netflix.com","N3tfl!x24","FUERTE","Personal"),
            ("Spotify","music@spotify.com","Sp0t!fy24","MODERADA","Personal"),
            ("PayPal","pay@paypal.com","P@yP4l2025","MUY FUERTE","Finanzas"),
        ]
        vault = self.current_user["vault"]
        with db() as conn:
            for svc, uname, pwd, strength, cat in samples:
                conn.execute("""INSERT INTO passwords(user_id,service,username,password_encrypted,strength,category,notes)
                                VALUES(?,?,?,?,?,?,?)""",
                             (self.current_user["id"], enc_text(vault, svc), enc_text(vault, uname),
                              vault.encrypt(pwd.encode("utf-8")).decode("ascii"), strength, cat, enc_text(vault, "")))
        messagebox.showinfo("✅", f"Se agregaron {len(samples)} contraseñas de prueba.")

    def _dev_reset_my_passwords(self):
        """Elimina todas las contraseñas guardadas del usuario actual, con confirmación previa."""
        if messagebox.askyesno("⚠️ Confirmar",
            "¿Eliminar TODAS tus contraseñas? Esta acción no se puede deshacer."):
            with db() as conn:
                conn.execute("DELETE FROM passwords WHERE user_id=?", (self.current_user["id"],))
            messagebox.showinfo("✅", "Todas tus contraseñas eliminadas.")

    def _dev_open_folder(self):
        """Abre en el explorador de archivos del sistema operativo la carpeta donde vive la base de datos y la configuración."""
        folder = os.path.dirname(DB_FILE)
        try:
            if platform.system() == "Windows":
                os.startfile(folder)
            elif platform.system() == "Darwin":
                import subprocess; subprocess.run(["open", folder])
            else:
                import subprocess; subprocess.run(["xdg-open", folder])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _dev_export_all(self):
        """Atajo de Dev Tools que reutiliza la exportación cifrada de la bóveda (_export_vault)."""
        self._export_vault()

    @staticmethod
    def _safe_filename(text: str) -> str:
        """Deja solo letras, números, punto, guion y guion bajo (para nombres de archivo)."""
        return re.sub(r"[^A-Za-z0-9_.\-]", "_", text or "") or "usuario"

    def _choose(self, title: str, message: str, options: list[tuple[str, str]],
                inline: bool = False) -> str | None:
        """Una opción por botón; devuelve la clave elegida o None. Por defecto es una ventanita
        de pregunta; con `inline=True` se muestra como pantalla dentro de la app."""
        win = self._inline_page() if inline else tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        self._set_popup_geometry(win, 560, 150 + 56 * len(options))
        choice: dict[str, str | None] = {"value": None}
        self._label(win, title, font_size=15, bold=True).pack(pady=(18, 4))
        self._label(win, message, color=C["muted"], font_size=10, wraplength=self._s(500),
                    justify="center").pack(padx=20, pady=(0, 12))
        for key, text in options:
            def pick(k=key):
                choice["value"] = k
                win.destroy()
            self._btn(win, text, pick, "Primary.TButton" if key == options[0][0] else "Secondary.TButton"
                      ).pack(fill="x", padx=40, pady=4)
        self._btn(win, "Cancelar", win.destroy).pack(pady=(8, 12))
        try:
            win.grab_set()
        except tk.TclError:
            pass
        self.root.wait_window(win)
        return choice["value"]

    def _vault_records(self) -> list[dict] | None:
        """Todas las entradas del usuario, descifradas (para exportar)."""
        vault = self.current_user["vault"]
        with db() as conn:
            rows = conn.execute("""SELECT service,username,password_encrypted,strength,category,notes,
                                          created_at,url,totp
                                   FROM passwords WHERE user_id=?""", (self.current_user["id"],)).fetchall()
        records = []
        try:
            for service, username, encrypted, strength, category, notes, created_at, url, totp in rows:
                records.append({"service": dec_text(vault, service), "username": dec_text(vault, username),
                                "password": vault.decrypt(encrypted.encode("utf-8")).decode("utf-8"),
                                "strength": strength, "category": category, "notes": dec_text(vault, notes),
                                "created_at": created_at, "url": dec_text(vault, url),
                                "totp": dec_text(vault, totp)})
        except (InvalidToken, UnicodeDecodeError):
            messagebox.showerror("Error de bóveda", "No se pudo preparar la exportación.")
            return None
        return records

    def _export_vault(self):
        """Exportar: respaldo cifrado .cvault (recomendado) o CSV sin cifrar para llevar
        las contraseñas a otro gestor o navegador."""
        if not get_features(self.user_version).get("export"):
            messagebox.showwarning("Plan requerido", "La exportación requiere el plan Premium.")
            return
        fmt = self._choose("Exportar bóveda", "¿En qué formato quieres exportar tus contraseñas?", [
            ("cvault", "🔒 Respaldo cifrado .cvault (recomendado)"),
            ("csv", "📄 CSV sin cifrar (para Chrome, Edge, Bitwarden…)"),
        ])
        if fmt == "csv":
            self._export_csv()
        elif fmt == "cvault":
            self._export_cvault()

    def _export_cvault(self):
        """Crea un respaldo cifrado (.cvault) en la ubicación que elija el usuario, protegido
        con una contraseña propia."""
        if not self._ask_master():
            return
        export_password = simpledialog.askstring(
            "Proteger exportación", "Crea una contraseña para el archivo exportado (mínimo 12 caracteres):", show="*")
        if not export_password or len(export_password) < 12:
            messagebox.showerror("Contraseña insuficiente", "La contraseña de exportación debe tener al menos 12 caracteres.")
            return
        confirm = simpledialog.askstring("Confirmar contraseña", "Escríbela otra vez:", show="*")
        if confirm != export_password:
            messagebox.showerror("No coinciden", "Las contraseñas no coinciden. No se creó el archivo.")
            return
        records = self._vault_records()
        if records is None:
            return

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        documents = Path.home() / "Documents"
        path = filedialog.asksaveasfilename(
            title="Guardar respaldo cifrado", defaultextension=".cvault",
            initialdir=str(documents if documents.is_dir() else DATA_PATH),
            initialfile=f"export_{self._safe_filename(self.current_user['username'])}_{stamp}.cvault",
            filetypes=[("Respaldo cifrado de CipherVault", "*.cvault")])
        if not path:
            return
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", export_password.encode("utf-8"), salt, VAULT_KDF_ITERATIONS, dklen=32)
        payload = _fernet_from_key(key).encrypt(json.dumps(records, ensure_ascii=False).encode("utf-8"))
        try:
            Path(path).write_text(json.dumps({
                "format": "CipherVault encrypted backup v1", "salt": _b64(salt),
                "iterations": VAULT_KDF_ITERATIONS, "ciphertext": _b64(payload)}, indent=2), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("No se pudo guardar", str(exc))
            return
        messagebox.showinfo("✅ Exportado", f"Respaldo cifrado guardado en:\n{path}\n\nNo compartas la contraseña de exportación.")

    def _export_csv(self):
        """Exporta un CSV SIN CIFRAR (formato de Chrome/Edge + totp y categoría), con advertencia."""
        if not messagebox.askyesno(
                "⚠️ Archivo sin cifrar",
                "El CSV guarda tus contraseñas en TEXTO PLANO: cualquiera que abra el archivo puede leerlas.\n\n"
                "Úsalo solo para importarlas en otro gestor o navegador y bórralo justo después.\n\n¿Continuar?"):
            return
        if not self._ask_master():
            return
        records = self._vault_records()
        if records is None:
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Guardar CSV (sin cifrar)", defaultextension=".csv",
            initialfile=f"ciphervault_{self._safe_filename(self.current_user['username'])}_{stamp}.csv",
            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        try:
            # utf-8-sig: Excel lo abre con tildes correctas.
            Path(path).write_text(cvx.records_to_csv(records), encoding="utf-8-sig", newline="")
        except OSError as exc:
            messagebox.showerror("No se pudo guardar", str(exc))
            return
        log.info("Bóveda exportada a CSV (%d entradas)", len(records))
        messagebox.showinfo("✅ CSV exportado",
                            f"Se exportaron {len(records)} contraseñas a:\n{path}\n\n"
                            "Recuerda borrar este archivo cuando termines.")

    def _insert_records(self, records: list, source: str) -> dict | None:
        """Guarda entradas importadas (de .cvault o CSV). Omite las que ya existen (mismo
        servicio y usuario) y respeta el límite del plan. Devuelve el conteo o None si falla."""
        feats = get_features(self.user_version)
        vault = self.current_user["vault"]
        counts = {"imported": 0, "duplicate": 0, "limit": 0, "invalid": 0}
        try:
            with db() as conn:
                existing = {(dec_text(vault, s).lower(), dec_text(vault, u).lower()) for s, u in conn.execute(
                    "SELECT service, username FROM passwords WHERE user_id=?", (self.current_user["id"],))}
                total = len(existing)
                for rec in records:
                    if not isinstance(rec, dict) or not all(isinstance(rec.get(k), str) and rec.get(k)
                                                            for k in ("service", "password")) \
                            or not isinstance(rec.get("username", ""), str):
                        counts["invalid"] += 1
                        continue
                    username = rec.get("username", "")
                    ident = (rec["service"].lower(), username.lower())
                    if ident in existing:
                        counts["duplicate"] += 1
                        continue
                    if feats["max_passwords"] != -1 and total >= feats["max_passwords"]:
                        counts["limit"] += 1
                        continue
                    notes = str(rec.get("notes") or "")[:feats["notes_max_length"]]
                    totp = str(rec.get("totp") or "").strip()
                    if totp:
                        try:
                            cvx.parse_totp(totp)
                        except ValueError:
                            notes = (notes + f"\n2FA (no reconocido): {totp}").strip()[:feats["notes_max_length"]]
                            totp = ""
                    strength, _ = self._eval_strength(rec["password"])
                    conn.execute(
                        "INSERT INTO passwords(user_id,service,username,password_encrypted,strength,category,"
                        "notes,url,totp) VALUES(?,?,?,?,?,?,?,?,?)",
                        (self.current_user["id"], enc_text(vault, rec["service"]), enc_text(vault, username),
                         vault.encrypt(rec["password"].encode("utf-8")).decode("ascii"), strength,
                         str(rec.get("category") or "General")[:40], enc_text(vault, notes),
                         enc_text(vault, str(rec.get("url") or "")), enc_text(vault, totp)))
                    existing.add(ident)
                    total += 1
                    counts["imported"] += 1
        except sqlite3.Error:
            log.exception("Fallo al importar (%s)", source)
            messagebox.showerror("Error", "No se pudo importar. No se hicieron cambios.")
            return None
        log.info("Importación %s: %s", source, counts)
        self._auto_backup()
        return counts

    def _import_summary(self, counts: dict, extra: str = "") -> str:
        summary = f"Importadas: {counts['imported']}"
        if counts["duplicate"]:
            summary += f"\nYa existían (omitidas): {counts['duplicate']}"
        if counts["limit"]:
            summary += (f"\nSuperaban el límite de tu plan (omitidas): {counts['limit']}"
                        "\n→ Con Premium no hay límite de contraseñas.")
        if counts["invalid"]:
            summary += f"\nEntradas inválidas (omitidas): {counts['invalid']}"
        return summary + extra

    def _import_vault(self, path: str | None = None):
        """Importa contraseñas desde un respaldo .cvault de CipherVault o desde un CSV exportado
        por Chrome, Edge, Firefox, Bitwarden, LastPass, 1Password, KeePass, Apple u otro gestor."""
        if path is None:
            path = filedialog.askopenfilename(
                title="Elegir archivo para importar",
                filetypes=[("Respaldo de CipherVault o CSV", "*.cvault *.csv"),
                           ("Respaldo cifrado de CipherVault", "*.cvault"),
                           ("CSV de navegador u otro gestor", "*.csv"), ("Todos los archivos", "*.*")])
        if not path:
            return
        if path.lower().endswith(".csv"):
            self._import_csv(path)
        else:
            self._import_cvault(path)

    def _import_csv(self, path: str):
        """Importa un CSV de contraseñas y ofrece borrar el archivo (está sin cifrar)."""
        try:
            raw = Path(path).read_bytes()
            if len(raw) > cvx.MAX_CSV_BYTES:
                raise ValueError("El archivo es demasiado grande.")
            records, skipped = cvx.parse_password_csv(cvx.decode_csv_bytes(raw))
        except (OSError, ValueError, csv.Error) as exc:
            messagebox.showerror("No se pudo leer el CSV", str(exc))
            return
        if not records:
            messagebox.showwarning("Sin contraseñas", "El archivo no tiene contraseñas para importar.")
            return
        counts = self._insert_records(records, "csv")
        if counts is None:
            return
        extra = f"\nFilas sin contraseña o que no son inicios de sesión: {skipped}" if skipped else ""
        messagebox.showinfo("Importación terminada", self._import_summary(counts, extra))
        if counts["imported"] and messagebox.askyesno(
                "Borrar el CSV",
                "El archivo CSV tiene tus contraseñas SIN CIFRAR. Ya están guardadas en CipherVault.\n\n"
                f"¿Borrar ahora el archivo?\n{path}"):
            try:
                Path(path).unlink()
            except OSError as exc:
                messagebox.showwarning("No se pudo borrar", f"Bórralo a mano: {exc}")
        if hasattr(self, "content_frame") and self.content_frame.winfo_exists():
            self._tab_list()

    def _import_cvault(self, path: str):
        """Importa un respaldo .cvault (creado con «Exportar bóveda»)."""
        if not self._ask_master():
            return
        backup_password = simpledialog.askstring(
            "Contraseña del respaldo", "Escribe la contraseña con la que se protegió ese archivo:", show="*")
        if not backup_password:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            iterations = int(data["iterations"])
            if not 100_000 <= iterations <= 5_000_000:
                raise ValueError("iteraciones fuera de rango")
            salt = base64.urlsafe_b64decode(data["salt"].encode("ascii"))
            token = base64.urlsafe_b64decode(data["ciphertext"].encode("ascii"))
            key = hashlib.pbkdf2_hmac("sha256", backup_password.encode("utf-8"), salt, iterations, dklen=32)
            records = json.loads(_fernet_from_key(key).decrypt(token).decode("utf-8"))
            if not isinstance(records, list):
                raise ValueError("formato inesperado")
        except (OSError, ValueError, KeyError, TypeError, InvalidToken):
            messagebox.showerror("No se pudo abrir",
                                 "El archivo está dañado o la contraseña es incorrecta. No se importó nada.")
            return
        counts = self._insert_records(records, "cvault")
        if counts is None:
            return
        messagebox.showinfo("Importación terminada", self._import_summary(counts))
        if hasattr(self, "content_frame") and self.content_frame.winfo_exists():
            self._tab_list()

    # ══════════════════════════════════════════
    #  VERIFICACIÓN EN DOS PASOS AL INICIAR SESIÓN
    # ══════════════════════════════════════════
    def _draw_qr(self, parent, text: str, size: int = 220) -> tk.Canvas:
        """Dibuja un código QR en un Canvas (fondo blanco y margen, para que lo lea el celular)."""
        matrix = cvx.qr_matrix(text)
        border = 4
        n = len(matrix) + 2 * border
        cell = max(2, self._s(size) // n)
        canvas = tk.Canvas(parent, width=cell * n, height=cell * n, bg="white", highlightthickness=0, bd=0)
        for y, row in enumerate(matrix):
            for x, dark in enumerate(row):
                if dark:
                    x0, y0 = (x + border) * cell, (y + border) * cell
                    canvas.create_rectangle(x0, y0, x0 + cell, y0 + cell, fill="black", width=0)
        return canvas

    def _enable_login_2fa(self):
        """Activa la verificación en dos pasos: muestra el QR, pide un código para confirmar
        que el celular quedó bien configurado y entrega los códigos de respaldo."""
        if not get_features(self.user_version).get("login_2fa"):
            messagebox.showinfo("Verificación en dos pasos", "Disponible en los planes Premium y Equipo.")
            self._show_plans_screen()
            return
        if not self._ask_master():
            return
        secret = cvx.new_login_secret()
        account = self.current_user.get("email") or self.current_user["username"]
        uri = cvx.login_totp_uri(secret, account)

        win = self._inline_page()
        win.title("Verificación en dos pasos")
        body = tk.Frame(win, bg=C["bg"])
        body.pack(fill="x", padx=24, pady=8)
        self._label(body, "📱 Verificación en dos pasos", font_size=20, bold=True).pack(anchor="w")
        self._label(body, "Después de tu contraseña maestra, CipherVault te pedirá el código de 6 dígitos "
                          "que muestra tu celular. Así nadie entra solo con tu contraseña.",
                    color=C["muted"], font_size=10, wraplength=self._s(640), justify="left").pack(anchor="w", pady=(4, 14))
        card = self._card(body, padx=24, pady=20)
        card.pack(fill="x")
        cols = tk.Frame(card, bg=C["card"])
        cols.pack(fill="x")
        try:
            self._draw_qr(cols, uri).pack(side="left", padx=(0, 24), anchor="n")
        except ImportError:
            log.warning("Falta el paquete segno: no se puede dibujar el QR")
        steps = tk.Frame(cols, bg=C["card"])
        steps.pack(side="left", fill="both", expand=True)
        self._label(steps, "1. Abre Google Authenticator, Microsoft Authenticator o una app similar y "
                           "escanea este código QR.", wraplength=self._s(420), justify="left").pack(anchor="w")
        self._label(steps, "¿No puedes escanearlo? Agrega una cuenta con esta clave:", color=C["muted"],
                    font_size=10).pack(anchor="w", pady=(10, 2))
        key_var = tk.StringVar(value=cvx.group_secret(secret))
        key_row = tk.Frame(steps, bg=C["card"])
        key_row.pack(anchor="w")
        tk.Entry(key_row, textvariable=key_var, state="readonly", width=40, font=("Consolas", 12),
                 readonlybackground=C["card2"], fg=C["text"], relief="flat", bd=6).pack(side="left")
        self._btn(key_row, "📋", lambda: self._copy_secret(secret, 60)).pack(side="left", padx=(6, 0))
        self._label(steps, "2. Escribe el código de 6 dígitos que aparece en la app:",
                    wraplength=self._s(420), justify="left").pack(anchor="w", pady=(16, 4))
        code_var = tk.StringVar()
        code_row = tk.Frame(steps, bg=C["card"])
        code_row.pack(anchor="w")
        code_entry = ttk.Entry(code_row, textvariable=code_var, width=10, font=("Consolas", 14))
        code_entry.pack(side="left")
        code_entry.focus_set()
        msg = self._label(steps, "", color=C["danger"], font_size=10)
        msg.pack(anchor="w", pady=(6, 0))

        def confirm(_event=None):
            counter = cvx.verify_login_totp(secret, code_var.get())
            if counter is None:
                msg.config(text="El código no coincide. Espera al siguiente y revisa la hora del celular.")
                return
            codes = cvx.new_backup_codes()
            uid = self.current_user["id"]
            with db() as conn:
                conn.execute("UPDATE users SET login_totp=?, login_totp_last=?, login_totp_backup=? WHERE id=?",
                             (enc_text(self.current_user["vault"], secret), str(counter),
                              json.dumps([cvx.hash_backup_code(uid, c) for c in codes]), uid))
            log.info("Verificación en dos pasos activada")
            win.destroy()
            self._show_backup_codes(codes, first_time=True)

        code_entry.bind("<Return>", confirm)
        self._btn(code_row, "✅ Verificar y activar", confirm, style="Primary.TButton").pack(side="left", padx=(8, 0))
        self._btn(body, "Cancelar", win.destroy).pack(anchor="w", pady=(14, 0))

    def _show_backup_codes(self, codes: list[str], first_time: bool = False):
        """Muestra una sola vez los códigos de respaldo, con opción de copiarlos o guardarlos."""
        win = self._inline_page()
        win.title("Códigos de respaldo")
        body = tk.Frame(win, bg=C["bg"])
        body.pack(fill="x", padx=24, pady=8)
        title = "✅ Verificación en dos pasos activada" if first_time else "🔁 Códigos de respaldo nuevos"
        self._label(body, title, font_size=20, bold=True).pack(anchor="w")
        self._label(body, "Guarda estos códigos en un lugar seguro (por ejemplo, en tu kit de emergencia). "
                          "Cada uno sirve una sola vez para entrar si pierdes o cambias el celular. "
                          "No se volverán a mostrar." + ("" if first_time else " Los códigos anteriores ya no sirven."),
                    color=C["muted"], font_size=10, wraplength=self._s(640), justify="left").pack(anchor="w", pady=(4, 14))
        card = self._card(body, padx=24, pady=20)
        card.pack(anchor="w")
        grid = tk.Frame(card, bg=C["card"])
        grid.pack()
        for i, code in enumerate(codes):
            tk.Label(grid, text=code, bg=C["card"], fg=C["text"], font=("Consolas", 14, "bold")
                     ).grid(row=i // 2, column=i % 2, padx=18, pady=4)
        text = "Códigos de respaldo de CipherVault (" + (self.current_user.get("email") or
                                                          self.current_user["username"]) + ")\n" + "\n".join(codes)

        def save():
            path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".txt",
                                                initialfile="CipherVault-codigos-de-respaldo.txt",
                                                filetypes=[("Texto", "*.txt")])
            if path:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                messagebox.showinfo("Guardado", "Códigos guardados. Guarda ese archivo en un lugar seguro.")

        row = tk.Frame(body, bg=C["bg"])
        row.pack(anchor="w", pady=(14, 0))
        self._btn(row, "📋 Copiar", lambda: self._copy_secret(text, 60)).pack(side="left", padx=(0, 8))
        self._btn(row, "💾 Guardar .txt", save).pack(side="left", padx=(0, 8))

        def done():
            win.destroy()
            self._tab_settings()
        self._btn(row, "Listo", done, style="Primary.TButton").pack(side="left")

    def _regen_backup_codes(self):
        if not self._ask_master():
            return
        codes = cvx.new_backup_codes()
        uid = self.current_user["id"]
        with db() as conn:
            conn.execute("UPDATE users SET login_totp_backup=? WHERE id=?",
                         (json.dumps([cvx.hash_backup_code(uid, c) for c in codes]), uid))
        log.info("Códigos de respaldo de la verificación en dos pasos regenerados")
        self._show_backup_codes(codes)

    def _disable_login_2fa(self):
        """Desactiva la verificación en dos pasos (pide la maestra y un código vigente)."""
        if not self._ask_master():
            return
        with db() as conn:
            user = get_user_by_id(conn, self.current_user["id"])
        try:
            secret = dec_text(self.current_user["vault"], user.get("login_totp"))
        except Exception:  # noqa: BLE001
            secret = ""
        code = simpledialog.askstring("Desactivar verificación en dos pasos",
                                      "Escribe el código de 6 dígitos de tu celular\n(o un código de respaldo):",
                                      parent=self.root)
        if code is None:
            return
        if not self._consume_login_code(user, secret, code):
            self._register_failure(user["username"])
            messagebox.showerror("Error", "El código no es correcto o ya se usó.")
            return
        with db() as conn:
            conn.execute("UPDATE users SET login_totp=NULL, login_totp_last=NULL, login_totp_backup=NULL "
                         "WHERE id=?", (user["id"],))
        log.info("Verificación en dos pasos desactivada")
        messagebox.showinfo("Verificación en dos pasos", "Se desactivó. Ahora entras solo con tu contraseña maestra.")
        self._tab_settings()

    def _change_master_password(self):
        """Cambia la contraseña maestra: pide la actual, genera un salt nuevo y vuelve a cifrar
        TODA la bóveda en una sola transacción (si algo falla, no cambia nada)."""
        if not self._ask_master():
            return
        new_pwd = simpledialog.askstring("Nueva contraseña maestra",
                                         "Nueva contraseña maestra (mínimo 12 caracteres):", show="*")
        if not new_pwd:
            return
        if len(new_pwd) < 12:
            messagebox.showerror("Contraseña insuficiente", "Debe tener al menos 12 caracteres.")
            return
        if simpledialog.askstring("Confirmar", "Escríbela otra vez:", show="*") != new_pwd:
            messagebox.showerror("No coinciden", "Las contraseñas no coinciden. No se cambió nada.")
            return

        old_vault = self.current_user["vault"]
        new_salt = _b64(os.urandom(16))
        new_key = _derive_vault_key(new_pwd, new_salt)
        new_vault = _fernet_from_key(new_key)
        skipped = 0
        try:
            with db() as conn:
                rows = conn.execute(
                    "SELECT id, service, username, password_encrypted, notes, url, totp FROM passwords WHERE user_id=?",
                    (self.current_user["id"],)).fetchall()
                for pid, service, username, value, notes, url, totp in rows:
                    try:
                        plain = old_vault.decrypt(value.encode("utf-8"))
                    except InvalidToken:
                        skipped += 1      # ya era ilegible: se deja igual
                        continue
                    conn.execute(
                        "UPDATE passwords SET service=?, username=?, password_encrypted=?, notes=?, url=?, totp=? "
                        "WHERE id=?",
                        (enc_text(new_vault, dec_text(old_vault, service)),
                         enc_text(new_vault, dec_text(old_vault, username)),
                         new_vault.encrypt(plain).decode("ascii"),
                         enc_text(new_vault, dec_text(old_vault, notes)),
                         enc_text(new_vault, dec_text(old_vault, url)),
                         enc_text(new_vault, dec_text(old_vault, totp)), pid))
                user = get_user_by_id(conn, self.current_user["id"])
                seal = None
                if str(user.get("version") or "") in REDEEMABLE_PLANS and user.get("license_seal"):
                    seal = license_seal(user["id"], user["version"], user.get("license_expiry"), new_salt)
                # Windows Hello guardaba la clave anterior: se desactiva y hay que volver a activarlo.
                conn.execute("UPDATE users SET password_hash=?, vault_salt=?, master_key='v3', "
                             "license_seal=COALESCE(?, license_seal), hello_challenge=NULL, hello_wrapped=NULL "
                             "WHERE id=?",
                             (_make_login_hash(new_key), new_salt, seal, user["id"]))
                hello_was_on = bool(user.get("hello_wrapped"))
                for column in ("sync_path", "sync_key", "team_priv", "team_path", "login_totp"):
                    if user.get(column):
                        conn.execute(f"UPDATE users SET {column}=? WHERE id=?",
                                     (enc_text(new_vault, dec_text(old_vault, user[column])), user["id"]))
        except sqlite3.Error:
            log.exception("Fallo al cambiar la contraseña maestra")
            messagebox.showerror("Error", "No se pudo cambiar la contraseña. No se hicieron cambios.")
            return
        self.current_user["vault"] = new_vault
        log.info("Contraseña maestra cambiada")
        extra = f"\n\n{skipped} entrada(s) ya eran ilegibles y se dejaron como estaban." if skipped else ""
        if hello_was_on:
            extra += "\n\nWindows Hello se desactivó: vuelve a activarlo en Configuración."
        messagebox.showinfo("✅ Contraseña cambiada",
                            "Tu contraseña maestra se cambió y la bóveda se volvió a cifrar. Los respaldos "
                            "anteriores (carpeta backups y archivos .cvault) siguen abriéndose con la "
                            "contraseña de ese momento." + extra)

    def _dev_activate_license(self):
        """
        Activa una licencia directamente en la DB (modo desarrollador).
        Útil para activar sin pasar por el flujo de Wompi/Make.
        """
        win = self._inline_page()
        win.title("🔑 Activar licencia — Dev")
        self._set_popup_geometry(win, 480, 400)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, "🔑 Activar licencia directa",
                    font_size=16, bold=True).pack(pady=(20, 4))
        self._label(win,
                    "Activa directamente en la DB (sin pasar por Make)",
                    color=C["muted"], font_size=9).pack(pady=(0, 12))

        body = self._card(win, padx=24, pady=20)
        body.pack(fill="x", padx=20)

        self._label(body, "Usuario:", bold=True, color=C["muted"]).grid(row=0, column=0, sticky="w", pady=6)
        uv = tk.StringVar(value=self.current_user["username"] if self.current_user else "")
        ttk.Entry(body, textvariable=uv, width=26).grid(row=0, column=1, padx=10, pady=6)

        self._label(body, "Plan:", bold=True, color=C["muted"]).grid(row=1, column=0, sticky="w", pady=6)
        pv = tk.StringVar(value="premium")
        ttk.Combobox(body, textvariable=pv, values=sorted(REDEEMABLE_PLANS - {"developer"}),
                     width=23, state="readonly").grid(row=1, column=1, padx=10, pady=6)

        self._label(body, "Meses:", bold=True, color=C["muted"]).grid(row=2, column=0, sticky="w", pady=6)
        mv = tk.StringVar(value="1")
        ttk.Combobox(body, textvariable=mv, values=["1","3","6","12"],
                     width=23, state="readonly").grid(row=2, column=1, padx=10, pady=6)

        self._label(body, "Referencia:", bold=True, color=C["muted"]).grid(row=3, column=0, sticky="w", pady=6)
        rv = tk.StringVar(value=f"DEV-{int(datetime.now().timestamp())}")
        ttk.Entry(body, textvariable=rv, width=26).grid(row=3, column=1, padx=10, pady=6)

        status_lbl = self._label(win, "", color=C["success"], font_size=10)
        status_lbl.pack(pady=(8, 0))

        def activate():
            username  = uv.get().strip()
            plan_key  = pv.get()
            meses     = int(mv.get())
            reference = rv.get().strip()

            if not username:
                messagebox.showerror("Error", "Ingresa un nombre de usuario.")
                return
            if plan_key not in REDEEMABLE_PLANS:
                messagebox.showerror("Error", f"Plan inválido: {plan_key}")
                return

            expiry = datetime.now() + timedelta(days=30 * meses)
            try:
                with db() as conn:
                    found = set_user_license(conn, username, plan_key, expiry, reference,
                                             "dev_manual", "developer", f"{meses} mes(es)")
            except sqlite3.Error:
                log.exception("Fallo en la activación manual")
                messagebox.showerror("Error", "No se pudo activar. Revisa el archivo de registro.")
                return
            if not found:
                messagebox.showerror("Error", f"Usuario '{username}' no encontrado en la DB.")
                return
            status_lbl.config(
                text=f"✅ Licencia {plan_key.upper()} activada hasta {expiry.strftime('%d/%m/%Y')}")
            messagebox.showinfo("✅ Licencia activada",
                f"Usuario:  {username}\nPlan:     {plan_key.upper()}\n"
                f"Válida hasta: {expiry.strftime('%d/%m/%Y')}\nReferencia: {reference}\n\n"
                "El usuario verá el plan activo en su próximo login.")
            win.destroy()

        btn_r = tk.Frame(win, bg=C["bg"])
        btn_r.pack(pady=12)
        self._btn(btn_r, "✅ Activar en DB", activate, "Primary.TButton").pack(side="left", padx=6)
        self._btn(btn_r, "↩️ Cancelar", win.destroy).pack(side="left", padx=6)

    # ─────────────────────────────────────────
    #  PANEL DE DESARROLLADOR (login)
    # ─────────────────────────────────────────
    def _show_dev_panel(self):
        """Muestra información técnica del equipo y accesos rápidos para iniciar sesión como developer o configurar sus credenciales."""
        win = self._inline_page()
        win.title("⚙️ Dev Panel")
        self._set_popup_geometry(win, 560, 480)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, "⚙️ Panel de Desarrollador",
                    font_size=18, bold=True, color=C["primary"]).pack(pady=(20, 8))

        body = self._card(win, padx=24, pady=20)
        body.pack(fill="x", padx=24)

        dev_user_actual, _ = DeveloperLicenseManager.get_dev_credentials()
        info = [
            f"• Máquina: {platform.node()}",
            f"• Usuario SO: {getpass.getuser()}",
            f"• Sistema: {platform.system()} {platform.release()}",
            f"• Python: {platform.python_version()}",
            f"• Directorio: {BASE_PATH}",
            f"• Licencia dev: {os.path.exists(LICENSE_FILE)}",
            f"• DB: {os.path.basename(DB_FILE)}",
            f"• Usuario developer configurado: {dev_user_actual}",
        ]
        for line in info:
            self._label(body, line, font_size=10, color=C["muted"]).pack(anchor="w", pady=2)

        btn_r = tk.Frame(win, bg=C["bg"])
        btn_r.pack(pady=(16, 6))
        self._btn(btn_r, "🔐 Login como Developer",
                  lambda: [win.destroy(), self._auto_dev_login()],
                  "Dev.TButton").pack(side="left", padx=6)
        self._btn(btn_r, "👤 Configurar usuario/clave",
                  lambda: [win.destroy(), self._configure_dev_credentials()]).pack(side="left", padx=6)

        btn_r2 = tk.Frame(win, bg=C["bg"])
        btn_r2.pack(pady=(0, 10))
        self._btn(btn_r2, "↩️ Volver", win.destroy).pack(side="left", padx=6)

    def _configure_dev_credentials(self):
        """Formulario para elegir el usuario/contraseña de la cuenta developer,
        sin tener que tocar el .env a mano. Se guarda en un archivo local
        (dev_credentials.json) que nunca se versiona ni se distribuye."""
        win = self._inline_page()
        win.title("👤 Usuario/clave de Developer")
        self._set_popup_geometry(win, 420, 360)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()

        self._label(win, "👤 Configurar cuenta Developer",
                    font_size=15, bold=True, color=C["primary"]).pack(pady=(20, 4))

        current_user, current_pass = DeveloperLicenseManager.get_dev_credentials()
        existing_user_row = None
        try:
            with db() as conn:
                existing_user_row = conn.execute("SELECT username FROM users WHERE username=?",
                                                 (current_user,)).fetchone()
        except sqlite3.Error:
            pass

        if existing_user_row:
            self._label(
                win,
                f"⚠️ Ya existe una cuenta '{current_user}'. Si cambias la\n"
                f"contraseña aquí y mantienes el mismo usuario, la cuenta\n"
                f"ya creada seguirá usando su contraseña original para\n"
                f"descifrar tu bóveda (no se puede re-derivar sin ella).\n"
                f"Usa un usuario nuevo si quieres una cuenta limpia.",
                font_size=9, color=C["warning"]
            ).pack(padx=20, pady=(0, 10))

        body = self._card(win, padx=20, pady=16)
        body.pack(fill="x", padx=20)

        self._label(body, "Usuario:", font_size=10).pack(anchor="w")
        entry_user = ttk.Entry(body, width=28, font=("Segoe UI", 11))
        entry_user.insert(0, current_user)
        entry_user.pack(fill="x", pady=(2, 10))

        self._label(body, "Contraseña:", font_size=10).pack(anchor="w")
        entry_pass = ttk.Entry(body, width=28, font=("Segoe UI", 11), show="•")
        entry_pass.pack(fill="x", pady=(2, 4))

        def save():
            u = entry_user.get().strip()
            p = entry_pass.get()
            if not u or not p:
                messagebox.showwarning("Datos incompletos", "Escribe usuario y contraseña.")
                return
            if len(p) < 12:
                messagebox.showwarning("Contraseña débil", "Usa al menos 12 caracteres.")
                return
            DeveloperLicenseManager.save_dev_credentials(u, p)
            messagebox.showinfo(
                "✅ Guardado",
                f"Credenciales guardadas.\nUsuario: {u}\n\n"
                f"Usa '🔐 Login como Developer' en el Dev Panel para entrar."
            )
            win.destroy()

        btn_r = tk.Frame(win, bg=C["bg"])
        btn_r.pack(pady=16)
        self._btn(btn_r, "💾 Guardar", save, "Primary.TButton").pack(side="left", padx=6)
        self._btn(btn_r, "↩️ Cancelar", win.destroy).pack(side="left", padx=6)

    def _auto_dev_login(self):
        """Login rápido de developer (solo ejecutando desde código fuente en una máquina autorizada).
        Crea la cuenta si no existe, con el mismo formato que cualquier cuenta (v3 + vault_salt).
        Si la cuenta ya existe con OTRA contraseña, no toca nada: antes ese caso re-cifraba la
        bóveda con la clave equivocada y la dejaba ilegible."""
        if not DeveloperLicenseManager.is_developer_machine():
            messagebox.showerror("Dev login", "El modo desarrollador no está habilitado en este equipo.")
            return
        dev_username, dev_password = DeveloperLicenseManager.get_dev_credentials()
        if not dev_username or not dev_password:
            messagebox.showinfo("Dev login",
                                "Configura usuario y contraseña con «Configurar usuario/clave» "
                                "(o CIPHERVAULT_DEV_USERNAME / CIPHERVAULT_DEV_PASSWORD en tu .env).")
            return
        with db() as conn:
            user = get_user_by_name(conn, dev_username)
            if user is None:
                vault_salt = _b64(os.urandom(16))
                key = _derive_vault_key(dev_password, vault_salt)
                conn.execute(
                    "INSERT INTO users(username,email,password_hash,master_key,vault_salt,version,is_developer) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (dev_username, "", _make_login_hash(key), "v3", vault_salt, "developer", 1))
                user = get_user_by_name(conn, dev_username)
        auth = authenticate(dev_password, user)
        if not auth.ok:
            messagebox.showerror(
                "Dev login",
                f"La cuenta '{dev_username}' ya existe con otra contraseña maestra. No se modificó nada.\n"
                "Usa «Configurar usuario/clave» para elegir un usuario nuevo, o inicia sesión normalmente.")
            return
        self._open_session(user, auth)

    # ─────────────────────────────────────────
    #  LOGOUT
    # ─────────────────────────────────────────
    # ─────────────────────────────────────────
    #  TAREAS EN SEGUNDO PLANO / AVISOS
    # ─────────────────────────────────────────
    def _run_background(self, func, on_done):
        """Ejecuta func() en un hilo (para no congelar la ventana) y llama on_done(resultado,
        error) en el hilo de Tk cuando termina."""
        box: dict = {}

        def worker():
            try:
                box["result"] = func()
            except Exception as exc:          # noqa: BLE001 - se entrega a on_done
                box["error"] = exc

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

        def check():
            if thread.is_alive():
                self.root.after(100, check)
            else:
                on_done(box.get("result"), box.get("error"))
        self.root.after(100, check)

    def _toast(self, message: str, seconds: int = 4):
        """Aviso pequeño, siempre encima, que se cierra solo (sirve aunque la app esté minimizada)."""
        try:
            win = tk.Toplevel(self.root)
            win.overrideredirect(True)
            win.attributes("-topmost", True)
            win.configure(bg=C["primary"])
            tk.Label(win, text=f"🔒 CipherVault\n{message}", bg=C["card"], fg=C["text"],
                     font=("Segoe UI", 10), justify="left", wraplength=360, padx=14, pady=10
                     ).pack(padx=2, pady=2)
            win.update_idletasks()
            x = win.winfo_screenwidth() - win.winfo_width() - 24
            y = win.winfo_screenheight() - win.winfo_height() - 72
            win.geometry(f"+{x}+{y}")
            win.after(seconds * 1000, win.destroy)
        except tk.TclError:
            pass

    # ─────────────────────────────────────────
    #  KIT DE EMERGENCIA
    # ─────────────────────────────────────────
    def _save_emergency_kit(self, username: str | None = None, email: str | None = None):
        """Guarda el PDF del kit de emergencia (sin ninguna contraseña) donde elija el usuario."""
        username = username or (self.current_user or {}).get("username", "")
        email = email if email is not None else (self.current_user or {}).get("email", "")
        documents = Path.home() / "Documents"
        path = filedialog.asksaveasfilename(
            title="Guardar kit de emergencia", defaultextension=".pdf",
            initialdir=str(documents if documents.is_dir() else DATA_PATH),
            initialfile=f"CipherVault_kit_de_emergencia_{self._safe_filename(username)}.pdf",
            filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        pdf = cvx.build_emergency_kit_pdf(username, email, str(DATA_PATH), SUPPORT_EMAIL, APP_VERSION)
        try:
            Path(path).write_bytes(pdf)
        except OSError as exc:
            messagebox.showerror("No se pudo guardar", str(exc))
            return
        messagebox.showinfo("✅ Kit guardado",
                            f"Kit de emergencia guardado en:\n{path}\n\n"
                            "Imprímelo, escribe tu contraseña maestra a mano y guárdalo en un lugar seguro.")
        if os.name == "nt":
            try:
                os.startfile(path)            # abre el PDF para imprimirlo
            except OSError:
                pass

    # ─────────────────────────────────────────
    #  AUTO-ESCRITURA (Ctrl + Alt + A en Windows, Ctrl + Option + A en Mac)
    # ─────────────────────────────────────────
    def _start_autotype(self):
        """Registra el atajo global si está activado en la configuración (solo Windows)."""
        if not hasattr(self, "_hotkey"):
            self._hotkey = cvx.HotkeyListener()
        if not cvx.autotype_supported():
            return
        if self.config.get("autotype_enabled", True):
            if not self._hotkey.start():
                log.warning("Auto-escritura desactivada: %s", self._hotkey.error)
        else:
            self._hotkey.stop()
        if not getattr(self, "_hotkey_polling", False):
            self._hotkey_polling = True
            self.root.after(150, self._poll_hotkey)

    def _poll_hotkey(self):
        try:
            event = self._hotkey.poll()
            if event:
                self._on_autotype(*event)
        finally:
            self.root.after(150, self._poll_hotkey)

    def _autotype_entries(self) -> list[dict]:
        vault = self.current_user["vault"]
        with db() as conn:
            rows = conn.execute("SELECT id, service, username, url FROM passwords WHERE user_id=?",
                                (self.current_user["id"],)).fetchall()
        entries = [{"id": pid, "service": dec_text(vault, svc), "username": dec_text(vault, uname),
                    "url": dec_text(vault, url)} for pid, svc, uname, url in rows]
        if get_features(self.user_version).get("team") and self._team_path():
            team = self._open_team(quiet=True)
            if team:
                entries += [{"id": f"t:{e['uid']}", "service": f"{e['service']} (equipo)",
                             "username": e["username"], "url": e["url"]} for e in team.entries]
        return entries

    def _credentials_for(self, entry_id) -> tuple[str, str, str] | None:
        """(usuario, contraseña, clave 2FA) de una entrada personal (id numérico) o del
        equipo ("t:<uid>")."""
        if isinstance(entry_id, str) and entry_id.startswith("t:"):
            team = getattr(self, "_team", None) or self._open_team(quiet=True)
            entry = next((e for e in (team.entries if team else []) if e["uid"] == entry_id[2:]), None)
            return (entry["username"], entry["password"], entry["totp"]) if entry else None
        vault = self.current_user["vault"]
        with db() as conn:
            row = conn.execute("SELECT username, password_encrypted, totp FROM passwords WHERE id=? AND user_id=?",
                               (int(entry_id), self.current_user["id"])).fetchone()
        if not row:
            return None
        try:
            return (dec_text(vault, row[0]), vault.decrypt(row[1].encode("utf-8")).decode("utf-8"),
                    dec_text(vault, row[2]))
        except (InvalidToken, UnicodeDecodeError):
            return None

    def _on_autotype(self, hwnd: int, title: str):
        """Se pulsó el atajo (Ctrl+Alt+A / Ctrl+Option+A) sobre la ventana `title`: busca la
        contraseña que corresponde y la escribe. Si hay varias, deja elegir; si la sesión está bloqueada, solo avisa."""
        if title.startswith("🔒 CipherVault"):
            return
        if not self.current_user:
            self._toast("CipherVault está bloqueado. Inicia sesión y vuelve a pulsar "
                        f"{cvx.AUTOTYPE_HOTKEY_LABEL}.")
            return
        entries = self._autotype_entries()
        page_url = cvx.browser_url(hwnd) if cvx.is_browser_window(hwnd) else ""
        if page_url and cvx._page_host(page_url):
            # Navegador: manda la dirección real de la pestaña (no el título, que una página
            # falsa puede copiar).
            matches = cvx.match_entries_by_url(page_url, entries)
            where = cvx._page_host(page_url)
        else:
            matches = cvx.match_entries(title, entries)
            where = title[:60]
        if not matches:
            self._toast(f"No hay ninguna contraseña para «{where}».\n"
                        "Guárdala con la página web del sitio (o el nombre del sitio) para usar el atajo.")
            return
        if len(matches) == 1:
            self._autotype_entry(matches[0]["id"], hwnd)
            return
        self._autotype_chooser(matches[:12], hwnd, title)

    def _autotype_chooser(self, matches: list[dict], hwnd: int, title: str):
        win = tk.Toplevel(self.root)
        win.title("¿Qué cuenta?")
        win.configure(bg=C["bg"])
        win.attributes("-topmost", True)
        self._set_popup_geometry(win, 460, 140 + 44 * len(matches))
        self._label(win, "¿Qué cuenta quieres escribir?", font_size=13, bold=True).pack(pady=(16, 2))
        self._label(win, title[:70], color=C["muted"], font_size=9).pack(pady=(0, 10))
        for entry in matches:
            text = f"{entry['service']} — {entry['username'] or '(sin usuario)'}"

            def pick(pid=entry["id"]):
                win.destroy()
                self.root.after(150, lambda: self._autotype_entry(pid, hwnd))
            self._btn(win, text, pick).pack(fill="x", padx=30, pady=3)
        self._btn(win, "Cancelar", win.destroy).pack(pady=10)
        win.focus_force()

    def _autotype_entry(self, password_id: int, hwnd: int):
        if not self.current_user:
            return
        creds = self._credentials_for(password_id)
        if not creds:
            self._toast("No se pudo descifrar esa contraseña.")
            return
        username, password, _totp = creds
        cvx.focus_window(hwnd)
        press_enter = bool(self.config.get("autotype_enter", False))

        def done(_result, error):
            if error and sys.platform == "darwin":
                log.warning("Auto-escritura falló: %s", error)
                self._toast("macOS no dejó escribir: da permiso a CipherVault en Ajustes del Sistema → "
                            "Privacidad y seguridad → Accesibilidad, y vuelve a abrir la app.")
            elif error:
                log.warning("Auto-escritura falló: %s", error)
                self._toast("Windows no dejó escribir en esa ventana (si es un programa abierto como "
                            "administrador, abre CipherVault también como administrador).")
        self._run_background(lambda: cvx.type_login(username, password, press_enter), done)

    # ─────────────────────────────────────────
    #  WINDOWS HELLO
    # ─────────────────────────────────────────
    @staticmethod
    def _hello_users() -> list[str]:
        if not IS_WINDOWS:
            return []
        try:
            with db() as conn:
                return [r[0] for r in conn.execute(
                    "SELECT username FROM users WHERE hello_wrapped IS NOT NULL AND hello_wrapped <> ''")]
        except sqlite3.Error:
            return []

    def _enable_hello(self):
        """Activa el desbloqueo con Windows Hello para la cuenta abierta."""
        if not self._ask_master():
            return
        username = self.current_user["username"]
        key = self.current_user.get("vault_key")
        if not key:
            messagebox.showerror("Windows Hello", "Cierra sesión y vuelve a entrar con tu contraseña maestra.")
            return

        def enroll():
            if not cvx.hello_available():
                raise cvx.HelloError("Este equipo no tiene Windows Hello configurado (huella, rostro o PIN). "
                                     "Actívalo en Configuración de Windows → Cuentas → Opciones de inicio de sesión.")
            challenge = os.urandom(32)
            signature = cvx.hello_sign(username, challenge, create=True)
            return _b64(challenge), cvx.hello_wrap_key(key, signature)

        def done(result, error):
            if error:
                messagebox.showerror("Windows Hello", str(error) if isinstance(error, cvx.HelloError)
                                     else "No se pudo activar Windows Hello. Revisa el archivo de registro.")
                if not isinstance(error, cvx.HelloError):
                    log.error("Fallo al activar Windows Hello", exc_info=error)
                return
            challenge, wrapped = result
            with db() as conn:
                conn.execute("UPDATE users SET hello_challenge=?, hello_wrapped=? WHERE id=?",
                             (challenge, wrapped, self.current_user["id"]))
            log.info("Windows Hello activado para %s", username)
            messagebox.showinfo("✅ Windows Hello activado",
                                "Desde ahora puedes entrar con tu huella, rostro o PIN de Windows.\n\n"
                                "Tu contraseña maestra sigue funcionando: no la olvides.")
            self._tab_settings()
        self._toast("Sigue las instrucciones de Windows Hello…", 3)
        self._run_background(enroll, done)

    def _disable_hello(self):
        username = self.current_user["username"]
        with db() as conn:
            conn.execute("UPDATE users SET hello_challenge=NULL, hello_wrapped=NULL WHERE id=?",
                         (self.current_user["id"],))
        self._run_background(lambda: cvx.hello_delete(username), lambda *_: None)
        messagebox.showinfo("Windows Hello", "Windows Hello quedó desactivado para esta cuenta.")
        self._tab_settings()

    def _login_hello(self):
        """Inicia sesión con Windows Hello en lugar de la contraseña maestra."""
        uname = self.entry_user.get().strip()
        hello_users = self._hello_users()
        if not uname and len(hello_users) == 1:
            uname = hello_users[0]
        if not uname:
            messagebox.showinfo("Windows Hello", "Escribe tu usuario y vuelve a pulsar «Entrar con Windows Hello».")
            return
        remaining = self._lock_remaining(uname)
        if remaining:
            messagebox.showerror("Espera un momento", f"Demasiados intentos. Intenta de nuevo en {remaining} segundos.")
            return
        with db() as conn:
            user = get_user_by_name(conn, uname)
        if not user or not user.get("hello_wrapped") or not user.get("hello_challenge"):
            messagebox.showinfo("Windows Hello", "Esa cuenta no tiene Windows Hello activado. Entra con tu "
                                                 "contraseña maestra y actívalo en Configuración.")
            return
        challenge = base64.urlsafe_b64decode(user["hello_challenge"].encode("ascii"))

        def unlock():
            signature = cvx.hello_sign(user["username"], challenge)
            return cvx.hello_unwrap_key(user["hello_wrapped"], signature)

        def done(key, error):
            if error:
                if isinstance(error, cvx.HelloError):
                    messagebox.showerror("Windows Hello", str(error))
                else:
                    log.error("Fallo de Windows Hello en el login", exc_info=error)
                    messagebox.showerror("Windows Hello", "No se pudo usar Windows Hello. Entra con tu contraseña maestra.")
                return
            auth = authenticate_with_key(key, user)
            if not auth.ok:
                messagebox.showerror("Windows Hello", "La clave guardada ya no corresponde a tu contraseña "
                                                      "maestra. Entra con ella y vuelve a activar Windows Hello.")
                return
            self._clear_failures(uname)
            self._open_session(user, auth)
        self._run_background(unlock, done)

    # ─────────────────────────────────────────
    #  SINCRONIZACIÓN ENTRE EQUIPOS (carpeta de OneDrive / Google Drive)
    # ─────────────────────────────────────────
    SYNC_INTERVAL_MS = 120_000

    def _sync_config(self) -> dict | None:
        """Ruta y clave del archivo de sincronización de la cuenta abierta, o None."""
        if not self.current_user or not get_features(self.user_version).get("sync"):
            return None
        with db() as conn:
            user = get_user_by_id(conn, self.current_user["id"])
        if not user or not user.get("sync_path") or not user.get("sync_key"):
            return None
        vault = self.current_user["vault"]
        try:
            return {"path": Path(dec_text(vault, user["sync_path"])),
                    "key": dec_text(vault, user["sync_key"]).encode("ascii"),
                    "header": {"salt": base64.urlsafe_b64decode(user["sync_salt"].encode("ascii")),
                               "iterations": int(user["sync_iterations"])}}
        except (ValueError, TypeError, AttributeError):
            return None

    def _local_sync_state(self) -> tuple[list[dict], dict]:
        vault = self.current_user["vault"]
        with db() as conn:
            rows = conn.execute("""SELECT uid,service,username,password_encrypted,notes,url,totp,category,
                                          created_at,updated_at FROM passwords WHERE user_id=?""",
                                (self.current_user["id"],)).fetchall()
            tombs = dict(conn.execute("SELECT uid, deleted_at FROM sync_tombstones WHERE user_id=?",
                                      (self.current_user["id"],)).fetchall())
        entries = []
        for uid, svc, uname, enc_pwd, notes, url, totp, cat, created, updated in rows:
            try:
                pwd = vault.decrypt(enc_pwd.encode("utf-8")).decode("utf-8")
            except (InvalidToken, UnicodeDecodeError, AttributeError):
                continue                       # ilegible: no se sincroniza
            entries.append({"uid": uid, "service": dec_text(vault, svc), "username": dec_text(vault, uname),
                            "password": pwd, "notes": dec_text(vault, notes), "url": dec_text(vault, url),
                            "totp": dec_text(vault, totp), "category": cat or "General",
                            "created_at": created or "", "updated_at": updated or ""})
        return entries, tombs

    def _apply_sync_result(self, local_entries: list[dict], merged: list[dict], tombs: dict) -> int:
        """Deja la base local igual al resultado de la mezcla. Devuelve cuántos cambios hubo."""
        upserts, deletes = cvs.plan_local_changes(local_entries, merged)
        if not upserts and not deletes:
            with db() as conn:
                for uid, when in tombs.items():
                    conn.execute("INSERT OR REPLACE INTO sync_tombstones(user_id,uid,deleted_at) VALUES(?,?,?)",
                                 (self.current_user["id"], uid, when))
            return 0
        vault = self.current_user["vault"]
        uid_self = self.current_user["id"]
        with db() as conn:
            for e in upserts:
                strength, _ = self._eval_strength(e["password"])
                values = (enc_text(vault, e["service"]), enc_text(vault, e["username"]),
                          vault.encrypt(e["password"].encode("utf-8")).decode("ascii"), strength,
                          e["category"][:40], enc_text(vault, e["notes"]), enc_text(vault, e["url"]),
                          enc_text(vault, e["totp"]), e["updated_at"] or cvs.utc_now())
                cur = conn.execute("""UPDATE passwords SET service=?,username=?,password_encrypted=?,strength=?,
                                      category=?,notes=?,url=?,totp=?,updated_at=? WHERE user_id=? AND uid=?""",
                                   values + (uid_self, e["uid"]))
                if cur.rowcount == 0:
                    conn.execute("""INSERT INTO passwords(service,username,password_encrypted,strength,category,
                                    notes,url,totp,updated_at,user_id,uid,created_at)
                                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                                 values + (uid_self, e["uid"], e["created_at"] or cvs.utc_now()))
            for uid in deletes:
                conn.execute("DELETE FROM passwords WHERE user_id=? AND uid=?", (uid_self, uid))
            for uid, when in tombs.items():
                conn.execute("INSERT OR REPLACE INTO sync_tombstones(user_id,uid,deleted_at) VALUES(?,?,?)",
                             (uid_self, uid, when))
        return len(upserts) + len(deletes)

    def _schedule_sync(self, delay_ms: int = 3000):
        """Programa una sincronización (agrupa varios cambios seguidos en una sola)."""
        if not hasattr(self, "root"):
            return
        job = getattr(self, "_sync_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except (tk.TclError, ValueError):
                pass
        self._sync_job = self.root.after(delay_ms, self._sync_now)

    def _sync_now(self, interactive: bool = False):
        """Sincroniza con el archivo de la carpeta (en un hilo) y refresca la lista si cambió algo."""
        self._sync_job = None
        cfg = self._sync_config()
        if not cfg or getattr(self, "_sync_running", False):
            return
        if not cfg["path"].parent.is_dir():
            if interactive:
                messagebox.showerror("Sincronización", f"No se encuentra la carpeta:\n{cfg['path'].parent}\n\n"
                                                      "¿Está abierto OneDrive / Google Drive?")
            self._sync_status = "⚠️ No se encuentra la carpeta de sincronización"
            return
        self._sync_running = True
        user_id = self.current_user["id"]
        local_entries, local_tombs = self._local_sync_state()
        device = platform.node() or "PC"

        def work():
            return cvs.sync_folder(cfg["path"], cfg["key"], cfg["header"], local_entries, local_tombs, device)

        def done(result, error):
            self._sync_running = False
            if not self.current_user or self.current_user["id"] != user_id:
                return
            if error:
                log.warning("Sincronización falló: %s", error)
                self._sync_status = f"⚠️ {error}" if isinstance(error, cvs.SyncError) else "⚠️ No se pudo sincronizar"
                if interactive:
                    messagebox.showerror("Sincronización", self._sync_status[2:])
                return
            merged, tombs = result
            try:
                changes = self._apply_sync_result(local_entries, merged, tombs)
            except sqlite3.Error:
                log.exception("No se pudieron aplicar los cambios sincronizados")
                return
            self._sync_status = f"✅ Sincronizado {datetime.now():%d/%m %H:%M}"
            if changes and hasattr(self, "tree"):
                try:
                    if self.tree.winfo_exists():
                        self._load_passwords()
                except tk.TclError:
                    pass
            if interactive:
                messagebox.showinfo("Sincronización", f"Listo. Cambios recibidos de otros equipos: {changes}")
        self._run_background(work, done)

    def _sync_loop(self):
        """Revisa la carpeta cada 2 minutos mientras haya una sesión abierta."""
        if self.current_user:
            self._sync_now()
        self.root.after(self.SYNC_INTERVAL_MS, self._sync_loop)

    def _enable_sync(self):
        """Elige la carpeta (OneDrive, Google Drive, Dropbox…) y activa la sincronización."""
        if not get_features(self.user_version).get("sync"):
            messagebox.showinfo("Plan Premium", "La sincronización entre equipos está en Premium.")
            return
        folder = filedialog.askdirectory(
            title="Elige una carpeta de OneDrive, Google Drive o Dropbox",
            initialdir=str(next((p for p in (Path.home() / "OneDrive", Path.home() / "Google Drive",
                                             Path.home() / "Dropbox") if p.is_dir()), Path.home())))
        if not folder:
            return
        pwd = self._ask_master_password()
        if not pwd:
            return
        path = Path(folder) / cvs.sync_file_name(self.current_user["username"])
        try:
            header = cvs.sync_file_info(path)
            if header:
                key = cvs.derive_sync_key(pwd, header["salt"], header["iterations"])
                cvs.read_sync(path, key)          # comprueba que la contraseña abre el archivo
            else:
                header = cvs.new_sync_header(VAULT_KDF_ITERATIONS)
                key = cvs.derive_sync_key(pwd, header["salt"], header["iterations"])
        except cvs.SyncError as exc:
            messagebox.showerror("Sincronización", str(exc))
            return
        vault = self.current_user["vault"]
        with db() as conn:
            conn.execute("UPDATE users SET sync_path=?, sync_key=?, sync_salt=?, sync_iterations=? WHERE id=?",
                         (enc_text(vault, str(path)), enc_text(vault, key.decode("ascii")),
                          base64.urlsafe_b64encode(header["salt"]).decode("ascii"), str(header["iterations"]),
                          self.current_user["id"]))
        log.info("Sincronización activada en %s", path.parent)
        messagebox.showinfo("✅ Sincronización activada",
                            f"Tus contraseñas se guardan cifradas en:\n{path}\n\n"
                            "En tu otro equipo: entra con la MISMA cuenta y contraseña maestra, ve a "
                            "Configuración → Sincronización y elige esta misma carpeta.")
        self._sync_now(interactive=True)
        self._tab_settings()

    def _disable_sync(self):
        with db() as conn:
            conn.execute("UPDATE users SET sync_path=NULL, sync_key=NULL, sync_salt=NULL, sync_iterations=NULL "
                         "WHERE id=?", (self.current_user["id"],))
        self._sync_status = ""
        messagebox.showinfo("Sincronización", "Sincronización desactivada en este equipo. El archivo de la "
                                              "carpeta no se borró.")
        self._tab_settings()

    # ─────────────────────────────────────────
    #  BÓVEDA DE EQUIPO (plan Equipo)
    # ─────────────────────────────────────────
    def _team_keys(self) -> tuple[bytes, bytes]:
        """(privada, pública) X25519 de la cuenta; se crean la primera vez."""
        vault = self.current_user["vault"]
        with db() as conn:
            user = get_user_by_id(conn, self.current_user["id"])
            if user.get("team_priv") and user.get("team_pub"):
                priv = base64.urlsafe_b64decode(dec_text(vault, user["team_priv"]).encode("ascii"))
                return priv, base64.urlsafe_b64decode(user["team_pub"].encode("ascii"))
            priv, pub = cvs.new_member_keypair()
            conn.execute("UPDATE users SET team_priv=?, team_pub=? WHERE id=?",
                         (enc_text(vault, base64.urlsafe_b64encode(priv).decode("ascii")),
                          base64.urlsafe_b64encode(pub).decode("ascii"), user["id"]))
            return priv, pub

    def _team_path(self) -> Path | None:
        with db() as conn:
            user = get_user_by_id(conn, self.current_user["id"])
        if not user.get("team_path"):
            return None
        return Path(dec_text(self.current_user["vault"], user["team_path"]))

    def _set_team_path(self, path: Path | None):
        vault = self.current_user["vault"]
        with db() as conn:
            conn.execute("UPDATE users SET team_path=? WHERE id=?",
                         (enc_text(vault, str(path)) if path else None, self.current_user["id"]))

    def _open_team(self, quiet: bool = False) -> "cvs.TeamVault | None":
        path = self._team_path()
        if not path:
            return None
        try:
            team = cvs.TeamVault.open(path, self._team_keys()[0])
        except FileNotFoundError:
            if not quiet:
                messagebox.showerror("Equipo", f"No se encuentra el archivo del equipo:\n{path}\n\n"
                                               "¿Está abierta la carpeta compartida (OneDrive/Drive/red)?")
            return None
        except cvs.SyncError as exc:
            if not quiet:
                messagebox.showerror("Equipo", str(exc))
            return None
        self._team = team
        return team

    def _tab_team(self):
        """Pestaña de la bóveda compartida del equipo."""
        self._clear_content()
        f = self.content_frame
        if not get_features(self.user_version).get("team"):
            self._label(f, "👥 Bóveda de equipo", font_size=20, bold=True).pack(anchor="w")
            self._plan_banner(f, C["card"], "Disponible en el plan Equipo",
                              "Comparte contraseñas de la empresa con tus empleados, con roles y permisos.",
                              self._choose_team_plan, "👥 Ver plan Equipo")
            return
        priv, pub = self._team_keys()
        path = self._team_path()
        team = self._open_team(quiet=True) if path else None
        if not team:
            self._label(f, "👥 Bóveda de equipo", font_size=20, bold=True).pack(anchor="w", pady=(0, 12))
            if path:
                self._label(f, f"⚠️ No se pudo abrir el equipo guardado ({path.name}). Revisa que la carpeta "
                               "compartida esté disponible o vuelve a unirte.",
                            color=C["warning"], font_size=10, wraplength=self._s(800), justify="left"
                            ).pack(anchor="w", pady=(0, 10))
            card = self._card(f, padx=24, pady=20)
            card.pack(fill="x")
            self._label(card, "Tu código de miembro", bold=True).pack(anchor="w")
            self._label(card, "Envíaselo al administrador del equipo para que te agregue. No es secreto: "
                              "solo sirve para que puedas abrir la bóveda del equipo.",
                        color=C["muted"], font_size=9, wraplength=self._s(760), justify="left").pack(anchor="w")
            code = cvs.member_code(pub)
            row = tk.Frame(card, bg=C["card"])
            row.pack(anchor="w", pady=8)
            entry = ttk.Entry(row, width=64)
            entry.insert(0, code)
            entry.config(state="readonly")
            entry.pack(side="left")
            self._btn(row, "📋 Copiar", lambda: [self.root.clipboard_clear(), self.root.clipboard_append(code),
                                                 messagebox.showinfo("✅", "Código copiado.")]).pack(side="left", padx=6)
            actions = self._card(f, padx=24, pady=20)
            actions.pack(fill="x", pady=(12, 0))
            self._label(actions, "¿Cómo funciona?", bold=True).pack(anchor="w")
            for line in ("1. El administrador crea el equipo en una carpeta compartida (OneDrive, Google Drive "
                         "o una carpeta de red de la empresa).",
                         "2. Cada empleado le envía su código de miembro y el administrador lo agrega con un rol.",
                         "3. El empleado pulsa «Unirme a un equipo» y elige el archivo .cvteam de esa carpeta."):
                self._label(actions, line, color=C["muted"], font_size=10, wraplength=self._s(760),
                            justify="left").pack(anchor="w", pady=1)
            btns = tk.Frame(actions, bg=C["card"])
            btns.pack(anchor="w", pady=(12, 0))
            self._btn(btns, "➕ Crear equipo", self._team_create, "Primary.TButton").pack(side="left", padx=(0, 8))
            self._btn(btns, "🔗 Unirme a un equipo", self._team_join).pack(side="left")
            return

        role = cvs.ROLES.get(team.my_role, team.my_role)
        self._label(f, f"👥 {team.name}", font_size=20, bold=True).pack(anchor="w")
        self._label(f, f"Tu rol: {role}  ·  {len(team.members)} miembro(s)  ·  {team.path.name}",
                    color=C["muted"]).pack(anchor="w", pady=(0, 10))
        ctrl = tk.Frame(f, bg=C["bg"])
        ctrl.pack(fill="x", pady=(0, 8))
        if team.can_edit:
            self._btn(ctrl, "➕ Agregar", lambda: self._team_entry_form(None), "Primary.TButton").pack(side="left", padx=(0, 6))
        self._btn(ctrl, "👁️ Ver", self._team_view).pack(side="left", padx=3)
        if team.can_edit:
            self._btn(ctrl, "✏️ Editar", lambda: self._team_entry_form(self._team_selected())).pack(side="left", padx=3)
            self._btn(ctrl, "🗑️ Eliminar", self._team_delete, "Danger.TButton").pack(side="left", padx=3)
        self._btn(ctrl, "🔄 Actualizar", self._tab_team).pack(side="left", padx=3)
        if team.is_admin:
            self._btn(ctrl, "👤 Miembros", self._team_members).pack(side="left", padx=3)
            self._btn(ctrl, "📜 Actividad", self._team_activity).pack(side="left", padx=3)
            self._btn(ctrl, "🛡️ Informe de seguridad", self._team_report).pack(side="left", padx=3)
        self._btn(ctrl, "🚪 Salir del equipo", self._team_leave).pack(side="right")

        tbl = tk.Frame(f, bg=C["card"])
        tbl.pack(fill="both", expand=True)
        cols = ("Servicio", "Usuario", "Categoría", "Actualizado")
        self.team_tree = ttk.Treeview(tbl, columns=cols, show="headings", height=18)
        for col, width in zip(cols, (220, 220, 140, 140)):
            self.team_tree.heading(col, text=col)
            self.team_tree.column(col, width=self._s(width))
        self.team_tree.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        sb = ttk.Scrollbar(tbl, orient="vertical", command=self.team_tree.yview)
        self.team_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        for e in sorted(team.entries, key=lambda x: x["service"].lower()):
            self.team_tree.insert("", "end", iid=e["uid"],
                                  values=(e["service"], e["username"], e["category"], e["updated_at"][:10]))
        self.team_tree.bind("<Double-1>", lambda _e: self._team_view())

    def _team_selected(self) -> dict | None:
        team = getattr(self, "_team", None)
        sel = self.team_tree.selection() if hasattr(self, "team_tree") else ()
        if not team or not sel:
            messagebox.showwarning("Sin selección", "Selecciona una entrada del equipo.")
            return None
        return next((e for e in team.entries if e["uid"] == sel[0]), None)

    def _team_create(self):
        folder = filedialog.askdirectory(title="Elige la carpeta compartida del equipo (OneDrive, Drive o red)")
        if not folder:
            return
        name = simpledialog.askstring("Crear equipo", "Nombre del equipo (por ejemplo, el de tu empresa):")
        if not name or not name.strip():
            return
        _, pub = self._team_keys()
        try:
            team = cvs.TeamVault.create(Path(folder), name, pub, self.current_user["username"],
                                        self.current_user.get("email", ""))
        except (cvs.SyncError, OSError) as exc:
            messagebox.showerror("Equipo", str(exc))
            return
        self._set_team_path(team.path)
        log.info("Equipo creado: %s", team.path)
        messagebox.showinfo("✅ Equipo creado",
                            f"Se creó «{team.name}» en:\n{team.path}\n\nComparte esa carpeta con tus empleados "
                            "y agrégalos en «Miembros» con el código que te envíe cada uno.")
        self._tab_team()

    def _team_join(self):
        path = filedialog.askopenfilename(title="Elige el archivo del equipo (.cvteam)",
                                          filetypes=[("Bóveda de equipo de CipherVault", "*.cvteam")])
        if not path:
            return
        try:
            team = cvs.TeamVault.open(Path(path), self._team_keys()[0])
        except (cvs.SyncError, OSError) as exc:
            messagebox.showerror("Equipo", str(exc))
            return
        self._set_team_path(Path(path))
        messagebox.showinfo("✅ Te uniste", f"Ahora ves las contraseñas de «{team.name}».")
        self._tab_team()

    def _team_leave(self):
        if not messagebox.askyesno("Salir del equipo", "¿Dejar de ver este equipo en este equipo (PC)? "
                                                       "El administrador sigue pudiendo agregarte de nuevo."):
            return
        self._set_team_path(None)
        self._team = None
        self._tab_team()

    def _team_save(self, team) -> bool:
        try:
            team.save_merged(self._team_keys()[0])
            return True
        except (cvs.SyncError, OSError) as exc:
            messagebox.showerror("Equipo", f"No se pudo guardar: {exc}")
            return False

    def _team_view(self):
        entry = self._team_selected()
        if not entry:
            return
        win = self._inline_page()
        win.title(f"👥 {entry['service']}")
        self._set_popup_geometry(win, 540, 440)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        self._label(win, f"👥 {entry['service']}", font_size=17, bold=True, color=C["primary"]).pack(pady=(18, 8))
        body = self._card(win, padx=22, pady=18)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        rows = [("👤 Usuario", entry["username"] or "—"), ("🌐 Página web", entry["url"] or "—"),
                ("📂 Categoría", entry["category"]), ("📝 Notas", entry["notes"] or "—")]
        for i, (lbl, val) in enumerate(rows):
            self._label(body, lbl, bold=True, color=C["muted"]).grid(row=i, column=0, sticky="nw", pady=4)
            self._label(body, val, wraplength=self._s(300), justify="left").grid(row=i, column=1, sticky="w", padx=10, pady=4)
        btns = tk.Frame(body, bg=C["card"])
        btns.grid(row=len(rows), column=0, columnspan=2, pady=(12, 0), sticky="w")
        def copy_password():
            self._copy_secret(entry["password"])
            self._team_log_copy(entry)
            messagebox.showinfo("✅", "Copiada (se borra en 30 s).")
        self._btn(btns, "📋 Copiar contraseña", copy_password).pack(side="left", padx=(0, 6))
        if entry["username"]:
            self._btn(btns, "📋 Copiar usuario", lambda: [self.root.clipboard_clear(),
                                                        self.root.clipboard_append(entry["username"])]
                      ).pack(side="left", padx=3)
        if entry["totp"]:
            def copy_code():
                try:
                    self._copy_secret(cvx.totp_code(entry["totp"])[0])
                    self._team_log_copy(entry, "el código 2FA")
                    messagebox.showinfo("✅", "Código 2FA copiado.")
                except ValueError:
                    messagebox.showerror("2FA", "La clave 2FA guardada no es válida.")
            self._btn(btns, "🔢 Copiar código 2FA", copy_code).pack(side="left", padx=3)
        self._btn(win, "Cerrar", win.destroy).pack(pady=(0, 12))

    def _team_entry_form(self, entry: dict | None):
        team = getattr(self, "_team", None)
        if not team:
            return
        data = dict(entry or {})
        win = self._inline_page()
        win.title("Entrada del equipo")
        self._set_popup_geometry(win, 560, 560)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        self._label(win, "✏️ Editar entrada" if entry else "➕ Nueva entrada del equipo",
                    font_size=16, bold=True).pack(pady=(18, 8))
        body = self._card(win, padx=22, pady=18)
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        fields = [("service", "Servicio *"), ("url", "Página web"), ("username", "Usuario"),
                  ("password", "Contraseña *"), ("totp", "Clave 2FA"), ("category", "Categoría")]
        vars_ = {}
        for i, (key, label) in enumerate(fields):
            self._label(body, label, bold=True, color=C["muted"]).grid(row=i, column=0, sticky="w", pady=5)
            var = tk.StringVar(value=data.get(key, "") or ("General" if key == "category" else ""))
            ttk.Entry(body, textvariable=var, width=34, show="•" if key == "password" else "").grid(
                row=i, column=1, padx=10, pady=5)
            vars_[key] = var
        self._label(body, "Notas", bold=True, color=C["muted"]).grid(row=len(fields), column=0, sticky="nw", pady=5)
        notes = tk.Text(body, height=3, width=34, bg=C["card2"], fg=C["text"], font=("Segoe UI", 10))
        notes.grid(row=len(fields), column=1, padx=10, pady=5)
        notes.insert("1.0", data.get("notes", ""))

        def save():
            values = {k: v.get().strip() for k, v in vars_.items()}
            values["password"] = vars_["password"].get()
            values["notes"] = notes.get("1.0", "end-1c").strip()
            if not values["service"] or not values["password"]:
                messagebox.showerror("Faltan datos", "Servicio y contraseña son obligatorios.")
                return
            if values["totp"]:
                try:
                    cvx.parse_totp(values["totp"])
                except ValueError as exc:
                    messagebox.showerror("Clave 2FA no válida", str(exc))
                    return
            values["uid"] = data.get("uid", "")
            values["created_at"] = data.get("created_at", "")
            try:
                team.upsert(values)
            except cvs.SyncError as exc:
                messagebox.showerror("Equipo", str(exc))
                return
            if self._team_save(team):
                win.destroy()
                self._tab_team()
        btns = tk.Frame(win, bg=C["bg"])
        btns.pack(pady=(0, 12))
        self._btn(btns, "💾 Guardar", save, "Primary.TButton").pack(side="left", padx=6)
        self._btn(btns, "Cancelar", win.destroy).pack(side="left", padx=6)

    def _team_delete(self):
        team = getattr(self, "_team", None)
        entry = self._team_selected()
        if not team or not entry:
            return
        if not messagebox.askyesno("Eliminar", f"¿Eliminar «{entry['service']}» para TODO el equipo?"):
            return
        try:
            team.delete(entry["uid"])
        except cvs.SyncError as exc:
            messagebox.showerror("Equipo", str(exc))
            return
        if self._team_save(team):
            self._tab_team()

    def _team_log_copy(self, entry: dict, what: str = "la contraseña"):
        """Anota en el registro de actividad que se copió un dato (sin molestar si falla)."""
        team = getattr(self, "_team", None)
        if not team:
            return
        try:
            team.log_copy(entry, what)
            team.save_merged(self._team_keys()[0])
        except (cvs.SyncError, OSError) as exc:
            log.warning("No se pudo anotar la copia en el registro del equipo: %s", exc)

    def _team_activity(self):
        """Registro de actividad del equipo (solo administradores): quién creó, editó, borró o
        copió cada contraseña, y los cambios de miembros."""
        team = getattr(self, "_team", None)
        if not team or not team.is_admin:
            return
        try:
            team = self._team = team.refresh(self._team_keys()[0])
        except (cvs.SyncError, OSError):
            pass
        win = self._inline_page()
        win.title("Actividad del equipo")
        self._set_popup_geometry(win, 820, 560)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        self._label(win, f"📜 Actividad de {team.name}", font_size=16, bold=True).pack(pady=(18, 4))
        self._label(win, f"Últimos {cvs.ACTIVITY_MAX} movimientos, del más reciente al más antiguo. "
                         "Fechas en hora de Colombia.", color=C["muted"], font_size=9).pack(pady=(0, 8))
        frame = tk.Frame(win, bg=C["card"])
        frame.pack(fill="both", expand=True, padx=20)
        cols = ("Fecha", "Persona", "Acción")
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=16)
        for col, width in zip(cols, (150, 180, 420)):
            tree.heading(col, text=col)
            tree.column(col, width=self._s(width))
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        sb.pack(side="right", fill="y")
        for event in reversed(team.activity):
            try:
                when = (datetime.strptime(event["at"][:19], SQL_DATETIME) - timedelta(hours=5)).strftime("%d/%m/%Y %H:%M")
            except (KeyError, ValueError):
                when = event.get("at", "")
            who = team.members.get(event.get("by"), {}).get("name") or event.get("by_name", "—")
            tree.insert("", "end", values=(when, who, f"{event.get('action', '')} {event.get('target', '')}".strip()))
        if not team.activity:
            tree.insert("", "end", values=("—", "—", "Todavía no hay movimientos registrados."))
        self._btn(win, "Cerrar", win.destroy).pack(pady=12)

    def _team_report(self):
        """Informe de seguridad de la bóveda del equipo (solo administradores)."""
        team = getattr(self, "_team", None)
        if not team or not team.is_admin:
            return
        rep = cvs.security_report(team.entries, lambda pwd: evaluate_strength(pwd)[0])
        win = self._inline_page()
        win.title("Informe de seguridad del equipo")
        self._set_popup_geometry(win, 720, 600)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        color = C["success"] if rep["score"] >= 80 else C["warning"] if rep["score"] >= 50 else C["danger"]
        self._label(win, f"🛡️ Seguridad de {team.name}", font_size=16, bold=True).pack(pady=(18, 4))
        self._label(win, f"Puntaje: {rep['score']}/100 · {rep['total']} contraseña(s) compartida(s)",
                    font_size=13, bold=True, color=color).pack(pady=(0, 10))
        body = self._card(win, padx=22, pady=16)
        body.pack(fill="both", expand=True, padx=20)
        sections = [
            ("🔴 Débiles", rep["weak"], "Cámbialas por una generada con el generador de CipherVault."),
            ("🟠 Repetidas", sorted(set(rep["reused"])), "La misma contraseña en varios servicios: si se filtra una, caen todas."),
            ("🕒 Sin cambiar en 6 meses", rep["stale"], "Conviene renovarlas, sobre todo si alguien salió del equipo."),
            ("🔢 Sin código 2FA", rep["no_2fa"], "Si el servicio lo permite, activa la verificación en dos pasos."),
        ]
        for title, names, tip in sections:
            self._label(body, f"{title}: {len(names)}", bold=True).pack(anchor="w", pady=(6, 0))
            text = ", ".join(names[:12]) + (f" y {len(names) - 12} más" if len(names) > 12 else "")
            self._label(body, text if names else "Ninguna 👍", color=C["text"] if names else C["success"],
                        font_size=9, wraplength=self._s(620), justify="left").pack(anchor="w")
            if names:
                self._label(body, tip, color=C["muted"], font_size=9, wraplength=self._s(620),
                            justify="left").pack(anchor="w")
        self._btn(win, "Cerrar", win.destroy).pack(pady=12)

    def _team_members(self):
        team = getattr(self, "_team", None)
        if not team or not team.is_admin:
            return
        win = self._inline_page()
        win.title("Miembros del equipo")
        self._set_popup_geometry(win, 720, 520)
        win.configure(bg=C["bg"])
        win.transient(self.root)
        self._label(win, f"👤 Miembros de {team.name}", font_size=16, bold=True).pack(pady=(18, 8))
        tree = ttk.Treeview(win, columns=("Nombre", "Email", "Rol"), show="headings", height=10)
        for col, width in (("Nombre", 200), ("Email", 260), ("Rol", 140)):
            tree.heading(col, text=col)
            tree.column(col, width=self._s(width))
        tree.pack(fill="both", expand=True, padx=20)
        for fp, m in team.members.items():
            label = cvs.ROLES.get(m["role"], m["role"]) + (" (tú)" if fp == team.my_fp else "")
            tree.insert("", "end", iid=fp, values=(m["name"], m.get("email", ""), label))

        def add():
            code = simpledialog.askstring("Agregar miembro", "Pega el código de miembro (CVM1-…) que te envió:",
                                          parent=win)
            if not code:
                return
            name = simpledialog.askstring("Agregar miembro", "Nombre de la persona:", parent=win) or ""
            email = simpledialog.askstring("Agregar miembro", "Email (opcional):", parent=win) or ""
            role = self._choose("Rol", "¿Qué puede hacer esta persona?", [
                ("lector", "👁️ Solo ver y copiar"), ("editor", "✏️ Ver, agregar y editar"),
                ("admin", "🛡️ Administrador (también maneja miembros)")])
            if not role:
                return
            try:
                team.add_member(code, name, email, role)
            except cvs.SyncError as exc:
                messagebox.showerror("Agregar miembro", str(exc), parent=win)
                return
            if self._team_save(team):
                win.destroy()
                messagebox.showinfo("✅ Miembro agregado", f"{name or 'La persona'} ya puede unirse con "
                                                          f"«Unirme a un equipo» eligiendo {team.path.name}.")
                self._team_members()

        def change_role():
            sel = tree.selection()
            if not sel:
                return
            role = self._choose("Cambiar rol", "Nuevo rol:", [
                ("lector", "👁️ Solo lectura"), ("editor", "✏️ Editor"), ("admin", "🛡️ Administrador")])
            if not role:
                return
            try:
                team.set_role(sel[0], role)
            except cvs.SyncError as exc:
                messagebox.showerror("Rol", str(exc), parent=win)
                return
            if self._team_save(team):
                win.destroy()
                self._team_members()

        def remove():
            sel = tree.selection()
            if not sel:
                return
            name = team.members.get(sel[0], {}).get("name", "")
            if not messagebox.askyesno("Quitar miembro",
                                       f"¿Quitar a {name}? Se cambiará la clave del equipo para que ya no pueda "
                                       "abrirlo.\n\nImportante: lo que ya vio no se puede borrar de su memoria. "
                                       "Cambia las contraseñas importantes que tenía acceso.", parent=win):
                return
            try:
                team.remove_member(sel[0])
            except cvs.SyncError as exc:
                messagebox.showerror("Quitar miembro", str(exc), parent=win)
                return
            if self._team_save(team):
                win.destroy()
                self._team_members()

        btns = tk.Frame(win, bg=C["bg"])
        btns.pack(pady=12)
        self._btn(btns, "➕ Agregar miembro", add, "Primary.TButton").pack(side="left", padx=5)
        self._btn(btns, "🔁 Cambiar rol", change_role).pack(side="left", padx=5)
        self._btn(btns, "🚫 Quitar", remove, "Danger.TButton").pack(side="left", padx=5)
        self._btn(btns, "Cerrar", win.destroy).pack(side="left", padx=5)

    def _logout(self):
        """Cierra la sesión actual (olvida la clave de la bóveda) y regresa a la pantalla de login."""
        self.current_user = None
        self._security_pwds = []
        self.is_developer = DeveloperLicenseManager.is_developer_machine()
        self.user_version = self._initial_version()
        self._setup_styles()
        self.show_login()

    # ─────────────────────────────────────────
    #  HELPER: FORTALEZA
    # ─────────────────────────────────────────
    @staticmethod
    def _eval_strength(pwd: str) -> tuple[str, int]:
        """Fortaleza de una contraseña (ver evaluate_strength): etiqueta DÉBIL/MODERADA/FUERTE/MUY FUERTE y puntaje 1-5."""
        return evaluate_strength(pwd)

# ══════════════════════════════════════════════
#  SETUP DESARROLLADOR
# ══════════════════════════════════════════════
def setup_developer():
    """Crea la licencia de desarrollador al arrancar, solo en una máquina de desarrollo autorizada."""
    if DeveloperLicenseManager.is_developer_machine() and not os.path.exists(LICENSE_FILE):
        DeveloperLicenseManager.create_license()
        log.info("Licencia de desarrollador creada")


def show_fatal_error(message: str):
    """Muestra un error grave en una ventana (el .exe no tiene consola) sin depender de la app."""
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("CipherVault", message)
        root.destroy()
    except Exception:
        pass


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════
def main():
    """Punto de entrada: crea la ventana Tkinter y lanza CipherVaultApp. Cualquier error
    de arranque queda en el log y se muestra en una ventana (no se pierde en silencio)."""
    try:
        setup_developer()
        root = tk.Tk()
        CipherVaultApp(root)
        root.mainloop()
    except Exception:
        log.exception("Error fatal al iniciar CipherVault")
        show_fatal_error("CipherVault no pudo iniciar.\n\nDetalle técnico guardado en:\n" + LOG_FILE)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
